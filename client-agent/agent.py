import threading
import time
import os

from config import CONFIG, logger
from detector import PatternBasedDetector
from scanner import FileScanner
from quarantine import QuarantineManager
from network.tcp_client import MasterCommunicator


class ClientAgent:
    """Main client agent orchestrator"""
    
    def __init__(self):
        self.config = CONFIG
        self.detector = PatternBasedDetector()
        self.scanner = FileScanner(self.config['SCAN_DIRECTORIES'])
        self.quarantine = QuarantineManager(self.config['QUARANTINE_DIR'])
        self.communicator = MasterCommunicator(
            self.config['MASTER_IP'],
            self.config['MASTER_PORT'],
            self.config['CLIENT_ID']
        )
        self.running = False
        self.current_task = None
    
    def start(self):
        """Start the agent"""
        self.running = True
        logger.info(f"Client Agent {self.config['CLIENT_ID']} starting...")
        
        # Connect to master
        while self.running and not self.communicator.connect():
            logger.info(f"Retrying connection in {self.config['RECONNECT_DELAY']}s...")
            time.sleep(self.config['RECONNECT_DELAY'])
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        # Main loop - listen for tasks
        self._main_loop()
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running and self.communicator.connected:
            try:
                self.communicator.send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
            time.sleep(self.config['HEARTBEAT_INTERVAL'])
    
    def _main_loop(self):
        """Main event loop"""
        while self.running:
            try:
                # Receive task from master
                message = self.communicator.receive_message(timeout=5.0)
                
                if message:
                    self._handle_message(message)
                
                # Reconnect if disconnected
                if not self.communicator.connected:
                    logger.warning("Disconnected from master, reconnecting...")
                    time.sleep(self.config['RECONNECT_DELAY'])
                    self.communicator.connect()
            
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                self.running = False
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                time.sleep(1)
    
    def _handle_message(self, message: dict):
        """Handle message from master"""
        msg_type = message.get('type')
        
        if msg_type == 'scan_task':
            self._execute_scan_task(message)
        elif msg_type == 'delete_approved':
            self._execute_deletion(message)
        elif msg_type == 'restore_file':
            self._restore_file(message)
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    def _execute_scan_task(self, task: dict):
        """Execute file scanning task"""
        logger.info(f"Received scan task: {task.get('task_id')}")
        self.current_task = task
        
        # Extract task parameters
        target_languages = task.get('target_languages', ['python', 'matlab', 'perl'])
        date_filter = task.get('date_filter')
        
        # Scan files
        files = self.scanner.scan(date_filter=date_filter)
        logger.info(f"Scanned directories: {self.config['SCAN_DIRECTORIES']}, found {len(files)} files")
        
        # Analyze files
        results = []
        for filepath in files:
            logger.info(f"Analyzing file: {filepath}")
            result = self.detector.analyze_file(filepath)
            logger.info(f"Analysis result: {result.filename} - {result.decision} ({result.language}) confidence: {result.confidence}")
            
            # Only quarantine files whose detected language is in the target set.
            # This prevents non-target-language files from being quarantined.
            is_target_language = result.language in target_languages
            should_quarantine = is_target_language  # Quarantine all target language files for testing
            logger.info(f"Should quarantine: {should_quarantine} (target: {is_target_language})")

            if should_quarantine:
                # Check if file is on a network share (UNC path)
                if filepath.startswith('\\\\'):
                    logger.info(f"Network share file detected: {filepath} - sending directly to master")
                    results.append(result)
                else:
                    # Check if on same drive/mount as quarantine directory
                    try:
                        file_drive = os.path.splitdrive(filepath)[0]
                        quarantine_drive = os.path.splitdrive(self.config['QUARANTINE_DIR'])[0]
                        
                        if file_drive and quarantine_drive and file_drive.lower() != quarantine_drive.lower():
                            logger.info(f"File on different drive ({file_drive}) than quarantine ({quarantine_drive}) - sending directly to master")
                            results.append(result)
                        else:
                            # Same drive (or unmatched drives due to empty config value) – attempt
                            # to quarantine; if that fails we still send the entry so the master
                            # can process it.  Cross‑device move errors inside quarantine
                            # manager are now handled there, but network issues or permission
                            # problems could still occur.
                            success, quarantine_path = self.quarantine.quarantine_file(filepath)
                            if success:
                                result.filepath = quarantine_path
                                results.append(result)
                                logger.info(f"Quarantined: {filepath} -> {quarantine_path}")
                            else:
                                logger.error(f"Failed to quarantine: {filepath}, forwarding to master")
                                # the file still needs analysis by the master, so include it
                                results.append(result)
                    except Exception as e:
                        logger.error(f"Error checking drives: {e}, sending directly to master")
                        results.append(result)
        
        # Send results to master
        logger.info(f"Sending {len(results)} results to master")
        if results:
            task_id = str(task.get('task_id') or 'unknown-task')
            self.communicator.send_scan_results(task_id, results)
        else:
            logger.info("No files found matching criteria")
    
    def _execute_deletion(self, message: dict):
        """Execute approved file deletions"""
        task_id = str(message.get('task_id') or 'unknown-task')
        approved_entries = message.get('approved_entries')
        approved_hashes = message.get('approved_hashes', [])

        if not approved_entries:
            approved_entries = [{'file_hash': h} for h in approved_hashes]

        logger.info(f"Deleting {len(approved_entries)} approved files for task {task_id}")

        reports = []

        for entry in approved_entries:
            file_hash = (entry or {}).get('file_hash', '')
            hint_path = (entry or {}).get('path', '')
            deleted = False
            deleted_path = ''
            details = ''

            # First, try hash-based lookup in quarantine.
            if file_hash:
                for root, _, files in os.walk(self.config['QUARANTINE_DIR']):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        if self.detector._calculate_hash(filepath) == file_hash:
                            deleted = self.quarantine.delete_quarantined(filepath)
                            deleted_path = filepath
                            details = 'deleted by hash' if deleted else 'hash found but delete failed'
                            break
                    if deleted or details:
                        break

            # Fallback: direct path delete if provided and still exists.
            if not deleted and hint_path and os.path.exists(hint_path):
                deleted = self.quarantine.delete_quarantined(hint_path)
                deleted_path = hint_path
                details = 'deleted by path fallback' if deleted else 'path found but delete failed'

            if not deleted and not details:
                details = 'file not found in quarantine'

            reports.append({
                'file_hash': file_hash,
                'path': deleted_path or hint_path,
                'status': 'deleted' if deleted else 'failed',
                'details': details,
            })

        deleted_count = sum(1 for r in reports if r['status'] == 'deleted')
        logger.info(f"Deleted {deleted_count}/{len(reports)} files for task {task_id}")

        try:
            self.communicator.send_deletion_report(task_id, reports)
        except Exception as e:
            logger.error(f"Failed to send deletion report: {e}")
    
    def _restore_file(self, message: dict):
        """Restore file from quarantine"""
        file_hash = message.get('file_hash')
        original_path = message.get('original_path')
        
        # Find and restore file
        # Implementation similar to deletion
        logger.info(f"Restoring file: {original_path}")
    
    def stop(self):
        """Stop the agent"""
        self.running = False
        self.communicator.disconnect()


if __name__ == '__main__':
    agent = ClientAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
        logger.info("Agent stopped")
