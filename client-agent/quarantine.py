import os
import shutil
from typing import Tuple
from config import logger


class QuarantineManager:
    """Manages file quarantine"""
    
    def __init__(self, quarantine_dir: str):
        self.quarantine_dir = quarantine_dir
        os.makedirs(quarantine_dir, exist_ok=True)
    
    def quarantine_file(self, filepath: str) -> Tuple[bool, str]:
        """
        Move file to quarantine
        
        Returns:
            (success: bool, quarantine_path: str)
        """
        try:
        
            # build a relative path that preserves drive information on Windows
            # e.g. C:\foo\bar.txt -> foo\\bar.txt under quarantine
            drive, tail = os.path.splitdrive(filepath)
            if drive:
                # strip the colon ("C:") so we can use it as a folder name
                drive_letter = drive.rstrip(':').upper()
                rel_root = drive + os.sep
            else:
                # non‑Windows or no drive; use root
                drive_letter = ''
                rel_root = os.path.sep

            rel_path = os.path.relpath(filepath, rel_root)
            # include drive letter as a subdir so quarantines from different
            # volumes don't collide
            if drive_letter:
                quarantine_path = os.path.join(self.quarantine_dir, drive_letter, rel_path)
            else:
                quarantine_path = os.path.join(self.quarantine_dir, rel_path)

            os.makedirs(os.path.dirname(quarantine_path), exist_ok=True)

            try:
                # shutil.move will attempt os.rename which fails across devices.
                # catch that and fall back to copy+remove so cross‑drive
                # quarantines succeed instead of erroring out.
                shutil.move(filepath, quarantine_path)
            except Exception as move_err:
                # if moving across mount points, perform manual copy+delete
                msg = str(move_err).lower()
                if 'mount' in msg or 'device' in msg or 'cross' in msg:
                    shutil.copy2(filepath, quarantine_path)
                    os.remove(filepath)
                else:
                    raise

            logger.info(f"Quarantined: {filepath} -> {quarantine_path}")

            return True, quarantine_path
        
        except Exception as e:
            logger.error(f"Failed to quarantine {filepath}: {e}")
            return False, ''
    
    def restore_file(self, quarantine_path: str, original_path: str) -> bool:
        """Restore file from quarantine"""
        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(quarantine_path, original_path)
            logger.info(f"Restored: {quarantine_path} -> {original_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore {quarantine_path}: {e}")
            return False
    
    def delete_quarantined(self, quarantine_path: str) -> bool:
        """Permanently delete quarantined file"""
        try:
            os.remove(quarantine_path)
            logger.info(f"Deleted: {quarantine_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {quarantine_path}: {e}")
            return False