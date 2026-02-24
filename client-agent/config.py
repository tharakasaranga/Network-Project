import os
import socket
import logging

# Configuration
CONFIG = {
    'MASTER_IP': os.getenv('MASTER_IP', '10.17.63.28'),
    'MASTER_PORT': int(os.getenv('MASTER_PORT', 5000)),
    'CLIENT_ID': os.getenv('CLIENT_ID', socket.gethostname()),
    'SCAN_DIRECTORIES': os.getenv('SCAN_DIRS', os.path.join(os.path.expanduser('~'), 'Downloads', 'Detwork_Test_Run')).split(','),
    'QUARANTINE_DIR': os.getenv('QUARANTINE_DIR', os.path.join(os.path.expanduser('~'), 'quarantine')),
    'LOG_DIR': os.getenv('LOG_DIR', os.path.join(os.path.expanduser('~'), 'logs')),
    'HEARTBEAT_INTERVAL': 30,  
    'RECONNECT_DELAY': 10,  
}

# Setup logging
os.makedirs(CONFIG['LOG_DIR'], exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{CONFIG['LOG_DIR']}/agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ClientAgent')