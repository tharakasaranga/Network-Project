try:
    from backend.network.protocol import send_message
    from backend.orchestrator.agent_registry import update_status
except ModuleNotFoundError:
    from network.protocol import send_message
    from orchestrator.agent_registry import update_status


def dispatch_scan_task(conn, agent_ip, task: dict = None):
    """Send a scan task to a connected agent. If `task` is None, send a default test task.
    """
    if task is None:
        task = {
            "type": "scan_task",
            "task_id": "test_scan_001",
            "target_languages": ["python"],
            "date_filter": None
        }

    try:
        send_message(conn, task)
        update_status(agent_ip, "SCANNING")
        print(f"[MASTER] Scan task dispatched → {agent_ip} (task={task.get('task_id')})")
    except Exception as e:
        print(f"[MASTER] Failed to dispatch scan task to {agent_ip}: {e}")
