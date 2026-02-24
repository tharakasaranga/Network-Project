from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
from collections import defaultdict
import logging
import os
import sys
import threading
import time


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.api.instructions import create_scan_instruction, SUPPORTED_LANGUAGES
from backend.orchestrator.agent_registry import get_active_agents, update_status, mark_offline_inactive
from backend.network.protocol import send_message
from backend.network.tcp_server import start_master
from models import db, DeletionAuditLog
from shared import persistence
from backend.orchestrator.result_collector import result_collector
import uuid
from datetime import datetime


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
with app.app_context():
    db.create_all()
persistence.init_db()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
_MASTER_THREAD_STARTED = False


def _start_master_thread_if_enabled():
    global _MASTER_THREAD_STARTED
    if _MASTER_THREAD_STARTED:
        return

    if os.getenv("START_MASTER_WITH_UI", "1") != "1":
        logger.info("START_MASTER_WITH_UI disabled; expecting external backend master.")
        _MASTER_THREAD_STARTED = True
        return

    threading.Thread(target=start_master, daemon=True).start()
    _MASTER_THREAD_STARTED = True
    logger.info("Embedded master TCP server started on 0.0.0.0:5000")

    # Start periodic offline marker
    threading.Thread(target=_periodic_mark_offline, daemon=True).start()


def _periodic_mark_offline():
    while True:
        time.sleep(10)  # Check every 10 seconds
        mark_offline_inactive(timeout=30)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _infer_languages_from_instruction(instruction: str):
    text = instruction.lower()
    inferred = set()

    # Keep this conservative; default remains python if no clear hit.
    mapping = {
        "python": ["python", ".py"],
        "matlab": ["matlab", ".m"],
        "java": ["java", ".java"],
        "cpp": ["c++", "cpp", ".cpp", ".cc"],
        "c": [" c ", " c-language ", ".c "],
    }

    padded = f" {text} "
    for lang, hints in mapping.items():
        for hint in hints:
            if hint in padded or hint in text:
                inferred.add(lang)
                break

    if not inferred:
        inferred = {"python"}
    return list(inferred)


def _flatten_pending_files(search: str = ""):
    return persistence.list_pending_files(search=search)


def _group_records_by_agent(records):
    grouped = defaultdict(list)
    for r in records:
        key = (r["agent_ip"], r.get("task_id") or "unknown-task")
        grouped[key].append({
            "file_hash": r.get("file_hash", ""),
            "path": r.get("path", ""),
            "record_id": r.get("id", "")
        })
    return grouped


def _remove_records_from_queue(records):
    persistence.delete_pending_by_ids([r["id"] for r in records])


@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json(silent=True) or {}
        target = data.get('target_language')

        # Build task
        if target and target != 'Other':
            # use create_scan_instruction for known languages
            try:
                task = create_scan_instruction({target.lower()})
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        else:
            # custom task
            task = {
                'type': 'scan_task',
                'task_id': f"scan-{uuid.uuid4().hex[:8]}",
                'custom': {
                    'name': data.get('custom_name'),
                    'keywords': data.get('keywords'),
                    'extension': data.get('extension'),
                    'pattern': data.get('pattern')
                },
                'created_at': datetime.utcnow().isoformat()
            }

        # Attempt to send to in-memory active agents; if agent not connected, enqueue task
        active_memory = get_active_agents()
        sent = 0
        queued = 0
        failed = []

        # Use persisted agents list to know which agents to target
        persisted = persistence.list_agents()
        for item in persisted:
            agent_ip = item.get('agent_ip')
            raw_status = item.get('status', 'OFFLINE')
            # only target agents not marked OFFLINE in persistence
            if raw_status == 'OFFLINE':
                continue

            info = active_memory.get(agent_ip)
            if info and info.get('conn'):
                try:
                    send_message(info['conn'], task)
                    update_status(agent_ip, 'SCANNING')
                    sent += 1
                except Exception:
                    failed.append(agent_ip)
            else:
                # agent not connected right now; enqueue task to be delivered on heartbeat
                persistence.enqueue_task(agent_ip, task['task_id'], task)
                queued += 1

        if sent == 0 and queued == 0:
            return jsonify({'error': 'No active agents available'}), 400

        return jsonify({'task_id': task['task_id'], 'sent_to': sent, 'queued': queued, 'failed_agents': failed, 'results': []})
    except Exception as e:
        logger.exception('Error handling scan request')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/scan-results', methods=['GET'])
def scan_results():
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'task_id required'}), 400
    results = result_collector.get_task_results(task_id)
    return jsonify({'task_id': task_id, 'results': results})


def _persist_audit_logs(records, action: str, notes: str = ""):
    for rec in records:
        db.session.add(DeletionAuditLog(
            record_id=rec.get("id", ""),
            task_id=rec.get("task_id"),
            agent_ip=rec.get("agent_ip"),
            file_hash=rec.get("file_hash"),
            filename=rec.get("filename", "unknown"),
            path=rec.get("path", ""),
            language=rec.get("language"),
            confidence=rec.get("confidence"),
            action=action,
            notes=notes,
            created_at=datetime.now()
        ))
    db.session.commit()


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/verification")
def verification():
    return render_template("verification.html")


@app.route("/submit-instruction", methods=["POST"])
def submit_instruction():
    try:
        data = request.get_json(silent=True) or {}
        instruction = str(data.get("instruction", "")).strip()
        target_languages = data.get("target_languages")

        if not target_languages:
            if not instruction:
                return jsonify({"error": "Instruction cannot be empty"}), 400
            target_languages = _infer_languages_from_instruction(instruction)

        target_languages = [str(x).lower().strip() for x in target_languages if str(x).strip()]
        invalid = [x for x in target_languages if x not in SUPPORTED_LANGUAGES]
        if invalid:
            return jsonify({"error": f"Unsupported languages: {invalid}"}), 400

        task = create_scan_instruction(target_languages=target_languages, date_filter=None)
        active_agents = get_active_agents()
        if not active_agents:
            return jsonify({"error": "No active agents available"}), 400

        dispatched = 0
        failed = []
        for agent_ip, info in active_agents.items():
            conn = info.get("conn")
            if conn is None:
                failed.append(agent_ip)
                continue

            try:
                send_message(conn, task)
                update_status(agent_ip, "SCANNING")
                dispatched += 1
            except Exception as e:
                failed.append(agent_ip)
                logger.error("Failed dispatch to %s: %s", agent_ip, e)

        logger.info("Task %s dispatched to %d agents", task["task_id"], dispatched)
        return jsonify({
            "message": f"Instruction dispatched to {dispatched} agent(s)",
            "task_id": task["task_id"],
            "target_languages": target_languages,
            "failed_agents": failed
        })
    except Exception as e:
        logger.error("Error submitting instruction: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/clients-status", methods=["GET"])
def clients_status():
    try:
        status_list = []
        now = time.time()

        # Load persisted agents into a map for ordering and base data
        persisted = {p.get('agent_ip'): p for p in persistence.list_agents()}

        # Merge in-memory active agents to ensure currently connected sockets appear
        active_memory = get_active_agents()
        for ip, info in active_memory.items():
            # Update persisted entry or create a synthetic one
            persisted[ip] = {
                'agent_ip': ip,
                'status': info.get('status', 'IDLE'),
                'last_seen': info.get('last_seen')
            }

        # Now build the list, but only include those seen within the last 60s
        idx = 1
        for agent_ip in sorted(persisted.keys()):
            item = persisted[agent_ip]
            raw_status = item.get('status', 'OFFLINE')
            last_seen_ts = item.get('last_seen') or 0
            if last_seen_ts and (now - float(last_seen_ts)) < 60:
                last_seen = datetime.fromtimestamp(float(last_seen_ts), tz=timezone.utc).isoformat()
                status_list.append({
                    'id': idx,
                    'name': f'Agent {idx}',
                    'ip': agent_ip,
                    'ip_address': agent_ip,
                    'status': 'online' if raw_status != 'OFFLINE' else 'offline',
                    'raw_status': raw_status,
                    'last_seen': last_seen
                })
                idx += 1

        return jsonify(status_list)
    except Exception as e:
        logger.error("Error getting client status: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/files-preview", methods=["GET"])
def files_preview():
    try:
        search = request.args.get("search", "").strip()
        return jsonify(_flatten_pending_files(search=search))
    except Exception as e:
        logger.error("Error getting files preview: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/audit-logs", methods=["GET"])
def audit_logs():
    try:
        limit = int(request.args.get("limit", 200))
        limit = max(1, min(limit, 1000))
        rows = (
            DeletionAuditLog.query
            .order_by(DeletionAuditLog.created_at.desc())
            .limit(limit)
            .all()
        )
        audit_rows = [{
            "id": row.id,
            "record_id": row.record_id,
            "task_id": row.task_id,
            "agent_ip": row.agent_ip,
            "file_hash": row.file_hash,
            "filename": row.filename,
            "path": row.path,
            "language": row.language,
            "confidence": row.confidence,
            "action": row.action,
            "action_by": row.action_by,
            "notes": row.notes,
            "created_at": row.created_at.isoformat() if row.created_at else None
        } for row in rows]

        report_rows = []
        for rep in persistence.list_deletion_reports(limit=limit):
            report_rows.append({
                "id": f"rep-{rep.get('id')}",
                "record_id": "",
                "task_id": rep.get("task_id"),
                "agent_ip": rep.get("agent_ip"),
                "file_hash": rep.get("file_hash"),
                "filename": rep.get("path", "").split("\\")[-1].split("/")[-1] if rep.get("path") else "unknown",
                "path": rep.get("path", ""),
                "language": None,
                "confidence": None,
                "action": "delete_confirmed" if rep.get("status") == "deleted" else "delete_failed",
                "action_by": "agent",
                "notes": rep.get("details", ""),
                "created_at": rep.get("created_at"),
            })

        combined = audit_rows + report_rows
        combined.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        # Hide dispatch-failed noise rows from UI; keep them in DB for troubleshooting.
        combined = [row for row in combined if row.get("action") != "delete_dispatch_failed"]

        # If same file has confirmed deletion, hide older failed-not-found noise rows.
        confirmed_keys = set()
        for row in combined:
            if row.get("action") == "delete_confirmed":
                confirmed_keys.add((row.get("task_id"), row.get("agent_ip"), row.get("file_hash"), row.get("path")))

        filtered = []
        for row in combined:
            if row.get("action") == "delete_failed":
                key = (row.get("task_id"), row.get("agent_ip"), row.get("file_hash"), row.get("path"))
                if key in confirmed_keys:
                    continue
            filtered.append(row)

        return jsonify(filtered[:limit])
    except Exception as e:
        logger.error("Error getting audit logs: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/approve-deletion", methods=["POST"])
def approve_deletion():
    try:
        data = request.get_json(silent=True) or {}
        file_ids = data.get("file_ids", [])
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({"error": "file_ids must be a non-empty list"}), 400

        selected = persistence.get_pending_by_ids(file_ids)
        if not selected:
            return jsonify({"error": "No matching pending files found"}), 404

        entries_by_agent = _group_records_by_agent(selected)
        active_agents = get_active_agents()

        sent_to = 0
        queued = 0
        delivered_record_ids = set()
        queued_record_ids = set()
        undelivered_agents = []

        for (agent_ip, task_id), approved_entries in entries_by_agent.items():
            payload = {
                "type": "delete_approved",
                "task_id": task_id,
                "approved_entries": approved_entries,
                "approved_hashes": [x.get("file_hash", "") for x in approved_entries if x.get("file_hash")],
                "timestamp": _now_iso(),
            }
            agent_info = active_agents.get(agent_ip)

            # If socket is available in this process, dispatch immediately.
            try:
                if agent_info and agent_info.get("conn"):
                    send_message(agent_info["conn"], payload)
                    update_status(agent_ip, "DELETION_DISPATCHED")
                    sent_to += 1
                    for item in approved_entries:
                        rid = item.get("record_id")
                        if rid:
                            delivered_record_ids.add(rid)
                else:
                    # Cross-process fallback: queue command for backend to send on next heartbeat.
                    persistence.enqueue_delete_command(agent_ip, task_id, payload)
                    queued += 1
                    for item in approved_entries:
                        rid = item.get("record_id")
                        if rid:
                            queued_record_ids.add(rid)
                    logger.info("Queued delete command for %s task=%s", agent_ip, task_id)
            except Exception as e:
                logger.error("Failed delete dispatch to %s: %s", agent_ip, e)
                try:
                    persistence.enqueue_delete_command(agent_ip, task_id, payload)
                    queued += 1
                    for item in approved_entries:
                        rid = item.get("record_id")
                        if rid:
                            queued_record_ids.add(rid)
                    logger.info("Queued delete command after dispatch failure for %s task=%s", agent_ip, task_id)
                except Exception:
                    undelivered_agents.append(agent_ip)

        delivered = [r for r in selected if r.get("id") in delivered_record_ids]
        undelivered = [r for r in selected if r.get("id") not in delivered_record_ids]

        if delivered:
            _persist_audit_logs(
                delivered,
                action="delete_dispatched",
                notes=f"Approved in UI and dispatched to {sent_to} agent(s)"
            )
            _remove_records_from_queue(delivered)

        queued_records = [r for r in selected if r.get("id") in queued_record_ids]
        if queued_records and queued > 0:
            _persist_audit_logs(
                queued_records,
                action="delete_queued",
                notes="Delete command queued; will dispatch on next agent heartbeat"
            )

        if undelivered:
            _persist_audit_logs(
                undelivered,
                action="delete_dispatch_failed",
                notes="Agent not connected or dispatch failed; kept pending"
            )

        return jsonify({
            "message": f"Dispatch success: {len(delivered)} file(s), queued: {len(queued_records)} file(s), failed: {len(undelivered)} file(s).",
            "sent_to_agents": sent_to,
            "queued_agents": queued,
            "undelivered_agents": sorted(set(undelivered_agents)),
        })
    except Exception as e:
        logger.error("Error approving deletion: %s", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/reject-deletion", methods=["POST"])
def reject_deletion():
    try:
        data = request.get_json(silent=True) or {}
        file_ids = data.get("file_ids", [])
        if not isinstance(file_ids, list) or not file_ids:
            return jsonify({"error": "file_ids must be a non-empty list"}), 400

        selected = persistence.get_pending_by_ids(file_ids)
        if not selected:
            return jsonify({"error": "No matching pending files found"}), 404

        _persist_audit_logs(selected, action="rejected", notes="Rejected in UI")
        _remove_records_from_queue(selected)
        return jsonify({"message": f"Rejected {len(selected)} file(s)"})
    except Exception as e:
        logger.error("Error rejecting deletion: %s", e)
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Avoid duplicate server thread under Flask debug reloader.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or os.getenv("FLASK_DEBUG", "0") != "1":
        _start_master_thread_if_enabled()
    app.run(host='0.0.0.0', debug=True)
