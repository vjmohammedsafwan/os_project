"""
Safe Response Simulator
Implements non-destructive endpoint containment actions with formal audit logs.
Stage 14 requirement.
"""
from datetime import datetime
from typing import Dict, Any, List
from processing.database import get_connection

def simulate_containment_action(incident_id: str, action_type: str, target: str) -> Dict[str, Any]:
    """
    Executes a simulated, safe response action without modifying live OS settings.
    Logs the action into the incident record in SQLite.
    """
    ts = datetime.utcnow().isoformat()
    action_templates = {
        "isolate_endpoint": f"[{ts}] [SAFE-SIMULATION] Host isolation rule triggered. Simulated network adapter disable for host: {target}.",
        "terminate_process": f"[{ts}] [SAFE-SIMULATION] Process tree kill signal triggered for PID: {target}. Sub-process hierarchy flagged for termination.",
        "block_ip": f"[{ts}] [SAFE-SIMULATION] Outbound firewall drop rule simulated for malicious C2 address: {target}.",
        "quarantine_file": f"[{ts}] [SAFE-SIMULATION] File quarantine simulated for artifact path: {target}."
    }

    log_entry = action_templates.get(action_type, f"[{ts}] [SAFE-SIMULATION] Generic containment simulated for {target}.")

    # Append to SQLite incident log
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT response_simulation_log FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if row:
        current_log = row["response_simulation_log"] or ""
        updated_log = (current_log + "\n" + log_entry).strip()
        cursor.execute("""
            UPDATE incidents 
            SET response_simulation_log = ?, status = 'Mitigated (Simulated)'
            WHERE incident_id = ?
        """, (updated_log, incident_id))
        conn.commit()
    conn.close()

    return {
        "incident_id": incident_id,
        "action_type": action_type,
        "target": target,
        "log_entry": log_entry,
        "status": "Success (Simulated)"
    }
