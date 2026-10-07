"""
Database & Telemetry Storage Engine
Handles SQLite schema, connection lifecycle, and event normalization.
Minimal, robust, self-contained.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

# --- System Paths & Storage Directories ---
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BASELINES_DIR = DATA_DIR / "baselines"
EXPORTS_DIR = DATA_DIR / "exports"
DB_PATH = DATA_DIR / "threat_detector.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
BASELINES_DIR.mkdir(parents=True, exist_ok=True)
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

# --- Operational Risk Tiers (0 to 100) ---
TIER_NORMAL_MAX = 30       # 0 - 30: Normal baseline
TIER_LOW_MAX = 60          # 31 - 60: Monitored
TIER_SUSPICIOUS_MAX = 80   # 61 - 80: Suspicious investigation
                           # 81 - 100: Critical incident containment

def get_risk_tier(score: float) -> str:
    """Map a numerical 0-100 score to its human-readable operational tier."""
    if score <= TIER_NORMAL_MAX:
        return "Normal"
    elif score <= TIER_LOW_MAX:
        return "Low"
    elif score <= TIER_SUSPICIOUS_MAX:
        return "Suspicious"
    else:
        return "Critical"

# --- Telemetry Event Normalization ---
SYSMON_EVENT_MAP = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    11: "FileCreate",
    12: "RegistryCreate",
    13: "RegistryValueSet"
}

def normalize_process_name(raw_path: Optional[str]) -> str:
    """Extracts lowercase executable filename from a full path."""
    if not raw_path or not str(raw_path).strip():
        return "unknown.exe"
    clean = str(raw_path).strip().replace("/", "\\")
    return Path(clean).name.lower()

def normalize_timestamp(raw_time: Optional[str]) -> str:
    """Ensures timestamp is formatted as an ISO-8601 string."""
    if not raw_time:
        return datetime.utcnow().isoformat()
    try:
        if isinstance(raw_time, datetime):
            return raw_time.isoformat()
        return datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()

def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Standardizes raw telemetry dictionaries into the uniform event schema."""
    event_id = int(raw.get("event_id", raw.get("EventID", 1)))
    event_type = SYSMON_EVENT_MAP.get(event_id, raw.get("event_type", "GenericEvent"))

    proc_name = normalize_process_name(
        raw.get("process_name") or raw.get("Image") or raw.get("OriginalFileName")
    )
    parent_name = normalize_process_name(
        raw.get("parent_process_name") or raw.get("ParentImage")
    )

    return {
        "timestamp": normalize_timestamp(raw.get("timestamp") or raw.get("UtcTime") or raw.get("TimeCreated")),
        "event_id": event_id,
        "event_type": event_type,
        "process_name": proc_name,
        "pid": int(raw.get("pid") or raw.get("ProcessId") or 0),
        "parent_pid": int(raw.get("parent_pid") or raw.get("ParentProcessId") or 0),
        "parent_process_name": parent_name,
        "command_line": str(raw.get("command_line") or raw.get("CommandLine") or "").strip(),
        "user": str(raw.get("user") or raw.get("User") or "DESKTOP\\User").strip(),
        "dest_ip": str(raw.get("dest_ip") or raw.get("DestinationIp") or "").strip(),
        "dest_port": int(raw.get("dest_port") or raw.get("DestinationPort") or 0),
        "file_path": str(raw.get("file_path") or raw.get("TargetFilename") or "").strip(),
        "registry_path": str(raw.get("registry_path") or raw.get("TargetObject") or "").strip()
    }

# --- SQLite Database Operations ---
def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Returns an active SQLite connection configured with Row factory."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Path = DB_PATH):
    """Initializes tables for clean endpoint telemetry, alerts, and incidents."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        process_name TEXT,
        pid INTEGER,
        parent_pid INTEGER,
        parent_process_name TEXT,
        command_line TEXT,
        user TEXT,
        dest_ip TEXT,
        dest_port INTEGER,
        file_path TEXT,
        registry_path TEXT,
        raw_json TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS processes (
        pid INTEGER,
        parent_pid INTEGER,
        process_name TEXT NOT NULL,
        command_line TEXT,
        user TEXT,
        start_time TEXT,
        end_time TEXT,
        PRIMARY KEY (pid, process_name, start_time)
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        pid INTEGER,
        process_name TEXT,
        dest_ip TEXT,
        dest_port INTEGER,
        protocol TEXT DEFAULT 'TCP'
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS features (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        window_start TEXT NOT NULL,
        window_end TEXT NOT NULL,
        process_count INTEGER,
        child_count INTEGER,
        process_lifetime REAL,
        parent_rarity REAL,
        chain_depth INTEGER,
        network_count INTEGER,
        unique_ips INTEGER,
        unique_ports INTEGER,
        connection_burst_rate REAL,
        file_count INTEGER,
        registry_count INTEGER,
        rarity_score REAL,
        feature_vector_json TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        process_name TEXT,
        pid INTEGER,
        parent_pid INTEGER,
        risk_score REAL NOT NULL,
        risk_tier TEXT NOT NULL,
        ml_score REAL NOT NULL,
        rule_score REAL NOT NULL,
        graph_score REAL NOT NULL,
        sequence_score REAL NOT NULL,
        mitre_technique_id TEXT,
        reasons TEXT,
        evidence_json TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        alert_id TEXT,
        timestamp TEXT NOT NULL,
        process_name TEXT,
        pid INTEGER,
        severity TEXT NOT NULL,
        recommended_actions TEXT,
        response_simulation_log TEXT,
        status TEXT DEFAULT 'Open',
        FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS drift_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evaluation_time TEXT NOT NULL,
        ks_statistic REAL,
        p_value REAL,
        is_drift_detected INTEGER,
        baseline_version TEXT,
        notes TEXT
    );
    """)

    conn.commit()
    conn.close()

def insert_event(event: Dict[str, Any], db_path: Path = DB_PATH) -> int:
    """Inserts an event record into SQLite."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO events (
        timestamp, event_id, event_type, process_name, pid, parent_pid,
        parent_process_name, command_line, user, dest_ip, dest_port,
        file_path, registry_path, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp"),
        event.get("event_id"),
        event.get("event_type", "Unknown"),
        event.get("process_name"),
        event.get("pid"),
        event.get("parent_pid"),
        event.get("parent_process_name"),
        event.get("command_line"),
        event.get("user"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("file_path"),
        event.get("registry_path"),
        json.dumps(event)
    ))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def insert_alert(alert: Dict[str, Any], db_path: Path = DB_PATH):
    """Inserts or replaces an alert record."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO alerts (
        alert_id, timestamp, process_name, pid, parent_pid,
        risk_score, risk_tier, ml_score, rule_score, graph_score,
        sequence_score, mitre_technique_id, reasons, evidence_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("alert_id"),
        alert.get("timestamp"),
        alert.get("process_name"),
        alert.get("pid"),
        alert.get("parent_pid"),
        alert.get("risk_score"),
        alert.get("risk_tier"),
        alert.get("ml_score"),
        alert.get("rule_score"),
        alert.get("graph_score"),
        alert.get("sequence_score"),
        alert.get("mitre_technique_id"),
        alert.get("reasons"),
        json.dumps(alert.get("evidence", {}))
    ))
    conn.commit()
    conn.close()

def insert_incident(incident: Dict[str, Any], db_path: Path = DB_PATH):
    """Inserts or replaces an incident investigation record."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO incidents (
        incident_id, alert_id, timestamp, process_name, pid,
        severity, recommended_actions, response_simulation_log, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident.get("incident_id"),
        incident.get("alert_id"),
        incident.get("timestamp"),
        incident.get("process_name"),
        incident.get("pid"),
        incident.get("severity", "Critical"),
        incident.get("recommended_actions"),
        incident.get("response_simulation_log"),
        incident.get("status", "Open")
    ))
    conn.commit()
    conn.close()

def fetch_all_alerts(db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Fetches all stored alerts sorted by timestamp descending."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def fetch_all_events(limit: int = 500, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Fetches most recent events from SQLite."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def clear_database(db_path: Path = DB_PATH):
    """Clears all records for clean, reproducible test runs."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    for table in ["events", "processes", "network_activity", "features", "alerts", "incidents", "drift_metrics"]:
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
