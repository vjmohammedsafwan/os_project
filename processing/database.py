"""
Database Management Module
Handles SQLite schema creation and structured queries for telemetry, features, alerts, and incidents.
Stage 3 requirement.
"""
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from config.settings import DB_PATH

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Returns a configured SQLite connection with row factory enabled."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Path = DB_PATH):
    """Initializes tables for clean endpoint telemetry and threat detection."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 1. Raw / Cleaned Endpoint Events
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

    # 2. Process Lineage Index
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

    # 3. Network Activity Table
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

    # 4. Behavioral Feature Vectors
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

    # 5. Alerts Table
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

    # 6. Incidents & Containment Simulation Table
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

    # 7. Concept Drift Metrics Table
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
    """Inserts a normalized telemetry event."""
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
    """Inserts or replaces a generated threat alert."""
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
    """Records an incident generated from a critical alert."""
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
    """Retrieves all alerts sorted by timestamp descending."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def fetch_all_events(limit: int = 500, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves latest events."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def clear_database(db_path: Path = DB_PATH):
    """Empties all tables for clean test runs."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    for table in ["events", "processes", "network_activity", "features", "alerts", "incidents", "drift_metrics"]:
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
