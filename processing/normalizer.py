"""
Telemetry Event Normalizer
Cleans raw events, standardizes timestamps, normalizes executable paths,
and maps Sysmon Event IDs into a consistent schema.
Stage 2 & 3 requirement.
"""
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

SYSMON_EVENT_MAP = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    11: "FileCreate",
    12: "RegistryCreate",
    13: "RegistryValueSet"
}

def normalize_process_name(raw_path: Optional[str]) -> str:
    """
    Extracts the lowercase executable name from a full path.
    Example: 'C:\\Windows\\System32\\cmd.exe' -> 'cmd.exe'
    """
    if not raw_path or raw_path.strip() == "":
        return "unknown.exe"
    clean = raw_path.strip().replace("/", "\\")
    return Path(clean).name.lower()

def normalize_timestamp(raw_time: Optional[str]) -> str:
    """Ensures timestamp is formatted as an ISO-8601 string."""
    if not raw_time:
        return datetime.utcnow().isoformat()
    try:
        # If it's already an ISO string or standard datetime
        if isinstance(raw_time, datetime):
            return raw_time.isoformat()
        return datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()

def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms any raw telemetry dictionary into the project's standard event schema.
    Explicitly handles missing fields without discarding useful data.
    """
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
