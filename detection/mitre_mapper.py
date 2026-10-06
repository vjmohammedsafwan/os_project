"""
MITRE ATT&CK Mapper
Attaches standardized technique IDs, names, tactics, and URLs to alerts.
Stage 10 requirement.
"""
from typing import List, Dict, Any, Optional
from config.mitre_catalog import lookup_technique, MITRE_TECHNIQUES

def map_event_to_techniques(event: Dict[str, Any]) -> List[str]:
    """Determines applicable MITRE techniques for an individual event."""
    techniques = []
    p_name = (event.get("process_name") or "").lower()
    parent_name = (event.get("parent_process_name") or "").lower()
    cmd = (event.get("command_line") or "").lower()
    r_path = (event.get("registry_path") or "").lower()

    if "powershell" in p_name:
        techniques.append("T1059.001")
    elif "cmd.exe" in p_name:
        techniques.append("T1059.003")
    
    if p_name in ["whoami.exe", "systeminfo.exe"]:
        techniques.append("T1082")
    if p_name in ["ipconfig.exe", "netstat.exe"]:
        techniques.append("T1016")

    if parent_name in ["winword.exe", "excel.exe"] and p_name in ["powershell.exe", "cmd.exe"]:
        techniques.append("T1204.002")

    if "\\run" in r_path:
        techniques.append("T1547.001")

    if "vssadmin" in p_name and "delete" in cmd:
        techniques.append("T1490")

    return techniques

def enrich_alert_with_mitre(technique_ids: List[str]) -> List[Dict[str, Any]]:
    """Enriches a list of technique IDs with complete metadata from the MITRE catalog."""
    enriched = []
    for tid in sorted(list(set(technique_ids))):
        enriched.append(lookup_technique(tid))
    return enriched
