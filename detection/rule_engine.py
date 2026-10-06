"""
Deterministic Heuristic Rule Engine
Evaluates behavioral events against high-confidence security detection rules.
Stage 8 requirement.
"""
from typing import List, Dict, Any, Tuple

RULES = [
    {
        "id": "RULE_01",
        "name": "Office Spawning Script Host",
        "technique_id": "T1204.002",
        "score": 90,
        "check": lambda ev: (
            ev.get("event_type") == "ProcessCreate" and
            (ev.get("parent_process_name") or "").lower() in ["winword.exe", "excel.exe", "powerpnt.exe"] and
            (ev.get("process_name") or "").lower() in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]
        ),
        "description": "Microsoft Office application spawned a scripting interpreter or command shell."
    },
    {
        "id": "RULE_02",
        "name": "Obfuscated / Encoded PowerShell",
        "technique_id": "T1059.001",
        "score": 85,
        "check": lambda ev: (
            ev.get("event_type") == "ProcessCreate" and
            "powershell" in (ev.get("process_name") or "").lower() and
            any(flag in (ev.get("command_line") or "").lower() for flag in ["-enc", "-encodedcommand", "-w hidden", "bypass"])
        ),
        "description": "PowerShell executed with hidden execution or encoded base64 parameters."
    },
    {
        "id": "RULE_03",
        "name": "System Discovery Profiling",
        "technique_id": "T1082",
        "score": 75,
        "check": lambda ev: (
            ev.get("event_type") == "ProcessCreate" and
            (ev.get("process_name") or "").lower() in ["whoami.exe", "ipconfig.exe", "netstat.exe", "systeminfo.exe"]
        ),
        "description": "Reconnaissance discovery command executed to profile system or network."
    },
    {
        "id": "RULE_04",
        "name": "Shadow Copy Deletion / Ransomware Indicator",
        "technique_id": "T1490",
        "score": 95,
        "check": lambda ev: (
            ev.get("event_type") == "ProcessCreate" and
            "vssadmin" in (ev.get("process_name") or "").lower() and
            "delete" in (ev.get("command_line") or "").lower()
        ),
        "description": "Volume shadow copies deletion detected (Ransomware defense evasion tactic)."
    },
    {
        "id": "RULE_05",
        "name": "Suspicious Autostart Registry Modification",
        "technique_id": "T1547.001",
        "score": 80,
        "check": lambda ev: (
            ev.get("event_type") in ["RegistryCreate", "RegistryValueSet"] and
            "\\run" in (ev.get("registry_path") or "").lower()
        ),
        "description": "Persistence established via modification of Windows autostart Registry Run key."
    },
    {
        "id": "RULE_06",
        "name": "Script Interpreter Outbound Connection",
        "technique_id": "T1071.001",
        "score": 85,
        "check": lambda ev: (
            ev.get("event_type") == "NetworkConnect" and
            (ev.get("process_name") or "").lower() in ["powershell.exe", "cmd.exe", "cscript.exe"] and
            ev.get("dest_port") not in [80, 443]  # Non-standard outbound port
        ),
        "description": "Script interpreter established outbound socket on non-standard port."
    }
]

def evaluate_rules(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates events against deterministic rules.
    Returns composite rule score (0-100), list of triggered rules, and MITRE techniques.
    """
    triggered_rules = []
    technique_ids = set()
    max_score = 0.0

    for ev in events:
        for r in RULES:
            try:
                if r["check"](ev):
                    rule_entry = {
                        "rule_id": r["id"],
                        "name": r["name"],
                        "score": r["score"],
                        "description": r["description"],
                        "technique_id": r["technique_id"],
                        "process_name": ev.get("process_name"),
                        "pid": ev.get("pid")
                    }
                    if rule_entry not in triggered_rules:
                        triggered_rules.append(rule_entry)
                        technique_ids.add(r["technique_id"])
                        max_score = max(max_score, r["score"])
            except Exception:
                continue

    # Boost score if multiple rules triggered
    if len(triggered_rules) > 1:
        composite_score = min(100.0, max_score + (len(triggered_rules) - 1) * 5.0)
    else:
        composite_score = max_score

    return {
        "rule_score": round(composite_score, 1),
        "triggered_rules": triggered_rules,
        "technique_ids": list(technique_ids)
    }
