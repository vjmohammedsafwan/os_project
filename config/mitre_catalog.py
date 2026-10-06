"""
MITRE ATT&CK Catalog Mapping Table
Provides standardized cybersecurity context for suspicious behaviors.
Stage 10 requirement.
"""

MITRE_TECHNIQUES = {
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution and automation.",
        "url": "https://attack.mitre.org/techniques/T1059/001/"
    },
    "T1059.003": {
        "id": "T1059.003",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse cmd.exe to execute commands, batch scripts, and automate actions.",
        "url": "https://attack.mitre.org/techniques/T1059/003/"
    },
    "T1082": {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "url": "https://attack.mitre.org/techniques/T1082/"
    },
    "T1016": {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for details about the network configuration and settings (ipconfig, netstat).",
        "url": "https://attack.mitre.org/techniques/T1016/"
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or files from an external system onto the compromised endpoint.",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Boot or Logon Autostart: Registry Run Keys",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by modifying Windows registry Run or RunOnce keys.",
        "url": "https://attack.mitre.org/techniques/T1547/001/"
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "An adversary may rely on a user opening a weaponized document or macro.",
        "url": "https://attack.mitre.org/techniques/T1204/002/"
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may abuse the Windows Task Scheduler (schtasks.exe) to execute malicious binaries.",
        "url": "https://attack.mitre.org/techniques/T1053/005/"
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or disable volume shadow copies (vssadmin) to prevent data restoration.",
        "url": "https://attack.mitre.org/techniques/T1490/"
    }
}

def lookup_technique(technique_id: str) -> dict:
    """Return dictionary of technique information or default unknown dict."""
    return MITRE_TECHNIQUES.get(technique_id, {
        "id": technique_id,
        "name": "Uncategorized Technique",
        "tactic": "Unknown",
        "description": "Suspicious endpoint activity observed.",
        "url": "https://attack.mitre.org/"
    })
