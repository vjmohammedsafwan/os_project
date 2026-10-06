"""
Live Windows Sysmon Telemetry Collector
Reads events directly from the Microsoft-Windows-Sysmon/Operational log channel
using pywin32 with a graceful fallback.
Stage 1 & 2 requirement.
"""
import subprocess
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from processing.normalizer import normalize_event

def is_sysmon_active() -> bool:
    """Checks if the Microsoft-Windows-Sysmon service is installed and operational."""
    try:
        cmd = "powershell -NoProfile -Command \"Get-Service -Name '*sysmon*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\""
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "running" in res.stdout.strip().lower()
    except Exception:
        return False

def collect_live_sysmon_events(max_events: int = 50) -> List[Dict[str, Any]]:
    """
    Collects the most recent Sysmon events from Windows Event Log.
    Uses PowerShell Get-WinEvent for reliable XML extraction across all Windows versions.
    """
    if not is_sysmon_active():
        return []

    ps_script = f"""
    $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents {max_events} -ErrorAction SilentlyContinue
    if ($events) {{
        $events | ForEach-Object {{
            $xml = [xml]$_.ToXml()
            $eventData = @{{}}
            $eventData['EventID'] = $_.Id
            $eventData['TimeCreated'] = $_.TimeCreated.ToString('o')
            $xml.Event.EventData.Data | ForEach-Object {{
                $eventData[$_.Name] = $_.'#text'
            }}
            [PSCustomObject]$eventData | ConvertTo-Json -Compress
        }}
    }}
    """
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []

        raw_events = []
        for line in proc.stdout.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    raw_events.append(normalize_event(data))
                except Exception:
                    continue
        return raw_events
    except Exception:
        return []
