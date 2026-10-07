"""
Endpoint Telemetry Collector & Workload Simulator
Captures live Windows process hierarchies (psutil), queries Sysmon Event Logs,
and generates realistic normal/attack/drift workloads.
Minimal, robust, self-contained.
"""
from datetime import datetime, timedelta
import random
import subprocess
import json
from typing import List, Dict, Any
import psutil

from database import normalize_process_name, normalize_event

# ==========================================
# 1. LIVE HOST COLLECTORS (WINDOWS)
# ==========================================

def capture_live_host_processes(max_processes: int = 80) -> List[Dict[str, Any]]:
    """
    Captures live running processes directly from the local Windows machine.
    Reconstructs PID, PPID, process name, command line, and network sockets using psutil.
    """
    events = []
    ts = datetime.utcnow().isoformat()

    proc_cache = {}
    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            proc_cache[proc.info['pid']] = proc.info.get('name', '')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    count = 0
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'username']):
        if count >= max_processes:
            break
        try:
            info = proc.info
            pid = info.get('pid')
            ppid = info.get('ppid')
            p_name = normalize_process_name(info.get('name'))
            parent_name = normalize_process_name(proc_cache.get(ppid, 'explorer.exe'))

            cmdline_list = info.get('cmdline') or []
            cmdline = " ".join(cmdline_list) if cmdline_list else p_name
            user = info.get('username') or "NT AUTHORITY\\SYSTEM"

            dest_ip = ""
            dest_port = 0
            try:
                conns = proc.net_connections(kind='inet')
                if conns and conns[0].raddr:
                    dest_ip = conns[0].raddr.ip
                    dest_port = conns[0].raddr.port
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            events.append({
                "timestamp": ts,
                "event_id": 1,
                "event_type": "ProcessCreate",
                "process_name": p_name,
                "pid": pid,
                "parent_pid": ppid,
                "parent_process_name": parent_name,
                "command_line": cmdline[:250],
                "user": user,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "file_path": "",
                "registry_path": ""
            })
            count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return events


def is_sysmon_active() -> bool:
    """Checks if Microsoft-Windows-Sysmon service is installed and running."""
    try:
        cmd = "powershell -NoProfile -Command \"Get-Service -Name '*sysmon*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status\""
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "running" in res.stdout.strip().lower()
    except Exception:
        return False


def collect_live_sysmon_events(max_events: int = 50) -> List[Dict[str, Any]]:
    """
    Collects the most recent Sysmon events from Windows Event Log via PowerShell.
    Gracefully returns an empty list if Sysmon is not installed.
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


# ==========================================
# 2. LAB WORKLOAD SIMULATORS
# ==========================================

def generate_normal_baseline_events(count: int = 150, base_time: datetime = None) -> List[Dict[str, Any]]:
    """
    Simulates routine daily endpoint activity:
    - Chrome web browsing (browsing, HTTPS socket connections to port 443)
    - VS Code / Python developer activity
    - File Explorer navigation and Notepad text editing
    """
    if base_time is None:
        base_time = datetime.utcnow() - timedelta(minutes=count // 2)

    events = []
    normal_apps = [
        {"parent": "explorer.exe", "child": "chrome.exe", "user": "CORP\\analyst"},
        {"parent": "chrome.exe", "child": "chrome.exe", "user": "CORP\\analyst"},
        {"parent": "explorer.exe", "child": "code.exe", "user": "CORP\\analyst"},
        {"parent": "code.exe", "child": "python.exe", "user": "CORP\\analyst"},
        {"parent": "explorer.exe", "child": "notepad.exe", "user": "CORP\\analyst"},
        {"parent": "services.exe", "child": "svchost.exe", "user": "NT AUTHORITY\\SYSTEM"}
    ]

    legit_ips = ["142.250.190.46", "172.217.16.206", "13.107.42.14", "151.101.1.69"]

    for i in range(count):
        cur_time = base_time + timedelta(seconds=i * 4)
        app = random.choice(normal_apps)
        pid = random.randint(1000, 9999)
        ppid = random.randint(500, 999)

        action_type = random.random()
        if action_type < 0.60:
            events.append({
                "timestamp": cur_time.isoformat(),
                "event_id": 1,
                "event_type": "ProcessCreate",
                "process_name": app["child"],
                "pid": pid,
                "parent_pid": ppid,
                "parent_process_name": app["parent"],
                "command_line": f"{app['child']} --normal-flag",
                "user": app["user"],
                "dest_ip": "",
                "dest_port": 0,
                "file_path": "",
                "registry_path": ""
            })
        elif action_type < 0.85:
            events.append({
                "timestamp": cur_time.isoformat(),
                "event_id": 3,
                "event_type": "NetworkConnect",
                "process_name": app["child"],
                "pid": pid,
                "parent_pid": ppid,
                "parent_process_name": app["parent"],
                "command_line": "",
                "user": app["user"],
                "dest_ip": random.choice(legit_ips),
                "dest_port": 443,
                "file_path": "",
                "registry_path": ""
            })
        else:
            events.append({
                "timestamp": cur_time.isoformat(),
                "event_id": 11,
                "event_type": "FileCreate",
                "process_name": app["child"],
                "pid": pid,
                "parent_pid": ppid,
                "parent_process_name": app["parent"],
                "command_line": "",
                "user": app["user"],
                "dest_ip": "",
                "dest_port": 0,
                "file_path": f"C:\\Users\\analyst\\AppData\\Local\\Temp\\cache_{i}.tmp",
                "registry_path": ""
            })

    return events


def generate_macro_attack_scenario(base_time: datetime = None) -> List[Dict[str, Any]]:
    """
    Simulates a realistic multi-stage kill-chain:
    1. User opens weaponized Word document (winword.exe).
    2. Word spawns powershell.exe with hidden encoded flags.
    3. Host discovery (whoami.exe, ipconfig.exe).
    4. Outbound C2 socket connection to unknown remote IP on port 4444.
    5. Ingress tool transfer (dropping beacon.exe in AppData).
    6. Persistence via Registry Run key modification.
    """
    if base_time is None:
        base_time = datetime.utcnow()

    word_pid = 4120
    ps_pid = 5824
    disc_pid = 6112

    scenario = [
        # 1. Office execution
        {
            "timestamp": (base_time + timedelta(seconds=2)).isoformat(),
            "event_id": 1,
            "event_type": "ProcessCreate",
            "process_name": "winword.exe",
            "pid": word_pid,
            "parent_pid": 1040,
            "parent_process_name": "explorer.exe",
            "command_line": "winword.exe /n C:\\Users\\analyst\\Downloads\\Invoice_Q3.docm",
            "user": "CORP\\analyst"
        },
        # 2. Suspicious child process spawned (Word -> PowerShell)
        {
            "timestamp": (base_time + timedelta(seconds=6)).isoformat(),
            "event_id": 1,
            "event_type": "ProcessCreate",
            "process_name": "powershell.exe",
            "pid": ps_pid,
            "parent_pid": word_pid,
            "parent_process_name": "winword.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgA...",
            "user": "CORP\\analyst"
        },
        # 3. Discovery: whoami
        {
            "timestamp": (base_time + timedelta(seconds=10)).isoformat(),
            "event_id": 1,
            "event_type": "ProcessCreate",
            "process_name": "whoami.exe",
            "pid": disc_pid,
            "parent_pid": ps_pid,
            "parent_process_name": "powershell.exe",
            "command_line": "whoami /all",
            "user": "CORP\\analyst"
        },
        # 4. Discovery: ipconfig
        {
            "timestamp": (base_time + timedelta(seconds=13)).isoformat(),
            "event_id": 1,
            "event_type": "ProcessCreate",
            "process_name": "ipconfig.exe",
            "pid": disc_pid + 4,
            "parent_pid": ps_pid,
            "parent_process_name": "powershell.exe",
            "command_line": "ipconfig /all",
            "user": "CORP\\analyst"
        },
        # 5. C2 Outbound connection
        {
            "timestamp": (base_time + timedelta(seconds=18)).isoformat(),
            "event_id": 3,
            "event_type": "NetworkConnect",
            "process_name": "powershell.exe",
            "pid": ps_pid,
            "parent_pid": word_pid,
            "parent_process_name": "winword.exe",
            "dest_ip": "185.220.101.5",
            "dest_port": 4444,
            "user": "CORP\\analyst"
        },
        # 6. Tool transfer / executable drop
        {
            "timestamp": (base_time + timedelta(seconds=24)).isoformat(),
            "event_id": 11,
            "event_type": "FileCreate",
            "process_name": "powershell.exe",
            "pid": ps_pid,
            "parent_pid": word_pid,
            "file_path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\updater_beacon.exe",
            "user": "CORP\\analyst"
        },
        # 7. Persistence via Registry Run Key
        {
            "timestamp": (base_time + timedelta(seconds=30)).isoformat(),
            "event_id": 13,
            "event_type": "RegistryValueSet",
            "process_name": "powershell.exe",
            "pid": ps_pid,
            "parent_pid": word_pid,
            "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper",
            "user": "CORP\\analyst"
        }
    ]
    return scenario


def generate_drift_workload(count: int = 80, base_time: datetime = None) -> List[Dict[str, Any]]:
    """
    Simulates a benign developer workload (Concept Drift):
    Heavy compilation, git, and npm operations. Higher frequency, but legitimate lineage.
    """
    if base_time is None:
        base_time = datetime.utcnow()

    events = []
    for i in range(count):
        cur_time = base_time + timedelta(seconds=i * 2)
        events.append({
            "timestamp": cur_time.isoformat(),
            "event_id": 1 if i % 2 == 0 else 11,
            "event_type": "ProcessCreate" if i % 2 == 0 else "FileCreate",
            "process_name": "node.exe" if i % 3 == 0 else "git.exe",
            "pid": 8000 + i,
            "parent_pid": 7500,
            "parent_process_name": "cmd.exe",
            "command_line": f"npm install package_{i}",
            "user": "CORP\\analyst",
            "file_path": f"C:\\Users\\analyst\\dev\\node_modules\\.cache_{i}.dat",
            "dest_ip": "104.16.25.34" if i % 5 == 0 else "",
            "dest_port": 443 if i % 5 == 0 else 0
        })
    return events
