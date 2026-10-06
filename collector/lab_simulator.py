"""
Controlled Lab Telemetry Simulator & Replay Engine
Generates realistic normal baseline activity and controlled multi-stage attack scenarios.
Stages 2, 5, 9, and 15 requirement.
"""
from datetime import datetime, timedelta
import random
from typing import List, Dict, Any

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

        # 60% Process creations, 25% Network traffic, 15% File writes
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
    Stage 1: User opens weaponized Word document (winword.exe).
    Stage 2: Word document spawns powershell.exe with hidden encoded flags.
    Stage 3: Discovery commands (whoami.exe, ipconfig.exe).
    Stage 4: Outbound C2 socket connection to unknown foreign IP on port 4444.
    Stage 5: Ingress tool transfer (dropping beacon.exe in AppData).
    Stage 6: Persistence via Registry Run key modification.
    """
    if base_time is None:
        base_time = datetime.utcnow()

    word_pid = 4120
    ps_pid = 5824
    disc_pid = 6112
    beacon_pid = 7240

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
    Simulates a benign change in workload (Concept Drift):
    A developer initiates intensive local compilation and npm package installations.
    Higher process count and file burst rate, but completely normal parentage.
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
