"""
Live Windows Host Process Collector
Captures real-time running processes and parent-child hierarchies from the actual host machine using psutil.
Provides live testing on the user's laptop.
"""
from datetime import datetime
from typing import List, Dict, Any
import psutil
from processing.normalizer import normalize_process_name

def capture_live_host_processes(max_processes: int = 80) -> List[Dict[str, Any]]:
    """
    Captures live running processes directly from the local Windows machine.
    Reconstructs PID, PPID, process name, command line, and active user.
    """
    events = []
    ts = datetime.utcnow().isoformat()

    # Pre-cache process names by PID for parent lookup
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

            # Check network connections if accessible
            dest_ip = ""
            dest_port = 0
            try:
                conns = proc.net_connections(kind='inet')
                if conns:
                    remote = conns[0].raddr
                    if remote:
                        dest_ip = remote.ip
                        dest_port = remote.port
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
                "command_line": cmdline[:250],  # trim if long
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
