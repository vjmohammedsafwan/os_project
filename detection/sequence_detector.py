"""
Multi-Stage Attack & Sequence Detector
Identifies ordered kill-chain attack sequences spanning multiple steps over time.
Stage 9 requirement.
"""
from datetime import datetime
from typing import List, Dict, Any

class SequenceDetector:
    def __init__(self, max_sequence_window_sec: int = 180):
        self.max_sequence_window_sec = max_sequence_window_sec

    def evaluate_sequence(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detects the classic 4-stage kill chain:
        Stage A: Initial Access / Office Spawn (winword/excel spawning powershell/cmd)
        Stage B: Host Discovery (whoami, ipconfig)
        Stage C: Command & Control (outbound network connection from shell or anomalous port)
        Stage D: Payload Dropped or Persistence (file drop in Temp / AppData, or Registry write)
        """
        if not events:
            return {"sequence_score": 0.0, "matched_stages": [], "is_killchain": False}

        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))

        matched_stages = []
        shell_pids = set()

        for ev in sorted_events:
            p_name = (ev.get("process_name") or "").lower()
            parent_name = (ev.get("parent_process_name") or "").lower()
            pid = ev.get("pid")
            parent_pid = ev.get("parent_pid")
            ev_type = ev.get("event_type")

            # Check Stage A: Office -> Shell
            if "A" not in [s["stage"] for s in matched_stages]:
                if parent_name in ["winword.exe", "excel.exe"] and p_name in ["powershell.exe", "cmd.exe"]:
                    matched_stages.append({
                        "stage": "A",
                        "name": "Initial Execution via Office Macro",
                        "timestamp": ev.get("timestamp"),
                        "details": f"{parent_name} spawned {p_name} (PID: {pid})"
                    })
                    if pid:
                        shell_pids.add(pid)
                    continue

            # Check Stage B: Discovery
            if "B" not in [s["stage"] for s in matched_stages]:
                if p_name in ["whoami.exe", "ipconfig.exe", "netstat.exe"] or parent_pid in shell_pids:
                    matched_stages.append({
                        "stage": "B",
                        "name": "Host & Network Discovery",
                        "timestamp": ev.get("timestamp"),
                        "details": f"Discovery utility {p_name} executed"
                    })
                    continue

            # Check Stage C: Network C2
            if "C" not in [s["stage"] for s in matched_stages]:
                if ev_type == "NetworkConnect" and (pid in shell_pids or p_name in ["powershell.exe", "cmd.exe"]):
                    matched_stages.append({
                        "stage": "C",
                        "name": "Command & Control Egress",
                        "timestamp": ev.get("timestamp"),
                        "details": f"{p_name} connected to remote socket {ev.get('dest_ip')}:{ev.get('dest_port')}"
                    })
                    continue

            # Check Stage D: Payload Drop or Persistence
            if "D" not in [s["stage"] for s in matched_stages]:
                if ev_type in ["FileCreate", "RegistryValueSet"]:
                    fpath = (ev.get("file_path") or "").lower()
                    rpath = (ev.get("registry_path") or "").lower()
                    if "temp" in fpath or ".exe" in fpath or "\\run" in rpath:
                        matched_stages.append({
                            "stage": "D",
                            "name": "Ingress Tool Transfer / Persistence",
                            "timestamp": ev.get("timestamp"),
                            "details": f"Artifact written: {fpath or rpath}"
                        })

        count = len(matched_stages)
        if count == 0:
            score = 0.0
        elif count == 1:
            score = 25.0
        elif count == 2:
            score = 55.0
        elif count == 3:
            score = 80.0
        else:
            score = 95.0

        return {
            "sequence_score": score,
            "matched_stages": matched_stages,
            "stage_count": count,
            "is_killchain": count >= 3
        }
