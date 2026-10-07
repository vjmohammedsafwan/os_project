"""
4-Signal Behavioral Threat Detection & AI Fusion Engine
Integrates:
- Behavioral Feature Engineering (Sliding 60s windows)
- Signal 1: Isolation Forest ML Anomaly Engine & Concept Drift Detector
- Signal 2: Directed Process Behavior Graph (NetworkX)
- Signal 3: Heuristic Rule Engine (High-confidence OS signatures)
- Signal 4: Multi-Stage Attack Sequence Detector (Kill-chain correlation)
- Hybrid Risk Fusion Engine: Final = (0.25*ML) + (0.30*Rule) + (0.20*Graph) + (0.25*Sequence)
- Explainable AI (XAI z-score deviation contributions)
- MITRE ATT&CK Catalog & Enrichment
- Incident Response Simulator & ReportLab PDF Generator
"""
import uuid
import shutil
import json
import csv
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
import networkx as nx
from scipy.stats import ks_2samp
from sklearn.ensemble import IsolationForest

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from database import DATA_DIR, BASELINES_DIR, EXPORTS_DIR, DB_PATH, get_risk_tier, get_connection

# =====================================================================
# 1. BEHAVIORAL FEATURE ENGINEERING
# =====================================================================

COMMON_PAIRS = {
    ("explorer.exe", "chrome.exe"): 0.05,
    ("chrome.exe", "chrome.exe"): 0.02,
    ("explorer.exe", "code.exe"): 0.05,
    ("code.exe", "python.exe"): 0.10,
    ("explorer.exe", "notepad.exe"): 0.05,
    ("services.exe", "svchost.exe"): 0.01,
    ("svchost.exe", "svchost.exe"): 0.02,
    ("explorer.exe", "cmd.exe"): 0.20,
    ("cmd.exe", "git.exe"): 0.15,
    ("cmd.exe", "node.exe"): 0.15,
}

FEATURE_COLUMNS = [
    "process_count",
    "child_count",
    "process_lifetime",
    "parent_rarity",
    "chain_depth",
    "network_count",
    "unique_ips",
    "unique_ports",
    "connection_burst_rate",
    "file_count",
    "registry_count",
    "rarity_score"
]

def calculate_parent_rarity(parent: str, child: str) -> float:
    """Returns rarity score between 0.0 (very common) and 1.0 (anomalous)."""
    parent = (parent or "").lower()
    child = (child or "").lower()
    if (parent, child) in COMMON_PAIRS:
        return COMMON_PAIRS[(parent, child)]
    if parent in ["winword.exe", "excel.exe", "powerpnt.exe"] and child in ["powershell.exe", "cmd.exe", "cscript.exe"]:
        return 0.98
    return 0.85

def extract_window_features(events: List[Dict[str, Any]], window_seconds: int = 60) -> List[Dict[str, Any]]:
    """Aggregates telemetry into sliding temporal windows and extracts numerical feature records."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
    df = pd.DataFrame(sorted_events)
    df["dt"] = pd.to_datetime(df["timestamp"])

    start_time = df["dt"].min()
    end_time = df["dt"].max()

    feature_records = []
    current_start = start_time

    while current_start <= end_time:
        current_end = current_start + pd.Timedelta(seconds=window_seconds)
        sub = df[(df["dt"] >= current_start) & (df["dt"] < current_end)]

        if not sub.empty:
            proc_creates = sub[sub["event_type"] == "ProcessCreate"]
            net_connects = sub[sub["event_type"] == "NetworkConnect"]
            file_creates = sub[sub["event_type"] == "FileCreate"]
            reg_ops = sub[sub["event_type"].isin(["RegistryCreate", "RegistryValueSet"])]

            process_count = len(proc_creates)
            child_count = proc_creates["parent_pid"].nunique() if not proc_creates.empty else 0
            time_delta = (sub["dt"].max() - sub["dt"].min()).total_seconds()
            process_lifetime = round(time_delta, 2)

            rarity_vals = [
                calculate_parent_rarity(r.get("parent_process_name"), r.get("process_name"))
                for _, r in proc_creates.iterrows()
            ]
            parent_rarity = float(np.mean(rarity_vals)) if rarity_vals else 0.05
            chain_depth = min(4, 1 + child_count)

            network_count = len(net_connects)
            unique_ips = net_connects["dest_ip"].nunique() if not net_connects.empty else 0
            unique_ports = net_connects["dest_port"].nunique() if not net_connects.empty else 0
            duration_minutes = max(1.0, window_seconds / 60.0)
            burst_rate = round(network_count / duration_minutes, 2)

            file_count = len(file_creates)
            registry_count = len(reg_ops)

            rarity_score = round(float(
                0.5 * parent_rarity +
                0.3 * (1.0 if unique_ports > 3 else 0.1) +
                0.2 * (1.0 if file_count > 10 else 0.1)
            ), 2)

            feature_records.append({
                "window_start": current_start.isoformat(),
                "window_end": current_end.isoformat(),
                "process_count": int(process_count),
                "child_count": int(child_count),
                "process_lifetime": float(process_lifetime),
                "parent_rarity": round(parent_rarity, 2),
                "chain_depth": int(chain_depth),
                "network_count": int(network_count),
                "unique_ips": int(unique_ips),
                "unique_ports": int(unique_ports),
                "connection_burst_rate": float(burst_rate),
                "file_count": int(file_count),
                "registry_count": int(registry_count),
                "rarity_score": float(rarity_score),
                "primary_process": sub["process_name"].mode()[0] if not sub["process_name"].empty else "unknown.exe",
                "events_count": len(sub)
            })

        current_start = current_end

    return feature_records

def to_feature_matrix(feature_records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Converts feature dictionaries into a consistent DataFrame."""
    if not feature_records:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    df = pd.DataFrame(feature_records)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df[FEATURE_COLUMNS]

# =====================================================================
# 2. SIGNAL 1: ISOLATION FOREST ML & CONCEPT DRIFT
# =====================================================================

MODEL_PATH = DATA_DIR / "isolation_forest.joblib"
DEFAULT_BASELINE_FILE = BASELINES_DIR / "baseline_v1.json"

def calculate_baseline_statistics(df_features: pd.DataFrame) -> Dict[str, Any]:
    """Computes descriptive statistics (mean, std, min, max, p5, p95) on normal telemetry."""
    stats = {}
    for col in FEATURE_COLUMNS:
        if col in df_features.columns:
            series = pd.to_numeric(df_features[col], errors='coerce').fillna(0)
            stats[col] = {
                "mean": round(float(series.mean()), 4),
                "std": round(float(series.std()), 4) if len(series) > 1 else 1.0,
                "min": round(float(series.min()), 4),
                "max": round(float(series.max()), 4),
                "p5": round(float(np.percentile(series, 5)), 4),
                "p95": round(float(np.percentile(series, 95)), 4)
            }
    return stats

def save_baseline(stats: Dict[str, Any], version: str = "v1.0", file_path: Path = DEFAULT_BASELINE_FILE) -> Path:
    """Saves baseline profile to disk."""
    payload = {
        "version": version,
        "created_at": datetime.utcnow().isoformat(),
        "feature_count": len(stats),
        "statistics": stats
    }
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return file_path

def load_baseline(file_path: Path = DEFAULT_BASELINE_FILE) -> Dict[str, Any]:
    """Loads baseline statistics from disk."""
    if not file_path.exists():
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

class IsolationForestEngine:
    def __init__(self, contamination: float = 0.08, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42
        )
        self.is_trained = False

    def train(self, df_features: pd.DataFrame) -> Path:
        """Fits Isolation Forest on baseline vectors and saves joblib artifact."""
        X = df_features[FEATURE_COLUMNS].fillna(0).values
        self.model.fit(X)
        self.is_trained = True
        joblib.dump(self.model, MODEL_PATH)
        return MODEL_PATH

    def load(self, model_path: Path = MODEL_PATH):
        """Loads pre-trained model."""
        if model_path.exists():
            self.model = joblib.load(model_path)
            self.is_trained = True

    def score_observation(self, feature_row: Dict[str, Any]) -> float:
        """Calculates calibrated 0-100 anomaly score (normal: 0-25; outlier: 70-100)."""
        if not self.is_trained:
            self.load()
            if not self.is_trained:
                rarity = feature_row.get("rarity_score", 0.1)
                return round(float(rarity * 100.0), 1)

        vec = np.array([[feature_row.get(col, 0) for col in FEATURE_COLUMNS]])
        raw_score = float(self.model.decision_function(vec)[0])
        normalized = (0.20 - raw_score) / 0.40 * 100.0
        calibrated = max(0.0, min(100.0, normalized))
        return round(calibrated, 1)

    def score_batch(self, df_features: pd.DataFrame) -> List[float]:
        """Scores multiple feature vectors."""
        return [self.score_observation(row.to_dict()) for _, row in df_features.iterrows()]

class ConceptDriftEngine:
    def __init__(self, p_threshold: float = 0.05):
        self.p_threshold = p_threshold

    def evaluate_drift(self, df_baseline: pd.DataFrame, df_recent: pd.DataFrame) -> Dict[str, Any]:
        """Performs two-sample Kolmogorov-Smirnov test to detect legitimate distribution drift."""
        if df_baseline.empty or df_recent.empty or len(df_recent) < 5:
            return {
                "is_drift_detected": False,
                "drift_score": 0.0,
                "drifting_features": [],
                "summary": "Insufficient recent samples to evaluate concept drift."
            }

        drift_results = {}
        drifting_cols = []

        for col in FEATURE_COLUMNS:
            if col in df_baseline.columns and col in df_recent.columns:
                s1 = pd.to_numeric(df_baseline[col], errors='coerce').fillna(0).values
                s2 = pd.to_numeric(df_recent[col], errors='coerce').fillna(0).values

                if np.all(s1 == s1[0]) and np.all(s2 == s1[0]):
                    stat, p_val = 0.0, 1.0
                else:
                    stat, p_val = ks_2samp(s1, s2)

                drift_results[col] = {
                    "ks_statistic": round(float(stat), 4),
                    "p_value": round(float(p_val), 4),
                    "drifting": bool(p_val < self.p_threshold)
                }
                if p_val < self.p_threshold:
                    drifting_cols.append(col)

        drift_ratio = len(drifting_cols) / len(FEATURE_COLUMNS)
        is_drift = drift_ratio >= 0.25

        return {
            "is_drift_detected": is_drift,
            "drift_score": round(drift_ratio * 100.0, 1),
            "drifting_features": drifting_cols,
            "feature_details": drift_results,
            "summary": (
                f"Significant concept drift detected in {len(drifting_cols)} features ({', '.join(drifting_cols[:3])}). Workload pattern shifted."
                if is_drift else "Telemetry distributions conform stably to current baseline."
            )
        }

    def adapt_baseline(self, df_new_normal: pd.DataFrame, new_version: str = "v2.0") -> Path:
        """Adapts baseline to new workload and saves backup."""
        current_file = BASELINES_DIR / "baseline_v1.json"
        backup_file = BASELINES_DIR / "baseline_backup.json"
        if current_file.exists():
            shutil.copyfile(current_file, backup_file)

        new_stats = calculate_baseline_statistics(df_new_normal)
        new_file = BASELINES_DIR / f"baseline_{new_version}.json"
        save_baseline(new_stats, version=new_version, file_path=new_file)
        save_baseline(new_stats, version=new_version, file_path=current_file)
        return new_file

    def rollback_baseline(self) -> bool:
        """Restores previous baseline from backup."""
        current_file = BASELINES_DIR / "baseline_v1.json"
        backup_file = BASELINES_DIR / "baseline_backup.json"
        if backup_file.exists():
            shutil.copyfile(backup_file, current_file)
            return True
        return False

# =====================================================================
# 3. SIGNAL 2: PROCESS BEHAVIOR GRAPH (NETWORKX)
# =====================================================================

SUSPICIOUS_EDGES = [
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("powerpnt.exe", "powershell.exe"),
    ("powershell.exe", "whoami.exe"),
    ("cmd.exe", "whoami.exe"),
    ("cmd.exe", "vssadmin.exe"),
    ("powershell.exe", "vssadmin.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("certutil.exe", "powershell.exe")
]

class ProcessGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph_from_events(self, events: List[Dict[str, Any]]) -> nx.DiGraph:
        """Builds directed graph (PPID -> PID) from ProcessCreate events."""
        self.graph.clear()
        for ev in events:
            if ev.get("event_type") == "ProcessCreate":
                pid = ev.get("pid")
                ppid = ev.get("parent_pid")
                proc_name = (ev.get("process_name") or "unknown.exe").lower()
                parent_name = (ev.get("parent_process_name") or "unknown.exe").lower()
                cmd = ev.get("command_line", "")
                user = ev.get("user", "")
                ts = ev.get("timestamp", "")

                if pid:
                    self.graph.add_node(pid, name=proc_name, cmd=cmd, user=user, timestamp=ts, is_root=False)
                if ppid:
                    if ppid not in self.graph:
                        self.graph.add_node(ppid, name=parent_name, cmd="", user=user, timestamp=ts, is_root=True)
                    self.graph.add_edge(ppid, pid, parent_name=parent_name, child_name=proc_name)

        return self.graph

    def analyze_graph(self) -> Dict[str, Any]:
        """Calculates topological graph metrics and identifies anomalous edges."""
        if self.graph.number_of_nodes() == 0:
            return {
                "node_count": 0, "edge_count": 0, "max_depth": 0,
                "max_fan_out": 0, "anomalous_edges": [], "graph_score": 0.0
            }

        out_degrees = dict(self.graph.out_degree())
        max_fan_out = max(out_degrees.values()) if out_degrees else 0

        try:
            max_depth = nx.dag_longest_path_length(self.graph) if nx.is_directed_acyclic_graph(self.graph) else 2
        except Exception:
            max_depth = 2

        anomalous_edges = []
        for u, v, data in self.graph.edges(data=True):
            p_name = data.get("parent_name", "")
            c_name = data.get("child_name", "")
            if (p_name, c_name) in SUSPICIOUS_EDGES:
                anomalous_edges.append({
                    "parent_pid": u,
                    "child_pid": v,
                    "parent_name": p_name,
                    "child_name": c_name,
                    "description": f"Suspicious execution chain: {p_name} spawned {c_name}"
                })

        edge_penalty = min(85.0, len(anomalous_edges) * 45.0)
        depth_penalty = min(15.0, max_depth * 3.0)
        fanout_penalty = min(10.0, max_fan_out * 2.0)
        graph_score = round(min(100.0, edge_penalty + depth_penalty + fanout_penalty), 1)

        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "max_depth": max_depth,
            "max_fan_out": max_fan_out,
            "anomalous_edges": anomalous_edges,
            "graph_score": graph_score
        }

    def get_layout_for_ui(self) -> Dict[str, Any]:
        """Generates 2D spring layout coordinates for Plotly SOC visualization."""
        if self.graph.number_of_nodes() == 0:
            return {"nodes": [], "edges": []}

        pos = nx.spring_layout(self.graph, seed=42)
        nodes_data = [
            {
                "pid": node,
                "x": float(pos[node][0]),
                "y": float(pos[node][1]),
                "name": self.graph.nodes[node].get("name", "proc"),
                "cmd": self.graph.nodes[node].get("cmd", ""),
                "user": self.graph.nodes[node].get("user", "")
            }
            for node in self.graph.nodes()
        ]

        edges_data = [
            {
                "u": u, "v": v,
                "x0": float(pos[u][0]), "y0": float(pos[u][1]),
                "x1": float(pos[v][0]), "y1": float(pos[v][1]),
                "parent_name": data.get("parent_name", ""),
                "child_name": data.get("child_name", ""),
                "is_suspicious": (data.get("parent_name"), data.get("child_name")) in SUSPICIOUS_EDGES
            }
            for u, v, data in self.graph.edges(data=True)
        ]

        return {"nodes": nodes_data, "edges": edges_data}

# =====================================================================
# 4. SIGNAL 3: HEURISTIC RULE ENGINE
# =====================================================================

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
            ev.get("dest_port") not in [80, 443]
        ),
        "description": "Script interpreter established outbound socket on non-standard port."
    }
]

def evaluate_rules(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluates telemetry events against heuristic security rules."""
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

    composite_score = min(100.0, max_score + (len(triggered_rules) - 1) * 5.0) if len(triggered_rules) > 1 else max_score

    return {
        "rule_score": round(composite_score, 1),
        "triggered_rules": triggered_rules,
        "technique_ids": list(technique_ids)
    }

# =====================================================================
# 5. SIGNAL 4: MULTI-STAGE ATTACK SEQUENCE DETECTOR
# =====================================================================

class SequenceDetector:
    def __init__(self, max_sequence_window_sec: int = 180):
        self.max_sequence_window_sec = max_sequence_window_sec

    def evaluate_sequence(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlates ordered kill-chain attack stages over time."""
        if not events:
            return {"sequence_score": 0.0, "matched_stages": [], "is_killchain": False, "stage_count": 0}

        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        matched_stages = []
        shell_pids = set()

        for ev in sorted_events:
            p_name = (ev.get("process_name") or "").lower()
            parent_name = (ev.get("parent_process_name") or "").lower()
            pid = ev.get("pid")
            parent_pid = ev.get("parent_pid")
            ev_type = ev.get("event_type")

            # Stage A: Initial Execution via Office
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

            # Stage B: Host & Network Discovery
            if "B" not in [s["stage"] for s in matched_stages]:
                if p_name in ["whoami.exe", "ipconfig.exe", "netstat.exe"] or parent_pid in shell_pids:
                    matched_stages.append({
                        "stage": "B",
                        "name": "Host & Network Discovery",
                        "timestamp": ev.get("timestamp"),
                        "details": f"Discovery utility {p_name} executed"
                    })
                    continue

            # Stage C: Network C2 Egress
            if "C" not in [s["stage"] for s in matched_stages]:
                if ev_type == "NetworkConnect" and (pid in shell_pids or p_name in ["powershell.exe", "cmd.exe"]):
                    matched_stages.append({
                        "stage": "C",
                        "name": "Command & Control Egress",
                        "timestamp": ev.get("timestamp"),
                        "details": f"{p_name} connected to remote socket {ev.get('dest_ip')}:{ev.get('dest_port')}"
                    })
                    continue

            # Stage D: Tool Transfer / Persistence
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
        scores = {0: 0.0, 1: 25.0, 2: 55.0, 3: 80.0}
        score = scores.get(count, 95.0)

        return {
            "sequence_score": score,
            "matched_stages": matched_stages,
            "stage_count": count,
            "is_killchain": count >= 3
        }

# =====================================================================
# 6. MITRE ATT&CK CATALOG & ENRICHMENT
# =====================================================================

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
        "description": "Adversaries may abuse cmd.exe to execute commands and batch scripts.",
        "url": "https://attack.mitre.org/techniques/T1059/003/"
    },
    "T1082": {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about OS and hardware.",
        "url": "https://attack.mitre.org/techniques/T1082/"
    },
    "T1016": {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for details about network configuration (ipconfig, netstat).",
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
        "description": "Adversaries may transfer tools or files from external systems onto the endpoint.",
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
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or disable volume shadow copies (vssadmin) to prevent data restoration.",
        "url": "https://attack.mitre.org/techniques/T1490/"
    }
}

def lookup_technique(technique_id: str) -> dict:
    """Returns technique metadata or default unknown dict."""
    return MITRE_TECHNIQUES.get(technique_id, {
        "id": technique_id,
        "name": "Uncategorized Technique",
        "tactic": "Unknown",
        "description": "Suspicious endpoint activity observed.",
        "url": "https://attack.mitre.org/"
    })

def map_event_to_techniques(event: Dict[str, Any]) -> List[str]:
    """Identifies MITRE techniques applicable to an individual event."""
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
    """Enriches technique IDs with full catalog descriptors."""
    return [lookup_technique(tid) for tid in sorted(list(set(technique_ids)))]

# =====================================================================
# 7. HYBRID RISK FUSION & EXPLAINABILITY
# =====================================================================

FUSION_WEIGHTS = {
    "ml_score": 0.25,        # 25% Isolation Forest ML
    "rule_score": 0.30,      # 30% Deterministic Rules
    "graph_score": 0.20,     # 20% Process Graph Lineage
    "sequence_score": 0.25   # 25% Multi-Stage Temporal Kill-Chain
}

def calculate_fused_risk(ml_score: float, rule_score: float, graph_score: float, seq_score: float) -> float:
    """Calculates weighted composite risk score (0-100)."""
    total = (
        FUSION_WEIGHTS["ml_score"] * ml_score +
        FUSION_WEIGHTS["rule_score"] * rule_score +
        FUSION_WEIGHTS["graph_score"] * graph_score +
        FUSION_WEIGHTS["sequence_score"] * seq_score
    )
    return round(max(0.0, min(100.0, total)), 1)

class HybridRiskFusionEngine:
    def __init__(self):
        self.weights = FUSION_WEIGHTS

    def evaluate_threat(
        self,
        ml_score: float,
        rule_score: float,
        graph_score: float,
        sequence_score: float,
        process_name: str,
        pid: int,
        parent_pid: int,
        technique_ids: List[str],
        rule_reasons: List[str],
        evidence: Dict[str, Any],
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Synthesizes the 4 detection signals into an actionable alert and optional incident."""
        if timestamp is None:
            timestamp = datetime.utcnow().isoformat()

        fused_score = calculate_fused_risk(ml_score, rule_score, graph_score, sequence_score)
        tier = get_risk_tier(fused_score)

        reasons_list = []
        if rule_reasons:
            reasons_list.extend(rule_reasons)
        if graph_score > 40:
            reasons_list.append(f"Anomalous process ancestry graph structure (score: {graph_score})")
        if sequence_score > 40:
            reasons_list.append(f"Multi-stage temporal attack kill-chain progression (score: {sequence_score})")
        if ml_score > 60:
            reasons_list.append(f"Statistical behavioral anomaly in observation window (score: {ml_score})")

        composite_reasons = " | ".join(reasons_list) if reasons_list else "Routine endpoint telemetry conforming to baseline."
        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

        alert = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "process_name": process_name,
            "pid": pid,
            "parent_pid": parent_pid,
            "risk_score": fused_score,
            "risk_tier": tier,
            "ml_score": ml_score,
            "rule_score": rule_score,
            "graph_score": graph_score,
            "sequence_score": sequence_score,
            "mitre_technique_id": technique_ids[0] if technique_ids else "None",
            "all_mitre_techniques": technique_ids,
            "mitre_details": enrich_alert_with_mitre(technique_ids),
            "reasons": composite_reasons,
            "evidence": evidence
        }

        incident = None
        if tier == "Critical":
            incident = {
                "incident_id": f"INC-{uuid.uuid4().hex[:6].upper()}",
                "alert_id": alert_id,
                "timestamp": timestamp,
                "process_name": process_name,
                "pid": pid,
                "severity": "Critical",
                "recommended_actions": (
                    "1. Isolate endpoint from network adapter. "
                    "2. Terminate malicious process tree. "
                    "3. Quarantine dropped binaries in Temp. "
                    "4. Revert autostart Registry Run keys."
                ),
                "response_simulation_log": "Pending response simulation review.",
                "status": "Open"
            }

        return {"alert": alert, "incident": incident}

class ExplainabilityEngine:
    def __init__(self, baseline_stats: Dict[str, Any] = None):
        if baseline_stats is None:
            baseline_data = load_baseline()
            self.baseline_stats = baseline_data.get("statistics", {})
        else:
            self.baseline_stats = baseline_stats

    def explain_observation(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates relative z-score deviation percentages driving an anomaly score."""
        deviations = {}
        for col in FEATURE_COLUMNS:
            val = float(feature_vector.get(col, 0.0))
            stat = self.baseline_stats.get(col, {"mean": 0.0, "std": 1.0})
            mean = stat.get("mean", 0.0)
            std = stat.get("std", 1.0)
            if std <= 0:
                std = 1.0
            z_score = max(0.0, (val - mean) / std)
            deviations[col] = z_score

        total_dev = sum(deviations.values())
        if total_dev <= 0:
            contributions = {col: round(100.0 / len(FEATURE_COLUMNS), 1) for col in FEATURE_COLUMNS}
        else:
            contributions = {col: round((val / total_dev) * 100.0, 1) for col, val in deviations.items()}

        ranked_features = sorted(contributions.items(), key=lambda x: x[1], reverse=True)
        top_drivers = ranked_features[:3]
        top_text = ", ".join([f"{k.replace('_', ' ').title()} ({v}%)" for k, v in top_drivers if v > 5.0])

        return {
            "contributions": contributions,
            "ranked_features": ranked_features,
            "top_drivers_text": top_text if top_text else "No abnormal feature spikes observed."
        }

# =====================================================================
# 8. INCIDENT CONTAINMENT SIMULATOR & REPORT GENERATION
# =====================================================================

def simulate_containment_action(incident_id: str, action_type: str, target: str) -> Dict[str, Any]:
    """Executes safe containment actions without modifying live system configuration."""
    ts = datetime.utcnow().isoformat()
    action_templates = {
        "isolate_endpoint": f"[{ts}] [SAFE-SIMULATION] Host isolation rule triggered. Simulated network adapter disable for host: {target}.",
        "terminate_process": f"[{ts}] [SAFE-SIMULATION] Process tree kill signal triggered for PID: {target}. Sub-process hierarchy flagged for termination.",
        "block_ip": f"[{ts}] [SAFE-SIMULATION] Outbound firewall drop rule simulated for malicious C2 address: {target}.",
        "quarantine_file": f"[{ts}] [SAFE-SIMULATION] File quarantine simulated for artifact path: {target}."
    }

    log_entry = action_templates.get(action_type, f"[{ts}] [SAFE-SIMULATION] Generic containment simulated for {target}.")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT response_simulation_log FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if row:
        current_log = row["response_simulation_log"] or ""
        updated_log = (current_log + "\n" + log_entry).strip()
        cursor.execute("""
            UPDATE incidents
            SET response_simulation_log = ?, status = 'Mitigated (Simulated)'
            WHERE incident_id = ?
        """, (updated_log, incident_id))
        conn.commit()
    conn.close()

    return {
        "incident_id": incident_id,
        "action_type": action_type,
        "target": target,
        "log_entry": log_entry,
        "status": "Success (Simulated)"
    }

def export_incident_to_json(incident: Dict[str, Any], alert: Dict[str, Any], output_path: Path = None) -> Path:
    """Exports structured incident data to a JSON file."""
    if output_path is None:
        output_path = EXPORTS_DIR / f"{incident.get('incident_id', 'INC')}.json"
    payload = {
        "report_generated_at": datetime.utcnow().isoformat(),
        "incident": incident,
        "associated_alert": alert
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return output_path

def export_incidents_to_csv(incidents: List[Dict[str, Any]], output_path: Path = None) -> Path:
    """Exports list of incidents to a CSV file."""
    if output_path is None:
        output_path = EXPORTS_DIR / "incident_summary.csv"
    if not incidents:
        return output_path
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(incidents[0].keys()))
        writer.writeheader()
        writer.writerows(incidents)
    return output_path

def export_incident_to_pdf(incident: Dict[str, Any], alert: Dict[str, Any], output_path: Path = None) -> Path:
    """Generates professional PDF investigation report using ReportLab."""
    if output_path is None:
        inc_id = incident.get("incident_id", "INC-001")
        output_path = EXPORTS_DIR / f"{inc_id}_Report.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor('#1E293B'))
    section_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=13, leading=16, textColor=colors.HexColor('#0F172A'), spaceBefore=10, spaceAfter=5)
    body_style = ParagraphStyle('BodyDark', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor('#334155'))

    story = [
        Paragraph("SECURITY INCIDENT INVESTIGATION REPORT", title_style),
        Paragraph("<b>System:</b> AI-Driven Adaptive Endpoint Behavioral Threat Detection System", body_style),
        Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style),
        Spacer(1, 10),
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#DC2626'), spaceAfter=12)
    ]

    inc_data = [
        [Paragraph("<b>Incident ID</b>", body_style), Paragraph(str(incident.get("incident_id")), body_style),
         Paragraph("<b>Severity Tier</b>", body_style), Paragraph(f"<font color='red'><b>{incident.get('severity', 'Critical')}</b></font>", body_style)],
        [Paragraph("<b>Timestamp</b>", body_style), Paragraph(str(incident.get("timestamp")), body_style),
         Paragraph("<b>Status</b>", body_style), Paragraph(str(incident.get("status", "Open")), body_style)],
        [Paragraph("<b>Root Process</b>", body_style), Paragraph(str(incident.get("process_name")), body_style),
         Paragraph("<b>Process ID (PID)</b>", body_style), Paragraph(str(incident.get("pid")), body_style)]
    ]
    t_inc = Table(inc_data, colWidths=[100, 170, 100, 170])
    t_inc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_inc)
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>HYBRID RISK FUSION SCORE BREAKDOWN</b>", section_style))
    scores_data = [
        ["Total Risk Score", "ML Score (IsoForest)", "Rule Score", "Process Graph", "Attack Sequence"],
        [
            f"{alert.get('risk_score', 0)} / 100",
            f"{alert.get('ml_score', 0)} / 100",
            f"{alert.get('rule_score', 0)} / 100",
            f"{alert.get('graph_score', 0)} / 100",
            f"{alert.get('sequence_score', 0)} / 100"
        ]
    ]
    t_scores = Table(scores_data, colWidths=[108]*5)
    t_scores.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#FEF2F2')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_scores)
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>MITRE ATT&CK FRAMEWORK ALIGNMENT</b>", section_style))
    mitre_details = alert.get("mitre_details", [])
    if mitre_details:
        m_table = [["Technique ID", "Name", "Tactic Classification"]]
        for m in mitre_details:
            m_table.append([m.get("id"), m.get("name"), m.get("tactic")])
        t_m = Table(m_table, colWidths=[100, 260, 180])
        t_m.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F766E')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_m)
    else:
        story.append(Paragraph("No direct MITRE technique matched.", body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>DETECTION RATIONALE & FORENSIC EXPLAINABILITY</b>", section_style))
    story.append(Paragraph(f"{alert.get('reasons', 'Behavioral anomaly detected.')}", body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>RECOMMENDED ACTIONS & CONTAINMENT AUDIT LOG</b>", section_style))
    rec = incident.get("recommended_actions", "Isolate endpoint.")
    sim_log = incident.get("response_simulation_log", "None recorded.")
    story.append(Paragraph(f"<b>Recommended:</b> {rec}", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Simulation Audit:</b><br/>{sim_log.replace(chr(10), '<br/>')}", body_style))

    doc.build(story)
    return output_path
