"""
Behavioral Feature Extractor
Converts raw event streams into numerical behavioral feature vectors.
Stage 4 requirement.
"""
from datetime import datetime, timedelta
from typing import List, Dict, Any
import numpy as np
import pandas as pd
from config.settings import OBSERVATION_WINDOW_SECONDS

# Known legitimate parent-child pairs for calculating parent rarity
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
    """Returns rarity score between 0.0 (very common) and 1.0 (unheard of / anomalous)."""
    parent = (parent or "").lower()
    child = (child or "").lower()
    if (parent, child) in COMMON_PAIRS:
        return COMMON_PAIRS[(parent, child)]
    # Suspicious pairs get maximum rarity
    if parent in ["winword.exe", "excel.exe", "powerpnt.exe"] and child in ["powershell.exe", "cmd.exe", "cscript.exe"]:
        return 0.98
    return 0.85  # Generic uncommon pair

def extract_window_features(events: List[Dict[str, Any]], window_seconds: int = OBSERVATION_WINDOW_SECONDS) -> List[Dict[str, Any]]:
    """
    Aggregates events into temporal windows and extracts behavioral vectors.
    Returns a list of structured feature records.
    """
    if not events:
        return []

    # Sort events by timestamp
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

            # 1. Process Features
            process_count = len(proc_creates)
            child_count = proc_creates["parent_pid"].nunique() if not proc_creates.empty else 0
            
            # Lifetime in window
            time_delta = (sub["dt"].max() - sub["dt"].min()).total_seconds()
            process_lifetime = round(time_delta, 2)

            # Parent Rarity
            rarity_vals = []
            for _, row in proc_creates.iterrows():
                rarity_vals.append(calculate_parent_rarity(row.get("parent_process_name"), row.get("process_name")))
            parent_rarity = float(np.mean(rarity_vals)) if rarity_vals else 0.05

            # Chain depth estimate
            chain_depth = min(4, 1 + child_count)

            # 2. Network Features
            network_count = len(net_connects)
            unique_ips = net_connects["dest_ip"].nunique() if not net_connects.empty else 0
            unique_ports = net_connects["dest_port"].nunique() if not net_connects.empty else 0
            duration_minutes = max(1.0, window_seconds / 60.0)
            burst_rate = round(network_count / duration_minutes, 2)

            # 3. File & Registry Features
            file_count = len(file_creates)
            registry_count = len(reg_ops)

            # Composite Rarity Score
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
    """Converts feature records to a Pandas DataFrame of numerical features."""
    if not feature_records:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    df = pd.DataFrame(feature_records)
    # Ensure all required numeric columns exist
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df[FEATURE_COLUMNS]
