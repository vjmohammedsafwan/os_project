"""
Normal Behavioral Baseline Manager
Learns, computes descriptive statistics, and versions baseline profiles.
Stage 5 requirement.
"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from config.settings import BASELINES_DIR
from features.feature_extractor import FEATURE_COLUMNS

DEFAULT_BASELINE_FILE = BASELINES_DIR / "baseline_v1.json"

def calculate_baseline_statistics(df_features: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculates descriptive statistics (mean, std, min, max, 5th and 95th percentiles)
    for all engineered features on clean normal activity.
    """
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
    """Saves baseline profile with version and metadata."""
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
