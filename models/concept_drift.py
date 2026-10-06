"""
Adaptive Baseline & Concept Drift Detector
Monitors statistical distribution shift between baseline and recent observation windows.
Implements versioned baseline updates (v1 -> v2) and instant rollback.
Stage 12 requirement.
"""
import shutil
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from config.settings import BASELINES_DIR, DRIFT_P_VALUE_THRESHOLD
from features.feature_extractor import FEATURE_COLUMNS
from models.baseline_manager import save_baseline, load_baseline, calculate_baseline_statistics

class ConceptDriftEngine:
    def __init__(self, p_threshold: float = DRIFT_P_VALUE_THRESHOLD):
        self.p_threshold = p_threshold

    def evaluate_drift(
        self,
        df_baseline: pd.DataFrame,
        df_recent: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Applies two-sample Kolmogorov-Smirnov test across feature columns.
        If p-value < threshold, we reject the null hypothesis that distributions are identical (Drift Detected).
        """
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
                
                # If both series are constant and identical, no drift
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
        is_drift = drift_ratio >= 0.25  # If 25% or more features drifted

        return {
            "is_drift_detected": is_drift,
            "drift_score": round(drift_ratio * 100.0, 1),
            "drifting_features": drifting_cols,
            "feature_details": drift_results,
            "summary": (
                f"Significant concept drift detected in {len(drifting_cols)} features ({', '.join(drifting_cols[:3])}). "
                "Workload pattern has shifted legitimately." if is_drift else
                "Telemetry distributions conform stably to current baseline."
            )
        }

    def adapt_baseline(self, df_new_normal: pd.DataFrame, new_version: str = "v2.0") -> Path:
        """
        Safely adapts the baseline:
        1. Backs up current baseline to baseline_backup.json
        2. Calculates new descriptive statistics
        3. Saves as new version
        """
        current_file = BASELINES_DIR / "baseline_v1.json"
        backup_file = BASELINES_DIR / "baseline_backup.json"

        # Backup current version before updating
        if current_file.exists():
            shutil.copyfile(current_file, backup_file)

        new_stats = calculate_baseline_statistics(df_new_normal)
        new_file = BASELINES_DIR / f"baseline_{new_version}.json"
        save_baseline(new_stats, version=new_version, file_path=new_file)
        
        # Also update active default file
        save_baseline(new_stats, version=new_version, file_path=current_file)
        return new_file

    def rollback_baseline(self) -> bool:
        """Restores the previous baseline from backup if available."""
        current_file = BASELINES_DIR / "baseline_v1.json"
        backup_file = BASELINES_DIR / "baseline_backup.json"
        if backup_file.exists():
            shutil.copyfile(backup_file, current_file)
            return True
        return False
