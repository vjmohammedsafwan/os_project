"""
Explainable Alert Generation Engine
Explains WHY the system generated an alert by ranking feature contributions (percentages)
and synthesizing human-readable forensic reasoning.
Stage 11 requirement.
"""
from typing import Dict, Any, List
import numpy as np
from features.feature_extractor import FEATURE_COLUMNS
from models.baseline_manager import load_baseline

class ExplainabilityEngine:
    def __init__(self, baseline_stats: Dict[str, Any] = None):
        if baseline_stats is None:
            baseline_data = load_baseline()
            self.baseline_stats = baseline_data.get("statistics", {})
        else:
            self.baseline_stats = baseline_stats

    def explain_observation(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates relative z-score deviation for each feature against the baseline,
        and translates deviations into percentage contributions of anomaly.
        """
        deviations = {}
        for col in FEATURE_COLUMNS:
            val = float(feature_vector.get(col, 0.0))
            stat = self.baseline_stats.get(col, {"mean": 0.0, "std": 1.0})
            mean = stat.get("mean", 0.0)
            std = stat.get("std", 1.0)
            if std <= 0:
                std = 1.0

            # Compute normalized absolute deviation
            z_score = max(0.0, (val - mean) / std)
            deviations[col] = z_score

        total_dev = sum(deviations.values())
        if total_dev <= 0:
            # Default even contribution if no deviations
            contributions = {col: round(100.0 / len(FEATURE_COLUMNS), 1) for col in FEATURE_COLUMNS}
        else:
            contributions = {
                col: round((val / total_dev) * 100.0, 1)
                for col, val in deviations.items()
            }

        # Sort features by percentage contribution descending
        ranked_features = sorted(contributions.items(), key=lambda x: x[1], reverse=True)

        # Human-readable summary of top 3 drivers
        top_drivers = ranked_features[:3]
        top_text = ", ".join([f"{k.replace('_', ' ').title()} ({v}%)" for k, v in top_drivers if v > 5.0])

        return {
            "contributions": contributions,
            "ranked_features": ranked_features,
            "top_drivers_text": top_text if top_text else "No abnormal feature spikes observed."
        }
