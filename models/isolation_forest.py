"""
Isolation Forest Anomaly Detection Engine
Trains an unsupervised Isolation Forest on normal behavior
and scores new behavioral observations on a calibrated 0-100 scale.
Stage 6 requirement.
"""
from pathlib import Path
from typing import Dict, Any, List
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from config.settings import DATA_DIR, ISO_FOREST_CONTAMINATION, ISO_FOREST_TREES, RANDOM_SEED
from features.feature_extractor import FEATURE_COLUMNS

MODEL_PATH = DATA_DIR / "isolation_forest.joblib"

class IsolationForestEngine:
    def __init__(self, contamination: float = ISO_FOREST_CONTAMINATION, n_estimators: int = ISO_FOREST_TREES):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=RANDOM_SEED
        )
        self.is_trained = False

    def train(self, df_features: pd.DataFrame) -> Path:
        """Trains the model on normal baseline vectors and saves it."""
        X = df_features[FEATURE_COLUMNS].fillna(0).values
        self.model.fit(X)
        self.is_trained = True
        joblib.dump(self.model, MODEL_PATH)
        return MODEL_PATH

    def load(self, model_path: Path = MODEL_PATH):
        """Loads a pre-trained model from disk."""
        if model_path.exists():
            self.model = joblib.load(model_path)
            self.is_trained = True

    def score_observation(self, feature_row: Dict[str, Any]) -> float:
        """
        Calculates a calibrated 0 to 100 anomaly score.
        Normal vectors score close to 0-25; extreme outliers score 80-100.
        """
        if not self.is_trained:
            self.load()
            if not self.is_trained:
                # If not trained yet, fallback to heuristic estimation
                rarity = feature_row.get("rarity_score", 0.1)
                return round(float(rarity * 100.0), 1)

        vec = np.array([[feature_row.get(col, 0) for col in FEATURE_COLUMNS]])
        
        # decision_function gives negative values for anomalies, positive for normal
        raw_score = float(self.model.decision_function(vec)[0])
        
        # Calibration formula:
        # Typical normal scores range from +0.10 to +0.25 -> Maps to 10 - 25
        # Typical anomaly scores range from -0.10 to -0.35 -> Maps to 70 - 100
        # Scaled smoothly using linear interpolation with clipping
        normalized = (0.20 - raw_score) / 0.40 * 100.0
        calibrated = max(0.0, min(100.0, normalized))
        return round(calibrated, 1)

    def score_batch(self, df_features: pd.DataFrame) -> List[float]:
        """Scores a DataFrame of feature observations."""
        scores = []
        for _, row in df_features.iterrows():
            scores.append(self.score_observation(row.to_dict()))
        return scores
