"""
System Settings and Thresholds
Configuration for observation windows, operational risk tiers, and paths.
"""
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
BASELINES_DIR = DATA_DIR / "baselines"
EXPORTS_DIR = DATA_DIR / "exports"
DB_PATH = DATA_DIR / "threat_detector.db"

# Create directories if they do not exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
BASELINES_DIR.mkdir(parents=True, exist_ok=True)
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Sliding Window Configuration
OBSERVATION_WINDOW_SECONDS = 60  # Aggregate telemetry in 1-minute windows

# Operational Risk Tiers (0 to 100)
# Calibrated according to Stage 8 guidelines
TIER_NORMAL_MAX = 30       # 0 - 30: Normal behavior
TIER_LOW_MAX = 60          # 31 - 60: Low risk (monitored)
TIER_SUSPICIOUS_MAX = 80   # 61 - 80: Suspicious (investigate)
                           # 81 - 100: Critical (immediate incident action)

def get_risk_tier(score: float) -> str:
    """Map a 0-100 score to its human-readable operational tier."""
    if score <= TIER_NORMAL_MAX:
        return "Normal"
    elif score <= TIER_LOW_MAX:
        return "Low"
    elif score <= TIER_SUSPICIOUS_MAX:
        return "Suspicious"
    else:
        return "Critical"

# Isolation Forest ML parameters
ISO_FOREST_CONTAMINATION = 0.08  # Expected ~8% baseline anomaly contamination
ISO_FOREST_TREES = 100
RANDOM_SEED = 42

# Concept Drift Threshold (KS-test p-value limit)
DRIFT_P_VALUE_THRESHOLD = 0.05
