"""
Hybrid Risk Fusion Weights
Defines the relative importance of the 4 detection signals.
Sum of weights must equal 1.0 (100%).
"""

# Weights for the 4 detection engines:
# 1. ML Isolation Forest: Statistical anomaly detection
# 2. Heuristic Rules: High-confidence deterministic indicators
# 3. Process Graph: Anomalous parent-child ancestry in process tree
# 4. Sequence Detector: Multi-stage temporal kill-chain match
FUSION_WEIGHTS = {
    "ml_score": 0.25,        # 25% weight
    "rule_score": 0.30,      # 30% weight
    "graph_score": 0.20,     # 20% weight
    "sequence_score": 0.25   # 25% weight
}

def calculate_fused_risk(ml_score: float, rule_score: float, 
                         graph_score: float, seq_score: float) -> float:
    """
    Combines the 4 signals into a final 0-100 risk score using the weighted formula:
    Final = (0.25 * ML) + (0.30 * Rule) + (0.20 * Graph) + (0.25 * Sequence)
    """
    total = (
        FUSION_WEIGHTS["ml_score"] * ml_score +
        FUSION_WEIGHTS["rule_score"] * rule_score +
        FUSION_WEIGHTS["graph_score"] * graph_score +
        FUSION_WEIGHTS["sequence_score"] * seq_score
    )
    # Clamp between 0.0 and 100.0
    return round(max(0.0, min(100.0, total)), 1)
