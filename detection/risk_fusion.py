"""
Hybrid Risk Fusion Engine
Integrates ML, Rule, Graph, and Sequence signals into a calibrated operational risk score.
Stage 8 requirement.
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from config.settings import get_risk_tier
from config.fusion_weights import calculate_fused_risk, FUSION_WEIGHTS
from detection.mitre_mapper import enrich_alert_with_mitre

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
        """
        Synthesizes the 4 detection signals into a fused risk tier and actionable alert.
        """
        if timestamp is None:
            timestamp = datetime.utcnow().isoformat()

        fused_score = calculate_fused_risk(ml_score, rule_score, graph_score, sequence_score)
        tier = get_risk_tier(fused_score)

        # Build composite human-readable reason string
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
        primary_technique = technique_ids[0] if technique_ids else "None"

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
            "mitre_technique_id": primary_technique,
            "all_mitre_techniques": technique_ids,
            "mitre_details": enrich_alert_with_mitre(technique_ids),
            "reasons": composite_reasons,
            "evidence": evidence
        }

        # If Critical tier, generate structured incident payload
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

        return {
            "alert": alert,
            "incident": incident
        }
