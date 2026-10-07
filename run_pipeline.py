"""
Master Pipeline Orchestrator
Connects ingestion, feature engineering, modeling, detection, and reporting.
Enables fast, reliable end-to-end runs for reviewer presentations and live demonstrations.
"""
import argparse
import sys
from pathlib import Path

from database import init_db, insert_event, insert_alert, insert_incident
from collector import (
    generate_normal_baseline_events,
    generate_macro_attack_scenario
)
from detector import (
    extract_window_features,
    to_feature_matrix,
    calculate_baseline_statistics,
    save_baseline,
    IsolationForestEngine,
    ProcessGraphEngine,
    evaluate_rules,
    SequenceDetector,
    HybridRiskFusionEngine,
    simulate_containment_action,
    export_incident_to_pdf,
    export_incident_to_json
)

def setup_system():
    """Initializes tables and directories."""
    print("[*] Initializing SQLite database schema...")
    init_db()
    print("[+] Database initialized successfully.")

def train_baseline_pipeline(count: int = 150):
    """Generates normal baseline telemetry and trains Isolation Forest model."""
    print(f"[*] Simulating {count} normal baseline endpoint events (Chrome, VS Code, Explorer)...")
    events = generate_normal_baseline_events(count=count)

    for ev in events:
        insert_event(ev)

    print("[*] Extracting behavioral window features...")
    windows = extract_window_features(events)
    df_features = to_feature_matrix(windows)

    print("[*] Computing descriptive baseline statistics...")
    stats = calculate_baseline_statistics(df_features)
    save_baseline(stats, version="v1.0")

    print("[*] Fitting Isolation Forest unsupervised anomaly model...")
    iso = IsolationForestEngine()
    iso.train(df_features)

    print(f"[+] Baseline trained successfully on {len(df_features)} behavioral windows.")
    return iso, stats

def run_attack_detection_demo():
    """
    Executes a complete demonstration of multi-stage attack detection:
    1. Injects weaponized Word macro scenario.
    2. Runs 4-signal detection (ML + Rules + Graph + Sequence).
    3. Triggers Critical Alert and Incident record.
    4. Simulates non-destructive containment response.
    5. Exports formal investigation PDF report.
    """
    print("\n" + "=" * 70)
    print("  EXECUTING LIVE THREAT DETECTION DEMONSTRATION")
    print("=" * 70)

    # Ensure DB and models exist
    setup_system()
    iso = IsolationForestEngine()
    iso.load()
    if not iso.is_trained:
        print("[!] No pre-trained model found. Training initial baseline first...")
        train_baseline_pipeline()

    # 1. Ingest Attack Scenario
    print("[1/5] Ingesting multi-stage attack scenario (Office -> PowerShell -> C2 -> Exe)...")
    attack_events = generate_macro_attack_scenario()
    for ev in attack_events:
        insert_event(ev)

    # 2. Extract Features
    windows = extract_window_features(attack_events)
    target_window = windows[-1] if windows else {}

    # 3. Compute 4 Signals
    print("[2/5] Evaluating detection signals across 4 engines:")
    # Signal A: ML Score
    s_ml = iso.score_observation(target_window)
    print(f"      - Signal 1 [Isolation Forest ML]: {s_ml} / 100")

    # Signal B: Process Graph
    graph_engine = ProcessGraphEngine()
    graph_engine.build_graph_from_events(attack_events)
    g_analysis = graph_engine.analyze_graph()
    s_graph = g_analysis["graph_score"]
    print(f"      - Signal 2 [Process Behavior Graph]: {s_graph} / 100")
    if g_analysis["anomalous_edges"]:
        print(f"        -> Anomalous Edge: {g_analysis['anomalous_edges'][0]['description']}")

    # Signal C: Rule Engine
    r_analysis = evaluate_rules(attack_events)
    s_rule = r_analysis["rule_score"]
    print(f"      - Signal 3 [Heuristic Rule Engine]: {s_rule} / 100")
    print(f"        -> Triggered: {[r['name'] for r in r_analysis['triggered_rules']]}")

    # Signal D: Sequence Detector
    seq_engine = SequenceDetector()
    seq_analysis = seq_engine.evaluate_sequence(attack_events)
    s_seq = seq_analysis["sequence_score"]
    print(f"      - Signal 4 [Multi-Stage Sequence]: {s_seq} / 100")
    print(f"        -> Stages Matched: {seq_analysis['stage_count']} / 4")

    # 4. Hybrid Risk Fusion
    print("[3/5] Fusing signals via weighted transfer function...")
    fusion_engine = HybridRiskFusionEngine()
    result = fusion_engine.evaluate_threat(
        ml_score=s_ml,
        rule_score=s_rule,
        graph_score=s_graph,
        sequence_score=s_seq,
        process_name="powershell.exe",
        pid=5824,
        parent_pid=4120,
        technique_ids=r_analysis.get("technique_ids", []),
        rule_reasons=[r["name"] for r in r_analysis.get("triggered_rules", [])],
        evidence={"events_count": len(attack_events), "anomalous_edges": g_analysis["anomalous_edges"]}
    )

    alert = result["alert"]
    incident = result["incident"]

    print(f"\n[+] FUSED RISK SCORE: {alert['risk_score']} / 100")
    print(f"[+] OPERATIONAL TIER: {alert['risk_tier'].upper()}")
    print(f"[+] MITRE ATT&CK:     {', '.join(alert['all_mitre_techniques'])}")
    print(f"[+] REASONING:        {alert['reasons']}")

    insert_alert(alert)

    # 5. Incident & Safe Response Simulation
    if incident:
        print(f"\n[4/5] Critical threat confirmed. Generating Incident ID: {incident['incident_id']}")
        insert_incident(incident)

        print("[5/5] Executing simulated, safe non-destructive response containment...")
        sim1 = simulate_containment_action(incident["incident_id"], "terminate_process", "PID 5824 (powershell.exe)")
        sim2 = simulate_containment_action(incident["incident_id"], "block_ip", "185.220.101.5")
        sim3 = simulate_containment_action(incident["incident_id"], "isolate_endpoint", "DESKTOP-ANALYSIS")
        print("      " + sim1["log_entry"])
        print("      " + sim2["log_entry"])
        print("      " + sim3["log_entry"])

        pdf_path = export_incident_to_pdf(incident, alert)
        json_path = export_incident_to_json(incident, alert)
        print(f"\n[+] Formal Incident PDF exported to:  {pdf_path}")
        print(f"[+] Structured Incident JSON exported to: {json_path}")

    print("=" * 70)
    print("DEMONSTRATION COMPLETED SUCCESSFULLY.")
    print("To view results interactively, run: streamlit run dashboard/app.py")
    print("=" * 70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Driven Behavioral Endpoint Threat Detection")
    parser.add_argument("--setup", action="store_true", help="Initialize SQLite database")
    parser.add_argument("--train", action="store_true", help="Generate baseline and train ML model")
    parser.add_argument("--demo", action="store_true", help="Run live attack detection demonstration")
    parser.add_argument("--eval", action="store_true", help="Run academic evaluation benchmark")
    args = parser.parse_args()

    if args.setup:
        setup_system()
    elif args.train:
        setup_system()
        train_baseline_pipeline()
    elif args.eval:
        from evaluate import run_evaluation_benchmark
        run_evaluation_benchmark()
    elif args.demo or len(sys.argv) == 1:
        run_attack_detection_demo()
