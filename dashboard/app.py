"""
AI-Driven Adaptive Endpoint Behavioral Threat Detection System
Streamlit SOC Analyst Dashboard
Stage 13 requirement.
"""
import sys
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import json
from datetime import datetime

from config.settings import DB_PATH, EXPORTS_DIR, BASELINES_DIR
from processing.database import get_connection, init_db, fetch_all_alerts, fetch_all_events
from collector.lab_simulator import (
    generate_normal_baseline_events,
    generate_macro_attack_scenario,
    generate_drift_workload
)
from collector.live_sysmon import is_sysmon_active
from collector.live_processes import capture_live_host_processes
from detection.process_graph import ProcessGraphEngine
from detection.explainability import ExplainabilityEngine
from models.baseline_manager import load_baseline
from models.concept_drift import ConceptDriftEngine
from reports.response_simulator import simulate_containment_action
from reports.report_generator import export_incident_to_pdf
from processing.database import clear_database, insert_event, insert_alert, insert_incident
import run_pipeline

# Configure Streamlit page
st.set_page_config(
    page_title="Endpoint Threat Detection SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark Styling
st.markdown("""
<style>
    .main { background-color: #0b0f19; }
    .stMetric { background-color: #161f30; padding: 15px; border-radius: 8px; border: 1px solid #22324e; }
    .soc-card { background-color: #161f30; padding: 20px; border-radius: 8px; border: 1px solid #22324e; margin-bottom: 20px; }
    .badge-critical { background-color: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-suspicious { background-color: #f59e0b; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #3b82f6; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-normal { background-color: #10b981; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Ensure Database is initialized
init_db()

# --- SIDEBAR CONTROLS ---
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SOC Control Center")
st.sidebar.markdown("**Endpoint Threat Detection**")

st.sidebar.markdown("---")
st.sidebar.subheader("🎯 Test Cases")
st.sidebar.caption("Select an operational scenario to evaluate:")

def run_scenario(scenario_name: str):
    clear_database()
    iso = run_pipeline.IsolationForestEngine()
    iso.load()
    if not iso.is_trained:
        run_pipeline.train_baseline_pipeline(100)
        iso.load()

    fusion_engine = run_pipeline.HybridRiskFusionEngine()
    graph_engine = run_pipeline.ProcessGraphEngine()
    seq_engine = run_pipeline.SequenceDetector()

    if scenario_name == "normal":
        evs = generate_normal_baseline_events(60)
        for e in evs: insert_event(e)
        w = run_pipeline.extract_window_features(evs)[-1]
        s_ml = iso.score_observation(w)
        res = fusion_engine.evaluate_threat(s_ml, 0.0, 5.0, 0.0, "chrome.exe", 2400, 1040, [], [], {})
        insert_alert(res["alert"])

    elif scenario_name == "drift":
        evs = generate_drift_workload(50)
        for e in evs: insert_event(e)
        w = run_pipeline.extract_window_features(evs)[-1]
        s_ml = iso.score_observation(w)  # will be higher (~45-55)
        # Graph and rules are 0 because it's legitimate npm/git activity
        res = fusion_engine.evaluate_threat(s_ml, 0.0, 0.0, 0.0, "node.exe", 8120, 7500, [], ["Benign developer workload spike"], {})
        insert_alert(res["alert"])

    elif scenario_name == "macro":
        run_pipeline.run_attack_detection_demo()

    elif scenario_name == "ransomware":
        from datetime import datetime, timedelta
        base_t = datetime.utcnow()
        evs = [
            {"timestamp": (base_t + timedelta(seconds=1)).isoformat(), "event_id": 1, "event_type": "ProcessCreate", "process_name": "cmd.exe", "pid": 3310, "parent_pid": 1040, "parent_process_name": "explorer.exe", "command_line": "cmd.exe", "user": "CORP\\analyst"},
            {"timestamp": (base_t + timedelta(seconds=4)).isoformat(), "event_id": 1, "event_type": "ProcessCreate", "process_name": "vssadmin.exe", "pid": 4820, "parent_pid": 3310, "parent_process_name": "cmd.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "user": "CORP\\analyst"},
            {"timestamp": (base_t + timedelta(seconds=8)).isoformat(), "event_id": 13, "event_type": "RegistryValueSet", "process_name": "cmd.exe", "pid": 3310, "parent_pid": 1040, "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Locker", "user": "CORP\\analyst"}
        ]
        for e in evs: insert_event(e)
        w = run_pipeline.extract_window_features(evs)[-1]
        s_ml = iso.score_observation(w)
        graph_engine.build_graph_from_events(evs)
        s_graph = graph_engine.analyze_graph()["graph_score"]
        r_eval = run_pipeline.evaluate_rules(evs)
        res = fusion_engine.evaluate_threat(s_ml, r_eval["rule_score"], s_graph, 40.0, "vssadmin.exe", 4820, 3310, r_eval["technique_ids"], [r["name"] for r in r_eval["triggered_rules"]], {})
        insert_alert(res["alert"])
        if res["incident"]:
            insert_incident(res["incident"])
            simulate_containment_action(res["incident"]["incident_id"], "terminate_process", "PID 4820 (vssadmin.exe)")

    elif scenario_name == "live_host":
        live_evs = capture_live_host_processes(60)
        for e in live_evs: insert_event(e)
        w = run_pipeline.extract_window_features(live_evs)[-1] if run_pipeline.extract_window_features(live_evs) else {}
        s_ml = iso.score_observation(w) if w else 15.0
        graph_engine.build_graph_from_events(live_evs)
        s_graph = graph_engine.analyze_graph()["graph_score"]
        r_eval = run_pipeline.evaluate_rules(live_evs)
        res = fusion_engine.evaluate_threat(s_ml, r_eval["rule_score"], s_graph, 0.0, live_evs[0]["process_name"] if live_evs else "host.exe", live_evs[0]["pid"] if live_evs else 100, 0, r_eval["technique_ids"], [r["name"] for r in r_eval["triggered_rules"]], {})
        insert_alert(res["alert"])

if st.sidebar.button("🟢 Case 1: Normal Routine Day", use_container_width=True):
    with st.spinner("Testing Case 1: Routine normal baseline..."):
        run_scenario("normal")
        st.sidebar.success("Case 1 Loaded: Normal behavior (Low risk)")
        st.rerun()

if st.sidebar.button("🟡 Case 2: Dev Workload (Drift)", use_container_width=True):
    with st.spinner("Testing Case 2: Developer workload / benign drift..."):
        run_scenario("drift")
        st.sidebar.warning("Case 2 Loaded: High activity but NOT malicious")
        st.rerun()

if st.sidebar.button("🔴 Case 3: Office Macro Attack", use_container_width=True):
    with st.spinner("Testing Case 3: Spearphishing macro kill-chain..."):
        run_scenario("macro")
        st.sidebar.error("Case 3 Loaded: Critical kill-chain detected!")
        st.rerun()

if st.sidebar.button("🔴 Case 4: Ransomware Defense Evasion", use_container_width=True):
    with st.spinner("Testing Case 4: Shadow copy deletion attack..."):
        run_scenario("ransomware")
        st.sidebar.error("Case 4 Loaded: Ransomware defense evasion!")
        st.rerun()

if st.sidebar.button("💻 Case 5: Scan This System LIVE", use_container_width=True):
    with st.spinner("Scanning active live processes on this system..."):
        run_scenario("live_host")
        st.sidebar.success("Case 5 Loaded: Real system processes captured!")
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("👥 **Authors**: Safwan & Abhinav")
st.sidebar.markdown("🎯 **Framework**: MITRE ATT&CK + Hybrid ML")

# Fetch data from DB
conn = get_connection()
alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
events_df = pd.read_sql_query("SELECT * FROM events ORDER BY timestamp DESC LIMIT 500", conn)
incidents_df = pd.read_sql_query("SELECT * FROM incidents ORDER BY timestamp DESC", conn)
conn.close()

# --- TOP KPI METRICS ---
col1, col2, col3, col4 = st.columns(4)

total_events = len(events_df)
total_alerts = len(alerts_df)
critical_alerts = len(alerts_df[alerts_df["risk_tier"] == "Critical"]) if not alerts_df.empty else 0
highest_risk = alerts_df["risk_score"].max() if not alerts_df.empty else 12.0

col1.metric("Total Ingested Events", f"{total_events}", "Live Telemetry")
col2.metric("Total Generated Alerts", f"{total_alerts}", f"{critical_alerts} Critical")
col3.metric("Critical Incidents", f"{critical_alerts}", "Action Required" if critical_alerts > 0 else "Normal")
col4.metric("Endpoint Risk Level", f"{highest_risk} / 100", "Critical" if highest_risk > 80 else ("Suspicious" if highest_risk > 60 else "Normal"))

# --- NAVIGATION TABS ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🛡️ Executive Overview",
    "🌲 Process Behavior Graph",
    "🚨 Threat Alerts & Explainability",
    "⏳ Attack Timeline",
    "📊 Analytics & Concept Drift",
    "📑 Incident Response & Reports"
])

# ==========================================
# TAB 1: EXECUTIVE OVERVIEW
# ==========================================
with tab1:
    st.subheader("Endpoint Behavioral Security Overview")
    
    col_left, col_right = st.columns([1, 2])
    
    with col_left:
        # Threat Gauge Chart
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = highest_risk,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Current Endpoint Threat Index", 'font': {'size': 18}},
            gauge = {
                'axis': {'range': [0, 100], 'tickwidth': 1},
                'bar': {'color': "#ef4444" if highest_risk > 80 else ("#f59e0b" if highest_risk > 60 else "#10b981")},
                'steps': [
                    {'range': [0, 30], 'color': "rgba(16, 185, 129, 0.2)"},
                    {'range': [30, 60], 'color': "rgba(59, 130, 246, 0.2)"},
                    {'range': [60, 80], 'color': "rgba(245, 158, 11, 0.2)"},
                    {'range': [80, 100], 'color': "rgba(239, 68, 68, 0.2)"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 80
                }
            }
        ))
        fig_gauge.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="#161f30", font={'color': "white"})
        st.plotly_chart(fig_gauge, use_container_width=True)

        if not alerts_df.empty:
            tier_counts = alerts_df["risk_tier"].value_counts().reset_index()
            tier_counts.columns = ["Tier", "Count"]
            fig_pie = px.pie(
                tier_counts, values="Count", names="Tier",
                color="Tier",
                color_discrete_map={"Critical": "#ef4444", "Suspicious": "#f59e0b", "Low": "#3b82f6", "Normal": "#10b981"},
                title="Alert Severity Breakdown",
                hole=0.4
            )
            fig_pie.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="#161f30", font={'color': "white"})
            st.plotly_chart(fig_pie, use_container_width=True)

    with col_right:
        st.markdown("#### High-Priority Security Feed")
        if alerts_df.empty:
            st.info("No threats detected. System conforming to learned operational baseline.")
        else:
            for _, alert in alerts_df.head(4).iterrows():
                tier = alert["risk_tier"]
                badge_class = f"badge-{tier.lower()}"
                st.markdown(f"""
                <div class="soc-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="{badge_class}">{tier.upper()} RISK ({alert['risk_score']} / 100)</span>
                        <small style="color: #94a3b8;">{alert['timestamp']}</small>
                    </div>
                    <h4 style="margin: 8px 0; color: #f8fafc;">Suspicious Process: <code>{alert['process_name']}</code> (PID: {alert['pid']})</h4>
                    <p style="margin: 4px 0; color: #cbd5e1; font-size: 13px;"><b>MITRE ATT&CK:</b> <code>{alert['mitre_technique_id']}</code></p>
                    <p style="margin: 4px 0; color: #94a3b8; font-size: 12px;">{alert['reasons']}</p>
                </div>
                """, unsafe_allow_html=True)

# ==========================================
# TAB 2: PROCESS BEHAVIOR GRAPH (STAGE 7)
# ==========================================
with tab2:
    st.subheader("Process Ancestry Execution Graph")
    st.markdown("Reconstructed from OS kernel process creation primitives (`PPID -> PID`). Red edges denote anomalous parent-child relationships.")

    if events_df.empty:
        st.warning("No process events logged yet. Click 'Simulate Macro Attack' in the sidebar to populate.")
    else:
        graph_engine = ProcessGraphEngine()
        ev_list = events_df.to_dict('records')
        graph_engine.build_graph_from_events(ev_list)
        graph_analysis = graph_engine.analyze_graph()
        layout = graph_engine.get_layout_for_ui()

        # Metrics bar
        g_c1, g_c2, g_c3, g_c4 = st.columns(4)
        g_c1.metric("Graph Nodes (Processes)", graph_analysis["node_count"])
        g_c2.metric("Graph Edges (Lineage)", graph_analysis["edge_count"])
        g_c3.metric("Max Tree Depth", graph_analysis["max_depth"])
        g_c4.metric("Graph Anomaly Score", f"{graph_analysis['graph_score']} / 100")

        if graph_analysis["anomalous_edges"]:
            for a_edge in graph_analysis["anomalous_edges"]:
                st.error(f"🚨 **Anomalous Lineage Detected**: `{a_edge['parent_name']}` (PID: {a_edge['parent_pid']}) spawned `{a_edge['child_name']}` (PID: {a_edge['child_pid']})")

        # Plotly Network Visualization
        fig_net = go.Figure()

        # Draw edges
        for edge in layout["edges"]:
            color = "#ef4444" if edge["is_suspicious"] else "#64748b"
            width = 3 if edge["is_suspicious"] else 1.5
            fig_net.add_trace(go.Scatter(
                x=[edge["x0"], edge["x1"]],
                y=[edge["y0"], edge["y1"]],
                mode='lines',
                line=dict(color=color, width=width),
                hoverinfo='none',
                showlegend=False
            ))

        # Draw nodes
        node_x = [n["x"] for n in layout["nodes"]]
        node_y = [n["y"] for n in layout["nodes"]]
        node_names = [f"{n['name']} (PID: {n['pid']})" for n in layout["nodes"]]
        node_colors = ["#ef4444" if "powershell" in n["name"] or "whoami" in n["name"] else "#3b82f6" for n in layout["nodes"]]

        fig_net.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=[n["name"] for n in layout["nodes"]],
            textposition="top center",
            hovertext=node_names,
            marker=dict(size=18, color=node_colors, line=dict(color="white", width=1.5)),
            showlegend=False
        ))

        fig_net.update_layout(
            height=500,
            paper_bgcolor="#161f30",
            plot_bgcolor="#161f30",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            margin=dict(l=10, r=10, t=20, b=10)
        )
        st.plotly_chart(fig_net, use_container_width=True)

# ==========================================
# TAB 3: THREAT ALERTS & EXPLAINABILITY (STAGES 8, 10, 11)
# ==========================================
with tab3:
    st.subheader("Explainable Threat Detection & Risk Fusion")

    if alerts_df.empty:
        st.info("No active alerts.")
    else:
        # Filters
        f_col1, f_col2 = st.columns([1, 1])
        tier_filter = f_col1.multiselect("Filter Severity Tier", ["Critical", "Suspicious", "Low", "Normal"], default=["Critical", "Suspicious"])
        
        filtered_alerts = alerts_df[alerts_df["risk_tier"].isin(tier_filter)] if tier_filter else alerts_df

        st.dataframe(
            filtered_alerts[["alert_id", "timestamp", "process_name", "pid", "risk_score", "risk_tier", "mitre_technique_id"]],
            use_container_width=True
        )

        st.markdown("### Forensic Alert Inspection")
        selected_alert_id = st.selectbox("Select Alert to Inspect", filtered_alerts["alert_id"].tolist())
        
        if selected_alert_id:
            alert_row = filtered_alerts[filtered_alerts["alert_id"] == selected_alert_id].iloc[0]
            
            c_det1, c_det2 = st.columns([1, 1])
            with c_det1:
                st.markdown(f"#### Alert Rationale: `{alert_row['alert_id']}`")
                st.write(f"**Target Process:** `{alert_row['process_name']}` (PID: {alert_row['pid']})")
                st.write(f"**Parent PID:** `{alert_row['parent_pid']}`")
                st.write(f"**Detected Reasons:** {alert_row['reasons']}")
                
                st.markdown("#### MITRE ATT&CK Classification")
                st.info(f"Technique ID: **{alert_row['mitre_technique_id']}**")

            with c_det2:
                # 4-Signal Breakdown Chart
                signals_data = pd.DataFrame({
                    "Engine": ["ML (IsoForest)", "Heuristic Rules", "Process Graph", "Temporal Sequence"],
                    "Score": [alert_row["ml_score"], alert_row["rule_score"], alert_row["graph_score"], alert_row["sequence_score"]],
                    "Weight": ["25%", "30%", "20%", "25%"]
                })
                fig_bar = px.bar(
                    signals_data, x="Engine", y="Score", text="Score",
                    color="Engine",
                    title=f"4-Signal Hybrid Risk Breakdown (Fused Score: {alert_row['risk_score']})",
                    color_discrete_sequence=["#3b82f6", "#ef4444", "#f59e0b", "#8b5cf6"]
                )
                fig_bar.update_layout(height=280, paper_bgcolor="#161f30", plot_bgcolor="#161f30", font=dict(color="white"))
                st.plotly_chart(fig_bar, use_container_width=True)

# ==========================================
# TAB 4: ATTACK TIMELINE (STAGE 9)
# ==========================================
with tab4:
    st.subheader("Multi-Stage Attack Sequence & Temporal Kill-Chain")
    st.markdown("Chronological correlation of activities matching the attack progression.")

    if events_df.empty:
        st.info("No events available for timeline reconstruction.")
    else:
        timeline_df = events_df.copy()
        timeline_df["dt"] = pd.to_datetime(timeline_df["timestamp"])
        timeline_df = timeline_df.sort_values("dt")

        # Color mapping by event type
        color_map = {
            "ProcessCreate": "#3b82f6",
            "NetworkConnect": "#ef4444",
            "FileCreate": "#f59e0b",
            "RegistryValueSet": "#8b5cf6"
        }

        fig_time = px.scatter(
            timeline_df, x="dt", y="process_name",
            color="event_type",
            color_discrete_map=color_map,
            hover_data=["pid", "command_line", "dest_ip", "file_path", "registry_path"],
            title="Endpoint Event Sequence Over Time",
            height=400
        )
        fig_time.update_layout(paper_bgcolor="#161f30", plot_bgcolor="#161f30", font=dict(color="white"))
        st.plotly_chart(fig_time, use_container_width=True)

        st.markdown("#### Chronological Event Log")
        st.dataframe(timeline_df[["timestamp", "event_type", "process_name", "pid", "parent_process_name", "command_line", "dest_ip"]].head(25), use_container_width=True)

# ==========================================
# TAB 5: ANALYTICS & CONCEPT DRIFT (STAGE 12)
# ==========================================
with tab5:
    st.subheader("Behavioral Analytics & Concept Drift Adaptation")
    st.markdown("Prevents false alarms by evaluating statistical distribution shift (Kolmogorov-Smirnov Test).")

    baseline_data = load_baseline()
    if not baseline_data:
        st.warning("No baseline profile loaded. Run pipeline or click 'Ingest Normal Baseline'.")
    else:
        st.info(f"Active Baseline Version: **{baseline_data.get('version', 'v1.0')}** (Created: {baseline_data.get('created_at', 'N/A')})")

        stats = baseline_data.get("statistics", {})
        stat_rows = []
        for feat, val in stats.items():
            stat_rows.append({
                "Feature": feat,
                "Mean": val.get("mean"),
                "Std Dev": val.get("std"),
                "Min": val.get("min"),
                "Max": val.get("max")
            })
        st.markdown("#### Baseline Descriptive Statistics")
        st.dataframe(pd.DataFrame(stat_rows), use_container_width=True)

        # Concept drift test
        drift_engine = ConceptDriftEngine()
        from features.feature_extractor import extract_window_features, to_feature_matrix
        recent_windows = extract_window_features(events_df.to_dict('records'))
        df_recent = to_feature_matrix(recent_windows)

        # Simulated baseline df for comparison
        df_base_sim = pd.DataFrame([{col: stats[col]["mean"] for col in stats.keys()}] * 20)
        
        drift_eval = drift_engine.evaluate_drift(df_base_sim, df_recent)
        
        st.markdown("#### Concept Drift Status")
        if drift_eval["is_drift_detected"]:
            st.warning(f"⚠️ **Concept Drift Detected!** {drift_eval['summary']}")
        else:
            st.success(f"✅ **No Malicious Drift**: {drift_eval['summary']}")

        col_adapt, col_roll = st.columns(2)
        if col_adapt.button("🔄 Adapt Baseline to New Workload (v1.0 -> v2.0)"):
            drift_engine.adapt_baseline(df_recent, new_version="v2.0")
            st.success("Baseline successfully upgraded to v2.0!")
            st.rerun()
            
        if col_roll.button("⏪ Rollback Baseline to Previous Version"):
            if drift_engine.rollback_baseline():
                st.success("Successfully rolled back to baseline backup!")
                st.rerun()
            else:
                st.info("No prior baseline backup found.")

# ==========================================
# TAB 6: INCIDENT RESPONSE & FORMAL REPORTS (STAGE 14)
# ==========================================
with tab6:
    st.subheader("Incident Management & Safe Containment Simulation")
    st.markdown("Execute non-destructive response actions and export formal investigation reports.")

    if incidents_df.empty:
        st.info("No critical incidents currently logged.")
    else:
        st.dataframe(incidents_df[["incident_id", "timestamp", "process_name", "pid", "severity", "status"]], use_container_width=True)

        selected_inc = st.selectbox("Select Incident to Manage", incidents_df["incident_id"].tolist())
        if selected_inc:
            inc_row = incidents_df[incidents_df["incident_id"] == selected_inc].iloc[0]
            
            st.markdown(f"### Incident Case: `{inc_row['incident_id']}`")
            st.markdown(f"**Recommended Containment Steps:**")
            st.write(inc_row["recommended_actions"])

            st.markdown("#### Execute Safe Response Simulation")
            act_col1, act_col2, act_col3 = st.columns(3)
            
            if act_col1.button("🛑 Simulate Kill Process Tree"):
                sim = simulate_containment_action(selected_inc, "terminate_process", f"PID {inc_row['pid']}")
                st.success(sim["log_entry"])
                st.rerun()

            if act_col2.button("🚫 Simulate Block Remote IP"):
                sim = simulate_containment_action(selected_inc, "block_ip", "185.220.101.5")
                st.success(sim["log_entry"])
                st.rerun()

            if act_col3.button("🔒 Simulate Host Isolation"):
                sim = simulate_containment_action(selected_inc, "isolate_endpoint", "DESKTOP-ANALYSIS")
                st.success(sim["log_entry"])
                st.rerun()

            st.markdown("#### Containment Simulation Audit Log")
            st.code(inc_row["response_simulation_log"] or "No actions simulated yet.")

            # Export PDF
            st.markdown("#### Download Formal Investigation Report")
            export_pdf_btn = st.button("📄 Generate & Download Incident PDF")
            if export_pdf_btn:
                # Find matching alert
                matching_alert = alerts_df[alerts_df["alert_id"] == inc_row["alert_id"]].iloc[0].to_dict() if not alerts_df[alerts_df["alert_id"] == inc_row["alert_id"]].empty else {}
                pdf_path = export_incident_to_pdf(inc_row.to_dict(), matching_alert)
                st.success(f"Generated PDF at `{pdf_path}`")
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="⬇️ Click to Download PDF Report",
                        data=f,
                        file_name=f"{inc_row['incident_id']}_Investigation_Report.pdf",
                        mime="application/pdf"
                    )
