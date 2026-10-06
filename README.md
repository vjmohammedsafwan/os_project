# AI-Driven Adaptive Endpoint Behavioral Threat Detection System

**Course / Project**: Operating Systems & Systems Security  
**Authors**: Safwan & Abhinav  
**Architecture**: 4-Signal Hybrid Threat Detection (ML + Process Graph + Temporal Sequence + Heuristic Rules)  
**Taxonomy**: MITRE ATT&CK Matrix Alignment  

---

## 📌 Project Overview

Traditional antivirus tools rely on static file signatures, failing against zero-day exploits and fileless attacks. Pure unsupervised machine learning models (such as standalone Isolation Forests) often suffer from excessive False Positives when legitimate users run resource-intensive workloads like compilers or heavy applications.

This project implements an **Operating-System-focused behavioral monitoring system** for Windows endpoints. It tracks low-level process hierarchies, models normal baseline activity, detects multi-stage kill-chain sequences, and evaluates threats using a **4-Signal Hybrid Risk Fusion Engine**:

$$\text{Final Risk Score} = 25\% \cdot \text{ML} + 30\% \cdot \text{Rules} + 20\% \cdot \text{Process Graph} + 25\% \cdot \text{Attack Sequence}$$

---

## 🚀 Quick Start (Running the Project)

### 1. Run the End-to-End Pipeline & Live Demonstration
To initialize the database, simulate normal baseline activity, inject a multi-stage attack scenario, compute the 4 signals, and export an investigation PDF report:

```bash
python run_pipeline.py --demo
```

### 2. Launch the Interactive Streamlit SOC Dashboard
To open the analyst dashboard with the live threat gauge, interactive process tree graph, and incident response console:

```bash
streamlit run dashboard/app.py
```

### 3. Run the Stage 15 Academic Benchmark Evaluation
To produce the exact quantitative evaluation comparison table (Precision, Recall, F1, False Positive Rate, Latency):

```bash
python evaluation/evaluate.py
```

---

## 🏗️ 15-Stage Architecture Summary

| Stage | Component | Description |
|---|---|---|
| **1 – 3** | Telemetry Pipeline & SQLite | Ingests Sysmon / Event Log telemetry, normalizes fields, stores in `data/threat_detector.db`. |
| **4 – 6** | Feature Extraction & Isolation Forest | 60-second sliding windows, parent rarity, child counts, bursts, calibrated 0–100 anomaly scoring. |
| **7** | Process Behavior Graph | NetworkX directed acyclic graph ($PPID \rightarrow PID$), highlights anomalous edges (e.g., `winword.exe` $\rightarrow$ `powershell.exe`). |
| **8** | Hybrid Risk Fusion Engine | Combines ML, Rule, Graph, and Sequence signals into operational tiers (`Normal`, `Low`, `Suspicious`, `Critical`). |
| **9** | Multi-Stage Sequence Detector | Correlates chronological attack stages: Macro Execution $\rightarrow$ Discovery $\rightarrow$ C2 $\rightarrow$ Payload Drop. |
| **10** | MITRE ATT&CK Mapping | Maps events to `T1059.001`, `T1082`, `T1016`, `T1071.001`, `T1105`, `T1547.001`. |
| **11** | Explainable AI (XAI) | Quantifies feature contribution percentages driving the anomaly score. |
| **12** | Adaptive Baseline & Concept Drift | Two-sample Kolmogorov-Smirnov (KS) test detects legitimate workload shifts with rollback capability. |
| **13** | SOC Web Dashboard | Multi-page Streamlit interface with Plotly charts and drill-downs. |
| **14** | Incident Reports & Safe Response | Non-destructive containment simulation (isolate host, kill PID, block IP) and formal ReportLab PDF generation. |
| **15** | Academic Evaluation | Rigorous comparative benchmark demonstrating a drastic reduction in False Positive Rate compared to ML-only models. |

---

## 📊 Evaluation Results (Stage 15)

```text
Method                                        | Precision | Recall | F1    | False Positive Rate | Detection Latency
----------------------------------------------+-----------+--------+-------+---------------------+------------------
Baseline ML-Only (Isolation Forest alone)     | 0.812     | 0.774  | 0.793 | 0.222 (22.2% FP)    | 4.34 ms
Proposed Hybrid Detection (ML+Rule+Graph+Seq) | 1.000     | 1.000  | 1.000 | 0.000 (0.0% FP)     | 4.09 ms
```

---

## 📁 Repository Structure

```text
os_project/
├── config/             # Settings, fusion weights, MITRE catalog
├── collector/          # Live Sysmon reader & lab workload simulator
├── processing/         # Event normalizer and SQLite database
├── features/           # Sliding window behavioral feature extractor
├── models/             # Baseline manager, Isolation Forest, Concept Drift
├── detection/          # Process graph, rule engine, sequence detector, risk fusion
├── reports/            # PDF report generator and response simulator
├── dashboard/          # Streamlit analyst SOC dashboard
├── evaluation/         # Stage 15 benchmark harness
├── run_pipeline.py     # Master orchestrator script
└── requirements.txt    # Pinned dependencies
```
