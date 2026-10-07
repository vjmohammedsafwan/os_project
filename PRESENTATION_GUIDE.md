# Reviewer Defense & Presentation Guide
## AI-Driven Adaptive Endpoint Behavioral Threat Detection System
**Presenters**: Safwan & Abhinav  
**Estimated Demo Time**: 3 to 5 minutes

---

### 1. The 30-Second Elevator Pitch
> *"Good morning / afternoon sir/ma'am. In an operating system, every process operates within a strict parent-child hierarchy ($PPID \rightarrow PID$). In normal OS operation, Explorer launches Chrome or Notepad. However, in modern cyber attacks, an exploit causes an innocent application like Word to secretly spawn a scripting shell like PowerShell, which queries system info, contacts a remote server, and drops malware.*
>
> *Traditional antivirus fails against these fileless attacks, and pure ML models cause too many false alarms when users run heavy apps like compilers. Our project solves this with an **OS-level behavioral monitoring framework**. We capture process lifecycles and evaluate activity using a **4-signal hybrid engine**:*
> 1. * **Isolation Forest ML** (unsupervised statistical anomaly scoring)*
> 2. * **Process Behavior Graph** (NetworkX topological parent-child edge analysis)*
> 3. * **Multi-Stage Sequence Detector** (temporal kill-chain state tracking)*
> 4. * **Heuristic Rules** (deterministic high-confidence checks)*
>
> *We fuse these into a single risk score (0 to 100), map the attack to MITRE ATT&CK, explain exactly which features caused the alert, and safely simulate OS containment actions on our interactive SOC dashboard."*

---

### 2. Live 3-Minute Demonstration Script

#### Step 1: Terminal Execution (30 seconds)
1. Open PowerShell and run:
   ```bash
   python run_pipeline.py --demo
   ```
2. **What to point out on screen**:
   * *"Look at the terminal: it ingests the multi-stage attack scenario, calculates the 4 signals individually, and computes a Fused Risk Score of 91.2 (Critical).*
   * *Notice it maps the attack directly to MITRE ATT&CK techniques ($T1059.001$, $T1082$, $T1204.002$).*
   * *It creates a formal Incident ID and safely simulates non-destructive host isolation and process termination."*

#### Step 2: Streamlit SOC Dashboard Walkthrough (2 to 3 minutes)
1. In the terminal, run:
   ```bash
   streamlit run dashboard/app.py
   ```
2. In the browser, point to the sidebar titled **"🎯 Test Cases"**.
   Tell the reviewer:
   > *"Sir/Ma'am, our system supports both live endpoint scanning and controlled attack scenarios so we can evaluate different workloads safely without risking this system's integrity."*

3. **Demonstrate the 5 Test Cases Live**:
   * **Click `🟢 Case 1: Normal Routine Day`**:
     - *Show the Threat Gauge*: Stays low and green ($\le 25/100$, Normal Tier).
     - *Talking point*: *"Under ordinary web browsing and document editing, the system remains quiet with zero false alarms."*
   * **Click `🟡 Case 2: Dev Workload (Drift)`**:
     - *Show the Threat Gauge*: ML detects an activity spike, but Fused Risk stays under 45 (Low Tier).
     - *Talking point*: *"A developer running heavy build tools triggers raw ML anomalies, but our Hybrid Fusion refuses to raise a Critical alert because there is no malicious process graph or kill-chain."*
   * **Click `🔴 Case 3: Office Macro Attack`**:
     - *Show the Threat Gauge*: Spikes to **Critical (85–95/100)**.
     - *Go to Tab 2 (Process Behavior Graph)*: Show the red line from `winword.exe` to `powershell.exe`.
     - *Go to Tab 3 (Threat Alerts)*: Show the 4-signal breakdown and MITRE technique badges.
   * **Click `🔴 Case 4: Ransomware Defense Evasion`**:
     - *Show the Alert*: Catches `vssadmin.exe delete shadows` (MITRE `T1490`).
     - *Go to Tab 6 (Incident Response)*: Shows the simulated automated kill signal.
   * **Click `💻 Case 5: Scan This System LIVE`**:
     - *Show Tab 2 (Process Graph)*: Displays the **real processes currently running on this host system** (Explorer, Chrome, Python, System) with real live Windows PIDs!
     - *Talking point*: *"This proves our engine operates directly on real Windows OS process tables in real time."*

#### Step 3: Academic Evaluation (30 seconds)
1. Show the evaluation benchmark:
   ```bash
   python evaluate.py
   ```
2. **Key talking point**:
   * *"When we test pure Isolation Forest ML on heavy developer workloads, it has a 22.2% False Positive Rate. But when we use our proposed Hybrid Fusion engine, the False Positive Rate drops to 0.0% while maintaining 100% detection recall."*

---

### 3. Answers to Expected Reviewer Questions

#### Q1: "Why is this an Operating Systems project rather than just an AI project?"
* **Answer**: *"Because our entire detection foundation is based on OS core primitives:
  1. **Process Management**: We track Process Control Block (PCB) attributes ($PID$, $PPID$, process creation, exit states, and parent-child inheritance).
  2. **OS Telemetry & Kernel Auditing**: We interface with the Windows Event Logging architecture and Sysmon kernel hooks.
  3. **OS Resource Tracing**: We monitor the file subsystem (I/O burst rates) and the Windows Registry (autostart persistence keys).
  4. **Containment & Signals**: Our incident response simulates OS-level process termination (`SIGTERM` / `taskkill`) and network adapter disconnection."*

#### Q2: "Why not just use Isolation Forest alone? Why did you add the other 3 signals?"
* **Answer**: *"An unsupervised ML model like Isolation Forest only knows that a data point looks statistically different. If a developer runs `npm install` or compiles a C++ program, file writes and process counts spike dramatically. Isolation Forest flags this as an attack (causing a 22.2% false positive rate in our benchmark).
By fusing the ML score with a **Process Lineage Graph** and **Attack Sequence Detector**, we verify whether the process tree is actually malicious (like Word spawning PowerShell) before raising a critical alarm."*

#### Q3: "What makes your work novel enough for an IEEE paper or patent?"
* **Answer**:
  * *"For an **IEEE Conference Paper**, our novelty is the **4-Signal Hybrid Risk Fusion Architecture** that mitigates false positives in endpoint ML, backed by empirical benchmark metrics (Precision, Recall, F1, FPR, and Latency).*
  * *For a **Patent**, our inventive step is the computer-implemented method that combines dynamic directed acyclic process graphs with temporal multi-stage kill-chain correlation, and an automated baseline drift adaptation engine with state rollback protection."*

#### Q4: "Did you actually kill processes or modify system firewall rules during the demo?"
* **Answer**: *"No. Following standard cybersecurity research ethics and safety practices, we implemented a **Non-Destructive Response Simulator**. It calculates and logs the exact containment vectors (target PID, socket rule, host isolation) to demonstrate the automated workflow without risking the health of the host machine."*
