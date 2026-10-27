# AI-Based Network Digital Twin for Cyber Attack Simulation and Risk Assessment

An end-to-end, production-grade **AI-Based Network Digital Twin (NDT)** platform for virtualizing enterprise network topologies, modeling threat vulnerabilities, simulating multi-stage cyber attack kill chains (MITRE ATT&CK Framework), evaluating real-time dynamic risk scores, and executing automated AI mitigation playbooks.

---

## 🌟 Key Features

1. **Enterprise Network Digital Twin Topology (`engine/network_graph.py`)**:
   - Virtualized multi-zone topology modeling WAN Edge, DMZ, Internal Corporate Network, Secure Core, and ICS/SCADA Operational Technology (OT).
   - Graph centrality analysis (Degree & Betweenness Centrality) to identify high-value pivot targets.
   - Comprehensive asset metadata: IPv4 address, open ports, OS/platform, CVSS vulnerability scores, and live telemetry feeds (CPU, RAM, bandwidth, failed logins, error rate).

2. **Machine Learning Threat & Anomaly Detection (`ml/` & `models/`)**:
   - **Synthetic Network Telemetry Generator (`ml/dataset_generator.py`)**: 6,000+ realistic flow records across 7 threat classes (*Normal*, *DDoS SYN Flood*, *Ransomware Propagation*, *Man-in-the-Middle*, *SSH Brute Force*, *SQLi / RCE*, *Port Scanning*).
   - **Supervised Threat Classifier**: Trained `RandomForestClassifier` achieving high accuracy and macro F1 score.
   - **Unsupervised Anomaly Detector**: Trained `IsolationForest` for identifying zero-day threat patterns.

3. **Multi-Stage Cyber Attack Simulator (`engine/attack_simulator.py`)**:
   - Implements MITRE ATT&CK kill chain stages: Reconnaissance $\rightarrow$ Initial Access $\rightarrow$ Privilege Escalation $\rightarrow$ Lateral Movement $\rightarrow$ Data Exfiltration / System Disruption.
   - Real-time packet particle trajectory visualization on HTML5 Canvas.
   - Live attack terminal logging and target node state updates (`healthy` $\rightarrow$ `under_attack` $\rightarrow$ `compromised`).

4. **Dynamic Risk Assessment Engine (`engine/risk_assessor.py`)**:
   - Calculates per-node Risk Index based on CVSS scores, asset criticality, centrality, and threat anomalies:
     $$R_{node} = w_1 \cdot \text{CVSS} + w_2 \cdot \text{Criticality} + w_3 \cdot \text{Centrality} + w_4 \cdot \text{Anomalies}$$
   - Evaluates overall System-Wide Network Risk Score (0-100) and Blast Radius percentage.

5. **Automated AI Defense & "What-If" Countermeasure Engine (`engine/mitigation_engine.py`)**:
   - Generates actionable playbooks: Micro-segmentation & Isolation, Firewall ACL Enforcement, Vulnerability Patching, Honeypot Traffic Diversion.
   - "What-If" Countermeasure Simulator evaluating expected Risk Score reduction before applying mitigations to live systems.

6. **Interactive Glassmorphism Web Dashboard & AI Copilot (`templates/` & `static/`)**:
   - HTML5 Canvas Force-Directed Network Graph Visualizer with zoom, pan, dragging, node inspection, and particle packet streams.
   - Chart.js timeline trends, threat distribution charts, and ML feature importances.
   - AI Digital Twin Copilot assistant for querying network health and remediation advice.
   - Automated Forensic Report Export (JSON/CSV download).

---

## 🏗️ System Architecture

```
+-----------------------------------------------------------------------------------+
|                            Modern Web Dashboard UI                                |
|   HTML5 Canvas Graph Visualizer | Chart.js Analytics | AI Security Copilot            |
+-----------------------------------------+-----------------------------------------+
                                          | REST API Requests / JSON
                                          v
+-----------------------------------------------------------------------------------+
|                              Flask REST Server (server.py)                        |
+---------------------+-------------------+-------------------+---------------------+
                      |                   |                   |
                      v                   v                   v
+---------------------------+ +-----------------------+ +---------------------------+
|  Digital Twin Engine      | | Attack Simulator      | | AI Threat Detection       |
|  NetworkX Topology Graph  | | MITRE ATT&CK Stages   | | Random Forest Classifier  |
|  CVSS & Centrality Model  | | Packet Trajectory     | | Isolation Forest Anomaly|
+---------------------------+ +-----------------------+ +---------------------------+
                      |                   |                   |
                      +-------------------+-------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                      Risk Assessment & Mitigation Engine                          |
|             Dynamic Risk Score (0-100), Blast Radius, AI Playbooks               |
+-----------------------------------------------------------------------------------+
```

---

## 📂 Project Structure

```
51. AI- Based Network Digital Twin for Cyber Attack Simulation and Risk Assessment/
├── ml/
│   ├── dataset_generator.py      # Synthetic telemetry generator (6,000 samples)
│   └── train_models.py           # ML training script for Random Forest & Isolation Forest
├── models/
│   ├── threat_classifier.pkl     # Trained ML threat classification model
│   ├── anomaly_detector.pkl      # Trained Isolation Forest anomaly detector
│   ├── scaler.pkl                # Standard Scaler artifact
│   └── model_metadata.json       # Feature importances, accuracy, confusion matrix
├── engine/
│   ├── __init__.py
│   ├── network_graph.py          # NetworkX Digital Twin graph model
│   ├── attack_simulator.py       # Multi-stage Cyber Attack Execution Engine
│   ├── risk_assessor.py          # Dynamic Risk Scoring & Blast Radius Engine
│   └── mitigation_engine.py      # Automated Defense Playbook & What-If Engine
├── static/
│   ├── css/
│   │   └── styles.css            # Dark mode cybersecurity glassmorphism styling
│   └── js/
│       ├── app.js                # Main application state & API coordinator
│       ├── network_viz.js        # HTML5 Canvas force-directed graph renderer
│       └── charts.js             # Chart.js analytics setup
├── templates/
│   └── index.html                # Main SPA dashboard markup
├── server.py                     # Flask REST API Server
├── requirements.txt              # Project Python dependencies
└── README.md                     # Documentation
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Installation
Ensure Python 3.9+ is installed on your system.

Install required dependencies:
```bash
pip install -r requirements.txt
```

### 2. Generate Dataset & Train AI Models
Run the ML pipeline to generate the synthetic telemetry dataset and train the threat classification & anomaly detection models:
```bash
python ml/dataset_generator.py
python ml/train_models.py
```

### 3. Start the Web Server
Launch the Flask REST API server:
```bash
python server.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🌐 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/topology` | GET | Returns current Digital Twin nodes, edges, positions, and telemetry |
| `POST /api/topology/node` | POST | Adds a custom network node to the Digital Twin |
| `POST /api/topology/reset` | POST | Resets network states and telemetry back to healthy baseline |
| `GET /api/metrics` | GET | Returns overall Network Risk Score, Threat Level, Blast Radius, and timeline logs |
| `POST /api/simulate` | POST | Triggers a cyber attack simulation (DDoS, Ransomware, SSH Brute, SQLi, Port Scan) |
| `GET /api/playbooks` | GET | Returns recommended defense playbooks and risk reduction estimates |
| `POST /api/mitigate/what-if` | POST | Evaluates hypothetical risk score drop before applying mitigation |
| `POST /api/mitigate` | POST | Enforces isolation, firewall blocking, patching, or honeypot redirection |
| `POST /api/ai/predict` | POST | Runs ML inference on live telemetry flow input |
| `POST /api/ai/copilot` | POST | AI Security Copilot query response engine |
| `GET /api/reports/export` | GET | Downloads complete Forensic Security & Risk Assessment JSON report |

---

## 🛡️ License & Citation
Designed for AI Cyber Defense Research, Network Digital Twin Simulation, and Operational Cyber Risk Assessment.
