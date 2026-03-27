

## Innovation

Traditional DDoS defenses rely on **static signatures** and **manual thresholds** — both fail against modern, evolving attacks. This project introduces an **AI-powered agent** that:

- **Learns** traffic behavior from the real-world CIC-DDoS2019 dataset
- **Detects** attacks using an ensemble of Random Forest + XGBoost (weighted soft-vote)
- **Mitigates** in real-time via automated IP blocking and port filtering
- **Scales** to 100 billion requests using a Kafka → Flink → Redis distributed pipeline

---

## Project Structure

```
ddos_ai_agent/
│
├── data_preprocessing.py   ← Clean, engineer features, scale, save X.npy / y.npy
├── model_training.py       ← Train RF + XGBoost, evaluate, save .pkl / .json
├── agent_core.py           ← Main agent loop + FireNet simulation mode
├── mitigation_handler.py   ← Automated iptables blocking with auto-expiry
├── scalable_pipeline.py    ← Kafka + Flink + Redis blueprint for 100B scale
│
├── data/
│   ├── raw/                ← Place CIC-DDoS2019 CSV files here
│   └── processed/          ← Auto-generated: X.npy, y.npy, feature_names.txt
│
├── models/                 ← rf_model.pkl, xgb_model.json, scaler.pkl
├── plots/                  ← Confusion matrices, ROC curves, feature importance
├── logs/                   ← agent.log, mitigation.log, alerts.csv
└── requirements.txt
```

---

## Setup

```bash
# 1. Clone / download this project
cd ddos_ai_agent

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download CIC-DDoS2019 dataset
#    URL: https://www.unb.ca/cic/datasets/ddos-2019.html
#    Place all CSV files in:  data/raw/
```

---

## Run the Pipeline

### Step 1 — Preprocess Data
```bash
python data_preprocessing.py
```
Outputs: `data/processed/X.npy`, `y.npy`, `feature_names.txt`, `models/scaler.pkl`

### Step 2 — Train Models
```bash
python model_training.py
```
Outputs: `models/rf_model.pkl`, `models/xgb_model.json`, `plots/` (ROC, CM, feature importance)

### Step 3 — Run Agent (Simulation Mode)
```bash
python agent_core.py --mode simulate --data data/raw/your_file.csv --max_rows 5000
```

### Step 3b — Run Agent (Live Mode)
```bash
# Requires FireNet integration (see agent_core.py live mode section)
python agent_core.py --mode live
```

### Step 4 — Test Mitigation Handler Standalone
```bash
python mitigation_handler.py
```

### Step 5 — Explore Distributed Pipeline
```bash
python scalable_pipeline.py
```

---

## Feature Engineering

| Feature Group | Features Used |
|---|---|
| **Flow Duration** | `Flow Duration`, `Flow IAT Mean/Std/Max/Min` |
| **Packet Rate** | `Total Fwd/Bwd Packets`, `Flow Packets/s`, `feat_pkt_rate` |
| **Byte Rate** | `Total Length Fwd/Bwd`, `Flow Bytes/s`, `feat_byte_rate` |
| **Port Behavior** | `Destination Port`, `SYN/ACK/FIN/RST Flag Counts` |
| **Connections/IP** | `feat_conn_per_src_ip` (Redis counter in scale mode) |
| **Derived** | `feat_fwd_bwd_ratio`, `feat_flag_density` |

---

## Model Performance (Expected on CIC-DDoS2019)

| Metric | Random Forest | XGBoost |
|---|---|---|
| Accuracy | ~99.7% | ~99.8% |
| Precision | ~99.98% | ~99.99% |
| Recall | ~99.63% | ~99.84% |
| F1-Score | ~99.80% | ~99.91% |
| ROC-AUC | ~0.999 | ~1 |

---

## Mitigation Strategy

```
Confidence ≥ 0.95  →  Immediate hard block (iptables DROP + port block)
Confidence ≥ 0.80  →  Rate-limit (512 kbps cap); hard block after 3 hits
Confidence ≥ 0.60  →  Log-only / monitor
```
- Auto-unblock after **300 seconds** (configurable)
- All events written to `logs/alerts.csv` for forensics

---

## Scalability Architecture (100 Billion Requests)

```
Network Edge → Apache Kafka (64 partitions)
                    ↓
              Apache Flink (distributed workers)
              • 1-second tumbling windows
              • Feature aggregation per src_ip
                    ↓
              Model Serving (Triton / Seldon on K8s)
              • Auto-scales with traffic load
                    ↓
              ┌──────────┐    ┌────────────────────┐
              │  BENIGN  │    │  ATTACK             │
              │  Allow   │    │  BGP Flowspec drop  │
              └──────────┘    │  AWS Shield WAF     │
                              │  Redis blocklist    │
                              └────────────────────┘
```

| Component | Technology | Why |
|---|---|---|
| Message Queue | Apache Kafka | Handles millions of msgs/sec, no packet loss |
| Stream Processing | Apache Flink | Sub-second latency, stateful windows |
| AI Serving | NVIDIA Triton | GPU-optimised, thousands of inferences/sec |
| Connection Tracking | Redis | O(1) INCR, 60s TTL per src IP |
| Edge Mitigation | BGP Flowspec | Drops attack at ISP — never hits your server |
| Cloud WAF | AWS Shield Advanced | Global edge protection |

---

## Tech Stack

```
Python 3.12+     scikit-learn 1.4    xgboost 2.0
pandas 2.2       numpy 1.26          matplotlib / seaborn
joblib           kafka-python        redis-py    (scalable pipeline)
boto3            iptables            Apache Flink (production)
```
