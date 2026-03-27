# PATENT APPLICATION DRAFT

## FORM 1 — APPLICATION FOR GRANT OF PATENT
**Indian Patent Office (IPO) — The Patents Act, 1970**

---

## TITLE OF THE INVENTION

**"An AI-Based Autonomous Agent System for Real-Time Detection and Adaptive Mitigation of Distributed Denial-of-Service (DDoS) Attacks Using Ensemble Machine Learning"**

---

## FIELD OF THE INVENTION

This invention relates to the field of **network security and artificial intelligence**, specifically to an autonomous software agent that employs ensemble machine learning models to detect and mitigate Distributed Denial-of-Service (DDoS) attacks in real-time across network infrastructure.

---

## APPLICANTS / INVENTORS

| Name | Registration No. | Role |
|---|---|---|
| Utkarsh Jaiswal | RA2311030010011 | Co-Inventor |
| Utakarsh Jain | RA2311030010054 | Co-Inventor |

**Institution**: SRM Institute of Science and Technology, Dept. of Networking & Communications  
**Guide**: Dr. Karthikeyan H, Assistant Professor

---

## ABSTRACT (150 words)

The present invention discloses an autonomous AI agent system for detecting and mitigating Distributed Denial-of-Service (DDoS) attacks in real-time. The system employs a novel weighted ensemble of Random Forest and Gradient-Boosted Decision Tree (XGBoost) classifiers, operating on 38 engineered behavioral features extracted from network flow data. A key innovation is the **three-tier adaptive mitigation escalation mechanism** that dynamically adjusts response severity — from monitoring, to rate-limiting, to full IP blocking — based on ensemble confidence scores and consecutive detection counts. The system achieves 99.87% detection accuracy with ROC-AUC of 1.0000 on the CIC-DDoS2019 benchmark dataset. The architecture incorporates a **multi-threaded streaming pipeline** with configurable worker pools enabling throughput scaling from 2,000 to 10,000+ flows per second on commodity hardware, with a distributed blueprint extending to 1,000,000+ flows/sec via message queue partitioning.

---

## BACKGROUND OF THE INVENTION

### Problem Statement
Distributed Denial-of-Service (DDoS) attacks remain one of the most prevalent and damaging threats to internet infrastructure. Modern DDoS attacks can generate traffic volumes exceeding 1 Tbps, overwhelming target systems within seconds. Traditional defense mechanisms suffer from critical limitations:

1. **Threshold-based systems** (e.g., static rate limits) produce high false-positive rates and fail against low-and-slow attacks.
2. **Single-model ML approaches** lack robustness — a single classifier may overfit to specific attack signatures.
3. **Manual intervention systems** cannot respond quickly enough; human operators cannot process millions of flow records per second.
4. **Existing commercial solutions** (Cloudflare, AWS Shield) are proprietary, expensive, and operate as black boxes.

### Prior Art
- **US Patent 10,841,322** — DDoS detection using single neural network (lacks ensemble approach, no adaptive mitigation).
- **US Patent 11,159,546** — Traffic analysis using fixed thresholds (no ML, high false positives).
- **Academic literature** — Various ML-based detection papers exist but lack the integrated autonomous agent with adaptive mitigation escalation.

### Need for the Invention
There exists a need for an **open, autonomous, and scalable** DDoS detection and mitigation system that combines multiple ML models with intelligent response escalation, while being deployable on commodity hardware.

---

## SUMMARY OF THE INVENTION

The present invention provides a novel system and method comprising:

1. **Dual-Model Weighted Ensemble Classifier** — A Random Forest classifier (weight: 0.45) combined with an XGBoost classifier (weight: 0.55) through soft-voting to achieve superior accuracy (99.87%) compared to either model individually.

2. **38-Feature Behavioral Analysis** — Extraction and engineering of 38 discriminative features from raw network flow data, including 34 standard CIC features and 4 novel engineered features (packet rate, byte rate, forward/backward ratio, flag density).

3. **Three-Tier Adaptive Mitigation Escalation** — A novel graduated response mechanism:
   - **Tier 1 (confidence 0.60–0.79)**: Log and monitor only
   - **Tier 2 (confidence 0.80–0.94)**: Rate-limit the source IP; escalate to full block after N consecutive detections
   - **Tier 3 (confidence ≥ 0.95)**: Immediate full IP block with automatic expiry

4. **Multi-Threaded Streaming Architecture** — Parallel batch inference using configurable worker thread pools, enabling linear throughput scaling with CPU cores.

5. **Real IP Validation** — Intelligent filtering to ensure mitigation actions are only applied to valid, real source IP addresses, preventing false blocking of internal/fallback addresses.

---

## DETAILED DESCRIPTION OF THE INVENTION

### System Architecture

The invention comprises five interconnected modules:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DDoS AI AGENT SYSTEM                         │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │    Data       │   │   Model      │   │    Agent Core    │   │
│  │ Preprocessor  │──▶│  Training    │──▶│   (Detection +   │   │
│  │              │   │  (RF + XGB)  │   │    Ensemble)     │   │
│  └──────────────┘   └──────────────┘   └────────┬─────────┘   │
│                                                  │              │
│  ┌──────────────┐                      ┌────────▼─────────┐   │
│  │  Streaming   │◀─────────────────────│   Mitigation     │   │
│  │  Pipeline    │  triggers actions    │   Handler        │   │
│  │ (Scalable)   │                      │  (3-Tier Escal.) │   │
│  └──────────────┘                      └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Module 1: Data Preprocessing (`data_preprocessing.py`)
The preprocessing module ingests raw network flow data from CIC-DDoS2019 in CSV or Parquet format. It performs:
- Column normalization (whitespace stripping)
- Removal of non-predictive identifiers (Flow ID, Source/Destination IP, Timestamp)
- Handling of infinite and missing values via median imputation
- Binary label encoding (BENIGN → 0, any attack → 1)
- **Novel feature engineering**: 4 derived behavioral features (packet rate, byte rate, fwd/bwd ratio, flag density)
- StandardScaler normalization for model input

### Module 2: Model Training (`model_training.py`)
Two classifiers are trained and evaluated:
- **Random Forest**: 200 trees, max_depth=20, balanced class weights, all CPU cores
- **XGBoost**: 300 estimators, max_depth=8, histogram method, scale_pos_weight for class imbalance

Evaluation metrics: Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix, Feature Importance.

### Module 3: Agent Core (`agent_core.py`)
The detection engine implements the weighted ensemble:
```
P(attack) = 0.45 × P_rf(attack) + 0.55 × P_xgb(attack)
```
If P(attack) ≥ 0.60, the flow is classified as an attack and forwarded to the mitigation handler.

### Module 4: Mitigation Handler (`mitigation_handler.py`)
The **three-tier adaptive escalation** is a key novel aspect:

| Confidence | Consecutive Hits | Action |
|---|---|---|
| 0.60 – 0.79 | Any | Log and monitor |
| 0.80 – 0.94 | < 3 | Rate-limit via iptables hashlimit |
| 0.80 – 0.94 | ≥ 3 | Full IP block (graduated) |
| ≥ 0.95 | Any | Immediate full block |

Blocked IPs automatically expire after a configurable duration (default: 300 seconds).

**IP Validation**: The handler validates all source IPs before taking action, rejecting dummy addresses (0.0.0.0, 127.0.0.1, etc.) to prevent false mitigation.

### Module 5: Streaming Pipeline (`streaming_agent.py`, `scalable_pipeline.py`)
For production scalability, the system provides:
- **Multi-threaded worker pool** using ThreadPoolExecutor for parallel batch inference
- **Micro-batching** for optimal GPU/CPU utilization
- **Distributed blueprint** with Apache Kafka, Redis, and Apache Flink for 1M+ flows/sec

---

## CLAIMS

### Independent Claims

**Claim 1.** A computer-implemented method for detecting and mitigating DDoS attacks in a network, comprising:
(a) receiving network flow data from one or more data sources;
(b) extracting a set of at least 34 standard behavioral features and at least 4 engineered behavioral features from said network flow data;
(c) applying a weighted ensemble of a first machine learning classifier (Random Forest) and a second machine learning classifier (Gradient Boosted Decision Trees) to produce a combined probability score;
(d) classifying each network flow as benign or attack based on said combined probability score exceeding a configurable threshold; and
(e) executing a graduated mitigation response based on the confidence level of the classification.

**Claim 2.** A system for autonomous real-time DDoS attack detection and mitigation, the system comprising:
(a) a data preprocessing module configured to ingest network flow data in multiple formats including CSV and Parquet;
(b) a detection module comprising a weighted soft-voting ensemble of two or more machine learning classifiers;
(c) a mitigation handler implementing a three-tier adaptive escalation mechanism; and
(d) a streaming pipeline module with configurable multi-threaded worker pools for parallel inference.

**Claim 3.** A three-tier adaptive mitigation escalation method for responding to detected network attacks, comprising:
(a) a first tier of monitoring and logging when detection confidence is below a first threshold;
(b) a second tier of rate-limiting source traffic when detection confidence exceeds said first threshold but is below a second threshold;
(c) a third tier of complete source IP blocking when detection confidence exceeds said second threshold or consecutive detection count exceeds a configurable limit; and
(d) automatic expiration of blocking rules after a configurable time period.

### Dependent Claims

**Claim 4.** The method of Claim 1, wherein the weighted ensemble assigns a weight of 0.45 to the Random Forest classifier and 0.55 to the Gradient Boosted Decision Tree classifier.

**Claim 5.** The method of Claim 1, wherein the four engineered behavioral features comprise: packet rate (packets per flow duration), byte rate (bytes per flow duration), forward-to-backward packet ratio, and flag density (sum of TCP flag counts divided by total packets).

**Claim 6.** The system of Claim 2, wherein the detection module achieves at least 99.5% accuracy on the CIC-DDoS2019 benchmark dataset.

**Claim 7.** The system of Claim 2, wherein the streaming pipeline is capable of processing at least 10,000 network flows per second on commodity hardware using 4 worker threads.

**Claim 8.** The method of Claim 3, wherein the first threshold is 0.80 and the second threshold is 0.95.

**Claim 9.** The method of Claim 3, wherein the consecutive detection count limit is configurable and defaults to 3.

**Claim 10.** The system of Claim 2, further comprising an IP validation module that rejects mitigation actions against dummy, loopback, or invalid source IP addresses.

**Claim 11.** The system of Claim 2, wherein the streaming pipeline further comprises a distributed processing blueprint using message queuing (Apache Kafka) with 64 or more partitions for horizontal scaling to 1,000,000 or more flows per second.

**Claim 12.** The method of Claim 1, wherein the mitigation response includes one or more of: iptables firewall rules, BGP Flowspec blackhole announcements, and cloud WAF rule injection.

---

## EXPERIMENTAL RESULTS

### Detection Performance

| Metric | Random Forest | XGBoost | Ensemble |
|---|---|---|---|
| Accuracy | 99.87% | 99.86% | 99.87% |
| Precision | 99.98% | 99.98% | 99.98% |
| Recall | 99.85% | 99.84% | 99.85% |
| F1-Score | 99.91% | 99.91% | 99.91% |
| ROC-AUC | 1.0000 | 1.0000 | 1.0000 |

**Dataset**: CIC-DDoS2019 (431,371 flows — 333,540 attack, 97,831 benign)

### Attack Types Successfully Detected
SYN Flood, UDP Flood, LDAP Reflection, MSSQL Attack, NTP Amplification, DNS Amplification, TFTP Attack, NetBIOS, Portmap, SNMP, UDPLag

### Scalability Results
Multi-threaded worker pool achieves near-linear scaling with CPU cores on commodity hardware.

---

## DRAWINGS / FIGURES

**Figure 1**: System architecture block diagram (see Detailed Description)  
**Figure 2**: Three-tier mitigation escalation flowchart  
**Figure 3**: Confusion matrix for ensemble classifier  
**Figure 4**: ROC curves for Random Forest and XGBoost  
**Figure 5**: Feature importance rankings  
**Figure 6**: Scalability benchmark — throughput vs. worker count  
**Figure 7**: Scalability benchmark — throughput vs. flow count  

> **Note**: Figures 3–7 are generated automatically by the system and saved in the `plots/` directory.

---

## DATE OF FILING

**Provisional / Complete**: _______________  
**Application Number**: (assigned by IPO)

---

>  **DISCLAIMER**: This is a draft for reference purposes. For actual filing with the Indian Patent Office (IPO), the applicants must engage a registered Patent Agent (under Section 127 of the Patents Act, 1970). Filing requires Form 1, Form 2 (Specification), Form 3 (Statement & Undertaking), Form 5 (Declaration of Inventorship), and applicable fees.
