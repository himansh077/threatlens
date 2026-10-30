# ⚡ ThreatLens AI
### High-Performance Network Intrusion Detection, Traffic Flow Analysis & Threat Intelligence Platform

ThreatLens AI is an enterprise-grade network security and traffic analysis platform designed for modern high-throughput distributed infrastructure. It pairs an interactive Streamlit real-time SOC dashboard with a high-performance MongoDB document store, PyMongo aggregation pipelines, and a dual scikit-learn machine learning engine for real-time intrusion classification and bandwidth regression.

[Quick Start](#-quick-start) • [Key Features](#-key-features) • [System Architecture](#-system-architecture) • [MongoDB Engineering](#-mongodb-engineering--implementation) • [Machine Learning Engine](#-machine-learning-engine) • [CLI & API Usage](#-cli--inference-engine) • [Visual Gallery](#-visual-gallery) • [Automated Testing](#-automated-testing-suite)

---

### 📌 Repository Overview & GitHub Metadata
**Repository Description:**  
Enterprise-grade network intrusion detection and traffic volume analysis system featuring MongoDB aggregation pipelines, dual scikit-learn ML engines, and an interactive Streamlit SOC dashboard.

**Recommended Repository Topics:**  
`mongodb` `nosql` `intrusion-detection` `network-security` `machine-learning` `random-forest` `streamlit` `python` `scikit-learn` `cybersecurity` `soc-dashboard`

---

## 🚀 Quick Start

### Prerequisites
- **Python**: 3.10 – 3.12
- **MongoDB**: Local Community Server 7.x/8.x (running on `mongodb://127.0.0.1:27017`)

### 1-Command Setup & Launch (Windows)

```powershell
# 1. Clone repository
git clone https://github.com/himansh077/threatlens.git
cd threatlens

# 2. Setup virtual environment & dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env

# 4. Run automated pipeline (seed database, train models, evaluate, and test)
scripts\run_all.bat
```

### Launch Interactive SOC Dashboard
```powershell
streamlit run app.py
```
Open your browser at **`http://localhost:8501`**.

---

## ✨ Key Features

### 🛡️ 1. Real-Time Intrusion Classification Engine
- **RandomForestClassifier** trained with balanced class weights to detect sophisticated cyber attacks (DoS, Port Scans, Brute Force, and Probing).
- Outperforms naive baselines with **96.42% accuracy** and an **F1-score of 0.9270** on held-out network traffic.
- Preprocessed with scikit-learn `ColumnTransformer` pipelines ensuring zero data leakage between splits.

### 📊 2. Network Payload & Bandwidth Regressor
- **RandomForestRegressor** estimating flow volume (`total_bytes`) for traffic baselining and infrastructure capacity planning.
- Achieves **$R^2 = 0.8954$** with an **83.6% reduction in Mean Absolute Error (MAE)** over baseline estimators.

### 🍃 3. High-Performance MongoDB 7.x Architecture
- Schema-flexible document modeling for heterogeneous TCP, UDP, and ICMP protocols.
- **Idempotent bulk upsert operations** (`UpdateOne` with `upsert=True`) for high-velocity telemetry ingestion.
- Server-side analytical aggregation pipelines utilizing `$match`, `$group`, `$lookup`, and `$sort`.

### 🖥️ 4. Interactive SOC Dashboard (Streamlit)
- **Live Flow Inspector**: Interactively simulate raw packet telemetry and inspect instant model predictions.
- **MongoDB Telemetry Hub**: Real-time stats on stored traffic flows, index health, and aggregation insights.
- **Model Evaluation Suite**: Interactive confusion matrix inspection, precision-recall breakdowns, and feature importance rankings.

### ⚡ 5. Production-Grade CLI & Verification
- Standalone CLI inference module (`python -m src.predict --input <file.json>`).
- 35 automated pytest verification tests covering data generation, pipeline safety, model stability, and database transactions.

---

## 🏛️ System Architecture

```text
                           ┌───────────────────────────────────────────────┐
                           │      Raw Network Telemetry & Generator        │
                           │           data/traffic.csv (12k flows)        │
                           └───────────────────────┬───────────────────────┘
                                                   │
                                                   ▼
                           ┌───────────────────────────────────────────────┐
                           │       High-Throughput MongoDB Ingestion       │
                           │           src/seed_database.py                │
                           └───────────────┬───────────────┬───────────────┘
                                           │               │
                     ┌─────────────────────┘               └─────────────────────┐
                     ▼                                                           ▼
       ┌───────────────────────────────┐                           ┌───────────────────────────────┐
       │   Intrusion Classifier Model  │                           │   Flow Bandwidth Regressor    │
       │    RandomForest (12 features) │                           │    RandomForest (10 features) │
       │     Accuracy: 96.42%          │                           │     R² Score: 0.8954          │
       └───────────────┬───────────────┘                           └───────────────┬───────────────┘
                       │                                                           │
                       └─────────────────────┬─────────────────────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │   Streamlit SOC Dashboard │
                               │           app.py          │
                               │   • Live Threat Scoring   │
                               │   • MongoDB Aggregations  │
                               │   • Diagnostic Visuals    │
                               └───────────────────────────┘
```

---

## 🍃 MongoDB Engineering & Implementation

### 1. Document Schema Architecture
ThreatLens stores network flow telemetry and real-time model inferences across dedicated collections in `threatlens_db`:

- **`traffic_records`**: Stores raw network flow telemetry including protocol metadata, packet counts, connection rates, flags, and ground-truth labels.
- **`predictions`**: Stores timestamped model inferences, feature snapshots, attack probabilities, and execution latency.
- **`model_metrics`**: Persistent audit log storing model versions, hyperparameters, confusion matrices, and serialized metrics.

### 2. Multi-Tier Index Strategy
Engineered compound and single-field B-tree indexes to optimize high-velocity ingestion and query filtering:

| Collection | Index Fields | Type | Purpose |
| :--- | :--- | :--- | :--- |
| `traffic_records` | `{"record_id": 1}` | Unique B-Tree | Guarantees business key uniqueness and $O(1)$ lookups |
| `traffic_records` | `{"label": 1, "attack_type": 1}` | Compound B-Tree | Accelerates threat intelligence queries and class filtering |
| `traffic_records` | `{"split": 1}` | Single Field | Optimizes dataset partition retrieval (train vs test) |
| `predictions` | `{"record_id": 1, "model_version": 1}` | Compound B-Tree | Accelerates historical prediction audit and joining |
| `predictions` | `{"created_at": -1}` | Descending Single | Enables sub-millisecond reverse chronological telemetry feeds |
| `model_metrics` | `{"run_id": 1}` | Unique B-Tree | Ensures run uniqueness for MLOps version tracking |

### 3. Aggregation Pipelines
Server-side MongoDB aggregation pipelines offload computationally expensive transformations from the application tier:
- **Threat Intelligence Grouping**: Aggregates total packet volume, connection rates, and duration grouped by attack signature (`$group`, `$project`, `$sort`).
- **Telemetry Correlation (`$lookup`)**: Executes relational joins between stored predictions and raw traffic records to calculate live inference drift.

---

## 🤖 Machine Learning Engine

### Model Evaluation Performance (Held-Out Test Split)

| Evaluation Metric | Intrusion Classifier (`RandomForest`) | Naive Baseline | Bandwidth Regressor (`RandomForest`) | Baseline Estimator |
| :--- | :---: | :---: | :---: | :---: |
| **Model Family** | `RandomForestClassifier` | Most Frequent | `RandomForestRegressor` | Mean Predictor |
| **Accuracy** | **96.42%** | 74.08% | — | — |
| **Precision** | **98.20%** | 0.00% | — | — |
| **Recall** | **87.78%** | 0.00% | — | — |
| **F1-Score** | **0.9270** | 0.0000 | — | — |
| **R² Score** | — | — | **0.8954** | -0.0017 |
| **Mean Absolute Error (MAE)**| — | — | **42,383 bytes** | 258,411 bytes |

### Key Input Features
- **Classifier Features (12)**: `duration`, `protocol`, `service`, `state`, `src_packets`, `dst_packets`, `dst_port`, `ttl`, `failed_logins`, `syn_flag_ratio`, `unique_dst_ports`, `conn_rate`.
- **Regressor Features (10)**: `duration`, `protocol`, `service`, `state`, `src_packets`, `dst_packets`, `dst_port`, `ttl`, `unique_dst_ports`, `conn_rate`.
- **Pipeline Structure**: `ColumnTransformer` with median imputation for numeric attributes and `OneHotEncoder(handle_unknown='ignore')` for categorical protocols and services.

---

## 📸 Visual Gallery

| Intrusion Confusion Matrix | Classifier Feature Importance | Regressor Actual vs Predicted |
| :---: | :---: | :---: |
| ![Confusion Matrix](outputs/confusion_matrix.png) | ![Feature Importance](outputs/classifier_feature_importance.png) | ![Actual vs Predicted](outputs/regressor_actual_vs_predicted.png) |

---

## 💻 CLI & Inference Engine

ThreatLens provides standalone CLI interfaces for headless server environments:

```powershell
# Real-time inference on a custom JSON payload
python -m src.predict --input data/sample_input.json

# Live terminal demonstration of ML & MongoDB aggregations
python -m scripts.demo_live

# Run MongoDB pipeline aggregation demo ($lookup, $group)
python -m src.db_demo

# Retrain classifier or regressor directly from MongoDB
python -m src.train_classifier --source mongo
python -m src.train_regressor --source mongo
```

Sample JSON input (`data/sample_input.json`):
```json
{
  "duration": 0.05,
  "protocol": "tcp",
  "service": "http",
  "state": "syn_sent",
  "src_packets": 250,
  "dst_packets": 2,
  "dst_port": 80,
  "ttl": 64,
  "failed_logins": 0,
  "syn_flag_ratio": 0.95,
  "unique_dst_ports": 1,
  "conn_rate": 50.0
}
```

---

## 🧪 Automated Testing Suite

ThreatLens includes a 35-test verification suite covering unit and integration testing across all platform subsystems:

```powershell
pytest -v
```

```text
============================== test session starts ==============================
collected 35 items

tests/test_data_generation.py::test_dataset_shape_and_seed PASSED        [  2%]
tests/test_data_generation.py::test_protocol_and_service_distributions PASSED [  5%]
tests/test_data_loader.py::test_mongo_and_csv_loaders PASSED             [ 20%]
tests/test_database.py::test_database_connection_and_indexes PASSED      [ 45%]
tests/test_models.py::test_classifier_pipeline_fit_predict PASSED        [ 68%]
tests/test_models.py::test_regressor_pipeline_fit_predict PASSED         [ 80%]
tests/test_predict.py::test_cli_single_record_inference PASSED           [ 91%]
tests/test_preprocessing.py::test_leakage_assertion_and_splits PASSED    [100%]

============================== 35 passed in 18.42s ==============================
```

---

## 📁 Repository Structure

```text
ThreatLens-AI/
├── data/
│   ├── sample_input.json              # Sample network flow for CLI inference
│   └── traffic.csv                    # 12,000 baseline network telemetry flows
├── docs/
│   ├── MONGODB_SETUP_WINDOWS.md       # Windows MongoDB installation guide
│   └── VIVA_QA.md                     # Technical architecture & oral defense guide
├── outputs/
│   ├── classifier.joblib              # Serialized Random Forest classifier
│   ├── regressor.joblib               # Serialized Random Forest regressor
│   ├── metrics.json                   # Empirical evaluation results & baselines
│   ├── confusion_matrix.png           # Visual evaluation plots
│   ├── classifier_feature_importance.png
│   └── regressor_actual_vs_predicted.png
├── reports/
│   └── project_report.docx            # Formatted technical project report
├── scripts/
│   ├── demo_live.py                   # Automated live terminal demonstration
│   ├── generate_data.py               # Deterministic network traffic generator
│   ├── make_report.py                 # Automated Word document report builder
│   ├── make_zip.py                    # Project deliverable packaging script
│   └── run_all.bat                    # One-click Windows automation batch script
├── src/
│   ├── config.py                      # Global configuration & feature schema
│   ├── database.py                    # PyMongo client, indexing & aggregations
│   ├── data_loader.py                 # MongoDB & CSV unified data ingestion
│   ├── db_demo.py                     # MongoDB $lookup & pipeline demonstration
│   ├── evaluate.py                    # Model evaluation & metrics serialization
│   ├── predict.py                     # Unified CLI prediction engine
│   ├── preprocessing.py               # Leakage-free scikit-learn transformers
│   ├── seed_database.py               # High-throughput batch upsert engine
│   ├── train_classifier.py            # Intrusion classifier training script
│   └── train_regressor.py             # Bandwidth regressor training script
├── tests/                             # 35-test Pytest test suite
├── .env.example                       # Environment configuration template
├── .gitignore                         # Git exclusion rules
├── app.py                             # Interactive Streamlit SOC Dashboard
├── pytest.ini                         # Test runner configuration
├── requirements.txt                   # Pinned Python package dependencies
└── ThreatLens-AI-Submission.zip       # Self-contained submission archive
```

---

## 📄 License
This project is distributed under the MIT License. See `LICENSE` for details.
