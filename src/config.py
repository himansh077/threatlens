"""ThreatLens AI - Configuration Module.

Single source of truth for paths, seeds, environment variables,
and machine learning feature lists.
"""

from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# Project Root and Standard Directories
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
REPORTS_DIR = PROJECT_ROOT / "reports"
DOCS_DIR = PROJECT_ROOT / "docs"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
TESTS_DIR = PROJECT_ROOT / "tests"

# Ensure directories exist
for directory in [DATA_DIR, OUTPUTS_DIR, REPORTS_DIR, DOCS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Standard File Paths
TRAFFIC_CSV_PATH = DATA_DIR / "traffic.csv"
SAMPLE_INPUT_JSON_PATH = DATA_DIR / "sample_input.json"
CLASSIFIER_MODEL_PATH = OUTPUTS_DIR / "classifier.joblib"
REGRESSOR_MODEL_PATH = OUTPUTS_DIR / "regressor.joblib"
METRICS_JSON_PATH = OUTPUTS_DIR / "metrics.json"
VERIFICATION_LOG_PATH = OUTPUTS_DIR / "verification_log.txt"

# Model Version and Reproducibility Seeds
MODEL_VERSION = "1.0.0"
RANDOM_SEED = 42
TEST_SIZE = 0.2

# MongoDB Configuration
# Default to 127.0.0.1, never localhost
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
DB_NAME = os.getenv("DB_NAME", "threatlens_db")
MONGO_TIMEOUT_MS = int(os.getenv("MONGO_TIMEOUT_MS", "3000"))

# Collection Names
TRAFFIC_COLLECTION = "traffic_records"
PREDICTIONS_COLLECTION = "predictions"
METRICS_COLLECTION = "model_metrics"

# ==============================================================================
# FEATURE LISTS (Single Source of Truth)
# ==============================================================================

# Classification Task: Binary Intrusion Detection (label: 0=normal, 1=attack)
CLASSIFIER_TARGET = "label"

CATEGORICAL_CLASSIFIER_FEATURES = [
    "protocol",
    "service",
    "state",
]

NUMERIC_CLASSIFIER_FEATURES = [
    "duration",
    "src_packets",
    "dst_packets",
    "dst_port",
    "ttl",
    "failed_logins",
    "syn_flag_ratio",
    "unique_dst_ports",
    "conn_rate",
]

CLASSIFIER_FEATURES = NUMERIC_CLASSIFIER_FEATURES + CATEGORICAL_CLASSIFIER_FEATURES

# Regression Task: Flow Volume Estimation (total_bytes)
REGRESSOR_TARGET = "total_bytes"

CATEGORICAL_REGRESSOR_FEATURES = [
    "protocol",
    "service",
    "state",
]

NUMERIC_REGRESSOR_FEATURES = [
    "duration",
    "src_packets",
    "dst_packets",
    "dst_port",
    "ttl",
    "unique_dst_ports",
    "conn_rate",
]

REGRESSOR_FEATURES = NUMERIC_REGRESSOR_FEATURES + CATEGORICAL_REGRESSOR_FEATURES

# Leakage and Metadata Columns to strictly exclude from feature sets
LEAKAGE_COLUMNS = [
    "record_id",
    "attack_type",
    "label",
    "split",
    "source",
    "imported_at",
    "src_bytes",
    "dst_bytes",
    "total_bytes",
]

# Classification Leakage Columns (cannot contain any target or future data)
CLASSIFIER_EXCLUDED = [
    "record_id",
    "attack_type",
    "label",
    "split",
    "source",
    "imported_at",
    "src_bytes",
    "dst_bytes",
    "total_bytes",
]

# Regression Leakage Columns (cannot contain bytes or intrusion labels)
REGRESSOR_EXCLUDED = [
    "src_bytes",
    "dst_bytes",
    "total_bytes",
    "label",
    "attack_type",
    "failed_logins",
    "syn_flag_ratio",
    "record_id",
    "split",
    "source",
    "imported_at",
]

