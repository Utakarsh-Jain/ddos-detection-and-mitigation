import os


# PATHS


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
PLOTS_DIR = os.path.join(PROJECT_ROOT, "plots")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

# Create directories if they don't exist
for directory in [MODELS_DIR, PLOTS_DIR, LOGS_DIR, PROCESSED_DATA_DIR]:
    os.makedirs(directory, exist_ok=True)

# Model file paths
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgb_model.json")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(PROCESSED_DATA_DIR, "feature_names.txt")

# Logs
AGENT_LOG_PATH = os.path.join(LOGS_DIR, "agent.log")
MITIGATION_LOG_PATH = os.path.join(LOGS_DIR, "mitigation.log")
ALERTS_CSV_PATH = os.path.join(LOGS_DIR, "alerts.csv")


# DATA PREPROCESSING


# Test / Train split
TEST_SIZE = 0.20
RANDOM_STATE = 42
STRATIFY = True


# RANDOM FOREST HYPERPARAMETERS


RF_CONFIG = {
    "n_estimators": 200,           # Number of trees
    "max_depth": 20,               # Prevent overfitting
    "min_samples_split": 5,        # Minimum samples to split a node
    "min_samples_leaf": 2,         # Minimum samples in leaf node
    "max_features": "sqrt",        # Feature selection strategy
    "class_weight": "balanced",    # Handle class imbalance
    "n_jobs": -1,                  # Use all CPU cores
    "random_state": RANDOM_STATE,
}


# XGBOOST HYPERPARAMETERS


XGBOOST_CONFIG = {
    "n_estimators": 300,
    "max_depth": 8,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "use_label_encoder": False,
    "eval_metric": "logloss",
    "tree_method": "hist",
    "n_jobs": -1,
    "random_state": RANDOM_STATE,
}

# DETECTION & MITIGATION THRESHOLDS

# Ensemble detection threshold (confidence above which flow is flagged as attack)
DETECTION_THRESHOLD = 0.60

# Ensemble weights in soft-voting
ENSEMBLE_WEIGHT_RF = 0.45
ENSEMBLE_WEIGHT_XGB = 0.55

# Mitigation confidence levels
CONFIDENCE_HARD_BLOCK = 0.95     # Immediate hard block
CONFIDENCE_RATE_LIMIT = 0.80     # Rate-limit; hard block after threshold hits
CONFIDENCE_LOG_ONLY = 0.60       # Log only

# Alert threshold (number of attacks before hard block)
ALERT_THRESHOLD = 3

# Block expiry time (seconds)
BLOCK_EXPIRY = 300  # 5 minutes


# SIMULATION & LIVE CAPTURE


# Simulation delay between flows (seconds)
SIMULATION_DELAY = 0.0

# Batch size for simulation
SIMULATION_BATCH_SIZE = 5000

# Live capture timeout (seconds)
LIVE_CAPTURE_TIMEOUT = 1


# PLOTTING & VISUALIZATION


# Plot DPI (dots per inch)
PLOT_DPI = 150

# Feature importance: top-N features to display
FEATURE_IMPORTANCE_TOP_N = 20

# Figure sizes for plots
FIGSIZE_CONFUSION_MATRIX = (5, 4)
FIGSIZE_ROC_CURVE = (6, 5)
FIGSIZE_FEATURE_IMPORTANCE = (10, 6)
FIGSIZE_MODEL_COMPARISON = (10, 6)


# CROSS-VALIDATION


CV_FOLDS = 5  # 5-fold stratified cross-validation


# LOGGING


LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = "%(asctime)s  [%(levelname)s]  %(message)s"


# FASTAPI / REST API


API_HOST = "0.0.0.0"
API_PORT = 8000
API_DEBUG = True
API_RELOAD = True


# SCALABLE PIPELINE (Kafka + Flink + Redis)


KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]
KAFKA_TOPIC = "network-flows"
KAFKA_PARTITIONS = 64

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

FLINK_JOB_NAME = "DDoS-Detection-Stream"
FLINK_PARALLELISM = 8

# ─────────────────────────────────────────────────────────────────────————————
# DISPLAY/DEBUG


# Print detailed metrics during training
VERBOSE = True

# Use dry-run mode for mitigation (log only, don't execute iptables)
DRY_RUN = os.getenv("DRY_RUN", "true").strip().lower() in {"1", "true", "yes", "on"}
