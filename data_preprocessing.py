"""
Module  : data_preprocessing.py
Purpose : Load, clean, engineer features from CIC-DDoS2019 and save processed
          data ready for model training.

CIC-DDoS2019 Dataset : https://www.unb.ca/cic/datasets/ddos-2019.html
Place raw CSV files  : data/raw/
"""

import os
import glob
import warnings
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib

from config import RAW_DATA_DIR as CONFIG_RAW_DATA_DIR

warnings.filterwarnings("ignore")


# CONSTANTS


RAW_DATA_DIR       = os.getenv("RAW_DATA_DIR", CONFIG_RAW_DATA_DIR)
PROCESSED_DATA_DIR = "data/processed"
ENCODER_PATH       = "models/label_encoder.pkl"

# Core behavioral features aligned with the project scope
SELECTED_FEATURES = [
    # Flow-level features
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",

    # Packet-level features (rate indicators)
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Std",

    # Inter-arrival times
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Total",
    "Bwd IAT Mean",

    # Port behavior
    "Destination Port",

    # TCP flags (connection behavior)
    "SYN Flag Count",
    "ACK Flag Count",
    "PSH Flag Count",
    "URG Flag Count",
    "FIN Flag Count",
    "RST Flag Count",

    # Derived / active flow features
    "Active Mean",
    "Active Std",
    "Idle Mean",
    "Idle Std",

    # Byte rate derived
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",

    # Subflow counts
    "Subflow Fwd Packets",
    "Subflow Bwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
]

TARGET_COLUMN = "Label"



# HELPER FUNCTIONS


def load_raw_data(directory: str) -> pd.DataFrame:
    """
    Reads all CSV and/or Parquet files from `directory` and concatenates them
    into one DataFrame.  Handles BOM-encoded CSVs and mixed-column files.
    """
    csv_paths     = glob.glob(os.path.join(directory, "*.csv"))
    parquet_paths = glob.glob(os.path.join(directory, "*.parquet"))
    all_paths     = csv_paths + parquet_paths

    if not all_paths:
        raise FileNotFoundError(
            f"No CSV or Parquet files found in '{directory}'.\n"
            "Download CIC-DDoS2019 and place data files in the directory above."
        )

    print(f"[INFO] Found {len(all_paths)} data file(s)  "
          f"({len(csv_paths)} CSV, {len(parquet_paths)} Parquet):")
    frames = []
    for path in all_paths:
        print(f"       ↳ Loading {os.path.basename(path)} …")
        if path.endswith(".parquet"):
            df = pd.read_parquet(path)
        else:
            df = pd.read_csv(path, encoding="utf-8", low_memory=False)
        # Normalize column names: strip leading/trailing whitespace
        df.columns = df.columns.str.strip()
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    print(f"[INFO] Combined shape : {combined.shape}")
    return combined


def drop_irrelevant_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Drop columns that leak labels or carry no predictive signal."""
    drop_cols = [c for c in ["Flow ID", "Source IP", "Destination IP",
                              "Timestamp"] if c in df.columns]
    df = df.drop(columns=drop_cols, errors="ignore")
    return df


def handle_missing_and_infinite(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/NaN with column medians to avoid crashing the scaler."""
    df = df.replace([np.inf, -np.inf], np.nan)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    medians = df[numeric_cols].median()
    df[numeric_cols] = df[numeric_cols].fillna(medians)
    return df


def encode_labels(df: pd.DataFrame, label_col: str = TARGET_COLUMN):
    """
    Binary-encode the label column:
        BENIGN  → 0
        Any attack type → 1

    Also saves the LabelEncoder for inference use.
    """
    os.makedirs("models", exist_ok=True)
    le = LabelEncoder()
    # Handle both string labels and numeric labels (from parquet)
    raw = df[label_col].astype(str).str.strip().str.upper()
    df["label_raw"] = raw
    df["label"] = (df["label_raw"] != "BENIGN").astype(int)
    print(f"[INFO] Label distribution:\n{df['label'].value_counts().to_string()}")
    joblib.dump(le, ENCODER_PATH)
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive additional behavioral features from raw columns.

    Feature Group          | New Column
    ───────────────────────┼──────────────────────────────────────
    Packet Rate            | feat_pkt_rate     (pkts / flow_dur)
    Byte Rate              | feat_byte_rate    (bytes / flow_dur)
    Fwd/Bwd Packet Ratio   | feat_fwd_bwd_ratio
    Flag Density           | feat_flag_density (sum of flag counts / total pkts)
    """
    eps = 1e-6  # avoid division by zero

    dur   = df.get("Flow Duration",              pd.Series(eps, index=df.index)).clip(lower=eps)
    fwd_p = df.get("Total Fwd Packets",           pd.Series(0,   index=df.index))
    bwd_p = df.get("Total Backward Packets",      pd.Series(0,   index=df.index))
    fwd_b = df.get("Total Length of Fwd Packets",  pd.Series(0,  index=df.index))
    bwd_b = df.get("Total Length of Bwd Packets",  pd.Series(0,  index=df.index))

    df["feat_pkt_rate"]   = (fwd_p + bwd_p) / dur
    df["feat_byte_rate"]  = (fwd_b + bwd_b) / dur
    df["feat_fwd_bwd_ratio"] = fwd_p / (bwd_p + eps)

    flag_cols = ["SYN Flag Count", "ACK Flag Count", "PSH Flag Count",
                 "FIN Flag Count", "RST Flag Count", "URG Flag Count"]
    existing_flags = [c for c in flag_cols if c in df.columns]
    if existing_flags:
        total_flags = df[existing_flags].sum(axis=1)
        total_pkts  = (fwd_p + bwd_p).clip(lower=eps)
        df["feat_flag_density"] = total_flags / total_pkts

    print("[INFO] Engineered 4 additional behavioral features.")
    return df


def select_and_scale(df: pd.DataFrame):
    """
    1. Intersect SELECTED_FEATURES with available columns.
    2. Append engineered feature columns.
    3. Return raw feature matrix (scaling happens in model_training.py).
    4. Return (X, y, feature_names).
    """
    engineered = [c for c in df.columns if c.startswith("feat_")]
    available   = [c for c in SELECTED_FEATURES if c in df.columns]
    all_features = available + engineered

    if len(all_features) == 0:
        raise ValueError("No matching features found. Check column names in your CSV.")

    print(f"[INFO] Using {len(all_features)} features for training.")

    X = df[all_features].values.astype(np.float32)
    y = df["label"].values.astype(int)

    return X, y, all_features



# MAIN PIPELINE


def run_preprocessing():
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

    print("\n═══════ STEP 1: Load Raw CSVs ═══════")
    df = load_raw_data(RAW_DATA_DIR)

    print("\n═══════ STEP 2: Drop Irrelevant Columns ═══════")
    df = drop_irrelevant_columns(df)

    print("\n═══════ STEP 3: Handle Missing / Infinite Values ═══════")
    df = handle_missing_and_infinite(df)

    print("\n═══════ STEP 4: Encode Labels ═══════")
    df = encode_labels(df)

    print("\n═══════ STEP 5: Feature Engineering ═══════")
    df = engineer_features(df)

    print("\n═══════ STEP 6: Feature Selection & Scaling ═══════")
    X, y, feature_names = select_and_scale(df)

    # Save processed arrays
    np.save(os.path.join(PROCESSED_DATA_DIR, "X.npy"), X)
    np.save(os.path.join(PROCESSED_DATA_DIR, "y.npy"), y)

    # Save feature names list
    with open(os.path.join(PROCESSED_DATA_DIR, "feature_names.txt"), "w") as f:
        f.write("\n".join(feature_names))

    print(f"\n[✓] Preprocessing complete.")
    print(f"    X shape : {X.shape}")
    print(f"    y shape : {y.shape}")
    print(f"    Saved   : {PROCESSED_DATA_DIR}/X.npy, y.npy, feature_names.txt")
    return X, y, feature_names


if __name__ == "__main__":
    run_preprocessing()
