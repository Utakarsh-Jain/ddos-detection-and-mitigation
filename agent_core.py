"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           DDoS AI AGENT — CORE AGENT MODULE                                 ║
║  SRM Institute of Science and Technology | Dept. Networking & Communications ║
║  Students : Utkarsh Jaiswal  (RA2311030010011)                               ║
║             Utakarsh Jain    (RA2311030010054)                               ║
║  Guide    : Dr. Karthikeyan H, Assistant Professor                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Module  : agent_core.py
Purpose : Main agent loop.
          1. Loads trained ML models (RF + XGBoost).
          2. Accepts incoming traffic samples (dict or numpy array).
          3. Runs both models and combines predictions (ensemble vote).
          4. Calls MitigationHandler on positive detections.
          5. Exposes a FireNet simulation mode that replays a CSV file
             row-by-row to mimic live ad-hoc network traffic.

Run modes
─────────
  python agent_core.py --mode simulate --data data/raw/test_traffic.csv
  python agent_core.py --mode live     # attach to real traffic source
"""

import os
import sys
import time
import argparse
import logging
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb
from datetime import datetime

from mitigation_handler import MitigationHandler

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/agent.log"),
    ],
)
log = logging.getLogger("AgentCore")

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

RF_MODEL_PATH   = "models/rf_model.pkl"
XGB_MODEL_PATH  = "models/xgb_model.json"
SCALER_PATH     = "models/scaler.pkl"
FEATURES_PATH   = "data/processed/feature_names.txt"

DETECTION_THRESHOLD = 0.60   # probability above which a flow is flagged
ENSEMBLE_WEIGHT_RF  = 0.45   # weight for RF in soft-voting ensemble
ENSEMBLE_WEIGHT_XGB = 0.55   # XGBoost slightly higher weight (generally better)

SIMULATION_DELAY    = 0.0    # seconds between batches in simulation (0 = max speed)


# ─────────────────────────────────────────────────────────────────────────────
# DETECTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DDoSDetector:
    """
    Loads RF + XGBoost models and the scaler.  Performs per-flow inference
    using a weighted soft-voting ensemble.
    """

    def __init__(self):
        log.info("Loading ML models …")
        self.scaler  = joblib.load(SCALER_PATH)
        self.rf      = joblib.load(RF_MODEL_PATH)
        self.xgb_clf = xgb.XGBClassifier()
        self.xgb_clf.load_model(XGB_MODEL_PATH)

        with open(FEATURES_PATH) as f:
            self.feature_names = [line.strip() for line in f.readlines()]

        log.info(f"Models loaded.  Feature count: {len(self.feature_names)}")

    def _extract_features(self, flow: dict) -> np.ndarray:
        """
        Convert a flow dictionary to a scaled numpy vector.
        Missing features default to 0.
        """
        row = [float(flow.get(feat, 0.0)) for feat in self.feature_names]
        vec = np.array(row, dtype=np.float32).reshape(1, -1)
        return self.scaler.transform(vec)

    def predict(self, flow: dict) -> tuple[int, float, float, float]:
        """
        Returns (prediction, ensemble_prob, rf_prob, xgb_prob).
          prediction = 1 → ATTACK, 0 → BENIGN
        """
        X = self._extract_features(flow)

        rf_prob  = self.rf.predict_proba(X)[0, 1]
        xgb_prob = self.xgb_clf.predict_proba(X)[0, 1]

        # Weighted soft-vote
        ensemble_prob = (ENSEMBLE_WEIGHT_RF  * rf_prob +
                         ENSEMBLE_WEIGHT_XGB * xgb_prob)

        prediction = int(ensemble_prob >= DETECTION_THRESHOLD)
        return prediction, ensemble_prob, rf_prob, xgb_prob

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Batch inference on a DataFrame.  Returns df with new columns:
          pred, ensemble_prob, rf_prob, xgb_prob
        """
        # Normalize column names (strip whitespace)
        df_cols_stripped = df.columns.str.strip()
        df_copy = df.copy()
        df_copy.columns = df_cols_stripped

        available = [c for c in self.feature_names if c in df_copy.columns]
        X_raw     = df_copy[available].reindex(columns=self.feature_names, fill_value=0.0)
        X_scaled  = self.scaler.transform(X_raw.values.astype(np.float32))

        rf_probs  = self.rf.predict_proba(X_scaled)[:, 1]
        xgb_probs = self.xgb_clf.predict_proba(X_scaled)[:, 1]

        ensemble  = ENSEMBLE_WEIGHT_RF * rf_probs + ENSEMBLE_WEIGHT_XGB * xgb_probs

        df_copy["rf_prob"]       = rf_probs
        df_copy["xgb_prob"]      = xgb_probs
        df_copy["ensemble_prob"] = ensemble
        df_copy["pred"]          = (ensemble >= DETECTION_THRESHOLD).astype(int)
        return df_copy


# ─────────────────────────────────────────────────────────────────────────────
# AGENT LOOP
# ─────────────────────────────────────────────────────────────────────────────

class DDoSAgent:
    """
    Orchestrates detection + mitigation.

    Call agent.process_flow(flow_dict) to process a single flow.
    Call agent.run_simulation(csv_path) to replay a CSV file.
    """

    def __init__(self, dry_run: bool = True):
        self.detector  = DDoSDetector()
        self.mitigator = MitigationHandler(dry_run=dry_run)
        self._counters = {"processed": 0, "attacks": 0, "benign": 0}

    # ── Single-flow entry point ───────────────────────────────────────────────

    def process_flow(self, flow: dict):
        """
        Core method — call this for every new network flow.

        Expected keys in `flow` (subset of feature names):
          " Flow Duration", " Flow Bytes/s", " Destination Port",
          " Source IP" (used only for mitigation, not ML),
          etc.
        """
        self._counters["processed"] += 1

        pred, ens_prob, rf_prob, xgb_prob = self.detector.predict(flow)

        src_ip  = flow.get("Source IP",        "0.0.0.0")
        dst_port= int(flow.get("Destination Port", 0))

        if pred == 1:
            self._counters["attacks"] += 1
            log.warning(
                f"[ATTACK DETECTED]  src={src_ip}  port={dst_port}  "
                f"ensemble={ens_prob:.3f}  rf={rf_prob:.3f}  xgb={xgb_prob:.3f}"
            )
            self.mitigator.handle_alert(
                src_ip     = src_ip,
                dst_port   = dst_port,
                confidence = ens_prob,
                model_name = "Ensemble(RF+XGB)",
            )
        else:
            self._counters["benign"] += 1
            log.debug(
                f"[BENIGN]  src={src_ip}  port={dst_port}  "
                f"ensemble={ens_prob:.3f}"
            )

        return pred, ens_prob

    # ── FireNet / CSV Simulation mode ─────────────────────────────────────────

    def run_simulation(self, data_path: str, delay: float = SIMULATION_DELAY,
                       max_rows: int = None, batch_size: int = 5000):
        """
        Replay a traffic CSV/Parquet file using fast batch processing.

        Parameters
        ──────────
        data_path  : path to a CIC-DDoS2019 CSV or Parquet file
        delay      : seconds between batches (set 0 for max speed)
        max_rows   : cap rows processed (None = all)
        batch_size : number of rows per batch (default 5000)
        """
        log.info(f"[SIMULATION] Loading {data_path} …")
        if data_path.endswith(".parquet"):
            df = pd.read_parquet(data_path)
        else:
            df = pd.read_csv(data_path, encoding="utf-8", low_memory=False)
        # Normalize column names
        df.columns = df.columns.str.strip()

        if max_rows:
            df = df.head(max_rows)

        total = len(df)
        log.info(f"[SIMULATION] Starting — {total} flows  |  batch_size={batch_size}  |  delay={delay}s")

        start = time.time()

        # ── Fast batch processing instead of slow row-by-row iterrows ──────
        for batch_start in range(0, total, batch_size):
            batch_end = min(batch_start + batch_size, total)
            batch_df  = df.iloc[batch_start:batch_end]

            result_df = self.detector.predict_batch(batch_df)

            # Count attacks and benign, trigger mitigation for attacks
            attack_mask = result_df["pred"] == 1
            n_attacks   = int(attack_mask.sum())
            n_benign    = len(batch_df) - n_attacks

            self._counters["processed"] += len(batch_df)
            self._counters["attacks"]   += n_attacks
            self._counters["benign"]    += n_benign

            # Trigger mitigation for each attacking IP in the batch
            if n_attacks > 0:
                attack_rows = result_df[attack_mask]
                for _, row in attack_rows.iterrows():
                    src_ip  = row.get("Source IP", "0.0.0.0")
                    dst_port= int(row.get("Destination Port", 0))
                    conf    = row["ensemble_prob"]
                    log.warning(
                        f"[ATTACK DETECTED]  src={src_ip}  port={dst_port}  "
                        f"ensemble={conf:.3f}  rf={row['rf_prob']:.3f}  "
                        f"xgb={row['xgb_prob']:.3f}"
                    )
                    self.mitigator.handle_alert(
                        src_ip     = str(src_ip),
                        dst_port   = dst_port,
                        confidence = conf,
                        model_name = "Ensemble(RF+XGB)",
                    )

            elapsed  = time.time() - start
            fps      = self._counters["processed"] / elapsed if elapsed > 0 else 0
            log.info(
                f"[SIMULATION]  {self._counters['processed']}/{total}  "
                f"attacks={self._counters['attacks']}  "
                f"fps={fps:.0f}"
            )

            if delay > 0:
                time.sleep(delay)

        elapsed = time.time() - start
        self._print_summary(elapsed)

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self, elapsed: float = 0.0):
        c = self._counters
        m = self.mitigator.get_stats()
        print("\n" + "═"*55)
        print("  AGENT SESSION SUMMARY")
        print("═"*55)
        print(f"  Flows processed  : {c['processed']}")
        print(f"  Attacks detected : {c['attacks']}")
        print(f"  Benign flows     : {c['benign']}")
        print(f"  IPs blocked      : {m['ips_blocked']}")
        print(f"  IPs unblocked    : {m['ips_unblocked']}")
        print(f"  Ports blocked    : {m['ports_blocked']}")
        if elapsed:
            print(f"  Elapsed time     : {elapsed:.1f}s")
            print(f"  Throughput       : {c['processed']/elapsed:.0f} flows/sec")
        print("═"*55)


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="DDoS AI Agent — SRM Major Project")
    p.add_argument("--mode",    choices=["simulate", "live"], default="simulate",
                   help="Run mode: 'simulate' replays a CSV, 'live' hooks real traffic")
    p.add_argument("--data",    default="data/raw/test_traffic.csv",
                   help="Path to traffic CSV (simulation mode)")
    p.add_argument("--delay",   type=float, default=SIMULATION_DELAY,
                   help="Seconds between flows in simulation (default 0.01)")
    p.add_argument("--max_rows",type=int,   default=None,
                   help="Max rows to process (simulation mode)")
    p.add_argument(
        "--execute",
        action="store_false",
        dest="dry_run",
        default=True,
        help="Execute iptables (requires root). Default is dry-run (log only).",
    )
    return p.parse_args()


if __name__ == "__main__":
    args  = parse_args()
    agent = DDoSAgent(dry_run=args.dry_run)

    if args.mode == "simulate":
        if not os.path.exists(args.data):
            log.error(f"Data file not found: {args.data}")
            log.error("Place a CIC-DDoS2019 CSV at the path above, then re-run.")
            sys.exit(1)
        agent.run_simulation(args.data, delay=args.delay, max_rows=args.max_rows)

    elif args.mode == "live":
        # ── Live mode skeleton ─────────────────────────────────────────────
        # In a real deployment, replace this loop with a packet-capture
        # library such as Scapy or a FireNet callback.
        log.info("[LIVE MODE] Waiting for traffic flows … (Ctrl+C to stop)")
        try:
            while True:
                # TODO: Replace with actual flow ingestion
                # flow = firenet_adapter.get_next_flow()
                # agent.process_flow(flow)
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Agent stopped by user.")
            agent._print_summary()
