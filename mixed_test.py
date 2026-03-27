import json
from datetime import datetime
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from data_preprocessing import drop_irrelevant_columns, handle_missing_and_infinite, encode_labels, engineer_features
from agent_core import DDoSAgent

TS_FMT = "%Y-%m-%d %H:%M:%S,%f"


def model_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_attack": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_attack": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_attack": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    run_start = datetime.now()

    # 1) Load and preprocess
    p = "data/raw/UDP-testing.parquet"
    df = pd.read_parquet(p)
    df.columns = df.columns.str.strip()
    df = drop_irrelevant_columns(df)
    df = handle_missing_and_infinite(df)
    df = encode_labels(df)
    df = engineer_features(df)

    # 2) Build balanced mixed sample
    att = df[df["label"] == 1]
    ben = df[df["label"] == 0]
    n = min(len(att), len(ben), 200)
    if n == 0:
        raise SystemExit("Not enough benign/attack rows for mixed test")

    sample = (
        pd.concat([
            att.sample(n=n, random_state=7),
            ben.sample(n=n, random_state=7),
        ], ignore_index=True)
        .sample(frac=1.0, random_state=7)
        .reset_index(drop=True)
    )

    # 3) Inject endpoint identity fields for all rows
    ports = [80, 443, 53, 8080]
    for i in range(len(sample)):
        sample.at[i, "Source IP"] = "203.0.113.{}".format((i % 250) + 1)
        sample.at[i, "Destination Port"] = ports[i % len(ports)]

    # 4) Score each model + trigger mitigation from ensemble predictions
    agent = DDoSAgent(dry_run=True)
    y_true = sample["label"].astype(int).tolist()
    rf_pred = []
    xgb_pred = []
    ens_pred = []

    for _, row in sample.iterrows():
        flow = row.to_dict()
        pred, ens_prob, rf_prob, xgb_prob = agent.detector.predict(flow)

        rf_p = int(rf_prob >= 0.5)
        xgb_p = int(xgb_prob >= 0.5)

        rf_pred.append(rf_p)
        xgb_pred.append(xgb_p)
        ens_pred.append(pred)

        if pred == 1:
            agent.mitigator.handle_alert(
                src_ip=str(flow.get("Source IP")),
                dst_port=int(flow.get("Destination Port", 0)),
                confidence=float(ens_prob),
                model_name="Ensemble(RF+XGB)",
            )

    # 5) Build metric report
    report = {
        "dataset": p,
        "sample_size_total": int(len(sample)),
        "sample_size_per_class": int(n),
        "injected_source_ip": True,
        "injected_destination_port": True,
        "model_metrics": {
            "random_forest": model_metrics(y_true, rf_pred),
            "xgboost": model_metrics(y_true, xgb_pred),
            "ensemble": model_metrics(y_true, ens_pred),
        },
        "mitigation_stats": agent.mitigator.get_stats(),
        "active_blocklist_size": len(agent.mitigator.get_blocklist()),
        "run_started_at": run_start.strftime(TS_FMT),
        "run_finished_at": datetime.now().strftime(TS_FMT),
    }

    Path("logs").mkdir(exist_ok=True)
    metrics_path = Path("logs/mixed_test_with_mitigation_metrics.json")
    metrics_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # 6) Extract only mitigation.log entries from this run window
    mitigation_log = Path("logs/mitigation.log")
    excerpt_path = Path("logs/mixed_test_with_mitigation_excerpt.log")
    kept = 0
    with mitigation_log.open("r", encoding="utf-8", errors="replace") as f_in, excerpt_path.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            ts_str = line[:23]
            try:
                ts = datetime.strptime(ts_str, TS_FMT)
            except Exception:
                continue
            if ts >= run_start and (
                "[ALERT]" in line or "[BLOCKED]" in line or "[PORT-BLOCK]" in line or "[RENEW]" in line
            ):
                f_out.write(line)
                kept += 1

    print("MIXED_TEST_WITH_MITIGATION_COMPLETE")
    print("dataset=", p)
    print("sample_total=", len(sample), "per_class=", n)
    print("rf_accuracy=", round(report["model_metrics"]["random_forest"]["accuracy"], 6))
    print("xgb_accuracy=", round(report["model_metrics"]["xgboost"]["accuracy"], 6))
    print("ensemble_accuracy=", round(report["model_metrics"]["ensemble"]["accuracy"], 6))
    print("ensemble_confusion=", report["model_metrics"]["ensemble"]["confusion_matrix"])
    print("mitigation_stats=", report["mitigation_stats"])
    print("excerpt_lines=", kept)
    print("metrics_file=", metrics_path.as_posix())
    print("excerpt_file=", excerpt_path.as_posix())


if __name__ == "__main__":
    main()
