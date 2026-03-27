"""

Module  : model_training.py
Purpose : Train Random Forest and XGBoost classifiers on preprocessed
          CIC-DDoS2019 data.  Evaluate with Accuracy, Precision, Recall,
          F1-Score, and ROC-AUC.  Save best models as .pkl files.
"""

import os
import sys
import time
import numpy as np

# Windows consoles often use cp1252; UTF-8 prints avoid UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass
import matplotlib
matplotlib.use("Agg")          # non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection  import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble         import RandomForestClassifier
from sklearn.metrics          import (accuracy_score, precision_score, recall_score,
                                      f1_score, roc_auc_score, confusion_matrix,
                                      classification_report, RocCurveDisplay)
import xgboost as xgb
import joblib


# PATHS


PROCESSED_DIR = "data/processed"
MODELS_DIR    = "models"
PLOTS_DIR     = "plots"

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR,  exist_ok=True)



# EVALUATION HELPER


def evaluate_model(name: str, model, X_test: np.ndarray, y_test: np.ndarray):
    """
    Print and return a dict of all required metrics.
    Also saves the confusion matrix and ROC curve to /plots.
    """
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy"  : accuracy_score(y_test, y_pred),
        "precision" : precision_score(y_test, y_pred, zero_division=0),
        "recall"    : recall_score(y_test, y_pred, zero_division=0),
        "f1_score"  : f1_score(y_test, y_pred, zero_division=0),
        "roc_auc"   : roc_auc_score(y_test, y_proba),
    }

    print(f"\n{'─'*55}")
    print(f"  Results for : {name}")
    print(f"{'─'*55}")
    for k, v in metrics.items():
        print(f"  {k:<12} : {v:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['BENIGN','ATTACK'])}")

    # ── Confusion Matrix ────────────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["BENIGN", "ATTACK"],
                yticklabels=["BENIGN", "ATTACK"], ax=ax)
    ax.set_title(f"{name} — Confusion Matrix")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    plt.tight_layout()
    cm_path = os.path.join(PLOTS_DIR, f"{name.replace(' ', '_')}_confusion_matrix.png")
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    print(f"  [✓] Confusion matrix saved → {cm_path}")

    # ── ROC Curve ───────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(6, 5))
    RocCurveDisplay.from_predictions(y_test, y_proba,
                                     name=name, ax=ax, color="steelblue")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_title(f"{name} — ROC Curve (AUC = {metrics['roc_auc']:.4f})")
    plt.tight_layout()
    roc_path = os.path.join(PLOTS_DIR, f"{name.replace(' ', '_')}_roc_curve.png")
    fig.savefig(roc_path, dpi=150)
    plt.close(fig)
    print(f"  [✓] ROC curve saved    → {roc_path}")

    return metrics


def plot_feature_importance(name: str, model, feature_names: list, top_n: int = 20):
    """Bar chart of the top-N most important features."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh([feature_names[i] for i in indices[::-1]],
            importances[indices[::-1]], color="steelblue")
    ax.set_title(f"{name} — Top {top_n} Feature Importances")
    ax.set_xlabel("Importance Score")
    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, f"{name.replace(' ', '_')}_feature_importance.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  [✓] Feature importance → {path}")


def compare_models(results: dict):
    """Side-by-side bar chart comparing both models on all metrics."""
    metrics_names = ["accuracy", "precision", "recall", "f1_score", "roc_auc"]
    model_names   = list(results.keys())
    x = np.arange(len(metrics_names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    for i, mname in enumerate(model_names):
        vals = [results[mname][m] for m in metrics_names]
        ax.bar(x + i * width, vals, width, label=mname)

    ax.set_xticks(x + width / 2)
    ax.set_xticklabels(metrics_names)
    ax.set_ylim(0.85, 1.02)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison — Random Forest vs XGBoost")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, "model_comparison.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"\n[✓] Model comparison chart → {path}")



# TRAINING PIPELINES


def train_random_forest(X_train, y_train):
    """
    Train a Random Forest classifier.
    Hyperparameters chosen for accuracy vs. inference speed balance.
    """
    print("\n═══════ Training Random Forest ═══════")
    rf = RandomForestClassifier(
        n_estimators   = 300,       # number of trees
        max_depth      = 8,        # prevent overfitting
        min_samples_split = 5,
        min_samples_leaf  = 2,
        max_features   = "sqrt",    # standard for classification
        class_weight   = "balanced",
        n_jobs         = -1,        # use all CPU cores
        random_state   = 42,
    )
    t0 = time.time()
    rf.fit(X_train, y_train)
    print(f"  Training time : {time.time() - t0:.1f}s")
    return rf


def train_xgboost(X_train, y_train):
    """
    Train an XGBoost classifier.
    scale_pos_weight handles class imbalance (more benign than attack traffic).
    """
    print("\n═══════ Training XGBoost ═══════")
    neg = int((y_train == 0).sum())
    pos = int((y_train == 1).sum())
    scale = neg / pos if pos > 0 else 1.0

    xgb_model = xgb.XGBClassifier(
        n_estimators      = 700,
        max_depth         = 8,
        learning_rate     = 0.03,
        subsample         = 0.8,
        colsample_bytree  = 0.8,
        scale_pos_weight  = scale,
        use_label_encoder = False,
        eval_metric       = "logloss",
        tree_method       = "hist",   # fast histogram method
        n_jobs            = -1,
        random_state      = 42,
    )
    t0 = time.time()
    xgb_model.fit(X_train, y_train,
                  eval_set=[(X_train, y_train)],
                  verbose=False)
    print(f"  Training time : {time.time() - t0:.1f}s")
    return xgb_model



# MAIN


def run_training():
    # ── Load preprocessed data ──────────────────────────────────────────────
    print("\n[INFO] Loading preprocessed data …")
    X = np.load(os.path.join(PROCESSED_DIR, "X.npy"))
    y = np.load(os.path.join(PROCESSED_DIR, "y.npy"))
    with open(os.path.join(PROCESSED_DIR, "feature_names.txt")) as f:
        feature_names = [line.strip() for line in f.readlines()]

    print(f"  X : {X.shape}  |  y : {y.shape}")
    print(f"  Class balance — BENIGN: {(y==0).sum()}  ATTACK: {(y==1).sum()}")

    # ── 80 / 20 Train-Test Split ─────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\n  Train samples : {len(X_train)}")
    print(f"  Test  samples : {len(X_test)}")

    results = {}

    # ── Random Forest ────────────────────────────────────────────────────────
    rf_model = train_random_forest(X_train, y_train)
    results["Random Forest"] = evaluate_model("Random Forest", rf_model, X_test, y_test)
    plot_feature_importance("Random Forest", rf_model, feature_names)

    rf_path = os.path.join(MODELS_DIR, "rf_model.pkl")
    joblib.dump(rf_model, rf_path)
    print(f"  [✓] Model saved → {rf_path}")

    # Optional: 5-fold CV score
    cv_rf = cross_val_score(rf_model, X_train, y_train,
                            cv=StratifiedKFold(5), scoring="f1", n_jobs=-1)
    print(f"  5-Fold CV F1 : {cv_rf.mean():.4f} ± {cv_rf.std():.4f}")

    # ── XGBoost ──────────────────────────────────────────────────────────────
    xgb_model = train_xgboost(X_train, y_train)
    results["XGBoost"] = evaluate_model("XGBoost", xgb_model, X_test, y_test)
    plot_feature_importance("XGBoost", xgb_model, feature_names)

    xgb_path = os.path.join(MODELS_DIR, "xgb_model.json")
    xgb_model.save_model(xgb_path)
    print(f"  [✓] Model saved → {xgb_path}")

    # ── Comparison Chart ─────────────────────────────────────────────────────
    compare_models(results)

    # ── Summary Table ────────────────────────────────────────────────────────
    print("\n" + "═"*55)
    print("  FINAL COMPARISON SUMMARY")
    print("═"*55)
    hdr = f"  {'Metric':<14}" + "".join(f"  {n:<16}" for n in results)
    print(hdr)
    print("  " + "─"*52)
    for metric in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]:
        row = f"  {metric:<14}"
        for mname in results:
            row += f"  {results[mname][metric]:.4f}          "
        print(row)
    print("═"*55)


if __name__ == "__main__":
    run_training()
