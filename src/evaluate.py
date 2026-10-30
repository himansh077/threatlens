"""ThreatLens AI - Model Evaluation and Visualization Module.

Evaluates trained classification and regression models strictly on the test split,
computes metrics and dummy baselines, generates visual diagnostic plots using
the matplotlib Agg backend, outputs metrics.json, and records run metrics
in MongoDB collection 'model_metrics'.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, Tuple
import uuid

import joblib
import matplotlib
matplotlib.use("Agg")  # Non-interactive, thread-safe backend for server / CLI execution
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier, DummyRegressor
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    mean_absolute_error,
    precision_score,
    r2_score,
    recall_score,
)

from src.config import (
    CLASSIFIER_MODEL_PATH,
    METRICS_JSON_PATH,
    MODEL_VERSION,
    OUTPUTS_DIR,
    RANDOM_SEED,
    REGRESSOR_MODEL_PATH,
)
from src.database import get_db, insert_metrics, ping
from src.data_loader import load_training_frame
from src.preprocessing import get_xy_classification, get_xy_regression


def evaluate_classifier(
    clf_artifact: Dict[str, Any],
    test_df: pd.DataFrame,
    train_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Evaluate Random Forest classifier on test data, alongside Dummy baseline."""
    pipeline = clf_artifact["pipeline"]
    X_test, y_test = get_xy_classification(test_df)
    X_train, y_train = get_xy_classification(train_df)

    # Predictions
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else None

    # Classification Metrics (pos_label=1, zero_division=0)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()  # [[TN, FP], [FN, TP]]

    # Dummy Baseline: Most Frequent Class
    dummy = DummyClassifier(strategy="most_frequent")
    dummy.fit(X_train, y_train)
    dummy_pred = dummy.predict(X_test)
    dummy_acc = float(accuracy_score(y_test, dummy_pred))
    dummy_f1 = float(f1_score(y_test, dummy_pred, pos_label=1, zero_division=0))

    class_dist_train = {str(k): int(v) for k, v in y_train.value_counts().items()}
    class_dist_test = {str(k): int(v) for k, v in y_test.value_counts().items()}

    return {
        "model_type": "classifier",
        "model_name": "RandomForestClassifier",
        "model_version": clf_artifact.get("model_version", MODEL_VERSION),
        "target": "label",
        "n_train": len(train_df),
        "n_test": len(test_df),
        "class_distribution": {
            "train": class_dist_train,
            "test": class_dist_test,
        },
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        },
        "confusion_matrix": cm,
        "baseline": {
            "strategy": "most_frequent",
            "accuracy": round(dummy_acc, 4),
            "f1": round(dummy_f1, 4),
            "comment": (
                "Shows why accuracy alone is deceptive: a baseline predicting always benign "
                f"achieves {dummy_acc*100:.1f}% accuracy despite zero attack detection capability."
            ),
        },
    }


def evaluate_regressor(
    reg_artifact: Dict[str, Any],
    test_df: pd.DataFrame,
    train_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Evaluate Random Forest regressor on test data, alongside Dummy baseline."""
    pipeline = reg_artifact["pipeline"]
    X_test, y_test = get_xy_regression(test_df)
    X_train, y_train = get_xy_regression(train_df)

    y_pred = pipeline.predict(X_test)

    r2 = float(r2_score(y_test, y_pred))
    mae = float(mean_absolute_error(y_test, y_pred))

    # Dummy Baseline: Predict Mean
    dummy = DummyRegressor(strategy="mean")
    dummy.fit(X_train, y_train)
    dummy_pred = dummy.predict(X_test)
    dummy_r2 = float(r2_score(y_test, dummy_pred))
    dummy_mae = float(mean_absolute_error(y_test, dummy_pred))

    return {
        "model_type": "regressor",
        "model_name": "RandomForestRegressor",
        "model_version": reg_artifact.get("model_version", MODEL_VERSION),
        "target": "total_bytes",
        "n_train": len(train_df),
        "n_test": len(test_df),
        "metrics": {
            "r2": round(r2, 4),
            "mae": round(mae, 2),
        },
        "baseline": {
            "strategy": "mean",
            "r2": round(dummy_r2, 4),
            "mae": round(dummy_mae, 2),
        },
        "mandatory_disclosure": (
            "Bytes are generated from packet counts and service packet sizes, so a high R2 "
            "partly reflects the generator structure and verifies the data/ML pipeline integrity, "
            "rather than real-world payload prediction skill."
        ),
    }


def save_plots(
    clf_eval: Dict[str, Any],
    reg_eval: Dict[str, Any],
    clf_artifact: Dict[str, Any],
    reg_artifact: Dict[str, Any],
    test_df: pd.DataFrame,
) -> Dict[str, str]:
    """Generate and save publication-quality diagnostic evaluation plots."""
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    plot_paths = {}

    # 1. Confusion Matrix Plot
    cm = np.array(clf_eval["confusion_matrix"])
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=np.arange(cm.shape[1]),
        yticks=np.arange(cm.shape[0]),
        xticklabels=["Benign (0)", "Attack (1)"],
        yticklabels=["Benign (0)", "Attack (1)"],
        title=f"Intrusion Classifier Confusion Matrix\n(Test Set N={clf_eval['n_test']})",
        ylabel="True Label",
        xlabel="Predicted Label",
    )
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, f"{cm[i, j]:,}",
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=12, fontweight="bold",
            )
    plt.tight_layout()
    cm_path = OUTPUTS_DIR / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=200)
    plt.close(fig)
    plot_paths["confusion_matrix"] = str(cm_path)

    # 2. Classifier Feature Importances
    try:
        clf_model = clf_artifact["pipeline"].named_steps["classifier"]
        preprocessor = clf_artifact["pipeline"].named_steps["preprocessor"]
        feature_names = preprocessor.get_feature_names_out()
        importances = clf_model.feature_importances_
        indices = np.argsort(importances)[::-1][:10]

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.barh(range(len(indices)), importances[indices][::-1], align="center", color="#2b5c8f")
        clean_names = [feature_names[i].replace("num__", "").replace("cat__", "") for i in indices][::-1]
        ax.set_yticks(range(len(indices)))
        ax.set_yticklabels(clean_names)
        ax.set_xlabel("Relative Importance (Gini)")
        ax.set_title("Top 10 Intrusion Classifier Features")
        plt.tight_layout()
        fi_path = OUTPUTS_DIR / "classifier_feature_importance.png"
        plt.savefig(fi_path, dpi=200)
        plt.close(fig)
        plot_paths["classifier_feature_importance"] = str(fi_path)
    except Exception as e:
        print(f"Warning: Could not plot classifier feature importance: {e}")

    # 3. Regressor Actual vs Predicted Plot
    try:
        X_test_reg, y_test_reg = get_xy_regression(test_df)
        reg_preds = reg_artifact["pipeline"].predict(X_test_reg)

        fig, ax = plt.subplots(figsize=(7, 6))
        ax.scatter(y_test_reg, reg_preds, alpha=0.35, edgecolors="none", color="#2a9d8f", s=25)
        # 45-degree reference line
        min_val = min(y_test_reg.min(), reg_preds.min())
        max_val = max(y_test_reg.max(), reg_preds.max())
        ax.plot([min_val, max_val], [min_val, max_val], "r--", lw=1.5, label="Perfect Agreement")
        ax.set_xlabel("Actual Total Bytes")
        ax.set_ylabel("Predicted Total Bytes")
        ax.set_title(f"Volume Regressor: Actual vs. Predicted\n(R2 = {reg_eval['metrics']['r2']:.4f}, MAE = {reg_eval['metrics']['mae']:,.0f} bytes)")
        ax.legend()
        plt.tight_layout()
        reg_path = OUTPUTS_DIR / "regressor_actual_vs_predicted.png"
        plt.savefig(reg_path, dpi=200)
        plt.close(fig)
        plot_paths["regressor_actual_vs_predicted"] = str(reg_path)
    except Exception as e:
        print(f"Warning: Could not plot regressor actual vs predicted: {e}")

    return plot_paths


def evaluate_models(source: str = "mongo") -> Dict[str, Any]:
    """Run full evaluation suite, save metrics.json, generate plots, and record to MongoDB."""
    print("=" * 70)
    print("THREATLENS AI: Model Evaluation Suite")
    print(f"Data source for evaluation: '{source}'")
    print("=" * 70)

    # 1. Load trained artifacts
    if not CLASSIFIER_MODEL_PATH.exists():
        raise FileNotFoundError(f"Classifier model missing at: {CLASSIFIER_MODEL_PATH}")
    if not REGRESSOR_MODEL_PATH.exists():
        raise FileNotFoundError(f"Regressor model missing at: {REGRESSOR_MODEL_PATH}")

    clf_artifact = joblib.load(CLASSIFIER_MODEL_PATH)
    reg_artifact = joblib.load(REGRESSOR_MODEL_PATH)

    # 2. Load dataset
    df = load_training_frame(source=source)
    train_df = df[df["split"] == "train"].copy()
    test_df = df[df["split"] == "test"].copy()

    print(f"Train split samples: {len(train_df):,}")
    print(f"Test split samples:  {len(test_df):,}")

    # 3. Perform Evaluations (Strictly on test split!)
    clf_eval = evaluate_classifier(clf_artifact, test_df, train_df)
    reg_eval = evaluate_regressor(reg_artifact, test_df, train_df)

    # Print summary
    print("\n--- CLASSIFIER EVALUATION METRICS (Test Set) ---")
    for k, v in clf_eval["metrics"].items():
        print(f"  {k:<12}: {v:.4f}")
    print(f"  Confusion Matrix: {clf_eval['confusion_matrix']}")
    print(f"  Baseline Acc:     {clf_eval['baseline']['accuracy']:.4f}")

    print("\n--- REGRESSOR EVALUATION METRICS (Test Set) ---")
    for k, v in reg_eval["metrics"].items():
        print(f"  {k:<12}: {v}")
    print(f"  Baseline R2:      {reg_eval['baseline']['r2']:.4f}")
    print(f"  Baseline MAE:     {reg_eval['baseline']['mae']:.2f}")

    # 4. Save Plots
    print("\nGenerating diagnostic evaluation plots...")
    plots = save_plots(clf_eval, reg_eval, clf_artifact, reg_artifact, test_df)
    for name, p in plots.items():
        print(f"  Saved {name}: {p}")

    # 5. Compile consolidated metrics.json
    metrics_summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data_source": source,
        "n_train": len(train_df),
        "n_test": len(test_df),
        "random_seed": RANDOM_SEED,
        "classifier": clf_eval,
        "regressor": reg_eval,
        "plots": plots,
        "library_versions": {
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "matplotlib": matplotlib.__version__,
        },
    }

    METRICS_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)
    print(f"\nSaved consolidated metrics to: {METRICS_JSON_PATH}")

    # 6. Record in MongoDB 'model_metrics' collection
    try:
        ping()
        run_timestamp = datetime.now(timezone.utc)
        clf_run_id = f"eval_clf_{uuid.uuid4().hex[:8]}"
        reg_run_id = f"eval_reg_{uuid.uuid4().hex[:8]}"

        doc_clf = {
            "run_id": clf_run_id,
            "model_type": "classifier",
            "model_name": clf_eval["model_name"],
            "created_at": run_timestamp,
            "metrics": clf_eval["metrics"],
            "confusion_matrix": clf_eval["confusion_matrix"],
            "class_distribution": clf_eval["class_distribution"],
            "n_train": len(train_df),
            "n_test": len(test_df),
            "random_seed": RANDOM_SEED,
            "data_source": source,
            "library_versions": metrics_summary["library_versions"],
            "baseline": clf_eval["baseline"],
        }
        insert_metrics(doc_clf)

        doc_reg = {
            "run_id": reg_run_id,
            "model_type": "regressor",
            "model_name": reg_eval["model_name"],
            "created_at": run_timestamp,
            "metrics": reg_eval["metrics"],
            "n_train": len(train_df),
            "n_test": len(test_df),
            "random_seed": RANDOM_SEED,
            "data_source": source,
            "library_versions": metrics_summary["library_versions"],
            "baseline": reg_eval["baseline"],
            "mandatory_disclosure": reg_eval["mandatory_disclosure"],
        }
        insert_metrics(doc_reg)
        print(f"Recorded 2 documents in MongoDB 'model_metrics' (IDs: {clf_run_id}, {reg_run_id})")
    except Exception as e:
        print(f"Warning: Could not record metrics in MongoDB: {e}")

    print("=" * 70)
    print("EVALUATION COMPLETED SUCCESSFULLY.")
    print("=" * 70)
    return metrics_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ThreatLens AI Models.")
    parser.add_argument(
        "--source",
        choices=["mongo", "csv"],
        default="mongo",
        help="Data source to load evaluation data from (default: mongo).",
    )
    args = parser.parse_args()

    try:
        evaluate_models(source=args.source)
    except Exception as e:
        print(f"ERROR: Model evaluation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

