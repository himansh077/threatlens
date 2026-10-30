"""ThreatLens AI - Prediction and Inference Engine.

Provides unified inference for both Intrusion Classification and Flow Volume Regression.
Supports single-flow prediction, batch evaluation, and CLI arguments (--record-id, --sample, --input-json).
Stores prediction snapshots and inference outcomes in MongoDB collection 'predictions'.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import warnings
import joblib
import pandas as pd
import sklearn

from src.config import (
    CLASSIFIER_FEATURES,
    CLASSIFIER_MODEL_PATH,
    MODEL_VERSION,
    REGRESSOR_FEATURES,
    REGRESSOR_MODEL_PATH,
    TRAFFIC_CSV_PATH,
)
from src.database import get_db, insert_prediction, ping, serialize, to_native


def load_models() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load and validate trained classifier and regressor artifacts.

    Verifies feature lists and warns on scikit-learn version mismatch.
    """
    if not CLASSIFIER_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Classifier model missing at {CLASSIFIER_MODEL_PATH}. Run 'python -m src.train_classifier' first."
        )
    if not REGRESSOR_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Regressor model missing at {REGRESSOR_MODEL_PATH}. Run 'python -m src.train_regressor' first."
        )

    clf_art = joblib.load(CLASSIFIER_MODEL_PATH)
    reg_art = joblib.load(REGRESSOR_MODEL_PATH)

    # Check sklearn version
    current_sklearn = sklearn.__version__
    clf_sklearn = clf_art.get("sklearn_version", current_sklearn)
    if clf_sklearn != current_sklearn:
        warnings.warn(
            f"Classifier was serialized with scikit-learn {clf_sklearn}, current runtime is {current_sklearn}."
        )

    # Verify features match config
    if clf_art["features"] != CLASSIFIER_FEATURES:
        raise ValueError(
            f"Classifier feature mismatch! Model expects: {clf_art['features']}, config specifies: {CLASSIFIER_FEATURES}"
        )
    if reg_art["features"] != REGRESSOR_FEATURES:
        raise ValueError(
            f"Regressor feature mismatch! Model expects: {reg_art['features']}, config specifies: {REGRESSOR_FEATURES}"
        )

    return clf_art, reg_art


def predict_one(
    row_dict: Dict[str, Any],
    clf_artifact: Optional[Dict[str, Any]] = None,
    reg_artifact: Optional[Dict[str, Any]] = None,
    store: bool = True,
    source: str = "manual_input",
    record_id: Optional[str] = None,
    actual_label: Optional[int] = None,
    actual_total_bytes: Optional[float] = None,
) -> Dict[str, Any]:
    """Execute classification and regression on a single flow dictionary.

    Parameters
    ----------
    row_dict : Dict[str, Any]
        Feature values for the flow.
    clf_artifact : Optional[Dict]
        Pre-loaded classifier artifact.
    reg_artifact : Optional[Dict]
        Pre-loaded regressor artifact.
    store : bool
        Whether to record prediction document in MongoDB.
    source : str
        Source marker ('manual_input', 'stored_record', 'test_batch').
    record_id : Optional[str]
        Reference ID linking to traffic_records.
    actual_label : Optional[int]
        Ground-truth label if known.
    actual_total_bytes : Optional[float]
        Ground-truth bytes if known.

    Returns
    -------
    Dict[str, Any]
        Prediction results and probabilities.
    """
    if clf_artifact is None or reg_artifact is None:
        clf_loaded, reg_loaded = load_models()
        clf_art = clf_artifact or clf_loaded
        reg_art = reg_artifact or reg_loaded
    else:
        clf_art = clf_artifact
        reg_art = reg_artifact

    # Check for missing required features
    all_required = set(CLASSIFIER_FEATURES).union(set(REGRESSOR_FEATURES))
    missing_fields = [f for f in all_required if f not in row_dict]
    if missing_fields:
        raise ValueError(f"Inference input rejected: Missing required fields: {missing_fields}")

    # Build input DataFrames with exact training column order
    clf_input = pd.DataFrame([{col: row_dict[col] for col in CLASSIFIER_FEATURES}])
    reg_input = pd.DataFrame([{col: row_dict[col] for col in REGRESSOR_FEATURES}])

    # 1. Classification Inference
    clf_pipeline = clf_art["pipeline"]
    pred_label = int(clf_pipeline.predict(clf_input)[0])
    if hasattr(clf_pipeline, "predict_proba"):
        prob_attack = float(clf_pipeline.predict_proba(clf_input)[0, 1])
    else:
        prob_attack = 1.0 if pred_label == 1 else 0.0

    # 2. Regression Inference
    reg_pipeline = reg_art["pipeline"]
    pred_bytes = float(max(0.0, reg_pipeline.predict(reg_input)[0]))

    result = {
        "record_id": record_id or row_dict.get("record_id"),
        "predicted_label": pred_label,
        "attack_probability": round(prob_attack, 4),
        "predicted_total_bytes": round(pred_bytes, 2),
        "actual_label": actual_label if actual_label is not None else row_dict.get("label"),
        "actual_total_bytes": actual_total_bytes if actual_total_bytes is not None else row_dict.get("total_bytes"),
        "model_version": clf_art.get("model_version", MODEL_VERSION),
        "source": source,
    }

    # Store prediction in MongoDB if requested
    if store:
        try:
            ping()
            pred_doc = {
                "record_id": result["record_id"],
                "input_snapshot": {k: to_native(row_dict[k]) for k in CLASSIFIER_FEATURES},
                "predicted_label": result["predicted_label"],
                "attack_probability": result["attack_probability"],
                "predicted_total_bytes": result["predicted_total_bytes"],
                "actual_label": int(result["actual_label"]) if result["actual_label"] is not None else None,
                "actual_total_bytes": float(result["actual_total_bytes"]) if result["actual_total_bytes"] is not None else None,
                "model_version": result["model_version"],
                "source": result["source"],
                "created_at": datetime.now(timezone.utc),
            }
            inserted_id = insert_prediction(pred_doc)
            result["prediction_id"] = inserted_id
        except Exception as e:
            result["storage_error"] = str(e)

    return result


def predict_batch(
    df: pd.DataFrame,
    store: bool = True,
    source: str = "test_batch",
) -> pd.DataFrame:
    """Run predictions across a batch DataFrame."""
    clf_art, reg_art = load_models()
    results = []

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        res = predict_one(
            row_dict=row_dict,
            clf_artifact=clf_art,
            reg_artifact=reg_art,
            store=store,
            source=source,
            record_id=row_dict.get("record_id"),
            actual_label=row_dict.get("label"),
            actual_total_bytes=row_dict.get("total_bytes"),
        )
        results.append(res)

    return pd.DataFrame(results)


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatLens AI Prediction Engine.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--record-id",
        type=str,
        help="Fetch a flow from MongoDB traffic_records by unique record_id and predict.",
    )
    group.add_argument(
        "--sample",
        type=int,
        help="Sample N flows from the test split and evaluate.",
    )
    group.add_argument(
        "--input-json",
        type=Path,
        help="Path to JSON file containing a single flow's features.",
    )
    parser.add_argument(
        "--no-store",
        action="store_true",
        help="Do not store predictions in MongoDB predictions collection.",
    )

    args = parser.parse_args()
    store = not args.no_store

    clf_art, reg_art = load_models()

    if args.record_id:
        print(f"\n[PREDICT CLI] Fetching record '{args.record_id}' from MongoDB...")
        ping()
        db = get_db()
        doc = db["traffic_records"].find_one({"record_id": args.record_id})
        if not doc:
            print(f"Error: record_id '{args.record_id}' not found in traffic_records.", file=sys.stderr)
            sys.exit(1)

        res = predict_one(
            row_dict=doc,
            clf_artifact=clf_art,
            reg_artifact=reg_art,
            store=store,
            source="stored_record",
            record_id=args.record_id,
        )

        label_desc = "ATTACK (1)" if res["predicted_label"] == 1 else "BENIGN (0)"
        print("\n" + "=" * 60)
        print(f"PREDICTION RESULT FOR: {res['record_id']}")
        print("=" * 60)
        print(f"  Classification:      {label_desc}")
        print(f"  Attack Probability:  {res['attack_probability']:.4f}")
        print(f"  Predicted Volume:    {res['predicted_total_bytes']:,.2f} bytes")
        if res.get("actual_label") is not None:
            actual_desc = "ATTACK (1)" if res["actual_label"] == 1 else "BENIGN (0)"
            print(f"  Actual Label:        {actual_desc}")
        if res.get("actual_total_bytes") is not None:
            print(f"  Actual Total Bytes:  {res['actual_total_bytes']:,} bytes")
        if store and "prediction_id" in res:
            print(f"  Stored in DB:        YES (_id: {res['prediction_id']})")
        print("=" * 60)

    elif args.input_json:
        print(f"\n[PREDICT CLI] Loading flow from JSON: {args.input_json}...")
        if not args.input_json.exists():
            print(f"Error: JSON file '{args.input_json}' does not exist.", file=sys.stderr)
            sys.exit(1)

        with open(args.input_json, "r", encoding="utf-8") as f:
            input_data = json.load(f)

        res = predict_one(
            row_dict=input_data,
            clf_artifact=clf_art,
            reg_artifact=reg_art,
            store=store,
            source="manual_input",
            record_id=input_data.get("record_id", "MANUAL-INPUT"),
        )

        label_desc = "ATTACK (1)" if res["predicted_label"] == 1 else "BENIGN (0)"
        print("\n" + "=" * 60)
        print("MANUAL INPUT PREDICTION RESULT")
        print("=" * 60)
        print(f"  Classification:      {label_desc}")
        print(f"  Attack Probability:  {res['attack_probability']:.4f}")
        print(f"  Predicted Volume:    {res['predicted_total_bytes']:,.2f} bytes")
        if store and "prediction_id" in res:
            print(f"  Stored in DB:        YES (_id: {res['prediction_id']})")
        print("=" * 60)

    elif args.sample:
        n = args.sample
        print(f"\n[PREDICT CLI] Sampling {n} test split flows...")
        try:
            ping()
            db = get_db()
            cursor = db["traffic_records"].aggregate([
                {"$match": {"split": "test"}},
                {"$sample": {"size": n}},
            ])
            sample_docs = list(cursor)
            df_sample = pd.DataFrame(sample_docs)
        except Exception:
            df_csv = pd.read_csv(TRAFFIC_CSV_PATH)
            df_sample = df_csv[df_csv["split"] == "test"].sample(n, random_state=42)

        results_df = predict_batch(df_sample, store=store, source="test_batch")

        print("\n" + "=" * 80)
        print(f"BATCH EVALUATION RESULTS ({n} Flows):")
        print("=" * 80)
        print(f" {'Record ID':<12} | {'Pred':<8} | {'Prob':<8} | {'Pred Bytes':>12} | {'Actual':<8} | {'Actual Bytes':>12}")
        print("-" * 80)
        for _, row in results_df.iterrows():
            rec = row.get("record_id", "N/A")
            pred = "ATTACK" if row["predicted_label"] == 1 else "BENIGN"
            prob = f"{row['attack_probability']:.3f}"
            pbytes = f"{row['predicted_total_bytes']:,.0f}"
            act = "ATTACK" if row.get("actual_label") == 1 else "BENIGN"
            abytes = f"{row.get('actual_total_bytes', 0):,.0f}"
            print(f" {rec:<12} | {pred:<8} | {prob:<8} | {pbytes:>12} | {act:<8} | {abytes:>12}")
        print("=" * 80)
        if store:
            print(f"All {n} predictions successfully recorded in MongoDB 'predictions' collection.")


if __name__ == "__main__":
    main()

