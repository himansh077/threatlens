"""ThreatLens AI - Classification Training Module.

Trains a Random Forest classifier to detect network intrusions
(binary classification: 0=normal, 1=attack) on training split only.
"""

import argparse
from datetime import datetime, timezone
import sys
from pathlib import Path
import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from src.config import (
    CATEGORICAL_CLASSIFIER_FEATURES,
    CLASSIFIER_FEATURES,
    CLASSIFIER_MODEL_PATH,
    CLASSIFIER_TARGET,
    MODEL_VERSION,
    NUMERIC_CLASSIFIER_FEATURES,
    RANDOM_SEED,
)
from src.data_loader import load_training_frame
from src.preprocessing import build_preprocessor, get_xy_classification


def train_classifier(source: str = "mongo") -> Path:
    """Train RandomForestClassifier on train split and save serialized model artifact.

    Parameters
    ----------
    source : str
        Data source: 'mongo' (default) or 'csv'.

    Returns
    -------
    Path
        Path to the saved model artifact.
    """
    print(f"[CLASSIFIER TRAINING] Loading dataset from source: '{source}'...")
    df = load_training_frame(source=source)

    # STRICT: Train on train split only!
    train_df = df[df["split"] == "train"].copy()
    if train_df.empty:
        raise ValueError("Training set is empty. Cannot train classifier.")

    print(f"[CLASSIFIER TRAINING] Training samples: {len(train_df):,} flows")
    X_train, y_train = get_xy_classification(train_df)

    # Build Pipeline with ColumnTransformer preprocessor and RandomForestClassifier
    # Note: Decision tree ensembles do not require monotonic feature scaling
    preprocessor = build_preprocessor(
        numeric_features=NUMERIC_CLASSIFIER_FEATURES,
        categorical_features=CATEGORICAL_CLASSIFIER_FEATURES,
    )

    classifier = RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )

    print("[CLASSIFIER TRAINING] Fitting RandomForestClassifier pipeline...")
    pipeline.fit(X_train, y_train)

    # Package artifact with reproducibility metadata
    artifact = {
        "pipeline": pipeline,
        "features": list(CLASSIFIER_FEATURES),
        "target": CLASSIFIER_TARGET,
        "model_version": MODEL_VERSION,
        "seed": RANDOM_SEED,
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_source": source,
        "n_train": len(X_train),
    }

    CLASSIFIER_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, CLASSIFIER_MODEL_PATH)
    print(f"[CLASSIFIER TRAINING] Artifact successfully saved to: {CLASSIFIER_MODEL_PATH}")
    return CLASSIFIER_MODEL_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="Train ThreatLens AI Intrusion Detection Classifier.")
    parser.add_argument(
        "--source",
        choices=["mongo", "csv"],
        default="mongo",
        help="Data source to load training data from (default: mongo).",
    )
    args = parser.parse_args()

    try:
        train_classifier(source=args.source)
    except Exception as e:
        print(f"ERROR: Classifier training failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

