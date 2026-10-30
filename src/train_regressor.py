"""ThreatLens AI - Regression Training Module.

Trains a Random Forest regressor to estimate network flow volume
(total bytes transferred) for network capacity planning and traffic baselining.

MANDATORY DISCLOSURE:
In this synthetic dataset, flow bytes are derived from packet counts, protocol
characteristics, and service packet size distributions. Consequently, a high R2
score primarily demonstrates that the end-to-end data pipeline, feature encoding,
and regression architecture function correctly as designed, rather than empirical
real-world network payload estimation skill.
"""

import argparse
from datetime import datetime, timezone
import sys
from pathlib import Path
import joblib
import sklearn
from sklearn.ensemble import RandomForestRegressor
from sklearn.pipeline import Pipeline

from src.config import (
    CATEGORICAL_REGRESSOR_FEATURES,
    MODEL_VERSION,
    NUMERIC_REGRESSOR_FEATURES,
    RANDOM_SEED,
    REGRESSOR_FEATURES,
    REGRESSOR_MODEL_PATH,
    REGRESSOR_TARGET,
)
from src.data_loader import load_training_frame
from src.preprocessing import build_preprocessor, get_xy_regression


def train_regressor(source: str = "mongo") -> Path:
    """Train RandomForestRegressor on train split and save serialized model artifact.

    Parameters
    ----------
    source : str
        Data source: 'mongo' (default) or 'csv'.

    Returns
    -------
    Path
        Path to the saved model artifact.
    """
    print(f"[REGRESSOR TRAINING] Loading dataset from source: '{source}'...")
    df = load_training_frame(source=source)

    # STRICT: Train on train split only!
    train_df = df[df["split"] == "train"].copy()
    if train_df.empty:
        raise ValueError("Training set is empty. Cannot train regressor.")

    print(f"[REGRESSOR TRAINING] Training samples: {len(train_df):,} flows")
    X_train, y_train = get_xy_regression(train_df)

    # Build Pipeline with ColumnTransformer preprocessor and RandomForestRegressor
    preprocessor = build_preprocessor(
        numeric_features=NUMERIC_REGRESSOR_FEATURES,
        categorical_features=CATEGORICAL_REGRESSOR_FEATURES,
    )

    regressor = RandomForestRegressor(
        n_estimators=200,
        min_samples_leaf=2,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("regressor", regressor),
        ]
    )

    print("[REGRESSOR TRAINING] Fitting RandomForestRegressor pipeline...")
    pipeline.fit(X_train, y_train)

    # Package artifact with reproducibility metadata
    artifact = {
        "pipeline": pipeline,
        "features": list(REGRESSOR_FEATURES),
        "target": REGRESSOR_TARGET,
        "model_version": MODEL_VERSION,
        "seed": RANDOM_SEED,
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_source": source,
        "n_train": len(X_train),
    }

    REGRESSOR_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, REGRESSOR_MODEL_PATH)
    print(f"[REGRESSOR TRAINING] Artifact successfully saved to: {REGRESSOR_MODEL_PATH}")
    return REGRESSOR_MODEL_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="Train ThreatLens AI Flow Volume Regressor.")
    parser.add_argument(
        "--source",
        choices=["mongo", "csv"],
        default="mongo",
        help="Data source to load training data from (default: mongo).",
    )
    args = parser.parse_args()

    try:
        train_regressor(source=args.source)
    except Exception as e:
        print(f"ERROR: Regressor training failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

