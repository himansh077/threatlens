"""ThreatLens AI - Model Training & Evaluation Tests."""

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.pipeline import Pipeline

from scripts.generate_data import generate_synthetic_dataset
from src.config import (
    CATEGORICAL_CLASSIFIER_FEATURES,
    CATEGORICAL_REGRESSOR_FEATURES,
    CLASSIFIER_FEATURES,
    NUMERIC_CLASSIFIER_FEATURES,
    NUMERIC_REGRESSOR_FEATURES,
    REGRESSOR_FEATURES,
)
from src.preprocessing import (
    build_preprocessor,
    get_xy_classification,
    get_xy_regression,
)


@pytest.fixture
def small_df():
    return generate_synthetic_dataset(n_flows=300, seed=42)


def test_classifier_training_and_probability_range(small_df):
    """Verify classifier pipeline trains on small sample and yields probabilities in [0, 1]."""
    X, y = get_xy_classification(small_df)
    preprocessor = build_preprocessor(NUMERIC_CLASSIFIER_FEATURES, CATEGORICAL_CLASSIFIER_FEATURES)
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    pipeline = Pipeline([("prep", preprocessor), ("clf", clf)])

    pipeline.fit(X, y)
    preds = pipeline.predict(X)
    probs = pipeline.predict_proba(X)

    assert preds.shape == (len(small_df),)
    assert probs.shape == (len(small_df), 2)
    assert (probs >= 0.0).all() and (probs <= 1.0).all()
    # Row probabilities sum to 1
    assert np.allclose(probs.sum(axis=1), 1.0)


def test_regressor_training_and_output_shape(small_df):
    """Verify regressor pipeline trains on small sample and yields expected shape."""
    X, y = get_xy_regression(small_df)
    preprocessor = build_preprocessor(NUMERIC_REGRESSOR_FEATURES, CATEGORICAL_REGRESSOR_FEATURES)
    reg = RandomForestRegressor(n_estimators=10, random_state=42)
    pipeline = Pipeline([("prep", preprocessor), ("reg", reg)])

    pipeline.fit(X, y)
    preds = pipeline.predict(X)

    assert preds.shape == (len(small_df),)
    assert (preds >= 0).all()


def test_model_reproducibility_with_seed(small_df):
    """Verify identical random state produces identical predictions."""
    X, y = get_xy_classification(small_df)

    p1 = Pipeline([
        ("prep", build_preprocessor(NUMERIC_CLASSIFIER_FEATURES, CATEGORICAL_CLASSIFIER_FEATURES)),
        ("clf", RandomForestClassifier(n_estimators=15, random_state=42)),
    ])
    p2 = Pipeline([
        ("prep", build_preprocessor(NUMERIC_CLASSIFIER_FEATURES, CATEGORICAL_CLASSIFIER_FEATURES)),
        ("clf", RandomForestClassifier(n_estimators=15, random_state=42)),
    ])

    p1.fit(X, y)
    p2.fit(X, y)

    np.testing.assert_array_equal(p1.predict(X), p2.predict(X))


def test_inference_columns_must_match_training_columns(small_df):
    """Verify inference requires the exact feature set in config."""
    X_clf, y_clf = get_xy_classification(small_df)
    assert list(X_clf.columns) == CLASSIFIER_FEATURES

    X_reg, y_reg = get_xy_regression(small_df)
    assert list(X_reg.columns) == REGRESSOR_FEATURES

