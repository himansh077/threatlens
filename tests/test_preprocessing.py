"""ThreatLens AI - Preprocessing and Split Tests."""

import pytest
import pandas as pd
from scripts.generate_data import generate_synthetic_dataset
from src.config import (
    CATEGORICAL_CLASSIFIER_FEATURES,
    CLASSIFIER_FEATURES,
    CLASSIFIER_TARGET,
    LEAKAGE_COLUMNS,
    NUMERIC_CLASSIFIER_FEATURES,
    REGRESSOR_EXCLUDED,
    REGRESSOR_FEATURES,
    REGRESSOR_TARGET,
)
from src.preprocessing import (
    assert_no_leakage,
    assign_split,
    build_preprocessor,
    get_xy_classification,
    get_xy_regression,
)


@pytest.fixture
def sample_df():
    return generate_synthetic_dataset(n_flows=500, seed=42)


def test_stratified_split_proportions(sample_df):
    """Verify split is 80/20 and preserves label proportions."""
    df_split = assign_split(sample_df, test_size=0.2, random_state=42)
    n_total = len(df_split)
    n_test = (df_split["split"] == "test").sum()
    assert n_test == int(n_total * 0.2)

    p_train = (df_split[df_split["split"] == "train"]["label"] == 1).mean()
    p_test = (df_split[df_split["split"] == "test"]["label"] == 1).mean()
    assert abs(p_train - p_test) < 0.05


def test_split_disjoint(sample_df):
    """Verify train and test record IDs have zero overlap."""
    df_split = assign_split(sample_df, test_size=0.2, random_state=42)
    train_ids = set(df_split[df_split["split"] == "train"]["record_id"])
    test_ids = set(df_split[df_split["split"] == "test"]["record_id"])
    assert len(train_ids.intersection(test_ids)) == 0


def test_deterministic_split(sample_df):
    """Verify same random state yields identical splits."""
    s1 = assign_split(sample_df.copy(), random_state=42)["split"]
    s2 = assign_split(sample_df.copy(), random_state=42)["split"]
    assert s1.equals(s2)


def test_assert_no_leakage_passes_valid_features():
    """Verify valid features pass leakage check."""
    assert_no_leakage(CLASSIFIER_FEATURES, CLASSIFIER_TARGET)


def test_assert_no_leakage_catches_target():
    """Verify leakage check catches target in features."""
    with pytest.raises(ValueError, match="Target .* is present in feature list"):
        assert_no_leakage(CLASSIFIER_FEATURES + [CLASSIFIER_TARGET], CLASSIFIER_TARGET)


def test_assert_no_leakage_catches_leakage_column():
    """Verify leakage check catches bytes or identifiers."""
    for leak_col in LEAKAGE_COLUMNS:
        with pytest.raises(ValueError, match="Data Leakage Detected"):
            assert_no_leakage(CLASSIFIER_FEATURES + [leak_col], CLASSIFIER_TARGET)


def test_regression_features_exclude_labels_and_bytes():
    """Verify regressor features do not contain label, attack_type, or bytes."""
    for forbidden in REGRESSOR_EXCLUDED:
        assert forbidden not in REGRESSOR_FEATURES


def test_imputer_statistics_isolated_to_train(sample_df):
    """Verify preprocessor calculates imputer medians exclusively from training data."""
    train_df = sample_df[sample_df["split"] == "train"].copy()
    test_df = sample_df[sample_df["split"] == "test"].copy()

    preprocessor = build_preprocessor(
        numeric_features=NUMERIC_CLASSIFIER_FEATURES,
        categorical_features=CATEGORICAL_CLASSIFIER_FEATURES,
    )

    X_train, _ = get_xy_classification(train_df)
    X_test, _ = get_xy_classification(test_df)

    # Fit only on train
    preprocessor.fit(X_train)
    num_imputer = preprocessor.named_transformers_["num"]

    # Verify fitted medians match training medians
    expected_medians = X_train[NUMERIC_CLASSIFIER_FEATURES].median().values
    actual_medians = num_imputer.statistics_
    assert (expected_medians == actual_medians).all()

