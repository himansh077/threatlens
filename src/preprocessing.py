"""ThreatLens AI - Preprocessing and Feature Engineering Module.

Provides data splitting, feature extraction, preprocessor construction,
and data leakage assertions.
"""

from typing import List, Tuple
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder

from src.config import (
    CATEGORICAL_CLASSIFIER_FEATURES,
    CATEGORICAL_REGRESSOR_FEATURES,
    CLASSIFIER_EXCLUDED,
    CLASSIFIER_FEATURES,
    CLASSIFIER_TARGET,
    LEAKAGE_COLUMNS,
    NUMERIC_CLASSIFIER_FEATURES,
    NUMERIC_REGRESSOR_FEATURES,
    RANDOM_SEED,
    REGRESSOR_EXCLUDED,
    REGRESSOR_FEATURES,
    REGRESSOR_TARGET,
    TEST_SIZE,
)


def assert_no_leakage(features: List[str], target: str) -> None:
    """Verify that features do not contain the target, identifiers, or leaked data.

    Parameters
    ----------
    features : List[str]
        List of feature column names.
    target : str
        The target column name.

    Raises
    ------
    ValueError
        If target or any leakage column is found in features.
    """
    if target in features:
        raise ValueError(f"Data Leakage Detected: Target '{target}' is present in feature list.")

    forbidden_set = set(LEAKAGE_COLUMNS)
    leakage = [col for col in features if col in forbidden_set]
    if leakage:
        raise ValueError(
            f"Data Leakage Detected: Features contain forbidden leakage columns: {leakage}"
        )


def assign_split(df: pd.DataFrame, test_size: float = TEST_SIZE, random_state: int = RANDOM_SEED) -> pd.DataFrame:
    """Deterministically assign stratified train/test split.

    Parameters
    ----------
    df : pd.DataFrame
        Input dataset containing the 'label' column.
    test_size : float
        Fraction of data for test set (default 0.2).
    random_state : int
        Seed for deterministic splitting.

    Returns
    -------
    pd.DataFrame
        DataFrame with an added or updated 'split' column ('train' or 'test').
    """
    if "label" not in df.columns:
        raise ValueError("DataFrame must contain 'label' column to perform stratified splitting.")

    df = df.copy()
    indices = df.index.to_numpy()
    train_idx, test_idx = train_test_split(
        indices,
        test_size=test_size,
        stratify=df["label"],
        random_state=random_state,
    )

    df["split"] = "train"
    df.loc[test_idx, "split"] = "test"
    return df


def build_preprocessor(
    numeric_features: List[str],
    categorical_features: List[str],
) -> ColumnTransformer:
    """Construct standard ColumnTransformer for classification or regression.

    NOTE ON FEATURE SCALING:
    We deliberately do NOT apply StandardScaler or MinMaxScaler. Random Forests
    (decision-tree ensembles) are invariant to monotonic transformations of continuous
    features because splits are evaluated based on feature value order rather than magnitude.
    Omitting scaling preserves interpretability, avoids floating-point roundoff issues,
    and simplifies production deployment.

    Missing values in numeric features are handled by SimpleImputer(strategy='median')
    to be robust against synthetic heavy tails. Categorical features are encoded using
    OneHotEncoder(handle_unknown='ignore', sparse_output=False).
    """
    numeric_transformer = SimpleImputer(strategy="median")
    categorical_transformer = OneHotEncoder(handle_unknown="ignore", sparse_output=False)

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features),
            ("cat", categorical_transformer, categorical_features),
        ],
        remainder="drop",
    )
    return preprocessor


def get_xy_classification(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Extract features X and binary target y for the Intrusion Detection Classifier.

    Parameters
    ----------
    df : pd.DataFrame
        Dataset containing CLASSIFIER_FEATURES and CLASSIFIER_TARGET.

    Returns
    -------
    Tuple[pd.DataFrame, pd.Series]
        (X, y)
    """
    assert_no_leakage(CLASSIFIER_FEATURES, CLASSIFIER_TARGET)

    missing = [c for c in CLASSIFIER_FEATURES if c not in df.columns]
    if missing:
        raise KeyError(f"DataFrame is missing required classification features: {missing}")
    if CLASSIFIER_TARGET not in df.columns:
        raise KeyError(f"DataFrame is missing target column '{CLASSIFIER_TARGET}'")

    X = df[CLASSIFIER_FEATURES].copy()
    y = df[CLASSIFIER_TARGET].astype(int)
    return X, y


def get_xy_regression(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Extract features X and continuous target y for the Total Bytes Regressor.

    Parameters
    ----------
    df : pd.DataFrame
        Dataset containing REGRESSOR_FEATURES and REGRESSOR_TARGET.

    Returns
    -------
    Tuple[pd.DataFrame, pd.Series]
        (X, y)
    """
    # Strict validation: verify no label or byte leakage into features
    if any(col in REGRESSOR_FEATURES for col in REGRESSOR_EXCLUDED):
        raise ValueError("Leakage in regression features: forbidden columns detected.")

    missing = [c for c in REGRESSOR_FEATURES if c not in df.columns]
    if missing:
        raise KeyError(f"DataFrame is missing required regression features: {missing}")
    if REGRESSOR_TARGET not in df.columns:
        raise KeyError(f"DataFrame is missing regression target '{REGRESSOR_TARGET}'")

    X = df[REGRESSOR_FEATURES].copy()
    y = df[REGRESSOR_TARGET].astype(float)
    return X, y

