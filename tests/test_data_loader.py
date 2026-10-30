"""ThreatLens AI - Data Loader & Validation Tests."""

import pytest
import pandas as pd
from scripts.generate_data import generate_synthetic_dataset
from src.data_loader import load_csv, validate_frame


@pytest.fixture
def valid_df():
    return generate_synthetic_dataset(n_flows=100, seed=42)


def test_validate_frame_success(valid_df):
    """Verify that a properly structured DataFrame passes validation."""
    assert validate_frame(valid_df) is True


def test_validate_frame_rejects_missing_column(valid_df):
    """Verify validation fails if a mandatory column is missing."""
    df_missing = valid_df.drop(columns=["duration"])
    with pytest.raises(ValueError, match="Missing required columns"):
        validate_frame(df_missing)


def test_validate_frame_rejects_duplicate_record_id(valid_df):
    """Verify validation fails if duplicate record_ids exist."""
    df_dupe = valid_df.copy()
    df_dupe.loc[1, "record_id"] = df_dupe.loc[0, "record_id"]
    with pytest.raises(ValueError, match="Duplicate record_id"):
        validate_frame(df_dupe)


def test_validate_frame_rejects_bad_label(valid_df):
    """Verify validation fails if label contains values outside {0, 1}."""
    df_bad_label = valid_df.copy()
    df_bad_label.loc[0, "label"] = 2
    with pytest.raises(ValueError, match="'label' column contains invalid values"):
        validate_frame(df_bad_label)


def test_validate_frame_rejects_negative_values(valid_df):
    """Verify validation fails if a non-negative column contains negative numbers."""
    df_neg = valid_df.copy()
    df_neg.loc[0, "src_packets"] = -5
    with pytest.raises(ValueError, match="contains .* negative values"):
        validate_frame(df_neg)


def test_validate_frame_rejects_out_of_bounds_syn_ratio(valid_df):
    """Verify validation fails if syn_flag_ratio > 1.0."""
    df_ratio = valid_df.copy()
    df_ratio.loc[0, "syn_flag_ratio"] = 1.5
    with pytest.raises(ValueError, match="syn_flag_ratio"):
        validate_frame(df_ratio)


def test_validate_frame_rejects_invalid_split(valid_df):
    """Verify validation fails if split contains non-standard labels."""
    df_split = valid_df.copy()
    df_split.loc[0, "split"] = "validation"
    with pytest.raises(ValueError, match="'split' contains invalid values"):
        validate_frame(df_split)


def test_load_csv_validates():
    """Verify load_csv loads and returns validated dataframe."""
    df = load_csv()
    assert len(df) >= 12000
    assert "split" in df.columns

