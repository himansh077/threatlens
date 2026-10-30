"""ThreatLens AI - Data Generation Tests."""

import pandas as pd
from scripts.generate_data import generate_synthetic_dataset
from src.data_loader import EXPECTED_COLUMNS


def test_reproducibility_same_seed():
    """Verify identical dataframes generated from identical seeds."""
    df1 = generate_synthetic_dataset(n_flows=100, seed=42)
    df2 = generate_synthetic_dataset(n_flows=100, seed=42)
    pd.testing.assert_frame_equal(df1, df2)


def test_different_seeds_produce_different_data():
    """Verify different seeds generate different random values."""
    df1 = generate_synthetic_dataset(n_flows=100, seed=42)
    df2 = generate_synthetic_dataset(n_flows=100, seed=99)
    assert not df1["duration"].equals(df2["duration"])


def test_columns_and_counts():
    """Verify all expected columns are present and flow counts match."""
    df = generate_synthetic_dataset(n_flows=200, seed=42)
    assert len(df) == 200
    for col in EXPECTED_COLUMNS:
        assert col in df.columns


def test_label_ratio():
    """Verify attack class ratio is roughly 25% (between 20% and 30%)."""
    df = generate_synthetic_dataset(n_flows=1000, seed=42)
    attack_ratio = (df["label"] == 1).mean()
    assert 0.20 <= attack_ratio <= 0.30


def test_bytes_relationship():
    """Verify total_bytes equals src_bytes + dst_bytes."""
    df = generate_synthetic_dataset(n_flows=200, seed=42)
    computed_total = df["src_bytes"] + df["dst_bytes"]
    assert (df["total_bytes"] == computed_total).all()


def test_non_negativity_and_ranges():
    """Verify packet counts, bytes, and durations are non-negative, and syn_flag_ratio in [0,1]."""
    df = generate_synthetic_dataset(n_flows=200, seed=42)
    assert (df["duration"] >= 0).all()
    assert (df["src_packets"] >= 0).all()
    assert (df["dst_packets"] >= 0).all()
    assert (df["src_bytes"] >= 0).all()
    assert (df["dst_bytes"] >= 0).all()
    assert (df["total_bytes"] >= 0).all()
    assert (df["syn_flag_ratio"] >= 0.0).all() and (df["syn_flag_ratio"] <= 1.0).all()

