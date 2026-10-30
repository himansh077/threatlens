"""ThreatLens AI - Data Loader and Validation Module.

Provides CSV loading, schema and range validation, split verification,
and training frame loading from either MongoDB or CSV.
"""

from pathlib import Path
from typing import List, Optional
import pandas as pd

from src.config import TRAFFIC_CSV_PATH
from src.preprocessing import assign_split

# Expected columns for full flow records
EXPECTED_COLUMNS: List[str] = [
    "record_id",
    "duration",
    "protocol",
    "service",
    "state",
    "src_packets",
    "dst_packets",
    "dst_port",
    "ttl",
    "failed_logins",
    "syn_flag_ratio",
    "unique_dst_ports",
    "conn_rate",
    "src_bytes",
    "dst_bytes",
    "total_bytes",
    "label",
    "attack_type",
    "split",
    "source",
]

NON_NEGATIVE_NUMERIC_COLS: List[str] = [
    "duration",
    "src_packets",
    "dst_packets",
    "dst_port",
    "ttl",
    "failed_logins",
    "syn_flag_ratio",
    "unique_dst_ports",
    "conn_rate",
    "src_bytes",
    "dst_bytes",
    "total_bytes",
]


def validate_frame(df: pd.DataFrame) -> bool:
    """Validate DataFrame integrity, required columns, datatypes, ranges, and uniqueness.

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame to validate.

    Returns
    -------
    bool
        True if all checks pass.

    Raises
    ------
    ValueError
        If any validation rule fails.
    """
    if df.empty:
        raise ValueError("Validation failed: DataFrame is empty.")

    # 1. Required columns presence
    missing_cols = [c for c in EXPECTED_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Validation failed: Missing required columns: {missing_cols}")

    # 2. Unique record_id
    if df["record_id"].duplicated().any():
        duplicate_ids = df[df["record_id"].duplicated()]["record_id"].head(5).tolist()
        raise ValueError(
            f"Validation failed: Duplicate record_id values found: {duplicate_ids}"
        )

    # 3. Label domain check: must be in {0, 1}
    unique_labels = set(df["label"].unique())
    if not unique_labels.issubset({0, 1}):
        raise ValueError(
            f"Validation failed: 'label' column contains invalid values: {unique_labels}. Must be in {{0, 1}}."
        )

    # 4. Non-negative numeric columns
    for col in NON_NEGATIVE_NUMERIC_COLS:
        if (df[col] < 0).any():
            invalid_cnt = (df[col] < 0).sum()
            raise ValueError(
                f"Validation failed: Column '{col}' contains {invalid_cnt} negative values."
            )

    # 5. Syn flag ratio must be between 0.0 and 1.0
    if ((df["syn_flag_ratio"] < 0.0) | (df["syn_flag_ratio"] > 1.0)).any():
        raise ValueError("Validation failed: syn_flag_ratio contains values outside [0.0, 1.0].")

    # 6. Split values check
    split_values = set(df["split"].unique())
    if not split_values.issubset({"train", "test"}):
        raise ValueError(
            f"Validation failed: 'split' contains invalid values: {split_values}. Must be 'train' or 'test'."
        )

    return True


def ensure_split(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure that the split column is present and properly populated.

    If missing or improperly formatted, computes stratified 80/20 train/test split.
    """
    if "split" not in df.columns or not set(df["split"].unique()).issubset({"train", "test"}):
        return assign_split(df)
    return df


def load_csv(csv_path: Optional[Path] = None) -> pd.DataFrame:
    """Load traffic records from CSV file with schema and integrity validation.

    Parameters
    ----------
    csv_path : Optional[Path]
        Path to CSV file. Defaults to config.TRAFFIC_CSV_PATH.

    Returns
    -------
    pd.DataFrame
        Validated DataFrame.
    """
    path = csv_path or TRAFFIC_CSV_PATH
    if not Path(path).exists():
        raise FileNotFoundError(f"Traffic CSV file not found at: {path}")

    df = pd.read_csv(path)
    df = ensure_split(df)
    validate_frame(df)
    return df


def load_training_frame(source: str = "mongo") -> pd.DataFrame:
    """Load dataset for training from either MongoDB or CSV.

    NO SILENT FALLBACK:
    If source='mongo', will attempt to load directly from MongoDB.
    If MongoDB is unreachable, it raises MongoUnavailableError.
    If source='csv', loads directly from the local traffic.csv.
    """
    source_lower = source.strip().lower()

    if source_lower == "csv":
        return load_csv(TRAFFIC_CSV_PATH)
    elif source_lower == "mongo":
        from src.database import load_records_df

        df = load_records_df()
        if df.empty:
            raise ValueError(
                "MongoDB collection 'traffic_records' is empty. "
                "Run 'python -m src.seed_database' first or use '--source csv'."
            )
        validate_frame(df)
        return df
    else:
        raise ValueError(f"Unknown data source '{source}'. Expected 'mongo' or 'csv'.")

