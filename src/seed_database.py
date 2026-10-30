"""ThreatLens AI - Database Seeding Script.

Loads traffic.csv, validates schema and ranges, ensures required indexes,
and performs idempotent bulk upserts into MongoDB collection 'traffic_records'.
"""

import sys
from pathlib import Path
import pandas as pd

from src.config import TRAFFIC_CSV_PATH
from src.database import ensure_indexes, get_db, ping, upsert_traffic_records
from src.data_loader import validate_frame


def seed_database() -> None:
    """Validate data and seed MongoDB with traffic records."""
    print("=" * 70)
    print("THREATLENS AI: Seeding MongoDB 'traffic_records' Collection")
    print("=" * 70)

    # 1. Connectivity Check
    print("[1/4] Verifying MongoDB connectivity...")
    ping()
    db = get_db()
    print(f"      Connected to database: '{db.name}'")

    # 2. Load & Validate CSV
    print(f"[2/4] Loading CSV from: {TRAFFIC_CSV_PATH}...")
    if not TRAFFIC_CSV_PATH.exists():
        raise FileNotFoundError(f"Traffic CSV not found at {TRAFFIC_CSV_PATH}. Run scripts/generate_data.py first.")

    df = pd.read_csv(TRAFFIC_CSV_PATH)
    print(f"      Validating {len(df):,} records with schema and domain rules...")
    validate_frame(df)
    print("      Validation check: PASSED.")

    # 3. Ensure Collection Indexes
    print("[3/4] Ensuring indexes on collections...")
    indexes = ensure_indexes(db)
    print(f"      Indexes verified for traffic_records: {indexes.get('traffic_records')}")

    # 4. Perform Idempotent Bulk Upsert
    print("[4/4] Performing bulk upsert (UpdateOne with upsert=True in batches of 1,000)...")
    res = upsert_traffic_records(df, db=db, batch_size=1000)

    print("\n" + "-" * 70)
    print("SEEDING SUMMARY:")
    print(f"  Total records in CSV:     {res['total_records']:,}")
    print(f"  Upserted (new inserts):   {res['upserted_count']:,}")
    print(f"  Modified (updated rows):  {res['modified_count']:,}")
    print(f"  Final Document Count:     {res['collection_count']:,}")
    print("-" * 70)

    if res["collection_count"] != len(df):
        raise ValueError(
            f"Document count mismatch! Expected {len(df):,}, found {res['collection_count']:,}"
        )

    print("[ACCEPTANCE CHECK] Database seeding completed successfully.")
    print("=" * 70)


def main() -> None:
    try:
        seed_database()
    except Exception as e:
        print(f"ERROR: Database seeding failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

