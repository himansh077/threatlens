"""ThreatLens AI - MongoDB Database Layer Tests.

Operates on throwaway database 'threatlens_test_db', dropped upon session teardown.
"""

from datetime import datetime, timezone
from bson import ObjectId
import numpy as np
import pytest
from pymongo.errors import DuplicateKeyError

from scripts.generate_data import generate_synthetic_dataset
from src.config import TRAFFIC_COLLECTION
from src.database import (
    aggregate_by_attack_type,
    ensure_indexes,
    serialize,
    to_native,
    upsert_traffic_records,
)


def test_serialize_handles_objectid_and_datetime():
    """Verify serialize converts ObjectId to str and datetime to ISO format."""
    oid = ObjectId()
    now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    raw_doc = {
        "_id": oid,
        "created_at": now,
        "nested": {"id": oid, "count": np.int64(42)},
        "val_float": np.float64(3.1415),
    }

    serialized = serialize(raw_doc)
    assert serialized["_id"] == str(oid)
    assert serialized["created_at"] == now.isoformat()
    assert serialized["nested"]["id"] == str(oid)
    assert isinstance(serialized["nested"]["count"], int)
    assert isinstance(serialized["val_float"], float)


def test_to_native_numpy_types():
    """Verify numpy scalar types convert to native Python primitives."""
    n_int = np.int64(100)
    n_flt = np.float64(99.9)
    n_bool = np.bool_(True)
    n_arr = np.array([1, 2, 3], dtype=np.int64)

    assert isinstance(to_native(n_int), int)
    assert isinstance(to_native(n_flt), float)
    assert isinstance(to_native(n_bool), bool)
    assert isinstance(to_native(n_arr), list)
    assert isinstance(to_native(n_arr)[0], int)


def test_numpy_types_insert_ok(test_db):
    """Verify document containing numpy scalar types can be inserted into MongoDB."""
    col = test_db["test_numpy_col"]
    doc = {
        "record_id": "TL-NP-001",
        "int_field": to_native(np.int64(12345)),
        "float_field": to_native(np.float64(45.67)),
        "bool_field": to_native(np.bool_(False)),
    }
    res = col.insert_one(doc)
    assert res.inserted_id is not None
    retrieved = col.find_one({"record_id": "TL-NP-001"})
    assert retrieved["int_field"] == 12345
    assert retrieved["float_field"] == 45.67


def test_unique_index_rejects_duplicates(test_db):
    """Verify unique record_id index prevents duplicate document inserts."""
    ensure_indexes(test_db)
    col = test_db[TRAFFIC_COLLECTION]
    doc1 = {"record_id": "TL-DUPE-TEST", "service": "http", "total_bytes": 100}
    doc2 = {"record_id": "TL-DUPE-TEST", "service": "dns", "total_bytes": 200}

    col.insert_one(doc1)
    with pytest.raises(DuplicateKeyError):
        col.insert_one(doc2)


def test_idempotent_seeding(test_db):
    """Verify running upsert twice maintains the exact same document count."""
    ensure_indexes(test_db)
    sample_df = generate_synthetic_dataset(n_flows=50, seed=42)

    # First seeding
    res1 = upsert_traffic_records(sample_df, db=test_db, batch_size=25)
    assert res1["collection_count"] == 50
    assert res1["upserted_count"] == 50
    assert res1["modified_count"] == 0

    # Second seeding (idempotent run)
    res2 = upsert_traffic_records(sample_df, db=test_db, batch_size=25)
    assert res2["collection_count"] == 50
    assert res2["upserted_count"] == 0
    assert res2["modified_count"] == 50


def test_aggregation_pipeline_result(test_db):
    """Verify aggregation pipeline computes correct flow counts and averages."""
    ensure_indexes(test_db)
    df = generate_synthetic_dataset(n_flows=100, seed=42)
    upsert_traffic_records(df, db=test_db)

    agg = aggregate_by_attack_type(db=test_db)
    assert len(agg) >= 2
    total_counted = sum(row["flow_count"] for row in agg)
    assert total_counted == 100
    for row in agg:
        assert "attack_type" in row
        assert row["avg_total_bytes"] >= 0
        assert row["avg_duration"] >= 0

