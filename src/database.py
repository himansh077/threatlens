"""ThreatLens AI - MongoDB Database Layer.

Handles database connections, index management, idempotent bulk upserts,
document serialization, type conversions, queries, and aggregations.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
from bson import ObjectId
import numpy as np
import pandas as pd
import pymongo
from pymongo import ASCENDING, DESCENDING, MongoClient, UpdateOne
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, PyMongoError, ServerSelectionTimeoutError

from src.config import (
    DB_NAME,
    METRICS_COLLECTION,
    MONGO_TIMEOUT_MS,
    MONGO_URI,
    PREDICTIONS_COLLECTION,
    TRAFFIC_COLLECTION,
)


class MongoUnavailableError(Exception):
    """Raised when MongoDB cannot be reached within configured timeout."""
    pass


_client: Optional[MongoClient] = None


def mask_uri(uri: str) -> str:
    """Mask credentials in MongoDB connection string for safe logging."""
    if not uri:
        return ""
    # Matches ://<username>:<password>@
    return re.sub(r"://([^:@]+):([^@]+)@", r"://\1:****@", uri)


def to_native(val: Any) -> Any:
    """Convert numpy scalars and non-standard types to native Python types for PyMongo.

    PyMongo cannot encode numpy.int64, numpy.float64, numpy.bool_, etc.
    Recursively converts dictionaries, lists, and primitives.
    """
    if isinstance(val, (np.integer, np.int64, np.int32, np.int16, np.int8)):
        return int(val)
    elif isinstance(val, (np.floating, np.float64, np.float32)):
        return float(val)
    elif isinstance(val, (np.bool_, bool)):
        return bool(val)
    elif isinstance(val, np.ndarray):
        return [to_native(x) for x in val.tolist()]
    elif isinstance(val, dict):
        return {k: to_native(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple, set)):
        return [to_native(x) for x in val]
    return val


def serialize(doc: Any) -> Any:
    """Serialize MongoDB documents into JSON-safe dictionaries.

    Converts ObjectId to str, datetime to ISO format string, and numpy to native.
    """
    if isinstance(doc, dict):
        out = {}
        for k, v in doc.items():
            if isinstance(v, ObjectId):
                out[k] = str(v)
            elif isinstance(v, datetime):
                out[k] = v.isoformat()
            elif isinstance(v, dict):
                out[k] = serialize(v)
            elif isinstance(v, (list, tuple)):
                out[k] = [serialize(x) for x in v]
            else:
                out[k] = to_native(v)
        return out
    elif isinstance(doc, list):
        return [serialize(x) for x in doc]
    elif isinstance(doc, ObjectId):
        return str(doc)
    elif isinstance(doc, datetime):
        return doc.isoformat()
    return to_native(doc)


def get_client(uri: Optional[str] = None, timeout_ms: Optional[int] = None) -> MongoClient:
    """Lazily construct or return singleton MongoClient instance, or a custom one if parameters provided."""
    global _client
    target_uri = uri or MONGO_URI
    target_timeout = timeout_ms or MONGO_TIMEOUT_MS

    if uri is not None or timeout_ms is not None:
        return MongoClient(
            target_uri,
            serverSelectionTimeoutMS=target_timeout,
            connectTimeoutMS=target_timeout,
        )

    if _client is None:
        _client = MongoClient(
            target_uri,
            serverSelectionTimeoutMS=target_timeout,
            connectTimeoutMS=target_timeout,
        )

    return _client


def ping(client: Optional[MongoClient] = None) -> bool:
    """Test connectivity to MongoDB server."""
    cli = client if client is not None else get_client()
    try:
        cli.admin.command("ping")
        return True
    except (ServerSelectionTimeoutError, ConnectionFailure, PyMongoError) as e:
        conn_str = MONGO_URI
        # Try to retrieve connection string from client if available
        try:
            conn_str = cli.HOST or MONGO_URI
            if hasattr(cli, "_topology_settings") and hasattr(cli._topology_settings, "seeds"):
                seeds = cli._topology_settings.seeds
                conn_str = f"mongodb://{seeds[0][0]}:{seeds[0][1]}"
        except Exception:
            pass
        masked = mask_uri(conn_str)
        raise MongoUnavailableError(
            f"Cannot reach MongoDB at {masked}. Start the MongoDB service (see docs/MONGODB_SETUP_WINDOWS.md)."
        ) from e


def get_db(db_name: Optional[str] = None, client: Optional[MongoClient] = None) -> Database:
    """Retrieve MongoDB database instance after verifying connectivity."""
    cli = client or get_client()
    ping(cli)
    return cli[db_name or DB_NAME]


def ensure_indexes(db: Optional[Database] = None) -> Dict[str, List[str]]:
    """Ensure required indexes are created on traffic_records, predictions, and model_metrics.

    Indexes:
    - traffic_records: unique record_id; compound (label, attack_type); split.
    - predictions: (record_id, model_version); created_at descending.
    - model_metrics: unique run_id; (model_type, created_at descending).
    """
    database = db if db is not None else get_db()
    index_results = {}

    # traffic_records indexes
    traffic_col: Collection = database[TRAFFIC_COLLECTION]
    traffic_col.create_index([("record_id", ASCENDING)], unique=True, name="uniq_record_id")
    traffic_col.create_index([("label", ASCENDING), ("attack_type", ASCENDING)], name="compound_label_attack")
    traffic_col.create_index([("split", ASCENDING)], name="idx_split")
    index_results[TRAFFIC_COLLECTION] = list(traffic_col.index_information().keys())

    # predictions indexes
    pred_col: Collection = database[PREDICTIONS_COLLECTION]
    pred_col.create_index([("record_id", ASCENDING), ("model_version", ASCENDING)], name="compound_rec_model")
    pred_col.create_index([("created_at", DESCENDING)], name="idx_created_at_desc")
    index_results[PREDICTIONS_COLLECTION] = list(pred_col.index_information().keys())

    # model_metrics indexes
    metrics_col: Collection = database[METRICS_COLLECTION]
    metrics_col.create_index([("run_id", ASCENDING)], unique=True, name="uniq_run_id")
    metrics_col.create_index([("model_type", ASCENDING), ("created_at", DESCENDING)], name="compound_model_created")
    index_results[METRICS_COLLECTION] = list(metrics_col.index_information().keys())

    return index_results


def upsert_traffic_records(
    df: pd.DataFrame,
    db: Optional[Database] = None,
    batch_size: int = 1000,
) -> Dict[str, int]:
    """Bulk upsert traffic records into traffic_records collection idempotently.

    Re-running this function on identical data will modify or maintain existing records
    without altering document count.
    """
    database = db if db is not None else get_db()
    ensure_indexes(database)
    col: Collection = database[TRAFFIC_COLLECTION]

    now = datetime.now(timezone.utc)
    records = df.to_dict(orient="records")

    total_upserted = 0
    total_modified = 0

    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        operations = []
        for r in batch:
            doc = to_native(r)
            doc["imported_at"] = now
            operations.append(
                UpdateOne(
                    {"record_id": doc["record_id"]},
                    {"$set": doc},
                    upsert=True,
                )
            )
        if operations:
            res = col.bulk_write(operations, ordered=False)
            total_upserted += res.upserted_count
            total_modified += res.modified_count

    return {
        "total_records": len(df),
        "upserted_count": total_upserted,
        "modified_count": total_modified,
        "collection_count": col.count_documents({}),
    }


def load_records_df(
    filter_query: Optional[Dict[str, Any]] = None,
    db: Optional[Database] = None,
) -> pd.DataFrame:
    """Load documents from traffic_records collection as a pandas DataFrame."""
    database = db if db is not None else get_db()
    col: Collection = database[TRAFFIC_COLLECTION]
    cursor = col.find(filter_query or {}, {"_id": 0})
    records = list(cursor)
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)


def find_records(
    filter_query: Optional[Dict[str, Any]] = None,
    sort_fields: Optional[List[tuple]] = None,
    limit: int = 50,
    db: Optional[Database] = None,
) -> List[Dict[str, Any]]:
    """Query documents from traffic_records collection."""
    database = db if db is not None else get_db()
    col: Collection = database[TRAFFIC_COLLECTION]
    query = filter_query or {}
    cursor = col.find(query)
    if sort_fields:
        cursor = cursor.sort(sort_fields)
    if limit > 0:
        cursor = cursor.limit(limit)
    return [serialize(doc) for doc in cursor]


def insert_prediction(
    prediction_doc: Dict[str, Any],
    db: Optional[Database] = None,
) -> str:
    """Insert a prediction document into the predictions collection."""
    database = db if db is not None else get_db()
    col: Collection = database[PREDICTIONS_COLLECTION]

    doc = to_native(prediction_doc)
    if "created_at" not in doc:
        doc["created_at"] = datetime.now(timezone.utc)

    result = col.insert_one(doc)
    return str(result.inserted_id)


def insert_metrics(
    metrics_doc: Dict[str, Any],
    db: Optional[Database] = None,
) -> str:
    """Insert an evaluation record into model_metrics collection."""
    database = db if db is not None else get_db()
    col: Collection = database[METRICS_COLLECTION]

    doc = to_native(metrics_doc)
    if "created_at" not in doc:
        doc["created_at"] = datetime.now(timezone.utc)

    # Upsert by run_id for idempotency
    col.update_one(
        {"run_id": doc["run_id"]},
        {"$set": doc},
        upsert=True,
    )
    return str(doc["run_id"])


def latest_metrics(
    model_type: str,
    db: Optional[Database] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch the most recent evaluation record for classifier or regressor."""
    database = db if db is not None else get_db()
    col: Collection = database[METRICS_COLLECTION]
    doc = col.find_one(
        {"model_type": model_type},
        sort=[("created_at", DESCENDING)],
    )
    return serialize(doc) if doc else None


def aggregate_by_attack_type(db: Optional[Database] = None) -> List[Dict[str, Any]]:
    """Aggregate traffic records by attack_type: count, avg total_bytes, avg duration."""
    database = db if db is not None else get_db()
    col: Collection = database[TRAFFIC_COLLECTION]

    pipeline = [
        {
            "$group": {
                "_id": "$attack_type",
                "flow_count": {"$sum": 1},
                "avg_total_bytes": {"$avg": "$total_bytes"},
                "avg_duration": {"$avg": "$duration"},
                "total_bytes_transferred": {"$sum": "$total_bytes"},
            }
        },
        {"$sort": {"flow_count": -1}},
    ]
    results = list(col.aggregate(pipeline))
    # Standardize output format
    formatted = []
    for r in results:
        formatted.append({
            "attack_type": r["_id"],
            "flow_count": r["flow_count"],
            "avg_total_bytes": round(float(r["avg_total_bytes"]), 2) if r["avg_total_bytes"] else 0.0,
            "avg_duration": round(float(r["avg_duration"]), 4) if r["avg_duration"] else 0.0,
            "total_bytes_transferred": r["total_bytes_transferred"],
        })
    return formatted


def aggregate_predictions_summary(db: Optional[Database] = None) -> Dict[str, Any]:
    """Aggregate prediction volume, average attack probability, and predicted labels."""
    database = db if db is not None else get_db()
    col: Collection = database[PREDICTIONS_COLLECTION]

    pipeline = [
        {
            "$group": {
                "_id": None,
                "total_predictions": {"$sum": 1},
                "avg_attack_prob": {"$avg": "$attack_probability"},
                "attacks_predicted": {
                    "$sum": {"$cond": [{"$eq": ["$predicted_label", 1]}, 1, 0]}
                },
                "benign_predicted": {
                    "$sum": {"$cond": [{"$eq": ["$predicted_label", 0]}, 1, 0]}
                },
            }
        }
    ]
    res = list(col.aggregate(pipeline))
    if not res:
        return {
            "total_predictions": 0,
            "avg_attack_prob": 0.0,
            "attacks_predicted": 0,
            "benign_predicted": 0,
        }
    r = res[0]
    return {
        "total_predictions": r.get("total_predictions", 0),
        "avg_attack_prob": round(float(r.get("avg_attack_prob", 0.0)), 4),
        "attacks_predicted": r.get("attacks_predicted", 0),
        "benign_predicted": r.get("benign_predicted", 0),
    }
