"""ThreatLens AI - MongoDB Interactive Demonstration Suite.

Demonstrates core MongoDB & PyMongo capabilities for the viva / academic evaluation:
1. Document Insertion
2. Document Finding
3. Complex Filtering
4. Sorting & Limiting
5. Document Updating
6. Document Deletion (restricted to marked demo documents)
7. Multi-stage Aggregation Pipeline
8. Relational Joins using $lookup
9. Index Inspection and Query Plan Explain
"""

from datetime import datetime, timezone
import json
import sys
from pymongo import ASCENDING, DESCENDING

from src.config import (
    PREDICTIONS_COLLECTION,
    TRAFFIC_COLLECTION,
)
from src.database import (
    ensure_indexes,
    get_db,
    ping,
    serialize,
    to_native,
)


def run_db_demos() -> None:
    print("=" * 80)
    print("THREATLENS AI: MONGODB & PYMONGO DEMONSTRATION SUITE")
    print("=" * 80)

    ping()
    db = get_db()
    traffic_col = db[TRAFFIC_COLLECTION]
    pred_col = db[PREDICTIONS_COLLECTION]
    ensure_indexes(db)

    # --------------------------------------------------------------------------
    # DEMO 1: INSERT
    # --------------------------------------------------------------------------
    print("\n[DEMO 1: INSERT] Inserting a marked demonstration document...")
    demo_doc = {
        "record_id": "DEMO-DOC-999999",
        "duration": 1.25,
        "protocol": "tcp",
        "service": "ssh",
        "state": "rejected",
        "src_packets": 25,
        "dst_packets": 2,
        "dst_port": 22,
        "ttl": 64,
        "failed_logins": 12,
        "syn_flag_ratio": 0.85,
        "unique_dst_ports": 1,
        "conn_rate": 35.0,
        "src_bytes": 3750,
        "dst_bytes": 300,
        "total_bytes": 4050,
        "label": 1,
        "attack_type": "brute_force",
        "split": "test",
        "source": "demo_synthetic",
        "is_temporary_demo": True,
        "imported_at": datetime.now(timezone.utc),
    }
    # Clean up prior run if present
    traffic_col.delete_one({"record_id": demo_doc["record_id"]})
    insert_res = traffic_col.insert_one(to_native(demo_doc))
    print(f" -> Inserted demo document with _id: {insert_res.inserted_id}")
    print(f" -> record_id: {demo_doc['record_id']}")

    # --------------------------------------------------------------------------
    # DEMO 2: FIND
    # --------------------------------------------------------------------------
    print("\n[DEMO 2: FIND] Finding document by unique record_id...")
    found_doc = traffic_col.find_one({"record_id": "DEMO-DOC-999999"})
    if found_doc:
        print(f" -> Found record_id: {found_doc.get('record_id')}")
        print(f" -> Attack Type:     {found_doc.get('attack_type')}")
        print(f" -> Service:         {found_doc.get('service')}, Port: {found_doc.get('dst_port')}")
        print(f" -> Failed Logins:   {found_doc.get('failed_logins')}")

    # --------------------------------------------------------------------------
    # DEMO 3: FILTER
    # --------------------------------------------------------------------------
    print("\n[DEMO 3: FILTER] Querying for SSH brute force flows with failed_logins >= 10...")
    filter_query = {
        "service": "ssh",
        "failed_logins": {"$gte": 10},
        "label": 1,
    }
    matching_count = traffic_col.count_documents(filter_query)
    sample_match = traffic_col.find_one(filter_query)
    print(f" -> Total matching flows in database: {matching_count:,}")
    if sample_match:
        print(f" -> Sample match: {sample_match.get('record_id')} with {sample_match.get('failed_logins')} failed logins")

    # --------------------------------------------------------------------------
    # DEMO 4: SORT & LIMIT
    # --------------------------------------------------------------------------
    print("\n[DEMO 4: SORT & LIMIT] Top 3 flows by total_bytes transferred descending...")
    cursor = traffic_col.find(
        {"is_temporary_demo": {"$ne": True}},
        {"record_id": 1, "service": 1, "total_bytes": 1, "src_packets": 1, "dst_packets": 1, "_id": 0}
    ).sort("total_bytes", DESCENDING).limit(3)
    for idx, doc in enumerate(cursor, 1):
        print(f" -> Rank {idx}: Flow {doc.get('record_id')} ({doc.get('service')}) -> {doc.get('total_bytes'):,} bytes transferred")

    # --------------------------------------------------------------------------
    # DEMO 5: UPDATE
    # --------------------------------------------------------------------------
    print("\n[DEMO 5: UPDATE] Updating demo document metadata ($set operator)...")
    update_res = traffic_col.update_one(
        {"record_id": "DEMO-DOC-999999"},
        {
            "$set": {
                "analyst_notes": "Identified by automated brute force rule.",
                "triage_status": "HIGH_CONFIDENCE_ATTACK",
                "updated_at": datetime.now(timezone.utc),
            }
        }
    )
    updated_doc = traffic_col.find_one({"record_id": "DEMO-DOC-999999"})
    print(f" -> Matched: {update_res.matched_count}, Modified: {update_res.modified_count}")
    print(f" -> Triage Status: {updated_doc.get('triage_status')}")
    print(f" -> Analyst Notes: {updated_doc.get('analyst_notes')}")

    # --------------------------------------------------------------------------
    # DEMO 6: DELETE (Only on clearly marked demo document)
    # --------------------------------------------------------------------------
    print("\n[DEMO 6: DELETE] Safely deleting the temporary demo document...")
    del_res = traffic_col.delete_one({"record_id": "DEMO-DOC-999999", "is_temporary_demo": True})
    print(f" -> Deleted count: {del_res.deleted_count}")
    verify_del = traffic_col.find_one({"record_id": "DEMO-DOC-999999"})
    assert verify_del is None, "Demo document was not properly deleted!"
    print(" -> Verification: DEMO-DOC-999999 successfully deleted from database.")

    # --------------------------------------------------------------------------
    # DEMO 7: AGGREGATION PIPELINE
    # --------------------------------------------------------------------------
    print("\n[DEMO 7: AGGREGATION PIPELINE] Grouping traffic by attack_type ($group, $avg, $sum, $sort)...")
    pipeline = [
        {"$match": {"is_temporary_demo": {"$ne": True}}},
        {
            "$group": {
                "_id": "$attack_type",
                "flow_count": {"$sum": 1},
                "avg_bytes": {"$avg": "$total_bytes"},
                "avg_duration": {"$avg": "$duration"},
                "total_bytes": {"$sum": "$total_bytes"},
            }
        },
        {"$sort": {"flow_count": -1}},
    ]
    agg_res = list(traffic_col.aggregate(pipeline))
    print(f" {'Attack Type':<15} | {'Flows':>7} | {'Avg Bytes':>12} | {'Avg Duration(s)':>16} | {'Total Volume(MB)':>16}")
    print(" " + "-" * 75)
    for row in agg_res:
        atype = row["_id"]
        flows = row["flow_count"]
        avg_b = row["avg_bytes"] or 0.0
        avg_d = row["avg_duration"] or 0.0
        tot_mb = (row["total_bytes"] or 0) / (1024 * 1024)
        print(f" {atype:<15} | {flows:>7,} | {avg_b:>12.1f} | {avg_d:>16.4f} | {tot_mb:>16.2f}")

    # --------------------------------------------------------------------------
    # DEMO 8: $LOOKUP (Cross-Collection Join: predictions -> traffic_records)
    # --------------------------------------------------------------------------
    print("\n[DEMO 8: $LOOKUP JOIN] Joining predictions collection to traffic_records by record_id...")
    # Find an existing stored record to link
    sample_flow = traffic_col.find_one({"label": 1})
    if sample_flow:
        sample_rec_id = sample_flow["record_id"]
        # Insert a sample prediction document referencing this flow
        pred_sample = {
            "record_id": sample_rec_id,
            "input_snapshot": {"protocol": sample_flow["protocol"], "service": sample_flow["service"]},
            "predicted_label": 1,
            "attack_probability": 0.985,
            "predicted_total_bytes": float(sample_flow.get("total_bytes", 1500)),
            "actual_label": 1,
            "actual_total_bytes": float(sample_flow.get("total_bytes", 1500)),
            "model_version": "1.0.0",
            "source": "stored_record",
            "created_at": datetime.now(timezone.utc),
        }
        # Clean up any previous test prediction for this record_id
        pred_col.delete_many({"record_id": sample_rec_id, "source": "stored_record"})
        pred_col.insert_one(to_native(pred_sample))

        # Perform $lookup join
        lookup_pipeline = [
            {"$match": {"record_id": sample_rec_id}},
            {
                "$lookup": {
                    "from": "traffic_records",
                    "localField": "record_id",
                    "foreignField": "record_id",
                    "as": "raw_traffic_flow",
                }
            },
            {"$limit": 1},
        ]
        joined = list(pred_col.aggregate(lookup_pipeline))
        if joined and joined[0].get("raw_traffic_flow"):
            linked_flow = joined[0]["raw_traffic_flow"][0]
            print(f" -> Joined Prediction for record_id: {joined[0].get('record_id')}")
            print(f" -> Predicted Label: {joined[0].get('predicted_label')} (Prob: {joined[0].get('attack_probability'):.3f})")
            print(f" -> Linked Raw Traffic Protocol: {linked_flow.get('protocol')}, Service: {linked_flow.get('service')}, Actual Attack Type: {linked_flow.get('attack_type')}")
        else:
            print(" -> Joined flow returned empty array.")

    # --------------------------------------------------------------------------
    # DEMO 9: INDEX INFORMATION & EXPLAIN PLAN
    # --------------------------------------------------------------------------
    print("\n[DEMO 9: INDEX INFORMATION & EXPLAIN PLAN]")
    index_info = traffic_col.index_information()
    print(" -> Existing traffic_records indexes:")
    for idx_name, details in index_info.items():
        keys = details.get("key", [])
        print(f"    * {idx_name:<25}: key={keys}")

    # Explain an indexed query
    explain_res = traffic_col.find({"record_id": "TL-000001"}).explain()
    winning_plan = explain_res.get("queryPlanner", {}).get("winningPlan", {})
    stage = winning_plan.get("stage", "UNKNOWN")
    index_name = winning_plan.get("inputStage", {}).get("indexName", winning_plan.get("indexName", "N/A"))
    print(f" -> Explain Plan Execution Stage: {stage} (Index used: {index_name})")
    print("=" * 80)
    print("DEMONSTRATION SUITE COMPLETED SUCCESSFULLY.")
    print("=" * 80)


def main() -> None:
    try:
        run_db_demos()
    except Exception as e:
        print(f"ERROR: Database demo suite failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

