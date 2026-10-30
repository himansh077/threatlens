"""ThreatLens AI - Live Interactive Demonstration."""

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.database import get_db, aggregate_by_attack_type, aggregate_predictions_summary
from src.predict import load_models, predict_one

def main():
    db = get_db()
    col = db["traffic_records"]
    clf_art, reg_art = load_models()

    attack_types = ["normal", "dos", "port_scan", "brute_force", "probe"]

    print("=" * 85)
    print("LIVE DEMONSTRATION: REAL-TIME INFERENCE ACROSS MULTIPLE ATTACK SIGNATURES")
    print("=" * 85)

    for atype in attack_types:
        doc = col.find_one({"attack_type": atype, "split": "test"})
        if doc:
            res = predict_one(doc, clf_artifact=clf_art, reg_artifact=reg_art, store=True, source="live_demo")
            pred_desc = "MALICIOUS ATTACK (1)" if res["predicted_label"] == 1 else "BENIGN TRAFFIC (0)"
            prob = res["attack_probability"] * 100.0
            pred_b = res["predicted_total_bytes"]
            act_b = doc.get("total_bytes", 0)
            rec = doc["record_id"]
            srv = doc["service"]
            proto = doc["protocol"]
            pid = res.get("prediction_id", "N/A")

            print(f"[{rec}] Protocol: {proto:<4} | Service: {srv:<6} | Actual Attack Type: {atype}")
            print(f"   -> Classification : {pred_desc} (Malicious Probability: {prob:.2f}%)")
            print(f"   -> Volume Regressor: {pred_b:,.0f} Bytes predicted (Actual: {act_b:,.0f} Bytes)")
            print(f"   -> MongoDB Snapshot: Persisted to 'predictions' collection (_id: {pid})")
            print("-" * 85)

    print("\n" + "=" * 85)
    print("SERVER-SIDE MONGODB AGGREGATION PIPELINE: TRAFFIC SUMMARY BY ATTACK TYPE")
    print("=" * 85)
    agg_rows = aggregate_by_attack_type()
    print(f" {'Attack Type':<15} | {'Flow Count':>10} | {'Avg Bytes':>15} | {'Avg Duration(s)':>16}")
    print("-" * 85)
    for r in agg_rows:
        print(f" {r['attack_type']:<15} | {r['flow_count']:>10,} | {r['avg_total_bytes']:>15,.1f} | {r['avg_duration']:>16.4f}")

    print("\n" + "=" * 85)
    print("PREDICTIONS COLLECTION REAL-TIME AUDIT SUMMARY")
    print("=" * 85)
    stats = aggregate_predictions_summary()
    print(f" Total Predictions Logged in MongoDB: {stats['total_predictions']:,}")
    print(f" Malicious Attacks Detected:         {stats['attacks_predicted']:,}")
    print(f" Benign Traffic Logged:              {stats['benign_predicted']:,}")
    print(f" Average Malicious Probability:      {stats['avg_attack_prob']*100:.2f}%")
    print("=" * 85)

if __name__ == "__main__":
    main()
