"""ThreatLens AI - Streamlit Web Dashboard.

Provides an interactive user interface for:
- Live flow prediction and payload volume estimation (Predict Tab)
- Real-time MongoDB traffic flow browser (Records Tab)
- Classifier and Regressor performance metrics and diagnostic plots (Metrics Tab)
- Dynamic MongoDB aggregation and index query explorer (DB Queries Tab)
"""

from datetime import datetime
import json
from pathlib import Path
import pandas as pd
import streamlit as st

from src.config import (
    CATEGORICAL_CLASSIFIER_FEATURES,
    CLASSIFIER_FEATURES,
    CLASSIFIER_MODEL_PATH,
    METRICS_JSON_PATH,
    NUMERIC_CLASSIFIER_FEATURES,
    OUTPUTS_DIR,
    REGRESSOR_MODEL_PATH,
    TRAFFIC_CSV_PATH,
)
from src.database import (
    MongoUnavailableError,
    aggregate_by_attack_type,
    aggregate_predictions_summary,
    ensure_indexes,
    find_records,
    get_db,
    latest_metrics,
    ping,
)
from src.predict import load_models, predict_batch, predict_one

# Page Configuration
st.set_page_config(
    page_title="ThreatLens AI - Network Intrusion & Traffic Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Header Banner
st.title("🛡️ ThreatLens AI")
st.caption(
    "A MongoDB-Based Network Intrusion Detection and Traffic Analysis System Using Machine Learning"
)

# MongoDB Health Check
db_online = False
try:
    ping()
    db_online = True
    st.sidebar.success("● MongoDB Connected (127.0.0.1:27017)")
except MongoUnavailableError as e:
    st.error(
        f"⚠️ **MongoDB Offline**: Cannot reach MongoDB service at `127.0.0.1:27017`. "
        f"Start it with `net start MongoDB` in an administrator command prompt (see docs/MONGODB_SETUP_WINDOWS.md)."
    )
    st.sidebar.error("○ MongoDB Disconnected")

# Sidebar Metadata
st.sidebar.title("System Info")
st.sidebar.markdown(
    """
**Course**: Intelligent NoSQL Databases  
**Architecture**:
- **Database**: MongoDB 
- **Driver**: PyMongo
- **Classifier**: Random Forest (Intrusions)
- **Regressor**: Random Forest (Bytes)
- **Dataset**: Synthetic Demonstration Data
"""
)

# Create 4 Primary Tabs
tab_predict, tab_records, tab_metrics, tab_queries = st.tabs(
    ["🎯 Predict", "📋 Records", "📊 Metrics", "🔍 DB Queries"]
)

# ==============================================================================
# TAB 1: PREDICT
# ==============================================================================
with tab_predict:
    st.header("Real-Time Flow Analysis & Prediction")
    st.write(
        "Enter network telemetry parameters below to perform simultaneous intrusion classification "
        "and flow transfer volume estimation."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("Network Protocol & State")
        protocol = st.selectbox("Protocol", ["tcp", "udp", "icmp"], index=0)
        service = st.selectbox(
            "Service",
            ["http", "https", "dns", "ssh", "ftp", "smtp", "other"],
            index=0,
        )
        state = st.selectbox(
            "State",
            ["established", "syn_sent", "reset", "rejected"],
            index=0,
        )
        dst_port = st.number_input("Destination Port", min_value=0, max_value=65535, value=80)

    with col2:
        st.subheader("Flow Volumes & Rates")
        duration = st.number_input("Duration (seconds)", min_value=0.001, max_value=3600.0, value=1.5, step=0.1)
        src_packets = st.number_input("Source Packets", min_value=0, max_value=100000, value=12)
        dst_packets = st.number_input("Destination Packets", min_value=0, max_value=100000, value=15)
        conn_rate = st.number_input("Connection Rate (conn/sec)", min_value=0.0, max_value=2000.0, value=10.0, step=1.0)

    with col3:
        st.subheader("Security & Behavior")
        ttl = st.number_input("Time to Live (TTL)", min_value=1, max_value=255, value=64)
        failed_logins = st.number_input("Failed Login Attempts", min_value=0, max_value=100, value=0)
        syn_flag_ratio = st.slider("SYN Flag Ratio", min_value=0.0, max_value=1.0, value=0.05, step=0.01)
        unique_dst_ports = st.number_input("Unique Dst Ports", min_value=1, max_value=1000, value=1)

    if st.button("🚀 Analyze Flow Telemetry", type="primary"):
        input_payload = {
            "protocol": protocol,
            "service": service,
            "state": state,
            "dst_port": int(dst_port),
            "duration": float(duration),
            "src_packets": int(src_packets),
            "dst_packets": int(dst_packets),
            "conn_rate": float(conn_rate),
            "ttl": int(ttl),
            "failed_logins": int(failed_logins),
            "syn_flag_ratio": float(syn_flag_ratio),
            "unique_dst_ports": int(unique_dst_ports),
        }

        try:
            clf_art, reg_art = load_models()
            prediction = predict_one(
                row_dict=input_payload,
                clf_artifact=clf_art,
                reg_artifact=reg_art,
                store=db_online,
                source="manual_input",
            )

            st.markdown("---")
            st.subheader("Inference Outcomes")
            rcol1, rcol2, rcol3 = st.columns(3)

            with rcol1:
                if prediction["predicted_label"] == 1:
                    st.error("🚨 **ALERT: MALICIOUS ATTACK**")
                else:
                    st.success("✅ **BENIGN TRAFFIC**")
                st.metric("Predicted Label", "Attack (1)" if prediction["predicted_label"] == 1 else "Normal (0)")

            with rcol2:
                prob = prediction["attack_probability"]
                st.metric("Attack Probability", f"{prob*100:.2f}%")
                st.progress(prob)

            with rcol3:
                pred_bytes = prediction["predicted_total_bytes"]
                st.metric("Estimated Volume", f"{pred_bytes:,.0f} Bytes")
                st.caption(f"~{pred_bytes/1024:.2f} KB transferred")

            if "prediction_id" in prediction:
                st.info(f"💾 Snapshot persisted to MongoDB collection `predictions` (ID: `{prediction['prediction_id']}`)")

        except Exception as e:
            st.error(f"Inference Error: {e}")

    st.markdown("---")
    st.subheader("Quick Sample Evaluation")
    if st.button("🎲 Pull 5 Random Test Flows from Database"):
        try:
            if db_online:
                db = get_db()
                sample_docs = list(db["traffic_records"].aggregate([{"$sample": {"size": 5}}]))
                df_sample = pd.DataFrame(sample_docs)
            else:
                df_csv = pd.read_csv(TRAFFIC_CSV_PATH)
                df_sample = df_csv.sample(5, random_state=42)

            batch_results = predict_batch(df_sample, store=db_online, source="test_batch")
            display_cols = ["record_id", "predicted_label", "attack_probability", "predicted_total_bytes", "actual_label", "actual_total_bytes"]
            st.dataframe(batch_results[display_cols], use_container_width=True)
        except Exception as e:
            st.error(f"Sampling Error: {e}")

# ==============================================================================
# TAB 2: RECORDS
# ==============================================================================
with tab_records:
    st.header("MongoDB Traffic Records Explorer")
    if db_online:
        db = get_db()
        col = db["traffic_records"]
        total_docs = col.count_documents({})
        st.write(f"Total stored traffic records in collection: **{total_docs:,}**")

        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            filter_attack = st.selectbox("Filter Attack Type", ["ALL", "normal", "dos", "port_scan", "brute_force", "probe"])
        with fcol2:
            filter_service = st.selectbox("Filter Service", ["ALL", "http", "https", "dns", "ssh", "ftp", "smtp", "other"])
        with fcol3:
            limit_n = st.slider("Max Documents to Display", 10, 100, 25)

        query = {}
        if filter_attack != "ALL":
            query["attack_type"] = filter_attack
        if filter_service != "ALL":
            query["service"] = filter_service

        records = find_records(filter_query=query, limit=limit_n)
        if records:
            df_display = pd.DataFrame(records)
            cols_to_show = [c for c in ["record_id", "protocol", "service", "state", "src_packets", "dst_packets", "failed_logins", "total_bytes", "label", "attack_type", "split"] if c in df_display.columns]
            st.dataframe(df_display[cols_to_show], use_container_width=True)
        else:
            st.warning("No records matched the filter criteria.")
    else:
        st.warning("MongoDB is offline. Displaying local CSV backup records.")
        if TRAFFIC_CSV_PATH.exists():
            df_csv = pd.read_csv(TRAFFIC_CSV_PATH)
            st.dataframe(df_csv.head(30), use_container_width=True)

# ==============================================================================
# TAB 3: METRICS
# ==============================================================================
with tab_metrics:
    st.header("Model Evaluation & Diagnostic Metrics")
    st.write("All metrics are evaluated exclusively on the held-out 20% test partition (N=2,400).")

    if METRICS_JSON_PATH.exists():
        with open(METRICS_JSON_PATH, "r", encoding="utf-8") as f:
            metrics_data = json.load(f)

        clf_m = metrics_data["classifier"]["metrics"]
        reg_m = metrics_data["regressor"]["metrics"]

        st.subheader("Intrusion Classifier Performance (Random Forest)")
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        mcol1.metric("Accuracy", f"{clf_m['accuracy']*100:.2f}%", f"Baseline: {metrics_data['classifier']['baseline']['accuracy']*100:.1f}%")
        mcol2.metric("Precision", f"{clf_m['precision']*100:.2f}%")
        mcol3.metric("Recall", f"{clf_m['recall']*100:.2f}%")
        mcol4.metric("F1-Score", f"{clf_m['f1']*100:.2f}%")

        st.subheader("Flow Volume Regressor Performance (Random Forest)")
        rcol1, rcol2 = st.columns(2)
        rcol1.metric("R² Score", f"{reg_m['r2']:.4f}", f"Baseline: {metrics_data['regressor']['baseline']['r2']:.4f}")
        rcol2.metric("Mean Absolute Error (MAE)", f"{reg_m['mae']:,.1f} Bytes", f"Baseline: {metrics_data['regressor']['baseline']['mae']:,.1f}")

        st.info(
            "📌 **Mandatory Methodology Disclosure**: "
            + metrics_data["regressor"].get("mandatory_disclosure", "")
        )

        st.subheader("Visual Evaluation Plots")
        pcol1, pcol2 = st.columns(2)
        cm_path = OUTPUTS_DIR / "confusion_matrix.png"
        fi_path = OUTPUTS_DIR / "classifier_feature_importance.png"
        reg_path = OUTPUTS_DIR / "regressor_actual_vs_predicted.png"

        with pcol1:
            if cm_path.exists():
                st.image(str(cm_path), caption="Intrusion Detection Confusion Matrix", use_container_width=True)
            if fi_path.exists():
                st.image(str(fi_path), caption="Top Predictive Features (Gini Importance)", use_container_width=True)

        with pcol2:
            if reg_path.exists():
                st.image(str(reg_path), caption="Flow Bytes: Actual vs. Predicted", use_container_width=True)
    else:
        st.warning("`outputs/metrics.json` not found. Please run `python -m src.evaluate`.")

# ==============================================================================
# TAB 4: DB QUERIES
# ==============================================================================
with tab_queries:
    st.header("MongoDB Analytics & Query Engine")
    st.write("Demonstrates server-side MongoDB aggregation pipelines and index query plans.")

    if db_online:
        st.subheader("1. Aggregation Pipeline: Traffic Distribution by Attack Type")
        agg_results = aggregate_by_attack_type()
        if agg_results:
            df_agg = pd.DataFrame(agg_results)
            st.dataframe(df_agg, use_container_width=True)
            st.bar_chart(df_agg.set_index("attack_type")["flow_count"])

        st.subheader("2. Prediction Analytics Pipeline")
        pred_stats = aggregate_predictions_summary()
        pcol1, pcol2, pcol3, pcol4 = st.columns(4)
        pcol1.metric("Total Predictions Logged", pred_stats["total_predictions"])
        pcol2.metric("Mean Attack Probability", f"{pred_stats['avg_attack_prob']*100:.2f}%")
        pcol3.metric("Attacks Predicted", pred_stats["attacks_predicted"])
        pcol4.metric("Benign Predicted", pred_stats["benign_predicted"])

        st.subheader("3. Database Indexes Status")
        db = get_db()
        for cname in ["traffic_records", "predictions", "model_metrics"]:
            indexes = db[cname].index_information()
            st.write(f"**Collection: `{cname}`** ({len(indexes)} indexes)")
            st.json(indexes)
    else:
        st.warning("MongoDB is offline. Connect MongoDB to run dynamic aggregation pipelines.")

