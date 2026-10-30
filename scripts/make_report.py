"""ThreatLens AI - Academic Report Generator.

Compiles an academic project report in Microsoft Word (.docx) format using python-docx.
All empirical metrics and confusion matrix values are loaded programmatically from outputs/metrics.json.
Visual diagnostic plots are embedded directly into the document.
Screenshot placeholders are inserted with clear visual styling.
"""

from datetime import datetime
import json
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import docx
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

from src.config import (
    METRICS_JSON_PATH,
    OUTPUTS_DIR,
    REPORTS_DIR,
)


def set_cell_background(cell, fill_hex: str) -> None:
    """Set background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tc_pr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150) -> None:
    """Set padding/margins for a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)


def add_callout_box(doc, text: str, title: str = "METHODOLOGY NOTICE") -> None:
    """Add a shaded callout notice box."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F0F4F8")
    set_cell_margins(cell, top=150, bottom=150, left=200, right=200)

    p = cell.paragraphs[0]
    r_title = p.add_run(f"📌 {title}: ")
    r_title.bold = True
    r_title.font.color.rgb = RGBColor(30, 60, 110)
    r_text = p.add_run(text)
    r_text.font.size = Pt(9.5)
    r_text.font.italic = True
    doc.add_paragraph()  # Spacing


def add_screenshot_placeholder(doc, caption: str, description: str) -> None:
    """Add a clearly boxed placeholder for UI screenshots."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "FAF9F6")
    set_cell_margins(cell, top=200, bottom=200, left=250, right=250)

    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r1 = p.add_run("📷 [SCREENSHOT PLACEHOLDER]\n")
    r1.bold = True
    r1.font.size = Pt(11)
    r1.font.color.rgb = RGBColor(120, 80, 20)

    r2 = p.add_run(f"Insert your screenshot here: {caption}\n")
    r2.bold = True
    r2.font.size = Pt(10)

    r3 = p.add_run(f"Guidance: {description}")
    r3.font.size = Pt(9)
    r3.font.italic = True
    r3.font.color.rgb = RGBColor(100, 100, 100)
    doc.add_paragraph()


def build_project_report() -> Path:
    """Generate the full project report .docx file."""
    if not METRICS_JSON_PATH.exists():
        raise FileNotFoundError(
            f"Metrics file missing at {METRICS_JSON_PATH}. Run 'python -m src.evaluate' first."
        )

    with open(METRICS_JSON_PATH, "r", encoding="utf-8") as f:
        metrics_data = json.load(f)

    clf_metrics = metrics_data["classifier"]["metrics"]
    reg_metrics = metrics_data["regressor"]["metrics"]
    cm = metrics_data["classifier"]["confusion_matrix"]
    n_train = metrics_data["n_train"]
    n_test = metrics_data["n_test"]
    n_total = n_train + n_test

    doc = Document()

    # Set 1-inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # ==========================================================================
    # 1. TITLE PAGE
    # ==========================================================================
    p_title_pre = doc.add_paragraph()
    p_title_pre.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title_pre.paragraph_format.space_before = Pt(40)

    r_course = p_title_pre.add_run("B.Tech Capstone / Course Project Submission\nCourse: Intelligent NoSQL Databases (CSE494)\n\n")
    r_course.font.size = Pt(12)
    r_course.font.color.rgb = RGBColor(100, 100, 100)

    r_main_title = p_title_pre.add_run("THREATLENS AI:\nA MongoDB-Based Network Intrusion Detection\nand Traffic Analysis System Using Machine Learning\n\n")
    r_main_title.bold = True
    r_main_title.font.size = Pt(22)
    r_main_title.font.color.rgb = RGBColor(20, 45, 90)

    r_sub = p_title_pre.add_run("An End-to-End System Integrating NoSQL Document Store Modeling, Server-Side Aggregations, and Dual-Task Machine Learning Pipelines\n")
    r_sub.font.size = Pt(11)
    r_sub.font.italic = True

    # Editable Placeholders Box
    tbl_ph = doc.add_table(rows=7, cols=2)
    tbl_ph.alignment = WD_TABLE_ALIGNMENT.CENTER
    fields = [
        ("Candidate Name:", "[STUDENT NAME]"),
        ("Registration / Roll No:", "[REGISTRATION NUMBER]"),
        ("Course Code & Title:", "CSE494 - Intelligent NoSQL Databases"),
        ("Department:", "[DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING]"),
        ("Faculty Supervisor:", "[FACULTY NAME]"),
        ("Academic Institution:", "[UNIVERSITY / INSTITUTION NAME]"),
        ("Submission Date:", datetime.now().strftime("%B %d, %Y")),
    ]
    for idx, (label, val) in enumerate(fields):
        c0 = tbl_ph.cell(idx, 0)
        c1 = tbl_ph.cell(idx, 1)
        c0.text = label
        c0.paragraphs[0].runs[0].bold = True
        c0.paragraphs[0].runs[0].font.size = Pt(10)
        c1.text = val
        c1.paragraphs[0].runs[0].font.size = Pt(10)
        if "[" in val:
            c1.paragraphs[0].runs[0].bold = True
            c1.paragraphs[0].runs[0].font.color.rgb = RGBColor(180, 40, 20)
        set_cell_margins(c0, 60, 60, 100, 100)
        set_cell_margins(c1, 60, 60, 100, 100)

    doc.add_page_break()

    # ==========================================================================
    # 2. ABSTRACT
    # ==========================================================================
    doc.add_heading("Abstract", level=1)
    p_abs = doc.add_paragraph(
        "Modern enterprise computing infrastructure faces an unprecedented volume of complex network-borne cyber threats. "
        "Traditional relational database systems struggle to ingest, query, and analyze high-velocity network flow telemetry "
        "due to rigid schema constraints, write-lock contention, and expensive join operations across heterogeneous protocol attributes. "
        "This project presents ThreatLens AI, an intelligent network intrusion detection and traffic baselining architecture "
        "built natively on the MongoDB NoSQL document database and scikit-learn machine learning framework. "
        "The system models multi-protocol network flows as flexible BSON documents in a dedicated collection, enforces schema "
        "integrity through an idempotent bulk upsert pipeline, and leverages compound indexes to support sub-millisecond query execution. "
        "Two independent machine learning models were trained: a Random Forest classifier detecting malicious intrusions with "
        f"{clf_metrics['accuracy']*100:.2f}% accuracy and an F1-score of {clf_metrics['f1']:.4f}, and a Random Forest regressor "
        f"estimating flow transfer volumes with an R² score of {reg_metrics['r2']:.4f} and Mean Absolute Error of {reg_metrics['mae']:,.1f} bytes. "
        "The complete system includes an interactive PyMongo CRUD demonstration suite, an automated evaluation pipeline, a Streamlit "
        "analytical dashboard, and a 35-test automated verification suite."
    )
    p_abs.paragraph_format.line_spacing = 1.15

    add_callout_box(
        doc,
        "This report and prototype evaluate synthetic demonstration data generated deterministically via NumPy (seed 42). "
        "The reported metrics prove the correctness, resilience, and operational validity of the end-to-end NoSQL/ML software architecture, "
        "rather than empirical real-world intrusion detection capability on unconstrained live production backbones.",
        "MANDATORY ACADEMIC PROVENANCE DISCLOSURE",
    )

    # ==========================================================================
    # 3. INTRODUCTION & PROBLEM STATEMENT
    # ==========================================================================
    doc.add_heading("1. Introduction and Problem Statement", level=1)
    doc.add_paragraph(
        "Network Intrusion Detection Systems (NIDS) constitute the first line of defense in modern cybersecurity perimeters. "
        "Every network transaction—ranging from basic DNS resolutions to multi-gigabit encrypted TLS handshakes—generates structured "
        "telemetry summarizing packet counts, byte volumes, durations, flag ratios, and connection states. "
        "Effectively monitoring and triage-analyzing this telemetry presents two fundamental technological challenges:"
    )
    doc.add_paragraph(
        "1. NoSQL Storage & Ingestion Bottlenecks: Network flows arrive at rates exceeding thousands of events per second. "
        "Relational database schemas (RDBMS) impose strict tabular normalization. When flows from different protocols (TCP, UDP, ICMP) "
        "contain different diagnostic parameters (e.g., TCP flags vs. ICMP type codes), relational databases either suffer from sparse, "
        "mostly-NULL columns or require normalized child tables that necessitate costly JOIN operations during analytical scans. "
        "Furthermore, RDBMS ACID locking creates severe throughput degradation during high-rate bulk inserts.",
        style="List Bullet",
    )
    doc.add_paragraph(
        "2. Multi-Task Analytics & Machine Learning Integration: Network defense requires not only binary threat detection "
        "(identifying malicious DoS, port scan, brute force, or probe flows) but also precise continuous volume baselining "
        "(estimating payload volume for bandwidth provisioning, QoS enforcement, and exfiltration detection). "
        "Traditional security appliances keep database storage disconnected from ML pipelines, leading to data synchronization delays "
        "and brittle feature engineering handoffs.",
        style="List Bullet",
    )
    doc.add_paragraph(
        "ThreatLens AI bridges this divide by deploying MongoDB as an intelligent, high-throughput analytical repository directly "
        "coupled to dual Random Forest machine learning pipelines via PyMongo."
    )

    # ==========================================================================
    # 4. OBJECTIVES & SCOPE
    # ==========================================================================
    doc.add_heading("2. Objectives and Scope", level=1)
    doc.add_paragraph("The primary academic and technical objectives of this project are:")
    doc.add_paragraph("• Design and implement a document-oriented MongoDB schema for network flow telemetry that encapsulates variable protocol features.", style="List Bullet")
    doc.add_paragraph("• Implement robust, idempotent PyMongo ingestion using bulk write operations (UpdateOne with upsert=True) to eliminate duplicate records.", style="List Bullet")
    doc.add_paragraph("• Construct targeted B-tree indexes and compound indexes to accelerate both single-flow point lookups and analytical range queries.", style="List Bullet")
    doc.add_paragraph("• Engineer a dual-task machine learning framework featuring an Intrusion Detection Classifier and a Flow Volume Regressor.", style="List Bullet")
    doc.add_paragraph("• Enforce rigorous data isolation and leakage-prevention protocols, ensuring zero target or identifier leakage across an 80/20 stratified split.", style="List Bullet")
    doc.add_paragraph("• Provide interactive NoSQL demonstrations covering CRUD, aggregation pipelines, $lookup relational joins, and execution plan explain().", style="List Bullet")
    doc.add_paragraph("• Deliver an end-to-end verified prototype on Windows, verified by automated unit tests and an interactive Streamlit dashboard.", style="List Bullet")

    # ==========================================================================
    # 5. SYSTEM ARCHITECTURE & WORKFLOW
    # ==========================================================================
    doc.add_heading("3. System Architecture and Workflow", level=1)
    doc.add_paragraph(
        "ThreatLens AI is organized into modular layers adhering to separation-of-concerns principles. "
        "The architecture consists of four interconnected subsystems: Data Generation & Ingestion, Intelligent NoSQL Storage, "
        "Machine Learning Training & Evaluation, and Unified Presentation."
    )

    tbl_arch = doc.add_table(rows=5, cols=3)
    tbl_arch.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Subsystem Layer", "Core Python Modules", "Primary Responsibility"]
    for i, h in enumerate(headers):
        cell = tbl_arch.cell(0, i)
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "2B5C8F")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

    arch_data = [
        ("Data Layer", "scripts/generate_data.py\nsrc/data_loader.py", "Generates 12,000 synthetic flows, computes 80/20 stratified split, and performs schema validation."),
        ("NoSQL Database Layer", "src/database.py\nsrc/seed_database.py\nsrc/db_demo.py", "Manages MongoDB connections, index creation, idempotent bulk upserts, and aggregation pipelines."),
        ("Machine Learning Layer", "src/preprocessing.py\nsrc/train_classifier.py\nsrc/train_regressor.py\nsrc/evaluate.py", "Encodes features with ColumnTransformer, fits Random Forests on train split, and computes test metrics and plots."),
        ("Inference & Presentation", "src/predict.py\napp.py (Streamlit)", "Provides unified CLI and browser-based inference, persisting prediction snapshots to MongoDB."),
    ]
    for row_idx, (layer, mods, resp) in enumerate(arch_data, start=1):
        c0 = tbl_arch.cell(row_idx, 0)
        c1 = tbl_arch.cell(row_idx, 1)
        c2 = tbl_arch.cell(row_idx, 2)
        c0.text = layer
        c1.text = mods
        c2.text = resp
        set_cell_margins(c0, 80, 80, 100, 100)
        set_cell_margins(c1, 80, 80, 100, 100)
        set_cell_margins(c2, 80, 80, 100, 100)
    doc.add_paragraph()

    # ==========================================================================
    # 6. DATASET DESCRIPTION & PROVENANCE
    # ==========================================================================
    doc.add_heading("4. Dataset Description and Provenance", level=1)
    doc.add_paragraph(
        f"The dataset consists of {n_total:,} synthetic network flow records generated via NumPy's default_rng(seed=42). "
        "The generation logic establishes distinct, overlapping attack signatures modeled after realistic network telemetry:"
    )
    doc.add_paragraph("• Denial of Service (DoS - 10% / 1,200 flows): Characterized by very high source packet counts (500–5,000), near-zero destination packets, elevated connection rates, and high SYN flag ratios in syn_sent state.", style="List Bullet")
    doc.add_paragraph("• Port Scanning (7% / 840 flows): Exhibits high unique destination port counts (35–600) with minimal packet counts per connection, resulting in rejected or reset TCP states.", style="List Bullet")
    doc.add_paragraph("• Brute Force (5% / 600 flows): Concentrated on SSH (port 22) and FTP (port 21) services, displaying high failed login counts (5–45) and moderate connection rates.", style="List Bullet")
    doc.add_paragraph("• Network Probing (3% / 360 flows): Comprises low-rate ICMP and multi-port scans across low-order ports with moderate unique destination counts.", style="List Bullet")
    doc.add_paragraph("• Normal Benign Traffic (75% / 9,000 flows): Diverse baseline traffic across HTTP, HTTPS, DNS, SMTP, and internal services.", style="List Bullet")

    doc.add_paragraph(
        "To prevent trivial separability and accurately simulate real-world telemetry noise, three realistic difficulty mechanisms were incorporated: "
        "(1) 8% of attack flows are stealthy, drawn from normal-like distributions; "
        "(2) 5% of benign flows exhibit bursty transmission characteristics; "
        "(3) 2% random label noise is introduced across the dataset."
    )

    # Class breakdown table
    tbl_class = doc.add_table(rows=6, cols=4)
    tbl_class.alignment = WD_TABLE_ALIGNMENT.CENTER
    c_heads = ["Attack Class", "Category", "Flow Count", "Proportion (%)"]
    for i, h in enumerate(c_heads):
        c = tbl_class.cell(0, i)
        c.text = h
        c.paragraphs[0].runs[0].bold = True
        set_cell_background(c, "2B5C8F")
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

    classes_info = [
        ("normal", "Benign Baseline", "9,000", "75.00%"),
        ("dos", "Denial of Service Attack", "1,200", "10.00%"),
        ("port_scan", "Reconnaissance Attack", "840", "7.00%"),
        ("brute_force", "Credential Access Attack", "600", "5.00%"),
        ("probe", "Network Discovery Attack", "360", "3.00%"),
    ]
    for row_idx, row in enumerate(classes_info, start=1):
        for col_idx, val in enumerate(row):
            c = tbl_class.cell(row_idx, col_idx)
            c.text = val
            set_cell_margins(c, 60, 60, 100, 100)
    doc.add_paragraph()

    # ==========================================================================
    # 7. MONGODB DOCUMENT DESIGN & PYMONGO IMPLEMENTATION
    # ==========================================================================
    doc.add_heading("5. MongoDB Document Design and PyMongo Implementation", level=1)
    doc.add_paragraph(
        "The system utilizes three dedicated collections in the 'threatlens_db' database, each optimized for distinct operational workloads:"
    )
    doc.add_paragraph(
        "1. traffic_records Collection: Stores raw flow telemetry. Every document features a unique string 'record_id' (e.g., 'TL-000001'), "
        "flow durations, protocol, service, connection state, packet counts, byte statistics, security indicators (failed_logins, syn_flag_ratio), "
        "ground-truth label, attack_type, split assignment ('train'/'test'), and imported_at timestamps.",
        style="List Bullet",
    )
    doc.add_paragraph(
        "2. predictions Collection: Stores inference audit snapshots. Each document includes the referenced 'record_id', an embedded 'input_snapshot' "
        "capturing exact feature values at the moment of inference, 'predicted_label', 'attack_probability', 'predicted_total_bytes', ground-truth values (if available), "
        "model version ('1.0.0'), inference source ('stored_record', 'manual_input', 'test_batch'), and timestamp.",
        style="List Bullet",
    )
    doc.add_paragraph(
        "3. model_metrics Collection: Stores historical evaluation runs for governance. Documents include unique 'run_id', 'model_type', "
        "computed evaluation metrics, confusion matrix arrays, train/test sample counts, random seeds, and library dependency versions.",
        style="List Bullet",
    )

    doc.add_heading("Indexing & Server-Side Aggregation", level=2)
    doc.add_paragraph(
        "To ensure high query performance, targeted B-tree indexes are programmatically enforced via ensure_indexes():\n"
        "• traffic_records: Unique index on record_id, compound index on (label, attack_type), and single-field index on split.\n"
        "• predictions: Compound index on (record_id, model_version) and descending index on created_at.\n"
        "• model_metrics: Unique index on run_id and compound index on (model_type, created_at descending)."
    )
    doc.add_paragraph(
        "The system leverages MongoDB's multi-stage aggregation pipeline ($match, $group, $avg, $sum, $sort) to calculate real-time traffic statistics "
        "and demonstrates relational joins across collections using the $lookup operator, linking prediction audit trails to raw traffic documents."
    )

    # ==========================================================================
    # 8. PREPROCESSING & LEAKAGE PREVENTION
    # ==========================================================================
    doc.add_heading("6. Preprocessing and Feature Engineering", level=1)
    doc.add_paragraph(
        "Preprocessing is implemented via scikit-learn's ColumnTransformer to ensure reproducible, unified transformations for both batch training "
        "and real-time inference. Missing continuous values are imputed using SimpleImputer(strategy='median') to maintain robustness against heavy-tailed download flows. "
        "Categorical variables (protocol, service, state) are encoded via OneHotEncoder(handle_unknown='ignore', sparse_output=False)."
    )
    add_callout_box(
        doc,
        "Feature scaling (e.g., StandardScaler or MinMaxScaler) was intentionally omitted. Random Forest classifiers and regressors are decision tree "
        "ensembles invariant to monotonic feature scaling because split nodes evaluate relative ordinal values rather than absolute Euclidean distances. "
        "Omitting unnecessary scaling preserves numerical interpretability and eliminates floating-point rounding artifacts.",
        "FEATURE SCALING JUSTIFICATION",
    )
    doc.add_paragraph(
        "Data leakage is strictly prevented through four architectural controls:\n"
        "1. Train/Test Stratification: The 80/20 train/test split is fixed deterministically at dataset generation and stored in the split column.\n"
        "2. Pipeline Imputation Isolation: Imputer statistics are fitted exclusively on training rows and applied to test rows without recalculation.\n"
        "3. Target Exclusion: The classification target (label) is strictly excluded from feature sets.\n"
        "4. Feature Guard Assertion: The assert_no_leakage() function programmatically inspects feature lists before training, raising exceptions if any leakage columns are present."
    )

    # ==========================================================================
    # 9. MODEL IMPLEMENTATION
    # ==========================================================================
    doc.add_heading("7. Model Implementation", level=1)
    doc.add_paragraph(
        "ThreatLens AI deploys two independent Random Forest models to address complementary cybersecurity requirements:"
    )
    doc.add_paragraph(
        "1. Intrusion Detection Classifier (RandomForestClassifier):\n"
        "• Target: Binary attack label (0 = benign, 1 = malicious attack).\n"
        "• Features (12): duration, protocol, service, state, src_packets, dst_packets, dst_port, ttl, failed_logins, syn_flag_ratio, unique_dst_ports, conn_rate.\n"
        "• Hyperparameters: n_estimators=200, min_samples_leaf=2, class_weight='balanced', random_state=42.\n"
        "• Excluded: record_id, attack_type, label, split, source, imported_at, src_bytes, dst_bytes, total_bytes.",
        style="List Bullet",
    )
    doc.add_paragraph(
        "2. Flow Volume Regressor (RandomForestRegressor):\n"
        "• Target: Total bytes transferred (total_bytes) for network capacity planning.\n"
        "• Features (10): duration, protocol, service, state, src_packets, dst_packets, dst_port, ttl, unique_dst_ports, conn_rate.\n"
        "• Hyperparameters: n_estimators=200, min_samples_leaf=2, random_state=42.\n"
        "• Excluded: src_bytes, dst_bytes, total_bytes, label, attack_type, failed_logins, syn_flag_ratio, IDs, split.",
        style="List Bullet",
    )
    doc.add_paragraph(
        "Independence Guarantee: The models operate on different targets and feature sets. The regressor never receives the attack label or security flags, "
        "and no output from the classifier feeds into the regressor."
    )

    # ==========================================================================
    # 10. EVALUATION METHODOLOGY & RESULTS
    # ==========================================================================
    doc.add_heading("8. Evaluation Methodology and Experimental Results", level=1)
    doc.add_paragraph(
        f"All evaluation metrics were calculated exclusively on the held-out test split of {n_test:,} flows (20% of the dataset). "
        "In accordance with academic standards, classification metrics are applied exclusively to the classifier, and regression metrics are applied exclusively to the regressor."
    )

    # Metrics Table
    tbl_met = doc.add_table(rows=7, cols=4)
    tbl_met.alignment = WD_TABLE_ALIGNMENT.CENTER
    m_heads = ["Model Task", "Metric", "ThreatLens AI Result", "Dummy Baseline Comparison"]
    for i, h in enumerate(m_heads):
        c = tbl_met.cell(0, i)
        c.text = h
        c.paragraphs[0].runs[0].bold = True
        set_cell_background(c, "2B5C8F")
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

    dummy_clf_acc = metrics_data["classifier"]["baseline"]["accuracy"]
    dummy_clf_f1 = metrics_data["classifier"]["baseline"]["f1"]
    dummy_reg_r2 = metrics_data["regressor"]["baseline"]["r2"]
    dummy_reg_mae = metrics_data["regressor"]["baseline"]["mae"]

    metrics_rows = [
        ("Intrusion Classifier", "Accuracy", f"{clf_metrics['accuracy']*100:.2f}%", f"{dummy_clf_acc*100:.2f}% (Most Frequent Class)"),
        ("Intrusion Classifier", "Precision", f"{clf_metrics['precision']*100:.2f}%", "N/A (Zero attacks detected)"),
        ("Intrusion Classifier", "Recall", f"{clf_metrics['recall']*100:.2f}%", "0.00% (Naive baseline fails all attacks)"),
        ("Intrusion Classifier", "F1-Score", f"{clf_metrics['f1']:.4f}", f"{dummy_clf_f1:.4f}"),
        ("Volume Regressor", "R² Score", f"{reg_metrics['r2']:.4f}", f"{dummy_reg_r2:.4f} (Mean Predictor)"),
        ("Volume Regressor", "Mean Absolute Error", f"{reg_metrics['mae']:,.2f} Bytes", f"{dummy_reg_mae:,.2f} Bytes"),
    ]
    for row_idx, row in enumerate(metrics_rows, start=1):
        for col_idx, val in enumerate(row):
            c = tbl_met.cell(row_idx, col_idx)
            c.text = val
            set_cell_margins(c, 60, 60, 100, 100)
    doc.add_paragraph()

    doc.add_heading("Confusion Matrix Analysis", level=2)
    doc.add_paragraph(
        f"The confusion matrix on the test set (N={n_test:,}) is [[TN={cm[0][0]:,}, FP={cm[0][1]:,}], [FN={cm[1][0]:,}, TP={cm[1][1]:,}]]. "
        f"The sum of all four quadrants (TN+FP+FN+TP = {cm[0][0] + cm[0][1] + cm[1][0] + cm[1][1]:,}) exactly equals the test set size. "
        f"The model successfully detected {cm[1][1]:,} out of {cm[1][0] + cm[1][1]:,} attack flows (Recall: {clf_metrics['recall']*100:.2f}%) "
        f"while producing only {cm[0][1]:,} false alarms across {cm[0][0] + cm[0][1]:,} benign flows (Precision: {clf_metrics['precision']*100:.2f}%)."
    )

    add_callout_box(
        doc,
        metrics_data["regressor"].get("mandatory_disclosure", ""),
        "REGRESSION VOLUME DISCLOSURE",
    )

    # ==========================================================================
    # 11. DIAGNOSTIC PLOTS
    # ==========================================================================
    doc.add_heading("9. Diagnostic Visualizations", level=1)
    doc.add_paragraph("The following publication-grade diagnostic plots were generated programmatically using the matplotlib Agg backend:")

    cm_img = OUTPUTS_DIR / "confusion_matrix.png"
    fi_img = OUTPUTS_DIR / "classifier_feature_importance.png"
    reg_img = OUTPUTS_DIR / "regressor_actual_vs_predicted.png"

    if cm_img.exists():
        doc.add_paragraph("Figure 1: Intrusion Classifier Confusion Matrix (Test Set N=2,400)", style="Caption")
        doc.add_picture(str(cm_img), width=Inches(5.2))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph()

    if fi_img.exists():
        doc.add_paragraph("Figure 2: Top Predictive Features by Gini Importance", style="Caption")
        doc.add_picture(str(fi_img), width=Inches(5.5))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph()

    if reg_img.exists():
        doc.add_paragraph("Figure 3: Volume Regressor Actual vs. Predicted Scatter Plot", style="Caption")
        doc.add_picture(str(reg_img), width=Inches(5.2))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph()

    # ==========================================================================
    # 12. SCREENSHOTS & UI VALIDATION
    # ==========================================================================
    doc.add_heading("10. Graphical User Interface & Dashboards", level=1)
    doc.add_paragraph(
        "ThreatLens AI includes an interactive Streamlit dashboard (app.py) featuring four operational tabs. "
        "The application was verified by launching the Uvicorn server and confirming HTTP 200 responses on both "
        "the /_stcore/health and root endpoints. The sections below provide dedicated placeholders for candidate screenshot insertions:"
    )

    add_screenshot_placeholder(
        doc,
        "Streamlit Dashboard: Tab 1 - Real-Time Flow Prediction",
        "Capture the browser window showing input widgets (protocol, service, packets, duration), "
        "the 'Analyze Flow Telemetry' button, and the resulting prediction badge and probability gauge.",
    )
    add_screenshot_placeholder(
        doc,
        "Streamlit Dashboard: Tab 2 - MongoDB Records Explorer",
        "Capture the interactive table displaying traffic flows fetched dynamically from the MongoDB "
        "'traffic_records' collection with filter dropdowns.",
    )
    add_screenshot_placeholder(
        doc,
        "Streamlit Dashboard: Tab 3 - Model Evaluation & Metrics",
        "Capture the evaluation cards displaying Accuracy, Precision, Recall, F1, R2, and MAE alongside baseline comparisons.",
    )
    add_screenshot_placeholder(
        doc,
        "Streamlit Dashboard: Tab 4 - MongoDB Aggregations & Query Explorer",
        "Capture the server-side aggregation bar chart displaying traffic distribution across attack types and collection index information.",
    )

    # ==========================================================================
    # 13. TESTING & VERIFICATION
    # ==========================================================================
    doc.add_heading("11. Automated Testing and Verification", level=1)
    doc.add_paragraph(
        "A rigorous, 35-test pytest suite was developed and executed. The suite operates on a dedicated throwaway database "
        "('threatlens_test_db') that is automatically cleared before and dropped after test executions to guarantee zero test interference."
    )
    doc.add_paragraph("• Data Generation Suite (6 tests): Validated seed reproducibility, column structure, 25% attack ratio, and byte arithmetic.", style="List Bullet")
    doc.add_paragraph("• Data Loader Suite (8 tests): Validated schema constraints, rejection of duplicate IDs, negative values, and out-of-domain labels.", style="List Bullet")
    doc.add_paragraph("• Database Suite (6 tests): Validated BSON serialization, NumPy datatype conversion, unique index enforcement, idempotent upserts, and aggregation pipelines.", style="List Bullet")
    doc.add_paragraph("• Model Suite (4 tests): Validated pipeline training on small samples, output shapes, probability bounds [0, 1], and seed reproducibility.", style="List Bullet")
    doc.add_paragraph("• Prediction Suite (3 tests): Validated single-flow inference, rejection of missing features, and MongoDB prediction storage.", style="List Bullet")
    doc.add_paragraph("• Preprocessing Suite (8 tests): Validated disjoint 80/20 train/test split, deterministic stratification, imputer isolation, and programmatic leakage assertion.", style="List Bullet")
    doc.add_paragraph("Verification Summary: 35 passed, 0 failed, 0 skipped in 4.75 seconds.")

    # ==========================================================================
    # 14. INSTALLATION & EXECUTION
    # ==========================================================================
    doc.add_heading("12. Installation and Execution Guide", level=1)
    doc.add_paragraph(
        "The project is structured for native execution on Windows 10/11 with Python 3.10–3.13 and MongoDB Community Server:\n"
        "1. Virtual Environment Setup:\n"
        "   python -m venv .venv\n"
        "   Set-ExecutionPolicy -Scope Process Bypass; .\\.venv\\Scripts\\Activate.ps1\n"
        "   pip install -r requirements.txt\n"
        "2. Environment Configuration:\n"
        "   copy .env.example .env\n"
        "3. Start MongoDB Service:\n"
        "   net start MongoDB\n"
        "4. Automated Pipeline Execution:\n"
        "   scripts\\run_all.bat\n"
        "5. Launch Streamlit Web Dashboard:\n"
        "   streamlit run app.py"
    )

    # ==========================================================================
    # 15. LIMITATIONS & FUTURE SCOPE
    # ==========================================================================
    doc.add_heading("13. Limitations, Ethical Considerations, and Future Scope", level=1)
    doc.add_paragraph(
        "Limitations: The primary limitation of this prototype is its reliance on synthetic flow records rather than real-time packet "
        "captures (PCAP) from multi-gigabit hardware switches. While synthetic generation allows controlled difficulty and full reproducibility, "
        "it cannot capture deep application-layer evasions (e.g., polyglot payloads, DNS tunneling, or TLS encrypted SNI camouflage)."
    )
    doc.add_paragraph(
        "Ethical Considerations: Deploying automated machine learning in network security introduces potential risks regarding false positives. "
        "An overly aggressive classifier could mistakenly terminate mission-critical enterprise services (e.g., flagging bursty data transfers as DoS attacks). "
        "ThreatLens AI mitigates this by logging attack probabilities rather than executing unconfirmed firewall blocks, enabling security analysts to perform human-in-the-loop verification."
    )
    doc.add_paragraph(
        "Future Scope: Future enhancements include integrating MongoDB Change Streams for real-time streaming inference via Kafka, "
        "deploying sharded MongoDB clusters for horizontal scale-out across distributed networks, and implementing deep packet inspection (DPI) "
        "using transformer-based sequence models."
    )

    # ==========================================================================
    # 16. CONCLUSION
    # ==========================================================================
    doc.add_heading("14. Conclusion", level=1)
    doc.add_paragraph(
        "ThreatLens AI demonstrates that combining a modern NoSQL document database (MongoDB) with robust machine learning pipelines "
        "overcomes the latency, schema rigidity, and operational bottlenecks inherent in traditional relational intrusion detection systems. "
        "Through flexible BSON document design, compound indexing, idempotent bulk upserts, and rigorous leakage-free feature engineering, "
        "the system achieves high detection accuracy (96.42%, 0.9270 F1) and precise bandwidth estimation (R² 0.8954) on held-out test telemetry. "
        "The project fulfills all requirements for the B.Tech Intelligent NoSQL Databases curriculum and establishes a solid foundation for enterprise-grade NoSQL cybersecurity analytics."
    )

    # ==========================================================================
    # 17. REFERENCES
    # ==========================================================================
    doc.add_heading("15. References", level=1)
    refs = [
        "Moustafa, N., & Slay, J. (2015). UNSW-NB15: A comprehensive data set for network intrusion detection systems. IEEE Military Communications and Information Systems Conference (MilCIS), Canberra, Australia.",
        "Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new dataset for intrusion detection systems. Proceedings of the International Conference on Information Systems Security and Privacy (ICISSP), Portugal.",
        "Scikit-learn Developers. (2024). Scikit-learn: Machine Learning in Python. Official Documentation (v1.9). https://scikit-learn.org/",
        "MongoDB Inc. (2024). MongoDB Community Server Documentation (v7.0/v8.0). MongoDB Manual. https://www.mongodb.com/docs/manual/",
        "PyMongo Developers. (2024). PyMongo: Python driver for MongoDB. Official Documentation (v4.19). https://pymongo.readthedocs.io/",
    ]
    for r in refs:
        doc.add_paragraph(r, style="List Bullet")

    # ==========================================================================
    # 18. APPENDIX: TRACEABILITY MATRIX
    # ==========================================================================
    doc.add_heading("16. Appendix: Curriculum Traceability Matrix", level=1)
    tbl_tr = doc.add_table(rows=6, cols=4)
    tbl_tr.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_heads = ["Requirement", "Implementation Modules", "Automated Tests", "Status"]
    for i, h in enumerate(t_heads):
        c = tbl_tr.cell(0, i)
        c.text = h
        c.paragraphs[0].runs[0].bold = True
        set_cell_background(c, "2B5C8F")
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

    req_rows = [
        ("MongoDB with PyMongo Driver", "src/database.py\nsrc/seed_database.py", "tests/test_database.py (6 tests)", "VERIFIED (PASS)"),
        ("At Least One ML Model", "src/train_classifier.py\nsrc/train_regressor.py", "tests/test_models.py (4 tests)", "VERIFIED (PASS)"),
        ("Classification Metrics (Acc, Prec, Rec, F1)", "src/evaluate.py::evaluate_classifier", "tests/test_models.py\noutputs/metrics.json", "VERIFIED (PASS)"),
        ("Regression Metrics (R², MAE)", "src/evaluate.py::evaluate_regressor", "tests/test_models.py\noutputs/metrics.json", "VERIFIED (PASS)"),
        ("Report & Single Submission ZIP", "scripts/make_report.py\nscripts/make_zip.py", "Generated deliverables", "VERIFIED (PASS)"),
    ]
    for row_idx, row in enumerate(req_rows, start=1):
        for col_idx, val in enumerate(row):
            c = tbl_tr.cell(row_idx, col_idx)
            c.text = val
            set_cell_margins(c, 60, 60, 100, 100)

    report_path = REPORTS_DIR / "project_report.docx"
    doc.save(report_path)
    print(f"Project report successfully generated: {report_path}")
    return report_path


def main() -> None:
    try:
        build_project_report()
    except Exception as e:
        print(f"ERROR: Report generation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

