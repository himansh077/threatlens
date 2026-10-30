# ThreatLens AI: Comprehensive Viva Voce Defense Guide

This guide prepares the student for oral defense (viva voce) for the B.Tech course **"Intelligent NoSQL Databases" (CSE494)**. It covers conceptual, mathematical, architectural, and practical questions likely to be asked by examiners.

---

## 1. Architectural & Database Design (MongoDB & PyMongo)

### Q1: Why did you choose MongoDB (a NoSQL document store) instead of a relational database (PostgreSQL/MySQL) for network traffic telemetry?
**Answer:**
Network traffic telemetry exhibits three core characteristics that make document databases particularly well-suited:
1. **Dynamic Schema & Heterogeneous Protocols**: Different network protocols have vastly different metadata attributes (e.g., DNS has query domains and record types; HTTP has methods, status codes, and URI lengths; TCP has window sizes and flag ratios; ICMP has type/code). In a relational schema, this leads to sparse tables with numerous NULL columns or excessive normalization (`JOIN` penalties). MongoDB documents natively encapsulate variable attributes within a single self-contained BSON document.
2. **High-Throughput Ingestion**: Network links generate thousands of flows per second. MongoDB’s bulk write capabilities (`UpdateOne` with `upsert=True` in unordered batches) allow high-throughput ingestion with minimal write locks.
3. **Embedded Inference Snapshots**: When storing ML predictions in relational databases, an analyst must either join multiple tables or duplicate schemas. In MongoDB, we embed an `input_snapshot` document inside the prediction document, guaranteeing an immutable audit trail of the exact feature values that produced that specific classification score.

### Q2: Explain the indexing strategy used in ThreatLens AI and how you proved it works.
**Answer:**
We created targeted indexes on each collection:
- `traffic_records`:
  - `uniq_record_id` (`{"record_id": 1}`, Unique): Guarantees entity integrity and makes single-flow lookups $O(1)$.
  - `compound_label_attack` (`{"label": 1, "attack_type": 1}`): Accelerates queries filtering on attack classification and subcategory.
  - `idx_split` (`{"split": 1}`): Enables rapid retrieval of the 80% train and 20% test partitions without in-memory filtering.
- `predictions`:
  - `compound_rec_model` (`{"record_id": 1, "model_version": 1}`): Fast lookups for prior model evaluations on specific flows.
  - `idx_created_at_desc` (`{"created_at": -1}`): Optimizes real-time dashboard feeds querying the newest predictions.

**Verification**: In `src/db_demo.py` (Demo 9), we ran `.explain("executionStats")` on a query for `record_id="TL-000001"`. The execution stage returned `EXPRESS_IXSCAN` utilizing the `uniq_record_id` index rather than a `COLLSCAN` (full collection scan), proving the index was used.

### Q3: How do you handle relationships between `predictions` and `traffic_records` in MongoDB?
**Answer:**
While MongoDB is non-relational, it supports relational joins through value references and the `$lookup` aggregation stage.
In ThreatLens AI, the `predictions` collection references the `traffic_records` collection via the `record_id` field. In `src/db_demo.py` (Demo 8), we execute:
```javascript
db.predictions.aggregate([
  { $match: { record_id: "TL-000002" } },
  {
    $lookup: {
      from: "traffic_records",
      localField: "record_id",
      foreignField: "record_id",
      as: "raw_traffic_flow"
    }
  }
])
```
This joins the raw flow telemetry into the prediction document on demand without violating schema denormalization best practices.

### Q4: What PyMongo gotchas did you encounter and how did you resolve them?
**Answer:**
1. **NumPy Datatypes**: PyMongo cannot natively BSON-encode NumPy scalar types (e.g., `numpy.int64`, `numpy.float64`, `numpy.bool_`), raising an `InvalidDocument` encoding exception. We implemented the `to_native()` function in `src/database.py`, which recursively converts all NumPy numbers and arrays into standard Python `int`, `float`, `bool`, and `list` primitives before insertion.
2. **JSON Serialization**: Standard `json.dumps()` fails on MongoDB documents containing BSON `ObjectId` and Python `datetime` objects. We engineered `serialize()`, which converts `ObjectId` to hex strings and `datetime` to ISO-8601 strings.
3. **Idempotent Ingestion**: To ensure that running database seeding repeatedly never creates duplicate documents or inflates collection count, we used `UpdateOne({"record_id": doc["record_id"]}, {"$set": doc}, upsert=True)`.

---

## 2. Machine Learning Methodology & Evaluation

### Q5: Why is Accuracy alone deceptive for evaluating our Intrusion Detection classifier?
**Answer:**
In network security and intrusion detection, datasets are inherently class-imbalanced. In our dataset, **75% of flows are benign (normal)** and **25% are attacks**.
If a naive classifier (or the `DummyClassifier(strategy='most_frequent')`) simply predicts "Normal (0)" for 100% of flows, it achieves an **accuracy of 74.08%** without detecting a single cyber attack. Its **Recall is 0.00%**, its **Precision is 0.00%**, and its **F1-Score is 0.0000**.
Therefore, accuracy creates a false sense of security. **Recall** (the percentage of actual attacks successfully flagged) and **F1-Score** (harmonic mean of precision and recall) are the definitive operational metrics. ThreatLens AI achieves **98.20% Precision**, **87.78% Recall**, and **92.70% F1-Score**.

### Q6: Why did you build two separate models (Classifier and Regressor), and how is independence guaranteed?
**Answer:**
They solve distinct operational problems in network security management:
1. **Intrusion Classifier (`RandomForestClassifier`)**: A classification model predicting discrete binary attack probability (`label`: 0 vs 1) for automated incident triage and threat mitigation.
2. **Flow Volume Regressor (`RandomForestRegressor`)**: A continuous estimation model predicting transferred bytes (`total_bytes`) for bandwidth allocation, capacity planning, and baseline anomaly detection.

**Independence Guarantee**:
- **Target Independence**: Classifier predicts `label`; Regressor predicts `total_bytes`.
- **Feature Independence**: The classifier feature set (12 features) includes security flags such as `failed_logins` and `syn_flag_ratio`. The regressor feature set (10 features) completely excludes `failed_logins`, `syn_flag_ratio`, `label`, and `attack_type`.
- **No Cascading**: No output of the classifier is passed to the regressor, and no output of the regressor is passed to the classifier.

### Q7: What do $R^2$ and MAE mean for the Regressor, and what is the Mandatory Disclosure?
**Answer:**
- **MAE (Mean Absolute Error)**: Measures the average magnitude of prediction errors in actual engineering units (bytes). Our regressor achieves an MAE of **42,383 bytes**, compared to the Dummy baseline MAE of **258,411 bytes**, representing an 83.6% reduction in volume prediction error.
- **$R^2$ (Coefficient of Determination)**: Measures the proportion of variance in total bytes explained by the input features. Our model achieves **0.8954** ($89.54\%$ variance explained), compared to the Dummy baseline $R^2$ of **-0.0017**.

**Mandatory Methodology Disclosure**:
In this synthetic dataset, packet bytes are generated based on service-specific packet size distributions multiplied by packet counts with log-normal noise. Because of this mathematical relationship, a high $R^2$ primarily confirms that the data preprocessing, ColumnTransformer encodings, and Random Forest regression pipeline work properly end-to-end, rather than claiming human-level payload estimation skill on unconstrained real-world Internet connections.

### Q8: How did you prevent Data Leakage between the training and test splits?
**Answer:**
We enforced five strict leakage-prevention mechanisms:
1. **Stratified Split Before Modeling**: The 80/20 train/test split is assigned at data generation and fixed in the `split` column using `assign_split(random_state=42)`.
2. **Strict Filtering**: Training scripts strictly filter `df[df["split"] == "train"]`. Testing and evaluation scripts strictly filter `df[df["split"] == "test"]`.
3. **Preprocessor Imputation Isolation**: The `SimpleImputer(strategy='median')` is fitted exclusively on `X_train`. The computed median statistics are then used to transform `X_test`. We verified this in unit test `test_imputer_statistics_isolated_to_train`.
4. **Programmatic Leakage Assertion**: In `src/preprocessing.py`, `assert_no_leakage(features, target)` verifies that neither the target nor any column from `LEAKAGE_COLUMNS` (`record_id`, `src_bytes`, `dst_bytes`, `total_bytes`, `attack_type`, `split`) is present in the feature list.
5. **No Monotonic Feature Scaling**: Standard scaling (mean/variance) can leak test set variance if applied across the whole dataframe. We intentionally omitted scaling because Random Forests are tree ensembles that split on feature order rather than scale.

### Q9: Why did you use Synthetic Data rather than a real-world PCAP capture?
**Answer:**
1. **Academic Reproducibility**: Live network PCAP datasets (e.g., DARPA 1999, KDD Cup 99, UNSW-NB15) are either gigabytes in size or contain obsolete network signatures. A synthetic generator with a fixed random seed (`seed=42`) allows examiners to reproduce the exact 12,000 flows and identical SHA-256 file hash on any laptop in seconds.
2. **Known Ground Truth & Controlled Difficulty**: Real network captures often contain mislabeled packets or proprietary encryption. With our synthetic generator, we controlled specific difficulty parameters:
   - 8% stealthy attacks (attacks with benign-like packet distributions)
   - 5% bursty benign flows (legitimate high-rate downloads)
   - 2% realistic telemetry label noise
   This prevents trivial 100% separability and demonstrates realistic false-positive / false-negative trade-offs.
3. **Data Provenance Compliance**: Synthetic data eliminates privacy, GDPR, and enterprise confidentiality concerns.

---

## 3. Quick Reference Metric Summary (For Viva Presentation)

```
========================================================================
TRAINING SPLIT: 9,600 Flows (80%) | TEST SPLIT: 2,400 Flows (20%)
========================================================================
Intrusion Classifier (RandomForestClassifier):
- Accuracy:  96.42% (Baseline: 74.08%)
- Precision: 98.20%
- Recall:    87.78%
- F1-Score:  92.70% (Baseline: 0.00%)
- Confusion Matrix: [[TN=1768, FP=10], [FN=76, TP=546]] (Sum = 2,400)

Flow Volume Regressor (RandomForestRegressor):
- R² Score: 0.8954 (Baseline: -0.0017)
- MAE:      42,383 Bytes (~41.4 KB) (Baseline: 258,411 Bytes)

Database:
- Collections: traffic_records (12,000 docs), predictions, model_metrics
- Pytest Suite: 35 passed in 4.75s (0 failures, 0 skips)
========================================================================
```

