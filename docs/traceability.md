# ThreatLens AI: Complete Requirements Traceability Matrix

This traceability matrix maps every project requirement, faculty specification, and academic constraint to its concrete implementation files, functions, automated tests, and report sections.

---

## 1. Faculty & Curriculum Requirements Matrix

| ID | Requirement Description | Implementation File(s) | Key Function(s) | Automated Test Name(s) | Project Report Section |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **REQ-01** | **MongoDB Database with PyMongo Driver** | `src/database.py`<br>`src/seed_database.py`<br>`src/db_demo.py` | `get_client()`<br>`ping()`<br>`ensure_indexes()`<br>`upsert_traffic_records()`<br>`aggregate_by_attack_type()` | `tests/test_database.py::test_unique_index_rejects_duplicates`<br>`tests/test_database.py::test_idempotent_seeding`<br>`tests/test_database.py::test_aggregation_pipeline_result` | Section 6: MongoDB Document Design & PyMongo Implementation |
| **REQ-02** | **At Least One Machine Learning Model** | `src/train_classifier.py`<br>`src/train_regressor.py` | `train_classifier()`<br>`train_regressor()`<br>`build_preprocessor()` | `tests/test_models.py::test_classifier_training_and_probability_range`<br>`tests/test_models.py::test_regressor_training_and_output_shape`<br>`tests/test_models.py::test_model_reproducibility_with_seed` | Section 8: Model Architecture & Classification Implementation<br>Section 9: Flow Volume Regression Implementation |
| **REQ-03A**| **Classification Evaluation Metrics** (Accuracy, Precision, Recall, F1) | `src/evaluate.py`<br>`src/predict.py` | `evaluate_classifier()`<br>`predict_one()`<br>`predict_batch()` | `tests/test_predict.py::test_predict_one_valid`<br>`tests/test_models.py::test_classifier_training_and_probability_range` | Section 10: Evaluation Methodology & Results |
| **REQ-03B**| **Regression Evaluation Metrics** ($R^2$, MAE) | `src/evaluate.py`<br>`src/predict.py` | `evaluate_regressor()`<br>`predict_one()` | `tests/test_models.py::test_regressor_training_and_output_shape` | Section 10: Evaluation Methodology & Results |
| **REQ-04** | **Mandatory Academic Report Sections** (Intro, Objectives, Dataset, MongoDB, Preprocessing, Evaluation, Conclusion) | `scripts/make_report.py` | `build_project_report()` | Verification inspection of `reports/project_report.docx` | Sections 1 through 15 in generated `.docx` |
| **REQ-05** | **Single Deliverable Submission ZIP** | `scripts/make_zip.py` | `create_submission_zip()` | Verification inspection of `ThreatLens-AI-Submission.zip` | Section 13: Installation & Clean-Room Execution |

---

## 2. Technical & Behavioral Constraints Matrix

| ID | Constraint Specification | Implementation Details | Verification Method |
| :--- | :--- | :--- | :--- |
| **CON-01** | **Pathlib Everywhere** | Standardized `Path` objects across all `src/`, `scripts/`, and `tests/` modules. | Verified across all imports and path manipulation functions. |
| **CON-02** | **Module Execution** (`python -m src.<module>`) | All executable files feature standardized `if __name__ == "__main__": main()` blocks. | Verified in `scripts/run_all.bat` and CLI runs. |
| **CON-03** | **No Localhost (`127.0.0.1` strictly used)** | Standardized in `src/config.py`, `.env.example`, and test fixtures. | Verified in network connection tests and configuration files. |
| **CON-04** | **Data Leakage Prevention** | `src/preprocessing.py::assert_no_leakage()` strictly verifies that target and identifier columns are absent from feature matrices. | `tests/test_preprocessing.py::test_assert_no_leakage_catches_target`<br>`tests/test_preprocessing.py::test_assert_no_leakage_catches_leakage_column` |
| **CON-05** | **Deterministic Splitting** | Stratified 80/20 train/test split seeded with `RANDOM_SEED=42`. | `tests/test_preprocessing.py::test_stratified_split_proportions`<br>`tests/test_preprocessing.py::test_split_disjoint`<br>`tests/test_preprocessing.py::test_deterministic_split` |
| **CON-06** | **Idempotent Database Upserts** | `UpdateOne({"record_id": ...}, {"$set": ...}, upsert=True)` executed in batches of 1,000. | `tests/test_database.py::test_idempotent_seeding` (asserts document count remains constant on re-run). |
| **CON-07** | **PyMongo Type Safety** | `to_native()` recursively converts `numpy.int64`, `numpy.float64`, and `numpy.ndarray` to Python primitives. | `tests/test_database.py::test_to_native_numpy_types`<br>`tests/test_database.py::test_numpy_types_insert_ok` |
| **CON-08** | **Document Serialization** | `serialize()` transforms `ObjectId` to string and `datetime` to ISO-8601 strings. | `tests/test_database.py::test_serialize_handles_objectid_and_datetime` |
| **CON-09** | **Clear Connection Errors & Masking** | Catches `ServerSelectionTimeoutError` and raises `MongoUnavailableError` with masked URI. | `tests/test_database.py` and Phase 6 error verification test in `outputs/verification_log.txt`. |
| **CON-10** | **Publication-Quality Artifacts** | Matplotlib Agg backend used to save PNG plots to `outputs/`. | Verified existence of `confusion_matrix.png`, `classifier_feature_importance.png`, `regressor_actual_vs_predicted.png`. |

