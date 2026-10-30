# ThreatLens AI: Verification Checklist & Execution Log

This checklist documents every verification stage, the exact command executed, expected output, observed output, and actual pass/fail status in this Windows environment.

---

| Phase | Description | Command Executed | Expected Output | Observed Output | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Environment Inspection | `python --version`<br>`Get-Service -Name '*mongo*'`<br>`Test-NetConnection -Port 27017` | Python 3.10–3.13, MongoDB service running, TCP port 27017 reachable | Python 3.13.15, mongod PID 5504 running, TcpTestSucceeded: True | **PASS** |
| **Phase 2** | Project Scaffolding | `pip install -r requirements.txt`<br>`python -c "import src.config"` | Dependencies install cleanly, pinned `requirements.txt` written, config loads | Pinned requirements.txt generated, config loaded successfully | **PASS** |
| **Phase 3** | Data Generator & Loader | `python scripts/generate_data.py` (Run 1 & 2) | 12,000 flows generated, class distribution printed, identical SHA-256 hash | 12,000 flows, SHA-256 `fd5ed63a...1765` matched on consecutive runs | **PASS** |
| **Phase 4** | Preprocessing & Splitting | `python -c "from src.preprocessing import ..."` | 80/20 train/test split, stratified, no overlap, leakage assertions caught | 9,600 train / 2,400 test, 0 overlap, leakage exception caught on injected column | **PASS** |
| **Phase 5** | CSV-Mode Model Training | `python -m src.train_classifier --source csv`<br>`python -m src.train_regressor --source csv` | Both joblib models serialized and reloadable | `classifier.joblib` & `regressor.joblib` created, features & pipelines reloaded | **PASS** |
| **Phase 6** | Database Layer & Indexes | `python -c "from src.database import ..."` | Ping succeeds, 3 collection indexes created, masked URI on invalid connection | Ping True, unique & compound indexes verified, error masked credentials | **PASS** |
| **Phase 7** | Seeding & DB Demos | `python -m src.seed_database` (x2)<br>`python -m src.db_demo` | Run 1: 12,000 upserted; Run 2: 12,000 modified (count stays 12,000); 9 demos run | Document count constant at 12,000; all 9 CRUD, $lookup, and explain demos passed | **PASS** |
| **Phase 8** | Mongo-Source Train & Evaluate | `python -m src.train_classifier --source mongo`<br>`python -m src.train_regressor --source mongo`<br>`python -m src.evaluate --source mongo` | Metrics computed on test set, plots generated, metrics.json written, 2 Mongo records | Accuracy: 96.42%, F1: 0.9270, $R^2$: 0.8954, MAE: 42,383 bytes; 3 plots; 2 Mongo docs | **PASS** |
| **Phase 9** | Prediction Engine CLI | `python -m src.predict --record-id TL-000001`<br>`python -m src.predict --sample 5`<br>`python -m src.predict --input-json data/sample_input.json` | Single flow, batch sample, and JSON file evaluated and stored in predictions collection | All 3 modes executed successfully; predictions collection reached 8 documents | **PASS** |
| **Phase 10**| Pytest Test Suite | `pytest -v` | All tests pass, 0 failures, 0 skips | **35 passed in 4.75s** across all test categories | **PASS** |
| **Phase 11**| Streamlit Web App | `streamlit run app.py` | App starts on port 8501, HTTP 200 on health and main routes | Server started on port 8501, health route 200, main route 200 | **PASS** |
| **Phase 11 (Screenshots)** | Browser UI Captures | Browser capture to `reports/screenshots/` | PNG screenshots of 4 tabs | *NOT RUN IN THIS ENVIRONMENT* (Headless CLI agent without graphical browser; boxed placeholders provided) | **NOT RUN IN THIS ENVIRONMENT** |
| **Phase 12**| Documentation Suite | Inspection of docs/ and README.md | README, MONGODB_SETUP_WINDOWS, traceability, checklist, VIVA_QA complete | All 5 documentation files created with full technical depth | **PASS** |
| **Phase 13**| Academic Report Generation | `python scripts/make_report.py` | Complete .docx generated with real numbers from metrics.json | Generated `reports/project_report.docx` (240 KB, 16 sections, 3 figures) | **PASS** |
| **Phase 14**| Clean-Room ZIP Check | `python scripts/make_zip.py`<br>Unzip & clean-room test | Fresh folder execution succeeds, exclusions verified | Clean-room extract to fresh dir, 35/35 tests passed in 4.72s, all exclusions verified | **PASS** |
