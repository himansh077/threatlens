@echo off
setlocal enabledelayedexpansion

echo ======================================================================
echo ThreatLens AI - Automated Pipeline Execution (Windows)
echo ======================================================================

echo [1/7] Generating synthetic traffic dataset...
python scripts\generate_data.py
if errorlevel 1 goto error

echo [2/7] Seeding MongoDB 'traffic_records' collection...
python -m src.seed_database
if errorlevel 1 goto error

echo [3/7] Training Intrusion Classifier (MongoDB Source)...
python -m src.train_classifier --source mongo
if errorlevel 1 goto error

echo [4/7] Training Flow Volume Regressor (MongoDB Source)...
python -m src.train_regressor --source mongo
if errorlevel 1 goto error

echo [5/7] Running Evaluation Suite and Diagnostic Plots...
python -m src.evaluate --source mongo
if errorlevel 1 goto error

echo [6/7] Executing MongoDB Interactive Demonstration Suite...
python -m src.db_demo
if errorlevel 1 goto error

echo [7/7] Running Complete Pytest Suite...
pytest -v
if errorlevel 1 goto error

echo ======================================================================
echo THREATLENS AI PIPELINE COMPLETED SUCCESSFULLY!
echo ======================================================================
exit /b 0

:error
echo ======================================================================
echo PIPELINE EXECUTION FAILED AT ERROR CODE %errorlevel%
echo ======================================================================
exit /b 1

