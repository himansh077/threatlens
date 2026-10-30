# Windows MongoDB Community Server Setup Guide

This guide provides step-by-step instructions for installing, configuring, starting, and verifying **MongoDB Community Server** as a native Windows Service for **ThreatLens AI**.

---

## 1. Installation Instructions

1. **Download the Installer**:
   - Download the official MongoDB Community Server MSI package from [MongoDB Download Center](https://www.mongodb.com/try/download/community).
   - Select **Version**: `7.0.x` or `8.0.x`, **Platform**: `Windows x64`, **Package**: `MSI`.

2. **Run the Installer**:
   - Double-click the downloaded `.msi` file.
   - Choose **Complete** setup type.
   - In the **Service Configuration** dialog:
     - Ensure **"Install MongoDB as a Service"** is checked (default).
     - Select **"Run service as Network Service user"**.
     - Service Name: `MongoDB`.
     - Data Directory: `C:\Program Files\MongoDB\Server\<version>\data\`.
     - Log Directory: `C:\Program Files\MongoDB\Server\<version>\log\`.
   - **MongoDB Compass**: You may choose to install MongoDB Compass (recommended for graphical inspection) or uncheck it to speed up installation.
   - Click **Install** and grant Administrator permissions when prompted.

---

## 2. Managing the Windows MongoDB Service

Open **PowerShell** or **Command Prompt** as **Administrator** (Right-click -> "Run as administrator"):

### Start the Service:
```cmd
net start MongoDB
```
*Expected Output:*
```
The MongoDB Server (MongoDB) service is starting.
The MongoDB Server (MongoDB) service was started successfully.
```

### Check Service Status:
```powershell
Get-Service -Name MongoDB
```
*Expected Output:*
```
Status   Name               DisplayName
------   ----               -----------
Running  MongoDB            MongoDB Server (MongoDB)
```

### Stop the Service (when finished):
```cmd
net stop MongoDB
```

### Restart the Service:
```cmd
net stop MongoDB && net start MongoDB
```

---

## 3. Verifying the Connection

You can verify that MongoDB is listening on local port `27017` using PowerShell or Python:

### Option A: PowerShell TCP Test
```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 27017
```
*Expected Result:* `TcpTestSucceeded : True`

### Option B: Python Ping Test
```powershell
python -c "from src.database import ping; print('Connected!' if ping() else 'Failed!')"
```
*Expected Result:* `Connected!`

---

## 4. Configuration & Troubleshooting

### Error: `Cannot reach MongoDB at mongodb://127.0.0.1:27017`
1. **Service Not Running**:
   - Run `net start MongoDB` as Administrator.
2. **Port Conflict**:
   - Verify what process is listening on port 27017:
     ```powershell
     Get-NetTCPConnection -LocalPort 27017
     ```
3. **Firewall or Antivirus**:
   - Ensure loopback connections (`127.0.0.1`) are permitted.
4. **Log Inspection**:
   - Inspect the mongod log file located at:
     `C:\Program Files\MongoDB\Server\<version>\log\mongod.log`
   - Look for error lines indicating unhandled shutdowns or corrupted lock files (`mongod.lock`).

### Error: `System.UnauthorizedAccessException` in PowerShell
If activating the virtual environment (`.\.venv\Scripts\Activate.ps1`) throws an execution policy error, run:
```powershell
Set-ExecutionPolicy -Scope Process Bypass
```
This safely permits script execution for the current terminal session without permanently altering system security policies.

---

## 5. Offline / CSV Fallback Mode

If MongoDB cannot be installed on a test machine, ThreatLens AI supports strict offline execution:
```powershell
# Train models directly from CSV
python -m src.train_classifier --source csv
python -m src.train_regressor --source csv

# Run evaluation on local dataset
python -m src.evaluate --source csv
```
*(Note: Mandatory submission requirements specify MongoDB. If evaluating for final submission grading, ensure the MongoDB service is active).*

