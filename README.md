# Defensive SOC Project

A simple Python-based Security Operations Center (SOC) project to detect suspicious activity from SSH and Apache logs.

## 🔧 Tools Used
- Python
- Regex
- Matplotlib
- Pandas

## Folders
- `logs/` → Contains `ssh.log` and `apache.log`
- `blacklist/` → Contains `blacklist.txt`
- `output/` → Stores generated alerts (CSV)

## Features
- Detects SSH brute-force attacks
- Detects Apache web scanning
- Visualizes attacks with charts
- Checks against a blacklist

## ▶️ Commands to Run the Project
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main.py
