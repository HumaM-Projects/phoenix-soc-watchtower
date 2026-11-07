# SOC Watchtower 🛡️

A defensive educational SOC log triage dashboard built with Python, Streamlit, Pandas, and SQLite.

## Features
- Dark SOC dashboard, metrics, severity chart, and event timeline.
- Demo dataset or sanitized CSV upload.
- Configurable failed-login threshold and detection window.
- Rule-based repeated-failure, post-failure-success, and privileged-account review alerts.
- Alert triage and incident investigation panel.
- **Persistent analyst notes stored locally in SQLite.**
- Investigation history table and CSV export; alert report CSV export.

## Windows setup
Open CMD in this folder:
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
streamlit run app.py
```
In PowerShell, if activation is blocked:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## CSV format
Required columns: `timestamp, source_ip, username, event_type, status, details`

Use sanitized training data only. Never upload passwords, tokens, or confidential production logs.

## SQLite database
The app creates `soc_watchtower.db` automatically in this folder. Select an alert, enter analyst notes, and click **Save investigation notes**. Notes remain available after closing and reopening the app. Keep this database file to retain records. Do not publish sensitive records to a public GitHub repository.

## Limitations
This is a rule-based educational prototype, not a production SIEM. Alerts may be false positives or miss events. MITRE mappings are contextual associations, not proof of compromise.
