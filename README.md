# 🛡️ Phoenix SOC Watchtower

### Defensive Security Log Monitoring & Incident Investigation Dashboard

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Streamlit](https://img.shields.io/badge/Framework-Streamlit-red)
![Database](https://img.shields.io/badge/Database-SQLite-lightgrey)
![Security](https://img.shields.io/badge/Focus-Blue%20Team-blue)
![Project](https://img.shields.io/badge/Project-Educational-success)

## 📌 Project Overview

**Phoenix SOC Watchtower** is a defensive and educational Security Operations Center (SOC) log monitoring and investigation dashboard developed using Python, Streamlit, Pandas, and SQLite.

The project helps security analysts review security events, identify suspicious login patterns, prioritize alerts based on severity, and maintain incident investigation records.

It demonstrates basic SOC analyst workflows in a practical and interactive environment.

## 🎯 Project Objectives

- Understand security log monitoring and analysis.
- Identify suspicious authentication activities.
- Prioritize security alerts according to severity.
- Practice incident investigation workflows.
- Maintain persistent analyst investigation notes.
- Understand basic SIEM and Blue Team concepts.

## ✨ Key Features

### 1. Security Monitoring Dashboard
- Dark-themed SOC dashboard.
- Security event metrics.
- Alert severity visualization.
- Security event timeline.

### 2. Log Analysis
- Built-in demonstration dataset.
- Sanitized CSV log upload.
- Configurable failed-login threshold.
- Configurable detection time window.

### 3. Alert Detection
- Repeated failed-login detection.
- Post-failure successful-login detection.
- Privileged-account activity review.
- Rule-based alert generation.

### 4. Incident Investigation
- Alert triage and investigation panel.
- Alert identification and severity review.
- Contextual MITRE ATT&CK associations.
- Analyst investigation notes.

### 5. Investigation History
- SQLite-based persistent storage.
- Save investigation notes.
- Review previous investigations.
- Export investigation history to CSV.
- Export alert reports to CSV.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming |
| Streamlit | Interactive dashboard |
| Pandas | Log processing and analysis |
| SQLite | Persistent investigation storage |
| CSV | Security log input and report export |
| Git & GitHub | Version control and project hosting |

## 🏗️ Project Structure

```text
phoenix-soc-watchtower/
│
├── app.py
├── detector.py
├── storage.py
├── sample_logs.csv
├── requirements.txt
├── README.md
├── .gitignore
│
└── tests/
    └── test_detector.py
```

## ⚙️ Installation and Setup

### Prerequisites

- Windows 10 or later
- Python installed
- Git installed
- Internet connection for installing dependencies

### Step 1: Clone the repository

```bash
git clone https://github.com/HumaM-Projects/phoenix-soc-watchtower.git
```

### Step 2: Open the project folder

```bash
cd phoenix-soc-watchtower
```

### Step 3: Create a virtual environment

```bash
python -m venv .venv
```

### Step 4: Activate the environment

For Windows CMD:

```bash
.venv\Scripts\activate.bat
```

For PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Step 5: Install dependencies

```bash
python -m pip install -r requirements.txt
```

### Step 6: Run the dashboard

```bash
streamlit run app.py
```

The Streamlit application will open in your browser.

## 📄 CSV Log Format

The application expects these required columns:

```text
timestamp
source_ip
username
event_type
status
details
```

Use sanitized training data when uploading logs.

Never upload passwords, authentication tokens, or confidential production logs.

## 🗄️ Database and Data Storage

The application automatically creates a local SQLite database:

```text
soc_watchtower.db
```

Investigation notes are stored locally so they remain available after closing and reopening the application.

The database is excluded from GitHub through `.gitignore` to avoid publishing potentially sensitive investigation records.

## 🔍 Example SOC Workflow

1. Open the SOC dashboard.
2. Review security monitoring metrics.
3. Select a security alert.
4. Examine its severity and investigation details.
5. Review the contextual MITRE ATT&CK mapping.
6. Add analyst investigation notes.
7. Save the investigation.
8. Review investigation history and export reports.

## 🧪 Testing

The project includes a detector test file:

```text
tests/test_detector.py
```

Run tests using:

```bash
python -m pytest
```

Install pytest first if it is not already included in the environment:

```bash
python -m pip install pytest
```

## ⚠️ Limitations

- This is an educational, rule-based SOC prototype.
- It is not a production SIEM platform.
- Detection rules may generate false positives or miss suspicious activity.
- MITRE ATT&CK mappings are contextual associations, not proof of compromise.
- Test only with authorized and sanitized data.

## 🚀 Future Improvements

- Advanced log correlation.
- Additional detection rules.
- Enhanced threat intelligence integration.
- More detailed incident reporting.
- Role-based analyst access.
- Advanced SIEM-style monitoring capabilities.

## 👩‍💻 Developer

**Huma Nawab**

GitHub: [@HumaM-Projects](https://github.com/HumaM-Projects)

Project Repository: [Phoenix SOC Watchtower](https://github.com/HumaM-Projects/phoenix-soc-watchtower)

---

⭐ If you find this educational project useful, feel free to explore the repository.

**Built for learning, defensive security, and SOC analyst skill development.**
