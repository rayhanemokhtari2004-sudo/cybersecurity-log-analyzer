# CYBER SENTINEL — SSH Threat Detection & Security Monitoring

Cyber Sentinel is a lightweight Security Operations Center (SOC) dashboard and backend engine designed to analyze Linux/SSH authentication logs (`auth.log`), detect brute force attacks in real-time using a sliding window algorithm, calculate dynamic IP risk scores, and present security insights via an interactive dark-mode dashboard.

---

## 🎯 Features

- **SSH Authentication Log Parsing**: Extracts success, failure, and invalid user login events with port and IP metadata.
- **Idempotent SQLite Database Storage**: Guarantees zero duplicate logs or alerts across repeated executions.
- **Dynamic Risk Scoring Engine**: Evaluates threat levels (LOW, MEDIUM, HIGH, CRITICAL) per IP based on failed login attempt counts.
- **Sliding Window Brute Force Detection**: Evaluates 5-minute time windows ($\ge 5$ failed attempts) to trigger immediate security alerts.
- **Interactive SOC Dashboard**: Cyber dark-mode single-page interface powered by Streamlit and Plotly.
- **IP Deep Investigation**: Interactive dropdown for granular IP-level security assessment and timeline inspection.
- **Log Explorer**: Structured log table with multi-criteria real-time filtering (IP, Username, Status).
- **Unit Test Suite**: Full test coverage with `pytest` for parsing, risk scoring, sliding window detection, and database idempotency.

---

## 🏗️ Architecture

```text
auth.log
   ↓
Parser (parser.py)
   ↓
SQLite Database (security_logs.db)
   ↓
IP Statistics (statistics.py)
   ↓
Brute Force Detection (detector.py)
   ↓
Risk Scoring (risk_scoring.py)
   ↓
Security Alerts (alerts.py)
   ↓
Cyber Sentinel SOC Dashboard (dashboard/app.py)
```

---

## 📊 Risk Scoring Matrix

| Failed Attempts | Risk Score | Risk Level | Threat Category |
| :--- | :---: | :---: | :--- |
| **$< 3$ attempts** | `10` | `LOW` | Standard activity / minor errors |
| **$3 - 4$ attempts** | `40` | `MEDIUM` | Suspicious activity |
| **$5 - 9$ attempts** | `70` | `HIGH` | Potential Brute Force |
| **$\ge 10$ attempts** | `100` | `CRITICAL` | Severe Brute Force Attack |

---

## ⚡ Brute Force Detection Rule

- **Window Size**: 5 minutes (`WINDOW_MINUTES = 5`)
- **Threshold**: 5 failed authentication attempts (`FAILED_THRESHOLD = 5`)
- **Trigger**: If an IP records $\ge 5$ failed login attempts within any 5-minute sliding window, a `BRUTE FORCE DETECTED` security alert is generated and stored in SQLite.

---

## 🚀 Installation & Setup

1. **Clone or navigate to the repository:**
   ```bash
   cd cybersecurity-log-analyzer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

### 1. Run Backend Analysis Pipeline
To execute log parsing, database storage, risk calculation, and threat detection via CLI:
```bash
python main.py
```

### 2. Launch Cyber Sentinel SOC Dashboard
To start the interactive web application:
```bash
streamlit run dashboard/app.py
```

---

## 🧪 Running Unit Tests

Run the Pytest suite to verify parser, scoring, detection, and database logic:
```bash
pytest -v
```
