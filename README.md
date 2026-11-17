# 🛡️ Cloud Intrusion Detection System (IDS)

A professional, real-time Cloud IDS dashboard built with Python + Streamlit.
Designed as a portfolio/resume project for cybersecurity and cloud engineering roles.

---

## 📁 Project Structure

```
cloud_ids/
├── main.py          # Streamlit dashboard (UI entry point)
├── detector.py      # Intrusion detection engine (rule-based + anomaly)
├── simulator.py     # Network traffic generator
├── utils.py         # Helper functions (export, filter, stats)
├── requirements.txt # Python dependencies
└── README.md        # This file
```

---

## 🚀 Setup & Run in VS Code

### Step 1 — Open the folder in VS Code
```
File → Open Folder → select the `cloud_ids` folder
```

### Step 2 — Create a virtual environment (recommended)
Open the integrated terminal (`Ctrl+` `` ` ``) and run:
```bash
python -m venv venv
```

Activate it:
- **Windows:**  `venv\Scripts\activate`
- **macOS/Linux:** `source venv/bin/activate`

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the dashboard
```bash
streamlit run main.py
```

The dashboard opens automatically at **http://localhost:8501**

---

## 🧩 Features

| Feature | Description |
|---|---|
| 🟢 Live Traffic Monitor | Simulated log stream with IP, endpoint, status, request count |
| 🔴 Real-Time Alerts | Detects DDoS, brute force, and restricted access attempts |
| 📊 Charts | Line chart (requests over time), bar chart (attack frequency), pie chart (top sources) |
| 🚫 Block IPs | Simulates blocking an attacker IP, filters it from future traffic |
| 🚩 Flag IPs | Marks IPs for human review |
| 💡 Recommendations | Context-specific security advice per attack type |
| 📥 Export | Download alerts and logs as CSV |
| ⚙️ Configurable | Adjust attack ratio, batch size, and refresh interval |

---

## 🔍 Detection Rules

| Attack Type | Rule |
|---|---|
| **DDoS** | Total requests from a single IP ≥ 50 in one batch |
| **Restricted Access** | Any request to `/admin`, `/.env`, `/config`, etc. |
| **Brute Force** | ≥ 5 failed login attempts (401/403) from same IP on `/login` |
| **Anomaly** | Z-score of IP request count > 2.0 (statistical outlier) |

---

## 🛡️ Severity Levels

| Level | Color | Meaning |
|---|---|---|
| 🔴 High | Red | Immediate threat — action required |
| 🟠 Medium | Orange | Suspicious behavior — monitor closely |
| 🟢 Low | Green | Low-risk activity — log and review |

---

## 📦 Tech Stack

- **Python 3.10+**
- **Streamlit** — Dashboard UI
- **Pandas** — Log data handling
- **Plotly** — Interactive charts

---

## 💼 Resume Talking Points

- Built a real-time **network intrusion detection system** using Python
- Implemented **rule-based detection** (threshold, pattern matching) and **anomaly detection** (Z-score)
- Designed a professional **security operations dashboard** using Streamlit
- Integrated **prevention actions** (IP blocking, flagging) with simulated response workflows
- Modular architecture: detector, simulator, and utilities as separate, testable modules
