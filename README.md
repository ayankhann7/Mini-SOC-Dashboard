# Mini SOC – Security Log Monitoring and Threat Detection

A functional Mini Security Operations Center (SOC) project designed for cybersecurity students. It provides a simple but realistic platform for security analysts to upload logs, detect suspicious activities automatically, and investigate alerts.

🚀 **Live Demo:** [https://mini-soc-dashboard-3ojq.onrender.com](https://mini-soc-dashboard-3ojq.onrender.com)
*(Note: Use `admin` / `admin123` to log in)*

## Project Structure

```text
MINI_SOC/
├── app.py              # Main Flask application
├── detector.py         # Rule-based detection engine
├── database.py         # SQLite database initialization
├── requirements.txt    # Python dependencies
├── README.md           # Documentation
├── database.db         # SQLite database file (auto-generated)
├── dataset/
│   ├── security_logs.csv     # Sample CSV dataset for testing
│   └── sample_capture.pcap   # Sample Wireshark PCAP for deep packet inspection
├── templates/          # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── logs.html
│   ├── alerts.html
│   └── alert_detail.html
└── static/             # CSS static files
    └── css/
        └── style.css
```

## Features
- **Analyst Login:** Secure login for SOC analysts.
- **Dashboard:** At-a-glance metrics including total events, alerts grouped by severity, open alerts, and a visual severity chart.
- **Reporting:** Export a CSV "Shift Report" of all resolved alerts directly from the dashboard.
- **Log Upload & Viewing:** Upload raw CSV security logs or Wireshark PCAP (`.pcap`) files. PCAP files are automatically unpacked, deeply inspected, and analyzed. Includes a search and filter bar to easily find specific IPs or events.
- **Threat Detection Engine:** Automated Python-based rule engine matching patterns in logs.
- **Alert Management:** Investigate auto-generated alerts and manage their lifecycle (New -> Investigating -> Resolved). Easily filter alerts by source IP.
- **Automated Mitigation (Block IP):** Analysts can instantly block malicious IPs directly from the alert investigation page, demonstrating proactive incident response.

## Detection Rules
1. **Brute Force (HIGH):** Triggers if a single IP has 5 or more failed login attempts.
2. **Port Scan (MEDIUM):** Triggers if a single IP accesses 5 or more different ports.
3. **Excessive Requests (HIGH):** Triggers if a single IP generates 15 or more events in total.
4. **After-Hours Login (MEDIUM):** Triggers if a successful login occurs between 1:00 AM and 5:00 AM.
5. **Directory Brute Force (HIGH):** Triggers if a single IP causes 10 or more '404 Not Found' errors.
6. **Threat Intel Match (CRITICAL):** Cross-references all IPs against a mock database of known malicious actors.
7. **Behavioral Analytics (HIGH):** Uses statistical mathematics to calculate the network's average traffic baseline. Triggers an anomaly alert if an IP exceeds 2 standard deviations above the mean.

## Installation & Setup

**Important Prerequisite for Live Network Sniffing (Windows Only):** 
To use the "Start Live Capture" feature on Windows, you must install **[Npcap](https://npcap.com/)** (the standard Windows packet capture library). During installation, make sure to check "Install Npcap in WinPcap API-compatible Mode". If you are on Linux/Mac, you might need to run the app with `sudo` instead.

1. **Navigate to the project folder:**
   ```bash
   cd path/to/MINI_SOC_Project
   ```
2. **Install requirements:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run application (will initialize DB automatically):**
   ```bash
   python app.py
   ```

## Usage

1. Open your browser and navigate to `http://127.0.0.1:5000`
2. **Login Credentials:**
   - **Username:** admin
   - **Password:** admin123
3. **Testing the Detection Engine:**
   - Go to the **Logs** tab.
   - Click **Choose File** and select **EITHER** `dataset/security_logs.csv` or `dataset/sample_capture.pcap`.
   - Click **Upload & Analyze**.
   - Navigate to the **Alerts** or **Dashboard** tab to view the generated threats.
4. **Investigating Alerts:**
   - Click **Investigate** on any alert to view its details and associated evidence logs for that specific IP.
   - Update the alert status from "New" to "Investigating" or "Resolved".

## Why I Built This (Motivation)
As a cybersecurity student, I found that most academic projects either focus entirely on writing a simple script, or using massively complex enterprise tools (like Splunk or ELK) that are difficult to setup for a quick demo. I wanted to build something right in the middle: a fully functional, end-to-end SOC dashboard that actually parses raw network data, runs real mathematical and rule-based detections, and allows a user to "respond" to threats.

## Technical Challenges Faced
- **PCAP Parsing Constraints:** Reading deep packet inspection data natively in Python was tricky. I initially wanted to build a live network sniffer, but handling Npcap driver issues on Windows proved too complex for a seamless setup. I pivoted to using `scapy` to parse offline `.pcap` files which is much more reliable for a standalone app.
- **Handling UI Design vs Functionality:** It was a challenge making the app look like a modern enterprise tool (using custom CSS and Chart.js) while keeping the backend entirely lightweight with Flask and SQLite.
- **Cloud Deployment Storage:** Deploying this to Render's free tier introduced the problem of "ephemeral storage," where the SQLite database gets wiped every time the server sleeps. To fix this, I engineered a custom startup command (`python database.py && gunicorn app:app`) to ensure the mock Threat Intel feeds are always re-seeded automatically upon boot.
