# Mini SOC – Security Log Monitoring and Threat Detection

A functional Mini Security Operations Center (SOC) project designed for cybersecurity students. It provides a simple but realistic platform for security analysts to upload logs, detect suspicious activities automatically, and investigate alerts.

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
│   └── security_logs.csv # Sample dataset for testing
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
   - Click **Choose File** and select `dataset/security_logs.csv`.
   - Click **Upload & Analyze**.
   - Navigate to the **Alerts** or **Dashboard** tab to view the generated threats.
4. **Investigating Alerts:**
   - Click **Investigate** on any alert to view its details and associated evidence logs for that specific IP.
   - Update the alert status from "New" to "Investigating" or "Resolved".
