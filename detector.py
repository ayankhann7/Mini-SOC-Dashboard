import pandas as pd
from database import get_db_connection
from scapy.all import rdpcap, IP, TCP, UDP, Raw
import datetime

def insert_alert_if_new(c, alert_type, source_ip, timestamp, severity, status, details):
    c.execute('SELECT id FROM alerts WHERE alert_type=? AND source_ip=? AND timestamp=?', (alert_type, source_ip, timestamp))
    if not c.fetchone():
        c.execute('''
            INSERT INTO alerts (alert_type, source_ip, timestamp, severity, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (alert_type, source_ip, timestamp, severity, status, details))

def run_detection_rules(df, c):
    # Rule 1: Brute Force (5 or more failed login attempts)
    if 'event_type' in df.columns and 'status' in df.columns:
        failed_logins = df[(df['event_type'] == 'login') & (df['status'] == 'failed')]
        login_counts = failed_logins.groupby('source_ip').size()
        
        for ip, count in login_counts.items():
            if count >= 5:
                latest_time = failed_logins[failed_logins['source_ip'] == ip]['timestamp'].max()
                insert_alert_if_new(c, 'Possible Brute Force Attack', ip, latest_time, 'HIGH', 'New', f"{count} failed login attempts detected.")

    # Rule 2: Port Scan (5 or more different ports accessed)
    if 'port' in df.columns:
        port_counts = df.groupby('source_ip')['port'].nunique()
        for ip, count in port_counts.items():
            if count >= 5:
                latest_time = df[df['source_ip'] == ip]['timestamp'].max()
                insert_alert_if_new(c, 'Possible Port Scan', ip, latest_time, 'MEDIUM', 'New', f"Accessed {count} different ports.")

    # Rule 3: Excessive Requests (15 or more events)
    event_counts = df.groupby('source_ip').size()
    for ip, count in event_counts.items():
        if count >= 15:
            latest_time = df[df['source_ip'] == ip]['timestamp'].max()
            insert_alert_if_new(c, 'Excessive Network Activity', ip, latest_time, 'HIGH', 'New', f"Generated {count} total events.")

    # Rule 4: After-Hours Access (successful login between 1 AM and 5 AM)
    if 'event_type' in df.columns and 'status' in df.columns and 'timestamp' in df.columns:
        try:
            df['dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
            after_hours = df[(df['event_type'] == 'login') & (df['status'] == 'success') & (df['dt'].dt.hour >= 1) & (df['dt'].dt.hour < 5)]
            
            for _, row in after_hours.iterrows():
                insert_alert_if_new(c, 'After-Hours Login', row['source_ip'], row['timestamp'], 'MEDIUM', 'New', f"Successful login at {row['timestamp']} (After Hours).")
        except Exception:
            pass

    # Rule 5: Multiple 404 Errors (10+ Not Found)
    if 'status' in df.columns:
        errors_404 = df[df['status'].astype(str) == '404']
        error_counts = errors_404.groupby('source_ip').size()
        for ip, count in error_counts.items():
            if count >= 10:
                latest_time = errors_404[errors_404['source_ip'] == ip]['timestamp'].max()
                insert_alert_if_new(c, 'Directory Brute Force (404 Errors)', ip, latest_time, 'HIGH', 'New', f"Caused {count} '404 Not Found' errors.")

    # Rule 6: Threat Intelligence Match (Known Bad IPs)
    try:
        c.execute('SELECT bad_ip, description FROM threat_intel')
        threat_ips = {row['bad_ip']: row['description'] for row in c.fetchall()}
        
        unique_ips = df['source_ip'].unique()
        for ip in unique_ips:
            if ip in threat_ips:
                first_seen = df[df['source_ip'] == ip]['timestamp'].min()
                desc = threat_ips[ip]
                insert_alert_if_new(c, 'Threat Intel Match', ip, first_seen, 'CRITICAL', 'New', f"IP matched known threat feed: {desc}")
    except Exception:
        pass # In case table isn't created yet for some reason

    # Rule 7: Statistical Anomaly Detection (Behavioral Analytics)
    # Identifies IPs generating traffic wildly above the network's normal baseline
    try:
        counts = df['source_ip'].value_counts()
        if len(counts) > 2:  # Need enough data points for statistics
            mean_val = counts.mean()
            std_val = counts.std()
            
            if std_val > 0:
                threshold = mean_val + (2 * std_val) # 2 standard deviations above mean
                
                for ip, count in counts.items():
                    if count > threshold:
                        first_seen = df[df['source_ip'] == ip]['timestamp'].min()
                        details = f"Behavioral Anomaly: Generated {count} events (Network average is {mean_val:.1f}). Statistically significant deviation."
                        insert_alert_if_new(c, 'Behavioral Anomaly (Volume)', ip, first_seen, 'HIGH', 'New', details)
    except Exception:
        pass

def process_logs_and_detect(csv_path):
    df = pd.read_csv(csv_path)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    for _, row in df.iterrows():
        c.execute('''
            INSERT INTO logs (timestamp, source_ip, event_type, status, port)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            row.get('timestamp', ''),
            row.get('source_ip', ''),
            row.get('event_type', ''),
            row.get('status', ''),
            row.get('port', 0)
        ))
    
    run_detection_rules(df, c)
    
    conn.commit()
    conn.close()

def process_pcap_and_detect(pcap_path):
    packets = rdpcap(pcap_path)
    
    logs = []
    for pkt in packets:
        if IP in pkt:
            # Format timestamp
            ts = datetime.datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
            src_ip = pkt[IP].src
            
            port = 0
            if TCP in pkt:
                port = pkt[TCP].dport
            elif UDP in pkt:
                port = pkt[UDP].dport
                
            event_type = 'connection'
            status = 'success'
            
            # Simple deep packet inspection
            if Raw in pkt:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if 'HTTP/1.1 404' in payload:
                    status = '404'
                    event_type = 'web_request'
                elif 'login:failed' in payload:
                    status = 'failed'
                    event_type = 'login'
                elif 'GET' in payload or 'POST' in payload:
                    event_type = 'web_request'
                    
            logs.append({
                'timestamp': ts,
                'source_ip': src_ip,
                'event_type': event_type,
                'status': status,
                'port': port
            })
            
    df = pd.DataFrame(logs)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    for _, row in df.iterrows():
        c.execute('''
            INSERT INTO logs (timestamp, source_ip, event_type, status, port)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            row.get('timestamp', ''),
            row.get('source_ip', ''),
            row.get('event_type', ''),
            row.get('status', ''),
            row.get('port', 0)
        ))
        
    run_detection_rules(df, c)
    
    conn.commit()
    conn.close()
