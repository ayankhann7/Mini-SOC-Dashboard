import threading
from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime
from database import get_db_connection
from detector import run_detection_rules
import pandas as pd

sniffing_active = False
sniff_thread = None

def packet_callback(pkt):
    global sniffing_active
    if not sniffing_active:
        return False

    if IP in pkt:
        ts = datetime.datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S')
        src_ip = pkt[IP].src
        
        port = 0
        if TCP in pkt:
            port = pkt[TCP].dport
        elif UDP in pkt:
            port = pkt[UDP].dport
            
        event_type = 'connection'
        status = 'success'
        
        if Raw in pkt:
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if 'HTTP/1.1 404' in payload:
                    status = '404'
                    event_type = 'web_request'
                elif 'login:failed' in payload:
                    status = 'failed'
                    event_type = 'login'
                elif 'GET' in payload or 'POST' in payload:
                    event_type = 'web_request'
            except Exception:
                pass
                
        # Only log if it has a port (TCP/UDP) to avoid background noise like ICMP spam
        if port != 0:
            conn = get_db_connection()
            c = conn.cursor()
            
            c.execute('''
                INSERT INTO logs (timestamp, source_ip, event_type, status, port)
                VALUES (?, ?, ?, ?, ?)
            ''', (ts, src_ip, event_type, status, port))
            conn.commit()
            
            # Fetch recent logs for this IP to run rules
            c.execute('SELECT * FROM logs WHERE source_ip = ? ORDER BY id DESC LIMIT 50', (src_ip,))
            rows = c.fetchall()
            df = pd.DataFrame([dict(row) for row in rows])
            
            run_detection_rules(df, c)
            conn.commit()
            conn.close()

def start_sniffing_thread():
    try:
        # We only sniff TCP and UDP to reduce overhead
        sniff(filter="tcp or udp", prn=packet_callback, store=0, stop_filter=lambda x: not sniffing_active)
    except Exception as e:
        print(f"Sniffing error: {e}")
        global sniffing_active
        sniffing_active = False

def toggle_sniffing(state):
    global sniffing_active, sniff_thread
    if state and not sniffing_active:
        sniffing_active = True
        sniff_thread = threading.Thread(target=start_sniffing_thread, daemon=True)
        sniff_thread.start()
        return True
    elif not state and sniffing_active:
        sniffing_active = False
        return False
    return sniffing_active
