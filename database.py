import sqlite3
import os

DB_PATH = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            status TEXT,
            port INTEGER
        )
    ''')
    
    # Alerts table (Drop and recreate to ensure schema matches requirements)
    c.execute('DROP TABLE IF EXISTS alerts')
    c.execute('''
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            source_ip TEXT,
            timestamp TEXT,
            severity TEXT,
            status TEXT DEFAULT 'New',
            details TEXT
        )
    ''')
    
    # Insert demo user if not exists
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'admin123'))
        
    # Blocked IPs table (for automated mitigation)
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            reason TEXT
        )
    ''')

    # Threat Intel table
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bad_ip TEXT UNIQUE NOT NULL,
            description TEXT
        )
    ''')
    
    # Insert some mock bad IPs for the Threat Intel feed
    mock_ips = [
        ('185.15.59.224', 'Known Ransomware Command & Control'),
        ('45.133.1.109', 'Lazarus Group Proxy Node'),
        ('103.45.2.10', 'Active SSH Brute Forcer (AbuseIPDB)')
    ]
    for ip, desc in mock_ips:
        # Use INSERT OR IGNORE so it doesn't crash if they already exist on subsequent runs
        c.execute('INSERT OR IGNORE INTO threat_intel (bad_ip, description) VALUES (?, ?)', (ip, desc))
        
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
