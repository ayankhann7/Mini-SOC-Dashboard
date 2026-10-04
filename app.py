from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import os
import csv
from io import StringIO
from werkzeug.utils import secure_filename
from database import get_db_connection, init_db
from detector import process_logs_and_detect
import sniffer

app = Flask(__name__)
app.secret_key = 'mini_soc_super_secret_key'
app.config['UPLOAD_FOLDER'] = 'dataset'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/toggle_live')
def toggle_live():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_state = sniffer.sniffing_active
    new_state = sniffer.toggle_sniffing(not current_state)
    
    if new_state:
        flash('Live Network Capture STARTED. (Note: May require Administrator privileges to capture packets)', 'success')
    else:
        flash('Live Network Capture STOPPED.', 'info')
        
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    total_events = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    high_alerts = conn.execute('SELECT COUNT(*) FROM alerts WHERE severity="HIGH"').fetchone()[0]
    medium_alerts = conn.execute('SELECT COUNT(*) FROM alerts WHERE severity="MEDIUM"').fetchone()[0]
    open_alerts = conn.execute('SELECT COUNT(*) FROM alerts WHERE status!="Resolved"').fetchone()[0]
    
    recent_alerts = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 5').fetchall()
    blocked_ips = conn.execute('SELECT * FROM blocked_ips ORDER BY id DESC LIMIT 5').fetchall()
    
    chart_data = {
        'high': high_alerts,
        'medium': medium_alerts
    }
    
    conn.close()
    
    return render_template('dashboard.html', 
                           total_events=total_events,
                           total_alerts=total_alerts,
                           high_alerts=high_alerts,
                           medium_alerts=medium_alerts,
                           open_alerts=open_alerts,
                           recent_alerts=recent_alerts,
                           chart_data=chart_data,
                           sniffing_active=sniffer.sniffing_active,
                           blocked_ips=blocked_ips)

@app.route('/export_report')
def export_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    resolved_alerts = conn.execute("SELECT * FROM alerts WHERE status='Resolved' ORDER BY id DESC").fetchall()
    conn.close()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Alert ID', 'Timestamp', 'Alert Type', 'Source IP', 'Severity', 'Details', 'Status'])
    for alert in resolved_alerts:
        cw.writerow([alert['id'], alert['timestamp'], alert['alert_type'], alert['source_ip'], alert['severity'], alert['details'], alert['status']])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=shift_report.csv"}
    )

@app.route('/logs', methods=['GET', 'POST'])
def logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file and (file.filename.endswith('.csv') or file.filename.endswith('.pcap')):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            if filename.endswith('.csv'):
                from detector import process_logs_and_detect
                process_logs_and_detect(filepath)
            elif filename.endswith('.pcap'):
                from detector import process_pcap_and_detect
                process_pcap_and_detect(filepath)
                
            flash('File uploaded and analyzed successfully.')
            return redirect(url_for('alerts'))
            
    search_ip = request.args.get('search_ip', '')
    search_event = request.args.get('search_event', '')
    
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    
    if search_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{search_ip}%")
    if search_event:
        query += " AND event_type LIKE ?"
        params.append(f"%{search_event}%")
        
    query += " ORDER BY id DESC LIMIT 100"
    
    conn = get_db_connection()
    logs_data = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('logs.html', logs=logs_data, search_ip=search_ip, search_event=search_event)

@app.route('/alerts')
def alerts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    search_ip = request.args.get('search_ip', '')
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if search_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{search_ip}%")
        
    query += " ORDER BY id DESC"
    
    conn = get_db_connection()
    alerts_data = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('alerts.html', alerts=alerts_data, search_ip=search_ip)

@app.route('/threat_intel')
def threat_intel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    try:
        intel_data = conn.execute('SELECT * FROM threat_intel ORDER BY id DESC').fetchall()
    except Exception:
        intel_data = []
    conn.close()
    
    return render_template('threat_intel.html', intel_data=intel_data)

@app.route('/block_ip', methods=['POST'])
def block_ip():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    ip_to_block = request.form.get('ip_address')
    reason = request.form.get('reason', 'Manual Block by Analyst')
    alert_id = request.form.get('alert_id')
    
    import datetime
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT OR IGNORE INTO blocked_ips (ip_address, timestamp, reason) VALUES (?, ?, ?)', (ip_to_block, timestamp, reason))
        conn.commit()
        flash(f'Successfully blocked IP: {ip_to_block}', 'success')
    except Exception as e:
        flash(f'Error blocking IP: {e}')
    finally:
        conn.close()
        
    if alert_id:
        return redirect(url_for('alert_detail', alert_id=alert_id))
    return redirect(url_for('dashboard'))

@app.route('/alerts/<int:alert_id>', methods=['GET', 'POST'])
def alert_detail(alert_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    if request.method == 'POST':
        new_status = request.form['status']
        conn.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, alert_id))
        conn.commit()
        flash('Alert status updated.')
        return redirect(url_for('alert_detail', alert_id=alert_id))
        
    alert = conn.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
    evidence = conn.execute('SELECT * FROM logs WHERE source_ip = ? ORDER BY id DESC LIMIT 20', (alert['source_ip'],)).fetchall()
    conn.close()
    
    return render_template('alert_detail.html', alert=alert, evidence=evidence)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
