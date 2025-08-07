#!/usr/bin/env python3
"""
Dashboard Module for MITM-X Framework
Real-time web dashboard for monitoring MITM activities
"""

import os
import sys
import json
import asyncio
import logging
import threading
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
import websockets
import psutil

class Dashboard:
    """
    Dashboard class for real-time monitoring of MITM activities
    """
    
    def __init__(self, port=5000, websocket_port=5001, host="0.0.0.0"):
        """
        Initialize Dashboard
        
        Args:
            port (int): HTTP server port
            websocket_port (int): WebSocket server port
            host (str): Host to bind to
        """
        self.port = port
        self.websocket_port = websocket_port
        self.host = host
        self.flask_app = Flask(__name__)
        
        # Dashboard data
        self.activity_log = []
        self.active_connections = set()
        self.statistics = {
            'total_requests': 0,
            'credentials_captured': 0,
            'payloads_injected': 0,
            'dns_spoofed': 0,
            'ssl_stripped': 0
        }
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Setup Flask routes
        self.setup_flask_routes()
        
        # WebSocket clients
        self.websocket_clients = set()
    
    def add_activity(self, activity_type, description, data=None):
        """
        Add activity to the log
        
        Args:
            activity_type (str): Type of activity
            description (str): Description of activity
            data (dict): Additional data
        """
        activity = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'description': description,
            'data': data or {}
        }
        
        self.activity_log.append(activity)
        
        # Keep only last 1000 activities
        if len(self.activity_log) > 1000:
            self.activity_log = self.activity_log[-1000:]
        
        # Update statistics
        if activity_type == 'credential_capture':
            self.statistics['credentials_captured'] += 1
        elif activity_type == 'payload_injection':
            self.statistics['payloads_injected'] += 1
        elif activity_type == 'dns_spoof':
            self.statistics['dns_spoofed'] += 1
        elif activity_type == 'ssl_strip':
            self.statistics['ssl_stripped'] += 1
        
        self.statistics['total_requests'] += 1
        
        # Broadcast to WebSocket clients
        asyncio.create_task(self.broadcast_activity(activity))
    
    async def broadcast_activity(self, activity):
        """
        Broadcast activity to all connected WebSocket clients
        
        Args:
            activity (dict): Activity data to broadcast
        """
        if self.websocket_clients:
            message = json.dumps({
                'type': 'activity',
                'data': activity
            })
            
            # Send to all connected clients
            disconnected_clients = set()
            for client in self.websocket_clients:
                try:
                    await client.send(message)
                except:
                    disconnected_clients.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected_clients
    
    def get_system_info(self):
        """
        Get system information
        
        Returns:
            dict: System information
        """
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'network_connections': len(psutil.net_connections()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {}
    
    def setup_flask_routes(self):
        """
        Setup Flask routes for the dashboard
        """
        @self.flask_app.route('/')
        def dashboard():
            """Main dashboard page"""
            dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITM-X Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #0d1117; 
            color: #c9d1d9; 
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #ff6b6b; font-size: 2.5em; margin-bottom: 10px; }
        .header .status { color: #4ecdc4; font-size: 1.2em; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #4ecdc4;
            display: block;
        }
        .stat-label {
            color: #8b949e;
            margin-top: 5px;
        }
        
        .activity-section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .activity-section h2 {
            color: #ff6b6b;
            margin-bottom: 15px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
        }
        
        .activity-log {
            max-height: 400px;
            overflow-y: auto;
            background: #0d1117;
            padding: 15px;
            border-radius: 4px;
            border: 1px solid #30363d;
        }
        .activity-item {
            margin-bottom: 10px;
            padding: 8px;
            border-left: 3px solid #4ecdc4;
            background: #161b22;
        }
        .activity-item.credential { border-left-color: #ff6b6b; }
        .activity-item.injection { border-left-color: #ffa726; }
        .activity-item.spoof { border-left-color: #ab47bc; }
        
        .activity-time {
            color: #8b949e;
            font-size: 0.9em;
        }
        .activity-desc {
            color: #c9d1d9;
            margin-top: 5px;
        }
        
        .controls {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .control-btn {
            background: #238636;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: background 0.3s;
        }
        .control-btn:hover { background: #2ea043; }
        .control-btn.stop { background: #da3633; }
        .control-btn.stop:hover { background: #f85149; }
        
        .system-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        .system-metric {
            background: #0d1117;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #30363d;
            text-align: center;
        }
        
        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 6px;
            font-weight: bold;
        }
        .connected { background: #238636; color: white; }
        .disconnected { background: #da3633; color: white; }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #8b949e;
            border-top: 1px solid #30363d;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #4ecdc4;
            border-radius: 50%;
            animation: pulse 2s infinite;
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 MITM-X Dashboard</h1>
            <div class="status">
                <span class="live-indicator"></span>
                Real-time Monitoring Active
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-number" id="total-requests">0</span>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <span class="stat-number" id="credentials-captured">0</span>
                <div class="stat-label">Credentials Captured</div>
            </div>
            <div class="stat-card">
                <span class="stat-number" id="payloads-injected">0</span>
                <div class="stat-label">Payloads Injected</div>
            </div>
            <div class="stat-card">
                <span class="stat-number" id="dns-spoofed">0</span>
                <div class="stat-label">DNS Spoofed</div>
            </div>
            <div class="stat-card">
                <span class="stat-number" id="ssl-stripped">0</span>
                <div class="stat-label">SSL Stripped</div>
            </div>
        </div>
        
        <div class="controls">
            <button class="control-btn" onclick="startModule('arp')">Start ARP Spoof</button>
            <button class="control-btn" onclick="startModule('dns')">Start DNS Spoof</button>
            <button class="control-btn" onclick="startModule('sniffer')">Start Sniffer</button>
            <button class="control-btn" onclick="startModule('ssl')">Start SSL Strip</button>
            <button class="control-btn" onclick="startModule('injector')">Start Injector</button>
            <button class="control-btn stop" onclick="stopAllModules()">Stop All</button>
        </div>
        
        <div class="activity-section">
            <h2>📊 Live Activity Feed</h2>
            <div class="activity-log" id="activity-log">
                <div class="activity-item">
                    <div class="activity-time">Waiting for activities...</div>
                </div>
            </div>
        </div>
        
        <div class="activity-section">
            <h2>🖥️ System Information</h2>
            <div class="system-info" id="system-info">
                <!-- System info will be populated here -->
            </div>
        </div>
        
        <div class="footer">
            <p>⚠️ MITM-X Framework - For Authorized Testing Only</p>
            <p>Use responsibly and only on networks you own or have permission to test</p>
        </div>
    </div>
    
    <div class="connection-status disconnected" id="connection-status">
        Disconnected
    </div>

    <script>
        let ws = null;
        let reconnectInterval = null;
        
        function connectWebSocket() {
            const wsUrl = `ws://${window.location.hostname}:{{ websocket_port }}`;
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function(event) {
                console.log('WebSocket connected');
                document.getElementById('connection-status').textContent = 'Connected';
                document.getElementById('connection-status').className = 'connection-status connected';
                
                if (reconnectInterval) {
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }
            };
            
            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                
                if (message.type === 'activity') {
                    addActivity(message.data);
                } else if (message.type === 'stats') {
                    updateStats(message.data);
                }
            };
            
            ws.onclose = function(event) {
                console.log('WebSocket disconnected');
                document.getElementById('connection-status').textContent = 'Disconnected';
                document.getElementById('connection-status').className = 'connection-status disconnected';
                
                // Try to reconnect every 5 seconds
                if (!reconnectInterval) {
                    reconnectInterval = setInterval(connectWebSocket, 5000);
                }
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        function addActivity(activity) {
            const activityLog = document.getElementById('activity-log');
            const activityItem = document.createElement('div');
            
            let className = 'activity-item';
            if (activity.type === 'credential_capture') className += ' credential';
            else if (activity.type === 'payload_injection') className += ' injection';
            else if (activity.type.includes('spoof')) className += ' spoof';
            
            activityItem.className = className;
            activityItem.innerHTML = `
                <div class="activity-time">${new Date(activity.timestamp).toLocaleString()}</div>
                <div class="activity-desc">${activity.description}</div>
            `;
            
            activityLog.insertBefore(activityItem, activityLog.firstChild);
            
            // Keep only last 50 items
            while (activityLog.children.length > 50) {
                activityLog.removeChild(activityLog.lastChild);
            }
        }
        
        function updateStats(stats) {
            document.getElementById('total-requests').textContent = stats.total_requests || 0;
            document.getElementById('credentials-captured').textContent = stats.credentials_captured || 0;
            document.getElementById('payloads-injected').textContent = stats.payloads_injected || 0;
            document.getElementById('dns-spoofed').textContent = stats.dns_spoofed || 0;
            document.getElementById('ssl-stripped').textContent = stats.ssl_stripped || 0;
        }
        
        function startModule(module) {
            fetch(`/api/start/${module}`, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addActivity({
                            timestamp: new Date().toISOString(),
                            type: 'module_start',
                            description: `${module.toUpperCase()} module started`
                        });
                    }
                })
                .catch(error => console.error('Error starting module:', error));
        }
        
        function stopAllModules() {
            fetch('/api/stop/all', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addActivity({
                            timestamp: new Date().toISOString(),
                            type: 'module_stop',
                            description: 'All modules stopped'
                        });
                    }
                })
                .catch(error => console.error('Error stopping modules:', error));
        }
        
        function loadSystemInfo() {
            fetch('/api/system-info')
                .then(response => response.json())
                .then(data => {
                    const systemInfoDiv = document.getElementById('system-info');
                    systemInfoDiv.innerHTML = `
                        <div class="system-metric">
                            <strong>CPU Usage</strong><br>
                            ${data.cpu_percent || 0}%
                        </div>
                        <div class="system-metric">
                            <strong>Memory Usage</strong><br>
                            ${data.memory_percent || 0}%
                        </div>
                        <div class="system-metric">
                            <strong>Disk Usage</strong><br>
                            ${data.disk_percent || 0}%
                        </div>
                        <div class="system-metric">
                            <strong>Connections</strong><br>
                            ${data.network_connections || 0}
                        </div>
                    `;
                })
                .catch(error => console.error('Error loading system info:', error));
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            connectWebSocket();
            loadSystemInfo();
            
            // Refresh system info every 30 seconds
            setInterval(loadSystemInfo, 30000);
            
            // Load initial stats
            fetch('/api/stats')
                .then(response => response.json())
                .then(updateStats)
                .catch(error => console.error('Error loading stats:', error));
        });
    </script>
</body>
</html>
            """
            return render_template_string(dashboard_html, websocket_port=self.websocket_port)
        
        @self.flask_app.route('/api/stats')
        def get_stats():
            """Get statistics"""
            return jsonify(self.statistics)
        
        @self.flask_app.route('/api/system-info')
        def get_system_info():
            """Get system information"""
            return jsonify(self.get_system_info())
        
        @self.flask_app.route('/api/activities')
        def get_activities():
            """Get recent activities"""
            return jsonify(self.activity_log[-50:])  # Last 50 activities
        
        @self.flask_app.route('/api/start/<module>', methods=['POST'])
        def start_module(module):
            """Start a module"""
            # This would interface with the actual modules
            self.add_activity('module_start', f'{module.upper()} module started')
            return jsonify({'success': True, 'message': f'{module} started'})
        
        @self.flask_app.route('/api/stop/<module>', methods=['POST'])
        def stop_module(module):
            """Stop a module"""
            # This would interface with the actual modules
            self.add_activity('module_stop', f'{module.upper()} module stopped')
            return jsonify({'success': True, 'message': f'{module} stopped'})
    
    async def websocket_handler(self, websocket, path):
        """
        Handle WebSocket connections
        
        Args:
            websocket: WebSocket connection
            path: Connection path
        """
        self.websocket_clients.add(websocket)
        self.logger.info(f"WebSocket client connected: {websocket.remote_address}")
        
        try:
            # Send initial data
            await websocket.send(json.dumps({
                'type': 'stats',
                'data': self.statistics
            }))
            
            # Send recent activities
            for activity in self.activity_log[-10:]:
                await websocket.send(json.dumps({
                    'type': 'activity',
                    'data': activity
                }))
            
            # Keep connection alive
            await websocket.wait_closed()
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            self.websocket_clients.discard(websocket)
            self.logger.info("WebSocket client disconnected")
    
    def start_websocket_server(self):
        """
        Start WebSocket server
        """
        try:
            start_server = websockets.serve(
                self.websocket_handler, 
                self.host, 
                self.websocket_port
            )
            
            asyncio.get_event_loop().run_until_complete(start_server)
            asyncio.get_event_loop().run_forever()
        except Exception as e:
            self.logger.error(f"Error starting WebSocket server: {e}")
    
    def start_dashboard(self):
        """
        Start the dashboard
        """
        self.logger.info(f"Starting dashboard on {self.host}:{self.port}")
        self.logger.info(f"WebSocket server on {self.host}:{self.websocket_port}")
        
        # Start WebSocket server in separate thread
        websocket_thread = threading.Thread(target=self.start_websocket_server)
        websocket_thread.daemon = True
        websocket_thread.start()
        
        try:
            # Disable Flask logging for cleaner output
            import logging as flask_logging
            flask_logging.getLogger('werkzeug').setLevel(flask_logging.ERROR)
            
            self.flask_app.run(host=self.host, port=self.port, debug=False)
        except Exception as e:
            self.logger.error(f"Error starting dashboard: {e}")
    
    def stop_dashboard(self):
        """
        Stop the dashboard
        """
        self.logger.info("Dashboard stopped")

def main():
    """
    Main function for standalone execution
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="MITM-X Dashboard")
    parser.add_argument("--port", "-p", type=int, default=5000, help="HTTP server port")
    parser.add_argument("--ws-port", type=int, default=5001, help="WebSocket server port")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    
    args = parser.parse_args()
    
    # Create dashboard
    dashboard = Dashboard(args.port, args.ws_port, args.host)
    
    # Add some test activities
    dashboard.add_activity('system_start', 'MITM-X Dashboard started')
    dashboard.add_activity('credential_capture', 'Login credentials captured from facebook.com', 
                          {'username': 'test@example.com', 'site': 'facebook.com'})
    dashboard.add_activity('payload_injection', 'JavaScript payload injected into google.com')
    dashboard.add_activity('dns_spoof', 'DNS request spoofed: facebook.com -> 192.168.1.100')
    
    try:
        print(f"Dashboard starting on http://{args.host}:{args.port}")
        dashboard.start_dashboard()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        dashboard.stop_dashboard()

if __name__ == "__main__":
    main()
