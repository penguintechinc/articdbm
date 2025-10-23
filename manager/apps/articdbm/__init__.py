"""
Simple test controller for ArticDBM
"""

from py4web import action, response
import json

@action('index')
@action('articdbm')
def index():
    """Simple test route"""
    response.headers['Content-Type'] = 'text/html'
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ArticDBM Manager</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #2c3e50, #3498db);
                color: white;
                text-align: center;
            }
            h1 { font-size: 3em; margin: 20px 0; }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 40px auto;
                max-width: 1200px;
            }
            .feature-card {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 10px;
                border: 1px solid rgba(255,255,255,0.2);
            }
        </style>
    </head>
    <body>
        <h1>🚀 ArticDBM Enterprise Manager</h1>
        <h2>Version 1.2.0</h2>
        <p>Comprehensive Database Proxy Management Platform</p>

        <div class="features">
            <div class="feature-card">
                <h3>🗄️ Cluster Management</h3>
                <p>MySQL, PostgreSQL, MongoDB, Redis, SQLite</p>
            </div>
            <div class="feature-card">
                <h3>🔧 Node Configuration</h3>
                <p>Read/Write roles, Load balancing</p>
            </div>
            <div class="feature-card">
                <h3>🔐 Security Center</h3>
                <p>SQL injection protection, Threat intelligence</p>
            </div>
            <div class="feature-card">
                <h3>👥 User Management</h3>
                <p>API keys, Permissions, Temporary access</p>
            </div>
            <div class="feature-card">
                <h3>⚡ Performance</h3>
                <p>ML optimization, Cache settings, XDP/AF_XDP</p>
            </div>
            <div class="feature-card">
                <h3>📊 Monitoring</h3>
                <p>Real-time metrics, Audit logs, Health checks</p>
            </div>
        </div>

        <h2>API Endpoints</h2>
        <ul style="list-style: none; padding: 0;">
            <li><a href="/articdbm/api/health" style="color: white;">Health Status</a></li>
            <li><a href="/articdbm/api/status" style="color: white;">System Status</a></li>
        </ul>
    </body>
    </html>
    """

@action('articdbm/api/health')
def api_health():
    """API health endpoint"""
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({
        "status": "healthy",
        "version": "1.2.0",
        "features": {
            "sqlite_support": True,
            "galera_support": True,
            "threat_intelligence": True,
            "ml_optimization": True,
            "xdp_optimization": False
        },
        "databases": {
            "mysql": {"enabled": True, "ports": [13306, 13308]},
            "postgresql": {"enabled": True, "ports": [15432, 15435]},
            "mongodb": {"enabled": True, "ports": [27017, 27018]},
            "redis": {"enabled": True, "ports": [16379, 16381]},
            "sqlite": {"enabled": True, "ports": [18765, 18766]}
        }
    })

@action('articdbm/api/status')
def api_status():
    """API status endpoint"""
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({
        "cluster_status": "active",
        "proxy_nodes": 2,
        "active_connections": 0,
        "total_queries": 0,
        "uptime": "Running"
    })