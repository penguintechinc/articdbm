"""
ArticDBM Default Homepage Controller
"""

from py4web import action, response, URL

@action('index')
def index():
    """Main homepage"""
    response.headers['Content-Type'] = 'text/html'
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ArticDBM Enterprise Manager</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #2c3e50, #3498db);
                color: white;
                min-height: 100vh;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 40px 20px;
            }}
            h1 {{
                font-size: 4em;
                margin: 20px 0;
                text-align: center;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }}
            h2 {{
                text-align: center;
                font-size: 1.5em;
                opacity: 0.9;
                margin-bottom: 40px;
            }}
            .features {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 30px;
                margin: 50px 0;
            }}
            .feature-card {{
                background: rgba(255,255,255,0.1);
                padding: 30px;
                border-radius: 15px;
                border: 1px solid rgba(255,255,255,0.2);
                backdrop-filter: blur(10px);
                transition: all 0.3s ease;
            }}
            .feature-card:hover {{
                transform: translateY(-5px);
                background: rgba(255,255,255,0.15);
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }}
            .feature-card h3 {{
                margin-top: 0;
                font-size: 1.5em;
            }}
            .feature-card p {{
                opacity: 0.9;
                line-height: 1.6;
            }}
            .cta {{
                text-align: center;
                margin: 60px 0;
            }}
            .btn {{
                display: inline-block;
                padding: 15px 40px;
                background: rgba(255,255,255,0.2);
                color: white;
                text-decoration: none;
                border-radius: 30px;
                border: 2px solid rgba(255,255,255,0.3);
                transition: all 0.3s;
                margin: 10px;
                font-size: 1.1em;
            }}
            .btn:hover {{
                background: rgba(255,255,255,0.3);
                border-color: rgba(255,255,255,0.5);
                transform: scale(1.05);
            }}
            .btn-primary {{
                background: #27ae60;
                border-color: #27ae60;
            }}
            .btn-primary:hover {{
                background: #2ecc71;
                border-color: #2ecc71;
            }}
            .stats {{
                display: flex;
                justify-content: space-around;
                margin: 40px 0;
                flex-wrap: wrap;
            }}
            .stat {{
                text-align: center;
                padding: 20px;
            }}
            .stat-value {{
                font-size: 3em;
                font-weight: bold;
            }}
            .stat-label {{
                opacity: 0.8;
                margin-top: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 ArticDBM</h1>
            <h2>Enterprise Database Proxy Management Platform</h2>

            <div class="stats">
                <div class="stat">
                    <div class="stat-value">5</div>
                    <div class="stat-label">Database Types</div>
                </div>
                <div class="stat">
                    <div class="stat-value">∞</div>
                    <div class="stat-label">Scalability</div>
                </div>
                <div class="stat">
                    <div class="stat-value">99.9%</div>
                    <div class="stat-label">Uptime</div>
                </div>
                <div class="stat">
                    <div class="stat-value">24/7</div>
                    <div class="stat-label">Protection</div>
                </div>
            </div>

            <div class="features">
                <div class="feature-card">
                    <h3>🗄️ Multi-Database Support</h3>
                    <p>Seamlessly manage MySQL, PostgreSQL, MongoDB, Redis, and SQLite databases from a single interface. Support for Galera clusters and advanced replication.</p>
                </div>
                <div class="feature-card">
                    <h3>🔐 Enterprise Security</h3>
                    <p>Advanced SQL injection protection, threat intelligence integration, API key management, and granular user permissions with audit logging.</p>
                </div>
                <div class="feature-card">
                    <h3>⚡ Performance Optimization</h3>
                    <p>ML-based query optimization, XDP/AF_XDP acceleration, intelligent connection pooling, and NUMA-aware configurations.</p>
                </div>
                <div class="feature-card">
                    <h3>📊 Real-time Monitoring</h3>
                    <p>Comprehensive metrics dashboard, health checks, performance analytics, and proactive alerting for all your database infrastructure.</p>
                </div>
                <div class="feature-card">
                    <h3>☁️ Cloud Integration</h3>
                    <p>Native support for AWS RDS, Google Cloud SQL, and Azure Database services. Auto-scaling and disaster recovery built-in.</p>
                </div>
                <div class="feature-card">
                    <h3>🔧 Load Balancing</h3>
                    <p>Intelligent read/write splitting, weighted load distribution, automatic failover, and connection warmup for optimal performance.</p>
                </div>
            </div>

            <div class="cta">
                <a href="/manager/dashboard" class="btn btn-primary">🎯 Open Manager Dashboard</a>
                <a href="/manager/clusters" class="btn">🗄️ Manage Clusters</a>
                <a href="/manager/nodes" class="btn">🔧 Configure Nodes</a>
                <a href="/manager/security" class="btn">🔐 Security Settings</a>
                <a href="/manager/performance" class="btn">⚡ Performance Tuning</a>
                <a href="/manager/users" class="btn">👥 User Management</a>
                <a href="/manager/metrics" class="btn">📊 System Metrics</a>
            </div>

            <div style="text-align: center; margin-top: 60px; opacity: 0.7;">
                <p>Version 1.2.0 | Enterprise Edition</p>
                <p>🏢 Trusted by MSPs and Enterprises Worldwide</p>
            </div>
        </div>
    </body>
    </html>
    """

@action('api/health')
def health():
    """API health check endpoint"""
    response.headers['Content-Type'] = 'application/json'
    import json
    return json.dumps({
        "status": "healthy",
        "version": "1.2.0",
        "timestamp": str(__import__('datetime').datetime.now())
    })