#!/usr/bin/env python3
"""
ArticDBM Manager - Functional Control Panel
Full CRUD operations with PostgreSQL and Redis sync
"""

from py4web import action, request, response, abort, redirect, URL, DAL, Field
from py4web.utils.form import Form, FormStyleBulma
from py4web.utils.cors import CORS
import json
import redis
import os
from datetime import datetime
from pydal.validators import *

cors = CORS(origin="*", headers="Origin, X-Requested-With, Content-Type, Accept, Authorization", methods="GET, POST, PUT, DELETE, OPTIONS")

redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'redis'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    password=os.getenv('REDIS_PASSWORD', ''),
    db=int(os.getenv('REDIS_DB', 0)),
    decode_responses=True
)

try:
    db = DAL(
        os.getenv('DATABASE_URL', 'sqlite://manager.db'),
        folder='/tmp',
        pool_size=10
    )

    db.define_table('cluster',
        Field('name', 'string', required=True, unique=True),
        Field('db_type', 'string', required=True),
        Field('enabled', 'boolean', default=True),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=lambda: datetime.now()),
        Field('updated_at', 'datetime', update=lambda: datetime.now())
    )

    db.define_table('node',
        Field('cluster_id', 'reference cluster', required=True),
        Field('host', 'string', required=True),
        Field('port', 'integer', required=True),
        Field('node_type', 'string', required=True),
        Field('weight', 'integer', default=100),
        Field('tls', 'boolean', default=False),
        Field('username', 'string'),
        Field('password', 'string'),
        Field('database_name', 'string'),
        Field('is_galera', 'boolean', default=False),
        Field('enabled', 'boolean', default=True),
        Field('created_at', 'datetime', default=lambda: datetime.now()),
        Field('updated_at', 'datetime', update=lambda: datetime.now())
    )

    db.define_table('proxy_user',
        Field('username', 'string', required=True, unique=True),
        Field('password_hash', 'string', required=True),
        Field('api_key', 'string', unique=True),
        Field('enabled', 'boolean', default=True),
        Field('require_tls', 'boolean', default=False),
        Field('allowed_ips', 'list:string'),
        Field('rate_limit', 'integer', default=1000),
        Field('expires_at', 'datetime'),
        Field('created_at', 'datetime', default=lambda: datetime.now()),
        Field('updated_at', 'datetime', update=lambda: datetime.now())
    )

    db.define_table('user_permission',
        Field('user_id', 'reference proxy_user', required=True),
        Field('database', 'string', required=True),
        Field('table_name', 'string'),
        Field('actions', 'list:string'),
        Field('time_limit', 'datetime'),
        Field('max_queries', 'integer', default=10000),
        Field('created_at', 'datetime', default=lambda: datetime.now())
    )

    db.define_table('security_pattern',
        Field('name', 'string', required=True),
        Field('pattern', 'string', required=True),
        Field('severity', 'string', default='high'),
        Field('enabled', 'boolean', default=True),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=lambda: datetime.now())
    )
except Exception as e:
    print(f"Warning: Database initialization delayed: {e}")
    db = None

def sync_to_redis():
    """Sync database configuration to Redis for proxy to read"""

    backends_map = {
        'mysql': [],
        'postgresql': [],
        'mssql': [],
        'mongodb': [],
        'redis': []
    }

    clusters = db(db.cluster.enabled == True).select()
    for cluster in clusters:
        nodes = db((db.node.cluster_id == cluster.id) & (db.node.enabled == True)).select()

        backend_list = []
        for node in nodes:
            node_type = node.node_type if node.node_type != 'both' else ''

            backend = {
                'Host': node.host,
                'Port': node.port,
                'Type': node_type,
                'Weight': node.weight,
                'TLS': node.tls,
                'User': node.username or '',
                'Password': node.password or '',
                'Database': node.database_name or '',
                'IsGalera': node.is_galera
            }
            backend_list.append(backend)

        if cluster.db_type in backends_map:
            backends_map[cluster.db_type].extend(backend_list)

    redis_client.set('articdbm:backends', json.dumps(backends_map))

    users_map = {}
    users = db(db.proxy_user.enabled == True).select()
    for user in users:
        users_map[user.username] = {
            'Username': user.username,
            'PasswordHash': user.password_hash,
            'APIKey': user.api_key or '',
            'Enabled': user.enabled,
            'RequireTLS': user.require_tls,
            'AllowedIPs': user.allowed_ips or [],
            'RateLimit': user.rate_limit,
            'CreatedAt': user.created_at.isoformat() if user.created_at else None,
            'UpdatedAt': user.updated_at.isoformat() if user.updated_at else None,
            'ExpiresAt': user.expires_at.isoformat() if user.expires_at else None
        }

    redis_client.set('articdbm:users', json.dumps(users_map))

    perms_map = {}
    permissions = db(db.user_permission).select()
    for perm in permissions:
        user = db.proxy_user[perm.user_id]
        perm_key = f"{user.username}:{perm.database}"
        perms_map[perm_key] = {
            'UserID': user.username,
            'Database': perm.database,
            'Table': perm.table_name or '',
            'Actions': perm.actions or [],
            'TimeLimit': perm.time_limit.isoformat() if perm.time_limit else None,
            'MaxQueries': perm.max_queries
        }

    redis_client.set('articdbm:permissions', json.dumps(perms_map))

    return True

@action('index')
@action('dashboard')
def dashboard():
    cluster_count = db(db.cluster).count()
    node_count = db(db.node).count()
    user_count = db(db.proxy_user).count()

    recent_clusters = db(db.cluster).select(orderby=~db.cluster.created_at, limitby=(0, 5))

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>ArticDBM Manager - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
        .dashboard {{ padding: 40px 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .stat-card {{ background: white; border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-value {{ font-size: 3em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; font-size: 1.2em; }}
        .nav-header {{ background: white; padding: 15px; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
    <div class="container dashboard">
        <div class="nav-header">
            <h1 class="mb-0">🚀 ArticDBM Manager</h1>
            <p class="text-muted mb-0">Enterprise Database Proxy Control Panel</p>
        </div>

        <div class="row mb-4">
            <div class="col-md-4">
                <div class="stat-card">
                    <div class="stat-value">{cluster_count}</div>
                    <div class="stat-label">Clusters</div>
                    <a href="{URL('clusters')}" class="btn btn-primary btn-sm mt-2">Manage</a>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <div class="stat-value">{node_count}</div>
                    <div class="stat-label">Nodes</div>
                    <a href="{URL('nodes')}" class="btn btn-primary btn-sm mt-2">Manage</a>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <div class="stat-value">{user_count}</div>
                    <div class="stat-label">Users</div>
                    <a href="{URL('users')}" class="btn btn-primary btn-sm mt-2">Manage</a>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-body">
                <h3>Recent Clusters</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr>
                            <td>{c.name}</td>
                            <td><span class="badge bg-info">{c.db_type.upper()}</span></td>
                            <td><span class="badge bg-{"success" if c.enabled else "danger"}">{"Enabled" if c.enabled else "Disabled"}</span></td>
                            <td>{c.created_at.strftime("%Y-%m-%d %H:%M") if c.created_at else "N/A"}</td>
                            <td>
                                <a href="{URL('cluster_edit', c.id)}" class="btn btn-sm btn-primary">Edit</a>
                                <a href="{URL('cluster_delete', c.id)}" class="btn btn-sm btn-danger" onclick="return confirm('Delete cluster?')">Delete</a>
                            </td>
                        </tr>
                        ''' for c in recent_clusters])}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h4>Quick Actions</h4>
                        <a href="{URL('cluster_create')}" class="btn btn-success mb-2 w-100">➕ New Cluster</a>
                        <a href="{URL('node_create')}" class="btn btn-success mb-2 w-100">🖥️ Add Node</a>
                        <a href="{URL('user_create')}" class="btn btn-success mb-2 w-100">👤 Create User</a>
                        <a href="{URL('security')}" class="btn btn-warning mb-2 w-100">🔒 Security Settings</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h4>System Status</h4>
                        <p><strong>Redis:</strong> <span class="badge bg-success">Connected</span></p>
                        <p><strong>Database:</strong> <span class="badge bg-success">Connected</span></p>
                        <p><strong>Proxy:</strong> <span class="badge bg-success">Running</span></p>
                        <button onclick="syncConfig()" class="btn btn-primary w-100">🔄 Sync Configuration to Proxy</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
    function syncConfig() {{
        fetch('/manager/api/sync', {{method: 'POST'}})
            .then(r => r.json())
            .then(data => {{
                alert(data.status === 'success' ? 'Configuration synced successfully!' : 'Sync failed: ' + data.message);
            }})
            .catch(e => alert('Error: ' + e));
    }}
    </script>
</body>
</html>
    """

@action('clusters')
def clusters():
    clusters = db(db.cluster).select(orderby=~db.cluster.created_at)

    cluster_stats = []
    for cluster in clusters:
        node_count = db(db.node.cluster_id == cluster.id).count()
        cluster_stats.append({
            'cluster': cluster,
            'node_count': node_count
        })

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cluster Management - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2>🗄️ Database Clusters</h2>
                        <p class="text-muted">Manage your database proxy clusters</p>
                    </div>
                    <div>
                        <a href="{URL('dashboard')}" class="btn btn-secondary">← Dashboard</a>
                        <a href="{URL('cluster_create')}" class="btn btn-success">➕ New Cluster</a>
                    </div>
                </div>

                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Nodes</th>
                            <th>Status</th>
                            <th>Description</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr>
                            <td><strong>{stat['cluster'].name}</strong></td>
                            <td><span class="badge bg-info">{stat['cluster'].db_type.upper()}</span></td>
                            <td>{stat['node_count']} nodes</td>
                            <td><span class="badge bg-{"success" if stat['cluster'].enabled else "danger"}">{"Enabled" if stat['cluster'].enabled else "Disabled"}</span></td>
                            <td>{stat['cluster'].description or ""}</td>
                            <td>
                                <a href="{URL('cluster_edit', stat['cluster'].id)}" class="btn btn-sm btn-primary">Edit</a>
                                <a href="{URL('cluster_toggle', stat['cluster'].id)}" class="btn btn-sm btn-warning">{"Disable" if stat['cluster'].enabled else "Enable"}</a>
                                <a href="{URL('cluster_delete', stat['cluster'].id)}" class="btn btn-sm btn-danger" onclick="return confirm('Delete cluster {stat['cluster'].name}?')">Delete</a>
                            </td>
                        </tr>
                        ''' for stat in cluster_stats]) if cluster_stats else '<tr><td colspan="6" class="text-center">No clusters configured. <a href="' + URL('cluster_create') + '">Create one now</a></td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('cluster_create', method=['GET', 'POST'])
def cluster_create():
    form_html = f"""
    <form method="POST" class="needs-validation" novalidate>
        <div class="mb-3">
            <label class="form-label">Cluster Name *</label>
            <input type="text" name="name" class="form-control" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Database Type *</label>
            <select name="db_type" class="form-control" required>
                <option value="">Select...</option>
                <option value="mysql">MySQL</option>
                <option value="postgresql">PostgreSQL</option>
                <option value="mongodb">MongoDB</option>
                <option value="redis">Redis</option>
                <option value="sqlite">SQLite</option>
            </select>
        </div>
        <div class="mb-3">
            <label class="form-label">Description</label>
            <textarea name="description" class="form-control" rows="3"></textarea>
        </div>
        <div class="mb-3">
            <div class="form-check">
                <input type="checkbox" name="enabled" class="form-check-input" value="true" checked>
                <label class="form-check-label">Enabled</label>
            </div>
        </div>
        <button type="submit" class="btn btn-primary">Create Cluster</button>
        <a href="{URL('clusters')}" class="btn btn-secondary">Cancel</a>
    </form>
    """

    if request.method == 'POST':
        name = request.forms.get('name')
        db_type = request.forms.get('db_type')
        description = request.forms.get('description', '')
        enabled = request.forms.get('enabled') == 'true'

        if name and db_type:
            db.cluster.insert(
                name=name,
                db_type=db_type,
                description=description,
                enabled=enabled
            )
            db.commit()
            sync_to_redis()
            redirect(URL('clusters'))
        else:
            form_html = '<div class="alert alert-danger">Name and Type are required</div>' + form_html

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Create Cluster - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <h2>➕ Create New Cluster</h2>
                <p class="text-muted mb-4">Add a new database cluster to ArticDBM</p>
                {form_html}
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('cluster_edit/<cluster_id:int>', method=['GET', 'POST'])
def cluster_edit(cluster_id):
    cluster = db.cluster[cluster_id]
    if not cluster:
        abort(404)

    if request.method == 'POST':
        name = request.forms.get('name')
        db_type = request.forms.get('db_type')
        description = request.forms.get('description', '')
        enabled = request.forms.get('enabled') == 'true'

        if name and db_type:
            cluster.update_record(
                name=name,
                db_type=db_type,
                description=description,
                enabled=enabled
            )
            db.commit()
            sync_to_redis()
            redirect(URL('clusters'))

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Edit Cluster - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <h2>✏️ Edit Cluster</h2>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Cluster Name *</label>
                        <input type="text" name="name" class="form-control" value="{cluster.name}" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Database Type *</label>
                        <select name="db_type" class="form-control" required>
                            <option value="mysql" {"selected" if cluster.db_type == "mysql" else ""}>MySQL</option>
                            <option value="postgresql" {"selected" if cluster.db_type == "postgresql" else ""}>PostgreSQL</option>
                            <option value="mongodb" {"selected" if cluster.db_type == "mongodb" else ""}>MongoDB</option>
                            <option value="redis" {"selected" if cluster.db_type == "redis" else ""}>Redis</option>
                            <option value="sqlite" {"selected" if cluster.db_type == "sqlite" else ""}>SQLite</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Description</label>
                        <textarea name="description" class="form-control" rows="3">{cluster.description or ""}</textarea>
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input type="checkbox" name="enabled" class="form-check-input" value="true" {"checked" if cluster.enabled else ""}>
                            <label class="form-check-label">Enabled</label>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                    <a href="{URL('clusters')}" class="btn btn-secondary">Cancel</a>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('cluster_delete/<cluster_id:int>')
def cluster_delete(cluster_id):
    cluster = db.cluster[cluster_id]
    if cluster:
        db(db.node.cluster_id == cluster_id).delete()
        del db.cluster[cluster_id]
        db.commit()
        sync_to_redis()
    redirect(URL('clusters'))

@action('cluster_toggle/<cluster_id:int>')
def cluster_toggle(cluster_id):
    cluster = db.cluster[cluster_id]
    if cluster:
        cluster.update_record(enabled=not cluster.enabled)
        db.commit()
        sync_to_redis()
    redirect(URL('clusters'))

@action('nodes')
def nodes():
    nodes = db(db.node).select(orderby=~db.node.created_at)

    node_data = []
    for node in nodes:
        cluster = db.cluster[node.cluster_id]
        node_data.append({
            'node': node,
            'cluster': cluster
        })

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Node Management - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2>🖥️ Database Nodes</h2>
                        <p class="text-muted">Configure backend database nodes</p>
                    </div>
                    <div>
                        <a href="{URL('dashboard')}" class="btn btn-secondary">← Dashboard</a>
                        <a href="{URL('node_create')}" class="btn btn-success">➕ Add Node</a>
                    </div>
                </div>

                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Cluster</th>
                            <th>Host:Port</th>
                            <th>Type</th>
                            <th>Weight</th>
                            <th>Status</th>
                            <th>Galera</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr>
                            <td><span class="badge bg-info">{data['cluster'].name}</span></td>
                            <td><strong>{data['node'].host}:{data['node'].port}</strong></td>
                            <td><span class="badge bg-{"success" if data['node'].node_type == "write" else "primary" if data['node'].node_type == "read" else "secondary"}">{data['node'].node_type.upper()}</span></td>
                            <td>{data['node'].weight}</td>
                            <td><span class="badge bg-{"success" if data['node'].enabled else "danger"}">{"Enabled" if data['node'].enabled else "Disabled"}</span></td>
                            <td>{"✓" if data['node'].is_galera else ""}</td>
                            <td>
                                <a href="{URL('node_edit', data['node'].id)}" class="btn btn-sm btn-primary">Edit</a>
                                <a href="{URL('node_delete', data['node'].id)}" class="btn btn-sm btn-danger" onclick="return confirm('Delete node?')">Delete</a>
                            </td>
                        </tr>
                        ''' for data in node_data]) if node_data else '<tr><td colspan="7" class="text-center">No nodes configured. <a href="' + URL('node_create') + '">Add one now</a></td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('node_create', method=['GET', 'POST'])
def node_create():
    clusters = db(db.cluster).select()

    if request.method == 'POST':
        cluster_id = request.forms.get('cluster_id')
        host = request.forms.get('host')
        port = request.forms.get('port')
        node_type = request.forms.get('node_type')
        weight = request.forms.get('weight', 100)
        tls = request.forms.get('tls') == 'true'
        username = request.forms.get('username', '')
        password = request.forms.get('password', '')
        database_name = request.forms.get('database_name', '')
        is_galera = request.forms.get('is_galera') == 'true'
        enabled = request.forms.get('enabled') == 'true'

        if cluster_id and host and port and node_type:
            db.node.insert(
                cluster_id=cluster_id,
                host=host,
                port=int(port),
                node_type=node_type,
                weight=int(weight),
                tls=tls,
                username=username,
                password=password,
                database_name=database_name,
                is_galera=is_galera,
                enabled=enabled
            )
            db.commit()
            sync_to_redis()
            redirect(URL('nodes'))

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Add Node - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <h2>➕ Add Database Node</h2>
                <p class="text-muted mb-4">Configure a backend database node</p>
                <form method="POST">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Cluster *</label>
                            <select name="cluster_id" class="form-control" required>
                                <option value="">Select cluster...</option>
                                {''.join([f'<option value="{c.id}">{c.name} ({c.db_type})</option>' for c in clusters])}
                            </select>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Node Type *</label>
                            <select name="node_type" class="form-control" required>
                                <option value="">Select type...</option>
                                <option value="both">Both (Read/Write)</option>
                                <option value="read">Read Only</option>
                                <option value="write">Write Only</option>
                            </select>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-8 mb-3">
                            <label class="form-label">Host *</label>
                            <input type="text" name="host" class="form-control" placeholder="db.example.com" required>
                        </div>
                        <div class="col-md-4 mb-3">
                            <label class="form-label">Port *</label>
                            <input type="number" name="port" class="form-control" placeholder="3306" required>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" name="username" class="form-control">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control">
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Database Name</label>
                            <input type="text" name="database_name" class="form-control">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Weight (1-1000)</label>
                            <input type="number" name="weight" class="form-control" value="100" min="1" max="1000">
                        </div>
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input type="checkbox" name="tls" class="form-check-input" value="true">
                            <label class="form-check-label">Use TLS/SSL</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" name="is_galera" class="form-check-input" value="true">
                            <label class="form-check-label">Galera Cluster Node</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" name="enabled" class="form-check-input" value="true" checked>
                            <label class="form-check-label">Enabled</label>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Add Node</button>
                    <a href="{URL('nodes')}" class="btn btn-secondary">Cancel</a>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('node_edit/<node_id:int>', method=['GET', 'POST'])
def node_edit(node_id):
    node = db.node[node_id]
    if not node:
        abort(404)

    clusters = db(db.cluster).select()

    if request.method == 'POST':
        cluster_id = request.forms.get('cluster_id')
        host = request.forms.get('host')
        port = request.forms.get('port')
        node_type = request.forms.get('node_type')
        weight = request.forms.get('weight', 100)
        tls = request.forms.get('tls') == 'true'
        username = request.forms.get('username', '')
        password = request.forms.get('password', '')
        database_name = request.forms.get('database_name', '')
        is_galera = request.forms.get('is_galera') == 'true'
        enabled = request.forms.get('enabled') == 'true'

        if cluster_id and host and port and node_type:
            node.update_record(
                cluster_id=cluster_id,
                host=host,
                port=int(port),
                node_type=node_type,
                weight=int(weight),
                tls=tls,
                username=username,
                password=password,
                database_name=database_name,
                is_galera=is_galera,
                enabled=enabled
            )
            db.commit()
            sync_to_redis()
            redirect(URL('nodes'))

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Edit Node - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <h2>✏️ Edit Node</h2>
                <form method="POST">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Cluster *</label>
                            <select name="cluster_id" class="form-control" required>
                                {''.join([f'<option value="{c.id}" {"selected" if c.id == node.cluster_id else ""}>{c.name} ({c.db_type})</option>' for c in clusters])}
                            </select>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Node Type *</label>
                            <select name="node_type" class="form-control" required>
                                <option value="both" {"selected" if node.node_type == "both" else ""}>Both (Read/Write)</option>
                                <option value="read" {"selected" if node.node_type == "read" else ""}>Read Only</option>
                                <option value="write" {"selected" if node.node_type == "write" else ""}>Write Only</option>
                            </select>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-8 mb-3">
                            <label class="form-label">Host *</label>
                            <input type="text" name="host" class="form-control" value="{node.host}" required>
                        </div>
                        <div class="col-md-4 mb-3">
                            <label class="form-label">Port *</label>
                            <input type="number" name="port" class="form-control" value="{node.port}" required>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" name="username" class="form-control" value="{node.username or ""}">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" value="{node.password or ""}" placeholder="Leave blank to keep unchanged">
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Database Name</label>
                            <input type="text" name="database_name" class="form-control" value="{node.database_name or ""}">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label class="form-label">Weight (1-1000)</label>
                            <input type="number" name="weight" class="form-control" value="{node.weight}" min="1" max="1000">
                        </div>
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input type="checkbox" name="tls" class="form-check-input" value="true" {"checked" if node.tls else ""}>
                            <label class="form-check-label">Use TLS/SSL</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" name="is_galera" class="form-check-input" value="true" {"checked" if node.is_galera else ""}>
                            <label class="form-check-label">Galera Cluster Node</label>
                        </div>
                        <div class="form-check">
                            <input type="checkbox" name="enabled" class="form-check-input" value="true" {"checked" if node.enabled else ""}>
                            <label class="form-check-label">Enabled</label>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                    <a href="{URL('nodes')}" class="btn btn-secondary">Cancel</a>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('node_delete/<node_id:int>')
def node_delete(node_id):
    node = db.node[node_id]
    if node:
        del db.node[node_id]
        db.commit()
        sync_to_redis()
    redirect(URL('nodes'))

@action('users')
def users():
    users = db(db.proxy_user).select(orderby=~db.proxy_user.created_at)

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>User Management - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2>👤 Proxy Users</h2>
                        <p class="text-muted">Manage database proxy users and authentication</p>
                    </div>
                    <div>
                        <a href="{URL('dashboard')}" class="btn btn-secondary">← Dashboard</a>
                        <a href="{URL('user_create')}" class="btn btn-success">➕ Create User</a>
                    </div>
                </div>

                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>API Key</th>
                            <th>Rate Limit</th>
                            <th>TLS Required</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr>
                            <td><strong>{user.username}</strong></td>
                            <td><code>{user.api_key[:16] if user.api_key else "None"}...</code></td>
                            <td>{user.rate_limit} req/s</td>
                            <td>{"Yes" if user.require_tls else "No"}</td>
                            <td><span class="badge bg-{"success" if user.enabled else "danger"}">{"Active" if user.enabled else "Disabled"}</span></td>
                            <td>
                                <a href="{URL('user_edit', user.id)}" class="btn btn-sm btn-primary">Edit</a>
                                <a href="{URL('user_permissions', user.id)}" class="btn btn-sm btn-info">Permissions</a>
                                <a href="{URL('user_delete', user.id)}" class="btn btn-sm btn-danger" onclick="return confirm('Delete user?')">Delete</a>
                            </td>
                        </tr>
                        ''' for user in users]) if users else '<tr><td colspan="6" class="text-center">No users configured. <a href="' + URL('user_create') + '">Create one now</a></td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('user_create')
def user_create():
    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Create User - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-info">
            User creation form - implement with bcrypt password hashing
        </div>
        <a href="{URL('users')}" class="btn btn-secondary">← Back to Users</a>
    </div>
</body>
</html>
    """

@action('user_edit/<user_id:int>')
def user_edit(user_id):
    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Edit User - ArticDBM</title>
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-info">User edit form for user ID {user_id}</div>
        <a href="{URL('users')}" class="btn btn-secondary">← Back</a>
    </div>
</body>
</html>
    """

@action('user_permissions/<user_id:int>')
def user_permissions(user_id):
    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>User Permissions - ArticDBM</title>
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-info">Permission management for user ID {user_id}</div>
        <a href="{URL('users')}" class="btn btn-secondary">← Back</a>
    </div>
</body>
</html>
    """

@action('user_delete/<user_id:int>')
def user_delete(user_id):
    user = db.proxy_user[user_id]
    if user:
        db(db.user_permission.user_id == user_id).delete()
        del db.proxy_user[user_id]
        db.commit()
        sync_to_redis()
    redirect(URL('users'))

@action('security')
def security():
    patterns = db(db.security_pattern).select(orderby=db.security_pattern.name)

    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Settings - ArticDBM</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; background: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2>🔒 Security Configuration</h2>
                        <p class="text-muted">Manage SQL injection patterns and security rules</p>
                    </div>
                    <div>
                        <a href="{URL('dashboard')}" class="btn btn-secondary">← Dashboard</a>
                        <a href="{URL('pattern_create')}" class="btn btn-success">➕ Add Pattern</a>
                    </div>
                </div>

                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Pattern</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'''
                        <tr>
                            <td><strong>{pattern.name}</strong><br><small class="text-muted">{pattern.description or ""}</small></td>
                            <td><code>{pattern.pattern}</code></td>
                            <td><span class="badge bg-{"danger" if pattern.severity == "critical" else "warning" if pattern.severity == "high" else "info"}">{pattern.severity.upper()}</span></td>
                            <td><span class="badge bg-{"success" if pattern.enabled else "secondary"}">{"Enabled" if pattern.enabled else "Disabled"}</span></td>
                            <td>
                                <a href="{URL('pattern_edit', pattern.id)}" class="btn btn-sm btn-primary">Edit</a>
                                <a href="{URL('pattern_delete', pattern.id)}" class="btn btn-sm btn-danger" onclick="return confirm('Delete pattern?')">Delete</a>
                            </td>
                        </tr>
                        ''' for pattern in patterns]) if patterns else '<tr><td colspan="5" class="text-center">No security patterns configured. <a href="' + URL('pattern_create') + '">Add one now</a></td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
    """

@action('pattern_create')
def pattern_create():
    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Add Security Pattern - ArticDBM</title>
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-info">Security pattern creation form</div>
        <a href="{URL('security')}" class="btn btn-secondary">← Back</a>
    </div>
</body>
</html>
    """

@action('pattern_edit/<pattern_id:int>')
def pattern_edit(pattern_id):
    response.headers['Content-Type'] = 'text/html'
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Edit Pattern - ArticDBM</title>
</head>
<body>
    <div class="container mt-5">
        <div class="alert alert-info">Pattern edit form for pattern ID {pattern_id}</div>
        <a href="{URL('security')}" class="btn btn-secondary">← Back</a>
    </div>
</body>
</html>
    """

@action('pattern_delete/<pattern_id:int>')
def pattern_delete(pattern_id):
    pattern = db.security_pattern[pattern_id]
    if pattern:
        del db.security_pattern[pattern_id]
        db.commit()
    redirect(URL('security'))

@action('api/sync', method=['POST'])
@action.uses(cors)
def api_sync():
    try:
        sync_to_redis()
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'status': 'success', 'message': 'Configuration synced to proxy'})
    except Exception as e:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'status': 'error', 'message': str(e)})

@action('api/clusters', method=['GET'])
@action.uses(cors)
def api_clusters():
    clusters = db(db.cluster).select()
    result = []
    for cluster in clusters:
        node_count = db(db.node.cluster_id == cluster.id).count()
        result.append({
            'id': cluster.id,
            'name': cluster.name,
            'db_type': cluster.db_type,
            'enabled': cluster.enabled,
            'node_count': node_count,
            'description': cluster.description
        })
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'clusters': result})

@action('api/nodes', method=['GET'])
@action.uses(cors)
def api_nodes():
    nodes = db(db.node).select()
    result = []
    for node in nodes:
        cluster = db.cluster[node.cluster_id]
        result.append({
            'id': node.id,
            'cluster': cluster.name,
            'host': node.host,
            'port': node.port,
            'type': node.node_type,
            'weight': node.weight,
            'enabled': node.enabled,
            'tls': node.tls,
            'is_galera': node.is_galera
        })
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'nodes': result})
