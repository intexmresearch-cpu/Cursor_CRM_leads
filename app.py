#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session, render_template, Response
)
import clickhouse_connect
import bcrypt
from jinja2 import DictLoader

# =========================
# ===== CONFIG / CREDS ====
# =========================
CH_HOST = os.getenv('CLICKHOUSE_HOST', 'localhost')
CH_PORT = int(os.getenv('CLICKHOUSE_PORT', '8123'))
CH_USER = os.getenv('CLICKHOUSE_USER', 'vinod')
CH_PASS = os.getenv('CLICKHOUSE_PASSWORD', 'o9xnq41#uiw@Ug1V')

CH_DB = 'Calling_CRM'
LEADS_TABLE      = f'{CH_DB}.call_leads'
ATTEMPTS_TABLE   = f'{CH_DB}.call_attempts'
USERS_TABLE      = f'{CH_DB}.users'
CALLBACKS_TABLE  = f'{CH_DB}.call_callbacks'
ASSIGN_TABLE     = f'{CH_DB}.call_assignments'

SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'crm-secret-key')
DEBUG = os.getenv('FLASK_DEBUG', '0') in ('1','true','yes')

DISPOSITIONS = [
    "No Answer", "Busy", "Switch Off", "Wrong Number", "DND/Spam",
    "Connected - Interested", "Connected - Not Interested",
    "Callback Scheduled", "Follow-up Needed"
]

RECENT_HOURS_COOLDOWN = 24  # avoid re-assigning numbers attempted in last N hours

# =========================
# ====== APP & DB =========
# =========================
app = Flask(__name__)
app.secret_key = SECRET_KEY

def ch():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT, username=CH_USER, password=CH_PASS, database=CH_DB
    )

def ensure_tables():
    c = ch()
    c.command('CREATE DATABASE IF NOT EXISTS Calling_CRM')

    # Users table
    c.command(f'''
    CREATE TABLE IF NOT EXISTS {USERS_TABLE} (
        user_id       UUID,
        name          String,
        username      LowCardinality(String),
        password_hash String,
        role          LowCardinality(String),     -- 'agent' | 'lead' | 'manager'
        team          LowCardinality(String),     -- e.g. 'A', 'B'
        manager       LowCardinality(String),     -- e.g. '11'
        is_active     UInt8 DEFAULT 1,
        created_at    DateTime DEFAULT now(),
        last_login    Nullable(DateTime)
    ) ENGINE = MergeTree
    ORDER BY (username)
    ''')

    # Attempts table (append-only)
    c.command(f'''
    CREATE TABLE IF NOT EXISTS {ATTEMPTS_TABLE} (
        attempt_id  UUID,
        mobile      String,
        lender      String,
        amount      Float64,
        disposition LowCardinality(String),
        comment     String,
        agent       String,
        team        String,
        manager     String,
        created_at  DateTime DEFAULT now(),
        ip          String,
        ua          String
    ) ENGINE = MergeTree
    ORDER BY (mobile, created_at)
    ''')

    # Callbacks table
    c.command(f'''
    CREATE TABLE IF NOT EXISTS {CALLBACKS_TABLE} (
        callback_id  UUID,
        mobile       String,
        schedule_at  DateTime,
        created_by   String,
        assigned_to  String DEFAULT '',
        status       LowCardinality(String) DEFAULT 'open',  -- 'open'|'closed'
        created_at   DateTime DEFAULT now(),
        closed_at    Nullable(DateTime)
    ) ENGINE = MergeTree
    ORDER BY (mobile, schedule_at)
    ''')

    # Assignments table
    c.command(f'''
    CREATE TABLE IF NOT EXISTS {ASSIGN_TABLE} (
        assign_id   UUID,
        mobile      String,
        agent       String,
        status      LowCardinality(String) DEFAULT 'open',   -- 'open'|'closed'
        assigned_at DateTime DEFAULT now(),
        closed_at   Nullable(DateTime)
    ) ENGINE = MergeTree
    ORDER BY (agent, assigned_at)
    ''')

ensure_tables()

# =========================
# ===== USER HELPERS ======
# =========================
def get_user(username: str):
    q = f"""
    SELECT user_id, name, username, password_hash, role, team, manager, is_active
    FROM {USERS_TABLE}
    WHERE username = %(u)s
    LIMIT 1
    """
    rows = ch().query(q, parameters={'u': username}).named_results()
    return rows[0] if rows else None

def set_last_login(user_id: str):
    ch().command(f"""
        ALTER TABLE {USERS_TABLE}
        UPDATE last_login = now()
        WHERE user_id = %(id)s
    """, parameters={'id': user_id})

def list_users():
    return ch().query(f"""
        SELECT user_id, name, username, role, team, manager, is_active, created_at, last_login
        FROM {USERS_TABLE}
        ORDER BY role DESC, username
    """).named_results()

def user_exists(username: str) -> bool:
    r = ch().query(f"SELECT count() FROM {USERS_TABLE} WHERE username = %(u)s", parameters={'u': username}).first_item
    return int(r or 0) > 0

def insert_user(name, username, password, role, team, manager, is_active=1):
    if user_exists(username):
        return False, "Username already exists"
    pwd_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    ch().command(f"""
        INSERT INTO {USERS_TABLE}
        (user_id, name, username, password_hash, role, team, manager, is_active)
        VALUES (%(id)s, %(n)s, %(u)s, %(ph)s, %(r)s, %(t)s, %(m)s, %(ia)s)
    """, parameters={
        'id': str(uuid.uuid4()), 'n': name, 'u': username, 'ph': pwd_hash,
        'r': role, 't': team, 'm': manager, 'ia': int(is_active)
    })
    return True, "User created"

def reset_password(username: str, new_password: str):
    if not user_exists(username):
        return False, "Username not found"
    pwd_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    ch().command(f"""
        ALTER TABLE {USERS_TABLE}
        UPDATE password_hash = %(ph)s
        WHERE username = %(u)s
    """, parameters={'ph': pwd_hash, 'u': username})
    return True, "Password updated"

def toggle_user(username: str, active: bool):
    if not user_exists(username):
        return False, "Username not found"
    ch().command(f"""
        ALTER TABLE {USERS_TABLE}
        UPDATE is_active = %(ia)s
        WHERE username = %(u)s
    """, parameters={'ia': int(active), 'u': username})
    return True, "User status updated"

# =========================
# ====== AUTH GUARDS ======
# =========================
def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login', next=request.path))
            if role:
                user_role = session.get('role')
                if role == 'lead' and user_role not in ('lead', 'manager'):
                    return "Forbidden (Lead/Manager only)", 403
                if role == 'manager' and user_role != 'manager':
                    return "Forbidden (Manager only)", 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# =========================
# ======= TEMPLATES =======
# =========================
BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Calling CRM</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <style>
    :root{ --ink:#0f172a; --muted:#64748b; --line:#e5e7eb; }
    body{ background:#f7fafc; color:var(--ink); }
    .card{ background:#fff; border:1px solid rgba(2,6,23,.06); border-radius:1rem; box-shadow:0 1px 2px rgba(2,6,23,.05); }
    .btn{ padding:.6rem 1rem; border-radius:.75rem; border:1px solid #e5e7eb; background:#0ea5e9; color:#fff; }
    .btn-secondary{ background:#f8fafc; color:#0f172a; }
    .chip{ font-size:.75rem; padding:.2rem .5rem; border-radius:.5rem; border:1px solid #e5e7eb; background:#f8fafc; }
    .tbl th{ background:#f8fafc; font-weight:600; }
    .tbl td, .tbl th { border-bottom:1px solid #eef2f7; padding:.5rem .75rem; }
    .link{ color:#0ea5e9; text-decoration:underline; }
  </style>
</head>
<body class="min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-semibold">📞 Calling CRM</h1>
      <div class="text-sm space-x-2">
        {% if session.user %}
          <a class="chip" href="{{ url_for('home') }}">Home</a>
          <a class="chip" href="{{ url_for('queue') }}">My Queue</a>
          <a class="chip" href="{{ url_for('assign_next') }}">🎯 Assign Next</a>
          <a class="chip" href="{{ url_for('overview') }}">Overview</a>
          <a class="chip" href="{{ url_for('logs') }}">Logs</a>
          {% if session.role == 'manager' %}
            <a href="{{ url_for('admin_users') }}" class="chip">Admin Users</a>
          {% endif %}
          <span class="chip">User: {{session.user}} ({{session.role}})</span>
          <a href="{{ url_for('logout') }}" class="chip">Logout</a>
        {% endif %}
      </div>
    </div>
    {% block content %}{% endblock %}
  </div>
</body>
</html>
"""

LOGIN_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="max-w-md mx-auto card p-6">
  <h2 class="text-xl font-semibold mb-4">Sign in</h2>
  <form method="post" class="space-y-3">
    <div>
      <label class="text-sm text-slate-600">Username</label>
      <input name="username" class="w-full border rounded-lg p-2" required />
    </div>
    <div>
      <label class="text-sm text-slate-600">Password</label>
      <input name="password" type="password" class="w-full border rounded-lg p-2" required />
    </div>
    <button class="btn w-full">Login</button>
    {% if error %}<p class="text-red-600 text-sm mt-2">{{ error }}</p>{% endif %}
  </form>
</div>
{% endblock %}
"""

HOME_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="grid md:grid-cols-3 gap-4">
  <div class="md:col-span-2 card p-5">
    <h2 class="font-semibold mb-3">Search Mobile</h2>
    <form hx-get="{{ url_for('lookup') }}" hx-target="#result" class="flex gap-2">
      <input name="mobile" placeholder="91XXXXXXXXXX" class="flex-1 border rounded-lg p-2" required>
      <button class="btn">Search</button>
    </form>
    <div id="result" class="mt-4"></div>
  </div>

  <div class="card p-5">
    <h2 class="font-semibold mb-3">Quick Actions</h2>
    <div class="flex flex-col gap-2">
      <a class="btn" href="{{ url_for('assign_next') }}">🎯 Assign Next</a>
      <a class="btn-secondary p-2 rounded-lg border" href="{{ url_for('queue') }}">📋 My Queue</a>
      <a class="btn-secondary p-2 rounded-lg border" href="{{ url_for('overview') }}">📊 Team Overview</a>
      <a class="btn-secondary p-2 rounded-lg border" href="{{ url_for('logs') }}">🧾 Recent Logs</a>
      {% if session.role in ('lead','manager') %}
      <a class="btn-secondary p-2 rounded-lg border" href="{{ url_for('export_csv') }}">⬇️ Export CSV</a>
      {% endif %}
    </div>
  </div>
</div>
{% endblock %}
"""

LOOKUP_PARTIAL = """
{% if lead %}
  <div class="border rounded-lg p-3 mb-3">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm text-slate-500">Lead</div>
        <div class="text-lg font-semibold">{{ lead['Mobile'] }}</div>
      </div>
      <div class="text-right">
        <div class="text-sm text-slate-500">Lender</div>
        <div class="font-semibold">{{ lead['Lender'] or '-' }}</div>
      </div>
      <div class="text-right">
        <div class="text-sm text-slate-500">Amount</div>
        <div class="font-semibold">{{ "%.2f"|format(lead['Amount']) if lead['Amount'] is not none else '-' }}</div>
      </div>
      <div class="text-right">
        <div class="text-sm text-slate-500">Lead Date</div>
        <div class="font-semibold">{{ lead['Lead_date'] }}</div>
      </div>
    </div>
  </div>
{% else %}
  <div class="p-3 border rounded-lg bg-yellow-50">No lead record found for this mobile in <code>{{ table }}</code>.</div>
{% endif %}

<div class="grid md:grid-cols-2 gap-4">
  <div class="card p-4">
    <h3 class="font-semibold mb-2">Add Attempt / Schedule Callback</h3>
  {% if session.role == 'lead' %}
    <div class="p-3 border rounded bg-slate-50 text-slate-600 text-sm">Leads are view-only. Please contact a manager for access.</div>
  {% else %}
    <form hx-post="{{ url_for('add_attempt') }}" hx-target="#history" hx-swap="outerHTML" class="space-y-2">
      <input type="hidden" name="mobile" value="{{ mobile }}">
      <input type="hidden" name="lender" value="{{ lead['Lender'] if lead else '' }}">
      <input type="hidden" name="amount" value="{{ lead['Amount'] if lead else 0 }}">
      <div>
        <label class="text-sm text-slate-600">Disposition</label>
        <select name="disposition" class="w-full border rounded-lg p-2" required>
          {% for d in dispositions %}
            <option value="{{ d }}">{{ d }}</option>
          {% endfor %}
        </select>
      </div>
      <div>
        <label class="text-sm text-slate-600">Comment</label>
        <textarea name="comment" class="w-full border rounded-lg p-2" rows="3" placeholder="Notes..."></textarea>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <div>
          <label class="text-sm text-slate-600">Next follow-up (optional)</label>
          <input type="datetime-local" name="next_followup_at" class="w-full border rounded-lg p-2">
        </div>
        <div class="flex items-end gap-2">
          <label class="text-sm text-slate-600">
            <input type="checkbox" name="resolve_callback" value="1" class="mr-1">
            Resolve open callback(s)
          </label>
        </div>
      </div>

      <button class="btn">Save Attempt</button>
    </form>
  {% endif %}
  </div>

  <div class="card p-4">
    <h3 class="font-semibold mb-2">History</h3>
    <div id="history" hx-get="{{ url_for('history') }}?mobile={{ mobile }}" hx-trigger="load"></div>
  </div>
</div>
"""

HISTORY_PARTIAL = """
<table class="w-full tbl text-sm">
  <thead>
    <tr>
      <th>Date/Time</th>
      <th>Agent</th>
      <th>Disposition</th>
      <th>Comment</th>
    </tr>
  </thead>
  <tbody>
  {% for r in rows %}
    <tr>
      <td>{{ r['created_at'] }}</td>
      <td>{{ r['agent'] }}</td>
      <td>{{ r['disposition'] }}</td>
      <td>{{ r['comment'] }}</td>
    </tr>
  {% else %}
    <tr><td colspan="4" class="text-center text-slate-500 py-4">No attempts yet.</td></tr>
  {% endfor %}
  </tbody>
</table>
"""

QUEUE_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="grid md:grid-cols-3 gap-4">
  <div class="card p-5 md:col-span-2">
    <div class="flex items-center justify-between">
      <h2 class="font-semibold mb-3">My Due Callbacks</h2>
      <a class="btn" href="{{ url_for('assign_next') }}">🎯 Assign Next</a>
    </div>
    <table class="w-full tbl text-sm">
      <thead><tr><th>When</th><th>Mobile</th><th>Assigned</th><th>Status</th><th>Action</th></tr></thead>
      <tbody>
      {% for c in due_callbacks %}
        <tr>
          <td>{{ c['schedule_at'] }}</td>
          <td>{{ c['mobile'] }}</td>
          <td>{{ c['assigned_to'] or '-' }}</td>
          <td>{{ c['status'] }}</td>
          <td><a class="link" href="{{ url_for('lookup') }}?mobile={{ c['mobile'] }}">Open</a></td>
        </tr>
      {% else %}
        <tr><td colspan="5" class="text-center text-slate-500 py-4">No due callbacks.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card p-5">
    <h2 class="font-semibold mb-3">Open Assignments</h2>
    <table class="w-full tbl text-sm">
      <thead><tr><th>Assigned At</th><th>Mobile</th><th>Action</th></tr></thead>
      <tbody>
      {% for a in open_assignments %}
        <tr>
          <td>{{ a['assigned_at'] }}</td>
          <td>{{ a['mobile'] }}</td>
          <td><a class="link" href="{{ url_for('lookup') }}?mobile={{ a['mobile'] }}">Open</a></td>
        </tr>
      {% else %}
        <tr><td colspan="3" class="text-center text-slate-500 py-4">No open assignments.</td></tr>
      {% endfor %}
      </tbody>
    </table>

    <h2 class="font-semibold my-3">Upcoming (next 24h)</h2>
    <table class="w-full tbl text-sm">
      <thead><tr><th>When</th><th>Mobile</th></tr></thead>
      <tbody>
      {% for c in upcoming_callbacks %}
        <tr>
          <td>{{ c['schedule_at'] }}</td>
          <td>{{ c['mobile'] }}</td>
        </tr>
      {% else %}
        <tr><td colspan="2" class="text-center text-slate-500 py-4">No upcoming callbacks.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

OVERVIEW_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="card p-5">
  <form method="get" class="grid md:grid-cols-5 gap-3">
    <div>
      <label class="text-sm text-slate-600">From</label>
      <input type="date" name="from" value="{{ q_from }}" class="w-full border rounded-lg p-2">
    </div>
    <div>
      <label class="text-sm text-slate-600">To</label>
      <input type="date" name="to" value="{{ q_to }}" class="w-full border rounded-lg p-2">
    </div>
    <div>
      <label class="text-sm text-slate-600">Agent</label>
      <input name="agent" value="{{ q_agent }}" class="w-full border rounded-lg p-2" placeholder="username">
    </div>
    <div>
      <label class="text-sm text-slate-600">Team</label>
      <input name="team" value="{{ q_team }}" class="w-full border rounded-lg p-2" placeholder="A">
    </div>
    <div class="flex items-end">
      <button class="btn w-full">Apply</button>
    </div>
  </form>
</div>

<div class="grid md:grid-cols-2 gap-4 mt-4">
  <div class="card p-4">
    <h3 class="font-semibold mb-2">Attempts by Day</h3>
    <table class="w-full tbl text-sm">
      <thead><tr><th>Date</th><th>Attempts</th><th>Connected</th></tr></thead>
      <tbody>
        {% for r in by_day %}
          <tr>
            <td>{{ r['d'] }}</td>
            <td>{{ r['attempts'] }}</td>
            <td>{{ r['connected'] }}</td>
          </tr>
        {% else %}
          <tr><td colspan="3" class="text-center text-slate-500 py-4">No data</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card p-4">
    <h3 class="font-semibold mb-2">Attempts by Agent</h3>
    <table class="w-full tbl text-sm">
      <thead><tr><th>Agent</th><th>Attempts</th><th>Connected</th></tr></thead>
      <tbody>
        {% for r in by_agent %}
          <tr>
            <td>{{ r['agent'] }}</td>
            <td>{{ r['attempts'] }}</td>
            <td>{{ r['connected'] }}</td>
          </tr>
        {% else %}
          <tr><td colspan="3" class="text-center text-slate-500 py-4">No data</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

LOGS_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="card p-5">
  <h2 class="font-semibold mb-3">Recent Attempts</h2>
  <table class="w-full tbl text-sm">
    <thead><tr>
      <th>Time</th><th>Mobile</th><th>Lender</th><th>Amount</th><th>Agent</th><th>Disposition</th><th>Comment</th>
    </tr></thead>
    <tbody>
      {% for r in rows %}
      <tr>
        <td>{{ r['created_at'] }}</td>
        <td>{{ r['mobile'] }}</td>
        <td>{{ r['lender'] }}</td>
        <td>{{ "%.2f"|format(r['amount']) }}</td>
        <td>{{ r['agent'] }}</td>
        <td>{{ r['disposition'] }}</td>
        <td>{{ r['comment'] }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

ADMIN_USERS_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="grid md:grid-cols-2 gap-4">
  <div class="card p-5">
    <h2 class="font-semibold mb-3">Users</h2>
    <table class="w-full tbl text-sm">
      <thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Team</th><th>Manager</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td><code>{{ u['username'] }}</code></td>
          <td>{{ u['name'] }}</td>
          <td>{{ u['role'] }}</td>
          <td>{{ u['team'] }}</td>
          <td>{{ u['manager'] }}</td>
          <td>{{ 'Active' if u['is_active']==1 else 'Disabled' }}</td>
          <td>{{ u['last_login'] or '-' }}</td>
          <td class="space-x-1">
            <form method="post" action="{{ url_for('admin_reset_password') }}" style="display:inline">
              <input type="hidden" name="username" value="{{ u['username'] }}"/>
              <input name="new_password" placeholder="new pass" class="border rounded p-1 text-xs" required />
              <button class="chip">Reset</button>
            </form>
            {% if u['is_active']==1 %}
            <form method="post" action="{{ url_for('admin_toggle_user') }}" style="display:inline">
              <input type="hidden" name="username" value="{{ u['username'] }}"/>
              <input type="hidden" name="active" value="0"/>
              <button class="chip">Disable</button>
            </form>
            {% else %}
            <form method="post" action="{{ url_for('admin_toggle_user') }}" style="display:inline">
              <input type="hidden" name="username" value="{{ u['username'] }}"/>
              <input type="hidden" name="active" value="1"/>
              <button class="chip">Enable</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card p-5">
    <h2 class="font-semibold mb-3">Add User</h2>
    <form method="post" action="{{ url_for('admin_add_user') }}" class="grid grid-cols-2 gap-2">
      <input name="name" placeholder="Full name" class="border rounded p-2 col-span-2" required />
      <input name="username" placeholder="Username" class="border rounded p-2" required />
      <input name="password" placeholder="Password" class="border rounded p-2" required />
      <select name="role" class="border rounded p-2" required>
        <option value="agent">agent</option>
        <option value="lead">lead</option>
        <option value="manager">manager</option>
      </select>
      <input name="team" placeholder="Team (e.g. A)" class="border rounded p-2" />
      <input name="manager" placeholder="Manager username" class="border rounded p-2" />
      <button class="btn col-span-2 mt-2">Create</button>
      {% if msg %}<div class="col-span-2 text-sm text-slate-600 mt-2">{{ msg }}</div>{% endif %}
    </form>
  </div>
</div>
{% endblock %}
"""

# —— Register templates once via DictLoader (fixes recursion) ——
app.jinja_loader = DictLoader({
    'base.html':         BASE_HTML,
    'login.html':        LOGIN_HTML,
    'home.html':         HOME_HTML,
    'lookup_partial.html':  LOOKUP_PARTIAL,
    'history_partial.html': HISTORY_PARTIAL,
    'queue.html':        QUEUE_HTML,
    'overview.html':     OVERVIEW_HTML,
    'logs.html':         LOGS_HTML,
    'admin_users.html':  ADMIN_USERS_HTML,
})

# =========================
# ========= ROUTES ========
# =========================
@app.route('/favicon.ico')
def favicon():
    return ('', 204)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')

        rec = get_user(u)
        if rec and rec['is_active'] == 1:
            try:
                if bcrypt.checkpw(p.encode('utf-8'), rec['password_hash'].encode('utf-8')):
                    session['user_id'] = rec['user_id']
                    session['user']    = rec['username']
                    session['role']    = rec['role']
                    session['team']    = rec['team']
                    session['manager'] = rec['manager']
                    set_last_login(rec['user_id'])
                    return redirect(request.args.get('next') or url_for('home'))
            except Exception:
                pass
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required()
def home():
    return render_template('home.html')

@app.route('/lookup')
@login_required()
def lookup():
    mobile = request.args.get('mobile','').strip()
    if not mobile:
        return '<div class="p-3 border rounded-lg bg-yellow-50">Enter a mobile.</div>'

    client = ch()
    lead = None
    try:
        q = f"""
        SELECT Lead_date, Lender, Mobile, Amount
        FROM {LEADS_TABLE}
        WHERE Mobile = %(mobile)s
        ORDER BY Lead_date DESC
        LIMIT 1
        """
        rows = client.query(q, parameters={'mobile': mobile}).named_results()
        lead = rows[0] if rows else None
    except Exception:
        lead = None

    return render_template('lookup_partial.html',
                           table=LEADS_TABLE,
                           lead=lead,
                           mobile=mobile,
                           dispositions=DISPOSITIONS)

@app.route('/history')
@login_required()
def history():
    mobile = request.args.get('mobile','').strip()
    rows = ch().query(f"""
        SELECT created_at, agent, disposition, comment
        FROM {ATTEMPTS_TABLE}
        WHERE mobile = %(m)s
        ORDER BY created_at DESC
        LIMIT 200
    """, parameters={'m': mobile}).named_results()
    return render_template('history_partial.html', rows=rows)

@app.route('/add_attempt', methods=['POST'])
@login_required()
def add_attempt():
    # Leads are view-only
    if session.get('role') == 'lead':
        return "Forbidden (Lead is view-only)", 403

    mobile = request.form.get('mobile','').strip()
    lender = (request.form.get('lender') or '').strip()
    amount = float(request.form.get('amount') or 0)
    disposition = request.form.get('disposition','').strip()
    comment = (request.form.get('comment') or '').strip()
    next_followup_at_raw = (request.form.get('next_followup_at') or '').strip()
    resolve_callback = (request.form.get('resolve_callback') == '1')

    user = session.get('user')
    team = session.get('team')
    manager = session.get('manager')

    meta_ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
    meta_ua = (request.user_agent.string or '')[:500]

    # 1) Insert attempt
    ch().command(f"""
    INSERT INTO {ATTEMPTS_TABLE}
        (attempt_id, mobile, lender, amount, disposition, comment, agent, team, manager, ip, ua)
    VALUES
        (%(id)s, %(m)s, %(l)s, %(a)s, %(d)s, %(c)s, %(ag)s, %(t)s, %(mg)s, %(ip)s, %(ua)s)
    """, parameters={
        'id': str(uuid.uuid4()), 'm': mobile, 'l': lender, 'a': amount, 'd': disposition, 'c': comment,
        'ag': user, 't': team, 'mg': manager, 'ip': meta_ip, 'ua': meta_ua
    })

    # 2) Schedule callback if provided
    if next_followup_at_raw:
        try:
            schedule_at = datetime.strptime(next_followup_at_raw, "%Y-%m-%dT%H:%M")
            ch().command(f"""
                INSERT INTO {CALLBACKS_TABLE}
                (callback_id, mobile, schedule_at, created_by, assigned_to, status)
                VALUES (%(id)s, %(m)s, %(s)s, %(by)s, %(assn)s, 'open')
            """, parameters={
                'id': str(uuid.uuid4()), 'm': mobile, 's': schedule_at,
                'by': user, 'assn': user  # assign to self by default
            })
        except Exception:
            pass

    # 3) Resolve open callbacks for this mobile if requested
    if resolve_callback:
        ch().command(f"""
            ALTER TABLE {CALLBACKS_TABLE}
            UPDATE status = 'closed', closed_at = now()
            WHERE mobile = %(m)s AND status = 'open'
        """, parameters={'m': mobile})

    # 4) Close open assignment for this agent & mobile (worked on)
    ch().command(f"""
        ALTER TABLE {ASSIGN_TABLE}
        UPDATE status = 'closed', closed_at = now()
        WHERE mobile = %(m)s AND agent = %(a)s AND status = 'open'
    """, parameters={'m': mobile, 'a': user})

    # Return updated history partial
    rows = ch().query(f"""
        SELECT created_at, agent, disposition, comment
        FROM {ATTEMPTS_TABLE}
        WHERE mobile = %(m)s
        ORDER BY created_at DESC
        LIMIT 200
    """, parameters={'m': mobile}).named_results()
    return render_template('history_partial.html', rows=rows)

# ------- Agent Queue -------
@app.route('/queue')
@login_required()
def queue():
    agent = session.get('user')

    # Due callbacks (assigned to me and open)
    due = ch().query(f"""
        SELECT mobile, schedule_at, assigned_to, status
        FROM {CALLBACKS_TABLE}
        WHERE status = 'open' AND assigned_to = %(a)s AND schedule_at <= now()
        ORDER BY schedule_at ASC
        LIMIT 200
    """, parameters={'a': agent}).named_results()

    # Upcoming (next 24h) callbacks assigned to me
    upcoming = ch().query(f"""
        SELECT mobile, schedule_at
        FROM {CALLBACKS_TABLE}
        WHERE status = 'open' AND assigned_to = %(a)s
          AND schedule_at > now() AND schedule_at <= now() + INTERVAL 1 DAY
        ORDER BY schedule_at ASC
        LIMIT 200
    """, parameters={'a': agent}).named_results()

    # Open assignments for me
    open_assn = ch().query(f"""
        SELECT mobile, assigned_at
        FROM {ASSIGN_TABLE}
        WHERE agent = %(a)s AND status = 'open'
        ORDER BY assigned_at DESC
        LIMIT 200
    """, parameters={'a': agent}).named_results()

    return render_template('queue.html',
                           due_callbacks=due,
                           upcoming_callbacks=upcoming,
                           open_assignments=open_assn)

@app.route('/assign-next')
@login_required()
def assign_next():
    """Assign next best mobile to the current agent:
       1) Due callbacks assigned to self
       2) Unassigned due callbacks
       3) Fresh leads not attempted in RECENT_HOURS_COOLDOWN and not assigned
    """
    agent = session.get('user')

    # Helper to create assignment and redirect
    def _assign_and_redirect(mobile: str):
        ch().command(f"""
            INSERT INTO {ASSIGN_TABLE} (assign_id, mobile, agent)
            VALUES (%(id)s, %(m)s, %(a)s)
        """, parameters={'id': str(uuid.uuid4()), 'm': mobile, 'a': agent})
        return redirect(url_for('lookup') + f'?mobile={mobile}')

    # 1) Due callbacks already assigned to this agent
    rows = ch().query(f"""
        SELECT mobile
        FROM {CALLBACKS_TABLE}
        WHERE status = 'open' AND assigned_to = %(a)s AND schedule_at <= now()
        ORDER BY schedule_at ASC
        LIMIT 1
    """, parameters={'a': agent}).named_results()
    if rows:
        return _assign_and_redirect(rows[0]['mobile'])

    # 2) Unassigned due callbacks → take ownership
    rows = ch().query(f"""
        SELECT mobile
        FROM {CALLBACKS_TABLE}
        WHERE status = 'open' AND (assigned_to = '' OR assigned_to = ' ')
          AND schedule_at <= now()
        ORDER BY schedule_at ASC
        LIMIT 1
    """).named_results()
    if rows:
        mobile = rows[0]['mobile']
        ch().command(f"""
            ALTER TABLE {CALLBACKS_TABLE}
            UPDATE assigned_to = %(a)s
            WHERE mobile = %(m)s AND status = 'open' AND schedule_at <= now()
            LIMIT 1
        """, parameters={'a': agent, 'm': mobile})
        return _assign_and_redirect(mobile)

    # 3) Fresh lead: not assigned and not attempted in recent hours by anyone
    rows = ch().query(f"""
        WITH recent_cutoff AS (now() - INTERVAL {RECENT_HOURS_COOLDOWN} HOUR)
        SELECT L.Mobile AS mobile
        FROM {LEADS_TABLE} AS L
        LEFT JOIN (
            SELECT mobile
            FROM {ASSIGN_TABLE}
            WHERE status = 'open'
            GROUP BY mobile
        ) AS A ON A.mobile = L.Mobile
        WHERE A.mobile IS NULL
          AND L.Mobile NOT IN (
            SELECT DISTINCT mobile
            FROM {ATTEMPTS_TABLE}
            WHERE created_at >= recent_cutoff
          )
        ORDER BY L.Lead_date DESC
        LIMIT 1
    """).named_results()

    if rows:
        return _assign_and_redirect(rows[0]['mobile'])

    return redirect(url_for('queue'))

# ------- Overview / Logs / Export -------
@app.route('/overview')
@login_required(role='lead')
def overview():
    today = datetime.now().date()
    q_from = request.args.get('from', (today - timedelta(days=7)).isoformat())
    q_to   = request.args.get('to', today.isoformat())
    q_agent = request.args.get('agent','').strip()
    q_team  = request.args.get('team','').strip()

    where = ["created_at >= toDateTime(%(from)s)", "created_at < toDateTime(%(to)s) + INTERVAL 1 DAY"]
    params = {'from': q_from + ' 00:00:00', 'to': q_to + ' 23:59:59'}
    if q_agent:
        where.append("agent = %(agent)s"); params['agent'] = q_agent
    if q_team:
        where.append("team = %(team)s"); params['team'] = q_team
    where_sql = " AND ".join(where)

    client = ch()
    by_day = client.query(f"""
        SELECT toDate(created_at) AS d,
               count() AS attempts,
               countIf(disposition LIKE 'Connected%') AS connected
        FROM {ATTEMPTS_TABLE}
        WHERE {where_sql}
        GROUP BY d
        ORDER BY d DESC
        LIMIT 60
    """, parameters=params).named_results()

    by_agent = client.query(f"""
        SELECT agent,
               count() AS attempts,
               countIf(disposition LIKE 'Connected%') AS connected
        FROM {ATTEMPTS_TABLE}
        WHERE {where_sql}
        GROUP BY agent
        ORDER BY attempts DESC
        LIMIT 100
    """, parameters=params).named_results()

    return render_template('overview.html',
                           by_day=by_day, by_agent=by_agent,
                           q_from=q_from, q_to=q_to, q_agent=q_agent, q_team=q_team)

@app.route('/logs')
@login_required()
def logs():
    rows = ch().query(f"""
        SELECT created_at, mobile, lender, amount, agent, disposition, comment
        FROM {ATTEMPTS_TABLE}
        ORDER BY created_at DESC
        LIMIT 200
    """).named_results()
    return render_template('logs.html', rows=rows)

@app.route('/export.csv')
@login_required(role='lead')
def export_csv():
    today = datetime.now().date()
    q_from = request.args.get('from', (today - timedelta(days=7)).isoformat())
    q_to   = request.args.get('to', today.isoformat())
    q_agent = request.args.get('agent','').strip()
    q_team  = request.args.get('team','').strip()

    where = ["created_at >= toDateTime(%(from)s)", "created_at < toDateTime(%(to)s) + INTERVAL 1 DAY"]
    params = {'from': q_from + ' 00:00:00', 'to': q_to + ' 23:59:59'}
    if q_agent:
        where.append("agent = %(agent)s"); params['agent'] = q_agent
    if q_team:
        where.append("team = %(team)s"); params['team'] = q_team
    where_sql = " AND ".join(where)

    data = ch().query(f"""
        SELECT created_at, mobile, lender, amount, agent, team, manager, disposition, comment, ip, ua
        FROM {ATTEMPTS_TABLE}
        WHERE {where_sql}
        ORDER BY created_at DESC
    """, parameters=params)

    def generate():
        header = ["created_at","mobile","lender","amount","agent","team","manager","disposition","comment","ip","ua"]
        yield ",".join(header) + "\n"
        for row in data.result_rows:
            vals = []
            for v in row:
                s = "" if v is None else str(v)
                if any(c in s for c in [",", "\n", '"']):
                    s = '"' + s.replace('"','""') + '"'
                vals.append(s)
            yield ",".join(vals) + "\n"

    filename = f"call_attempts_{q_from}_to_{q_to}.csv"
    return Response(generate(), mimetype='text/csv',
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

# -------- Admin (Manager only) --------
@app.route('/admin/users')
@login_required(role='manager')
def admin_users():
    users = list_users()
    return render_template('admin_users.html', users=users, msg=None)

@app.route('/admin/users/add', methods=['POST'])
@login_required(role='manager')
def admin_add_user():
    name     = (request.form.get('name') or '').strip()
    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()
    role     = (request.form.get('role') or '').strip()
    team     = (request.form.get('team') or '').strip()
    manager  = (request.form.get('manager') or '').strip()

    ok, msg = insert_user(name, username, password, role, team, manager or session.get('user'))
    users = list_users()
    return render_template('admin_users.html', users=users, msg=msg)

@app.route('/admin/users/reset', methods=['POST'])
@login_required(role='manager')
def admin_reset_password():
    username    = (request.form.get('username') or '').strip()
    new_password = (request.form.get('new_password') or '').strip()
    ok, msg = reset_password(username, new_password)
    users = list_users()
    return render_template('admin_users.html', users=users, msg=msg)

@app.route('/admin/users/toggle', methods=['POST'])
@login_required(role='manager')
def admin_toggle_user():
    username = (request.form.get('username') or '').strip()
    active   = (request.form.get('active') or '1') in ('1','true','yes')
    ok, msg = toggle_user(username, active)
    users = list_users()
    return render_template('admin_users.html', users=users, msg=msg)

# =========================
# ======== BOOT ===========
# =========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=DEBUG)
