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
# ==== CONTEXT GLOBALS ====
# =========================
@app.context_processor
def inject_globals():
    return {'datetime': datetime}

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
    rows = list(ch().query(q, parameters={'u': username}).named_results())
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
  <meta name="color-scheme" content="light"/>
  <title>{% block title %}Calling CRM{% endblock %}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Poppins:wght@500;600;700&family=Space+Mono:wght@400;700&family=Manrope:wght@500;600&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:wght,FILL,GRAD,opsz@400,0,0,48" rel="stylesheet" />
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <style>
    :root{
      --ink:#0f172a;
      --muted:#64748b;
      --line:#e2e8f0;
      --surface:#ffffff;
      --surface-muted:#f8fafc;
      --accent:#0ea5e9;
      --accent-strong:#0284c7;
      --accent-soft:#e0f2fe;
      --warning:#f97316;
      --success:#10b981;
      --indigo:#6366f1;
      --plum:#a855f7;
      --rose:#f43f5e;
    }
    body{
      background:radial-gradient(circle at top left,#e0f2fe 0%,#f5f3ff 40%,#f8fafc 70%);
      color:var(--ink);
      font-family:'Inter','Manrope',system-ui,sans-serif;
      -webkit-font-smoothing:antialiased;
    }
    h1,h2,h3,h4{
      font-family:'Poppins','Inter',sans-serif;
      letter-spacing:-0.01em;
    }
    code,.font-mono{
      font-family:'Space Mono',monospace;
    }
    .card{
      background:var(--surface);
      border:1px solid rgba(2,6,23,.06);
      border-radius:1rem;
      box-shadow:0 12px 24px -16px rgba(15,23,42,.35);
      transition:transform .2s ease, box-shadow .2s ease;
    }
    .card:hover{
      transform:translateY(-2px);
      box-shadow:0 16px 32px -20px rgba(15,23,42,.4);
    }
    .btn{
      padding:.65rem 1.1rem;
      border-radius:.85rem;
      border:1px solid transparent;
      background:linear-gradient(135deg,var(--accent),var(--accent-strong));
      color:#fff;
      font-weight:600;
      font-family:'Manrope','Inter',sans-serif;
      transition:transform .18s ease, box-shadow .18s ease;
      box-shadow:0 10px 18px -12px rgba(2,132,199,.8);
    }
    .btn:hover{
      transform:translateY(-1px);
      box-shadow:0 14px 28px -18px rgba(2,132,199,.85);
    }
    .btn-secondary{
      background:var(--surface);
      border:1px solid var(--line);
      color:var(--ink);
      border-radius:.85rem;
      padding:.55rem 1rem;
      font-family:'Manrope','Inter',sans-serif;
      transition:background .18s ease, color .18s ease, transform .18s ease;
    }
    .btn-secondary:hover{
      background:var(--surface-muted);
      transform:translateY(-1px);
    }
    .btn-ghost{
      padding:.5rem .9rem;
      border-radius:.75rem;
      color:var(--muted);
      font-family:'Manrope','Inter',sans-serif;
    }
    .material-symbols-rounded{
      font-variation-settings:'FILL' 0,'wght' 400,'GRAD' 0,'opsz' 24;
      font-size:1.35rem;
      line-height:1;
      display:inline-flex;
      align-items:center;
      justify-content:center;
    }
    .stat-card{
      border-radius:1.5rem;
      padding:1.5rem;
      background:var(--surface);
      border:1px solid rgba(148,163,184,.12);
      box-shadow:0 22px 32px -24px rgba(15,23,42,.45);
      position:relative;
      overflow:hidden;
    }
    .stat-card::after{
      content:"";
      position:absolute;
      inset:auto -40% -40% auto;
      width:8rem;
      height:8rem;
      border-radius:999px;
      background:rgba(255,255,255,.2);
      filter:blur(0.5px);
      transform:translate(40%,40%);
    }
    .stat-card__icon{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:2.75rem;
      height:2.75rem;
      border-radius:1rem;
      background:rgba(255,255,255,.25);
      margin-bottom:.75rem;
    }
    .stat-card__value{
      font-size:2.6rem;
      font-weight:600;
      letter-spacing:-0.03em;
    }
    .stat-card__label{
      text-transform:uppercase;
      font-size:.68rem;
      font-weight:700;
      letter-spacing:.22em;
    }
    .stat-card--sky{
      background:linear-gradient(140deg,#0ea5e9 0%,#0284c7 100%);
      color:#ecfeff;
    }
    .stat-card--sunrise{
      background:linear-gradient(140deg,#fb7185 0%,#f43f5e 100%);
      color:#fff7fb;
    }
    .stat-card--lime{
      background:linear-gradient(140deg,#34d399 0%,#10b981 100%);
      color:#ecfdf5;
    }
    .stat-card--violet{
      background:linear-gradient(145deg,#a855f7 0%,#6366f1 100%);
      color:#f5f3ff;
    }
    .chip{
      font-size:.75rem;
      padding:.35rem .7rem;
      border-radius:999px;
      border:1px solid rgba(15,23,42,.1);
      background:rgba(241,245,249,.8);
      backdrop-filter:blur(8px);
      display:inline-flex;
      align-items:center;
      gap:.35rem;
    }
    .quick-link{
      display:flex;
      align-items:center;
      gap:.75rem;
      padding:.75rem 1rem;
      border-radius:1.1rem;
      border:1px solid rgba(148,163,184,.18);
      background:linear-gradient(135deg,#f8fafc,rgba(148,163,184,.08));
      transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;
      color:var(--ink);
      text-decoration:none;
    }
    .quick-link:hover{
      transform:translateY(-2px);
      border-color:rgba(14,165,233,.45);
      box-shadow:0 18px 32px -22px rgba(14,165,233,.75);
    }
    .quick-link__icon{
      display:inline-flex;
      width:2.25rem;
      height:2.25rem;
      border-radius:0.9rem;
      align-items:center;
      justify-content:center;
      background:rgba(14,165,233,.14);
      color:var(--accent-strong);
    }
    .tbl{
      border-radius:1rem;
      overflow:hidden;
      background:var(--surface);
    }
    .tbl thead th{
      background:linear-gradient(120deg,rgba(99,102,241,.12),rgba(14,165,233,.12));
      font-weight:600;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-size:.7rem;
      color:var(--muted);
    }
    .tbl td,
    .tbl th{
      border-bottom:1px solid #e2e8f0;
      padding:.65rem .9rem;
    }
    .list-tile{
      display:flex;
      gap:.8rem;
      padding:1rem 1.1rem;
      border-radius:1.1rem;
      border:1px solid rgba(148,163,184,.12);
      background:rgba(255,255,255,.65);
      transition:transform .18s ease, border-color .18s ease;
    }
    .list-tile:not(:last-child){
      margin-bottom:.8rem;
    }
    .list-tile:hover{
      transform:translateY(-2px);
      border-color:rgba(14,165,233,.4);
    }
    .list-tile__icon{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:2.4rem;
      height:2.4rem;
      border-radius:.9rem;
      background:rgba(99,102,241,.08);
      color:var(--indigo);
      flex-shrink:0;
    }
    .tip-list li{
      display:flex;
      align-items:flex-start;
      gap:.65rem;
      line-height:1.4;
    }
    .tip-list .material-symbols-rounded{
      font-size:1rem;
      margin-top:.15rem;
      color:var(--accent-strong);
    }
    .link{
      color:var(--accent-strong);
      text-decoration:none;
      font-weight:500;
    }
    .link:hover{
      text-decoration:underline;
    }
    .nav-link{
      display:inline-flex;
      align-items:center;
      gap:.45rem;
      padding:.45rem .75rem;
      border-radius:.75rem;
      color:var(--muted);
      font-weight:500;
      transition:color .18s ease, background .18s ease, transform .18s ease;
    }
    .nav-link:hover{
      color:var(--ink);
      background:rgba(148,163,184,.12);
    }
    .nav-link-active{
      color:var(--ink);
      background:rgba(14,165,233,.16);
    }
    .input{
      border-radius:.9rem;
      border:1px solid rgba(148,163,184,.3);
      padding:.6rem .85rem;
      width:100%;
      transition:border-color .18s ease, box-shadow .18s ease;
    }
    .input:focus{
      outline:none;
      border-color:rgba(14,165,233,.6);
      box-shadow:0 0 0 4px rgba(14,165,233,.1);
    }
    .badge{
      display:inline-flex;
      align-items:center;
      gap:.3rem;
      padding:.3rem .65rem;
      border-radius:999px;
      background:rgba(14,165,233,.12);
      color:var(--accent-strong);
      font-size:.7rem;
      font-weight:600;
    }
    .htmx-indicator{
      position:fixed;
      inset:0;
      background:rgba(15,23,42,.12);
      display:flex;
      align-items:center;
      justify-content:center;
      z-index:50;
      backdrop-filter:blur(3px);
    }
    .htmx-indicator .spinner{
      width:3rem;
      height:3rem;
      border-radius:999px;
      border:4px solid rgba(14,165,233,.35);
      border-top-color:var(--accent-strong);
      animation:spin 1s linear infinite;
    }
    @keyframes spin{
      to{ transform:rotate(360deg); }
    }
  </style>
</head>
<body class="min-h-screen font-sans">
  <div id="htmx-indicator" class="htmx-indicator hidden" role="status" aria-live="polite">
    <div class="flex flex-col items-center gap-3 rounded-2xl bg-white/90 px-8 py-7 shadow-2xl">
      <div class="spinner"></div>
      <p class="text-sm font-medium text-slate-600">Updating...</p>
    </div>
  </div>
  <div class="flex min-h-screen flex-col">
    <header class="sticky top-0 z-40 border-b border-white/50 bg-white/80 shadow-sm backdrop-blur">
      <div class="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-4">
        <div class="flex items-center gap-3">
          <div class="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-100 text-indigo-600">
            <span class="material-symbols-rounded" aria-hidden="true">support_agent</span>
          </div>
          <div>
            <p class="text-sm uppercase tracking-[0.28em] text-slate-400">Calling CRM</p>
            <h1 class="text-xl font-semibold text-slate-800">Agent Workspace</h1>
          </div>
        </div>
        {% if session.user %}
        <nav class="hidden items-center gap-1 text-sm font-medium md:flex">
          {% set nav_links = [
            ('home', 'home', 'Home'),
            ('queue', 'checklist', 'My Queue'),
            ('assign_next', 'my_location', 'Assign Next'),
            ('overview', 'insights', 'Overview'),
            ('logs', 'history', 'Logs')
          ] %}
          {% for ep, icon, label in nav_links %}
            <a href="{{ url_for(ep) }}" class="nav-link {% if request.endpoint == ep %}nav-link-active{% endif %}" aria-current="{% if request.endpoint == ep %}page{% else %}false{% endif %}">
              <span class="material-symbols-rounded" aria-hidden="true">{{ icon }}</span>
              <span>{{ label }}</span>
            </a>
          {% endfor %}
          {% if session.role == 'manager' %}
            <a href="{{ url_for('admin_users') }}" class="nav-link {% if request.endpoint == 'admin_users' %}nav-link-active{% endif %}">
              <span class="material-symbols-rounded" aria-hidden="true">shield_person</span>
              <span>Admin</span>
            </a>
          {% endif %}
        </nav>
        <div class="flex items-center gap-2">
          <div class="hidden items-center gap-2 md:flex">
            <span class="chip">
              <span class="inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
              {{ session.user }}
              <span class="text-slate-500">- {{ session.role }}</span>
            </span>
            <a href="{{ url_for('logout') }}" class="btn-secondary">Log out</a>
          </div>
          <button type="button" class="btn-secondary md:hidden" hx-get="{{ url_for('queue') }}" hx-target="#page" hx-swap="innerHTML" aria-label="Open quick queue">Menu</button>
        </div>
        {% endif %}
      </div>
    </header>
    <main id="page" class="mx-auto w-full max-w-7xl flex-1 px-4 py-8">
      {% block content %}{% endblock %}
    </main>
    <footer class="border-t border-white/60 bg-white/70 py-4 text-center text-xs text-slate-500">
      <p>&copy; {{ datetime.utcnow().year }} Calling CRM. Crafted for delightful calling experiences.</p>
    </footer>
  </div>
  <script>
    document.addEventListener('DOMContentLoaded', function(){
      var indicator = document.getElementById('htmx-indicator');
      if(!indicator || !window.htmx){ return; }
      document.body.addEventListener('htmx:beforeRequest', function(){
        indicator.classList.remove('hidden');
      });
      document.body.addEventListener('htmx:afterRequest', function(){
        indicator.classList.add('hidden');
      });
      document.body.addEventListener('htmx:responseError', function(){
        indicator.classList.add('hidden');
      });
    });
  </script>
</body>
</html>
"""

LOGIN_HTML = """
{% extends "base.html" %}
{% block title %}Sign In - Calling CRM{% endblock %}
{% block content %}
<div class="mx-auto flex max-w-5xl flex-col items-center gap-6 text-center">
  <div class="space-y-2">
    <span class="chip text-xs">Calling CRM</span>
    <h2 class="text-3xl font-semibold text-slate-800">Welcome back</h2>
    <p class="text-sm text-slate-500">Log in to access your calling workspace, queues and live analytics.</p>
  </div>
  <div class="card w-full max-w-md p-8 text-left">
    <form method="post" class="space-y-4">
      <div>
        <label class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">Username</label>
        <input name="username" class="input mt-2" placeholder="your.username" autocomplete="username" required />
      </div>
      <div>
        <div class="flex items-center justify-between text-xs">
          <label class="font-semibold uppercase tracking-[0.2em] text-slate-500">Password</label>
        </div>
        <input name="password" type="password" class="input mt-2" placeholder="********" autocomplete="current-password" required />
      </div>
      <button class="btn w-full">Sign in</button>
      {% if error %}<p class="text-sm text-red-500">{{ error }}</p>{% endif %}
    </form>
  </div>
</div>
{% endblock %}
"""

HOME_HTML = """
{% extends "base.html" %}
{% block title %}Dashboard - Calling CRM{% endblock %}
{% block content %}
<div class="space-y-8">
  <section class="grid gap-4 lg:grid-cols-[2fr_1fr]">
    <div class="card p-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p class="text-sm text-slate-500">Welcome back, {{ session.user }}.</p>
          <h2 class="text-2xl font-semibold text-slate-800">Let's make great calls today.</h2>
          <p class="mt-1 text-sm text-slate-500">Track your calling impact and action the next best lead in a couple of clicks.</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <a class="btn" href="{{ url_for('assign_next') }}">Start calling</a>
          <a class="btn-secondary" href="{{ url_for('queue') }}">View queue</a>
        </div>
      </div>
      <div class="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div class="stat-card stat-card--sky">
          <div class="stat-card__icon"><span class="material-symbols-rounded" aria-hidden="true">phone_in_talk</span></div>
          <p class="stat-card__label">Calls today</p>
          <p class="stat-card__value">{{ stats.today_attempts }}</p>
          <p class="text-xs opacity-80">{{ stats.today_connected }} connected</p>
        </div>
        <div class="stat-card stat-card--sunrise">
          <div class="stat-card__icon"><span class="material-symbols-rounded" aria-hidden="true">event_available</span></div>
          <p class="stat-card__label">Due callbacks</p>
          <p class="stat-card__value">{{ stats.due_callbacks }}</p>
          <p class="text-xs opacity-85">Ready to action now</p>
        </div>
        <div class="stat-card stat-card--lime">
          <div class="stat-card__icon"><span class="material-symbols-rounded" aria-hidden="true">schedule</span></div>
          <p class="stat-card__label">Upcoming 24h</p>
          <p class="stat-card__value">{{ stats.upcoming_callbacks }}</p>
          <p class="text-xs opacity-85">Keep your pipeline warm</p>
        </div>
        <div class="stat-card stat-card--violet">
          <div class="stat-card__icon"><span class="material-symbols-rounded" aria-hidden="true">assignment</span></div>
          <p class="stat-card__label">Open assignments</p>
          <p class="stat-card__value">{{ stats.open_assignments }}</p>
          <p class="text-xs opacity-85">Awaiting follow-up</p>
        </div>
      </div>
      <div class="mt-6 flex flex-wrap items-center gap-3 text-sm text-slate-500">
        <span class="badge">Last attempt - {{ stats.last_attempt or '-' }}</span>
        <span class="badge">Streak - {{ stats.streak_days }} day{{ 's' if stats.streak_days != 1 else '' }}</span>
      </div>
    </div>
    <div class="card flex flex-col justify-between gap-5 p-6">
      <div>
        <h3 class="text-lg font-semibold text-slate-800">Quick actions</h3>
        <p class="mt-1 text-sm text-slate-500">Jump to your most common workflows.</p>
      </div>
      <div class="flex flex-col gap-3 text-sm">
        <a class="quick-link" href="{{ url_for('assign_next') }}">
          <span class="quick-link__icon material-symbols-rounded" aria-hidden="true">my_location</span>
          <span>
            <span class="block text-sm font-semibold">Assign next lead</span>
            <span class="block text-xs text-slate-500">Auto-pull the best number to call now.</span>
          </span>
        </a>
        <a class="quick-link" href="{{ url_for('queue') }}">
          <span class="quick-link__icon material-symbols-rounded" aria-hidden="true">checklist</span>
          <span>
            <span class="block text-sm font-semibold">Open my queue</span>
            <span class="block text-xs text-slate-500">Review due callbacks and assignments.</span>
          </span>
        </a>
        <a class="quick-link" href="{{ url_for('logs') }}">
          <span class="quick-link__icon material-symbols-rounded" aria-hidden="true">history_edu</span>
          <span>
            <span class="block text-sm font-semibold">Recent logs</span>
            <span class="block text-xs text-slate-500">See the latest attempts you recorded.</span>
          </span>
        </a>
        <a class="quick-link" href="{{ url_for('overview') }}">
          <span class="quick-link__icon material-symbols-rounded" aria-hidden="true">insights</span>
          <span>
            <span class="block text-sm font-semibold">Team overview</span>
            <span class="block text-xs text-slate-500">Track performance trends across the floor.</span>
          </span>
        </a>
        {% if session.role in ('lead','manager') %}
        <a class="quick-link" href="{{ url_for('export_csv') }}">
          <span class="quick-link__icon material-symbols-rounded" aria-hidden="true">download</span>
          <span>
            <span class="block text-sm font-semibold">Export CSV</span>
            <span class="block text-xs text-slate-500">Pull detailed call data for offline analysis.</span>
          </span>
        </a>
        {% endif %}
        {% if session.role == 'manager' %}
        <a class="quick-link" href="{{ url_for('admin_users') }}">
          <span class="quick-link__icon material-symbols-rounded" aria-hidden="true">admin_panel_settings</span>
          <span>
            <span class="block text-sm font-semibold">Manage users</span>
            <span class="block text-xs text-slate-500">Invite teammates, reset passwords, toggle access.</span>
          </span>
        </a>
        {% endif %}
      </div>
      <p class="text-xs text-slate-400">Tip: press Shift + / to search within the page.</p>
    </div>
  </section>

  <section class="grid gap-6 lg:grid-cols-[2fr_1fr]">
    <div class="card p-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h3 class="text-lg font-semibold text-slate-800">Search a lead</h3>
          <p class="text-sm text-slate-500">Find complete history for any mobile number.</p>
        </div>
        <div class="text-xs text-slate-400">Powered by live ClickHouse data</div>
      </div>
      <form hx-get="{{ url_for('lookup') }}" hx-target="#result" hx-indicator="#htmx-indicator" class="mt-5 flex flex-col gap-3 md:flex-row">
        <input name="mobile" placeholder="Enter mobile number (e.g. 91XXXXXXXXXX)" class="input md:flex-1" required>
        <button class="btn md:w-auto">Search</button>
      </form>
      <div id="result" class="mt-6"></div>
    </div>
    <div class="card p-6">
      <h3 class="text-lg font-semibold text-slate-800">Upcoming callbacks</h3>
      <p class="mt-1 text-sm text-slate-500">Here is what is coming up shortly.</p>
      <div class="mt-4">
        {% for cb in upcoming %}
          <div class="list-tile">
            <div class="list-tile__icon">
              <span class="material-symbols-rounded" aria-hidden="true">alarm</span>
            </div>
            <div class="flex-1">
              <p class="font-medium text-slate-800">{{ cb['mobile'] }}</p>
              <p class="text-xs text-slate-500">Scheduled {{ cb['schedule_at'] }}</p>
              <a class="mt-2 inline-flex items-center text-xs font-semibold text-sky-600" href="{{ url_for('lookup') }}?mobile={{ cb['mobile'] }}">Open details</a>
            </div>
          </div>
        {% else %}
          <p class="py-8 text-center text-sm text-slate-500">No callbacks scheduled. Add a follow-up from any attempt.</p>
        {% endfor %}
      </div>
    </div>
  </section>

  <section class="grid gap-6 xl:grid-cols-2">
    <div class="card p-6">
      <div class="flex items-center justify-between">
        <h3 class="text-lg font-semibold text-slate-800">Recent activity</h3>
        <a class="text-xs font-semibold uppercase tracking-[0.2em] text-sky-600" href="{{ url_for('logs') }}">View all</a>
      </div>
      <table class="mt-4 w-full tbl text-sm">
        <thead><tr><th>When</th><th>Mobile</th><th>Outcome</th><th>Notes</th></tr></thead>
        <tbody>
        {% for attempt in recent_attempts %}
          <tr>
            <td class="whitespace-nowrap text-slate-500">{{ attempt['created_at'] }}</td>
            <td class="font-medium text-slate-800">{{ attempt['mobile'] }}</td>
            <td>{{ attempt['disposition'] }}</td>
            <td class="max-w-xs truncate text-slate-500">{{ attempt['comment'] or '-' }}</td>
          </tr>
        {% else %}
          <tr><td colspan="4" class="py-6 text-center text-slate-500">Your next attempt will show here. Let's get calling!</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    <div class="card p-6">
      <h3 class="text-lg font-semibold text-slate-800">Focus tips</h3>
      <ul class="mt-4 tip-list text-sm text-slate-600">
        <li><span class="material-symbols-rounded" aria-hidden="true">rocket_launch</span><span>Block 30 minute calling sprints to power through your queue.</span></li>
        <li><span class="material-symbols-rounded" aria-hidden="true">edit_note</span><span>Capture objections and commitments in the comment field for easy reference.</span></li>
        <li><span class="material-symbols-rounded" aria-hidden="true">event_upcoming</span><span>Schedule callbacks with context so you never lose momentum.</span></li>
        <li><span class="material-symbols-rounded" aria-hidden="true">lightbulb</span><span>Scan recent activity before dialing to personalise your opener.</span></li>
      </ul>
    </div>
  </section>
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
      <a class="btn" href="{{ url_for('assign_next') }}">Assign next</a>
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

# Register templates once via DictLoader (fixes recursion)
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
    user = session.get('user')
    client = ch()

    stats = {
        'today_attempts': 0,
        'today_connected': 0,
        'due_callbacks': 0,
        'upcoming_callbacks': 0,
        'open_assignments': 0,
        'last_attempt': None,
        'streak_days': 0,
    }
    upcoming = []
    recent_attempts = []

    try:
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        summary = client.query(f"""
            SELECT
                count() AS attempts,
                countIf(disposition LIKE 'Connected%') AS connected,
                max(created_at) AS last_attempt
            FROM {ATTEMPTS_TABLE}
            WHERE agent = %(agent)s AND created_at >= %(start)s
        """, parameters={'agent': user, 'start': today_start}).named_results()
        if summary:
            row = summary[0]
            stats['today_attempts'] = int(row.get('attempts') or 0)
            stats['today_connected'] = int(row.get('connected') or 0)
            last_attempt = row.get('last_attempt')
            if isinstance(last_attempt, datetime):
                stats['last_attempt'] = last_attempt.strftime('%d %b %Y %H:%M')
            else:
                stats['last_attempt'] = last_attempt

        due_callbacks = client.query(f"""
            SELECT count()
            FROM {CALLBACKS_TABLE}
            WHERE status = 'open' AND assigned_to = %(agent)s AND schedule_at <= now()
        """, parameters={'agent': user}).first_item
        stats['due_callbacks'] = int(due_callbacks or 0)

        upcoming_count = client.query(f"""
            SELECT count()
            FROM {CALLBACKS_TABLE}
            WHERE status = 'open' AND assigned_to = %(agent)s
              AND schedule_at > now() AND schedule_at <= now() + INTERVAL 1 DAY
        """, parameters={'agent': user}).first_item
        stats['upcoming_callbacks'] = int(upcoming_count or 0)

        open_assignments = client.query(f"""
            SELECT count()
            FROM {ASSIGN_TABLE}
            WHERE agent = %(agent)s AND status = 'open'
        """, parameters={'agent': user}).first_item
        stats['open_assignments'] = int(open_assignments or 0)

        upcoming_rows = client.query(f"""
            SELECT mobile, schedule_at
            FROM {CALLBACKS_TABLE}
            WHERE status = 'open' AND assigned_to = %(agent)s
              AND schedule_at > now()
            ORDER BY schedule_at ASC
            LIMIT 5
        """, parameters={'agent': user}).named_results()
        upcoming = []
        for row in upcoming_rows:
            item = dict(row)
            sched = item.get('schedule_at')
            if isinstance(sched, datetime):
                item['schedule_at'] = sched.strftime('%d %b %Y %H:%M')
            upcoming.append(item)

        attempt_rows = client.query(f"""
            SELECT created_at, mobile, disposition, comment
            FROM {ATTEMPTS_TABLE}
            WHERE agent = %(agent)s
            ORDER BY created_at DESC
            LIMIT 7
        """, parameters={'agent': user}).named_results()
        recent_attempts = []
        for row in attempt_rows:
            item = dict(row)
            created = item.get('created_at')
            if isinstance(created, datetime):
                item['created_at'] = created.strftime('%d %b %Y %H:%M')
            recent_attempts.append(item)

        streak_rows = client.query(f"""
            SELECT toDate(created_at) AS d
            FROM {ATTEMPTS_TABLE}
            WHERE agent = %(agent)s AND created_at >= now() - INTERVAL 21 DAY
            GROUP BY d
            ORDER BY d DESC
        """, parameters={'agent': user}).named_results()
        days_with_attempts = {row['d'] for row in streak_rows}
        streak = 0
        cursor_day = datetime.now().date()
        while cursor_day in days_with_attempts:
            streak += 1
            cursor_day = cursor_day - timedelta(days=1)
        stats['streak_days'] = streak
    except Exception:
        pass

    return render_template('home.html', stats=stats, upcoming=upcoming, recent_attempts=recent_attempts)

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
        rows = list(client.query(q, parameters={'mobile': mobile}).named_results())
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
    rows = list(ch().query(f"""
        SELECT mobile
        FROM {CALLBACKS_TABLE}
        WHERE status = 'open' AND assigned_to = %(a)s AND schedule_at <= now()
        ORDER BY schedule_at ASC
        LIMIT 1
    """, parameters={'a': agent}).named_results())
    if rows:
        return _assign_and_redirect(rows[0]['mobile'])

    # 2) Unassigned due callbacks ? take ownership
    rows = list(ch().query(f"""
        SELECT mobile
        FROM {CALLBACKS_TABLE}
        WHERE status = 'open' AND (assigned_to = '' OR assigned_to = ' ')
          AND schedule_at <= now()
        ORDER BY schedule_at ASC
        LIMIT 1
    """).named_results())
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
    rows = list(ch().query(f"""
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
    """).named_results())

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
