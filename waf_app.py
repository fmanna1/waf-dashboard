from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, make_response
import re
import os
import sqlite3
from datetime import datetime
import secrets
import json
import joblib
import math
import requests

import dash
from dash import html, dcc, dash_table
import pandas as pd
import plotly.express as px

from sklearn.tree import DecisionTreeClassifier

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --- SQLite Setup ---
DB_FILE = "waf_logs.db"
MODEL_FILE = "ml_model.joblib"
clf = joblib.load(MODEL_FILE)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                attack_type TEXT,
                ip TEXT,
                payload TEXT
            )
        """)

init_db()

def log_attack(level, attack_type, ip, payload):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT INTO logs (timestamp, level, attack_type, ip, payload)
            VALUES (?, ?, ?, ?, ?)""", (datetime.utcnow().isoformat(), level, attack_type, ip, payload))

def extract_features(payload):
    payload = str(payload)
    entropy = -sum((payload.count(c)/len(payload)) * math.log(payload.count(c)/len(payload), 2) for c in set(payload) if c)
    return [len(payload), entropy, len(re.findall(r"\w+", payload))]

CSRF_TOKENS_REQUIRED = True

@app.before_request
def waf_filter():
    if request.path.startswith('/dashboard') or request.path.startswith('/static') or request.path == '/tester':
        return
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    full_data = str(request.args.to_dict()) + str(request.form.to_dict())

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, full_data):
            log_attack("WARNING", "SQL Injection", ip, full_data)
            return jsonify({"error": "Blocked: SQL Injection detected"}), 403

    for pattern in XSS_PATTERNS:
        if re.search(pattern, full_data):
            log_attack("WARNING", "XSS", ip, full_data)
            return jsonify({"error": "Blocked: XSS attempt detected"}), 403

    features = extract_features(full_data)
    if clf.predict([features])[0] == 1:
        log_attack("WARNING", "Anomaly", ip, full_data)
        return jsonify({"error": "Blocked: Anomalous behavior detected"}), 403

    if CSRF_TOKENS_REQUIRED and request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not token or token != session.get("csrf_token"):
            log_attack("WARNING", "CSRF", ip, full_data)
            return jsonify({"error": "Blocked: CSRF token missing or invalid"}), 403

@app.route('/')
def index():
    return "Welcome to the WAF-protected app with SQLite logging."

@app.route('/waf/search')
def waf_search():
    return jsonify({"message": "Search executed (if not blocked)."})

@app.route('/waf/login', methods=['POST'])
def waf_login():
    return jsonify({"message": "Login successful (if not blocked)."})

@app.route('/tester')
def tester():
    csrf_token = secrets.token_urlsafe()
    session['csrf_token'] = csrf_token
    response = make_response(render_template_string("""
        <h2>🧪 WAF Attack Tester</h2>
        <form method="get" action="/waf/search">
            <b>SQLi/XSS via GET</b><br>
            <input type="text" name="q" placeholder="Payload here" size="60"/>
            <input type="submit" value="Test GET" />
        </form>
        <br><hr><br>
        <form method="post" action="/waf/login">
            <b>CSRF via POST</b><br>
            Username: <input type="text" name="username" />
            Password: <input type="password" name="password" />
            CSRF Token: <input type="text" name="csrf_token" value="{{ csrf_token }}" />
            <input type="submit" value="Test POST" />
        </form>
    """, csrf_token=csrf_token))
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True)
    return response

@app.route('/export/csv')
def export_csv():
    df = query_logs()
    return df.to_csv(index=False), 200, {'Content-Type': 'text/csv'}

@app.route('/export/json')
def export_json():
    df = query_logs()
    return df.to_json(orient="records"), 200, {'Content-Type': 'application/json'}

# --- Attack Patterns (Modular Rule Loading) ---
with open("rules.json") as f:
    rules = json.load(f)
SQLI_PATTERNS = rules.get("sqli", [])
XSS_PATTERNS = rules.get("xss", [])

# --- Dash Setup ---
dash_app = dash.Dash(__name__, server=app, routes_pathname_prefix='/dashboard/')
dash_app.title = "WAF Dashboard"

def query_logs():
    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query("SELECT timestamp, level, attack_type, ip, payload FROM logs", conn)
    return df

def get_geo(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        return resp.json().get("country", "Unknown")
    except:
        return "Unknown"

def threat_score(row):
    weights = {"SQL Injection": 3, "XSS": 2, "CSRF": 2, "Anomaly": 4}
    return weights.get(row["attack_type"], 1)

def generate_recommendations(df):
    if df.empty:
        return "✅ All clear. No suspicious activity logged."
    recs = []
    ip_counts = df['ip'].value_counts()
    if any(ip_counts > 5):
        recs.append("⚠️ Consider rate-limiting high-frequency IPs.")
    if len(df[df.attack_type == "CSRF"]) > 3:
        recs.append("🛡️ Rotate CSRF tokens more frequently.")
    return "\n".join(recs)

dash_app.layout = html.Div([
    html.H1("🛡️ WAF Dashboard", style={"textAlign": "center"}),
    dcc.Interval(id='interval', interval=5000, n_intervals=0),
    dcc.Dropdown(id='attack-type-dropdown', options=[
        {"label": x, "value": x} for x in ["SQL Injection", "XSS", "CSRF", "Anomaly"]
    ], multi=True, placeholder="Filter attack types..."),
    dcc.Graph(id='attack-count-chart'),
    dash_table.DataTable(id='log-table', columns=[
        {"name": i, "id": i} for i in ["timestamp", "attack_type", "ip", "payload"]
    ], page_size=10, style_cell={'textAlign': 'left'}),
    html.Pre(id='recommendation-panel')
])

@dash_app.callback(
    [dash.dependencies.Output("log-table", "data"),
     dash.dependencies.Output("attack-count-chart", "figure"),
     dash.dependencies.Output("recommendation-panel", "children")],
    [dash.dependencies.Input("attack-type-dropdown", "value"),
     dash.dependencies.Input("interval", "n_intervals")]
)
def update_dashboard(filter_types, _):
    df = query_logs()
    if filter_types:
        df = df[df["attack_type"].isin(filter_types)]
    if df.empty:
        return [], {"layout": {"title": "No logs"}}, "✅ No activity"
    df["geo"] = df["ip"].apply(get_geo)
    df["score"] = df.apply(threat_score, axis=1)
    fig = px.histogram(df, x="timestamp", color="attack_type", title="Attack Trend Over Time")
    return df.to_dict("records"), fig, generate_recommendations(df)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    app.run(host="0.0.0.0", port=port)
