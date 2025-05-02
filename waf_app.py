from flask import Flask, request, jsonify, render_template_string
import re
import logging
from datetime import datetime
import os

app = Flask(__name__)

# --- Logging Setup ---
logging.basicConfig(
    filename="waf_logs.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Blocked %(message)s"
)

# --- Attack Patterns ---
SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b).*(=|\bLIKE\b|\bIN\b|\bIS\b|\bNULL\b)",
    r"(?i)(union(\s+all)?(\s+select))",
    r"(?i)select.+from",
    r"(?i)insert\s+into",
    r"(?i)drop\s+table",
    r"(?i)'\s*or\s*'1'='1"
]

XSS_PATTERNS = [
    r"(?i)<script.*?>.*?</script.*?>",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)<img\s+.*?on\w+=.*?>"
]

CSRF_TOKENS_REQUIRED = True

# --- WAF Middleware ---
@app.before_request
def waf_filter():
    if request.path == '/tester':
        return  # Skip WAF for test form display

    ip = request.remote_addr or "unknown"
    full_data = str(request.args.to_dict()) + str(request.form.to_dict())

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, full_data):
            logging.warning(f"SQL Injection attack from {ip}. Payload: {full_data}")
            return jsonify({"error": "Blocked: SQL Injection detected"}), 403

    for pattern in XSS_PATTERNS:
        if re.search(pattern, full_data):
            logging.warning(f"XSS attack from {ip}. Payload: {full_data}")
            return jsonify({"error": "Blocked: XSS attempt detected"}), 403

    if CSRF_TOKENS_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            logging.warning(f"CSRF attack from {ip}. Payload: {full_data}")
            return jsonify({"error": "Blocked: CSRF token missing or invalid"}), 403

# --- Routes ---
@app.route('/')
def index():
    return "Welcome to the WAF-protected web app!"

@app.route('/waf/search')
def waf_search():
    return jsonify({"message": "Search executed (if not blocked)."})

@app.route('/waf/login', methods=['POST'])
def waf_login():
    return jsonify({"message": "Login successful (if not blocked)."})

@app.route('/tester', methods=['GET', 'POST'])
def tester():
    result = ""
    if request.method == "GET" and "q" in request.args:
        from urllib.parse import urlencode
        import requests
        try:
            q = request.args.get("q", "")
            r = requests.get(f"http://127.0.0.1:5000/waf/search", params={"q": q})
            result = f"GET /waf/search → {r.status_code} | {r.text}"
        except Exception as e:
            result = str(e)
    elif request.method == "POST":
        try:
            uname = request.form.get("username", "")
            pwd = request.form.get("password", "")
            headers = {"X-CSRF-Token": request.form.get("csrf_token", "")}
            data = {"username": uname, "password": pwd}
            import requests
            r = requests.post("http://127.0.0.1:5000/waf/login", data=data, headers=headers)
            result = f"POST /waf/login → {r.status_code} | {r.text}"
        except Exception as e:
            result = str(e)

    return render_template_string("""
        <h2>🧪 WAF Attack Tester</h2>
        <form method="get">
            <b>SQLi/XSS via GET</b><br>
            <input type="text" name="q" placeholder="Payload here" size="60"/>
            <input type="submit" value="Test GET" />
        </form>
        <br><hr><br>
        <form method="post">
            <b>CSRF via POST</b><br>
            Username: <input type="text" name="username" />
            Password: <input type="password" name="password" />
            CSRF Token: <input type="text" name="csrf_token" value="securetoken123" />
            <input type="submit" value="Test POST" />
        </form>
        <br><br>
        <textarea rows="10" cols="100">{{result}}</textarea>
    """, result=result)

# --- Run ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
