import pandas as pd
import dash
from dash import html, dcc, dash_table
import plotly.express as px
import re
import os

LOG_FILE = "waf_logs.log"

# --- Parse WAF Log File ---
def parse_logs():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=["timestamp", "level", "attack_type", "ip", "payload"])

    data = []
    with open(LOG_FILE, 'r') as file:
        for line in file:
            match = re.search(r'^(.*?) - (\w+) - Blocked (.*?) attack from (.*?)\. Payload: (.*)$', line.strip())
            if match:
                timestamp, level, attack_type, ip, payload = match.groups()
                data.append({
                    "timestamp": timestamp,
                    "level": level,
                    "attack_type": attack_type,
                    "ip": ip,
                    "payload": payload
                })
    return pd.DataFrame(data)

# --- Generate Recommendations ---
def generate_recommendations(df):
    if df.empty:
        return "✅ All clear. No suspicious activity logged."

    recs = []
    ip_counts = df['ip'].value_counts()
    csrf_count = len(df[df["attack_type"] == "CSRF"])
    sqli_count = len(df[df["attack_type"] == "SQL Injection"])

    if any(ip_counts > 5):
        recs.append("⚠️ Consider rate-limiting requests from high-frequency IPs.")
    if csrf_count > 3:
        recs.append("🛡️ Consider enforcing or rotating CSRF tokens more frequently.")
    if sqli_count > 5:
        recs.append("🔒 SQLi patterns detected frequently. Consider IP blocking or stricter input validation.")

    return "\n".join(recs) if recs else "✅ System is stable. No urgent recommendations."

# --- Dash App Initialization ---
app = dash.Dash(__name__)
app.title = "WAF Real-Time Monitor"

# --- App Layout ---
app.layout = html.Div([
    html.H1("🛡️ WAF Attack Monitoring Dashboard", style={"textAlign": "center"}),

    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),  # Auto-refresh every 5s

    html.Div([
        html.Label("Filter by attack type:"),
        dcc.Dropdown(id='attack-type-dropdown', options=[
            {'label': 'SQL Injection', 'value': 'SQL Injection'},
            {'label': 'XSS', 'value': 'XSS'},
            {'label': 'CSRF', 'value': 'CSRF'}
        ], multi=True)
    ], style={'width': '40%', 'margin': '20px auto'}),

    dcc.Graph(id='attack-count-chart'),

    html.H3("📜 Suspicious Request Logs", style={'marginTop': 30}),
    dash_table.DataTable(id='log-table',
                         columns=[
                             {"name": "Timestamp", "id": "timestamp"},
                             {"name": "Attack Type", "id": "attack_type"},
                             {"name": "IP", "id": "ip"},
                             {"name": "Payload", "id": "payload"},
                         ],
                         style_table={'overflowX': 'auto'},
                         style_cell={'textAlign': 'left'},
                         page_size=10
    ),

    html.Div(id='recommendation-panel', style={
        "backgroundColor": "#f9f9f9",
        "padding": "20px",
        "marginTop": "40px",
        "border": "2px dashed #ccc"
    }),
])

# --- Callback with Error Handling ---
@app.callback(
    [dash.dependencies.Output('log-table', 'data'),
     dash.dependencies.Output('attack-count-chart', 'figure'),
     dash.dependencies.Output('recommendation-panel', 'children')],
    [dash.dependencies.Input('attack-type-dropdown', 'value'),
     dash.dependencies.Input('interval-component', 'n_intervals')]
)
def update_dashboard(filter_types, _):
    try:
        df = parse_logs()

        if filter_types:
            df = df[df["attack_type"].isin(filter_types)]

        # If DataFrame is empty
        if df.empty:
            fig = {
                "layout": {
                    "title": "No Attack Logs Yet",
                    "xaxis": {"visible": False},
                    "yaxis": {"visible": False},
                    "annotations": [{
                        "text": "No data available",
                        "xref": "paper", "yref": "paper",
                        "showarrow": False,
                        "font": {"size": 20}
                    }]
                }
            }
            return [], fig, "✅ No suspicious activity yet."

        fig = px.histogram(df, x="attack_type", color="attack_type", title="Attack Type Frequency")
        recommendations = generate_recommendations(df)

        return df.to_dict("records"), fig, html.Pre(recommendations)

    except Exception as e:
        print("❌ Error in dashboard callback:", str(e))
        return [], {}, f"⚠️ Dashboard Error: {str(e)}"

# --- Run Server ---
if __name__ == '__main__':
    app.run(debug=True, port=8050)
