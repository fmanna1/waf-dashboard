import pandas as pd
import re
import os
from dash import Dash, html, dcc, dash_table
import plotly.express as px

app = Dash(__name__)
app.title = "WAF Monitoring Dashboard"

# --- Function to Parse WAF Logs ---
def parse_logs():
    log_path = "waf_logs.log"
    logs = []

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            for line in f:
                match = re.search(r'^(.*?) - (\w+) - Blocked (.*?) attack.*?from (.*?)\. Payload: (.*)$', line.strip())
                if match:
                    timestamp, level, attack_type, ip, payload = match.groups()
                    logs.append({
                        "Timestamp": timestamp,
                        "Level": level,
                        "Attack Type": attack_type,
                        "IP Address": ip,
                        "Payload": payload
                    })

    return pd.DataFrame(logs)

# --- Prepare DataFrame ---
df = parse_logs()

# ✅ SAFEGUARD: Prevent crash if log is empty
if df.empty:
    df = pd.DataFrame(columns=["Timestamp", "Level", "Attack Type", "IP Address", "Payload"])

# --- Dash App Layout ---
app.layout = html.Div([
    html.H1("🛡️ WAF Dashboard", style={"textAlign": "center"}),

    dcc.Graph(
        id='attack-chart',
        figure=px.histogram(
            df,
            x='Attack Type',
            color='Attack Type',
            title='Attack Frequency by Type'
        )
    ),

    dash_table.DataTable(
        id='log-table',
        columns=[{"name": i, "id": i} for i in df.columns],
        data=df.to_dict('records'),
        page_size=10,
        style_table={"overflowX": "auto"},
        style_cell={"textAlign": "left"},
    )
])

# --- Run App (Render-Compatible) ---
if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 8050))
    app.run_server(debug=True, host="0.0.0.0", port=port)
