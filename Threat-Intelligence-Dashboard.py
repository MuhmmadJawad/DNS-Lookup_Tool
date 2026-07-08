import dash
from dash import dcc, html, dash_table, Input, Output, callback
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import random

# ── Sample data ────────────────────────────────────────────────────────────────

THREATS = [
    {"id": 1, "name": "LockBit 3.0 Ransomware",     "type": "Malware",   "severity": "Critical", "source": "TA505",            "target": "Finance",    "time": "2m ago",  "status": "Active"},
    {"id": 2, "name": "Spear-phishing Campaign",     "type": "Phishing",  "severity": "Critical", "source": "APT28",            "target": "Gov't",      "time": "9m ago",  "status": "Active"},
    {"id": 3, "name": "CVE-2024-3400 Exploit",       "type": "Exploit",   "severity": "High",     "source": "Unknown",          "target": "Tech",       "time": "22m ago", "status": "Investigating"},
    {"id": 4, "name": "DarkGate Malware Loader",     "type": "Malware",   "severity": "Critical", "source": "TA577",            "target": "Healthcare", "time": "35m ago", "status": "Active"},
    {"id": 5, "name": "Business Email Compromise",   "type": "Phishing",  "severity": "High",     "source": "Scattered Spider", "target": "Finance",    "time": "1h ago",  "status": "Mitigated"},
    {"id": 6, "name": "Port Scanning Activity",      "type": "Recon",     "severity": "Low",      "source": "185.220.x.x",      "target": "Energy",     "time": "1h ago",  "status": "Monitoring"},
    {"id": 7, "name": "Credential Stuffing Attack",  "type": "Exploit",   "severity": "High",     "source": "Botnet-7",         "target": "Finance",    "time": "2h ago",  "status": "Blocked"},
    {"id": 8, "name": "Emotet Banking Trojan",       "type": "Malware",   "severity": "Critical", "source": "Mealybug",         "target": "Finance",    "time": "2h ago",  "status": "Active"},
    {"id": 9, "name": "SQL Injection Campaign",      "type": "Exploit",   "severity": "Medium",   "source": "Unknown",          "target": "Tech",       "time": "3h ago",  "status": "Blocked"},
    {"id": 10,"name": "DNS Tunneling Detected",      "type": "C2",        "severity": "High",     "source": "APT41",            "target": "Gov't",      "time": "3h ago",  "status": "Investigating"},
]

IOCS = [
    {"indicator": "185.220.101.47",          "type": "IP",     "confidence": 95, "first_seen": "2025-06-14", "tags": "C2, Tor"},
    {"indicator": "malware-cdn.ru",           "type": "Domain", "confidence": 92, "first_seen": "2025-06-13", "tags": "Malware"},
    {"indicator": "a3f1e2d4b7c8f09e1a2b",   "type": "Hash",   "confidence": 99, "first_seen": "2025-06-14", "tags": "LockBit"},
    {"indicator": "204.144.204.14",           "type": "IP",     "confidence": 88, "first_seen": "2025-06-12", "tags": "Phishing"},
    {"indicator": "phish-kit.xyz/login",      "type": "URL",    "confidence": 97, "first_seen": "2025-06-14", "tags": "Phishing"},
    {"indicator": "evil-loader.com",          "type": "Domain", "confidence": 91, "first_seen": "2025-06-11", "tags": "Dropper"},
    {"indicator": "3d5f9a2c1b4e8d6f7a9c",   "type": "Hash",   "confidence": 98, "first_seen": "2025-06-14", "tags": "DarkGate"},
    {"indicator": "103.224.182.245",          "type": "IP",     "confidence": 85, "first_seen": "2025-06-10", "tags": "APT41"},
]

ATTACK_ORIGINS = [
    {"country": "China",     "lat": 35.86, "lon": 104.19, "attacks": 89, "color": "#E24B4A"},
    {"country": "Russia",    "lat": 61.52, "lon":  105.3, "attacks": 61, "color": "#E24B4A"},
    {"country": "Iran",      "lat": 32.42, "lon":  53.68, "attacks": 34, "color": "#BA7517"},
    {"country": "N. Korea",  "lat": 40.33, "lon": 127.51, "attacks": 22, "color": "#BA7517"},
    {"country": "USA",       "lat": 37.09, "lon": -95.71, "attacks":  9, "color": "#185FA5"},
    {"country": "Brazil",    "lat": -14.2, "lon": -51.92, "attacks":  6, "color": "#185FA5"},
    {"country": "Germany",   "lat": 51.16, "lon":  10.45, "attacks":  5, "color": "#185FA5"},
]

HOURS = list(range(24))
THREAT_VOLUME = [34,28,62,89,71,45,38,52,67,74,81,79,88,92,95,84,76,69,61,57,48,43,39,36]

SECTORS = {"Finance": 78, "Healthcare": 62, "Government": 55, "Energy": 41, "Technology": 33, "Retail": 21}

MITRE_TACTICS = {
    "Initial Access":     12,
    "Execution":           8,
    "Persistence":        15,
    "Privilege Esc.":      6,
    "Defense Evasion":    11,
    "Credential Access":   9,
    "Discovery":          14,
    "Lateral Movement":    7,
    "Collection":          5,
    "Exfiltration":        9,
    "Command & Control":   3,
    "Impact":              4,
}

# ── Colour helpers ──────────────────────────────────────────────────────────────

SEV_COLOR = {
    "Critical":     "#E24B4A",
    "High":         "#BA7517",
    "Medium":       "#378ADD",
    "Low":          "#639922",
}

SEV_BG = {
    "Critical":     "#FCEBEB",
    "High":         "#FAEEDA",
    "Medium":       "#E6F1FB",
    "Low":          "#EAF3DE",
}

STATUS_COLOR = {
    "Active":         "#E24B4A",
    "Investigating":  "#BA7517",
    "Monitoring":     "#378ADD",
    "Blocked":        "#639922",
    "Mitigated":      "#639922",
}

# ── Chart builders ──────────────────────────────────────────────────────────────

def build_volume_chart():
    bar_colors = ["#E24B4A" if v > 80 else "#BA7517" if v > 60 else "#378ADD" for v in THREAT_VOLUME]
    fig = go.Figure(go.Bar(
        x=[f"{h:02d}:00" for h in HOURS],
        y=THREAT_VOLUME,
        marker_color=bar_colors,
        hovertemplate="%{x} — %{y} threats<extra></extra>",
    ))
    fig.update_layout(
        margin=dict(l=0, r=0, t=8, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="sans-serif", size=11, color="#888780"),
        xaxis=dict(showgrid=False, tickangle=-45, tickfont=dict(size=10)),
        yaxis=dict(showgrid=True, gridcolor="rgba(136,135,128,0.15)", zeroline=False),
        height=220,
        showlegend=False,
    )
    return fig


def build_sector_chart():
    sectors = list(SECTORS.keys())
    values  = list(SECTORS.values())
    colors  = ["#E24B4A","#BA7517","#BA7517","#378ADD","#639922","#888780"]
    fig = go.Figure(go.Bar(
        x=values, y=sectors, orientation="h",
        marker_color=colors,
        text=[f"{v}%" for v in values],
        textposition="outside",
        hovertemplate="%{y}: %{x}%<extra></extra>",
    ))
    fig.update_layout(
        margin=dict(l=0, r=40, t=8, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="sans-serif", size=11, color="#888780"),
        xaxis=dict(range=[0, 110], showgrid=False, showticklabels=False),
        yaxis=dict(showgrid=False, tickfont=dict(size=11)),
        height=220,
        showlegend=False,
    )
    return fig


def build_mitre_chart():
    tactics = list(MITRE_TACTICS.keys())
    counts  = list(MITRE_TACTICS.values())
    max_c   = max(counts)
    colors  = [
        "#E24B4A" if c == max_c else "#BA7517" if c >= 10 else "#378ADD" if c >= 7 else "#639922"
        for c in counts
    ]
    fig = go.Figure(go.Bar(
        x=tactics, y=counts,
        marker_color=colors,
        hovertemplate="%{x}: %{y} techniques<extra></extra>",
    ))
    fig.update_layout(
        margin=dict(l=0, r=0, t=8, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="sans-serif", size=10, color="#888780"),
        xaxis=dict(showgrid=False, tickangle=-35, tickfont=dict(size=9)),
        yaxis=dict(showgrid=True, gridcolor="rgba(136,135,128,0.15)", zeroline=False),
        height=200,
        showlegend=False,
    )
    return fig


def build_map():
    df = pd.DataFrame(ATTACK_ORIGINS)
    fig = go.Figure(go.Scattergeo(
        lat=df["lat"], lon=df["lon"],
        text=df.apply(lambda r: f"{r['country']}: {r['attacks']} attacks", axis=1),
        mode="markers+text",
        textposition="top center",
        textfont=dict(size=10, color="#E24B4A"),
        marker=dict(
            size=df["attacks"] / 4,
            color=df["color"],
            opacity=0.85,
            line=dict(width=1, color="white"),
        ),
        hovertemplate="%{text}<extra></extra>",
    ))
    fig.update_geos(
        showframe=False,
        showcoastlines=True, coastlinecolor="#D3D1C7",
        showland=True,       landcolor="#F1EFE8",
        showocean=True,      oceancolor="#E6F1FB",
        showlakes=False,
        projection_type="natural earth",
    )
    fig.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        geo=dict(bgcolor="rgba(0,0,0,0)"),
        height=260,
        showlegend=False,
    )
    return fig


def build_severity_pie():
    counts = {}
    for t in THREATS:
        counts[t["severity"]] = counts.get(t["severity"], 0) + 1
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [SEV_COLOR.get(l, "#888780") for l in labels]
    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        marker=dict(colors=colors, line=dict(color="white", width=2)),
        hole=0.55,
        textinfo="label+percent",
        hovertemplate="%{label}: %{value} threats<extra></extra>",
    ))
    fig.update_layout(
        margin=dict(l=0, r=0, t=8, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="sans-serif", size=11, color="#444441"),
        height=220,
        showlegend=False,
    )
    return fig


# ── Layout helpers ──────────────────────────────────────────────────────────────

def metric_card(label, value, sub, sub_color="#639922"):
    return html.Div([
        html.P(label, style={"fontSize": "11px", "color": "#888780", "margin": "0 0 4px",
                              "textTransform": "uppercase", "letterSpacing": ".05em"}),
        html.P(value, style={"fontSize": "26px", "fontWeight": "500", "margin": "0", "color": "#2C2C2A"}),
        html.P(sub,   style={"fontSize": "12px", "color": sub_color, "margin": "4px 0 0"}),
    ], style={
        "background": "#F1EFE8", "borderRadius": "8px",
        "padding": "14px 16px", "flex": "1",
    })


def badge(text, color, bg):
    return html.Span(text, style={
        "fontSize": "10px", "fontWeight": "500",
        "padding": "2px 8px", "borderRadius": "20px",
        "background": bg, "color": color,
        "whiteSpace": "nowrap",
    })


def section_card(title, children, style=None):
    return html.Div([
        html.P(title, style={"fontSize": "11px", "fontWeight": "500", "color": "#888780",
                              "textTransform": "uppercase", "letterSpacing": ".05em",
                              "margin": "0 0 12px"}),
        *children,
    ], style={
        "background": "white", "border": "0.5px solid #D3D1C7",
        "borderRadius": "12px", "padding": "16px",
        **(style or {}),
    })


# ── App layout ──────────────────────────────────────────────────────────────────

app = dash.Dash(__name__, title="Threat Intelligence Dashboard")
app.config.suppress_callback_exceptions = True

FILTER_BTN_BASE = {
    "fontSize": "11px", "padding": "4px 12px", "borderRadius": "20px",
    "border": "0.5px solid #D3D1C7", "background": "transparent",
    "cursor": "pointer", "marginRight": "6px", "color": "#5F5E5A",
}
FILTER_BTN_ACTIVE = {**FILTER_BTN_BASE, "background": "#E6F1FB", "color": "#185FA5", "border": "0.5px solid #185FA5"}

app.layout = html.Div([
    dcc.Interval(id="clock-tick", interval=1000, n_intervals=0),

    # ── Top bar ────────────────────────────────────────────────────────────────
    html.Div([
        html.Div([
            html.Span("●", style={"color": "#E24B4A", "fontSize": "10px", "marginRight": "8px",
                                   "animation": "pulse 1.5s infinite"}),
            html.Span("Threat Intelligence Dashboard",
                      style={"fontWeight": "500", "fontSize": "15px", "marginRight": "10px"}),
            badge("DEFCON 3", "#A32D2D", "#FCEBEB"),
        ], style={"display": "flex", "alignItems": "center"}),
        html.Span(id="live-clock", style={"fontSize": "12px", "color": "#888780"}),
    ], style={
        "display": "flex", "justifyContent": "space-between", "alignItems": "center",
        "padding": "10px 16px", "background": "#F1EFE8",
        "border": "0.5px solid #D3D1C7", "borderRadius": "12px", "marginBottom": "16px",
    }),

    # ── Metric cards ───────────────────────────────────────────────────────────
    html.Div([
        metric_card("Active Threats",  "247",    "▲ 18 in last hour", "#A32D2D"),
        metric_card("Indicators (IOCs)", "14,832", "↑ 341 today",     "#5F5E5A"),
        metric_card("Blocked Attacks", "9,104",  "97.3% block rate",  "#3B6D11"),
        metric_card("CVEs Tracked",    "63",     "8 critical severity","#854F0B"),
    ], style={"display": "flex", "gap": "12px", "marginBottom": "16px"}),

    # ── Map ────────────────────────────────────────────────────────────────────
    section_card("Attack origin map", [
        dcc.Graph(figure=build_map(), config={"displayModeBar": False}),
    ], style={"marginBottom": "16px"}),

    # ── Middle row: threat feed + severity pie ─────────────────────────────────
    html.Div([
        section_card("Recent threat activity", [
            html.Div([
                html.Button("All",      id="f-all",      n_clicks=0, style=FILTER_BTN_ACTIVE),
                html.Button("Critical", id="f-critical", n_clicks=0, style=FILTER_BTN_BASE),
                html.Button("Malware",  id="f-malware",  n_clicks=0, style=FILTER_BTN_BASE),
                html.Button("Phishing", id="f-phishing", n_clicks=0, style=FILTER_BTN_BASE),
            ], style={"marginBottom": "10px"}),
            html.Div(id="threat-list"),
        ], style={"flex": "2"}),

        html.Div([
            section_card("Severity breakdown", [
                dcc.Graph(id="pie-chart", figure=build_severity_pie(), config={"displayModeBar": False}),
            ], style={"marginBottom": "12px"}),
            section_card("Targeted sectors", [
                dcc.Graph(figure=build_sector_chart(), config={"displayModeBar": False}),
            ]),
        ], style={"flex": "1", "display": "flex", "flexDirection": "column", "gap": "0"}),

    ], style={"display": "flex", "gap": "12px", "marginBottom": "16px"}),

    # ── Bottom row: IOC table + volume chart + MITRE ───────────────────────────
    html.Div([
        section_card("Top indicators of compromise (IOCs)", [
            dash_table.DataTable(
                data=IOCS,
                columns=[
                    {"name": "Indicator",   "id": "indicator"},
                    {"name": "Type",        "id": "type"},
                    {"name": "Confidence",  "id": "confidence"},
                    {"name": "First Seen",  "id": "first_seen"},
                    {"name": "Tags",        "id": "tags"},
                ],
                style_table={"overflowX": "auto"},
                style_header={"background": "#F1EFE8", "fontWeight": "500",
                               "fontSize": "11px", "color": "#5F5E5A",
                               "border": "none", "textTransform": "uppercase",
                               "letterSpacing": ".04em"},
                style_cell={"fontFamily": "monospace", "fontSize": "12px",
                             "padding": "7px 10px", "border": "none",
                             "borderBottom": "0.5px solid #D3D1C7",
                             "color": "#2C2C2A", "background": "white"},
                style_data_conditional=[
                    {"if": {"filter_query": '{type} = "IP"'},     "color": "#A32D2D"},
                    {"if": {"filter_query": '{type} = "Domain"'}, "color": "#854F0B"},
                    {"if": {"filter_query": '{type} = "Hash"'},   "color": "#185FA5"},
                    {"if": {"filter_query": '{type} = "URL"'},    "color": "#3B6D11"},
                    {"if": {"state": "active"},   "background": "#F1EFE8", "border": "none"},
                    {"if": {"state": "selected"}, "background": "#E6F1FB", "border": "none"},
                ],
                page_size=8,
            ),
        ], style={"flex": "1"}),

        html.Div([
            section_card("Threat volume — last 24h", [
                dcc.Graph(figure=build_volume_chart(), config={"displayModeBar": False}),
            ], style={"marginBottom": "12px"}),
            section_card("MITRE ATT&CK coverage", [
                dcc.Graph(figure=build_mitre_chart(), config={"displayModeBar": False}),
            ]),
        ], style={"flex": "1", "display": "flex", "flexDirection": "column", "gap": "0"}),

    ], style={"display": "flex", "gap": "12px"}),

    # ── CSS for pulse animation ────────────────────────────────────────────────
    html.Style("""
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
        body { background: #FAF9F7; font-family: -apple-system, sans-serif; margin: 0; padding: 0; }
    """),

], style={"maxWidth": "1300px", "margin": "0 auto", "padding": "20px"})


# ── Callbacks ───────────────────────────────────────────────────────────────────

@app.callback(Output("live-clock", "children"), Input("clock-tick", "n_intervals"))
def update_clock(_):
    return datetime.utcnow().strftime("UTC  %Y-%m-%d  %H:%M:%S")


@app.callback(
    Output("threat-list", "children"),
    [Input("f-all", "n_clicks"), Input("f-critical", "n_clicks"),
     Input("f-malware", "n_clicks"), Input("f-phishing", "n_clicks")],
)
def update_threat_list(n_all, n_crit, n_mal, n_phi):
    ctx = dash.callback_context
    triggered = ctx.triggered[0]["prop_id"].split(".")[0] if ctx.triggered else "f-all"

    if triggered == "f-critical":
        items = [t for t in THREATS if t["severity"] == "Critical"]
    elif triggered == "f-malware":
        items = [t for t in THREATS if t["type"] == "Malware"]
    elif triggered == "f-phishing":
        items = [t for t in THREATS if t["type"] == "Phishing"]
    else:
        items = THREATS

    rows = []
    for t in items:
        sev_c  = SEV_COLOR.get(t["severity"], "#888780")
        sev_bg = SEV_BG.get(t["severity"],   "#F1EFE8")
        sta_c  = STATUS_COLOR.get(t["status"], "#888780")
        rows.append(html.Div([
            html.Div(t["type"][0], style={
                "width": "30px", "height": "30px", "borderRadius": "8px",
                "background": sev_bg, "color": sev_c,
                "display": "flex", "alignItems": "center", "justifyContent": "center",
                "fontWeight": "500", "fontSize": "12px", "flexShrink": "0",
            }),
            html.Div([
                html.P(t["name"],   style={"margin": "0", "fontSize": "13px", "fontWeight": "500", "color": "#2C2C2A"}),
                html.P(f"{t['source']} · {t['target']}", style={"margin": "0", "fontSize": "11px", "color": "#888780"}),
            ], style={"flex": "1", "minWidth": "0"}),
            html.Div([
                html.Span(t["severity"], style={
                    "display": "block", "fontSize": "10px", "fontWeight": "500",
                    "color": sev_c, "background": sev_bg,
                    "padding": "2px 8px", "borderRadius": "20px",
                    "textAlign": "center", "marginBottom": "3px",
                }),
                html.Span(t["status"], style={"fontSize": "10px", "color": sta_c}),
            ], style={"flexShrink": "0", "textAlign": "right"}),
            html.Span(t["time"], style={"fontSize": "11px", "color": "#B4B2A9", "flexShrink": "0", "marginLeft": "6px"}),
        ], style={
            "display": "flex", "alignItems": "center", "gap": "10px",
            "padding": "8px 0", "borderBottom": "0.5px solid #D3D1C7",
        }))
    return rows


if __name__ == "__main__":
    print("\n  Threat Intelligence Dashboard")
    print("  ─────────────────────────────")
    print("  Open: http://127.0.0.1:8050\n")
    app.run(debug=True, port=8050)