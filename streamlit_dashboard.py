import sqlite3
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Setup page configuration
st.set_page_config(
    page_title="DeepShield AI - Automotive Cybersecurity Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Premium Dark Glassmorphism Theme CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Main Background */
    .stApp {
        background: linear-gradient(135deg, #080B11 0%, #0F172A 100%);
        color: #F8FAFC;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: rgba(15, 23, 42, 0.95) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    /* Glassmorphism Cards */
    .glass-card {
        background: rgba(30, 41, 59, 0.45);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
        backdrop-filter: blur(12px);
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4);
    }
    
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 18px;
        margin-bottom: 25px;
    }
    
    .kpi-card {
        background: rgba(30, 41, 59, 0.45);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 10px;
        padding: 20px;
        text-align: left;
        position: relative;
        overflow: hidden;
    }
    
    .kpi-card::after {
        content: '';
        position: absolute;
        bottom: 0;
        left: 0;
        width: 100%;
        height: 4px;
    }
    
    .kpi-safe::after { background: #10B981; }
    .kpi-suspicious::after { background: #F59E0B; }
    .kpi-danger::after { background: #EF4444; }
    .kpi-info::after { background: #3B82F6; }
    
    .kpi-val {
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1.1;
        margin-top: 5px;
    }
    
    .kpi-lbl {
        color: #94A3B8;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    /* Gradient Headers */
    .gradient-text {
        background: linear-gradient(90deg, #3B82F6 0%, #0D9488 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 700;
    }
    
    .footer {
        text-align: center;
        padding: 20px;
        font-size: 0.8rem;
        color: #64748B;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        margin-top: 50px;
    }
</style>
""", unsafe_allow_html=True)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "deepshield.db"

# Page Header
st.markdown("""
<div style='margin-bottom: 25px;'>
    <span style='text-transform: uppercase; font-size: 0.8rem; letter-spacing: 2px; color: #0D9488; font-weight: 700;'>TATA Technologies Edge AI Node</span>
    <h1 class='gradient-text' style='font-size: 2.8rem; margin: 0;'>🛡️ DeepShield AI Fleet Console</h1>
    <p style='color: #94A3B8; font-size: 1.1rem; margin-top: 5px;'>Real-time threat intelligence and edge binary audits for connected automotive networks</p>
</div>
""", unsafe_allow_html=True)

# Validate DB exists
if not DB_PATH.exists():
    st.info("No scan database detected. Run the Flask web app first and scan a file.")
    st.stop()

# Query SQLite Data safely
try:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM scans ORDER BY id DESC", conn)
    conn.close()
except Exception as e:
    st.error(f"Error querying database: {e}")
    st.stop()

if df.empty:
    st.info("The threat database is currently empty. Open the Flask portal and run a security scan.")
    st.stop()

# Data Preprocessing
df["scanned_at_dt"] = pd.to_datetime(df["scanned_at"])
df["file_size_kb"] = df["file_size"] / 1024.0

# Sidebar Filters
st.sidebar.markdown("### 🎛️ Analytics Controller")

# Selection Filters
severity_list = ["All"] + sorted(df["severity"].unique().tolist())
selected_severity = st.sidebar.selectbox("Filter by Severity Level", severity_list)

class_list = ["All"] + sorted(df["classification"].unique().tolist())
selected_classification = st.sidebar.selectbox("Filter by Inference Verdict", class_list)

# Search Input
search_query = st.sidebar.text_input("🔍 Search File Name", "")

# Apply filters
df_filtered = df.copy()
if selected_severity != "All":
    df_filtered = df_filtered[df_filtered["severity"] == selected_severity]
if selected_classification != "All":
    df_filtered = df_filtered[df_filtered["classification"] == selected_classification]
if search_query:
    df_filtered = df_filtered[df_filtered["filename"].str.contains(search_query, case=False)]

# System KPI Widgets (Calculated from filtered dataset)
total_scans = len(df_filtered)
high_risk = int((df_filtered["classification"] == "Malware").sum())
suspicious = int((df_filtered["classification"] == "Suspicious").sum())
avg_confidence = df_filtered["confidence"].mean() if total_scans > 0 else 0.0
safe_ratio = ((df_filtered["classification"] == "Safe").sum() / total_scans * 100) if total_scans > 0 else 100.0

st.markdown(f"""
<div class="kpi-container">
    <div class="kpi-card kpi-info">
        <div class="kpi-lbl">Active Edge Audits</div>
        <div class="kpi-val">{total_scans}</div>
    </div>
    <div class="kpi-card kpi-danger">
        <div class="kpi-lbl">Critical Backdoors</div>
        <div class="kpi-val" style="color: #EF4444;">{high_risk}</div>
    </div>
    <div class="kpi-card kpi-suspicious">
        <div class="kpi-lbl">Suspicious Packages</div>
        <div class="kpi-val" style="color: #F59E0B;">{suspicious}</div>
    </div>
    <div class="kpi-card kpi-safe">
        <div class="kpi-lbl">Inference Model Confidence</div>
        <div class="kpi-val" style="color: #10B981;">{avg_confidence:.2f}%</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Main Grid Layout
left_chart, right_chart = st.columns(2)

with left_chart:
    st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
    # Donut Chart for Verdict distribution
    counts = df_filtered["classification"].value_counts()
    labels = counts.index.tolist()
    values = counts.values.tolist()
    
    # Custom safety color mappings
    color_map = {"Safe": "#10B981", "Suspicious": "#F59E0B", "Malware": "#EF4444"}
    chart_colors = [color_map.get(label, "#3B82F6") for label in labels]
    
    fig_donut = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.45,
        marker=dict(colors=chart_colors, line=dict(color='rgba(15, 23, 42, 0.8)', width=2))
    )])
    
    fig_donut.update_layout(
        title="Fleet Compliance Classification Mix",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#F8FAFC', family="Outfit"),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )
    st.plotly_chart(fig_donut, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with right_chart:
    st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
    # Bar Chart representing confidence by file
    fig_bar = px.bar(
        df_filtered.head(10),
        x="filename",
        y="confidence",
        color="classification",
        title="Recent File Scan Confidence Levels (%)",
        color_discrete_map={"Safe": "#10B981", "Suspicious": "#F59E0B", "Malware": "#EF4444"},
        labels={"filename": "Device Binary", "confidence": "AI Model Confidence (%)"}
    )
    
    fig_bar.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#F8FAFC', family="Outfit"),
        xaxis=dict(gridcolor='rgba(255,255,255,0.05)', tickangle=45),
        yaxis=dict(gridcolor='rgba(255,255,255,0.05)', range=[0, 100])
    )
    st.plotly_chart(fig_bar, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# Scan History Section
st.markdown("<div class='glass-card'>", unsafe_allow_html=True)
st.subheader("📋 Supply Chain Forensic Audit History")

# Clean displaying fields
df_table = df_filtered.copy()
df_table["file_size_kb"] = df_table["file_size_kb"].apply(lambda s: f"{s:.2f} KB")
df_table["confidence"] = df_table["confidence"].apply(lambda c: f"{c:.1f}%")
df_table["file_hash_trunc"] = df_table["file_hash"].apply(lambda h: f"{h[:10]}...")

df_display = df_table[[
    "id", "filename", "file_hash_trunc", "file_size_kb",
    "classification", "confidence", "severity", "scanned_at"
]].copy()

df_display.columns = [
    "Scan ID", "File Target Name", "Checksum (SHA-256)", "File Size",
    "Model Classification", "Model Confidence", "Severity Index", "Scan Date"
]

st.dataframe(df_display, use_container_width=True, hide_index=True)
st.markdown("</div>", unsafe_allow_html=True)

# Footer
st.markdown("""
<div class='footer'>
    🛡️ DeepShield AI is developed as an AI-at-the-Edge solution. Under compliance metrics with ISO/SAE 21434 & UNECE WP.29 security validation workflows.
    <br>© 2026 Tata Technologies Cybersecurity Division. All Rights Reserved.
</div>
""", unsafe_allow_html=True)
