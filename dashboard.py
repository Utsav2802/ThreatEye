import streamlit as st
import pandas as pd
import sqlite3
import configparser
import time

# ── CONFIG ──
ALERT_DB   = "data/threats.db"
STATE_FILE = "monitor_state.ini"

st.set_page_config(page_title="Threat Dashboard", layout="wide")
st.title("📡 Endpoint Threat Feed")

# ── MONITOR CONTROLS ──
def set_monitor_status(status):
    cfg = configparser.ConfigParser()
    cfg["Monitor"] = {"status": status}
    with open(STATE_FILE, "w") as f:
        cfg.write(f)

st.sidebar.header("🧠 Monitor Control")
if st.sidebar.button("▶️ Start Monitor"):
    set_monitor_status("ON")
    st.success("Monitoring activated")
if st.sidebar.button("⏹️ Stop Monitor"):
    set_monitor_status("OFF")
    st.warning("Monitoring stopped")

# ── FILTERS ──
st.sidebar.header("🔎 Filters")
user_filter   = st.sidebar.text_input("Username")
pid_filter    = st.sidebar.text_input("PID")
reason_filter = st.sidebar.text_input("Keyword")

# ── LOAD ALERTS ──
def load_alerts():
    conn = sqlite3.connect(ALERT_DB)
    df = pd.read_sql_query("SELECT * FROM alerts", conn)
    conn.close()

    df['pid'] = df['pid'].astype(str)
    df['timestamp'] = df['timestamp'].astype(str)
    df['quarantined'] = df['quarantined'].astype(str)

    df['Quarantine Status'] = df['quarantined'].apply(
        lambda x: "✅ Quarantined" if x.strip().lower() == "yes" else "🔔 Alert-Only"
    )

    df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)
    df['Threat #'] = df.index + 1
    return df

alerts_df = load_alerts()
if user_filter:
    alerts_df = alerts_df[alerts_df['username'].str.contains(user_filter, case=False, na=False)]
if pid_filter:
    alerts_df = alerts_df[alerts_df['pid'] == pid_filter]
if reason_filter:
    alerts_df = alerts_df[alerts_df['reason'].str.contains(reason_filter, case=False, na=False)]

# ── LIVE FEED ──
st.subheader("🔴 Live Alert Feed")
st.write(f"Last updated: {time.strftime('%H:%M:%S')}")
if alerts_df.empty:
    st.info("No alerts detected.")
else:
    st.dataframe(
        alerts_df[[
            'Threat #', 'timestamp', 'process_name', 'pid',
            'username', 'exe', 'reason', 'Quarantine Status'
        ]],
        use_container_width=True
    )

# ── SUMMARY ──
st.subheader("📊 Threat Summary")
col1, col2, col3 = st.columns(3)
col1.metric("Total Alerts", len(alerts_df))
col2.metric("Unique Processes", alerts_df['process_name'].nunique())
col3.metric("Quarantined", (alerts_df['quarantined'] == "Yes").sum())

st.caption("🔒 Powered by Utsav, Mehlam and Surbhi's Endpoint Threat Detection System")
