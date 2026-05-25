from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

st.set_page_config(page_title="SentinelX Security Dashboard", layout="wide")

API_BASE = st.sidebar.text_input("API Base URL", value="http://127.0.0.1:8000")

st.title("SentinelX Security Dashboard")
st.caption("Live traffic, anomaly detection, and model verdicts from the FastAPI backend")


def fetch_json(path: str) -> Dict[str, Any]:
    response = requests.get(f"{API_BASE}{path}", timeout=5)
    response.raise_for_status()
    return response.json()


def safe_get(path: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return fetch_json(path)
    except Exception as exc:
        st.sidebar.error(f"API error on {path}: {exc}")
        return fallback


stats = safe_get(
    "/traffic_stats",
    {
        "packets_processed": 0,
        "predictions_made": 0,
        "attacks_detected": 0,
        "normal_traffic": 0,
        "uncertain": 0,
        "validation_failed": 0,
        "attack_rate": 0,
        "normal_rate": 0,
        "uncertain_rate": 0,
        "live_capture_enabled": False,
        "recent_predictions": [],
    },
)

recent_predictions: List[Dict[str, Any]] = stats.get("recent_predictions", [])

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Packets", stats.get("packets_processed", 0))
col2.metric("Predictions", stats.get("predictions_made", 0))
col3.metric("Attacks", stats.get("attacks_detected", 0))
col4.metric("Normal", stats.get("normal_traffic", 0))
col5.metric("Uncertain", stats.get("uncertain", 0))

st.subheader("System Status")
status_col1, status_col2, status_col3 = st.columns(3)
status_col1.metric("Live Capture", "ON" if stats.get("live_capture_enabled") else "OFF")
status_col2.metric("Uptime (s)", stats.get("uptime_seconds", 0))
status_col3.metric("Validation Failed", stats.get("validation_failed", 0))

st.subheader("Prediction Mix")
mix_df = pd.DataFrame(
    [
        {"Label": "Attack", "Count": stats.get("attacks_detected", 0)},
        {"Label": "Normal", "Count": stats.get("normal_traffic", 0)},
        {"Label": "Uncertain", "Count": stats.get("uncertain", 0)},
    ]
)
fig = px.bar(mix_df, x="Label", y="Count", color="Label", text="Count", color_discrete_sequence=["#b42318", "#027a48", "#f79009"])
fig.update_layout(showlegend=False, height=360, margin=dict(l=20, r=20, t=20, b=20))
st.plotly_chart(fig, use_container_width=True)

st.subheader("Latest Predictions")
if recent_predictions:
    pred_df = pd.DataFrame(recent_predictions)
    display_cols = [
        c
        for c in [
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol_type",
            "service",
            "predicted_label",
            "normal_probability",
            "attack_probability",
            "confidence",
            "severity",
        ]
        if c in pred_df.columns
    ]
    st.dataframe(pred_df[display_cols], use_container_width=True, hide_index=True)
else:
    st.info("No live predictions yet. Start the API capture or wait for traffic.")

st.subheader("Recent Activity")
stats_table = pd.DataFrame(
    [
        ["Attack rate", f"{stats.get('attack_rate', 0)}%"],
        ["Normal rate", f"{stats.get('normal_rate', 0)}%"],
        ["Uncertain rate", f"{stats.get('uncertain_rate', 0)}%"],
        ["Last prediction", stats.get("last_prediction_at", "-")],
        ["Last packet", stats.get("last_packet_at", "-")],
        ["Last error", stats.get("last_error", "-")],
    ],
    columns=["Metric", "Value"],
)
st.table(stats_table)

if st.button("Refresh now"):
    st.rerun()

st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")