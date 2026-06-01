from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from Backend.compiler.engine import DSLExecutor, render_result

st.set_page_config(page_title="SentinelX Security Dashboard", layout="wide")

API_BASE = st.sidebar.text_input("API Base URL", value="http://127.0.0.1:8000")
ROOT_DIR = Path(__file__).resolve().parents[2]


def ensure_backend_running() -> None:
    if not API_BASE.startswith("http://127.0.0.1") and not API_BASE.startswith("http://localhost"):
        return

    try:
        requests.get(f"{API_BASE}/health", timeout=1.5)
        st.session_state["sentinelx_backend_ready"] = True
        return
    except Exception:
        pass

    if st.session_state.get("sentinelx_backend_started"):
        # Re-check quickly in case previous start attempt was still booting.
        try:
            requests.get(f"{API_BASE}/health", timeout=1.0)
            st.session_state["sentinelx_backend_ready"] = True
            return
        except Exception:
            # Allow another start attempt in this session if backend is still down.
            st.session_state["sentinelx_backend_started"] = False

    try:
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "Backend.api.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
            ],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        st.session_state["sentinelx_backend_started"] = True

        for _ in range(20):
            try:
                requests.get(f"{API_BASE}/health", timeout=1.0)
                st.session_state["sentinelx_backend_ready"] = True
                break
            except Exception:
                time.sleep(0.5)

        if not st.session_state.get("sentinelx_backend_ready"):
            st.session_state["sentinelx_backend_error"] = (
                "Backend auto-start attempted but API is still unreachable at /health."
            )
    except Exception as exc:
        st.session_state["sentinelx_backend_error"] = str(exc)


ensure_backend_running()

if st.session_state.get("sentinelx_backend_error"):
    st.sidebar.warning(f"Backend startup warning: {st.session_state['sentinelx_backend_error']}")

DSL_EXECUTOR = DSLExecutor()
DSL_EXECUTOR.repository.api_base = API_BASE.rstrip("/")

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


def post_json(path: str) -> Dict[str, Any]:
    response = requests.post(f"{API_BASE}{path}", timeout=5)
    response.raise_for_status()
    return response.json()


def get_pipeline_status() -> Dict[str, Any]:
    status: Dict[str, Any] = {
        "api_online": False,
        "api_error": "",
        "db_online": False,
        "db_error": "",
        "db_predictions_count": 0,
        "db_traffic_stats_count": 0,
        "db_last_prediction_at": "-",
        "db_last_stats_at": "-",
    }

    try:
        health = fetch_json("/health")
        status["api_online"] = bool(health.get("status") == "ok")
    except Exception as exc:
        status["api_error"] = str(exc)

    try:
        from Backend.db.database import SessionLocal
        from Backend.db.models import Prediction, TrafficStats

        session = SessionLocal()
        try:
            predictions_count = session.query(Prediction).count()
            traffic_stats_count = session.query(TrafficStats).count()
            latest_prediction = session.query(Prediction).order_by(Prediction.id.desc()).first()
            latest_stats = session.query(TrafficStats).order_by(TrafficStats.id.desc()).first()

            status["db_online"] = True
            status["db_predictions_count"] = predictions_count
            status["db_traffic_stats_count"] = traffic_stats_count
            status["db_last_prediction_at"] = "-" if latest_prediction is None else str(latest_prediction.timestamp)
            status["db_last_stats_at"] = "-" if latest_stats is None else str(latest_stats.timestamp)
        finally:
            session.close()
    except Exception as exc:
        status["db_error"] = str(exc)

    return status


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
        "capture_session_active": False,
        "capture_started_at": None,
        "capture_stopped_at": None,
        "capture_session_seconds": 0,
        "recent_predictions": [],
    },
)

recent_predictions: List[Dict[str, Any]] = stats.get("recent_predictions", [])
pipeline_status = get_pipeline_status()

if stats.get("capture_session_active") and not st.session_state.get("capture_session_started_at"):
    st.session_state["capture_session_started_at"] = stats.get("capture_started_at")
if not stats.get("capture_session_active") and stats.get("capture_stopped_at"):
    st.session_state["capture_last_session_seconds"] = stats.get("capture_session_seconds", 0)
    st.session_state["capture_session_started_at"] = None

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

capture_col1, capture_col2, capture_col3 = st.columns(3)
capture_elapsed = 0.0
started_at = st.session_state.get("capture_session_started_at")
if started_at and stats.get("capture_session_active"):
    try:
        capture_elapsed = (datetime.now() - datetime.fromisoformat(started_at)).total_seconds()
    except Exception:
        capture_elapsed = float(stats.get("capture_session_seconds", 0))
else:
    capture_elapsed = float(stats.get("capture_session_seconds", st.session_state.get("capture_last_session_seconds", 0)))

capture_col1.metric("Capture Session", "ACTIVE" if stats.get("capture_session_active") else "IDLE")
capture_col2.metric("Capture Elapsed (s)", round(capture_elapsed, 2))
capture_col3.metric("Session Started", started_at or stats.get("capture_started_at") or "-")

button_col1, button_col2, button_col3 = st.columns(3)
if button_col1.button("Start Live Capture"):
    try:
        result = post_json("/capture/start")
        st.session_state["capture_session_started_at"] = result.get("capture_started_at")
        st.session_state["capture_last_session_seconds"] = 0.0
        st.success("Live capture started.")
        st.rerun()
    except Exception as exc:
        st.error(f"Could not start live capture: {exc}")

if button_col2.button("Stop Live Capture"):
    try:
        result = post_json("/capture/stop")
        st.session_state["capture_last_session_seconds"] = result.get("capture_session_seconds", 0)
        st.session_state["capture_session_started_at"] = None
        st.success("Live capture stopped.")
        st.rerun()
    except Exception as exc:
        st.error(f"Could not stop live capture: {exc}")

if button_col3.button("Restart Backend"):
    st.session_state["sentinelx_backend_started"] = False
    st.session_state["sentinelx_backend_ready"] = False
    st.session_state.pop("sentinelx_backend_error", None)
    ensure_backend_running()
    st.rerun()

st.subheader("Pipeline Status")
pipe_col1, pipe_col2, pipe_col3, pipe_col4 = st.columns(4)
pipe_col1.metric("API", "ONLINE" if pipeline_status["api_online"] else "OFFLINE")
pipe_col2.metric("DB", "ONLINE" if pipeline_status["db_online"] else "OFFLINE")
pipe_col3.metric("DB Predictions", pipeline_status["db_predictions_count"])
pipe_col4.metric("DB Stats Rows", pipeline_status["db_traffic_stats_count"])

pipeline_table = pd.DataFrame(
    [
        ["Capture active", "YES" if stats.get("capture_session_active") else "NO"],
        ["Capture elapsed", f"{round(capture_elapsed, 2)}"],
        ["DB last prediction", str(pipeline_status["db_last_prediction_at"])],
        ["DB last stats", str(pipeline_status["db_last_stats_at"])],
        ["API error", str(pipeline_status["api_error"] or "-")],
        ["DB error", str(pipeline_status["db_error"] or "-")],
    ],
    columns=["Pipeline Check", "Value"],
)
pipeline_table["Value"] = pipeline_table["Value"].astype(str)
st.table(pipeline_table)

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

st.subheader("Mini DSL")
st.caption("Query the DB first, then fall back to the API if the DB is not reachable.")
dsl_query = st.text_area(
    "DSL Query",
    value="show predictions limit 10",
    height=90,
    help="Examples: show predictions limit 10 | show threats limit 10 | show traffic limit 5 | show stats | show latest",
)

if st.button("Run DSL Query"):
    try:
        dsl_result = DSL_EXECUTOR.execute(dsl_query)
        st.code(render_result(dsl_result), language="text")
        if dsl_result.rows:
            st.dataframe(pd.DataFrame(dsl_result.rows), use_container_width=True, hide_index=True)
    except Exception as exc:
        st.error(f"DSL error: {exc}")

st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")