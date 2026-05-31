# Flow 03 - Streamlit Dashboard

## Objective
Provide one final visual web dashboard for monitoring and control.

## Primary Files
- `Frontend/app.py`
- `Backend/network/dashboard.py`

## What It Does
- Shows traffic metrics, prediction mix, latest predictions.
- Shows system status and recent activity.
- Includes DSL query panel.
- Tries to auto-start local backend API.
- Shows pipeline status (API/DB health and DB row counts).

## Run
```bash
streamlit run Frontend/app.py
```

## Notes
- Dashboard is the intended single UI entry point.
