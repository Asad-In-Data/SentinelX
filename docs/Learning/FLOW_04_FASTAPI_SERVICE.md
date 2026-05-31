# Flow 04 - FastAPI Service

## Objective
Expose live prediction and stats endpoints, and run packet->ML pipeline.

## Primary Files
- `Backend/api/main.py`
- `Backend/api/traffic_service.py`

## What It Does
- On startup, starts `TrafficAnalyzer`.
- Captures packets with Scapy.
- Extracts features, predicts with model, updates in-memory stats.
- Persists results to DB queue worker.
- Exposes endpoints:
  - `/health`
  - `/predict`
  - `/traffic_stats`
  - `/recent_predictions`

## Run
```bash
python -m uvicorn Backend.api.main:app --host 127.0.0.1 --port 8000
```

## Notes
- This is the runtime bridge between sniffing, ML, and DB.
