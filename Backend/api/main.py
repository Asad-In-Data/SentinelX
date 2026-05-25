from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from traffic_service import TrafficAnalyzer

app = FastAPI(
    title="SentinelX API",
    version="1.0.0",
    description="Live network anomaly detection API for SentinelX",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = TrafficAnalyzer()


class PredictRequest(BaseModel):
    packet: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional feature payload. If omitted, returns the latest live prediction.",
    )


@app.on_event("startup")
def on_startup() -> None:
    try:
        analyzer.start()
    except Exception:
        # API should still boot even if packet capture is unavailable.
        pass


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": "SentinelX API",
        "status": "running",
        "endpoints": ["/predict", "/traffic_stats", "/health", "/recent_predictions"],
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "live_capture_enabled": analyzer.get_traffic_stats()["live_capture_enabled"],
        "model_loaded": True,
    }


@app.get("/predict")
def predict_latest() -> Dict[str, Any]:
    latest = analyzer.get_latest_prediction()
    if latest is None:
        raise HTTPException(status_code=404, detail="No live predictions available yet")
    return latest


@app.post("/predict")
def predict(request: Optional[PredictRequest] = None) -> Dict[str, Any]:
    if request is not None and request.packet is not None:
        result = analyzer.predict_from_feature_payload(request.packet)
        if result.get("status") == "validation_failed":
            raise HTTPException(status_code=400, detail=result)
        return result

    latest = analyzer.get_latest_prediction()
    if latest is None:
        raise HTTPException(status_code=404, detail="No live predictions available yet")
    return latest


@app.get("/traffic_stats")
def traffic_stats() -> Dict[str, Any]:
    stats = analyzer.get_traffic_stats()
    stats["recent_predictions"] = analyzer.get_recent_predictions(limit=10)
    return stats


@app.get("/recent_predictions")
def recent_predictions(limit: int = 20) -> Dict[str, Any]:
    return {"items": analyzer.get_recent_predictions(limit=limit)}


@app.post("/capture/start")
def start_capture() -> Dict[str, Any]:
    analyzer.start()
    return {"status": "started", "live_capture_enabled": True}


@app.post("/capture/stop")
def stop_capture() -> Dict[str, Any]:
    analyzer.stop()
    return {"status": "stopped", "live_capture_enabled": False}
