from fastapi.testclient import TestClient
import pytest

from Backend.api import main as api_main

client = TestClient(api_main.app)


class StubAnalyzer:
    def __init__(self):
        self.started = False
        self.latest = None

    def start(self):
        self.started = True

    def stop(self):
        self.started = False

    def get_traffic_stats(self):
        return {
            "live_capture_enabled": self.started,
            "capture_started_at": "2026-06-03T00:00:00Z",
            "capture_stopped_at": "2026-06-03T00:00:30Z",
            "capture_session_seconds": 30,
        }

    def get_latest_prediction(self):
        return self.latest

    def get_recent_predictions(self, limit=20):
        return [{"id": 1, "predicted_label": "benign", "risk_score": 0.1}]

    def predict_from_feature_payload(self, payload):
        if payload.get("invalid"):
            return {"status": "validation_failed", "reason": "invalid features"}
        return {"status": "ok", "prediction": {"predicted_label": "malicious", "risk_score": 0.95}}


@pytest.fixture(autouse=True)
def stub_analyzer_fixture():
    api_main.analyzer = StubAnalyzer()
    yield


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["service"] == "SentinelX API"
    assert "/predict" in data["endpoints"]


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "live_capture_enabled" in data
    assert data["model_loaded"] is True


def test_predict_when_no_latest_available():
    r = client.get("/predict")
    assert r.status_code == 404
    assert r.json()["detail"] == "No live predictions available yet"


def test_predict_with_payload_success():
    payload = {"packet": {"some_feature": 1}}
    r = client.post("/predict", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["prediction"]["predicted_label"] == "malicious"


def test_capture_start_stop():
    r = client.post("/capture/start")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "started"
    assert data["live_capture_enabled"] is True

    r2 = client.post("/capture/stop")
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["status"] == "stopped"
    assert data2["live_capture_enabled"] is False
