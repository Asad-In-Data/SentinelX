from __future__ import annotations

import json
import sys
import threading
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP

BASE_DIR = Path(__file__).resolve().parents[2]
ML_DIR = BASE_DIR / "Backend" / "ML"
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from feature_aggregator import NetworkFeatureAggregator  # noqa: E402
from validation_layer import PredictionPostProcessor, PredictionValidator  # noqa: E402


@dataclass
class PredictionRecord:
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol_type: str
    service: str
    predicted_label: str
    normal_probability: float
    attack_probability: float
    confidence: float
    severity: str
    validation_warnings: int
    validation_errors: int
    packet_summary: Dict[str, Any]


class TrafficAnalyzer:
    def __init__(self, interface: Optional[str] = None, window_size: int = 10):
        self.interface = interface
        self.window_size = window_size
        self.lock = threading.Lock()
        self.sniffer_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.last_error: Optional[str] = None
        self.live_capture_enabled = False
        self.started_at = datetime.utcnow()
        self.recent_predictions: deque[PredictionRecord] = deque(maxlen=100)
        self.stats: Dict[str, Any] = {
            "packets_processed": 0,
            "predictions_made": 0,
            "attacks_detected": 0,
            "normal_traffic": 0,
            "uncertain": 0,
            "validation_failed": 0,
            "last_prediction_at": None,
            "last_packet_at": None,
        }

        self._load_artifacts()
        self._build_runtime_components()

    def _load_artifacts(self) -> None:
        model_dir = ML_DIR / "models"
        self.model = joblib.load(model_dir / "model.pkl")
        self.scaler = joblib.load(model_dir / "scaler.pkl")
        self.encoders = joblib.load(model_dir / "encoders.pkl")
        self.feature_names = joblib.load(model_dir / "features.pkl")
        target_encoder_path = model_dir / "target_encoder.pkl"
        self.target_encoder = joblib.load(target_encoder_path) if target_encoder_path.exists() else None

    def _build_runtime_components(self) -> None:
        attack_class_index = 0
        if self.target_encoder is not None and hasattr(self.target_encoder, "classes_"):
            classes = list(self.target_encoder.classes_)
            if "attack" in classes:
                attack_class_index = classes.index("attack")

        self.aggregator = NetworkFeatureAggregator(
            window_size=self.window_size,
            feature_names=self.feature_names,
        )
        self.validator = PredictionValidator(feature_names=self.feature_names)
        self.post_processor = PredictionPostProcessor(
            confidence_threshold=0.85,
            attack_probability_threshold=0.70,
            attack_class_index=attack_class_index,
        )

    def encode_categorical_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        encoded_df = features_df.copy()
        for column in ["protocol_type", "service", "flag"]:
            if column not in encoded_df.columns:
                continue
            value = encoded_df[column].iloc[0]
            encoder = self.encoders.get(column)
            if encoder is not None and value in encoder.classes_:
                encoded_df[column] = encoder.transform([value])[0]
            else:
                encoded_df[column] = 0
        return encoded_df

    def process_packet(self, packet) -> Optional[PredictionRecord]:
        with self.lock:
            self.stats["packets_processed"] += 1
            self.stats["last_packet_at"] = datetime.utcnow().isoformat()

        if not packet.haslayer(IP):
            return None

        features_df = self.aggregator.extract_features(packet)
        if features_df is None:
            return None

        raw_features_df = features_df.copy()
        features_df = self.encode_categorical_features(features_df)
        is_valid, validation_report = self.validator.validate(features_df)

        if not is_valid:
            with self.lock:
                self.stats["validation_failed"] += 1
            return None

        features_df = features_df[self.feature_names]
        features_scaled = self.scaler.transform(features_df)
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        result = self.post_processor.process_prediction(
            prediction=prediction,
            probabilities=probabilities,
            validation_report=validation_report,
        )

        ip_layer = packet[IP]
        record = PredictionRecord(
            timestamp=datetime.utcnow().isoformat(),
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            protocol_type=str(raw_features_df["protocol_type"].iloc[0]),
            service=str(raw_features_df["service"].iloc[0]),
            predicted_label=str(result["final_prediction"]),
            normal_probability=float(result["normal_probability"]),
            attack_probability=float(result["attack_probability"]),
            confidence=float(result["confidence"]),
            severity=str(result["severity"]),
            validation_warnings=len(validation_report.get("warnings", [])),
            validation_errors=len(validation_report.get("errors", [])),
            packet_summary={
                "src_bytes": int(features_df["src_bytes"].iloc[0]),
                "dst_bytes": int(features_df["dst_bytes"].iloc[0]),
                "count": int(features_df["count"].iloc[0]),
                "srv_count": int(features_df["srv_count"].iloc[0]),
            },
        )

        with self.lock:
            self.stats["predictions_made"] += 1
            self.stats["last_prediction_at"] = record.timestamp
            if record.predicted_label == "ATTACK":
                self.stats["attacks_detected"] += 1
            elif record.predicted_label == "NORMAL":
                self.stats["normal_traffic"] += 1
            else:
                self.stats["uncertain"] += 1
            self.recent_predictions.appendleft(record)

        return record

    def _sniff_loop(self) -> None:
        self.live_capture_enabled = True
        try:
            while not self.stop_event.is_set():
                sniff(
                    prn=self.process_packet,
                    store=False,
                    iface=self.interface,
                    timeout=1,
                    lfilter=lambda pkt: pkt.haslayer(IP),
                )
        except Exception as exc:
            self.last_error = str(exc)
            self.live_capture_enabled = False

    def start(self) -> bool:
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return True

        self.stop_event.clear()
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        return True

    def stop(self) -> None:
        self.stop_event.set()
        self.live_capture_enabled = False

    def get_traffic_stats(self) -> Dict[str, Any]:
        with self.lock:
            total_predictions = max(self.stats["predictions_made"], 1)
            uptime_seconds = (datetime.utcnow() - self.started_at).total_seconds()
            return {
                **self.stats,
                "uptime_seconds": round(uptime_seconds, 2),
                "attack_rate": round((self.stats["attacks_detected"] / total_predictions) * 100, 2),
                "normal_rate": round((self.stats["normal_traffic"] / total_predictions) * 100, 2),
                "uncertain_rate": round((self.stats["uncertain"] / total_predictions) * 100, 2),
                "live_capture_enabled": self.live_capture_enabled,
                "last_error": self.last_error,
                "recent_predictions_count": len(self.recent_predictions),
            }

    def get_latest_prediction(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            if not self.recent_predictions:
                return None
            return asdict(self.recent_predictions[0])

    def get_recent_predictions(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.lock:
            return [asdict(item) for item in list(self.recent_predictions)[:limit]]

    def predict_from_feature_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        frame = pd.DataFrame([payload])
        frame = self.encode_categorical_features(frame)
        missing = [name for name in self.feature_names if name not in frame.columns]
        for name in missing:
            frame[name] = 0
        frame = frame[self.feature_names]

        is_valid, validation_report = self.validator.validate(frame)
        if not is_valid:
            return {
                "status": "validation_failed",
                "validation_report": validation_report,
            }

        scaled = self.scaler.transform(frame)
        prediction = self.model.predict(scaled)[0]
        probabilities = self.model.predict_proba(scaled)[0]
        result = self.post_processor.process_prediction(
            prediction=prediction,
            probabilities=probabilities,
            validation_report=validation_report,
        )
        result["status"] = "ok"
        return result
