from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Prediction(Base):
    __tablename__ = "predictions"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(64))
    destination_ip = Column(String(64))
    protocol_type = Column(String(32))
    service = Column(String(64))
    predicted_label = Column(String(32))
    normal_probability = Column(Float)
    attack_probability = Column(Float)
    confidence = Column(Float)
    severity = Column(String(32))
    validation_warnings = Column(Integer)
    validation_errors = Column(Integer)
    packet_summary = Column(Text)


class TrafficStats(Base):
    __tablename__ = "traffic_stats"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_predictions = Column(Integer, default=0)
    attacks_detected = Column(Integer, default=0)
    normal_traffic = Column(Integer, default=0)
    uncertain = Column(Integer, default=0)
    uptime_seconds = Column(Float, default=0.0)
