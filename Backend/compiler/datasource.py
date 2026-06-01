from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import requests
from sqlalchemy import asc, desc, func

from Backend.db.database import SessionLocal, create_tables
from Backend.db.models import Prediction, TrafficStats


@dataclass(frozen=True)
class SourceResult:
    source: str
    rows: List[Dict[str, Any]]


class DataRepository:
    """Read from DB first; fall back to the API when DB access is unavailable."""

    def __init__(self, api_base: Optional[str] = None):
        self.api_base = (api_base or os.getenv("SENTINELX_API_BASE", "http://127.0.0.1:8000")).rstrip("/")
        try:
            create_tables()
        except Exception:
            pass

    def fetch_threats(self, limit: int = 10, filters: Optional[Sequence] = None, order_by: Optional[str] = None, order_direction: str = "DESC") -> SourceResult:
        try:
            rows = self._fetch_threats_db(limit, filters or [], order_by, order_direction)
            return SourceResult(source="database", rows=rows)
        except Exception:
            pass
        return SourceResult(source="api", rows=self._fetch_threats_api(limit))

    def fetch_predictions(self, limit: int = 20, filters: Optional[Sequence] = None, order_by: Optional[str] = None, order_direction: str = "DESC") -> SourceResult:
        try:
            rows = self._fetch_predictions_db(limit, filters or [], order_by, order_direction)
            return SourceResult(source="database", rows=rows)
        except Exception:
            pass
        return SourceResult(source="api", rows=self._fetch_predictions_api(limit))

    def fetch_traffic(self, limit: int = 10) -> SourceResult:
        try:
            rows = self._fetch_traffic_db(limit)
            if rows:
                return SourceResult(source="database", rows=rows)
        except Exception:
            pass
        return SourceResult(source="api", rows=[self._fetch_stats_api()])

    def fetch_stats(self) -> SourceResult:
        try:
            rows = self._fetch_stats_db(limit=1)
            if rows:
                return SourceResult(source="database", rows=rows)
        except Exception:
            pass
        return SourceResult(source="api", rows=[self._fetch_stats_api()])

    def fetch_latest(self) -> SourceResult:
        try:
            rows = self._fetch_latest_db()
            if rows:
                return SourceResult(source="database", rows=rows)
        except Exception:
            pass

        api_row = self._fetch_latest_api()
        if api_row:
            return SourceResult(source="api", rows=[api_row])

        return SourceResult(source="local", rows=[])

    def help_rows(self) -> SourceResult:
        return SourceResult(
            source="local",
            rows=[
                {
                    "command": "SHOW PREDICTIONS LIMIT 20",
                    "meaning": "List all recent predictions from DB or API fallback",
                },
                {
                    "command": "SHOW_THREATS",
                    "meaning": "Show attack/high-risk rows",
                },
                {
                    "command": "SHOW_TRAFFIC",
                    "meaning": "Show traffic snapshots",
                },
                {
                    "command": "SHOW_IPS",
                    "meaning": "Show unique IP activity",
                },
                {
                    "command": "SHOW_PROTOCOLS",
                    "meaning": "Show protocol counts",
                },
                {
                    "command": "COUNT_PACKETS / COUNT_THREATS / COUNT_IPS",
                    "meaning": "Show totals",
                },
                {
                    "command": "SHOW_HIGH_RISK / SHOW_MEDIUM_RISK / SHOW_LOW_RISK",
                    "meaning": "Show risk buckets",
                },
                {
                    "command": "SHOW_TCP / SHOW_UDP / SHOW_ICMP",
                    "meaning": "Filter by protocol",
                },
                {
                    "command": "LATEST_THREATS / LATEST_PACKETS / TOP_ATTACKERS",
                    "meaning": "Show latest or top activity",
                },
                {
                    "command": "HELP / VERSION / STATUS",
                    "meaning": "System commands",
                },
                {
                    "command": "SHOW THREATS LIMIT 10 WHERE severity = HIGH",
                    "meaning": "List attack rows from DB or API fallback",
                },
                {
                    "command": "SHOW TRAFFIC LIMIT 5",
                    "meaning": "Show recent traffic snapshots",
                },
                {
                    "command": "SHOW STATS",
                    "meaning": "Show current live summary",
                },
                {
                    "command": "SHOW LATEST",
                    "meaning": "Show latest prediction",
                },
            ],
        )

    def explain_rows(self, query: str) -> SourceResult:
        return SourceResult(
            source="local",
            rows=[
                {
                    "query": query,
                    "meaning": "The DSL parser will execute the query against DB first, then API fallback.",
                }
            ],
        )

    def _fetch_threats_db(self, limit: int, filters: Sequence, order_by: Optional[str], order_direction: str) -> List[Dict[str, Any]]:
        session = SessionLocal()
        try:
            query = session.query(Prediction)
            query = query.filter((Prediction.predicted_label == "ATTACK") | (Prediction.severity.in_(["HIGH", "CRITICAL"])) )

            for condition in filters:
                column = getattr(Prediction, condition.field, None)
                if column is None:
                    raise ValueError(f"Unknown field: {condition.field}")
                query = query.filter(self._build_filter(column, condition.operator, condition.value))

            if order_by:
                column = getattr(Prediction, order_by, None)
                if column is None:
                    raise ValueError(f"Unknown order field: {order_by}")
                query = query.order_by(desc(column) if order_direction.upper() == "DESC" else asc(column))
            else:
                query = query.order_by(desc(Prediction.timestamp))

            query = query.limit(limit)
            return [self._prediction_to_dict(row) for row in query.all()]
        finally:
            session.close()

    def count_packets(self) -> SourceResult:
        session = SessionLocal()
        try:
            total = session.query(func.count(Prediction.id)).scalar() or 0
            return SourceResult(source="database", rows=[{"metric": "packets", "count": int(total)}])
        finally:
            session.close()

    def count_threats(self) -> SourceResult:
        session = SessionLocal()
        try:
            total = (
                session.query(func.count(Prediction.id))
                .filter((Prediction.predicted_label == "ATTACK") | (Prediction.severity.in_(["HIGH", "CRITICAL"])))
                .scalar()
                or 0
            )
            return SourceResult(source="database", rows=[{"metric": "threats", "count": int(total)}])
        finally:
            session.close()

    def count_ips(self) -> SourceResult:
        rows = self.fetch_ips(limit=100000).rows
        return SourceResult(source="database", rows=[{"metric": "ips", "count": len(rows)}])

    def fetch_ips(self, limit: int = 20) -> SourceResult:
        session = SessionLocal()
        try:
            rows = session.query(Prediction.source_ip, Prediction.destination_ip).order_by(desc(Prediction.timestamp)).limit(limit).all()
            seen: Dict[str, int] = {}
            for source_ip, destination_ip in rows:
                for ip_address in [source_ip, destination_ip]:
                    if not ip_address:
                        continue
                    seen[ip_address] = seen.get(ip_address, 0) + 1
            items = [{"ip": ip_address, "count": count} for ip_address, count in sorted(seen.items(), key=lambda item: item[1], reverse=True)]
            return SourceResult(source="database", rows=items[:limit])
        finally:
            session.close()

    def fetch_protocols(self, limit: int = 20) -> SourceResult:
        session = SessionLocal()
        try:
            rows = (
                session.query(Prediction.protocol_type, func.count(Prediction.id).label("count"))
                .group_by(Prediction.protocol_type)
                .order_by(desc("count"))
                .limit(limit)
                .all()
            )
            return SourceResult(source="database", rows=[{"protocol": protocol or "unknown", "count": int(count)} for protocol, count in rows])
        finally:
            session.close()

    def fetch_risk(self, risk: str, limit: int = 20) -> SourceResult:
        risk = risk.upper()
        severity_map = {
            "HIGH": ["HIGH", "CRITICAL"],
            "MEDIUM": ["MEDIUM"],
            "LOW": ["LOW", "WARNING", "INFO"],
        }
        severities = severity_map.get(risk, [risk])
        session = SessionLocal()
        try:
            rows = (
                session.query(Prediction)
                .filter(Prediction.severity.in_(severities))
                .order_by(desc(Prediction.timestamp))
                .limit(limit)
                .all()
            )
            return SourceResult(source="database", rows=[self._prediction_to_dict(row) for row in rows])
        finally:
            session.close()

    def fetch_protocol(self, protocol: str, limit: int = 20) -> SourceResult:
        session = SessionLocal()
        try:
            rows = (
                session.query(Prediction)
                .filter(func.lower(Prediction.protocol_type) == protocol.lower())
                .order_by(desc(Prediction.timestamp))
                .limit(limit)
                .all()
            )
            return SourceResult(source="database", rows=[self._prediction_to_dict(row) for row in rows])
        finally:
            session.close()

    def latest_threats(self, limit: int = 5) -> SourceResult:
        return self.fetch_threats(limit=limit)

    def latest_packets(self, limit: int = 5) -> SourceResult:
        return self.fetch_predictions(limit=limit)

    def top_attackers(self, limit: int = 10) -> SourceResult:
        session = SessionLocal()
        try:
            rows = (
                session.query(Prediction.source_ip, func.count(Prediction.id).label("count"))
                .filter((Prediction.predicted_label == "ATTACK") | (Prediction.severity.in_(["HIGH", "CRITICAL"])))
                .group_by(Prediction.source_ip)
                .order_by(desc("count"))
                .limit(limit)
                .all()
            )
            return SourceResult(source="database", rows=[{"source_ip": source_ip or "unknown", "count": int(count)} for source_ip, count in rows])
        finally:
            session.close()

    def system_status(self) -> SourceResult:
        api_online = False
        api_error = ""
        live_capture = False
        capture_seconds = 0.0
        try:
            health = self._get_json("/health")
            api_online = health.get("status") == "ok"
            stats = self._get_json("/traffic_stats")
            live_capture = bool(stats.get("live_capture_enabled", False))
            capture_seconds = float(stats.get("capture_session_seconds", 0.0) or 0.0)
        except Exception as exc:
            api_error = str(exc)

        session = SessionLocal()
        try:
            packets = session.query(func.count(Prediction.id)).scalar() or 0
            threats = (
                session.query(func.count(Prediction.id))
                .filter((Prediction.predicted_label == "ATTACK") | (Prediction.severity.in_(["HIGH", "CRITICAL"])))
                .scalar()
                or 0
            )
            ips = len(self.fetch_ips(limit=100000).rows)
        finally:
            session.close()

        return SourceResult(
            source="database",
            rows=[
                {
                    "api_online": api_online,
                    "api_error": api_error or "-",
                    "db_packets": int(packets),
                    "db_threats": int(threats),
                    "db_ips": int(ips),
                    "live_capture_enabled": live_capture,
                    "capture_session_seconds": round(capture_seconds, 2),
                }
            ],
        )

    def _fetch_predictions_db(self, limit: int, filters: Sequence, order_by: Optional[str], order_direction: str) -> List[Dict[str, Any]]:
        session = SessionLocal()
        try:
            query = session.query(Prediction)

            for condition in filters:
                column = getattr(Prediction, condition.field, None)
                if column is None:
                    raise ValueError(f"Unknown field: {condition.field}")
                query = query.filter(self._build_filter(column, condition.operator, condition.value))

            if order_by:
                column = getattr(Prediction, order_by, None)
                if column is None:
                    raise ValueError(f"Unknown order field: {order_by}")
                query = query.order_by(desc(column) if order_direction.upper() == "DESC" else asc(column))
            else:
                query = query.order_by(desc(Prediction.timestamp))

            query = query.limit(limit)
            return [self._prediction_to_dict(row) for row in query.all()]
        finally:
            session.close()

    def _fetch_threats_api(self, limit: int) -> List[Dict[str, Any]]:
        try:
            payload = self._get_json("/recent_predictions?limit=%d" % limit)
            rows = payload.get("items", [])
            return [row for row in rows if self._is_threat_row(row)]
        except Exception:
            return []

    def _fetch_predictions_api(self, limit: int) -> List[Dict[str, Any]]:
        try:
            payload = self._get_json("/recent_predictions?limit=%d" % limit)
            return payload.get("items", [])
        except Exception:
            return []

    def _fetch_traffic_db(self, limit: int) -> List[Dict[str, Any]]:
        session = SessionLocal()
        try:
            rows = session.query(TrafficStats).order_by(desc(TrafficStats.timestamp)).limit(limit).all()
            return [self._traffic_to_dict(row) for row in rows]
        finally:
            session.close()

    def _fetch_stats_db(self, limit: int = 1) -> List[Dict[str, Any]]:
        session = SessionLocal()
        try:
            rows = session.query(TrafficStats).order_by(desc(TrafficStats.timestamp)).limit(limit).all()
            return [self._traffic_to_stats(row) for row in rows]
        finally:
            session.close()

    def _fetch_latest_db(self) -> List[Dict[str, Any]]:
        session = SessionLocal()
        try:
            rows = session.query(Prediction).order_by(desc(Prediction.timestamp)).limit(1).all()
            return [self._prediction_to_dict(row) for row in rows]
        finally:
            session.close()

    def _fetch_stats_api(self) -> Dict[str, Any]:
        try:
            payload = self._get_json("/traffic_stats")
            payload.pop("recent_predictions", None)
            return payload
        except Exception:
            return {
                "packets_processed": 0,
                "predictions_made": 0,
                "attacks_detected": 0,
                "normal_traffic": 0,
                "uncertain": 0,
                "uptime_seconds": 0,
                "attack_rate": 0,
                "normal_rate": 0,
                "uncertain_rate": 0,
            }

    def _fetch_latest_api(self) -> Dict[str, Any]:
        try:
            return self._get_json("/predict")
        except Exception:
            return {}

    def _get_json(self, path: str) -> Dict[str, Any]:
        response = requests.get(f"{self.api_base}{path}", timeout=5)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _build_filter(column, operator: str, value: Any):
        op = operator.strip()
        if op in {"=", "=="}:
            return column == value
        if op == "!=":
            return column != value
        if op == ">":
            return column > value
        if op == ">=":
            return column >= value
        if op == "<":
            return column < value
        if op == "<=":
            return column <= value
        raise ValueError(f"Unsupported operator: {operator}")

    @staticmethod
    def _prediction_to_dict(row: Prediction) -> Dict[str, Any]:
        packet_summary = row.packet_summary
        if isinstance(packet_summary, str):
            try:
                packet_summary = json.loads(packet_summary)
            except Exception:
                pass
        return {
            "id": row.id,
            "timestamp": row.timestamp,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "protocol_type": row.protocol_type,
            "service": row.service,
            "predicted_label": row.predicted_label,
            "normal_probability": row.normal_probability,
            "attack_probability": row.attack_probability,
            "confidence": row.confidence,
            "severity": row.severity,
            "validation_warnings": row.validation_warnings,
            "validation_errors": row.validation_errors,
            "packet_summary": packet_summary,
        }

    @staticmethod
    def _traffic_to_dict(row: TrafficStats) -> Dict[str, Any]:
        return {
            "id": row.id,
            "timestamp": row.timestamp,
            "total_predictions": row.total_predictions,
            "attacks_detected": row.attacks_detected,
            "normal_traffic": row.normal_traffic,
            "uncertain": row.uncertain,
            "uptime_seconds": row.uptime_seconds,
        }

    @staticmethod
    def _traffic_to_stats(row: TrafficStats) -> Dict[str, Any]:
        total = max(row.total_predictions or 0, 1)
        attack_rate = round((row.attacks_detected or 0) / total * 100, 2)
        normal_rate = round((row.normal_traffic or 0) / total * 100, 2)
        uncertain_rate = round((row.uncertain or 0) / total * 100, 2)
        return {
            "timestamp": row.timestamp,
            "packets_processed": row.total_predictions,
            "predictions_made": row.total_predictions,
            "attacks_detected": row.attacks_detected,
            "normal_traffic": row.normal_traffic,
            "uncertain": row.uncertain,
            "uptime_seconds": row.uptime_seconds,
            "attack_rate": attack_rate,
            "normal_rate": normal_rate,
            "uncertain_rate": uncertain_rate,
        }

    @staticmethod
    def _is_threat_row(row: Dict[str, Any]) -> bool:
        label = str(row.get("predicted_label", "")).upper()
        severity = str(row.get("severity", "")).upper()
        return label not in {"NORMAL", "SAFE"} or severity in {"HIGH", "CRITICAL"}
