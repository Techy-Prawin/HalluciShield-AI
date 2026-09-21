"""
Runtime Security Monitoring Agent for HalluciShield AI.

Records and analyzes runtime events to detect security anomalies.
Simulation mode only - no real production connections.
"""
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.agents.models import (
    EventSeverity,
    MonitoringConfig,
    MonitoringSummary,
    RuntimeEvent,
    RuntimeEventType,
    SecurityAlert,
)

logger = logging.getLogger(__name__)

MODEL_VERSION = "v1.0"

EVENT_TO_VULNERABILITY_MAP = {
    RuntimeEventType.API_ANOMALY: "SECURITY_MISCONFIGURATION",
    RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST: "BROKEN_AUTHENTICATION",
    RuntimeEventType.ERROR_SPIKE: "SENSITIVE_DATA_EXPOSURE",
    RuntimeEventType.AUTH_ANOMALY: "BROKEN_AUTHENTICATION",
    RuntimeEventType.SECURITY_EVENT: "SECURITY_MISCONFIGURATION",
    RuntimeEventType.PERFORMANCE_REGRESSION: "SENSITIVE_DATA_EXPOSURE",
}

RECOMMENDED_ACTIONS = {
    RuntimeEventType.API_ANOMALY: "Investigate API endpoint for injection vulnerabilities",
    RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST: "Review authentication and rate limiting",
    RuntimeEventType.ERROR_SPIKE: "Check for information disclosure in error messages",
    RuntimeEventType.AUTH_ANOMALY: "Audit authentication and session management",
    RuntimeEventType.SECURITY_EVENT: "Perform comprehensive security review of affected endpoint",
    RuntimeEventType.PERFORMANCE_REGRESSION: "Profile endpoint for resource exhaustion",
}

SIMULATED_ENDPOINTS = [
    "/api/v1/users",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/data/query",
    "/api/v1/files/upload",
    "/api/v1/admin/settings",
    "/api/v1/payments/process",
    "/api/v1/search",
]

SIMULATED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "masscan", "nmap",
    "dirbuster", "gobuster", "wfuzz", "burpsuite",
]

SIMULATED_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "sqlmap/1.6",
    "nikto/2.1.6",
]

SIMULATED_IPS = [
    "192.168.1.100",
    "10.0.0.50",
    "172.16.0.25",
    "203.0.113.50",
    "198.51.100.23",
]


class RuntimeMonitor:

    def __init__(self, config: Optional[MonitoringConfig] = None):
        self._config = config or MonitoringConfig()
        self._events: List[RuntimeEvent] = []
        self._alerts: List[SecurityAlert] = []
        self._start_time = datetime.now(timezone.utc)
        self._model_version = MODEL_VERSION

    @property
    def config(self) -> MonitoringConfig:
        return self._config

    @property
    def model_version(self) -> str:
        return self._model_version

    def record_event(self, event: RuntimeEvent) -> RuntimeEvent:
        if not event.event_id:
            event.event_id = "evt-" + uuid.uuid4().hex[:12]
        if not event.detected_at:
            event.detected_at = datetime.now(timezone.utc).isoformat()
        event.model_version = self._model_version
        self._events.append(event)
        return event

    def detect_anomalies(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        alert = None
        if event.event_type == RuntimeEventType.API_ANOMALY:
            alert = self._detect_api_anomaly(event)
        elif event.event_type == RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST:
            alert = self._detect_repeated_suspicious(event)
        elif event.event_type == RuntimeEventType.ERROR_SPIKE:
            alert = self._detect_error_spike(event)
        elif event.event_type == RuntimeEventType.AUTH_ANOMALY:
            alert = self._detect_auth_anomaly(event)
        elif event.event_type == RuntimeEventType.SECURITY_EVENT:
            alert = self._detect_security_event(event)
        elif event.event_type == RuntimeEventType.PERFORMANCE_REGRESSION:
            alert = self._detect_performance_regression(event)
        if alert:
            self._alerts.append(alert)
        return alert

    def _detect_api_anomaly(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        severity = EventSeverity.LOW
        risk_score = 20.0
        triggered = False
        if event.status_code and event.status_code >= 500:
            severity = EventSeverity.HIGH
            risk_score = 70.0
            triggered = True
        elif event.status_code and event.status_code == 429:
            severity = EventSeverity.MEDIUM
            risk_score = 50.0
            triggered = True
        elif event.status_code and event.status_code >= 400:
            severity = EventSeverity.LOW
            risk_score = 20.0
            triggered = True
        if (event.response_time_ms
                and event.response_time_ms > self._config.response_time_threshold_ms):
            severity = EventSeverity.MEDIUM
            risk_score = max(risk_score, 40.0)
            triggered = True
        if triggered:
            return self._create_alert(event=event, severity=severity, risk_score=risk_score)
        return None

    def _detect_repeated_suspicious(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        if event.request_count >= self._config.suspicious_request_threshold:
            severity = EventSeverity.HIGH
            risk_score = 80.0
            is_suspicious = any(
                s in (event.user_agent or "").lower() for s in SUSPICIOUS_USER_AGENTS
            )
            if is_suspicious:
                severity = EventSeverity.CRITICAL
                risk_score = 95.0
            return self._create_alert(event=event, severity=severity, risk_score=risk_score)
        return None

    def _detect_error_spike(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        if event.request_count >= 20:
            severity = EventSeverity.HIGH
            risk_score = 75.0
            if event.request_count >= 50:
                severity = EventSeverity.CRITICAL
                risk_score = 90.0
            return self._create_alert(event=event, severity=severity, risk_score=risk_score)
        return None

    def _detect_auth_anomaly(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        severity = EventSeverity.HIGH
        risk_score = 85.0
        if event.error_message and "brute" in event.error_message.lower():
            severity = EventSeverity.CRITICAL
            risk_score = 95.0
        if event.request_count >= self._config.auth_failure_threshold:
            return self._create_alert(event=event, severity=severity, risk_score=risk_score)
        return None

    def _detect_security_event(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        severity = EventSeverity.MEDIUM
        risk_score = 60.0
        if event.severity in (EventSeverity.CRITICAL, EventSeverity.HIGH):
            severity = event.severity
            risk_score = 85.0 if event.severity == EventSeverity.CRITICAL else 70.0
        return self._create_alert(event=event, severity=severity, risk_score=risk_score)

    def _detect_performance_regression(self, event: RuntimeEvent) -> Optional[SecurityAlert]:
        if (event.response_time_ms
                and event.response_time_ms > self._config.response_time_threshold_ms):
            severity = EventSeverity.MEDIUM
            risk_score = 50.0
            if event.response_time_ms > self._config.response_time_threshold_ms * 3:
                severity = EventSeverity.HIGH
                risk_score = 75.0
            return self._create_alert(event=event, severity=severity, risk_score=risk_score)
        return None

    def _create_alert(
        self,
        event: RuntimeEvent,
        severity: EventSeverity,
        risk_score: float,
    ) -> SecurityAlert:
        vuln_type = EVENT_TO_VULNERABILITY_MAP.get(event.event_type, "UNKNOWN")
        recommended = RECOMMENDED_ACTIONS.get(
            event.event_type, "Investigate the reported anomaly"
        )
        return SecurityAlert(
            alert_id="alert-" + uuid.uuid4().hex[:12],
            event_id=event.event_id,
            event_type=event.event_type,
            severity=severity,
            vulnerability_type=vuln_type,
            vulnerability_description=(
                "Runtime " + event.event_type.value.replace("_", " ")
                + " detected at " + (event.endpoint or "unknown endpoint")
            ),
            affected_endpoint=event.endpoint or "",
            risk_score=risk_score,
            recommended_action=recommended,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def get_events(
        self,
        event_type: Optional[RuntimeEventType] = None,
        severity: Optional[EventSeverity] = None,
    ) -> List[RuntimeEvent]:
        events = self._events
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            events = [e for e in events if e.severity == severity]
        return events

    def get_alerts(
        self,
        event_type: Optional[RuntimeEventType] = None,
        severity: Optional[EventSeverity] = None,
    ) -> List[SecurityAlert]:
        alerts = self._alerts
        if event_type:
            alerts = [a for a in alerts if a.event_type == event_type]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts

    def get_summary(self) -> MonitoringSummary:
        total_events = len(self._events)
        total_alerts = len(self._alerts)

        events_by_type: Dict[str, int] = {}
        for e in self._events:
            key = e.event_type.value
            events_by_type[key] = events_by_type.get(key, 0) + 1

        events_by_severity: Dict[str, int] = {}
        for e in self._events:
            key = e.severity.value
            events_by_severity[key] = events_by_severity.get(key, 0) + 1

        alerts_by_severity: Dict[str, int] = {}
        for a in self._alerts:
            key = a.severity.value
            alerts_by_severity[key] = alerts_by_severity.get(key, 0) + 1

        endpoint_counts: Dict[str, int] = {}
        for e in self._events:
            if e.endpoint:
                endpoint_counts[e.endpoint] = endpoint_counts.get(e.endpoint, 0) + 1
        top_endpoints = sorted(
            endpoint_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        top_anomaly_endpoints = [
            {"endpoint": ep, "count": cnt} for ep, cnt in top_endpoints
        ]

        uptime = int((datetime.now(timezone.utc) - self._start_time).total_seconds())
        last_event = self._events[-1].detected_at if self._events else None

        return MonitoringSummary(
            total_events=total_events,
            total_alerts=total_alerts,
            events_by_type=events_by_type,
            events_by_severity=events_by_severity,
            alerts_by_severity=alerts_by_severity,
            recent_events=self._events[-20:],
            recent_alerts=self._alerts[-20:],
            top_anomaly_endpoints=top_anomaly_endpoints,
            monitoring_config=self._config,
            uptime_seconds=uptime,
            last_event_at=last_event,
        )

    def simulate_events(self, count: int = 10) -> List[RuntimeEvent]:
        events = []
        event_types = list(RuntimeEventType)
        for _ in range(count):
            etype = random.choice(event_types)
            severity = random.choice(list(EventSeverity))
            endpoint = random.choice(SIMULATED_ENDPOINTS)
            method = random.choice(SIMULATED_METHODS)
            ua = random.choice(SIMULATED_USER_AGENTS)
            ip = random.choice(SIMULATED_IPS)

            event = RuntimeEvent(
                event_type=etype,
                severity=severity,
                source="simulation",
                description="Simulated " + etype.value.replace("_", " ").lower(),
                endpoint=endpoint,
                method=method,
                client_ip=ip,
                user_agent=ua,
            )

            if etype == RuntimeEventType.API_ANOMALY:
                event.status_code = random.choice([400, 403, 404, 429, 500, 502, 503])
                event.response_time_ms = random.randint(100, 10000)
            elif etype == RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST:
                event.request_count = random.randint(5, 100)
                if random.random() < 0.3:
                    event.user_agent = random.choice(SUSPICIOUS_USER_AGENTS)
            elif etype == RuntimeEventType.ERROR_SPIKE:
                event.request_count = random.randint(10, 80)
                event.status_code = random.choice([500, 502, 503])
            elif etype == RuntimeEventType.AUTH_ANOMALY:
                event.request_count = random.randint(3, 20)
                event.error_message = "Invalid credentials"
            elif etype == RuntimeEventType.SECURITY_EVENT:
                event.status_code = random.choice([401, 403])
            elif etype == RuntimeEventType.PERFORMANCE_REGRESSION:
                event.response_time_ms = random.randint(5000, 30000)

            recorded = self.record_event(event)
            self.detect_anomalies(recorded)
            events.append(recorded)

        return events
