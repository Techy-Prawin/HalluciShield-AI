"""
Tests for Runtime Security Monitoring (Milestone 17).
"""
import pytest
from app.agents.runtime_monitor import (
    RuntimeMonitor, MODEL_VERSION,
    EVENT_TO_VULNERABILITY_MAP, RECOMMENDED_ACTIONS,
    SUSPICIOUS_USER_AGENTS,
)
from app.agents.models import (
    EventSeverity, MonitoringConfig, RuntimeEvent,
    RuntimeEventType, SecurityAlert,
)


def _mk(**kw):
    d = dict(
        event_type=RuntimeEventType.API_ANOMALY,
        severity=EventSeverity.MEDIUM, source="test",
        description="test", endpoint="/api/v1/test",
        method="GET", client_ip="127.0.0.1",
        user_agent="test-agent",
    )
    d.update(kw)
    return RuntimeEvent(**d)


class TestEventRecording:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_assigns_id(self):
        r = self.m.record_event(_mk())
        assert r.event_id.startswith("evt-")

    def test_assigns_timestamp(self):
        r = self.m.record_event(_mk())
        assert r.detected_at is not None

    def test_sets_model_version(self):
        r = self.m.record_event(_mk())
        assert r.model_version == MODEL_VERSION

    def test_preserves_existing_id(self):
        r = self.m.record_event(_mk(event_id="evt-x1"))
        assert r.event_id == "evt-x1"

    def test_record_multiple(self):
        for _ in range(5):
            self.m.record_event(_mk())
        assert len(self.m._events) == 5


class TestApiAnomaly:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_500_high(self):
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=500)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.HIGH

    def test_429_medium(self):
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=429)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.MEDIUM

    def test_200_no_alert(self):
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=200)
        self.m.record_event(e)
        assert self.m.detect_anomalies(e) is None

    def test_slow_response(self):
        m = RuntimeMonitor(config=MonitoringConfig(response_time_threshold_ms=1000))
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=200, response_time_ms=5000)
        m.record_event(e)
        assert m.detect_anomalies(e) is not None

    def test_502_high(self):
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=502)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.HIGH

    def test_404_low(self):
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=404)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.LOW


class TestRepeatedSuspicious:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_below_threshold(self):
        e = _mk(event_type=RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST, request_count=5)
        self.m.record_event(e)
        assert self.m.detect_anomalies(e) is None

    def test_above_threshold(self):
        e = _mk(event_type=RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST, request_count=15)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.HIGH

    def test_suspicious_ua_critical(self):
        e = _mk(
            event_type=RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST,
            request_count=15, user_agent="sqlmap/1.6",
        )
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.CRITICAL
        assert a.risk_score >= 90.0


class TestErrorSpike:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_low_count_no_alert(self):
        e = _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=5)
        self.m.record_event(e)
        assert self.m.detect_anomalies(e) is None

    def test_high_count_alert(self):
        e = _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=25)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.HIGH

    def test_very_high_critical(self):
        e = _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=60)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.CRITICAL


class TestAuthAnomaly:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_below_threshold(self):
        e = _mk(event_type=RuntimeEventType.AUTH_ANOMALY, request_count=2)
        self.m.record_event(e)
        assert self.m.detect_anomalies(e) is None

    def test_above_threshold(self):
        e = _mk(event_type=RuntimeEventType.AUTH_ANOMALY, request_count=8)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.HIGH

    def test_brute_force_critical(self):
        e = _mk(
            event_type=RuntimeEventType.AUTH_ANOMALY,
            request_count=8, error_message="brute force detected",
        )
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.CRITICAL


class TestSecurityEvent:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_creates_alert(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.risk_score >= 50.0

    def test_critical_higher_risk(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT, severity=EventSeverity.CRITICAL)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.CRITICAL
        assert a.risk_score >= 80.0


class TestPerformanceRegression:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_normal_no_alert(self):
        e = _mk(event_type=RuntimeEventType.PERFORMANCE_REGRESSION, response_time_ms=500)
        self.m.record_event(e)
        assert self.m.detect_anomalies(e) is None

    def test_slow_medium(self):
        e = _mk(event_type=RuntimeEventType.PERFORMANCE_REGRESSION, response_time_ms=6000)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.MEDIUM

    def test_very_slow_high(self):
        m = RuntimeMonitor(config=MonitoringConfig(response_time_threshold_ms=1000))
        e = _mk(event_type=RuntimeEventType.PERFORMANCE_REGRESSION, response_time_ms=5000)
        m.record_event(e)
        a = m.detect_anomalies(e)
        assert a is not None and a.severity == EventSeverity.HIGH


class TestAlertProperties:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_alert_has_correct_event_type(self):
        e = _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=25)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a.event_type == RuntimeEventType.ERROR_SPIKE

    def test_alert_has_vuln_type(self):
        e = _mk(event_type=RuntimeEventType.AUTH_ANOMALY, request_count=8)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a.vulnerability_type == "BROKEN_AUTHENTICATION"

    def test_alert_has_recommended_action(self):
        e = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=500)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert len(a.recommended_action) > 0

    def test_alert_has_affected_endpoint(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT, endpoint="/api/v1/users")
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a.affected_endpoint == "/api/v1/users"

    def test_alert_id_format(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a.alert_id.startswith("alert-")

    def test_alert_has_created_at(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT)
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a.created_at is not None

    def test_alert_stored_in_list(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT)
        self.m.record_event(e)
        self.m.detect_anomalies(e)
        assert len(self.m._alerts) == 1


class TestGetEvents:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_get_all(self):
        for _ in range(3):
            self.m.record_event(_mk())
        assert len(self.m.get_events()) == 3

    def test_filter_by_type(self):
        self.m.record_event(_mk(event_type=RuntimeEventType.API_ANOMALY))
        self.m.record_event(_mk(event_type=RuntimeEventType.ERROR_SPIKE))
        assert len(self.m.get_events(event_type=RuntimeEventType.API_ANOMALY)) == 1

    def test_filter_by_severity(self):
        self.m.record_event(_mk(severity=EventSeverity.HIGH))
        self.m.record_event(_mk(severity=EventSeverity.LOW))
        assert len(self.m.get_events(severity=EventSeverity.HIGH)) == 1


class TestGetAlerts:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_get_all_alerts(self):
        e1 = _mk(event_type=RuntimeEventType.SECURITY_EVENT)
        e2 = _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=500)
        self.m.record_event(e1)
        self.m.record_event(e2)
        self.m.detect_anomalies(e1)
        self.m.detect_anomalies(e2)
        assert len(self.m.get_alerts()) == 2

    def test_filter_alerts_by_severity(self):
        e1 = _mk(event_type=RuntimeEventType.SECURITY_EVENT, severity=EventSeverity.CRITICAL)
        e2 = _mk(event_type=RuntimeEventType.SECURITY_EVENT, severity=EventSeverity.LOW)
        self.m.record_event(e1)
        self.m.record_event(e2)
        self.m.detect_anomalies(e1)
        self.m.detect_anomalies(e2)
        assert len(self.m.get_alerts(severity=EventSeverity.CRITICAL)) == 1


class TestSummary:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_empty_summary(self):
        s = self.m.get_summary()
        assert s.total_events == 0
        assert s.total_alerts == 0

    def test_summary_after_events(self):
        e = _mk(event_type=RuntimeEventType.SECURITY_EVENT)
        self.m.record_event(e)
        self.m.detect_anomalies(e)
        s = self.m.get_summary()
        assert s.total_events == 1
        assert s.total_alerts == 1

    def test_summary_events_by_type(self):
        self.m.record_event(_mk(event_type=RuntimeEventType.API_ANOMALY))
        self.m.record_event(_mk(event_type=RuntimeEventType.API_ANOMALY))
        self.m.record_event(_mk(event_type=RuntimeEventType.ERROR_SPIKE))
        s = self.m.get_summary()
        assert s.events_by_type["API_ANOMALY"] == 2
        assert s.events_by_type["ERROR_SPIKE"] == 1

    def test_summary_events_by_severity(self):
        self.m.record_event(_mk(severity=EventSeverity.HIGH))
        self.m.record_event(_mk(severity=EventSeverity.LOW))
        s = self.m.get_summary()
        assert s.events_by_severity["HIGH"] == 1
        assert s.events_by_severity["LOW"] == 1

    def test_summary_has_uptime(self):
        s = self.m.get_summary()
        assert s.uptime_seconds >= 0

    def test_summary_has_config(self):
        s = self.m.get_summary()
        assert isinstance(s.monitoring_config, MonitoringConfig)

    def test_summary_top_endpoints(self):
        for _ in range(5):
            self.m.record_event(_mk(endpoint="/api/v1/hot"))
        self.m.record_event(_mk(endpoint="/api/v1/cold"))
        s = self.m.get_summary()
        assert len(s.top_anomaly_endpoints) >= 1
        assert s.top_anomaly_endpoints[0]["endpoint"] == "/api/v1/hot"
        assert s.top_anomaly_endpoints[0]["count"] == 5

    def test_summary_recent_events_capped(self):
        for _ in range(25):
            self.m.record_event(_mk())
        s = self.m.get_summary()
        assert len(s.recent_events) <= 20


class TestSimulation:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_simulate_creates_events(self):
        events = self.m.simulate_events(count=5)
        assert len(events) == 5

    def test_simulate_events_have_ids(self):
        events = self.m.simulate_events(count=3)
        for e in events:
            assert e.event_id.startswith("evt-")

    def test_simulate_events_stored(self):
        self.m.simulate_events(count=10)
        assert len(self.m._events) == 10

    def test_simulate_generates_alerts(self):
        self.m.simulate_events(count=50)
        assert len(self.m._alerts) > 0

    def test_simulate_varies_event_types(self):
        events = self.m.simulate_events(count=50)
        types = set(e.event_type for e in events)
        assert len(types) > 1


class TestEventToVulnMapping:
    def test_all_event_types_mapped(self):
        for etype in RuntimeEventType:
            assert etype in EVENT_TO_VULNERABILITY_MAP

    def test_all_recommended_actions(self):
        for etype in RuntimeEventType:
            assert etype in RECOMMENDED_ACTIONS


class TestModelVersion:
    def test_model_version_constant(self):
        assert MODEL_VERSION == "v1.0"

    def test_model_version_set_on_event(self):
        m = RuntimeMonitor()
        e = _mk()
        r = m.record_event(e)
        assert r.model_version == MODEL_VERSION

    def test_model_version_property(self):
        m = RuntimeMonitor()
        assert m.model_version == MODEL_VERSION


class TestMonitoringConfig:
    def test_default_config(self):
        m = RuntimeMonitor()
        assert m.config.error_rate_threshold == 0.1
        assert m.config.response_time_threshold_ms == 5000
        assert m.config.suspicious_request_threshold == 10
        assert m.config.auth_failure_threshold == 5

    def test_custom_config(self):
        cfg = MonitoringConfig(
            error_rate_threshold=0.2,
            response_time_threshold_ms=2000,
            suspicious_request_threshold=20,
        )
        m = RuntimeMonitor(config=cfg)
        assert m.config.error_rate_threshold == 0.2
        assert m.config.response_time_threshold_ms == 2000
        assert m.config.suspicious_request_threshold == 20


class TestEdgeCases:
    def setup_method(self):
        self.m = RuntimeMonitor()

    def test_no_endpoint_event(self):
        e = RuntimeEvent(
            event_type=RuntimeEventType.SECURITY_EVENT,
            severity=EventSeverity.MEDIUM,
            source="test", description="test",
            endpoint="", method="GET",
            client_ip="127.0.0.1", user_agent="test",
        )
        self.m.record_event(e)
        a = self.m.detect_anomalies(e)
        assert a is not None
        assert a.affected_endpoint == ""

    def test_all_event_types_detectable(self):
        events = [
            _mk(event_type=RuntimeEventType.API_ANOMALY, status_code=500),
            _mk(event_type=RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST, request_count=15),
            _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=25),
            _mk(event_type=RuntimeEventType.AUTH_ANOMALY, request_count=8),
            _mk(event_type=RuntimeEventType.SECURITY_EVENT),
            _mk(event_type=RuntimeEventType.PERFORMANCE_REGRESSION, response_time_ms=6000),
        ]
        for e in events:
            self.m.record_event(e)
            a = self.m.detect_anomalies(e)
            assert a is not None, f"No alert for {e.event_type}"

    def test_custom_threshold_changes_detection(self):
        cfg = MonitoringConfig(
            suspicious_request_threshold=3,
            auth_failure_threshold=2,
        )
        m = RuntimeMonitor(config=cfg)
        e = _mk(event_type=RuntimeEventType.REPEATED_SUSPICIOUS_REQUEST, request_count=5)
        m.record_event(e)
        a = m.detect_anomalies(e)
        assert a is not None

    def test_deterministic_detection(self):
        e1 = _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=25)
        e2 = _mk(event_type=RuntimeEventType.ERROR_SPIKE, request_count=25)
        m1 = RuntimeMonitor()
        m2 = RuntimeMonitor()
        m1.record_event(e1)
        m2.record_event(e2)
        a1 = m1.detect_anomalies(e1)
        a2 = m2.detect_anomalies(e2)
        assert a1.severity == a2.severity
        assert a1.risk_score == a2.risk_score
