"""
Runtime Security Monitoring API Endpoints.

Provides endpoints for recording events, querying alerts,
simulating security events, and viewing the monitoring dashboard.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from typing import List

from app.agents.models import (
    MonitoringConfig,
    RuntimeEvent,
    RuntimeEventType,
    EventSeverity,
    SimulateEventsRequest,
    SimulateEventsResponse,
)
from app.agents.runtime_monitor import RuntimeMonitor
from app.security import require_api_key

router = APIRouter(
    prefix="/api/v1/monitoring",
    tags=["monitoring"],
    dependencies=[Depends(require_api_key)],
)

_monitor = RuntimeMonitor()


@router.post("/events")
async def record_event(event: RuntimeEvent):
    recorded = _monitor.record_event(event)
    alert = _monitor.detect_anomalies(event)
    result = {"event": recorded, "alert": alert}
    return result


@router.post("/events/batch")
async def record_events_batch(events: List[RuntimeEvent]):
    results = []
    for evt in events:
        recorded = _monitor.record_event(evt)
        alert = _monitor.detect_anomalies(evt)
        results.append({"event": recorded, "alert": alert})
    return {"processed": len(results), "results": results}


@router.get("/events")
async def get_events(
    event_type: str = None,
    severity: str = None,
    limit: int = 100,
):
    etype = RuntimeEventType(event_type) if event_type else None
    sev = EventSeverity(severity) if severity else None
    events = _monitor.get_events(event_type=etype, severity=sev)
    return {"events": events[-limit:], "total": len(events)}


@router.get("/alerts")
async def get_alerts(
    event_type: str = None,
    severity: str = None,
    limit: int = 100,
):
    etype = RuntimeEventType(event_type) if event_type else None
    sev = EventSeverity(severity) if severity else None
    alerts = _monitor.get_alerts(event_type=etype, severity=sev)
    return {"alerts": alerts[-limit:], "total": len(alerts)}


@router.get("/summary")
async def get_summary():
    return _monitor.get_summary()


@router.post("/simulate")
async def simulate_events(request: SimulateEventsRequest = None):
    count = request.count if request else 10
    events = _monitor.simulate_events(count=count)
    alerts = _monitor.get_alerts()
    recent_alerts = alerts[-count:]
    return SimulateEventsResponse(
        events_created=len(events),
        alerts_triggered=len(recent_alerts),
        events=events,
        alerts=recent_alerts,
    )


@router.get("/config")
async def get_config():
    return _monitor.config


@router.put("/config")
async def update_config(config: MonitoringConfig):
    _monitor._config = config
    return {"status": "updated", "config": _monitor.config}
