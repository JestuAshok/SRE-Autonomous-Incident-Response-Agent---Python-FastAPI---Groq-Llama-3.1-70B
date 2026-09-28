"""FastAPI application for Incident Response Agent."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.agent import agent_instance
from agent.models import Incident, RemediationAction, IncidentStatus
from agent.policy_engine import PolicyMode
from tools.deploy_tool import get_deploy_history
from tools.log_tool import read_logs
from tools.metrics_tool import detect_anomalies, get_metrics

app = FastAPI(
    title="Incident Response Agent Service",
    description="Autonomous Agent for triage, root cause correlation, and automated remediation approvals.",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UI_DIR = Path(__file__).resolve().parent.parent / "ui"


# Request / Response Schemas
class AnalyzeRequest(BaseModel):
    service: str
    title: Optional[str] = None
    description: Optional[str] = None


class AlertDiagnoseRequest(BaseModel):
    alert: str
    service: Optional[str] = None


class ActionDecisionRequest(BaseModel):
    action_id: str
    approve: bool
    reviewer: Optional[str] = "oncall_lead@company.com"


class PolicyUpdateRequest(BaseModel):
    mode: Optional[str] = None
    confidence_threshold: Optional[float] = None
    auto_execute_delay_seconds: Optional[int] = None
    require_zero_db_migrations: Optional[bool] = None


# Pre-seed default incidents on startup (real-world famous outages & production scenarios)
@app.on_event("startup")
def startup_event():
    """Seed initial demonstration incidents on service startup."""
    agent_instance.policy_engine.update_policy(mode=PolicyMode.MANUAL)
    if not agent_instance.list_incidents():
        agent_instance.investigate(
            service_name="crowdstrike-sensor",
            title="🚨 GLOBAL HOST CRASH: CrowdStrike Falcon Sensor Kernel Panic (BugCheck 0x50) After Channel File 291",
            description="Automated PagerDuty alert: Host crash rate surged to 94.2% and kernel driver csagent.sys encountered PAGE_FAULT_IN_NONPAGED_AREA at csagent.sys:184 following Channel File 291 content rollout.",
        )
        agent_instance.investigate(
            service_name="cloudflare-edge",
            title="🔥 GLOBAL OUTAGE: Cloudflare Edge 100% CPU Saturation & HTTP 502 Wave Post-WAF Rule Deploy",
            description="Automated Datadog alert: Edge proxy 502 Bad Gateway rate surged to 88.5% and CPU pegged at 99.8% across worker processes due to catastrophic regex backtracking in ManagedRulesEngine.lua:214.",
        )
        agent_instance.investigate(
            service_name="checkout-service",
            title="🛒 CRITICAL: 5xx Error Rate Spike & P99 Latency Degradation in Checkout Flow",
            description="Automated PagerDuty alert: checkout-service error rate spiked to 52.3% and P99 latency exceeded 4,000ms following deployment v2.4.0.",
        )
        agent_instance.investigate(
            service_name="payment-gateway",
            title="💳 UPSTREAM ALERT: Third-Party Stripe API HTTP 503 Global Outage (Red Herring)",
            description="Automated Sentry alert: Stripe API returning HTTP 503 Service Unavailable on payment captures. Deploy v1.5.2 is benign; vendor outage identified.",
        )


# API Endpoints
@app.get("/api/incidents", response_model=List[Incident])
def list_incidents():
    """List all tracked incidents."""
    return agent_instance.list_incidents()


@app.get("/api/incidents/reset-demo")
@app.post("/api/incidents/reset-demo")
def reset_demo_incidents():
    """Reset the system to the canonical demonstration incidents in MANUAL mode."""
    agent_instance.policy_engine.update_policy(mode=PolicyMode.MANUAL)
    agent_instance._incidents.clear()
    agent_instance._audit_log.clear()
    agent_instance.notification_dispatcher._history.clear()

    inc1 = agent_instance.investigate(
        service_name="crowdstrike-sensor",
        title="🚨 GLOBAL HOST CRASH: CrowdStrike Falcon Sensor Kernel Panic (BugCheck 0x50) After Channel File 291",
        description="Automated PagerDuty alert: Host crash rate surged to 94.2% and kernel driver csagent.sys encountered PAGE_FAULT_IN_NONPAGED_AREA at csagent.sys:184 following Channel File 291 content rollout.",
    )
    inc2 = agent_instance.investigate(
        service_name="cloudflare-edge",
        title="🔥 GLOBAL OUTAGE: Cloudflare Edge 100% CPU Saturation & HTTP 502 Wave Post-WAF Rule Deploy",
        description="Automated Datadog alert: Edge proxy 502 Bad Gateway rate surged to 88.5% and CPU pegged at 99.8% across worker processes due to catastrophic regex backtracking in ManagedRulesEngine.lua:214.",
    )
    inc3 = agent_instance.investigate(
        service_name="checkout-service",
        title="🛒 CRITICAL: 5xx Error Rate Spike & P99 Latency Degradation in Checkout Flow",
        description="Automated PagerDuty alert: checkout-service error rate spiked to 52.3% and P99 latency exceeded 4,000ms following deployment v2.4.0.",
    )
    inc4 = agent_instance.investigate(
        service_name="payment-gateway",
        title="💳 UPSTREAM ALERT: Third-Party Stripe API HTTP 503 Global Outage (Red Herring)",
        description="Automated Sentry alert: Stripe API returning HTTP 503 Service Unavailable on payment captures. Deploy v1.5.2 is benign; vendor outage identified.",
    )
    return {"status": "ok", "message": "Reset to demo incidents in MANUAL mode", "incidents": [inc1, inc2, inc3, inc4]}


@app.post("/api/incidents/analyze", response_model=Incident)
def analyze_incident(req: AnalyzeRequest):
    """Trigger agent investigation for a given service."""
    incident = agent_instance.investigate(
        service_name=req.service,
        title=req.title,
        description=req.description,
    )
    return incident


@app.post("/api/agent/diagnose")
def diagnose_alert(req: AlertDiagnoseRequest):
    """Trigger Groq AI multi-signal forensic diagnosis for an alert."""
    return agent_instance.diagnose_alert(alert=req.alert, service_name=req.service)



@app.get("/api/incidents/{incident_id}", response_model=Incident)
@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str):
    """Get full incident diagnostic report by ID."""
    incident = agent_instance.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/incidents/{incident_id}/action", response_model=RemediationAction)
@app.post("/incidents/{incident_id}/action", response_model=RemediationAction)
def take_action(incident_id: str, req: ActionDecisionRequest):
    """
    Approve or reject a remediation action requiring human confirmation.
    The agent NEVER auto-executes a fix - it only proposes one.
    """
    try:
        updated_action = agent_instance.handle_action(
            incident_id=incident_id,
            action_id=req.action_id,
            approve=req.approve,
            reviewer=req.reviewer or "oncall_lead@company.com",
        )
        return updated_action
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/decisions")
@app.get("/decisions")
def list_decisions():
    """Retrieve decision audit trail for all approved and rejected remediation actions."""
    return agent_instance.list_decisions()


@app.get("/api/policy")
def get_policy():
    """Retrieve current auto-remediation policy configuration."""
    return agent_instance.policy_engine.get_policy()


@app.post("/api/policy")
def update_policy(req: PolicyUpdateRequest):
    """Update auto-remediation policy configuration (e.g. toggle Night Mode)."""
    updated = agent_instance.policy_engine.update_policy(**req.model_dump(exclude_none=True))
    # When user explicitly enables TIMED_FALLBACK, set 30s countdown on pending proposed actions
    if updated.mode == PolicyMode.TIMED_FALLBACK:
        now = datetime.now(timezone.utc)
        delay_sec = updated.auto_execute_delay_seconds
        for inc in agent_instance._incidents.values():
            if inc.status == IncidentStatus.ACTION_PROPOSED and inc.actions and not inc.auto_mitigate_deadline:
                inc.auto_mitigate_deadline = (now + timedelta(seconds=delay_sec)).isoformat()
    elif updated.mode == PolicyMode.MANUAL:
        for inc in agent_instance._incidents.values():
            inc.auto_mitigate_deadline = None
    return updated


@app.post("/api/incidents/{incident_id}/start-timer")
def start_incident_timer(incident_id: str, delay_seconds: Optional[int] = 30):
    """Explicitly start a 30s auto-remediation countdown on this incident when clicked."""
    incident = agent_instance.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status != IncidentStatus.ACTION_PROPOSED or not incident.actions:
        raise HTTPException(status_code=400, detail="Incident is not in an actionable proposed state")

    delay = delay_seconds or agent_instance.policy_engine.policy.auto_execute_delay_seconds
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(seconds=delay)
    incident.auto_mitigate_deadline = deadline.isoformat()
    # Also ensure policy mode allows timed fallback
    agent_instance.policy_engine.update_policy(mode=PolicyMode.TIMED_FALLBACK)
    return {"status": "ok", "deadline": incident.auto_mitigate_deadline, "seconds": delay}


@app.post("/api/incidents/{incident_id}/pause-timer")
def pause_incident_timer(incident_id: str):
    """Pause/cancel the auto-remediation countdown on this incident."""
    incident = agent_instance.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.auto_mitigate_deadline = None
    return {"status": "ok", "message": "Countdown paused"}


@app.get("/api/notifications")
def list_notifications():
    """List sent PagerDuty / Slack escalation notifications."""
    return agent_instance.notification_dispatcher.list_notifications()


@app.post("/api/policy/check-fallbacks")
def check_fallbacks():
    """Trigger checking of dead man's switch timed fallbacks."""
    mitigated = agent_instance.check_timed_fallbacks()
    return {"mitigated_count": len(mitigated), "mitigated": [m.id for m in mitigated]}


@app.get("/api/incidents/{incident_id}/quick-action")
def quick_action(incident_id: str, action_id: str, approve: bool, reviewer: Optional[str] = "mobile_oncall@company.com"):
    """1-click mobile URL for approving/rejecting from Slack or PagerDuty SMS."""
    try:
        updated_action = agent_instance.handle_action(
            incident_id=incident_id,
            action_id=action_id,
            approve=approve,
            reviewer=reviewer or "mobile_oncall@company.com",
        )
        return {
            "status": "success",
            "message": f"Action {'APPROVED' if approve else 'REJECTED'} successfully via mobile 1-click URL.",
            "action": updated_action,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))




# Direct Tool Inspection Endpoints
@app.get("/api/tools/logs")
def tool_query_logs(
    service: str,
    level: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 100,
):
    """Directly query logs tool."""
    return read_logs(service_name=service, level=level, keyword=keyword, limit=limit)


@app.get("/api/tools/deployments")
def tool_query_deployments(service: Optional[str] = None, limit: int = 10):
    """Directly query deployments tool."""
    return get_deploy_history(service_name=service, limit=limit)


@app.get("/api/tools/metrics")
def tool_query_metrics(service: str, metric_name: Optional[str] = None):
    """Directly query metrics tool."""
    return {
        "metrics": get_metrics(service_name=service, metric_name=metric_name),
        "anomalies": detect_anomalies(service_name=service),
    }


# Static UI Mount & Root Handler
if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")


@app.get("/")
def read_root():
    """Serve the Incident Command UI."""
    index_path = UI_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"status": "ok", "message": "Incident Response Agent API is running"}
