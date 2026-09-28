"""Notification Dispatcher for PagerDuty and Slack escalation alerts."""
from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AlertNotification(BaseModel):
    id: str = Field(default_factory=lambda: f"notif-{uuid.uuid4().hex[:8]}")
    incident_id: str
    service: str
    channel: str  # "PAGERDUTY", "SLACK", "SMS"
    recipient: str
    title: str
    severity: str
    summary: str
    proposed_action: Optional[str] = None
    quick_approve_url: Optional[str] = None
    quick_reject_url: Optional[str] = None
    status: str = "DELIVERED"
    sent_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NotificationDispatcher:
    """
    Simulates sending instant push notifications to PagerDuty, Slack,
    and on-call engineer phones with 1-click mobile approval buttons.
    """

    def __init__(self):
        self._history: List[AlertNotification] = []

    def list_notifications(self) -> List[AlertNotification]:
        return sorted(self._history, key=lambda n: n.sent_at, reverse=True)

    def dispatch(
        self,
        incident_id: str,
        service: str,
        title: str,
        severity: str,
        summary: str,
        action_title: Optional[str] = None,
        action_id: Optional[str] = None,
        base_url: str = "http://127.0.0.1:8000",
        sent_at: Optional[str] = None,
    ) -> List[AlertNotification]:
        """Dispatch alerts across PagerDuty on-call and Slack #incidents channels."""
        dispatched: List[AlertNotification] = []
        alert_time = sent_at or datetime.now(timezone.utc).isoformat()

        approve_url = f"{base_url}/api/incidents/{incident_id}/action?token=quick_auth&action_id={action_id}&approve=true" if action_id else None
        reject_url = f"{base_url}/api/incidents/{incident_id}/action?token=quick_auth&action_id={action_id}&approve=false" if action_id else None

        # 1. PagerDuty Alert
        pd_alert = AlertNotification(
            incident_id=incident_id,
            service=service,
            channel="PAGERDUTY",
            recipient="On-Call Primary (+1-555-SRE-ALERT)",
            title=f"🚨 [PagerDuty High Urgency] {title}",
            severity=severity,
            summary=summary,
            proposed_action=action_title,
            quick_approve_url=approve_url,
            quick_reject_url=reject_url,
            sent_at=alert_time,
        )
        self._history.append(pd_alert)
        dispatched.append(pd_alert)

        # 2. Slack Alert
        slack_alert = AlertNotification(
            incident_id=incident_id,
            service=service,
            channel="SLACK",
            recipient="#sre-incident-room",
            title=f"⚡ SRE Agent Alert: {service} Degradation",
            severity=severity,
            summary=summary,
            proposed_action=action_title,
            quick_approve_url=approve_url,
            quick_reject_url=reject_url,
            sent_at=alert_time,
        )
        self._history.append(slack_alert)
        dispatched.append(slack_alert)

        return dispatched


# Global notification dispatcher instance
notification_dispatcher = NotificationDispatcher()
