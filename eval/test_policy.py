"""Tests for Autonomous Night Mode, Safety Guardrails, and Escalations."""
import pytest
from datetime import datetime, timezone, timedelta
from agent.agent import IncidentResponseAgent
from agent.models import (
    ApprovalStatus,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    RemediationAction,
    ActionType,
    DeployEvidence,
)
from agent.policy_engine import PolicyEngine, PolicyMode, AutoRemediationPolicy
from tools.notification_tool import NotificationDispatcher


def test_policy_manual_mode_blocks_auto_execution():
    policy_engine = PolicyEngine(AutoRemediationPolicy(mode=PolicyMode.MANUAL))
    agent = IncidentResponseAgent()
    inc = agent.investigate("checkout-service")
    assert inc.actions
    eval_res = policy_engine.evaluate_action(inc, inc.actions[0])
    assert not eval_res.can_execute
    assert "MANUAL" in eval_res.reason


def test_policy_autonomous_mode_allows_high_confidence_low_risk():
    policy_engine = PolicyEngine(AutoRemediationPolicy(mode=PolicyMode.AUTONOMOUS, confidence_threshold=0.90))
    agent = IncidentResponseAgent()
    inc = agent.investigate("checkout-service")
    assert inc.actions
    eval_res = policy_engine.evaluate_action(inc, inc.actions[0])
    assert eval_res.can_execute
    assert eval_res.confidence_passed
    assert eval_res.risk_passed
    assert eval_res.safety_checks_passed


def test_policy_blocks_low_confidence_action():
    policy_engine = PolicyEngine(AutoRemediationPolicy(mode=PolicyMode.AUTONOMOUS, confidence_threshold=0.99))
    agent = IncidentResponseAgent()
    inc = agent.investigate("checkout-service")
    eval_res = policy_engine.evaluate_action(inc, inc.actions[0])
    # checkout-service confidence is 0.98, threshold is 0.99 -> should fail
    assert not eval_res.can_execute
    assert not eval_res.confidence_passed


def test_policy_blocks_database_migrations_guardrail():
    policy_engine = PolicyEngine(AutoRemediationPolicy(mode=PolicyMode.AUTONOMOUS, require_zero_db_migrations=True))
    agent = IncidentResponseAgent()
    inc = agent.investigate("checkout-service")
    
    # Simulate suspect deployment that included a DB migration
    inc.deploy_evidence.suspect_deployment["commit_message"] = "feat: add schema migration for payment tables"
    eval_res = policy_engine.evaluate_action(inc, inc.actions[0])
    assert not eval_res.can_execute
    assert not eval_res.safety_checks_passed
    assert "database safety guardrail" in eval_res.reason.lower()


def test_timed_fallback_dead_mans_switch():
    agent = IncidentResponseAgent()
    agent.policy_engine.update_policy(mode=PolicyMode.TIMED_FALLBACK, auto_execute_delay_seconds=1)
    
    # Investigate triggers timed deadline
    inc = agent.investigate("checkout-service")
    assert inc.status == IncidentStatus.ACTION_PROPOSED
    assert inc.auto_mitigate_deadline is not None
    
    # Fast forward deadline to the past
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    inc.auto_mitigate_deadline = past_iso
    
    # Run fallback check
    mitigated = agent.check_timed_fallbacks()
    assert len(mitigated) == 1
    assert inc.status == IncidentStatus.MITIGATED
    assert inc.auto_mitigated is True
    assert inc.actions[0].approval_status == ApprovalStatus.EXECUTED
    assert "Timed Fallback" in inc.actions[0].reviewer


def test_notification_dispatcher_generates_quick_links():
    dispatcher = NotificationDispatcher()
    alerts = dispatcher.dispatch(
        incident_id="inc-test-123",
        service="checkout-service",
        title="CRITICAL: Outage",
        severity="CRITICAL",
        summary="NPE crash detected",
        action_title="Rollback to v2.3.9",
        action_id="act-test-rollback",
    )
    assert len(alerts) == 2
    pd_alert = [a for a in alerts if a.channel == "PAGERDUTY"][0]
    slack_alert = [a for a in alerts if a.channel == "SLACK"][0]
    
    assert pd_alert.quick_approve_url is not None
    assert "approve=true" in pd_alert.quick_approve_url
    assert "approve=false" in pd_alert.quick_reject_url
    assert slack_alert.channel == "SLACK"
