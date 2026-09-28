"""Pytest suite for Incident Response Agent."""
import pytest
from agent.agent import IncidentResponseAgent
from agent.models import ActionType, ApprovalStatus, IncidentSeverity, IncidentStatus
from tools.deploy_tool import get_deploy_history, get_latest_deployment
from tools.log_tool import read_logs
from tools.metrics_tool import detect_anomalies, get_metrics


def test_log_tool_read_and_parse():
    """Verify log tool parses logs and extracts stack traces properly."""
    logs = read_logs("checkout-service")
    assert len(logs) > 0

    error_logs = [l for l in logs if l["level"] == "ERROR"]
    assert len(error_logs) >= 4

    # Check for NullPointerException stack trace
    has_npe = any("NullPointerException" in (l.get("stack_trace") or "") for l in error_logs)
    assert has_npe is True


def test_deploy_tool():
    """Verify deploy tool reads and filters deployment events."""
    deploys = get_deploy_history("checkout-service")
    assert len(deploys) >= 2
    latest = deploys[0]
    assert latest["version"] == "v2.4.0"
    assert latest["commit_hash"] == "a9f4c3b"
    assert latest["rollback_version"] == "v2.3.9"


def test_metrics_tool_anomaly_detection():
    """Verify anomaly detection catches error rate and latency spikes."""
    anomalies = detect_anomalies("checkout-service")
    assert len(anomalies) >= 1

    error_anomaly = next((a for a in anomalies if "error" in a["metric_name"]), None)
    assert error_anomaly is not None
    assert error_anomaly["peak_value"] > 40.0
    assert error_anomaly["severity"] == "CRITICAL"


def test_incident_agent_investigation_and_remediation():
    """End-to-end test of agent investigation on checkout-service regression."""
    agent = IncidentResponseAgent()
    incident = agent.investigate("checkout-service")

    # 1. Verification of Incident attributes
    assert incident.service == "checkout-service"
    assert incident.severity == IncidentSeverity.CRITICAL
    assert incident.status == IncidentStatus.ACTION_PROPOSED

    # 2. Verification of Root Cause
    rc = incident.root_cause
    assert rc is not None
    assert rc.culprit_commit == "a9f4c3b"
    assert "NullPointerException" in rc.exception_type
    assert rc.faulty_file_and_line == "PaymentMethodValidator.java:142"
    assert rc.confidence >= 0.90

    # 3. Verification of Action Proposal
    assert len(incident.actions) == 1
    action = incident.actions[0]
    assert action.action_type == ActionType.ROLLBACK_DEPLOYMENT
    assert action.target_version == "v2.3.9"
    assert action.approval_status == ApprovalStatus.PENDING

    # 4. Verification of Action Approval Execution (Human in the Loop)
    executed_action = agent.handle_action(
        incident_id=incident.id,
        action_id=action.action_id,
        approve=True,
        reviewer="lead_sre@company.com",
    )
    assert executed_action.approval_status == ApprovalStatus.EXECUTED
    assert incident.status == IncidentStatus.MITIGATED
    assert executed_action.execution_result["status"] == "SUCCESS"
    assert executed_action.reviewer == "lead_sre@company.com"


def test_incident_agent_action_rejection():
    """Test human rejecting proposed action."""
    agent = IncidentResponseAgent()
    incident = agent.investigate("checkout-service")
    action = incident.actions[0]

    rejected_action = agent.handle_action(
        incident_id=incident.id,
        action_id=action.action_id,
        approve=False,
        reviewer="incident_commander@company.com",
    )
    assert rejected_action.approval_status == ApprovalStatus.REJECTED
    assert incident.status == IncidentStatus.ACTION_REJECTED
    assert rejected_action.execution_result["status"] == "CANCELLED"


def test_claude_diagnosis_agent_alert_investigation():
    """Verify ClaudeDiagnosisAgent diagnoses alert, cites log/deploy evidence, and outputs structured JSON report."""
    from agent.diagnosis_agent import ClaudeDiagnosisAgent

    agent = ClaudeDiagnosisAgent()
    report = agent.diagnose("CRITICAL: checkout-service error rate spiked at 2026-09-01T10:14:00Z")

    # 1. Structure validation
    assert report.root_cause_hypothesis != ""
    assert report.confidence_score >= 0.90
    assert len(report.supporting_evidence) >= 2
    assert report.risk_level == "LOW"

    # 2. Evidence citation checks (specific log lines and deploy IDs)
    evidence_text = " ".join(report.supporting_evidence)
    assert "dep-checkout-240" in evidence_text or "a9f4c3b" in evidence_text
    assert "PaymentMethodValidator" in evidence_text or "NullPointerException" in evidence_text
    assert "error_rate_5xx_pct" in evidence_text or "spiked" in evidence_text

    # 3. Recommended action validation
    rec_action = report.recommended_action
    assert rec_action["action_type"] == "ROLLBACK_DEPLOYMENT"
    assert rec_action["target_service"] == "checkout-service"
    assert rec_action["target_version"] == "v2.3.9"
    assert "kubectl rollout undo" in rec_action["command"]


def test_claude_diagnosis_agent_low_confidence_on_healthy_service():
    """Verify agent reports low confidence rather than guessing when telemetry is healthy."""
    from agent.diagnosis_agent import ClaudeDiagnosisAgent

    agent = ClaudeDiagnosisAgent()
    report = agent.diagnose("Unconfirmed rumor: auth-service has an issue at 2026-09-01T10:14:00Z", service_name="auth-service")

    # Confidence must be low (< 0.50)
    assert report.confidence_score <= 0.50
    assert "undetermined" in report.root_cause_hypothesis.lower() or "insufficient" in report.root_cause_hypothesis.lower()
    assert report.recommended_action["action_type"] == "MANUAL_INVESTIGATION"


def test_all_10_evaluation_scenarios():
    """Verify all 10 benchmark evaluation scenarios pass with 100% accuracy and 0% false positives."""
    from eval.run_eval import run_evaluation

    summary = run_evaluation()
    assert summary["accuracy_pct"] == 100.0
    assert summary["fp_rate_pct"] == 0.0
    assert summary["avg_confidence_pct"] >= 90.0
    assert summary["avg_evidence_pct"] >= 90.0


