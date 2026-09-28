"""Policy Engine for Autonomous Night Mode and Safety Guardrails."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .models import Incident, RemediationAction, ActionType


class PolicyMode(str, Enum):
    MANUAL = "MANUAL"                   # Standard HITL: human must approve all actions
    AUTONOMOUS = "AUTONOMOUS"           # Instant auto-mitigation when safety guardrails pass
    TIMED_FALLBACK = "TIMED_FALLBACK"   # Dead Man's Switch: alert sent, auto-mitigates if unreviewed


class AutoRemediationPolicy(BaseModel):
    mode: PolicyMode = PolicyMode.MANUAL
    confidence_threshold: float = Field(default=0.90, ge=0.50, le=1.0)
    allowed_risk_levels: List[str] = Field(default_factory=lambda: ["LOW"])
    auto_execute_delay_seconds: int = Field(default=30, ge=1, le=3600)
    require_zero_db_migrations: bool = True
    enabled_channels: List[str] = Field(default_factory=lambda: ["PAGERDUTY", "SLACK"])


class PolicyEvaluationResult(BaseModel):
    can_execute: bool
    mode: PolicyMode
    reason: str
    confidence_passed: bool
    risk_passed: bool
    safety_checks_passed: bool


class PolicyEngine:
    """
    Evaluates actions against strict SRE safety guardrails before
    permitting automated execution during out-of-hours / night operations.
    """

    UNSAFE_CHANGE_KEYWORDS = [
        "migration", "schema", "db migration", "drop table", "alter table",
        "database schema", "secret", "vault", "encryption key", "partition"
    ]

    def __init__(self, policy: Optional[AutoRemediationPolicy] = None):
        self.policy = policy or AutoRemediationPolicy()

    def get_policy(self) -> AutoRemediationPolicy:
        return self.policy

    def update_policy(self, **kwargs) -> AutoRemediationPolicy:
        data = self.policy.model_dump()
        for k, v in kwargs.items():
            if v is not None and k in data:
                data[k] = v
        self.policy = AutoRemediationPolicy(**data)
        return self.policy

    def evaluate_action(
        self,
        incident: Incident,
        action: RemediationAction,
    ) -> PolicyEvaluationResult:
        """
        Evaluate if a proposed remediation action qualifies for automated execution
        under current policy guardrails.
        """
        if self.policy.mode == PolicyMode.MANUAL:
            return PolicyEvaluationResult(
                can_execute=False,
                mode=self.policy.mode,
                reason="Policy is set to MANUAL: Human review is strictly required.",
                confidence_passed=False,
                risk_passed=False,
                safety_checks_passed=False,
            )

        # 1. Confidence check
        confidence = action.confidence_score
        confidence_passed = confidence >= self.policy.confidence_threshold
        if not confidence_passed:
            return PolicyEvaluationResult(
                can_execute=False,
                mode=self.policy.mode,
                reason=f"Confidence {confidence*100:.1f}% is below required policy threshold {self.policy.confidence_threshold*100:.1f}%.",
                confidence_passed=False,
                risk_passed=False,
                safety_checks_passed=False,
            )

        # 2. Risk level check
        risk_passed = action.risk_level.upper() in [r.upper() for r in self.policy.allowed_risk_levels]
        if not risk_passed:
            return PolicyEvaluationResult(
                can_execute=False,
                mode=self.policy.mode,
                reason=f"Action risk level '{action.risk_level}' is not in allowed safe tiers {self.policy.allowed_risk_levels}.",
                confidence_passed=True,
                risk_passed=False,
                safety_checks_passed=False,
            )

        # 3. Deep Safety Checks: Verify no database migrations or irreversible operations
        if self.policy.require_zero_db_migrations and incident.deploy_evidence:
            dep = incident.deploy_evidence.suspect_deployment
            if dep:
                commit_msg = (dep.get("commit_message") if isinstance(dep, dict) else getattr(dep, "commit_message", "")) or ""
                commit_msg = commit_msg.lower()
                changes_list = (dep.get("changes") if isinstance(dep, dict) else getattr(dep, "changes", [])) or []
                changes_text = " ".join(changes_list).lower()
                combined = f"{commit_msg} {changes_text}"
                
                for kw in self.UNSAFE_CHANGE_KEYWORDS:
                    if kw in combined:
                        return PolicyEvaluationResult(
                            can_execute=False,
                            mode=self.policy.mode,
                            reason=f"Blocked by database safety guardrail: Detected '{kw}' in recent deployment diff.",
                            confidence_passed=True,
                            risk_passed=False,
                            safety_checks_passed=False,
                        )

        return PolicyEvaluationResult(
            can_execute=True,
            mode=self.policy.mode,
            reason=f"All guardrails passed ({confidence*100:.0f}% confidence, low blast radius, zero DB mutations).",
            confidence_passed=True,
            risk_passed=True,
            safety_checks_passed=True,
        )
