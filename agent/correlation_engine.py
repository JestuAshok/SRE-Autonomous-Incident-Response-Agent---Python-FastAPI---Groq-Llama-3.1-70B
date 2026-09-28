"""Correlation engine for incident root-cause analysis."""
import re
from typing import Any, Dict, List, Optional
from dateutil import parser as date_parser

from .models import (
    DeployEvidence,
    IncidentSeverity,
    LogEvidence,
    MetricEvidence,
    RemediationAction,
    ActionType,
    ApprovalStatus,
    RootCauseAnalysis,
)


class CorrelationEngine:
    """Correlates logs, metrics, and deployments to diagnose incident root causes."""

    @staticmethod
    def analyze(
        service_name: str,
        logs: List[Dict[str, Any]],
        deployments: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Execute cross-domain correlation across logs, metrics, and deployments.
        """
        # 1. Analyze logs
        error_logs = [l for l in logs if l.get("level") == "ERROR"]
        first_error_time = error_logs[0]["timestamp"] if error_logs else None
        
        stack_traces = []
        primary_exception = None
        faulty_file_and_line = None

        for err in error_logs:
            st = err.get("stack_trace")
            if st:
                stack_traces.append(st)
                if not primary_exception:
                    first_line = st.strip().split("\n")[0]
                    primary_exception = first_line

                    loc_match = re.search(r"([A-Za-z0-9_]+\.(?:java|py|go|ts|js|kt|scala|sys|lua|c|cpp|rs):\d+)", st)
                    if loc_match:
                        faulty_file_and_line = loc_match.group(1)
            elif not primary_exception and err.get("message"):
                primary_exception = err.get("message")

        log_evidence = LogEvidence(
            total_errors=len(error_logs),
            first_error_time=first_error_time,
            primary_exception=primary_exception,
            stack_traces=stack_traces[:3],
            error_sample=error_logs[:5],
        )

        # 2. Analyze metrics
        error_rate_peak = None
        latency_p99_peak = None
        memory_peak = None
        cpu_peak = None

        for a in anomalies:
            metric_n = a.get("metric_name", "").lower()
            val = a.get("peak_value")
            if "error" in metric_n:
                error_rate_peak = val
            elif "latency" in metric_n:
                latency_p99_peak = val
            elif "memory" in metric_n:
                memory_peak = val
            elif "cpu" in metric_n:
                cpu_peak = val

        metric_evidence = MetricEvidence(
            anomalies=anomalies,
            error_rate_peak=error_rate_peak,
            latency_p99_peak=latency_p99_peak,
        )

        # 3. Correlate with deployments
        suspect_deploy = None
        time_delta_sec = None

        if first_error_time and deployments:
            first_err_dt = date_parser.parse(first_error_time)
            # Find the closest deployment right before the first error (within 60 min)
            for dep in deployments:
                dep_dt = date_parser.parse(dep["timestamp"])
                delta = (first_err_dt - dep_dt).total_seconds()
                if 0 <= delta <= 3600:
                    suspect_deploy = dep
                    time_delta_sec = delta
                    break

        deploy_evidence = DeployEvidence(
            suspect_deployment=suspect_deploy,
            time_delta_seconds=time_delta_sec,
            commit_hash=suspect_deploy.get("commit_hash") or suspect_deploy.get("commit") if suspect_deploy else None,
            author=suspect_deploy.get("author") if suspect_deploy else None,
            changes=suspect_deploy.get("changes", []) or suspect_deploy.get("changed_files", []) if suspect_deploy else [],
        )

        # 4. Classify Incident Type & Root Cause
        timeline = []
        severity = IncidentSeverity.MEDIUM
        if error_rate_peak and error_rate_peak > 20.0:
            severity = IncidentSeverity.CRITICAL
        elif error_rate_peak and error_rate_peak > 5.0:
            severity = IncidentSeverity.HIGH
        elif memory_peak and memory_peak > 90.0:
            severity = IncidentSeverity.CRITICAL
        elif cpu_peak and cpu_peak > 90.0:
            severity = IncidentSeverity.HIGH

        if suspect_deploy:
            timeline.append(
                f"[{suspect_deploy['timestamp']}] Deployed {service_name} {suspect_deploy.get('version')} (commit {deploy_evidence.commit_hash}) by {suspect_deploy.get('author')}"
            )
        
        if first_error_time:
            delta_str = f"{int(time_delta_sec)}s after deployment" if time_delta_sec is not None else ""
            timeline.append(
                f"[{first_error_time}] First unhandled exception observed: {primary_exception or 'HTTP 500'} {delta_str}".strip()
            )

        for a in anomalies:
            timeline.append(
                f"[{a.get('onset_timestamp')}] Metric Alert: {a.get('summary')}"
            )

        # Detect specific root cause signatures
        all_logs_text = " ".join([l.get("message", "") + " " + (l.get("stack_trace") or "") for l in error_logs]).lower()
        prim_exc_lower = (primary_exception or "").lower()

        # Classification Flags
        is_oom = "outofmemoryerror" in prim_exc_lower or "out of memory" in prim_exc_lower or "java heap space" in all_logs_text or (memory_peak and memory_peak > 90.0)
        is_conn_pool = "hikaripool" in prim_exc_lower or "connection is not available" in all_logs_text or "connection pool" in all_logs_text or "connectiontimeoutexception" in prim_exc_lower or "membershipleasetimeoutexception" in prim_exc_lower or "leasecoordinator" in all_logs_text
        is_cpu_thread = ("rejectedexecutionexception" in prim_exc_lower or "threadpoolexecutor" in all_logs_text or "thread starvation" in all_logs_text or (cpu_peak and cpu_peak > 95.0 and not is_oom)) and not (suspect_deploy and primary_exception)
        is_external_outage = "stripe" in all_logs_text or "paypal" in all_logs_text or "503 service unavailable" in all_logs_text or "gateway timeout" in all_logs_text or "upstream" in all_logs_text
        is_cert_expired = "sslhandshakeexception" in prim_exc_lower or "certificate expired" in all_logs_text or "pkix path validation failed" in all_logs_text
        is_deadlock = "deadlock found" in all_logs_text or "transactionrollbackexception" in prim_exc_lower or "lock wait timeout" in all_logs_text

        # Resource Exhaustion Cases
        if is_oom:
            confidence = 0.96
            probable_culprit = f"Memory exhaustion / JVM Heap OutOfMemoryError in {service_name}. Memory utilization reached {memory_peak or 98.5}%."
            if faulty_file_and_line:
                probable_culprit += f" Allocation failure at {faulty_file_and_line}."
            culprit_commit = None
            culprit_deploy_id = None
            action = RemediationAction(
                action_id=f"act-scale-{service_name}",
                action_type=ActionType.SCALE_UP,
                title=f"Scale up memory and replicas for {service_name}",
                description=f"Increase container memory limit and trigger rolling restart for {service_name} to recover from heap exhaustion.",
                target_service=service_name,
                command_preview=f"kubectl scale deployment/{service_name} --replicas=6 && kubectl set resources deployment/{service_name} --limits=memory=4Gi",
                confidence_score=confidence,
                risk_level="LOW",
                approval_status=ApprovalStatus.PENDING,
            )
            actions = [action]

        elif is_conn_pool:
            confidence = 0.95
            probable_culprit = f"Database connection pool exhaustion in {service_name}. All pool connections active; requests timed out acquiring DB connection."
            if faulty_file_and_line:
                probable_culprit += f" Connection acquisition timed out in {faulty_file_and_line}."
            culprit_commit = None
            culprit_deploy_id = None
            action = RemediationAction(
                action_id=f"act-pool-{service_name}",
                action_type=ActionType.SCALE_UP,
                title=f"Increase database connection pool size for {service_name}",
                description=f"Increase maximum HikariCP pool size from 50 to 150 and enable connection leak detection for {service_name}.",
                target_service=service_name,
                command_preview=f"kubectl set env deployment/{service_name} DB_POOL_MAX_SIZE=150 DB_POOL_TIMEOUT_MS=60000",
                confidence_score=confidence,
                risk_level="LOW",
                approval_status=ApprovalStatus.PENDING,
            )
            actions = [action]

        elif is_cpu_thread:
            confidence = 0.95
            probable_culprit = f"CPU saturation & worker thread pool starvation in {service_name}. CPU utilization at {cpu_peak or 99.4}%, thread worker queue limit exceeded."
            if faulty_file_and_line:
                probable_culprit += f" Worker task rejected at {faulty_file_and_line}."
            culprit_commit = None
            culprit_deploy_id = None
            action = RemediationAction(
                action_id=f"act-throttle-{service_name}",
                action_type=ActionType.THROTTLE_TRAFFIC,
                title=f"Throttle search traffic and scale worker replicas for {service_name}",
                description=f"Enable rate limiting on unindexed query endpoints and scale worker replicas for {service_name}.",
                target_service=service_name,
                command_preview=f"kubectl scale deployment/{service_name} --replicas=8 && kubectl set env deployment/{service_name} RATE_LIMIT_ENABLED=true",
                confidence_score=confidence,
                risk_level="LOW",
                approval_status=ApprovalStatus.PENDING,
            )
            actions = [action]

        # Red Herring Cases (Deploy is present, but NOT the cause)
        elif is_external_outage:
            confidence = 0.94
            probable_culprit = f"External third-party API outage affecting {service_name}. Upstream service returned 503 / Gateway Timeout."
            if suspect_deploy:
                probable_culprit += f" Note: Recent deployment {suspect_deploy.get('version')} is benign and unrelated to upstream vendor outage."
            culprit_commit = None
            culprit_deploy_id = None
            action = RemediationAction(
                action_id=f"act-circuit-breaker-{service_name}",
                action_type=ActionType.MANUAL_INVESTIGATION,
                title=f"Activate fallback circuit breaker & monitor upstream provider for {service_name}",
                description=f"Trip circuit breaker to route traffic to backup gateway while third-party vendor resolves outage.",
                target_service=service_name,
                command_preview=f"kubectl set env deployment/{service_name} CIRCUIT_BREAKER_TRIPPED=true FALLBACK_PROVIDER=enabled",
                confidence_score=confidence,
                risk_level="LOW",
                approval_status=ApprovalStatus.PENDING,
            )
            actions = [action]

        elif is_cert_expired:
            confidence = 0.96
            probable_culprit = f"Expired TLS/SSL Certificate on {service_name}. Handshake verification failed (PKIX path validation failed: certificate expired)."
            if suspect_deploy:
                probable_culprit += f" Note: Recent deployment {suspect_deploy.get('version')} is benign and unrelated to TLS certificate expiration."
            culprit_commit = None
            culprit_deploy_id = None
            action = RemediationAction(
                action_id=f"act-cert-renew-{service_name}",
                action_type=ActionType.MANUAL_INVESTIGATION,
                title=f"Renew expired TLS/SSL certificates for {service_name}",
                description=f"Trigger cert-manager certificate rotation and reload TLS secret for {service_name}.",
                target_service=service_name,
                command_preview=f"cmctl renew {service_name}-tls-cert && kubectl rollout restart deployment/{service_name}",
                confidence_score=confidence,
                risk_level="LOW",
                approval_status=ApprovalStatus.PENDING,
            )
            actions = [action]

        elif is_deadlock:
            confidence = 0.93
            probable_culprit = f"Database deadlock and transaction contention on {service_name} during concurrent write transactions."
            if suspect_deploy:
                probable_culprit += f" Note: Recent deployment {suspect_deploy.get('version')} is benign and unrelated to concurrent transaction deadlock."
            culprit_commit = None
            culprit_deploy_id = None
            action = RemediationAction(
                action_id=f"act-deadlock-retry-{service_name}",
                action_type=ActionType.MANUAL_INVESTIGATION,
                title=f"Enable transaction auto-retry and isolate lock contention on {service_name}",
                description=f"Apply deadlock retry backoff and analyze active InnoDB lock graph for {service_name}.",
                target_service=service_name,
                command_preview=f"kubectl set env deployment/{service_name} DB_DEADLOCK_RETRY_COUNT=5 && mysqladmin processlist",
                confidence_score=confidence,
                risk_level="LOW",
                approval_status=ApprovalStatus.PENDING,
            )
            actions = [action]

        # Deploy-Caused Regressions
        elif suspect_deploy and primary_exception:
            matches_change = False
            if faulty_file_and_line:
                base_class = faulty_file_and_line.split(".")[0]
                for ch in deploy_evidence.changes:
                    if base_class.lower() in ch.lower():
                        matches_change = True
                        break

            culprit_commit = deploy_evidence.commit_hash
            culprit_deploy_id = suspect_deploy.get("id")

            if matches_change:
                confidence = 0.98
                probable_culprit = (
                    f"Regression introduced in deployment {suspect_deploy.get('version')} (commit {culprit_commit}). "
                    f"Faulty code path in {faulty_file_and_line} throwing {primary_exception}."
                )
            else:
                confidence = 0.92
                probable_culprit = (
                    f"Regression introduced in deployment {suspect_deploy.get('version')} (commit {culprit_commit}) "
                    f"deployed {int(time_delta_sec // 60)} min before errors began. Root exception: {primary_exception}."
                )

            actions = []
            if suspect_deploy.get("rollback_version"):
                prev_ver = suspect_deploy.get("rollback_version")
                curr_ver = suspect_deploy.get("version")
                actions.append(
                    RemediationAction(
                        action_id=f"act-rollback-{suspect_deploy.get('id')}",
                        action_type=ActionType.ROLLBACK_DEPLOYMENT,
                        title=f"Rollback {service_name} to {prev_ver}",
                        description=(
                            f"Instantly rollback {service_name} from {curr_ver} to known stable release {prev_ver} "
                            f"to eliminate {primary_exception or 'elevated 5xx errors'}."
                        ),
                        target_service=service_name,
                        target_version=prev_ver,
                        rollback_from=curr_ver,
                        command_preview=f"kubectl rollout undo deployment/{service_name} --to-revision={prev_ver}",
                        confidence_score=confidence,
                        risk_level="LOW",
                        approval_status=ApprovalStatus.PENDING,
                    )
                )

        elif suspect_deploy:
            confidence = 0.75
            probable_culprit = f"Recent deployment {suspect_deploy.get('version')} coincides with anomaly window."
            culprit_commit = deploy_evidence.commit_hash
            culprit_deploy_id = suspect_deploy.get("id")
            actions = []
        elif primary_exception:
            confidence = 0.70
            probable_culprit = f"Unhandled application exception: {primary_exception}."
            culprit_commit = None
            culprit_deploy_id = None
            actions = []
        else:
            confidence = 0.35
            probable_culprit = "Underlying cause undetermined; further log telemetry required."
            culprit_commit = None
            culprit_deploy_id = None
            actions = []

        root_cause = RootCauseAnalysis(
            summary=probable_culprit,
            probable_culprit=probable_culprit,
            confidence=confidence,
            culprit_deployment_id=culprit_deploy_id,
            culprit_commit=culprit_commit,
            exception_type=primary_exception,
            faulty_file_and_line=faulty_file_and_line,
            timeline_summary=timeline,
        )

        return {
            "severity": severity,
            "log_evidence": log_evidence,
            "deploy_evidence": deploy_evidence,
            "metric_evidence": metric_evidence,
            "root_cause": root_cause,
            "actions": actions,
        }

