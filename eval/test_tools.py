"""Unit tests for tool functions: read_logs, get_deploy_history, get_metrics."""
import pytest
from datetime import datetime
from tools.log_tool import read_logs, parse_log_line, parse_time_range as parse_log_time_range
from tools.deploy_tool import get_deploy_history, get_latest_deployment
from tools.metrics_tool import get_metrics, detect_anomalies


# ============================================================================
# 1. read_logs(time_range) Unit Tests
# ============================================================================

def test_read_logs_with_tuple_time_range():
    """Verify read_logs returns structured log records within a tuple time window."""
    time_window = ("2026-09-01T10:15:00Z", "2026-09-01T10:17:00Z")
    logs = read_logs(time_range=time_window, service_name="checkout-service")
    
    assert isinstance(logs, list)
    assert len(logs) > 0

    # Ensure all entries are within time_window
    for entry in logs:
        assert "timestamp" in entry
        assert "level" in entry
        assert "service" in entry
        assert "message" in entry
        assert "2026-09-01T10:15:00Z" <= entry["timestamp"] <= "2026-09-01T10:17:00Z"
        assert entry["service"] == "checkout-service"


def test_read_logs_with_string_interval():
    """Verify read_logs parses ISO string interval format."""
    interval_str = "2026-09-01T10:15:00Z/2026-09-01T10:16:00Z"
    logs = read_logs(time_range=interval_str, service_name="checkout-service")
    
    assert len(logs) > 0
    for entry in logs:
        assert entry["timestamp"] <= "2026-09-01T10:16:00Z"


def test_read_logs_with_dict_time_range():
    """Verify read_logs parses dictionary time range format."""
    time_dict = {"start": "2026-09-01T10:15:20Z", "end": "2026-09-01T10:15:30Z"}
    logs = read_logs(time_range=time_dict)
    
    assert isinstance(logs, list)
    assert len(logs) > 0
    for entry in logs:
        assert "2026-09-01T10:15:20Z" <= entry["timestamp"] <= "2026-09-01T10:15:30Z"


def test_read_logs_structured_json_fields_and_stack_traces():
    """Verify log records contain full structured JSON schema including multi-line stack traces."""
    logs = read_logs(service_name="checkout-service", level="ERROR")
    assert len(logs) >= 4

    error_entry = logs[0]
    # Required JSON schema fields
    assert "timestamp" in error_entry
    assert "level" in error_entry
    assert "service" in error_entry
    assert "logger" in error_entry
    assert "message" in error_entry
    assert "stack_trace" in error_entry
    assert "raw" in error_entry
    assert error_entry["level"] == "ERROR"
    assert "NullPointerException" in (error_entry["stack_trace"] or "")


def test_read_logs_across_all_services():
    """Verify read_logs without a service_name reads and aggregates all services in data/logs."""
    logs = read_logs(time_range=("2026-09-01T10:00:00Z", "2026-09-01T10:20:00Z"))
    assert len(logs) > 0
    services_found = {e["service"] for e in logs}
    # Should include multiple services from data/logs
    assert len(services_found) >= 2


# ============================================================================
# 2. get_deploy_history(time_range) Unit Tests
# ============================================================================

def test_get_deploy_history_structured_fields():
    """Verify get_deploy_history returns structured JSON with commit, author, timestamp, changed files."""
    deploys = get_deploy_history(service_name="checkout-service")
    assert len(deploys) >= 2

    d = deploys[0]
    # Required structured fields
    assert "commit" in d
    assert "author" in d
    assert "timestamp" in d
    assert "changed_files" in d or "changes" in d
    assert "service" in d
    assert "version" in d

    assert d["commit"] == "a9f4c3b"
    assert d["author"] == "alice@company.com"
    assert d["version"] == "v2.4.0"
    assert len(d["changed_files"]) > 0
    assert any("PaymentMethodValidator" in ch for ch in d["changed_files"])


def test_get_deploy_history_time_range_filter():
    """Verify get_deploy_history filters deployments by time window."""
    # Window that only covers 2026-09-01 deployments
    time_window = ("2026-09-01T00:00:00Z", "2026-09-01T23:59:59Z")
    deploys = get_deploy_history(time_range=time_window)

    assert len(deploys) >= 2
    for dep in deploys:
        assert dep["timestamp"].startswith("2026-09-01")

    # Older window covering 2026-08-30
    older_window = ("2026-08-30T00:00:00Z", "2026-08-30T23:59:59Z")
    older_deploys = get_deploy_history(time_range=older_window)
    assert len(older_deploys) >= 1
    for dep in older_deploys:
        assert dep["timestamp"].startswith("2026-08-30")
    assert older_deploys[0]["version"] == "v2.3.9"
    assert older_deploys[0]["commit"] == "c2198fa"


def test_get_deploy_history_empty_window():
    """Verify get_deploy_history returns empty list when no deployments match window."""
    future_window = ("2027-01-01T00:00:00Z", "2027-01-02T00:00:00Z")
    deploys = get_deploy_history(time_range=future_window)
    assert deploys == []


# ============================================================================
# 3. get_metrics(time_range) Unit Tests
# ============================================================================

def test_get_metrics_structured_cpu_memory_error_rate():
    """Verify get_metrics returns structured CPU, memory, and error-rate time series."""
    metrics = get_metrics(service_name="checkout-service")
    
    assert isinstance(metrics, dict)
    assert "cpu_utilization_pct" in metrics
    assert "memory_utilization_pct" in metrics
    assert "error_rate_5xx_pct" in metrics
    assert "p99_latency_ms" in metrics

    # Verify structured time-series data points
    cpu_points = metrics["cpu_utilization_pct"]
    assert len(cpu_points) > 0
    assert "timestamp" in cpu_points[0]
    assert "value" in cpu_points[0]
    assert isinstance(cpu_points[0]["value"], (int, float))


def test_get_metrics_time_range_filter():
    """Verify get_metrics filters time-series data points within the specified window."""
    time_window = ("2026-09-01T10:14:00Z", "2026-09-01T10:16:00Z")
    metrics = get_metrics(time_range=time_window, service_name="checkout-service")

    for metric_name, points in metrics.items():
        assert len(points) > 0
        for pt in points:
            assert "2026-09-01T10:14:00Z" <= pt["timestamp"] <= "2026-09-01T10:16:00Z"


def test_get_metrics_specific_metric_filter():
    """Verify querying a single specific metric."""
    error_metrics = get_metrics(
        service_name="checkout-service",
        metric_name="error_rate_5xx_pct",
        time_range=("2026-09-01T10:15:00Z", "2026-09-01T10:18:00Z"),
    )
    assert "error_rate_5xx_pct" in error_metrics
    assert len(error_metrics) == 1
    points = error_metrics["error_rate_5xx_pct"]
    assert len(points) == 4
    # Spiking error rate in this window
    assert points[-1]["value"] > 50.0


def test_get_metrics_across_all_services():
    """Verify get_metrics across all services returns structured nested JSON."""
    all_metrics = get_metrics(time_range=("2026-09-01T10:00:00Z", "2026-09-01T10:10:00Z"))
    assert isinstance(all_metrics, dict)
    assert "checkout-service" in all_metrics
    assert "payment-gateway" in all_metrics
    assert "auth-service" in all_metrics
    assert "cpu_utilization_pct" in all_metrics["checkout-service"]
