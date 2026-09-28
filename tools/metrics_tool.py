"""Tool for querying time-series metrics and detecting anomalous spikes."""
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional
from dateutil import parser as date_parser

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "metrics.json"


def load_metrics(data_file: Optional[Path] = None) -> Dict[str, Any]:
    """Load time-series metrics from JSON file."""
    file_path = data_file or DATA_FILE
    if not file_path.exists():
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_time_range(time_range: Any) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse various time_range formats into (start_datetime, end_datetime).
    """
    if not time_range:
        return None, None

    if isinstance(time_range, (list, tuple)):
        start = date_parser.parse(str(time_range[0])) if len(time_range) > 0 and time_range[0] else None
        end = date_parser.parse(str(time_range[1])) if len(time_range) > 1 and time_range[1] else None
        return start, end

    if isinstance(time_range, dict):
        start_val = time_range.get("start") or time_range.get("start_time") or time_range.get("from")
        end_val = time_range.get("end") or time_range.get("end_time") or time_range.get("to")
        start = date_parser.parse(str(start_val)) if start_val else None
        end = date_parser.parse(str(end_val)) if end_val else None
        return start, end

    if isinstance(time_range, str):
        for delim in ["/", " - ", " to ", ","]:
            if delim in time_range:
                parts = time_range.split(delim, 1)
                start = date_parser.parse(parts[0].strip()) if parts[0].strip() else None
                end = date_parser.parse(parts[1].strip()) if parts[1].strip() else None
                return start, end
        try:
            return date_parser.parse(time_range), None
        except Exception:
            return None, None

    return None, None


def get_metrics(
    time_range: Any = None,
    service_name: Optional[str] = None,
    metric_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    data_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Get time-series metrics (CPU, memory, error rates, latency) for a service or across services.

    Args:
        time_range: Time window as tuple/list [start, end], dict {"start", "end"}, or string interval.
                    If passed as a service name string, it is automatically handled as service_name.
        service_name: Name of the service (e.g. 'checkout-service'). If None, returns metrics for all services.
        metric_name: Specific metric (e.g. 'cpu_utilization_pct', 'memory_utilization_pct', 'error_rate_5xx_pct', 'p99_latency_ms')
        start_time: ISO8601 start timestamp filter (optional override)
        end_time: ISO8601 end timestamp filter (optional override)
        data_file: Custom metrics JSON file path override

    Returns:
        Structured JSON dictionary mapping metric names (or service -> metric names) to filtered data points:
        {"error_rate_5xx_pct": [{"timestamp": "...", "value": ...}], "cpu_utilization_pct": [...], "memory_utilization_pct": [...]}
    """
    all_metrics = load_metrics(data_file)

    actual_time_range = time_range
    actual_service = service_name

    # Handle polymorphic first argument
    if isinstance(time_range, str) and not actual_service:
        norm_key = time_range.replace("_", "-")
        if norm_key in all_metrics or time_range.replace("-", "_") in all_metrics:
            actual_service = time_range
            actual_time_range = None
        else:
            # If time_range does not parse as a time window, treat it as a requested service name
            start_check, end_check = parse_time_range(time_range)
            if start_check is None and end_check is None:
                actual_service = time_range
                actual_time_range = None

    start_dt, end_dt = parse_time_range(actual_time_range)
    if start_time:
        start_dt = date_parser.parse(start_time)
    if end_time:
        end_dt = date_parser.parse(end_time)

    def filter_points(points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered = []
        for pt in points:
            pt_dt = date_parser.parse(pt["timestamp"])
            if start_dt and pt_dt < start_dt:
                continue
            if end_dt and pt_dt > end_dt:
                continue
            filtered.append(pt)
        return filtered

    if actual_service:
        normalized = actual_service.replace("_", "-")
        service_metrics = all_metrics.get(normalized) or all_metrics.get(actual_service.replace("-", "_")) or {}

        if metric_name:
            if metric_name not in service_metrics:
                return {}
            target_metrics = {metric_name: service_metrics[metric_name]}
        else:
            target_metrics = service_metrics

        result: Dict[str, List[Dict[str, Any]]] = {}
        for m_name, points in target_metrics.items():
            result[m_name] = filter_points(points)
        return result

    # When no specific service is requested, filter across all services
    multi_service_result: Dict[str, Any] = {}
    for svc, metrics in all_metrics.items():
        svc_result: Dict[str, List[Dict[str, Any]]] = {}
        if metric_name:
            if metric_name in metrics:
                svc_result[metric_name] = filter_points(metrics[metric_name])
        else:
            for m_name, points in metrics.items():
                svc_result[m_name] = filter_points(points)
        if svc_result:
            multi_service_result[svc] = svc_result

    return multi_service_result


def detect_anomalies(
    service_name: str,
    threshold_multiplier: float = 3.0,
    data_file: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Detect statistical anomalies (spikes) across metrics for a service.

    Args:
        service_name: Service identifier
        threshold_multiplier: Multiplier over baseline standard deviation
        data_file: Custom metrics JSON file path override

    Returns:
        List of detected anomalies with onset timestamps, baseline values, and peak values.
    """
    metrics = get_metrics(service_name=service_name, data_file=data_file)
    anomalies: List[Dict[str, Any]] = []

    for metric_name, points in metrics.items():
        if not isinstance(points, list) or len(points) < 3:
            continue

        values = [p["value"] for p in points]
        # Use first 3 points as baseline if available
        baseline_slice = values[: min(4, len(values) // 2)]
        mean = sum(baseline_slice) / len(baseline_slice)
        variance = sum((x - mean) ** 2 for x in baseline_slice) / max(len(baseline_slice), 1)
        std_dev = math.sqrt(variance) or 0.05  # minimum jitter floor

        spike_detected = False
        onset_time = None
        peak_value = mean
        peak_time = None

        for pt in points:
            val = pt["value"]
            # Detect significant jump (> 5x mean and > absolute threshold or > std_dev threshold)
            is_anomaly = False
            if "error" in metric_name and val > 5.0 and val > (mean + 2.0):
                is_anomaly = True
            elif "latency" in metric_name and val > (mean * 2.5) and val > 500:
                is_anomaly = True
            elif val > (mean + threshold_multiplier * std_dev) and val > (mean * 2):
                is_anomaly = True

            if is_anomaly:
                if not spike_detected:
                    spike_detected = True
                    onset_time = pt["timestamp"]
                if val > peak_value:
                    peak_value = val
                    peak_time = pt["timestamp"]

        if spike_detected and onset_time:
            anomalies.append({
                "service": service_name,
                "metric_name": metric_name,
                "onset_timestamp": onset_time,
                "peak_timestamp": peak_time or onset_time,
                "baseline_mean": round(mean, 2),
                "peak_value": round(peak_value, 2),
                "severity": "CRITICAL" if ("error" in metric_name and peak_value > 20) else "HIGH",
                "summary": f"{metric_name} spiked from {mean:.2f} to {peak_value:.2f} starting at {onset_time}",
            })

    return anomalies
