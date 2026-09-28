"""Tool for querying deployment history and release metadata."""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from dateutil import parser as date_parser

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "deployments.json"


def load_deployments(data_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load deployment records from JSON file."""
    file_path = data_file or DATA_FILE
    if not file_path.exists():
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_time_range(time_range: Any) -> tuple[Optional[Any], Optional[Any]]:
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


def get_deploy_history(
    time_range: Any = None,
    service_name: Optional[str] = None,
    limit: int = 10,
    data_file: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Get recent deployment history filtered by time window and/or service.

    Args:
        time_range: Time window as tuple/list [start, end], dict {"start", "end"}, or string interval.
                    If passed as a service name string, it is automatically handled as service_name.
        service_name: Service name filter (e.g. 'checkout-service')
        limit: Max results to return
        data_file: Custom deployments JSON file path override

    Returns:
        List of structured JSON deployment records (commit, author, timestamp, changed files, service, etc.)
        sorted newest first.
    """
    raw_deployments = load_deployments(data_file)

    actual_time_range = time_range
    actual_service = service_name

    # Handle polymorphic first argument
    if isinstance(time_range, str) and not actual_service:
        # Check if time_range matches any known service in deployments
        known_services = {d.get("service", "").replace("_", "-") for d in raw_deployments}
        if time_range.replace("_", "-") in known_services:
            actual_service = time_range
            actual_time_range = None

    start_dt, end_dt = parse_time_range(actual_time_range)

    deployments: List[Dict[str, Any]] = []
    for d in raw_deployments:
        if actual_service:
            norm_svc = actual_service.replace("_", "-")
            if d.get("service", "").replace("_", "-") != norm_svc:
                continue

        dep_time_str = d.get("timestamp")
        if dep_time_str:
            try:
                dep_dt = date_parser.parse(dep_time_str)
                if start_dt and dep_dt < start_dt:
                    continue
                if end_dt and dep_dt > end_dt:
                    continue
            except Exception:
                pass

        # Ensure structured format with commit, author, timestamp, changed files
        normalized_record = {
            "id": d.get("id"),
            "service": d.get("service"),
            "version": d.get("version"),
            "previous_version": d.get("previous_version"),
            "timestamp": d.get("timestamp"),
            "status": d.get("status", "COMPLETED"),
            "commit": d.get("commit_hash") or d.get("commit"),
            "commit_hash": d.get("commit_hash") or d.get("commit"),
            "author": d.get("author"),
            "branch": d.get("branch", "main"),
            "commit_message": d.get("commit_message"),
            "rollback_version": d.get("rollback_version"),
            "changes": d.get("changes", []),
            "changed_files": d.get("changes", []),
        }
        deployments.append(normalized_record)

    # Sort descending by timestamp
    deployments.sort(
        key=lambda d: date_parser.parse(d.get("timestamp", "1970-01-01T00:00:00Z")),
        reverse=True,
    )

    return deployments[:limit]


def get_deployment_by_id(
    deployment_id: str,
    data_file: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve specific deployment by ID."""
    deployments = load_deployments(data_file)
    for d in deployments:
        if d.get("id") == deployment_id:
            return d
    return None


def get_latest_deployment(
    service_name: str,
    before_time: Optional[str] = None,
    data_file: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Get the most recent deployment for a service, optionally before a specific timestamp."""
    deployments = get_deploy_history(service_name=service_name, limit=100, data_file=data_file)
    
    if not before_time:
        return deployments[0] if deployments else None

    before_dt = date_parser.parse(before_time)
    for d in deployments:
        dep_dt = date_parser.parse(d["timestamp"])
        if dep_dt <= before_dt:
            return d

    return None
