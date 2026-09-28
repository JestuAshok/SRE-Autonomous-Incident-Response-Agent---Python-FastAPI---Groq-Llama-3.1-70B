"""Tool for reading, parsing, and filtering service logs."""
from datetime import datetime
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from dateutil import parser as date_parser

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "logs"

# Regex for standard structured log line:
# 2026-09-01T10:15:22.104Z [ERROR] [checkout-service] [thread] logger - message
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+\[(?P<level>[A-Z]+)\]\s+\[(?P<service>[^\]]+)\]\s+(?:\[(?P<thread>[^\]]+)\]\s+)?(?P<logger>\S+)\s+-\s+(?P<message>.*)$"
)


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single log line into structured components."""
    match = LOG_PATTERN.match(line.strip())
    if match:
        data = match.groupdict()
        return {
            "timestamp": data["timestamp"],
            "level": data["level"],
            "service": data["service"],
            "thread": data.get("thread"),
            "logger": data["logger"],
            "message": data["message"],
            "stack_trace": None,
            "raw": line.rstrip("\r\n"),
        }
    return None


def parse_time_range(time_range: Any) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse various time_range formats into (start_datetime, end_datetime).
    Supports:
      - (start, end) or [start, end]
      - {"start": ..., "end": ...} or {"start_time": ..., "end_time": ...}
      - ISO interval string "start/end", "start - end", "start,end"
      - single timestamp or datetime objects
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
        # Check for delimiters
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


def read_logs(
    time_range: Any = None,
    service_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    level: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 200,
    logs_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Read and filter service logs with support for time windows and multi-line stack traces.

    Args:
        time_range: Time window as tuple/list [start, end], dict {"start", "end"}, or string interval.
                    If passed as a service name string, it is automatically handled as service_name.
        service_name: Service identifier (e.g. 'checkout-service' or 'checkout_service').
                      If None, reads logs across all services in the data directory.
        start_time: ISO8601 start timestamp filter (optional override)
        end_time: ISO8601 end timestamp filter (optional override)
        level: Minimum/exact log level (INFO, WARN, ERROR)
        keyword: Substring filter for log message or stack trace
        limit: Max entries to return
        logs_dir: Custom logs directory override (optional)

    Returns:
        List of structured JSON log entries with stack traces and timestamps.
    """
    target_dir = logs_dir or DATA_DIR

    # Handle polymorphic first argument (time_range vs service_name)
    actual_time_range = time_range
    actual_service = service_name

    if isinstance(time_range, str) and not actual_service:
        # Check if time_range is actually a service name
        norm_test = time_range.replace("-", "_")
        if (target_dir / f"{norm_test}.log").exists() or (target_dir / f"{time_range}.log").exists():
            actual_service = time_range
            actual_time_range = None

    start_dt, end_dt = parse_time_range(actual_time_range)
    if start_time:
        start_dt = date_parser.parse(start_time)
    if end_time:
        end_dt = date_parser.parse(end_time)

    # Collect target log files
    log_files: List[Path] = []
    if actual_service:
        normalized_name = actual_service.replace("-", "_")
        log_file = target_dir / f"{normalized_name}.log"
        if not log_file.exists():
            alt_file = target_dir / f"{actual_service}.log"
            if alt_file.exists():
                log_files.append(alt_file)
        else:
            log_files.append(log_file)
    else:
        # Read from all log files in target_dir
        if target_dir.exists():
            log_files = sorted(list(target_dir.glob("*.log")))

    if not log_files:
        return []

    entries: List[Dict[str, Any]] = []

    for l_file in log_files:
        current_entry: Optional[Dict[str, Any]] = None
        stack_lines: List[str] = []

        with open(l_file, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    # Flush previous entry if any
                    if current_entry:
                        if stack_lines:
                            current_entry["stack_trace"] = "\n".join(stack_lines)
                            current_entry["raw"] += "\n" + "\n".join(stack_lines)
                        entries.append(current_entry)
                        current_entry = None
                        stack_lines = []

                    current_entry = parsed
                else:
                    # Part of previous entry (e.g. stack trace)
                    if current_entry:
                        stack_lines.append(line.rstrip("\r\n"))

            # Flush final entry
            if current_entry:
                if stack_lines:
                    current_entry["stack_trace"] = "\n".join(stack_lines)
                    current_entry["raw"] += "\n" + "\n".join(stack_lines)
                entries.append(current_entry)

    # Filter entries
    filtered: List[Dict[str, Any]] = []
    for entry in entries:
        try:
            entry_dt = date_parser.parse(entry["timestamp"])
        except Exception:
            entry_dt = None

        if start_dt and entry_dt and entry_dt < start_dt:
            continue
        if end_dt and entry_dt and entry_dt > end_dt:
            continue
        if level and entry["level"].upper() != level.upper():
            continue
        if keyword:
            kw_lower = keyword.lower()
            in_msg = kw_lower in entry["message"].lower()
            in_trace = entry["stack_trace"] and kw_lower in entry["stack_trace"].lower()
            if not (in_msg or in_trace):
                continue

        filtered.append(entry)

    # Sort filtered entries chronologically by timestamp
    filtered.sort(
        key=lambda e: date_parser.parse(e.get("timestamp", "1970-01-01T00:00:00Z"))
    )

    return filtered[:limit]


def extract_error_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract aggregated error patterns, stack traces, and first occurrence timestamp."""
    error_entries = [e for e in entries if e["level"] == "ERROR"]
    signatures: Dict[str, int] = {}
    first_error_time = None
    stack_traces: List[str] = []

    for err in error_entries:
        if not first_error_time:
            first_error_time = err["timestamp"]
        
        # Check stack trace for exception class
        if err["stack_trace"]:
            stack_traces.append(err["stack_trace"])
            first_line = err["stack_trace"].strip().split("\n")[0]
            signatures[first_line] = signatures.get(first_line, 0) + 1
        else:
            msg_snippet = err["message"][:80]
            signatures[msg_snippet] = signatures.get(msg_snippet, 0) + 1

    return {
        "total_errors": len(error_entries),
        "first_error_timestamp": first_error_time,
        "error_signatures": signatures,
        "sample_stack_traces": stack_traces[:3],
    }
