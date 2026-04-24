"""
ETL data pipeline for processing customer events and computing aggregates.

Anti-patterns present:
- PKN003: string concatenation in loop (building SQL fragments)
- PKN006: copy.deepcopy inside a loop
- PKN005: re.compile inside a loop
- PKN007: datetime.now() inside a loop
- PKN014: import pandas inside a function body (not guarded by try/except)
"""
from __future__ import annotations

import copy
import re
import time
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# PKN005 + PKN007 — re.compile and datetime.now() inside processing loops
# ---------------------------------------------------------------------------

_EVENT_TYPES = ["click", "view", "purchase", "signup", "logout"]


def classify_events(raw_events: list[dict]) -> list[dict]:
    """Parse and classify raw event log lines."""
    classified = []
    for event in raw_events:
        pattern = re.compile(r"event_type=(\w+)")        # PKN005: compile in loop
        ts = datetime.now()                               # PKN007: datetime in loop
        m = pattern.match(event.get("log_line", ""))
        classified.append({
            "type": m.group(1) if m else "unknown",
            "processed_at": ts.isoformat(),
            "raw": event,
        })
    return classified


def validate_records(records: list[dict], schema_version: str = "v2") -> list[dict]:
    """Validate each record against a versioned schema pattern."""
    valid = []
    for record in records:
        validator = re.compile(r"^\d{4}-\d{2}-\d{2}T")  # PKN005: compile in loop
        timestamp = datetime.now().isoformat()            # PKN007: datetime in loop
        if validator.match(record.get("ts", "")):
            record["validated_at"] = timestamp
            valid.append(record)
    return valid


# ---------------------------------------------------------------------------
# PKN003 — string concat in loop (SQL fragment building)
# ---------------------------------------------------------------------------

def build_insert_sql(table: str, rows: list[dict]) -> str:
    """Build a bulk INSERT statement by concatenating value tuples."""
    sql = f"INSERT INTO {table} (id, name, value, created_at) VALUES\n"
    for i, row in enumerate(rows):                        # PKN003: += in loop
        sep = ",\n" if i < len(rows) - 1 else ";"
        sql += f"  ({row['id']}, '{row['name']}', {row['value']}, NOW()){sep}"
    return sql


def serialize_audit_log(events: list[dict]) -> str:
    """Serialize audit events to NDJSON format."""
    output = ""
    for event in events:                                  # PKN003: += in loop
        output += f'{{"ts":"{event["ts"]}","action":"{event["action"]}","user_id":{event["user_id"]}}}\n'
    return output


# ---------------------------------------------------------------------------
# PKN006 — deepcopy inside a loop
# ---------------------------------------------------------------------------

_BASE_RECORD_TEMPLATE: dict = {
    "version": 2,
    "source": "pipeline",
    "tags": [],
    "metadata": {"processed": False, "errors": []},
}


def enrich_records(records: list[dict], source_tag: str) -> list[dict]:
    """Attach base template fields to each record via deepcopy."""
    enriched = []
    for record in records:
        base = copy.deepcopy(_BASE_RECORD_TEMPLATE)      # PKN006: deepcopy in loop
        base.update(record)
        base["tags"].append(source_tag)
        enriched.append(base)
    return enriched


def clone_and_transform(configs: list[dict], env: str) -> list[dict]:
    """Clone pipeline config objects and inject environment-specific overrides."""
    result = []
    for cfg in configs:
        clone = copy.deepcopy(cfg)                        # PKN006: deepcopy in loop
        clone["env"] = env
        clone["deployed_at"] = time.time()
        result.append(clone)
    return result


# ---------------------------------------------------------------------------
# PKN014 — import heavy module inside function body
# ---------------------------------------------------------------------------

def compute_aggregates(data: list[dict]) -> dict[str, Any]:
    """Compute statistical aggregates over the dataset."""
    import pandas as pd                                   # PKN014: import in function

    df = pd.DataFrame(data)
    return {
        "count": len(df),
        "mean_value": float(df["value"].mean()) if "value" in df.columns else 0.0,
        "std_value": float(df["value"].std()) if "value" in df.columns else 0.0,
    }


def run_feature_extraction(matrix: list[list[float]]) -> list[float]:
    """Extract principal components from a feature matrix."""
    import numpy as np                                    # PKN014: import in function

    arr = np.array(matrix)
    return arr.mean(axis=0).tolist()
