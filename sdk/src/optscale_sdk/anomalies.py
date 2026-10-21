"""Daily expense/resource-count spikes without platform services.

Uses the percentage-above-mean predicate from
docker_images/organization_violations/worker.py::_process_anomaly.
Unlike the platform, requires explicit, consecutive, complete daily evidence.
"""

from datetime import date, datetime, timedelta, timezone
import re

from .analysis import number, scope

ANOMALY_TYPES = ("expense", "resource_count")


def anomaly_options(types=None, lookback_days=7, threshold_percent=30):
    selected = ["expense"] if types is None else list(types)
    if not selected or len(set(selected)) != len(selected) or set(selected) - set(ANOMALY_TYPES):
        raise ValueError("Select supported anomaly types without duplicates")
    number(lookback_days, "lookback_days", minimum=1, maximum=180)
    if not isinstance(lookback_days, int):
        raise ValueError("lookback_days must be an integer")
    number(threshold_percent, "threshold_percent")
    return selected


def parse_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Expected ISO date")
    return date.fromisoformat(value)


def detect_anomalies(snapshot, *, types=None, lookback_days=7, threshold_percent=30):
    """Evaluate snapshot['date'] against the preceding complete UTC days.

    Series IDs are caller-owned scopes (e.g. service names); no allocation of
    account costs to individual resources is attempted. Missing days are not zero.
    """
    selected = anomaly_options(types, lookback_days, threshold_percent)
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
        raise ValueError("Expected snapshot schema_version 1")
    scope(snapshot.get("account_id"), snapshot.get("region"))
    now = number(snapshot.get("collected_at"), "collected_at")
    target = parse_date(snapshot.get("date"))
    if target >= datetime.fromtimestamp(now, timezone.utc).date():
        raise ValueError("The target must be a closed UTC day")
    if not isinstance(snapshot.get("series"), list) or not isinstance(snapshot.get("collection"), dict):
        raise ValueError("Expected series and per-type collection completeness")
    findings, errors, coverage, seen = [], [], {}, set()
    for kind in selected:
        coverage[kind] = {"complete": snapshot["collection"].get(kind) is True,
                          "evaluated": 0, "skipped": 0, "findings": 0}
        if not coverage[kind]["complete"]:
            errors.append({"anomaly_type": kind, "code": "collection_incomplete"})
    required = [(target - timedelta(days=offset)).isoformat()
                for offset in range(lookback_days + 1)]
    for series in snapshot["series"]:
        if not isinstance(series, dict) or series.get("type") not in ANOMALY_TYPES:
            raise ValueError("Unknown or malformed anomaly type")
        kind = series["type"]
        if kind not in selected:
            continue
        stats = coverage[kind]
        reason = "invalid_series"
        try:
            identifier = series.get("id")
            if not isinstance(identifier, str) or not identifier or (kind, identifier) in seen:
                raise ValueError("Missing or duplicate series ID")
            seen.add((kind, identifier))
            currency = series.get("currency") if kind == "expense" else None
            if kind == "expense" and (not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency)):
                raise ValueError("Expected currency")
            if not isinstance(series.get("points"), list):
                raise ValueError("Expected daily points")
            points = {}
            for point in series["points"]:
                day = parse_date(point["date"]).isoformat()
                if day in points:
                    raise ValueError("Duplicate daily point")
                points[day] = point
                value = number(point["value"], "daily value")
                if kind == "resource_count" and int(value) != value:
                    raise ValueError("Resource count must be integral")
                if not isinstance(point.get("complete"), bool):
                    raise ValueError("Expected daily completeness")
            if any(day not in points or points[day]["complete"] is not True for day in required):
                reason = "insufficient_history"
                raise ValueError("Incomplete daily window")
            current = points[required[0]]["value"]
            average = number(sum(points[day]["value"] / lookback_days for day in required[1:]), "average")
            limit = number(average + average * threshold_percent / 100, "limit")
            if current > limit:
                increase = number((current - average) / average * 100, "increase_percent") if average else None
                findings.append({"engine": "optscale", "rule_id": f"{kind}_anomaly",
                                 "series_id": identifier, "anomaly_type": kind,
                                 "account_id": snapshot["account_id"], "region": snapshot["region"],
                                 "date": target.isoformat(), "current": current, "average": average,
                                 "threshold_percent": threshold_percent, "lookback_days": lookback_days,
                                 "increase_percent": increase,
                                 "currency": currency, "action": "review",
                                 "title": f"Daily {kind.replace('_', ' ')} spike"})
                stats["findings"] += 1
            stats["evaluated"] += 1
        except (ValueError, TypeError, KeyError, OverflowError):
            stats["complete"] = False
            stats["skipped"] += 1
            errors.append({"anomaly_type": kind, "code": reason})
    complete = all(item["complete"] for item in coverage.values())
    return {"schema_version": 1, "engine": "optscale", "mode": "anomalies",
            "account_id": snapshot["account_id"], "region": snapshot["region"],
            "collected_at": now, "date": target.isoformat(),
            "status": "complete" if complete else "partial", "findings": findings,
            "errors": errors, "coverage": {"completed": complete, "anomaly_types": coverage}}
