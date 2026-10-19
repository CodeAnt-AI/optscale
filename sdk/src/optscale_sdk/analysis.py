"""Extracted Bumi predicates; data collection and persistence belong to callers.

Derived from bumiworker/modules/recommendations/{obsolete_ips,
volumes_not_attached_for_a_long_time,abandoned_instances}.py. These rules retain
the original default thresholds, but missing cost does not suppress a finding.
Missing history/metrics is explicitly incomplete, never interpreted as zero.
"""

import math
import re

DAY = 86400
RULES = {
    "volumes_not_attached_for_a_long_time": {
        "resource_type": "volume", "days_threshold": 1,
        "action": "delete", "title": "Unattached EBS volume",
    },
    "obsolete_ips": {
        "resource_type": "elastic_ip", "days_threshold": 7,
        "action": "release_ip", "title": "Unused Elastic IP",
    },
    "abandoned_instances": {
        "resource_type": "instance", "days_threshold": 7,
        "cpu_percent_threshold": 5, "network_bps_threshold": 1000,
        "minimum_metric_coverage": 0.9,
        "action": "review", "title": "Idle EC2 instance",
    },
}


def number(value, name, minimum=0, maximum=None):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < minimum
            or (maximum is not None and value > maximum)):
        raise ValueError(f"Invalid {name}")
    return value


def scope(account_id, region):
    if not isinstance(account_id, str) or not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("account_id must be a 12-digit AWS account ID")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region):
        raise ValueError("An explicit AWS region is required")


def rule_options(rules=None, options=None):
    selected = list(RULES) if rules is None else list(rules)
    if not selected or len(set(selected)) != len(selected):
        raise ValueError("Select at least one rule, without duplicates")
    if any(rule not in RULES for rule in selected):
        raise ValueError("Unsupported rule; use optscale-scan --list-rules")
    options = {} if options is None else options
    if not isinstance(options, dict) or set(options) - set(selected):
        raise ValueError("Options must be keyed by selected rule IDs")
    configured = {}
    for rule in selected:
        defaults = RULES[rule]
        overrides = options.get(rule, {})
        allowed = set(defaults) - {"resource_type", "action", "title"}
        if not isinstance(overrides, dict) or set(overrides) - allowed:
            raise ValueError(f"Unsupported options for {rule}")
        configured[rule] = {**defaults, **overrides}
        for key in allowed:
            maximum = {"days_threshold": 30, "cpu_percent_threshold": 100,
                       "minimum_metric_coverage": 1}.get(key)
            minimum = 1 if key == "days_threshold" else 0
            number(configured[rule][key], key, minimum, maximum)
        if configured[rule].get("minimum_metric_coverage") == 0:
            raise ValueError("minimum_metric_coverage must be greater than zero")
    return configured


def _match(resource, config, now):
    """Return (match, unavailable_reason, evidence), independently of cost."""
    resource_type = config["resource_type"]
    cutoff = now - config["days_threshold"] * DAY
    if resource_type in {"volume", "elastic_ip"}:
        if not isinstance(resource.get("unused"), bool):
            raise ValueError("unused must be boolean")
        if not resource["unused"]:
            return False, None, {}
        since = resource.get("unused_since")
        if since is None:
            return False, "history_unavailable", {}
        number(since, "unused_since", maximum=now)
        if since >= cutoff:
            return False, "observation_window_pending", {}
        return True, None, {"unused_since": since,
                            "history_source": "consecutive_scan_observations"}

    if not isinstance(resource.get("running"), bool):
        raise ValueError("running must be boolean")
    if not resource["running"]:
        return False, None, {}
    launched = number(resource.get("launched_at"), "launched_at", maximum=now)
    if launched >= cutoff:
        return False, "observation_window_pending", {}
    metrics = resource.get("metrics")
    if not isinstance(metrics, dict):
        return False, "metrics_unavailable", {}
    start = number(metrics.get("start"), "metrics.start", maximum=now)
    end = number(metrics.get("end"), "metrics.end", minimum=start, maximum=now)
    # Live collection uses complete UTC hours; tolerate only the final hour.
    if abs(start - cutoff) > 3600 or now - end > 3600:
        return False, "metric_window_mismatch", {}
    for key in ("cpu", "network_in", "network_out"):
        metric = metrics.get(key)
        if not isinstance(metric, dict) or metric.get("average") is None:
            return False, "metrics_unavailable", {}
        number(metric["average"], f"{key}.average",
               maximum=100 if key == "cpu" else None)
        coverage = number(metric.get("coverage"), f"{key}.coverage", maximum=1)
        if coverage < config["minimum_metric_coverage"]:
            return False, "insufficient_metric_coverage", {}
    idle = (metrics["cpu"]["average"] <= config["cpu_percent_threshold"]
            and metrics["network_in"]["average"] + metrics["network_out"]["average"]
            <= config["network_bps_threshold"])
    return idle, None, {"metrics": metrics}


def _finding(resource, rule, config, snapshot, evidence):
    # Costs are caller-provided resource costs, never guessed from account totals.
    cost = resource.get("cost")
    savings = None
    currency = None
    if cost is not None:
        if not isinstance(cost, dict):
            raise ValueError("cost must be an object")
        daily = number(cost.get("average_daily_cost"), "average_daily_cost")
        currency = cost.get("currency")
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("cost.currency must be a three-letter currency code")
        savings = round(number(daily * 30, "monthly savings"), 2)
        evidence = {**evidence, "average_daily_cost": daily, "currency": currency}
    return {
        "engine": "optscale", "rule_id": rule,
        "resource_arn": resource["arn"], "resource_id": resource["id"],
        "resource_type": resource["type"], "region": snapshot["region"],
        "account_id": snapshot["account_id"], "action": config["action"],
        "title": config["title"],
        "rationale": f"Matches {rule} over a {config['days_threshold']}-day window.",
        "evidence": [{"source": "optscale", "detail": evidence}],
        "estimated_monthly_savings": savings, "currency": currency,
        "savings_source": "provided_daily_cost_30_days" if cost is not None else None,
        "confidence": "medium", "related_findings": [],
        "risk_notes": "Review ownership and workload requirements before changing resources. "
                      "Savings are gross estimates; commitments may prevent realized savings.",
    }


def analyze(snapshot, *, rules=None, options=None):
    """Analyze a normalized single-account, single-region snapshot without I/O.

    The returned coverage is authoritative: do not auto-resolve old findings from
    incomplete rules. Unknown rules and malformed envelopes raise ValueError.
    Invalid individual records are isolated and make their rule incomplete.
    """
    configured = rule_options(rules, options)
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
        raise ValueError("Expected snapshot schema_version 1")
    scope(snapshot.get("account_id"), snapshot.get("region"))
    now = number(snapshot.get("collected_at"), "collected_at")
    resources = snapshot.get("resources")
    if not isinstance(resources, list):
        raise ValueError("resources must be a list")
    if any(not isinstance(resource, dict) or resource.get("type") not in
           {entry["resource_type"] for entry in RULES.values()} for resource in resources):
        raise ValueError("Unknown or malformed resource type")
    collection = snapshot.get("collection")
    if not isinstance(collection, dict):
        raise ValueError("collection must describe completeness for each resource type")
    findings, errors, coverage = [], [], {}
    for rule, config in configured.items():
        resource_type = config["resource_type"]
        stats = {"complete": collection.get(resource_type) is True,
                 "evaluated": 0, "skipped": 0, "findings": 0}
        if not stats["complete"]:
            errors.append({"rule_id": rule, "code": "collection_incomplete"})
        seen = set()
        for resource in resources:
            if resource["type"] != resource_type:
                continue
            try:
                identifier = resource.get("id")
                arn = resource.get("arn")
                if not isinstance(identifier, str) or not identifier or identifier in seen:
                    raise ValueError("Missing or duplicate resource ID")
                seen.add(identifier)
                kind = {"volume": "volume", "elastic_ip": "elastic-ip",
                        "instance": "instance"}[resource_type]
                expected = f":ec2:{snapshot['region']}:{snapshot['account_id']}:{kind}/{identifier}"
                if not isinstance(arn, str) or not re.fullmatch(r"arn:aws(?:-[a-z]+)*" + re.escape(expected), arn):
                    raise ValueError("Resource ARN does not match snapshot scope")
                matches, reason, evidence = _match(resource, config, now)
                if reason:
                    stats["complete"] = False
                    stats["skipped"] += 1
                    errors.append({"rule_id": rule, "resource_id": identifier, "code": reason})
                    continue
                if matches:
                    findings.append(_finding(resource, rule, config, snapshot, evidence))
                    stats["findings"] += 1
                stats["evaluated"] += 1
            except (ValueError, TypeError, KeyError):
                stats["complete"] = False
                stats["skipped"] += 1
                errors.append({"rule_id": rule, "code": "invalid_resource"})
        coverage[rule] = stats
    complete = all(item["complete"] for item in coverage.values())
    return {"schema_version": 1, "engine": "optscale", "status": "complete" if complete else "partial",
            "account_id": snapshot["account_id"], "region": snapshot["region"],
            "collected_at": now, "findings": findings, "errors": errors,
            "coverage": {"completed": complete, "rules": coverage}}
