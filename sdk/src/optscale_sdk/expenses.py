"""Daily Cost Explorer data independent of anomaly thresholds or inventory types."""

import copy
import re
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, localcontext

from .analysis import number, scope
from .anomalies import parse_date

COST_METRICS = ("UnblendedCost", "AmortizedCost", "NetUnblendedCost", "NetAmortizedCost", "BlendedCost")
GROUP_DIMENSIONS = {"service": "SERVICE", "region": "REGION", "usage_type": "USAGE_TYPE"}


def expense_options(start_date, end_date, group_by=None, metric="UnblendedCost", *, now=None):
    start, end = parse_date(start_date), parse_date(end_date)
    today = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).date()
    if not start < end <= today or (end - start).days > 366:
        raise ValueError("Select 1–366 closed UTC days; end is exclusive")
    groups = ["service", "region"] if group_by is None else list(group_by)
    if not 1 <= len(groups) <= 2 or len(set(groups)) != len(groups) or any(key not in GROUP_DIMENSIONS for key in groups):
        raise ValueError("Select one or two distinct billing dimensions")
    if metric not in COST_METRICS:
        raise ValueError("Unsupported cost metric")
    return start, end, groups


def _amount(value):
    # Preserve AWS decimal precision and negative credits/refunds; never use float sums.
    if not isinstance(value, str):
        raise TypeError("Cost must be a decimal string")
    if len(value) > 128:
        raise ValueError("Invalid cost")
    try:
        amount = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("Invalid cost") from error
    if not amount.is_finite() or abs(amount.adjusted()) > 100:
        raise ValueError("Invalid cost")
    return amount


def expenses_report(snapshot):
    """Validate/replay normalized billing evidence, retaining incomplete daily data."""
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
        raise ValueError("Expected billing snapshot schema_version 1")
    scope(snapshot.get("account_id"), snapshot.get("region"))
    now = number(snapshot.get("collected_at"), "collected_at")
    start, end, groups = expense_options(snapshot["start_date"], snapshot["end_date"],
                                         snapshot["group_by"], snapshot["metric"], now=now)
    if not isinstance(snapshot.get("expenses"), list) or not isinstance(snapshot.get("days"), dict):
        raise TypeError("Expected daily expense records and coverage")
    records, errors, seen, totals = [], [], set(), {}
    days = {}
    for offset in range((end - start).days):
        day = (start + timedelta(days=offset)).isoformat()
        evidence = snapshot["days"].get(day, {})
        complete = (snapshot.get("collection_complete") is True and evidence.get("returned") is True
                    and evidence.get("estimated") is False)
        days[day] = {"returned": evidence.get("returned") is True,
                     "estimated": evidence.get("estimated"), "complete": complete}
        if not complete:
            errors.append({"date": day, "code": "estimated_billing" if evidence.get("estimated") is True else "incomplete_billing_day"})
    for record in snapshot["expenses"]:
        try:
            if not isinstance(record, dict):
                raise TypeError("Invalid billing row")
            day, dimensions = record["date"], record["dimensions"]
            if day not in days or not isinstance(dimensions, dict) or set(dimensions) != set(groups):
                raise ValueError("Billing row outside scope")
            if any(not isinstance(value, str) for value in dimensions.values()):
                raise ValueError("Invalid billing dimensions")
            if not days[day]["returned"]:
                raise ValueError("Billing row has no day evidence")
            currency = record["currency"]
            if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
                raise ValueError("Invalid currency")
            amount = _amount(record["amount"])
            identity = (day, tuple(dimensions[key] for key in groups))
            if identity in seen:
                raise ValueError("Duplicate daily billing group")
            seen.add(identity)
            normalized = copy.deepcopy(record)
            normalized.update(account_id=snapshot["account_id"], metric=snapshot["metric"],
                              estimated=days[day]["estimated"], complete=days[day]["complete"])
            records.append(normalized)
            with localcontext() as context:
                context.prec = 300
                totals[currency] = totals.get(currency, Decimal(0)) + amount
        except (ValueError, KeyError, TypeError):
            errors.append({"code": "invalid_expense_record"})
    complete = not errors and snapshot.get("collection_complete") is True
    return {"schema_version": 1, "engine": "optscale", "mode": "expenses",
            "account_id": snapshot["account_id"], "region": snapshot["region"],
            "collected_at": now, "start_date": start.isoformat(), "end_date": end.isoformat(),
            "granularity": "DAILY", "group_by": groups, "metric": snapshot["metric"],
            "status": "complete" if complete else "partial", "expenses": records,
            "summary": {"total": len(records), "totals_by_currency": {key: str(value) for key, value in totals.items()}},
            "coverage": {"completed": complete, "days": days,
                         "collection_complete": snapshot.get("collection_complete") is True}, "errors": errors}


def collect_expenses_aws(*, region, start_date, end_date, session=None, account_id=None,
                         group_by=None, metric="UnblendedCost", services=None, billing_regions=None,
                         timeout_seconds=600, max_records=10000):
    """Read daily account costs across ALL services/regions, including global charges.

    region selects the SDK client, not a billing filter. Filters are explicit.
    No costs are allocated to resource IDs. End date is exclusive, as in AWS CE.
    """
    from .aws import _collection_error, _operation_collector

    start, end, groups = expense_options(start_date, end_date, group_by, metric)
    for selected in (services, billing_regions):
        if selected is not None and (not isinstance(selected, list) or not selected
                                     or any(not isinstance(value, str) or not value for value in selected)):
            raise ValueError("Billing filters must be nonempty string lists")
    collector, identity = _operation_collector(session, region, account_id, timeout_seconds,
                                               max_records, ("sts", "ce"))
    filters = [{"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [identity["Account"]]}}]
    for dimension, values in (("SERVICE", services), ("REGION", billing_regions)):
        if values is not None:
            filters.append({"Dimensions": {"Key": dimension, "Values": values}})
    request = {"TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
               "Granularity": "DAILY", "Metrics": [metric],
               "GroupBy": [{"Type": "DIMENSION", "Key": GROUP_DIMENSIONS[key]} for key in groups],
               "Filter": filters[0] if len(filters) == 1 else {"And": filters}}
    snapshot = {"schema_version": 1, "account_id": identity["Account"], "region": region,
                "collected_at": time.time(), "start_date": start.isoformat(), "end_date": end.isoformat(),
                "group_by": groups, "metric": metric, "days": {}, "expenses": [], "collection_complete": False}
    errors, tokens, seen = [], set(), set()
    try:
        while True:
            response = collector.call("ce", "get_cost_and_usage", **request)
            definitions = response.get("GroupDefinitions")
            if definitions is not None and definitions != request["GroupBy"]:
                raise ValueError("Unexpected billing group definitions")
            for period in response["ResultsByTime"]:
                # Periods legitimately repeat across group pagination pages.
                day = parse_date(period["TimePeriod"]["Start"])
                if not start <= day < end or parse_date(period["TimePeriod"]["End"]) != day + timedelta(days=1):
                    raise ValueError("Unexpected billing period")
                if not isinstance(period.get("Estimated"), bool):
                    raise TypeError("Missing billing estimate flag")
                evidence = snapshot["days"].setdefault(day.isoformat(), {"returned": True, "estimated": False})
                evidence["estimated"] |= period["Estimated"]
                if not period["Groups"] and metric in period.get("Total", {}) and _amount(period["Total"][metric]["Amount"]) != 0:
                    raise ValueError("Grouped billing response contains unallocated costs")
                for group in period["Groups"]:
                    if collector.remaining <= 0:
                        raise OverflowError("Billing record limit reached")
                    keys = group["Keys"]
                    if not isinstance(keys, list) or len(keys) != len(groups) or any(not isinstance(key, str) for key in keys):
                        raise ValueError("Unexpected billing dimensions")
                    identity_key = (day.isoformat(), tuple(keys))
                    if identity_key in seen:
                        raise ValueError("Duplicate daily billing group")
                    cost = group["Metrics"][metric]
                    _amount(cost["Amount"])
                    snapshot["expenses"].append({"date": day.isoformat(), "dimensions": dict(zip(groups, keys)),
                                                 "amount": cost["Amount"], "currency": cost["Unit"]})
                    collector.remaining -= 1
                    seen.add(identity_key)
            token = response.get("NextPageToken")
            if not token:
                snapshot["collection_complete"] = True
                break
            if not isinstance(token, str) or token in tokens:
                raise ValueError("Repeated billing pagination token")
            tokens.add(token)
            request["NextPageToken"] = token
    except Exception as error:  # noqa: BLE001 - redact optional AWS SDK exception bodies
        errors.append({"code": _collection_error(error)})
    result = expenses_report(snapshot)
    result["filters"] = {"services": services, "regions": billing_regions}
    result["errors"].extend(errors)
    if errors:
        result["status"] = "timed_out" if any(error["code"] == "deadline_exceeded" for error in errors) else "partial"
        result["coverage"]["completed"] = False
    # Every point is top-level; callers need not persist private anomaly snapshots.
    return result
