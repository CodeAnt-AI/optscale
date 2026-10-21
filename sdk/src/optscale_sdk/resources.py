"""Normalized resource inventory independent of recommendation eligibility."""

import copy
import re

from .analysis import number, scope

RESOURCE_TYPES = {
    "volume": ("describe_volumes", "Volumes", "VolumeId", "volume"),
    "elastic_ip": ("describe_addresses", "Addresses", "AllocationId", "elastic-ip"),
    "instance": ("describe_instances", "Reservations", "InstanceId", "instance"),
}


def resource_types(selected=None):
    selected = list(RESOURCE_TYPES) if selected is None else list(selected)
    if (not selected or len(set(selected)) != len(selected)
            or any(kind not in RESOURCE_TYPES for kind in selected)):
        raise ValueError("Select supported resource types without duplicates")
    return selected


def validate_resource(record, account_id, region):
    if not isinstance(record, dict) or record.get("type") not in RESOURCE_TYPES:
        raise ValueError("Invalid resource type")
    identifier = record.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise ValueError("Missing resource ID")
    kind = RESOURCE_TYPES[record["type"]][3]
    expected = f":ec2:{region}:{account_id}:{kind}/{identifier}"
    arn = record.get("arn")
    if not isinstance(arn, str) or not re.fullmatch(r"arn:aws(?:-[a-z]+)*" + re.escape(expected), arn):
        raise ValueError("Resource ARN does not match snapshot scope")


def inventory(snapshot, *, types=None):
    """Validate/filter a snapshot without requiring history, prices or metrics."""
    selected = resource_types(types)
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
        raise ValueError("Expected snapshot schema_version 1")
    scope(snapshot.get("account_id"), snapshot.get("region"))
    now = number(snapshot.get("collected_at"), "collected_at")
    if not isinstance(snapshot.get("resources"), list) or not isinstance(snapshot.get("collection"), dict):
        raise ValueError("Expected resources and collection")
    resources, errors, coverage, seen = [], [], {}, set()
    for kind in selected:
        coverage[kind] = {"complete": snapshot["collection"].get(kind) is True, "count": 0}
        if not coverage[kind]["complete"]:
            errors.append({"resource_type": kind, "code": "collection_incomplete"})
    for record in snapshot["resources"]:
        # Unknown types cannot be assigned safely to a shard.
        if not isinstance(record, dict) or record.get("type") not in RESOURCE_TYPES:
            raise ValueError("Unknown or malformed resource type")
        kind = record["type"]
        if kind not in selected:
            continue
        try:
            validate_resource(record, snapshot["account_id"], snapshot["region"])
            identity = (kind, record["id"])
            if identity in seen:
                raise ValueError("Duplicate resource")
            seen.add(identity)
            resources.append(copy.deepcopy(record))
            coverage[kind]["count"] += 1
        except ValueError:
            coverage[kind]["complete"] = False
            errors.append({"resource_type": kind, "code": "invalid_resource"})
    complete = all(item["complete"] for item in coverage.values())
    return {"schema_version": 1, "engine": "optscale", "mode": "resources",
            "account_id": snapshot["account_id"], "region": snapshot["region"],
            "collected_at": now, "status": "complete" if complete else "partial",
            "resources": resources, "errors": errors,
            "coverage": {"completed": complete, "resource_types": coverage}}
