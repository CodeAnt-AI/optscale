"""Additional read-only AWS cost checks, independent of hosted OptScale services.

These are CLI-native checks, not claims of parity with every hosted Bumi rule.
Absent CloudWatch samples are unknown, never zero usage.
"""

from datetime import datetime, timezone

RULES = {
    "idle_rds_instances": {
        "resource_type": "rds_instance", "days_threshold": 7,
        "minimum_metric_coverage": 0.9, "cpu_percent_threshold": 5,
        "action": "review", "title": "Idle RDS instance",
    },
    "abandoned_load_balancers": {
        "resource_type": "load_balancer", "days_threshold": 7,
        "minimum_metric_coverage": 0.9,
        "action": "review", "title": "Idle load balancer",
    },
    "idle_dynamodb_tables": {
        "resource_type": "dynamodb_table", "days_threshold": 7,
        "minimum_metric_coverage": 0.9,
        "action": "review", "title": "Idle provisioned DynamoDB table",
    },
    "underused_lambda_provisioned_concurrency": {
        "resource_type": "lambda_function", "days_threshold": 7,
        "minimum_metric_coverage": 0.9, "utilization_percent_threshold": 10,
        "action": "review", "title": "Underused Lambda provisioned concurrency",
    },
    "s3_incomplete_multipart_uploads": {
        "resource_type": "s3_bucket", "days_threshold": 7,
        "action": "review", "title": "Stale S3 multipart uploads",
    },
    "log_groups_without_retention": {
        "resource_type": "log_group", "days_threshold": 7,
        "action": "review", "title": "Stored CloudWatch logs without retention",
    },
}


def _metrics_match(metrics, limits, config, now):
    from .analysis import DAY, number

    if not isinstance(metrics, dict):
        return False, "metrics_unavailable"
    start = number(metrics.get("start"), "metrics.start", maximum=now)
    end = number(metrics.get("end"), "metrics.end", minimum=start, maximum=now)
    if abs(start - (now - config["days_threshold"] * DAY)) > 3600 or now - end > 3600:
        return False, "metric_window_mismatch"
    for name in limits:
        point = metrics.get(name)
        if not isinstance(point, dict) or point.get("maximum") is None:
            return False, "metrics_unavailable"
        number(point["maximum"], name)
        coverage = number(point.get("coverage"), "metric coverage", maximum=1)
        if coverage < config["minimum_metric_coverage"]:
            return False, "insufficient_metric_coverage"
    return all(metrics[name]["maximum"] <= limit for name, limit in limits.items()), None


def match(resource, config, now):
    from .analysis import DAY, number

    kind = config["resource_type"]
    if resource.get("recommendation_collection_failed"):
        return False, "recommendation_collection_failed", {}
    if kind == "log_group":
        stored = number(resource.get("stored_bytes"), "stored_bytes")
        retention = resource.get("retention_days")
        if retention is not None:
            number(retention, "retention_days", minimum=1)
        return retention is None and stored > 0, None, {
            "stored_bytes": stored, "retention_days": retention,
            "reason": "Stored logs never expire. Review retention requirements and set an expiry policy.",
        }
    if kind == "s3_bucket":
        count = number(resource.get("stale_upload_count"), "stale_upload_count")
        oldest = resource.get("oldest_upload_at")
        if count:
            number(oldest, "oldest_upload_at", maximum=now - config["days_threshold"] * DAY)
        return count > 0, None, {
            "stale_upload_count": count, "oldest_upload_at": oldest,
            "reason": f"Incomplete multipart uploads are older than {config['days_threshold']} days. "
                      "Review and abort stale uploads or configure an abort lifecycle rule.",
        }
    if kind == "lambda_function":
        candidates = []
        unavailable = None
        for allocation in resource["provisioned_concurrency"]:
            if number(allocation["allocated"], "allocated") == 0:
                continue
            modified = number(allocation["modified_at"], "modified_at", maximum=now)
            if modified > now - config["days_threshold"] * DAY:
                unavailable = "observation_window_pending"
                continue
            matched, reason = _metrics_match(allocation.get("metrics"), {
                "utilization": config["utilization_percent_threshold"] / 100,
            }, config, now)
            unavailable = unavailable or reason
            if matched:
                candidates.append(allocation)
        # Preserve supported candidates while marking unknown allocations incomplete.
        return bool(candidates), unavailable, {
            "allocations": candidates, "other_allocations_incomplete": unavailable is not None,
            "reason": "Provisioned concurrency remains under the utilization threshold. "
                      "Review the listed qualifiers and reduce provisioned capacity if appropriate.",
        }
    if kind == "dynamodb_table":
        if resource["billing_mode"] != "PROVISIONED" or resource["state"] != "ACTIVE":
            return False, None, {}
        limits = {"reads": 0, "writes": 0}
    elif kind == "rds_instance":
        if resource["state"] != "available":
            return False, None, {}
        limits = {"cpu": config["cpu_percent_threshold"], "connections": 0,
                  "reads": 0, "writes": 0}
    else:
        if resource["state"] != "active":
            return False, None, {}
        limits = {"traffic": 0, "bytes": 0}
    matched, reason = _metrics_match(resource.get("metrics"), limits, config, now)
    return matched, reason, {"metrics": resource.get("metrics"), "thresholds": limits}


def _metrics(collector, namespace, dimensions, names, days, now):
    from .analysis import DAY, number
    from .aws import _timestamp

    end = int(now // 3600 * 3600)
    start = end - days * DAY
    result = {"start": start, "end": end}
    for key, name in names.items():
        response = collector.call(
            "cloudwatch", "get_metric_statistics", Namespace=namespace, MetricName=name,
            Dimensions=[{"Name": name, "Value": value} for name, value in dimensions.items()],
            StartTime=datetime.fromtimestamp(start, timezone.utc),
            EndTime=datetime.fromtimestamp(end, timezone.utc), Period=3600,
            Statistics=["Maximum", "SampleCount"],
        )
        points = {}
        for point in response["Datapoints"]:
            stamp = _timestamp(point["Timestamp"])
            if start <= stamp < end:
                number(point["Maximum"], "Maximum")
                number(point["SampleCount"], "SampleCount", minimum=1)
                points[stamp] = point
        result[key] = {
            "maximum": max((point["Maximum"] for point in points.values()), default=None),
            "coverage": min(len(points) / (days * 24),
                            sum(point["SampleCount"] for point in points.values()) / (days * 24 * 60), 1),
        }
    return result


def enrich(collector, resource, config, now):
    """Collect only the additional evidence required for a recommendation."""
    from .analysis import DAY
    from .aws import _timestamp

    kind = resource["type"]
    days = config["days_threshold"]
    if kind == "log_group":
        return
    if kind == "s3_bucket":
        request = {"Bucket": resource["id"], "ExpectedBucketOwner": resource["account_id"]}
        seen = set()
        resource.update(stale_upload_count=0, oldest_upload_at=None)
        while True:
            response = collector.call("s3", "list_multipart_uploads", **request)
            for upload in response.get("Uploads", []):
                if collector.remaining <= 0:
                    raise OverflowError("Resource limit reached")
                collector.remaining -= 1
                initiated = _timestamp(upload["Initiated"])
                if initiated < now - days * DAY:
                    resource["stale_upload_count"] += 1
                    resource["oldest_upload_at"] = min(resource["oldest_upload_at"] or initiated, initiated)
            if not response["IsTruncated"]:
                return
            token = (response["NextKeyMarker"], response.get("NextUploadIdMarker", ""))
            if not token[0] or token in seen:
                raise ValueError("Repeated multipart pagination token")
            seen.add(token)
            request.update(KeyMarker=token[0], UploadIdMarker=token[1])
    if kind == "lambda_function":
        request = {"FunctionName": resource["id"]}
        seen = set()
        resource["provisioned_concurrency"] = []
        while True:
            response = collector.call("lambda", "list_provisioned_concurrency_configs", **request)
            for allocation in response.get("ProvisionedConcurrencyConfigs", []):
                if collector.remaining <= 0:
                    raise OverflowError("Resource limit reached")
                collector.remaining -= 1
                if allocation["Status"] != "READY":
                    raise ValueError("Provisioned concurrency is changing")
                function_arn = allocation["FunctionArn"]
                if not function_arn.startswith(resource["arn"] + ":"):
                    raise ValueError("Foreign concurrency allocation")
                modified = datetime.fromisoformat(allocation["LastModified"].replace("Z", "+00:00"))
                entry = {"qualifier": function_arn.rsplit(":", 1)[1],
                         "allocated": allocation["AllocatedProvisionedConcurrentExecutions"],
                         "modified_at": _timestamp(modified)}
                if entry["allocated"] > 0 and entry["modified_at"] <= now - days * DAY:
                    entry["metrics"] = _metrics(collector, "AWS/Lambda", {
                        "FunctionName": resource["id"], "Resource": function_arn.split(":function:")[1],
                    }, {"utilization": "ProvisionedConcurrencyUtilization"}, days, now)
                resource["provisioned_concurrency"].append(entry)
            token = response.get("NextMarker")
            if not token:
                return
            if token in seen:
                raise ValueError("Repeated concurrency pagination token")
            seen.add(token)
            request["Marker"] = token
    if kind == "dynamodb_table":
        if resource["billing_mode"] != "PROVISIONED" or resource["state"] != "ACTIVE":
            return
        namespace, dimensions, names = "AWS/DynamoDB", {"TableName": resource["id"]}, {
            "reads": "ConsumedReadCapacityUnits", "writes": "ConsumedWriteCapacityUnits"}
    elif kind == "rds_instance":
        if resource["state"] != "available":
            return
        namespace, dimensions, names = "AWS/RDS", {"DBInstanceIdentifier": resource["id"]}, {
            "cpu": "CPUUtilization", "connections": "DatabaseConnections", "reads": "ReadIOPS", "writes": "WriteIOPS"}
    else:
        if resource["state"] != "active":
            return
        lb_type = resource["load_balancer_type"]
        if lb_type not in ("application", "network"):
            raise ValueError("Unsupported load balancer metrics")
        namespace = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB"
        dimensions = {"LoadBalancer": resource["arn"].split(":loadbalancer/")[1]}
        names = {"traffic": "RequestCount" if lb_type == "application" else "NewFlowCount", "bytes": "ProcessedBytes"}
    resource["metrics"] = _metrics(collector, namespace, dimensions, names, days, now)
