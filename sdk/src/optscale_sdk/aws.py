"""Read-only AWS collectors, bounded to one account/region per invocation."""

import time
from datetime import datetime, timezone

from .analysis import DAY, analyze, number, rule_options, scope


def _clients(session, region):
    try:
        from botocore.config import Config
        if session is None:
            import boto3
            session = boto3.Session(region_name=region)
    except ImportError as error:
        raise RuntimeError("Install optscale-analysis[aws] for live scanning") from error
    config = Config(connect_timeout=3, read_timeout=10,
                    retries={"mode": "standard", "total_max_attempts": 2})
    return {service: session.client(service, region_name=region, config=config)
            for service in ("sts", "ec2", "cloudwatch")}


def _timestamp(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("AWS timestamp must be timezone-aware")
    return value.timestamp()


class _Collector:
    def __init__(self, clients, deadline, max_resources):
        self.clients = clients
        self.deadline = deadline
        self.remaining = max_resources

    def call(self, service, method, **kwargs):
        # Leave time for one bounded SDK request (including retry) and output.
        if time.monotonic() + 35 >= self.deadline:
            raise TimeoutError("Scan deadline reached")
        return getattr(self.clients[service], method)(**kwargs)

    def records(self, method, key):
        token = None
        seen_tokens = set()
        while True:
            args = {"NextToken": token} if token else {}
            response = self.call("ec2", method, **args)
            records = response[key]
            if key == "Reservations":
                records = [instance for reservation in records for instance in reservation["Instances"]]
            for record in records:
                if self.remaining <= 0:
                    raise OverflowError("Resource limit reached")
                self.remaining -= 1
                yield record
            token = response.get("NextToken")
            if not token:
                return
            if token in seen_tokens:
                raise ValueError("Repeated pagination token")
            seen_tokens.add(token)

    def metrics(self, instance_id, days, now, detailed):
        end = int(now // 3600 * 3600)
        start = int(end - days * DAY)
        period = 3600
        result = {"start": start, "end": end}
        expected_points = (end - start) / period
        expected_samples = (end - start) / (60 if detailed else 300)
        for key, metric in (("cpu", "CPUUtilization"), ("network_in", "NetworkIn"),
                            ("network_out", "NetworkOut")):
            response = self.call(
                "cloudwatch", "get_metric_statistics", Namespace="AWS/EC2",
                MetricName=metric, Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=datetime.fromtimestamp(start, timezone.utc),
                EndTime=datetime.fromtimestamp(end, timezone.utc), Period=period,
                Statistics=["Sum", "SampleCount"],
            )
            points = {}
            for point in response["Datapoints"]:
                stamp = _timestamp(point["Timestamp"])
                if start <= stamp < end:
                    number(point["Sum"], "metric sum")
                    number(point["SampleCount"], "sample count", minimum=1)
                    points[stamp] = point
            samples = sum(point["SampleCount"] for point in points.values())
            total = sum(point["Sum"] for point in points.values())
            denominator = samples if key == "cpu" else len(points) * period
            result[key] = {
                "average": total / denominator if denominator else None,
                "coverage": min(len(points) / expected_points, samples / expected_samples, 1),
            }
        return result


def _history(previous_state, account_id, region, now):
    if previous_state is None:
        return {}
    if (not isinstance(previous_state, dict) or previous_state.get("schema_version") != 1
            or previous_state.get("account_id") != account_id
            or previous_state.get("region") != region
            or not isinstance(previous_state.get("resources"), dict)):
        raise ValueError("Previous state must match the scan account, region and schema")
    for arn, observation in previous_state["resources"].items():
        if not isinstance(arn, str) or not isinstance(observation, dict):
            raise ValueError("Invalid previous observation")
        parts = arn.split(":", 5)
        if (len(parts) != 6 or parts[0] != "arn" or parts[2:5] != ["ec2", region, account_id]
                or not parts[5].startswith(("volume/", "elastic-ip/"))):
            raise ValueError("Previous observation ARN does not match scan scope")
        if not isinstance(observation.get("unused"), bool):
            raise ValueError("Invalid previous observation state")
        observed_at = number(observation.get("observed_at"), "observed_at", maximum=now)
        number(observation.get("unused_since"), "unused_since", maximum=observed_at)
    return previous_state["resources"]


def scan_aws(*, region, session=None, account_id=None, rules=None, options=None, previous_state=None,
             timeout_seconds=600, max_resources=10000, max_history_gap_seconds=2 * DAY):
    """Collect and analyze AWS inventory with ambient or caller-supplied credentials.

    Caller owns scheduling, retries, tenancy and state storage. This function
    creates no AWS resources. The timeout is cooperative: use a subprocess hard
    timeout below the Lambda deadline as well. Results include next observation
    state and the normalized snapshot, allowing offline replay/cost enrichment.
    """
    configured = rule_options(rules, options)
    scope("000000000000", region)
    if account_id is not None:
        scope(account_id, region)
    number(timeout_seconds, "timeout_seconds", minimum=40, maximum=840)
    number(max_resources, "max_resources", minimum=1)
    if not isinstance(max_resources, int):
        raise ValueError("max_resources must be an integer")
    number(max_history_gap_seconds, "max_history_gap_seconds", minimum=1, maximum=30 * DAY)
    deadline = time.monotonic() + timeout_seconds
    collector = _Collector(_clients(session, region), deadline, max_resources)
    identity = collector.call("sts", "get_caller_identity")
    if account_id is not None and identity["Account"] != account_id:
        raise ValueError("AWS credentials do not match the requested account")
    account_id = identity["Account"]
    scope(account_id, region)
    partition = identity["Arn"].split(":")[1]
    now = time.time()
    previous = _history(previous_state, account_id, region, now)
    # Bound retained state by both age and account/region. Missing observations
    # on a failed scan must not reset the other rule's history.
    observations = {arn: dict(value) for arn, value in previous.items()
                    if now - value["observed_at"] <= max_history_gap_seconds}
    snapshot = {"schema_version": 1, "account_id": account_id, "region": region,
                "collected_at": now, "resources": [], "collection": {}}
    collection_errors = []
    timed_out = False
    for rule, config in configured.items():
        resource_type = config["resource_type"]
        snapshot["collection"][resource_type] = False
        method, key, id_field, arn_type = {
            "volume": ("describe_volumes", "Volumes", "VolumeId", "volume"),
            "elastic_ip": ("describe_addresses", "Addresses", "AllocationId", "elastic-ip"),
            "instance": ("describe_instances", "Reservations", "InstanceId", "instance"),
        }[resource_type]
        seen_arns = set()
        try:
            for raw in collector.records(method, key):
                identifier = raw[id_field]
                arn = f"arn:{partition}:ec2:{region}:{account_id}:{arn_type}/{identifier}"
                seen_arns.add(arn)
                resource = {"id": identifier, "arn": arn, "type": resource_type}
                if resource_type == "instance":
                    resource["running"] = raw["State"]["Name"] == "running"
                    resource["launched_at"] = _timestamp(raw["LaunchTime"])
                    if resource["running"] and resource["launched_at"] < now - config["days_threshold"] * DAY:
                        try:
                            resource["metrics"] = collector.metrics(
                                identifier, config["days_threshold"], now,
                                raw.get("Monitoring", {}).get("State") == "enabled")
                        except TimeoutError:
                            snapshot["resources"].append(resource)
                            raise
                        except Exception:
                            # analyze() marks this resource/rule incomplete;
                            # retain successfully collected metrics elsewhere.
                            collection_errors.append({"rule_id": rule, "resource_id": identifier,
                                                      "code": "metrics_collection_failed"})
                else:
                    unused = (raw["State"] == "available" and not raw["Attachments"]
                              if resource_type == "volume" else
                              not any(raw.get(field) for field in
                                      ("AssociationId", "NetworkInterfaceId", "InstanceId")))
                    old = observations.get(arn, {})
                    since = old["unused_since"] if unused and old.get("unused") else now
                    observations[arn] = {"unused": unused, "unused_since": since, "observed_at": now}
                    resource.update(unused=unused, unused_since=since)
                snapshot["resources"].append(resource)
            snapshot["collection"][resource_type] = True
            if resource_type != "instance":
                prefix = f"arn:{partition}:ec2:{region}:{account_id}:{arn_type}/"
                observations = {arn: value for arn, value in observations.items()
                                if not arn.startswith(prefix) or arn in seen_arns}
        except Exception as error:
            code = "collection_failed"
            if isinstance(error, TimeoutError):
                timed_out = True
                code = "deadline_exceeded"
            elif isinstance(error, OverflowError):
                code = "resource_limit_exceeded"
            # Exception messages can contain credentials/endpoints; never emit them.
            collection_errors.append({"rule_id": rule, "code": code})
    result = analyze(snapshot, rules=list(configured), options=options)
    result["errors"].extend(collection_errors)
    if timed_out:
        result["status"] = "timed_out"
    result["snapshot"] = snapshot
    result["state"] = {"schema_version": 1, "account_id": account_id, "region": region,
                       "resources": observations}
    return result
