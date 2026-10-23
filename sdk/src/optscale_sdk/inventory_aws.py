"""Additional AWS inventory adapters. Explicit allowlists keep secrets out of JSON."""

from datetime import datetime

# service, API, result key, input token, output token
COLLECTORS = {
    "rds_instance": ("rds", "describe_db_instances", "DBInstances", "Marker", "Marker"),
    "rds_cluster": ("rds", "describe_db_clusters", "DBClusters", "Marker", "Marker"),
    "lambda_function": ("lambda", "list_functions", "Functions", "Marker", "NextMarker"),
    "load_balancer": ("elbv2", "describe_load_balancers", "LoadBalancers", "Marker", "NextMarker"),
    "dynamodb_table": ("dynamodb", "list_tables", "TableNames", "ExclusiveStartTableName", "LastEvaluatedTableName"),
    "s3_bucket": ("s3", "list_buckets", "Buckets", "ContinuationToken", "ContinuationToken"),
    "ecs_cluster": ("ecs", "list_clusters", "clusterArns", "nextToken", "nextToken"),
    "eks_cluster": ("eks", "list_clusters", "clusters", "nextToken", "nextToken"),
    "log_group": ("logs", "describe_log_groups", "logGroups", "nextToken", "nextToken"),
}
# ARN service and resource prefix. S3 is account-owned, but its ARN has no region/account.
ARN_TYPES = {
    "rds_instance": ("rds", "db:"), "rds_cluster": ("rds", "cluster:"),
    "lambda_function": ("lambda", "function:"), "load_balancer": ("elasticloadbalancing", "loadbalancer/"),
    "dynamodb_table": ("dynamodb", "table/"), "s3_bucket": ("s3", ""),
    "ecs_cluster": ("ecs", "cluster/"), "eks_cluster": ("eks", "cluster/"),
    "log_group": ("logs", "log-group:"),
}


def _pages(collector, kind, region):
    service, method, key, input_token, output_token = COLLECTORS[kind]
    request = {}
    # Regional bucket listing avoids duplicate global buckets and N GetBucketLocation calls.
    if kind == "s3_bucket":
        request = {"BucketRegion": region, "MaxBuckets": 1000}
    seen = set()
    while True:
        response = collector.call(service, method, **request)
        for raw in response[key]:
            if collector.remaining <= 0:
                raise OverflowError("Resource limit reached")
            collector.remaining -= 1
            yield raw
        token = response.get(output_token)
        if not token:
            return
        if not isinstance(token, str) or token in seen:
            raise ValueError("Repeated inventory pagination token")
        seen.add(token)
        request[input_token] = token


def collect_type(collector, kind, account_id, region, partition):
    """Yield normalized resources; never serialize an AWS response wholesale."""
    for raw in _pages(collector, kind, region):
        service = ARN_TYPES[kind][0]
        record = {"type": kind, "service": service, "account_id": account_id, "region": region}
        if kind in ("rds_instance", "rds_cluster"):
            instance = kind == "rds_instance"
            identifier = raw["DBInstanceIdentifier" if instance else "DBClusterIdentifier"]
            record.update(id=identifier, arn=raw["DBInstanceArn" if instance else "DBClusterArn"],
                          state=raw["DBInstanceStatus" if instance else "Status"], engine=raw.get("Engine"),
                          instance_type=raw.get("DBInstanceClass"), size_gib=raw.get("AllocatedStorage"))
            if "TagList" in raw:
                record["tags"] = {tag["Key"]: tag["Value"] for tag in raw["TagList"]}
        elif kind == "lambda_function":
            record.update(id=raw["FunctionName"], arn=raw["FunctionArn"],
                          runtime=raw.get("Runtime"), memory_mib=raw.get("MemorySize"),
                          state=raw.get("State"), last_modified=raw.get("LastModified"))
        elif kind == "load_balancer":
            record.update(id=raw["LoadBalancerName"], arn=raw["LoadBalancerArn"],
                          state=raw.get("State", {}).get("Code"), load_balancer_type=raw.get("Type"),
                          scheme=raw.get("Scheme"))
        elif kind == "dynamodb_table":
            table = collector.call("dynamodb", "describe_table", TableName=raw)["Table"]
            record.update(id=table["TableName"], arn=table["TableArn"], state=table["TableStatus"],
                          size_bytes=table.get("TableSizeBytes"), item_count=table.get("ItemCount"),
                          billing_mode=table.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"))
        elif kind == "s3_bucket":
            record.update(id=raw["Name"], arn=f"arn:{partition}:s3:::{raw['Name']}")
            if raw.get("BucketRegion", region) != region:
                raise ValueError("Bucket returned outside requested region")
            if isinstance(raw.get("CreationDate"), datetime):
                record["created_at"] = raw["CreationDate"].isoformat()
        elif kind == "ecs_cluster":
            record.update(id=raw.split("/")[-1], arn=raw)
        elif kind == "eks_cluster":
            cluster = collector.call("eks", "describe_cluster", name=raw)["cluster"]
            record.update(id=cluster["name"], arn=cluster["arn"], state=cluster["status"],
                          version=cluster.get("version"), tags=cluster.get("tags", {}))
        elif kind == "log_group":
            record.update(id=raw["logGroupName"], arn=raw["arn"].removesuffix(":*"),
                          stored_bytes=raw.get("storedBytes"), retention_days=raw.get("retentionInDays"))
        yield record
