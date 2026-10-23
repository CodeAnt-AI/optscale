"""Cross-service recommendations, including missing evidence and AWS contracts."""

import copy
import json
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from optscale_sdk import analyze, scan_aws
from optscale_sdk.analysis import DAY
from optscale_sdk.aws import _clients, _Collector
from optscale_sdk.recommendations import RULES, enrich
from test_analysis import ACCOUNT, NOW, REGION


def metrics(**values):
    return {"start": NOW // 3600 * 3600 - 7 * DAY, "end": NOW // 3600 * 3600,
            **{name: {"maximum": value, "coverage": 1} for name, value in values.items()}}


def records():
    configurations = [
        ("rds_instance", "rds", "database", "db:database", {"state": "available", "metrics": metrics(cpu=1, connections=0, reads=0, writes=0)}),
        ("load_balancer", "elasticloadbalancing", "balance", "loadbalancer/app/balance/123", {"state": "active", "metrics": metrics(traffic=0, bytes=0)}),
        ("dynamodb_table", "dynamodb", "table", "table/table", {"state": "ACTIVE", "billing_mode": "PROVISIONED", "metrics": metrics(reads=0, writes=0)}),
        ("lambda_function", "lambda", "function", "function:function", {"provisioned_concurrency": [{"qualifier": "live", "allocated": 10, "modified_at": NOW - 10 * DAY, "metrics": metrics(utilization=0.05)}]}),
        ("s3_bucket", "s3", "example-bucket", "example-bucket", {"stale_upload_count": 2, "oldest_upload_at": NOW - 10 * DAY}),
        ("log_group", "logs", "/aws/lambda/function", "log-group:/aws/lambda/function", {"stored_bytes": 1024, "retention_days": None}),
    ]
    return [{"type": kind, "service": service, "id": identifier,
             "account_id": ACCOUNT, "region": REGION,
             "arn": f"arn:aws:{service}:" + (f"::{suffix}" if service == "s3" else f"{REGION}:{ACCOUNT}:{suffix}"),
             **details} for kind, service, identifier, suffix, details in configurations]


def snapshot(resources):
    return {"schema_version": 1, "account_id": ACCOUNT, "region": REGION,
            "collected_at": NOW, "resources": resources,
            "collection": {config["resource_type"]: True for config in RULES.values()}}


class RecommendationTests(unittest.TestCase):
    def analyze(self, resources=None):
        return analyze(snapshot(records() if resources is None else resources), rules=list(RULES))

    def test_every_new_service_emits_supported_findings_without_fake_savings(self):
        resources = records()
        for resource in resources:
            resource["cost"] = {"average_daily_cost": 10, "currency": "USD"}
        original = copy.deepcopy(resources)
        result = self.analyze(resources)
        self.assertEqual(result["status"], "complete", result["errors"])
        self.assertEqual({finding["rule_id"] for finding in result["findings"]}, set(RULES))
        self.assertEqual(len({finding["service"] for finding in result["findings"]}), 6)
        self.assertTrue(all(finding["estimated_monthly_savings"] is None for finding in result["findings"]))
        self.assertEqual(resources, original)

    def test_active_resources_and_bounded_retention_are_not_findings(self):
        resources = records()
        resources[0]["metrics"]["connections"]["maximum"] = 1
        resources[1]["metrics"]["traffic"]["maximum"] = 1
        resources[2]["billing_mode"] = "PAY_PER_REQUEST"
        resources[3]["provisioned_concurrency"][0]["metrics"]["utilization"]["maximum"] = 0.5
        resources[4].update(stale_upload_count=0, oldest_upload_at=None)
        resources[5]["retention_days"] = 30
        result = self.analyze(resources)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["findings"], [])

    def test_missing_sparse_stale_metrics_are_incomplete(self):
        for index, metric_name in ((0, "cpu"), (1, "bytes"), (2, "writes")):
            for change in (lambda data, name=metric_name: data.pop(name),
                           lambda data, name=metric_name: data[name].update(coverage=0.01),
                           lambda data: data.update(end=NOW - DAY)):
                resources = records()
                change(resources[index]["metrics"])
                result = self.analyze(resources)
                self.assertEqual(len(result["findings"]), 5)
                self.assertEqual(result["status"], "partial")

    def test_lambda_unknown_qualifier_does_not_hide_known_finding_or_complete_coverage(self):
        resources = records()
        allocation = copy.deepcopy(resources[3]["provisioned_concurrency"][0])
        allocation.update(qualifier="unknown", metrics=None)
        resources[3]["provisioned_concurrency"].append(allocation)
        result = self.analyze(resources)
        self.assertEqual(len(result["findings"]), 6)
        self.assertFalse(result["coverage"]["rules"]["underused_lambda_provisioned_concurrency"]["complete"])

    def test_recent_lambda_allocation_is_pending(self):
        resources = records()
        resources[3]["provisioned_concurrency"][0]["modified_at"] = NOW - DAY
        result = self.analyze(resources)
        self.assertEqual(len(result["findings"]), 5)
        self.assertIn("observation_window_pending", [entry["code"] for entry in result["errors"]])

    def test_foreign_account_region_and_arns_are_rejected(self):
        for field, value in (("account_id", "999999999999"), ("region", "us-west-2"), ("arn", "arn:aws:s3:::another-bucket")):
            for record in records():
                record[field] = value
                result = self.analyze([record])
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["status"], "partial")

    def test_new_checks_run_in_real_cli_process(self):
        result = subprocess.run([sys.executable, "-m", "optscale_sdk", "--input", "-", "--rules", *RULES],
                                input=json.dumps(snapshot(records())), text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["findings"]), 6)

    def test_default_live_scan_collects_every_service_and_retains_permission_failures(self):
        clients = {name: Mock() for name in ("sts", "ec2", "cloudwatch", "rds", "elbv2", "lambda", "dynamodb", "s3", "logs")}
        clients["sts"].get_caller_identity.return_value = {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/scanner/test"}
        for method, key in (("describe_volumes", "Volumes"), ("describe_addresses", "Addresses"), ("describe_instances", "Reservations")):
            getattr(clients["ec2"], method).return_value = {key: []}
        clients["rds"].describe_db_instances.return_value = {"DBInstances": []}
        clients["elbv2"].describe_load_balancers.return_value = {"LoadBalancers": []}
        clients["dynamodb"].list_tables.return_value = {"TableNames": []}
        clients["lambda"].list_functions.return_value = {"Functions": []}
        clients["s3"].list_buckets.side_effect = RuntimeError("SECRET_TOKEN")
        clients["logs"].describe_log_groups.return_value = {"logGroups": [{"logGroupName": "example", "arn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:example:*", "storedBytes": 4096}]}
        with patch("optscale_sdk.aws._clients", return_value=clients) as factory:
            result = scan_aws(region=REGION, account_id=ACCOUNT)
        self.assertEqual(len(result["coverage"]["rules"]), 9)
        self.assertEqual(result["findings"][0]["service"], "logs")
        self.assertFalse(result["coverage"]["rules"]["s3_incomplete_multipart_uploads"]["complete"])
        self.assertTrue(result["coverage"]["rules"]["log_groups_without_retention"]["complete"])
        self.assertNotIn("SECRET_TOKEN", str(result))
        self.assertIn("lambda", factory.call_args.args[2])


class EnrichmentTests(unittest.TestCase):
    def test_rds_alb_nlb_dynamodb_cloudwatch_contracts(self):
        import boto3
        from botocore.stub import Stubber
        session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
        clients = _clients(session, REGION, ("cloudwatch",))
        end = NOW // 3600 * 3600
        cases = [
            (0, "idle_rds_instances", "AWS/RDS", "DBInstanceIdentifier", "database", ["CPUUtilization", "DatabaseConnections", "ReadIOPS", "WriteIOPS"]),
            (1, "abandoned_load_balancers", "AWS/ApplicationELB", "LoadBalancer", "app/balance/123", ["RequestCount", "ProcessedBytes"]),
            (1, "abandoned_load_balancers", "AWS/NetworkELB", "LoadBalancer", "net/balance/123", ["NewFlowCount", "ProcessedBytes"]),
            (2, "idle_dynamodb_tables", "AWS/DynamoDB", "TableName", "table", ["ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"]),
        ]
        for index, rule, namespace, dimension, identifier, names in cases:
            resource = records()[index]
            if index == 1:
                network = namespace == "AWS/NetworkELB"
                resource["load_balancer_type"] = "network" if network else "application"
                resource["arn"] = resource["arn"].replace("app/", "net/") if network else resource["arn"]
            with Stubber(clients["cloudwatch"]) as stub:
                for name in names:
                    stub.add_response("get_metric_statistics", {"Datapoints": [{
                        "Timestamp": datetime.fromtimestamp(end - offset * 3600, timezone.utc), "Maximum": 0, "SampleCount": 60,
                    } for offset in range(1, 169)]}, {
                        "Namespace": namespace, "MetricName": name, "Dimensions": [{"Name": dimension, "Value": identifier}],
                        "StartTime": datetime.fromtimestamp(end - 7 * DAY, timezone.utc), "EndTime": datetime.fromtimestamp(end, timezone.utc),
                        "Period": 3600, "Statistics": ["Maximum", "SampleCount"],
                    })
                enrich(_Collector(clients, float("inf"), 100), resource, RULES[rule], NOW)
                result = analyze(snapshot([resource]), rules=[rule])
                self.assertEqual(len(result["findings"]), 1, result["errors"])
                stub.assert_no_pending_responses()

    def test_paginated_multipart_contract_and_old_upload_filter(self):
        import boto3
        from botocore.stub import Stubber
        session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
        clients = _clients(session, REGION, ("s3",))
        resource = records()[4]
        with Stubber(clients["s3"]) as stub:
            request = {"Bucket": resource["id"], "ExpectedBucketOwner": ACCOUNT}
            stub.add_response("list_multipart_uploads", {"IsTruncated": True, "NextKeyMarker": "key", "NextUploadIdMarker": "id",
                "Uploads": [{"Key": "key", "UploadId": "id", "Initiated": datetime.fromtimestamp(NOW - 9 * DAY, timezone.utc)}]}, request)
            stub.add_response("list_multipart_uploads", {"IsTruncated": False,
                "Uploads": [{"Key": "recent", "UploadId": "id2", "Initiated": datetime.fromtimestamp(NOW - DAY, timezone.utc)}]},
                {**request, "KeyMarker": "key", "UploadIdMarker": "id"})
            enrich(_Collector(clients, float("inf"), 100), resource, RULES["s3_incomplete_multipart_uploads"], NOW)
            stub.assert_no_pending_responses()
        self.assertEqual(resource["stale_upload_count"], 1)

    def test_lambda_config_and_cloudwatch_dimension_contract(self):
        import boto3
        from botocore.stub import Stubber
        session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
        clients = _clients(session, REGION, ("lambda", "cloudwatch"))
        resource = records()[3]
        end = NOW // 3600 * 3600
        with Stubber(clients["lambda"]) as provisioned, Stubber(clients["cloudwatch"]) as cloudwatch:
            provisioned.add_response("list_provisioned_concurrency_configs", {"ProvisionedConcurrencyConfigs": [{
                "FunctionArn": resource["arn"] + ":live", "Status": "READY", "AllocatedProvisionedConcurrentExecutions": 10,
                "LastModified": datetime.fromtimestamp(NOW - 10 * DAY, timezone.utc).isoformat()}]}, {"FunctionName": resource["id"]})
            cloudwatch.add_response("get_metric_statistics", {"Datapoints": [{
                "Timestamp": datetime.fromtimestamp(end - offset * 3600, timezone.utc), "Maximum": 0.05, "SampleCount": 60,
            } for offset in range(1, 169)]}, {
                "Namespace": "AWS/Lambda", "MetricName": "ProvisionedConcurrencyUtilization",
                "Dimensions": [{"Name": "FunctionName", "Value": resource["id"]}, {"Name": "Resource", "Value": "function:live"}],
                "StartTime": datetime.fromtimestamp(end - 7 * DAY, timezone.utc), "EndTime": datetime.fromtimestamp(end, timezone.utc),
                "Period": 3600, "Statistics": ["Maximum", "SampleCount"],
            })
            enrich(_Collector(clients, float("inf"), 100), resource, RULES["underused_lambda_provisioned_concurrency"], NOW)
            self.assertEqual(resource["provisioned_concurrency"][0]["metrics"]["utilization"]["coverage"], 1)
            provisioned.assert_no_pending_responses()
            cloudwatch.assert_no_pending_responses()

    def test_multipart_pagination_and_record_limits_fail_explicitly(self):
        client = Mock()
        client.list_multipart_uploads.return_value = {"IsTruncated": True, "NextKeyMarker": "same", "NextUploadIdMarker": "id"}
        with self.assertRaises(ValueError):
            enrich(_Collector({"s3": client}, float("inf"), 100), records()[4], RULES["s3_incomplete_multipart_uploads"], NOW)
        client.list_multipart_uploads.return_value = {"IsTruncated": False, "Uploads": [{"Initiated": datetime.now(timezone.utc)}]}
        with self.assertRaises(OverflowError):
            enrich(_Collector({"s3": client}, float("inf"), 0), records()[4], RULES["s3_incomplete_multipart_uploads"], NOW)
