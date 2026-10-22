"""Inventory adapters use real botocore shapes and never copy raw resource secrets."""

import contextlib
import io
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from optscale_sdk import collect_resources_aws, inventory
from optscale_sdk.cli import main
from optscale_sdk.inventory_aws import COLLECTORS
from test_analysis import ACCOUNT, NOW, REGION

try:
    import boto3
    from botocore.stub import Stubber
except ImportError:
    boto3 = None


def arn(service, identifier):
    return f"arn:aws:{service}:{REGION}:{ACCOUNT}:{identifier}"


RAW = {
    "rds_instance": {"DBInstanceIdentifier": "db1", "DBInstanceArn": arn("rds", "db:db1"), "DBInstanceStatus": "available", "Engine": "postgres", "TagList": [{"Key": "Owner", "Value": "Platform"}]},
    "rds_cluster": {"DBClusterIdentifier": "cluster1", "DBClusterArn": arn("rds", "cluster:cluster1"), "Status": "available"},
    "lambda_function": {"FunctionName": "worker", "FunctionArn": arn("lambda", "function:worker"), "Runtime": "python3.12", "MemorySize": 128, "Environment": {"Variables": {"TOKEN": "SECRET_CREDENTIAL"}}},
    "load_balancer": {"LoadBalancerName": "web", "LoadBalancerArn": arn("elasticloadbalancing", "loadbalancer/app/web/123"), "State": {"Code": "active"}, "Type": "application"},
    "dynamodb_table": "table1",
    "s3_bucket": {"Name": "bucket-one", "CreationDate": datetime(2020, 1, 1, tzinfo=timezone.utc), "BucketRegion": REGION},
    "ecs_cluster": arn("ecs", "cluster/cluster1"),
    "eks_cluster": "k8s",
    "log_group": {"logGroupName": "/app/worker", "arn": arn("logs", "log-group:/app/worker:*")},
}


def details(client, kind):
    if kind == "dynamodb_table":
        client.describe_table.return_value = {"Table": {"TableName": "table1", "TableArn": arn("dynamodb", "table/table1"), "TableStatus": "ACTIVE"}}
    if kind == "eks_cluster":
        client.describe_cluster.return_value = {"cluster": {"name": "k8s", "arn": arn("eks", "cluster/k8s"), "status": "ACTIVE", "tags": {"Owner": "Platform"}}}


class InventoryAdapterTests(unittest.TestCase):
    def setUp(self):
        self.clients = {service: Mock() for service in {"sts", *(row[0] for row in COLLECTORS.values())}}
        self.clients["sts"].get_caller_identity.return_value = {"Account": ACCOUNT, "Arn": arn("sts", "assumed-role/scanner/test")}
        for kind, (service, method, key, _, _) in COLLECTORS.items():
            getattr(self.clients[service], method).return_value = {key: [RAW[kind]]}
            details(self.clients[service], kind)
        factory = patch("optscale_sdk.aws._clients", return_value=self.clients)
        factory.start()
        self.addCleanup(factory.stop)

    def collect(self, **kwargs):
        return collect_resources_aws(region=REGION, account_id=ACCOUNT, types=list(COLLECTORS), **kwargs)

    def test_all_services_normalized_with_account_and_region_and_no_secrets(self):
        result = self.collect()
        self.assertEqual(result["status"], "complete", result["errors"])
        self.assertEqual(len(result["resources"]), 9)
        self.assertEqual({record["service"] for record in result["resources"]}, {"rds", "lambda", "elasticloadbalancing", "dynamodb", "s3", "ecs", "eks", "logs"})
        self.assertTrue(all(record["account_id"] == ACCOUNT and record["region"] == REGION for record in result["resources"]))
        self.assertNotIn("SECRET_CREDENTIAL", json.dumps(result))
        self.assertEqual(self.clients["s3"].list_buckets.call_args.kwargs, {"BucketRegion": REGION, "MaxBuckets": 1000})
        self.clients["dynamodb"].describe_table.assert_called_once_with(TableName="table1")
        self.clients["eks"].describe_cluster.assert_called_once_with(name="k8s")

    def test_each_service_paginates_using_its_own_token_names(self):
        for kind, (service, method, key, input_token, output_token) in COLLECTORS.items():
            with self.subTest(kind=kind):
                call = getattr(self.clients[service], method)
                call.side_effect = [{key: [], output_token: "next"}, {key: [RAW[kind]]}]
                result = collect_resources_aws(region=REGION, types=[kind])
                self.assertEqual(result["status"], "complete", result["errors"])
                self.assertEqual(call.call_args.kwargs[input_token], "next")
                call.side_effect = None

    def test_failed_type_does_not_hide_other_service_results(self):
        self.clients["lambda"].list_functions.side_effect = RuntimeError("SECRET_CREDENTIAL")
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["resources"]), 8)
        self.assertFalse(result["coverage"]["resource_types"]["lambda_function"]["complete"])
        self.assertTrue(result["coverage"]["resource_types"]["rds_instance"]["complete"])
        self.assertNotIn("SECRET_CREDENTIAL", json.dumps(result))

    def test_foreign_arns_and_duplicate_inventory_are_not_accepted(self):
        self.clients["lambda"].list_functions.return_value = {"Functions": [{**RAW["lambda_function"], "FunctionArn": arn("lambda", "function:worker").replace(ACCOUNT, "999999999999")}]}
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["resources"]), 8)
        self.clients["rds"].describe_db_instances.return_value = {"DBInstances": [RAW["rds_instance"], RAW["rds_instance"]]}
        result = collect_resources_aws(region=REGION, types=["rds_instance"])
        self.assertEqual(len(result["resources"]), 1)
        self.assertEqual(result["status"], "partial")

    def test_limits_repeated_tokens_and_timeout_are_explicit(self):
        result = self.collect(max_resources=1)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["resources"]), 1)
        self.clients["rds"].describe_db_instances.return_value = {"DBInstances": [], "Marker": "repeat"}
        result = collect_resources_aws(region=REGION, types=["rds_instance"])
        self.assertEqual(result["status"], "partial")
        self.clients["rds"].describe_db_instances.side_effect = TimeoutError()
        self.assertEqual(collect_resources_aws(region=REGION, types=["rds_instance"])["status"], "timed_out")

    def test_bucket_scope_and_missing_tag_metadata_are_not_invented(self):
        result = collect_resources_aws(region=REGION, types=["s3_bucket"])
        record = result["resources"][0]
        self.assertNotIn("tags", record)
        record["account_id"] = "999999999999"
        data = {"schema_version": 1, "account_id": ACCOUNT, "region": REGION, "collected_at": NOW,
                "resources": [record], "collection": {"s3_bucket": True}}
        self.assertEqual(inventory(data, types=["s3_bucket"])["status"], "partial")
        self.clients["s3"].list_buckets.return_value = {"Buckets": [{**RAW["s3_bucket"], "BucketRegion": "us-west-2"}]}
        self.assertEqual(collect_resources_aws(region=REGION, types=["s3_bucket"])["status"], "partial")

    def test_cli_all_resource_types_is_explicit_and_not_allowed_for_other_modes(self):
        with patch("optscale_sdk.cli.collect_resources_aws", return_value={"status": "complete"}) as collect, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--mode", "resources", "--region", REGION, "--all-resource-types"]), 0)
        self.assertTrue(set(COLLECTORS).issubset(collect.call_args.kwargs["types"]))
        for args in (["--all-resource-types"], ["--mode", "resources", "--all-resource-types", "--resource-types", "instance"]):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)


@unittest.skipIf(boto3 is None, "Install aws extra for AWS API contract tests")
class InventoryBotocoreTests(unittest.TestCase):
    def test_real_shapes_for_every_new_adapter(self):
        from contextlib import ExitStack

        from optscale_sdk.aws import _clients
        services = tuple(dict.fromkeys(["sts"] + [row[0] for row in COLLECTORS.values()]))
        session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name=REGION)
        clients = _clients(session, REGION, services)
        stubs = {service: Stubber(client) for service, client in clients.items()}
        stubs["sts"].add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": arn("sts", "assumed-role/scanner/test"), "UserId": "test"}, {})
        for kind, (service, method, key, _, _) in COLLECTORS.items():
            params = {"BucketRegion": REGION, "MaxBuckets": 1000} if kind == "s3_bucket" else {}
            stubs[service].add_response(method, {key: [RAW[kind]]}, params)
            if kind == "dynamodb_table":
                stubs[service].add_response("describe_table", {"Table": {"TableName": "table1", "TableArn": arn("dynamodb", "table/table1"), "TableStatus": "ACTIVE"}}, {"TableName": "table1"})
            if kind == "eks_cluster":
                stubs[service].add_response("describe_cluster", {"cluster": {"name": "k8s", "arn": arn("eks", "cluster/k8s"), "status": "ACTIVE"}}, {"name": "k8s"})
        with ExitStack() as stack:
            for stub in stubs.values():
                stack.enter_context(stub)
            stack.enter_context(patch("optscale_sdk.aws._clients", return_value=clients))
            result = collect_resources_aws(region=REGION, account_id=ACCOUNT, types=list(COLLECTORS))
            self.assertEqual(result["status"], "complete", result["errors"])
            self.assertEqual(len(result["resources"]), 9)
            for stub in stubs.values():
                stub.assert_no_pending_responses()
