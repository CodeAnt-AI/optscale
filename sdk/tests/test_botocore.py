"""Validate live collector request/response shapes without any AWS network I/O."""

import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import patch

try:
    import boto3
    from botocore.stub import Stubber
except ImportError:
    boto3 = None

from optscale_sdk import collect_resources_aws, scan_anomalies_aws, scan_aws
from optscale_sdk.aws import _clients
from optscale_sdk.analysis import DAY
from test_analysis import ACCOUNT, REGION, NOW, INSTANCE_RULE, VOLUME_RULE


@unittest.skipIf(boto3 is None, "Install the aws extra to run botocore contract tests")
class BotocoreTests(unittest.TestCase):
    def clients(self, services=("sts", "ec2", "cloudwatch")):
        session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing",
                                aws_session_token="testing", region_name=REGION)
        return _clients(session, REGION, services)

    def identity(self, stub):
        stub.add_response("get_caller_identity", {
            "Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/scanner/test",
            "UserId": "test-user"}, {})

    def test_real_api_shapes_and_bounded_client_configuration(self):
        clients = self.clients()
        for client in clients.values():
            self.assertEqual(client.meta.config.read_timeout, 10)
            self.assertEqual(client.meta.config.connect_timeout, 3)
            self.assertEqual(client.meta.config.retries["total_max_attempts"], 2)
        stubs = {name: Stubber(client) for name, client in clients.items()}
        self.identity(stubs["sts"])
        stubs["ec2"].add_response("describe_volumes", {"Volumes": []}, {})
        stubs["ec2"].add_response("describe_addresses", {"Addresses": []}, {})
        stubs["ec2"].add_response("describe_instances", {"Reservations": [{"Instances": [{
            "InstanceId": "i-123", "State": {"Name": "running", "Code": 16},
            "LaunchTime": datetime.fromtimestamp(NOW - 20 * DAY, timezone.utc),
            "Monitoring": {"State": "disabled"}}]}]}, {})
        end = NOW // 3600 * 3600
        for metric in ("CPUUtilization", "NetworkIn", "NetworkOut"):
            points = [{"Timestamp": datetime.fromtimestamp(end - offset * 3600, timezone.utc),
                       "Sum": 12, "SampleCount": 12} for offset in range(1, 169)]
            stubs["cloudwatch"].add_response("get_metric_statistics", {"Datapoints": points}, {
                "Namespace": "AWS/EC2", "MetricName": metric,
                "Dimensions": [{"Name": "InstanceId", "Value": "i-123"}],
                "StartTime": datetime.fromtimestamp(end - 7 * DAY, timezone.utc),
                "EndTime": datetime.fromtimestamp(end, timezone.utc), "Period": 3600,
                "Statistics": ["Sum", "SampleCount"],
            })
        with ExitStack() as stack:
            for stub in stubs.values():
                stack.enter_context(stub)
            stack.enter_context(patch("optscale_sdk.aws._clients", return_value=clients))
            stack.enter_context(patch("optscale_sdk.aws.time.time", return_value=NOW))
            result = scan_aws(region=REGION, account_id=ACCOUNT,
                              rules=[VOLUME_RULE, "obsolete_ips", INSTANCE_RULE])
            self.assertEqual(result["status"], "complete", result["errors"])
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["rule_id"], INSTANCE_RULE)
            for stub in stubs.values():
                stub.assert_no_pending_responses()

    def test_access_denied_is_partial_and_redacted(self):
        clients = self.clients()
        with Stubber(clients["sts"]) as sts, Stubber(clients["ec2"]) as ec2:
            self.identity(sts)
            ec2.add_client_error("describe_volumes", service_error_code="UnauthorizedOperation",
                                 service_message="SECRET_TOKEN", expected_params={})
            with patch("optscale_sdk.aws._clients", return_value=clients):
                result = scan_aws(region=REGION, rules=[VOLUME_RULE])
            self.assertEqual(result["status"], "partial")
            self.assertFalse(result["coverage"]["completed"])
            self.assertNotIn("SECRET_TOKEN", str(result))
            sts.assert_no_pending_responses()
            ec2.assert_no_pending_responses()

    def test_inventory_api_contract_without_cloudwatch(self):
        clients = self.clients(("sts", "ec2"))
        with Stubber(clients["sts"]) as sts, Stubber(clients["ec2"]) as ec2:
            self.identity(sts)
            ec2.add_response("describe_volumes", {"Volumes": [{
                "VolumeId": "vol-123", "State": "available", "Attachments": [],
                "Size": 10, "VolumeType": "gp3", "Tags": [{"Key": "Name", "Value": "test"}]}]}, {})
            with patch("optscale_sdk.aws._clients", return_value=clients):
                result = collect_resources_aws(region=REGION, types=["volume"])
            self.assertEqual(result["status"], "complete", result["errors"])
            self.assertEqual(result["resources"][0]["size_gib"], 10)
            sts.assert_no_pending_responses()
            ec2.assert_no_pending_responses()

    def test_cost_explorer_api_contract(self):
        from datetime import timedelta
        from test_modes import TARGET, ce_rows

        clients = self.clients(("sts", "ce"))
        with Stubber(clients["sts"]) as sts, Stubber(clients["ce"]) as ce:
            self.identity(sts)
            ce.add_response("get_cost_and_usage", {"ResultsByTime": ce_rows()}, {
                "TimePeriod": {"Start": (TARGET - timedelta(days=7)).isoformat(),
                               "End": (TARGET + timedelta(days=1)).isoformat()},
                "Granularity": "DAILY", "Metrics": ["UnblendedCost"],
                "Filter": {"And": [
                    {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [ACCOUNT]}},
                    {"Dimensions": {"Key": "REGION", "Values": [REGION]}}]},
            })
            with patch("optscale_sdk.aws._clients", return_value=clients), \
                    patch("optscale_sdk.aws.time.time", return_value=NOW):
                result = scan_anomalies_aws(region=REGION, account_id=ACCOUNT)
            self.assertEqual(result["status"], "complete", result["errors"])
            self.assertEqual(len(result["findings"]), 1)
            sts.assert_no_pending_responses()
            ce.assert_no_pending_responses()


@unittest.skipIf(boto3 is None, "Install aws extra for billing contract tests")
class ExpenseBotocoreTests(unittest.TestCase):
    clients = BotocoreTests.clients
    identity = BotocoreTests.identity
    def test_grouped_daily_billing_api_and_same_day_pagination(self):
        from optscale_sdk import collect_expenses_aws
        clients = self.clients(("sts", "ce"))
        request = {"TimePeriod": {"Start": "2020-01-01", "End": "2020-01-02"},
                   "Granularity": "DAILY", "Metrics": ["UnblendedCost"],
                   "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "REGION"}],
                   "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [ACCOUNT]}}}
        def response(service, token=None):
            result = {"ResultsByTime": [{"TimePeriod": request["TimePeriod"], "Estimated": False,
                                        "Groups": [{"Keys": [service, ""], "Metrics": {"UnblendedCost": {"Amount": "0.25", "Unit": "USD"}}}]}]}
            if token:
                result["NextPageToken"] = token
            return result
        with Stubber(clients["sts"]) as sts, Stubber(clients["ce"]) as ce:
            self.identity(sts)
            ce.add_response("get_cost_and_usage", response("Amazon Simple Storage Service", "next"), request)
            ce.add_response("get_cost_and_usage", response("Amazon Relational Database Service"), {**request, "NextPageToken": "next"})
            with patch("optscale_sdk.aws._clients", return_value=clients):
                result = collect_expenses_aws(region=REGION, account_id=ACCOUNT,
                                              start_date="2020-01-01", end_date="2020-01-02")
            self.assertEqual(result["status"], "complete", result["errors"])
            self.assertEqual(result["summary"]["totals_by_currency"], {"USD": "0.50"})
            sts.assert_no_pending_responses()
            ce.assert_no_pending_responses()
