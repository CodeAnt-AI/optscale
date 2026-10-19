import copy
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from optscale_sdk import scan_aws
from optscale_sdk.aws import _Collector
from optscale_sdk.analysis import DAY
from test_analysis import ACCOUNT, REGION, NOW, VOLUME_RULE, IP_RULE, INSTANCE_RULE, resource


class AwsTests(unittest.TestCase):
    def setUp(self):
        self.sts, self.ec2, self.cloudwatch = Mock(), Mock(), Mock()
        self.sts.get_caller_identity.return_value = {
            "Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/scanner/session"}
        self.ec2.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-123", "State": "available", "Attachments": []}]}
        self.ec2.describe_addresses.return_value = {"Addresses": [{"AllocationId": "eipalloc-123"}]}
        self.ec2.describe_instances.return_value = {"Reservations": []}
        self.clients = {"sts": self.sts, "ec2": self.ec2, "cloudwatch": self.cloudwatch}
        client_patch = patch("optscale_sdk.aws._clients", return_value=self.clients)
        client_patch.start()
        self.addCleanup(client_patch.stop)
        clock_patch = patch("optscale_sdk.aws.time.time", return_value=NOW)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def scan(self, **kwargs):
        return scan_aws(region=REGION, **kwargs)

    def state(self, unused=True, gap=DAY):
        return {"schema_version": 1, "account_id": ACCOUNT, "region": REGION,
                "resources": {resource()["arn"]: {"unused": unused,
                              "unused_since": NOW - 10 * DAY, "observed_at": NOW - gap}}}

    def test_first_scan_does_not_use_volume_creation_time(self):
        self.ec2.describe_volumes.return_value["Volumes"][0]["CreateTime"] = datetime(2000, 1, 1, tzinfo=timezone.utc)
        result = self.scan(rules=[VOLUME_RULE])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["state"]["resources"][resource()["arn"]]["unused_since"], NOW)

    def test_history_retained_without_mutation(self):
        previous = self.state()
        original = copy.deepcopy(previous)
        result = self.scan(rules=[VOLUME_RULE], previous_state=previous)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(previous, original)

    def test_history_resets_after_use_or_observation_gap(self):
        for previous in (self.state(unused=False), self.state(gap=3 * DAY)):
            result = self.scan(rules=[VOLUME_RULE], previous_state=previous)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["state"]["resources"][resource()["arn"]]["unused_since"], NOW)

    def test_wrong_account_history_rejected_before_inventory(self):
        previous = self.state()
        previous["account_id"] = "999999999999"
        with self.assertRaises(ValueError):
            self.scan(previous_state=previous)
        self.ec2.describe_volumes.assert_not_called()

    def test_wrong_credential_account_rejected_before_inventory(self):
        with self.assertRaises(ValueError):
            self.scan(account_id="999999999999")
        self.ec2.describe_volumes.assert_not_called()

    def test_foreign_observation_rejected(self):
        previous = self.state()
        arn = resource()["arn"]
        previous["resources"][arn.replace(ACCOUNT, "999999999999")] = previous["resources"].pop(arn)
        with self.assertRaises(ValueError):
            self.scan(previous_state=previous)

    def test_repeated_pagination_token_is_partial(self):
        self.ec2.describe_volumes.return_value = {"Volumes": [], "NextToken": "same"}
        result = self.scan(rules=[VOLUME_RULE])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(self.ec2.describe_volumes.call_count, 2)

    def test_attached_volume_resets_observation(self):
        self.ec2.describe_volumes.return_value["Volumes"][0].update(
            State="in-use", Attachments=[{"InstanceId": "i-123"}])
        result = self.scan(rules=[VOLUME_RULE], previous_state=self.state())
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["state"]["resources"][resource()["arn"]]["unused"])

    def test_eip_with_interface_is_not_unused(self):
        self.ec2.describe_addresses.return_value["Addresses"][0]["NetworkInterfaceId"] = "eni-123"
        result = self.scan(rules=[IP_RULE])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["findings"], [])
        self.ec2.describe_volumes.assert_not_called()

    def test_pagination_collects_all_pages(self):
        self.ec2.describe_volumes.side_effect = [
            {"Volumes": [{"VolumeId": "vol-123", "State": "in-use", "Attachments": [{}]}], "NextToken": "page2"},
            {"Volumes": [{"VolumeId": "vol-456", "State": "in-use", "Attachments": [{}]}]},
        ]
        result = self.scan(rules=[VOLUME_RULE])
        self.assertEqual(len(result["snapshot"]["resources"]), 2)
        self.ec2.describe_volumes.assert_called_with(NextToken="page2")
        self.assertEqual(result["status"], "complete")

    def test_failed_collection_keeps_history_and_other_results(self):
        self.ec2.describe_volumes.side_effect = RuntimeError("SECRET_CREDENTIAL")
        result = self.scan(previous_state=self.state())
        self.assertEqual(result["status"], "partial")
        self.assertIn(resource()["arn"], result["state"]["resources"])
        self.assertNotIn("SECRET_CREDENTIAL", str(result))
        self.ec2.describe_addresses.assert_called_once()

    def test_successful_empty_collection_prunes_deleted_history(self):
        self.ec2.describe_volumes.return_value = {"Volumes": []}
        result = self.scan(rules=[VOLUME_RULE], previous_state=self.state())
        self.assertEqual(result["state"]["resources"], {})
        self.assertEqual(result["status"], "complete")

    def test_resource_limit_is_explicit(self):
        result = self.scan(max_resources=1)
        self.assertEqual(result["status"], "partial")
        self.assertIn("resource_limit_exceeded", [error["code"] for error in result["errors"]])

    def test_expiring_deadline_returns_partial_state(self):
        with patch("optscale_sdk.aws.time.monotonic", side_effect=[0, 0, 599]):
            result = self.scan(rules=[VOLUME_RULE])
        self.assertEqual(result["status"], "timed_out")
        self.assertFalse(result["coverage"]["completed"])
        self.ec2.describe_volumes.assert_not_called()

    def test_metrics_use_weighted_cpu_and_bytes_per_second(self):
        end = NOW // 3600 * 3600
        points = [{"Timestamp": datetime.fromtimestamp(end - offset * 3600, timezone.utc),
                   "Sum": 120, "SampleCount": 12} for offset in range(1, 25)]
        self.cloudwatch.get_metric_statistics.return_value = {"Datapoints": points}
        collector = _Collector(self.clients, float("inf"), 100)
        metrics = collector.metrics("i-123", 1, NOW, detailed=False)
        self.assertEqual(metrics["cpu"]["average"], 10)
        self.assertEqual(metrics["cpu"]["coverage"], 1)
        self.assertAlmostEqual(metrics["network_in"]["average"], 120 / 3600)
        self.assertEqual(self.cloudwatch.get_metric_statistics.call_count, 3)

    def test_sparse_samples_do_not_count_as_full_coverage(self):
        end = NOW // 3600 * 3600
        self.cloudwatch.get_metric_statistics.return_value = {"Datapoints": [
            {"Timestamp": datetime.fromtimestamp(end - offset * 3600, timezone.utc),
             "Sum": 0, "SampleCount": 1} for offset in range(1, 25)]}
        metrics = _Collector(self.clients, float("inf"), 100).metrics("i-123", 1, NOW, False)
        self.assertAlmostEqual(metrics["cpu"]["coverage"], 1 / 12)

    def test_missing_metrics_do_not_produce_idle_findings(self):
        self.ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{
            "InstanceId": "i-123", "State": {"Name": "running"},
            "LaunchTime": datetime.fromtimestamp(NOW - 20 * DAY, timezone.utc)}]}]}
        self.cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}
        result = self.scan(rules=[INSTANCE_RULE])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "partial")


if __name__ == "__main__":
    unittest.main()
