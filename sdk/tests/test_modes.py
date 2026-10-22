"""Standalone inventory and anomaly contracts, including subprocess isolation."""

import contextlib
import copy
import io
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from optscale_sdk import collect_resources_aws, detect_anomalies, inventory, scan_anomalies_aws
from optscale_sdk.cli import main
from test_analysis import ACCOUNT, REGION, NOW, resource, snapshot

TARGET = datetime.fromtimestamp(NOW, timezone.utc).date() - timedelta(days=1)


def history(kind="expense", current=140, baseline=100):
    series = {"id": "regional_total", "type": kind,
              "points": [{"date": (TARGET - timedelta(days=offset)).isoformat(),
                          "value": baseline if offset else current, "complete": True}
                         for offset in range(8)]}
    if kind == "expense":
        series["currency"] = "USD"
    return {"schema_version": 1, "account_id": ACCOUNT, "region": REGION,
            "collected_at": NOW, "date": TARGET.isoformat(),
            "series": [series], "collection": {kind: True}}


def ce_rows():
    return [{"TimePeriod": {"Start": point["date"],
                            "End": (datetime.fromisoformat(point["date"]) + timedelta(days=1)).date().isoformat()},
             "Estimated": False,
             "Total": {"UnblendedCost": {"Amount": str(point["value"]), "Unit": "USD"}}}
            for point in history()["series"][0]["points"]]


class InventoryTests(unittest.TestCase):
    def test_inventory_needs_no_recommendation_evidence(self):
        record = resource()
        record.pop("unused_since")
        record.pop("unused")
        data = snapshot(record)
        original = copy.deepcopy(data)
        result = inventory(data, types=["volume"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["resources"], [record])
        result["resources"][0]["id"] = "changed"
        self.assertEqual(data, original)

    def test_scope_duplicates_and_incomplete_collection(self):
        foreign = resource()
        foreign["arn"] = foreign["arn"].replace(ACCOUNT, "999999999999")
        for data in (snapshot(foreign), snapshot(resource(), resource()),
                     {**snapshot(), "collection": {}}):
            self.assertEqual(inventory(data, types=["volume"])["status"], "partial")

    def test_shards_do_not_require_other_types(self):
        result = inventory({**snapshot(resource()), "collection": {"volume": True}}, types=["volume"])
        self.assertTrue(result["coverage"]["completed"])
        for types in ([], ["volume", "volume"], ["unknown"]):
            with self.assertRaises(ValueError):
                inventory(snapshot(), types=types)


class AnomalyTests(unittest.TestCase):
    def test_spike_predicate_and_evidence_without_mutation(self):
        data = history()
        original = copy.deepcopy(data)
        result = detect_anomalies(data)
        self.assertEqual(result["status"], "complete")
        finding = result["findings"][0]
        self.assertEqual(finding["average"], 100)
        self.assertEqual(finding["current"], 140)
        self.assertAlmostEqual(finding["increase_percent"], 40)
        self.assertEqual(data, original)
        self.assertEqual(detect_anomalies(history(current=130))["findings"], [])
        self.assertEqual(detect_anomalies(data, threshold_percent=50)["findings"], [])

    def test_zero_baseline_and_resource_count(self):
        result = detect_anomalies(history("resource_count", current=2, baseline=0), types=["resource_count"])
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["findings"][0]["increase_percent"])
        self.assertIsNone(result["findings"][0]["currency"])
        self.assertEqual(detect_anomalies(history(current=0, baseline=0))["findings"], [])

    def test_missing_estimated_and_duplicate_days_are_partial(self):
        for change in (lambda points: points.pop(),
                       lambda points: points[0].update(complete=False),
                       lambda points: points.append(copy.deepcopy(points[0])),
                       lambda points: points[1].update(value=float("nan")),
                       lambda points: points[1].update(value=-1)):
            data = history()
            change(data["series"][0]["points"])
            result = detect_anomalies(data)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["findings"], [])

    def test_bad_series_keeps_other_results(self):
        data = history()
        data["series"].append({"id": "bad", "type": "expense"})
        result = detect_anomalies(data)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["findings"]), 1)

    def test_no_empty_success_without_collection_coverage(self):
        data = history()
        data["series"] = []
        data["collection"] = {}
        self.assertEqual(detect_anomalies(data)["status"], "partial")

    def test_current_day_and_invalid_options_fail(self):
        data = history()
        data["date"] = datetime.fromtimestamp(NOW, timezone.utc).date().isoformat()
        with self.assertRaises(ValueError):
            detect_anomalies(data)
        for settings in ({"types": []}, {"types": ["unknown"]}, {"lookback_days": 0},
                         {"lookback_days": 2.5}, {"threshold_percent": -1}):
            with self.assertRaises(ValueError):
                detect_anomalies(history(), **settings)


class LiveModesTests(unittest.TestCase):
    def setUp(self):
        self.sts, self.ec2, self.ce = Mock(), Mock(), Mock()
        self.sts.get_caller_identity.return_value = {
            "Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/scanner/test"}
        self.ec2.describe_volumes.return_value = {"Volumes": [
            {"VolumeId": "vol-123", "State": "available", "Attachments": [],
             "Tags": [{"Key": "Name", "Value": "example"}]}]}
        self.ec2.describe_addresses.return_value = {"Addresses": []}
        self.ec2.describe_instances.return_value = {"Reservations": []}
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": ce_rows()}
        self.clients = {"sts": self.sts, "ec2": self.ec2, "ce": self.ce}
        self.patch_clients = patch("optscale_sdk.aws._clients", return_value=self.clients)
        self.factory = self.patch_clients.start()
        self.addCleanup(self.patch_clients.stop)
        clock = patch("optscale_sdk.aws.time.time", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def test_inventory_never_requests_cloudwatch_or_history(self):
        result = collect_resources_aws(region=REGION, types=["volume"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["resources"][0]["tags"], {"Name": "example"})
        self.factory.assert_called_once_with(None, REGION, ("sts", "ec2"))
        self.ec2.describe_instances.assert_not_called()

    def test_instance_and_ip_inventory_includes_used_resources(self):
        self.ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{
            "InstanceId": "i-123", "State": {"Name": "stopped"}, "InstanceType": "t3.micro",
            "LaunchTime": datetime.fromtimestamp(NOW, timezone.utc)}]}]}
        self.ec2.describe_addresses.return_value = {"Addresses": [{
            "AllocationId": "eipalloc-123", "PublicIp": "192.0.2.1", "NetworkInterfaceId": "eni-123"}]}
        result = collect_resources_aws(region=REGION, types=["instance", "elastic_ip"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["resources"]), 2)
        self.assertFalse(result["resources"][0]["running"])
        self.assertFalse(result["resources"][1]["unused"])
        self.ec2.describe_volumes.assert_not_called()

    def test_inventory_partial_limit_and_pagination(self):
        self.ec2.describe_volumes.side_effect = [
            {"Volumes": self.ec2.describe_volumes.return_value["Volumes"], "NextToken": "next"},
            {"Volumes": [{"VolumeId": "vol-456", "State": "available", "Attachments": []}]}]
        result = collect_resources_aws(region=REGION, types=["volume"], max_resources=1)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["resources"]), 1)
        self.assertIn("resource_limit_exceeded", str(result["errors"]))

    def test_anomalies_request_is_account_and_region_scoped(self):
        result = scan_anomalies_aws(region=REGION, account_id=ACCOUNT)
        self.assertEqual(result["status"], "complete", result["errors"])
        self.assertEqual(len(result["findings"]), 1)
        request = self.ce.get_cost_and_usage.call_args.kwargs
        self.assertEqual(request["Filter"], {"And": [
            {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [ACCOUNT]}},
            {"Dimensions": {"Key": "REGION", "Values": [REGION]}}]})
        self.assertEqual(request["TimePeriod"]["End"], (TARGET + timedelta(days=1)).isoformat())
        self.assertEqual(request["Metrics"], ["UnblendedCost"])
        self.assertEqual(len(result["daily_expenses"]), 8)
        self.assertEqual(result["daily_expenses"][0]["currency"], "USD")
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [
            {**row, "Total": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}} for row in ce_rows()]}
        no_spikes = scan_anomalies_aws(region=REGION)
        self.assertEqual(no_spikes["findings"], [])
        self.assertEqual(len(no_spikes["daily_expenses"]), 8)

    def test_account_mismatch_prevents_inventory_and_billing_calls(self):
        for operation in (collect_resources_aws, scan_anomalies_aws):
            with self.assertRaises(ValueError):
                operation(region=REGION, account_id="999999999999")
        self.ec2.describe_volumes.assert_not_called()
        self.ce.get_cost_and_usage.assert_not_called()

    def test_estimated_billing_and_empty_response_are_incomplete(self):
        for rows in ([], [{**row, "Estimated": True} for row in ce_rows()]):
            self.ce.get_cost_and_usage.return_value = {"ResultsByTime": rows}
            result = scan_anomalies_aws(region=REGION)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["findings"], [])

    def test_ce_pagination_and_repeated_token(self):
        rows = ce_rows()
        self.ce.get_cost_and_usage.side_effect = [
            {"ResultsByTime": rows[:4], "NextPageToken": "next"},
            {"ResultsByTime": rows[4:]}]
        self.assertEqual(scan_anomalies_aws(region=REGION)["status"], "complete")
        self.assertEqual(self.ce.get_cost_and_usage.call_args.kwargs["NextPageToken"], "next")
        self.ce.get_cost_and_usage.side_effect = None
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [], "NextPageToken": "repeat"}
        self.assertEqual(scan_anomalies_aws(region=REGION)["status"], "partial")

    def test_limits_failures_and_deadlines_preserve_contract(self):
        result = scan_anomalies_aws(region=REGION, max_resources=1)
        self.assertEqual(result["status"], "partial")
        for operation, client in ((collect_resources_aws, self.ec2.describe_volumes),
                                  (scan_anomalies_aws, self.ce.get_cost_and_usage)):
            client.side_effect = RuntimeError("SECRET_CREDENTIAL")
            result = operation(region=REGION)
            self.assertEqual(result["status"], "partial")
            self.assertNotIn("SECRET_CREDENTIAL", str(result))
            client.side_effect = TimeoutError()
            result = operation(region=REGION)
            self.assertEqual(result["status"], "timed_out")
            self.assertFalse(result["coverage"]["completed"])
            client.side_effect = None


class ModeCliTests(unittest.TestCase):
    def run_cli(self, mode, data, *args):
        return subprocess.run([sys.executable, "-m", "optscale_sdk", "--mode", mode,
                               "--input", "-", *args], input=json.dumps(data),
                              text=True, capture_output=True, timeout=10, check=False)

    def test_all_modes_in_separate_processes(self):
        for mode, data, key in (("resources", snapshot(resource()), "resources"),
                                ("anomalies", history(), "findings"),
                                ("recommendations", snapshot(resource()), "findings")):
            result = self.run_cli(mode, data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)[key])

    def test_partial_anomaly_exit_code(self):
        data = history()
        data["series"][0]["points"].pop()
        result = self.run_cli("anomalies", data)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "partial")

    def test_invalid_mode_options_fail_before_collection(self):
        for args in (["--mode", "resources", "--rules", "obsolete_ips"],
                     ["--resource-types", "volume"],
                     ["--mode", "anomalies", "--state", "missing.json"],
                     ["--mode", "anomalies", "--region", REGION, "--anomaly-types", "resource_count"],
                     ["--mode", "resources", "--list-rules"]):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)

    def test_live_dispatch(self):
        for mode, target in (("resources", "collect_resources_aws"), ("anomalies", "scan_anomalies_aws")):
            with patch(f"optscale_sdk.cli.{target}", return_value={"status": "complete"}) as call, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--mode", mode, "--region", REGION, "--account-id", ACCOUNT]), 0)
            self.assertEqual(call.call_args.kwargs["account_id"], ACCOUNT)
