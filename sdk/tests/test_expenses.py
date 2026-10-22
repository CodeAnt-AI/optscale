"""Billing evidence must survive pagination, credits, estimates and partial failures."""

import contextlib
import copy
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from optscale_sdk import collect_expenses_aws, expenses_report
from optscale_sdk.cli import main
from test_analysis import ACCOUNT, NOW, REGION

START, END = "2020-01-01", "2020-01-03"


def period(day="2020-01-01", groups=None, estimated=False):
    return {"TimePeriod": {"Start": day, "End": "2020-01-02" if day == START else END},
            "Estimated": estimated, "Groups": groups if groups is not None else [group()]}


def group(service="Amazon Simple Storage Service", region="", amount="0.1"):
    return {"Keys": [service, region], "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}}


def snapshot():
    return {"schema_version": 1, "account_id": ACCOUNT, "region": REGION, "collected_at": NOW,
            "start_date": START, "end_date": END, "metric": "UnblendedCost", "group_by": ["service", "region"],
            "collection_complete": True, "days": {START: {"returned": True, "estimated": False},
                                                     "2020-01-02": {"returned": True, "estimated": False}},
            "expenses": [{"date": START, "dimensions": {"service": "Amazon S3", "region": ""}, "amount": "0.1", "currency": "USD"}]}


class ExpensesTests(unittest.TestCase):
    def setUp(self):
        self.sts, self.ce = Mock(), Mock()
        self.sts.get_caller_identity.return_value = {
            "Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/scanner/test"}
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [period(), period("2020-01-02")]}
        clients = patch("optscale_sdk.aws._clients", return_value={"sts": self.sts, "ce": self.ce})
        self.factory = clients.start()
        self.addCleanup(clients.stop)

    def collect(self, **kwargs):
        return collect_expenses_aws(region=REGION, start_date=START, end_date=END, **kwargs)

    def test_all_services_and_global_costs_without_anomaly_threshold(self):
        result = self.collect(account_id=ACCOUNT)
        self.assertEqual(result["status"], "complete", result["errors"])
        self.assertEqual(len(result["expenses"]), 2)
        self.assertEqual(result["expenses"][0]["dimensions"]["region"], "")
        self.assertEqual(result["summary"]["totals_by_currency"], {"USD": "0.2"})
        request = self.ce.get_cost_and_usage.call_args.kwargs
        self.assertEqual(request["Filter"], {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [ACCOUNT]}})
        self.assertEqual(request["Granularity"], "DAILY")
        self.assertEqual(request["GroupBy"], [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "REGION"}])
        self.factory.assert_called_once_with(None, REGION, ("sts", "ce"))

    def test_explicit_filters_are_combined_with_verified_account(self):
        self.collect(services=["Amazon S3"], billing_regions=[REGION])
        filters = self.ce.get_cost_and_usage.call_args.kwargs["Filter"]["And"]
        self.assertEqual(filters[0]["Dimensions"]["Values"], [ACCOUNT])
        self.assertEqual(filters[1]["Dimensions"], {"Key": "SERVICE", "Values": ["Amazon S3"]})
        self.assertEqual(filters[2]["Dimensions"], {"Key": "REGION", "Values": [REGION]})

    def test_pages_repeat_days_but_must_not_duplicate_groups(self):
        self.ce.get_cost_and_usage.side_effect = [
            {"ResultsByTime": [period()], "NextPageToken": "next"},
            {"ResultsByTime": [period(groups=[group("Amazon RDS", REGION, "0.2")]), period("2020-01-02", [])]}]
        result = self.collect()
        self.assertEqual(result["status"], "complete", result["errors"])
        self.assertEqual(result["summary"]["totals_by_currency"], {"USD": "0.3"})
        self.assertEqual(self.ce.get_cost_and_usage.call_args.kwargs["NextPageToken"], "next")
        self.ce.get_cost_and_usage.side_effect = [
            {"ResultsByTime": [period()], "NextPageToken": "next"}, {"ResultsByTime": [period()]}]
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["summary"]["totals_by_currency"], {"USD": "0.1"})

    def test_negative_credits_and_zero_are_retained_as_decimal_strings(self):
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [period(groups=[group(amount="-0.10")]),
                                                                 period("2020-01-02", [group(amount="0.00")])]}
        result = self.collect()
        self.assertEqual(result["status"], "complete")
        self.assertEqual([row["amount"] for row in result["expenses"]], ["-0.10", "0.00"])
        self.assertEqual(result["summary"]["totals_by_currency"], {"USD": "-0.10"})

    def test_totals_do_not_round_long_decimal_amounts(self):
        data = snapshot()
        data["expenses"][0]["amount"] = "1.123456789012345678901234567890"
        data["expenses"].append({**data["expenses"][0], "date": "2020-01-02", "amount": "0.000000000000000000000000000001"})
        self.assertEqual(expenses_report(data)["summary"]["totals_by_currency"]["USD"], "1.123456789012345678901234567891")

    def test_unexpected_group_definitions_or_ungrouped_costs_are_not_empty_success(self):
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [period()], "GroupDefinitions": [{"Type": "DIMENSION", "Key": "USAGE_TYPE"}]}
        self.assertEqual(self.collect()["status"], "partial")
        row = period(groups=[])
        row["Total"] = {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [row]}
        self.assertEqual(self.collect()["status"], "partial")

    def test_estimated_days_are_visible_and_distinguished_from_missing_days(self):
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [period(estimated=True)]}
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["expenses"]), 1)
        self.assertTrue(result["expenses"][0]["estimated"])
        self.assertFalse(result["expenses"][0]["complete"])
        self.assertEqual(result["coverage"]["days"]["2020-01-02"]["returned"], False)
        self.assertEqual({row["code"] for row in result["errors"]}, {"estimated_billing", "incomplete_billing_day"})

    def test_confirmed_empty_day_does_not_fabricate_service_cost_rows(self):
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [period(groups=[]), period("2020-01-02", [])]}
        result = self.collect()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["expenses"], [])
        self.assertEqual(result["summary"]["totals_by_currency"], {})
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": []}
        self.assertEqual(self.collect()["status"], "partial")

    def test_limits_deadlines_and_denials_preserve_collected_data_and_redact_errors(self):
        limited = self.collect(max_records=1)
        self.assertEqual(len(limited["expenses"]), 1)
        self.assertEqual(limited["status"], "partial")
        self.assertIn("resource_limit_exceeded", str(limited["errors"]))
        self.ce.get_cost_and_usage.side_effect = [{"ResultsByTime": [period()], "NextPageToken": "next"},
                                                RuntimeError("SECRET_CREDENTIAL")]
        denied = self.collect()
        self.assertEqual(len(denied["expenses"]), 1)
        self.assertFalse(denied["coverage"]["completed"])
        self.assertNotIn("SECRET_CREDENTIAL", json.dumps(denied))
        self.ce.get_cost_and_usage.side_effect = TimeoutError()
        self.assertEqual(self.collect()["status"], "timed_out")

    def test_repeated_tokens_invalid_periods_amounts_and_dimensions_are_partial(self):
        self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [], "NextPageToken": "same"}
        self.assertEqual(self.collect()["status"], "partial")
        self.assertEqual(self.ce.get_cost_and_usage.call_count, 2)
        for update in ({"Estimated": None}, {"TimePeriod": {"Start": "1999-01-01", "End": "1999-01-02"}},
                       {"Groups": [{**group(), "Keys": ["one"]}]}, {"Groups": [group(amount="NaN")]}):
            self.ce.get_cost_and_usage.return_value = {"ResultsByTime": [{**period(), **update}]}
            self.assertEqual(self.collect()["status"], "partial")

    def test_invalid_scope_fails_before_cost_calls(self):
        for options in ({"account_id": "999999999999"}, {"group_by": ["service", "region", "usage_type"]},
                        {"group_by": []}, {"metric": "UsageQuantity"}, {"services": []}):
            with self.assertRaises(ValueError):
                self.collect(**options)
        self.ce.get_cost_and_usage.assert_not_called()
        for start, end in ((END, START), (START, START), ("2020-01-01", "2025-01-01"), ("2099-01-01", "2099-01-02")):
            with self.assertRaises(ValueError):
                collect_expenses_aws(region=REGION, start_date=start, end_date=end)

    def test_replay_is_immutable_and_rejects_duplicate_currency_groups(self):
        data = snapshot()
        original = copy.deepcopy(data)
        result = expenses_report(data)
        self.assertEqual(result["status"], "complete")
        result["expenses"][0]["dimensions"]["service"] = "changed"
        self.assertEqual(data, original)
        data["expenses"].append(copy.deepcopy(data["expenses"][0]))
        self.assertEqual(expenses_report(data)["status"], "partial")

    def test_offline_cli_and_live_dispatch(self):
        result = subprocess.run([sys.executable, "-m", "optscale_sdk", "--mode", "expenses", "--input", "-"],
                                input=json.dumps(snapshot()), text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["expenses"][0]["amount"], "0.1")
        with patch("optscale_sdk.cli.collect_expenses_aws", return_value={"status": "partial"}) as collect, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--mode", "expenses", "--region", REGION, "--start-date", START,
                                   "--end-date", END, "--max-records", "500"]), 2)
        self.assertEqual(collect.call_args.kwargs["max_records"], 500)
        for args in (["--mode", "resources", "--start-date", START],
                     ["--mode", "expenses", "--region", REGION, "--date", START],
                     ["--mode", "expenses", "--region", REGION, "--state", "missing.json"]):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
