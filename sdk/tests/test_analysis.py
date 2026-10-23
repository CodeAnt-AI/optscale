import copy
import unittest

from optscale_sdk import analyze
from optscale_sdk.analysis import DAY, RULES

NOW = 1800000000
ACCOUNT = "123456789012"
REGION = "us-east-1"
VOLUME_RULE = "volumes_not_attached_for_a_long_time"
IP_RULE = "obsolete_ips"
INSTANCE_RULE = "abandoned_instances"


def resource(kind="volume", identifier="vol-123"):
    arn_kind = {"volume": "volume", "elastic_ip": "elastic-ip", "instance": "instance"}[kind]
    return {"type": kind, "id": identifier,
            "arn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:{arn_kind}/{identifier}",
            "unused": True, "unused_since": NOW - 8 * DAY}


def snapshot(*resources):
    return {"schema_version": 1, "account_id": ACCOUNT, "region": REGION,
            "collected_at": NOW, "resources": list(resources),
            "collection": {config["resource_type"]: True for config in RULES.values()}}


def instance():
    record = resource("instance", "i-123")
    record.update(running=True, launched_at=NOW - 14 * DAY, metrics={
        "start": NOW - 7 * DAY, "end": NOW,
        "cpu": {"average": 5, "coverage": 1},
        "network_in": {"average": 400, "coverage": 1},
        "network_out": {"average": 600, "coverage": 1},
    })
    return record


class AnalysisTests(unittest.TestCase):
    def test_default_thresholds_match_original_modules(self):
        self.assertEqual(RULES[VOLUME_RULE]["days_threshold"], 1)
        self.assertEqual(RULES[IP_RULE]["days_threshold"], 7)
        self.assertEqual(RULES[INSTANCE_RULE]["days_threshold"], 7)
        self.assertEqual(RULES[INSTANCE_RULE]["cpu_percent_threshold"], 5)
        self.assertEqual(RULES[INSTANCE_RULE]["network_bps_threshold"], 1000)

    def test_known_and_unknown_savings(self):
        record = resource()
        result = analyze(snapshot(record), rules=[VOLUME_RULE])
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["findings"][0]["estimated_monthly_savings"])
        record["cost"] = {"average_daily_cost": 2, "currency": "USD"}
        finding = analyze(snapshot(record), rules=[VOLUME_RULE])["findings"][0]
        self.assertEqual(finding["estimated_monthly_savings"], 60)
        self.assertEqual(finding["currency"], "USD")

    def test_no_input_mutation(self):
        data = snapshot(resource(), instance())
        original = copy.deepcopy(data)
        analyze(data)
        self.assertEqual(data, original)

    def test_used_resources_are_not_findings(self):
        record = resource()
        record["unused"] = False
        result = analyze(snapshot(record), rules=[VOLUME_RULE])
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["coverage"]["completed"])

    def test_exact_age_threshold_is_not_old_enough(self):
        record = resource()
        record["unused_since"] = NOW - DAY
        result = analyze(snapshot(record), rules=[VOLUME_RULE])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["errors"][0]["code"], "observation_window_pending")

    def test_missing_history_never_fabricates_age(self):
        record = resource()
        record.pop("unused_since")
        result = analyze(snapshot(record), rules=[VOLUME_RULE])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["errors"][0]["code"], "history_unavailable")

    def test_rule_selection_and_override(self):
        record = resource("elastic_ip", "eipalloc-123")
        self.assertEqual(len(analyze(snapshot(record), rules=[IP_RULE])["findings"]), 1)
        result = analyze(snapshot(record), rules=[IP_RULE], options={IP_RULE: {"days_threshold": 10}})
        self.assertEqual(result["findings"], [])
        self.assertEqual(list(result["coverage"]["rules"]), [IP_RULE])

    def test_idle_thresholds_include_equality(self):
        result = analyze(snapshot(instance()), rules=[INSTANCE_RULE])
        self.assertEqual(len(result["findings"]), 1)
        record = instance()
        record["metrics"]["network_out"]["average"] += 1
        self.assertEqual(analyze(snapshot(record), rules=[INSTANCE_RULE])["findings"], [])

    def test_missing_sparse_and_stale_metrics_are_not_idle(self):
        for change, reason in (
            (lambda metrics: metrics.pop("cpu"), "metrics_unavailable"),
            (lambda metrics: metrics["cpu"].update(coverage=0.01), "insufficient_metric_coverage"),
            (lambda metrics: metrics.update(end=NOW - DAY), "metric_window_mismatch"),
            (lambda metrics: metrics.update(start=NOW - 14 * DAY), "metric_window_mismatch"),
        ):
            with self.subTest(reason=reason):
                record = instance()
                change(record["metrics"])
                result = analyze(snapshot(record), rules=[INSTANCE_RULE])
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["errors"][0]["code"], reason)

    def test_invalid_record_does_not_discard_other_findings(self):
        invalid = resource(identifier="vol-invalid")
        invalid["unused_since"] = float("nan")
        result = analyze(snapshot(invalid, resource()), rules=[VOLUME_RULE])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["status"], "partial")

    def test_foreign_arn_and_duplicate_ids_are_incomplete(self):
        foreign = resource()
        foreign["arn"] = foreign["arn"].replace(ACCOUNT, "999999999999")
        for records in ([foreign], [resource(), resource()]):
            result = analyze(snapshot(*records), rules=[VOLUME_RULE])
            self.assertFalse(result["coverage"]["completed"])
            self.assertEqual(result["errors"][0]["code"], "invalid_resource")

    def test_failed_collection_is_not_empty_success(self):
        data = snapshot()
        data["collection"]["volume"] = False
        result = analyze(data, rules=[VOLUME_RULE])
        self.assertFalse(result["coverage"]["completed"])
        self.assertEqual(result["status"], "partial")

    def test_invalid_configuration_rejected(self):
        for kwargs in ({"rules": []}, {"rules": ["rightsizing_instances"]},
                       {"rules": [IP_RULE, IP_RULE]},
                       {"options": {IP_RULE: {"days_threshold": float("nan")}}},
                       {"options": {INSTANCE_RULE: {"minimum_metric_coverage": 0}}},
                       {"options": {IP_RULE: {"action": "delete"}}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                analyze(snapshot(), **kwargs)

    def test_empty_snapshot_requires_explicit_collection_coverage(self):
        data = snapshot()
        data["collection"] = {}
        self.assertEqual(analyze(data)["status"], "partial")


if __name__ == "__main__":
    unittest.main()
