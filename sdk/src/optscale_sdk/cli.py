"""JSON CLI for CodeAnt subprocess jobs. Findings do not imply scan failure."""

import argparse
import json
import sys

from .analysis import RULES, analyze
from .anomalies import ANOMALY_TYPES, detect_anomalies
from .aws import collect_resources_aws, scan_anomalies_aws, scan_aws
from .resources import RESOURCE_TYPES, inventory
from .expenses import COST_METRICS, GROUP_DIMENSIONS, collect_expenses_aws, expenses_report


def _read(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Service-free OptScale AWS cost analysis")
    parser.add_argument("--mode", choices=("recommendations", "resources", "anomalies", "expenses"),
                        default="recommendations", help="Operation; default recommendations")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--resource-types", nargs="+", choices=sorted(RESOURCE_TYPES))
    parser.add_argument("--all-resource-types", action="store_true", help="Collect every supported inventory type (default: legacy EC2 types)")
    parser.add_argument("--start-date", help="Billing start date YYYY-MM-DD, inclusive UTC")
    parser.add_argument("--end-date", help="Billing end date YYYY-MM-DD, exclusive UTC")
    parser.add_argument("--group-by", nargs="+", choices=sorted(GROUP_DIMENSIONS), help="One/two billing dimensions; default service region")
    parser.add_argument("--cost-metric", choices=COST_METRICS)
    parser.add_argument("--services", nargs="+", help="Exact AWS billing service names; default all")
    parser.add_argument("--billing-regions", nargs="+", help="Explicit cost-region filter; default all, including global")
    parser.add_argument("--anomaly-types", nargs="+", choices=ANOMALY_TYPES)
    parser.add_argument("--lookback-days", type=int, help="Anomaly baseline days; default 7")
    parser.add_argument("--threshold-percent", type=float, help="Anomaly increase threshold; default 30")
    parser.add_argument("--date", help="Live anomaly target YYYY-MM-DD; default yesterday UTC")
    parser.add_argument("--rules", nargs="+", choices=sorted(RULES))
    parser.add_argument("--options", help="JSON file with per-rule threshold overrides")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", help="Normalized snapshot JSON for the selected mode; '-' reads stdin")
    source.add_argument("--region", help="Live AWS scan in this region, using the AWS credential chain")
    parser.add_argument("--account-id", help="Require live credentials to belong to this AWS account")
    parser.add_argument("--state", help="Previous live scan observation state JSON")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--max-resources", "--max-records", type=int, default=10000, help="Maximum collected resource/billing records")
    parser.add_argument("--max-history-gap", type=float, help="Recommendation history gap in seconds; default two days")
    parser.add_argument("--output", help="Result JSON path; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        if args.mode != "recommendations" and any(
                value is not None for value in (args.rules, args.options, args.state, args.max_history_gap)):
            raise ValueError("Recommendation arguments require --mode recommendations")
        if args.list_rules and args.mode != "recommendations":
            raise ValueError("--list-rules requires recommendations mode")
        if args.all_resource_types and (args.mode != "resources" or args.resource_types is not None):
            raise ValueError("--all-resource-types requires resources mode and cannot combine with --resource-types")
        if args.all_resource_types:
            args.resource_types = sorted(RESOURCE_TYPES)
        billing_args = (args.start_date, args.end_date, args.group_by, args.cost_metric, args.services, args.billing_regions)
        if args.mode != "expenses" and any(value is not None for value in billing_args):
            raise ValueError("Billing arguments require expenses mode")
        if args.mode == "expenses" and args.input and any(value is not None for value in billing_args):
            raise ValueError("Offline billing scope is defined in the input snapshot")
        if args.resource_types is not None and args.mode != "resources":
            raise ValueError("--resource-types requires resources mode")
        if args.mode != "anomalies" and any(value is not None for value in (
                args.anomaly_types, args.lookback_days, args.threshold_percent, args.date)):
            raise ValueError("Anomaly arguments require anomalies mode")
        if args.input and (args.state or args.account_id or args.date):
            raise ValueError("--state, --account-id and --date apply only to live scans")
        if args.list_rules:
            result = {"schema_version": 1, "rules": RULES}
        else:
            if not args.input and not args.region:
                raise ValueError("Specify --region or --input")
            if args.options == "-":
                raise ValueError("--options requires a file")
            if args.mode == "recommendations":
                options = _read(args.options) if args.options else None
                if args.input:
                    result = analyze(_read(args.input), rules=args.rules, options=options)
                else:
                    result = scan_aws(region=args.region, account_id=args.account_id,
                                      rules=args.rules, options=options,
                                      previous_state=_read(args.state) if args.state else None,
                                      timeout_seconds=args.timeout, max_resources=args.max_resources,
                                      max_history_gap_seconds=(args.max_history_gap
                                                               if args.max_history_gap is not None else 172800))
            elif args.mode == "resources":
                if args.input:
                    result = inventory(_read(args.input), types=args.resource_types)
                else:
                    result = collect_resources_aws(region=args.region, account_id=args.account_id,
                                                   types=args.resource_types, timeout_seconds=args.timeout,
                                                   max_resources=args.max_resources)
            elif args.mode == "expenses":
                if args.input:
                    result = expenses_report(_read(args.input))
                else:
                    result = collect_expenses_aws(
                        region=args.region, account_id=args.account_id,
                        start_date=args.start_date, end_date=args.end_date, group_by=args.group_by,
                        metric=args.cost_metric or "UnblendedCost", services=args.services,
                        billing_regions=args.billing_regions, timeout_seconds=args.timeout,
                        max_records=args.max_resources)
            else:
                settings = {"lookback_days": args.lookback_days if args.lookback_days is not None else 7,
                            "threshold_percent": args.threshold_percent if args.threshold_percent is not None else 30}
                if args.input:
                    result = detect_anomalies(_read(args.input), types=args.anomaly_types, **settings)
                else:
                    if args.anomaly_types is not None and args.anomaly_types != ["expense"]:
                        raise ValueError("Live anomalies support expense only; provide resource count history via --input")
                    result = scan_anomalies_aws(region=args.region, account_id=args.account_id,
                                               date=args.date, timeout_seconds=args.timeout,
                                               max_resources=args.max_resources, **settings)
        serialized = json.dumps(result, allow_nan=False, sort_keys=True) + "\n"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as target:
                target.write(serialized)
        else:
            sys.stdout.write(serialized)
        return 0 if result.get("status", "complete") == "complete" else 2
    except Exception:
        # Never print SDK exception bodies: they may contain credential material.
        sys.stderr.write(json.dumps({"schema_version": 1, "status": "failed",
                                     "errors": [{"code": "scan_failed"}]}) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
