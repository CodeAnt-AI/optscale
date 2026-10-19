"""JSON CLI for CodeAnt subprocess jobs. Findings do not imply scan failure."""

import argparse
import json
import sys

from .analysis import RULES, analyze
from .aws import scan_aws


def _read(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Service-free OptScale AWS cost analysis")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--rules", nargs="+", choices=sorted(RULES))
    parser.add_argument("--options", help="JSON file with per-rule threshold overrides")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", help="Analyze normalized snapshot JSON; '-' reads stdin")
    source.add_argument("--region", help="Live AWS scan in this region, using the AWS credential chain")
    parser.add_argument("--account-id", help="Require live credentials to belong to this AWS account")
    parser.add_argument("--state", help="Previous live scan observation state JSON")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--max-resources", type=int, default=10000)
    parser.add_argument("--max-history-gap", type=float, default=172800, help="Seconds; default two days")
    parser.add_argument("--output", help="Result JSON path; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        if args.list_rules:
            result = {"schema_version": 1, "rules": RULES}
        else:
            if not args.input and not args.region:
                raise ValueError("Specify --region or --input")
            if args.input and (args.state or args.account_id):
                raise ValueError("--state and --account-id apply only to live scans")
            if args.options == "-":
                raise ValueError("--options requires a file")
            options = _read(args.options) if args.options else None
            if args.input:
                result = analyze(_read(args.input), rules=args.rules, options=options)
            else:
                result = scan_aws(region=args.region, account_id=args.account_id,
                                  rules=args.rules, options=options,
                                  previous_state=_read(args.state) if args.state else None,
                                  timeout_seconds=args.timeout, max_resources=args.max_resources,
                                  max_history_gap_seconds=args.max_history_gap)
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
