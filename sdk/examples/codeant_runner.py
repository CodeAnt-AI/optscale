"""Copy/adapt into CodeAnt's background scan worker; no new infrastructure.

Install optscale-analysis[aws] into the same Python environment as this runner.
The caller supplies already-assumed-role credentials. Recommendation jobs store
result['state'] using existing per-tenant/account/region blob storage. Set mode
to resources, anomalies or expenses to run those operations in separate CLI processes.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run_optscale(credentials, region, previous_state=None, *, mode="recommendations",
                 rules=None, resource_types=None, anomaly_types=None,
                 lookback_days=7, threshold_percent=30, all_resource_types=False,
                 start_date=None, end_date=None, group_by=None, cost_metric="UnblendedCost",
                 services=None, billing_regions=None):
    with tempfile.TemporaryDirectory(prefix="optscale-") as directory:
        output = Path(directory) / "result.json"
        command = [sys.executable, "-m", "optscale_sdk", "--region", region,
                   "--account-id", credentials["account_id"], "--mode", mode,
                   "--timeout", "600", "--output", str(output)]
        if rules is not None:
            command.extend(["--rules", *rules])
        if resource_types is not None:
            command.extend(["--resource-types", *resource_types])
        if all_resource_types:
            command.append("--all-resource-types")
        if mode == "expenses":
            if not start_date or not end_date:
                raise ValueError("Expenses require start/end dates")
            command.extend(["--start-date", start_date, "--end-date", end_date,
                            "--cost-metric", cost_metric])
            for flag, values in (("--group-by", group_by), ("--services", services),
                                 ("--billing-regions", billing_regions)):
                if values is not None:
                    command.extend([flag, *values])
        if anomaly_types is not None:
            command.extend(["--anomaly-types", *anomaly_types])
        if mode == "anomalies":
            command.extend(["--lookback-days", str(lookback_days),
                            "--threshold-percent", str(threshold_percent)])
        if previous_state is not None:
            state_path = Path(directory) / "state.json"
            state_path.write_text(json.dumps(previous_state), encoding="utf-8")
            command.extend(["--state", str(state_path)])
        environment = dict(os.environ)
        for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN",
                    "AWS_WEB_IDENTITY_TOKEN_FILE"):
            environment.pop(key, None)
        environment.update({
            "AWS_ACCESS_KEY_ID": credentials["access_key"],
            "AWS_SECRET_ACCESS_KEY": credentials["secret_key"],
            "AWS_SESSION_TOKEN": credentials["session_token"],
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
        })
        try:
            process = subprocess.run(command, env=environment, capture_output=True,
                                     timeout=660, check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError("OptScale scan exceeded the subprocess deadline") from None
        if process.returncode not in (0, 2) or not output.exists():
            raise RuntimeError("OptScale scan failed; retain prior findings")
        result = json.loads(output.read_text(encoding="utf-8"))
        if result.get("account_id") != credentials["account_id"] or result.get("region") != region:
            raise RuntimeError("OptScale result scope mismatch")
        return result
