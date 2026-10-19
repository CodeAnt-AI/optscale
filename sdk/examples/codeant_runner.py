"""Copy/adapt into CodeAnt's background scan worker; no new infrastructure.

Install optscale-analysis[aws] into the same Python environment as this runner.
The caller supplies already-assumed-role credentials and stores result['state']
using its existing per-tenant/account/region blob storage.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run_optscale(credentials, region, previous_state=None, *, rules=None):
    with tempfile.TemporaryDirectory(prefix="optscale-") as directory:
        output = Path(directory) / "result.json"
        command = [sys.executable, "-m", "optscale_sdk", "--region", region,
                   "--account-id", credentials["account_id"],
                   "--timeout", "600", "--output", str(output)]
        if rules is not None:
            command.extend(["--rules", *rules])
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
