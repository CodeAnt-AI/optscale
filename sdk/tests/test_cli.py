import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from optscale_sdk.cli import main
from test_analysis import VOLUME_RULE, resource, snapshot


class CliTests(unittest.TestCase):
    def test_offline_json_subprocess_without_cloud_dependencies(self):
        result = subprocess.run(
            [sys.executable, "-m", "optscale_sdk", "--input", "-", "--rules", VOLUME_RULE],
            input=json.dumps(snapshot(resource())), text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(json.loads(result.stdout)["findings"]), 1)

    def test_partial_exit_code_and_output_file(self):
        record = resource()
        record.pop("unused_since")
        with tempfile.TemporaryDirectory() as directory:
            output_path = os.path.join(directory, "result.json")
            with patch("sys.stdin", io.StringIO(json.dumps(snapshot(record)))):
                code = main(["--input", "-", "--rules", VOLUME_RULE, "--output", output_path])
            self.assertEqual(code, 2)
            with open(output_path) as output:
                self.assertEqual(json.load(output)["status"], "partial")

    def test_errors_do_not_expose_credentials(self):
        with patch("optscale_sdk.cli.scan_aws", side_effect=RuntimeError("SECRET_CREDENTIAL")):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["--region", "us-east-1"])
            self.assertEqual(code, 1)
            self.assertNotIn("SECRET_CREDENTIAL", stderr.getvalue())
            self.assertEqual(json.loads(stderr.getvalue())["status"], "failed")

    def test_invalid_json_fails(self):
        with patch("sys.stdin", io.StringIO("invalid")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--input", "-"]), 1)

    def test_list_rules(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["--list-rules"]), 0)
        self.assertIn(VOLUME_RULE, json.loads(stdout.getvalue())["rules"])


if __name__ == "__main__":
    unittest.main()
