"""The SDK must run with platform imports and all network access unavailable."""

import subprocess
import sys
import textwrap
import unittest


class NoOptScaleLoginTests(unittest.TestCase):
    def test_python_and_cli_run_without_platform_authentication(self):
        script = textwrap.dedent('''
            import contextlib
            import importlib.abc
            import io
            import json
            import sys
            from unittest.mock import Mock, patch

            class BlockPlatform(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split('.')[0] in {
                        'optscale_client', 'auth', 'rest_api', 'etcd', 'bumiworker'
                    }:
                        raise AssertionError('SDK attempted a platform import')

            sys.meta_path.insert(0, BlockPlatform())
            with patch('socket.socket.connect', side_effect=AssertionError('Network forbidden')), \\
                 patch('socket.create_connection', side_effect=AssertionError('Network forbidden')), \\
                 patch.dict('os.environ', {}, clear=True):
                from optscale_sdk import analyze, scan_aws
                from optscale_sdk.cli import main

                rule = 'volumes_not_attached_for_a_long_time'
                snapshot = {
                    'schema_version': 1, 'account_id': '123456789012',
                    'region': 'us-east-1', 'collected_at': 1800000000,
                    'resources': [], 'collection': {'volume': True},
                }
                assert analyze(snapshot, rules=[rule])['status'] == 'complete'
                with patch('sys.stdin', io.StringIO(json.dumps(snapshot))), \\
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    assert main(['--input', '-', '--rules', rule]) == 0
                assert json.loads(output.getvalue())['status'] == 'complete'

                # Only AWS transport is substituted: SDK orchestration and
                # analysis execute normally with no OptScale auth available.
                sts, ec2 = Mock(), Mock()
                sts.get_caller_identity.return_value = {
                    'Account': '123456789012',
                    'Arn': 'arn:aws:sts::123456789012:assumed-role/scanner/test',
                }
                ec2.describe_volumes.return_value = {'Volumes': []}
                with patch('optscale_sdk.aws._clients', return_value={'sts': sts, 'ec2': ec2}):
                    assert scan_aws(region='us-east-1', rules=[rule])['status'] == 'complete'
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        assert main(['--region', 'us-east-1', '--rules', rule]) == 0
                    assert json.loads(output.getvalue())['status'] == 'complete'
        ''')
        result = subprocess.run([sys.executable, "-c", script], text=True,
                                capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
