# OptScale analysis SDK

An installable, service-free extraction of OptScale's AWS recommendation logic
for CodeAnt background scanners. Python 3.10+ (including CodeAnt's Python 3.11).
The core has **no runtime dependencies**; live AWS collection uses optional boto3.
The wheel contains only `optscale_sdk`, not the OptScale platform, cloud-adapter
dependency tree, databases, HTTP servers, queues, schedulers or UI.

This first version prioritizes AWS cost recommendations. It is not full OptScale
feature parity or a replacement for the existing `/finops/*` HTTP contract.
Original platform code remains available in the repository but is not imported
or installed by the SDK.

## Authentication

The SDK runs directly without OptScale login, signup, an OptScale user or
organization, a session token, a cluster secret, or an integration service key.
Neither the Python API nor the CLI calls OptScale's authentication or REST API.
`OPTSCALE_URL` and `OPTSCALE_INTEGRATION_SECRET` are not used by this SDK.

Offline analysis requires no credentials. Live scans require only AWS credentials
with the read permissions listed below. CodeAnt should authorize the scan using
its existing tenant access controls, then supply its existing assumed-role AWS
credentials. This SDK integration does not change the separate `/finops/*` proxy,
which still calls a hosted OptScale service.

## Install and run

From the repository root:

```sh
python -m pip install './sdk[aws]'
optscale-scan --list-rules
optscale-scan --region us-east-1 --account-id 123456789012 --output /tmp/optscale.json
```

Supply the AWS credential chain (including the session token for assumed roles),
or pass a boto3 Session to `scan_aws`. There are no credential command-line flags.
No AWS resources are created and no OptScale server URL is needed. Existing IAM
access and network connectivity to regional AWS APIs are required.

One invocation scans one account and one explicit region. CodeAnt owns fan-out,
scheduling and result/state storage. Use `--rules RULE_ID ...` to shard further.

```python
import boto3
from optscale_sdk import scan_aws

session = boto3.Session(
    aws_access_key_id=credentials["access_key"],
    aws_secret_access_key=credentials["secret_key"],
    aws_session_token=credentials["session_token"],
)
result = scan_aws(
    region="us-east-1",
    account_id=credentials["account_id"],
    session=session,
    previous_state=previous_state,  # None on first run
    timeout_seconds=600,
)
# Persist result["state"] under your tenant/account/region scope.
# Ingest result["findings"] and retain result["coverage"] and result["errors"].
```

For Trivy/Prowler-style process isolation, see
[`examples/codeant_runner.py`](examples/codeant_runner.py). It uses a child-only
credential environment, scratch files, an expected-account guard, a 600-second
cooperative scan deadline and a 660-second hard subprocess timeout. Provision
enough time in the parent invocation to collect and persist results. The SDK
does not start background threads that outlive the call.

## Extracted rules

| Rule ID | Source in `bumiworker/bumiworker/modules/recommendations/` | Default |
| --- | --- | --- |
| `volumes_not_attached_for_a_long_time` | `volumes_not_attached_for_a_long_time.py` | Unattached for more than 1 day |
| `obsolete_ips` | `obsolete_ips.py` | Unassociated Elastic IP for more than 7 days |
| `abandoned_instances` | `abandoned_instances.py` | Running instance older than 7 days, mean CPU ≤5%, combined mean network ≤1,000 bytes/s |

The core predicates and default thresholds are ported from these modules; their
REST/MongoDB/ClickHouse/Metroculus dependencies are replaced by explicit input.
Differences from platform behavior are deliberate:

- Missing prices do **not** suppress waste findings. Savings are `null` until
  resource-level cost is supplied. Known zero savings remains zero.
- Missing metrics are not zero usage. Each metric needs at least 90% coverage by
  both hourly buckets and expected samples (1-minute detailed or 5-minute basic
  monitoring). Network sums are converted to bytes per second. CPU is weighted
  by sample count. Network conversion uses the observed interval rather than a
  fixed per-sample divisor.
- Inventory observations establish the first observed unused state; the SDK does
  not invent a last attachment/association time from a creation timestamp.
- Findings recommend review; the SDK never deletes, stops or modifies resources.
- OptScale pool/owner/dismissal state is not replicated. CodeAnt owns that state.

Rightsizing, RI/Savings Plans analysis, S3 analysis, snapshot/AMI dependency
analysis, billing imports, notifications and other cloud providers are **not yet
extracted**. Unknown rule IDs fail explicitly rather than silently doing nothing.

## Observation history

Save the `state` object from a live scan and pass it via `previous_state` or
`--state /tmp/previous-state.json` on the next scan. Scope storage by CodeAnt
tenant, AWS account and region. The SDK validates AWS account and region; it does
not implement CodeAnt tenant authorization.

New unused volumes/EIPs remain `observation_window_pending` until enough history
exists. Daily scans are suitable for the default maximum observation gap of two
days. A larger gap resets the unused observation. Configure
`max_history_gap_seconds` / `--max-history-gap` to match an explicitly chosen
cadence; this trades off confidence in continuity. Observations cannot detect a
resource being used and released between scans. Validate before remediation.

Failed inventory collection preserves prior observations within that gap;
successful complete inventory removes observations for deleted resources.
Do not run overlapping writers for the same tenant/account/region state object
without caller-side serialization/version checks. Persist each shard's state
separately or merge it deliberately when scanning different rule subsets.

Without any persisted state, the idle-instance rule still works from CloudWatch,
but age-based unused-volume/IP rules cannot accumulate history. `/tmp` is only
scratch space; CodeAnt's existing blob storage can retain state between Lambdas.

## Result contract and failure handling

Every result has `schema_version: 1`, `engine: "optscale"`, `account_id`, `region`,
`collected_at`, `status`, `findings`, `errors`, and `coverage`. Live scans also
return `snapshot` and `state`. API responses/credentials are not copied wholesale.

`coverage.rules[RULE_ID]` contains `complete`, `evaluated`, `skipped` and
`findings`. `coverage.completed` is true only when **all selected rules** completed
with sufficient evidence. Collection failure, deadline, resource limit, pending
history, invalid records or insufficient metrics must not be interpreted as an
empty successful scan. Partial results retain successful findings.

| Exit status | Meaning |
| --- | --- |
| 0 | Complete scan, even when findings exist; or rule listing |
| 2 | Partial/timed-out result, or CLI argument parsing error (the latter has no result JSON) |
| 1 | Fatal setup/input/output error; no usable scan result |

Consumers must require a valid result envelope as well as an accepted exit code.
On any fatal error, retain prior findings. Do not auto-resolve prior findings for
incomplete rules. Completed-rule reconciliation must be scoped by tenant,
account, region, engine and rule ID; a narrow shard cannot clear other rules.
The existing CodeAnt ledger uses `resource_arn + action` for identity: add engine
and rule identity or explicitly merge provenance before combining OptScale and
Custodian findings for the same resource. Do not sum overlapping savings.

Findings include the CodeAnt-style fields `resource_arn`, `action`, `title`,
`rationale`, `evidence`, `estimated_monthly_savings`, `savings_source`, `confidence`,
`risk_notes`, and `related_findings`, plus rule/account/region/currency fields.
Resource types are `volume`, `elastic_ip`, `instance`; map to any UI-specific
labels at the CodeAnt boundary. This is an integration-ready scanner contract,
not an already-wired backend change.

API timeouts and retries are bounded. The 10,000-resource default cap applies to
inventory records across selected rules; `--max-resources` changes it. Larger
accounts may need narrower rule shards or another execution budget. The SDK
does not silently truncate with success or promise arbitrary accounts fit one
Lambda invocation. There is no resource-page resume token in v0.1.

## Offline input and cost enrichment

The core can be installed without boto3:

```sh
python -m pip install ./sdk
optscale-scan --input sdk/examples/snapshot.json \
  --rules volumes_not_attached_for_a_long_time
```

```python
from optscale_sdk import analyze
result = analyze(snapshot, rules=["volumes_not_attached_for_a_long_time"])
```

Input is a normalized snapshot, **not raw Prowler findings**. Start with
[`examples/snapshot.json`](examples/snapshot.json) or a live result's `snapshot`:

- Envelope: `schema_version`, `account_id`, `region`, UTC Unix `collected_at`,
  `resources`, and `collection` mapping resource type to an explicit completeness
  boolean. Set false for any failed/truncated source, even if some records exist.
- Every resource: `id`, `arn`, `type` (`volume`, `elastic_ip`, `instance`).
- Volume/IP: boolean `unused`, Unix `unused_since` from observation history.
- Instance: boolean `running`, Unix `launched_at`, and `metrics` containing Unix
  `start`/`end` and `cpu`/`network_in`/`network_out` objects, each with `average`
  and `coverage` (0–1). CPU is percent, network is bytes/second. Windows must
  match the configured lookback, allowing a final partial UTC hour.
- Optional resource `cost`: `average_daily_cost` (nonnegative, finite) and
  three-letter `currency`. Supply an appropriate recent resource-level average
  from existing billing evidence. Estimated monthly savings is that value ×30.
  These are gross estimates, not guaranteed bill reductions under commitments.

Live collection intentionally does not ingest CUR or allocate service-level
Cost Explorer totals to resources. To enrich costs, update the live snapshot with
trusted resource costs and call `analyze` again using the same rule options.

Pass an options JSON file via `--options`, or a dict to either Python entry point:

```json
{"abandoned_instances": {"days_threshold": 14, "cpu_percent_threshold": 3,
                         "network_bps_threshold": 500, "minimum_metric_coverage": 0.95}}
```

Days range from 1 to 30. Options must belong to selected rules; unknown options
are rejected. No threshold configuration is stored globally between invocations.

## AWS permissions

The caller supplies an existing role with read access to selected operations:
`ec2:DescribeVolumes`, `ec2:DescribeAddresses`, `ec2:DescribeInstances`, and
`cloudwatch:GetMetricStatistics` (idle instances only). The scanner also calls
`sts:GetCallerIdentity` before inventory to verify its account. It does not
perform AssumeRole itself, request billing exports, create metrics, or enroll
the account in an optimization service.

## Development

```sh
PYTHONPATH=sdk/src python -m unittest discover -s sdk/tests -v
python -m pip wheel --no-deps ./sdk --wheel-dir /tmp/optscale-wheels
```

Tests use fixtures/fake AWS clients; they do not contact AWS. CI checks Python
3.10–3.12 and builds/installs the standalone wheel. Live account behavior and
Lambda resource/runtime sizing require a sandbox-account benchmark before rollout.

The SDK retains the repository's Apache-2.0 license in `LICENSE`; source logic
attribution is recorded above and in `analysis.py`.
