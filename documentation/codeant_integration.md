# CodeAnt → self-hosted OptScale FinOps

CodeAnt exposes `POST /finops/{operation}` and forwards allowlisted operations to
`/restapi/v2/codeant/...` on OptScale. There is no OptScale signup, login, auth user,
password, email verification or token exchange. Native OptScale authentication is
unchanged. The service API is disabled unless a dedicated shared key is configured.

## Deploy

1. Build/deploy the patched OptScale `rest_api` image. The workers and data stores
   remain required. This patch must be deployed before enabling CodeAnt's routes.
2. Provision a random shared service key through your secret manager. Set
   `CODEANT_INTEGRATION_SECRET` on OptScale REST API and
   `OPTSCALE_INTEGRATION_SECRET` on CodeAnt backend to the same value. Do not use
   the OptScale cluster secret or put this credential in browser runtime config.
3. Kubernetes: set Helm value `codeant_integration_secret_name` to an existing
   Secret with a `service-key` entry. Both Compose definitions also accept
   `CODEANT_INTEGRATION_SECRET` for local evaluation.
4. Set CodeAnt `OPTSCALE_URL=https://optscale.codeant.ai` (the origin, **without
   `/api`**). Prefer the private service origin where reachable; HTTP is permitted
   for private cluster networking. No public ingress changes are required because
   the integration sits beneath the existing `/restapi` route.
5. Run the smoke sequence below with a normal CodeAnt session. This change does
   not deploy images, create live cloud connections, or configure live secrets.

## CodeAnt API contract

Every call uses the existing CodeAnt `fetchApi` authentication and organization /
provider context. The backend requires middleware-verified `auth_context` and
provider URL audit fields, so a debug request without verified identity fails
closed. Callers cannot choose OptScale organization IDs or authentication headers.

The organization ID is deterministic from the verified provider, provider-instance
URL and CodeAnt organization. Setup uses an etcd lock and creates an organization,
root pool, default constraints, and a local allocation employee with **no auth user**.
It reuses those records on subsequent calls. There are no registration emails.
Keep the provider URL representation stable: changing it changes the tenant ID.

Requests use `params` for native OptScale query parameters and `payload` for native
write fields. Top-level `cloud_account_id`, `resource_id` and `constraint_id` select
an object. These are OptScale IDs returned by this API, not AWS account numbers.
List filters become repeated query arguments; dates use Unix seconds. Responses
use native OptScale JSON shapes with connection configuration removed. Error
responses expose the upstream error code, not credential-bearing error details.

Read access requires organization-wide `view_cloud_security`; mutations require
organization-wide `settings_cloud_security:write`. Organizations without configured
RBAC fall back to admin-only access. Permission lookup failures fail closed. Read
operations do not provision tenants; an authorized admin calls setup once first.

Examples below omit the standard CodeAnt authentication/provider fields:

```json
POST /finops/setup
{"org":"acme","payload":{"name":"Acme","currency":"USD"}}
```

Reuse an existing CodeAnt AWS infrastructure connection. The backend loads its
role and external ID; neither is accepted from the browser for this operation:

```json
POST /finops/accounts/reuse/create
{"org":"acme","config_id":"saved-codeant-config-id","payload":{"billing":{"config_scheme":"find_report","bucket_name":"existing-billing-bucket"}}}
```

The OptScale AWS service principal still needs trust to assume that role, and the
role needs billing/metrics permissions. Existing security permissions may not be
sufficient. Native OptScale cloud validation returns failures rather than treating
security connectivity as proof of billing access. This shortcut supports the AWS
commercial partition, matching the current adapter's role-ARN construction.

Alternatively use `/finops/accounts/create` with native `name`, `type`, `config`,
`auto_import` and `process_recommendations` in `payload`. This supports native
cloud adapters; provider billing exports/agents still need their own setup.

```json
POST /finops/breakdown
{"org":"acme","params":{"start_date":1790812800,"end_date":1792108800,"breakdown_by":"service_name","cloud_account_id":["optscale-account-id"]}}
```

```json
POST /finops/imports/create
{"org":"acme","payload":{"cloud_account_id":"optscale-account-id","import_from":1790812800,"import_to":1792108800}}
```

```json
POST /finops/recommendations/update
{"org":"acme","resource_id":"optscale-resource-id","payload":{"action":"dismiss","recommendation":"rightsizing_instances"}}
```

Supported operations are defined in `routes/finops/operations.json`:

- Setup, account list/create/reuse/get/update/delete, import history and backfill.
- Overview, expense summary, daily breakdowns, resources, filters, tags, metadata.
- Recommendation summaries/data and resource recommendation activation/dismissal.
- Reserved Instances, Savings Plans, offers and reservation group breakdowns.
- Traffic, resource expenses and resource metrics.
- Organization constraints (including native budget/anomaly types) CRUD and limit hits.

There is no arbitrary upstream URL/path/method proxy, organization deletion, auth
API, resource power action, or script execution through this adapter. The manifests
in both repos must be updated together when adding an operation.

## Existing Cost Optimization UI

The existing `/cloud/aws/cost/*` endpoints are the separate CSPM-based analysis
ledger, including notes and frozen scan history. Their response shapes are not
compatible with OptScale. They remain intact; Cost Explorer clients should call
`/finops/*`. No frontend screen migration or historical-ledger migration is included
in this backend integration. Power actions and OptScale employee/role management
are deliberately not exposed by this FinOps service API.

## Verification

Backend: `python -m pytest tests/routes/finops/test_api.py`.
OptScale: `python -m pytest rest_api/rest_api_server/tests/unittests/test_codeant_service.py`.
The service-boundary tests isolate infrastructure dependencies; they do not replace
an integration test against actual MariaDB, etcd, queues and workers.

Deployment smoke test: setup twice (same organization ID), connect a sandbox cloud,
check imports/accounts, read a populated breakdown, and verify another CodeAnt
organization cannot read/update that cloud ID. Revoke the shared key and verify
requests fail. Check native OptScale login still operates normally. Match imported
cost totals against the provider before enabling customer organizations.
