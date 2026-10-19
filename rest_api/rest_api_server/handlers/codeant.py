"""Opt-in CodeAnt service API. Native OptScale authentication is unchanged."""

import hmac
import json
import os
from pathlib import Path
from uuid import UUID

from etcd import Lock
from rest_api.rest_api_server.constants import urls_v2
from rest_api.rest_api_server.controllers.base_async import BaseAsyncControllerWrapper
from rest_api.rest_api_server.controllers.cloud_account import CloudAccountController
from rest_api.rest_api_server.controllers.employee import EmployeeController
from rest_api.rest_api_server.controllers.organization import OrganizationController
from rest_api.rest_api_server.controllers.pool import PoolController
from rest_api.rest_api_server.controllers.rule import RuleController
from rest_api.rest_api_server.handlers.v1.base import BaseHandler
from rest_api.rest_api_server.models.models import (
    CloudAccount,
    Employee,
    OrganizationConstraint,
    Pool,
)
from rest_api.rest_api_server.utils import ModelEncoder, run_task
from tornado.web import HTTPError

OPERATIONS = json.loads(Path(__file__).with_name("codeant_operations.json").read_text())


def service_organization(headers):
    expected = os.environ.get("CODEANT_INTEGRATION_SECRET", "")
    supplied = headers.get("X-CodeAnt-Service-Key", "")
    if (
        not expected
        or not supplied
        or not hmac.compare_digest(expected.encode(), supplied.encode())
    ):
        raise HTTPError(401)
    try:
        return str(UUID(headers.get("X-CodeAnt-Organization", "")))
    except (ValueError, AttributeError):
        raise HTTPError(400, reason="Invalid CodeAnt organization")


class CodeAntCloudAccountController(CloudAccountController):
    """Create cloud allocation records without an OptScale auth user."""

    def get_user_info(self, user_id=None):
        return {}

    def _create_pool_and_rule(self, cloud_account):
        parent_pool = cloud_account.organization.pool
        employee = parent_pool.default_owner
        if employee is None:
            raise HTTPError(409, reason="Run CodeAnt FinOps setup first")
        pool = PoolController(self.session, self._config).create(
            organization_id=cloud_account.organization_id,
            parent_id=parent_pool.id,
            name=self._generate_pool_name(cloud_account),
            default_owner_id=employee.id,
        )
        # The service boundary has already authorized the organization. Build
        # its allocation rule locally; there is no auth user to authorize.
        controller = RuleController(self.session, self._config)
        rule, _, _ = controller._prepare_rule_data(
            employee,
            cloud_account.organization_id,
            is_deprioritized=True,
            name="CodeAnt " + cloud_account.id,
            owner_id=employee.id,
            pool_id=pool.id,
            conditions=[{"type": "cloud_is", "meta_info": cloud_account.id}],
        )
        self.session.add(rule)
        self.session.commit()


class CodeAntCloudAccountAsyncController(BaseAsyncControllerWrapper):
    def _get_controller_class(self):
        return CodeAntCloudAccountController


class CodeAntServiceMixin:
    allowed_methods = ()
    codeant_route = None

    @property
    def token(self):
        return None

    async def prepare(self):
        self.codeant_organization = service_organization(self.request.headers)
        if self.request.method not in self.allowed_methods:
            raise HTTPError(405)
        # Do not run native prepare methods which require an OptScale token.
        BaseHandler.prepare(self)
        await run_task(self._validate_scope)

    def check_cluster_secret(self, raises=True):
        # Called only after service authentication on namespaced handlers.
        return True

    async def check_permissions(self, action, resource_type, resource_id):
        if resource_type == "organization":
            if resource_id != self.codeant_organization:
                raise HTTPError(403)
        elif resource_type == "cloud_account":
            await run_task(self._check_account, resource_id)
        elif resource_type == "organization_constraint":
            await run_task(self._check_entity, OrganizationConstraint, resource_id)
        elif resource_type == "cloud_resource":
            await run_task(self._check_resource, resource_id)
        else:
            # No implicit authorization for unsupported identity-based flows.
            raise HTTPError(403)

    async def check_self_auth(self, user_id=None):
        if self.codeant_route != "resource_optimizations":
            raise HTTPError(403)
        # Native recommendation updates use this only to choose an ownership
        # permission; the service path authorizes the resource's tenant instead.
        return None

    def _get_controller_class(self):
        if self.codeant_route in {"cloud_account", "cloud_account_collection"}:
            return CodeAntCloudAccountAsyncController
        return super()._get_controller_class()

    def _check_account(self, account_id):
        self._check_entity(CloudAccount, account_id)

    def _check_entity(self, model, entity_id):
        if not isinstance(entity_id, str):
            raise HTTPError(400)
        entity = (
            self.session()
            .query(model)
            .filter(
                model.id == entity_id.rstrip("+"),
                model.organization_id == self.codeant_organization,
                model.deleted.is_(False),
            )
            .one_or_none()
        )
        if entity is None:
            raise HTTPError(404)

    def _validate_body_references(self, payload, references):
        if not isinstance(payload, dict):
            return
        for name, value in payload.items():
            if name == "config":
                continue  # Provider identifiers inside credentials are not OptScale IDs.
            if name in references:
                for entity_id in value if isinstance(value, list) else [value]:
                    self._check_entity(references[name], entity_id)
            elif isinstance(value, dict):
                self._validate_body_references(value, references)

    def _check_resource(self, resource_id):
        from rest_api.rest_api_server.controllers.expense import RawExpenseController

        controller = RawExpenseController(self.session(), self._config)
        try:
            if controller.get_organization_id(resource_id) != self.codeant_organization:
                raise HTTPError(404)
        finally:
            controller.on_finish()

    def _validate_scope(self):
        if self.codeant_route == "setup":
            return
        organization = OrganizationController(self.session(), self._config).get(
            self.codeant_organization
        )
        if organization is None:
            raise HTTPError(404, reason="Run CodeAnt FinOps setup first")
        if organization.disabled:
            raise HTTPError(403)
        path_org = self.path_kwargs.get("organization_id")
        if path_org and path_org != self.codeant_organization:
            raise HTTPError(403)
        account_id = self.path_kwargs.get("cloud_account_id")
        if self.codeant_route == "cloud_account":
            account_id = self.path_kwargs.get("id")
        if account_id:
            self._check_account(account_id)
        if self.codeant_route == "organization_constraints":
            self._check_entity(OrganizationConstraint, self.path_kwargs.get("id"))
        if self.codeant_route in {
            "raw_expenses",
            "resource_metrics",
            "resource_optimizations",
        }:
            resource_id = self.path_kwargs.get("resource_id") or self.path_kwargs.get(
                "id"
            )
            self._check_resource(resource_id)
        payload = self._request_body() if self.request.body else {}
        allowed = {
            "cloud_account_collection": {
                "name",
                "type",
                "config",
                "auto_import",
                "process_recommendations",
            },
            "cloud_account": {
                "name",
                "config",
                "auto_import",
                "process_recommendations",
            },
            "schedule_imports": {
                "cloud_account_id",
                "import_from",
                "import_to",
                "priority",
            },
            "resource_optimizations": {"action", "recommendation"},
            "organization_constraints_collection": {
                "name",
                "type",
                "definition",
                "filters",
            },
            "organization_constraints": {"name", "definition", "filters"},
        }.get(self.codeant_route, set())
        if not isinstance(payload, dict) or set(payload) - allowed:
            raise HTTPError(400, reason="Unsupported integration payload fields")
        if self.codeant_route == "schedule_imports" and not payload.get(
            "cloud_account_id"
        ):
            raise HTTPError(400, reason="A cloud account is required")
        references = {
            "cloud_account_id": CloudAccount,
            "pool_id": Pool,
            "owner_id": Employee,
            "employee_id": Employee,
        }
        self._validate_body_references(payload, references)
        for name, model in references.items():
            values = [value.decode() for value in self.request.arguments.get(name, [])]
            for value in values:
                self._check_entity(model, value)
        for value in self.request.arguments.get("resource_id", []):
            self._check_resource(value.decode())
        for name in ("organization_id", "tenant_id", "token"):
            if name in self.request.arguments:
                raise HTTPError(400)


class CodeAntSetupHandler(CodeAntServiceMixin, BaseHandler):
    allowed_methods = ("PUT",)
    codeant_route = "setup"

    async def put(self):
        body = self._request_body()
        if not isinstance(body, dict) or set(body) - {"name", "currency"}:
            raise HTTPError(400)
        result = await run_task(self._setup, body)
        self.write(json.dumps(result, cls=ModelEncoder))

    def _setup(self, body):
        # Distributed lock covers root-pool, constraints and allocation-owner
        # initialization, not just the initial organization row insert.
        with Lock(self._config, "codeant-finops-" + self.codeant_organization):
            controller = OrganizationController(self.session(), self._config)
            organization = controller.get(self.codeant_organization)
            if organization is None:
                organization = controller.create(
                    id=self.codeant_organization,
                    name=body.get("name", "CodeAnt"),
                    currency=body.get("currency", "USD"),
                )
            if organization.disabled:
                raise HTTPError(403)
            if organization.pool.default_owner is None:
                employee = EmployeeController(self.session(), self._config).create(
                    organization_id=organization.id,
                    name="CodeAnt",
                    auth_user_id=None,
                )
                organization.pool.default_owner_id = employee.id
                self.session().commit()
            return organization.to_dict()


def integration_handlers(existing_handlers, handler_kwargs):
    """Reuse native handlers only for explicit FinOps routes and methods."""
    routes = {}
    for spec in OPERATIONS.values():
        if spec["route"]:
            routes.setdefault(spec["route"], set()).add(spec["method"])
    handlers_by_path = {entry[0]: entry[1] for entry in existing_handlers}
    result = [("/restapi/v2/codeant/setup", CodeAntSetupHandler, handler_kwargs)]
    for route, methods in routes.items():
        path = getattr(urls_v2, route)
        handler = handlers_by_path[path]
        wrapped = type(
            "CodeAnt" + handler.__name__,
            (CodeAntServiceMixin, handler),
            {
                "allowed_methods": tuple(methods),
                "codeant_route": route,
            },
        )
        result.append(
            (
                path.replace("/restapi/v2/", "/restapi/v2/codeant/", 1),
                wrapped,
                handler_kwargs,
            )
        )
    return result
