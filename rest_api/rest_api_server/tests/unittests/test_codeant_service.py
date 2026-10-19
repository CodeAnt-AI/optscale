"""Unit-test the integration boundary without booting OptScale's datastores."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

import pytest


class ServiceHTTPError(Exception):
    def __init__(self, status_code, **kwargs):
        self.status_code = status_code


@pytest.fixture
def service():
    # Stub external infrastructure at import time; execute the actual handler
    # module so auth, scope checks and route construction remain under test.
    root = Path(__file__).resolve().parents[2]
    path = root / "handlers" / "codeant.py"
    # Use the actual route definitions, not a second set of hand-written paths.
    constants = importlib.util.spec_from_file_location(
        "codeant_test_constants", root / "constants.py"
    )
    constants_module = importlib.util.module_from_spec(constants)
    constants.loader.exec_module(constants_module)
    urls = constants_module.urls_v2

    class Controller:
        pass

    dependencies = {
        "etcd": SimpleNamespace(Lock=Mock()),
        "tornado.web": SimpleNamespace(HTTPError=ServiceHTTPError),
        "rest_api.rest_api_server.constants": SimpleNamespace(urls_v2=urls),
        "rest_api.rest_api_server.controllers.cloud_account": SimpleNamespace(
            CloudAccountController=Controller
        ),
        "rest_api.rest_api_server.controllers.base_async": SimpleNamespace(
            BaseAsyncControllerWrapper=Controller
        ),
        "rest_api.rest_api_server.controllers.employee": SimpleNamespace(
            EmployeeController=Mock()
        ),
        "rest_api.rest_api_server.controllers.organization": SimpleNamespace(
            OrganizationController=Mock()
        ),
        "rest_api.rest_api_server.controllers.pool": SimpleNamespace(
            PoolController=Mock()
        ),
        "rest_api.rest_api_server.controllers.rule": SimpleNamespace(
            RuleController=Mock()
        ),
        "rest_api.rest_api_server.handlers.v1.base": SimpleNamespace(
            BaseHandler=type("BaseHandler", (), {})
        ),
        "rest_api.rest_api_server.models.models": SimpleNamespace(
            CloudAccount=MagicMock(),
            Employee=MagicMock(),
            Pool=MagicMock(),
            OrganizationConstraint=MagicMock(),
        ),
        "rest_api.rest_api_server.utils": SimpleNamespace(
            ModelEncoder=json.JSONEncoder, run_task=Mock()
        ),
    }
    spec = importlib.util.spec_from_file_location("codeant_service_under_test", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, dependencies):
        spec.loader.exec_module(module)
    return module


def test_service_auth_is_disabled_without_configuration(service, monkeypatch):
    monkeypatch.delenv("CODEANT_INTEGRATION_SECRET", raising=False)
    with pytest.raises(ServiceHTTPError) as error:
        service.service_organization({"X-CodeAnt-Service-Key": "anything"})
    assert error.value.status_code == 401


@pytest.mark.parametrize("supplied", ["", "wrong-key"])
def test_service_rejects_invalid_credentials(service, monkeypatch, supplied):
    monkeypatch.setenv("CODEANT_INTEGRATION_SECRET", "correct-key")
    with pytest.raises(ServiceHTTPError) as error:
        service.service_organization({"X-CodeAnt-Service-Key": supplied})
    assert error.value.status_code == 401


def test_service_requires_valid_organization(service, monkeypatch):
    monkeypatch.setenv("CODEANT_INTEGRATION_SECRET", "correct-key")
    headers = {
        "X-CodeAnt-Service-Key": "correct-key",
        "X-CodeAnt-Organization": "../other",
    }
    with pytest.raises(ServiceHTTPError) as error:
        service.service_organization(headers)
    assert error.value.status_code == 400
    headers["X-CodeAnt-Organization"] = str(uuid4())
    assert service.service_organization(headers) == headers["X-CodeAnt-Organization"]


def test_only_declared_methods_are_exposed_on_namespaced_routes(service):
    existing = []
    for spec in service.OPERATIONS.values():
        if not spec["route"]:
            continue
        path = getattr(service.urls_v2, spec["route"])
        if path not in {entry[0] for entry in existing}:
            existing.append((path, type("NativeHandler", (), {}), {}))
    wrapped = service.integration_handlers(existing, {})
    assert all("/restapi/v2/codeant/" in path for path, _, _ in wrapped)
    assert len(wrapped) == len(existing) + 1
    for spec in service.OPERATIONS.values():
        if spec["route"]:
            path = getattr(service.urls_v2, spec["route"]).replace(
                "/restapi/v2/", "/restapi/v2/codeant/"
            )
            handler = next(
                handler for registered, handler, _ in wrapped if registered == path
            )
            assert spec["method"] in handler.allowed_methods
            methods = {
                item["method"]
                for item in service.OPERATIONS.values()
                if item["route"] == spec["route"]
            }
            if methods == {"GET"}:
                assert handler.allowed_methods == ("GET",)


def test_cross_tenant_path_is_rejected_before_native_handler(service):
    handler = service.CodeAntServiceMixin()
    handler._config = Mock()
    handler.codeant_route = "cloud_account_collection"
    handler.codeant_organization = str(uuid4())
    handler.path_kwargs = {"organization_id": str(uuid4())}
    handler.session = Mock()
    service.OrganizationController.return_value.get.return_value = SimpleNamespace(
        disabled=False
    )
    with pytest.raises(ServiceHTTPError) as error:
        handler._validate_scope()
    assert error.value.status_code == 403


def test_imports_cannot_schedule_all_tenants(service):
    handler = service.CodeAntServiceMixin()
    handler._config = Mock()
    handler.codeant_route = "schedule_imports"
    handler.codeant_organization = str(uuid4())
    handler.path_kwargs = {}
    handler.session = Mock()
    handler.request = SimpleNamespace(body=b"{}", arguments={})
    handler._request_body = lambda: {}
    service.OrganizationController.return_value.get.return_value = SimpleNamespace(
        disabled=False
    )
    with pytest.raises(ServiceHTTPError) as error:
        handler._validate_scope()
    assert error.value.status_code == 400


def test_setup_reuses_org_and_does_not_create_auth_users(service):
    handler = service.CodeAntSetupHandler()
    handler.codeant_organization = str(uuid4())
    handler._config = Mock()
    handler.session = Mock()
    lock = service.Lock.return_value
    lock.__enter__ = Mock()
    lock.__exit__ = Mock(return_value=False)
    organization = Mock(disabled=False)
    organization.to_dict.return_value = {"id": handler.codeant_organization}
    service.OrganizationController.return_value.get.return_value = organization
    assert handler._setup({"name": "Customer"}) == {"id": handler.codeant_organization}
    service.OrganizationController.return_value.create.assert_not_called()
    service.EmployeeController.assert_not_called()


def test_cloud_allocation_uses_local_owner_without_auth(service):
    controller = service.CodeAntCloudAccountController()
    controller._session = Mock()
    controller.session = Mock()
    controller._config = Mock()
    controller._generate_pool_name = lambda account: "Cloud costs"
    account = SimpleNamespace(
        id=str(uuid4()), organization_id=str(uuid4()), organization=Mock()
    )
    rule = Mock()
    service.RuleController.return_value._prepare_rule_data.return_value = (
        rule,
        Mock(),
        Mock(),
    )
    controller._create_pool_and_rule(account)
    controller.session.add.assert_called_once_with(rule)
    assert (
        service.RuleController.return_value._prepare_rule_data.call_args.args[0]
        is account.organization.pool.default_owner
    )


def test_cross_tenant_account_is_not_found(service):
    handler = service.CodeAntServiceMixin()
    handler.codeant_organization = str(uuid4())
    handler.session = Mock()
    handler.session.return_value.query.return_value.filter.return_value.one_or_none.return_value = None
    with pytest.raises(ServiceHTTPError) as error:
        handler._check_account(str(uuid4()))
    assert error.value.status_code == 404
    service.CloudAccount.organization_id.__eq__.assert_called_with(
        handler.codeant_organization
    )


def test_nested_constraint_account_filters_are_scoped(service):
    handler = service.CodeAntServiceMixin()
    handler._check_entity = Mock(side_effect=ServiceHTTPError(404))
    with pytest.raises(ServiceHTTPError):
        handler._validate_body_references(
            {"filters": {"cloud_account_id": ["foreign"]}},
            {"cloud_account_id": service.CloudAccount},
        )
    handler._check_entity.assert_called_once_with(service.CloudAccount, "foreign")
