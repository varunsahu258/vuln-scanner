"""Pipeline tests use a mocked session to isolate task orchestration from the DB."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

pytest.importorskip("celery")
pytest.importorskip("sqlalchemy")

from backend.models.scan import Finding, ModuleResult
from backend.worker.celery_app import celery_app
from backend.worker import tasks


@pytest.fixture(autouse=True)
def eager_celery_tasks():
    previous = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    try:
        yield
    finally:
        celery_app.conf.task_always_eager = previous


def _result(module_name: str) -> ModuleResult:
    return ModuleResult(
        module_name=module_name,
        score="A",
        findings=[Finding(check_name="check", severity="info", passed=True, detail="ok")],
    )


def _mock_session(scan):
    # A MagicMock is cleaner than an in-memory database here: these tests verify
    # task state transitions and scanner orchestration, not SQLAlchemy behavior.
    session = MagicMock()
    session.get.return_value = scan
    return session


@patch("backend.worker.tasks.check_subdomain_recon", return_value=_result("recon"))
@patch("backend.worker.tasks.check_open_redirect", return_value=_result("redirect"))
@patch("backend.worker.tasks.check_cors", return_value=_result("cors"))
@patch("backend.worker.tasks.check_tls", return_value=_result("tls"))
@patch("backend.worker.tasks.check_headers", return_value=_result("headers"))
@patch("backend.worker.tasks.check_jwt", return_value=_result("jwt"))
@patch("backend.worker.tasks.SessionLocal")
def test_successful_scan_persists_all_module_results(
    session_local,
    check_jwt,
    check_headers,
    check_tls,
    check_cors,
    check_open_redirect,
    check_subdomain_recon,
):
    scan = SimpleNamespace(
        id=uuid4(), target_url="https://example.com", jwt_token="token", status=None,
        completed_at=None, results=None,
    )
    session_local.return_value = _mock_session(scan)

    tasks.run_scan.delay(str(scan.id))

    assert scan.status.value == "completed"
    assert {module["module_name"] for module in scan.results["modules"]} == {
        "headers", "tls", "cors", "redirect", "recon", "jwt"
    }
    assert scan.results["overall_grade"] == "A"
    check_jwt.assert_called_once_with("token")


@patch("backend.worker.tasks.check_subdomain_recon", return_value=_result("recon"))
@patch("backend.worker.tasks.check_open_redirect", return_value=_result("redirect"))
@patch("backend.worker.tasks.check_cors", return_value=_result("cors"))
@patch("backend.worker.tasks.check_tls", return_value=_result("tls"))
@patch("backend.worker.tasks.check_headers", return_value=_result("headers"))
@patch("backend.worker.tasks.SessionLocal")
def test_scan_without_token_records_info_only_jwt_skip(
    session_local,
    check_headers,
    check_tls,
    check_cors,
    check_open_redirect,
    check_subdomain_recon,
):
    scan = SimpleNamespace(
        id=uuid4(), target_url="https://example.com", jwt_token=None, status=None,
        completed_at=None, results=None,
    )
    session_local.return_value = _mock_session(scan)

    tasks.run_scan.delay(str(scan.id))

    jwt_result = next(
        module for module in scan.results["modules"] if module["module_name"] == "jwt"
    )
    assert jwt_result["score"] == "N/A"
    assert jwt_result["findings"][0]["detail"] == "JWT check skipped - no token provided"


@patch("backend.worker.tasks.check_subdomain_recon", return_value=_result("recon"))
@patch("backend.worker.tasks.check_open_redirect", return_value=_result("redirect"))
@patch("backend.worker.tasks.check_cors", return_value=_result("cors"))
@patch("backend.worker.tasks.check_tls", return_value=_result("tls"))
@patch("backend.worker.tasks.check_headers", side_effect=RuntimeError("scanner exploded"))
@patch("backend.worker.tasks.SessionLocal")
def test_scanner_exception_marks_scan_as_failed(
    session_local,
    check_headers,
    check_tls,
    check_cors,
    check_open_redirect,
    check_subdomain_recon,
):
    scan = SimpleNamespace(
        id=uuid4(), target_url="https://example.com", jwt_token=None, status=None,
        completed_at=None, results=None,
    )
    session_local.return_value = _mock_session(scan)

    tasks.run_scan.delay(str(scan.id))

    assert scan.status.value == "failed"
    assert scan.results == {"error": "scanner exploded"}


@patch("backend.worker.tasks.SessionLocal")
def test_unknown_scan_id_is_handled_without_raising(session_local):
    session = _mock_session(None)
    session_local.return_value = session

    tasks.run_scan.delay(str(uuid4()))

    session.commit.assert_not_called()
    session.close.assert_called_once()
