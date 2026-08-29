from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from backend.api.main import app
from backend.db.database import SessionLocal
from backend.db.models import Scan, ScanStatus


@pytest.fixture(autouse=True)
def clean_scans_table():
    db = SessionLocal()
    db.query(Scan).delete()
    db.commit()
    with patch("backend.api.main.is_safe_target", return_value=(True, "")):
        try:
            yield
        finally:
            db.query(Scan).delete()
            db.commit()
            db.close()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_create_authorized_scan_returns_pending_record(client):
    response = client.post(
        "/scan", json={"target_url": "https://example.com", "authorized": True}
    )

    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    db = SessionLocal()
    try:
        scan = db.get(Scan, UUID(scan_id))
        assert scan is not None
        assert scan.status == ScanStatus.pending
    finally:
        db.close()


def test_create_scan_requires_authorization(client):
    response = client.post(
        "/scan", json={"target_url": "https://example.com", "authorized": False}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "must confirm authorization to scan target"


def test_create_scan_requires_http_url(client):
    response = client.post(
        "/scan", json={"target_url": "example.com", "authorized": True}
    )

    assert response.status_code == 400


def test_get_existing_scan_returns_expected_fields(client):
    create_response = client.post(
        "/scan", json={"target_url": "https://example.com", "authorized": True}
    )

    response = client.get(f"/scan/{create_response.json()['scan_id']}")

    assert response.status_code == 200
    assert response.json()["target_url"] == "https://example.com"
    assert response.json()["status"] == "pending"
    assert response.json()["results"] is None


def test_get_nonexistent_scan_returns_404(client):
    response = client.get(f"/scan/{uuid4()}")

    assert response.status_code == 404


def test_status_endpoint_matches_scan_record(client):
    create_response = client.post(
        "/scan", json={"target_url": "https://example.com", "authorized": True}
    )
    scan_id = create_response.json()["scan_id"]

    scan_response = client.get(f"/scan/{scan_id}")
    status_response = client.get(f"/scan/{scan_id}/status")

    assert status_response.status_code == 200
    assert status_response.json()["status"] == scan_response.json()["status"]
