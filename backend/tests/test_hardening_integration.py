from unittest.mock import patch

import pytest

pytest.importorskip("slowapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from backend.api.main import app, limiter
from backend.db.database import SessionLocal
from backend.db.models import Scan


@pytest.fixture(autouse=True)
def clean_scans_and_limits():
    db = SessionLocal()
    db.query(Scan).delete()
    db.commit()
    limiter._storage.reset()
    try:
        yield
    finally:
        db.query(Scan).delete()
        db.commit()
        db.close()
        limiter._storage.reset()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_unauthorized_scan_request_is_rejected(client):
    response = client.post(
        "/scan", json={"target_url": "https://example.com", "authorized": False}
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "must confirm authorization to scan target"}


def test_private_dns_target_is_rejected(client):
    with patch("backend.security.ssrf_guard.socket.getaddrinfo") as getaddrinfo:
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]
        response = client.post(
            "/scan", json={"target_url": "https://internal.example", "authorized": True}
        )

    assert response.status_code == 400
    assert "private or local" in response.json()["detail"]


def test_sixth_scan_request_is_rate_limited(client):
    # Rapid requests exercise SlowAPI's in-memory fixed-window counter directly;
    # no clock mocking is needed because all six stay in the same one-hour window.
    with patch("backend.api.main.is_safe_target", return_value=(True, "")):
        responses = [
            client.post(
                "/scan", json={"target_url": "https://example.com", "authorized": True}
            )
            for _ in range(6)
        ]

    assert [response.status_code for response in responses[:5]] == [201] * 5
    assert responses[5].status_code == 429
    assert responses[5].json() == {"detail": "Rate limit exceeded, try again later"}
