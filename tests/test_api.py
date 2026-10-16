import pytest
from fastapi.testclient import TestClient

from app import main
from app.analyzer import live_check
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def offline_certificate_check(monkeypatch):
    monkeypatch.setattr(live_check, "check_certificate",
                        lambda host, port=443: {"status": "unreachable", "issuer": None, "expires": None, "days_left": None, "error": "offline test"})


def test_analyze_returns_explained_verdict():
    r = client.post("/api/analyze", json={"content": "Your SBI KYC is pending, account will be blocked. Update at http://sbi-kyc.xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body["level"] == "high"
    assert body["indicators"] and body["advice"] and body["urls"]
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_rejects_empty_and_oversized_input():
    assert client.post("/api/analyze", json={"content": ""}).status_code == 422
    assert client.post("/api/analyze", json={"content": "   "}).status_code == 422
    assert client.post("/api/analyze", json={"content": "a" * 20001}).status_code == 422
    assert client.post("/api/analyze", json={}).status_code == 422


def test_rate_limit():
    main._hits.clear()
    codes = [client.post("/api/analyze", json={"content": "hello there friend"},
                         headers={"x-forwarded-for": f"203.0.113.{i}"}).status_code for i in range(main.RATE_LIMIT + 1)]
    assert codes[-1] == 429 and set(codes[:-1]) == {200}
    main._hits.clear()


def test_pages_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/report").status_code == 200
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["models"] == {"text": True, "url": True}
