from email.message import EmailMessage

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.analyzer.engine import analyze
from app.gmail import client, config, report, store, worker
from app.main import app


def _phish() -> bytes:
    m = EmailMessage()
    m["From"] = "SBI Bank Security <alerts@sbi-secure-mail.top>"
    m["Reply-To"] = "sbi.support.desk@gmail.com"
    m["To"] = "me@example.com"
    m["Subject"] = "Urgent: your account will be blocked"
    m["Authentication-Results"] = "mx.google.com; spf=fail; dkim=none; dmarc=fail"
    m.set_content("Your SBI account will be blocked today. Update KYC now.")
    m.add_alternative('<p>Your SBI account will be <b>blocked today</b>.</p>'
                      '<a href="http://sbi-kyc-verify.xyz/login">Update KYC now</a>', subtype="html")
    return m.as_bytes()


def _normal() -> bytes:
    m = EmailMessage()
    m["From"] = "Priya <priya@example.org>"
    m["To"] = "me@example.com"
    m["Subject"] = "Lunch on Friday?"
    m.set_content("Hi! Are we still on for lunch at 1 on Friday? I'll book the table.")
    return m.as_bytes()


@pytest.fixture
def temp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(config, "TOKEN_KEY", Fernet.generate_key().decode())
    yield


def test_compact_keeps_headers_text_and_link_targets():
    text, meta = client.compact(_phish())
    assert text.startswith("From: SBI Bank Security <alerts@sbi-secure-mail.top>")
    assert "Reply-To: sbi.support.desk@gmail.com" in text
    assert "spf=fail" in text
    assert meta["subject"] == "Urgent: your account will be blocked" and not meta["is_report"]
    assert analyze(text)["level"] == "high"


def test_html_to_text_keeps_real_link_address():
    out = client.html_to_text('<style>x{}</style><a href="https://evil.example/x">Click &amp; verify</a><br>Bye')
    assert "Click & verify" in out and "https://evil.example/x" in out and "x{}" not in out


def test_report_escapes_attacker_controlled_text():
    rows = [{"msg_id": "1", "level": "high", "score": 95, "subject": "<script>alert(1)</script>",
             "sender": "x <a@b.c>", "received_at": None, "reasons": ["<img src=x>"], "scenarios": []}]
    subject, text, html_body = report.build(rows, "digest")
    assert "1 high-risk" in subject
    assert "<script>" not in html_body and "&lt;script&gt;" in html_body and "<img" not in html_body


def test_store_roundtrip_encrypts_tokens(temp_store):
    assert store.save_user("me@example.com", '{"token": "abc"}') is True
    assert store.save_user("me@example.com", '{"token": "def"}') is False
    assert store.creds_json("me@example.com") == '{"token": "def"}'
    import sqlite3
    raw = sqlite3.connect(config.DB_PATH).execute("SELECT token FROM users").fetchone()[0]
    assert b"def" not in raw
    store.add_result("me@example.com", "m1", received_at=1.0, sender="s", subject="hi", score=80, level="high",
                     scenarios=["Credential phishing"], reasons=["r"], summary="x")
    assert store.known_ids("me@example.com", ["m1", "m2"]) == {"m1"}
    assert store.stats("me@example.com") == {"total": 1, "high": 1, "medium": 0, "low": 0}
    store.delete_user("me@example.com")
    assert store.user("me@example.com") is None and store.stats("me@example.com")["total"] == 0


def test_scan_analyses_new_mail_and_skips_own_reports(temp_store, monkeypatch):
    own = EmailMessage()
    own["From"] = own["To"] = "me@example.com"
    own["Subject"] = "FraudLens report"
    own[client.REPORT_HEADER] = "1"
    own.set_content("report body")
    raws = {"a": _phish(), "b": _normal(), "c": own.as_bytes()}

    class FakeCreds:
        def to_json(self):
            return "{}"

    store.save_user("me@example.com", "{}")
    monkeypatch.setattr(worker, "_session", lambda email: (FakeCreds(), None))
    monkeypatch.setattr(client, "list_inbox", lambda svc, limit: list(raws))
    monkeypatch.setattr(client, "fetch_raw", lambda svc, mid: (raws[mid], 1_700_000_000.0))

    assert worker.scan("me@example.com") == 2
    assert worker.scan("me@example.com") == 0
    levels = {r["subject"]: r["level"] for r in store.results("me@example.com")}
    assert levels == {"Urgent: your account will be blocked": "high", "Lunch on Friday?": "low"}


def _bank_alert(auth: list[str]) -> bytes:
    m = EmailMessage()
    m["From"] = "Axis Bank Alerts <alerts@axis.bank.in>"
    m["To"] = "me@example.com"
    m["Subject"] = "Axis Bank: Payment - Credited to beneficiary"
    for a in auth:
        m["Authentication-Results"] = a
    m.set_content("Dear Customer, your payment of INR 500 was credited. Never share your OTP. "
                  "Details: https://www.axis.bank.in/support")
    return m.as_bytes()


GMAIL_PASS = "mx.google.com; dkim=pass header.i=@axis.bank.in; spf=pass smtp.mailfrom=axis.bank.in; dmarc=pass (p=REJECT) header.from=axis.bank.in"


def test_verified_bank_alert_is_low_risk():
    text, _ = client.compact(_bank_alert([GMAIL_PASS]))
    r = analyze(text)
    assert r["email"]["from_domain"] == "axis.bank.in" and r["email"]["trusted_sender"]
    assert r["level"] == "low"
    assert not any(i["id"] == "sender_brand_mismatch" for i in r["indicators"])


def test_forged_lower_auth_header_is_ignored():
    raw = _bank_alert(["mx.google.com; spf=fail; dkim=none; dmarc=fail", GMAIL_PASS])
    text, _ = client.compact(raw)
    assert "dmarc=pass" not in text
    assert analyze(text)["email"]["verified"] is False


def test_rescan_updates_verdict_and_keeps_alerted_flag(temp_store, monkeypatch):
    class FakeCreds:
        def to_json(self):
            return "{}"

    store.save_user("me@example.com", "{}")
    store.add_result("me@example.com", "a", received_at=1.0, sender="s", subject="old", score=90, level="high",
                     scenarios=[], reasons=[], summary="")
    store.mark_alerted("me@example.com", ["a"])
    monkeypatch.setattr(worker, "_session", lambda email: (FakeCreds(), None))
    monkeypatch.setattr(client, "list_inbox", lambda svc, limit: ["a"])
    monkeypatch.setattr(client, "fetch_raw", lambda svc, mid: (_normal(), 1.0))
    assert worker.scan("me@example.com", rescan=True) == 1
    assert store.results("me@example.com")[0]["level"] == "low"
    assert store.pending_alerts("me@example.com", 0) == []


def test_dashboard_when_not_configured(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_ID", "")
    c = TestClient(app)
    assert c.get("/dashboard").status_code == 200
    assert c.get("/api/me").json()["configured"] is False
    r = c.get("/auth/google", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard?error=not_configured"
    assert c.get("/api/my-emails").status_code == 401
    assert c.post("/api/my-emails/scan").status_code == 401
