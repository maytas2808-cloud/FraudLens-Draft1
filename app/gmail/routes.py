"""Sign in with Google, dashboard API and report actions."""
import logging
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

from . import client, config, store, worker

router = APIRouter()
log = logging.getLogger("fraudlens.gmail")
STATIC = Path(__file__).resolve().parents[1] / "static"


def _back(error: str) -> RedirectResponse:
    return RedirectResponse(f"/dashboard?error={error}", status_code=303)


def _require_user(request: Request) -> str:
    email = request.session.get("email")
    if not email or not config.configured() or not store.user(email):
        raise HTTPException(status_code=401, detail="Sign in with Google first.")
    return email


@router.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC / "dashboard.html")


@router.get("/auth/google", include_in_schema=False)
def login(request: Request):
    if not config.configured():
        return _back("not_configured")
    # The session cookie must be set on the same host Google redirects back to.
    if request.url.netloc != urlsplit(config.BASE_URL).netloc:
        return RedirectResponse(f"{config.BASE_URL}/auth/google", status_code=303)
    flow = client.make_flow()
    url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopes="true")
    request.session["oauth_state"] = state
    request.session["code_verifier"] = flow.code_verifier
    return RedirectResponse(url, status_code=303)


@router.get("/auth/callback", include_in_schema=False)
def callback(request: Request):
    if not config.configured():
        return _back("not_configured")
    params = request.query_params
    state = request.session.pop("oauth_state", None)
    verifier = request.session.pop("code_verifier", None)
    if params.get("error"):
        return _back("denied")
    if not state or params.get("state") != state or not params.get("code"):
        return _back("state")
    flow = client.make_flow(state=state)
    flow.code_verifier = verifier
    try:
        flow.fetch_token(code=params["code"])
    except Exception:
        log.exception("google token exchange failed")
        return _back("token")
    if not set(config.SCOPES) <= client.granted_scopes(flow):
        return _back("scopes")
    creds = flow.credentials
    try:
        email = client.service(creds).users().getProfile(userId="me").execute()["emailAddress"].lower()
    except Exception:
        log.exception("gmail profile lookup failed")
        return _back("profile")
    is_new = store.save_user(email, creds.to_json())
    request.session["email"] = email
    if is_new:
        threading.Thread(target=worker.safe_scan, args=(email, config.INITIAL_SCAN), daemon=True).start()
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/auth/logout", include_in_schema=False)
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@router.post("/auth/disconnect", include_in_schema=False)
def disconnect(request: Request):
    email = _require_user(request)
    data = store.creds_json(email)
    if data:
        client.revoke(client.credentials(data))
    store.delete_user(email)
    request.session.clear()
    return {"ok": True}


@router.get("/api/me", include_in_schema=False)
def me(request: Request):
    base = {"configured": config.configured(), "signed_in": False, "poll_seconds": config.POLL_SECONDS}
    email = request.session.get("email")
    u = store.user(email) if (email and config.configured()) else None
    if not u:
        return base
    return {**base, "signed_in": True, "email": email, "connected": bool(u["active"]), "error": u["error"],
            "prefs": {"digest": u["digest"], "alerts": bool(u["alerts"])},
            "last_scan_at": u["last_scan_at"], "last_digest_at": u["last_digest_at"], "stats": store.stats(email)}


@router.get("/api/my-emails", include_in_schema=False)
def my_emails(request: Request, level: str | None = None):
    email = _require_user(request)
    if level not in (None, "high", "medium", "low"):
        raise HTTPException(status_code=422, detail="level must be high, medium or low")
    return {"emails": store.results(email, level=level, limit=200)}


@router.post("/api/my-emails/scan", include_in_schema=False)
async def scan_now(request: Request):
    email = _require_user(request)
    try:
        new = await run_in_threadpool(worker.scan, email, config.SCAN_BATCH)
    except Exception:
        log.exception("manual gmail scan failed")
        raise HTTPException(status_code=502, detail="Couldn't read your inbox. Try signing in again.")
    return {"new": new}


@router.post("/api/my-report", include_in_schema=False)
async def report_now(request: Request):
    email = _require_user(request)
    try:
        count = await run_in_threadpool(worker.send_report, email, time.time() - worker.DAY)
    except Exception:
        log.exception("sending gmail report failed")
        raise HTTPException(status_code=502, detail="Couldn't send the report. Try signing in again.")
    return {"sent": True, "emails": count}


class Prefs(BaseModel):
    digest: str
    alerts: bool


@router.post("/api/prefs", include_in_schema=False)
def prefs(body: Prefs, request: Request):
    email = _require_user(request)
    if body.digest not in ("daily", "off"):
        raise HTTPException(status_code=422, detail="digest must be daily or off")
    store.set_prefs(email, body.digest, body.alerts)
    return {"ok": True}
