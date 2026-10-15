"""Scan connected inboxes, send instant alerts and daily reports."""
import asyncio
import logging
import threading
import time

from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError

from ..analyzer.engine import analyze
from . import client, config, report, store

log = logging.getLogger("fraudlens.gmail")
DAY = 24 * 3600
_running: set[str] = set()
_running_lock = threading.Lock()


class NotConnected(Exception):
    pass


def _reasons(result: dict) -> list[str]:
    labels = [i["label"] for i in result["indicators"] if i["weight"] < 0] if result["level"] == "low" else []
    labels += [i["label"] for i in result["indicators"] if i["weight"] > 0]
    labels += [i["label"] for u in result["urls"] if u.get("counted", True) for i in u["indicators"] if i["weight"] > 0]
    return list(dict.fromkeys(labels))[:4]


def _session(email: str):
    data = store.creds_json(email)
    if not data:
        raise NotConnected(email)
    creds = client.credentials(data)
    return creds, client.service(creds)


def _save_if_refreshed(email: str, creds, before: str) -> None:
    after = creds.to_json()
    if after != before:
        store.update_token(email, after)


def scan(email: str, limit: int = config.SCAN_BATCH, rescan: bool = False) -> int:
    """Analyse inbox messages not seen before (or, with rescan, re-rate the latest ones). Returns how many were analysed."""
    with _running_lock:
        if email in _running:
            return 0
        _running.add(email)
    try:
        creds, svc = _session(email)
        before = creds.to_json()
        ids = client.list_inbox(svc, limit)
        known = store.known_ids(email, ids)
        new = ids if rescan else [i for i in ids if i not in known]
        count = 0
        for msg_id in new:
            raw, received = client.fetch_raw(svc, msg_id)
            text, meta = client.compact(raw)
            if meta["is_report"]:
                store.add_result(email, msg_id, received_at=received, sender=meta["sender"], subject=meta["subject"],
                                 score=0, level="skipped", scenarios=[], reasons=[], summary="")
                continue
            r = analyze(text)
            verdict = dict(score=r["score"], level=r["level"], scenarios=[s["name"] for s in r["scenarios"]],
                           reasons=_reasons(r), summary=r["summary"])
            if msg_id in known:
                store.update_result(email, msg_id, **verdict)
            else:
                store.add_result(email, msg_id, received_at=received, sender=meta["sender"], subject=meta["subject"], **verdict)
            count += 1
        _save_if_refreshed(email, creds, before)
        store.mark(email, last_scan_at=time.time(), error=None)
        log.info("gmail scan: %d messages analysed", count)
        return count
    except RefreshError:
        store.mark(email, active=0, error="Google access expired or was revoked. Please sign in again.")
        raise
    except HttpError as e:
        store.mark(email, error=f"Gmail API error ({e.status_code}).")
        raise
    finally:
        with _running_lock:
            _running.discard(email)


def send_report(email: str, since: float | None = None) -> int:
    u = store.user(email)
    if since is None:
        since = (u or {}).get("last_digest_at") or time.time() - DAY
    rows = store.results(email, since=since, limit=500)
    creds, svc = _session(email)
    before = creds.to_json()
    subject, text, html_body = report.build(rows, "digest")
    client.send_to_self(svc, email, subject, text, html_body)
    _save_if_refreshed(email, creds, before)
    store.mark(email, last_digest_at=time.time())
    return len(rows)


def _send_alerts(u: dict) -> None:
    pending = store.pending_alerts(u["email"], received_after=u["created_at"])
    if not pending:
        return
    creds, svc = _session(u["email"])
    subject, text, html_body = report.build(pending, "alert")
    client.send_to_self(svc, u["email"], subject, text, html_body)
    store.mark_alerted(u["email"], [r["msg_id"] for r in pending])


def safe_scan(email: str, limit: int) -> None:
    try:
        scan(email, limit)
    except Exception:
        log.exception("gmail scan failed")


def poll_all() -> None:
    for u in store.active_users():
        try:
            scan(u["email"])
            if u["alerts"]:
                _send_alerts(u)
            last = u["last_digest_at"] or u["created_at"]
            if u["digest"] == "daily" and time.time() - last >= DAY:
                send_report(u["email"], since=last)
        except Exception:
            log.exception("gmail poll failed for one user")


async def loop() -> None:
    while True:
        try:
            await asyncio.to_thread(poll_all)
        except Exception:
            log.exception("gmail poll loop error")
        await asyncio.sleep(config.POLL_SECONDS)
