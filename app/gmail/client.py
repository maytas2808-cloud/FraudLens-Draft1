"""Google OAuth and Gmail API helpers."""
import base64
import html
import json
import re
import urllib.parse
import urllib.request
from email import message_from_bytes, policy
from email.message import EmailMessage

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from . import config

REPORT_HEADER = "X-FraudLens-Report"
MAX_BODY = 12000
_HEADERS = ("From", "Reply-To", "Return-Path", "To", "Subject", "Date")


def make_flow(state: str | None = None) -> Flow:
    client = {"web": {
        "client_id": config.CLIENT_ID,
        "client_secret": config.CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [config.REDIRECT_URI],
    }}
    flow = Flow.from_client_config(client, scopes=config.SCOPES, state=state)
    flow.redirect_uri = config.REDIRECT_URI
    return flow


def granted_scopes(flow: Flow) -> set[str]:
    scope = flow.oauth2session.token.get("scope", "")
    return set(scope.split() if isinstance(scope, str) else scope)


def credentials(creds_json: str) -> Credentials:
    return Credentials.from_authorized_user_info(json.loads(creds_json), config.SCOPES)


def service(creds: Credentials):
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def revoke(creds: Credentials) -> None:
    token = creds.refresh_token or creds.token
    if not token:
        return
    data = urllib.parse.urlencode({"token": token}).encode()
    req = urllib.request.Request("https://oauth2.googleapis.com/revoke", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except OSError:
        pass


def html_to_text(markup: str) -> str:
    t = re.sub(r"(?is)<(script|style|head)\b.*?</\1\s*>", " ", markup)
    t = re.sub(r"""(?is)<a\b[^>]*?href\s*=\s*["']\s*(https?://[^"'\s]+)["'][^>]*>(.*?)</a\s*>""",
               lambda m: f" {m.group(2)} {m.group(1)} ", t)
    t = re.sub(r"(?i)<br\s*/?>|</(?:p|div|tr|li|h[1-6])\s*>", "\n", t)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    t = re.sub(r"[ \t\u00a0]+", " ", t)
    return re.sub(r"\n\s*\n+", "\n\n", t).strip()


def _part_text(part) -> str:
    try:
        return part.get_content()
    except (LookupError, ValueError, KeyError, AssertionError):
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", "ignore") if isinstance(payload, bytes) else str(payload or "")


def _body(msg) -> str:
    plain, rich = [], []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.is_multipart() or part.is_attachment():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain.append(_part_text(part))
        elif ctype == "text/html":
            rich.append(html_to_text(_part_text(part)))
    return "\n".join(plain) if any(p.strip() for p in plain) else "\n".join(rich)


def _clean_header(value) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def compact(raw: bytes) -> tuple[str, dict]:
    """Turn a full RFC 822 message into the short header + text form the analyser expects."""
    msg = message_from_bytes(raw, policy=policy.default)
    lines = [f"{h}: {_clean_header(msg.get(h))}" for h in _HEADERS if msg.get(h)]
    # Only the topmost result is written by Gmail itself; lower ones can be forged by the sender.
    auth = msg.get_all("Authentication-Results") or []
    if auth:
        lines.append(f"Authentication-Results: {_clean_header(auth[0])}")
    if not any(ln.startswith("From:") for ln in lines):
        lines.insert(0, "From: unknown")
    text = "\n".join(lines) + "\n\n" + _body(msg)[:MAX_BODY]
    meta = {
        "sender": _clean_header(msg.get("From")),
        "subject": _clean_header(msg.get("Subject")) or "(no subject)",
        "is_report": msg.get(REPORT_HEADER) is not None,
    }
    return text, meta


def fetch_raw(svc, msg_id: str) -> tuple[bytes, float | None]:
    m = svc.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    received = int(m["internalDate"]) / 1000 if m.get("internalDate") else None
    return base64.urlsafe_b64decode(m["raw"].encode()), received


def list_inbox(svc, limit: int) -> list[str]:
    resp = svc.users().messages().list(userId="me", q="in:inbox", maxResults=limit).execute()
    return [m["id"] for m in resp.get("messages", [])]


def send_to_self(svc, to: str, subject: str, text: str, html_body: str) -> None:
    msg = EmailMessage()
    msg["To"] = to
    msg["From"] = to
    msg["Subject"] = subject
    msg[REPORT_HEADER] = "1"
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    svc.users().messages().send(userId="me", body={"raw": raw}).execute()
