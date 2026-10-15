"""Build the plain-text and HTML report emails."""
from datetime import datetime
from html import escape

from . import config

COLORS = {"high": ("#b91c1c", "#fde8e8"), "medium": ("#92400e", "#fff4e0"), "low": ("#166534", "#e8f6ec")}
LABELS = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _when(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b, %H:%M") if ts else ""


def _counts(rows: list[dict]) -> dict:
    return {lvl: sum(r["level"] == lvl for r in rows) for lvl in ("high", "medium", "low")}


def subject_line(rows: list[dict], kind: str) -> str:
    c = _counts(rows)
    if kind == "alert":
        return f"FraudLens alert: {c['high']} high-risk email{'s' if c['high'] != 1 else ''} in your inbox"
    if not c["high"] and not c["medium"]:
        return f"FraudLens report: all clear ({len(rows)} emails checked)"
    return f"FraudLens report: {c['high']} high-risk, {c['medium']} suspicious of {len(rows)} emails"


def build(rows: list[dict], kind: str = "digest") -> tuple[str, str, str]:
    """Return (subject, plain text, html) for a digest or an instant alert."""
    c = _counts(rows)
    risky = [r for r in rows if r["level"] in ("high", "medium")]
    risky.sort(key=lambda r: -(r["score"] or 0))
    subject = subject_line(rows, kind)
    dashboard = f"{config.BASE_URL}/dashboard"

    intro = ("FraudLens found emails in your inbox that look like phishing or fraud."
             if kind == "alert" else
             f"FraudLens checked {len(rows)} emails: {c['high']} high risk, {c['medium']} suspicious, {c['low']} low risk.")
    text = [intro, ""]
    for r in risky:
        text.append(f"[{LABELS[r['level']]} {r['score']}] {r['subject']}")
        text.append(f"    From: {r['sender']}")
        if r["reasons"]:
            text.append("    Why: " + "; ".join(r["reasons"]))
        text.append("")
    if not risky:
        text.append("No suspicious emails found.")
    text += ["", "Don't click links, reply or pay in the flagged emails.",
             "Lost money to a scam? Call 1930 or report at cybercrime.gov.in.", f"Dashboard: {dashboard}"]

    items = []
    for r in risky:
        fg, bg = COLORS[r["level"]]
        reasons = "".join(f"<li>{escape(x)}</li>" for x in r["reasons"])
        items.append(
            f'<tr><td style="padding:12px;border-bottom:1px solid #e3e6ee;vertical-align:top">'
            f'<span style="display:inline-block;padding:2px 10px;border-radius:999px;background:{bg};color:{fg};'
            f'font-weight:700;font-size:12px">{LABELS[r["level"]]} · {r["score"]}</span>'
            f'<div style="font-weight:600;margin:6px 0 2px">{escape(r["subject"])}</div>'
            f'<div style="color:#5b6475;font-size:13px">From: {escape(r["sender"])} · {_when(r["received_at"])}</div>'
            f'<ul style="margin:6px 0 0;padding-left:18px;color:#111827;font-size:13px">{reasons}</ul></td></tr>')
    if not items:
        items.append('<tr><td style="padding:12px;color:#166534">No suspicious emails found.</td></tr>')

    cards = "".join(
        f'<td style="padding:10px;background:{COLORS[lvl][1]};color:{COLORS[lvl][0]};border-radius:8px;text-align:center">'
        f'<div style="font-size:24px;font-weight:800">{c[lvl]}</div><div style="font-size:12px">{LABELS[lvl]}</div></td>'
        for lvl in ("high", "medium", "low"))
    html_body = (
        '<div style="font-family:Segoe UI,Roboto,Arial,sans-serif;max-width:640px;margin:auto;color:#111827">'
        '<div style="background:#1f3a8a;color:#fff;padding:16px 20px;border-radius:12px 12px 0 0;'
        'border-bottom:4px solid #f59e0b"><div style="font-size:20px;font-weight:700">FraudLens</div>'
        f'<div style="font-size:13px;opacity:.85">{escape(subject)}</div></div>'
        f'<div style="padding:16px 20px;border:1px solid #e3e6ee;border-top:0;border-radius:0 0 12px 12px">'
        f'<p style="margin:0 0 12px">{escape(intro)}</p>'
        + (f'<table style="width:100%;border-spacing:8px 0;margin-bottom:12px"><tr>{cards}</tr></table>' if kind != "alert" else "")
        + f'<table style="width:100%;border-collapse:collapse">{"".join(items)}</table>'
        '<p style="font-size:13px;color:#5b6475;margin-top:16px">Don\'t click links, reply or pay in the flagged emails. '
        'Lost money to a scam? Call <b>1930</b> or report at cybercrime.gov.in.</p>'
        f'<p style="font-size:13px"><a href="{escape(dashboard)}" style="color:#1f3a8a">Open your FraudLens dashboard</a></p>'
        '</div></div>')
    return subject, "\n".join(text), html_body
