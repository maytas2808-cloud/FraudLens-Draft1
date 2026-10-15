"""Header checks for pasted raw emails (From / Reply-To / Return-Path / authentication results)."""
import re
from email import message_from_string, policy
from email.utils import parseaddr

from . import intel
from .text_rules import Hit
from .url_rules import BRANDS, _EXTRACT

# Registries that only verified organisations can register under.
RESTRICTED_SUFFIXES = ("bank.in", "gov.in", "nic.in")
OFFICIAL_DOMAINS = {d for domains in BRANDS.values() for d in domains}
TRUSTED_RANK = 50000

FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "rediffmail.com",
             "aol.com", "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com", "zoho.com"}
_HEADER_START = re.compile(r"^(?:from|to|subject|date|received|return-path|reply-to|message-id|delivered-to|mime-version)\s*:", re.I | re.M)


def looks_like_raw_email(text: str) -> bool:
    head = text.lstrip()[:2000]
    return len(_HEADER_START.findall(head)) >= 2 and bool(re.search(r"^from\s*:", head, re.I | re.M))


def _domain(addr: str) -> str:
    addr = addr.strip().lower()
    if "@" not in addr:
        return ""
    host = addr.rsplit("@", 1)[1].strip(">").strip()
    ext = _EXTRACT(host)
    reg = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    return reg or host


def _restricted(domain: str) -> bool:
    return any(domain.endswith("." + s) for s in RESTRICTED_SUFFIXES)


def _verified(first_auth: str, from_dom: str) -> bool:
    """True when the receiving server's own result says DMARC (or an aligned DKIM signature) passed for the From domain.

    Only the topmost Authentication-Results header is trusted: anything below it could have been written by the sender.
    """
    if not from_dom:
        return False
    m = re.search(r"\bdmarc\s*=\s*(\w+)[^;]*?header\.from\s*=\s*([\w.-]+)", first_auth, re.I)
    if m:
        return m.group(1).lower() == "pass" and _domain("x@" + m.group(2)) == from_dom
    for m in re.finditer(r"\bdkim\s*=\s*pass\b[^;]*?header\.[id]\s*=\s*@?([\w.-]+)", first_auth, re.I):
        if _domain("x@" + m.group(1)) == from_dom:
            return True
    return False


def _body_text(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html") and not part.is_attachment():
                try:
                    parts.append(part.get_content())
                except (LookupError, ValueError):
                    parts.append(part.get_payload(decode=True).decode("utf-8", "ignore") if part.get_payload(decode=True) else "")
        return "\n".join(parts)
    try:
        return msg.get_content()
    except (LookupError, ValueError, KeyError):
        return msg.get_payload() or ""


def analyze_email(raw: str) -> tuple[dict, list[Hit], str]:
    """Return (header summary, header hits, body text) for a raw RFC 822 email."""
    msg = message_from_string(raw, policy=policy.default)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))
    subject = str(msg.get("Subject", ""))
    auth_headers = [str(v) for v in msg.get_all("Authentication-Results", []) or []]
    auth = " ".join(auth_headers)
    from_dom = _domain(from_addr)
    verified = _verified(auth_headers[0] if auth_headers else "", from_dom)
    rank = intel.rank(from_dom) if verified else None
    trusted = verified and (_restricted(from_dom) or from_dom in OFFICIAL_DOMAINS or (rank is not None and rank <= TRUSTED_RANK))
    hits: list[Hit] = []

    def add(id_, label, weight, explanation, evidence, category="email"):
        hits.append(Hit(id_, label, weight, explanation, [evidence], category))

    if trusted:
        add("sender_verified_trusted", f"Verified sender: {from_dom}", -25,
            f"The mail server confirmed (DMARC/DKIM) that this email really came from {from_dom}, an established domain. "
            "Phishing from such a domain needs the account itself to be hacked.", f"{from_name} <{from_addr}>", "reassurance")
    elif verified:
        add("sender_verified", f"Sender domain verified ({from_dom})", -5,
            f"The mail server confirmed this email really came from {from_dom}, so it is not spoofed. "
            "Anyone can verify a domain they own, so this is only a weak sign.", f"{from_name} <{from_addr}>", "reassurance")

    name_l = (from_name + " " + subject).lower()
    claimed = [b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", name_l)]
    for brand in claimed:
        if from_dom and from_dom not in BRANDS[brand] and not (verified and _restricted(from_dom)):
            add("sender_brand_mismatch", f"Sender claims to be '{brand}' but writes from {from_dom}", 30,
                f"The display name or subject mentions '{brand}', whose real domain is {BRANDS[brand][0]}.", f"{from_name} <{from_addr}>")
            break
    if from_dom in FREE_MAIL and (claimed or re.search(r"\b(?:bank|support|security|team|department|official|helpdesk|service)\b", name_l)):
        add("free_mail_official", "Organisation writing from a free email account", 20,
            "Banks, companies and government offices don't send official mail from Gmail/Yahoo addresses.", from_addr)
    if reply_addr and _domain(reply_addr) and from_dom and _domain(reply_addr) != from_dom:
        add("reply_to_mismatch", "Replies go to a different domain", 15,
            f"Replies would go to {reply_addr} instead of the sender's domain {from_dom}.", f"Reply-To: {reply_addr}")
    if not verified and return_addr and _domain(return_addr) and from_dom and _domain(return_addr) != from_dom:
        add("return_path_mismatch", "Return-Path differs from sender", 5,
            "The technical sender differs from the visible one. Common with mailing services, but also with spoofing.", f"Return-Path: {return_addr}")
    for check in ("spf", "dkim", "dmarc"):
        m = re.search(check + r"\s*=\s*(\w+)", auth, re.I)
        if m and m.group(1).lower() in ("fail", "softfail", "none", "permerror"):
            add(f"{check}_fail", f"{check.upper()} check: {m.group(1).lower()}", 15 if check != "dkim" else 10,
                f"The receiving server's {check.upper()} check did not pass, so the sender address may be forged.", m.group(0))
    summary = {"from": f"{from_name} <{from_addr}>".strip(), "reply_to": reply_addr or None, "subject": subject,
               "from_domain": from_dom or None, "verified": verified, "trusted_sender": trusted}
    return summary, hits, f"{subject}\n{_body_text(msg)}"
