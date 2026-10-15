"""Inspect a live web page for fake-login and brand-impersonation signs.

Only the HTML of the page is downloaded (no scripts run, no images or other resources are fetched),
only public internet addresses are contacted, the connection is pinned to the address that was checked,
and nothing is stored.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from . import intel
from .engine import _level
from .text_rules import Hit
from .url_rules import BRANDS, parse

TIMEOUT = 5
MAX_HOPS = 5
MAX_BYTES = 1_000_000
UA = "Mozilla/5.0 (compatible; FraudLens-site-inspector/1.0)"

# Services phishing kits use to receive stolen form data.
EXFIL_HOSTS = ("api.telegram.org", "formspree.io", "script.google.com", "discord.com", "discordapp.com",
               "ngrok.io", "ngrok-free.app", "webhook.site", "formsubmit.co", "getform.io", "000webhostapp.com")
SENSITIVE = (
    ("pin", "UPI / ATM PIN", 25, re.compile(r"\b(?:upi|atm|m)?[\s_-]?pin\b|mpin", re.I)),
    ("card", "card number or CVV", 20, re.compile(r"card|cvv|cvc|expiry|cc-(?:number|csc|exp)", re.I)),
    ("otp", "OTP", 20, re.compile(r"\botp\b|one[\s_-]?time", re.I)),
    ("id_doc", "Aadhaar or PAN", 15, re.compile(r"aadh?aar|\bpan(?:[\s_-]?(?:card|no|number))?\b", re.I)),
)
LOGIN_WORDS = re.compile(r"\b(?:log ?in|sign ?in|verify|verification|kyc|update|secure|account|unlock|reactivate)\b", re.I)


class BlockedAddress(Exception):
    pass


def _public_ip(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedAddress(f"{host} resolves to a non-public address")
    return infos[0][4][0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, **kw):
        super().__init__(host, port, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, **kw):
        super().__init__(host, port, **kw)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def _get(url: str):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("unsupported URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = _public_ip(parts.hostname, port)
    if parts.scheme == "https":
        conn = _PinnedHTTPS(parts.hostname, ip, port, timeout=TIMEOUT, context=ssl.create_default_context())
    else:
        conn = _PinnedHTTP(parts.hostname, ip, port, timeout=TIMEOUT)
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html", "Accept-Encoding": "identity"})
        resp = conn.getresponse()
        location = resp.getheader("Location")
        ctype = resp.getheader("Content-Type") or ""
        body = resp.read(MAX_BYTES) if "html" in ctype.lower() and resp.status < 300 else b""
        charset = re.search(r"charset=([\w-]+)", ctype)
        return resp.status, location, ctype, body.decode(charset.group(1) if charset else "utf-8", "ignore")
    finally:
        conn.close()


def fetch(url: str) -> dict:
    current = url if "://" in url else "https://" + url
    out = {"chain": [], "final_url": None, "html": "", "content_type": None, "error": None}
    for _ in range(MAX_HOPS + 1):
        try:
            status, location, ctype, html_text = _get(current)
        except ssl.SSLError as e:
            out["error"] = f"TLS certificate problem: {e.reason or e}"
            return out
        except BlockedAddress as e:
            out["error"] = str(e)
            return out
        except (LookupError, OSError, ValueError, http.client.HTTPException) as e:
            out["error"] = f"Could not reach the site ({type(e).__name__})"
            return out
        out["chain"].append({"url": current, "status": status})
        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        out.update(final_url=current, html=html_text, content_type=ctype)
        if status >= 400:
            out["error"] = f"The site answered with HTTP {status}"
        return out
    out["error"] = "Too many redirects"
    return out


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.site_name, self.h1, self.alts = "", "", [], []
        self.forms: list[dict] = []
        self.loose_inputs: list[dict] = []
        self.resources: list[str] = []
        self.anchors: list[str] = []
        self.refresh = None
        self.scripts: list[str] = []
        self.anti_inspect = False
        self._in = None
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if any(k == "oncontextmenu" and "false" in v.lower() for k, v in a.items()):
            self.anti_inspect = True
        if tag in ("title", "h1", "script"):
            self._in = tag
        elif tag == "meta":
            if a.get("property", "").lower() == "og:site_name" or a.get("name", "").lower() == "application-name":
                self.site_name = a.get("content", "")[:200]
            if a.get("http-equiv", "").lower() == "refresh":
                self.refresh = a.get("content", "")[:300]
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea"):
            field = {k: a.get(k, "") for k in ("type", "name", "id", "placeholder", "autocomplete", "aria-label")}
            (self._form["inputs"] if self._form is not None else self.loose_inputs).append(field)
        elif tag == "img":
            if a.get("alt"):
                self.alts.append(a["alt"][:120])
            if a.get("src"):
                self.resources.append(a["src"])
        elif tag in ("link", "script") and (a.get("href") or a.get("src")):
            self.resources.append(a.get("href") or a.get("src"))
        if tag == "a":
            self.anchors.append(a.get("href", ""))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        if tag == self._in:
            self._in = None

    def handle_data(self, data):
        if self._in == "title":
            self.title += data
        elif self._in == "h1":
            self.h1.append(data.strip()[:200])
        elif self._in == "script" and len(self.scripts) < 50:
            self.scripts.append(data[:20000])


def _sensitive(field: dict) -> list[tuple[str, str, int]]:
    blob = " ".join(field.values())
    found = [("password", "password", 10)] if field.get("type", "").lower() == "password" else []
    for id_, label, weight, rx in SENSITIVE:
        if rx.search(blob):
            found.append((id_, label, weight))
    return found


def _reg(url: str) -> str | None:
    p = parse(url)
    return p.registered_domain if p else None


def analyse_html(page_url: str, html_text: str, *, start_url: str | None = None) -> dict:
    """Score a fetched page. Pure function so it can be tested without the network."""
    page = parse(page_url)
    page_reg = page.registered_domain if page else None
    p = _PageParser()
    try:
        p.feed(html_text[:MAX_BYTES])
    except Exception:
        pass
    hits: list[Hit] = []

    def add(id_, label, weight, explanation, evidence="", category="site"):
        hits.append(Hit(id_, label, weight, explanation, [evidence] if evidence else [], category))

    identity = " ".join([p.title, p.site_name, *p.h1, *p.alts[:20]]).lower()
    claimed = [b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", identity)]
    official = [b for b in claimed if page_reg in BRANDS[b]]
    impersonated = [b for b in claimed if b not in official]

    fields = [f for form in p.forms for f in form["inputs"]] + p.loose_inputs
    asks: dict[str, tuple[str, int]] = {}
    for f in fields:
        for id_, label, weight in _sensitive(f):
            asks[id_] = (label, weight)

    if impersonated and not official:
        brand = impersonated[0]
        add("site_brand_impersonation", f"Page presents itself as '{brand}' but is on {page_reg}", 30,
            f"The page title, heading or logo says '{brand}', whose real website is {BRANDS[brand][0]}. "
            "A copy of a real brand's page on another domain is how fake login sites work.", (p.title or "").strip()[:120])
    elif official:
        add("site_official", f"Official {official[0]} website", -25,
            f"{page_reg} is a known official domain of {official[0]}.", page_reg or "", "reassurance")

    if asks:
        worst = max(w for _, w in asks.values())
        weight = min(30, worst + 5 * (len(asks) - 1))
        labels = ", ".join(label for label, _ in asks.values())
        add("site_sensitive_form", f"Page asks for: {labels}", weight,
            "Banks and government sites never need your OTP or PIN typed into a web page you reached from a message.", labels)

    sensitive_forms = [f for f in p.forms if any(_sensitive(i) for i in f["inputs"])]
    for form in sensitive_forms:
        action = urljoin(page_url, form["action"]) if form["action"] else page_url
        host = (urlsplit(action).hostname or "").lower()
        target = _reg(action)
        if any(host == h or host.endswith("." + h) for h in EXFIL_HOSTS):
            add("site_form_exfil", f"Form sends what you type to {host}", 30,
                "The login form posts straight to a messaging or form-collection service, a hallmark of phishing kits.", action[:120])
            break
        if target and page_reg and target != page_reg:
            add("site_form_offsite", f"Form sends what you type to another site ({target})", 20,
                f"The form is on {page_reg} but submits your details to {target}.", action[:120])
            break
    if asks and page and page.scheme == "http":
        add("site_no_https", "Asks for secrets over plain HTTP", 15,
            "Anything typed on this page travels unencrypted.", page_url[:120])

    if impersonated and not official:
        hot = sorted({_reg(urljoin(page_url, r)) for r in p.resources} & {d for b in impersonated for d in BRANDS[b]})
        if hot:
            add("site_hotlinks_brand", f"Copies images or styles from {hot[0]}", 10,
                "The page loads pictures or styles straight from the real brand's website, a shortcut used by cloned pages.", hot[0])

    redirect_js = re.search(r"(?:window|document|top)\.location(?:\.href)?\s*=\s*['\"](https?://[^'\"]+)", " ".join(p.scripts))
    refresh_url = re.search(r"url\s*=\s*['\"]?(https?://[^'\"\s>]+)", p.refresh or "", re.I)
    jump = (refresh_url or redirect_js)
    if jump and _reg(jump.group(1)) not in (None, page_reg):
        add("site_auto_redirect", f"Page sends you on to {_reg(jump.group(1))}", 8,
            "The page forwards visitors automatically, which can hide the real destination from checks.", jump.group(1)[:120])
    if p.anti_inspect or re.search(r"\bdebugger\b|devtools", " ".join(p.scripts), re.I):
        add("site_anti_inspect", "Page tries to block inspection", 5,
            "Disabling right-click or detecting developer tools is used to stop people checking the page.")
    dead = [h for h in p.anchors if not h.strip() or h.strip() == "#" or h.lower().startswith("javascript:")]
    if len(p.anchors) >= 5 and len(dead) / len(p.anchors) > 0.7:
        add("site_dead_links", "Most links on the page go nowhere", 8,
            f"{len(dead)} of {len(p.anchors)} links are empty. Cloned login pages keep the look but not the working menus.")
    if not official and LOGIN_WORDS.search(p.title or ""):
        add("site_login_title", "Login or verification page", 5,
            "The page title is about logging in or verifying an account.", p.title.strip()[:120])
    start_reg = _reg(start_url) if start_url else None
    same_owner = any(start_reg in d and page_reg in d for d in BRANDS.values()) or \
        any(page_reg and page_reg.endswith("." + s) for s in ("bank.in", "gov.in", "nic.in"))
    if start_reg and page_reg and start_reg != page_reg and not same_owner:
        add("site_redirected", f"Link landed on a different site ({page_reg})", 8,
            f"The link pointed at {start_reg} but the page you land on is {page_reg}.", page_url[:120])
    rank = intel.rank(page_reg) if page_reg else None
    if rank and rank <= 10000 and not impersonated and not official:
        add("site_reputation", f"Well-established site (top {rank:,} worldwide)", -15,
            f"{page_reg} is one of the most visited domains.", page_reg, "reassurance")

    intel_hit = intel.lookup(page_url, page.host if page else "", allow_host_match=not (rank and rank <= 10000)) if page else None
    raw = sum(h.weight for h in hits)
    score = max(0, min(100, raw))
    if intel_hit:
        score = max(score, 90)
    level = _level(score)
    return {
        "score": score,
        "level": level,
        "findings": [h.as_dict() for h in sorted(hits, key=lambda h: -h.weight)],
        "intel": intel_hit,
        "page": {"title": (p.title or "").strip()[:200], "domain": page_reg, "forms": len(p.forms),
                 "sensitive_fields": [label for label, _ in asks.values()], "brands_claimed": claimed},
        "summary": _summary(level, hits, intel_hit),
    }


def _summary(level: str, hits: list[Hit], intel_hit) -> str:
    if intel_hit:
        return "This page is on a public list of known phishing or malware sites. Do not enter anything."
    top = [h.label for h in sorted(hits, key=lambda h: -h.weight) if h.weight > 0][:2]
    if level == "low":
        return "No signs of a fake login page were found on this page."
    prefix = "Likely fake website" if level == "high" else "Possibly fake website"
    return f"{prefix}: " + "; ".join(top).lower() + "."


def inspect(url: str) -> dict:
    started = time.perf_counter()
    fetched = fetch(url)
    base = {"url": url, "final_url": fetched["final_url"], "redirects": fetched["chain"], "error": fetched["error"]}
    if not fetched["final_url"] or not fetched["html"]:
        reason = fetched["error"] or "The address did not return a web page."
        result = {"score": 0, "level": "unknown", "findings": [], "intel": None, "page": None,
                  "summary": f"The page could not be inspected. {reason}"}
    else:
        result = analyse_html(fetched["final_url"], fetched["html"], start_url=url)
    return {**base, **result, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)}
