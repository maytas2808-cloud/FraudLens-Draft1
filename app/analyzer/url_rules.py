"""Rule-based URL and domain analysis."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract

from . import intel
from .text_rules import Hit

# bank.in is the RBI-run registry for Indian banks; the bundled public-suffix snapshot predates it.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=("bank.in",))

# Brand -> official registered domains. Used to spot brand names on unofficial domains.
BRANDS: dict[str, tuple[str, ...]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "onlinesbi.com", "sbi"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcbank.bank.in"),
    "icici": ("icicibank.com", "icicidirect.com", "icicilombard.com", "icicibank.bank.in"),
    "axis": ("axisbank.com", "axis.bank.in", "axisbank.bank.in", "axisdirect.in"),
    "kotak": ("kotak.com", "kotak.in", "kotak.bank.in", "kotakalert.bank.in", "kotaksecurities.com"),
    "pnb": ("pnbindia.in", "pnb.bank.in", "netpnb.com"),
    "paytm": ("paytm.com", "paytm.in", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "paypal": ("paypal.com", "paypal.me"),
    "amazon": ("amazon.in", "amazon.com", "amazon.co.uk", "amazonaws.com", "amazonpay.in", "amazon.de"),
    "flipkart": ("flipkart.com",),
    "netflix": ("netflix.com",),
    "apple": ("apple.com", "icloud.com", "apple.co"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com", "sharepoint.com"),
    "office365": ("office.com", "microsoft.com", "office365.com"),
    "outlook": ("outlook.com", "live.com", "microsoft.com", "office.com"),
    "google": ("google.com", "google.co.in", "gmail.com", "youtube.com", "goo.gl", "googleusercontent.com", "g.co"),
    "gmail": ("gmail.com", "google.com"),
    "facebook": ("facebook.com", "fb.com", "fb.me", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "irctc": ("irctc.co.in", "irctc.com"),
    "indiapost": ("indiapost.gov.in",),
    "incometax": ("incometax.gov.in", "incometaxindia.gov.in"),
    "epfo": ("epfindia.gov.in", "epfo.gov.in"),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "rbi": ("rbi.org.in",),
    "parivahan": ("parivahan.gov.in",),
    "echallan": ("parivahan.gov.in",),
    "npci": ("npci.org.in",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com", "dhl.co.in"),
    "bluedart": ("bluedart.com",),
    "delhivery": ("delhivery.com",),
    "jio": ("jio.com", "jiomart.com"),
    "airtel": ("airtel.in", "airtel.com"),
    "naukri": ("naukri.com",),
    "lic": ("licindia.in",),
    "bankofbaroda": ("bankofbaroda.in", "bankofbaroda.com"),
    "canarabank": ("canarabank.com", "canarabank.in"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
}
# Brand names short enough to cause false matches inside unrelated words get exact-token matching only.
_SHORT_BRANDS = {"sbi", "pnb", "lic", "rbi", "dhl", "jio", "axis", "apple", "steam", "adobe"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "rebrand.ly", "t.ly", "s.id", "v.gd", "bl.ink", "short.io", "shorturl.asia", "u.to", "clck.ru", "qr.io", "lnkd.in",
    "surl.li", "linktr.ee", "tny.im", "bitly.com", "urlz.fr", "shrtco.de", "rebrand.ly", "da.gd",
}
FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app", "pages.dev", "netlify.app",
    "vercel.app", "github.io", "glitch.me", "ngrok.io", "ngrok-free.app", "ngrok.app", "blogspot.com", "herokuapp.com",
    "repl.co", "replit.app", "workers.dev", "square.site", "godaddysites.com", "webflow.io", "yolasite.com",
    "sites.google.com", "forms.gle", "carrd.co", "framer.app", "glide.page", "trycloudflare.com", "azurewebsites.net",
    "r2.dev", "surge.sh", "duckdns.org", "myshopify.com", "jimdosite.com", "mystrikingly.com", "wordpress.com",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "rest", "cyou", "sbs", "bond", "click", "link", "work",
    "support", "live", "online", "site", "website", "space", "fun", "shop", "store", "vip", "club", "monster", "cam",
    "quest", "zip", "mov", "lol", "country", "kim", "pw", "su", "cc", "ws", "info", "biz", "loan", "win", "bid", "men",
}
SENSITIVE_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "security", "update", "kyc", "account",
    "banking", "wallet", "confirm", "unlock", "suspend", "reward", "refund", "claim", "bonus", "password", "auth",
    "validate", "recover", "billing", "invoice", "payment", "otp", "aadhaar", "pan-card", "challan", "netbanking",
)
# Characters that look alike are mapped to one shape; i, l, 1 and ! all collapse to "l".
HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "i": "l", "!": "l", "|": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
    "$": "s", "6": "g", "9": "g", "q": "g",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "l", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ո": "n", "ս": "u", "ɡ": "g", "ı": "l", "ӏ": "l",
})
# Letter pairs that read as one letter at a glance (arnazon -> amazon, vvhatsapp -> whatsapp, cliff -> diff).
LOOKALIKE_PAIRS = (("rn", "m"), ("nn", "m"), ("vv", "w"), ("cl", "d"))
_TRICK_NAMES = {"rn": "'rn' looks like 'm'", "nn": "'nn' looks like 'm'", "vv": "'vv' looks like 'w'",
                "cl": "'cl' looks like 'd'"}


@dataclass
class ParsedURL:
    raw: str
    full: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    registered_domain: str
    domain_label: str
    subdomain: str
    suffix: str
    is_ip: bool
    unicode_host: str


def parse(url: str) -> ParsedURL | None:
    raw = url.strip()
    full = raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else "http://" + raw
    try:
        parts = urlsplit(full)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    ext = _EXTRACT(host)
    registered = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    try:
        unicode_host = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        unicode_host = host
    scheme = parts.scheme.lower() if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else ""
    return ParsedURL(raw, full, scheme, host, port, parts.path or "", parts.query or "", registered or host,
                     ext.domain, ext.subdomain, ext.suffix, is_ip, unicode_host)


def _levenshtein(a: str, b: str) -> int:
    """Edit distance where swapping two neighbouring letters counts as one edit (amzaon -> amazon)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    rows = [list(range(len(b) + 1))]
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            d = min(rows[-1][j] + 1, cur[j - 1] + 1, rows[-1][j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                d = min(d, rows[-2][j - 2] + 1)
            cur.append(d)
        rows.append(cur)
    return rows[-1][-1]


def _skeleton(label: str) -> str:
    s = label.lower().replace("-", "").replace("_", "").translate(HOMOGLYPHS)
    for pair, single in LOOKALIKE_PAIRS:
        s = s.replace(pair, single)
    return s


def _tricks(cand: str, target: str) -> list[str]:
    """Plain-language list of the disguises that turn `target` into `cand`."""
    found = [_TRICK_NAMES[pair] for pair, single in LOOKALIKE_PAIRS if pair in cand and single in target and pair not in target]
    digits = sorted({c for c in cand if c.isdigit()} - set(target))
    if digits:
        found.append("digit" + ("s " if len(digits) > 1 else " ") + ", ".join(f"'{d}'" for d in digits) + " in place of letters")
    if any(ord(c) > 127 for c in cand):
        found.append("foreign letters that look Latin")
    if len(cand) == len(target) and any({a, b} == {"i", "l"} for a, b in zip(cand, target)):
        found.append("'i' and 'l' swapped")
    return found


def _official(brand: str, registered: str) -> bool:
    return registered in BRANDS[brand]


def _brand_tokens(text: str) -> set[str]:
    return set(t for t in re.split(r"[^a-z0-9]+", text.lower()) if t)


def find_brand_misuse(p: ParsedURL) -> tuple[str, str] | None:
    """Return (brand, where) if a brand name appears on a domain that brand doesn't own."""
    if p.is_ip:
        return None
    reg = p.registered_domain
    r = intel.rank(reg)
    if r is not None and r <= 20000 and not any(p.host.endswith(fh) for fh in FREE_HOSTING):
        return None
    label_tokens = _brand_tokens(p.domain_label)
    host_tokens = _brand_tokens(p.subdomain)
    path_tokens = _brand_tokens(unquote(p.path))
    compact_label = p.domain_label.replace("-", "")
    for brand in BRANDS:
        if _official(brand, reg):
            continue
        in_label = brand in label_tokens or (brand not in _SHORT_BRANDS and brand in compact_label)
        if in_label:
            return brand, "domain name"
        if brand in host_tokens or (brand not in _SHORT_BRANDS and any(brand in t for t in host_tokens)):
            return brand, "subdomain"
        if brand in path_tokens and brand not in _SHORT_BRANDS:
            return brand, "path"
    return None


_BRAND_NAMES = [(brand, official, [(ol, _skeleton(ol)) for ol in sorted({o.split(".")[0] for o in official} | {brand})
                                    if len(ol) >= 5])
                for brand, official in BRANDS.items()]
# Official names that are also everyday words; they only count when they are the whole domain name.
_GENERIC_NAMES = {"office", "outlook", "apple", "steam", "adobe", "naukri"}


def _transposed(a: str, b: str) -> bool:
    return len(a) == len(b) and sorted(a) == sorted(b) and _levenshtein(a, b) == 1


def find_typosquat(p: ParsedURL) -> tuple[str, str, list[str], bool] | None:
    """Return (imitated name, official domain, disguises used, visually disguised?) for domains that read like a brand.

    Look-alike characters are collapsed first (rn -> m, 0 -> o, Cyrillic а -> a), then one more ordinary typo is
    allowed for names of 6+ letters and two for 9+, so stacked tricks like 'arnozon' (rn for m, o for a) are caught.
    """
    if p.is_ip or not p.domain_label:
        return None
    label = p.domain_label.lower()
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    rank = intel.rank(p.registered_domain)
    if rank is not None and rank <= 20000:
        return None
    candidates = [label] + [t for t in re.split(r"[-_.]", label) if len(t) >= 4 and t != label]
    for brand, official, names in _BRAND_NAMES:
        if _official(brand, p.registered_domain):
            continue
        for ol, so in names:
            for cand in candidates:
                if cand != label and ol in _GENERIC_NAMES:
                    continue
                if cand == ol:
                    if cand == label and p.registered_domain not in official:
                        return ol, official[0], [f"the real name on a different domain ending (.{p.suffix})"], False
                    continue
                sc = _skeleton(cand)
                tricks = _tricks(cand, ol)
                if sc == so:
                    return ol, official[0], tricks or ["look-alike letters"], True
                if len(ol) < 6:
                    if _transposed(cand, ol):
                        return ol, official[0], tricks + ["two neighbouring letters swapped"], bool(tricks)
                    continue
                d = _levenshtein(cand, ol)
                # After undoing a disguise, only a same-length change counts (arnozon -> amozon -> amazon).
                if tricks and len(sc) == len(so) and _levenshtein(sc, so) == 1:
                    d = 1
                if d == 1 or (d == 2 and len(ol) >= 9):
                    typo = "one letter added, dropped, changed or swapped" if d == 1 else "two letters changed"
                    return ol, official[0], tricks + [typo], bool(tricks)
                if tricks and so in sc and ol not in cand:
                    return ol, official[0], tricks + ["extra words around the name"], True
    return None


def analyze_url(url: str) -> tuple[ParsedURL | None, list[Hit], dict | None]:
    p = parse(url)
    hits: list[Hit] = []
    if p is None:
        return None, [Hit("url_unparseable", "URL could not be parsed", 10,
                          "Malformed links are sometimes used to confuse filters.", [url], "url")], None

    def add(id_, label, weight, explanation, evidence):
        hits.append(Hit(id_, label, weight, explanation, [evidence], "url"))

    on_free_host = next((fh for fh in FREE_HOSTING if p.host == fh or p.host.endswith("." + fh)), None)
    reg_rank = None if p.is_ip else intel.rank(p.registered_domain)
    shared_platform = reg_rank is not None and reg_rank <= 10000 and not on_free_host
    intel_hit = intel.lookup(p.full if p.scheme else url, p.host, allow_host_match=not shared_platform)
    if intel_hit:
        add("intel_match", f"Listed in threat intelligence ({intel_hit['source']})", 60,
            f"This {intel_hit['match']} appears in a public feed of known {intel_hit['type']} links.", p.host)

    if p.is_ip:
        add("ip_host", "Link uses a raw IP address", 20,
            "Legitimate services use domain names; raw IP links hide who runs the site.", p.host)
    if "@" in p.raw.split("?")[0].split("://", 1)[-1].split("/")[0]:
        add("at_symbol", "'@' trick in the link", 20,
            "Everything before '@' is ignored by the browser, so the real destination is hidden.", p.raw[:80])
    if "xn--" in p.host:
        add("punycode", "Internationalised (look-alike) domain", 20,
            f"The domain is written with special characters and displays as '{p.unicode_host}', which can imitate a real brand.", p.host)

    squat = find_typosquat(p)
    misuse = None if squat else find_brand_misuse(p)
    if misuse:
        brand, where = misuse
        add("brand_mismatch", f"'{brand}' used on a domain it doesn't own", 30,
            f"The {where} contains '{brand}', but the real site is {BRANDS[brand][0]}. The link actually goes to {p.registered_domain}.",
            p.host + (p.path[:40] if where == "path" else ""))
    if squat:
        target, official, tricks, disguised = squat
        if disguised:
            add("lookalike", "Disguised copy of a well-known domain", 60,
                f"'{p.registered_domain}' is made to read like '{official}' at a glance: {'; '.join(tricks)}. "
                "Letters chosen to fool the eye are a deliberate trick; genuine companies never do this.", p.registered_domain)
        else:
            add("lookalike", "Look-alike of a well-known domain", 40,
                f"'{p.registered_domain}' imitates '{official}': {'; '.join(tricks)}.", p.registered_domain)

    if p.registered_domain in SHORTENERS:
        add("shortener", "Shortened link hides the destination", 10,
            "Link shorteners hide where you will really land.", p.host)
    if on_free_host and p.host != on_free_host:
        add("free_hosting", "Hosted on a free website builder", 10,
            f"Anyone can create a site on {on_free_host} in minutes; banks and government don't host there.", p.host)
    if p.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"Uncommon domain ending '.{p.suffix}'", 10,
            "Cheap domain endings like this are heavily used for throwaway scam sites.", p.registered_domain)
    if p.scheme == "http":
        add("no_https", "Not using HTTPS", 8,
            "The link isn't encrypted. HTTPS alone doesn't make a site safe, but its absence is a warning sign.", p.raw[:60])
    if p.subdomain.count(".") >= 2:
        add("deep_subdomain", "Unusually many subdomains", 8,
            "Long chains like 'secure.bank.com.example.xyz' make a fake site look official.", p.host)
    if p.port and p.port not in (80, 443):
        add("odd_port", "Non-standard port", 10, "Ordinary websites don't use unusual ports.", f"{p.host}:{p.port}")
    words = [w for w in SENSITIVE_WORDS if w in (p.host + p.path + "?" + p.query).lower()]
    if words:
        add("sensitive_words", "Login / verification words in the link", 8,
            "Words like " + ", ".join(f"'{w}'" for w in words[:4]) + " are typical of credential-harvesting pages.", p.raw[:80])
    for k, v in parse_qsl(p.query):
        if re.match(r"^(?:https?:)?//", unquote(v), re.I) or k.lower() in ("redirect", "redirect_uri", "url", "next", "goto", "dest", "continue", "target"):
            if re.search(r"https?:|//|\.", unquote(v)):
                add("redirect_param", "Link redirects to another site", 10,
                    "The link carries another address inside it, a common way to bounce through a trusted domain.", f"{k}={v[:50]}")
                break
    if len(p.raw) > 100:
        add("long_url", "Very long link", 5, "Very long links are often used to hide the real domain.", f"{len(p.raw)} characters")
    if p.raw.count("%") >= 5:
        add("encoded", "Heavily encoded characters", 5, "Lots of %-encoding can hide the real text of a link.", p.raw[:60])

    rank = reg_rank
    risky = any(h.id in ("intel_match", "brand_mismatch", "lookalike", "punycode", "at_symbol") for h in hits)
    if rank and not risky and not on_free_host and p.registered_domain not in SHORTENERS:
        weight = -25 if rank <= 10000 else -12
        add("reputation", f"Well-established domain (top {rank:,} worldwide)", weight,
            f"{p.registered_domain} is one of the most visited domains (Tranco rank {rank:,}). Phishing rarely uses such domains, unless the account itself was hacked.",
            p.registered_domain)
    elif not rank and not p.is_ip:
        add("unknown_domain", "Domain not in the top-100k sites list", 4,
            "This isn't proof of anything, but most big brands' real sites are in this list.", p.registered_domain)
    return p, hits, intel_hit
