"""Robustness stress test: disguise every labelled scam the way attackers do and measure what is still caught.

Each transform is applied to every malicious item in data/eval/scenarios.jsonl and holdout.jsonl. Threat feeds
are switched off so a catch can only come from the rules and models. Reworded legitimate items are also checked,
so the false-positive cost of the same tricks is reported.

Usage: .venv\\Scripts\\python.exe scripts\\stress_test.py
Writes app/model/robustness.json.
"""
import json
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.analyzer import engine  # noqa: E402
from scripts.evaluate import FLAG_AT, without_intel  # noqa: E402

EVAL = ROOT / "data" / "eval"
OUT = ROOT / "app" / "model" / "robustness.json"
SEED = 42

URL_RE = re.compile(r"(?:https?://)?(?:[\w-]+\.)+(?:com|in|net|org|xyz|top|online|site|info|co|io|me|app|live|shop|club|"
                    r"buzz|link|cc|ru|tk|ml|gq|cf|ga|vip|icu|support|help|biz|cn)\b(?:/[^\s]*)?", re.I)
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
DIGITS = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"}
KEY_TERMS = ("kyc", "otp", "pin", "blocked", "suspended", "verify", "account", "aadhaar", "pan", "refund", "arrest", "upi", "password")
SYNONYMS = [
    (r"\bblocked\b", "deactivated"), (r"\bsuspended\b", "put on hold"), (r"\bimmediately\b", "right away"),
    (r"\burgent(?:ly)?\b", "time-sensitive"), (r"\bclick\b", "tap"), (r"\bupdate\b", "refresh"), (r"\bverify\b", "confirm"),
    (r"\baccount\b", "a/c"), (r"\bcustomer\b", "valued user"), (r"\btoday\b", "before midnight"), (r"\bdear\b", "hello"),
    (r"\bwithin (\d+) hours?\b", r"in the next \1 hrs"), (r"\bwon\b", "been selected for"), (r"\bpay\b", "deposit"),
]


def _split(text: str):
    """Yield (is_url, chunk) pieces so text-only tricks leave links intact and vice versa."""
    pos = 0
    for m in URL_RE.finditer(text):
        if m.start() > pos:
            yield False, text[pos:m.start()]
        yield True, m.group(0)
        pos = m.end()
    if pos < len(text):
        yield False, text[pos:]


def _on_words(text: str, fn, rng, share: float) -> str:
    out = []
    for is_url, chunk in _split(text):
        if is_url:
            out.append(chunk)
            continue
        out.append(re.sub(r"[A-Za-z]{4,}", lambda m: fn(m.group(0), rng) if rng.random() < share else m.group(0), chunk))
    return "".join(out)


def _swap(word: str, table: dict, rng) -> str:
    idx = [i for i, c in enumerate(word) if c.lower() in table]
    if not idx:
        return word
    i = rng.choice(idx)
    return word[:i] + table[word[i].lower()] + word[i + 1:]


def digit_swap(text, rng):
    return _on_words(text, lambda w, r: _swap(w, DIGITS, r), rng, 0.35)


def cyrillic_letters(text, rng):
    return _on_words(text, lambda w, r: _swap(w, CYRILLIC, r), rng, 0.35)


def zero_width(text, rng):
    return _on_words(text, lambda w, r: w[: len(w) // 2] + "\u200b" + w[len(w) // 2:], rng, 0.5)


def spaced_keywords(text, rng):
    def spread(m):
        word = m.group(0)
        return (" " if len(word) <= 4 else ".").join(word) if rng.random() < 0.5 else ".".join(word)
    pattern = re.compile(r"\b(?:" + "|".join(KEY_TERMS) + r")\b", re.I)
    return "".join(chunk if is_url else pattern.sub(spread, chunk) for is_url, chunk in _split(text))


def reworded(text, rng):
    out = []
    for is_url, chunk in _split(text):
        if not is_url:
            for pat, rep in SYNONYMS:
                chunk = re.sub(pat, rep, chunk, flags=re.I)
        out.append(chunk)
    return "".join(out)


def defanged_links(text, rng):
    def defang(u):
        u = re.sub(r"^http", "hxxp", u, flags=re.I)
        return u.replace(".", "[.]")
    return "".join(defang(chunk) if is_url else chunk for is_url, chunk in _split(text))


def shortened_links(text, rng):
    def short(_):
        return "https://bit.ly/" + "".join(rng.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(7))
    return "".join(short(chunk) if is_url else chunk for is_url, chunk in _split(text))


def moved_to_free_host(text, rng):
    def move(u):
        m = re.match(r"(?:https?://)?([^/\s]+)(.*)", u)
        host, rest = m.group(1), m.group(2)
        label = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")[:40]
        return f"https://{label}.{rng.choice(['web.app', 'pages.dev', 'netlify.app', 'vercel.app'])}{rest}"
    return "".join(move(chunk) if is_url else chunk for is_url, chunk in _split(text))


def combined(text, rng):
    return zero_width(cyrillic_letters(reworded(text, rng), rng), rng)


TRANSFORMS = [
    ("digit_swap", "Digits for letters (bl0cked, acc0unt)", digit_swap),
    ("cyrillic_letters", "Look-alike Cyrillic letters (аccount with a Russian 'а')", cyrillic_letters),
    ("zero_width", "Invisible zero-width characters inside words", zero_width),
    ("spaced_keywords", "Spaced or dotted keywords (K Y C, O.T.P)", spaced_keywords),
    ("reworded", "Reworded with synonyms (blocked → deactivated, click → tap)", reworded),
    ("defanged_links", "Disguised links (hxxp://, [.] dots)", defanged_links),
    ("shortened_links", "Links hidden behind a URL shortener", shortened_links),
    ("moved_to_free_host", "Scam page moved to free hosting (web.app, pages.dev …)", moved_to_free_host),
    ("combined", "Reworded + Cyrillic letters + invisible characters together", combined),
]
LEGIT_TRANSFORMS = ("reworded", "zero_width")


def _flag(text: str) -> tuple[bool, int]:
    r = engine.analyze(text)
    return r["score"] >= FLAG_AT, r["score"]


def run() -> dict:
    items = [json.loads(ln) for f in ("scenarios.jsonl", "holdout.jsonl")
             for ln in (EVAL / f).read_text(encoding="utf-8").splitlines() if ln.strip()]
    bad = [it for it in items if it["label"] == 1]
    good = [it for it in items if it["label"] == 0]
    engine.analyze("warm up http://example.com")
    baseline = {it["id"]: _flag(it["text"])[0] for it in bad}
    legit_baseline_fps = sum(_flag(it["text"])[0] for it in good)
    rows = []
    for key, name, fn in TRANSFORMS:
        rng = random.Random(f"{SEED}-{key}")
        changed, caught, misses = 0, 0, []
        for it in bad:
            mutated = fn(it["text"], rng)
            if mutated == it["text"]:
                continue
            changed += 1
            hit, score = _flag(mutated)
            caught += hit
            if not hit and len(misses) < 5:
                misses.append({"id": it["id"], "category": it["category"], "score": score, "text": mutated[:160]})
        base = sum(baseline[it["id"]] for it in bad if fn(it["text"], random.Random(f"{SEED}-{key}")) != it["text"])
        row = {"id": key, "name": name, "n": changed, "caught": caught,
               "detection_rate": round(caught / changed, 4) if changed else None,
               "baseline_rate": round(base / changed, 4) if changed else None, "misses": misses}
        if key in LEGIT_TRANSFORMS:
            lrng = random.Random(f"{SEED}-{key}-legit")
            mutated_good = [fn(it["text"], lrng) for it in good]
            fps = sum(_flag(t)[0] for t in mutated_good)
            row["legit_n"], row["legit_false_positives"] = len(good), fps
        rows.append(row)
    total_n = sum(r["n"] for r in rows)
    total_caught = sum(r["caught"] for r in rows)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "description": (f"Every malicious item in the scenario and holdout sets ({len(bad)} scams) was disguised with each "
                        f"transform below. Threat feeds were switched off, so catches come only from rules and models. "
                        f"Flagged = score >= {FLAG_AT}. Reworded legitimate items ({len(good)}) check the false-positive cost."),
        "malicious_items": len(bad),
        "legit_items": len(good),
        "legit_baseline_false_positives": legit_baseline_fps,
        "baseline_detection_rate": round(sum(baseline.values()) / len(bad), 4),
        "overall": {"n": total_n, "caught": total_caught, "detection_rate": round(total_caught / total_n, 4) if total_n else None},
        "transforms": rows,
    }


def main():
    report = without_intel(run)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"baseline {report['baseline_detection_rate']:.1%}  disguised overall {report['overall']['detection_rate']:.1%}  "
          f"legit FP undisguised {report['legit_baseline_false_positives']}/{report['legit_items']}")
    for r in report["transforms"]:
        extra = f"  legit FP {r['legit_false_positives']}/{r['legit_n']}" if "legit_n" in r else ""
        print(f"{r['id']:20} {r['caught']:3}/{r['n']:<3} {r['detection_rate']:.1%} (undisguised {r['baseline_rate']:.1%}){extra}")


if __name__ == "__main__":
    main()
