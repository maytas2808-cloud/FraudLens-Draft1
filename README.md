# FraudLens — explainable phishing & digital-fraud detection

Runs locally: once started (see [Run locally](#run-locally)), open `http://localhost:8000`. The evaluation is at `/report` and the API docs at `/docs`.

Paste an SMS, a WhatsApp message, a raw email (headers included) or a link. FraudLens returns:

- a **risk score (0–100) and level** (low < 30 ≤ medium < 60 ≤ high);
- the **scam type**: fake KYC, digital arrest, fake job, investment, prize, delivery, government impersonation and more;
- **every indicator**, with the exact evidence and a plain-language explanation;
- **where the score came from** (wording, language model, links, email headers, combined signals);
- a per-link breakdown and **what to do next**, including India's 1930 helpline and cybercrime.gov.in.

Built for the CC6-AI05 brief "Intelligent Phishing and Digital Fraud Detection".

## Results

All numbers come from `scripts/evaluate.py` (full detail in [`REPORT.md`](REPORT.md) and on `/report`). An item counts as flagged when it scores medium or high. Threat-intel lookup is switched off for the public-data tests, so they measure the rules and models alone.

| Test | Precision | Recall | Notes |
|---|---|---|---|
| 2,000 public URLs never used in training or tuning | 97.6% | 82.6% | 20 of 1,000 legitimate URLs flagged |
| 300 live OpenPhish URLs (feed lookup off) | — | 83.0% | measures *new* attacks |
| 1,000 held-out public emails/SMS | 96.3% | 82.7% | 12 of 624 legitimate flagged |
| Held-out hand-written set (45 Indian-context items) | 83.3% | 90.9% | 4 of 23 false alarms, 2 of 22 missed |
| Development set (110 items, used while building) | 90.9% | 100% | optimistic — regression test only |
| URL model alone (60,000 unseen URLs) | 95.2% | 96.4% | ROC AUC 0.994; 88% recall at 1% false alarms |
| Text model alone (4,028 unseen texts) | 96.1% | 97.1% | ROC AUC 0.997 |

Mean analysis time is about 2 ms per item (p95 ≈ 3 ms) without the live check.

**What changed in the latest version.** The table below compares it with the previous release on the same test sets:

| Test | Before | Now |
|---|---|---|
| Unseen URLs, recall / precision | 76.8% / 97.8% | 82.6% / 97.6% |
| Live OpenPhish URLs caught | 76.0% | 83.0% |
| Emails/SMS, precision / recall | 92.2% / 81.9% | 96.3% / 82.7% |
| Held-out hand-written, precision / recall | 87.0% / 90.9% | 83.3% / 90.9% |

The one regression is a new false alarm on the hand-written held-out set: a genuine police "beware of digital-arrest calls" awareness message now scores 33. That set is never tuned on, so the error is reported rather than fixed.

## How it works

```
input ─► normalise (NFKC, zero-width strip, refang hxxp/[.] , undo "K.Y.C"/"bl0cked")
      ├─► raw email? ─► header checks: display-name brand vs sender domain, free-mail "official",
      │                 Reply-To / Return-Path mismatch, SPF / DKIM / DMARC failures
      ├─► text rules  ─► 20 weighted Indian-context fraud patterns + "genuine message" patterns
      ├─► text ML     ─► TF-IDF word 1–2-grams + logistic regression; top contributing words shown
      └─► each link   ─► threat intel (OpenPhish, URLhaus), Tranco top-100k reputation,
                         brand-on-wrong-domain, typosquat (look-alike letters such as rn→m, vv→w, 0→o, i↔l
                         and Cyrillic, plus one extra typo: arnozon.com → amazon),
                         punycode/IDN, IP host, "@" trick, shorteners, free hosting, risky TLDs,
                         redirect parameters, URL ML model,
                         optional live check (redirect chain, TLS, RDAP domain age)
score = wording (cap 70) + email + text ML + combination bonuses + riskiest link; intel hit ⇒ ≥ 90
```

**Models.** Both are scikit-learn logistic regressions exported to plain JSON. Inference is pure Python and matches scikit-learn to within 0.00002, so the running app needs only FastAPI, Uvicorn and tldextract.

- **URL model:** character 3–5-grams plus host and path word tokens (for example `hpaypal`, `psignin`, `tldxyz`), trained on 756k URLs.
- **Text model:** word 1–2-grams, trained on 14.5k emails/SMS.

Data: Hugging Face `ealvaradob/phishing-dataset` (Apache-2.0).

**Scoring.** `scripts/tune.py` sets how model probabilities become points. It uses a validation slice (20k URLs, 1.6k texts) that is in neither the training nor the test data. A grid search maximises recall while keeping:

- false alarms at or under 2% on URLs and under 4.5% on texts;
- the hand-written development set at no misses and at most 6 of its 50 legitimate messages flagged.

A link inside a message that otherwise reads as harmless gets no points from the URL model, only from the URL rules. A message counts as harmless when the text model scores it low and it asks you to do nothing: click, call, pay or share. This one change cut false alarms on legitimate emails by more than half.

## Privacy

Content is analysed in memory and never stored or logged (logs record only type, level, score and time). History stays in the browser's localStorage and can be switched off or cleared. The live link check is opt-in because it contacts the link's server; it refuses private/internal addresses. Responses are `Cache-Control: no-store`, with a strict Content-Security-Policy (no inline scripts or styles, no third-party assets).

## Run locally

Requires Python 3.12+. Everything needed to run the app is in this repo: the trained models (`app/model/*_model.json`) and the threat-intel snapshot (`app/model/intel/*.gz`). No download step is needed.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload          # http://127.0.0.1:8000
.venv/bin/python -m pytest -q                    # unit + API tests
.venv/bin/python scripts/smoke_test.py           # end-to-end HTTP checks (or pass a deployed URL)
```

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
.\.venv\Scripts\python -m uvicorn app.main:app --reload
.\.venv\Scripts\python -m pytest -q
```

`requirements.txt` is what the app needs; `requirements-dev.txt` adds scikit-learn (training only), pytest and httpx (tests).

### Not in the repo (and when you need it)

| Path | What | Needed for | How to get it |
|---|---|---|---|
| `.env` | Google OAuth client, session and token-encryption keys | Gmail protection only | Copy `.env.example` to `.env` and fill it in (see below) |
| `data/fraudlens.db` | Gmail scan results (SQLite) | Created automatically | — |
| `data/raw/` (~160 MB) | Training datasets and the Tranco list | Retraining and evaluation only | See "Retrain, retune, refresh intel" below |
| `data/intel/` | Raw OpenPhish / URLhaus / Phishing.Database downloads | Rebuilding the intel snapshot offline | `scripts/fetch_intel.py` downloads them |
| `.venv/` | Python virtual environment | — | Created by the commands above |

Docker: `docker build -t fraudlens . && docker run -p 8000:8000 fraudlens`

## Website inspection

Every link in a result has an **Inspect website** button (`POST /api/inspect-site`, 10 per minute). It downloads the page's HTML once (at most 1 MB, no scripts run, private/internal addresses refused) and checks for brand impersonation on the wrong domain, password/card/OTP/PIN/ID forms, forms that send data to another site, no HTTPS, hot-linked brand assets, automatic redirects, anti-inspection tricks and dead navigation links. A threat-feed match forces the score to at least 90.

## Robustness stress test

`scripts/stress_test.py` disguises every labelled scam the way attackers do and measures what is still caught. The disguises are digit swaps, Cyrillic look-alikes, zero-width characters, spaced keywords, rewording, defanged links, URL shorteners, free hosting and all of these combined. Threat feeds are off, so only the rules and models count. Results are on `/report` (section 6, served from `GET /api/robustness`). Currently 97.6% of scams are caught undisguised and 92.6% overall when disguised; the weakest case is everything combined (79.5%).

## Gmail protection (optional)

Users sign in with Google at `/dashboard`. FraudLens then checks their inbox every `POLL_SECONDS`, rates each new email with the same engine, emails an instant alert for high-risk mail and a daily report, and lists results on the dashboard. Email bodies are not stored, only sender, subject, score, level and reasons (SQLite, `data/fraudlens.db`). Google tokens are encrypted with `TOKEN_ENCRYPTION_KEY`.

1. In Google Cloud Console, create a project and enable the **Gmail API**.
2. Configure the **OAuth consent screen** (External, Testing) and add every Gmail address that will sign in as a **test user** (up to 100).
3. Create an **OAuth client ID** (Web application) with the authorised redirect URI `http://localhost:8000/auth/callback`.
4. Copy `.env.example` to `.env` and fill in `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SECRET` and `TOKEN_ENCRYPTION_KEY`.
5. Start the server and open `http://localhost:8000/dashboard` (use `localhost`, not `127.0.0.1`, so the sign-in cookie matches the redirect URI).

Scopes requested: `gmail.readonly` and `gmail.send`. Public release would need Google's app verification and an annual CASA security assessment; Testing mode needs neither. The background checker only runs while the server is running.

## Retrain, retune, refresh intel, re-evaluate

Raw data (not committed, ~160 MB) goes in `data/raw/`:

- `texts.json` and `urls.json`: download from the Hugging Face dataset [`ealvaradob/phishing-dataset`](https://huggingface.co/datasets/ealvaradob/phishing-dataset).
- `tranco.zip`: downloaded automatically by `scripts/fetch_intel.py` from [tranco-list.eu](https://tranco-list.eu/top-1m.csv.zip).

`scripts/fetch_intel.py` also saves the raw feeds to `data/intel/`, so `fetch_intel.py --offline` can rebuild the snapshot without the network. Train, validation and test splits are fixed in `scripts/splits.py`.

```bash
.venv/bin/python scripts/train.py        # ~5 min; writes app/model/{text,url}_model.json
.venv/bin/python scripts/tune.py         # prints the best TEXT_ML / URL_ML weights for app/analyzer/engine.py
.venv/bin/python scripts/fetch_intel.py  # refresh OpenPhish / URLhaus / Tranco snapshot
.venv/bin/python scripts/evaluate.py     # writes REPORT.md and app/model/eval_report.json
.venv/bin/python scripts/stress_test.py  # writes app/model/robustness.json
```

Intel is a snapshot; refresh it and restart the server regularly (daily is reasonable).

The rate limit (30 analyses and 10 website inspections per minute per IP) is kept in memory and resets when the server restarts.

## Limitations (short version)

- The hand-written test sets are small, so their confidence intervals are wide.
- The public training text is mostly English email, so Indian SMS coverage relies on the rules.
- Genuine bank and delivery alerts can score medium. These alerts are also what limits recall: weighting the text model more heavily would catch more phishing but flag them.
- Phishing hosted on big shared platforms gets less help from reputation.
- A phishing link sent with completely innocent wording is judged on its URL rules alone.
- Only text is analysed: no images, QR codes, attachments or calls.

The full list is in `REPORT.md`.
