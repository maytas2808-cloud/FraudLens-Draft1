"""SQLite storage for connected users and per-email verdicts.

Email bodies are never stored: only sender, subject, score, level and the top reasons.
Google tokens are encrypted with Fernet (TOKEN_ENCRYPTION_KEY).
"""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from cryptography.fernet import Fernet

from . import config

_lock = threading.Lock()
_ready_for = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    token BLOB NOT NULL,
    created_at REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    digest TEXT NOT NULL DEFAULT 'daily',
    alerts INTEGER NOT NULL DEFAULT 1,
    last_scan_at REAL,
    last_digest_at REAL,
    error TEXT
);
CREATE TABLE IF NOT EXISTS results (
    email TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    received_at REAL,
    analyzed_at REAL NOT NULL,
    sender TEXT,
    subject TEXT,
    score INTEGER,
    level TEXT NOT NULL,
    scenarios TEXT,
    reasons TEXT,
    summary TEXT,
    alerted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email, msg_id)
);
CREATE INDEX IF NOT EXISTS results_by_time ON results (email, analyzed_at);
"""


@contextmanager
def _db():
    global _ready_for
    with _lock:
        path = config.DB_PATH
        if _ready_for != str(path):
            path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(path) as c:
                c.executescript(SCHEMA)
            _ready_for = str(path)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def _fernet() -> Fernet:
    return Fernet(config.TOKEN_KEY.encode())


def save_user(email: str, creds_json: str) -> bool:
    """Create or reconnect a user. Returns True if the user is new."""
    token = _fernet().encrypt(creds_json.encode())
    with _db() as c:
        exists = c.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
        if exists:
            c.execute("UPDATE users SET token = ?, active = 1, error = NULL WHERE email = ?", (token, email))
        else:
            c.execute("INSERT INTO users (email, token, created_at) VALUES (?, ?, ?)", (email, token, time.time()))
    return not exists


def update_token(email: str, creds_json: str) -> None:
    with _db() as c:
        c.execute("UPDATE users SET token = ? WHERE email = ?", (_fernet().encrypt(creds_json.encode()), email))


def creds_json(email: str) -> str | None:
    with _db() as c:
        row = c.execute("SELECT token FROM users WHERE email = ? AND active = 1", (email,)).fetchone()
    return _fernet().decrypt(row["token"]).decode() if row else None


def user(email: str) -> dict | None:
    with _db() as c:
        row = c.execute("SELECT email, created_at, active, digest, alerts, last_scan_at, last_digest_at, error "
                        "FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def active_users() -> list[dict]:
    with _db() as c:
        rows = c.execute("SELECT email, created_at, digest, alerts, last_digest_at FROM users WHERE active = 1").fetchall()
    return [dict(r) for r in rows]


def set_prefs(email: str, digest: str, alerts: bool) -> None:
    with _db() as c:
        c.execute("UPDATE users SET digest = ?, alerts = ? WHERE email = ?", (digest, int(alerts), email))


def mark(email: str, **fields) -> None:
    allowed = {"active", "last_scan_at", "last_digest_at", "error"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    with _db() as c:
        c.execute(f"UPDATE users SET {', '.join(f'{k} = ?' for k in sets)} WHERE email = ?", (*sets.values(), email))


def delete_user(email: str) -> None:
    with _db() as c:
        c.execute("DELETE FROM results WHERE email = ?", (email,))
        c.execute("DELETE FROM users WHERE email = ?", (email,))


def known_ids(email: str, ids: list[str]) -> set[str]:
    if not ids:
        return set()
    with _db() as c:
        rows = c.execute(f"SELECT msg_id FROM results WHERE email = ? AND msg_id IN ({','.join('?' * len(ids))})",
                         (email, *ids)).fetchall()
    return {r["msg_id"] for r in rows}


def add_result(email: str, msg_id: str, *, received_at: float | None, sender: str, subject: str, score: int,
               level: str, scenarios: list[str], reasons: list[str], summary: str) -> bool:
    with _db() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO results (email, msg_id, received_at, analyzed_at, sender, subject, score, level, "
            "scenarios, reasons, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (email, msg_id, received_at, time.time(), sender[:300], subject[:300], score, level,
             json.dumps(scenarios), json.dumps(reasons), summary[:500]))
    return cur.rowcount == 1


def update_result(email: str, msg_id: str, *, score: int, level: str, scenarios: list[str], reasons: list[str],
                  summary: str) -> None:
    """Replace the verdict of an analysed message, keeping its alerted flag so no alert is sent twice."""
    with _db() as c:
        c.execute("UPDATE results SET analyzed_at = ?, score = ?, level = ?, scenarios = ?, reasons = ?, summary = ? "
                  "WHERE email = ? AND msg_id = ? AND level != 'skipped'",
                  (time.time(), score, level, json.dumps(scenarios), json.dumps(reasons), summary[:500], email, msg_id))


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["scenarios"] = json.loads(d["scenarios"] or "[]")
    d["reasons"] = json.loads(d["reasons"] or "[]")
    return d


def results(email: str, level: str | None = None, since: float | None = None, limit: int = 100) -> list[dict]:
    q = "SELECT * FROM results WHERE email = ? AND level != 'skipped'"
    args: list = [email]
    if level:
        q += " AND level = ?"
        args.append(level)
    if since is not None:
        q += " AND analyzed_at >= ?"
        args.append(since)
    q += " ORDER BY COALESCE(received_at, analyzed_at) DESC LIMIT ?"
    args.append(limit)
    with _db() as c:
        return [_row(r) for r in c.execute(q, args).fetchall()]


def pending_alerts(email: str, received_after: float) -> list[dict]:
    with _db() as c:
        rows = c.execute("SELECT * FROM results WHERE email = ? AND level = 'high' AND alerted = 0 AND received_at >= ? "
                         "ORDER BY received_at DESC", (email, received_after)).fetchall()
    return [_row(r) for r in rows]


def mark_alerted(email: str, msg_ids: list[str]) -> None:
    if not msg_ids:
        return
    with _db() as c:
        c.execute(f"UPDATE results SET alerted = 1 WHERE email = ? AND msg_id IN ({','.join('?' * len(msg_ids))})",
                  (email, *msg_ids))


def stats(email: str) -> dict:
    with _db() as c:
        rows = c.execute("SELECT level, COUNT(*) AS n FROM results WHERE email = ? AND level != 'skipped' GROUP BY level",
                         (email,)).fetchall()
    counts = {r["level"]: r["n"] for r in rows}
    return {"total": sum(counts.values()), "high": counts.get("high", 0), "medium": counts.get("medium", 0),
            "low": counts.get("low", 0)}
