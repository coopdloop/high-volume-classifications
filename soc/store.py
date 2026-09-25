"""SQLite-backed store: classified events, campaigns, SOAR approval queue."""

import json
import os
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.getenv("SOC_DB", "data/soc.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, source TEXT, host TEXT, user TEXT, raw TEXT,
  is_suspicious REAL, suspicious_confidence REAL,
  severity REAL, severity_confidence REAL,
  tactic TEXT, tactic_confidence REAL,
  needs_context REAL, decision TEXT, backend TEXT
);
CREATE TABLE IF NOT EXISTS campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  anchor TEXT,            -- host or user the campaign clusters around
  started_at REAL, updated_at REAL,
  hosts TEXT, users TEXT, tactics TEXT, event_ids TEXT,
  narrative TEXT, status TEXT DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER, action TEXT, risk TEXT, reason TEXT,
  disruptive_prob REAL,
  status TEXT DEFAULT 'pending',   -- pending | approved | rejected | simulated-executed
  created_at REAL, decided_at REAL
);
"""


@contextmanager
def db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with db() as conn:
        conn.executescript(SCHEMA)


def insert_event(ev: dict) -> int:
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO events (ts, source, host, user, raw, is_suspicious,
               suspicious_confidence, severity, severity_confidence, tactic,
               tactic_confidence, needs_context, decision, backend)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ev["ts"], ev["source"], ev.get("host"), ev.get("user"), json.dumps(ev["raw"]),
                ev.get("is_suspicious"), ev.get("suspicious_confidence"),
                ev.get("severity"), ev.get("severity_confidence"),
                ev.get("tactic"), ev.get("tactic_confidence"),
                ev.get("needs_context"), ev["decision"], ev.get("backend"),
            ),
        )
        return cur.lastrowid


def escalation_count(host: str | None, user: str | None, window_sec: int) -> int:
    since = time.time() - window_sec
    with db() as conn:
        row = conn.execute(
            """SELECT COUNT(*) c FROM events WHERE decision='escalate' AND ts > ?
               AND (host = ? OR user = ?)""",
            (since, host, user),
        ).fetchone()
        return row["c"]


def escalations_since(last_id: int, window_sec: int) -> list[dict]:
    since = time.time() - window_sec
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE id > ? AND decision='escalate' AND ts > ? ORDER BY id",
            (last_id, since),
        ).fetchall()
        return [dict(r) for r in rows]


def find_open_campaign(anchor: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM campaigns WHERE anchor = ? AND status='open' ORDER BY id DESC LIMIT 1",
            (anchor,),
        ).fetchone()
        return dict(row) if row else None


def upsert_campaign(c: dict) -> int:
    now = time.time()
    with db() as conn:
        if c.get("id"):
            conn.execute(
                "UPDATE campaigns SET updated_at=?, hosts=?, users=?, tactics=?, event_ids=?, narrative=? WHERE id=?",
                (now, json.dumps(c["hosts"]), json.dumps(c["users"]), json.dumps(c["tactics"]),
                 json.dumps(c["event_ids"]), c.get("narrative"), c["id"]),
            )
            return c["id"]
        cur = conn.execute(
            "INSERT INTO campaigns (anchor, started_at, updated_at, hosts, users, tactics, event_ids, narrative) VALUES (?,?,?,?,?,?,?,?)",
            (c["anchor"], now, now, json.dumps(c["hosts"]), json.dumps(c["users"]),
             json.dumps(c["tactics"]), json.dumps(c["event_ids"]), c.get("narrative")),
        )
        return cur.lastrowid


def insert_approval(campaign_id: int, action: dict) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO approvals (campaign_id, action, risk, reason, disruptive_prob, created_at) VALUES (?,?,?,?,?,?)",
            (campaign_id, action["action"], action.get("risk", "medium"),
             action.get("reason", ""), action.get("disruptive_prob"), time.time()),
        )
        return cur.lastrowid


def query(sql: str, params: tuple = ()) -> list[dict]:
    with db() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def execute(sql: str, params: tuple = ()):
    with db() as conn:
        conn.execute(sql, params)
