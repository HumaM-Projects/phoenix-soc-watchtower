import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent / "soc_watchtower.db"

def get_connection():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with get_connection() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS investigations (
            alert_id TEXT PRIMARY KEY, severity TEXT NOT NULL, source_ip TEXT,
            username TEXT, rule TEXT, mitre TEXT, notes TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL)""")

def save_note(alert_id, notes, severity, source_ip, username, rule, mitre):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_connection() as con:
        con.execute("""INSERT INTO investigations
        (alert_id,severity,source_ip,username,rule,mitre,notes,updated_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(alert_id) DO UPDATE SET severity=excluded.severity,
        source_ip=excluded.source_ip, username=excluded.username,
        rule=excluded.rule, mitre=excluded.mitre, notes=excluded.notes,
        updated_at=excluded.updated_at""",
        (alert_id,severity,source_ip,username,rule,mitre,notes,now))

def load_note(alert_id):
    with get_connection() as con:
        row = con.execute("SELECT notes FROM investigations WHERE alert_id=?",
                           (alert_id,)).fetchone()
    return row["notes"] if row else ""
