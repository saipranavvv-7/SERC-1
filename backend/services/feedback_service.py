"""Analyst feedback storage (SQLite). Feedback never changes the original alert."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List

DECISIONS = {"accepted", "rejected", "review"}


class FeedbackService:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._ready = False

    @contextmanager
    def _conn(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            if not self._ready:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS feedback (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           alert_id TEXT NOT NULL,
                           claim_id TEXT NOT NULL,
                           claim_text TEXT,
                           decision TEXT NOT NULL,
                           note TEXT,
                           created_at TEXT NOT NULL
                       )""")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_alert ON feedback(alert_id)")
                self._ready = True
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, alert_id: str, claim_id: str, decision: str, claim_text: str = "", note: str = "") -> Dict[str, Any]:
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
        with self._conn() as c:
            # one current decision per claim: replace the previous one
            c.execute("DELETE FROM feedback WHERE alert_id=? AND claim_id=?", (alert_id, claim_id))
            c.execute(
                "INSERT INTO feedback (alert_id, claim_id, claim_text, decision, note, created_at) VALUES (?,?,?,?,?,?)",
                (alert_id[:120], claim_id[:40], claim_text[:600], decision, note[:500], time.strftime("%Y-%m-%d %H:%M:%S")))
        return {"alert_id": alert_id, "claim_id": claim_id, "decision": decision}

    def list_for_alert(self, alert_id: str) -> List[Dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT claim_id, claim_text, decision, note, created_at FROM feedback WHERE alert_id=? ORDER BY claim_id",
                             (alert_id,)).fetchall()
        return [dict(r) for r in rows]
