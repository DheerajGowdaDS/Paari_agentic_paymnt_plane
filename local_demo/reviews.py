"""Sandbox review queue: timeouts and explicit reviewer authority; NEVER payment approval."""
from __future__ import annotations

import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from local_demo.core import EvidenceStore, decision_preview


class ReviewQueue:
    def __init__(self, db_path: Path, store: EvidenceStore, reviewer_code: str | None = None):
        self.path = db_path
        self.store = store
        self._lock = threading.RLock()
        self._reviewer_code = reviewer_code or secrets.token_urlsafe(18)
        # Explicit connect/close (not `with ... as db`): a sqlite3.Connection used
        # as a context manager only commits/rolls back - it does NOT release the OS
        # file handle. On Windows that lingering handle blocks the caller's
        # `tempfile.TemporaryDirectory` cleanup. Mirrors the EvidenceStore fix.
        db = self._db()
        try:
            db.executescript("""CREATE TABLE IF NOT EXISTS reviews(
                id TEXT PRIMARY KEY, scenario TEXT NOT NULL, requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, status TEXT NOT NULL,
                disposition TEXT NOT NULL, decision_reason TEXT,
                reviewer TEXT);
            """)
            db.commit()
        finally:
            db.close()

    def _db(self):
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        return connection

    def request(self, scenario: str, *, ttl_seconds: int = 120) -> dict:
        preview = decision_preview(scenario)
        if preview["disposition"] != "ESCALATE":
            raise ValueError("Only an escalated action can enter human review")
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("Invalid review timeout")
        now = datetime.now(timezone.utc)
        item = dict(id=uuid.uuid4().hex, scenario=scenario, requested_at=now.isoformat(),
                    expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
                    status="pending", disposition="ESCALATE", decision_reason=None, reviewer=None)
        with self._lock:
            db = self._db()
            try:
                db.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?,?,?)", tuple(item.values()))
                db.commit()
                self.store.append("review_requested", {"review_id": item["id"], "scenario": scenario,
                    "expires_at": item["expires_at"], "decision": "ESCALATE"})
            finally:
                db.close()
        return item

    def resolve(self, item_id: str, *, decision: str, reviewer_code: str, reviewer: str) -> dict:
        if not secrets.compare_digest(reviewer_code, self._reviewer_code):
            raise PermissionError("reviewer authority verification failed")
        if decision not in {"approve", "deny"} or reviewer != "local-reviewer":
            raise ValueError("Invalid local reviewer decision or identity")
        with self._lock:
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM reviews WHERE id=?", (item_id,)).fetchone()
                if row is None:
                    db.rollback()
                    db.close()
                    raise KeyError(item_id)
                if row["status"] != "pending":
                    db.rollback()
                    db.close()
                    raise ValueError("Review already resolved or expired")
                now = datetime.now(timezone.utc)
                expired = now >= datetime.fromisoformat(row["expires_at"])
                # Human approval cannot bypass a new hard denial or execute a payment.
                updated = decision_preview(row["scenario"])
                if updated["disposition"] != "ESCALATE":
                    decision = "deny"
                status = "expired" if expired else ("approved_preview" if decision == "approve" else "denied")
                db.execute("UPDATE reviews SET status=?, decision_reason=?, reviewer=? WHERE id=?",
                           (status, "EXPIRED_FAIL_CLOSED" if expired else "AUTHORIZED_LOCAL_REVIEW_PREVIEW",
                            reviewer, item_id))
                db.commit()
                self.store.append("review_resolved", {"review_id": item_id, "status": status,
                              "reviewer": reviewer, "expires_at": row["expires_at"],
                              "provider_executed": False})
                db.close()
                return dict(self._get(item_id))
            except (KeyError, ValueError):
                raise
            except Exception:
                try:
                    db.rollback()
                finally:
                    db.close()
                raise

    def _get(self, item_id: str):
        db = self._db()
        try:
            row = db.execute("SELECT * FROM reviews WHERE id=?", (item_id,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def list(self, limit=30) -> list[dict]:
        db = self._db()
        try:
            return [dict(r) for r in db.execute(
                "SELECT * FROM reviews ORDER BY requested_at DESC LIMIT ?", (limit,))]
        finally:
            db.close()
