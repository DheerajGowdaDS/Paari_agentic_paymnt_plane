"""Provider reconciliation worker for missed webhooks and unknown executions."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from logging import getLogger
from typing import Callable

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import or_

from app import models
from app.database import get_engine
from app.reconcile import reconcile_one
from app.transitions import RECONCILABLE_STATES, TERMINAL_STATES

logger = getLogger("paari.reconcile")


def _transition_with_treasury(db: Session, txn, to_state: str) -> None:
    from app.transitions import transition_txn
    transition_txn(txn, to_state)
    from app.treasury_service import sync_reservation_after_transition
    sync_reservation_after_transition(db, txn, to_state)


@dataclass
class ReconciliationAlertSink:
    webhook_url: str = ""

    def alert(self, event: str, authorization_id: str, org_id: str, detail: str = ""):
        msg = f"[reconcile] {event} auth={authorization_id} org={org_id} {detail}".strip()
        logger.warning(msg)
        if not self.webhook_url:
            return
        import httpx
        try:
            httpx.post(
                self.webhook_url,
                json={"event": event, "authorization_id": authorization_id, "org_id": org_id, "detail": detail},
                timeout=5.0,
            )
        except Exception:
            pass


@dataclass
class ReconciliationWorker:
    interval_seconds: int = 60
    dead_letter_after: int = 5
    alert_sink: ReconciliationAlertSink = field(default_factory=ReconciliationAlertSink)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def start(self, db_url: str | None = None):
        # Default to the database the app itself resolved. `start()` used to do
        # `get_engine(db_url) if db_url else None`, and app.main calls it with no
        # argument - so the worker came up with engine=None, built no session
        # factory, and `_run_batch(None)` raised AttributeError on every tick.
        # It logged "reconciliation batch failed" forever and reconciled nothing:
        # exactly the failure mode where a background job looks started (the log
        # says so, the thread exists) and is in fact inert. Tests passed because
        # they call start(db_url=...) directly, so the untested path was the only
        # path production takes.
        from app.database import DATABASE_URL
        engine = get_engine(db_url or DATABASE_URL)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(engine,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 5)

    def _loop(self, engine):
        if engine is None:
            # Loud, once, at construction - rather than a None session that
            # raises inside every batch and reads like a database fault.
            raise RuntimeError("ReconciliationWorker started without an engine")
        SessionLocal = sessionmaker(bind=engine)
        while not self._stop.is_set():
            try:
                self._run_batch(SessionLocal() if SessionLocal else None)
            except Exception:
                logger.exception("reconciliation batch failed")
            self._stop.wait(self.interval_seconds)

    def _run_batch(self, session: Session):
        """Claim due work, then retry with bounded exponential backoff.

        `next_reconcile_at` doubles as a durable lease while a provider read is
        in flight. PostgreSQL workers use SKIP LOCKED for claiming; the lease
        also protects against a worker crash after the claim transaction commits.
        """
        from app.reconcile import reconcile_one as _reconcile_one, _audit
        from app.audit import record_audit

        now = datetime.now(timezone.utc)
        claim_until = now + timedelta(seconds=max(15, self.interval_seconds * 2))
        due = (
            session.query(models.ProviderTransaction)
            .filter(
                models.ProviderTransaction.state.in_(RECONCILABLE_STATES),
                models.ProviderTransaction.dead_lettered_at.is_(None),
                or_(models.ProviderTransaction.next_reconcile_at.is_(None),
                    models.ProviderTransaction.next_reconcile_at <= now),
            )
            .order_by(models.ProviderTransaction.updated_at.asc())
            .with_for_update(skip_locked=True)
            .limit(100)
            .all()
        )
        claimed_ids = [txn.authorization_id for txn in due]
        for txn in due:
            txn.next_reconcile_at = claim_until
        session.commit()

        for authorization_id in claimed_ids:
            try:
                result = _reconcile_one(session, authorization_id)
            except Exception as exc:
                result = {"status": "unreconciled", "error": str(exc)[:2000]}

            txn = session.query(models.ProviderTransaction).filter_by(
                authorization_id=authorization_id).first()
            if txn is None:
                continue
            now = datetime.now(timezone.utc)
            txn.last_reconcile_at = now
            if result.get("error"):
                txn.last_error = str(result["error"])[:2000]

            if txn.state in TERMINAL_STATES:
                txn.next_reconcile_at = None
                session.commit()
                continue

            txn.reconciliation_attempts = int(txn.reconciliation_attempts or 0) + 1
            # Preserve the historical attempts counter for older dashboards;
            # v4.0 exposes the separate reconciliation_attempts field.
            txn.attempts = int(txn.attempts or 0) + 1
            if txn.reconciliation_attempts >= self.dead_letter_after:
                if txn.dead_lettered_at is None:
                    txn.dead_lettered_at = now
                    txn.next_reconcile_at = None
                    txn.last_error = txn.last_error or "dead-letter: exceeded max reconcile attempts"
                    _audit(session, txn, "reconcile_dead_letter", {
                        "state": txn.state,
                        "attempts": txn.reconciliation_attempts,
                        "reason": "dead-letter: exceeded max reconcile attempts",
                        "manual_review_required": True,
                    })
                    self.alert_sink.alert("dead_letter", txn.authorization_id, txn.org_id, txn.last_error)
            else:
                backoff_seconds = min(3600, max(self.interval_seconds, 2 ** min(txn.reconciliation_attempts, 10)))
                txn.next_reconcile_at = now + timedelta(seconds=backoff_seconds)
            session.commit()

