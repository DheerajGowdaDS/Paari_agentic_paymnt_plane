"""Dedicated reconciliation worker entry point for horizontally separated deployment."""
from __future__ import annotations

import logging
import os
import signal
import threading

from app.reconcile_worker import ReconciliationWorker, ReconciliationAlertSink

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
stop = threading.Event()


def _handle_signal(signum, frame):
    stop.set()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    worker = ReconciliationWorker(
        interval_seconds=int(os.environ.get("PAARI_RECONCILE_INTERVAL", "30")),
        dead_letter_after=int(os.environ.get("PAARI_RECONCILE_DEAD_LETTER_AFTER", "8")),
        alert_sink=ReconciliationAlertSink(
            webhook_url=os.environ.get("PAARI_RECONCILE_ALERT_WEBHOOK", "")),
    )
    worker.start()
    try:
        stop.wait()
    finally:
        worker.stop()
