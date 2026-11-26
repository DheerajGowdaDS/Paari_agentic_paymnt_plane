"""Independent WORM anchors for audit-chain heads."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.audit import verify_chain


def _anchor_key(event: models.AuditEvent) -> str:
    org_digest = hashlib.sha256(event.org_id.encode("utf-8")).hexdigest()
    transaction_digest = hashlib.sha256(event.transaction_id.encode("utf-8")).hexdigest()
    return (f"paari-audit-anchors/{org_digest}/{transaction_digest}/"
            f"{event.id}-{event.event_hash}.json")


def _anchor_payload(event: models.AuditEvent) -> dict:
    return {
        "version": 1,
        "org_id": event.org_id,
        "transaction_id": event.transaction_id,
        "event_id": event.id,
        "event_hash": event.event_hash,
        "prev_hash": event.prev_hash,
        "kind": event.kind,
        "created_at": event.created_at.isoformat() if event.created_at else None,
        "anchored_at": datetime.now(timezone.utc).isoformat(),
    }


def _read_anchor(s3, bucket: str, key: str) -> dict:
    body = s3.get_object(Bucket=bucket, Key=key)["Body"]
    raw = body.read() if hasattr(body, "read") else body
    return json.loads(raw)


def _require_worm_bucket(s3, bucket: str) -> None:
    if s3.get_bucket_versioning(Bucket=bucket).get("Status") != "Enabled":
        raise RuntimeError("Audit anchor bucket versioning must be enabled")
    config = s3.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration", {})
    if config.get("ObjectLockEnabled") != "Enabled":
        raise RuntimeError("Audit anchor bucket must have S3 Object Lock enabled")


def _audit_heads(db: Session) -> list[models.AuditEvent]:
    latest_ids = (
        db.query(func.max(models.AuditEvent.id).label("id"))
        .group_by(models.AuditEvent.transaction_id)
        .subquery()
    )
    return (
        db.query(models.AuditEvent)
        .join(latest_ids, models.AuditEvent.id == latest_ids.c.id)
        .order_by(models.AuditEvent.id.asc())
        .all()
    )


def anchor_audit_heads(db: Session, s3, *, bucket: str,
                       retain_until: datetime) -> list[dict]:
    """Store each verified chain head under S3 Object Lock COMPLIANCE mode.

    The S3 bucket and its retention policy are deployment-owned. This function
    refuses unversioned/non-Object-Lock buckets rather than downgrading to a
    mutable remote copy.
    """
    if not bucket:
        raise ValueError("An audit anchor bucket is required")
    if retain_until.tzinfo is None or retain_until <= datetime.now(timezone.utc):
        raise ValueError("Audit anchor retention must be a future timezone-aware datetime")
    _require_worm_bucket(s3, bucket)

    anchored = []
    for event in _audit_heads(db):
        if not verify_chain(db, event.transaction_id):
            raise RuntimeError(f"Audit chain is invalid for transaction {event.transaction_id!r}")
        payload = _anchor_payload(event)
        key = _anchor_key(event)
        existing = s3.list_objects_v2(Bucket=bucket, Prefix=key, MaxKeys=1).get("Contents", [])
        if any(item.get("Key") == key for item in existing):
            stored = _read_anchor(s3, bucket, key)
            if any(stored.get(field) != payload[field] for field in (
                "org_id", "transaction_id", "event_id", "event_hash", "prev_hash",
            )):
                raise RuntimeError(f"Existing immutable audit anchor differs for {key}")
            anchored.append({
                "key": key,
                "transaction_id": event.transaction_id,
                "event_id": event.id,
                "event_hash": event.event_hash,
                "status": "already_anchored",
            })
            continue

        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until.astimezone(timezone.utc),
        )
        anchored.append({
            "key": key,
            "transaction_id": event.transaction_id,
            "event_id": event.id,
            "event_hash": event.event_hash,
            "status": "anchored",
        })
    return anchored


def verify_audit_anchor(db: Session, s3, *, bucket: str, transaction_id: str,
                        event_id: int, event_hash: str) -> bool:
    """Compare a WORM anchor with its database event and verify the full chain."""
    event = db.query(models.AuditEvent).filter_by(
        id=event_id, transaction_id=transaction_id,
    ).first()
    if event is None or event.event_hash != event_hash:
        return False
    if not verify_chain(db, transaction_id):
        return False
    try:
        payload = _read_anchor(s3, bucket, _anchor_key(event))
    except Exception as exc:
        response = getattr(exc, "response", {})
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        code = response.get("Error", {}).get("Code")
        if status == 404 or code in {"NoSuchKey", "NotFound"}:
            return False
        raise
    return (payload.get("transaction_id") == transaction_id
            and payload.get("event_id") == event_id
            and payload.get("event_hash") == event_hash
            and payload.get("org_id") == event.org_id)