from datetime import datetime, timedelta, timezone

import pytest


class FakeObjectLockStore:
    def __init__(self, *, object_lock=True, versioning=True):
        self.object_lock = object_lock
        self.versioning = versioning
        self.objects = {}
        self.puts = []

    def get_bucket_versioning(self, **_kwargs):
        return {"Status": "Enabled" if self.versioning else "Suspended"}

    def get_object_lock_configuration(self, **_kwargs):
        if not self.object_lock:
            return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}}
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def list_objects_v2(self, *, Prefix, **_kwargs):
        return {"Contents": [{"Key": key} for key in self.objects if key == Prefix]}

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        self.objects[kwargs["Key"]] = kwargs["Body"]

    def get_object(self, *, Key, **_kwargs):
        return {"Body": self.objects[Key]}


def test_audit_head_is_anchored_in_compliance_lock_and_detects_database_tampering(paari_client):
    from app.audit import record_audit
    from app.audit_anchor import anchor_audit_heads, verify_audit_anchor

    db = paari_client.Session()
    event = record_audit(
        db,
        transaction_id="anchor-test-transaction",
        agent_id=paari_client.agent_id,
        parent_id=None,
        kind="anchor_test",
        detail={"status": "original"},
        org_id="default",
    )
    db.commit()
    store = FakeObjectLockStore()
    try:
        anchored = anchor_audit_heads(
            db, store, bucket="paari-audit-test",
            retain_until=datetime.now(timezone.utc) + timedelta(days=30),
        )
        event_anchor = next(item for item in anchored if item["event_id"] == event.id)
        assert event_anchor["status"] == "anchored"
        assert all(item["ObjectLockMode"] == "COMPLIANCE" for item in store.puts)
        assert verify_audit_anchor(
            db, store, bucket="paari-audit-test",
            transaction_id=event.transaction_id,
            event_id=event.id,
            event_hash=event.event_hash,
        )

        event.detail = {"status": "tampered"}
        db.commit()
        assert not verify_audit_anchor(
            db, store, bucket="paari-audit-test",
            transaction_id=event.transaction_id,
            event_id=event.id,
            event_hash=event.event_hash,
        )
    finally:
        db.close()


def test_audit_anchoring_refuses_bucket_without_object_lock(paari_client):
    from app.audit_anchor import anchor_audit_heads

    with paari_client.Session() as db:
        with pytest.raises(RuntimeError, match="Object Lock"):
            anchor_audit_heads(
                db,
                FakeObjectLockStore(object_lock=False),
                bucket="paari-audit-test",
                retain_until=datetime.now(timezone.utc) + timedelta(days=30),
            )


def test_audit_anchoring_refuses_unversioned_bucket(paari_client):
    """Versioning is the precondition for retaining superseded anchor objects."""
    from app.audit_anchor import anchor_audit_heads

    with paari_client.Session() as db:
        with pytest.raises(RuntimeError, match="versioning"):
            anchor_audit_heads(
                db,
                FakeObjectLockStore(versioning=False),
                bucket="paari-audit-test",
                retain_until=datetime.now(timezone.utc) + timedelta(days=30),
            )


def test_audit_anchoring_refuses_to_overwrite_a_conflicting_anchor(paari_client):
    """An existing immutable anchor with a different hash must abort, not be replaced."""
    import json

    from app.audit import record_audit
    from app.audit_anchor import _anchor_key, anchor_audit_heads

    with paari_client.Session() as db:
        event = record_audit(
            db,
            transaction_id="anchor-conflict-transaction",
            agent_id=paari_client.agent_id,
            parent_id=None,
            kind="anchor_conflict_test",
            detail={"status": "original"},
            org_id="default",
        )
        db.commit()

        store = FakeObjectLockStore()
        key = _anchor_key(event)
        conflicting_body = json.dumps({
            "version": 1,
            "org_id": event.org_id,
            "transaction_id": event.transaction_id,
            "event_id": event.id,
            "event_hash": "0" * 64,
            "prev_hash": event.prev_hash,
        }).encode("utf-8")
        store.objects[key] = conflicting_body

        with pytest.raises(RuntimeError, match="differs"):
            anchor_audit_heads(
                db, store, bucket="paari-audit-test",
                retain_until=datetime.now(timezone.utc) + timedelta(days=30),
            )
        # The immutable object was not replaced by the database head.
        assert store.objects[key] == conflicting_body