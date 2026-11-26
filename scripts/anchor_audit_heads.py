"""Anchor verified audit-chain heads in an S3 Object Lock bucket."""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import sessionmaker

from app.audit_anchor import anchor_audit_heads, verify_audit_anchor
from app.database import get_engine, resolve_database_url


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", default=os.environ.get("PAARI_AUDIT_WORM_BUCKET"))
    parser.add_argument("--database-url", default=resolve_database_url())
    parser.add_argument("--retention-days", type=int)
    parser.add_argument("--verify-transaction-id")
    parser.add_argument("--verify-event-id", type=int)
    parser.add_argument("--verify-event-hash")
    args = parser.parse_args()
    if not args.bucket:
        parser.error("--bucket or PAARI_AUDIT_WORM_BUCKET is required")

    verification_args = (args.verify_transaction_id, args.verify_event_id, args.verify_event_hash)
    if any(value is not None for value in verification_args) and not all(
        value is not None for value in verification_args
    ):
        parser.error("verification requires transaction ID, event ID, and event hash")
    if not any(value is not None for value in verification_args):
        if args.retention_days is None or args.retention_days < 1:
            parser.error("anchoring requires --retention-days >= 1")

    try:
        import boto3
    except ImportError as exc:
        raise SystemExit("Install optional audit-anchor dependencies: pip install -r requirements-audit.txt") from exc

    s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION"))
    engine = get_engine(args.database_url)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        with Session() as db:
            if all(value is not None for value in verification_args):
                valid = verify_audit_anchor(
                    db,
                    s3,
                    bucket=args.bucket,
                    transaction_id=args.verify_transaction_id,
                    event_id=args.verify_event_id,
                    event_hash=args.verify_event_hash,
                )
                print(json.dumps({"valid": valid}, sort_keys=True))
                if not valid:
                    raise SystemExit(1)
            else:
                retain_until = datetime.now(timezone.utc) + timedelta(days=args.retention_days)
                results = anchor_audit_heads(
                    db, s3, bucket=args.bucket, retain_until=retain_until,
                )
                print(json.dumps(results, sort_keys=True))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()