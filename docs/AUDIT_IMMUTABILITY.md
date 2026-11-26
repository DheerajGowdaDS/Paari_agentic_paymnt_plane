# Audit Immutability Operations

`audit_events` is hash-chained in PostgreSQL, but the chain alone is not independently immutable: a database owner can rewrite rows and recompute later hashes. Production deployments should anchor verified chain heads in a separate S3 bucket with versioning and Object Lock enabled in COMPLIANCE mode.

## Local development

External anchoring is a **production/deployment control**, not a local-dev
requirement: the threat it addresses is a privileged database operator, which
does not exist in a local SQLite setup. Local development relies on the
hash chain alone.

The anchoring code path is covered offline in `tests/test_audit_anchor.py`
against a fake Object Lock store: it verifies COMPLIANCE-mode writes, refuses a
bucket without versioning, refuses a bucket without Object Lock, and refuses to
replace an existing anchor whose hash differs. No AWS credentials are needed to
run these tests.


Install the optional uploader dependency with `pip install -r requirements-audit.txt`. Provision the bucket in a separate AWS account from the Paari database, enable versioning and Object Lock at bucket creation, and grant the scheduled anchoring identity only `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration`, `s3:ListBucket`, `s3:GetObject`, `s3:PutObject`, and `s3:PutObjectRetention` for the anchor prefix. Do not grant delete-object, delete-version, bucket-policy, retention-bypass, or Object Lock configuration permissions to the Paari runtime identity. Keep the bucket owner and retention administration separate from the application and database operators.

Set `PAARI_AUDIT_WORM_BUCKET` and the standard AWS credential/region environment for a dedicated scheduled job, then run:

```powershell
python -m scripts.anchor_audit_heads --retention-days 365
```

The command refuses buckets without versioning and Object Lock, and refuses to anchor a chain that fails local hash verification. Store the emitted `transaction_id`, `event_id`, and `event_hash` in the job report. Verify a reported anchor with:

```powershell
python -m scripts.anchor_audit_heads --verify-transaction-id <transaction-id> --verify-event-id <event-id> --verify-event-hash <event-hash>
```

Run the uploader on a schedule independent of database backups and alert on any failed run. An anchor only protects events that have already been uploaded; the schedule and retention interval define the maximum unanchored exposure window. Object Lock compliance retention prevents replacement or deletion of the anchored object version until its retention date, but does not protect events that were never anchored or a bucket whose policy/admin identity is compromised.

For PostgreSQL, use a dedicated non-login role as the `audit_events` table/sequence owner and a distinct runtime role. Apply the optional privilege script as a database administrator, substituting the existing role names:

```powershell
psql "$env:PAARI_DATABASE_URL" -v paari_app_role=paari_runtime -v paari_audit_owner_role=paari_audit_owner -f scripts/restrict_audit_event_mutations.sql
```

The runtime role gets only `SELECT`/`INSERT` on the table and `USAGE` on its sequence. Migrations must run under a separate schema-owner role. Check inherited grants and role memberships: a runtime role that can assume the owner role or inherits another role with mutation privileges is not restricted by this script. Database superusers remain outside this control; the external WORM anchor is the independent evidence against privileged database edits.