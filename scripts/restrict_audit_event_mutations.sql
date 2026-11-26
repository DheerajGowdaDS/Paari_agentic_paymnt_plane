\if :{?paari_app_role}
\else
\echo 'Set -v paari_app_role=<runtime-role>'
\quit
\endif
\if :{?paari_audit_owner_role}
\else
\echo 'Set -v paari_audit_owner_role=<non-login-owner-role>'
\quit
\endif

ALTER ROLE :"paari_audit_owner_role" NOLOGIN;

SELECT format('ALTER TABLE public.audit_events OWNER TO %I', :'paari_audit_owner_role')
\gexec
SELECT format(
    'ALTER SEQUENCE %s OWNER TO %I',
    pg_get_serial_sequence('public.audit_events', 'id'),
    :'paari_audit_owner_role'
)
\gexec

REVOKE ALL PRIVILEGES ON TABLE public.audit_events FROM PUBLIC;
SELECT format('REVOKE ALL PRIVILEGES ON TABLE public.audit_events FROM %I', :'paari_app_role')
\gexec
SELECT format('GRANT SELECT, INSERT ON TABLE public.audit_events TO %I', :'paari_app_role')
\gexec

SELECT format(
    'REVOKE ALL PRIVILEGES ON SEQUENCE %s FROM PUBLIC',
    pg_get_serial_sequence('public.audit_events', 'id')
)
\gexec
SELECT format(
    'REVOKE ALL PRIVILEGES ON SEQUENCE %s FROM %I',
    pg_get_serial_sequence('public.audit_events', 'id'),
    :'paari_app_role'
)
\gexec
SELECT format(
    'GRANT USAGE, SELECT ON SEQUENCE %s TO %I',
    pg_get_serial_sequence('public.audit_events', 'id'),
    :'paari_app_role'
)
\gexec