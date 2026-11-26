"""Start a genuinely live, dynamic Paari demo against local PostgreSQL.

Required: the COMPLETE Paari repository, incl. alembic/, alembic.ini,
requirements-dev.txt, and PostgreSQL installed/running locally. The 231-file
source export lacks these infrastructure files: merge this add-on into the
original, complete local repository, NOT only that reduced ZIP.

PowerShell:
  python scripts/start_live_demo.py --database-url postgresql+psycopg://paari:...@127.0.0.1:5439/paari_demo

All entities, mandates, policies and transactions are created on operator
clicks. Startup applies migrations but never deletes demo data.
"""
from __future__ import annotations
import argparse
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from local_demo.portal import safe_demo_env
from live_demo_mode.app import build_app


def guarded_dsn(dsn: str) -> str:
    parsed = urlparse(dsn)
    if parsed.scheme not in ('postgresql', 'postgresql+psycopg'):
        raise ValueError('Paari Live Mode requires local PostgreSQL, not SQLite')
    if parsed.hostname not in ('127.0.0.1', 'localhost'):
        raise ValueError('External/non-loopback PostgreSQL is forbidden')
    if parsed.path.lstrip('/') not in ('paari_demo', 'paari_demo_test'):
        raise ValueError('Database must be named paari_demo or paari_demo_test')
    return dsn


def check_free(port: int):
    with socket.socket() as s:
        s.bind(('127.0.0.1', port))


def await_health(url: str, service: subprocess.Popen, timeout: int = 45):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if service.poll() is not None:
            raise RuntimeError('Paari API exited during startup')
        try:
            r = httpx.get(url+'/health', timeout=1)
            if r.status_code == 200 and r.json().get('database') == 'up':
                health = r.json()
                if not health.get('control_plane_enforcement'):
                    raise RuntimeError('Refusing demo: strict control-plane enforcement is OFF')
                if not health.get('require_signed_mandate'):
                    raise RuntimeError('Refusing demo: signed mandates are not required')
                if health.get('env') != 'sandbox':
                    raise RuntimeError('Refusing demo: API is not in the sandbox environment')
                return
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(.4)
    raise RuntimeError('Paari API did not become database-healthy')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database-url', default=os.environ.get('PAARI_PG_DSN', ''),
                   help='Loopback Postgres paari_demo DSN')
    p.add_argument('--api-port', type=int, default=8120)
    p.add_argument('--demo-api-port', '--ui-port', dest='demo_api_port', type=int, default=8770)
    p.add_argument('--stub-port', type=int, default=9911)
    args = p.parse_args(argv)
    if not args.database_url:
        p.error('Pass --database-url or set PAARI_PG_DSN (local paari_demo PostgreSQL)')
    try:
        guarded_dsn(args.database_url)
        for port in (args.api_port, args.demo_api_port, args.stub_port):
            if not 1024 <= port <= 65535:
                raise ValueError('Ports must be between 1024 and 65535')
        if len({args.api_port, args.demo_api_port, args.stub_port}) != 3:
            raise ValueError('Port numbers must be different')
        for port in (args.api_port, args.demo_api_port, args.stub_port):
            check_free(port)
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    if not (ROOT/'alembic.ini').is_file() or not (ROOT/'alembic'/'env.py').is_file():
        p.error('Missing alembic.ini/alembic/: merge Live Mode into your COMPLETE original repository. The reduced 231-file export is not enough.')
    home = ROOT/'data'/'local_demo'
    home.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass
    # Keys and provider state never become part of the source ZIP or the agent request log.
    admin = secrets.token_urlsafe(40)
    stub_base = f'http://127.0.0.1:{args.stub_port}/v1'
    env = safe_demo_env(home)
    env.update({'DATABASE_URL': args.database_url, 'ALEMBIC_URL': args.database_url,
                'PAARI_DATABASE_URL': args.database_url, 'PAARI_ENV': 'sandbox',
                'PAARI_LIVE': '0', 'PAARI_MODE': 'standard',
                'PAARI_REQUIRE_USER_MANDATE': '0', 'PAARI_REQUIRE_SIGNED_MANDATE': '1',
                'PAARI_CONTROL_PLANE_ENFORCEMENT': '1', 'PAARI_REQUIRE_SAFR_ENVELOPE': '1',
                'PAARI_SIGNING_KEY_PATH': str(home/'live_demo_signing_key.pem'),
                'PAARI_SIGNING_BACKEND': 'local_pem', 'PAARI_ADMIN_API_KEY': admin,
                'RAZORPAY_KEY_ID': 'rzp_test_SIM_LOCAL',
                'RAZORPAY_KEY_SECRET': 'simulated-secret',
                'RAZORPAY_WEBHOOK_SECRET': 'stub_webhook_secret',
                'RAZORPAY_API_BASE': stub_base,
                'STUB_STATE_FILE': str(home/'live_provider_state.json'),
                'PYTHONIOENCODING': 'utf-8'})
    print('[Paari Live] Applying NON-DESTRUCTIVE schema migrations...')
    mig = subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'],
                         cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
    if mig.returncode != 0:
        print((mig.stderr or mig.stdout)[-3000:], file=sys.stderr)
        return 1
    processes = []
    try:
        processes.append(subprocess.Popen([sys.executable, str(ROOT/'scripts'/'stub_razorpay.py'),
                                           str(args.stub_port)], cwd=ROOT, env=env))
        api_base = f'http://127.0.0.1:{args.api_port}'
        processes.append(subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app',
            '--host', '127.0.0.1', '--port', str(args.api_port)], cwd=ROOT, env=env))
        await_health(api_base, processes[-1])
        print('[READY] Paari strict runtime: '+api_base)
        demo_api_token = secrets.token_urlsafe(36)
        print('[READY] Headless demo orchestration API: http://127.0.0.1:'+str(args.demo_api_port))
        print('[LOCAL OPERATOR API TOKEN] '+demo_api_token)
        print('[AUTH HEADER] X-Paari-Demo-Token: <token shown above>')
        print('[MODE] Live registration/delegation and agent API requests; payment provider SIMULATED.')
        print('[NOTICE] No pre-created agents, mandates, policies or payments; persistent database is not reset.')
        # API-only local demo service; explicit bearer-style operator token.
        app = build_app(backend_url=api_base, stub_base=stub_base,
                        admin_api_key=admin, webhook_secret='stub_webhook_secret',
                        demo_api_token=demo_api_token)
        uvicorn.run(app, host='127.0.0.1', port=args.demo_api_port, log_level='warning')
    except (KeyboardInterrupt, RuntimeError) as exc:
        if isinstance(exc, RuntimeError):
            print('[ERROR] '+str(exc), file=sys.stderr)
            return 1
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
