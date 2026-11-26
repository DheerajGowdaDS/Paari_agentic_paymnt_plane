from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORG = ROOT / "web" / "organization" / "index.html"
CONSOLE = ROOT / "web" / "internal" / "index.html"


class ElementIdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key == "id" and value:
                self.ids.add(value)


def html_ids(path: Path):
    parser = ElementIdCollector()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.ids


def test_both_separate_website_documents_exist_and_are_nonempty():
    assert ORG.is_file() and ORG.stat().st_size > 50_000
    assert CONSOLE.is_file() and CONSOLE.stat().st_size > 50_000


def test_external_organization_portal_does_not_ship_internal_console_shell():
    ids = html_ids(ORG)
    assert {"publicView", "appView", "verifyView", "page-agents", "page-payments", "page-treasury", "page-profile"}.issubset(ids)
    assert not {"platformConsole", "platformAdminKey", "topAdmin", "p-page-overview"}.intersection(ids)


def test_internal_console_does_not_ship_parent_onboarding_or_workspace_shell():
    ids = html_ids(CONSOLE)
    assert {"platformView", "platformConsole", "platformAdminKey", "p-page-applications", "p-page-tenants", "p-page-agents", "p-page-payments", "p-page-governance", "p-page-audit"}.issubset(ids)
    assert not {"publicView", "appView", "parentForm", "loginForm", "page-agents", "page-payments"}.intersection(ids)


def test_backend_serves_distinct_website_assets_and_legacy_portal_alias():
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert '@app.get("/organization"' in main
    assert '@app.get("/portal"' in main
    assert '@app.get("/console"' in main
    assert '_ORGANIZATION_PORTAL_HTML = _WEB_ROOT / "organization" / "index.html"' in main
    assert '_INTERNAL_CONSOLE_HTML = _WEB_ROOT / "internal" / "index.html"' in main


def test_docker_image_copies_both_separate_websites():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY web/ ./web/" in dockerfile
    assert "COPY paari_product_portal.html" not in dockerfile
