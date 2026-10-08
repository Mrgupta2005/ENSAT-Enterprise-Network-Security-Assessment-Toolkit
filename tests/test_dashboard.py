"""Render every dashboard page against a seeded database (no browser needed)."""
from pathlib import Path

import pytest
from test_pipeline_db import FakeIntel, fake_scanner

from ensat.config import settings
from ensat.db import Database
from ensat.models import ScanOptions
from ensat.pipeline import assess

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
from streamlit.testing.v1 import app_test as _app_test  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "ensat" / "dashboard" / "app.py")
PAGES = ["overview", "scan", "findings", "assets", "services", "cves", "history", "reports", "settings"]


@pytest.fixture(scope="module")
def seeded():
    db = Database(settings.db_path)
    xml = (Path(__file__).parent / "fixtures" / "nmap_lab.xml").read_text(encoding="utf-8")
    for _ in range(2):
        assess(ScanOptions(target="192.168.56.0/30", authorized_by="tester", tls_checks=False, web_checks=False),
               settings, db, intel=FakeIntel(), scanner=fake_scanner(xml))
    return db


def open_page(page: str) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    at._page_hash = _app_test.calc_hash(page)  # st.navigation pages are keyed by url_path
    return at.run()


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(seeded, page):
    at = open_page(page)
    assert not at.exception, [e.message for e in at.exception]
    assert at.title, f"{page} rendered no title"


def test_overview_kpis(seeded):
    at = open_page("overview")
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Assets"] == "2" and int(metrics["Critical"]) >= 1


def test_scan_form_validates_target(seeded):
    at = open_page("scan")
    at.text_input[0].input("10.0.0.1; rm -rf /")
    at.button[0].click().run()
    assert any("Invalid characters" in e.value or "Unrecognised target" in e.value for e in at.error)


def test_scan_form_requires_authorization(seeded):
    at = open_page("scan")
    at.text_input[0].input("203.0.113.5")
    at.button[0].click().run()
    assert any("authorized scope" in e.value for e in at.error)
