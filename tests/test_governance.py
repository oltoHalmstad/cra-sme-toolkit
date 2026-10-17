import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "tools"))
import redact_check  # noqa: E402

PUBLISHABLE = ["examples", "experiments", "notebooks", "docs", "comparison", "templates", "data"]


def test_publishable_folders_have_no_secrets_or_emails():
    hits = redact_check.scan([ROOT / p for p in PUBLISHABLE], redact_check.DEFAULT_ALLOWED_EMAIL_DOMAINS)
    assert hits == [], hits


def test_detector_finds_planted_secrets(tmp_path):
    f = tmp_path / "e.json"
    f.write_text('{"k": "AKIA' + "ABCDEFGHIJKLMNOP" + '", "mail": "jane.doe@corp.eu", "password": "hunter2hunter2"}')
    kinds = {h[2] for h in redact_check.scan([tmp_path], redact_check.DEFAULT_ALLOWED_EMAIL_DOMAINS)}
    assert {"aws_access_key", "email", "password_assignment"} <= kinds
    assert redact_check.main([str(tmp_path)]) == 1


def test_allowed_domains_and_redacted_values_pass(tmp_path):
    f = tmp_path / "ok.md"
    f.write_text("security@example.invalid  password: ***REDACTED***")
    assert redact_check.main([str(tmp_path)]) == 0
