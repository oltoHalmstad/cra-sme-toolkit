"""Scan files intended for publication or sharing for secrets and personal data (rec. P1-05).

    python tools/redact_check.py examples experiments notebooks docs        # exit 1 on findings
    python tools/redact_check.py evidence/ --allow-email-domain mycompany.eu

Heuristic only: a clean result does not prove absence of sensitive data; a human must review
evidence bundles before sharing (docs/evidence-data-governance.md).
"""
import argparse
import re
import sys
from pathlib import Path

PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "password_assignment": re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key)['\"]?\s*[:=]\s*['\"]?[^\s'\"<>{}]{8,}"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}
DEFAULT_ALLOWED_EMAIL_DOMAINS = {"example.invalid", "example.com", "example.org", "anthropic.com"}
TEXT_SUFFIXES = {".json", ".md", ".txt", ".csv", ".yaml", ".yml", ".ipynb", ".sarif", ".py", ".sh", ".xml", ".html"}


def scan(paths, allowed_domains):
    hits = []
    for root in paths:
        root = Path(root)
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for f in files:
            if f.suffix.lower() not in TEXT_SUFFIXES or f.stat().st_size > 20_000_000:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            for name, rx in PATTERNS.items():
                for m in rx.finditer(text):
                    val = m.group(0)
                    if name == "email" and val.split("@")[1].lower() in allowed_domains:
                        continue
                    if name == "password_assignment" and ("REDACTED" in val or "REPLACE" in val.upper()):
                        continue
                    line = text.count("\n", 0, m.start()) + 1
                    hits.append((str(f), line, name, val[:6] + "…"))
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--allow-email-domain", action="append", default=[])
    a = ap.parse_args(argv)
    hits = scan(a.paths, DEFAULT_ALLOWED_EMAIL_DOMAINS | {d.lower() for d in a.allow_email_domain})
    for h in hits:
        print(f"{h[0]}:{h[1]}: {h[2]} ({h[3]})")
    print(f"{len(hits)} potential sensitive item(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
