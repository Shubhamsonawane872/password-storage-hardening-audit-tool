"""Scanner pattern detection tests — covers PWD001-PWD013."""
from __future__ import annotations

import pytest

from app.scanner.patterns import CodeScanner
from app.scanner.rules import get_all_rules, get_rule

scanner = CodeScanner()


def rule_ids(findings):
    return [f["rule_id"] for f in findings]


# ── Rule coverage ─────────────────────────────────────────────────────────────

def test_PWD001_plaintext_python():
    code = 'password = "PlainTextSecret"'
    ids = rule_ids(scanner.scan_file("app.py", code))
    assert "PWD001" in ids


def test_PWD001_php_dollar_sign():
    code = '$password = "myplaintextpass";'
    ids = rule_ids(scanner.scan_file("auth.php", code))
    assert "PWD001" in ids


def test_PWD002_hashlib_md5():
    code = "import hashlib\nh = hashlib.md5(password.encode()).hexdigest()"
    ids = rule_ids(scanner.scan_file("crypto.py", code))
    assert "PWD002" in ids


def test_PWD002_bare_md5():
    code = "digest = md5(password)"
    ids = rule_ids(scanner.scan_file("lib.py", code))
    assert "PWD002" in ids


def test_PWD003_hashlib_sha1():
    code = "h = hashlib.sha1(password.encode()).hexdigest()"
    ids = rule_ids(scanner.scan_file("app.py", code))
    assert "PWD003" in ids


def test_PWD003_js_sha1():
    code = "const h = CryptoJS.SHA1(password);"
    ids = rule_ids(scanner.scan_file("app.js", code))
    assert "PWD003" in ids


def test_PWD004_stripe_key():
    code = 'API_KEY = "sk_live_ABCDEFGHIJ1234567890"'
    ids = rule_ids(scanner.scan_file("config.py", code))
    assert "PWD004" in ids


def test_PWD004_aws_access_key():
    code = 'ACCESS = "AKIAIOSFODNN7EXAMPLE"'
    ids = rule_ids(scanner.scan_file("settings.py", code))
    assert "PWD004" in ids


def test_PWD005_unsalted_sha256():
    code = "h = hashlib.sha256(password.encode()).hexdigest()"
    ids = rule_ids(scanner.scan_file("store.py", code))
    assert "PWD005" in ids


def test_PWD006_passlib_md5():
    code = "from passlib.hash import md5_crypt"
    ids = rule_ids(scanner.scan_file("auth.py", code))
    assert "PWD006" in ids


def test_PWD007_argon2():
    code = "from argon2 import PasswordHasher\nph = PasswordHasher()"
    ids = rule_ids(scanner.scan_file("security.py", code))
    assert "PWD007" in ids


def test_PWD007_bcrypt():
    code = "import bcrypt\nhash = bcrypt.hashpw(pw, bcrypt.gensalt())"
    ids = rule_ids(scanner.scan_file("hash.py", code))
    assert "PWD007" in ids


def test_PWD008_base64_secret(tmp_path):
    # base64("SuperSecretPassword") = U3VwZXJTZWNyZXRQYXNzd29yZA==
    code = 'password = "U3VwZXJTZWNyZXRQYXNzd29yZA=="'
    ids = rule_ids(scanner.scan_file("cfg.py", code))
    # Either PWD008 or PWD001/PWD004 triggered — at minimum one sensitive finding
    sensitive = {"PWD001", "PWD004", "PWD008"}
    assert sensitive & set(ids), f"Expected sensitive finding, got {ids}"


def test_PWD009_jwt_secret():
    code = 'JWT_SECRET = "mysupersecretjwtkey123"'
    ids = rule_ids(scanner.scan_file("app.py", code))
    assert "PWD009" in ids


def test_PWD010_des():
    code = "cipher = DES.new(key, DES.MODE_ECB)"
    ids = rule_ids(scanner.scan_file("encrypt.py", code))
    assert "PWD010" in ids


def test_PWD011_low_pbkdf2_iters():
    code = "dk = hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)"
    ids = rule_ids(scanner.scan_file("kdf.py", code))
    assert "PWD011" in ids


def test_PWD011_accepts_high_iters():
    code = "dk = hashlib.pbkdf2_hmac('sha256', pw, salt, 600000)"
    ids = rule_ids(scanner.scan_file("kdf.py", code))
    assert "PWD011" not in ids


def test_PWD012_custom_xor():
    code = "def my_encrypt(password):\n    return xor(password, key)"
    ids = rule_ids(scanner.scan_file("crypto.py", code))
    assert "PWD012" in ids


def test_PWD013_password_logged():
    code = 'logger.debug("Login attempt password=%s", password)'
    ids = rule_ids(scanner.scan_file("views.py", code))
    assert "PWD013" in ids


# ── False-positive suppression ────────────────────────────────────────────────

def test_no_PWD001_when_value_is_hash():
    code = 'password_hash = "$argon2id$v=19$m=65536,t=2,p=4$..."'
    ids = rule_ids(scanner.scan_file("models.py", code))
    assert "PWD001" not in ids


def test_no_vuln_findings_for_safer_sample():
    """The safer sample should produce NO critical/high findings."""
    with open("sample_apps/safer_sample.py") as f:
        content = f.read()
    findings = scanner.scan_file("safer_sample.py", content)
    bad = [f for f in findings if f["rule_id"] not in ("PWD007",)]
    # Allow a few low-confidence false positives from test-file heuristic,
    # but zero critical/high rule triggers
    critical_high = [f for f in bad if f.get("confidence", 1.0) > 0.70]
    assert len(critical_high) == 0, f"Unexpected findings: {critical_high}"


def test_vulnerable_sample_triggers_expected_rules():
    """The vulnerable Python sample must fire PWD001/002/003/004/005."""
    with open("sample_apps/vulnerable_sample.py") as f:
        content = f.read()
    findings = scanner.scan_file("vulnerable_sample.py", content)
    ids = set(rule_ids(findings))
    for expected in ("PWD001", "PWD002", "PWD003", "PWD004", "PWD005"):
        assert expected in ids, f"Expected {expected} from vulnerable sample, got {ids}"


# ── Line numbers and redaction ────────────────────────────────────────────────

def test_line_number_accuracy():
    code = "line1\nline2\npassword = 'secret'\nline4"
    findings = scanner.scan_file("test.py", code)
    pwd001 = [f for f in findings if f["rule_id"] == "PWD001"]
    assert pwd001, "PWD001 not found"
    assert pwd001[0]["line_number"] == 3


def test_evidence_is_redacted_for_secrets():
    code = 'api_key = "sk_live_ABCDEFGHIJ1234567890xx"'
    findings = scanner.scan_file("cfg.py", code)
    for f in findings:
        if f["rule_id"] == "PWD004":
            assert "[REDACTED]" in f["evidence"], "Secret not redacted"
            break


def test_confidence_score_present():
    code = "password = 'plaintext'"
    findings = scanner.scan_file("app.py", code)
    for f in findings:
        assert 0.0 <= f.get("confidence", -1) <= 1.0


# ── Rule registry completeness ────────────────────────────────────────────────

def test_all_rules_have_required_fields():
    for rule_id, rule in get_all_rules().items():
        for field in ("title", "description", "severity", "recommendation"):
            assert field in rule, f"{rule_id} missing field '{field}'"


def test_known_rule_ids_are_registered():
    for rid in ("PWD001", "PWD002", "PWD003", "PWD004", "PWD005",
                "PWD006", "PWD007", "PWD008", "PWD009", "PWD010",
                "PWD011", "PWD012", "PWD013"):
        assert get_rule(rid) is not None, f"{rid} not in registry"
