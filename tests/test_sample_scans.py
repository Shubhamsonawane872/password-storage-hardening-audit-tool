"""Representative sample scans, stable output, and multi-file archive behavior."""
import io
import zipfile
from pathlib import Path

from app.scanner.patterns import CodeScanner
from app.scanner.rules import get_rule
from app.scoring import ComprehensiveScorer


SAMPLES = {
    "plaintext_password.py": ({"PWD001"}, 70, "C"),
    "md5_only.py": ({"PWD002"}, 80, "B"),
    "sha1_only.py": ({"PWD003"}, 80, "B"),
    "unsalted_sha256.py": ({"PWD005"}, 80, "B"),
    "hardcoded_secret.py": ({"PWD004"}, 80, "B"),
    "safe_hashing.py": ({"PWD007"}, 100, "A"),
    "comment_only.py": (set(), 100, "A"),
    "irrelevant.py": (set(), 100, "A"),
}


def test_sample_files_have_expected_rule_sets_and_grades():
    scanner = CodeScanner()
    scorer = ComprehensiveScorer()
    for filename, (expected_rules, expected_score, expected_grade) in SAMPLES.items():
        content = (Path("sample_apps") / filename).read_text(encoding="utf-8")
        raw = scanner.scan_file(filename, content)
        rules = {finding["rule_id"] for finding in raw}
        scoring_input = [
            {"rule_id": finding["rule_id"], "severity": get_rule(finding["rule_id"])["severity"]}
            for finding in raw
        ]
        summary = scorer.score_all(scoring_input)["scan_summary"]
        assert rules == expected_rules, filename
        assert (summary["overall_score"], summary["grade"]) == (expected_score, expected_grade), filename


def test_scanning_same_sample_twice_is_deterministic():
    path = Path("sample_apps/vulnerable_sample.py")
    scanner = CodeScanner()
    content = path.read_text(encoding="utf-8")
    assert scanner.scan_file(path.name, content) == scanner.scan_file(path.name, content)


def test_zip_scan_keeps_findings_separated_by_source_file(auth_client):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("first.py", "import hashlib\nh = hashlib.md5(password.encode()).hexdigest()\n")
        zipped.writestr("second.py", "import hashlib\nh = hashlib.sha1(password.encode()).hexdigest()\n")
    archive.seek(0)
    response = auth_client.post(
        "/api/scanner/upload",
        data={"file": (archive, "two_sources.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200, response.get_json()
    scan_id = response.get_json()["scan_id"]
    detail = auth_client.get(f"/api/scanner/scan/{scan_id}").get_json()
    assert {finding["file_name"] for finding in detail["findings"]} == {"first.py", "second.py"}
    assert {finding["rule_id"] for finding in detail["findings"]} == {"PWD002", "PWD003"}


def test_zip_path_traversal_is_rejected(auth_client):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../outside.py", "password = 'not stored'\n")
    archive.seek(0)
    response = auth_client.post(
        "/api/scanner/upload",
        data={"file": (archive, "traversal.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "path traversal" in response.get_json()["detail"].lower()


def test_zip_with_only_empty_source_files_is_rejected(auth_client):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("empty.py", "")
    archive.seek(0)
    response = auth_client.post(
        "/api/scanner/upload",
        data={"file": (archive, "empty_source.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "no readable supported" in response.get_json()["detail"].lower()


def test_uploaded_file_is_removed_after_scan(auth_client, tmp_path, monkeypatch):
    import app.scanner.routes as scanner_routes

    upload_dir = tmp_path / "single-scan-temp"
    def make_temp_dir(prefix):
        upload_dir.mkdir()
        return str(upload_dir)
    monkeypatch.setattr(scanner_routes.tempfile, "mkdtemp", make_temp_dir)
    response = auth_client.post(
        "/api/scanner/upload",
        data={"file": (io.BytesIO(b"import hashlib\nh = hashlib.md5(password)\n"), "upload.py")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200, response.get_json()
    assert not upload_dir.exists()
