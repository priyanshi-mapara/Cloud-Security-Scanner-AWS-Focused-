from pathlib import Path

from app.scanner.engine import ScannerEngine


DATA_DIR = Path("sample_data")


def test_s3_rules_trigger_multiple_findings():
    result = ScannerEngine().scan_file(DATA_DIR / "s3_bucket_public.json")
    assert result.summary.total_findings == 4


def test_iam_policy_wildcard_admin_detected():
    result = ScannerEngine().scan_file(DATA_DIR / "iam_policy_admin.json")
    assert any(f.finding_id.startswith("IAM-001") for f in result.findings)


def test_iam_user_mfa_and_key_rotation_checks():
    result = ScannerEngine().scan_file(DATA_DIR / "iam_user_legacy.json")
    ids = {f.finding_id.split(":")[0] for f in result.findings}
    assert "IAM-002" in ids
    assert "IAM-003" in ids


def test_security_group_open_ports_findings():
    result = ScannerEngine().scan_file(DATA_DIR / "security_group_open.json")
    ids = {f.finding_id.split(":")[0] for f in result.findings}
    assert {"EC2-001", "EC2-002", "EC2-003"}.issubset(ids)


def test_cloudtrail_rules_when_disabled():
    result = ScannerEngine().scan_file(DATA_DIR / "cloudtrail_disabled.json")
    ids = {f.finding_id.split(":")[0] for f in result.findings}
    assert "CT-001" in ids
    assert "CT-002" not in ids


def test_weighted_risk_score_is_computed():
    result = ScannerEngine().scan_directory(DATA_DIR)
    assert result.summary.weighted_risk_score > 0
    assert result.scanned_resources >= 8
