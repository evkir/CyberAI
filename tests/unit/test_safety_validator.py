from cyberai.agents.exploit.safety_validator import (
    _target_in_scope,
    validate_exploit_scope,
)


def test_valid_public_ip_no_scope():
    result = validate_exploit_scope("93.184.216.34", [])
    assert result.passed
    assert len(result.violations) == 0


def test_private_ip_blocked():
    result = validate_exploit_scope("192.168.1.1", [])
    assert not result.passed
    assert any("protected range" in v for v in result.violations)


def test_loopback_blocked():
    result = validate_exploit_scope("127.0.0.1", [])
    assert not result.passed


def test_target_in_cidr_scope():
    result = validate_exploit_scope("10.10.10.5", ["10.10.10.0/24"])
    assert result.passed


def test_target_not_in_scope():
    result = validate_exploit_scope("93.184.216.34", ["10.0.0.0/8"])
    assert not result.passed
    assert any("NOT in authorized scope" in v for v in result.violations)


def test_hostname_in_scope():
    result = validate_exploit_scope("target.example.com", ["target.example.com"])
    assert result.passed


def test_wildcard_scope():
    assert _target_in_scope("sub.example.com", ["*.example.com"])
    assert not _target_in_scope("example.com", ["*.example.com"])


def test_high_risk_technique_warning():
    paths = [
        {
            "cve_id": "CVE-2024-1234",
            "technique": "Remote code execution — low effort",
            "success_probability": 0.5,
        }
    ]
    result = validate_exploit_scope("93.184.216.34", [], paths)
    assert any("High-risk" in w for w in result.warnings)


def test_high_probability_warning():
    paths = [
        {
            "cve_id": "CVE-2024-9999",
            "technique": "Buffer overflow",
            "success_probability": 0.95,
        }
    ]
    result = validate_exploit_scope("93.184.216.34", [], paths)
    assert any("95%" in w or "Very high" in w for w in result.warnings)


def test_validation_result_bool():
    result = validate_exploit_scope("93.184.216.34", [])
    assert bool(result) is True


# ── URL targets ───────────────────────────────────────────────────────
# Every web run reaches this validator as a URL, and the checks below all
# compare bare hosts. Until these cases existed the exploit phase aborted on
# any http:// target and no unit test noticed, because none of them passed a
# URL in.


def test_url_target_matches_bare_host_scope():
    assert validate_exploit_scope("http://10.10.10.5:3000", ["10.10.10.5"]).passed


def test_url_with_path_matches_wildcard_scope():
    assert validate_exploit_scope("https://sub.acme.com:8443/app?x=1", ["*.acme.com"]).passed


def test_url_target_still_hits_protected_range_check():
    result = validate_exploit_scope("http://192.168.1.1:8080", [])
    assert not result.passed
    assert any("protected range" in v for v in result.violations)


def test_violation_quotes_the_target_as_typed():
    result = validate_exploit_scope("http://10.10.10.5:3000", ["example.com"])
    assert any("http://10.10.10.5:3000" in v for v in result.violations)


def test_bare_host_scope_matching_unchanged():
    assert _target_in_scope("sub.example.com", ["*.example.com"])
    assert not _target_in_scope("example.com", ["*.example.com"])
