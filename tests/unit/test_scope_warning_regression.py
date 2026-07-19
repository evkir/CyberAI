from cyberai.agents.exploit.safety_validator import validate_exploit_scope


def test_in_scope_target_no_false_warning():
    v = validate_exploit_scope("scanme.nmap.org", ["scanme.nmap.org"], [])
    assert v.passed
    assert not any("No authorized_scope" in w for w in v.warnings)


def test_empty_scope_still_warns():
    v = validate_exploit_scope("scanme.nmap.org", [], [])
    assert any("No authorized_scope" in w for w in v.warnings)


def test_out_of_scope_target_violation():
    v = validate_exploit_scope("evil.example.com", ["scanme.nmap.org"], [])
    assert not v.passed
    assert any("NOT in authorized scope" in x for x in v.violations)
