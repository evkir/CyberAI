from cyberai.agents.exploit.attack_metadata import (
    ExploitStatus,
    SeverityTier,
    enrich_all,
    enrich_attack_path,
)

CRITICAL_PATH = {
    "cve_id": "CVE-2024-1234",
    "attack_vector": "Network",
    "attack_complexity": "Low",
    "technique": "Remote code execution — low effort",
    "success_probability": 0.95,
    "requires_auth": False,
    "requires_interaction": False,
    "notes": "CVSS 9.8 | PoC: Yes",
    "cvss": 9.8,
}

LOW_PATH = {
    "cve_id": "CVE-2024-5678",
    "attack_vector": "Local",
    "attack_complexity": "High",
    "technique": "Local privilege escalation",
    "success_probability": 0.2,
    "requires_auth": True,
    "requires_interaction": True,
    "notes": "CVSS 4.0 | PoC: No",
    "cvss": 4.0,
}


def test_critical_severity_tier():
    meta = enrich_attack_path(CRITICAL_PATH)
    assert meta.severity_tier == SeverityTier.CRITICAL


def test_low_severity_tier():
    meta = enrich_attack_path(LOW_PATH)
    assert meta.severity_tier == SeverityTier.LOW


def test_weaponized_status():
    meta = enrich_attack_path(CRITICAL_PATH)
    assert meta.exploit_status == ExploitStatus.WEAPONIZED


def test_unconfirmed_status():
    meta = enrich_attack_path(LOW_PATH)
    assert meta.exploit_status == ExploitStatus.UNCONFIRMED


def test_mitre_id_rce():
    meta = enrich_attack_path(CRITICAL_PATH)
    assert meta.mitre_technique_id == "T1190"


def test_tags_critical():
    meta = enrich_attack_path(CRITICAL_PATH)
    assert "remote" in meta.tags
    assert "no-auth" in meta.tags
    assert "critical-prob" in meta.tags


def test_remediation_present():
    meta = enrich_attack_path(CRITICAL_PATH)
    assert len(meta.remediation) > 0


def test_to_dict_keys():
    meta = enrich_attack_path(CRITICAL_PATH)
    d = meta.to_dict()
    assert "severity_tier" in d
    assert "mitre_technique_id" in d
    assert "remediation" in d


def test_enrich_all():
    result = enrich_all([CRITICAL_PATH, LOW_PATH])
    assert len(result) == 2
