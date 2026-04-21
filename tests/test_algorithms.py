from pqc_scan.algorithms import ALGORITHMS, CATEGORY_DESCRIPTIONS
from pqc_scan.findings import Severity


def test_every_algorithm_has_known_category():
    for alg in ALGORITHMS.values():
        assert alg.category in CATEGORY_DESCRIPTIONS, alg


def test_severities_are_enum():
    for alg in ALGORITHMS.values():
        assert isinstance(alg.severity, Severity)


def test_id_matches_registry_key():
    for key, alg in ALGORITHMS.items():
        assert key == alg.id


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank
    assert Severity.LOW.rank > Severity.INFO.rank
