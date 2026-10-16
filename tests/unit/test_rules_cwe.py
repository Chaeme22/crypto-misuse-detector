"""
규칙마다 CWE 하나를 고정한다.

규칙표와 가이드라인 색인이 서로 다른 번호를 적고 있었다. 난수는 330과 338, 하드코딩
키는 798과 321이었다. 더 큰 문제는 하드코딩 규칙 하나가 키·IV를 함께 잡고, 벤치마크
매핑에서는 비밀번호·솔트까지 떠안고 있었다는 점이다. 재료마다 CWE가 다르므로 한 규칙에
한 번호를 붙이면 어느 쪽이든 틀린다. 그래서 재료별로 규칙을 나눴다.

CWE는 가장 구체적인 하위 항목을 쓴다. 상위 항목(330, 798)은 분류 체계에서 관리한다.
"""

from __future__ import annotations

import pytest

from rag_app.analysis import rules

CANONICAL = {
    "CRYPTO-HASH-WEAK": "CWE-328",
    "CRYPTO-MODE-ECB": "CWE-327",
    "CRYPTO-CIPHER-OBSOLETE": "CWE-327",
    "CRYPTO-KEYSIZE-SHORT": "CWE-326",
    "CRYPTO-RNG-INSECURE": "CWE-338",
    "CRYPTO-SEED-PREDICTABLE": "CWE-337",
    "CRYPTO-KEY-HARDCODED": "CWE-321",
    "CRYPTO-IV-STATIC": "CWE-329",
    "CRYPTO-PASSWORD-HARDCODED": "CWE-259",
    "CRYPTO-SALT-STATIC": "CWE-760",
    "CRYPTO-KDF-WEAK": "CWE-916",
}


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def test_every_rule_has_its_canonical_cwe(tier1):
    assert {r.rule_id: r.cwe for r in tier1} == CANONICAL


def test_rule_ids_are_unique(tier1):
    ids = [r.rule_id for r in tier1]
    assert len(ids) == len(set(ids))


def test_material_args_name_known_triggers(tier1):
    """출처를 볼 인자는 그 규칙의 트리거에 있어야 판정기가 호출을 확인할 수 있다."""
    for rule in tier1:
        for trigger, _ in rule.material_args + rule.iteration_args:
            assert trigger in rule.api_triggers, f"{rule.rule_id}: {trigger}"


def test_iteration_rule_has_minimum(tier1):
    for rule in tier1:
        if rule.iteration_args:
            assert rule.min_iterations and rule.min_iterations > 0


def test_key_and_iv_are_separate_rules(tier1):
    """키를 잡는 규칙이 IV까지 잡으면 고정 IV가 하드코딩 키(CWE-321)로 보고된다."""
    key = rules.match_api("new SecretKeySpec", tier1)
    iv = rules.match_api("new IvParameterSpec", tier1)
    assert key is not None and key.rule_id == "CRYPTO-KEY-HARDCODED"
    assert iv is not None and iv.rule_id == "CRYPTO-IV-STATIC"
