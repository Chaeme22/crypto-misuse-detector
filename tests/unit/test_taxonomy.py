"""
오용 분류(taxonomy)와 근거 레지스트리를 규칙표·지식베이스와 묶어 둔다.

파인튜닝 데이터의 라벨은 이 두 파일에서 온다. 규칙표의 CWE와 분류의 CWE가 어긋나거나,
인용문이 지식베이스 원문에 없는 문장이면 그 라벨은 믿을 수 없다. 사람이 손으로 고치는
파일이라 어긋나기 쉬워서 테스트로 지킨다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rag_app.analysis import rules

DATASET = Path("dataset")


@pytest.fixture(scope="module")
def taxonomy() -> dict:
    return json.loads((DATASET / "misuse_taxonomy.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry() -> list[dict]:
    lines = (DATASET / "evidence_registry.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def _normalize(text: str) -> str:
    return " ".join(text.split())


def test_every_rule_has_one_misuse_with_the_same_cwe(taxonomy, tier1):
    by_rule = {m["rule_id"]: m for m in taxonomy["misuses"]}
    assert len(by_rule) == len(taxonomy["misuses"]), "규칙 하나에 오용 유형 하나"
    for rule in tier1:
        misuse = by_rule.get(rule.rule_id)
        assert misuse is not None, f"{rule.rule_id}가 분류에 없다"
        assert misuse["cwe"] == rule.cwe, rule.rule_id
        assert misuse["severity"] == rule.level.value, rule.rule_id
    assert set(by_rule) == {r.rule_id for r in tier1}


def test_every_misuse_states_all_three_outcomes(taxonomy):
    """undetermined도 정답이다. 조건이 비어 있으면 그 판정을 라벨로 쓸 수 없다."""
    for misuse in taxonomy["misuses"]:
        for outcome in ("violation", "clean", "undetermined"):
            assert misuse["conditions"][outcome], f"{misuse['misuse_id']}: {outcome}"


def test_misuse_ids_are_unique(taxonomy):
    ids = [m["misuse_id"] for m in taxonomy["misuses"] + taxonomy["planned"]]
    assert len(ids) == len(set(ids))


def test_evidence_ids_are_unique(registry):
    ids = [r["evidence_id"] for r in registry]
    assert len(ids) == len(set(ids))


def test_evidence_supports_known_misuses(registry, taxonomy):
    known = {m["misuse_id"] for m in taxonomy["misuses"] + taxonomy["planned"]}
    for row in registry:
        assert row["misuse_ids"], row["evidence_id"]
        assert set(row["misuse_ids"]) <= known, row["evidence_id"]


def test_every_implemented_misuse_has_evidence(registry, taxonomy):
    covered = {m for row in registry for m in row["misuse_ids"]}
    for misuse in taxonomy["misuses"]:
        assert misuse["misuse_id"] in covered, misuse["misuse_id"]


def test_clause_quotes_exist_in_the_knowledge_base(registry):
    """인용문은 지식베이스 조각에 글자 그대로 있어야 한다. 지어낸 인용을 막는다."""
    for row in registry:
        if "#chunk_index=" not in (row["machine_source"] or ""):
            continue
        path, _, index = row["machine_source"].partition("#chunk_index=")
        chunks = json.loads(Path(path).read_text(encoding="utf-8"))["chunk_records"]
        content = next(c["content"] for c in chunks if c["chunk_index"] == int(index))
        assert _normalize(row["quote"]) in _normalize(content), row["evidence_id"]


def test_table_evidence_matches_threshold_sources(registry):
    """기준표 근거의 쪽수는 판정에 실제로 쓰는 기준표 행의 출처와 같아야 한다."""
    rows = json.loads(Path("config/tier1_thresholds.json").read_text(encoding="utf-8"))["rows"]
    pages: dict[str, set[int]] = {}
    for row in rows:
        pages.setdefault(row["source"]["table"], set()).add(row["source"]["page"])
    for row in registry:
        if row["table_id"]:
            expected = pages[row["quote"]]
            assert (row["page_start"], row["page_end"]) == (min(expected), max(expected))


def test_only_human_checked_evidence_is_verified(registry):
    """자동 추출한 조항을 검수된 것으로 표시하지 않는다."""
    for row in registry:
        if row["verified"]:
            assert row["table_id"], row["evidence_id"]
            assert row["verification_note"], row["evidence_id"]


def test_evidence_cwe_follows_the_taxonomy(registry, taxonomy):
    """근거의 CWE는 손으로 적지 않고 분류에서 온다. 어긋나면 라벨이 갈라진다."""
    cwe = {m["misuse_id"]: m["cwe"] for m in taxonomy["misuses"]}
    for row in registry:
        assert row["cwe_ids"] == sorted({cwe[m] for m in row["misuse_ids"]}), row["evidence_id"]


def test_every_evidence_names_a_clause_or_table(registry):
    """설계 6.1: clause_id나 table_id 중 하나는 있어야 원문 위치를 다시 찾을 수 있다."""
    for row in registry:
        assert row["clause_id"] or row["table_id"], row["evidence_id"]
