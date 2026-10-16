"""
학습 데이터 생성기가 지켜야 할 성질을 고정한다.

학습 데이터가 운영과 어긋나면 모델은 운영에서 본 적 없는 입력을 받는다. 그래서 프롬프트,
고르는 지점, 문맥이 모자랄 때의 정답을 운영 코드와 묶어 둔다.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from rag_app.analysis import rules
from rag_app.analysis.findings import Decision, Verdict
from rag_app.analysis.verdict import _parse, format_answer
from rag_app.dataset import build, templates

pytest.importorskip("jsonschema")
sys.path.insert(0, str(Path("tools").resolve()))
import validate_dataset  # noqa: E402


@pytest.fixture(scope="module")
def built():
    taxonomy = json.loads(Path("dataset/misuse_taxonomy.json").read_text(encoding="utf-8"))
    registry = [json.loads(l) for l in
                Path("dataset/evidence_registry.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()]
    samples = templates.generate()
    manifest, sft, skipped = build.build(samples, rules.load(), taxonomy, registry)
    return samples, manifest, sft, skipped


def _by_template(manifest, template_id):
    return [m for m in manifest if m["validation"]["notes"] == f"template {template_id}"]


def test_answer_format_round_trips_through_the_parser():
    """학습 정답은 운영 parser가 그대로 읽어야 한다."""
    verdict = Verdict(decision=Decision.VIOLATION, role="crypto_operation",
                      reasoning="키가 상수다.\n두 번째 줄", suggested_fix="난수로 만든다.")
    parsed = _parse(format_answer(verdict))
    assert parsed is not None
    assert parsed.decision is Decision.VIOLATION
    assert parsed.role == "crypto_operation"
    assert parsed.reasoning == "키가 상수다. 두 번째 줄"
    assert parsed.suggested_fix == "난수로 만든다."


def test_fix_is_empty_unless_violation():
    verdict = Verdict(decision=Decision.CLEAN, role="name_list", reasoning="목록이다.",
                      suggested_fix="무시돼야 한다")
    assert format_answer(verdict).endswith("fix: ")


def test_every_row_is_valid(built):
    _, manifest, sft, _ = built
    context = validate_dataset.load_context()
    assert manifest and len(manifest) == len(sft)
    for example in manifest:
        assert validate_dataset.check_example(example, context) == [], example["example_id"]
    for row in sft:
        assert validate_dataset.check_sft(row, context) == [], row["example_id"]


def test_build_is_deterministic(built):
    taxonomy = json.loads(Path("dataset/misuse_taxonomy.json").read_text(encoding="utf-8"))
    registry = [json.loads(l) for l in
                Path("dataset/evidence_registry.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()]
    again = build.build(templates.generate(), rules.load(), taxonomy, registry)
    assert again[0] == built[1] and again[1] == built[2]


def test_value_out_of_view_is_undetermined(built):
    """필드에 둔 상수는 메서드만 보면 보이지 않는다. 그때 정답은 판정 보류다."""
    _, manifest, _, _ = built
    rows = {m["context_depth_available"]: m
            for m in _by_template(manifest, "CRYPTO-KEY-HARDCODED-V0-field-N0-main")}
    assert rows[2]["decision"] == "violation"
    assert rows[1]["decision"] == "undetermined"
    assert rows[2]["context_depth_required"] == 2


def test_inline_constant_needs_no_more_than_the_statement(built):
    _, manifest, _, _ = built
    rows = _by_template(manifest, "CRYPTO-MODE-ECB-V0-inline-N0-main")
    assert {r["decision"] for r in rows} == {"violation"}
    assert all(r["context_depth_required"] == 0 for r in rows)


def test_parameter_from_outside_is_undetermined(built):
    _, manifest, _, _ = built
    rows = _by_template(manifest, "CRYPTO-IV-STATIC-V0-parameter-N0-main")
    assert rows and {r["decision"] for r in rows} == {"undetermined"}


def test_test_source_is_a_fixture(built):
    _, manifest, _, _ = built
    rows = _by_template(manifest, "CRYPTO-PASSWORD-HARDCODED-V0-inline-N0-test")
    assert rows and {(r["role"], r["decision"]) for r in rows} == {("test_fixture", "clean")}


def test_name_list_is_clean(built):
    _, manifest, _, _ = built
    rows = [m for m in manifest if m["role"] == "name_list"]
    assert rows and {r["decision"] for r in rows} == {"clean"}


def test_prompt_is_the_runtime_prompt(built):
    """학습 입력은 운영 판정 프롬프트와 같은 틀이다(같은 함수가 만든다)."""
    _, _, sft, _ = built
    for row in sft:
        user = row["messages"][0]["content"]
        assert user.startswith("당신은 코드를 읽고 암호 오용인지 판정한다.")
        assert "[사실]" in user and "아래 네 줄만 출력하라" in user


def test_examples_closed_by_structure_are_left_out(built):
    """SecureRandom이 만든 값처럼 운영에서 모델에게 묻지 않는 지점은 학습에 넣지 않는다."""
    _, manifest, _, skipped = built
    assert skipped
    assert all("secure_random" not in m["provenance"] for m in manifest)


def test_context_pairs_teach_purpose_not_api(built):
    """같은 API라도 보안 용도면 위반, 보안과 무관하면 정상이다. 파일럿에서 이 구분을 못 배웠다."""
    _, manifest, _, _ = built
    ctx = [m for m in manifest if "-CTX" in m["validation"]["notes"]
           and m["context_depth_available"] == 2]
    pairs = {(m["rule_id"], m["role"], m["decision"]) for m in ctx}
    for rule in ("CRYPTO-RNG-INSECURE", "CRYPTO-HASH-WEAK"):
        assert (rule, "crypto_operation", "violation") in pairs
        assert (rule, "non_security", "clean") in pairs


def test_context_pairs_are_split_by_lineage(built):
    """대조 쌍도 학습·검증·평가에 모두 들어가되 같은 묶음은 한쪽에만 간다."""
    sys.path.insert(0, str(Path("tools").resolve()))
    import build_dataset
    _, manifest, _, _ = built
    splits: dict[str, set[str]] = {}
    for m in manifest:
        if "-CTX" in m["validation"]["notes"]:
            splits.setdefault(m["lineage_group"], set()).add(build_dataset.split_of(m["lineage_group"]))
    assert all(len(s) == 1 for s in splits.values())
    assert {next(iter(s)) for s in splits.values()} == {"train", "validation", "test"}


def test_purpose_is_invisible_from_the_statement_alone(built):
    """`Random rnd = new Random();` 한 줄로는 쓰임새가 안 보인다. 그때 정답은 판정 보류다."""
    _, manifest, _, _ = built
    depth0 = [m for m in manifest if "-CTX" in m["validation"]["notes"]
              and m["context_depth_available"] == 0]
    assert depth0 and {m["decision"] for m in depth0} == {"undetermined"}
