"""
같은 입력에 같은 보고서가 나오는지 확인한다.

정적 분석 도구는 이 성질이 없으면 쓸 수 없다. CI에 붙였을 때 코드를 고치지 않았는데
보고서가 달라지면 어느 줄이 새 문제인지 알 수 없다. 그래서 diff로 비교할 수 있어야 한다.

여기서는 정적 판정 경로만 본다. 검색과 LLM을 포함한 경로는 모델을 올려야 해서
`python -m rag_app.cli analyze` 를 두 번 돌려 확인한다.
"""

from __future__ import annotations

import json
from pathlib import Path

from rag_app.analysis import pipeline, rules, sarif
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict

FIXTURES = Path("tests/fixtures/java").resolve()


def _run() -> str:
    state = pipeline.AnalysisState(target=str(FIXTURES), root=FIXTURES)
    state.rules = rules.load()
    state.thresholds = ThresholdTable.load()
    state = pipeline.extract_sites(state)
    state = pipeline.judge_sites(state, StaticVerdict(), None)
    document = sarif.build(state.findings, root=str(FIXTURES))
    return json.dumps(document, ensure_ascii=False, indent=2)


def test_same_input_same_report():
    assert _run() == _run()


def test_results_are_sorted_deterministically():
    """정렬 키가 모든 항목에서 유일해야 순서가 흔들리지 않는다."""
    results = json.loads(_run())["runs"][0]["results"]
    keys = [(r["level"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
             r["locations"][0]["physicalLocation"]["region"]["startLine"], r["ruleId"])
            for r in results]
    assert len(set(keys)) == len(keys)


def test_measurement_recorded_for_table_rules():
    """표가 답하는 규칙에는 대조 결과가 남아야 한다. 없으면 근거 없이 보고한 것이다."""
    results = json.loads(_run())["runs"][0]["results"]
    measured = {"CRYPTO-HASH-WEAK", "CRYPTO-CIPHER-OBSOLETE", "CRYPTO-KEYSIZE-SHORT"}
    for result in results:
        if result["ruleId"] in measured:
            check = result["properties"]["tableCheck"]
            assert check is not None, result["ruleId"]
            assert check["found"] and check["requirement"]


def test_compliant_key_size_is_not_reported():
    """RSA-4096은 표 기준을 만족하므로 보고서에 없어야 한다."""
    text = _run()
    assert "4096" not in text
