"""
SARIF 2.1.0 직렬화.

LLM에게 이 문서를 쓰게 하지 않는다. 스키마 준수가 확률적이고, 같은 코드에 다른 보고서가
나오면 정적 분석 도구로 쓸 수 없다. 위치와 규칙 번호는 이미 정확히 아는 값이므로 옮겨 적게
할 이유도 없다. 그래서 여기서 결정적으로 만든다.

같은 입력에 같은 바이트가 나오도록 정렬 순서를 고정한다. 보고서를 diff로 비교해 회귀를
잡을 수 있어야 한다.
"""

from __future__ import annotations

import json
from pathlib import Path

from .findings import Decision, Finding, Rule

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
VERSION = "2.1.0"
TOOL_NAME = "CryptoMisuse-OSS"


def _rule_object(rule: Rule) -> dict:
    """SARIF `reportingDescriptor`. 규칙 메타데이터는 규칙표에서 그대로 온다."""
    return {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.summary},
        "fullDescription": {"text": rule.detail},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": rule.level.value},
        "properties": {
            "tags": ["security", "cryptography", rule.cwe],
            "cwe": rule.cwe,
        },
    }


def _level_of(finding: Finding) -> str:
    """
    보고 심각도. 규칙이 상한을 정하고 표 대조 결과가 낮춘다.

    `RSA 2048비트`는 지금 기준을 만족하고 2030년에 만료된다. 규칙만 보면 키 길이 규칙의
    error가 되는데, 오늘 고쳐야 하는 `RSA 1024비트`와 같은 줄에 놓으면 둘 다 안 읽힌다.
    """
    if finding.verdict.needs_human:
        return "note"
    measurement = finding.measurement
    if measurement is not None and measurement.outcome.value == "expiring":
        return "note"
    return finding.rule.level.value


def _result_object(finding: Finding) -> dict:
    """SARIF `result`. 위치는 정적 추출 값을 그대로 쓴다."""
    site = finding.site
    # 미결은 사람이 확인할 항목이다. SARIF에 그 뜻을 담는 자리가 있다(kind=review).
    # 실패로 보고하면 오탐이 되고, 빼버리면 검사에서 빠진 자리를 아무도 모른다.
    undetermined = finding.verdict.needs_human
    result = {
        "ruleId": finding.rule.rule_id,
        "kind": "review" if undetermined else "fail",
        "level": _level_of(finding),
        "message": {"text": finding.message()},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": site.file_path},
                "region": {"startLine": site.line, "startColumn": site.column},
            },
        }],
        "properties": {
            # 확신도 숫자는 싣지 않는다. 대신 판정을 뒷받침하는 사실을 남긴다. 검토자는
            # "값이 확정됐고 근거가 검수된 조항인가"만 보면 고칠지 볼지 정할 수 있다.
            "valueResolved": finding.value_resolved,
            "evidenceReviewed": finding.evidence_reviewed,
            "api": site.api,
            # 표 대조 결과. 어느 표의 몇 쪽과 견줬는지까지 남긴다. 사람이 숫자를
            # 되짚을 수 있어야 판정을 신뢰할 수 있다.
            "tableCheck": ({
                "outcome": finding.measurement.outcome.value,
                "purpose": finding.measurement.purpose,
                "found": finding.measurement.found,
                "requirement": finding.measurement.requirement,
            } if finding.measurement is not None else None),
            # 모델이 이 코드의 역할을 무엇으로 봤는지. 오탐을 추적할 때 판단 경로가 된다.
            "codeRole": finding.verdict.role,
            "decision": finding.verdict.decision.value,
            # 값을 못 찾은 인자와 따라가서 찾은 값. 사람이 확인할 때 출발점이 된다.
            "unresolvedArgs": list(site.unresolved_args),
            "tracedValues": list(site.traced_values),
            # 인용을 구조로도 남긴다. 사람이 읽는 message와 별개로 기계가 추적할 수 있어야
            # 한다. 어느 판독에서 나온 조항인지(needs_review)까지 남긴다.
            "citations": [
                {
                    "document": c.document,
                    "page": c.page,
                    "sectionPath": list(c.section_path),
                    "quote": c.quote,
                    "needsReview": c.needs_review,
                }
                for c in finding.citations
            ],
        },
    }
    if site.snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": site.snippet}
    return result


def build(findings: list[Finding], root: str, tool_version: str = "0.1.0",
          provenance: dict | None = None,
          dependencies: list[dict] | None = None) -> dict:
    """
    판정 목록을 SARIF 문서로 만든다.

    위반과 미결을 함께 넣는다. 미결은 `kind=review`로 구분한다. 위반이 아니라고 판정한
    것만 뺀다. 미결을 빼면 판정하지 못한 자리가 보고서에서 사라져, 검사했다는 착각을 준다.
    """
    confirmed = [f for f in findings if f.verdict.decision is not Decision.CLEAN]
    # 정렬은 결정적이어야 한다. 같은 입력에 같은 보고서가 나와야 diff로 회귀를 잡는다.
    # 확신도 숫자가 없으니 심각도와 근거 완전성으로 줄을 세운다. 바로 고칠 수 있는 건이
    # 위로, 사람이 확인해야 하는 건이 아래로 간다.
    level_order = {"error": 0, "warning": 1, "note": 2, "none": 3}
    confirmed.sort(key=lambda f: (
        level_order.get(_level_of(f), 9),
        0 if f.verdict.decision is Decision.VIOLATION else 1,
        0 if (f.value_resolved and f.evidence_reviewed) else 1,
        f.site.file_path, f.site.line, f.rule.rule_id))

    rules = {f.rule.rule_id: f.rule for f in confirmed}
    run: dict = {
        "tool": {"driver": {
            "name": TOOL_NAME,
            "version": tool_version,
            "informationUri": "https://github.com/",
            "rules": [_rule_object(rules[key]) for key in sorted(rules)],
        }},
        "originalUriBaseIds": {"SRCROOT": {"uri": Path(root).as_uri() + "/"}},
        "results": [_result_object(f) for f in confirmed],
    }
    # 어느 커밋을 검사했는지. SARIF 표준이 이 자리를 정의한다. 실행 시각은 넣지 않는다.
    # 같은 입력에 같은 바이트가 나와야 하고, 커밋 해시가 이미 시점을 고정한다.
    if provenance:
        run["versionControlProvenance"] = [provenance]
    # 선언된 의존성. 보고서만 보고도 이 프로젝트가 어떤 암호 라이브러리를 쓰는지
    # 알 수 있어야 한다. 전이 의존성은 빌드를 돌려야 나오므로 여기서 다루지 않는다.
    if dependencies:
        run["properties"] = {"declaredDependencies": dependencies}
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [run],
    }


def write(findings: list[Finding], root: str, out_path: Path,
          tool_version: str = "0.1.0", provenance: dict | None = None,
          dependencies: list[dict] | None = None) -> dict:
    document = build(findings, root, tool_version, provenance, dependencies)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    return document
