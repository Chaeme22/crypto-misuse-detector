"""
판정 제공자.

LLM은 이 인터페이스 뒤에 있다. 모델을 바꿔도 파이프라인이 그대로 돌아야 하므로, 오가는
것을 `UsageSite`·`Rule`·`Citation` 입력과 `Verdict` 출력으로 못 박는다. LLM이 위치나
규칙 번호를 만들어내지 않는다는 점이 핵심이다. 그건 이미 아는 값이다.

`StaticVerdict`는 LLM 없이 도는 대조군이다. 호출을 실제로 한 자리만 위반으로 보고,
문자열 리터럴만 걸린 자리는 판정을 보류한다. 알고리즘 이름이 적힌 목록과 실제 사용을
정적 신호만으로 가릴 수 없기 때문이다. 적게 보고하는 쪽으로 틀린다.
"""

from __future__ import annotations

import json
import re
from typing import Protocol, runtime_checkable

from ..observability.logging import get_logger
from . import provenance
from .findings import Citation, Decision, Rule, UsageSite, Verdict

logger = get_logger(__name__)


@runtime_checkable
class VerdictProvider(Protocol):
    """사용 지점 하나를 판정한다."""

    name: str

    def judge(self, site: UsageSite, rule: Rule,
              citations: tuple[Citation, ...],
              measurement=None) -> Verdict:
        ...


class StaticVerdict:
    """
    LLM 없이 정적 신호와 표 대조만으로 판정한다. 대조군이자 LLM이 없을 때의 기본값이다.

    표가 답을 주는 규칙에서는 이 경로만으로도 판정이 선다. `RSA 1024비트`는 표와
    견줘 미달이 계산되므로 모델에게 물을 것이 없다. 남는 것은 그 코드가 무엇에 쓰이는지고
    그건 여기서 답하지 않는다.
    """

    name = "static"

    def judge(self, site: UsageSite, rule: Rule,
              citations: tuple[Citation, ...],
              measurement=None) -> Verdict:
        # 표 대조가 결론을 냈고 그 규칙의 질문이 표로 끝나면 그 결과를 그대로 쓴다.
        if (measurement is not None and rule.table_decides
                and measurement.outcome.value in ("below", "not_listed")):
            return Verdict(decision=Decision.VIOLATION,
                           reasoning=measurement.sentence(),
                           suggested_fix=rule.remediation,
                           role="표 대조로 확정")

        # 호출 이름으로 본다. `site.api`는 리터럴까지 담은 사람용 표기라 비교에 쓰지
        # 않는다. `MessageDigest.getInstance("MD5")`는 어느 트리거와도 같지 않다.
        called = site.call in rule.api_triggers or site.api in rule.api_triggers
        if not called:
            return Verdict(
                decision=Decision.UNDETERMINED,
                reasoning=(f"문자열 `{site.api}`만 발견했다. 알고리즘 이름이 적힌 목록인지 "
                           f"실제 사용인지 정적 신호로는 가릴 수 없어 판정을 보류한다."),
                role="unknown",
            )
        # 출처를 판별한 자리는 그 사실이 판정 근거다. 호출만 보고 위반이라 하지 않는다.
        # 위반 출처가 아니면 여기서 보류한다. enforce가 다시 막지만 거기에만 기대지 않는다.
        if site.provenance and site.provenance not in provenance.VIOLATING:
            return Verdict(decision=Decision.UNDETERMINED,
                           reasoning=(f"{site.provenance_note}. 출처가 확정되지 않아 "
                                      f"판정을 보류한다."),
                           role="unknown")
        if site.provenance:
            return Verdict(
                decision=Decision.VIOLATION,
                reasoning=f"{site.provenance_note}. {rule.summary}에 해당한다.",
                suggested_fix=rule.remediation,
            )
        return Verdict(
            decision=Decision.VIOLATION,
            reasoning=(f"`{site.api}` 호출을 확인했다. {rule.summary}에 해당한다. "
                       f"호출 자체는 확실하나 용도(보안 통제인지 단순 지문인지)는 "
                       f"코드 문맥을 읽어야 확정된다."),
            suggested_fix=rule.remediation,
        )


PROMPT = """당신은 코드를 읽고 암호 오용인지 판정한다. 규칙이 걸렸다는 것은 후보라는
뜻일 뿐이다. **후보 대부분은 위반이 아니다.** 이름이 언급된 것과 실제로 쓰인 것을 가리는 것이
당신의 일이다.

[걸린 규칙]
{rule_id} ({cwe}) — {summary}
{detail}

[참고 조항]
{clauses}

[코드] {file_path}, 화살표(>)가 걸린 줄이다. 호출/문자열: `{api}`
```
{context}
```

[사실] 이 값들은 우리가 코드에서 확인하고 표준문서 표와 견준 것이다. 추측으로 뒤집지 마라.
{value_note}
{test_note}
{table_note}

키 길이나 보안강도가 충분한지는 이미 위에 계산돼 있다. 기억으로 다시 계산하지 마라.
당신이 답할 것은 이 코드가 무엇에 쓰이는지다.

먼저 화살표 줄의 역할을 아래 중 하나로 정하라.
- crypto_operation: 실제로 암호 연산이나 보안 통제를 수행한다.
- name_list: 알고리즘 이름을 담은 목록·집합·상수 배열이다. 문자열 검사나 사전 용도다.
- config_value: 설정 값으로 알고리즘을 지정한다. 그 설정이 실제로 쓰이면 위반이다.
- test_fixture: 테스트 데이터나 더미 값이다.
- documentation: 주석, 문서 문자열, 설명문이다.
- non_security: 실제로 실행되지만 보안과 무관한 용도다. 셔플·표본추출·지터·통계용 난수,
  캐시 키·중복 제거·파일 식별용 해시처럼 결과가 비밀이나 인증을 지키지 않는다.

그다음 판정하라. 답은 셋이다.
- violation: 위반이다.
- clean: 위반이 아니다.
- undetermined: **판정에 필요한 값을 위 코드에서 확인할 수 없다.** 값 확인 결과가 "못
  찾았다"이면 이것을 골라라. 보이지 않는 값을 주변 코드에서 추측하지 마라. 모른다고 답하는
  것이 지어낸 답보다 낫다.

`crypto_operation`과 `config_value`만 위반이 될 수 있다. `name_list`, `test_fixture`,
`documentation`, `non_security`는 위반이 아니다. 테스트 소스인지는 아래 [사실]에 적혀 있으니
경로를 보고 추측하지 마라. 코드가 무엇을 하는지만 보라. 규칙 설명을 되풀이하지 마라.

아래 네 줄만 출력하라. 다른 말은 쓰지 마라. 값에 따옴표를 써도 된다.
role: 위 여섯 중 하나
decision: violation 또는 clean 또는 undetermined
reasoning: 이 코드가 무엇을 하는지 근거로 두세 문장, 한 줄로
fix: 위반일 때만 고치는 방법 한 문장, 아니면 비워라"""


class LlmVerdict:
    """
    LLM에게 판정만 시킨다.

    SARIF 문서를 쓰게 하지 않는다. 스키마 준수가 확률적이고 위치와 규칙 번호는 이미 아는
    값이라 옮겨 적게 하면 틀린다. 그래서 받는 것은 판정 네 가지뿐이고, 규격을 어기면
    한 번 다시 시키고 그래도 어기면 보류로 떨어뜨린다.
    """

    name = "llm"

    def __init__(self, model, max_retries: int = 1):
        self.model = model
        self.max_retries = max_retries

    def judge(self, site: UsageSite, rule: Rule,
              citations: tuple[Citation, ...],
              measurement=None) -> Verdict:
        prompt = build_prompt(site, rule, citations, measurement)

        for attempt in range(self.max_retries + 1):
            text = self._ask(prompt)
            parsed = _parse(text)
            if parsed is not None:
                return parsed
            logger.warning("verdict_schema_violation",
                           f"판정 스키마를 어겼다 (시도 {attempt + 1}): {text[:200]}")

        return Verdict(
            decision=Decision.UNDETERMINED,
            reasoning="모델이 판정 규격을 지키지 못해 보류한다.", role="unknown")

    def _ask(self, prompt: str) -> str:
        from ..domain.models import GenerationRequest

        # 온도 0과 고정 시드로 부른다. 같은 코드에 같은 판정이 나와야 보고서를 비교할 수 있다.
        result = self.model.generate(GenerationRequest(
            question=prompt, max_tokens=512, temperature=0.0, seed=0))
        return getattr(result, "answer", "") or ""


# 위반이 될 수 없는 역할. 모델이 역할은 맞게 보고 판정만 규칙 설명에 끌려 위반이라 할 때 되돌린다.
NON_VIOLATING_ROLES = ("name_list", "test_fixture", "documentation", "non_security")


def build_prompt(site: UsageSite, rule: Rule, citations: tuple[Citation, ...] = (),
                 measurement=None) -> str:
    """
    판정 프롬프트. 운영 판정과 학습 데이터가 같은 함수를 쓴다.

    학습 데이터의 입력이 운영 프롬프트와 한 글자라도 다르면 모델은 운영에서 본 적 없는
    입력을 받는다. 그래서 프롬프트를 만드는 곳을 하나로 둔다.
    """
    clauses = "\n".join(f"- {c.label()}: {c.quote[:300]}" for c in citations) or "(없음)"
    return PROMPT.format(
        rule_id=rule.rule_id, cwe=rule.cwe, summary=rule.summary, detail=rule.detail,
        clauses=clauses, file_path=site.file_path,
        api=site.api or "(문자열)", context=site.context or site.snippet,
        value_note=_value_note(site),
        test_note=("이 파일은 빌드 규약상 테스트 소스다."
                   if site.is_test else "이 파일은 운영 소스다."),
        table_note=_table_note(measurement))


def format_answer(verdict: Verdict) -> str:
    """판정을 parser가 읽는 네 줄로 쓴다. 학습 데이터의 정답 출력이 이 형식이다."""
    one_line = lambda text: " ".join(str(text).split())  # noqa: E731
    fix = one_line(verdict.suggested_fix) if verdict.decision is Decision.VIOLATION else ""
    return (f"role: {verdict.role}\ndecision: {verdict.decision.value}\n"
            f"reasoning: {one_line(verdict.reasoning)}\nfix: {fix}")


def _parse(text: str) -> Verdict | None:
    """
    모델 출력에서 판정을 꺼낸다. 규격을 어기면 None.

    줄 단위 형식을 먼저 본다. JSON으로 받았을 때 근거 문장 안의 따옴표가 문자열을 끊어
    파싱이 깨졌고, 그 바람에 확실한 위반 하나를 놓쳤다. 값에 무슨 글자가 와도 줄 단위는
    깨지지 않는다. 예전 형식으로 답하는 모델을 위해 JSON도 계속 받는다.
    """
    data = _parse_lines(text) or _parse_json(text)
    if data is None:
        return None
    try:
        role = str(data.get("role", "")).strip()
        decision = Decision(str(data["decision"]).strip().lower())
        # 역할이 위반이 될 수 없는 종류라면 판정을 내린다. 모델이 역할은 맞게 보고도
        # 규칙 설명에 끌려 위반이라고 답하는 경우가 있다.
        if role in NON_VIOLATING_ROLES:
            decision = Decision.CLEAN
        return Verdict(
            decision=decision,
            reasoning=str(data.get("reasoning", "")),
            suggested_fix=str(data.get("fix", data.get("suggested_fix", ""))),
            role=role,
        )
    except (KeyError, ValueError, TypeError):
        return None


_LINE = re.compile(r"^\s*(role|decision|reasoning|fix|suggested_fix)\s*[:=]\s*(.*)$",
                   re.IGNORECASE)


def _parse_lines(text: str) -> dict | None:
    """`키: 값` 줄들을 사전으로. 필수 키가 없으면 None."""
    data: dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.match(line)
        if match:
            data[match.group(1).lower()] = match.group(2).strip().strip('"').strip("'")
    if "decision" in data:
        return data
    return None


def _parse_json(text: str) -> dict | None:
    """예전 JSON 형식도 받는다. 중괄호 짝을 찾아 읽는다."""
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        return {k: parsed[k] for k in parsed}
    except ValueError:
        return None


def _table_note(measurement) -> str:
    """
    표 대조 결과를 모델에게 넘길 문장으로 만든다.

    모델에게 `RSA 2048비트면 충분한가`를 묻지 않는다. 그건 표에 적힌 값이고 모델이
    기억으로 답하면 틀린다. 이미 계산한 결과를 사실로 주고, 모델에게는 이 코드가
    무엇에 쓰이는지만 남긴다.
    """
    if measurement is None:
        return "표 대조: 이 규칙은 임계값 표로 답할 질문이 아니다."
    where = f" (근거: {measurement.citation.label()})" if measurement.citation else ""
    return f"표 대조: {measurement.sentence()}{where}"


def _value_note(site: UsageSite) -> str:
    """모델에게 값 확인 결과를 그대로 알려준다. 추측할 자리를 없앤다."""
    if site.provenance:
        return (f"값의 출처(코드가 구조로 판별): {site.provenance} — "
                f"{site.provenance_note}. 이 사실로 판단하라.")
    if site.traced_values:
        values = ", ".join(f'"{value}"' for value in site.traced_values)
        return f"변수를 따라가 찾은 값: {values}. 이 값으로 판단하라."
    if site.unresolved_args:
        names = ", ".join(site.unresolved_args)
        return (f"`{names}`의 값을 이 파일에서 찾지 못했다. 다른 파일이나 실행 시점에 "
                f"정해진다. 추측하지 말고 undetermined로 답하라.")
    return "인자에 값이 리터럴로 적혀 있거나 인자가 없다. 코드 그대로 판단하라."
