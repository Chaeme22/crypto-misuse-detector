"""
Tier-1 규칙표.

탐지를 촉발하는 쪽이다. 임계값과 CWE 번호는 사람이 표준문서를 보고 확정한 값이며 검색으로
정하지 않는다. 같은 코드에 같은 판정이 나와야 정적 분석 도구로 쓸 수 있다.

Tier-2 조항 검색은 이 표가 걸린 뒤에 근거를 붙이는 데만 쓴다.
"""

from __future__ import annotations

import json
from pathlib import Path

from .findings import Level, Rule

DEFAULT_PATH = Path("config/tier1_rules.json")


def load(path: Path = DEFAULT_PATH) -> list[Rule]:
    """규칙표를 읽는다. 파일이 없으면 조용히 비우지 않고 알린다."""
    if not path.exists():
        raise FileNotFoundError(f"Tier-1 규칙표가 없다: {path}")

    rules = []
    for entry in json.loads(path.read_text(encoding="utf-8")):
        rules.append(Rule(
            rule_id=entry["rule_id"],
            name=entry["name"],
            cwe=entry["cwe"],
            level=Level(entry["level"]),
            summary=entry["summary"],
            detail=entry["detail"],
            remediation=entry["remediation"],
            clause_query=entry.get("clause_query", ""),
            api_triggers=tuple(entry.get("api_triggers", ())),
            literal_triggers=tuple(entry.get("literal_triggers", ())),
            table_purposes=tuple(entry.get("table_purposes", ())),
            table_measures=bool(entry.get("table_measures", False)),
            table_decides=bool(entry.get("table_decides", False)),
        ))
    return rules


def match_api(name: str, rules: list[Rule]) -> Rule | None:
    """호출 이름으로 규칙을 찾는다. `hashlib.md5` 같은 점 표기다."""
    for rule in rules:
        if name in rule.api_triggers:
            return rule
    return None


def match_literal(value: str, rules: list[Rule]) -> Rule | None:
    """
    문자열 리터럴 값으로 규칙을 찾는다.

    부분 문자열로 보면 `md5_hash="md5_guide"`나 SQL 문장까지 걸린다. 그래서 두 가지만
    받는다. 알고리즘 이름은 리터럴 전체가 그 이름과 같을 때, 변환 스펙(`AES/ECB/...`)은
    슬래시가 있는 트리거가 포함될 때다.

    긴 트리거가 이긴다. `AES/ECB`가 `MD5`보다 구체적이므로 운영모드 규칙으로 가야 한다.
    """
    text = value.strip()
    best: tuple[int, Rule] | None = None
    for rule in rules:
        for trigger in rule.literal_triggers:
            hit = (trigger in text) if "/" in trigger else (text == trigger)
            if hit and (best is None or len(trigger) > best[0]):
                best = (len(trigger), rule)
    return best[1] if best else None


def owner_of(purpose: str, rules: list[Rule]) -> Rule | None:
    """
    그 목적의 표를 담당하는 규칙.

    손으로 적은 리터럴 목록에 없는 알고리즘이 나왔을 때 쓴다. 전에는 목록에 없으면
    안전하다고 보고 넘겼다. 그래서 `RC2`, `IDEA`, `MD4`, `MD2`, `HmacMD5`가 모두
    통과했다. 목록을 늘려도 다음 이름에서 또 새어 나간다. 이제는 표가 관문이므로
    표에 없는 이름이 곧 위반이고, 그 위반을 어느 규칙으로 보고할지 여기서 정한다.
    """
    for rule in rules:
        if purpose in rule.table_purposes:
            return rule
    return None
