"""
사람이 원문과 대조해 확정한 값 보정.

OCR이 특정 자리에서 반복해 틀리는 값이 있다. 다시 돌려도 같게 읽히므로 파서를 고쳐서
해결할 수 없고, 그렇다고 틀린 값을 규칙표에 넣을 수도 없다. 그래서 사람이 원문을 보고
확정한 보정만 목록으로 두고 파싱 직후에 적용한다.

원칙 셋을 지킨다.

  근거를 남긴다      보정마다 무엇을 보고 정했는지 적는다. 나중에 이 값을 의심하는 사람이
                     추적할 수 있어야 한다.
  적용을 기록한다    보정된 블록에 표시를 남겨서, 색인된 값이 원문 판독인지 사람 보정인지
                     구분할 수 있게 한다.
  실패를 알린다      찾을 문자열이 없으면 조용히 넘기지 않는다. 파서가 개선되어 그 자리를
                     제대로 읽게 되면 보정은 목록에서 빠져야 하고, 그 사실을 알아야 한다.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_PATH = Path("config/value_corrections.json")


def load(path: Path = DEFAULT_PATH) -> list[dict]:
    """보정 목록을 읽는다. 파일이 없으면 빈 목록."""
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def apply(blocks: list[dict], document: str, corrections: list[dict]) -> tuple[int, list[dict]]:
    """
    한 문서의 블록에 보정을 적용한다. 블록은 파싱 덤프 형식의 dict다.

    이미 적용된 보정은 못 찾은 것으로 세지 않는다. 같은 덤프에 두 번 적용해도 결과가 같아야
    하고, 그때마다 경고가 뜨면 진짜 경고를 못 알아본다.

    Returns:
        (고친 블록 수, 대상을 못 찾은 보정 목록)
    """
    mine = [c for c in corrections if c["document"] == document]
    if not mine:
        return 0, []

    changed = 0
    missed = []
    for correction in mine:
        hit = False
        already = False
        for block in blocks:
            if block["page"] != correction["page"]:
                continue
            if correction["wrong"] not in block["text"]:
                already = already or correction["right"] in block["text"]
                continue
            block["text"] = block["text"].replace(correction["wrong"], correction["right"])
            applied = list(block["metadata"].get("corrected", []))
            applied.append(f"{correction['wrong']} → {correction['right']}")
            block["metadata"]["corrected"] = applied
            changed += 1
            hit = True
        if not hit and not already:
            missed.append(correction)
    return changed, missed
