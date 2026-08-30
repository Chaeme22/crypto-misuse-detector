"""
표에서 뽑은 값을 전수로 검사한다.

이 도구가 내리는 판정의 근거는 표 안의 알고리즘명과 키 길이다. 그 값이 한 자리라도
틀리면 판정이 뒤집힌다. 설명문은 한두 글자 틀려도 검색과 인용이 견디지만 값은 못 견딘다.
그래서 값만 따로 전수 검사한다.

두 가지를 본다.

  형식 검사   키 길이와 보안강도가 실제로 존재하는 값인지. 알고리즘에 붙은 키 길이가 그
              알고리즘이 갖는 길이인지. `156 비트 이상`, `ARIA-792`, `싸5-128` 같은 것이
              여기서 걸린다. 사람 손이 안 간다.

  교차 검증   같은 표를 격자와 인식기가 각각 읽었으므로 값이 일치하는지 본다. 일치하면
              두 방식이 독립적으로 같은 값을 냈다는 뜻이라 통과시키고, 어긋난 것만 사람에게
              넘긴다. 표를 중복으로 남긴 것이 여기서 쓸모가 된다.

사용법:
    python tools/value_audit.py
    python tools/value_audit.py --out data/value_audit.md
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

DEFAULT_IN = Path("data/parsed")
DEFAULT_OUT = Path("data/value_audit.md")

# 표준에 실제로 나오는 비트 길이. 대칭키·해시 출력·공개키 계수를 모두 포함한다.
KNOWN_BITS = {
    56, 64, 80, 112, 128, 160, 192, 224, 256, 283, 384, 409, 512, 521, 571,
    1024, 2048, 3072, 4096, 7680, 15360,
}

# 알고리즘마다 존재하는 키 길이 또는 출력 길이.
ALGORITHM_BITS = {
    "AES": {128, 192, 256},
    "ARIA": {128, 192, 256},
    "LEA": {128, 192, 256},
    "SEED": {128},
    "HIGHT": {64, 128},
    "CAMELLIA": {128, 192, 256},
    "SERPENT": {128, 192, 256},
    "SHA": {1, 224, 256, 384, 512},
    "SHA2": {224, 256, 384, 512},
    "SHA3": {224, 256, 384, 512},
    "LSH": {224, 256, 384, 512},
    "HAS": {160},
    "RSA": {1024, 2048, 3072, 4096, 7680, 15360},
    "DH": {1024, 2048, 3072, 7680, 15360},
    "ECC": {160, 224, 256, 283, 384, 409, 512, 521, 571},
}

# `AES-128`, `SHA-512/224`, `ARIA-792` 같은 이름-길이 쌍.
_NAMED = re.compile(r"\b([A-Za-z][A-Za-z0-9]*)\s*[-–]\s*(\d{2,5})\b")
# `112 비트`, `256비트 이상`, `키 사이즈(619)` 같은 표현.
_BITS = re.compile(r"(\d{2,5})\s*(?:비트|bit|bits)\b", re.IGNORECASE)
# 값 칸에 섞인 깨진 글자. 한글 자모 단독, 전각 문자, 치환 실패 문자.
# 가운뎃점(U+318D)과 중점(U+00B7)은 `제ㆍ개정`처럼 정상 표기에 쓰이므로 제외한다.
_BROKEN = re.compile(r"[ㄱ-ㆌㆎＡ-Ｚａ-ｚ０-９�]")


def cells_of(block: dict) -> list[str]:
    """표 블록을 칸 단위로 쪼갠다. 두 판독의 표기 방식이 달라 구분자를 함께 본다."""
    out = []
    for line in block["text"].splitlines():
        line = re.sub(r"^\[(?:Header|Row \d+)\]\s*", "", line)
        out += [c.strip() for c in re.split(r"\||=", line) if c.strip()]
    return out


def check_cell(cell: str) -> list[str]:
    """값 칸 하나를 검사해 발견한 문제를 돌려준다."""
    problems = []

    for number in _BITS.findall(cell):
        if int(number) not in KNOWN_BITS:
            problems.append(f"없는 비트 길이 {number}")

    for name, number in _NAMED.findall(cell):
        allowed = ALGORITHM_BITS.get(name.upper())
        if allowed and int(number) not in allowed:
            problems.append(f"{name}에 없는 길이 {number}")

    if _BROKEN.search(cell) and re.search(r"\d", cell):
        problems.append("값 칸에 깨진 글자")

    return problems


def value_tokens(text: str) -> set[str]:
    """비교에 쓸 값 토큰. 알고리즘명-길이 쌍과 비트 표현만 본다."""
    tokens = {f"{n.upper()}-{v}" for n, v in _NAMED.findall(text)}
    tokens |= {f"{v}bit" for v in _BITS.findall(text)}
    return tokens


def audit(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    tables = [b for b in payload["blocks"] if b["type"] == "table"]

    findings = []
    checked = 0
    for block in tables:
        for cell in cells_of(block):
            if not re.search(r"\d", cell):
                continue
            checked += 1
            for problem in check_cell(cell):
                findings.append({
                    "page": block["page"],
                    "source": block["metadata"].get("table_source", "?"),
                    "problem": problem,
                    "cell": cell[:120],
                })

    # 같은 쪽에서 두 판독이 모두 나온 표만 견준다.
    by_page = defaultdict(lambda: defaultdict(str))
    for block in tables:
        by_page[block["page"]][block["metadata"].get("table_source", "?")] += " " + block["text"]

    agreed = disagreed = 0
    conflicts = []
    for page, sources in sorted(by_page.items()):
        if len(sources) < 2:
            continue
        grid = value_tokens(sources.get("vector_ocr", ""))
        read = value_tokens(sources.get("page_ocr", ""))
        if not grid or not read:
            continue
        agreed += len(grid & read)
        only = (grid ^ read)
        disagreed += len(only)
        if only:
            conflicts.append({
                "page": page,
                "grid_only": sorted(grid - read)[:12],
                "read_only": sorted(read - grid)[:12],
            })

    return {
        "file_name": payload["file_name"],
        "tables": len(tables),
        "cells_checked": checked,
        "findings": findings,
        "cross_agreed": agreed,
        "cross_disagreed": disagreed,
        "conflicts": conflicts,
    }


def render(results: list[dict]) -> str:
    lines = ["# 표 값 전수 검사\n"]
    lines.append("판정에 쓰이는 값만 본다. 형식 검사는 기계가 끝냈고, 교차 검증에서 어긋난 "
                 "값이 사람이 볼 목록이다.\n")

    total_findings = sum(len(r["findings"]) for r in results)
    total_cells = sum(r["cells_checked"] for r in results)
    lines.append(f"- 검사한 값 칸: {total_cells}개")
    lines.append(f"- 형식 검사에서 걸린 것: {total_findings}개")
    lines.append(f"- 두 판독이 같은 값을 낸 것: {sum(r['cross_agreed'] for r in results)}개")
    lines.append(f"- 두 판독이 어긋난 값: {sum(r['cross_disagreed'] for r in results)}개\n")

    for r in results:
        if not r["findings"] and not r["conflicts"]:
            continue
        lines.append(f"## {r['file_name']}\n")
        if r["findings"]:
            lines.append(f"### 형식 검사 {len(r['findings'])}건\n")
            for f in r["findings"]:
                lines.append(f"- {f['page']}쪽 `{f['source']}` **{f['problem']}** — {f['cell']}")
            lines.append("")
        if r["conflicts"]:
            lines.append(f"### 두 판독이 어긋난 쪽 {len(r['conflicts'])}개\n")
            for c in r["conflicts"]:
                lines.append(f"- {c['page']}쪽: 격자만 {c['grid_only']} / 인식기만 {c['read_only']}")
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="표에서 뽑은 값을 전수 검사한다")
    ap.add_argument("target", nargs="?", type=Path, default=DEFAULT_IN)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    files = (sorted(args.target.glob("*.json")) if args.target.is_dir() else [args.target])
    if not files:
        print(f"파싱 덤프 없음: {args.target}")
        return 1

    results = [audit(f) for f in files]

    print(f"{'문서':<34}{'표':>5}{'값칸':>6}{'형식':>5}{'일치':>6}{'어긋':>6}")
    print("-" * 64)
    for r in results:
        print(f"{r['file_name'][:33]:<34}{r['tables']:>5}{r['cells_checked']:>6}"
              f"{len(r['findings']):>5}{r['cross_agreed']:>6}{r['cross_disagreed']:>6}")

    args.out.write_text(render(results), encoding="utf-8")
    print(f"\n검수 목록: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
