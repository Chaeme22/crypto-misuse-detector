"""
파싱된 표에서 판정용 임계값 표를 만든다.

지금 규칙표의 임계값은 산문이다. `RSA 2048비트 이상이어야 한다`는 문장이 있을 뿐이라
코드에서 `RSA-1536`을 만나면 2048과 비교하지 못한다. 손으로 나열한 이름 목록에 없으면
그냥 통과한다. 그래서 표에서 숫자를 뽑아 비교할 수 있는 행으로 만든다.

**어느 블록을 어떻게 읽을지는 사람이 지정한다**(`config/threshold_tables.json`). 처음에는
표를 전부 훑어 자동으로 뽑았는데 목적이 다른 표를 섞은 탓에 RSA가 256비트 보안강도를
만족한다는 행이 나왔다. 표 3(메시지인증용 해시)과 표 4(전자서명용 해시)는 같은
알고리즘에 다른 기준을 쓴다. 자동으로 가릴 수 없다. 8쪽에는 표 3의 꼬리와 표 4의 머리가
같이 있어 페이지 단위로도 부족했다.

표 종류가 둘이다.
  membership  `112 비트 이상` 행마다 그 강도를 만족하는 알고리즘이 나열된 표. 강도가 높은
              알고리즘은 낮은 행에도 다시 나오므로, 이름이 등장한 가장 높은 행이 그
              알고리즘이 낼 수 있는 강도다.
  key_length  보안강도별로 필요한 키 길이가 적힌 표. `112 비트 2048 2048 224 224`.
              여기 숫자는 최소값이다.

사용법:
    python tools/build_thresholds.py
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DEFAULT_IN = Path("data/parsed")
DEFAULT_MAP = Path("config/threshold_tables.json")
DEFAULT_OUT = Path("config/tier1_thresholds.json")

_STRENGTH_ROW = re.compile(r"(\d{2,4})\s*비트\s*이상")
_KEY_LENGTH_ROW = re.compile(r"(\d{2,4})\s*비트(?!\s*이상)")

# 표에 실제로 나오는 계열 이름. 이 목록에 없는 토큰은 버린다. 열 제목·각주·기관명이
# 같은 자리에 섞여 있어 알고리즘처럼 생긴 것을 모두 받으면 쓰레기가 들어온다.
_FAMILIES = ("SHA3", "SHA2", "SHA", "LSH", "HAS", "WHIRLPOOL", "BLAKE", "MD5",
             "AES", "ARIA", "LEA", "SEED", "HIGHT", "CAMELLIA", "SERPENT",
             "3TDEA", "2TDEA", "TDEA", "3DES", "DES")
# 이름 뒤에 붙는 꼬리. `-224`, `-512/256`, `-512-224`, `-shake128`, `-1`.
_TAIL = re.compile(r"^-(shake\d{3}|\d{1,5}(?:[-/]\d{2,4})?)$", re.IGNORECASE)
# 각주 표시. `1)`, `2)` 같은 토큰이 알고리즘 이름에 붙어 다닌다.
_FOOTNOTE = re.compile(r"^\d\)$")


def parse_token(token: str) -> tuple[str, str, int | None] | None:
    """
    표의 한 토큰을 (이름, 계열, 비트) 로 바꾼다. 알고리즘이 아니면 None.

    이름은 표에 적힌 그대로 쓴다. `SHA-512/256`을 `SHA-256`으로 뭉개면 안 된다. 출력이
    256비트인 건 같지만 전자서명용 기준이 다르고, 무엇보다 서로 다른 알고리즘이다.
    """
    token = token.strip().strip(",.·")
    if not token or _FOOTNOTE.match(token):
        return None

    upper = token.upper()
    for family in _FAMILIES:
        if not upper.startswith(family):
            continue
        tail = upper[len(family):]
        if not tail:
            return family, family, None
        matched = _TAIL.match(tail)
        if not matched:
            return None  # `SHAKE128`처럼 계열 이름에 다른 글자가 붙은 것. 버린다.
        suffix = matched.group(1)
        if suffix.startswith("SHAKE"):
            return f"{family}-{suffix}", family, None
        numbers = [int(n) for n in re.split(r"[-/]", suffix)]
        # `SHA-1`은 판본 번호다. 길이가 아니다.
        bits = None if numbers[-1] < 64 else numbers[-1]
        return f"{family}-{suffix}", family, bits
    return None


def read_membership(text: str) -> list[tuple[int, str, str, int | None]]:
    """`N 비트 이상` 행마다 그 뒤 구간에 나열된 알고리즘을 그 강도에 넣는다."""
    marks = list(_STRENGTH_ROW.finditer(text))
    out = []
    for index, mark in enumerate(marks):
        strength = int(mark.group(1))
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        for token in text[mark.end():end].split():
            parsed = parse_token(token)
            if parsed:
                out.append((strength, *parsed))
    return out


def read_key_length(text: str) -> list[tuple[int, str, int]]:
    """
    보안강도별 공개키 최소 길이.

    열 순서는 머리행 그대로 인수분해, 이산대수 공개키, 이산대수 개인키, 타원곡선이다.
    숫자를 위치로 읽으므로 순서가 다른 표가 오면 지도에서 빼야 한다.
    """
    if "인수분해" not in text:
        return []
    columns = ["RSA", "DH", "DH_PRIVATE", "ECC"]
    marks = list(_KEY_LENGTH_ROW.finditer(text))
    out = []
    for index, mark in enumerate(marks):
        strength = int(mark.group(1))
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        # 행 경계까지만 읽는다. 한 번에 훑으면 다음 행의 강도 숫자까지 열로 삼켜
        # 그 행이 통째로 사라진다.
        numbers = [int(n.replace(",", ""))
                   for n in re.findall(r"[\d,]+", text[mark.end():end])]
        for column, bits in zip(columns, numbers[:len(columns)]):
            out.append((strength, column, bits))
    return out


def pick(payload: dict, spec: dict, want: dict) -> dict | None:
    """지도가 가리키는 블록 하나를 찾는다."""
    if spec["document"] not in payload["file_name"]:
        return None
    for block in payload["blocks"]:
        if (block["type"] == "table"
                and block["page"] == want["page"]
                and block["text"].startswith(want["starts_with"])):
            return block
    return None


def build(parsed_dir: Path, table_map: Path) -> dict:
    config = json.loads(table_map.read_text(encoding="utf-8"))
    documents = [json.loads(p.read_text(encoding="utf-8"))
                 for p in sorted(parsed_dir.glob("*.json"))]

    rows: list[dict] = []
    used: list[dict] = []
    missing: list[str] = []

    for spec in config["tables"]:
        for want in spec["blocks"]:
            block = next((b for b in (pick(d, spec, want) for d in documents) if b), None)
            if block is None:
                missing.append(f"{spec['label']} / {want['page']}쪽 "
                               f"`{want['starts_with']}`")
                continue

            # 파싱 단계의 검수 표시는 이중 판독이 어긋났다는 뜻이다. 사람이 원문과
            # 대조해 확인한 블록은 지도에 그 사실을 적어 두고 여기서 해제한다. 그러지
            # 않으면 모든 인용에 `원문 대조 필요`가 붙어 표시가 뜻을 잃는다.
            source = {
                "document": spec["document"], "page": block["page"],
                "table": spec["label"],
                "needs_review": (bool(block["metadata"].get("needs_review"))
                                 and not want.get("verified")),
                "verified": want.get("verified", ""),
            }
            found = 0
            if spec["kind"] == "membership":
                for strength, name, family, bits in read_membership(block["text"]):
                    rows.append({
                        "algorithm": name, "family": family, "key_bits": bits,
                        "security_strength": strength, "kind": "membership",
                        "purpose": spec["purpose"], "context": spec["context"],
                        "verdict": "allowed", "source": source,
                    })
                    found += 1
            else:
                for strength, column, bits in read_key_length(block["text"]):
                    rows.append({
                        "algorithm": column, "family": column,
                        "min_key_bits": bits,
                        "security_strength": strength, "kind": "key_length",
                        "purpose": spec["purpose"], "context": spec["context"],
                        "verdict": "allowed", "source": source,
                    })
                    found += 1
            used.append({"table": spec["label"], "page": block["page"],
                         "rows": found})

    # 나열형 표에서 같은 알고리즘이 여러 강도 행에 나오면 가장 높은 것만 남긴다. 낮은
    # 행에도 다시 나오는 표라서, 등장한 최고 강도가 그 알고리즘이 낼 수 있는 강도다.
    # 키 길이 표는 합치지 않는다. 강도마다 필요한 길이가 다른 별개의 임계값이다.
    best: dict[tuple, dict] = {}
    keep: list[dict] = []
    for row in rows:
        if row["kind"] == "key_length":
            keep.append(row)
            continue
        key = (row["purpose"], row["context"], row["algorithm"])
        current = best.get(key)
        if current is None or row["security_strength"] > current["security_strength"]:
            best[key] = row
    keep.extend(best.values())

    return {
        "note": config["note"],
        "policy": config["policy"],
        "tables_used": used,
        "blocks_missing": missing,
        "excluded": [{k: v for k, v in e.items() if k != "starts_with"}
                     for e in config.get("excluded", [])],
        "rows": sorted(keep,
                       key=lambda r: (r["purpose"], r["context"],
                                      r["security_strength"], r["algorithm"])),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="파싱된 표에서 임계값 표를 만든다")
    ap.add_argument("target", nargs="?", type=Path, default=DEFAULT_IN)
    ap.add_argument("--map", type=Path, default=DEFAULT_MAP)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    table = build(args.target, args.map)
    args.out.write_text(json.dumps(table, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")

    policy = table["policy"]
    print(f"기준 보안강도 최소 {policy['minimum_security_strength']}비트 · "
          f"권장 {policy['recommended_security_strength']}비트 "
          f"({policy['basis_document']} {policy['basis_page']}쪽 {policy['basis_table']})")
    print(f"읽은 블록 {len(table['tables_used'])}개 → 임계값 {len(table['rows'])}행")
    for entry in table["tables_used"]:
        print(f"  {entry['page']:>2}쪽  {entry['rows']:>3}건  {entry['table']}")
    if table["blocks_missing"]:
        print("\n지도에 있으나 파싱 결과에 없는 블록:")
        for item in table["blocks_missing"]:
            print(f"  {item}")
    print(f"\n의도적으로 뺀 블록 {len(table['excluded'])}개")
    for item in table["excluded"]:
        print(f"  {item['page']}쪽 - {item.get('affects', item['reason'])}")

    current = None
    for row in table["rows"]:
        head = f"{row['purpose']}/{row['context']}"
        if head != current:
            print(f"\n[{head}]")
            current = head
        if row["kind"] == "key_length":
            print(f"  {row['security_strength']:>3}비트 강도 ← "
                  f"{row['algorithm']:<12} {row['min_key_bits']}비트 이상")
        else:
            print(f"  {row['security_strength']:>3}비트 강도 ← {row['algorithm']}")

    print(f"\n저장: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
