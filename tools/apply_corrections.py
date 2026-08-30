"""
이미 만들어 둔 파싱 덤프에 값 보정을 적용한다.

파싱을 다시 돌리지 않고 보정만 반영하려고 둔다. 파싱은 GPU로 30분이고 보정은 문자열
치환이다. 보정 목록을 손볼 때마다 재파싱하는 것은 낭비다.

사용법:
    python tools/apply_corrections.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_app.parsing import corrections as value_corrections  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="파싱 덤프에 값 보정을 적용한다")
    ap.add_argument("target", nargs="?", type=Path, default=Path("data/parsed"))
    ap.add_argument("--corrections", type=Path, default=value_corrections.DEFAULT_PATH)
    args = ap.parse_args()

    table = value_corrections.load(args.corrections)
    if not table:
        print(f"보정 목록이 없다: {args.corrections}")
        return 1

    files = sorted(args.target.glob("*.json")) if args.target.is_dir() else [args.target]
    total_fixed = 0
    for f in files:
        payload = json.loads(f.read_text(encoding="utf-8"))
        fixed, missed = value_corrections.apply(payload["blocks"], f.stem, table)
        if not fixed and not missed:
            continue
        payload["corrections_applied"] = fixed
        payload["corrections_missed"] = [c["wrong"] for c in missed]
        f.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        total_fixed += fixed
        print(f"{f.stem[:45]:<47} 고친 블록 {fixed}개"
              + (f", 대상 못 찾음 {[c['wrong'] for c in missed]}" if missed else ""))

    print(f"\n합계 {total_fixed}개 블록 보정. 대상이 없어진 보정은 목록에서 빼야 한다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
