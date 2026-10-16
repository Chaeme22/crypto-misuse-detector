"""
합성 학습 데이터를 만들고 학습용 파일로 내보낸다.

    python tools/build_dataset.py                       # 생성 + 검증 + 통계
    python tools/build_dataset.py --export              # 승인(approved) 샘플만 train/validation/test로
    python tools/build_dataset.py --export --allow-unreviewed   # 파일럿: 검토 전 샘플도 포함

산출물 (dataset/generated/):
  manifest.jsonl   샘플마다 라벨·근거·출처·검증 결과
  sft.jsonl        운영 판정 프롬프트와 같은 입력 + 정답 네 줄
  skipped.jsonl    운영에서 모델에게 묻지 않아 뺀 샘플과 이유
  stats.md         규칙·판정·깊이·역할별 개수
  train/validation/test.jsonl   --export일 때

분할은 lineage_group 단위다. 같은 값의 변형이 train과 test에 갈라 들어가면 모델이 외운 것을
맞힌 것으로 세게 된다. CryptoAPI-Bench는 여기 넣지 않는다(외부 평가용).

승인은 사람이 한다. manifest의 validation.status를 approved로 바꾸고 human_reviewers를
채운 뒤 다시 --export 한다. 승인 샘플의 근거는 검수(verified)된 것이어야 한다
(tools/validate_dataset.py가 막는다).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rag_app.analysis import rules as tier1  # noqa: E402
from rag_app.dataset import build, templates  # noqa: E402
import validate_dataset  # noqa: E402

OUT = ROOT / "dataset" / "generated"
SPLITS = (("train", 80), ("validation", 10), ("test", 10))


def split_of(lineage_group: str) -> str:
    """
    같은 묶음은 늘 같은 쪽으로 간다. 합성 묶음(`LG-…-V<n>`)은 유형마다 값이 다섯 개라
    순번으로 나눠 모든 분할에 모든 유형이 들어가게 한다(0·1·2 학습, 3 검증, 4 평가).
    그 밖의 묶음(실제 코드 등)은 이름 해시로 80/10/10을 나눈다.
    """
    match = re.search(r"-V(\d+)$", lineage_group)
    if match:
        return ("train", "train", "train", "validation", "test")[int(match.group(1)) % 5]
    bucket = int(hashlib.sha256(lineage_group.encode("utf-8")).hexdigest(), 16) % 100
    edge = 0
    for name, share in SPLITS:
        edge += share
        if bucket < edge:
            return name
    return SPLITS[-1][0]


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def stats(manifest: list[dict], skipped: list[dict]) -> str:
    rows = ["# 합성 데이터 통계", "",
            f"- 샘플 {len(manifest)}건 (운영에서 모델에게 묻지 않아 뺀 것 {len(skipped)}건)",
            f"- 검토 상태: {dict(Counter(m['validation']['status'] for m in manifest))}",
            f"- 분할: {dict(sorted(Counter(m['split'] for m in manifest).items()))}",
            f"- 정적 판정과 일치: {dict(Counter(m['validation']['rule_engine'] for m in manifest))}",
            ""]
    for title, key in (("규칙", lambda m: m["rule_id"]), ("판정", lambda m: m["decision"]),
                       ("역할", lambda m: m["role"]),
                       ("제공 문맥 깊이", lambda m: m["context_depth_available"]),
                       ("규칙 × 판정", lambda m: f"{m['rule_id']} / {m['decision']}")):
        rows += [f"## {title}", "", "| 값 | 개수 |", "|---|---|"]
        rows += [f"| {k} | {v} |" for k, v in sorted(Counter(map(key, manifest)).items())]
        rows.append("")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="합성 학습 데이터를 만든다")
    ap.add_argument("--export", action="store_true", help="train/validation/test JSONL을 쓴다")
    ap.add_argument("--allow-unreviewed", action="store_true",
                    help="검토 전(needs_review) 샘플도 내보낸다. 파일럿 학습용")
    ap.add_argument("--oversample-context", type=int, default=4,
                    help="학습 분할에서 대조 쌍(보안 용도 vs 무관)을 몇 배로 넣을지")
    ap.add_argument("--keep-reviews", action="store_true", default=True,
                    help="이미 있는 manifest의 검토 결과(status·reviewers)를 같은 example_id에 옮긴다")
    args = ap.parse_args()

    taxonomy = json.loads((ROOT / "dataset" / "misuse_taxonomy.json").read_text(encoding="utf-8"))
    registry = _read_jsonl(ROOT / "dataset" / "evidence_registry.jsonl")
    manifest, sft, skipped = build.build(templates.generate(), tier1.load(), taxonomy, registry)

    # 사람이 해 둔 검토를 잃지 않는다. 코드가 같은(같은 해시) 샘플에만 옮긴다.
    previous = OUT / "manifest.jsonl"
    if args.keep_reviews and previous.exists():
        reviewed = {(m["example_id"], m["code_sha256"]): m["validation"]
                    for m in _read_jsonl(previous)
                    if m["validation"]["status"] != "needs_review"}
        for m in manifest:
            kept = reviewed.get((m["example_id"], m["code_sha256"]))
            if kept:
                m["validation"].update({k: kept[k] for k in ("status", "human_reviewers")
                                        if k in kept})
                if "notes" in kept:
                    m["validation"]["notes"] = kept["notes"]

    for m in manifest:
        m["split"] = split_of(m["lineage_group"])

    context = validate_dataset.load_context()
    errors = [e for m in manifest for e in validate_dataset.check_example(m, context)]
    errors += [e for r in sft for e in validate_dataset.check_sft(r, context)]

    build.write_jsonl(OUT / "manifest.jsonl", manifest)
    build.write_jsonl(OUT / "sft.jsonl", sft)
    build.write_jsonl(OUT / "skipped.jsonl", skipped)
    (OUT / "stats.md").write_text(stats(manifest, skipped) + "\n", encoding="utf-8")
    print(f"샘플 {len(manifest)}건 · 제외 {len(skipped)}건 · 검증 오류 {len(errors)}건 → {OUT}")
    for e in errors[:20]:
        print(f"  ✗ {e}")
    if errors:
        return 1

    if args.export:
        allowed = {"approved"} | ({"needs_review"} if args.allow_unreviewed else set())
        keep = {m["example_id"]: m["split"] for m in manifest
                if m["validation"]["status"] in allowed}
        context = {m["example_id"] for m in manifest if "-CTX" in m["validation"]["notes"]}
        for name, _ in SPLITS:
            rows = [r for r in sft if keep.get(r["example_id"]) == name]
            if name == "train" and args.oversample_context > 1:
                # 대조 쌍은 수가 적어 다른 템플릿에 묻힌다. 학습 분할에서만 반복해 넣는다.
                # 검증·평가는 그대로 둬야 지표가 부풀지 않는다.
                rows += [r for r in rows if r["example_id"] in context] * (args.oversample_context - 1)
            build.write_jsonl(OUT / f"{name}.jsonl", rows)
            print(f"  {name}: {len(rows)}건")
        marker = OUT / "PILOT_UNREVIEWED"
        if args.allow_unreviewed:
            marker.write_text("이 export에는 사람이 검토하지 않은 샘플이 들어 있다. 파일럿 학습용.\n",
                              encoding="utf-8")
        elif marker.exists():
            marker.unlink()
        if not keep:
            print("  승인된 샘플이 없다. manifest를 검토하거나 --allow-unreviewed로 파일럿을 만든다")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
