"""
파싱 결과를 파일로 떨어뜨린다.

파싱과 청킹 사이에 중간 산출물을 두는 이유는 세 가지다. 표준문서는 몇 년에 한 번
바뀌므로 파싱은 사실상 일회성 작업이고, OCR이 붙으면 비싸지며, 표에서 뽑은 값은 사람이
원문과 대조해야 한다. 메모리에서 청킹으로 바로 넘어가면 검수할 대상이 없다.

두 가지를 쓴다.
  <이름>.json      기계용. 청킹이 읽을 전체 구조.
  <이름>.review.md 사람용. 표를 먼저 놓고 검수 필요 항목을 표시한 읽기용 문서.

사용법:
    python tools/parse_dump.py "수정방향/암호 가이드라인"
    python tools/parse_dump.py <파일.pdf> --out data/parsed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from uuid import uuid5, NAMESPACE_URL

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_app.domain.enums import BlockType  # noqa: E402
from rag_app.parsing import corrections as value_corrections  # noqa: E402
from rag_app.parsing.ocr_engine import create_engine  # noqa: E402
from rag_app.parsing.pdf_parser import PdfParser  # noqa: E402
from rag_app.parsing import text_quality  # noqa: E402

DEFAULT_OUT = Path("data/parsed")


def _safe(text: str) -> str:
    """
    JSON으로 쓸 수 없는 짝 없는 서러게이트 문자를 걷어낸다.

    깨진 PDF에서 추출한 텍스트에 이런 문자가 섞이면 저장 단계에서 예외가 나고 문서 하나가
    통째로 유실된다. 정규화 단계에도 같은 처리가 있으나 덤프는 그 앞이라 여기서 한다.
    """
    if not text:
        return text
    return text.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")


def parse_one(path: Path, out_dir: Path, engine: str = "tesseract") -> dict:
    # 같은 파일은 항상 같은 id를 갖게 해서 재실행 결과를 비교할 수 있게 한다.
    doc_id = uuid5(NAMESPACE_URL, str(path.resolve()))
    doc = PdfParser(ocr=create_engine(engine)).parse(path, doc_id, md5_hash="dump")

    blocks = []
    for b in doc.blocks:
        blocks.append({
            "sequence": b.sequence,
            "type": b.block_type.value,
            "page": b.page_number,
            "section_path": [_safe(s) for s in (b.section_path or ())],
            "text": _safe(b.text),
            "metadata": dict(b.metadata or {}),
        })

    # 사람이 원문과 대조해 확정한 값을 여기서 덮어쓴다. OCR이 같은 자리에서 반복해 틀리는
    # 값은 파서를 고쳐 해결할 수 없다.
    fixed, missed = value_corrections.apply(
        blocks, path.stem, value_corrections.load())

    counts: dict[str, int] = {}
    for b in blocks:
        counts[b["type"]] = counts.get(b["type"], 0) + 1

    review_needed = [b for b in blocks if b["metadata"].get("needs_review")]
    quality = text_quality.assess("\n".join(b["text"] for b in blocks))

    payload = {
        "file_name": doc.file_name,
        "source_path": doc.source_path,
        "language": doc.language,
        "ocr_status": doc.ocr_status.value,
        "ocr_pages": list(doc.ocr_pages),
        "block_counts": counts,
        "blocks_with_section": sum(1 for b in blocks if b["section_path"]),
        "blocks_needing_review": len(review_needed),
        "text_quality": {
            "ok": quality.ok,
            "reasons": list(quality.reasons),
            **{k: v for k, v in asdict(quality.metrics).items()},
        },
        "corrections_applied": fixed,
        "corrections_missed": [c["wrong"] for c in missed],
        "blocks": blocks,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = path.stem
    (out_dir / f"{stem}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / f"{stem}.review.md").write_text(
        _render_review(payload), encoding="utf-8")
    return payload


def _render_review(p: dict) -> str:
    """사람이 원문과 대조하기 좋은 형태로 쓴다. 표를 먼저 놓는다."""
    lines: list[str] = []
    lines.append(f"# 파싱 검수 - {p['file_name']}\n")
    lines.append(f"- 언어 판정: `{p['language']}`")
    lines.append(f"- OCR 상태: `{p['ocr_status']}`"
                 + (f" (텍스트 없는 페이지 {len(p['ocr_pages'])}개)" if p["ocr_pages"] else ""))
    lines.append(f"- 블록: {p['block_counts']}")
    lines.append(f"- 조항 경로가 붙은 블록: {p['blocks_with_section']}/{sum(p['block_counts'].values())}")
    q = p["text_quality"]
    lines.append(f"- 텍스트 품질: {'정상' if q['ok'] else '손상 의심'}"
                 + ("" if q["ok"] else " - " + "; ".join(q["reasons"])))
    if p["blocks_needing_review"]:
        lines.append(f"- **OCR 이중 판독이 어긋난 블록 {p['blocks_needing_review']}개** - 원문 대조 필요")
    lines.append("")

    tables = [b for b in p["blocks"] if b["type"] == BlockType.TABLE.value]
    lines.append(f"## 표 {len(tables)}개\n")
    lines.append("표 안의 숫자와 알고리즘명이 규칙표의 임계값이 된다. 원문과 한 칸씩 대조할 것.\n")
    for i, t in enumerate(tables, 1):
        mark = " ⚠ 검수필요" if t["metadata"].get("needs_review") else ""
        sec = " > ".join(t["section_path"]) or "(조항 정보 없음)"
        lines.append(f"### 표 {i} - {t['page']}쪽{mark}")
        lines.append(f"조항: {sec}  ·  출처: `{t['metadata'].get('table_source', '?')}`\n")
        lines.append("```")
        lines.append(t["text"])
        lines.append("```\n")

    headings = [b for b in p["blocks"] if b["type"] == BlockType.HEADING.value]
    if headings:
        lines.append(f"## 인식된 제목 {len(headings)}개\n")
        for h in headings[:80]:
            lines.append(f"- {h['page']}쪽  {h['text']}")
        if len(headings) > 80:
            lines.append(f"- ... 외 {len(headings) - 80}개")
        lines.append("")

    paras = [b for b in p["blocks"] if b["type"] == BlockType.PARAGRAPH.value]
    lines.append(f"## 본문 {len(paras)}블록 (앞 40개)\n")
    for b in paras[:40]:
        sec = " > ".join(b["section_path"]) or "(조항 없음)"
        lines.append(f"**{b['page']}쪽 | {sec}**")
        lines.append(f"> {b['text'][:600]}\n")
    return "\n".join(lines)


def _summarize(name: str, p: dict) -> str:
    total = sum(p["block_counts"].values())
    tables = p["block_counts"].get("table", 0)
    heads = p["block_counts"].get("heading", 0)
    pct = p["blocks_with_section"] * 100 // total if total else 0
    flag = []
    if p["ocr_status"] not in ("not_needed", "completed"):
        flag.append(p["ocr_status"])
    if not p["text_quality"]["ok"]:
        flag.append("품질의심")
    if p["blocks_needing_review"]:
        flag.append(f"검수{p['blocks_needing_review']}건")
    if p.get("corrections_applied"):
        flag.append(f"보정{p['corrections_applied']}건")
    if p.get("corrections_missed"):
        flag.append(f"보정대상없음{len(p['corrections_missed'])}건")
    flag.append(f"토큰{p['text_quality']['crypto_tokens_found']}/23")
    return (f"{name[:45]:<46} {total:>6} {tables:>4} {heads:>5} {pct:>5}%  "
            + ", ".join(flag))


def _worker(args_tuple):
    """프로세스 풀에서 문서 하나를 처리한다."""
    path, out_dir, engine = args_tuple
    try:
        return path.name, _summarize(path.name, parse_one(path, out_dir, engine)), None
    except Exception as e:
        return path.name, None, f"{type(e).__name__}: {e}"


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="PDF 파싱 결과를 JSON과 검수용 문서로 저장")
    ap.add_argument("target", type=Path, help="PDF 파일 또는 디렉터리")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"출력 폴더 (기본 {DEFAULT_OUT})")
    ap.add_argument("--engine", default="tesseract",
                    help="OCR 엔진. tesseract+easyocr은 tesseract가 못 읽은 자리를 "
                         "easyocr로 메우고 숫자가 어긋나면 검수 대상으로 표시한다 "
                         "(easyocr과 GPU 필요).")
    ap.add_argument("--workers", type=int, default=1,
                    help="동시에 처리할 문서 수. OCR이 프로세스 호출이라 코어 수만큼 올리면 "
                         "그만큼 빨라진다. 0을 주면 코어 수에 맞춘다.")
    args = ap.parse_args()

    files = sorted(args.target.rglob("*.pdf")) if args.target.is_dir() else [args.target]
    if not files:
        print(f"PDF 없음: {args.target}")
        return 1

    workers = args.workers
    if workers == 0:
        workers = min(len(files), (os.cpu_count() or 4))
    workers = max(1, min(workers, len(files)))

    print(f"문서 {len(files)}건 · 동시 처리 {workers} · 엔진 {args.engine}")
    print(f"{'파일':<46} {'블록':>6} {'표':>4} {'제목':>5} {'조항%':>6}  상태")
    print("-" * 100)

    if workers == 1:
        for f in files:
            name, line, err = _worker((f, args.out, args.engine))
            print(line if line else f"{name[:45]:<46} 실패: {err}", flush=True)
    else:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_worker, (f, args.out, args.engine)): f
                       for f in files}
            for fut in as_completed(futures):
                name, line, err = fut.result()
                print(line if line else f"{name[:45]:<46} 실패: {err}", flush=True)

    print(f"\n저장 위치: {args.out.resolve()}")
    print("  <이름>.json       청킹이 읽을 구조")
    print("  <이름>.review.md  사람이 원문과 대조할 검수 문서")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
