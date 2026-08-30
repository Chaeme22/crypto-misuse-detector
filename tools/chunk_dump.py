"""
청킹 결과를 파일로 떨어뜨린다.

파싱 산출물(`data/parsed/*.json`)을 읽어 청킹한다. 파싱을 다시 돌리지 않는 이유는 비용
차이다. 파싱은 GPU로 문서당 몇 분이고 청킹은 초 단위다. 청킹 기준을 바꿔가며 여러 번
재보려면 중간 산출물에서 출발해야 한다.

두 가지를 쓴다.
  <이름>.json        색인이 읽을 청크 목록.
  <이름>.review.md   사람용. 청크 경계와 조항 경로, 토큰 수를 나란히 놓은 문서.

사용법:
    python tools/chunk_dump.py                      # data/parsed 전체
    python tools/chunk_dump.py --target-tokens 500
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_app.domain.enums import BlockType, FileType, OCRStatus  # noqa: E402
from rag_app.domain.models import ParsedBlock, ParsedDocument  # noqa: E402
from rag_app.processing.chunker import Chunker, ChunkingConfig, TokenCounter  # noqa: E402
from rag_app.processing.sentence_splitter import CompositeSentenceSplitter  # noqa: E402

DEFAULT_IN = Path("data/parsed")
DEFAULT_OUT = Path("data/chunks")


def load_document(path: Path) -> tuple[ParsedDocument, dict]:
    """파싱 덤프를 ParsedDocument로 되돌린다."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    source = Path(payload["source_path"])

    blocks = []
    for b in payload["blocks"]:
        blocks.append(ParsedBlock(
            block_type=BlockType(b["type"]),
            text=b["text"],
            page_number=b["page"],
            section_path=tuple(b["section_path"]),
            sequence=b["sequence"],
            metadata=dict(b["metadata"] or {}),
        ))

    document = ParsedDocument(
        document_id=uuid5(NAMESPACE_URL, str(source)),
        source_path=payload["source_path"],
        file_name=payload["file_name"],
        file_type=FileType.PDF,
        file_size=source.stat().st_size if source.exists() else 0,
        md5_hash="dump",
        modified_at=datetime.now(),
        blocks=tuple(blocks),
        language=payload["language"],
        ocr_status=OCRStatus(payload["ocr_status"]),
        ocr_pages=tuple(payload["ocr_pages"]),
    )
    return document, payload


def chunk_one(path: Path, out_dir: Path, chunker: Chunker) -> dict:
    document, payload = load_document(path)
    version_id = uuid5(NAMESPACE_URL, f"{document.source_path}#dump")
    chunks = chunker.chunk_document(document, document.document_id, version_id, "dump")

    records = [{
        "chunk_index": c.chunk_index,
        "page": c.page_number,
        "section_title": c.section_title,
        "token_count": c.token_count,
        "content": c.content,
    } for c in chunks]

    tokens = [c.token_count for c in chunks] or [0]
    tables = [b for b in document.blocks if b.block_type is BlockType.TABLE]
    review_blocks = [b for b in document.blocks if b.metadata.get("needs_review")]

    summary = {
        "file_name": document.file_name,
        "blocks": len(document.blocks),
        "chunks": len(chunks),
        "tokens_median": int(statistics.median(tokens)),
        "tokens_max": max(tokens),
        "over_max": sum(1 for t in tokens if t > chunker.config.max_tokens),
        "with_section": sum(1 for c in chunks if c.section_title),
        "tables": len(tables),
        # 표 하나가 청크 하나 안에 온전히 들어갔는지. 잘리면 행이 헤더와 떨어져 인용이 깨진다.
        "tables_intact": sum(1 for t in tables
                             if any(t.text in c.content for c in chunks)),
        # 검수 대상 블록의 글자가 어느 청크에 들어갔는지. 청크에는 검수 표시가 없다.
        "review_blocks": len(review_blocks),
        "review_in_chunks": sum(1 for b in review_blocks
                                if any(b.text[:60] in c.content for c in chunks)),
        "chunk_records": records,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = path.stem
    (out_dir / f"{stem}.json").write_text(
        json.dumps({k: v for k, v in summary.items()}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (out_dir / f"{stem}.review.md").write_text(_render_review(summary), encoding="utf-8")
    return summary


def _render_review(s: dict) -> str:
    lines = [f"# 청킹 검수 - {s['file_name']}\n"]
    lines.append(f"- 블록 {s['blocks']}개 → 청크 {s['chunks']}개")
    lines.append(f"- 토큰: 중앙값 {s['tokens_median']}, 최대 {s['tokens_max']}, "
                 f"상한 초과 {s['over_max']}개")
    lines.append(f"- 조항 경로가 붙은 청크: {s['with_section']}/{s['chunks']}")
    lines.append(f"- 표: {s['tables']}개 중 온전히 한 청크에 들어간 것 {s['tables_intact']}개")
    lines.append(f"- 검수 대상 블록 {s['review_blocks']}개 중 청크에 실린 것 "
                 f"{s['review_in_chunks']}개")
    lines.append("")
    for r in s["chunk_records"]:
        lines.append(f"## 청크 {r['chunk_index']} · {r['page']}쪽 · {r['token_count']}토큰")
        lines.append(f"조항: {r['section_title'] or '(없음)'}\n")
        lines.append("```")
        lines.append(r["content"])
        lines.append("```\n")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="파싱 덤프를 청킹해 검수용으로 저장")
    ap.add_argument("target", nargs="?", type=Path, default=DEFAULT_IN,
                    help=f"파싱 덤프 파일 또는 폴더 (기본 {DEFAULT_IN})")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--target-tokens", type=int, default=700)
    ap.add_argument("--overlap-tokens", type=int, default=100)
    ap.add_argument("--max-tokens", type=int, default=900)
    ap.add_argument("--page-boundary", action="store_true",
                    help="페이지 경계에서 끊는다. 기본은 조항 경계다.")
    args = ap.parse_args()

    files = (sorted(p for p in args.target.glob("*.json")) if args.target.is_dir()
             else [args.target])
    if not files:
        print(f"파싱 덤프 없음: {args.target}")
        return 1

    chunker = Chunker(
        config=ChunkingConfig(target_tokens=args.target_tokens,
                              overlap_tokens=args.overlap_tokens,
                              max_tokens=args.max_tokens,
                              preserve_page_boundary=args.page_boundary),
        token_counter=TokenCounter("BAAI/bge-m3"),
        sentence_splitter=CompositeSentenceSplitter(),
    )

    print(f"문서 {len(files)}건 · 목표 {args.target_tokens}토큰 "
          f"(겹침 {args.overlap_tokens}, 상한 {args.max_tokens}, "
          f"경계 {'페이지' if args.page_boundary else '조항'})")
    print(f"{'파일':<44} {'청크':>5} {'중앙':>5} {'최대':>5} {'초과':>4} {'조항%':>6} {'표온전':>8} 검수")
    print("-" * 100)
    for f in files:
        try:
            s = chunk_one(f, args.out, chunker)
        except Exception as e:
            print(f"{f.stem[:43]:<44} 실패: {type(e).__name__}: {e}")
            continue
        pct = s["with_section"] * 100 // s["chunks"] if s["chunks"] else 0
        print(f"{s['file_name'][:43]:<44} {s['chunks']:>5} {s['tokens_median']:>5} "
              f"{s['tokens_max']:>5} {s['over_max']:>4} {pct:>5}% "
              f"{s['tables_intact']:>3}/{s['tables']:<4} "
              f"{s['review_in_chunks']}/{s['review_blocks']}")

    print(f"\n저장 위치: {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
