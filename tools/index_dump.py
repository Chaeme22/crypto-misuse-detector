"""
파싱 산출물을 청킹·임베딩해 Qdrant에 넣는다.

`data/parsed/*.json`에서 출발한다. 파싱을 다시 돌리지 않고 색인만 반복할 수 있어야 하고,
청킹 기준이나 임베딩 방식을 바꿔 재보려면 그래야 한다.

밀집과 희소를 함께 넣는다. 표준문서 인용은 `ARIA-192`와 `ARIA-256`을 가려야 하는데
밀집 벡터만으로는 두 값이 거의 같은 점으로 간다. 어휘 가중치가 그걸 가른다.

사용법:
    python tools/index_dump.py                 # 기존 컬렉션에 추가
    python tools/index_dump.py --reset         # 비우고 다시 색인
    python tools/index_dump.py --dense-only    # 비교용. 희소 없이 밀집만
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chunk_dump import load_document  # noqa: E402
from rag_app.config.schema import AppConfig  # noqa: E402
from rag_app.domain.models import EmbeddedChunk  # noqa: E402
from rag_app.indexing.qdrant_store import QdrantStore  # noqa: E402
from rag_app.models.embedding import BgeM3Embedder  # noqa: E402
from rag_app.processing.chunker import Chunker, ChunkingConfig, TokenCounter  # noqa: E402
from rag_app.processing.sentence_splitter import CompositeSentenceSplitter  # noqa: E402


def embed_chunks(chunks: list[EmbeddedChunk], embedder: BgeM3Embedder,
                 dense_only: bool) -> list[EmbeddedChunk]:
    """청크 목록에 벡터를 채워 새 객체로 돌려준다."""
    texts = [c.content for c in chunks]
    dense = embedder.embed_documents(texts)
    sparse = [{}] * len(texts) if dense_only else embedder.embed_sparse(texts)

    return [replace(chunk, embedding=vector, sparse_embedding=weights)
            for chunk, vector, weights in zip(chunks, dense, sparse)]


def main() -> int:
    ap = argparse.ArgumentParser(description="파싱 산출물을 색인한다")
    ap.add_argument("target", nargs="?", type=Path, default=Path("data/parsed"))
    ap.add_argument("--target-tokens", type=int, default=700)
    ap.add_argument("--overlap-tokens", type=int, default=100)
    ap.add_argument("--max-tokens", type=int, default=900)
    ap.add_argument("--dense-only", action="store_true",
                    help="희소 벡터 없이 밀집만 색인한다. 하이브리드와 비교할 때 쓴다.")
    ap.add_argument("--reset", action="store_true",
                    help="색인 전에 컬렉션을 비운다. 기본은 비우지 않는다.")
    args = ap.parse_args()

    files = sorted(args.target.glob("*.json")) if args.target.is_dir() else [args.target]
    if not files:
        print(f"파싱 덤프 없음: {args.target}")
        return 1

    config = AppConfig(environment="development")
    store = QdrantStore(config)
    if args.reset:
        store.clear_collection()

    embedder = BgeM3Embedder(
        model_name=config.models.embedding.model_id,
        normalize_embeddings=config.models.embedding.normalize,
        hybrid=not args.dense_only,
    )
    chunker = Chunker(
        config=ChunkingConfig(target_tokens=args.target_tokens,
                              overlap_tokens=args.overlap_tokens,
                              max_tokens=args.max_tokens,
                              preserve_page_boundary=False),
        token_counter=TokenCounter(config.models.embedding.model_id),
        sentence_splitter=CompositeSentenceSplitter(),
    )

    print(f"문서 {len(files)}건 · 벡터 {'밀집' if args.dense_only else '밀집+희소'} "
          f"· 컬렉션 {config.qdrant.collection}")
    print(f"{'파일':<46}{'청크':>6}{'검수':>6}{'조항':>6}")
    print("-" * 66)

    total = 0
    for f in files:
        document, _ = load_document(f)
        version_id = uuid5(NAMESPACE_URL, f"{document.source_path}#dump")
        chunks = chunker.chunk_document(document, document.document_id, version_id, "dump")
        # 인용에 쓸 출처를 청크에 싣는다. 청커는 문서 메타데이터를 채우지 않는다.
        chunks = [replace(c,
                          source_path=document.source_path,
                          file_name=document.file_name,
                          file_type=document.file_type.value)
                  for c in chunks]
        chunks = embed_chunks(chunks, embedder, args.dense_only)
        store.stage(chunks)
        total += len(chunks)
        print(f"{document.file_name[:45]:<46}{len(chunks):>6}"
              f"{sum(1 for c in chunks if c.needs_review):>6}"
              f"{sum(1 for c in chunks if c.section_path):>6}", flush=True)

    print(f"\n색인한 청크 {total}개")
    print(f"저장 위치: {config.qdrant.url or '임베디드 모드'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
