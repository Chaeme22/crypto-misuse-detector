"""
검색 방식을 우리 코퍼스로 비교한다.

Tier-2 인용이 목적이므로 재는 것은 "근거 조항이 상위 k개 안에 들어오는가"다. 답변 품질이
아니라 인용 정확도다. 질의는 finding 모양으로 쓰고, 정답은 문서와 쪽 범위로 라벨링한다.
표나 절이 여러 쪽에 걸치므로 쪽 하나로 못 박지 않는다.

세 방식을 같은 색인 위에서 비교한다.
  밀집        질의를 밀집 벡터로만 검색
  하이브리드   밀집 + 어휘 가중치를 RRF로 합침
  +재순위     하이브리드 결과를 교차 인코더로 다시 정렬

사용법:
    python tools/retrieval_eval.py
    python tools/retrieval_eval.py --k 5
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_app.config.schema import AppConfig  # noqa: E402
from rag_app.domain.models import SearchQuery  # noqa: E402
from rag_app.indexing.qdrant_store import QdrantStore  # noqa: E402
from rag_app.models.embedding import BgeM3Embedder  # noqa: E402
from rag_app.models.reranker import BgeReranker  # noqa: E402

DEFAULT_SET = Path("config/retrieval_eval.json")


def matches(hit, expected: list[dict]) -> bool:
    """검색 결과가 정답 조항에 해당하는지. 문서 이름과 쪽 범위로 본다."""
    for target in expected:
        if target["document"] not in hit.file_name:
            continue
        if hit.page_number in target["pages"]:
            return True
    return False


def rank_of_first_match(hits, expected: list[dict]) -> int | None:
    for position, hit in enumerate(hits, 1):
        if matches(hit, expected):
            return position
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="검색 방식을 비교한다")
    ap.add_argument("--eval-set", type=Path, default=DEFAULT_SET)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--candidates", type=int, default=30)
    ap.add_argument("--show", action="store_true", help="질의별 결과를 함께 출력")
    args = ap.parse_args()

    spec = json.loads(args.eval_set.read_text(encoding="utf-8"))
    queries = spec["queries"]

    config = AppConfig(environment="development")
    store = QdrantStore(config)
    embedder = BgeM3Embedder(model_name=config.models.embedding.model_id,
                             normalize_embeddings=config.models.embedding.normalize,
                             hybrid=True)
    reranker = BgeReranker(config)

    scores = {"밀집": [], "하이브리드": [], "+재순위": []}
    rows = []

    for item in queries:
        text, expected = item["query"], item["expected"]
        dense = embedder.embed_query(text)
        sparse = embedder.embed_sparse([text])[0]

        dense_hits = store.search(SearchQuery(
            query_text=text, query_embedding=dense,
            candidate_count=args.candidates, minimum_score=0.0))
        hybrid_hits = store.search(SearchQuery(
            query_text=text, query_embedding=dense, query_sparse=sparse,
            candidate_count=args.candidates, minimum_score=0.0))
        reranked = reranker.rerank(text, list(hybrid_hits), top_k=args.k)

        ranks = {
            "밀집": rank_of_first_match(dense_hits[:args.k], expected),
            "하이브리드": rank_of_first_match(hybrid_hits[:args.k], expected),
            "+재순위": rank_of_first_match(reranked[:args.k], expected),
        }
        for name, rank in ranks.items():
            scores[name].append(rank)
        rows.append((text, ranks, hybrid_hits[:3]))

    print(f"질의 {len(queries)}건 · 상위 {args.k}개 안에 근거 조항이 있는지 · "
          f"후보 {args.candidates}개")
    print(f"{'방식':<12}{'적중':>8}{'적중률':>9}{'평균순위':>10}")
    print("-" * 42)
    for name, ranks in scores.items():
        hit = [r for r in ranks if r]
        mean = sum(hit) / len(hit) if hit else 0
        print(f"{name:<12}{len(hit):>4}/{len(ranks):<4}{len(hit)/len(ranks):>8.0%}{mean:>10.1f}")

    if args.show:
        print()
        for text, ranks, top in rows:
            marks = " ".join(f"{n}={r or '-'}" for n, r in ranks.items())
            print(f"- {text[:52]:<54} {marks}")
            for hit in top:
                print(f"    {hit.file_name[:34]:<36} {hit.page_number}쪽 "
                      f"{(hit.section_title or '')[:26]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
