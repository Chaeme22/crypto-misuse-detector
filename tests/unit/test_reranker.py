"""
Unit tests for BgeReranker in models/reranker.py.
"""

from uuid import uuid4
from rag_app.config.schema import AppConfig
from rag_app.domain.models import SearchHit
from rag_app.models.reranker import BgeReranker


def test_bge_reranker_fallback():
    """모델을 못 불러온 경우 밀집 점수 순서를 그대로 유지하는지 본다.

    모델이 설치된 환경에서는 실제 리랭커가 순서를 바꾸므로, 폴백 경로만 확정적으로
    검사하도록 모델을 떼어 놓는다. 이 테스트의 대상은 폴백이지 리랭커 품질이 아니다.
    """
    config = AppConfig(environment="test")
    reranker = BgeReranker(config)
    reranker.model = None

    hit1 = SearchHit(
        chunk_id=uuid4(),
        document_id=uuid4(),
        version_id=uuid4(),
        index_profile_id="p1",
        chunk_index=0,
        content="낮은 dense 점수의 아주 관련성 높은 본문",
        source_path="doc1.pdf",
        file_name="doc1.pdf",
        file_type=".pdf",
        score=0.6,
    )
    hit2 = SearchHit(
        chunk_id=uuid4(),
        document_id=uuid4(),
        version_id=uuid4(),
        index_profile_id="p1",
        chunk_index=0,
        content="높은 dense 점수의 덜 관련성 있는 본문",
        source_path="doc2.pdf",
        file_name="doc2.pdf",
        file_type=".pdf",
        score=0.9,
    )

    hits = [hit1, hit2]
    result = reranker.rerank("관련성 테스트 질문", hits, top_k=2)

    assert len(result) == 2
    # In fallback mode, sorted by score descending (hit2 first)
    assert result[0].score == 0.9
