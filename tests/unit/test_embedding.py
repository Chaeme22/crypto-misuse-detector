"""
Unit tests for BgeM3Embedder in models/embedding.py.
"""

import pytest
from rag_app.models.embedding import BgeM3Embedder, normalize_l2


def test_normalize_l2():
    vec = [3.0, 4.0]
    norm_vec = normalize_l2(vec)
    assert pytest.approx(norm_vec[0]) == 0.6
    assert pytest.approx(norm_vec[1]) == 0.8


def test_bge_m3_embedder_dummy_fallback():
    # 상수 벡터 폴백은 이제 명시적으로 허용해야 한다. 실환경에서 조용히 이 경로를 타면
    # 색인이 무의미해지므로 기본은 예외다.
    embedder = BgeM3Embedder(model_name="non_existent_model_name_for_fallback",
                             allow_dummy=True)
    assert embedder.dimension == 1024
    
    texts = ["안녕하세요", "RAG 시스템 구현 테스트입니다."]
    embeddings = embedder.embed_documents(texts)
    
    assert len(embeddings) == 2
    assert len(embeddings[0]) == 1024
    assert len(embeddings[1]) == 1024


def test_bge_m3_embed_query():
    # 상수 벡터 폴백은 이제 명시적으로 허용해야 한다. 실환경에서 조용히 이 경로를 타면
    # 색인이 무의미해지므로 기본은 예외다.
    embedder = BgeM3Embedder(model_name="non_existent_model_name_for_fallback",
                             allow_dummy=True)
    query_vec = embedder.embed_query("테스트 질의")
    
    assert len(query_vec) == 1024
