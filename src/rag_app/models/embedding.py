"""
Embedding provider module using BAAI/bge-m3.

Provides EmbeddingProvider protocol and BgeM3Embedder implementation with batching,
vector normalization, and dimension validation.
"""

from typing import Protocol, List, Optional
import math
from ..domain.exceptions import ModelError
from ..observability.logging import get_logger

logger = get_logger(__name__)


class EmbeddingProvider(Protocol):
    """Protocol for embedding model providers."""
    
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of document texts."""
        ...
        
    def embed_sparse(self, texts: list[str]) -> list[dict[int, float]]:
        """어휘 가중치를 돌려준다. 하이브리드 검색용 희소 벡터."""
        ...

    def embed_query(self, text: str) -> list[float]:
        """Embed a single query text."""
        ...
        
    @property
    def dimension(self) -> int:
        """Return embedding vector dimension."""
        ...


def normalize_l2(vector: list[float]) -> list[float]:
    """Normalize vector to unit length (L2 norm = 1.0)."""
    sq_sum = sum(v * v for v in vector)
    if sq_sum <= 0:
        return vector
    norm = math.sqrt(sq_sum)
    return [v / norm for v in vector]


class BgeM3Embedder:
    """
    Embedding provider for BAAI/bge-m3 model.
    Supports local FlagEmbedding / SentenceTransformers / Transformers with CPU/GPU fallback.
    """
    
    def __init__(
        self,
        model_name: str = "BAAI/bge-m3",
        batch_size: int = 32,
        normalize_embeddings: bool = True,
        device: Optional[str] = None,
        hybrid: bool = False,
        allow_dummy: bool = False,
    ):
        self.model_name = model_name
        self.batch_size = int(batch_size) if batch_size else 32
        self.normalize_embeddings = bool(normalize_embeddings)
        self.device = device
        # 희소(어휘) 벡터까지 받으려면 FlagEmbedding 백엔드가 필요하다. SentenceTransformer
        # 경로는 밀집만 낸다. 우리 질의는 `ARIA-192`, `SHA-512/224` 같은 희귀 식별자가
        # 핵심이고 밀집 벡터는 그런 토큰을 구별하지 못하므로, 인용을 정확히 하려면 어휘
        # 일치가 필요하다.
        self.hybrid = bool(hybrid)
        # 모델을 못 불러왔을 때 상수 벡터로 계속 가도 되는지. 기본은 안 된다. 색인이
        # 무의미해지는데 파이프라인은 성공으로 보고하기 때문이다. 테스트에서만 켠다.
        self.allow_dummy = bool(allow_dummy)
        self._expected_dim = 1024
        self._model = None
        self._is_flag_model = False
        self._init_model()

    def _init_model(self):
        """Lazy or immediate model initialization."""
        import os

        # Check GPU availability. torch 자체가 없으면 아래 백엔드 로드도 실패하므로
        # 여기서 예외를 내지 않고 dummy 폴백 경로로 흘려보낸다.
        gpu_device = "cpu"
        try:
            import torch
            if torch.cuda.is_available():
                gpu_device = "cuda"
                logger.info("gpu_available", f"CUDA available: {torch.cuda.device_count()} GPU(s)")
            else:
                logger.warning("gpu_not_available", "CUDA not available, falling back to CPU")
        except ImportError:
            logger.warning("torch_not_available", "torch not installed, embedder will fall back to dummy")
        
        # 하이브리드가 필요하면 FlagEmbedding을 먼저 시도한다. 조용히 밀집 전용으로
        # 떨어지면 희소 검색이 사라진 것을 알아채기 어렵다.
        if self.hybrid:
            from FlagEmbedding import BGEM3FlagModel
            use_fp16 = (gpu_device == "cuda")
            self._model = BGEM3FlagModel(self.model_name, use_fp16=use_fp16, device=gpu_device)
            self._is_flag_model = True
            logger.info("bgem3_hybrid_loaded",
                        f"Loaded FlagEmbedding {self.model_name} on {gpu_device.upper()} (hybrid)")
            return

        # Try SentenceTransformer first (no multiprocessing pool issues)
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name, device=gpu_device)
            logger.info("st_loaded", f"Loaded SentenceTransformer model {self.model_name} on {gpu_device.upper()}")
            return
        except Exception as e:
            logger.warning("st_load_failed", f"SentenceTransformer load failed: {e}")

        # Fallback to FlagEmbedding if SentenceTransformer not available
        try:
            from FlagEmbedding import BGEM3FlagModel
            use_fp16 = (gpu_device == "cuda")
            self._model = BGEM3FlagModel(self.model_name, use_fp16=use_fp16, device=gpu_device)
            logger.info("bgem3_loaded", f"Loaded FlagEmbedding model {self.model_name} on {gpu_device.upper()} (fp16={use_fp16})")
            return
        except Exception as e:
            logger.warning("bgem3_load_failed", f"FlagEmbedding load failed: {e}")

        logger.warning("embedder_init_fallback", f"No embedding backend found for {self.model_name}, fallback dummy mode")

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """
        Generate embedding vectors for a list of document texts in batches.
        """
        if not texts:
            return []
        
        # Handle empty/blank texts
        processed_texts = [t.strip() if t and t.strip() else "(empty)" for t in texts]
        
        if self._model is not None:
            try:
                if hasattr(self._model, "encode"):
                    model_type = type(self._model).__name__
                    b_size = int(self.batch_size)
                    if "BGEM3" in model_type or "Flag" in model_type or "M3Embedder" in model_type:
                        # device는 모델 생성 시 정해진다. FlagEmbedding 최신판은 encode에
                        # device를 다시 받으면 중복 인자로 터진다.
                        output = self._model.encode(processed_texts, batch_size=b_size,
                                                    max_length=8192)
                        dense_vecs = output["dense_vecs"] if isinstance(output, dict) and "dense_vecs" in output else output
                    else:
                        try:
                            output = self._model.encode(
                                processed_texts, 
                                batch_size=b_size,
                                normalize_embeddings=self.normalize_embeddings,
                            )
                        except TypeError:
                            output = self._model.encode(processed_texts, batch_size=b_size)
                        # Always extract dense_vecs from dict output (safety)
                        dense_vecs = output["dense_vecs"] if isinstance(output, dict) and "dense_vecs" in output else output
                    
                    results = []
                    for vec in dense_vecs:
                        v_list = vec.tolist() if hasattr(vec, "tolist") else [float(x) for x in vec]
                        if self.normalize_embeddings:
                            v_list = normalize_l2(v_list)
                        self._validate_dimension(v_list)
                        results.append(v_list)
                    return results
            except Exception as e:
                logger.error("embedding_error", f"Embedding generation failed: {e}")
                raise ModelError(f"Embedding failed: {e}") from e
        
        # 모든 텍스트에 동일한 상수 벡터를 주는 폴백. 검색 결과가 사실상 무작위가 되므로
        # 실환경에서 이 경로를 타면 색인 전체가 무의미해진다. 그런데도 파이프라인은 성공으로
        # 보고한다. 그래서 명시적으로 허용하지 않으면 여기서 멈춘다.
        if not self.allow_dummy:
            raise ModelError(
                f"임베딩 백엔드를 불러오지 못했다({self.model_name}). 상수 벡터로 계속하면 "
                f"색인이 무의미해지므로 중단한다. torch와 모델을 설치하거나 "
                f"allow_dummy=True로 명시할 것.")

        logger.warning(
            "embedding_dummy_used",
            f"No embedding backend loaded - returning {len(processed_texts)} identical constant "
            f"vectors. Search results will be meaningless. Install torch and the embedding model.",
            model_id=self.model_name,
            count=len(processed_texts),
        )
        results = []
        for text in processed_texts:
            dummy_vec = [0.01 * (i % 10 + 1) for i in range(self._expected_dim)]
            if self.normalize_embeddings:
                dummy_vec = normalize_l2(dummy_vec)
            results.append(dummy_vec)
        return results

    def embed_sparse(self, texts: list[str]) -> list[dict[int, float]]:
        """
        어휘 가중치를 돌려준다. 토큰 id를 키로 하는 희소 벡터다.

        하이브리드로 만들지 않은 임베더에서는 빈 사전을 돌려준다. 조용히 밀집만 쓰는 상황을
        호출한 쪽에서 확인할 수 있어야 하므로 예외를 내지 않는다.
        """
        if not texts or not self._is_flag_model:
            return [{} for _ in texts]

        processed = [t.strip() if t and t.strip() else "(empty)" for t in texts]
        out: list[dict[int, float]] = []
        for start in range(0, len(processed), self.batch_size):
            batch = processed[start:start + self.batch_size]
            result = self._model.encode(batch, return_dense=False, return_sparse=True,
                                        return_colbert_vecs=False)
            for weights in result["lexical_weights"]:
                out.append({int(token): float(weight) for token, weight in weights.items()
                            if float(weight) > 0})
        return out

    def embed_query(self, text: str) -> list[float]:
        """Embed a single query text."""
        res = self.embed_documents([text])
        return res[0] if res else [0.0] * self._expected_dim

    @property
    def dimension(self) -> int:
        return self._expected_dim

    def _validate_dimension(self, vector: list[float]):
        """Ensure vector dimension matches expected 1024."""
        if len(vector) != self._expected_dim:
            raise ModelError(f"Vector dimension mismatch: expected {self._expected_dim}, got {len(vector)}")


def get_embedder(config) -> BgeM3Embedder:
    """Factory function for BgeM3Embedder."""
    emb_cfg = config.models.embedding
    return BgeM3Embedder(
        model_name=emb_cfg.model_id,
        normalize_embeddings=emb_cfg.normalize,
    )
