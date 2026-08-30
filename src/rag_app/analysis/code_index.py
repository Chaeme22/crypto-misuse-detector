"""
코드 벡터 인덱스.

파이프라인 설계의 지식 소스 셋 중 하나다. 표준문서 쪽은 bge-m3로 색인해 두었고, 이건
검사 대상 코드 쪽이다.

용도를 분명히 해둔다. **값을 확정하는 데 쓰지 않는다.** 그건 호출 지점 색인이 구조로
정확히 답한다. 여기는 의미로 찾는 자리다. 트리거 목록이 모르는 암호 관련 코드를 후보로
올리거나, 판정할 지점과 비슷한 자리를 찾아 함께 보여주는 데 쓴다.

임베딩은 GraphCodeBERT를 쓴다. 코드와 데이터 흐름을 함께 학습한 인코더라 식별자 중심의
코드에서 일반 문장 임베딩보다 낫다. 분류기로 쓰려면 학습이 필요하지만 **유사도 검색은
학습 없이 된다.** 지금 쓰는 건 검색뿐이다.

길이 제한이 512 토큰이라 함수 하나가 그보다 길면 잘린다. 표준문서 청킹(700토큰 목표)과
기준이 다르므로 같은 잣대로 보면 안 된다.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from ..observability.logging import get_logger

logger = get_logger(__name__)

MODEL_ID = "microsoft/graphcodebert-base"
MAX_TOKENS = 512
COLLECTION = "code_chunks_v1"
VECTOR_SIZE = 768


@dataclass(frozen=True, slots=True)
class CodeChunk:
    """색인 단위. 함수 하나가 기본이다."""
    file_path: str
    start_line: int
    end_line: int
    name: str            # 함수나 메서드 이름
    language: str
    text: str


def chunk_python(path: Path, relative: str, source: str) -> list[CodeChunk]:
    """Python 파일을 함수·메서드 단위로 자른다. 최상위 문장은 버린다."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines = source.splitlines()
    out: list[CodeChunk] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", start) or start
        body = "\n".join(lines[start - 1:end])
        if body.strip():
            out.append(CodeChunk(relative, start, end, node.name, "python", body))
    return out


def chunk_java(path: Path, relative: str, source: str) -> list[CodeChunk]:
    """Java 파일을 메서드 단위로 자른다."""
    from tree_sitter import Language, Parser
    import tree_sitter_java

    from .extract_java import _text, _walk

    raw = source.encode("utf-8")
    tree = Parser(Language(tree_sitter_java.language())).parse(raw)
    out: list[CodeChunk] = []
    for node in _walk(tree.root_node):
        if node.type not in ("method_declaration", "constructor_declaration"):
            continue
        name_node = node.child_by_field_name("name")
        out.append(CodeChunk(
            file_path=relative,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            name=_text(name_node, raw) if name_node is not None else "?",
            language="java",
            text=_text(node, raw),
        ))
    return out


def collect_chunks(root: Path, max_bytes: int = 2_000_000,
                   skip_dirs: frozenset[str] = frozenset(
                       {".git", "__pycache__", ".venv", "venv", "node_modules",
                        ".pytest_cache", ".mypy_cache", "data", "build", "target"})
                   ) -> list[CodeChunk]:
    """검사 루트에서 색인할 코드 덩어리를 모은다."""
    out: list[CodeChunk] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.suffix not in (".py", ".java"):
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        if path.suffix == ".py":
            out.extend(chunk_python(path, relative, source))
        else:
            try:
                out.extend(chunk_java(path, relative, source))
            except Exception as e:
                logger.warning("code_chunk_failed", f"{relative}: {e}")
    return out


class CodeEmbedder:
    """GraphCodeBERT로 코드를 벡터로 만든다. 평균 풀링을 쓴다."""

    def __init__(self, model_id: str = MODEL_ID, device: str = "cuda",
                 batch_size: int = 16):
        import torch
        from transformers import AutoModel, AutoTokenizer

        if device == "cuda" and not torch.cuda.is_available():
            device = "cpu"
        self.device = device
        self.batch_size = batch_size
        self.tokenizer = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModel.from_pretrained(model_id).to(device)
        self.model.eval()
        logger.info("code_embedder_loaded", f"Loaded {model_id} on {device.upper()}")

    def embed(self, texts: list[str]) -> list[list[float]]:
        import torch

        out: list[list[float]] = []
        for start in range(0, len(texts), self.batch_size):
            batch = texts[start:start + self.batch_size]
            encoded = self.tokenizer(batch, padding=True, truncation=True,
                                     max_length=MAX_TOKENS, return_tensors="pt").to(self.device)
            with torch.no_grad():
                hidden = self.model(**encoded).last_hidden_state
            # 패딩 자리를 빼고 평균한다. 그냥 평균하면 짧은 코드가 패딩에 묻힌다.
            mask = encoded["attention_mask"].unsqueeze(-1).float()
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
            pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
            out.extend(pooled.cpu().tolist())
        return out


class CodeIndex:
    """
    코드 벡터를 Qdrant에 담고 찾는다.

    표준문서와 다른 컬렉션을 쓴다. 임베딩 모델이 다르고(768차원 대 1024차원) 성격도 달라서
    섞으면 검색 결과가 뒤엉킨다.

    저장소마다 다시 만드는 색인이므로 넣기 전에 그 저장소 몫을 지운다. 남겨두면 지난 검사의
    코드가 결과에 섞인다.
    """

    def __init__(self, config, embedder: CodeEmbedder | None = None,
                 collection: str = COLLECTION):
        from qdrant_client.http import models as rest

        from ..indexing.qdrant_store import QdrantStore

        self.collection = collection
        self.embedder = embedder or CodeEmbedder()
        # 문서 저장소와 같은 클라이언트를 쓰되 컬렉션만 다르게 둔다.
        self.client = QdrantStore(config).client
        if self.client is None:
            raise RuntimeError("Qdrant에 연결하지 못해 코드 색인을 만들 수 없다")

        existing = {c.name for c in self.client.get_collections().collections}
        if collection not in existing:
            self.client.create_collection(
                collection_name=collection,
                vectors_config={"code": rest.VectorParams(
                    size=VECTOR_SIZE, distance=rest.Distance.COSINE)},
            )
            self.client.create_payload_index(
                collection_name=collection, field_name="repo",
                field_schema=rest.PayloadSchemaType.KEYWORD)

    def build(self, root: Path, repo: str | None = None) -> int:
        """저장소를 색인한다. 넣은 덩어리 수를 돌려준다."""
        from qdrant_client.http import models as rest

        repo = repo or str(root.resolve())
        chunks = collect_chunks(root)
        if not chunks:
            return 0

        self.client.delete(
            collection_name=self.collection,
            points_selector=rest.FilterSelector(filter=rest.Filter(must=[
                rest.FieldCondition(key="repo", match=rest.MatchValue(value=repo))])),
        )

        vectors = self.embedder.embed([c.text for c in chunks])
        points = []
        for position, (chunk, vector) in enumerate(zip(chunks, vectors)):
            points.append(rest.PointStruct(
                id=abs(hash((repo, chunk.file_path, chunk.start_line, position))) % (2**63),
                vector={"code": vector},
                payload={
                    "repo": repo,
                    "file_path": chunk.file_path,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "name": chunk.name,
                    "language": chunk.language,
                    "text": chunk.text[:4000],
                },
            ))

        for start in range(0, len(points), 256):
            self.client.upsert(collection_name=self.collection,
                               points=points[start:start + 256], wait=True)
        logger.info("code_index_built", f"{repo}: 코드 덩어리 {len(points)}개 색인")
        return len(points)

    def search(self, query_code: str, repo: str | None = None,
               limit: int = 5) -> list[dict]:
        """비슷한 코드를 찾는다. 질의는 코드 조각이다."""
        from qdrant_client.http import models as rest

        vector = self.embedder.embed([query_code])[0]
        query_filter = None
        if repo:
            query_filter = rest.Filter(must=[rest.FieldCondition(
                key="repo", match=rest.MatchValue(value=repo))])
        response = self.client.query_points(
            collection_name=self.collection, query=vector, using="code",
            limit=limit, query_filter=query_filter, with_payload=True)
        return [{**point.payload, "score": round(float(point.score), 4)}
                for point in response.points]
