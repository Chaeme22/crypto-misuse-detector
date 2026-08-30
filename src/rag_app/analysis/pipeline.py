"""
검사 파이프라인.

목표 설계의 노드 배치를 따른다. 획득 → 정적 추출 → (규칙 조회) → 판정 → 상관 → 보고.
지금은 조건부 분기가 없어 함수 호출로 잇는다. triage에서 provenance slice로 갈라지는
분기가 생기면 그때 상태 기계로 감싼다. 노드마다 상태를 넘겨받고 상태를 돌려주는 모양을
지켜 두었으므로 감싸는 작업이 배선으로 끝난다.

Tier-2 조항은 판정 전에 붙인다. 근거를 본 뒤 판정하게 하는 것이 설계의 요지다.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import replace
from dataclasses import dataclass, field
from pathlib import Path

from ..config.schema import AppConfig
from ..domain.models import SearchQuery
from ..observability.logging import get_logger
from . import extract, repo_info, rules as tier1, sarif
from .findings import Citation, Decision, Finding, Rule, UsageSite, Verdict
from .thresholds import Measurement, Outcome, ThresholdTable
from .verdict import StaticVerdict, VerdictProvider

logger = get_logger(__name__)


@dataclass
class AnalysisState:
    """노드 사이를 오가는 상태. 상태 기계로 감쌀 때 그대로 쓴다."""
    target: str                       # 저장소 URL 또는 로컬 경로
    root: Path | None = None          # 획득한 소스 루트
    rules: list[Rule] = field(default_factory=list)
    sites: list[tuple[UsageSite, Rule]] = field(default_factory=list)
    thresholds: ThresholdTable | None = None
    # 표 대조만으로 닫힌 건수. 모델을 부르지 않고 끝난 자리다.
    closed_by_table: int = 0
    # 검사 대상의 신원. 보고서가 어느 시점의 어떤 코드에 대한 것인지 증명한다.
    provenance: dict | None = None
    dependencies: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    cleanup: Path | None = None       # 임시로 clone한 경로. 끝나면 지운다.


def acquire(state: AnalysisState) -> AnalysisState:
    """저장소를 가져온다. URL이면 얕은 clone, 경로면 그대로 쓴다."""
    target = state.target
    if target.startswith(("http://", "https://", "git@")):
        destination = Path(tempfile.mkdtemp(prefix="cryptomisuse_"))
        logger.info("acquire_clone", f"clone {target} → {destination}")
        # 히스토리는 필요 없다. 검사 대상은 현재 스냅샷이다.
        subprocess.run(["git", "clone", "--depth", "1", target, str(destination)],
                       check=True, capture_output=True, text=True, timeout=600)
        state.root = destination
        state.cleanup = destination
    else:
        root = Path(target).expanduser().resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"검사할 경로가 없다: {root}")
        state.root = root

    # 무엇을 검사했는지 못박는다. 커밋 해시가 없으면 보고서와 코드를 잇지 못한다.
    state.provenance = repo_info.snapshot(state.root)
    if state.provenance is None:
        logger.warning("no_git_snapshot",
                       "git 저장소가 아니라 커밋 스냅샷을 남기지 못했다")
    state.dependencies = repo_info.dependencies(state.root)
    logger.info("acquired",
                f"커밋 {(state.provenance or {}).get('revisionId', '없음')[:12]} · "
                f"선언된 의존성 {len(state.dependencies)}개")
    return state


def load_rules(state: AnalysisState) -> AnalysisState:
    state.rules = tier1.load()
    logger.info("rules_loaded", f"Tier-1 규칙 {len(state.rules)}개")
    return state


def load_thresholds(state: AnalysisState) -> AnalysisState:
    """표에서 뽑은 임계값을 읽는다. 규칙표의 산문을 숫자 비교로 바꾸는 값이다."""
    state.thresholds = ThresholdTable.load()
    logger.info("thresholds_loaded",
                f"임계값 {len(state.thresholds.rows)}행 · 최소 "
                f"{state.thresholds.minimum}비트 · 권장 {state.thresholds.recommended}비트")
    return state


def extract_sites(state: AnalysisState) -> AnalysisState:
    state.sites = extract.collect(state.root, state.rules)
    logger.info("sites_extracted", f"암호 사용 지점 {len(state.sites)}건")
    return state


class ClauseFinder:
    """
    Tier-2 조항 검색.

    밀집과 희소를 함께 쓴다. `ARIA-192`와 `ARIA-256`을 밀집 벡터만으로는 못 가리므로
    인용이 어긋난다. 재순위까지 얹으면 첫 번째 결과의 정확도가 올라간다.
    """

    def __init__(self, config: AppConfig, top_k: int = 2):
        from ..indexing.qdrant_store import QdrantStore
        from ..models.embedding import BgeM3Embedder
        from ..models.reranker import BgeReranker

        self.top_k = top_k
        self.store = QdrantStore(config)
        self.embedder = BgeM3Embedder(
            model_name=config.models.embedding.model_id,
            normalize_embeddings=config.models.embedding.normalize,
            hybrid=True)
        self.reranker = BgeReranker(config)
        self.candidate_count = config.retrieval.candidate_count

    def find(self, query: str) -> tuple[Citation, ...]:
        if not query.strip():
            return ()
        hits = self.store.search(SearchQuery(
            query_text=query,
            query_embedding=self.embedder.embed_query(query),
            query_sparse=self.embedder.embed_sparse([query])[0],
            candidate_count=self.candidate_count,
            minimum_score=0.0))
        best = self.reranker.rerank(query, list(hits), top_k=self.top_k)
        return tuple(
            Citation(
                document=hit.file_name,
                page=hit.page_number,
                section_path=tuple(hit.section_path),
                quote=hit.content[:400],
                score=round(float(hit.rerank_score or hit.score), 4),
                needs_review=hit.needs_review,
            )
            for hit in best[:self.top_k]
        )


def enforce(site: UsageSite, verdict: Verdict) -> Verdict:
    """
    판정의 전제가 없으면 모델 판정을 채택하지 않는다.

    판단은 모델이 하지만, 판단의 바닥이 비어 있으면 그 판단을 쓸 수 없다. 두 경우다.

    값을 못 찾은 자리를 모델이 위반으로 단정하는 일이 실제로 있었다. 프롬프트에 못 찾았다고
    적어도 무시했다. 그래서 코드가 확인 필요로 되돌린다.

    테스트 소스는 운영 취약점이 아니다. 실제 저장소에서 `src/test/java` 아래 열한 건이
    전부 위반으로 보고됐다. 빌드 규약으로 판정할 수 있는 사실이므로 코드가 정한다.
    """
    if site.is_test and verdict.decision is Decision.VIOLATION:
        return replace(verdict, decision=Decision.CLEAN,
                       reasoning=("빌드 규약상 테스트 소스다. 운영 코드가 아니므로 "
                                  "보고하지 않는다. 원래 판정: "
                                  + verdict.reasoning.strip()[:200]))

    if site.unresolved_args and verdict.decision is not Decision.UNDETERMINED:
        # 위반이든 정상이든 마찬가지다. 값을 못 본 자리에서 나온 판정은 어느 쪽으로도
        # 채택하지 않는다. 전에는 위반만 되돌리고 정상은 그대로 받았는데, 그 비대칭
        # 때문에 하드코딩된 키 스물두 건이 조용히 사라졌다. 모델은 `byte[] keyBytes`가
        # 어디서 왔는지 볼 수 없었고, 볼 수 없는 것을 정상이라고 답한 것이다.
        # 조용히 버리면 검사에서 빠진 자리를 아무도 모른다.
        names = ", ".join(site.unresolved_args)
        return replace(verdict, decision=Decision.UNDETERMINED,
                       reasoning=(f"{names}의 값을 코드에서 확인하지 못해 판정을 채택하지 "
                                  f"않는다. 모델 판단({verdict.decision.value}): "
                                  + verdict.reasoning.strip()[:200]))
    return verdict


def measure(state: AnalysisState, site: UsageSite, rule: Rule) -> Measurement | None:
    """
    표와 견준다. 이 규칙의 질문에 표가 답을 주지 않으면 재지 않는다.

    운영모드와 난수 생성은 표에 없다. 그런 자리에 `AES는 표 기준 만족` 문장을 붙이면
    ECB 지적 옆에 만족 문구가 놓여 보고서가 사람을 헷갈리게 한다.
    """
    if not rule.table_measures or state.thresholds is None:
        return None
    return state.thresholds.measure(site)


def judge_sites(state: AnalysisState, provider: VerdictProvider,
                finder: ClauseFinder | None) -> AnalysisState:
    """
    사용 지점마다 재고, 근거를 붙이고, 판정한다.

    순서가 뜻을 갖는다. 먼저 코드가 표와 견줘 숫자를 확정하고, 그 결과를 사실로 모델에게
    넘긴다. 모델에게 `RSA 2048비트면 충분한가`를 묻지 않는다. 그건 표에 적힌 값이고
    모델이 기억으로 답하면 틀린다. 모델에게 남는 질문은 이 코드가 무엇에 쓰이는지다.

    표가 기준 만족이라고 답하고 그 규칙의 질문이 표로 끝나면 모델을 부르지 않는다.
    `MessageDigest.getInstance("SHA-256")`을 모델에게 물을 이유가 없다.
    """
    clause_cache: dict[str, tuple[Citation, ...]] = {}
    for site, rule in state.sites:
        measurement = measure(state, site, rule)

        if (measurement is not None and rule.table_decides
                and measurement.outcome is Outcome.MEETS):
            state.closed_by_table += 1
            state.findings.append(Finding(
                site=site, rule=rule, measurement=measurement,
                citations=(measurement.citation,) if measurement.citation else (),
                verdict=Verdict(decision=Decision.CLEAN,
                                reasoning=measurement.sentence(),
                                role="표 대조로 확정")))
            continue

        citations: tuple[Citation, ...] = ()
        if finder is not None:
            if rule.rule_id not in clause_cache:
                clause_cache[rule.rule_id] = finder.find(rule.clause_query)
            citations = clause_cache[rule.rule_id]
        # 표에서 온 인용을 앞에 둔다. 판정의 직접 근거이고 검색 결과보다 정확하다.
        if measurement is not None and measurement.citation is not None:
            citations = (measurement.citation,) + tuple(
                c for c in citations if (c.document, c.page) !=
                (measurement.citation.document, measurement.citation.page))

        verdict = enforce(site, provider.judge(site, rule, citations,
                                               measurement=measurement))
        state.findings.append(Finding(site=site, rule=rule, verdict=verdict,
                                      citations=citations,
                                      measurement=measurement))
    return state


def report(state: AnalysisState, out_path: Path) -> dict:
    return sarif.write(state.findings, root=str(state.root), out_path=out_path,
                       provenance=state.provenance,
                       dependencies=state.dependencies)


def run(target: str, out_path: Path, config: AppConfig,
        provider: VerdictProvider | None = None,
        with_clauses: bool = True) -> tuple[dict, AnalysisState]:
    """종단 실행. 상태를 함께 돌려주므로 호출한 쪽에서 중간 결과를 볼 수 있다."""
    import shutil

    state = AnalysisState(target=target)
    try:
        state = acquire(state)
        state = load_rules(state)
        state = load_thresholds(state)
        state = extract_sites(state)
        finder = ClauseFinder(config) if with_clauses else None
        state = judge_sites(state, provider or StaticVerdict(), finder)
        document = report(state, out_path)
        return document, state
    finally:
        if state.cleanup is not None:
            shutil.rmtree(state.cleanup, ignore_errors=True)
