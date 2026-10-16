"""
판정 계약.

LLM이 내놓는 것과 코드가 만드는 것을 여기서 가른다. LLM은 `Verdict`만 낸다. 위반인지,
확신도가 얼마인지, 왜 그런지, 어떻게 고치는지다. 위치와 규칙 번호와 인용 조항은 LLM이
쓰지 않는다. 위치는 정적 추출이 이미 정확히 알고, 규칙 번호는 표에서 조회하는 값이고,
조항은 검색이 돌려주는 값이다. 그것들을 LLM에게 옮겨 적게 하면 틀린다.

이렇게 가르면 모델을 바꿔도 계약이 같다. LLM은 교체 가능한 부품이고 이 스키마가 소켓이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    """
    판정 결과. 답이 둘뿐이면 정보가 부족해도 하나를 골라야 하므로 억지 판정이 나온다.

    실제로 그런 일이 있었다. 값이 변수로 들어온 자리에서 모델이 주변 코드의 다른 문자열을
    끌어다 "실제로는 DESede/CBC가 쓰인다"고 답했다. 볼 수 없는 것을 물었기 때문이다.
    모르겠다고 답할 길을 열어두면 그 답이 지어낸 답보다 쓸모 있다.
    """
    VIOLATION = "violation"
    CLEAN = "clean"
    UNDETERMINED = "undetermined"   # 판정에 필요한 사실을 확인하지 못했다
    # 표 기준 최소(112비트)는 만족하지만 권장(128비트)에 못 미친다. KISA 안내서상 2030년까지 유효하다.
    # SEED·ARIA-128·LEA-128·HIGHT·3TDEA·RSA-2048이 여기다. 위반과 섞으면 국내에서 요구하는 SEED 사용까지
    # 고쳐야 할 것으로 보고된다. 표 대조로만 정해지고 모델에게 묻지 않는다(2026-10-08 결정).
    WARNING = "warning"


class Level(str, Enum):
    """SARIF가 정의한 심각도. 우리 규칙표가 이 값을 갖는다."""
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class UsageSite:
    """정적 추출이 찾아낸 암호 사용 지점. 위치의 유일한 출처다."""
    file_path: str            # 검사 대상 루트 기준 상대 경로
    line: int                 # 1부터
    column: int = 1
    snippet: str = ""         # 그 줄. SARIF region의 snippet이 된다.
    # 판정에 넘길 주변 코드. 한 줄만 주면 알고리즘 이름 목록과 실제 연산을 가릴 수 없다.
    # 실제로 한 줄만 넘겼을 때 모델이 후보 5건을 전부 위반으로 판정했다.
    context: str = ""
    api: str = ""             # 무엇을 호출했는지. 사람이 읽는 표기다.
    # 임계값 표와 견주려면 사람이 읽는 표기 말고 구조가 필요하다. `api`는
    # `MessageDigest.getInstance("MD5")`처럼 호출과 값을 한 문자열에 담아 보고서에는
    # 좋지만 비교에는 못 쓴다. 아래 셋을 나눠 둔다.
    call: str = ""            # 호출 이름만. `MessageDigest.getInstance`. 목적을 정한다.
    algorithm_spec: str = ""  # 코드에 적힌 알고리즘. `MD5`, `AES/ECB/PKCS5Padding`
    key_bits: int | None = None   # 코드에서 찾은 키 길이. `initialize(1024)`의 1024
    language: str = ""
    # 변수를 따라가 찾아낸 실제 값. 찾았으면 모델이 값을 보고 판단할 수 있다.
    traced_values: tuple[str, ...] = ()
    # 빌드 규약으로 판정한 테스트 코드 여부. 모델에게 경로를 보고 추측하게 하지 않는다.
    # 실제 저장소에서 `src/test/java` 아래 열한 건이 전부 위반으로 보고됐다.
    is_test: bool = False
    # 값이 리터럴이 아니라 변수로 들어온 인자 이름. 예를 들어
    # `Cipher.getInstance(transformation)`은 그 변수가 어디서 왔는지 봐야 판정이 된다.
    # 설계에서 provenance slice로 넘기는 대상이 이것이고, 확신도 상한도 여기서 걸린다.
    unresolved_args: tuple[str, ...] = ()
    # 비밀 재료(키·IV·솔트·비밀번호·시드)가 어디서 왔는지. provenance.py가 구조로 판별한다.
    # `constant`·`predictable`·`below_minimum`이면 위반, `secure_random`·`meets_minimum`이면
    # 정상, 그 밖이면 판정하지 않는다. 비어 있으면 출처를 묻는 규칙이 아니다.
    provenance: str = ""
    provenance_note: str = ""   # 왜 그렇게 봤는지. 보고서와 모델 프롬프트에 그대로 쓴다.

    def __post_init__(self):
        if self.line < 1:
            raise ValueError("line은 1부터 시작한다")
        if not self.file_path:
            raise ValueError("file_path가 비어 있다")


@dataclass(frozen=True, slots=True)
class Rule:
    """
    Tier-1 규칙. 탐지를 촉발하는 쪽이다.

    임계값은 표준문서에서 뽑아 사람이 확인한 값이다. 검색으로 정하지 않는다. 같은 코드에
    같은 판정이 나와야 하기 때문이다.
    """
    rule_id: str              # 예: CRYPTO-HASH-WEAK
    name: str
    cwe: str                  # 예: CWE-328
    level: Level
    summary: str              # 한 문장. SARIF rule의 shortDescription.
    detail: str               # 왜 문제인지. fullDescription.
    remediation: str          # 무엇으로 바꾸라는 것인지.
    # 이 규칙의 근거를 찾을 때 Tier-2 검색에 넣을 질의.
    clause_query: str = ""
    # 규칙이 걸리는 호출 이름. `hashlib.md5`처럼 점으로 이은 형태다.
    api_triggers: tuple[str, ...] = ()
    # 규칙이 걸리는 문자열 리터럴 조각. `AES/ECB`처럼 코드에 적히는 값이다.
    literal_triggers: tuple[str, ...] = ()
    # 이 규칙이 담당하는 임계값 표의 목적. 리터럴 목록에 없는 알고리즘이 나왔을 때
    # 어느 규칙으로 보고할지 정한다. 목록을 손으로 늘리는 대신 표가 답하게 하려면
    # 표의 목적과 규칙을 잇는 이 연결이 필요하다.
    table_purposes: tuple[str, ...] = ()
    # 임계값 표가 이 규칙의 질문에 답을 주는지. 운영모드(ECB)와 난수 생성은 표에 아예
    # 없다. 그런 규칙에 표 대조 문장을 붙이면 `AES는 표 기준 만족`이 ECB 지적 옆에
    # 붙어 보고서가 사람을 헷갈리게 한다.
    table_measures: bool = False
    # 임계값 표의 비교만으로 이 규칙의 질문이 끝나는지. 끝나지 않는 규칙이 있다.
    # 운영모드(ECB)와 난수 생성은 표에 아예 없고, `PBKDF2WithHmacSHA1`은 표 3에 따르면
    # 해시 선택이 문제가 아니라 반복 횟수가 문제인데 그건 재고 있지 않다. 표가 만족이라고
    # 해도 그런 규칙은 닫지 않는다.
    table_decides: bool = False
    # 출처를 볼 인자. (트리거, 인자 위치) 쌍이다. `new PBEKeySpec`의 0번은 비밀번호,
    # 1번은 솔트다. 호출이 있다는 것만으로는 판정이 서지 않고 그 인자가 상수인지 난수인지가
    # 판정을 가른다.
    material_args: tuple[tuple[str, int], ...] = ()
    # 반복 횟수를 볼 인자와 최소값. 최소값은 표준 문서 값이며 출처를 규칙표에 적는다.
    iteration_args: tuple[tuple[str, int], ...] = ()
    min_iterations: int | None = None


@dataclass(frozen=True, slots=True)
class Citation:
    """Tier-2 근거 조항. 검색이 돌려준 값을 그대로 옮긴다."""
    document: str
    page: int | None
    section_path: tuple[str, ...]
    quote: str
    score: float = 0.0
    needs_review: bool = False   # 원문 대조가 필요한 판독에서 나온 조항인지

    def label(self) -> str:
        """사람이 읽을 인용 표기."""
        where = " > ".join(self.section_path) if self.section_path else "(조항 정보 없음)"
        page = f", {self.page}쪽" if self.page else ""
        return f"{self.document}{page} — {where}"


@dataclass(frozen=True, slots=True)
class Verdict:
    """
    LLM이 내놓는 판정. 이 스키마를 어기면 받지 않는다.

    `CLEAN`만 보고서에서 빠진다. `UNDETERMINED`는 사람이 확인할 목록으로 나간다. 조용히
    버리면 검사에서 빠진 자리를 아무도 모른다.

    확신도 숫자는 받지 않는다. 모델이 신고하는 값은 늘 0.95나 1.0이라 아무것도 구분하지
    못했고, 검량하지 않은 숫자를 보고서에 실으면 거짓 안심을 준다. `0.89`를 본 사람이
    무엇을 해야 하는지도 알 수 없다. 대신 판정을 뒷받침하는 사실을 그대로 드러낸다.
    값이 확정됐는지, 근거 조항이 검수된 판독에서 나왔는지다. 그 둘이면 고칠지 사람이 볼지
    정할 수 있다.
    """
    decision: Decision
    reasoning: str             # 왜 그렇게 봤는지. 한 문단.
    suggested_fix: str = ""
    # 코드의 역할을 무엇으로 봤는지. 오탐을 추적하려면 판단 경로가 남아야 한다.
    role: str = ""

    def __post_init__(self):
        if self.decision is Decision.VIOLATION and not self.reasoning.strip():
            raise ValueError("위반으로 판정했으면 근거를 적어야 한다")

    @property
    def is_violation(self) -> bool:
        return self.decision is Decision.VIOLATION

    @property
    def needs_human(self) -> bool:
        return self.decision is Decision.UNDETERMINED


@dataclass(frozen=True, slots=True)
class Finding:
    """SARIF 한 건이 되는 조립 결과. 네 출처가 여기서 합쳐진다."""
    site: UsageSite            # 정적 추출
    rule: Rule                 # Tier-1 규칙표
    verdict: Verdict           # LLM
    citations: tuple[Citation, ...] = field(default=())   # Tier-2 검색
    measurement: object | None = None   # 코드가 표와 견준 결과. thresholds.Measurement

    @property
    def value_resolved(self) -> bool:
        """판정에 필요한 값이 확정됐는지. 못 찾은 인자가 있으면 아니다."""
        return not self.site.unresolved_args

    @property
    def evidence_reviewed(self) -> bool:
        """근거 조항이 모두 원문 대조를 마친 판독에서 나왔는지."""
        return bool(self.citations) and not any(c.needs_review for c in self.citations)

    def message(self) -> str:
        """SARIF result의 message. 판정 근거와 인용을 함께 놓는다."""
        parts = []
        if self.verdict.needs_human:
            unknown = ", ".join(self.site.unresolved_args) or "값"
            parts.append(f"[확인 필요] {unknown}의 실제 값을 코드에서 찾지 못해 판정하지 "
                         f"못했다. 이 값이 어디서 오는지 확인해야 한다.")
        parts.append(self.verdict.reasoning.strip())

        # 표 대조만으로 판정이 선 건은 근거가 이미 그 문장이다. 두 번 쓰지 않는다.
        if (self.measurement is not None
                and self.measurement.sentence() not in self.verdict.reasoning):
            parts.append("표 대조: " + self.measurement.sentence())

        if self.value_resolved:
            traced = ", ".join(self.site.traced_values)
            parts.append(f"값 확인: 코드에서 확정됨" + (f" ({traced})" if traced else ""))

        if self.citations:
            mark = "" if self.evidence_reviewed else " · 원문 대조가 필요한 판독에서 나온 조항"
            parts.append("근거: " + "; ".join(c.label() for c in self.citations) + mark)

        if self.verdict.suggested_fix:
            parts.append("수정 제안: " + self.verdict.suggested_fix.strip())
        return "\n".join(parts)
