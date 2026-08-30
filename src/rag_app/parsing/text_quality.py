"""
추출된 텍스트의 손상 여부 판정.

스캔 문서를 OCR한 PDF는 텍스트 레이어가 존재하므로 글자 수 검사만으로는 정상 문서와
구분되지 않는다. 이 모듈은 문자 수준의 손상 흔적을 세어 색인 가능 여부를 판정한다.

표준/가이드라인 문서는 답이 짧은 토큰(2048, 112비트, SHA-1)에 담기므로 문자 하나가 깨지면
임계값 추출이 실패한다. 그래서 손상이 의심되면 색인을 막고 사람 검수로 넘긴다.

색인 파이프라인(`ingestion/coordinator.py`)과 진단 도구(`tools/kb_doctor.py`)가 같은 판정을
내려야 하므로 로직을 여기 한 곳에 둔다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# 단독 자모: 정상 한글 문서에는 거의 없고 OCR 실패 시 급증한다.
_JAMO = re.compile(r"[ㄱ-ㆎ]")
# 숫자에 붙은 l/I/O/S: "2O48", "1l2", "SHA-l" 형태의 문자-숫자 혼동 후보.
_DIGIT_CONFUSE = re.compile(r"(?:\d[lIOS]|[lIOS]\d)")
# 치환 실패 문자(U+FFFD)와 사물함 문자.
_REPLACEMENT = re.compile(r"[�□]")
# 공백 없이 이어진 과도하게 긴 토큰: 레이아웃 붕괴 신호.
# URL과 목차 점선 리더는 정상 문서에도 흔하므로 아래에서 걸러낸다.
_LONG_TOKEN = re.compile(r"\S{40,}")
_URL = re.compile(r"https?://|www\.|doi\.org")
_FILLER_RUN = re.compile(r"^[.\-_·‥…=~*]+$")

_HANGUL = re.compile(r"[가-힣]")
_LATIN = re.compile(r"[A-Za-z]")

# 한글 낱글자 사이에 공백이 끼어드는 현상("패 스 워 드 선 택").
# 한글 OCR의 전형적 실패이며, 어절이 깨지므로 검색·매칭이 전부 실패한다.
_SPACED_HANGUL = re.compile(r"(?:[가-힣][ \t]){3,}[가-힣]")

# 이 코퍼스에서 살아 있어야 하는 핵심 토큰. 판정에는 쓰지 않고 참고 지표로만 보고한다.
CRYPTO_TOKENS = (
    "AES", "SEED", "ARIA", "LEA", "HIGHT", "SHA", "RSA", "3DES", "DES",
    "ECB", "CBC", "GCM", "CTR", "KCDSA", "HAS-160", "PKCS",
    "112", "128", "192", "256", "1024", "2048", "3072",
)


@dataclass(frozen=True, slots=True)
class QualityThresholds:
    """손상 판정 문턱값. 실제 문서로 확인한 뒤 조정한다."""
    jamo_per_10k: float = 5.0
    digit_confuse_per_10k: float = 10.0
    replacement_per_10k: float = 1.0
    long_token_per_10k: float = 5.0
    spaced_hangul_ratio: float = 0.15
    min_chars: int = 200  # 이보다 짧으면 비율 통계가 무의미하므로 판정하지 않는다


DEFAULT_THRESHOLDS = QualityThresholds()


@dataclass(frozen=True, slots=True)
class QualityMetrics:
    """1만자당 출현율로 정규화한 손상 지표."""
    total_chars: int = 0
    hangul_ratio: float = 0.0
    jamo_per_10k: float = 0.0
    digit_confuse_per_10k: float = 0.0
    replacement_per_10k: float = 0.0
    long_token_per_10k: float = 0.0
    spaced_hangul_ratio: float = 0.0  # 낱글자 분리가 일어난 한글의 비율
    crypto_tokens_found: int = 0


@dataclass(frozen=True, slots=True)
class QualityVerdict:
    """판정 결과. `ok`가 거짓이면 색인을 막는다."""
    ok: bool
    metrics: QualityMetrics
    reasons: tuple[str, ...] = field(default=())


def _per_10k(count: int, chars: int) -> float:
    return round(count * 10000 / chars, 2) if chars else 0.0


def _count_broken_long_tokens(text: str) -> int:
    """
    레이아웃 붕괴로 붙어버린 장문 토큰만 센다.

    URL과 목차 점선 리더(`......`)는 정상 문서에도 흔하므로 제외한다. 실제 표준문서로
    확인한 결과 이 둘이 오탐의 대부분을 차지했다.
    """
    broken = 0
    for token in _LONG_TOKEN.findall(text):
        if _URL.search(token) or _FILLER_RUN.match(token):
            continue
        broken += 1
    return broken


def measure(text: str) -> QualityMetrics:
    """텍스트의 손상 지표를 계산한다."""
    if not text:
        return QualityMetrics()

    chars = len(text)
    han = len(_HANGUL.findall(text))
    lat = len(_LATIN.findall(text))

    spaced = sum(len(_HANGUL.findall(m)) for m in _SPACED_HANGUL.findall(text))

    return QualityMetrics(
        spaced_hangul_ratio=round(spaced / han, 3) if han else 0.0,
        total_chars=chars,
        hangul_ratio=round(han / (han + lat), 3) if (han + lat) else 0.0,
        jamo_per_10k=_per_10k(len(_JAMO.findall(text)), chars),
        digit_confuse_per_10k=_per_10k(len(_DIGIT_CONFUSE.findall(text)), chars),
        replacement_per_10k=_per_10k(len(_REPLACEMENT.findall(text)), chars),
        long_token_per_10k=_per_10k(_count_broken_long_tokens(text), chars),
        crypto_tokens_found=sum(1 for t in CRYPTO_TOKENS if t in text),
    )


def evaluate(
    metrics: QualityMetrics,
    thresholds: QualityThresholds = DEFAULT_THRESHOLDS,
) -> QualityVerdict:
    """지표가 문턱을 넘는지 판정한다. 넘으면 손상 의심으로 보고 색인을 막는다."""
    if metrics.total_chars < thresholds.min_chars:
        # 표본이 작으면 비율이 요동치므로 판정을 보류하고 통과시킨다.
        return QualityVerdict(ok=True, metrics=metrics)

    reasons = []
    if metrics.jamo_per_10k > thresholds.jamo_per_10k:
        reasons.append(f"단독 자모 {metrics.jamo_per_10k}/10k (한글 OCR 깨짐 의심)")
    if metrics.digit_confuse_per_10k > thresholds.digit_confuse_per_10k:
        reasons.append(f"숫자-문자 혼동 후보 {metrics.digit_confuse_per_10k}/10k (키 길이 오독 위험)")
    if metrics.replacement_per_10k > thresholds.replacement_per_10k:
        reasons.append(f"치환 실패 문자 {metrics.replacement_per_10k}/10k")
    if metrics.long_token_per_10k > thresholds.long_token_per_10k:
        reasons.append(f"비정상 장문 토큰 {metrics.long_token_per_10k}/10k (레이아웃 붕괴)")
    if metrics.spaced_hangul_ratio > thresholds.spaced_hangul_ratio:
        reasons.append(
            f"한글 낱글자 분리 {metrics.spaced_hangul_ratio:.0%} "
            '("패 스 워 드" 형태 - 어절이 깨져 검색 불가)')

    return QualityVerdict(ok=not reasons, metrics=metrics, reasons=tuple(reasons))


def assess(text: str, thresholds: QualityThresholds = DEFAULT_THRESHOLDS) -> QualityVerdict:
    """measure + evaluate 단축 호출."""
    return evaluate(measure(text), thresholds)


# 텍스트 레이어를 버리고 OCR로 돌릴 문턱. 색인 차단용 문턱(5/10k)보다 훨씬 높게 잡는다.
# 여기서 걸리는 것은 "조금 지저분한" 페이지가 아니라 글자 코드가 어긋난 페이지여야 한다.
#
# 문서별로 재보고 정했다. 사물인터넷 안내서는 1만자당 중앙값 63.2로 53쪽 중 39쪽이 이
# 문턱을 넘었고(`제절에서는서비스전주기에서의보안위협`처럼 공백이 사라진다), 패스워드
# 안내서와 NIST 문서 두 건은 한 쪽도 넘지 않았다.
LAYOUT_COLLAPSE_PER_10K = 40.0


def layout_collapsed(text: str, thresholds: QualityThresholds = DEFAULT_THRESHOLDS) -> bool:
    """
    추출한 텍스트가 못 쓸 정도로 붕괴했는지.

    참이면 그 페이지의 텍스트 레이어를 믿지 않고 OCR로 읽어야 한다. 두 가지를 본다.

    낱말이 붙어버린 경우: 공백이 사라져 `제절에서는서비스전주기에서의보안위협`처럼 나오고,
    그런 페이지는 글자 코드도 어긋나 있었다.

    낱글자로 분리된 경우: `안전한기 억 하 기 쉬 운 패 스 워 드`처럼 글자마다 공백이
    들어간다. 이러면 낱말 검색이 걸리지 않는다. 문서별로 재보니 패스워드 안내서만 중앙값
    0.724였고 나머지 문서는 모두 0.000이라 이 신호도 깨끗하게 갈린다.
    """
    metrics = measure(text)
    return (metrics.long_token_per_10k > LAYOUT_COLLAPSE_PER_10K
            or metrics.spaced_hangul_ratio > thresholds.spaced_hangul_ratio)


def detect_language(text: str, hangul_threshold: float = 0.15) -> str:
    """한글 비율로 언어를 추정한다. 문서 단위가 아니라 페이지 단위로 부르는 것을 전제한다."""
    if not text:
        return "unknown"
    han = len(_HANGUL.findall(text))
    lat = len(_LATIN.findall(text))
    if han + lat == 0:
        return "unknown"
    return "ko" if han / (han + lat) >= hangul_threshold else "en"
