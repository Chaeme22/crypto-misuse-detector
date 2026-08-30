"""
OCR 엔진 교체 계층.

표준문서에서 뽑은 값이 그대로 탐지 규칙의 임계값이 되므로 인식 정확도가 곧 도구의
신뢰도다. 사람이 11개 문서를 일일이 대조할 수 없으니 엔진을 바꿔가며 재보고 가장 나은
것을 골라야 한다. 그래서 인식기를 이 인터페이스 뒤에 두고 설정으로 바꾼다.

구조상 유리한 점이 하나 있다. 우리는 표 격자와 문단 경계를 벡터 도형에서 이미 얻으므로
엔진에 레이아웃 분석을 시키지 않는다. 잘라낸 작은 조각의 **글자만 읽으면 된다.**
그래서 검출기 성능보다 인식기 성능이 중요하고, 조각이 작아 GPU 배치도 잘 먹는다.

어느 엔진이 나은지는 `tools/ocr_bench.py`로 우리 문서에 대해 재고 정한다. 일반적인
벤치마크 순위가 이 코퍼스에 그대로 적용된다고 가정하지 않는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..observability.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class OCRText:
    """
    인식 결과.

    두 번 읽어 결과가 어긋나면 어느 쪽도 임의로 고르지 않고 둘 다 남긴 뒤 검수 대상으로
    표시한다. 추정으로 채운 값이 규칙표에 들어가는 것을 막기 위해서다.
    """
    text: str
    alternate: str = ""
    needs_review: bool = False
    confidence: float | None = None


@runtime_checkable
class OCREngine(Protocol):
    """잘라낸 이미지 조각에서 글자를 읽는다."""

    name: str

    def available(self) -> bool:
        """엔진을 실제로 호출할 수 있는지."""
        ...

    def read(self, image: Path, psm: int = 11, dual_pass: bool = True) -> OCRText:
        """
        이미지 한 장을 읽는다.

        psm은 Tesseract의 페이지 분할 모드다. 다른 엔진은 줄 단위/블록 단위 힌트로만
        해석하며, 해당 개념이 없으면 무시한다.
        """
        ...


# ---------------------------------------------------------------- GPU 엔진들
#
# 아래 엔진들은 딥러닝 기반이라 GPU를 쓴다. 무거운 의존성이므로 전부 지연 임포트한다.
# 이 노트북에는 GPU와 torch가 없어 동작 확인을 하지 못했다. GPU 서버에서
# `tools/ocr_bench.py`로 검증한 뒤 채택할 것.


class EasyOCREngine:
    """
    EasyOCR (torch 기반).

    설치가 가장 단순하고 한국어를 기본 지원한다. 검출기와 인식기가 함께 들어 있으나
    우리는 이미 조각을 잘라 넘기므로 인식 위주로 쓴다.
    """

    name = "easyocr"

    def __init__(self, languages: list[str] | None = None, gpu: bool = True):
        self.languages = languages or ["ko", "en"]
        self.gpu = gpu
        self._reader = None

    def _get_reader(self):
        if self._reader is None:
            import easyocr
            self._reader = easyocr.Reader(self.languages, gpu=self.gpu)
        return self._reader

    def available(self) -> bool:
        try:
            import easyocr  # noqa: F401
            return True
        except ImportError:
            return False

    def read(self, image: Path, psm: int = 11, dual_pass: bool = True) -> OCRText:
        reader = self._get_reader()
        # detail=0 이면 문자열만, paragraph=True 면 줄을 이어 붙인다.
        parts = reader.readtext(str(image), detail=0, paragraph=True)
        return OCRText(text=" ".join(p.strip() for p in parts if p.strip()))

    def detect_lines(self, image: Path) -> list[tuple[tuple[float, float, float, float], str, float]]:
        """
        그림에서 글자 줄을 찾아 (사각형, 글자, 신뢰도)로 돌려준다. 좌표는 픽셀이다.

        벡터 아웃라인 문서는 글자가 획 단위 곡선 조각으로 쪼개져 있어 도형 좌표로 줄을
        복원하면 앞뒤가 잘린다. 검출기는 렌더한 그림에서 줄을 직접 찾으므로 그 문제가 없다.
        """
        boxes = []
        for box, text, confidence in self._get_reader().readtext(str(image), paragraph=False):
            xs = [point[0] for point in box]
            ys = [point[1] for point in box]
            boxes.append(((min(xs), min(ys), max(xs), max(ys)), text, float(confidence)))
        return boxes


class PaddleOCREngine:
    """
    PaddleOCR (paddlepaddle 기반).

    다국어 인식 품질이 좋다고 알려져 있고 한국어 모델이 있다. 다만 paddlepaddle-gpu는
    CUDA 버전에 민감해 설치가 까다로울 수 있다.
    """

    name = "paddleocr"

    def __init__(self, lang: str = "korean", gpu: bool = True):
        self.lang = lang
        self.gpu = gpu
        self._ocr = None

    def _get_ocr(self):
        if self._ocr is None:
            from paddleocr import PaddleOCR
            self._ocr = PaddleOCR(lang=self.lang, use_angle_cls=False, use_gpu=self.gpu,
                                  show_log=False)
        return self._ocr

    def available(self) -> bool:
        try:
            import paddleocr  # noqa: F401
            return True
        except ImportError:
            return False

    def read(self, image: Path, psm: int = 11, dual_pass: bool = True) -> OCRText:
        result = self._get_ocr().ocr(str(image), cls=False)
        lines: list[str] = []
        scores: list[float] = []
        for page in result or []:
            for entry in page or []:
                if len(entry) >= 2 and entry[1]:
                    lines.append(str(entry[1][0]))
                    if len(entry[1]) > 1:
                        scores.append(float(entry[1][1]))
        return OCRText(
            text=" ".join(lines),
            confidence=(sum(scores) / len(scores)) if scores else None,
        )


@dataclass(frozen=True, slots=True)
class PageBlock:
    """페이지에서 읽어낸 덩어리 하나. 라벨은 인식기가 분류한 종류다."""
    label: str              # Text, SectionHeader, Table, PageHeader, PageFooter, ...
    html: str
    text: str
    order: int
    bbox: tuple[float, float, float, float] = (0, 0, 0, 0)   # 넘긴 이미지의 픽셀 좌표
    confidence: float | None = None


class SuryaEngine:
    """
    Surya (torch 기반). 레이아웃 분석과 인식을 함께 한다.

    쪽 단위로 읽고 덩어리마다 종류를 붙여준다. 우리가 좌표로 어림잡던 것을 모델이
    구분해 준다는 뜻이다. 실제 문서로 확인한 바:
      - 스캔본에서 `카테고리에서 분리되어야한다[SHOULD].`와 16진 바이트열을 그대로 읽었다.
        tesseract는 같은 자리를 `[바104Ｌ미`로 냈다.
      - 벡터 아웃라인 문서에서 조사까지 정확했다. 세로로 돌아간 쪽 탭은 PageHeader,
        꼬리말은 PageFooter로 분류한다.
      - 표는 HTML로 뽑는다. 셀 격자를 좌표로 복원하지 않아도 된다.
    페이지당 2.5초 안이다(RTX 3090).
    """

    name = "surya"

    def __init__(self, languages: list[str] | None = None):
        self.languages = languages or ["ko", "en"]
        self._predictors = None

    def available(self) -> bool:
        try:
            import surya  # noqa: F401
            return True
        except ImportError:
            return False

    def _get_predictors(self):
        if self._predictors is None:
            from surya.layout import LayoutPredictor
            from surya.recognition import RecognitionPredictor
            self._predictors = (RecognitionPredictor(), LayoutPredictor())
        return self._predictors

    def read_page(self, image: Path) -> list[PageBlock]:
        """쪽 하나를 읽어 덩어리 목록으로 돌려준다. 읽기 순서대로 정렬한다."""
        from PIL import Image

        recognizer, layout = self._get_predictors()
        img = Image.open(image)
        result = recognizer([img], layout_results=layout([img]))[0]

        blocks = []
        for block in sorted(result.blocks, key=lambda b: b.reading_order):
            html = (block.html or "").strip()
            if not html:
                continue
            xs = [point[0] for point in block.polygon]
            ys = [point[1] for point in block.polygon]
            blocks.append(PageBlock(
                label=block.label,
                html=html,
                text=_strip_tags(html),
                order=block.reading_order,
                bbox=(min(xs), min(ys), max(xs), max(ys)),
                confidence=block.confidence,
            ))
        return blocks

    def read(self, image: Path, psm: int = 11, dual_pass: bool = True) -> OCRText:
        blocks = self.read_page(image)
        return OCRText(text=" ".join(b.text for b in blocks if b.text))


def _strip_tags(html: str) -> str:
    """
    HTML 표기를 걷어낸 순 글자. 셀 경계와 윗주는 공백으로 남긴다.

    윗주를 그냥 지우면 각주 번호가 값에 달라붙는다. `HAS-160`의 각주 `2)`가 붙어
    `HAS-1602)`가 되고, 이러면 키 길이가 1602로 읽힌다. 규칙 판정이 뒤집히는 자리다.
    """
    text = re.sub(r"</?(br|tr|td|th|sup|sub)\s*/?>", " ", html)
    return " ".join(re.sub(r"<[^>]+>", "", text).split())


# --------------------------------------------------------------- 조합 엔진


class TesseractEasyOCRPair:
    """
    tesseract를 기본으로 두고 easyocr로 보완한다.

    두 엔진의 실패 방식이 정반대다. 정답 표본 21개(암호 알고리즘 및 키 길이 안내서)로
    재보니 tesseract는 짧은 한글 셀을 빈 문자열로 버렸고(`NIST(미국)`, `국내` 등 3/17),
    easyocr은 숫자 1을 7로 읽어 `ARIA-192`를 `ARIA-792`로 만들었다(핵심토큰 97.2% →
    80.6%). 키 길이 숫자가 그대로 규칙표 임계값이 되므로 숫자는 tesseract를 믿고,
    tesseract가 아무것도 못 읽은 자리만 easyocr로 메운다. 이 조합에서 CER 9.0% → 5.4%,
    완전일치 12/21 → 14/21이 되고 핵심토큰은 97.2%로 유지됐다.

    숫자가 있는 자리는 easyocr로 한 번 더 읽어 숫자가 어긋나는지 본다. 어긋나면 어느
    쪽도 고르지 않고 둘 다 남긴 뒤 검수 대상으로 표시한다. 실제로 어긋난 자리에는
    tesseract가 틀린 경우(`CRYPTREC(일본)`을 `CRYPTREC(2!)`로)도 섞여 있었다.
    """

    name = "tesseract+easyocr"

    def __init__(self, languages: list[str] | None = None, gpu: bool = True):
        from .ocr_cli import TesseractCLI
        self._tesseract = TesseractCLI()
        self._easyocr = EasyOCREngine(languages=languages, gpu=gpu)

    def available(self) -> bool:
        return self._tesseract.available() and self._easyocr.available()

    def languages(self) -> set[str]:
        return self._tesseract.languages()

    def read_lines(self, image: Path, psm: int = 3, lang: str = "kor+eng") -> list[str]:
        """줄 구조가 필요한 스캔본은 tesseract로만 읽는다. easyocr은 줄바꿈을 버린다."""
        return self._tesseract.read_lines(image, psm=psm, lang=lang)

    def detect_lines(self, image: Path):
        """줄 검출은 easyocr 검출기만 할 수 있다."""
        return self._easyocr.detect_lines(image)

    def read_line(self, image: Path, hint: str, psm: int = 7) -> OCRText:
        """
        검출기가 찾아준 줄 하나를 읽는다. `hint`는 같은 줄에 대한 검출기 쪽 판독이다.

        줄 상자가 정확하면 tesseract가 한국어 산문을 더 잘 읽는다. 같은 줄에서 tesseract는
        `키 자료를 정해진 암호 연산을 수행할 때 사용한다.`를, easyocr은 `키 자료름 ...
        사용하다.`를 냈다. 조사를 틀리면 뜻이 흔들리므로 tesseract를 본문으로 삼는다.

        대신 tesseract는 한글 낱말을 라틴 대문자로 뒤집는 실패를 한다. 그 자리만 검출기 쪽
        한글로 갈아끼우고, 고친 줄과 숫자가 어긋난 줄은 검수 대상으로 표시한다.
        """
        from .ocr_cli import merge_hangul_tokens, merge_latin_tokens

        primary = self._tesseract.read(image, psm=psm)
        if not primary.text.strip():
            return OCRText(text=hint, needs_review=bool(_DIGIT_RUN.search(hint)))

        # 두 종류의 깨짐을 각각 상대 판독으로 되살린다. 라틴 약어가 한글 자모로 깨진 자리
        # (`RBG` → `8ㅇ`)와 한글 낱말이 라틴 대문자로 깨진 자리(`무결성을` → `PASS`)다.
        merged, restored = merge_latin_tokens(primary.text, hint, allow_digits=False)
        merged, swapped = merge_hangul_tokens(merged, hint)
        repaired = restored + swapped
        digits_differ = _DIGIT_RUN.findall(merged) != _DIGIT_RUN.findall(hint)
        # tesseract 자체 이중 판독(kor+eng 대 eng)은 거의 항상 어긋나므로 검수 사유로 쓰지
        # 않는다. 그걸 켜면 문서의 모든 블록이 검수 대상이 되어 신호 구실을 못 한다.
        return OCRText(
            text=merged,
            alternate=hint,
            needs_review=bool(repaired) or digits_differ,
        )

    def read_baseline(self, image: Path, psm: int = 7) -> str:
        """대조용 tesseract 단독 판독. 숫자가 어긋나는지 보는 데만 쓴다."""
        return self._tesseract.read(image, psm=psm, dual_pass=False).text

    def read(self, image: Path, psm: int = 11, dual_pass: bool = True) -> OCRText:
        primary = self._tesseract.read(image, psm=psm, dual_pass=dual_pass)

        if not primary.text.strip():
            # tesseract가 못 읽은 자리. 대조할 상대가 없으니 숫자가 섞였으면 검수로 넘긴다.
            filled = self._easyocr.read(image, psm=psm, dual_pass=dual_pass).text
            return OCRText(text=filled, needs_review=bool(_DIGIT_RUN.search(filled)))

        if not _DIGIT_RUN.search(primary.text):
            return primary   # 숫자가 없으면 easyocr을 부를 이유가 없다

        second = self._easyocr.read(image, psm=psm, dual_pass=dual_pass)
        if _DIGIT_RUN.findall(primary.text) == _DIGIT_RUN.findall(second.text):
            return primary
        return OCRText(
            text=primary.text,
            alternate=second.text,
            needs_review=True,
            confidence=primary.confidence,
        )


_DIGIT_RUN = re.compile(r"\d+")


class SuryaTesseractPair:
    """
    본문은 Surya가 쪽 단위로, 표는 tesseract가 셀 단위로 읽는다.

    두 방식의 강점이 다른 자리에 있다. 우리 문서로 재본 결과다.

    본문: Surya가 쪽 전체를 보고 읽으면 조사까지 맞고 스캔본도 읽는다. 같은 문장에서
    tesseract는 `[SHOULD]`를 `[바104Ｌ미`로, `무결성을`을 `PASS`로 냈다. 덩어리마다
    종류를 붙여주므로 제목과 꼬리말을 좌표로 어림잡지 않아도 된다.

    표: 격자를 실측하는 기존 방식이 안전하다. Surya는 표가 쪽을 넘어가는 자리에서
    `156 비트 이상`이라는 없는 행을 만들고 열을 4개로 줄였다. 존재하지 않는 보안강도가
    조용히 규칙표에 들어가므로 받을 수 없다. 셀 판독은 핵심토큰 97.2%인 tesseract가 한다.

    작은 조각은 Surya에 주지 않는다. 정답 표본 21개(셀 크롭)에서 CER 73.8%였고,
    `CRYPTREC(일본)`을 `CONTENTS CRYSTALLINE ( BVBIDE (이후) ) ...`로 지어냈다.
    """

    name = "surya+tesseract"

    def __init__(self, languages: list[str] | None = None, gpu: bool = True):
        self._surya = SuryaEngine(languages=languages)
        # 셀 대조용 easyocr은 CPU로 돌린다. GPU는 Surya가 띄우는 서버가 15GB를 쓰므로,
        # 문서를 여러 개 동시에 처리하면 워커마다 easyocr이 2GB씩 더 잡아 메모리가 터진다.
        # 터진 자리에서 표 추출이 예외를 삼키면 표가 조용히 빠진다. 셀은 작아 CPU로 충분하다.
        self._cells = TesseractEasyOCRPair(languages=languages, gpu=False)

    def available(self) -> bool:
        return self._surya.available() and self._cells.available()

    def languages(self) -> set[str]:
        return self._cells.languages()

    def read_page(self, image: Path) -> list[PageBlock]:
        return self._surya.read_page(image)

    def read(self, image: Path, psm: int = 11, dual_pass: bool = True) -> OCRText:
        """표 셀을 읽는다. 조각 판독은 Surya에 맡기지 않는다."""
        return self._cells.read(image, psm=psm, dual_pass=dual_pass)

    def read_baseline(self, image: Path, psm: int = 7) -> str:
        """대조용 tesseract 단독 판독. 본문 숫자가 어긋나는지 보는 데 쓴다."""
        return self._cells.read_baseline(image, psm=psm)


# ------------------------------------------------------------------- 팩토리

_BUILTIN = {
    "easyocr": EasyOCREngine,
    "paddleocr": PaddleOCREngine,
    "surya": SuryaEngine,
    "tesseract+easyocr": TesseractEasyOCRPair,
    "surya+tesseract": SuryaTesseractPair,
}


def create_engine(name: str = "tesseract", **options) -> OCREngine:
    """
    이름으로 엔진을 만든다.

    사용할 수 없는 엔진을 조용히 다른 것으로 바꾸지 않는다. 어떤 엔진으로 읽은 값인지가
    증거 추적에 남아야 하므로, 요청한 엔진이 없으면 그대로 실패시킨다.
    """
    key = (name or "tesseract").lower()

    if key == "tesseract":
        from .ocr_cli import TesseractCLI
        engine = TesseractCLI(**options)
    elif key in _BUILTIN:
        engine = _BUILTIN[key](**options)
    else:
        raise ValueError(
            f"Unknown OCR engine: {name!r}. "
            f"Available: tesseract, {', '.join(sorted(_BUILTIN))}"
        )

    if not engine.available():
        raise RuntimeError(
            f"OCR engine {key!r} is not installed or not callable. "
            "Install it, or choose another engine in config."
        )
    logger.info("ocr_engine_ready", f"OCR engine: {key}")
    return engine
