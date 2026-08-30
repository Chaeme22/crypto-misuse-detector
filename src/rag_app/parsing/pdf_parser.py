"""
PDF parser using PyMuPDF (fitz) with structure extraction.

표는 표로, 조항은 조항으로 뽑는다. 표준/가이드라인 문서는 답이 표 안에 있고 인용
단위가 조항이므로, 페이지 텍스트를 통째로 뽑는 방식으로는 쓸 수 없다.

텍스트 레이어가 없는 벡터 아웃라인 문서(KISA 안내서 등)는 표 셀 좌표를 복원한 뒤
셀 단위 OCR로 표를 얻는다. 자세한 근거는 `pdf_structure` 참고.
"""

import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

from ..config.schema import AppConfig
from ..domain.enums import BlockType, FileType, OCRStatus
from ..domain.exceptions import ParserError
from ..domain.models import ParsedBlock, ParsedDocument
from ..observability.logging import get_logger
from . import pdf_structure, text_quality
from .registry import DocumentParser

logger = get_logger(__name__)


class PdfParser(DocumentParser):
    """Parser for PDF files using PyMuPDF."""

    def __init__(self, config: Optional[AppConfig] = None, ocr=None):
        self.config = config
        self.supported_exts = {".pdf"}
        self._ocr = ocr  # TesseractCLI 호환 객체. None이면 첫 사용 시 만든다.

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.supported_exts

    def supported_extensions(self) -> set[str]:
        return {".pdf"}

    def _get_ocr(self):
        """설정된 OCR 엔진을 지연 생성한다. 지정한 엔진이 없으면 조용히 대체하지 않는다."""
        if self._ocr is None:
            from .ocr_engine import create_engine
            name, options = "tesseract", {}
            if self.config is not None:
                ocr_cfg = self.config.ocr
                name = ocr_cfg.engine
                if name in ("easyocr", "tesseract+easyocr", "surya+tesseract"):
                    options = {"languages": [l for l in ocr_cfg.languages if l in ("ko", "en", "ja")],
                               "gpu": ocr_cfg.device != "cpu"}
                elif name == "paddleocr":
                    options = {"gpu": ocr_cfg.device != "cpu"}
            self._ocr = create_engine(name, **options)
        return self._ocr

    def _render_dpi(self) -> int:
        return self.config.ocr.render_dpi if self.config is not None else 400

    def parse(self, file_path: Path, document_id: UUID, md5_hash: str) -> ParsedDocument:
        """Parse PDF document, preserving tables, section paths and reading order."""
        file_path = file_path.resolve()
        if not file_path.exists():
            raise ParserError(f"File not found: {file_path}")

        try:
            import fitz
        except ImportError as e:
            raise ParserError(f"PyMuPDF required to parse PDF: {e}") from e

        try:
            doc = fitz.open(str(file_path))
        except Exception as e:
            raise ParserError(f"Failed to open PDF {file_path.name}: {e}") from e

        try:
            blocks, pages_without_text, languages, recovered = self._extract(doc, file_path)
            total_pages = len(doc)
        finally:
            doc.close()

        ocr_status = self._ocr_status(pages_without_text, recovered, total_pages)
        unrecovered = [p for p in pages_without_text if p not in recovered]

        if not blocks:
            blocks.append(ParsedBlock(
                block_type=BlockType.PARAGRAPH,
                text=f"(No text extracted from PDF. OCR status: {ocr_status.value})",
                page_number=1,
                sequence=0,
            ))

        stat = file_path.stat()
        return ParsedDocument(
            document_id=document_id,
            source_path=str(file_path),
            file_name=file_path.name,
            file_type=FileType.PDF,
            file_size=stat.st_size,
            md5_hash=md5_hash,
            modified_at=datetime.fromtimestamp(stat.st_mtime),
            blocks=tuple(blocks),
            language=_dominant(languages),
            ocr_status=ocr_status,
            ocr_pages=tuple(unrecovered),   # 아직 내용을 얻지 못한 페이지만 남긴다
        )

    # ------------------------------------------------------------------ 추출

    def _extract(self, doc, file_path: Path):
        import fitz

        toc_map = pdf_structure.build_toc_map(doc)
        running_heads = pdf_structure.find_running_heads(doc)
        tmp_dir = Path(tempfile.gettempdir()) / "rag_pdf_ocr" / file_path.stem

        blocks: list[ParsedBlock] = []
        pages_without_text: list[int] = []
        recovered_pages: set[int] = set()   # 텍스트가 없었으나 OCR로 복원한 페이지
        languages: list[str] = []
        sequence = 0
        # 목차가 없을 때 본문 제목으로 쌓아 올리는 경로
        heading_path: list[str] = []

        for index in range(len(doc)):
            page = doc.load_page(index)
            page_number = index + 1

            try:
                raw_text = page.get_text("text").strip()
            except Exception:
                raw_text = ""

            # 텍스트가 있어도 붕괴한 페이지는 OCR로 돌린다. 이 문턱을 넘는 페이지는 공백이
            # 사라지고 글자 코드가 어긋나 있어 그대로 색인하면 검색이 안 된다.
            has_text = len(raw_text) >= 20 and not text_quality.layout_collapsed(raw_text)
            if not has_text:
                pages_without_text.append(page_number)

            if has_text and _is_toc_page(raw_text):
                # 목차는 본문이 아니다. 쪽번호 나열이 청크를 채우고, 목차 항목이 번호형
                # 제목으로 검출되어 조항 경로를 덮는다. 쪽 단위로 읽는 경로는 인식기가
                # TableOfContents로 분류해 주므로 여기서만 걸러낸다.
                continue

            section_path = pdf_structure.section_path_for_page(toc_map, page_number)

            if has_text:
                languages.append(text_quality.detect_language(raw_text))
                page_blocks, sequence, heading_path = self._text_page(
                    page, page_number, section_path, heading_path,
                    running_heads, sequence,
                )
                blocks.extend(page_blocks)
            else:
                page_blocks, sequence, heading_path = self._vector_page(
                    page, page_number, section_path, heading_path, tmp_dir, sequence
                )
                if page_blocks:
                    languages.append(_dominant_from_blocks(page_blocks))
                    recovered_pages.add(page_number)
                blocks.extend(page_blocks)

        return blocks, pages_without_text, languages, recovered_pages

    def _text_page(self, page, page_number, section_path, heading_path,
                   running_heads, sequence):
        """텍스트 레이어가 있는 페이지: 표를 먼저 떼고 나머지를 본문으로."""
        import fitz

        blocks: list[ParsedBlock] = []

        tables = pdf_structure.extract_text_tables(page)
        table_rects = [fitz.Rect(t.bbox) for t in tables if any(t.bbox)]

        for table in tables:
            blocks.append(ParsedBlock(
                block_type=BlockType.TABLE,
                text=table.to_text(),
                page_number=page_number,
                section_path=tuple(section_path or heading_path),
                sequence=sequence,
                metadata={"table_source": table.source},
            ))
            sequence += 1

        try:
            raw_blocks = page.get_text("blocks", sort=True)
        except Exception:
            raw_blocks = []

        for raw in raw_blocks:
            if len(raw) < 5:
                continue
            rect = fitz.Rect(raw[:4])
            if any(rect.intersects(tr) for tr in table_rects):
                continue  # 표 본문이 중복으로 들어가지 않게 한다

            text = _join_wrapped_lines(str(raw[4]), running_heads)
            if not text:
                continue

            heading = pdf_structure.detect_heading(text)
            if heading:
                heading_path = _push_heading(heading_path, heading)
                blocks.append(ParsedBlock(
                    block_type=BlockType.HEADING,
                    text=text,
                    page_number=page_number,
                    section_path=tuple(section_path or heading_path),
                    sequence=sequence,
                ))
            else:
                blocks.append(ParsedBlock(
                    block_type=BlockType.PARAGRAPH,
                    text=text,
                    page_number=page_number,
                    section_path=tuple(section_path or heading_path),
                    sequence=sequence,
                ))
            sequence += 1

        return blocks, sequence, heading_path

    def _grid_table(self, page, ocr, tmp_dir: Path, dpi: int, page_number: int):
        """셀 격자에서 표를 실측해 읽는다. 실패하면 None."""
        try:
            return pdf_structure.extract_vector_table(page, ocr, tmp_dir, dpi=dpi)
        except Exception as e:
            logger.warning("vector_table_failed", f"page {page_number}: {e}")
            return None

    def _ocr_block(self, text, page_number, section_path, heading_path, sequence,
                   metadata: dict, label: str = ""):
        """
        OCR로 읽은 덩어리 하나를 블록으로 만든다. 제목이면 조항 경로를 갱신한다.

        텍스트 레이어가 없는 문서는 목차 북마크도 없는 경우가 많아 본문 제목이 조항을
        아는 유일한 근거다. 그래서 OCR 경로도 텍스트 경로와 같이 제목을 검출한다.

        인식기가 제목이라고 분류해 준 덩어리는 번호가 없어도 제목으로 받는다. `1. 운영모드`
        처럼 번호형이면 검출기와 결과가 같고, `가용성 보장`처럼 번호가 없으면 라벨만이 근거다.
        """
        heading = pdf_structure.detect_heading(text)
        if not heading and label in pdf_structure.HEADING_LABELS and _titlelike(text):
            heading = text.strip()
        if heading:
            heading_path = _push_heading(heading_path, heading)
        return ParsedBlock(
            block_type=BlockType.HEADING if heading else BlockType.PARAGRAPH,
            text=text,
            page_number=page_number,
            section_path=tuple(section_path or heading_path),
            sequence=sequence,
            metadata=metadata,
        ), heading_path

    def _vector_page(self, page, page_number, section_path, heading_path,
                     tmp_dir: Path, sequence: int):
        """
        텍스트가 없는 페이지: 표 격자를 복원해 셀 단위로 OCR하고, 나머지 본문은 문단
        단위로 OCR한다. 표와 본문을 세로 위치 순으로 섞어 읽기 순서를 지킨다.
        """
        ocr = self._get_ocr()
        if not ocr.available():
            logger.warning("ocr_unavailable",
                           f"tesseract not callable; page {page_number} left unparsed")
            return [], sequence, heading_path

        dpi = self._render_dpi()
        page_reader = getattr(ocr, "read_page", None)
        scanned = pdf_structure.is_scanned_page(page)

        # 순수 스캔본은 벡터 좌표가 없어 표 격자를 실측할 수 없다. 쪽 단위로 읽는 인식기가
        # 없으면 페이지 전체를 한 번에 읽는 옛 경로로 돌아간다.
        if scanned and page_reader is None:
            blocks = []
            for body in pdf_structure.extract_scanned_page(page, ocr, tmp_dir, dpi=dpi):
                block, heading_path = self._ocr_block(
                    body.text, page_number, section_path, heading_path, sequence,
                    {"source": "scanned_ocr", "needs_review": True},
                )
                blocks.append(block)
                sequence += 1
            return blocks, sequence, heading_path

        cells = [] if scanned else pdf_structure.detect_table_cells(page)
        table = None

        if page_reader is not None:
            # 본문을 먼저 읽는다. 격자가 진짜 표인지 판정하려면 인식기가 그 자리를 어떻게
            # 봤는지 알아야 한다. 이 문서들에는 장 구분용 색 띠와 강조 상자가 셀로 잡혀
            # `[Header] > 03, 제 | 3 At 양자정보통신...` 같은 표가 만들어지는 쪽이 있다.
            body_source = "page_ocr"
            try:
                bodies = pdf_structure.extract_page_blocks(page, ocr, tmp_dir, check_dpi=dpi)
            except Exception as e:
                logger.warning("page_read_failed", f"page {page_number}: {e}")
                bodies = []

            if cells:
                table = self._grid_table(page, ocr, tmp_dir, dpi, page_number)

            # 본문은 좌표로 걸러내지 않는다. 인식기가 표와 본문을 이미 나눠 주므로 걸러낼
            # 이유가 없고, 걸러내면 장식 도형이 셀로 잡힌 쪽에서 본문이 통째로 사라진다.
            # 실제로 그 쪽들에서 블록이 하나만 남았다.
            #
            # 격자가 장식 도형을 표로 만들어 내는 것 자체는 아직 못 걸러낸다. 격자 표와
            # 인식기 판독을 견줘 봤지만(본문과 겹치는 비율, 인식기 표와 겹치는 비율, 행·열
            # 모양) 정상과 쓰레기가 갈리지 않았다. 정상 표가 본문과 0.28 겹치는데 쓰레기가
            # 0.29였다. 그래서 남기고 검수 표시에 맡긴다. 잘못 만든 표는 잡음이지만,
            # 본문을 지우는 것과 달리 되돌릴 수 있다.
            # 두 판독이 같은 표를 읽었더라도 하나로 합치지 않는다. 내용이 겹치는지로
            # 합쳐 봤더니, 두 표를 뭉갠 격자 표에 겹친다는 이유로 깨끗한 판독이 버려졌다.
            # 실제로 `112 비트 이상 AES-128 AES-192 AES-256 3TDEA` 행이 통째로 사라졌다.
            # 어느 쪽이 맞는지는 이 자리에서 알 수 없고 표 값은 규칙표의 임계값이 되므로,
            # 둘 다 남기고 검수에 맡긴다. 중복은 잡음이지만 유실은 되돌릴 수 없다.
        else:
            if cells:
                table = self._grid_table(page, ocr, tmp_dir, dpi, page_number)
            # 표로 실제로 읽어낸 영역만 본문에서 뺀다. 격자를 잡았어도 표가 아니라고
            # 판정되면 그 자리는 여전히 본문이므로 제외하면 페이지 내용이 사라진다.
            exclude = cells if table is not None else []
            try:
                if hasattr(ocr, "detect_lines"):
                    body_source = "detected_ocr"
                    bodies = pdf_structure.extract_detected_body(page, ocr, tmp_dir,
                                                                 exclude=exclude, dpi=dpi)
                else:
                    body_source = "vector_ocr"
                    bodies = pdf_structure.extract_vector_body(page, ocr, tmp_dir,
                                                               exclude=exclude, dpi=dpi)
            except Exception as e:
                logger.warning("vector_body_failed", f"page {page_number}: {e}")
                body_source, bodies = "vector_ocr", []

        # 표는 셀 격자의 위쪽 좌표를, 본문은 덩어리 상자의 위쪽 좌표를 기준으로 정렬한다.
        # 어떤 경로로 읽은 글자인지는 metadata에 남긴다. 증거 추적에 필요하다.
        items: list[tuple[float, bool, str, dict, str]] = []
        if table is not None:
            top = min((c.y0 for c in cells), default=0.0)
            items.append((top, True, table.to_text(),
                          {"table_source": table.source,
                           "needs_review": table.needs_review}, ""))
        for body in bodies:
            if body.label == "Table":
                # 격자가 놓친 표다. 인식기는 표가 쪽을 넘어가는 자리에서 없는 행을 만들기도
                # 하므로 검수 대상으로 남긴다.
                items.append((body.bbox[1], True, body.text,
                              {"table_source": "page_ocr", "needs_review": True}, ""))
                continue
            items.append((body.bbox[1], False, body.text,
                          {"source": body_source, "needs_review": body.needs_review},
                          body.label))

        # 제목은 읽기 순서대로 쌓아야 조항 경로가 맞으므로 정렬한 뒤에 블록을 만든다.
        blocks = []
        for _, is_table, text, metadata, label in sorted(items, key=lambda item: item[0]):
            if is_table:
                blocks.append(ParsedBlock(
                    block_type=BlockType.TABLE,
                    text=text,
                    page_number=page_number,
                    section_path=tuple(section_path or heading_path),
                    sequence=sequence,
                    metadata=metadata,
                ))
            else:
                block, heading_path = self._ocr_block(
                    text, page_number, section_path, heading_path, sequence, metadata, label)
                blocks.append(block)
            sequence += 1
        return blocks, sequence, heading_path

    @staticmethod
    def _ocr_status(pages_without_text: list[int], recovered: set[int],
                    total_pages: int) -> OCRStatus:
        """
        텍스트가 없던 페이지를 OCR로 얼마나 복원했는지로 상태를 정한다.

        복원했는데도 REQUIRED로 남기면 색인 게이트가 멀쩡한 문서를 막는다. 반대로 한 장도
        못 읽었으면 REQUIRED로 남겨 사람이 처리하게 한다.
        """
        if not pages_without_text:
            return OCRStatus.NOT_NEEDED

        missing = [p for p in pages_without_text if p not in recovered]
        if not missing:
            return OCRStatus.COMPLETED
        if not recovered:
            return (OCRStatus.REQUIRED if len(pages_without_text) == total_pages
                    else OCRStatus.PARTIAL)
        return OCRStatus.PARTIAL_FAILED


def _join_wrapped_lines(text: str, running_heads: set[str]) -> str:
    """줄바꿈으로 끊긴 문장을 잇고 머리말/꼬리말을 걷어낸다."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or pdf_structure.is_running_head(line, running_heads):
            continue
        lines.append(line)

    if not lines:
        return ""

    out = lines[0]
    for line in lines[1:]:
        if out.endswith("-") and line[:1].isalpha():
            out = out[:-1] + line          # 영문 하이픈 분절
        elif _is_hangul(out[-1:]) and _is_hangul(line[:1]):
            out += line                     # 한글은 붙여 쓴다
        else:
            out += " " + line
    return out.strip()


def _is_hangul(ch: str) -> bool:
    return bool(ch) and "가" <= ch <= "힣"


_TOC_NUMERIC = re.compile(r"^[\d\s.\-–—·ㆍ]+$")
_TOC_DOTTED = re.compile(r"\.{3,}\s*\d+$")


def _is_toc_page(text: str, min_lines: int = 5, ratio: float = 0.5) -> bool:
    """
    쪽번호 나열이 절반을 넘으면 목차 페이지로 본다.

    문서들로 재보니 이 기준에 걸리는 것은 실제 목차뿐이었다(Recommendation for Key
    Management 8~13쪽, 사물인터넷 안내서 3쪽 등). 본문 페이지는 하나도 걸리지 않았다.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < min_lines:
        return False
    numbered = sum(1 for line in lines
                   if _TOC_NUMERIC.match(line) or _TOC_DOTTED.search(line))
    return numbered >= len(lines) * ratio


def _titlelike(text: str) -> bool:
    """
    인식기가 제목이라 분류해 준 줄을 조항 경로로 쓸 만한지 본다.

    번호나 기호만 있는 줄은 제목이 아니다. 실제로 16진 바이트열
    `30 0d 06 0a 2a ...`이 SectionHeader로 분류되어 조항 경로가 그 문자열이 됐다.
    """
    body = text.strip()
    if len(body) < 2:
        return False
    words = re.findall(r"[가-힣]{2,}|[A-Za-z]{3,}", body)
    if not words:
        return False
    letters = sum(len(w) for w in words)
    return letters >= len(re.sub(r"\s", "", body)) * 0.4


def _push_heading(path: list[str], heading: str) -> list[str]:
    """번호 깊이에 맞춰 조항 경로를 갱신한다. 5.1 다음에 5.1.1이 오면 아래로 쌓는다."""
    number = heading.split(" ", 1)[0]
    depth = number.count(".") + 1 if number and number[0].isdigit() else 1
    return path[: depth - 1] + [heading]


def _dominant_from_blocks(blocks: list[ParsedBlock]) -> str:
    """OCR로 얻은 페이지의 언어를 그 페이지 글자에서 판정한다."""
    return text_quality.detect_language(" ".join(b.text for b in blocks))


def _dominant(languages: list[str]) -> str:
    known = [lang for lang in languages if lang in ("ko", "en", "ja")]
    if not known:
        return "ko"
    return max(set(known), key=known.count)
