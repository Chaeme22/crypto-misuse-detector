"""
PDF에서 문서 구조를 추출한다: 조항 경로, 표, 반복 머리말/꼬리말.

두 종류의 PDF를 다룬다.

**텍스트형** (NIST 문서 등) - 텍스트 레이어가 있다. 표는 `find_tables()`로, 조항 경로는
목차 북마크와 번호형 제목으로 얻는다.

**벡터 아웃라인형** (KISA 안내서 등) - CorelDRAW 등에서 글자를 곡선으로 변환해 내보낸
문서라 텍스트 추출이 0자다. 다만 표 셀 배경이 채워진 사각형으로 남아 있어 격자 좌표를
정확히 복원할 수 있다. 셀 영역만 고해상도로 렌더링해 OCR하면 레이아웃 추측 없이 표를
얻는다. 실제 문서로 확인한 결과 알고리즘명과 숫자는 정확히 읽혔다.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..observability.logging import get_logger

logger = get_logger(__name__)

# 번호형 제목. 국문/영문 서식을 모두 받는다.
_HEADING = re.compile(
    r"^(?:"
    r"(?P<num>\d+(?:\.\d+)*)\s+(?P<t1>\S.{0,80})"          # 5.1 Title
    r"|제\s*(?P<ch>\d+)\s*(?P<kind>장|절|조)\s*(?P<t2>\S.{0,80})"  # 제3장 제목
    r"|(?P<tbl>[<\[［]?\s*(?:표|Table)\s*\d+(?:[-–.]\d+)?\s*[>\]］]?)\s*(?P<t3>.{0,80})"  # <표 3-2>
    r")\s*$"
)

# 페이지 번호만 담긴 자동 생성 목차 항목("쪽 1")은 조항 경로로 쓸 수 없다.
_PLACEHOLDER_TOC = re.compile(r"^(?:쪽|페이지|page|p\.?)\s*\d+$|^\d+$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class TableBlock:
    """추출한 표 하나. 행은 헤더와 짝지어 자립적으로 만든다."""
    page_number: int
    rows: tuple[tuple[str, ...], ...]
    header: tuple[str, ...] = ()
    caption: str = ""
    bbox: tuple[float, float, float, float] = (0, 0, 0, 0)
    source: str = "text"          # "text" | "vector_ocr"
    needs_review: bool = False    # OCR 이중 패스가 어긋난 셀이 있음

    def to_text(self) -> str:
        """검색과 인용에 쓸 선형 표현. 행 하나가 스스로 의미를 갖게 만든다."""
        lines = []
        if self.caption:
            lines.append(f"[표] {self.caption}")
        if self.header:
            lines.append("[Header] " + " | ".join(self.header))
        for i, row in enumerate(self.rows, start=1):
            if self.header and len(self.header) == len(row):
                pairs = [f"{h}={v}" for h, v in zip(self.header, row) if v]
                lines.append(f"[Row {i}] " + " | ".join(pairs))
            else:
                lines.append(f"[Row {i}] " + " | ".join(v for v in row if v))
        return "\n".join(lines)


@dataclass
class PageStructure:
    """한 페이지에서 뽑은 구조."""
    page_number: int
    section_path: tuple[str, ...] = ()
    tables: list[TableBlock] = field(default_factory=list)
    paragraphs: list[str] = field(default_factory=list)
    has_text_layer: bool = True


# ---------------------------------------------------------------- 조항 경로

def build_toc_map(doc) -> dict[int, tuple[str, ...]]:
    """
    목차 북마크에서 페이지 → 조항 경로 매핑을 만든다.

    "쪽 1", "쪽 2" 같은 껍데기 목차는 조항 정보가 없으므로 무시한다. 벡터 아웃라인
    문서들이 이런 목차를 갖고 있다.
    """
    try:
        toc = doc.get_toc()
    except Exception:
        return {}
    if not toc:
        return {}

    placeholder = sum(1 for _, title, _ in toc if _PLACEHOLDER_TOC.match(title.strip()))
    if placeholder >= len(toc) * 0.8:
        logger.info("toc_placeholder_ignored",
                    f"Ignoring {len(toc)} placeholder TOC entries (page-number titles)")
        return {}

    mapping: dict[int, tuple[str, ...]] = {}
    stack: list[str] = []
    for level, title, page in toc:
        stack = stack[: max(level - 1, 0)]
        stack.append(title.strip())
        mapping.setdefault(int(page), tuple(stack))
    return mapping


def section_path_for_page(toc_map: dict[int, tuple[str, ...]], page_number: int) -> tuple[str, ...]:
    """해당 페이지 이하에서 가장 가까운 조항 경로를 고른다."""
    best: tuple[str, ...] = ()
    best_page = -1
    for page, path in toc_map.items():
        if best_page < page <= page_number:
            best, best_page = path, page
    return best


def detect_heading(line: str) -> Optional[str]:
    """본문 줄이 번호형 제목이면 정규화한 제목을 돌려준다."""
    line = line.strip()
    if not line or len(line) > 120:
        return None
    m = _HEADING.match(line)
    if not m:
        return None
    if m.group("num"):
        return f"{m.group('num')} {m.group('t1')}".strip()
    if m.group("ch"):
        return f"제{m.group('ch')}{m.group('kind')} {m.group('t2')}".strip()
    return f"{m.group('tbl')} {m.group('t3')}".strip()


# ------------------------------------------------------- 머리말 / 꼬리말 제거

def find_running_heads(doc, sample_limit: int = 40, threshold: float = 0.6) -> set[str]:
    """
    페이지 상·하단에서 반복되는 줄을 찾는다.

    표준문서는 매 페이지에 기관명, 문서명, 쪽번호가 반복되어 모든 청크에 노이즈로
    섞인다. 전체 페이지의 threshold 비율 이상에서 나타나는 짧은 줄을 머리말/꼬리말로 본다.
    """
    counter: Counter[str] = Counter()
    pages = min(len(doc), sample_limit)
    if pages < 3:
        return set()

    for i in range(pages):
        page = doc.load_page(i)
        h = page.rect.height
        try:
            blocks = page.get_text("blocks", sort=True)
        except Exception:
            continue
        for b in blocks:
            if len(b) < 5:
                continue
            y0, y1, text = b[1], b[3], b[4]
            if y0 > h * 0.08 and y1 < h * 0.92:
                continue  # 본문 영역
            for line in str(text).splitlines():
                line = line.strip()
                if 0 < len(line) <= 60:
                    counter[_mask_digits(line)] += 1

    cutoff = pages * threshold
    return {text for text, n in counter.items() if n >= cutoff}


def _mask_digits(s: str) -> str:
    """쪽번호만 다른 줄을 같은 것으로 보기 위해 숫자를 가린다."""
    return re.sub(r"\d+", "#", s)


def is_running_head(line: str, heads: set[str]) -> bool:
    return _mask_digits(line.strip()) in heads


# ------------------------------------------------------------------ 표 (텍스트형)

def extract_text_tables(page) -> list[TableBlock]:
    """텍스트 레이어가 있는 페이지에서 표를 뽑는다."""
    try:
        found = page.find_tables()
    except Exception as e:
        logger.warning("find_tables_failed", f"page {page.number + 1}: {e}")
        return []

    out: list[TableBlock] = []
    for t in found.tables:
        try:
            rows = t.extract()
        except Exception:
            continue
        grid = _clean_grid(rows)
        header, body = split_header(grid)
        if not is_meaningful_table(header, body):
            continue
        out.append(TableBlock(
            page_number=page.number + 1,
            rows=tuple(tuple(r) for r in body),
            header=header,
            bbox=tuple(round(v, 1) for v in t.bbox),
            source="text",
        ))
    return out


def _clean_grid(rows: list[list]) -> list[list[str]]:
    """병합 셀 때문에 생기는 빈 행과 빈 열을 제거한다."""
    grid = [[(c or "").replace("\n", " ").strip() for c in r] for r in rows]
    grid = [r for r in grid if any(c for c in r)]
    if not grid:
        return []
    width = max(len(r) for r in grid)
    grid = [r + [""] * (width - len(r)) for r in grid]
    keep = [i for i in range(width) if any(r[i] for r in grid)]
    return [[r[i] for i in keep] for r in grid]


# 헤더 셀로 인정할 최대 길이. 이보다 길면 설명문이므로 데이터 행으로 본다.
_MAX_HEADER_CELL = 40


def split_header(grid: list[list[str]]) -> tuple[tuple[str, ...], list[list[str]]]:
    """
    첫 행이 헤더인지 판정한다.

    모든 표에 헤더가 있는 것은 아니다. 용어-정의 목록처럼 첫 행부터 데이터인 표가 있는데,
    이를 헤더로 오인하면 `용어=다음행값` 같은 엉뚱한 짝이 만들어진다. 그래서 첫 행의
    모든 칸이 짧고 비어 있지 않을 때만 헤더로 인정하고, 아니면 헤더 없이 돌려준다.
    """
    if not grid:
        return (), []
    first = grid[0]
    looks_like_header = (
        len(grid) >= 2
        and all(cell for cell in first)
        and all(len(cell) <= _MAX_HEADER_CELL for cell in first)
    )
    if looks_like_header:
        return tuple(first), grid[1:]
    return (), grid


# 낱말다운 토큰: 두 글자 이상이고 문자/숫자로만 이루어진 것.
_WORDLIKE = re.compile(r"^[0-9A-Za-z가-힣][0-9A-Za-z가-힣\-/.]+$")


def is_meaningful_table(
    header: tuple[str, ...],
    rows: list[list[str]],
    ocr_source: bool = False,
) -> bool:
    """
    표지 장식이나 삽화가 표로 잡히는 것을 걸러낸다.

    구조 신호(대부분의 행에 두 칸 이상이 채워짐)가 1차 기준이다. OCR로 읽은 표에는
    낱말 비율 검사를 추가로 건다. 장식 도형을 OCR하면 기호와 한두 글자 조각만 나오기
    때문이다. 텍스트 추출 표에는 이 검사를 걸지 않는다. 수식이 많은 표(키 길이 조건 등)가
    낱말 비율에서 잘못 걸러지기 때문이다.
    """
    if len(rows) < 1:
        return False
    width = len(header) if header else len(rows[0])
    if width < 2:
        return False

    all_rows = ([list(header)] if header else []) + rows
    filled_ok = sum(1 for r in all_rows if sum(1 for c in r if c.strip()) >= 2)
    if filled_ok < max(2, len(all_rows) * 0.5):
        return False

    if not ocr_source:
        return True

    tokens = (" ".join(header) + " " + " ".join(c for r in rows for c in r)).split()
    if len(tokens) < 6:
        return False
    wordlike = sum(1 for t in tokens if _WORDLIKE.match(t))
    return wordlike >= 5 and wordlike / len(tokens) >= 0.45


# ------------------------------------------------------------- 표 (벡터형)

def find_vector_cells(page, min_w: float = 35.0, min_h: float = 15.0) -> list:
    """
    채워진 사각형 중 격자를 이루는 것만 표 셀로 인정한다.

    한 페이지에는 표 외에도 장식 박스와 강조 박스가 있다. 표 셀은 같은 열(같은 x0)과
    같은 행(같은 y0)에 다른 셀이 반드시 존재한다. 고립된 박스는 이 조건에서 탈락한다.
    """
    import fitz

    candidates = []
    for drawing in page.get_drawings():
        if drawing.get("type") not in ("f", "fs"):
            continue
        rect = drawing["rect"]
        if (rect.width >= min_w and rect.height >= min_h
                and rect.width < page.rect.width * 0.9):
            candidates.append(fitz.Rect(rect))

    if len(candidates) < 4:
        return []

    xs = _snap([r.x0 for r in candidates])
    ys = _snap([r.y0 for r in candidates])
    x_count = Counter(xs[r.x0] for r in candidates)
    y_count = Counter(ys[r.y0] for r in candidates)

    return [r for r in candidates
            if x_count[xs[r.x0]] >= 2 and y_count[ys[r.y0]] >= 2]


def find_ruled_cells(page, min_rule: float = 40.0, tol: float = 2.5) -> list:
    """
    괘선으로 그려진 표의 셀을 복원한다.

    셀 배경을 칠하지 않고 선으로만 칸을 나눈 표가 있다. HTML5 안내서가 그렇다. 이런 표는
    채워진 사각형이 없으므로 `find_vector_cells`로는 잡히지 않는다.

    가로선의 y와 세로선의 x를 모아 격자를 세우고, 이웃한 두 선 사이를 셀로 본다.
    """
    import fitz

    h_lines: list[tuple[float, float, float]] = []   # (y, x0, x1)
    v_lines: list[tuple[float, float, float]] = []   # (x, y0, y1)

    for drawing in page.get_drawings():
        for item in drawing.get("items", ()):
            rect = _item_bbox(item)
            if rect is None:
                continue
            if rect.height <= tol and rect.width >= min_rule:
                h_lines.append(((rect.y0 + rect.y1) / 2, rect.x0, rect.x1))
            elif rect.width <= tol and rect.height >= min_rule / 4:
                v_lines.append(((rect.x0 + rect.x1) / 2, rect.y0, rect.y1))

    if len(h_lines) < 3 or len(v_lines) < 2:
        return []

    # 페이지 테두리와 머리말 밑줄은 지면 폭에 가깝게 그어진다. 표 괘선은 본문 여백 안에
    # 머문다. 실제 문서에서 장식선은 폭 511~526, 표 괘선은 414였다(지면 폭 556).
    page_width = page.rect.width
    h_lines = [ln for ln in h_lines if (ln[2] - ln[1]) <= page_width * 0.88]
    if len(h_lines) < 3:
        return []

    ys = _cluster_values([y for y, _, _ in h_lines], tol)
    if len(ys) < 3:
        return []

    # 열 경계는 표 높이의 상당 부분을 지나는 세로선만 인정한다. 장식용 짧은 선을 경계로
    # 삼으면 설명 칸이 중간에서 잘려 글자가 두 셀로 쪼개진다.
    table_height = ys[-1] - ys[0]
    spans: dict[float, float] = {}
    for x, y0, y1 in v_lines:
        key = next((k for k in spans if abs(k - x) <= tol), x)
        spans[key] = spans.get(key, 0.0) + (y1 - y0)
    xs = sorted(x for x, covered in spans.items() if covered >= table_height * 0.4)
    if len(xs) < 1:
        return []

    # 표의 가로 범위는 가장 긴 가로선을 기준으로 삼는다.
    left = min(x0 for _, x0, _ in h_lines)
    right = max(x1 for _, _, x1 in h_lines)
    xs = [x for x in xs if left - tol <= x <= right + tol]
    if xs and abs(xs[0] - left) > tol:
        xs.insert(0, left)
    if xs and abs(xs[-1] - right) > tol:
        xs.append(right)
    if len(xs) < 2:
        return []

    # 페이지 테두리와 본문 여백선도 가로/세로선이므로 격자로 잡힌다. 그러면 페이지를
    # 통째로 덮는 칸이 만들어지고, 그 안의 본문이 전부 표로 오인되어 사라진다.
    # 표 칸은 페이지에 비해 작다는 성질로 걸러낸다.
    max_cell_h = page.rect.height * 0.35
    max_cell_w = page.rect.width * 0.92

    cells = []
    for ri in range(len(ys) - 1):
        for ci in range(len(xs) - 1):
            rect = fitz.Rect(xs[ci], ys[ri], xs[ci + 1], ys[ri + 1])
            if not (20 <= rect.width <= max_cell_w):
                continue
            if not (8 <= rect.height <= max_cell_h):
                continue
            cells.append(rect)
    return cells if len(cells) >= 4 else []


def detect_table_cells(page) -> list:
    """
    페이지의 표 셀을 찾는다.

    셀 배경을 칠한 표(키 길이 안내서)와 괘선으로만 그린 표(HTML5 안내서)가 둘 다 있다.
    채움 방식이 더 정확하므로 먼저 보고, 없으면 괘선으로 넘어간다.
    """
    filled = find_vector_cells(page)
    if len(filled) >= 4:
        return filled
    return find_ruled_cells(page)


def _cluster_values(values: list[float], tol: float) -> list[float]:
    """가까운 좌표를 하나로 묶어 정렬해 돌려준다."""
    out: list[float] = []
    for v in sorted(values):
        if out and v - out[-1] <= tol:
            continue
        out.append(v)
    return out


def _snap(values: list[float], tol: float = 3.0) -> dict[float, float]:
    """가까운 좌표를 하나로 묶는다."""
    mapping: dict[float, float] = {}
    for v in sorted(values):
        key = next((k for k in mapping.values() if abs(k - v) <= tol), None)
        mapping[v] = key if key is not None else v
    return mapping


def vector_grid(cells: list) -> tuple[list[float], list[float], dict[tuple[int, int], object]]:
    """셀 사각형을 행/열 격자로 정렬한다."""
    xs_map = _snap([c.x0 for c in cells])
    ys_map = _snap([c.y0 for c in cells])
    xs = sorted({xs_map[c.x0] for c in cells})
    ys = sorted({ys_map[c.y0] for c in cells})
    grid = {}
    for c in cells:
        grid[(ys.index(ys_map[c.y0]), xs.index(xs_map[c.x0]))] = c
    return xs, ys, grid


@dataclass(frozen=True, slots=True)
class VectorTextBlock:
    """벡터 페이지에서 OCR로 읽은 본문 덩어리."""
    page_number: int
    text: str
    bbox: tuple[float, float, float, float]
    line_count: int
    needs_review: bool = False
    label: str = ""            # 인식기가 분류한 종류. 없으면 빈 문자열.


def _item_bbox(item):
    """경로 조각 하나의 경계상자. 선/베지어/사각형/사변형을 모두 받는다."""
    import fitz

    points = []
    for part in item[1:]:
        if isinstance(part, fitz.Point):
            points.append(part)
        elif isinstance(part, fitz.Rect):
            points.extend([fitz.Point(part.x0, part.y0), fitz.Point(part.x1, part.y1)])
        elif isinstance(part, fitz.Quad):
            points.extend([part.ul, part.ur, part.ll, part.lr])
    if not points:
        return None
    xs = [p.x for p in points]
    ys = [p.y for p in points]
    return fitz.Rect(min(xs), min(ys), max(xs), max(ys))


def _text_run_rects(page, min_height: float = 2.0, max_height: float = 24.0,
                    max_width_ratio: float = 0.55) -> list:
    """
    글자 획으로 보이는 경로 조각을 모은다.

    아웃라인 변환 문서마다 글자를 묶는 단위가 다르다. 어떤 문서는 단어 뭉치마다 도형
    하나이고, 어떤 문서는 페이지의 글자 수천 개를 도형 하나에 몰아넣는다. 실제로 HTML5
    안내서는 도형이 92개인데 그 안의 경로 조각이 22,458개였다. 그래서 도형 단위 크기로
    거르면 후자에서 전부 탈락한다.

    조각 단위로 내려가면 두 형태를 같은 방식으로 다룰 수 있다. 높이 하한은 괘선을,
    상한은 표 세로선과 배경 상자를 빼기 위한 것이다.
    """
    max_width = page.rect.width * max_width_ratio
    out = []
    for drawing in page.get_drawings():
        for item in drawing.get("items", ()):
            rect = _item_bbox(item)
            if rect is None or rect.is_empty:
                continue
            if not (min_height <= rect.height <= max_height):
                continue
            if rect.width > max_width:
                continue
            out.append(rect)
    return out


def _group_lines(rects: list, y_tol: float = 4.0, min_line_width: float = 20.0) -> list[dict]:
    """
    세로 중심이 가까운 글자 조각을 한 줄로 묶는다.

    기준 중심은 줄이 만들어질 때 값으로 고정한다. 합집합 사각형에서 다시 계산하면 줄이
    커질수록 중심이 밀려 이웃 줄까지 연쇄로 흡수한다.
    """
    import fitz

    lines: list[dict] = []
    for rect in sorted(rects, key=lambda r: ((r.y0 + r.y1) / 2, r.x0)):
        cy = (rect.y0 + rect.y1) / 2
        for line in lines:
            if abs(line["cy"] - cy) <= y_tol:
                line["rect"] |= rect
                line["glyphs"] += 1
                break
        else:
            lines.append({"cy": cy, "rect": fitz.Rect(rect), "glyphs": 1})
    # 조각 개수가 아니라 줄 폭으로 거른다. 짧은 장식은 빠지고 두 조각짜리 줄은 남는다.
    return [ln for ln in lines if ln["rect"].width >= min_line_width]


def _group_paragraphs(lines: list[dict], gap: float = 12.0) -> list[dict]:
    """줄 사이 세로 간격이 좁으면 같은 문단으로 본다."""
    import fitz

    blocks: list[dict] = []
    for line in sorted(lines, key=lambda l: l["rect"].y0):
        if blocks and line["rect"].y0 - blocks[-1]["rect"].y1 <= gap:
            blocks[-1]["rect"] |= line["rect"]
            blocks[-1]["lines"] += 1
        else:
            blocks.append({"rect": fitz.Rect(line["rect"]), "lines": 1})
    return blocks


def _looks_like_text(s: str) -> bool:
    """
    삽화를 OCR한 결과를 걸러낸다.

    토큰 수로 재면 `[메시지인증/키유도/난수생성]용 해시함수` 같은 짧은 소제목이 함께
    떨어져 나간다. 그래서 글자 비율로 잰다. 삽화를 읽으면 기호와 한두 글자 조각이
    대부분이라 이 비율에서 갈린다.
    """
    s = s.strip()
    if len(s) < 4:
        return False
    good = sum(1 for ch in s if ch.isalnum())
    return good >= 4 and good / len(s) >= 0.55


def _mostly_inside(rect, area, ratio: float = 0.6) -> bool:
    """
    문단이 이미 표로 읽은 영역 안에 들어 있는지.

    닿기만 해도 버리면 표 옆이나 아래에 붙은 본문이 통째로 사라진다. 실제로 강조 박스를
    셀로 잡은 페이지에서 문단 8개 중 7개가 이 방식으로 유실됐다. 그래서 겹친 면적이
    문단의 대부분일 때만 표로 이미 읽은 것으로 본다.
    """
    overlap = rect & area
    if overlap.is_empty:
        return False
    body = rect.get_area()
    return bool(body) and overlap.get_area() / body >= ratio


_DIGIT_RUN = re.compile(r"\d+")

# 쪽 전체를 인식기에 넘길 때의 해상도. 이 값으로 우리 문서를 확인했다.
PAGE_READ_DPI = 200

# 본문으로 쓰지 않는 라벨. 쪽 탭과 꼬리말은 청크마다 노이즈로 들어가고, 목차는 조항
# 경로를 목차 항목으로 덮는다. 표는 버리지 않고 넘긴다. 격자를 실측하는 경로가 그 표를
# 실제로 잡았는지는 호출한 쪽에서 판단한다. 무조건 버리면 격자가 실패한 표가 사라진다.
SKIP_LABELS = {"PageHeader", "PageFooter", "TableOfContents"}
HEADING_LABELS = {"SectionHeader", "Title", "SubsectionHeader"}


def mostly_inside(bbox: tuple[float, float, float, float], area, ratio: float = 0.6) -> bool:
    """좌표 네 개로 주어진 상자가 어떤 영역 안에 대체로 들어 있는지."""
    import fitz

    return _mostly_inside(fitz.Rect(*bbox), area, ratio)


def extract_page_blocks(page, ocr, tmp_dir: Path,
                        dpi: int = PAGE_READ_DPI, check_dpi: int = 400) -> list[VectorTextBlock]:
    """
    쪽 전체를 인식기에 넘겨 덩어리 단위로 받는다.

    조각을 잘라 넘기지 않는다. 문맥 없는 작은 조각을 주면 이 부류의 인식기는 그럴듯한
    말을 지어낸다. 실제로 셀 크롭에서 `CRYPTREC(일본)`이 `CONTENTS CRYSTALLINE
    ( BVBIDE (이후) ) ...`로 나왔다. 쪽 전체를 주면 같은 문서에서 조사까지 맞았다.

    덩어리마다 종류가 붙어 오므로 제목과 꼬리말을 좌표로 어림잡지 않는다.

    숫자가 있는 덩어리는 tesseract로 다시 읽어 대조한다. 숫자는 규칙표의 임계값이 되므로
    한 판독만 믿지 않는다.
    """
    import fitz

    tmp_dir.mkdir(parents=True, exist_ok=True)
    scale = dpi / 72
    page_img = tmp_dir / f"page_p{page.number + 1}.png"
    page.get_pixmap(matrix=fitz.Matrix(scale, scale)).save(str(page_img))

    baseline = getattr(ocr, "read_baseline", None)
    check_matrix = fitz.Matrix(check_dpi / 72, check_dpi / 72)

    out: list[VectorTextBlock] = []
    for block in ocr.read_page(page_img):
        if block.label in SKIP_LABELS or not block.text:
            continue
        rect = fitz.Rect(*(value / scale for value in block.bbox))

        needs_review = False
        if baseline is not None and _DIGIT_RUN.search(block.text):
            crop = tmp_dir / f"check_p{page.number + 1}_{block.order}.png"
            clip = fitz.Rect(rect.x0 - 3, rect.y0 - 3, rect.x1 + 3, rect.y1 + 3)
            page.get_pixmap(matrix=check_matrix, clip=clip).save(str(crop))
            reference = baseline(crop, 6)
            needs_review = _DIGIT_RUN.findall(block.text) != _DIGIT_RUN.findall(reference)

        out.append(VectorTextBlock(
            page_number=page.number + 1,
            text=block.text,
            bbox=(round(rect.x0, 1), round(rect.y0, 1), round(rect.x1, 1), round(rect.y1, 1)),
            line_count=1,
            needs_review=needs_review,
            label=block.label,
        ))
    return out


def extract_detected_body(page, ocr, tmp_dir: Path, exclude: Optional[list] = None,
                          dpi: int = 400, min_confidence: float = 0.1) -> list[VectorTextBlock]:
    """
    인식기의 줄 검출로 벡터 페이지의 본문을 읽는다.

    도형 좌표로 문단 상자를 복원하는 방식(`extract_vector_body`)은 이 문서들에서 줄
    앞뒤가 잘린다. 글자가 획 단위 곡선 조각으로 쪼개져 있어(한 장에 24,000조각) 높이로
    거르면 조각 대부분이 탈락하기 때문이다. 검출기는 렌더한 그림에서 줄을 직접 찾으므로
    그 문제가 없다. 실제 페이지로 대조해보니 같은 페이지에서 잘린 1,065자 대신 온전한
    1,107자를 얻었다.

    세로로 돌아간 쪽 탭 글자는 신뢰도가 0.05 아래로 나오고 상자가 가로보다 세로로 길다.
    두 기준으로 걸러낸다.

    글자는 검출기가 아니라 tesseract로 읽는다. 상자가 정확하면 tesseract가 한국어 산문을
    더 잘 읽는다. 같은 줄에서 tesseract는 `키 자료를 ... 사용한다.`를, 검출기 쪽 인식기는
    `키 자료름 ... 사용하다.`를 냈다. 검출기 판독은 대조용으로 넘겨 라틴으로 깨진 한글을
    되살리고 숫자가 어긋나는지 보는 데 쓴다.

    쪽 아래 6%에 있는 줄은 꼬리말이다. 이 문서들은 매 쪽 하단에 문서명과 쪽번호가 있고,
    번호형 제목 모양이라 그대로 두면 조항 경로가 꼬리말로 덮인다.
    """
    import fitz

    tmp_dir.mkdir(parents=True, exist_ok=True)
    scale = dpi / 72
    matrix = fitz.Matrix(scale, scale)
    page_img = tmp_dir / f"page_p{page.number + 1}.png"
    page.get_pixmap(matrix=matrix).save(str(page_img))

    exclude = exclude or []
    footer_top = page.rect.height * 0.94
    boxes: list[dict] = []
    for (x0, y0, x1, y1), text, confidence in ocr.detect_lines(page_img):
        text = text.strip()
        if not text or confidence < min_confidence:
            continue
        rect = fitz.Rect(x0 / scale, y0 / scale, x1 / scale, y1 / scale)
        if rect.height > rect.width * 1.5:
            continue                            # 세로로 돌아간 쪽 탭 글자
        if rect.y0 >= footer_top:
            continue                            # 꼬리말
        if any(_mostly_inside(rect, cell) for cell in exclude):
            continue                            # 표로 이미 읽은 자리
        boxes.append({"rect": rect, "text": text})

    if not boxes:
        return []

    read_line = getattr(ocr, "read_line", None)
    out: list[VectorTextBlock] = []
    for index, para in enumerate(_group_detected_paragraphs(_merge_baselines(boxes))):
        rect, hint, line_count = para["rect"], para["text"], para["lines"]

        text, needs_review = hint, False
        if read_line is not None:
            clip = fitz.Rect(rect.x0 - 3, rect.y0 - 3, rect.x1 + 3, rect.y1 + 3)
            crop = tmp_dir / f"line_p{page.number + 1}_{index}.png"
            page.get_pixmap(matrix=matrix, clip=clip).save(str(crop))
            result = read_line(crop, hint, 6 if line_count > 1 else 7)
            text, needs_review = result.text, result.needs_review

        if not text.strip():
            continue

        out.append(VectorTextBlock(
            page_number=page.number + 1,
            text=text,
            bbox=(round(rect.x0, 1), round(rect.y0, 1), round(rect.x1, 1), round(rect.y1, 1)),
            line_count=line_count,
            needs_review=needs_review,
        ))
    return out


def _merge_baselines(boxes: list[dict], ) -> list[dict]:
    """
    한 줄이 여러 상자로 쪼개져 검출된 것을 가로로 이어 붙인다.

    기준 중심은 줄이 만들어질 때 값으로 고정한다. 합집합에서 다시 계산하면 줄이 커질수록
    중심이 밀려 이웃 줄까지 연쇄로 흡수한다.
    """
    import fitz

    lines: list[dict] = []
    for box in sorted(boxes, key=lambda b: (b["rect"].y0, b["rect"].x0)):
        rect = box["rect"]
        cy = (rect.y0 + rect.y1) / 2
        for line in lines:
            if abs(line["cy"] - cy) <= max(2.0, rect.height * 0.5):
                line["parts"].append(box)
                line["rect"] |= rect
                break
        else:
            lines.append({"cy": cy, "rect": fitz.Rect(rect), "parts": [box]})

    for line in lines:
        parts = sorted(line["parts"], key=lambda b: b["rect"].x0)
        line["text"] = " ".join(p["text"] for p in parts)
    return lines


def _group_detected_paragraphs(lines: list[dict]) -> list[dict]:
    """
    줄을 문단으로 묶는다. 세로 간격이 벌어지거나 제목 줄이 나오면 끊는다.

    제목을 따로 떼는 이유는 조항 경로가 제목에서 나오기 때문이다. 본문에 붙어 버리면
    인용 단위를 잃는다.
    """
    import fitz

    if not lines:
        return []
    heights = sorted(line["rect"].height for line in lines)
    typical = heights[len(heights) // 2] or 10.0

    paragraphs: list[dict] = []
    for line in sorted(lines, key=lambda l: (l["rect"].y0, l["rect"].x0)):
        rect = line["rect"]
        is_heading = detect_heading(line["text"]) is not None
        if paragraphs and not is_heading and not paragraphs[-1]["heading"]:
            previous = paragraphs[-1]
            gap = rect.y0 - previous["rect"].y1
            overlaps = rect.x1 > previous["rect"].x0 and rect.x0 < previous["rect"].x1
            if gap <= typical * 1.2 and overlaps:
                previous["text"] += " " + line["text"]
                previous["rect"] |= rect
                previous["lines"] += 1
                continue
        paragraphs.append({"rect": fitz.Rect(rect), "text": line["text"],
                           "lines": 1, "heading": is_heading})
    return paragraphs


def extract_vector_body(
    page,
    ocr,
    tmp_dir: Path,
    exclude: Optional[list] = None,
    dpi: int = 400,
) -> list[VectorTextBlock]:
    """
    벡터 페이지의 본문을 문단 단위로 읽는다.

    글자가 벡터 도형이므로 도형 좌표를 뭉치면 OCR 없이 문단 경계를 얻을 수 있다. 그래서
    읽기 순서와 위치가 보존되고, 문단마다 따로 읽으므로 페이지 전체를 한 번에 읽는 것보다
    정확하다. 표 영역은 이미 표로 처리하므로 제외한다.
    """
    import fitz

    lines = _group_lines(_text_run_rects(page))
    if not lines:
        return []

    exclude = exclude or []
    tmp_dir.mkdir(parents=True, exist_ok=True)
    matrix = fitz.Matrix(dpi / 72, dpi / 72)

    out: list[VectorTextBlock] = []
    for index, block in enumerate(_group_paragraphs(lines)):
        rect = block["rect"]
        if any(_mostly_inside(rect, cell) for cell in exclude):
            continue

        clip = fitz.Rect(rect.x0 - 2, rect.y0 - 2, rect.x1 + 2, rect.y1 + 2)
        pix = page.get_pixmap(matrix=matrix, clip=clip)
        img = tmp_dir / f"body_p{page.number + 1}_{index}.png"
        pix.save(str(img))

        psm = 7 if block["lines"] == 1 else 6
        result = ocr.read(img, psm=psm)
        if not _looks_like_text(result.text):
            continue

        out.append(VectorTextBlock(
            page_number=page.number + 1,
            text=result.text,
            bbox=(round(rect.x0, 1), round(rect.y0, 1), round(rect.x1, 1), round(rect.y1, 1)),
            line_count=block["lines"],
            needs_review=result.needs_review,
        ))
    return out


def is_scanned_page(page) -> bool:
    """
    페이지가 순수 스캔 이미지인지 판정한다.

    벡터 글자도 텍스트 레이어도 없고 페이지를 덮는 이미지가 있으면 스캔본이다. 이 경우
    셀 좌표를 얻을 수 없어 페이지 전체를 읽는 수밖에 없다.
    """
    try:
        if len(page.get_text("text").strip()) >= 20:
            return False
    except Exception:
        pass

    # 벡터 조각이 조금 있다고 벡터 페이지는 아니다. 본문은 이미지인데 머리말 로고만
    # 벡터로 얹힌 문서가 있다(키 관리 안내서). 글자 줄이 여러 개 잡혀야 벡터로 본다.
    if len(_group_lines(_text_run_rects(page))) >= 5:
        return False

    page_area = page.rect.width * page.rect.height
    try:
        for info in page.get_image_info():
            bbox = info.get("bbox")
            if not bbox:
                continue
            import fitz
            r = fitz.Rect(bbox)
            if abs(r.width * r.height) >= page_area * 0.5:
                return True
    except Exception:
        return False
    return False


def extract_scanned_page(page, ocr, tmp_dir: Path, dpi: int = 400) -> list[VectorTextBlock]:
    """
    스캔 페이지를 통째로 읽어 문단으로 나눈다.

    벡터 문서와 달리 문단 경계를 좌표로 알 수 없으므로 인식기가 낸 줄바꿈에 의존한다.
    빈 줄을 문단 경계로 본다. 위치 정보가 없어 인용 정밀도가 떨어지고 표 구조도 복원되지
    않는다. 다른 수단이 없을 때만 쓰는 경로다.
    """
    import fitz

    tmp_dir.mkdir(parents=True, exist_ok=True)
    pix = page.get_pixmap(matrix=fitz.Matrix(dpi / 72, dpi / 72))
    img = tmp_dir / f"scan_p{page.number + 1}.png"
    pix.save(str(img))

    reader = getattr(ocr, "read_lines", None)
    if reader is None:
        text = ocr.read(img, psm=3).text
        lines = text.splitlines() or ([text] if text else [])
    else:
        lines = reader(img, psm=3)

    paragraphs: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line.strip())
        elif current:
            paragraphs.append(current)
            current = []
    if current:
        paragraphs.append(current)

    out: list[VectorTextBlock] = []
    for para in paragraphs:
        text = " ".join(para)
        if not _looks_like_text(text):
            continue
        out.append(VectorTextBlock(
            page_number=page.number + 1,
            text=text,
            bbox=(round(page.rect.x0, 1), round(page.rect.y0, 1),
                  round(page.rect.x1, 1), round(page.rect.y1, 1)),
            line_count=len(para),
            needs_review=True,   # 위치를 특정할 수 없으므로 항상 검수 대상
        ))
    return out


def extract_vector_table(page, ocr, tmp_dir: Path, dpi: int = 400) -> Optional[TableBlock]:
    """
    벡터 아웃라인 페이지에서 표를 OCR로 복원한다.

    셀 좌표를 알고 있으므로 셀 영역만 잘라 읽는다. 레이아웃 추측이 없어 행과 열이
    뒤섞이지 않는다.
    """
    import fitz

    cells = detect_table_cells(page)
    if not cells:
        return None

    xs, ys, grid = vector_grid(cells)
    if len(xs) < 2 or len(ys) < 2:
        return None

    tmp_dir.mkdir(parents=True, exist_ok=True)
    matrix = fitz.Matrix(dpi / 72, dpi / 72)
    needs_review = False
    table: list[list[str]] = []
    table_width = max((c.x1 for c in cells), default=1.0) - min((c.x0 for c in cells), default=0.0)

    for ri in range(len(ys)):
        row: list[str] = []
        for ci in range(len(xs)):
            cell = grid.get((ri, ci))
            if cell is None:
                row.append("")
                continue
            clip = fitz.Rect(cell.x0 + 1.5, cell.y0 + 1.5, cell.x1 - 1.5, cell.y1 - 1.5)
            pix = page.get_pixmap(matrix=matrix, clip=clip)
            img = tmp_dir / f"p{page.number + 1}_r{ri}_c{ci}.png"
            pix.save(str(img))
            # 칸 모양으로 인식 모드를 고른다. 넓고 높은 칸은 줄바꿈된 산문이라 블록 모드가,
            # 좁은 칸은 알고리즘명 목록이라 흩어진 글자 모드가 정확했다.
            is_prose = cell.width >= table_width * 0.35 and cell.height > 18
            result = ocr.read(img, psm=6 if is_prose else 11)
            needs_review = needs_review or result.needs_review
            row.append(result.text)
        table.append(row)

    grid = _clean_grid(table)
    header, body = split_header(grid)
    if not is_meaningful_table(header, body, ocr_source=True):
        return None

    return TableBlock(
        page_number=page.number + 1,
        rows=tuple(tuple(r) for r in body),
        header=header,
        source="vector_ocr",
        needs_review=needs_review,
    )
