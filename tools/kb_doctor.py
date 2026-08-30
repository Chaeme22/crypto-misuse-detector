"""
kb_doctor — 지식베이스(표준/가이드라인 PDF) 색인 적합성 진단기.

색인 전에 각 PDF가 다음 중 무엇인지 판정한다.
  OK        : 원본 텍스트 레이어. 그대로 색인 가능.
  OCR_CHECK : 텍스트는 있으나 OCR 흔적/깨짐 지표가 높음 → 사람 검수 필요.
  SCAN      : 텍스트 레이어 없음 → OCR 선행 필요. 현 상태로 색인하면 유령 청크 발생.
  MIXED     : 일부 페이지만 스캔.

부가로 표 감지 수, 목차(TOC) 유무, 언어 추정치를 함께 보고한다.
  - 표 감지 0건이면 키길이/보안강도 표에서 임계값 추출이 불가능하다는 신호.
  - TOC 유무는 조항(section) 단위 인용 메타데이터 확보 가능성을 뜻한다.
  - 언어 추정치는 파서가 language="ko" 로 하드코딩한 것이 맞는지 검증용.

사용법:
    python tools/kb_doctor.py document/
    python tools/kb_doctor.py document/ --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    sys.exit("PyMuPDF 필요:  python -m pip install pymupdf")

# 색인 파이프라인과 동일한 판정을 쓰기 위해 앱 모듈을 가져온다.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from rag_app.parsing import text_quality  # noqa: E402

import re  # noqa: E402

# "쪽 1", "Page 3", "1" 처럼 페이지 번호만 담은 자동 생성 목차 항목.
_PLACEHOLDER_TOC = re.compile(r"^(?:쪽|페이지|page|p\.?)\s*\d+$|^\d+$", re.IGNORECASE)


@dataclass
class PageStat:
    page: int
    chars: int
    has_text: bool
    images: int
    image_area_ratio: float
    tables: int


@dataclass
class DocReport:
    file: str
    pages: int = 0
    verdict: str = "UNKNOWN"
    reasons: list[str] = field(default_factory=list)

    text_pages: int = 0
    scan_pages: list[int] = field(default_factory=list)
    embedded_fonts: int = 0
    total_chars: int = 0

    tables_detected: int = 0
    toc_entries: int = 0
    toc_is_placeholder: bool = False

    lang_guess: str = "unknown"
    hangul_ratio: float = 0.0

    # OCR 품질 지표 (1만자당 출현율)
    jamo_per_10k: float = 0.0
    digit_confuse_per_10k: float = 0.0
    replacement_per_10k: float = 0.0
    long_token_per_10k: float = 0.0
    critical_tokens_found: int = 0

    error: str | None = None


def diagnose(path: Path) -> DocReport:
    rep = DocReport(file=path.name)
    try:
        doc = fitz.open(str(path))
    except Exception as e:
        rep.error = f"열기 실패: {e}"
        rep.verdict = "ERROR"
        return rep

    rep.pages = len(doc)
    all_text: list[str] = []
    page_stats: list[PageStat] = []

    for idx in range(rep.pages):
        page = doc.load_page(idx)
        try:
            text = page.get_text("text")
        except Exception:
            text = ""

        chars = len(text.strip())
        area = page.rect.width * page.rect.height
        img_area = 0.0
        images = 0
        try:
            for info in page.get_image_info():
                bbox = info.get("bbox")
                if bbox:
                    r = fitz.Rect(bbox)
                    img_area += abs(r.width * r.height)
                    images += 1
        except Exception:
            pass

        n_tables = 0
        try:
            n_tables = len(page.find_tables().tables)
        except Exception:
            pass

        has_text = chars >= 20
        page_stats.append(PageStat(
            page=idx + 1, chars=chars, has_text=has_text, images=images,
            image_area_ratio=round(img_area / area, 3) if area else 0.0,
            tables=n_tables,
        ))
        if has_text:
            rep.text_pages += 1
            all_text.append(text)
        else:
            rep.scan_pages.append(idx + 1)
        rep.tables_detected += n_tables

    # 폰트 임베딩: 스캔 이미지 PDF는 통상 0에 가깝다.
    fonts = set()
    for idx in range(rep.pages):
        try:
            for f in doc.get_page_fonts(idx):
                fonts.add(f[3])
        except Exception:
            pass
    rep.embedded_fonts = len(fonts)

    # 목차는 항목 수보다 내용이 중요하다. CorelDRAW 등에서 내보낸 문서는 "쪽 1", "쪽 2" 같은
    # 자동 생성 껍데기 목차를 갖는데, 이건 조항 경로 확보에 아무 쓸모가 없다.
    try:
        toc = doc.get_toc()
        rep.toc_entries = len(toc)
        placeholder = sum(1 for lvl, title, page in toc if _PLACEHOLDER_TOC.match(title.strip()))
        rep.toc_is_placeholder = bool(toc) and placeholder >= len(toc) * 0.8
    except Exception:
        rep.toc_entries = 0
    doc.close()

    joined = "\n".join(all_text)
    rep.total_chars = len(joined)

    verdict = text_quality.assess(joined)
    metrics = verdict.metrics
    if rep.total_chars:
        rep.hangul_ratio = metrics.hangul_ratio
        rep.lang_guess = text_quality.detect_language(joined)
        rep.jamo_per_10k = metrics.jamo_per_10k
        rep.digit_confuse_per_10k = metrics.digit_confuse_per_10k
        rep.replacement_per_10k = metrics.replacement_per_10k
        rep.long_token_per_10k = metrics.long_token_per_10k
        rep.critical_tokens_found = metrics.crypto_tokens_found

    # --- 판정 ---------------------------------------------------------------
    if rep.text_pages == 0:
        rep.verdict = "SCAN"
        rep.reasons.append("텍스트 레이어 없음 → OCR 선행 필요 (현 상태 색인 시 유령 청크 생성)")
    elif rep.scan_pages:
        ratio = len(rep.scan_pages) / rep.pages
        rep.verdict = "MIXED" if ratio > 0.05 else "OK"
        if ratio > 0.05:
            rep.reasons.append(f"{len(rep.scan_pages)}/{rep.pages} 페이지에 텍스트 없음 (부분 스캔)")
    else:
        rep.verdict = "OK"

    if rep.verdict in ("OK", "MIXED"):
        ocr_flags = list(verdict.reasons)
        if rep.embedded_fonts == 0:
            ocr_flags.append("임베딩 폰트 0 (이미지 기반 문서 가능성)")
        if ocr_flags:
            rep.verdict = "OCR_CHECK"
            rep.reasons.extend(ocr_flags)

    # 코퍼스 특성상 반드시 확인할 항목
    if rep.tables_detected == 0 and rep.text_pages:
        rep.reasons.append("표 감지 0건 → 키길이/보안강도 표에서 임계값 추출 불가 (Tier-1 규칙 영향)")
    if rep.toc_is_placeholder:
        rep.reasons.append(
            f"목차 {rep.toc_entries}개가 페이지 번호 껍데기 → 조항 경로 확보 불가 (제목 인식 필요)")
    elif rep.toc_entries == 0:
        rep.reasons.append("목차 북마크 없음 → 조항 단위 인용 메타는 제목 정규식으로만 확보 가능")
    if rep.critical_tokens_found < 8 and rep.text_pages:
        rep.reasons.append(
            f"핵심 암호 토큰 {rep.critical_tokens_found}/{len(text_quality.CRYPTO_TOKENS)}종만 발견 "
            "(문자 깨짐 또는 무관 문서)")

    return rep


ICON = {"OK": "[ OK ]", "OCR_CHECK": "[CHECK]", "MIXED": "[MIXED]",
        "SCAN": "[SCAN ]", "ERROR": "[ERR  ]", "UNKNOWN": "[  ?  ]"}


def main() -> int:
    # Windows 콘솔(cp949)에서 인코딩 불가 문자로 죽지 않도록 방어
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="지식베이스 PDF 색인 적합성 진단")
    ap.add_argument("target", type=Path, help="PDF 파일 또는 디렉터리")
    ap.add_argument("--json", type=Path, help="상세 결과를 JSON으로 저장")
    args = ap.parse_args()

    if args.target.is_dir():
        files = sorted(args.target.rglob("*.pdf"))
    elif args.target.is_file():
        files = [args.target]
    else:
        print(f"경로 없음: {args.target}")
        return 1

    if not files:
        print(f"PDF 없음: {args.target}")
        return 1

    reports = [diagnose(f) for f in files]

    print(f"\n{'판정':<8} {'파일':<44} {'쪽':>4} {'표':>4} {'TOC':>4} {'언어':>4}  비고")
    print("-" * 110)
    for r in reports:
        name = r.file if len(r.file) <= 43 else r.file[:40] + "..."
        print(f"{ICON[r.verdict]:<8} {name:<44} {r.pages:>4} "
              f"{r.tables_detected:>4} {r.toc_entries:>4} {r.lang_guess:>4}")
        for reason in r.reasons:
            print(f"{'':<8} └─ {reason}")
        if r.error:
            print(f"{'':<8} └─ {r.error}")

    counts: dict[str, int] = {}
    for r in reports:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print("-" * 110)
    print("요약: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    blocking = [r for r in reports if r.verdict in ("SCAN", "ERROR")]
    if blocking:
        print(f"\n색인 차단 권고 {len(blocking)}건 - OCR 선행 없이 색인하면 빈 청크가 검색·인용됩니다:")
        for r in blocking:
            print(f"  - {r.file}")
    checks = [r for r in reports if r.verdict in ("OCR_CHECK", "MIXED")]
    if checks:
        print(f"\n사람 검수 권고 {len(checks)}건 - 표 안 숫자(키 길이)를 원문과 대조하세요:")
        for r in checks:
            print(f"  - {r.file}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps([asdict(r) for r in reports], ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"\n상세 결과 저장: {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
