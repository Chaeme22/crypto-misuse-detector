"""
OCR 엔진 비교 - 우리 문서로 재고 고른다.

일반 벤치마크 순위가 이 코퍼스에 그대로 적용된다고 가정하지 않는다. 국문 표준문서를
벡터 아웃라인으로 내보낸 특수한 형태이고, 우리가 읽어야 하는 것은 페이지 전체가 아니라
표 셀과 문단 조각이기 때문이다.

정답은 사람이 원문 페이지를 눈으로 보고 적었다(`GOLD`). 추정으로 채운 항목은 없다.

측정 지표
  CER   글자 오류율. 낮을수록 좋다. 삽입/삭제/치환을 편집거리로 센다.
  핵심   알고리즘명과 숫자가 정확히 살아 있는지. 규칙표 임계값에 직결되므로 따로 센다.

사용법
    python tools/ocr_bench.py --engines tesseract
    python tools/ocr_bench.py --engines tesseract,easyocr,paddleocr   # GPU 서버에서
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fitz  # noqa: E402
from rag_app.parsing.ocr_engine import create_engine  # noqa: E402

KISA = Path("수정방향/암호 가이드라인/KISA/암호 알고리즘 및 키 길이 이용 안내서_2018.pdf")

# 원문 페이지를 보고 적은 정답. (페이지, 영역, 정답)
# 영역은 PDF 좌표계(72dpi 기준)다.
GOLD: list[tuple[int, tuple[float, float, float, float], str, int]] = [
    # --- 5쪽 표 2: 머리행과 112비트 행 (좌표는 벡터 격자에서 뽑은 실제 셀) ---
    (5, (86.3, 495.1, 163.1, 516.1), "보안강도", 11),
    (5, (163.1, 495.1, 239.9, 516.1), "NIST(미국)", 11),
    (5, (239.9, 495.1, 316.7, 516.1), "CRYPTREC(일본)", 11),
    (5, (316.7, 495.1, 393.4, 516.1), "ECRYPT(유럽)", 11),
    (5, (393.4, 495.1, 470.2, 516.1), "국내", 11),
    (5, (86.3, 519.0, 163.1, 621.4), "112 비트 이상", 11),
    (5, (163.1, 519.0, 239.9, 621.4), "AES-128 AES-192 AES-256 3TDEA", 11),
    (5, (393.4, 519.0, 470.2, 621.4),
     "SEED HIGHT ARIA-128 ARIA-192 ARIA-256 LEA-128 LEA-192 LEA-256", 11),
    # --- 6쪽 표 2: 128/192/256비트 행 ---
    (6, (88.2, 89.3, 165.0, 191.8), "128 비트 이상", 11),
    (6, (165.0, 89.3, 241.8, 191.8), "AES-128 AES-192 AES-256", 11),
    (6, (395.3, 89.3, 472.1, 191.8),
     "SEED HIGHT ARIA-128 ARIA-192 ARIA-256 LEA-128 LEA-192 LEA-256", 11),
    (6, (88.2, 191.8, 165.0, 259.5), "192 비트 이상", 11),
    (6, (165.0, 191.8, 241.8, 259.5), "AES-192 AES-256", 11),
    (6, (395.3, 191.8, 472.1, 259.5), "ARIA-192 ARIA-256 LEA-192 LEA-256", 11),
    (6, (88.2, 259.5, 165.0, 295.7), "256 비트 이상", 11),
    (6, (165.0, 259.5, 241.8, 295.7), "AES-256", 11),
    (6, (395.3, 259.5, 472.1, 295.7), "ARIA-256 LEA-256", 11),
    # --- 6쪽 본문 (좌표는 문단 묶기 결과) ---
    (6, (88.0, 328.0, 250.0, 353.0), "2) 해시함수", 7),
    (6, (88.0, 366.0, 472.0, 398.0),
     "해시함수는 사용 목적에 따라 메시지인증/키유도/난수생성용과 단순해시(메시지 압축)/"
     "전자서명용으로 나뉘지며, 사용 목적과 보안강도에 따라 <표 3>, <표 4>와 같이 분류된다.", 6),
    (6, (88.0, 425.0, 320.0, 441.0), "[메시지인증/키유도/난수생성]용 해시함수", 7),
    (6, (100.0, 455.0, 400.0, 482.0),
     "메시지 인증용 : 메시지의 위·변조를 확인하기 위해 해시함수 이용 "
     "키유도/난수생성용 : 안전한 키와 랜덤한 난수를 생성하기 위해 해시함수 이용", 6),
]

# 규칙표 임계값에 직결되는 토큰. 이게 깨지면 다른 글자가 맞아도 쓸모가 없다.
_KEY_TOKEN = re.compile(
    r"(?:AES|SEED|ARIA|LEA|HIGHT|3TDEA|TDEA|SHA3?|RSA|DSA|ECDSA|Camellia|Serpent)"
    r"(?:-\d+)?|\d{2,4}\s*비트|\d{3,4}"
)


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def norm(s: str) -> str:
    """공백 차이는 오류로 세지 않는다."""
    return re.sub(r"\s+", " ", s).strip()


def key_tokens(s: str) -> set[str]:
    return {re.sub(r"\s+", "", t) for t in _KEY_TOKEN.findall(s)}


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="OCR 엔진을 우리 문서로 비교")
    ap.add_argument("--engines", default="tesseract",
                    help="쉼표로 구분 (tesseract,easyocr,paddleocr,surya)")
    ap.add_argument("--pdf", type=Path, default=KISA)
    ap.add_argument("--dpi", type=int, default=400)
    ap.add_argument("--show", action="store_true", help="항목별 인식 결과를 함께 출력")
    args = ap.parse_args()

    if not args.pdf.exists():
        print(f"PDF 없음: {args.pdf}")
        return 1

    tmp = Path(tempfile.gettempdir()) / "ocr_bench"
    tmp.mkdir(exist_ok=True)

    # 정답 영역을 이미지로 미리 잘라 둔다. 모든 엔진이 같은 입력을 받아야 공정하다.
    doc = fitz.open(str(args.pdf))
    matrix = fitz.Matrix(args.dpi / 72, args.dpi / 72)
    samples = []
    for idx, (page_no, rect, truth, psm) in enumerate(GOLD):
        page = doc.load_page(page_no - 1)
        pix = page.get_pixmap(matrix=matrix, clip=fitz.Rect(*rect))
        img = tmp / f"gold_{idx:02d}.png"
        pix.save(str(img))
        samples.append((img, truth, psm))
    doc.close()
    print(f"정답 표본 {len(samples)}개 · {args.dpi} DPI · {args.pdf.name}\n")

    results = {}
    for name in [e.strip() for e in args.engines.split(",") if e.strip()]:
        try:
            engine = create_engine(name)
        except Exception as e:
            print(f"[{name}] 사용 불가: {e}\n")
            continue

        total_dist = total_len = 0
        key_hit = key_total = 0
        exact = 0
        start = time.time()
        rows = []
        for img, truth, psm in samples:
            got = norm(engine.read(img, psm=psm).text)
            want = norm(truth)
            dist = edit_distance(got, want)
            total_dist += dist
            total_len += len(want)
            if got == want:
                exact += 1
            want_keys = key_tokens(want)
            got_keys = key_tokens(got)
            key_total += len(want_keys)
            key_hit += len(want_keys & got_keys)
            rows.append((want, got, dist))
        elapsed = time.time() - start

        cer = total_dist / total_len if total_len else 0
        key_acc = key_hit / key_total if key_total else 0
        results[name] = (cer, key_acc, exact, elapsed)
        print(f"[{name}]  CER {cer:6.1%}   핵심토큰 {key_acc:6.1%}   "
              f"완전일치 {exact}/{len(samples)}   {elapsed:.0f}초")

        if args.show:
            for want, got, dist in rows:
                mark = "OK " if dist == 0 else f"d={dist:<3}"
                print(f"    {mark} 정답: {want[:70]}")
                if dist:
                    print(f"         인식: {got[:70]}")
            print()

    if len(results) > 1:
        print("\n요약 (CER 낮은 순)")
        for name, (cer, key_acc, exact, el) in sorted(results.items(), key=lambda kv: kv[1][0]):
            print(f"  {name:<12} CER {cer:6.1%}  핵심토큰 {key_acc:6.1%}  {el:5.0f}초")
        print("\n핵심토큰 정확도를 먼저 본다. 알고리즘명과 키 길이가 규칙표 임계값이 되므로,")
        print("전체 CER이 낮아도 핵심토큰이 틀리면 쓸 수 없다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
