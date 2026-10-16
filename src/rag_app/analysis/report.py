"""
사람이 읽는 보고서(Markdown, PDF).

SARIF는 기계와 IDE가 읽는 형식이다. 개발자나 검토자가 파일 하나로 결과를 받아 보려면
요약과 근거가 정리된 문서가 필요하다. 이 모듈은 SARIF 문서만 입력으로 받는다. 판정을 다시
하지 않고 SARIF에 이미 있는 값을 옮겨 적기만 하므로, 두 보고서의 내용이 어긋날 수 없다.
같은 SARIF에는 같은 Markdown이 나온다(실행 시각을 넣지 않는다).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# 보고서 제목에 쓰는 우리말 이름. 규칙표의 name은 영문 식별자다.
RULE_TITLES = {
    "CRYPTO-HASH-WEAK": "약한 해시",
    "CRYPTO-MODE-ECB": "ECB 운영모드",
    "CRYPTO-CIPHER-OBSOLETE": "낡은 암호",
    "CRYPTO-KEYSIZE-SHORT": "짧은 키",
    "CRYPTO-RNG-INSECURE": "약한 난수",
    "CRYPTO-SEED-PREDICTABLE": "예측 가능한 시드",
    "CRYPTO-KEY-HARDCODED": "하드코딩 키",
    "CRYPTO-IV-STATIC": "고정 IV",
    "CRYPTO-PASSWORD-HARDCODED": "하드코딩 비밀번호",
    "CRYPTO-SALT-STATIC": "고정 솔트",
    "CRYPTO-KDF-WEAK": "약한 키 유도",
}

# 판정 묶음. 보고서는 이 순서로 놓는다. 바로 고칠 것이 위로 간다.
GROUPS = (
    ("violation", "위반", "고쳐야 한다"),
    ("warning", "경고", "지금은 허용되나 2030년 이후 교체 대상(112비트 보안강도)"),
    ("review", "확인 필요", "값이 코드 밖에서 오거나 경로마다 달라 사람이 확인해야 한다"),
)

# PDF에 쓸 한글 글꼴을 찾는 곳. 환경 변수가 먼저다.
FONT_ENV = "CRYPTO_REPORT_FONT"
FONT_CANDIDATES = (
    "C:/Windows/Fonts/malgun.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/usr/share/fonts/nanum/NanumGothic.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
    "/Library/Fonts/AppleGothic.ttf",
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
)


# Finding.message()가 붙이는 줄 중 보고서가 구조로 따로 적는 것.
_STRUCTURED_PREFIXES = ("표 대조:", "근거:", "수정 제안:")


def group_of(result: dict) -> str:
    """SARIF result 하나가 위반·경고·확인 필요 중 어디에 속하는지."""
    if result.get("kind") == "review":
        return "review"
    return "warning" if result.get("level") == "warning" else "violation"


def render_markdown(document: dict) -> str:
    """SARIF 문서를 Markdown 보고서로 옮긴다."""
    run = document["runs"][0]
    results = run.get("results", [])
    rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
    props = run.get("properties", {})
    lines = ["# 암호 오용 검사 보고서", ""]

    root = run.get("originalUriBaseIds", {}).get("SRCROOT", {}).get("uri", "")
    lines.append(f"- 검사 대상: `{root}`")
    vcs = run.get("versionControlProvenance") or []
    if vcs:
        where = vcs[0].get("branch", "")
        lines.append(f"- 커밋: `{vcs[0].get('revisionId', '')[:12]}`" + (f" ({where})" if where else ""))
    verdict = props.get("verdict", {})
    if verdict.get("mode") == "llm":
        lines.append(f"- 판정 방식: 기준표·값 추적 판정 + AI 보조 판단({verdict.get('model', '')})")
    else:
        lines.append("- 판정 방식: 기준표·값 추적 판정")
    driver = run["tool"]["driver"]
    lines.append(f"- 도구: {driver.get('name', '')} {driver.get('version', '')}")
    lines.append("- 기준: KISA 암호 알고리즘 및 키 길이 이용 안내서 등(최소 112비트, 권장 128비트 보안강도)")
    lines.append("")

    groups = {key: [r for r in results if group_of(r) == key] for key, _, _ in GROUPS}
    lines += ["## 요약", "", "| 판정 | 건수 | 뜻 |", "|---|---|---|"]
    for key, label, meaning in GROUPS:
        lines.append(f"| {label} | {len(groups[key])} | {meaning} |")
    lines.append("")

    if results:
        by_rule: dict[str, dict[str, int]] = {}
        for r in results:
            by_rule.setdefault(r["ruleId"], {k: 0 for k, _, _ in GROUPS})[group_of(r)] += 1
        lines += ["| 오용 유형 | CWE | 위반 | 경고 | 확인 필요 |", "|---|---|---|---|---|"]
        for rule_id in sorted(by_rule):
            counts = by_rule[rule_id]
            cwe = rules.get(rule_id, {}).get("properties", {}).get("cwe", "")
            lines.append(f"| {RULE_TITLES.get(rule_id, rule_id)} | {cwe} | {counts['violation']} | "
                         f"{counts['warning']} | {counts['review']} |")
        lines.append("")
    else:
        lines += ["검사한 범위에서 보고할 암호 오용을 찾지 못했다.", ""]

    for key, label, _ in GROUPS:
        if not groups[key]:
            continue
        lines += [f"## {label} ({len(groups[key])}건)", ""]
        for number, result in enumerate(groups[key], 1):
            lines += _render_result(number, result, rules.get(result["ruleId"], {}))
    return "\n".join(lines).rstrip() + "\n"


def _render_result(number: int, result: dict, rule: dict) -> list[str]:
    location = result["locations"][0]["physicalLocation"]
    uri = location["artifactLocation"]["uri"]
    line = location["region"].get("startLine", "")
    rule_id = result["ruleId"]
    cwe = rule.get("properties", {}).get("cwe", "")
    out = [f"### {number}. [{RULE_TITLES.get(rule_id, rule_id)}] `{uri}:{line}`", ""]
    snippet = location["region"].get("snippet", {}).get("text", "").strip()
    if snippet:
        out += ["```java", *snippet.splitlines(), "```", ""]
    out.append(f"- 규칙: `{rule_id}` ({cwe})" + (f" — {rule['shortDescription']['text']}"
                                                if rule.get("shortDescription") else ""))
    # message에는 표 대조·근거·수정 제안도 문장으로 들어 있다. 아래에서 구조로 따로 적으므로
    # 판정 이유 줄만 옮긴다.
    for part in result["message"]["text"].splitlines():
        part = part.strip()
        if part and not part.startswith(_STRUCTURED_PREFIXES):
            out.append(f"- {part}" if part.startswith("값 확인:") else f"- 판정: {part}")
    props = result.get("properties", {})
    table = props.get("tableCheck")
    if table and table.get("found"):
        out.append(f"- 기준표 비교: 코드 `{table['found']}` / 기준 {table.get('requirement') or '-'} "
                   f"(용도 {table.get('purpose') or '-'})")
    for citation in props.get("citations", []):
        quote = " ".join(str(citation.get("quote", "")).split())
        if len(quote) > 200:
            quote = quote[:200] + "…"
        out.append(f"- 근거 조항: {citation.get('document', '')} {citation.get('page', '')}쪽"
                   + (f" — \"{quote}\"" if quote else ""))
    if rule.get("help", {}).get("text") and group_of(result) != "review":
        out.append(f"- 수정 방안: {rule['help']['text']}")
    out.append("")
    return out


def find_font() -> Path | None:
    """PDF용 한글 글꼴(TTF 또는 TTC). 없으면 None."""
    env = os.environ.get(FONT_ENV)
    if env and Path(env).is_file():
        return Path(env)
    for candidate in FONT_CANDIDATES:
        if Path(candidate).is_file():
            return Path(candidate)
    return None


def write_pdf(markdown_text: str, out_path: Path) -> None:
    """
    Markdown 보고서를 PDF로 쓴다.

    fpdf2(순수 파이썬)를 쓴다. 한글을 그리려면 TTF 글꼴이 필요하다. 글꼴을 찾지 못하면
    무엇을 하면 되는지 알려 주고 멈춘다(빈 글자 상자로 가득한 PDF를 내지 않는다).
    """
    try:
        import markdown
        from fpdf import FPDF
    except ImportError as exc:
        raise RuntimeError("PDF 보고서에는 fpdf2가 필요하다: pip install fpdf2") from exc
    font = find_font()
    if font is None:
        raise RuntimeError(f"한글 TTF 글꼴을 찾지 못했다. 환경 변수 {FONT_ENV}에 글꼴 파일 경로를 "
                           "지정하거나 --report md를 쓴다")
    html = markdown.markdown(markdown_text, extensions=["tables", "fenced_code"])
    pdf = FPDF()
    # 글꼴 모음(.ttc)이면 한국어 판을 고른다. Noto Sans CJK 모음은 일본어·한국어·중국어 순이다.
    extra = {"collection_font_number": 1} if font.suffix.lower() == ".ttc" else {}
    for style in ("", "B", "I", "BI"):
        pdf.add_font("report", style, str(font), **extra)
    pdf.set_font("report", size=10)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.write_html(html, font_family="report", pre_code_font="report")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out_path))


def write(document: dict, out_path: Path, fmt: str) -> Path:
    """보고서를 `fmt`(md 또는 pdf) 형식으로 쓴다."""
    text = render_markdown(document)
    if fmt == "md":
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    elif fmt == "pdf":
        write_pdf(text, out_path)
    else:
        raise ValueError(f"알 수 없는 보고서 형식: {fmt}")
    return out_path


def from_sarif(sarif_path: Path, out_path: Path, fmt: str) -> Path:
    """이미 만든 SARIF 파일에서 보고서를 만든다."""
    document = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    return write(document, out_path, fmt)
