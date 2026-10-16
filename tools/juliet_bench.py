"""
NIST Juliet Test Suite (Java)로 채점한다.

Juliet은 NSA·NIST가 정적 분석 도구 평가용으로 만든 공식 시험지다(SARD). 시험 사례 파일마다 오용 코드 `bad()`와 고친
코드 `good…()`가 짝으로 들어 있어 정답이 코드 구조 자체다. 여러 파일로 나뉜 변형(`_51a`, `_51b` …)은 `badSink`,
`goodG2BSink`처럼 메서드 이름 앞머리로 구분한다.

채점 단위는 (시험 사례, bad/good)이다. 사례의 CWE에 대응하는 우리 규칙이 bad 쪽 메서드에서 위반·경고를 내면 TP,
good 쪽 메서드에서 내면 FP다. 다른 규칙의 탐지(예: Juliet이 흔히 쓰는 `Cipher.getInstance("AES")`의 기본 ECB)는 그
사례의 정답과 무관하므로 세지 않는다.

    python tools/juliet_bench.py --root repos/juliet-java --out eval/juliet-static.json [--llm ...]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# Juliet CWE → 우리 규칙. None이면 규칙 범위 밖(참고로만 잰다)
CWE_RULES = {
    "321": {"CRYPTO-KEY-HARDCODED"},
    # Juliet CWE-327은 깨진 알고리즘(DES 등)만 본다. good 쪽도 `Cipher.getInstance("AES")`(기본 ECB)를 쓰므로
    # ECB 탐지는 이 사례의 정답과 무관하다(Apache 채점 대응과 같은 방식)
    "327": {"CRYPTO-CIPHER-OBSOLETE"},
    "328": {"CRYPTO-HASH-WEAK"},
    "329": {"CRYPTO-IV-STATIC"},
    "338": {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE"},
    # 범위 밖: 259 일반 비밀번호(PasswordAuthentication·DB 연결), 325 키 생성 초기화 누락,
    # 759 솔트 없는 해시, 760 MessageDigest에 예측 가능한 솔트(우리 솔트 규칙은 PBE만 본다)
    "259": None, "325": None, "759": None, "760": None,
}
_CASE = re.compile(r"^(CWE\d+_.+?_\d+)[a-e]?$")


def _methods(path: Path) -> list[tuple[int, int, str]]:
    """(시작 줄, 끝 줄, 메서드 이름)."""
    from tree_sitter import Language, Parser
    import tree_sitter_java
    parser = Parser(Language(tree_sitter_java.language()))
    tree = parser.parse(path.read_bytes())
    out, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("method_declaration", "constructor_declaration"):
            name = node.child_by_field_name("name")
            if name is not None:
                out.append((node.start_point[0] + 1, node.end_point[0] + 1,
                            name.text.decode("utf-8", errors="replace")))
        stack.extend(node.children)
    return out


def _side(method: str) -> str | None:
    lower = method.lower()
    if lower.startswith("bad"):
        return "bad"
    if lower.startswith("good"):
        return "good"
    return None


def score(root: Path, provider) -> dict:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable

    rows, totals = [], defaultdict(Counter)
    for cwe in sorted(CWE_RULES):
        folder = root / f"juliet-cwe{cwe}"
        if not folder.exists():
            continue
        state = pipeline.AnalysisState(target=str(folder), root=folder,
                                       rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                       thresholds=ThresholdTable.load())
        state = pipeline.judge_sites(pipeline.extract_sites(state), provider, None)
        by_file: dict[str, list] = defaultdict(list)
        for f in state.findings:
            by_file[f.site.file_path].append(f)

        cases: dict[str, dict] = defaultdict(lambda: {"bad": set(), "good": set(), "has_good": False})
        for path in sorted(folder.rglob(f"CWE{cwe}_*.java")):
            match = _CASE.match(path.stem)
            if not match:
                continue
            case = cases[match.group(1)]
            methods = _methods(path)
            if any(_side(m) == "good" for _, _, m in methods):
                case["has_good"] = True
            rel = path.relative_to(folder).as_posix()
            for finding in by_file.get(rel, []):
                side = next((_side(m) for s, e, m in methods if s <= finding.site.line <= e), None)
                if side:
                    case[side].add((finding.rule.rule_id, finding.verdict.decision.value))

        wanted = CWE_RULES[cwe]
        for name, case in sorted(cases.items()):
            def outcome(hits: set, positive: bool) -> str:
                relevant = {d for r, d in hits if wanted is None or r in wanted}
                if relevant & {"violation", "warning"}:
                    return "TP" if positive else "FP"
                if "undetermined" in relevant:
                    return "review_pos" if positive else "review_neg"
                return "FN" if positive else "TN"
            bad = outcome(case["bad"], True)
            good = outcome(case["good"], False) if case["has_good"] else None
            totals[cwe][bad] += 1
            if good:
                totals[cwe][good] += 1
            rows.append({"cwe": cwe, "case": name, "bad": bad, "good": good,
                         "bad_hits": sorted(case["bad"])[:4], "good_hits": sorted(case["good"])[:4]})
        print(f"  CWE-{cwe}: 사례 {len(cases)} {dict(totals[cwe])}", flush=True)

    def summarize(keys) -> dict:
        c = Counter()
        for k in keys:
            c.update(totals[k])
        tp, fp = c["TP"], c["FP"]
        fn = c["FN"] + c["review_pos"]
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        return {**c, "precision": p and round(p, 3), "recall": r and round(r, 3),
                "f1": round(2 * p * r / (p + r), 3) if p and r else None}

    in_scope = [k for k, v in CWE_RULES.items() if v is not None and k in totals]
    return {"in_scope": summarize(in_scope),
            "by_cwe": {k: {**summarize([k]), "in_scope": CWE_RULES[k] is not None} for k in sorted(totals)},
            "cases": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="NIST Juliet Java 채점")
    ap.add_argument("--root", type=Path, required=True, help="juliet-java-test-suite 체크아웃")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--llm-backend", choices=("local", "ollama"), default="local")
    ap.add_argument("--llm-model", default=None)
    ap.add_argument("--llm-4bit", action="store_true")
    ap.add_argument("--llm-adapter", default=None)
    args = ap.parse_args()

    from rag_app.analysis.verdict import LlmVerdict, StaticVerdict
    provider, name = StaticVerdict(), "static"
    if args.llm:
        from rag_app.config.loader import load_config
        from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
        model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
        provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend, model,
                                                 args.llm_4bit, args.llm_adapter))
        name = f"{args.llm_backend}:{model}" + (f"+{Path(args.llm_adapter).name}" if args.llm_adapter else "")
    report = {"provider": name, **score(args.root, provider)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
