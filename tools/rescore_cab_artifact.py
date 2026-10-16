"""
Xia 외(ISSTA 2025) 공개 자료의 CryptoAPI-Bench 실행 결과를 우리 정답으로 다시 채점한다 — 같은 조건 비교.

공개 자료에는 LLM 5종(GPT-4, GPT-3.5, Gemini-Pro, CodeLlama-34B, DeepSeek-Coder-33B)을 같은 프롬프트로 돌린 결과와
GPT-4 검증 단계(`refine.json`) 결과가 사례(=CryptoAPI-Bench 파일)마다 들어 있다. 우리 정답(`tools/benchmark.py`)과
사례 이름으로 맞춰 파일 단위로 채점한다.

- 관대: 그 파일에 오용을 하나라도 보고하면 탐지
- 유형 일치: 보고한 오용 유형이 정답 범주와 맞을 때만 탐지(`compare_tools.gpt_types`와 같은 키워드 대응)
우리 도구도 같은 파일 단위로 센다(그 파일에 위반·경고가 있으면 탐지 / 정답 범주 규칙의 위반·경고면 유형 일치).

    python tools/rescore_cab_artifact.py --artifact repos/CryptoGPT-online.github.io/cryptogpt-artifact/cryptoapi-bench-master \
        --out eval/compare-cab-artifact.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

# CryptoAPI-Bench 범주(폴더) → compare_tools.gpt_types가 내는 유형 이름
CATEGORY_TYPES = {
    "brokencrypto": {"CipherAlgo"}, "ecbcrypto": {"ModeofOperation"}, "brokenhash": {"MessageDigest"},
    "staticinitializationvector": {"static IV"}, "predictablekeyseeds": {"Constantkey", "Random"},
    "predictablecryptographickey": {"Constantkey"}, "predictablepbepassword": {"Constantkey"},
    "staticsalts": {"PBESalt"}, "pbeiteration": {"PBEIteration"}, "impropersslsocketfactory": set(),
    "predictableseeds": {"Random"}, "insecureasymmetriccrypto": {"CipherAlgo"},
    "predictablekeystorepassword": {"Constantkey"}, "credentialinstring": {"Constantkey"},
    "brokenmac": {"Mac", "MessageDigest"}, "untrustedprng": {"Random"},
}


def _model_hits(folder: Path, refined: bool) -> dict[str, tuple[bool, set[str]]]:
    """사례 이름 → (오용을 하나라도 보고했나, 보고한 유형들)."""
    from compare_tools import gpt_types
    out = {}
    for case in folder.glob("**/*"):
        if not case.is_dir():
            continue
        path = case / ("refine.json" if refined else "0.json")
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if refined and "### Optimized Misuse JSON ###" in text:
            text = text.split("### Optimized Misuse JSON ###", 1)[1]
        match = re.search(r"\[.*\]", text, re.S)
        items = []
        if match:
            try:
                items = json.loads(match.group(0))
            except json.JSONDecodeError:
                items = [{"misuse": text}]   # JSON이 깨졌어도 내용이 있으면 보고한 것으로 본다
        items = [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []
        types = set()
        for item in items:
            types |= gpt_types(str(item.get("misuse", "")),
                               f"{item.get('vulnerable_code', '')} {item.get('description', '')}")
        out[case.name] = (bool(items), types)
    return out


def _metrics(rows):
    tp = sum(t and p for t, p in rows); fp = sum((not t) and p for t, p in rows)
    fn = sum(t and not p for t, p in rows); tn = sum((not t) and not p for t, p in rows)
    prec = tp / (tp + fp) if tp + fp else None; rec = tp / (tp + fn) if tp + fn else None
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": prec and round(prec, 3),
            "recall": rec and round(rec, 3),
            "f1": round(2 * prec * rec / (prec + rec), 3) if prec and rec else None}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    from benchmark import ground_truth
    from compare_tools import OUR_TYPES
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable
    from rag_app.analysis.verdict import StaticVerdict

    cab = ROOT / "repos" / "CryptoAPI-Bench"
    truth = {Path(k).stem: v for k, v in ground_truth(cab).items() if v["expect"] in ("violation", "clean")}
    state = pipeline.AnalysisState(target=str(cab), root=cab,
                                   rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    ours: dict[str, tuple[bool, set[str]]] = {}
    for f in state.findings:
        if f.verdict.decision.value in ("violation", "warning"):
            any_, types = ours.get(Path(f.site.file_path).stem, (False, set()))
            ours[Path(f.site.file_path).stem] = (True, types | OUR_TYPES.get(f.rule.rule_id, set()))

    tools = {"ours (static)": ours}
    for folder in sorted((args.artifact / "llm-result").iterdir()):
        if folder.is_dir():
            tools[folder.name] = _model_hits(folder, refined=False)
            if (next(folder.glob("**/refine.json"), None)) is not None:
                tools[folder.name + " +refine"] = _model_hits(folder, refined=True)

    report = {"cases_in_truth": len(truth), "tools": {}}
    for name, hits in tools.items():
        common = [c for c in truth if c in hits] if name != "ours (static)" else list(truth)
        lenient = [(truth[c]["expect"] == "violation", hits.get(c, (False, set()))[0]) for c in common]
        typed = [(truth[c]["expect"] == "violation",
                  bool(hits.get(c, (False, set()))[1] & CATEGORY_TYPES.get(truth[c]["category"], set())))
                 for c in common]
        report["tools"][name] = {"cases": len(common), "lenient": _metrics(lenient), "type_match": _metrics(typed)}
    # 모든 도구가 함께 가진 사례만으로 한 번 더 (공정 비교)
    # 공개 결과가 대부분 사례에 있는 도구만 공통 사례 계산에 넣는다(2건뿐인 검증 결과 폴더 등은 뺀다)
    full = {n: h for n, h in tools.items() if n != "ours (static)" and len(h) >= 100}
    shared = [c for c in truth if all(c in h for h in full.values())]
    report["shared_cases"] = len(shared)
    report["shared"] = {}
    for name, hits in [("ours (static)", ours), *full.items()]:
        get = lambda c: hits.get(c, (False, set()))  # noqa: E731
        report["shared"][name] = {
            "lenient": _metrics([(truth[c]["expect"] == "violation", get(c)[0]) for c in shared]),
            "type_match": _metrics([(truth[c]["expect"] == "violation",
                                     bool(get(c)[1] & CATEGORY_TYPES.get(truth[c]["category"], set())))
                                    for c in shared])}
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"정답 사례 {len(truth)}, 공개 결과 공통 {len(shared)} — 공통 사례 기준")
    for name, r in report["shared"].items():
        print(f"  {name:62} 관대 F1 {r['lenient']['f1']} (P {r['lenient']['precision']} R "
              f"{r['lenient']['recall']}) | 유형일치 F1 {r['type_match']['f1']} "
              f"(P {r['type_match']['precision']} R {r['type_match']['recall']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
