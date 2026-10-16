"""
CamBench_Cap으로 채점한다 (Schlichtig 외, MSR 2022 registered report).

CamBench_Cap은 분석 능력(문맥·필드·흐름·경로·객체 민감도, 메서드 간 추적)을 시험하는 합성 사례다. 사례마다 YAML
메타데이터에 정답(`violation: true/false`)과 위치(파일·줄)가 있다. 그 정답을 그대로 쓴다.

채점 단위는 메타데이터의 사용 지점 하나다. 사례 범주(폴더 이름)에 대응하는 우리 규칙이 그 줄(±1)에서 위반·경고를
내면 탐지로 센다. 정답이 오용이면 TP, 정상이면 FP다.

기준 차이(채점에 그대로 반영되므로 해석할 때 본다):
- PBE 반복 횟수: CamBench는 최소 10,000,000회, 우리는 NIST SP 800-132의 1,000회
- RSA 키 길이: CamBench는 2048비트를 안전으로 본다(우리는 2048을 "경고"로 낸다 — 탐지로 세면 FP)

    python tools/cambench.py --root repos/CamBench/CamBench_Cap --out eval/cambench-cap-static.json [--llm ...]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

CATEGORY_RULES = {
    "brokencrypto": {"CRYPTO-CIPHER-OBSOLETE"},
    "brokenhash": {"CRYPTO-HASH-WEAK"},
    "ecbmode": {"CRYPTO-MODE-ECB"},
    # CamBench는 약한 난수의 오용 위치를 그 난수가 쓰이는 줄(`new IvParameterSpec(ivBytes)`)에 둔다. 우리 도구는 그
    # 줄에서 재료 규칙(IV·키·솔트)으로, 출처를 "약한 난수"로 보고한다. 같은 결함을 쓰는 쪽 규칙으로 낸 것이다
    "insecurerandom": {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE", "CRYPTO-IV-STATIC",
                       "CRYPTO-KEY-HARDCODED", "CRYPTO-SALT-STATIC"},
    "pbeparameters": {"CRYPTO-SALT-STATIC", "CRYPTO-KDF-WEAK", "CRYPTO-PASSWORD-HARDCODED"},
    "smallkeysize": {"CRYPTO-KEYSIZE-SHORT"},
    "staticiv": {"CRYPTO-IV-STATIC"},
}


def _usages(meta: dict) -> list[dict]:
    usage = meta.get("crypto-usage")
    return usage if isinstance(usage, list) else [usage] if usage else []


def load_cases(root: Path) -> list[dict]:
    import yaml
    cases = []
    for path in sorted(root.rglob("*.yaml")):
        if path.name == "metadata.yaml":
            continue   # 스키마 예시
        meta = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        parts = path.relative_to(root).parts
        category = next((p for p in parts if p in CATEGORY_RULES), None)
        capability = next((p for p in parts if p in ("basic", "patterns", "interprocedural2",
                                                       "interprocedural3", "contextsensitivity",
                                                       "mixedsensitivities", "fieldsensitivity",
                                                       "flowsensitivity", "pathsensitivity",
                                                       "objectsensitivity")), parts[6] if len(parts) > 6 else "")
        for usage in _usages(meta):
            loc = (usage or {}).get("location") or {}
            if "file" not in loc or "line" not in loc:
                continue
            cases.append({"meta": path.relative_to(root).as_posix(), "category": category,
                          "capability": capability, "api": str(meta.get("api", "")).strip(),
                          "violation": bool(usage.get("violation")),
                          "file": loc["file"], "line": int(loc["line"])})
    return cases


def score(root: Path, provider) -> dict:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable

    src = root / "src"
    state = pipeline.AnalysisState(target=str(src), root=src,
                                   rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), provider, None)
    by_file: dict[str, list] = defaultdict(list)
    for f in state.findings:
        by_file[f.site.file_path].append(f)

    rows, totals, by_cat, by_cap = [], Counter(), defaultdict(Counter), defaultdict(Counter)
    for case in load_cases(root):
        wanted = CATEGORY_RULES.get(case["category"] or "", set())
        hits = [f for f in by_file.get(case["file"], [])
                if abs(f.site.line - case["line"]) <= 1 and f.rule.rule_id in wanted]
        decisions = {f.verdict.decision.value for f in hits}
        pos = case["violation"]
        if "violation" in decisions:
            outcome = "TP" if pos else "FP"
        elif "warning" in decisions:
            # 112비트(2030년 만료) 경고. CamBench는 RSA 2048을 안전으로 보므로 엄격 숫자에서는 탐지로 세지 않는다
            outcome = "TP_warning" if pos else "FP_warning"
        elif "undetermined" in decisions:
            outcome = "review_pos" if pos else "review_neg"
        else:
            outcome = "FN" if pos else "TN"
        totals[outcome] += 1
        by_cat[case["category"]][outcome] += 1
        by_cap[case["capability"]][outcome] += 1
        rows.append({**case, "outcome": outcome,
                     "hits": [(f.rule.rule_id, f.verdict.decision.value) for f in hits][:3]})

    def metrics(c: Counter) -> dict:
        def prf(tp, fp, fn):
            p = tp / (tp + fp) if tp + fp else None
            r = tp / (tp + fn) if tp + fn else None
            return p and round(p, 3), r and round(r, 3), round(2 * p * r / (p + r), 3) if p and r else None
        miss = c["FN"] + c["review_pos"]
        p, r, f = prf(c["TP"] + c["TP_warning"], c["FP"] + c["FP_warning"], miss)
        sp, sr, sf = prf(c["TP"], c["FP"], miss + c["TP_warning"])
        return {**c, "precision": p, "recall": r, "f1": f,
                "strict_precision": sp, "strict_recall": sr, "strict_f1": sf}

    return {"total": metrics(totals), "by_category": {k: metrics(v) for k, v in sorted(by_cat.items(), key=str)},
            "by_capability": {k: metrics(v) for k, v in sorted(by_cap.items(), key=str)}, "cases": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="CamBench_Cap 채점")
    ap.add_argument("--root", type=Path, required=True, help="CamBench/CamBench_Cap")
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
