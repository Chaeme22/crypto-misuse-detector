"""
OWASP Benchmark (Java, v1.2)의 암호 관련 사례로 채점한다.

`expectedresults-1.2.csv`의 정답(사례 이름·범주·실제 취약 여부·CWE)을 그대로 쓴다. 암호 관련 범주만 본다:
crypto(CWE-327, 깨진 암호) 246, hash(CWE-328, 약한 해시) 236, weakrand(CWE-330, 약한 난수) 493 — 합 975건.
Masood·Vargas Martin(SECRYPT 2025)이 같은 975건을 썼다(CryptoGuard F 92.9, GPT-4o-mini F 65.7).

채점 단위는 사례 파일 하나(`BenchmarkTest#####.java`)다. 범주에 대응하는 우리 규칙이 그 파일에서 위반·경고를 내면 탐지다.

    python tools/owasp_bench.py --root repos/BenchmarkJava --out eval/owasp-static.json [--llm ...]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

CATEGORY_RULES = {
    "crypto": {"CRYPTO-CIPHER-OBSOLETE", "CRYPTO-MODE-ECB"},
    "hash": {"CRYPTO-HASH-WEAK"},
    "weakrand": {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE"},
}


def read_truth(root: Path) -> dict[str, dict]:
    truth = {}
    with (root / "expectedresults-1.2.csv").open(encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#") or row[1] not in CATEGORY_RULES:
                continue
            truth[row[0]] = {"category": row[1], "vulnerable": row[2].strip() == "true", "cwe": row[3]}
    return truth


def score(root: Path, provider) -> dict:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable

    truth = read_truth(root)
    # resources(설정 파일 benchmark.properties)까지 함께 본다. 알고리즘 이름 일부가 거기 있다
    src = root / "src" / "main"
    state = pipeline.AnalysisState(target=str(src), root=src,
                                   rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), provider, None)
    by_case: dict[str, list] = defaultdict(list)
    for f in state.findings:
        by_case[Path(f.site.file_path).stem].append(f)

    rows, totals = [], defaultdict(Counter)
    for name, t in sorted(truth.items()):
        wanted = CATEGORY_RULES[t["category"]]
        decisions = {f.verdict.decision.value for f in by_case.get(name, []) if f.rule.rule_id in wanted}
        pos = t["vulnerable"]
        if decisions & {"violation", "warning"}:
            outcome = "TP" if pos else "FP"
        elif "undetermined" in decisions:
            outcome = "review_pos" if pos else "review_neg"
        else:
            outcome = "FN" if pos else "TN"
        totals[t["category"]][outcome] += 1
        totals["all"][outcome] += 1
        rows.append({"case": name, **t, "outcome": outcome, "decisions": sorted(decisions)})

    def metrics(c: Counter) -> dict:
        tp, fp, fn = c["TP"], c["FP"], c["FN"] + c["review_pos"]
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        return {**c, "precision": p and round(p, 3), "recall": r and round(r, 3),
                "f1": round(2 * p * r / (p + r), 3) if p and r else None}

    return {"by_category": {k: metrics(v) for k, v in sorted(totals.items())}, "cases": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="OWASP Benchmark 암호 범주 채점")
    ap.add_argument("--root", type=Path, required=True)
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
    print(json.dumps(report["by_category"], ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
