"""
최종 확인용 측정. 기준은 `training/eval/final/*`에 측정 전에 확정했다. 결과를 보고 도구를 고치지 않는다.

세트
- masc_minimal: MASC 최소 예제(정답 `masc_minimal_labels.json`)
- masc_mutants: MASC exhaustive 변형 앱(정답 서버 `~/final/masc_mutants_truth.json`, 기준 `masc_mutants_spec.md`)
- ghsa: GitHub 보안 권고 수정 커밋(목록 `~/final/ghsa_manifest.json`, 기준 `ghsa_spec.md`)

    python tools/final_bench.py --set all --out eval/final/static.json
    python tools/final_bench.py --set all --out eval/final/v2.json --llm --llm-backend local \
        --llm-model Qwen/Qwen2.5-Coder-7B-Instruct --llm-4bit --llm-adapter <v2 어댑터>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# 측정 자료 위치. 환경 변수로 바꿀 수 있다.
MASC = Path(os.environ.get("MASC_ROOT", Path.home() / "repos/MASC-orig"))
FINAL = Path(os.environ.get("FINAL_DATA", Path.home() / "final"))
HIT = {"violation", "warning"}
SETS = {"cipher": {"CRYPTO-CIPHER-OBSOLETE", "CRYPTO-MODE-ECB"}, "iv": {"CRYPTO-IV-STATIC"},
        "digest": {"CRYPTO-HASH-WEAK"}, "seed": {"CRYPTO-SEED-PREDICTABLE", "CRYPTO-RNG-INSECURE"}}
ALL_RULES = {"CRYPTO-HASH-WEAK", "CRYPTO-MODE-ECB", "CRYPTO-CIPHER-OBSOLETE", "CRYPTO-KEYSIZE-SHORT",
             "CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE", "CRYPTO-KEY-HARDCODED", "CRYPTO-IV-STATIC",
             "CRYPTO-PASSWORD-HARDCODED", "CRYPTO-SALT-STATIC", "CRYPTO-KDF-WEAK"}
CWE_RULES = {
    "CWE-327": {"CRYPTO-CIPHER-OBSOLETE", "CRYPTO-MODE-ECB", "CRYPTO-HASH-WEAK", "CRYPTO-KEYSIZE-SHORT", "CRYPTO-IV-STATIC"},
    "CWE-328": {"CRYPTO-HASH-WEAK"}, "CWE-326": {"CRYPTO-KEYSIZE-SHORT", "CRYPTO-KDF-WEAK"},
    "CWE-321": {"CRYPTO-KEY-HARDCODED", "CRYPTO-PASSWORD-HARDCODED"},
    "CWE-798": {"CRYPTO-KEY-HARDCODED", "CRYPTO-PASSWORD-HARDCODED"},
    "CWE-329": {"CRYPTO-IV-STATIC"}, "CWE-323": {"CRYPTO-IV-STATIC"},
    "CWE-330": {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE"}, "CWE-338": {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE"},
    "CWE-337": {"CRYPTO-SEED-PREDICTABLE"}, "CWE-759": {"CRYPTO-SALT-STATIC"}, "CWE-760": {"CRYPTO-SALT-STATIC"},
    "CWE-916": {"CRYPTO-KDF-WEAK", "CRYPTO-HASH-WEAK", "CRYPTO-SALT-STATIC"},
    "CWE-325": ALL_RULES, "CWE-1240": ALL_RULES,
}


def analyze(root: Path, provider) -> list:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable
    state = pipeline.AnalysisState(target=str(root), root=root,
                                   rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), provider, None)
    return [(Path(f.site.file_path).as_posix(), f.site.line, f.rule.rule_id, f.verdict.decision.value)
            for f in state.findings]


def masc_minimal(provider) -> dict:
    labels = json.loads((ROOT / "training/eval/final/masc_minimal_labels.json").read_text(encoding="utf-8"))
    root = MASC / "minimal_flaws/src/main/java/com/minimals"
    by_dir = defaultdict(list)
    for path, line, rule, decision in analyze(root, provider):
        by_dir[str(Path(path).parent.as_posix())].append((rule, decision))
    counts, rows = Counter(), []
    for case in labels["cases"]:
        wanted = SETS[case["set"]]
        decisions = {d for r, d in by_dir.get(case["dir"], []) if r in wanted}
        hit = bool(decisions & HIT)
        if case["label"] == "positive":
            outcome = "TP" if hit else ("review" if "undetermined" in decisions else "FN")
        elif case["label"] == "negative":
            outcome = "FP" if hit else "TN"
        else:
            outcome = "excluded:" + ("flagged" if hit else "clean")
        counts[outcome] += 1
        rows.append({**case, "outcome": outcome, "decisions": sorted(decisions)})
    pos = counts["TP"] + counts["FN"] + counts["review"]
    return {"counts": dict(counts), "recall": round(counts["TP"] / pos, 3) if pos else None, "cases": rows}


def masc_mutants(provider) -> dict:
    from rag_app.analysis.extract import is_test_path
    truth = json.loads((FINAL / "masc_mutants_truth.json").read_text(encoding="utf-8"))
    base = MASC / "mutated_apps"
    out = {}
    for name, root in (("exhaustive_android", base / "exhaustive/android_apps"),
                       ("exhaustive_qpid", base / "exhaustive/qpid")):
        prefix = root.relative_to(base).as_posix() + "/"
        flagged = defaultdict(list)
        for path, line, rule, decision in analyze(root, provider):
            flagged[prefix + path].append((line, rule, decision))
        counts = Counter()
        for case in truth[name]["cases"]:
            inner = case["file"][len(prefix):]
            if is_test_path(inner.split("/", 1)[1] if name == "exhaustive_android" and "/" in inner else inner):
                counts["test_path"] += 1
                continue
            decisions = {d for line, r, d in flagged.get(case["file"], [])
                         if r in SETS["cipher"] and case["start"] <= line <= case["end"]}
            counts["TP" if decisions & HIT else ("review" if "undetermined" in decisions else "FN")] += 1
        scored = counts["TP"] + counts["FN"] + counts["review"]
        out[name] = {"counts": dict(counts), "recall": round(counts["TP"] / scored, 3) if scored else None}
    # 참고: 변형 전 원본에서 나온 낡은 암호·ECB 위반 수
    for name, root in (("original_android", base / "exhaustive/original_android_apps"),
                       ("original_qpid", base / "exhaustive/original_qpid")):
        out[name + "_violations"] = sum(1 for _, _, r, d in analyze(root, provider) if r in SETS["cipher"] and d in HIT)
    return out


def ghsa(provider) -> dict:
    items = json.loads((FINAL / "ghsa_manifest.json").read_text(encoding="utf-8"))
    by_id = defaultdict(list)
    for it in items:
        by_id[it["id"]].append(it)
    rows, counts = [], Counter()
    for gid, files in sorted(by_id.items()):
        cwes = files[0]["cwes"]
        strict_rules = set().union(*(CWE_RULES.get(c, set()) for c in cwes)) or ALL_RULES
        res = {}
        for side in ("before", "after"):
            root = FINAL / "ghsa_src" / gid / side
            res[side] = analyze(root, provider) if root.exists() else []
        broad = strict = review = after_flag = False
        for it in files:
            if it["api_lines"] == 0:
                continue
            old = set(it["old_lines"]); new = set(it["new_lines"])
            near_old = {l + d for l in old for d in range(-2, 3)}
            near_new = {l + d for l in new for d in range(-2, 3)}
            for path, line, rule, decision in res["before"]:
                if path != it["file"] or line not in near_old or rule not in ALL_RULES:
                    continue
                if decision in HIT:
                    broad = True
                    strict = strict or rule in strict_rules
                elif decision == "undetermined":
                    review = True
            for path, line, rule, decision in res["after"]:
                if path == it["file"] and line in near_new and rule in strict_rules and decision in HIT:
                    after_flag = True
        outcome = "TP" if broad else ("review" if review else "FN")
        counts[outcome] += 1
        counts["strict_TP"] += strict
        counts["after_fix_flag"] += after_flag
        rows.append({"id": gid, "cwes": cwes, "outcome": outcome, "strict": strict, "after_fix_flag": after_flag})
    n = len(rows)
    return {"advisories": n, "counts": dict(counts), "recall_broad": round(counts["TP"] / n, 3) if n else None,
            "recall_strict": round(counts["strict_TP"] / n, 3) if n else None, "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="최종 확인용 측정")
    ap.add_argument("--set", choices=("all", "masc_minimal", "masc_mutants", "ghsa"), default="all")
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
    report = {"provider": name}
    for key, fn in (("masc_minimal", masc_minimal), ("masc_mutants", masc_mutants), ("ghsa", ghsa)):
        if args.set in ("all", key):
            report[key] = fn(provider)
            print(key, json.dumps({k: v for k, v in report[key].items() if k not in ("cases", "rows")},
                                  ensure_ascii=False), flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
