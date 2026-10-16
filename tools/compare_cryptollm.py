"""
CryptoLLM(Baek·Lee·Kim, ESORICS 2024)과 같은 기준으로 비교한다.

CryptoLLM은 파일마다 오용(m)/정상(b)만 낸다. 그래서 우리 도구의 판정도 **파일 단위**로 모은다(그 파일에서 위반·경고가
하나라도 나오면 오용). CryptoLLM이 분석하지 못한 파일(X)과 암호 줄을 찾지 못한 파일은 "탐지 안 함"으로 센다 — 원본
도구가 사용자에게 보여 주는 결과와 같다.

정답(파일 단위)
- CryptoAPI-Bench: `*Corrected*` 파일이 정상, 나머지 범위 안 파일이 오용(`tools/benchmark.py`의 정답과 같음)
- CamBench_Cap: 메타데이터의 사용 지점 중 하나라도 오용이면 그 파일은 오용, 모두 정상이면 정상
- 실제 GitHub 홀드아웃: 개발자 확인 오용 파일(범위 안) — 오용만 있어 재현율만 잰다
- ApacheCryptoAPI-Bench: 클래스 단위(그 클래스에 보안 용도 정답이 하나라도 있으면 오용)

Juliet은 한 파일에 오용(bad)과 수정(good)이 함께 있어 파일 단위 비교가 무의미하므로 넣지 않는다.

    python tools/compare_cryptollm.py --eval eval --out eval/compare-cryptollm.json [--llm ...]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
REPOS = ROOT / "repos"
FLAGGED = ("violation", "warning")


def _ours(root: Path, provider) -> dict[str, set[str]]:
    """파일(root 기준 상대 경로) → 그 파일에서 나온 판정들."""
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable
    state = pipeline.AnalysisState(target=str(root), root=root,
                                   rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), provider, None)
    out: dict[str, set[str]] = {}
    for f in state.findings:
        out.setdefault(f.site.file_path, set()).add(f.verdict.decision.value)
    return out


def _metrics(rows: list[tuple[bool, bool]]) -> dict:
    tp = sum(t and p for t, p in rows)
    fp = sum((not t) and p for t, p in rows)
    fn = sum(t and not p for t, p in rows)
    tn = sum((not t) and not p for t, p in rows)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": prec and round(prec, 3),
            "recall": rec and round(rec, 3), "f1": f1 and round(f1, 3)}


def _cryptollm(path: Path) -> dict[str, str]:
    return json.loads(path.read_text(encoding="utf-8"))["files"] if path.exists() else {}


def cab(evaldir: Path, provider) -> dict:
    from benchmark import ground_truth
    root = REPOS / "CryptoAPI-Bench"
    truth = {k: v["expect"] == "violation" for k, v in ground_truth(root).items()
             if v["expect"] in ("violation", "clean")}
    ours = _ours(root, provider)
    theirs = _cryptollm(evaldir / "cryptollm-cab.json")
    return {"unit": "file", "files": len(truth), "positive": sum(truth.values()),
            "ours": _metrics([(t, bool(ours.get(f, set()) & set(FLAGGED))) for f, t in truth.items()]),
            "cryptollm": _metrics([(t, theirs.get(f) == "m") for f, t in truth.items()])}


def cambench(evaldir: Path, provider) -> dict:
    from cambench import load_cases
    cap = REPOS / "CamBench" / "CamBench_Cap"
    truth: dict[str, bool] = {}
    for c in load_cases(cap):
        truth[c["file"]] = truth.get(c["file"], False) or c["violation"]
    ours = _ours(cap / "src", provider)
    theirs = _cryptollm(evaldir / "cryptollm-cambench.json")
    return {"unit": "file", "files": len(truth), "positive": sum(truth.values()),
            "ours": _metrics([(t, bool(ours.get(f, set()) & set(FLAGGED))) for f, t in truth.items()]),
            "cryptollm": _metrics([(t, theirs.get(f) == "m") for f, t in truth.items()])}


def wild(evaldir: Path, provider) -> dict:
    from wild_bench import read_cases
    sheet = REPOS / "CryptoGPT-online.github.io" / "cryptogpt-artifact" / "report-summary.xlsx"
    src = REPOS / "wild-src"
    files = {(f"{c.owner}__{c.repo}", c.filename) for c in read_cases(sheet) if c.rules}
    theirs = _cryptollm(evaldir / "cryptollm-wild.json")
    rows_ours, rows_theirs = [], []
    for repo, name in sorted(files):
        ours = _ours(src / repo, provider) if (src / repo).exists() else {}
        hit_ours = any(Path(p).name == name and (d & set(FLAGGED)) for p, d in ours.items())
        hit_theirs = any(Path(p).name == name and p.startswith(repo + "/") and v == "m"
                         for p, v in theirs.items())
        rows_ours.append((True, hit_ours))
        rows_theirs.append((True, hit_theirs))
    return {"unit": "file (misuse only — recall)", "files": len(files),
            "ours": _metrics(rows_ours), "cryptollm": _metrics(rows_theirs)}


def apache(evaldir: Path, our_report: Path) -> dict:
    import apache_bench as ab
    from compare_tools import units
    truth_units = units(ab.read_labels(REPOS / "ApacheCryptoAPI-Bench"))
    truth: dict[str, bool] = {}
    for (cls, _), positive in truth_units.items():
        truth[cls] = truth.get(cls, False) or positive
    ours_flagged = {f["class"] for f in json.loads(our_report.read_text(encoding="utf-8"))["findings"]
                    if f["decision"] in FLAGGED}
    theirs = _cryptollm(evaldir / "cryptollm-apache.json")
    theirs_flagged = set()
    for path, v in theirs.items():
        if v == "m":
            dotted = path.removesuffix(".java").replace("/", ".")
            theirs_flagged.add(dotted)

    def hit(cls: str, flagged: set[str]) -> bool:
        key = cls.lstrip(".")
        return any(f == cls or f.endswith("." + key) or f.endswith(key) for f in flagged)

    return {"unit": "class", "classes": len(truth), "positive": sum(truth.values()),
            "ours": _metrics([(t, hit(c, ours_flagged)) for c, t in truth.items()]),
            "cryptollm": _metrics([(t, hit(c, theirs_flagged)) for c, t in truth.items()]),
            "ours_report": our_report.name}


def main() -> int:
    ap = argparse.ArgumentParser(description="CryptoLLM과 파일 단위 비교")
    ap.add_argument("--eval", type=Path, required=True, help="cryptollm-*.json이 있는 폴더")
    ap.add_argument("--apache-report", type=Path, required=True, help="우리 apache_bench 결과 json")
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
    report = {"ours_provider": name, "cryptollm": "CryptoLLM-codet5 (공개 가중치, ESORICS 2024)",
              "CryptoAPI-Bench": cab(args.eval, provider),
              "CamBench_Cap": cambench(args.eval, provider),
              "wild_holdout": wild(args.eval, provider),
              "ApacheCryptoAPI-Bench": apache(args.eval, args.apache_report)}
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for bench in ("CryptoAPI-Bench", "CamBench_Cap", "wild_holdout", "ApacheCryptoAPI-Bench"):
        r = report[bench]
        print(f"{bench:24} ours {r['ours']}\n{'':24} CryptoLLM {r['cryptollm']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
