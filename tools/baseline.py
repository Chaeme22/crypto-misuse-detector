"""
파인튜닝 전 기준선을 파일로 고정한다.

학습한 모델이 나아졌는지는 학습 전 숫자가 남아 있어야 말할 수 있다. 화면에 찍고 지나간
숫자는 다시 재면 코드가 바뀌어 있어 같은 조건이 아니다. 그래서 무엇으로 쟀는지(코드 커밋,
규칙표·기준표 해시, 벤치마크 커밋)를 숫자와 함께 묶어 둔다.

만드는 파일:
  rule_engine.json      LLM 없이 규칙·표만으로 낸 지점별 판정
  cryptoapi_bench.json  같은 실행의 벤치마크 채점과 오탐·미탐 사례
  coverage.json         언어·규칙별로 지금 무엇을 잡을 수 있는지
  prompt_only.json      `--llm`일 때만. 파인튜닝 전 모델의 지점별 판정과 채점

시각은 넣지 않는다. 같은 코드·같은 입력이면 같은 파일이 나와야 diff로 비교할 수 있다.

사용법:
    python tools/baseline.py /tmp/CryptoAPI-Bench --out baseline
    python tools/baseline.py /tmp/CryptoAPI-Bench --out baseline --llm \\
        --llm-backend ollama --llm-model qwen2.5-coder:7b   # GPU 없는 PC
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark  # noqa: E402
from rag_app.analysis import extract, rules as tier1  # noqa: E402
from rag_app.analysis.verdict import StaticVerdict  # noqa: E402

RULES_PATH = ROOT / "config" / "tier1_rules.json"
THRESHOLDS_PATH = ROOT / "config" / "tier1_thresholds.json"

# 언어별 추출 능력. 코드에서 읽은 사실이다. 추출기를 고치면 여기도 고친다.
#   java   extract_java.py — 문법 분해, 지역 변수·필드·파일 간 호출자까지 값 추적,
#          알고리즘 이름·키 길이를 기준표와 비교
#   python extract.py collect_file — 호출 이름과 문자열 리터럴만 본다. 값 추적이 없고
#          call·algorithm_spec을 채우지 않아 표 대조가 일어나지 않는다
LANGUAGES = {
    "java": {"extensions": [".java"], "value_tracing": True, "cross_file_tracing": True,
             "table_comparison": True},
    "python": {"extensions": [".py"], "value_tracing": False, "cross_file_tracing": False,
               "table_comparison": False},
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: Path, *args: str) -> str:
    try:
        # 한글 경로가 섞이면 Windows 기본 코덱(cp949)이 출력을 못 읽는다.
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace").stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def meta(bench_root: Path, provider: str, model: str | None) -> dict:
    """이 숫자를 무엇으로 쟀는지. 커밋하지 않은 변경이 있으면 dirty로 남긴다."""
    return {
        "detector_commit": _git(ROOT, "rev-parse", "HEAD"),
        "detector_dirty": bool(_git(ROOT, "status", "--porcelain")),
        "rules_sha256": _sha256(RULES_PATH),
        "thresholds_sha256": _sha256(THRESHOLDS_PATH),
        "benchmark": "CryptoAPI-Bench",
        "benchmark_commit": _git(bench_root, "rev-parse", "HEAD"),
        "provider": provider,
        "model": model,
    }


def site_records(state) -> list[dict]:
    """지점마다 무엇을 찾았고 어떻게 판정했는지. 정렬해 순서를 고정한다."""
    out = []
    for finding in state.findings:
        site, rule, verdict = finding.site, finding.rule, finding.verdict
        measurement = finding.measurement
        out.append({
            "file": site.file_path.replace("\\", "/"),
            "line": site.line,
            "language": site.language,
            "rule_id": rule.rule_id,
            "cwe": rule.cwe,
            "api": site.api,
            "call": site.call,
            "algorithm_spec": site.algorithm_spec,
            "key_bits": site.key_bits,
            "traced_values": list(site.traced_values),
            "unresolved_args": list(site.unresolved_args),
            "is_test": site.is_test,
            "decision": verdict.decision.value,
            "role": verdict.role,
            "reasoning": verdict.reasoning,
            "measurement": None if measurement is None else measurement.outcome.value,
        })
    return sorted(out, key=lambda r: (r["file"], r["line"], r["rule_id"]))


def decision_counts(records: list[dict]) -> dict:
    by_rule: dict[str, Counter] = {}
    for record in records:
        by_rule.setdefault(record["rule_id"], Counter())[record["decision"]] += 1
    return {rule: dict(sorted(counts.items())) for rule, counts in sorted(by_rule.items())}


def cases(truth: dict, document: dict) -> dict:
    """
    오탐·미탐 사례를 파일 단위로 남긴다. 숫자만 남기면 학습 후에 무엇이 고쳐졌고 무엇이
    새로 틀렸는지 비교할 수 없다.
    """
    fail: dict[str, set[str]] = {}
    review: dict[str, set[str]] = {}
    for result in document["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        bucket = review if result.get("kind") == "review" else fail
        bucket.setdefault(uri, set()).add(result["ruleId"])

    missed, reviewed, wrong_rule, false_positive = [], [], [], []
    for relative, want in sorted(truth.items()):
        key = relative.replace("\\", "/")
        hits = sorted(fail.get(relative, set()))
        asked = sorted(review.get(relative, set()))
        row = {"file": key, "category": want["category"],
               "expected_rule": want.get("rule"), "reported": hits, "review": asked}
        if want["expect"] == "violation" and want["rule"] not in hits:
            if asked:
                reviewed.append(row)
            elif hits:
                wrong_rule.append(row)
            else:
                missed.append(row)
        elif want["expect"] == "clean" and hits:
            false_positive.append(row)
    return {"missed": missed, "review_only": reviewed, "wrong_rule": wrong_rule,
            "false_positive": false_positive}


def coverage(rule_list) -> dict:
    """
    규칙마다 어느 언어에서 잡을 수 있는지. 트리거 이름으로 언어를 가른다.

    지원하지 않는 확장자의 트리거(예: Node.js `crypto.createHash`)는 규칙표에 있어도
    실제로는 걸리지 않는다. 그런 트리거를 따로 드러낸다.
    """
    python_prefixes = ("hashlib.", "random.", "Crypto.", "secrets.", "os.")
    javascript = ("crypto.",)
    supported = {ext for lang in LANGUAGES.values() for ext in lang["extensions"]}
    assert supported == set(extract.SUFFIXES), "LANGUAGES와 extract.SUFFIXES가 어긋났다"

    per_rule = {}
    for rule in rule_list:
        triggers: dict[str, list[str]] = {"java": [], "python": [], "unsupported": []}
        for trigger in rule.api_triggers:
            if trigger.startswith(python_prefixes):
                triggers["python"].append(trigger)
            elif trigger.startswith(javascript):
                triggers["unsupported"].append(trigger)
            else:
                triggers["java"].append(trigger)
        per_rule[rule.rule_id] = {
            "cwe": rule.cwe,
            "level": rule.level.value,
            "table_decides": rule.table_decides,
            "table_measures": rule.table_measures,
            "api_triggers": triggers,
            "literal_triggers": list(rule.literal_triggers),
            "languages": sorted(lang for lang in ("java", "python")
                                if triggers[lang] or rule.literal_triggers),
        }
    return {"languages": LANGUAGES, "rules": per_rule,
            "not_supported": ["c", "cpp", "javascript"]}


def snapshot(bench_root: Path, provider, model: str | None) -> dict:
    truth = benchmark.ground_truth(bench_root)
    document, state = benchmark.analyze(bench_root, provider, with_clauses=False)
    result = benchmark.score(truth, document)
    records = site_records(state)
    return {
        "meta": meta(bench_root, provider.name, model),
        "sites_total": len(state.sites),
        "closed_by_table": state.closed_by_table,
        "decisions_by_rule": decision_counts(records),
        "score": benchmark.summarize(result),
        "per_category": {k: v for k, v in sorted(result["per_category"].items())},
        "cases": cases(truth, document),
        "sites": records,
    }


def write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
                    encoding="utf-8")
    print(f"저장: {path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="파인튜닝 전 기준선을 파일로 고정한다")
    ap.add_argument("bench_root", type=Path, help="CryptoAPI-Bench 경로")
    ap.add_argument("--out", type=Path, default=ROOT / "baseline")
    ap.add_argument("--llm", action="store_true", help="prompt_only.json만 만든다 (GPU)")
    ap.add_argument("--llm-backend", choices=("local", "ollama"), default="local")
    ap.add_argument("--llm-adapter", default=None, help="local 백엔드에 얹을 LoRA 어댑터 폴더")
    ap.add_argument("--llm-model", default=None,
                    help="local은 HF 이름, ollama는 태그. 생략하면 백엔드별 기본값")
    ap.add_argument("--llm-4bit", action="store_true", default=True)
    args = ap.parse_args()

    bench_root = args.bench_root.resolve()
    args.out.mkdir(parents=True, exist_ok=True)

    if args.llm:
        from rag_app.analysis.verdict import LlmVerdict
        from rag_app.config.loader import load_config
        from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
        model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
        provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend, model,
                                                 args.llm_4bit, args.llm_adapter))
        write(args.out / "prompt_only.json",
              snapshot(bench_root, provider, f"{args.llm_backend}:{model}"
                       + (f"+adapter:{Path(args.llm_adapter).name}" if args.llm_adapter else "")))
        return 0

    data = snapshot(bench_root, StaticVerdict(), None)
    write(args.out / "rule_engine.json", {
        "meta": data["meta"],
        "sites_total": data["sites_total"],
        "closed_by_table": data["closed_by_table"],
        "decisions_by_rule": data["decisions_by_rule"],
        "sites": data["sites"],
    })
    write(args.out / "cryptoapi_bench.json", {
        "meta": data["meta"],
        "score": data["score"],
        "per_category": data["per_category"],
        "cases": data["cases"],
    })
    write(args.out / "coverage.json", {
        "meta": {k: data["meta"][k] for k in ("detector_commit", "detector_dirty",
                                               "rules_sha256")},
        **coverage(tier1.load(RULES_PATH)),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
