"""
CamBench_Real로 채점한다 — 실제 GitHub 프로젝트의 암호 API 사용을 사람이 정답(오용/정상)으로 단 것.

정답 메타데이터(`usages/<owner_repo>/<n>.yaml`)는 API, 위치(파일·줄), `violation`을 갖고, 정답을 단 시점의 커밋은
`gh_data/<owner_repo>/github.json`의 `commits[0].sha`다. 그 커밋을 받아 검사한다.

채점 단위는 사용 지점 하나다. API에 대응하는 우리 규칙이 그 줄(±1)에서 위반·경고를 내면 탐지로 센다.

개발에 쓴 코드와 겹치는 프로젝트는 표시하고 주 숫자에서 뺀다: apache/pdfbox(개발 코퍼스), dbeaver(홀드아웃).

    python tools/cambench_real.py fetch --bench repos/CamBench/CamBench_Real --repos repos/cambench-real
    python tools/cambench_real.py score --bench ... --repos repos/cambench-real --out eval/cambench-real-static.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

API_RULES = {
    "java.security.MessageDigest": {"CRYPTO-HASH-WEAK"},
    "java.security.Signature": {"CRYPTO-HASH-WEAK"},
    "javax.crypto.Mac": {"CRYPTO-HASH-WEAK"},
    "javax.crypto.Cipher": {"CRYPTO-MODE-ECB", "CRYPTO-CIPHER-OBSOLETE"},
    "javax.crypto.KeyGenerator": {"CRYPTO-CIPHER-OBSOLETE", "CRYPTO-KEYSIZE-SHORT"},
    "java.security.KeyPairGenerator": {"CRYPTO-KEYSIZE-SHORT"},
    "javax.crypto.spec.SecretKeySpec": {"CRYPTO-KEY-HARDCODED", "CRYPTO-CIPHER-OBSOLETE"},
    "javax.crypto.spec.IvParameterSpec": {"CRYPTO-IV-STATIC"},
    "javax.crypto.spec.GCMParameterSpec": {"CRYPTO-IV-STATIC"},
    "javax.crypto.spec.PBEKeySpec": {"CRYPTO-PASSWORD-HARDCODED", "CRYPTO-SALT-STATIC", "CRYPTO-KDF-WEAK"},
    "javax.crypto.spec.PBEParameterSpec": {"CRYPTO-SALT-STATIC", "CRYPTO-KDF-WEAK"},
    "javax.crypto.SecretKeyFactory": {"CRYPTO-KDF-WEAK", "CRYPTO-HASH-WEAK"},
    "java.security.SecureRandom": {"CRYPTO-SEED-PREDICTABLE", "CRYPTO-RNG-INSECURE"},
    "java.util.Random": {"CRYPTO-RNG-INSECURE"},
    "java.security.KeyStore": {"CRYPTO-PASSWORD-HARDCODED"},
}
SEEN_IN_DEVELOPMENT = {"apache_pdfbox": "개발 코퍼스", "dbeaver_dbeaver": "실제 GitHub 홀드아웃"}


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def fetch(bench: Path, repos: Path) -> None:
    repos.mkdir(parents=True, exist_ok=True)
    for project in sorted(p.name for p in (bench / "usages").iterdir() if p.is_dir()):
        meta = json.loads((bench / "gh_data" / project / "github.json").read_text(encoding="utf-8"))
        url = meta.get("html_url") or f"https://github.com/{project.replace('_', '/', 1)}"
        sha = meta["commits"][0]["sha"]
        out = repos / project
        if (out / ".git").exists():
            continue
        out.mkdir(parents=True, exist_ok=True)
        print(f"fetch {project} @ {sha[:10]}", flush=True)
        try:
            _git("init", "-q", cwd=out)
            _git("remote", "add", "origin", url + ".git", cwd=out)
            _git("fetch", "-q", "--depth", "1", "origin", sha, cwd=out)
            _git("checkout", "-q", "FETCH_HEAD", cwd=out)
        except subprocess.CalledProcessError as error:
            print(f"  실패: {error.stderr.decode(errors='replace')[:200]}", flush=True)


def load_usages(bench: Path) -> list[dict]:
    import yaml
    out = []
    for path in sorted((bench / "usages").rglob("*.yaml")):
        meta = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        usage = meta.get("crypto-usage") or {}
        loc = usage.get("location") or {}
        if not loc.get("file") or not str(loc.get("line", "")).strip():
            continue
        out.append({"project": path.parent.name, "id": path.stem, "api": str(meta.get("api", "")).strip(),
                    "violation": bool(usage.get("violation")), "file": loc["file"],
                    "line": int(str(loc["line"]).strip())})
    return out


def score(bench: Path, repos: Path, provider) -> dict:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable

    usages = load_usages(bench)
    findings: dict[str, list] = {}
    for project in sorted({u["project"] for u in usages}):
        root = repos / project
        if not root.exists():
            continue
        state = pipeline.AnalysisState(target=str(root), root=root,
                                       rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                       thresholds=ThresholdTable.load())
        state = pipeline.judge_sites(pipeline.extract_sites(state), provider, None)
        findings[project] = state.findings
        print(f"  {project}: 지점 {len(state.findings)}", flush=True)

    rows, totals = [], defaultdict(Counter)
    for u in usages:
        wanted = API_RULES.get(u["api"], set())
        # 메타데이터 경로는 저장소 이름으로 시작하기도 한다(`struts/core/...`). 뒤쪽이 맞으면 같은 파일로 본다
        hits = [f for f in findings.get(u["project"], [])
                if f.rule.rule_id in wanted and abs(f.site.line - u["line"]) <= 1
                and (u["file"].endswith(f.site.file_path) or f.site.file_path.endswith(u["file"]))]
        decisions = {f.verdict.decision.value for f in hits}
        pos = u["violation"]
        if "violation" in decisions:
            outcome = "TP" if pos else "FP"
        elif "warning" in decisions:
            outcome = "TP_warning" if pos else "FP_warning"
        elif "undetermined" in decisions:
            outcome = "review_pos" if pos else "review_neg"
        elif u["project"] not in findings:
            outcome = "not_fetched"
        else:
            outcome = "FN" if pos else "TN"
        group = "seen" if u["project"] in SEEN_IN_DEVELOPMENT else "unseen"
        totals[group][outcome] += 1
        rows.append({**u, "group": group, "outcome": outcome,
                     "hits": [(f.rule.rule_id, f.verdict.decision.value) for f in hits][:3]})

    def metrics(c: Counter) -> dict:
        tp, fp = c["TP"] + c["TP_warning"], c["FP"] + c["FP_warning"]
        fn = c["FN"] + c["review_pos"]
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        return {**c, "precision": p and round(p, 3), "recall": r and round(r, 3)}

    return {"unseen": metrics(totals["unseen"]), "seen_in_development": metrics(totals["seen"]),
            "cases": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="CamBench_Real 채점")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    s = sub.add_parser("score")
    for p in (f, s):
        p.add_argument("--bench", type=Path, required=True)
        p.add_argument("--repos", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--llm", action="store_true")
    s.add_argument("--llm-backend", choices=("local", "ollama"), default="local")
    s.add_argument("--llm-model", default=None)
    s.add_argument("--llm-4bit", action="store_true")
    s.add_argument("--llm-adapter", default=None)
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch(args.bench, args.repos)
        return 0

    from rag_app.analysis.verdict import LlmVerdict, StaticVerdict
    provider, name = StaticVerdict(), "static"
    if args.llm:
        from rag_app.config.loader import load_config
        from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
        model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
        provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend, model,
                                                 args.llm_4bit, args.llm_adapter))
        name = f"{args.llm_backend}:{model}" + (f"+{Path(args.llm_adapter).name}" if args.llm_adapter else "")
    report = {"provider": name, **score(args.bench, args.repos, provider)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}, ensure_ascii=False, indent=1))
    for r in report["cases"]:
        print(f"  {r['outcome']:11} {r['group']:6} {'오용' if r['violation'] else '정상'} {r['project']}/{r['id']} "
              f"{r['api'].split('.')[-1]} | {r['hits'][:2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
