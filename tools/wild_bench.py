"""
개발자가 확인한 실제 GitHub 암호 오용으로 평가한다 (본 적 없는 시험지).

출처: Xia 외, "Beyond Static Pattern Matching? Rethinking Automatic Cryptographic API Misuse Detection in the
Era of LLMs", ISSTA 2025 — 공개 자료의 report-summary.xlsx(Java 시트). GPT-4가 찾아 개발자에게 보고하고 수정·인정
여부를 받은 사례다. 소스는 들어 있지 않아 GitHub에서 보고 당시 버전(파일 마지막 수정일 기준 커밋)을 받는다.

이 도구를 개발·조정하는 데 쓰지 않은 실제 코드라 과적합 없이 잴 수 있다. 다만 GPT-4가 찾은 오용들이라
LLM에 유리한 시험지이고, 정상 정답이 없어 오탐은 잴 수 없다(추가로 잡은 위반 수만 보고).

    python tools/wild_bench.py fetch --sheet .../report-summary.xlsx --repos repos/wild-git --src repos/wild-src
    python tools/wild_bench.py score --sheet ... --src repos/wild-src [--llm ...] --out eval/wild-static.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# 보고된 유형 문구 → 우리 규칙. 범위 밖이면 None.
TYPE_RULES = [
    (r"aes/ecb|ecb", {"CRYPTO-MODE-ECB"}),
    (r"pbewithmd5anddes", {"CRYPTO-CIPHER-OBSOLETE", "CRYPTO-HASH-WEAK", "CRYPTO-KDF-WEAK"}),
    (r"\b3des\b|\bdes used\b|^des used", {"CRYPTO-CIPHER-OBSOLETE"}),
    (r"constant iv|ctr with constant iv", {"CRYPTO-IV-STATIC"}),
    (r"hardcoded key|constant key", {"CRYPTO-KEY-HARDCODED", "CRYPTO-PASSWORD-HARDCODED"}),
    (r"hardcoded credentials", {"CRYPTO-KEY-HARDCODED", "CRYPTO-PASSWORD-HARDCODED"}),
    (r"iteration", {"CRYPTO-KDF-WEAK"}),
    # SSLContext.init에 SecureRandom을 안 넘긴 것 — 기본값이 안전한 난수라 우리 규칙 범위 밖
    (r"not specifying secure randomness", set()),
    (r"hardcoded seed",{"CRYPTO-SEED-PREDICTABLE", "CRYPTO-RNG-INSECURE"}),
    (r"random", {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE"}),
    (r"sha1withrsa|rsa/sha1|sha1 used", {"CRYPTO-HASH-WEAK"}),
    (r"key size", {"CRYPTO-KEYSIZE-SHORT"}),
]
CONFIRMED = {"fixed", "accept"}


@dataclass
class Case:
    index: int
    owner: str
    repo: str
    filename: str
    date: str          # 파일 마지막 수정일 (YYYY-MM-DD)
    issue: str
    status: str        # fixed / accept / no reply / ...
    confirmed: bool
    rules: list[str]   # 비어 있으면 범위 밖


def read_cases(sheet: Path) -> list[Case]:
    import openpyxl
    rows = list(openpyxl.load_workbook(sheet, read_only=True)["Java"].iter_rows(values_only=True))[1:]
    cases, last_status, last_date = [], {}, {}
    for i, row in enumerate(rows, 1):
        if not row[2]:
            continue
        name = str(row[2]).strip()
        owner, repo, filename = name.split("__", 2)
        date = str(row[1]).strip() if row[1] and str(row[1]).strip() not in ("-", "None") else \
            last_date.get(name, "")
        status = str(row[4]).strip().lower() if row[4] and str(row[4]).strip() != "-" else \
            last_status.get((owner, repo), "")
        if row[4] and str(row[4]).strip() != "-":
            last_status[(owner, repo)] = status
        if date:
            last_date[name] = date
        vuln = str(row[3]).strip().lower()
        rules: set[str] = set()
        for pattern, mapped in TYPE_RULES:
            if re.search(pattern, vuln):
                rules = mapped
                break
        cases.append(Case(i, owner, repo, filename, date.replace(".", "-"), str(row[7] or ""),
                          status, status in CONFIRMED, sorted(rules)))
    return cases


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True).stdout.strip()


def fetch(cases: list[Case], repos: Path, src: Path) -> None:
    """저장소를 이력만 받고(treeless), 파일 수정일 끝 시점의 커밋에서 해당 파일만 꺼낸다."""
    repos.mkdir(parents=True, exist_ok=True)
    done = set()
    for case in cases:
        key = (case.owner, case.repo, case.filename)
        if key in done or not case.date:
            continue
        done.add(key)
        clone = repos / f"{case.owner}__{case.repo}"
        if not clone.exists():
            print(f"clone {case.owner}/{case.repo}", flush=True)
            _git("clone", "--quiet", "--filter=tree:0", "--no-checkout",
                 f"https://github.com/{case.owner}/{case.repo}.git", str(clone))
        y, m, d = (int(x) for x in case.date.split("-"))
        before = f"--before={y:04d}-{m:02d}-{d:02d} 23:59:59"
        # 기본 브랜치가 그 뒤에 새로 만들어진 저장소가 있다. 그때는 모든 브랜치에서 찾는다.
        commit = (_git("rev-list", "-1", before, "HEAD", cwd=clone)
                  or _git("rev-list", "-1", before, "--all", cwd=clone))
        if not commit:
            print(f"  {case.filename}: {case.date} 이전 커밋이 없다 — 건너뛴다", flush=True)
            continue
        paths = [p for p in _git("ls-tree", "-r", "--name-only", commit, cwd=clone).splitlines()
                 if p.endswith("/" + case.filename) or p == case.filename]
        for path in paths:
            out = src / f"{case.owner}__{case.repo}" / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(_git("show", f"{commit}:{path}", cwd=clone), encoding="utf-8")
        print(f"  {case.filename} @ {commit[:10]} ({case.date}): {len(paths)} 파일", flush=True)


def score(cases: list[Case], src: Path, provider) -> dict:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable

    findings = []
    for repo_dir in sorted(p for p in src.iterdir() if p.is_dir()):
        state = pipeline.AnalysisState(target=str(repo_dir), root=repo_dir,
                                       rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                       thresholds=ThresholdTable.load())
        state = pipeline.extract_sites(state)
        state = pipeline.judge_sites(state, provider, None)
        for f in state.findings:
            findings.append({"repo": repo_dir.name, "file": Path(f.site.file_path).name,
                             "line": f.site.line, "rule": f.rule.rule_id,
                             "decision": f.verdict.decision.value, "api": f.site.api[:100],
                             "reasoning": f.verdict.reasoning[:200]})
        print(f"  {repo_dir.name}: 지점 {len(state.findings)}", flush=True)
    return tally(cases, findings)


# Semgrep 커뮤니티 규칙(semgrep-rules/java) 이름 → 우리 규칙
SEMGREP_RULES = [
    (r"md5|sha1|sha224", "CRYPTO-HASH-WEAK"),
    (r"ecb|default-aes", "CRYPTO-MODE-ECB"),
    (r"desede|des-is|blowfish|rc2|rc4", "CRYPTO-CIPHER-OBSOLETE"),
    (r"static-initialization-vector", "CRYPTO-IV-STATIC"),
    (r"weak-random", "CRYPTO-RNG-INSECURE"),
    (r"weak-rsa", "CRYPTO-KEYSIZE-SHORT"),
    (r"hardcode|hard-code", "CRYPTO-KEY-HARDCODED"),
]


def semgrep_findings(raw: Path, src: Path) -> list[dict]:
    """semgrep --json 결과를 우리 findings 모양으로. 매핑 안 되는 규칙은 버린다. 모두 violation이다."""
    findings = []
    for r in json.loads(raw.read_text(encoding="utf-8"))["results"]:
        name = r["check_id"].split(".")[-1]
        rule = next((rule for pattern, rule in SEMGREP_RULES if re.search(pattern, name)), None)
        if not rule:
            continue
        path = Path(r["path"])
        rel = path.relative_to(src) if path.is_absolute() else Path(*path.parts[path.parts.index(src.name) + 1:])
        findings.append({"repo": rel.parts[0], "file": path.name, "line": r["start"]["line"], "rule": rule,
                         "decision": "violation", "api": name, "reasoning": ""})
        # 하드코딩 키 규칙은 비밀번호도 덮는다고 보고 같이 센다 (우리 쪽 매핑과 같은 관대함)
        if rule == "CRYPTO-KEY-HARDCODED":
            findings.append({**findings[-1], "rule": "CRYPTO-PASSWORD-HARDCODED"})
    return findings


def tally(cases: list[Case], findings: list[dict]) -> dict:
    rows = []
    for case in cases:
        if not case.rules:
            continue
        same = [f for f in findings if f["repo"] == f"{case.owner}__{case.repo}"
                and f["file"] == case.filename and f["rule"] in case.rules]
        decisions = {f["decision"] for f in same}
        outcome = ("TP" if "violation" in decisions else "TP_warning" if "warning" in decisions
                   else "review" if "undetermined" in decisions else "FN")
        rows.append({**asdict(case), "outcome": outcome, "hits": same[:4]})
    flagged = {(f["repo"], f["file"], f["rule"]) for f in findings
               if f["decision"] in ("violation", "warning")}
    expected = {(f"{c.owner}__{c.repo}", c.filename, r) for c in cases for r in c.rules}
    summary = {}
    for group, keep in (("all_in_scope", lambda r: True), ("confirmed", lambda r: r["confirmed"])):
        part = [r for r in rows if keep(r)]
        strict = sum(r["outcome"] == "TP" for r in part)
        tp = strict + sum(r["outcome"] == "TP_warning" for r in part)
        summary[group] = {"cases": len(part), "TP": tp, "TP_warning": tp - strict,
                          "review": sum(r["outcome"] == "review" for r in part),
                          "FN": sum(r["outcome"] == "FN" for r in part),
                          "recall": round(tp / len(part), 3) if part else None,
                          "strict_recall": round(strict / len(part), 3) if part else None}
    summary["extra_violations_not_in_list"] = len(flagged - expected)
    summary["out_of_scope_cases"] = sum(1 for c in cases if not c.rules)
    return {**summary, "cases": rows, "findings": findings}


def main() -> int:
    ap = argparse.ArgumentParser(description="개발자 확인 실제 GitHub 오용 평가")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    s = sub.add_parser("score")
    g = sub.add_parser("semgrep", help="semgrep --json 결과를 같은 기준으로 채점")
    for p in (f, s, g):
        p.add_argument("--sheet", type=Path, required=True)
        p.add_argument("--src", type=Path, required=True)
    f.add_argument("--repos", type=Path, required=True)
    g.add_argument("--raw", type=Path, required=True)
    for p in (s, g):
        p.add_argument("--out", type=Path, required=True)
    s.add_argument("--llm", action="store_true")
    s.add_argument("--llm-backend", choices=("local", "ollama"), default="local")
    s.add_argument("--llm-model", default=None)
    s.add_argument("--llm-4bit", action="store_true")
    s.add_argument("--llm-adapter", default=None)
    args = ap.parse_args()

    cases = read_cases(args.sheet)
    if args.cmd == "fetch":
        fetch(cases, args.repos, args.src)
        return 0
    if args.cmd == "semgrep":
        report = {"provider": "semgrep (semgrep-rules/java)", **tally(cases, semgrep_findings(args.raw, args.src))}
        return _write(report, args.out)

    from rag_app.analysis.verdict import LlmVerdict, StaticVerdict
    provider, name = StaticVerdict(), "static"
    if args.llm:
        from rag_app.config.loader import load_config
        from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
        model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
        provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend, model,
                                                 args.llm_4bit, args.llm_adapter))
        name = f"{args.llm_backend}:{model}" + (f"+{Path(args.llm_adapter).name}" if args.llm_adapter else "")
    return _write({"provider": name, **score(cases, args.src, provider)}, args.out)


def _write(report: dict, out: Path) -> int:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in ("cases", "findings")},
                     ensure_ascii=False, indent=1))
    for r in report["cases"]:
        print(f"  {r['outcome']:6} {'확인' if r['confirmed'] else '미확인':3} {r['repo']}/{r['filename']} "
              f"{r['rules']} | {[(h['rule'], h['decision']) for h in r['hits'][:2]]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
