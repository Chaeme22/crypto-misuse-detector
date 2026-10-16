"""
국산 암호 실제 코드 시험(시험용 분할, `tools/kr_corpus.py`).

정답이 없는 코드라 사람이 정답을 단다. 순서는 셋이다.

1. `sheet` — 시험용 저장소에서 국산 암호를 부르는 줄을 정규식으로 모아 정답 시트(CSV)를 만든다. 시트에는 코드와 앞뒤
   문맥만 넣고 **우리 도구의 판정은 넣지 않는다.** 판정을 보고 정답을 달면 정답이 도구 쪽으로 기운다.
2. 사람이 `misuses` 칸에 그 줄의 오용을 적는다. 쓸 값: ECB, KEY(하드코딩 키), IV(고정 IV·카운터), HASH(취약 해시),
   CIPHER(표에 없는·폐기 알고리즘), NONE(오용 없음), ?(판단 불가 — 채점에서 뺀다). 여러 개면 `;`로 잇는다.
3. `score` — 정답 시트와 우리 판정(정적·LLM)을 줄·규칙 단위로 맞춰 본다.

    python tools/kr_bench.py sheet --repos repos/kr-test --out eval/kr-test-sheet.csv
    python tools/kr_bench.py predict --repos repos/kr-test --out eval/kr-test-static.json [--llm ...]
    python tools/kr_bench.py score --sheet eval/kr-test-sheet.csv --pred eval/kr-test-static.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

KR_LINE = re.compile(
    r"getInstance\s*\(\s*\"(SEED|ARIA|LEA|HIGHT|HAS-?160|LSH|KCDSA|EC-?KCDSA)[^\"]*\""
    r"|\bKISA_SEED_(ECB|CBC|CTR)\s*\.\s*SEED_\w+_(Encrypt|Decrypt|init)\s*\("
    r"|\bnew\s+ARIAEngine\s*\(\s*\w+\s*,"
    r"|\bnew\s+LEA\b|\bLEA\.(ECB|CBC|CTR|GCM|CCM)\b", re.IGNORECASE)
LABELS = {"ECB": {"CRYPTO-MODE-ECB"}, "KEY": {"CRYPTO-KEY-HARDCODED", "CRYPTO-PASSWORD-HARDCODED"},
          "IV": {"CRYPTO-IV-STATIC"}, "HASH": {"CRYPTO-HASH-WEAK"},
          "CIPHER": {"CRYPTO-CIPHER-OBSOLETE"}}
MAX_FILES = 5000
CONTEXT = 6


def _excluded(name: str) -> bool:
    """
    개발에 쓴 코드와 겹치거나 응용 코드가 아닌 저장소.

    일반 개발 코퍼스(`dev_corpus.REPOS`)와 저장소 이름이 같으면 사본까지 뺀다(`apache/santuario-xml-security-java`와
    그 사본 `signerry/santuario-xml-security-java`). BouncyCastle 계열(spongycastle 등)은 암호 라이브러리 구현과
    시험 벡터라 응용 코드의 오용이 아니다.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    from dev_corpus import REPOS
    repo_name = name.split("__", 1)[-1].lower()
    if repo_name in {r.split("/")[1].lower() for r in REPOS}:
        return True
    return any(k in repo_name for k in ("bouncycastle", "spongycastle"))


def _repos(root: Path):
    for repo in sorted(p for p in root.iterdir() if p.is_dir()):
        if _excluded(repo.name) or sum(1 for _ in repo.rglob("*.java")) > MAX_FILES:
            continue
        yield repo


def sheet(root: Path, out: Path) -> int:
    from rag_app.analysis.extract import SKIP_DIRS, is_test_path
    rows = []
    for repo in _repos(root):
        for path in sorted(repo.rglob("*.java")):
            relative = path.relative_to(repo).as_posix()
            if any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
                continue
            # KISA 참조 구현 파일 자체, 저장소에 복사해 둔 BouncyCastle 계열(spongycastle 등)은 사용 코드가 아니다
            if re.search(r"/KISA_SEED_(ECB|CBC|CTR)\.java$|/ARIAEngine\.java$|spongycastle|bouncycastle",
                         "/" + relative, re.IGNORECASE):
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("//", "*", "/*")) or not KR_LINE.search(line):
                    continue
                start, end = max(0, number - 1 - CONTEXT), min(len(lines), number + CONTEXT)
                context = "\n".join(f"{n + 1:>5}{'>' if n + 1 == number else ' '} {lines[n]}"
                                    for n in range(start, end))
                rows.append({"id": f"{repo.name}:{relative}:{number}", "repo": repo.name,
                             "file": relative, "line": number, "is_test": is_test_path(relative),
                             "code": stripped[:200], "context": context,
                             "misuses": "", "note": ""})
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)}줄, 저장소 {len({r['repo'] for r in rows})}개 → {out}")
    return 0


def predict(root: Path, out: Path, provider, name: str,
            only: dict[str, set[str]] | None = None) -> int:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable
    findings = []
    for repo in _repos(root):
        if only is not None and repo.name not in only:
            continue   # 정답 시트에 줄이 없는 저장소는 채점에 쓰이지 않는다. LLM 경로는 느리므로 건너뛴다
        state = pipeline.AnalysisState(target=str(repo), root=repo,
                                       rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                       thresholds=ThresholdTable.load())
        state = pipeline.extract_sites(state)
        if only is not None:
            # 추출·값 추적은 저장소 전체로 하고, 판정은 정답 시트에 있는 파일만 한다. 벤치마크 사본을 통째로 담은
            # 저장소(SURF 등)는 지점이 수천 개라 LLM 판정이 몇 시간 걸린다
            state.sites = [(s, r) for s, r in state.sites if s.file_path in only[repo.name]]
        state = pipeline.judge_sites(state, provider, None)
        for f in state.findings:
            findings.append({"repo": repo.name, "file": f.site.file_path, "line": f.site.line,
                             "rule": f.rule.rule_id, "decision": f.verdict.decision.value,
                             "api": f.site.api[:120], "reasoning": f.verdict.reasoning[:200]})
        print(f"  {repo.name}: {len(state.findings)}", flush=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"provider": name, "findings": findings}, ensure_ascii=False, indent=1)
                   + "\n", encoding="utf-8")
    return 0


def from_semgrep(raw: Path, root: Path, out: Path) -> int:
    """`semgrep --json` 결과를 채점용 예측 모양으로. 규칙 이름 대응은 wild_bench와 같다."""
    sys.path.insert(0, str(ROOT / "tools"))
    from wild_bench import SEMGREP_RULES
    findings = []
    for r in json.loads(raw.read_text(encoding="utf-8"))["results"]:
        name = r["check_id"].split(".")[-1]
        rule = next((rule for pattern, rule in SEMGREP_RULES if re.search(pattern, name)), None)
        if not rule:
            continue
        rel = Path(r["path"]).resolve().relative_to(root.resolve())
        findings.append({"repo": rel.parts[0], "file": Path(*rel.parts[1:]).as_posix(),
                         "line": r["start"]["line"], "rule": rule, "decision": "violation",
                         "api": name, "reasoning": ""})
    out.write_text(json.dumps({"provider": "semgrep (semgrep-rules/java)", "findings": findings},
                              ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(findings)}건 → {out}")
    return 0


LABEL_COLUMNS = ("ECB", "KEY", "IV", "HASH", "CIPHER")


def _read_annotator(path: Path) -> dict[int, dict]:
    """평가자 정답지 한 장 → 번호별 {라벨: bool, 'none': bool, 'unsure': bool}."""
    with path.open(encoding="utf-8-sig") as f:
        out = {}
        for r in csv.DictReader(f):
            mark = {k: bool(r.get(k, "").strip()) for k in LABEL_COLUMNS}
            mark["none"] = bool(r.get("오용없음", "").strip())
            mark["unsure"] = bool(r.get("판단불가", "").strip())
            out[int(r["번호"])] = mark
    return out


def _fleiss(ratings: list[list[bool]]) -> float | None:
    """이진 판정의 Fleiss 카파. ratings[행] = 평가자들의 True/False."""
    n = len(ratings[0]) if ratings else 0
    if n < 2 or not ratings:
        return None
    p_yes = sum(sum(r) for r in ratings) / (len(ratings) * n)
    p_e = p_yes ** 2 + (1 - p_yes) ** 2
    p_i = [(sum(r) * (sum(r) - 1) + (n - sum(r)) * (n - sum(r) - 1)) / (n * (n - 1)) for r in ratings]
    p_bar = sum(p_i) / len(p_i)
    return round((p_bar - p_e) / (1 - p_e), 3) if p_e < 1 else 1.0


def agree(sheets: list[Path], base: Path, out: Path) -> dict:
    """
    여러 평가자의 정답지를 합친다. 라벨마다 Fleiss 카파를 내고, 과반수가 표시한 라벨을 최종 정답으로 한다.

    판단불가를 준 평가자는 그 행에서 빠진다. 남은 평가자가 둘 미만이거나 어느 라벨이든 정확히 반반이면
    합의가 필요한 행으로 표시한다(최종 정답 `?` — 채점에서 빠진다).
    """
    names = [p.stem.removeprefix("정답지_") for p in sheets]
    marks = [_read_annotator(p) for p in sheets]
    with base.open(encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    disputes, kappa_input = [], {k: [] for k in LABEL_COLUMNS}
    for i, row in enumerate(rows, 1):
        votes = [m[i] for m in marks if i in m and not m[i]["unsure"]
                 and (m[i]["none"] or any(m[i][k] for k in LABEL_COLUMNS))]
        if len(votes) == len(marks):
            for k in LABEL_COLUMNS:
                kappa_input[k].append([v[k] for v in votes])
        final, tie = [], len(votes) < 2
        for k in LABEL_COLUMNS:
            yes = sum(v[k] for v in votes)
            if votes and yes * 2 == len(votes):
                tie = True
            if votes and yes * 2 > len(votes):
                final.append(k)
        row["misuses"] = "?" if tie else (";".join(final) or "NONE")
        row["note"] = f"[평가자 {len(votes)}/{len(marks)}명 합의]"
        if tie:
            disputes.append({"번호": i, "repo": row["repo"], "file": row["file"], "line": row["line"],
                             "votes": {names[j]: [k for k in LABEL_COLUMNS if m[i][k]] or
                                       (["판단불가"] if m[i]["unsure"] else ["없음"])
                                       for j, m in enumerate(marks) if i in m}})
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    report = {"annotators": names, "rows": len(rows),
              "kappa": {k: _fleiss(v) for k, v in kappa_input.items() if any(any(r) for r in v)},
              "disputes": disputes}
    print(json.dumps(report, ensure_ascii=False, indent=1))
    return report


def score(sheet_path: Path, pred_path: Path, tests: bool = False) -> dict:
    """
    줄·라벨 단위 채점. 기본은 운영 코드만 본다. 도구는 빌드 규약상 테스트 소스를 보고하지 않으므로
    테스트 줄을 넣으면 의도된 동작이 놓침으로 잡힌다. `tests=True`면 테스트 줄만 따로 본다.
    """
    with sheet_path.open(encoding="utf-8-sig") as f:
        rows = [r for r in csv.DictReader(f) if r["misuses"].strip() and r["misuses"].strip() != "?"
                and (r["is_test"] == "True") == tests]
    pred = json.loads(pred_path.read_text(encoding="utf-8"))
    flagged: dict[tuple[str, str, int], set[str]] = {}
    for f in pred["findings"]:
        if f["decision"] in ("violation", "warning"):
            flagged.setdefault((f["repo"], f["file"], f["line"]), set()).add(f["rule"])
    per = {label: Counter() for label in LABELS}
    for row in rows:
        truth = {t.strip().upper() for t in row["misuses"].split(";") if t.strip()} - {"NONE"}
        got = flagged.get((row["repo"], row["file"], int(row["line"])), set())
        for label, rule_ids in LABELS.items():
            hit = bool(got & rule_ids)
            key = ("TP" if hit else "FN") if label in truth else ("FP" if hit else "TN")
            per[label][key] += 1
    report = {"provider": pred["provider"], "scope": "test sources" if tests else "production",
              "lines": len(rows), "by_label": {}}
    total = Counter()
    for label, c in per.items():
        total.update(c)
        p = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else None
        r = c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else None
        report["by_label"][label] = {**c, "precision": p and round(p, 3), "recall": r and round(r, 3)}
    p = total["TP"] / (total["TP"] + total["FP"]) if total["TP"] + total["FP"] else 0
    r = total["TP"] / (total["TP"] + total["FN"]) if total["TP"] + total["FN"] else 0
    report["total"] = {**total, "precision": round(p, 3), "recall": round(r, 3),
                       "f1": round(2 * p * r / (p + r), 3) if p + r else 0}
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="국산 암호 실제 코드 시험")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sheet")
    s.add_argument("--repos", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("predict")
    p.add_argument("--repos", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--llm", action="store_true")
    p.add_argument("--llm-backend", choices=("local", "ollama"), default="local")
    p.add_argument("--llm-model", default=None)
    p.add_argument("--llm-4bit", action="store_true")
    p.add_argument("--llm-adapter", default=None)
    p.add_argument("--sheet", type=Path, default=None, help="이 정답 시트에 있는 저장소만 검사한다")
    g = sub.add_parser("semgrep", help="semgrep --json 결과를 채점용 예측으로 바꾼다")
    g.add_argument("--raw", type=Path, required=True)
    g.add_argument("--repos", type=Path, required=True)
    g.add_argument("--out", type=Path, required=True)
    a = sub.add_parser("agree", help="평가자 정답지들을 합치고 일치도(Fleiss 카파)를 낸다")
    a.add_argument("--sheets", type=Path, nargs="+", required=True)
    a.add_argument("--base", type=Path, required=True, help="sheet로 만든 원본 시트(행 순서 기준)")
    a.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("score")
    c.add_argument("--sheet", type=Path, required=True)
    c.add_argument("--pred", type=Path, nargs="+", required=True)
    args = ap.parse_args()

    if args.cmd == "sheet":
        return sheet(args.repos, args.out)
    if args.cmd == "semgrep":
        return from_semgrep(args.raw, args.repos, args.out)
    if args.cmd == "agree":
        agree(args.sheets, args.base, args.out)
        return 0
    if args.cmd == "predict":
        from rag_app.analysis.verdict import LlmVerdict, StaticVerdict
        provider, name = StaticVerdict(), "static"
        if args.llm:
            from rag_app.config.loader import load_config
            from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
            model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
            provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend, model,
                                                     args.llm_4bit, args.llm_adapter))
            name = f"{args.llm_backend}:{model}" + (f"+{Path(args.llm_adapter).name}"
                                                     if args.llm_adapter else "")
        only = None
        if args.sheet is not None:
            only = {}
            with args.sheet.open(encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    only.setdefault(r["repo"], set()).add(r["file"])
        return predict(args.repos, args.out, provider, name, only)
    for pred in args.pred:
        print(json.dumps(score(args.sheet, pred), ensure_ascii=False, indent=1))
        print(json.dumps(score(args.sheet, pred, tests=True)["total"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
