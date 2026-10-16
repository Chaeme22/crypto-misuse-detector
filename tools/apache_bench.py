"""
ApacheCryptoAPI-Bench로 탐지 정확도를 잰다 (실제 Apache 프로젝트 10개, 줄 단위 정답).

논문: Afrose 외, "Evaluation of Static Vulnerability Detection Tools with Java Cryptographic
API Benchmarks", IEEE TSE 2023. 저장소: github.com/CryptoAPI-Bench/ApacheCryptoAPI-Bench

저장소에는 JAR와 정답 엑셀(ApacheCryptoAPI-Bench_detail_list.xlsx)만 있고 소스가 없다. 우리 도구는
소스를 읽으므로 같은 버전의 소스를 Maven Central의 -sources.jar로 받는다. 벤치마크 JAR는 출시
직전 SNAPSHOT이라 줄 번호가 조금 어긋날 수 있어, 클래스·메서드로 맞추고 메서드가 없는 정답만
줄 범위로 맞춘다. 소스 jar가 없는 프로젝트(ManifoldCF, Taverna)는 제공 JAR를 디컴파일한다.

    python tools/apache_bench.py fetch  --bench repos/ApacheCryptoAPI-Bench --src repos/apache-src
    python tools/apache_bench.py score  --bench repos/ApacheCryptoAPI-Bench --src repos/apache-src \
        [--llm --llm-backend local --llm-4bit --llm-adapter runs/...] --out eval/apache-static.json

채점은 논문과 같은 틀이다. 보안 용도(TP) 정답에 경보가 나면 찾음, 아니면 놓침. 무관(TN) 정답에
경보가 나면 오탐. 판정 보류(확인 요청)는 따로 센다. SSL/TLS 유형(TrustManager, HostnameVerifier,
http)은 이 도구의 규칙 밖이라 뺀다.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

MAVEN = "https://repo1.maven.org/maven2"
# 프로젝트 → 소스 jar 좌표. 벤치마크 JAR 버전과 같은 출시본(없으면 가장 가까운 것).
SOURCES = {
    "tika": ["org/apache/tika/tika-core/1.17"],
    "wicket": ["org/apache/wicket/wicket-util/8.0.0"],
    "deltaspike": ["org/apache/deltaspike/core/deltaspike-core-impl/1.8.1"],
    "directoryserver": ["org/apache/directory/server/apacheds-kerberos-codec/2.0.0.AM25"],
    "tomee": ["org/apache/tomee/openejb-core/7.0.5"],
    "meecrowave": ["org/apache/meecrowave/meecrowave-core/1.2.0"],
    "activemq": ["org/apache/activemq/artemis-commons/2.5.0"],
    # Spark는 Jetty를 org.spark_project.jetty로 이름만 바꿔 넣었다. Spark 2.4.0이 쓰는 Jetty 원본을 받는다.
    "spark": ["org/apache/spark/spark-core_2.11/2.4.0",
              "org/eclipse/jetty/jetty-util/9.3.24.v20180605",
              "org/eclipse/jetty/jetty-client/9.3.24.v20180605",
              "org/eclipse/jetty/jetty-security/9.3.24.v20180605",
              "org/eclipse/jetty/jetty-server/9.3.24.v20180605"],
}
# Maven에 소스가 없어 제공 JAR를 디컴파일하는 프로젝트 (apache_codes 아래 경로 조각).
DECOMPILE = {"manifold": "manifoldcf", "traverna": "incubator-taverna-workbench"}
ALIASES = {"artimis": "activemq", "manifoldcf": "manifold", "directoryserver": "directoryserver"}

# 벤치마크 유형 → 우리 규칙. 이 밖의 유형은 SSL/TLS라 범위 밖.
RULES = {
    # ECB는 엑셀이 같은 줄을 ModeofOperation으로 따로 단다. 알고리즘 유형에 넣으면 이중으로 센다.
    "CipherAlgo": {"CRYPTO-CIPHER-OBSOLETE"},
    "Constantkey": {"CRYPTO-KEY-HARDCODED", "CRYPTO-PASSWORD-HARDCODED"},
    "MessageDigest": {"CRYPTO-HASH-WEAK"},
    "Mac": {"CRYPTO-HASH-WEAK"},
    "ModeofOperation": {"CRYPTO-MODE-ECB"},
    "Random": {"CRYPTO-RNG-INSECURE", "CRYPTO-SEED-PREDICTABLE"},
    "static IV": {"CRYPTO-IV-STATIC"},
    "PBESalt": {"CRYPTO-SALT-STATIC"},
    "PBEIteration": {"CRYPTO-KDF-WEAK"},
}
OUT_OF_SCOPE = {"TrustManager", "HostnameVerifier", "http"}
LINE_WINDOW = 15


@dataclass
class Label:
    index: int
    project: str
    type: str
    positive: bool       # 보안 용도(TP) 정답인지
    cls: str             # 바깥 클래스 FQN
    method: str | None
    line: int | None
    snippet: str
    explanation: str


def _project(name: str) -> str:
    key = name.strip().lower()
    return ALIASES.get(key, key)


def _outer(cls: str) -> str:
    cls = cls.split(":")[0].strip().split("$")[0]
    # 정답 엑셀에 경로 조각이 섞인 이름이 있다(`utils/DefaultSensitiveStringCodec`).
    cls = cls.replace("/", ".")
    if cls and not cls.startswith(("org.", "com.", "net.", "java.", "javax.")):
        cls = "." + cls   # 패키지가 빠진 이름. 뒷부분 일치로 맞춘다
    return cls.replace("org.spark_project.jetty", "org.eclipse.jetty")


def read_labels(bench: Path) -> list[Label]:
    import openpyxl
    sheet = openpyxl.load_workbook(bench / "ApacheCryptoAPI-Bench_detail_list.xlsx",
                                   read_only=True)["all cases"]
    labels = []
    for i, row in enumerate(list(sheet.iter_rows(values_only=True))[1:], 1):
        if not row[0]:
            continue
        line = None
        if row[8] is not None:
            match = re.match(r"\d+", str(row[8]))
            line = int(match.group(0)) if match else None
        method = str(row[7]).strip() if row[7] else None
        if method:
            method = method.split("(")[0].strip() or None
        labels.append(Label(i, _project(str(row[0])), str(row[1]).strip(),
                            bool(row[3]) and str(row[3]).lower().startswith("crypto"),
                            _outer(str(row[6] or "")), method, line,
                            str(row[2] or ""), str(row[4] or "")))
    return labels


# --- 소스 준비 -------------------------------------------------------------------

def fetch(bench: Path, src: Path) -> None:
    for project, coords in SOURCES.items():
        target = src / project
        if target.exists() and any(target.rglob("*.java")):
            print(f"{project}: 이미 있음")
            continue
        target.mkdir(parents=True, exist_ok=True)
        for coord in coords:
            artifact, version = coord.split("/")[-2], coord.split("/")[-1]
            url = f"{MAVEN}/{coord}/{artifact}-{version}-sources.jar"
            data = urllib.request.urlopen(url, timeout=300).read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    if name.endswith(".java"):
                        out = target / name
                        out.parent.mkdir(parents=True, exist_ok=True)
                        out.write_bytes(z.read(name))
            print(f"{project}: {artifact}-{version}-sources.jar")
    for project, folder in DECOMPILE.items():
        target = src / project
        if target.exists() and any(target.rglob("*.java")):
            print(f"{project}: 이미 있음")
            continue
        jars = list((bench / "apache_codes" / folder).rglob("*.jar"))
        decompile(jars, target)
        print(f"{project}: 디컴파일 {len(jars)}개 JAR")


def decompile(jars: list[Path], target: Path) -> None:
    """Vineflower로 디컴파일한다. 원래 줄 번호를 맞추려고 줄 맞춤 옵션을 켠다."""
    tool = Path.home() / ".cache" / "crypto-misuse" / "vineflower.jar"
    if not tool.exists():
        tool.parent.mkdir(parents=True, exist_ok=True)
        url = f"{MAVEN}/org/vineflower/vineflower/1.10.1/vineflower-1.10.1.jar"
        tool.write_bytes(urllib.request.urlopen(url, timeout=300).read())
    target.mkdir(parents=True, exist_ok=True)
    for jar in jars:
        out = target / jar.stem
        out.mkdir(parents=True, exist_ok=True)
        subprocess.run(["java", "-jar", str(tool), "--bytecode-source-mapping=1",
                        "--dump-code-lines=1", str(jar), str(out)], check=True,
                       stdout=subprocess.DEVNULL)
        for archive in out.glob("*.jar"):
            with zipfile.ZipFile(archive) as z:
                z.extractall(out)
            archive.unlink()


# --- 위치 → 클래스·메서드 ---------------------------------------------------------

def _parser():
    from tree_sitter import Language, Parser
    import tree_sitter_java
    return Parser(Language(tree_sitter_java.language()))


def locate(path: Path) -> tuple[str, list[tuple[int, int, str]]]:
    """(바깥 클래스 FQN, [(시작 줄, 끝 줄, 메서드 이름)])."""
    code = path.read_bytes()
    tree = _parser().parse(code)
    package, top, methods = "", "", []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "package_declaration":
            package = code[node.start_byte:node.end_byte].decode(errors="replace")
            package = package.replace("package", "").replace(";", "").strip()
        elif node.type in ("class_declaration", "interface_declaration", "enum_declaration") \
                and not top:
            name = node.child_by_field_name("name")
            top = code[name.start_byte:name.end_byte].decode() if name else ""
        elif node.type in ("method_declaration", "constructor_declaration"):
            name = node.child_by_field_name("name")
            label = code[name.start_byte:name.end_byte].decode() if name else ""
            if node.type == "constructor_declaration":
                label = "<init>"
            methods.append((node.start_point[0] + 1, node.end_point[0] + 1, label))
        stack.extend(node.children)
    cls = f"{package}.{path.stem}" if package else path.stem
    return cls, methods


def method_at(methods, line: int) -> str | None:
    inside = [m for m in methods if m[0] <= line <= m[1]]
    return min(inside, key=lambda m: m[1] - m[0])[2] if inside else None


# --- 채점 -------------------------------------------------------------------------

def run_detector(src: Path, provider) -> list[dict]:
    from rag_app.analysis import pipeline, rules as tier1
    from rag_app.analysis.thresholds import ThresholdTable

    findings = []
    for project_dir in sorted(p for p in src.iterdir() if p.is_dir()):
        state = pipeline.AnalysisState(target=str(project_dir), root=project_dir,
                                       rules=tier1.load(ROOT / "config" / "tier1_rules.json"),
                                       thresholds=ThresholdTable.load())
        state = pipeline.extract_sites(state)
        state = pipeline.judge_sites(state, provider, None)
        cache: dict[str, tuple] = {}
        for f in state.findings:
            rel = f.site.file_path
            if rel not in cache:
                cache[rel] = locate(project_dir / rel)
            cls, methods = cache[rel]
            findings.append({"project": project_dir.name, "file": rel, "line": f.site.line,
                             "class": cls, "method": method_at(methods, f.site.line),
                             "rule": f.rule.rule_id, "decision": f.verdict.decision.value,
                             "role": f.verdict.role, "api": f.site.api[:120]})
        print(f"  {project_dir.name}: 지점 {len(state.findings)}건", flush=True)
    return findings


def _same_class(f: dict, label: Label) -> bool:
    return f["class"] == label.cls or (label.cls.startswith(".")
                                       and f["class"].endswith(label.cls))


def match(label: Label, findings: list[dict], labels: list[Label] | None = None) -> list[dict]:
    """
    정답 하나에 걸리는 탐지 결과.

    정답 엑셀의 줄 번호는 소스와 일정하게 어긋나지 않는다(디컴파일 화면 기준으로 보이며, 프로젝트에
    따라 -700 ~ +140줄). 그래서 줄의 절대값으로 맞추지 않고 클래스·메서드·규칙으로 맞춘다. 한 메서드에
    같은 유형의 정답이 여러 개고 탐지 지점도 같은 수면 줄 순서(순위)로 짝짓는다. 줄 값은 틀려도
    순서는 보존된다.
    """
    rules = RULES[label.type]
    pool = [f for f in findings if _same_class(f, label) and f["rule"] in rules]
    if label.method == "<clinit>":
        return [f for f in pool if f["method"] is None]
    if not label.method:
        if label.line is None:
            return pool
        return [f for f in pool if abs(f["line"] - label.line) <= LINE_WINDOW]

    candidates = [f for f in pool if f["method"] == label.method]
    if label.line is None or labels is None:
        return candidates
    siblings = sorted({l.line for l in labels if l.cls == label.cls and l.method == label.method
                       and l.type == label.type and l.line is not None})
    lines = sorted({f["line"] for f in candidates})
    if len(siblings) > 1 and len(lines) == len(siblings):
        target = lines[siblings.index(label.line)]
        return [f for f in candidates if f["line"] == target]
    return candidates


def score(labels: list[Label], findings: list[dict]) -> dict:
    rows, totals = [], Counter()
    by_type: dict[str, Counter] = defaultdict(Counter)
    for label in labels:
        if label.type in OUT_OF_SCOPE:
            continue
        hits = match(label, findings, labels)
        decisions = {h["decision"] for h in hits}
        if "violation" in decisions:
            outcome = "TP" if label.positive else "FP"
        elif "warning" in decisions:
            # 112비트(2030년 만료) 경고. 보고서에는 나오므로 탐지로 세되, 엄격 기준 숫자도 따로 낸다.
            outcome = "TP_warning" if label.positive else "FP_warning"
        elif "undetermined" in decisions:
            outcome = "review_pos" if label.positive else "review_neg"
        else:
            outcome = "FN" if label.positive else "TN"
        totals[outcome] += 1
        by_type[label.type][outcome] += 1
        rows.append({"index": label.index, "project": label.project, "type": label.type,
                     "positive": label.positive, "class": label.cls, "method": label.method,
                     "line": label.line, "snippet": label.snippet, "explanation": label.explanation,
                     "outcome": outcome, "hits": hits[:3]})
    tp = totals["TP"] + totals["TP_warning"]
    fp = totals["FP"] + totals["FP_warning"]
    fn = totals["FN"] + totals["review_pos"]
    s_tp, s_fp, s_fn = totals["TP"], totals["FP"], fn + totals["TP_warning"]
    return {"in_scope_positive": sum(1 for r in rows if r["positive"]),
            "in_scope_negative": sum(1 for r in rows if not r["positive"]),
            "totals": dict(totals),
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            # 경고를 빼고 위반만 센 숫자
            "strict_precision": round(s_tp / (s_tp + s_fp), 3) if s_tp + s_fp else None,
            "strict_recall": round(s_tp / (s_tp + s_fn), 3) if s_tp + s_fn else None,
            "by_type": {k: dict(v) for k, v in sorted(by_type.items())},
            "cases": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="ApacheCryptoAPI-Bench 채점")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    s = sub.add_parser("score")
    r = sub.add_parser("rescore", help="저장된 결과의 탐지 지점으로 채점만 다시 한다 (모델을 다시 돌리지 않음)")
    r.add_argument("--bench", type=Path, required=True)
    r.add_argument("reports", type=Path, nargs="+")
    for p in (f, s):
        p.add_argument("--bench", type=Path, required=True)
        p.add_argument("--src", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--llm", action="store_true")
    s.add_argument("--llm-backend", choices=("local", "ollama"), default="local")
    s.add_argument("--llm-model", default=None)
    s.add_argument("--llm-4bit", action="store_true")
    s.add_argument("--llm-adapter", default=None)
    args = ap.parse_args()

    if args.cmd == "fetch":
        fetch(args.bench, args.src)
        return 0
    if args.cmd == "rescore":
        labels = read_labels(args.bench)
        for path in args.reports:
            old = json.loads(path.read_text(encoding="utf-8"))
            report = {"provider": old["provider"], **score(labels, old["findings"]),
                      "findings": old["findings"]}
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
            t = report["totals"]
            print(f"{report['provider']:45} TP {t.get('TP', 0)} FP {t.get('FP', 0)} "
                  f"FN {t.get('FN', 0)} review+ {t.get('review_pos', 0)} "
                  f"review- {t.get('review_neg', 0)} TN {t.get('TN', 0)} "
                  f"P {report['precision']} R {report['recall']}")
        return 0

    from rag_app.analysis.verdict import LlmVerdict, StaticVerdict
    provider = StaticVerdict()
    name = "static"
    if args.llm:
        from rag_app.config.loader import load_config
        from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
        model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
        provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend, model,
                                                 args.llm_4bit, args.llm_adapter))
        name = f"{args.llm_backend}:{model}" + (f"+{Path(args.llm_adapter).name}"
                                                 if args.llm_adapter else "")
    labels = read_labels(args.bench)
    findings = run_detector(args.src, provider)
    report = {"provider": name, **score(labels, findings), "findings": findings}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("provider", "in_scope_positive", "in_scope_negative",
                                             "totals", "precision", "recall", "by_type")},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
