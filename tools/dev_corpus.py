"""
추출기 개선용 개발 코퍼스. 실제 오픈소스 Java에서 추출기가 놓치는 암호 API 호출 모양을 찾는다.

평가용 홀드아웃(wild_bench, Xia 외 ISSTA 2025 저장소)과 겹치는 저장소는 받지 않는다. 그 시험지는 마지막
검증에만 쓴다.

정답 라벨이 없으므로 오용 여부가 아니라 "추출 커버리지"를 잰다. 단순 정규식으로 찾은 암호 API 호출 줄 중에
추출기가 사용 지점으로 잡은 비율이다. 못 잡은 줄을 호출 종류·인자 모양별로 묶어 예시와 함께 낸다.

    python tools/dev_corpus.py fetch --repos repos/dev-git
    python tools/dev_corpus.py gaps --repos repos/dev-git --out eval/dev-gaps.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# 암호를 직접 쓰는 응용 저장소. 암호 라이브러리 구현체(BouncyCastle 등)는 넣지 않는다.
REPOS = [
    "dromara/hutool", "apache/shiro", "spring-projects/spring-security", "jwtk/jjwt", "auth0/java-jwt",
    "alibaba/nacos", "apache/dubbo", "xuxueli/xxl-job", "macrozheng/mall", "yangzongzhuan/RuoYi-Vue",
    "dromara/Sa-Token", "apache/rocketmq", "apache/zookeeper", "apolloconfig/apollo",
    "thingsboard/thingsboard", "apache/shardingsphere", "apache/dolphinscheduler", "pig-mesh/pig",
    "elunez/eladmin", "ulisesbocchio/jasypt-spring-boot", "jasypt/jasypt", "apache/pdfbox",
    "apache/poi", "apache/tomcat", "gitblit-org/gitblit", "traccar/traccar", "apache/ofbiz-framework",
    "apache/santuario-xml-security-java", "apache/cxf", "openhab/openhab-core",
]

# 평가 홀드아웃 저장소. 여기 있는 것은 절대 받지 않는다.
HOLDOUT = {"alibaba/canal", "alibaba/datax", "alibaba/druid", "apache/incubator-seata", "baomidou/mybatis-plus",
           "dbeaver/dbeaver", "elastic/elasticsearch", "grasscutters/grasscutter", "halo-dev/halo",
           "jeecgboot/jeecg-boot", "jenkinsci/jenkins", "justauth/justauth", "keycloak/keycloak",
           "netty/netty", "signalapp/signal-android", "yuliskov/smarttube"}

# 추출기와 무관한 기준. 호출 이름만 본다.
PATTERNS = {
    "MessageDigest.getInstance": r"\bMessageDigest\s*\.\s*getInstance\s*\(",
    "Cipher.getInstance": r"\bCipher\s*\.\s*getInstance\s*\(",
    "Signature.getInstance": r"\bSignature\s*\.\s*getInstance\s*\(",
    "Mac.getInstance": r"\bMac\s*\.\s*getInstance\s*\(",
    "KeyGenerator.getInstance": r"\bKeyGenerator\s*\.\s*getInstance\s*\(",
    "KeyPairGenerator.getInstance": r"\bKeyPairGenerator\s*\.\s*getInstance\s*\(",
    "SecretKeyFactory.getInstance": r"\bSecretKeyFactory\s*\.\s*getInstance\s*\(",
    "DigestUtils.weak": r"\bDigestUtils\s*\.\s*(md5|sha1|sha|md2)\w*\s*\(",
    "new SecretKeySpec": r"\bnew\s+SecretKeySpec\s*\(",
    "new DES(ede)?KeySpec": r"\bnew\s+DES(ede)?KeySpec\s*\(",
    "new IvParameterSpec": r"\bnew\s+IvParameterSpec\s*\(",
    "new GCMParameterSpec": r"\bnew\s+GCMParameterSpec\s*\(",
    "new PBEKeySpec": r"\bnew\s+PBEKeySpec\s*\(",
    "new PBEParameterSpec": r"\bnew\s+PBEParameterSpec\s*\(",
    "new Random": r"\bnew\s+(java\.util\.)?Random\s*\(",
    "Math.random": r"\bMath\s*\.\s*random\s*\(",
    "setSeed": r"\.\s*setSeed\s*\(",
    "new SecureRandom(seed)": r"\bnew\s+SecureRandom\s*\(\s*[^)\s]",
    "KeyStore.load": r"\.\s*load\s*\(.*(toCharArray|password|passwd|pwd)",
    # 국산 암호 KISA 참조 구현 (tools/kr_corpus.py)
    "KISA_SEED_*": r"\bKISA_SEED_(ECB|CBC|CTR)\s*\.\s*SEED_\w+_(Encrypt|Decrypt|init)\s*\(",
    "new ARIAEngine(n, key)": r"\bnew\s+ARIAEngine\s*\(\s*\w+\s*,",
}
_COMPILED = {name: re.compile(p) for name, p in PATTERNS.items()}


def _git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def fetch(repos: Path) -> None:
    repos.mkdir(parents=True, exist_ok=True)
    for name in REPOS:
        assert name.lower() not in HOLDOUT, f"{name}는 평가 홀드아웃이다"
        out = repos / name.replace("/", "__")
        if out.exists():
            continue
        print(f"clone {name}", flush=True)
        try:
            _git("clone", "--quiet", "--depth", "1", f"https://github.com/{name}.git", str(out))
        except subprocess.CalledProcessError as error:
            print(f"  실패: {error.stderr.decode(errors='replace')[:200]}", flush=True)


def _is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith(("//", "*", "/*"))


def _arg_shape(line: str, match: re.Match) -> str:
    """첫 인자의 모양: 문자열 / 상수(대문자) / 변수 / 호출 / 없음."""
    rest = line[match.end():].lstrip()
    if not rest or rest.startswith(")"):
        return "no-arg"
    if rest.startswith('"'):
        return "literal"
    token = re.match(r"[\w.]+", rest)
    if not token:
        return "other"
    word = token.group(0)
    after = rest[len(word):].lstrip()
    if after.startswith("("):
        return "call"
    last = word.split(".")[-1]
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", last):
        return "constant" if "." not in word else "qualified-constant"
    return "variable"


def inventory(path: Path) -> list[tuple[int, str, str, str]]:
    """(줄, 패턴, 인자 모양, 코드) 목록."""
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    if not any(k in text for k in ("getInstance", "Spec", "Random", "setSeed", "DigestUtils", ".load")):
        return out
    for number, line in enumerate(text.splitlines(), 1):
        if _is_comment(line):
            continue
        for name, pattern in _COMPILED.items():
            m = pattern.search(line)
            if m:
                out.append((number, name, _arg_shape(line, m), line.strip()[:160]))
    return out


def gaps(repos: Path, max_files: int = 0) -> dict:
    from rag_app.analysis import extract, rules as tier1

    rule_list = tier1.load(ROOT / "config" / "tier1_rules.json")
    totals: Counter = Counter()
    covered: Counter = Counter()
    examples: dict[str, list[dict]] = defaultdict(list)
    shapes: Counter = Counter()
    resolution: dict[str, Counter] = defaultdict(Counter)
    reasons: Counter = Counter()
    unresolved_examples: dict[str, list[dict]] = defaultdict(list)
    per_repo = {}
    for repo in sorted(p for p in repos.iterdir() if p.is_dir()):
        if max_files and sum(1 for _ in repo.rglob("*.java")) > max_files:
            # 역컴파일 덤프·분석 데이터 같은 거대 저장소. 응용 코드라 보기 어렵고 검사 시간만 잡아먹는다.
            per_repo[repo.name] = {"skipped": "too many files"}
            print(f"  {repo.name}: 건너뜀(Java 파일 {max_files}개 초과)", flush=True)
            continue
        hits = {}
        for path in repo.rglob("*.java"):
            if any(part in extract.SKIP_DIRS for part in path.relative_to(repo).parts):
                continue
            found = inventory(path)
            if found:
                hits[path.relative_to(repo).as_posix()] = found
        if not hits:
            per_repo[repo.name] = {"calls": 0}
            continue
        sites = extract.collect(repo, rule_list)
        lines = defaultdict(set)
        for site, rule in sites:
            lines[site.file_path].add(site.line)
            # 지점은 잡았지만 값을 못 찾은 자리. 실제 코드에서 놓치는 두 번째 원인이다.
            resolved = not site.unresolved_args and site.provenance not in ("unknown",)
            resolution[rule.rule_id][resolved] += 1
            if not resolved:
                reason = _reason(site)
                reasons[(rule.rule_id, reason)] += 1
                if len(unresolved_examples[reason]) < 15:
                    unresolved_examples[reason].append({
                        "repo": repo.name, "file": site.file_path, "line": site.line,
                        "rule": rule.rule_id, "api": site.api[:100],
                        "note": site.provenance_note[:160], "code": site.snippet[:160]})
        n = c = 0
        for rel, found in hits.items():
            for number, name, shape, code in found:
                hit = any(abs(number - x) <= 1 for x in lines.get(rel, ()))
                totals[name] += 1
                n += 1
                if hit:
                    covered[name] += 1
                    c += 1
                else:
                    shapes[(name, shape)] += 1
                    if len(examples[name]) < 25:
                        examples[name].append({"repo": repo.name, "file": rel, "line": number,
                                               "shape": shape, "code": code})
        per_repo[repo.name] = {"calls": n, "covered": c, "sites": len(sites)}
        print(f"  {repo.name}: 호출 {n} 중 {c} 잡음 (사이트 {len(sites)})", flush=True)

    by_pattern = {name: {"calls": totals[name], "covered": covered[name],
                         "rate": round(covered[name] / totals[name], 3)}
                  for name in sorted(totals, key=lambda k: -totals[k])}
    all_calls, all_cov = sum(totals.values()), sum(covered.values())
    return {"calls": all_calls, "covered": all_cov,
            "rate": round(all_cov / all_calls, 3) if all_calls else None,
            "by_pattern": by_pattern,
            "missed_shapes": {f"{k[0]} | {k[1]}": v for k, v in shapes.most_common()},
            "resolution": {rule: {"resolved": c[True], "unresolved": c[False]}
                           for rule, c in sorted(resolution.items())},
            "unresolved_reasons": {f"{k[0]} | {k[1]}": v for k, v in reasons.most_common()},
            "per_repo": per_repo, "examples": examples,
            "unresolved_examples": unresolved_examples}


def _reason(site) -> str:
    """값을 못 찾은 까닭을 거칠게 나눈다. 출처 판별 메모의 앞부분이나 인자 모양으로 본다."""
    note = site.provenance_note or ""
    if note:
        return re.sub(r"[`'\"(].*", "", note).strip()[:40] or "note"
    args = " ".join(site.unresolved_args)
    if not args:
        return "no-arg"
    if re.search(r"\w\(", args):
        return "arg: method call"
    if re.fullmatch(r"[A-Z][A-Za-z0-9_]*\.[A-Z0-9_]+", args.strip()):
        return "arg: other-class constant"
    if "." in args:
        return "arg: field/qualified"
    return "arg: variable"


def main() -> int:
    ap = argparse.ArgumentParser(description="추출기 개선용 개발 코퍼스")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    g = sub.add_parser("gaps")
    for p in (f, g):
        p.add_argument("--repos", type=Path, required=True)
    g.add_argument("--out", type=Path, required=True)
    g.add_argument("--max-files", type=int, default=0, help="Java 파일이 이보다 많은 저장소는 건너뛴다")
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch(args.repos)
        return 0
    report = gaps(args.repos, args.max_files)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("calls", "covered", "rate", "by_pattern")},
                     ensure_ascii=False, indent=1))
    print(json.dumps(report["missed_shapes"], ensure_ascii=False, indent=1))
    print(json.dumps({k: report[k] for k in ("resolution", "unresolved_reasons")},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
