"""
국산 암호(SEED·ARIA·LEA·HIGHT·LSH·HAS-160·KCDSA)를 쓰는 실제 오픈소스 Java 코퍼스.

관련 연구의 벤치마크(CryptoAPI-Bench, ApacheCryptoAPI-Bench, Xia 외)에는 국산 암호가 없다. KISA 안내서를 기준으로
삼는 이 도구의 차별점을 재려면 국산 암호를 실제로 쓰는 코드가 필요하다.

GitHub 코드 검색으로 찾은 파일 목록(`select`의 입력, `gh api search/code` 결과 TSV)에서 저장소를 고르고, 저장소 이름의
해시로 개발용(60%)과 시험용(40%)을 나눈다. 해시로 나누므로 누가 언제 돌려도 같은 분할이다. 개발용만 보고 추출기를
고치고, 시험용은 사람이 정답을 확인한 뒤 마지막에 한 번 잰다.

    python tools/kr_corpus.py select --hits kr_hits.tsv --out dataset/kr_corpus.json
    python tools/kr_corpus.py fetch --corpus dataset/kr_corpus.json --split dev --repos repos/kr-git
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path

# 라이브러리 구현 자체. 이런 경로만 걸린 저장소는 국산 암호를 "쓰는" 코드가 아니다.
LIBRARY_PATHS = ("org/bouncycastle", "bouncycastle", "/crypto/engines/", "/jce/provider/",
                 "kr/re/nsr/crypto/", "/kcdsa/", "KCDSA")
# 구현 파일 이름. 이 파일만 걸렸으면 라이브러리를 복사해 둔 것뿐일 수 있으나, 같은 저장소에서 부르는 코드가
# 있을 가능성이 커 저장소는 남긴다. 다만 이것만 걸리고 쿼리가 KCDSA뿐이면 뺀다.
DEV_SHARE = 6   # 10 중


def split_of(repo: str) -> str:
    digest = int(hashlib.sha1(repo.lower().encode()).hexdigest(), 16)
    return "dev" if digest % 10 < DEV_SHARE else "test"


def select(hits: Path) -> dict:
    by_repo: dict[str, dict] = defaultdict(lambda: {"queries": set(), "paths": set(), "fork": False})
    with hits.open(encoding="utf-8") as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) < 4:
                continue
            query, repo, fork, path = row[:4]
            entry = by_repo[repo]
            entry["queries"].add(query)
            entry["paths"].add(path)
            entry["fork"] = entry["fork"] or fork == "true"

    chosen, dropped = {}, defaultdict(list)
    for repo, entry in sorted(by_repo.items()):
        if entry["fork"]:
            dropped["fork"].append(repo)
            continue
        usage = [p for p in entry["paths"] if not any(m in p for m in LIBRARY_PATHS)]
        if not usage:
            dropped["library-only"].append(repo)
            continue
        chosen[repo] = {"split": split_of(repo), "queries": sorted(entry["queries"]),
                        "paths": sorted(usage)}
    return {"repos": chosen,
            "counts": {"dev": sum(v["split"] == "dev" for v in chosen.values()),
                       "test": sum(v["split"] == "test" for v in chosen.values()),
                       **{f"dropped_{k}": len(v) for k, v in dropped.items()}}}


def fetch(corpus: dict, split: str, repos: Path) -> None:
    repos.mkdir(parents=True, exist_ok=True)
    for name, entry in sorted(corpus["repos"].items()):
        if entry["split"] != split:
            continue
        out = repos / name.replace("/", "__")
        if out.exists():
            continue
        print(f"clone {name}", flush=True)
        result = subprocess.run(["git", "clone", "--quiet", "--depth", "1",
                                 f"https://github.com/{name}.git", str(out)],
                                capture_output=True, text=True,
                                env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin"})
        if result.returncode != 0:
            print(f"  실패: {result.stderr.strip()[:160]}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="국산 암호 실제 코드 코퍼스")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("select")
    s.add_argument("--hits", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--corpus", type=Path, required=True)
    f.add_argument("--split", choices=("dev", "test"), required=True)
    f.add_argument("--repos", type=Path, required=True)
    args = ap.parse_args()
    if args.cmd == "select":
        corpus = select(args.hits)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(corpus, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(corpus["counts"])
        return 0
    fetch(json.loads(args.corpus.read_text(encoding="utf-8")), args.split, args.repos)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
