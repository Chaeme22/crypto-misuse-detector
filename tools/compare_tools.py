"""
ApacheCryptoAPI-Bench에서 다른 도구의 실제 탐지 결과를 우리와 같은 정답으로 다시 채점한다.

논문마다 사례 구성이 달라(논문 88건 vs 공개 엑셀) 발표된 숫자를 그대로 나란히 놓을 수 없다. Xia 외
(ISSTA 2025)가 공개한 CryptoGuard 실행 결과와 GPT-4 보고서를 받아, 같은 정답 엑셀·같은 채점 단위로
우리 도구와 함께 잰다.

채점 단위는 (클래스, 오용 유형)이다. CryptoGuard가 클래스 단위로만 보고하므로 모든 도구를 거기에 맞춘다.
한 단위에 보안 용도(TP) 정답이 하나라도 있으면 그 단위는 오용, 무관(TN) 정답뿐이면 정상이다.

    python tools/compare_tools.py --bench repos/ApacheCryptoAPI-Bench \
        --artifact repos/CryptoGPT-online.github.io/cryptogpt-artifact/ApacheBench \
        --ours eval/apache-v2-static.json eval/apache-v2-adapter.json --out eval/compare-apache.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apache_bench as ab  # noqa: E402

# 우리 규칙 → 벤치마크 유형
OUR_TYPES = defaultdict(set)
for bench_type, rules in ab.RULES.items():
    for rule in rules:
        OUR_TYPES[rule].add(bench_type)

# CryptoGuard 규칙 번호 → 벤치마크 유형 (범위 밖 규칙은 뺀다: 4 TrustManager, 6·12 Hostname, 7 HTTP)
CG_TYPES = {1: {"CipherAlgo", "ModeofOperation"}, 2: {"MessageDigest", "Mac"}, 3: {"Constantkey"},
            8: {"PBEIteration"}, 9: {"PBESalt"}, 10: {"static IV"}, 13: {"Random"}}


def gpt_types(misuse: str, text: str) -> set[str]:
    """GPT 보고서 한 건의 유형. CWE 번호와 설명 키워드로 정한다."""
    blob = f"{misuse} {text}".lower()
    found = set()
    if "ecb" in blob or "mode of operation" in blob:
        found.add("ModeofOperation")
    if re.search(r"cwe-32[17]\b|cwe-798|hard-?coded|constant key|static key", blob) and \
            "salt" not in blob and "iv" not in blob.split():
        found.add("Constantkey")
    if re.search(r"\bdes\b|desede|3des|triple|rc4|arcfour|blowfish|rc2|broken.*(cipher|algorithm)|"
                 r"risky cryptographic algorithm", blob):
        found.add("CipherAlgo")
    if re.search(r"md5|sha-?1\b|cwe-328|weak hash", blob):
        found.add("Mac" if "hmac" in blob or "mac" in blob.split() else "MessageDigest")
    if re.search(r"\biv\b|initialization vector|cwe-329|cwe-1204", blob):
        found.add("static IV")
    if "salt" in blob or "cwe-760" in blob or "cwe-759" in blob:
        found.add("PBESalt")
    if "iteration" in blob or "cwe-916" in blob:
        found.add("PBEIteration")
    if re.search(r"java\.util\.random|\brandom\b|prng|cwe-33[08]", blob) and "securerandom" not in blob:
        found.add("Random")
    return found


def load_gpt(folder: Path, refined: bool) -> tuple[set[tuple[str, str]], set[str]]:
    """(보고된 (클래스, 유형) 집합, GPT가 본 클래스 이름 집합). 클래스는 단순 이름이다."""
    flagged, seen = set(), set()
    for case in folder.glob("*/*"):
        if not case.is_dir():
            continue
        cls = case.name
        seen.add(cls)
        path = case / ("refine.json" if refined else "0.json")
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if refined and "### Optimized Misuse JSON ###" in text:
            text = text.split("### Optimized Misuse JSON ###", 1)[1]
        match = re.search(r"\[.*\]", text, re.S)
        if not match:
            continue
        try:
            items = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            for t in gpt_types(str(item.get("misuse", "")),
                               f"{item.get('vulnerable_code', '')} {item.get('description', '')}"):
                flagged.add((cls, t))
    return flagged, seen


def load_cryptoguard(folder: Path) -> set[tuple[str, str]]:
    flagged = set()
    for path in folder.glob("*.json"):
        for issue in json.loads(path.read_text(encoding="utf-8")).get("Issues", []):
            types = CG_TYPES.get(issue.get("RuleNumber"))
            if not types:
                continue
            cls = issue.get("_FullPath", "").split(".jar/")[-1].removesuffix(".class")
            cls = ab._outer(cls.replace("/", "."))
            for t in types:
                flagged.add((cls, t))
    return flagged


def load_ours(report: Path) -> set[tuple[str, str]]:
    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    # 112비트 경고도 보고서에 나오는 탐지다(다른 도구의 3DES 탐지와 같은 선상)
    return {(f["class"], t) for f in findings if f["decision"] in ("violation", "warning")
            for t in OUR_TYPES.get(f["rule"], ())}


def units(labels: list[ab.Label]) -> dict[tuple[str, str], bool]:
    """(클래스, 유형) → 오용인지."""
    out: dict[tuple[str, str], bool] = {}
    for label in labels:
        if label.type in ab.OUT_OF_SCOPE:
            continue
        key = (label.cls, label.type)
        out[key] = out.get(key, False) or label.positive
    return out


def _hit(unit: tuple[str, str], flagged: set[tuple[str, str]], simple: bool) -> bool:
    cls, t = unit
    if simple:
        return (cls.split(".")[-1], t) in flagged
    return any(ft == t and (fc == cls or (cls.startswith(".") and fc.endswith(cls)))
               for fc, ft in flagged)


def score(truth: dict[tuple[str, str], bool], flagged, simple: bool = False) -> dict:
    tp = fp = fn = tn = 0
    for unit, positive in truth.items():
        hit = _hit(unit, flagged, simple)
        tp += positive and hit
        fn += positive and not hit
        fp += (not positive) and hit
        tn += (not positive) and not hit
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": round(p, 3),
            "recall": round(r, 3), "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0}


def main() -> int:
    ap = argparse.ArgumentParser(description="다른 도구 결과를 같은 정답으로 채점")
    ap.add_argument("--bench", type=Path, required=True)
    ap.add_argument("--artifact", type=Path, required=True, help="cryptogpt-artifact/ApacheBench")
    ap.add_argument("--ours", type=Path, nargs="+", required=True)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    truth = units(ab.read_labels(args.bench))
    tools = {"CryptoGuard (Xia 외 실행 결과)": (load_cryptoguard(args.artifact / "sat-result" / "CG"), False)}
    for report in args.ours:
        name = json.loads(report.read_text(encoding="utf-8"))["provider"]
        tools[f"ours: {name}"] = (load_ours(report), False)
    gpt_dir = args.artifact / "llm-result" / "gpt-4-1106-preview-temp1-prompt_insecure_classify"
    gpt_raw, gpt_seen = load_gpt(gpt_dir, refined=False)
    gpt_refined, _ = load_gpt(gpt_dir, refined=True)

    report = {"unit": "(class, type)", "positive_units": sum(truth.values()),
              "negative_units": sum(1 for v in truth.values() if not v), "all": {}, "gpt_subset": {}}
    for name, (flagged, simple) in tools.items():
        report["all"][name] = score(truth, flagged, simple)

    subset = {u: v for u, v in truth.items() if u[0].split(".")[-1] in gpt_seen}
    report["gpt_subset_units"] = {"positive": sum(subset.values()),
                                  "negative": sum(1 for v in subset.values() if not v)}
    for name, (flagged, simple) in tools.items():
        report["gpt_subset"][name] = score(subset, flagged, simple)
    report["gpt_subset"]["GPT-4 (첫 실행)"] = score(subset, gpt_raw, True)
    report["gpt_subset"]["GPT-4 (검증 단계 후)"] = score(subset, gpt_refined, True)

    print(f"단위 (클래스, 유형): 오용 {report['positive_units']} · 정상 {report['negative_units']}")
    for section in ("all", "gpt_subset"):
        title = "전체" if section == "all" else (f"GPT-4가 본 파일만 (오용 {report['gpt_subset_units']['positive']}"
                                                 f" · 정상 {report['gpt_subset_units']['negative']})")
        print(f"\n== {title}")
        for name, s in report[section].items():
            print(f"  {name:60} TP {s['TP']:3} FP {s['FP']:3} FN {s['FN']:3} TN {s['TN']:3} "
                  f"P {s['precision']:.3f} R {s['recall']:.3f} F1 {s['f1']:.3f}")
    if args.out:
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
