"""
공개 벤치마크로 탐지 정확도를 잰다.

우리 표가 맞는지, 규칙이 실제 오용을 잡는지는 우리가 만든 픽스처로는 알 수 없다. 정답을
우리가 썼기 때문이다. 그래서 남이 만든 정답을 쓴다. CryptoAPI-Bench는 자바 암호 API
오용 사례 모음이고 `*Corrected.java`가 정상 사례다. 그 이름이 정답이 된다.

세 갈래로 센다.
  탐지 대상   오용 사례 파일 중 그 파일 안에 암호 API 호출이 있는 것
  정상 사례   `*Corrected*` 파일. 여기서 경보가 나오면 오탐이다
  간접 호출   호출만 있고 API는 다른 파일에 있는 사례. 파일 단위로 셀 수 없어 따로 적는다

간접 호출을 정확도 계산에서 빼는 이유는 유리하게 만들려는 게 아니다. 그 사례의 경보는
호출된 파일에 뜨는 것이 옳고, 그러면 같은 경보를 두 파일에서 세게 된다. 대신 개수를
그대로 적어 무엇을 안 셌는지 드러낸다.

사용법:
    python tools/benchmark.py /tmp/CryptoAPI-Bench
    python tools/benchmark.py /tmp/CryptoAPI-Bench --llm --llm-backend ollama
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rag_app.analysis import pipeline, rules as tier1, sarif  # noqa: E402
from rag_app.analysis.thresholds import ThresholdTable  # noqa: E402
from rag_app.analysis.verdict import StaticVerdict  # noqa: E402
from rag_app.config.loader import load_config  # noqa: E402

# 벤치마크 분류 → 우리 규칙. 우리 규칙이 없는 분류는 검사 범위 밖이므로 세지 않는다.
CATEGORIES = {
    "brokenhash": "CRYPTO-HASH-WEAK",
    "brokenmac": "CRYPTO-HASH-WEAK",
    "brokencrypto": "CRYPTO-CIPHER-OBSOLETE",
    "ecbcrypto": "CRYPTO-MODE-ECB",
    "insecureasymmetriccrypto": "CRYPTO-KEYSIZE-SHORT",
    "untrustedprng": "CRYPTO-RNG-INSECURE",
    "predictableseeds": "CRYPTO-SEED-PREDICTABLE",
    "pbeiteration": "CRYPTO-KDF-WEAK",
    "credentialinstring": "CRYPTO-KEY-HARDCODED",
    "predictablecryptographickey": "CRYPTO-KEY-HARDCODED",
    "staticinitializationvector": "CRYPTO-IV-STATIC",
    # 재료마다 규칙이 다르다. 키 규칙에 몰아 두면 고정 솔트가 하드코딩 키로 잡혀도 맞힌
    # 것으로 세어진다.
    "predictablepbepassword": "CRYPTO-PASSWORD-HARDCODED",
    "predictablekeystorepassword": "CRYPTO-PASSWORD-HARDCODED",
    "staticsalts": "CRYPTO-SALT-STATIC",
}
# 우리 규칙이 다루지 않는 분류. TLS 인증서·호스트명 검증은 암호 알고리즘 선택이 아니다.
OUT_OF_SCOPE = ("dummycertvalidation", "dummyhostnameverifier",
                "impropersslsocketfactory", "http")

# 파일 안에 암호 API 호출이 있는지. 없으면 다른 파일의 오용을 부르는 사례다.
_CRYPTO_API = re.compile(
    r"\b(MessageDigest|Cipher|Mac|KeyPairGenerator|KeyGenerator|SecretKeyFactory|"
    r"SecretKeySpec|IvParameterSpec|PBEKeySpec|PBEParameterSpec|Random|"
    r"KeyStore|SecureRandom)\s*[.(]")


def ground_truth(root: Path) -> dict[str, dict]:
    """파일마다 무엇을 기대하는지. 디렉터리 이름과 파일 이름이 정답이다."""
    truth: dict[str, dict] = {}
    for path in sorted(root.rglob("*.java")):
        relative = path.relative_to(root).as_posix()
        category = path.parent.name
        if category in OUT_OF_SCOPE:
            truth[relative] = {"category": category, "expect": "out_of_scope"}
            continue
        rule = CATEGORIES.get(category)
        if rule is None:
            truth[relative] = {"category": category, "expect": "unmapped"}
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "Corrected" in path.stem:
            expect = "clean"
        elif _CRYPTO_API.search(text):
            expect = "violation"
        else:
            expect = "indirect"
        truth[relative] = {"category": category, "expect": expect, "rule": rule}
    return truth


def analyze(root: Path, provider, with_clauses: bool) -> dict:
    """검사를 돌려 SARIF를 만든다. 파이프라인 노드를 직접 이어 중간 상태를 본다."""
    state = pipeline.AnalysisState(target=str(root), root=root)
    state.rules = tier1.load()
    state.thresholds = ThresholdTable.load()
    state = pipeline.extract_sites(state)
    finder = None
    if with_clauses:
        finder = pipeline.ClauseFinder(load_config())
    state = pipeline.judge_sites(state, provider, finder)
    return sarif.build(state.findings, root=str(root)), state


def score(truth: dict, document: dict) -> dict:
    """파일 단위로 센다. 규칙이 맞는 경보만 참으로 본다."""
    # 확정 경보와 확인 요청을 나눈다. `kind=review`는 값을 확인하지 못해 사람에게
    # 넘긴 것이고 오탐이 아니다. 둘을 한 통에 넣으면 정상 사례에 붙은 확인 요청이
    # 오탐으로 세어지고, 반대로 확정 경보의 정밀도가 흐려진다.
    reported: dict[str, set[str]] = defaultdict(set)
    review: dict[str, set[str]] = defaultdict(set)
    for result in document["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        (review if result.get("kind") == "review" else reported)[uri].add(
            result["ruleId"])

    per_category: dict[str, dict] = defaultdict(
        lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "wrong_rule": 0,
                 "indirect": 0, "indirect_flagged": 0,
                 "review_hit": 0, "review_clean": 0})
    unexpected: list[tuple[str, str]] = []

    for relative, want in sorted(truth.items()):
        category = want["category"]
        bucket = per_category[category]
        hits = reported.get(relative, set())

        asked = review.get(relative, set())
        if want["expect"] == "violation":
            if asked and want["rule"] not in hits:
                # 값을 확인하지 못해 사람에게 넘겼다. 놓친 것도 잡은 것도 아니다.
                # 규칙이 기대와 달라도 마찬가지다. `Cipher.getInstance(변수)`는 값을
                # 모르니 운영모드 규칙으로 남는데, 그 파일이 검토 목록에 오른 것은
                # 사실이다. 이걸 조용히 놓침으로 세면 도구가 실제로 무엇을 내놨는지
                # 가려진다.
                bucket["review_hit"] += 1
                bucket["fn"] += 1
                continue
            if want["rule"] in hits:
                bucket["tp"] += 1
            elif hits:
                # 경보는 났지만 다른 규칙이다. 잡았다고 하기도, 놓쳤다고 하기도 어렵다.
                bucket["wrong_rule"] += 1
                bucket["fn"] += 1
            else:
                bucket["fn"] += 1
        elif want["expect"] == "clean":
            if asked and not hits:
                bucket["review_clean"] += 1
                bucket["tn"] += 1
                continue
            if hits:
                bucket["fp"] += 1
                unexpected.append((relative, ", ".join(sorted(hits))))
            else:
                bucket["tn"] += 1
        elif want["expect"] == "indirect":
            bucket["indirect"] += 1
            if hits:
                bucket["indirect_flagged"] += 1
        elif want["expect"] == "out_of_scope" and hits:
            unexpected.append((relative, ", ".join(sorted(hits)) + " (범위 밖 분류)"))
    return {"per_category": dict(per_category), "unexpected": unexpected}


def summarize(result: dict) -> dict:
    """범위 안 분류만 합친다. 화면 출력과 기준선 파일이 같은 숫자를 쓰게 한다."""
    total: dict[str, int] = defaultdict(int)
    for category, bucket in result["per_category"].items():
        if category in OUT_OF_SCOPE or category not in CATEGORIES:
            continue
        for key in ("tp", "fn", "fp", "tn", "wrong_rule", "indirect",
                    "indirect_flagged", "review_hit", "review_clean"):
            total[key] += bucket[key]
    tp, fn, fp = total["tp"], total["fn"], total["fp"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"total": dict(total), "precision": precision, "recall": recall, "f1": f1}


def main() -> int:
    ap = argparse.ArgumentParser(description="공개 벤치마크로 탐지 정확도를 잰다")
    ap.add_argument("root", type=Path)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--llm-backend", choices=("local", "ollama"), default="local",
                    help="GPU가 없으면 ollama")
    ap.add_argument("--llm-adapter", default=None, help="local 백엔드에 얹을 LoRA 어댑터 폴더")
    ap.add_argument("--llm-model", default=None,
                    help="local은 HF 이름, ollama는 태그. 생략하면 백엔드별 기본값")
    ap.add_argument("--llm-4bit", action="store_true", default=True)
    ap.add_argument("--clauses", action="store_true")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--detail", action="store_true",
                    help="놓친 사례를 그 파일의 암호 호출 줄과 함께 보여준다. "
                         "숫자만 보면 왜 놓쳤는지 알 수 없다.")
    args = ap.parse_args()

    root = args.root.resolve()
    truth = ground_truth(root)

    provider = StaticVerdict()
    if args.llm:
        from rag_app.analysis.verdict import LlmVerdict
        from rag_app.models.llm import DEFAULT_VERDICT_MODELS, make_verdict_model
        args.llm_model = args.llm_model or DEFAULT_VERDICT_MODELS[args.llm_backend]
        provider = LlmVerdict(make_verdict_model(load_config(), args.llm_backend,
                                                 args.llm_model, args.llm_4bit,
                                                 args.llm_adapter))

    document, state = analyze(root, provider, args.clauses)
    result = score(truth, document)

    print(f"판정 경로: {provider.name}"
          + (f" ({args.llm_model})" if args.llm else "")
          + f" · 조항 검색 {'사용' if args.clauses else '미사용'}")
    print(f"사용 지점 {len(state.sites)}건 · 표로 닫힘 {state.closed_by_table}건 · "
          f"보고 {len(document['runs'][0]['results'])}건\n")

    print(f"{'분류':<30} {'대상':>4} {'잡음':>4} {'놓침':>4} {'확인':>4} {'정상':>4} "
          f"{'오탐':>4} {'다른규칙':>7} {'간접':>4}")
    print("-" * 88)
    for category in sorted(result["per_category"]):
        bucket = result["per_category"][category]
        if category in OUT_OF_SCOPE or category not in CATEGORIES:
            continue
        target = bucket["tp"] + bucket["fn"]
        clean = bucket["fp"] + bucket["tn"]
        print(f"{category:<30} {target:>4} {bucket['tp']:>4} {bucket['fn']:>4} "
              f"{bucket['review_hit']:>4} {clean:>4} {bucket['fp']:>4} "
              f"{bucket['wrong_rule']:>7} {bucket['indirect']:>4}")

    print("-" * 88)
    summary = summarize(result)
    total = summary["total"]
    tp, fn, fp = total["tp"], total["fn"], total["fp"]
    precision, recall, f1 = summary["precision"], summary["recall"], summary["f1"]
    print(f"{'합계':<30} {tp + fn:>4} {tp:>4} {fn:>4} {total['review_hit']:>4} "
          f"{fp + total['tn']:>4} {fp:>4} {total['wrong_rule']:>7} "
          f"{total['indirect']:>4}")
    target = tp + fn
    surfaced = (tp + total["review_hit"]) / target if target else 0.0
    print(f"\n확정 경보 기준: 정밀도 {precision:.3f} · 재현율 {recall:.3f} · F1 {f1:.3f}")
    print(f"검토 목록에 올린 비율: {surfaced:.3f} "
          f"({tp} 확정 + {total['review_hit']} 확인 / {target})")
    print(f"확인 요청 {total['review_hit'] + total['review_clean']}건 "
          f"(오용 사례 {total['review_hit']}건, 정상 사례 {total['review_clean']}건). "
          f"값을 확인하지 못해 사람에게 넘긴 것이고 정밀도 계산에 넣지 않았다.")
    print(f"간접 호출 사례 {total['indirect']}건은 정확도 계산에서 빼고, 그중 "
          f"{total['indirect_flagged']}건에 경보가 났다.")

    if result["unexpected"]:
        print(f"\n정상 사례에 난 경보 {len(result['unexpected'])}건:")
        for relative, why in result["unexpected"]:
            print(f"  {relative}  ← {why}")

    if args.detail:
        reported = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in document["runs"][0]["results"]}
        missed = [(k, v) for k, v in sorted(truth.items())
                  if v["expect"] == "violation" and k not in reported]
        wrong = [(k, v) for k, v in sorted(truth.items())
                 if v["expect"] == "violation" and k in reported
                 and v["rule"] not in {
                     r["ruleId"] for r in document["runs"][0]["results"]
                     if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == k}]
        print(f"\n놓친 사례 {len(missed)}건 — 그 파일의 암호 호출 줄")
        for relative, want in missed:
            print(f"  [{want['category']}] {Path(relative).name}")
            for line in (root / relative).read_text(encoding="utf-8",
                                                    errors="replace").splitlines():
                if _CRYPTO_API.search(line) or re.search(r'=\s*"', line):
                    print(f"      {line.strip()[:110]}")
        print(f"\n다른 규칙으로 잡은 사례 {len(wrong)}건")
        for relative, want in wrong:
            got = ", ".join(sorted(
                r["ruleId"] for r in document["runs"][0]["results"]
                if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == relative))
            print(f"  [{want['category']}] {Path(relative).name}: 기대 {want['rule']} → 실제 {got}")

    if args.out:
        args.out.write_text(json.dumps(
            {"provider": provider.name, "clauses": args.clauses,
             "score": result, "sarif": document}, ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"\n저장: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
