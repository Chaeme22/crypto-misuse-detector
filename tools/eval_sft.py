"""
판정 모델을 SFT 평가셋(test.jsonl)으로 잰다. 기본 모델과 학습한 모델을 같은 잣대로 비교한다.

운영 판정과 같은 방식으로 부른다: 프롬프트 그대로, 온도 0, 시드 0, 같은 parser. 다만
enforce()는 적용하지 않는다. 값을 못 본 자리는 운영에서 모델 답과 상관없이 보류로 덮이므로,
그것까지 넣으면 모델이 나아졌는지가 가려진다. 모델 자체의 판정을 본다.

    python tools/eval_sft.py dataset/generated/test.jsonl --model qwen2.5-coder:7b

    # GPU 서버 (transformers 4비트, 학습과 같은 설정으로 기본 모델과 어댑터를 비교)
    python tools/eval_sft.py test.jsonl --backend hf --model Qwen/Qwen2.5-Coder-7B-Instruct
    python tools/eval_sft.py test.jsonl --backend hf --model Qwen/Qwen2.5-Coder-7B-Instruct         --adapter runs/qwen7b-pilot-v1
    python tools/eval_sft.py dataset/generated/test.jsonl --model crypto-verdict:qwen7b-v1 \\
        --out eval/qwen7b-v1.json

지표: 형식 준수율, 판정 정확도, 판정별 정밀도·재현율·F1, 역할 정확도, 규칙·문맥 깊이별 정확도,
그리고 가장 나쁜 실패인 "정답이 판정 보류인데 위반·정상으로 단정한 비율".
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rag_app.analysis.verdict import _parse  # noqa: E402

DECISIONS = ("violation", "clean", "undetermined")


def _gold(row: dict):
    return _parse(row["messages"][1]["content"])


def score(records: list[dict]) -> dict:
    total = len(records)
    parsed = [r for r in records if r["predicted"] is not None]
    correct = [r for r in parsed if r["predicted"]["decision"] == r["gold"]["decision"]]
    by_class = {}
    for name in DECISIONS:
        tp = sum(1 for r in parsed if r["predicted"]["decision"] == name and r["gold"]["decision"] == name)
        fp = sum(1 for r in parsed if r["predicted"]["decision"] == name and r["gold"]["decision"] != name)
        fn = sum(1 for r in records if r["gold"]["decision"] == name
                 and (r["predicted"] is None or r["predicted"]["decision"] != name))
        p = tp / (tp + fp) if tp + fp else 0.0
        rc = tp / (tp + fn) if tp + fn else 0.0
        by_class[name] = {"precision": round(p, 3), "recall": round(rc, 3),
                          "f1": round(2 * p * rc / (p + rc), 3) if p + rc else 0.0,
                          "support": tp + fn}
    gold_undetermined = [r for r in records if r["gold"]["decision"] == "undetermined"]
    guessed = [r for r in gold_undetermined if r["predicted"] is not None
               and r["predicted"]["decision"] != "undetermined"]

    def accuracy_by(key) -> dict:
        groups: dict[str, list] = defaultdict(list)
        for r in records:
            groups[str(key(r))].append(r)
        return {k: round(sum(1 for r in v if r["predicted"] is not None and
                             r["predicted"]["decision"] == r["gold"]["decision"]) / len(v), 3)
                for k, v in sorted(groups.items())}

    return {
        "examples": total,
        "format_ok": round(len(parsed) / total, 3) if total else 0.0,
        "decision_accuracy": round(len(correct) / total, 3) if total else 0.0,
        "macro_f1": round(sum(c["f1"] for c in by_class.values()) / len(by_class), 3),
        "per_decision": by_class,
        "role_accuracy": round(sum(1 for r in parsed if r["predicted"]["role"] == r["gold"]["role"])
                               / total, 3) if total else 0.0,
        "guessed_when_undetermined": round(len(guessed) / len(gold_undetermined), 3)
        if gold_undetermined else None,
        "accuracy_by_rule": accuracy_by(lambda r: r["rule_id"]),
        "accuracy_by_depth": accuracy_by(lambda r: r["depth"]),
        "confusion": dict(Counter(f"{r['gold']['decision']}->"
                                  f"{r['predicted']['decision'] if r['predicted'] else 'FORMAT'}"
                                  for r in records)),
    }


def ollama_asker(model: str):
    from rag_app.config.loader import load_config
    from rag_app.domain.models import GenerationRequest
    from rag_app.models.llm import make_verdict_model

    llm = make_verdict_model(load_config(), "ollama", model)

    def ask(prompt: str) -> str:
        result = llm.generate(GenerationRequest(question=prompt, max_tokens=512,
                                                temperature=0.0, seed=0))
        return getattr(result, "answer", "") or ""
    return ask


def hf_asker(model_id: str, adapter: Path | None, load_4bit: bool):
    """
    학습과 같은 방식(4비트 nf4, chat template, 탐욕 디코딩)으로 부른다. 기본 모델과 어댑터를
    같은 조건에서 재야 차이가 학습에서만 온다.
    """
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    kwargs: dict = {"device_map": "auto"}
    if load_4bit:
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16)
    else:
        kwargs["dtype"] = torch.float16
    model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
    if adapter is not None:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, str(adapter))
    model.eval()

    def ask(prompt: str) -> str:
        ids = tokenizer.apply_chat_template([{"role": "user", "content": prompt}],
                                            add_generation_prompt=True, return_tensors="pt")
        if hasattr(ids, "input_ids"):
            ids = ids["input_ids"]
        ids = ids.to(model.device)
        with torch.no_grad():
            out = model.generate(ids, attention_mask=torch.ones_like(ids), max_new_tokens=256,
                                 do_sample=False, pad_token_id=tokenizer.eos_token_id)
        return tokenizer.decode(out[0, ids.shape[1]:], skip_special_tokens=True).strip()
    return ask


def main() -> int:
    ap = argparse.ArgumentParser(description="판정 모델을 SFT 평가셋으로 잰다")
    ap.add_argument("data", type=Path)
    ap.add_argument("--model", required=True, help="Ollama 태그 또는 (hf) HF 모델 이름")
    ap.add_argument("--backend", choices=("ollama", "hf"), default="ollama")
    ap.add_argument("--adapter", type=Path, help="(hf) PEFT 어댑터 폴더")
    ap.add_argument("--no-4bit", action="store_true", help="(hf) 4비트로 올리지 않는다")
    ap.add_argument("--manifest", type=Path, default=ROOT / "dataset" / "generated" / "manifest.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="앞에서 N건만 (시험용)")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    rows = [json.loads(l) for l in args.data.read_text(encoding="utf-8").splitlines() if l.strip()]
    if args.limit:
        rows = rows[:args.limit]
    manifest = {}
    if args.manifest.exists():
        for line in args.manifest.read_text(encoding="utf-8").splitlines():
            if line.strip():
                m = json.loads(line)
                manifest[m["example_id"]] = m

    ask = (hf_asker(args.model, args.adapter, not args.no_4bit) if args.backend == "hf"
           else ollama_asker(args.model))
    records = []
    started = time.time()
    for i, row in enumerate(rows, 1):
        answer = ask(row["messages"][0]["content"])
        predicted = _parse(answer)
        gold = _gold(row)
        m = manifest.get(row["example_id"], {})
        records.append({
            "example_id": row["example_id"], "rule_id": m.get("rule_id"),
            "depth": m.get("context_depth_available"),
            "gold": {"decision": gold.decision.value, "role": gold.role},
            "predicted": None if predicted is None else
            {"decision": predicted.decision.value, "role": predicted.role},
            "answer": answer[:400],
        })
        if i % 10 == 0 or i == len(rows):
            print(f"  {i}/{len(rows)} ({time.time() - started:.0f}s)", flush=True)

    report = {"model": args.model, "backend": args.backend,
              "adapter": str(args.adapter) if args.adapter else None, "data": str(args.data.name), "seconds": round(time.time() - started),
              **score(records)}
    print(json.dumps({k: v for k, v in report.items() if k != "records"}, ensure_ascii=False, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({**report, "records": records}, ensure_ascii=False, indent=2)
                            + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
