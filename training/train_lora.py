"""
판정 모델 LoRA 학습 (Colab·Kaggle GPU용, CPU에서 작은 모델로 시험 가능).

입력은 tools/build_dataset.py --export가 만든 train.jsonl·validation.jsonl이다. 한 행은
user(운영 판정 프롬프트 그대로)와 assistant(판정 네 줄) 두 메시지다.

손실은 assistant 토큰에만 준다. 프롬프트까지 외우게 하면 긴 프롬프트가 학습을 지배하고,
모델이 답 형식보다 프롬프트 문장을 따라 쓰는 쪽으로 기운다.

    # Colab T4 (16GB): 7B를 4비트로 올리고 LoRA만 학습
    python training/train_lora.py --train train.jsonl --validation validation.jsonl \
        --base Qwen/Qwen2.5-Coder-7B-Instruct --load-4bit --out adapter-qwen7b

    # 이 PC에서 스크립트 시험 (CPU, 몇 단계만)
    python training/train_lora.py --train dataset/generated/train.jsonl \
        --base Qwen/Qwen2.5-Coder-0.5B-Instruct --max-steps 2 --out scratch-adapter

산출물(--out): adapter_config.json, adapter_model.safetensors, 토크나이저, training_meta.json
(데이터 해시·기본 모델·하이퍼파라미터·평가 손실). 모델 버전을 재현하려면 이 메타가 필요하다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import time
from pathlib import Path


def read_rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def file_sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def encode(tokenizer, row: dict, max_length: int) -> dict | None:
    """
    프롬프트는 운영과 같은 chat template으로 감싼다(Ollama의 qwen2.5-coder 템플릿과 같은 ChatML).
    정답 부분만 labels에 남기고 나머지는 -100으로 가린다.
    """
    user, assistant = row["messages"][0]["content"], row["messages"][1]["content"]
    prompt_ids = tokenizer.apply_chat_template(
        [{"role": "user", "content": user}], tokenize=True, add_generation_prompt=True)
    if hasattr(prompt_ids, "input_ids"):
        prompt_ids = prompt_ids["input_ids"]
    answer_ids = tokenizer(assistant + tokenizer.eos_token, add_special_tokens=False)["input_ids"]
    if len(prompt_ids) + len(answer_ids) > max_length:
        return None  # 잘라 넣으면 정답이 잘리거나 문맥이 빠진다. 빼고 개수를 알린다
    input_ids = list(prompt_ids) + list(answer_ids)
    labels = [-100] * len(prompt_ids) + list(answer_ids)
    return {"input_ids": input_ids, "labels": labels, "attention_mask": [1] * len(input_ids)}


def collate(batch, pad_id: int):
    """
    손실은 정답 토큰에서만 계산하므로 출력층 로짓도 끝부분만 만든다(logits_to_keep).

    로짓은 `길이 × 어휘(15만) × fp32`라서 긴 프롬프트 전체에 만들면 기울기까지 1GB 가까이
    든다. 8GB GPU(RTX 2070)에서 7B 학습이 첫 단계에 여기서 넘쳤다. 라벨도 같은 길이로 잘라
    넘기면 모델의 손실 계산(한 칸 밀기)이 그대로 맞는다. 정답 첫 토큰을 예측하는 프롬프트
    마지막 위치까지 포함하려고 한 칸 더 남긴다.
    """
    import torch
    width = max(len(b["input_ids"]) for b in batch)
    def pad(seq, value):
        return seq + [value] * (width - len(seq))
    labels = torch.tensor([pad(b["labels"], -100) for b in batch])
    first = min(next(i for i, v in enumerate(b["labels"]) if v != -100) for b in batch)
    keep = width - first + 1
    return {
        "input_ids": torch.tensor([pad(b["input_ids"], pad_id) for b in batch]),
        "labels": labels[:, -keep:],
        "attention_mask": torch.tensor([pad(b["attention_mask"], 0) for b in batch]),
        "logits_to_keep": keep,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="판정 모델 LoRA 학습")
    ap.add_argument("--train", type=Path, required=True)
    ap.add_argument("--validation", type=Path)
    ap.add_argument("--base", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--load-4bit", action="store_true", help="QLoRA. CUDA 필요")
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=32)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=16)
    ap.add_argument("--max-length", type=int, default=2048)
    ap.add_argument("--max-steps", type=int, default=-1, help="시험용. 이 단계만 돌고 멈춘다")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--targets", choices=("all", "attn"), default="all",
                    help="LoRA를 붙일 층. attn은 attention만이라 메모리가 적게 든다")
    ap.add_argument("--low-vram", action="store_true",
                    help="8GB급 GPU. 임베딩·출력층을 fp32로 올리지 않는다")
    args = ap.parse_args()

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (AutoModelForCausalLM, AutoTokenizer, Trainer,
                              TrainingArguments, set_seed)

    set_seed(args.seed)
    random.seed(args.seed)
    cuda = torch.cuda.is_available()
    # bf16은 Ampere(계산 능력 8) 이상만 하드웨어로 돈다. RTX 20xx(Turing)에서도 torch는
    # is_bf16_supported()가 True라고 답하지만 에뮬레이션이라 매우 느리다. 세대로 판별한다.
    bf16 = cuda and torch.cuda.get_device_capability(0)[0] >= 8
    if args.load_4bit and not cuda:
        raise SystemExit("--load-4bit는 CUDA GPU가 필요하다. CPU 시험은 작은 모델로 4비트 없이 돌린다")

    tokenizer = AutoTokenizer.from_pretrained(args.base)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def load(path: Path) -> tuple[list[dict], int]:
        encoded, dropped = [], 0
        for row in read_rows(path):
            item = encode(tokenizer, row, args.max_length)
            if item is None:
                dropped += 1
            else:
                encoded.append(item)
        return encoded, dropped

    train, train_dropped = load(args.train)
    valid, valid_dropped = load(args.validation) if args.validation else ([], 0)
    print(f"학습 {len(train)}건 (길이 초과 제외 {train_dropped}) · 검증 {len(valid)}건 "
          f"(제외 {valid_dropped})", flush=True)

    kwargs: dict = {}
    if args.load_4bit:
        from transformers import BitsAndBytesConfig
        compute = torch.bfloat16 if bf16 else torch.float16
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute)
        kwargs["device_map"] = "auto"
    else:
        # CPU는 bf16 가속이 없으면 매우 느리다(이 프로젝트 PC에서 실측). fp32로 올린다.
        kwargs["dtype"] = torch.float16 if cuda else torch.float32
    model = AutoModelForCausalLM.from_pretrained(args.base, **kwargs)
    if args.load_4bit and not args.low_vram:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    else:
        # prepare_model_for_kbit_training은 양자화하지 않은 임베딩·출력층을 fp32로 올린다.
        # Qwen 7B는 어휘가 15만이라 이 두 층만 fp32로 4GB가 넘어 8GB GPU에서 넘쳤다(RTX 2070
        # 실측). 저메모리 모드는 그 단계를 빼고 작은 정규화 층만 fp32로 둔다.
        if args.load_4bit:
            for name, param in model.named_parameters():
                param.requires_grad = False
                if "norm" in name and param.dtype in (torch.float16, torch.bfloat16):
                    param.data = param.data.float()
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    targets = ["q_proj", "k_proj", "v_proj", "o_proj"]
    if args.targets == "all":
        targets += ["gate_proj", "up_proj", "down_proj"]
    model = get_peft_model(model, LoraConfig(
        r=args.rank, lora_alpha=args.alpha, lora_dropout=args.dropout, task_type="CAUSAL_LM",
        target_modules=targets))
    model.print_trainable_parameters()

    fp16 = cuda and not bf16
    # warmup_ratio는 transformers 5에서 없어졌다. 단계 수를 직접 계산해 4·5 모두에서 돌게 한다.
    total_steps = (args.max_steps if args.max_steps > 0 else
                   math.ceil(len(train) / (args.batch * args.grad_accum) * args.epochs))
    training_args = TrainingArguments(
        output_dir=str(args.out / "checkpoints"), num_train_epochs=args.epochs,
        max_steps=args.max_steps, learning_rate=args.lr, lr_scheduler_type="cosine",
        warmup_steps=max(1, int(total_steps * 0.05)), per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch, gradient_accumulation_steps=args.grad_accum,
        logging_steps=1 if args.max_steps > 0 else 10, save_strategy="epoch" if args.max_steps < 0 else "no", save_total_limit=2,
        eval_strategy="epoch" if valid and args.max_steps < 0 else "no",
        bf16=bf16, fp16=fp16,
        gradient_checkpointing=True, report_to=[], seed=args.seed, data_seed=args.seed,
        remove_unused_columns=False, use_cpu=not cuda)
    trainer = Trainer(model=model, args=training_args, train_dataset=train,
                      eval_dataset=valid or None,
                      data_collator=lambda batch: collate(batch, tokenizer.pad_token_id))
    started = time.time()
    result = trainer.train()
    metrics = trainer.evaluate() if valid and args.max_steps < 0 else {}

    args.out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(args.out))
    tokenizer.save_pretrained(str(args.out))
    meta = {
        "base_model": args.base, "load_4bit": args.load_4bit,
        "train_file": args.train.name, "train_sha256": file_sha(args.train),
        "validation_file": args.validation.name if args.validation else None,
        "validation_sha256": file_sha(args.validation) if args.validation else None,
        "train_examples": len(train), "train_dropped_too_long": train_dropped,
        "hyperparameters": {k: v for k, v in vars(args).items()
                            if k in ("epochs", "lr", "rank", "alpha", "dropout", "batch",
                                     "grad_accum", "max_length", "max_steps", "seed",
                                     "targets", "low_vram")},
        "train_loss": result.training_loss,
        "eval_loss": metrics.get("eval_loss"),
        "eval_perplexity": math.exp(metrics["eval_loss"]) if "eval_loss" in metrics else None,
        "seconds": round(time.time() - started, 1),
        "device": torch.cuda.get_device_name(0) if cuda else "cpu",
        "peak_vram_gb": round(torch.cuda.max_memory_allocated() / 2**30, 2) if cuda else None,
    }
    (args.out / "training_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
