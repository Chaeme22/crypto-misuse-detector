#!/bin/bash
# v2 재학습 + 평가 (GPU 서버). 보강 데이터(보안 용도 vs 무관 대조 쌍), 새 프롬프트(non_security 역할).
#   bash training/v2_pipeline.sh
set -u
cd ~/crypto-misuse
export PATH=~/miniforge3/envs/train/bin:$PATH PYTHONPATH=src PYTHONIOENCODING=utf-8 \
       PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
BASE=Qwen/Qwen2.5-Coder-7B-Instruct
RUN=runs/qwen7b-v2
LLM="--llm --llm-backend local --llm-model $BASE --llm-4bit"
mkdir -p eval logs
rm -f eval/V2_DONE
step() { echo "$(date '+%H:%M') $*" >> logs/v2_pipeline.log; }

step "train start"
python training/train_lora.py --train data/v2/train.jsonl --validation data/v2/validation.jsonl \
  --base $BASE --load-4bit --low-vram --targets attn --max-length 1536 --epochs 2 --grad-accum 16 \
  --out $RUN > logs/qwen7b-v2.log 2>&1
step "train done: $(grep -E 'eval_loss|train_loss' $RUN/training_meta.json | tr -d '\n ')"

step "synthetic test"
python tools/eval_sft.py data/v2/test.jsonl --backend hf --model $BASE \
  --manifest data/v2/manifest.jsonl --out eval/v2-synth-base.json > logs/v2-synth-base.log 2>&1
python tools/eval_sft.py data/v2/test.jsonl --backend hf --model $BASE --adapter $RUN \
  --manifest data/v2/manifest.jsonl --out eval/v2-synth-adapter.json > logs/v2-synth-adapter.log 2>&1

step "apache bench"
ARGS="--bench repos/ApacheCryptoAPI-Bench --src repos/apache-src"
python tools/apache_bench.py score $ARGS --out eval/apache-v2-static.json > logs/apache-v2-static.log 2>&1
python tools/apache_bench.py score $ARGS $LLM --out eval/apache-v2-base.json > logs/apache-v2-base.log 2>&1
python tools/apache_bench.py score $ARGS $LLM --llm-adapter $RUN --out eval/apache-v2-adapter.json \
  > logs/apache-v2-adapter.log 2>&1

step "cryptoapi bench"
python tools/baseline.py repos/CryptoAPI-Bench --out eval/cab-v2-static > logs/cab-v2-static.log 2>&1
python tools/baseline.py repos/CryptoAPI-Bench --out eval/cab-v2-base $LLM > logs/cab-v2-base.log 2>&1
python tools/baseline.py repos/CryptoAPI-Bench --out eval/cab-v2-adapter $LLM --llm-adapter $RUN \
  > logs/cab-v2-adapter.log 2>&1

step "all done"
echo FINISHED > eval/V2_DONE
