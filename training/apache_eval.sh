#!/bin/bash
# ApacheCryptoAPI-Bench 채점 (GPU 서버). 정적 / 기본 7B / 기본 7B + 어댑터.
#   bash training/apache_eval.sh runs/qwen7b-pilot-v1 [태그]
set -u
cd ~/crypto-misuse
export PATH=~/miniforge3/envs/train/bin:$PATH PYTHONPATH=src PYTHONIOENCODING=utf-8 \
       PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
ADAPTER=${1:-runs/qwen7b-pilot-v1}
TAG=${2:-v1}
BASE=Qwen/Qwen2.5-Coder-7B-Instruct
ARGS="--bench repos/ApacheCryptoAPI-Bench --src repos/apache-src"
mkdir -p eval logs
rm -f eval/APACHE_DONE_$TAG

python tools/apache_bench.py score $ARGS --out eval/apache-$TAG-static.json > logs/apache-$TAG-static.log 2>&1
python tools/apache_bench.py score $ARGS --llm --llm-backend local --llm-model $BASE --llm-4bit \
  --out eval/apache-$TAG-base.json > logs/apache-$TAG-base.log 2>&1
python tools/apache_bench.py score $ARGS --llm --llm-backend local --llm-model $BASE --llm-4bit \
  --llm-adapter $ADAPTER --out eval/apache-$TAG-adapter.json > logs/apache-$TAG-adapter.log 2>&1
echo FINISHED > eval/APACHE_DONE_$TAG
