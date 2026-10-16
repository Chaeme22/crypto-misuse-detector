#!/bin/bash
# 실제 코드에서 판정 모델 비교 (GPU 서버). 정적 판정 / 기본 모델 / 기본 모델 + 어댑터.
#   bash training/real_eval.sh runs/qwen7b-pilot-v1
# 결과: runs/real/<이름>/ (CryptoAPI-Bench 기준선 JSON), runs/real/<이름>-<저장소>.sarif·.log
set -u
cd ~/crypto-misuse
export PYTHONPATH=src PYTHONIOENCODING=utf-8 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
P=~/miniforge3/envs/train/bin/python
ADAPTER=${1:-runs/qwen7b-pilot-v1}
BASE=Qwen/Qwen2.5-Coder-7B-Instruct
OUT=runs/real
mkdir -p $OUT logs
rm -f $OUT/DONE

run_all() {   # $1=이름, 나머지=판정 옵션
  local name=$1; shift
  $P tools/baseline.py repos/CryptoAPI-Bench --out $OUT/$name "$@" > logs/real-$name-bench.log 2>&1
  for repo in javamelody shiro; do
    $P -m rag_app.cli analyze repos/$repo --no-clauses --out $OUT/$name-$repo.sarif \
      $( [ "$name" = static ] || echo --llm --llm-backend local --llm-model $BASE --llm-4bit ) \
      $( [ "$name" = adapter ] && echo --llm-adapter $ADAPTER ) > $OUT/$name-$repo.log 2>&1
  done
}

run_all static
run_all base --llm --llm-backend local --llm-model $BASE
run_all adapter --llm --llm-backend local --llm-model $BASE --llm-adapter $ADAPTER
echo FINISHED > $OUT/DONE
