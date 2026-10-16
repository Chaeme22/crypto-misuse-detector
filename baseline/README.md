# 파인튜닝 전 기준선

파인튜닝한 모델이 나아졌는지 비교하려고 학습 전 성능을 고정해 둔 파일이다.
`tools/baseline.py`가 만든다. 같은 코드와 같은 입력이면 같은 파일이 나온다.
시각은 넣지 않고, 무엇으로 쟀는지는 각 파일의 `meta`에 적힌다.

| 파일 | 내용 | 상태 |
|---|---|---|
| `rule_engine.json` | LLM 없이 규칙·기준표만으로 낸 지점별 판정 (CryptoAPI-Bench 178 지점) | 생성됨 |
| `cryptoapi_bench.json` | 벤치마크 채점 + 사례 목록 (`missed`, `review_only`, `wrong_rule`, `false_positive`) | 생성됨 |
| `coverage.json` | 언어별 추출 능력, 규칙별 트리거와 지원 언어 | 생성됨 |
| `prompt_only.json` | 파인튜닝 전 LLM의 지점별 판정과 채점 | **GPU 서버에서 생성 필요** |

## 만드는 법

```bash
export PYTHONPATH=$PWD/src
git clone --depth 1 https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git /tmp/CryptoAPI-Bench

# 정적 기준선 (GPU 불필요)
python tools/baseline.py /tmp/CryptoAPI-Bench --out baseline

# LLM 기준선 — GPU 없는 PC (Ollama, CPU로 약 1시간). 먼저 `ollama serve`
python tools/baseline.py /tmp/CryptoAPI-Bench --out baseline --llm \
    --llm-backend ollama --llm-model qwen2.5-coder:7b

# LLM 기준선 — GPU 서버 (transformers 4비트)
python tools/baseline.py /tmp/CryptoAPI-Bench --out baseline --llm \
    --llm-model Qwen/Qwen2.5-Coder-7B-Instruct --llm-4bit
```

## 읽을 때 주의

- `meta.detector_dirty`가 `true`이면 커밋하지 않은 변경이 있는 상태에서 잰 것이다.
  재현하려면 커밋한 뒤 다시 만든다.
- `meta.rules_sha256`이 현재 `config/tier1_rules.json`과 다르면 규칙이 바뀐 뒤다. 비교하기
  전에 기준선을 다시 만들지, 옛 기준선과 비교할지 정한다.
- CryptoAPI-Bench는 규칙 개발 중에 이미 미탐 분석에 써 왔다. 엄밀한 외부 평가셋이 아니다.
- 정적 경로의 정밀도 1.000은 확정 경보 기준이다. 확인 요청(`review`)은 정밀도 계산에서 뺀다.
