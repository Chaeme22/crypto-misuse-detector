# crypto-misuse-detector

**암호 오용 탐지 시스템** — 저장소를 검사해 암호를 잘못 쓴 자리를 찾고, 국내(KISA)·NIST
표준 문서의 근거 조항을 인용하는 SARIF 보고서를 만든다.

- 입력: GitHub URL 또는 로컬 프로젝트 경로
- 출력: SARIF 2.1.0 보고서 (GitHub Security 탭, IDE에서 파일·줄 단위로 표시되는 표준 형식)

```
$ python -m rag_app.cli analyze https://github.com/javamelody/javamelody --out report.sarif

커밋: e5fa3dcfe74b (master)
사용 지점 18건 → 위반 4건, 확인 필요 1건, 문제없음 13건 (그중 테스트 소스 13건 제외)
  위반 [CRYPTO-HASH-WEAK] .../CounterRequest.java:475  값 확정 · 근거 검수됨
  ...
```

판정 하나를 열어보면 이렇게 나온다:

> 표에 없는 알고리즘: 코드는 SHA-1, 표는 단순해시·전자서명용 해시 표의 어느 보안강도
> 행에도 없다.
> 근거: 암호 알고리즘 및 키 길이 이용 안내서(KISA, 2018), 표 4
> 수정 제안: SHA-256 이상 또는 SHA3-256, LSH-256으로 교체한다.

단순히 위험하다고 알리는 데 그치지 않고, **표준 문서의 어느 표에 따라 어떤 기준에 미달하는지**를 제시한다.

## 표준 근거 지식층

판정 근거를 표준 문서에서 기계가 사용할 수 있는 지식으로 변환하는 층이 시스템의
핵심이다. 세 부분으로 구성된다.

**숫자 기준표 (Tier-1).** KISA 안내서의 표들에서 "112비트 보안강도에는 RSA
2048비트 이상" 같은 숫자 기준 82행을 뽑아냈다. 표마다 목적이 달라(같은 SHA-256도
전자서명용 표와 메시지인증용 표의 기준이 다르다) 자동 수집이 불가능했고, **어느 문서
몇 쪽의 어느 표를 어떤 용도로 읽을지 사람이 지정하는 지도**(`config/threshold_tables.json`)
방식으로 해결했다. 판정의 대부분이 이 표와의 결정적 숫자 비교로 끝난다.

**조항 검색·인용 (Tier-2, RAG).** KISA 안내서 8권 + NIST 3권을 조항 경계로 잘라
하이브리드 색인(의미 벡터 + 어휘)을 만들고, 판정마다 근거 조항을 검색해 인용으로
붙인다. `ARIA-192`와 `ARIA-256`처럼 한 글자가 다른 조항을 갈라야 해서 어휘 검색이
필수였다. **검색은 인용에만 쓰이고 탐지를 촉발하지 않는다** — 검색이 틀려도 판정은
바뀌지 않는 구조다.

**문서 신뢰 공정.** 스캔 PDF의 표 숫자가 판정 기준이 되므로, OCR을 두 엔진 이중
판독으로 돌려 어긋나면 검수 표시를 붙이고, 사람이 원문과 대조해 확정한 보정 목록과
값 셀 전수 감사를 거쳤다. 파싱 결과물마다 사람이 검토한 기록(`data/parsed/*.review.md`)이
남아 있다.

## 동작 원리

```
저장소 받기 → 암호 API 지점 찾기 → 값 역추적 → 기준표와 숫자 비교 → (LLM 역할 판정) → SARIF
```

1. **찾기** — 코드를 문법 분해(tree-sitter)해 암호 API 호출을 찾는다. 주석·문자열
   속 단어에는 반응하지 않는다
2. **값 역추적** — 인자가 변수면 선언·필드·다른 파일의 호출자까지 거꾸로 따라가
   실제 값을 확정한다. 못 찾으면 추측하지 않고 "확인 필요"로 남긴다
   - 키·IV·솔트·비밀번호·시드는 **출처**를 판별한다(`analysis/provenance.py`). 코드에 박힌
     상수면 위반, `SecureRandom`으로 만든 값이면 정상, 외부 입력이거나 경로마다 다르면
     확인 필요다. 조건문 안에서만 난수로 채우는 경우처럼 상수가 남을 수 있으면 정상으로
     닫지 않는다
3. **표와 비교** — 찾은 값을 기준표와 비교한다. 안전하면 여기서 종료(LLM 호출 없음)
4. **LLM 역할 판정(선택)** — 표로 안 갈리는 자리만, 이 줄이 실제 암호 연산인지 /
   알고리즘 이름 목록인지 / 테스트 데이터인지를 판정한다. **숫자 비교·위치·규칙
   번호는 LLM에 맡기지 않는다**
5. **보고** — 코드가 SARIF를 조립한다. 같은 입력이면 바이트까지 같은 보고서가
   나온다(결정성 검증·테스트 고정)

## 정확도

값을 확인하지 못한 자리는 위반으로 단정하지 않고 "확인 요청"으로 사람에게 넘긴다. 아래 재현율은
확인 요청을 **놓침으로 센** 엄격한 값이다.

### 최종 확인 세트 (개발 중 한 번도 보지 않은 세트, 2026-10-12)

정답과 채점 기준을 결과를 보기 전에 `training/eval/final/`에 고정했고, 결과를 본 뒤 도구를 고치지 않았다.
채점기: `tools/final_bench.py`.

| 세트 | 정적 (LLM 없음) | LLM(v2) 포함 |
|---|---|---|
| MASC 최소 예제 (오용 25 · 정상 1) | 탐지 14 · 확인 요청 11 · 놓침 0 · 오탐 0 (재현율 .56) | 탐지 12 · 확인 요청 13 · 놓침 0 · 오탐 0 (.48) |
| MASC 변형 앱 — 안드로이드 10개 (오용 2,298) | 재현율 **1.00** (확인 요청 1) | 측정 예정 |
| MASC 변형 앱 — qpid (오용 17,550) | 재현율 **.99** (확인 요청 124, 놓침 16) | 측정 예정 |
| 변형 전 원본 앱의 오탐 | 0 | 측정 예정 |
| GitHub 보안 권고(GHSA) 수정 커밋 22건 | 넓은 기준 9건(.41) · 엄격 기준 7건(.32) · 확인 요청 4 | 정적과 동일 |

- MASC 변형 앱은 같은 오용(`"DES"`)을 코드의 모든 위치에 넣은 세트라 "빠짐없이 보는가"를 잰다(테스트 경로 블록은 따로 셈).
- GHSA는 저장소 전체가 아니라 수정 커밋이 고친 파일만 검사한다. 22건에는 라이브러리 내부 구현(Bouncy Castle)·프로토콜
  설정처럼 이 도구가 다루지 않는 종류가 섞여 있으나, 결과를 본 뒤 빼지 않고 그대로 셌다.
- 1차 측정이 큰 메서드에서 너무 느려 판정에 영향이 없는 속도 수정 후 다시 쟀다. 연습용 36개 코퍼스에서 모든 판정이
  수정 전과 같음을 확인했다(36/36).

### 연습용 세트 (개발 중 보며 개선한 세트 — 일반화 수치가 아님)

| 세트 | 정적 | 비고 |
|---|---|---|
| CryptoAPI-Bench (오용 155) | 탐지 142, 재현율 .916, 정밀도 .986 | 오탐 2는 벤치 라벨 모순 |
| ApacheCryptoAPI-Bench | 정밀도 .941, 재현율 .857 | v2 정밀도 .960 |
| 실제 GitHub 오용(개발자 확인) | 재현율 .667 | v2 .704 |
| NIST Juliet (5 CWE) | F1 .955 | |
| CamBench | F1 .891 | |

수치와 사례 목록은 `baseline/`, `eval/`에 있다.

## 실행

```bash
conda create -n rag python=3.12 && conda activate rag
pip install -r requirements.txt
export PYTHONPATH=$PWD/src

# 검사 (LLM 없이 — 빠름)
python -m rag_app.cli analyze <URL 또는 경로> --out report.sarif
#   → report.sarif(GitHub 보안 탭·VS Code용) + report.md(사람이 읽는 보고서)
#   --report pdf 로 PDF 보고서(한글 TTF 글꼴 필요, 환경 변수 CRYPTO_REPORT_FONT로 지정 가능), --report none 으로 끔

# 이미 만든 SARIF를 보고서로 변환
python -m rag_app.cli report report.sarif --format pdf

# 검사 (LLM 판정 포함 — GPU 필요)
python -m rag_app.cli analyze <경로> --out report.sarif \
    --llm --llm-model Qwen/Qwen2.5-Coder-7B-Instruct --llm-4bit

# 테스트
python -m pytest tests/unit -q

# 정확도 측정
python tools/benchmark.py /path/to/CryptoAPI-Bench
```

파싱 결과물과 검색 DB(`data/`)가 저장소에 포함돼 있어 별도 준비 없이 실행된다. 원본 PDF는
용량 문제로 제외했다 — [KISA 암호이용활성화](https://seed.kisa.or.kr)와
[NIST CSRC](https://csrc.nist.gov/publications)에서 공개 배포되며, 문서를
추가·개정할 때만 필요하다(절차는 `development_document/인수인계.md` 5절).

## 더 읽을 것

- `development_document/인수인계.md` — 폴더·파일 지도, 실행법, 설계 원칙, 남은 일
- `baseline/README.md` — 파인튜닝 전 기준선과 다시 만드는 법
- `dataset/` — 오용 분류(`misuse_taxonomy.json`), 근거 레지스트리, 스키마. 검증: `python tools/validate_dataset.py`
- `development_document/판정-근거.md` — 판정 설계의 상세 근거 (왜 표가 관문인가,
  왜 확신도 점수를 없앴는가, 왜 값을 못 보면 판정하지 않는가)

## 라이선스

소스 코드는 [MIT License](LICENSE)를 따른다.

`data/`의 파싱 결과물과 검색 색인, `config/tier1_thresholds.json`의 기준값은 한국인터넷진흥원(KISA)과
미국 국립표준기술연구소(NIST)가 공개 배포하는 문서에서 가져왔다. 원 문서의 저작권은 각 발행 기관에 있으며
MIT License의 대상이 아니다. 원문은 [KISA 암호이용활성화](https://seed.kisa.or.kr)와
[NIST CSRC](https://csrc.nist.gov/publications)에서 받을 수 있다.

학습한 어댑터(`adapters/qwen7b-v2`)는 [Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct)
(Apache License 2.0)를 기반으로 한다.
