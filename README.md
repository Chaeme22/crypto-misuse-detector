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

"이거 위험해요"가 아니라 **"표준 문서 몇 쪽 어느 표에 따르면 이 값은 기준 미달"**을 말한다.

## 표준 근거 지식층 — 이 시스템의 심장

판정 근거를 표준 문서에서 기계가 믿고 쓸 수 있는 지식으로 바꾸는 층이 시스템의
중심이다. 세 갈래로 만들어져 있다.

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
   속 단어에는 안 속는다
2. **값 역추적** — 인자가 변수면 선언·필드·다른 파일의 호출자까지 거꾸로 따라가
   실제 값을 확정한다. 못 찾으면 추측하지 않고 "확인 필요"로 남긴다
3. **표와 비교** — 찾은 값을 기준표와 비교한다. 안전하면 여기서 종료(LLM 호출 없음)
4. **LLM 역할 판정(선택)** — 표로 안 갈리는 자리만, 이 줄이 실제 암호 연산인지 /
   알고리즘 이름 목록인지 / 테스트 데이터인지를 판정한다. **숫자 비교·위치·규칙
   번호는 LLM에 맡기지 않는다**
5. **보고** — 코드가 SARIF를 조립한다. 같은 입력이면 바이트까지 같은 보고서가
   나온다(결정성 검증·테스트 고정)

## 정확도

공개 벤치마크 CryptoAPI-Bench(자바 오용 155건) 기준:

| 판정 경로 | 확정 경보 | 오탐 | 확인 요청 | 정밀도 |
|---|---|---|---|---|
| 정적 (LLM 없음) | 44 | 0 | 58 | 1.000 |
| LLM 판정 포함 | 48 | 0 | 46 | 1.000 |

값을 확인하지 못한 자리는 위반으로 단정하지 않고 "확인 요청"으로 사람에게 넘긴다.
놓친 53건 중 51건은 아직 규칙이 없는 유형(솔트·시드·PBE 반복 횟수 등)이다.

## 실행

```bash
conda create -n rag python=3.12 && conda activate rag
pip install -r requirements.txt
export PYTHONPATH=$PWD/src

# 검사 (LLM 없이 — 빠름)
python -m rag_app.cli analyze <URL 또는 경로> --out report.sarif

# 검사 (LLM 판정 포함 — GPU 필요)
python -m rag_app.cli analyze <경로> --out report.sarif \
    --llm --llm-model Qwen/Qwen2.5-Coder-7B-Instruct --llm-4bit

# 테스트
python -m pytest tests/unit -q

# 정확도 측정
python tools/benchmark.py /path/to/CryptoAPI-Bench
```

파싱 결과물과 검색 DB(`data/`)가 저장소에 포함돼 있어 바로 돌아간다. 원본 PDF는
용량 문제로 제외했다 — [KISA 암호이용활성화](https://seed.kisa.or.kr)와
[NIST CSRC](https://csrc.nist.gov/publications)에서 공개 배포되며, 문서를
추가·개정할 때만 필요하다(절차는 `development_document/인수인계.md` 5절).

## 더 읽을 것

- `development_document/인수인계.md` — 폴더·파일 지도, 실행법, 설계 원칙, 남은 일
- `development_document/판정-근거.md` — 판정 설계의 상세 근거 (왜 표가 관문인가,
  왜 확신도 점수를 없앴는가, 왜 값을 못 보면 판정하지 않는가)
