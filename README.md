# crypto-misuse-detector

Java 코드의 암호 API 오용을 찾아 KISA·NIST 기준 근거와 함께 보고하는 CLI 도구.

- 입력: GitHub 저장소 URL 또는 로컬 폴더
- 출력: SARIF 2.1.0 + Markdown/PDF 보고서
- 기준: KISA 「암호 알고리즘 및 키 길이 이용 안내서」 보안강도(최소 112비트, 권장 128비트), NIST SP 800-38A/57/131A/132

## 탐지 항목

| 규칙 | CWE | 예 |
|---|---|---|
| CRYPTO-MODE-ECB | 327 | `"AES/ECB/..."`, 모드 생략 `"AES"` |
| CRYPTO-CIPHER-OBSOLETE | 327 | DES, RC4, Blowfish |
| CRYPTO-HASH-WEAK | 328 | MD5, SHA-1(서명·단순 해시) |
| CRYPTO-KEYSIZE-SHORT | 326 | RSA 1024 |
| CRYPTO-KEY-HARDCODED | 321 | `new SecretKeySpec("key".getBytes(), "AES")` |
| CRYPTO-PASSWORD-HARDCODED | 798 | 상수 비밀번호로 `PBEKeySpec` |
| CRYPTO-IV-STATIC | 329 | `new IvParameterSpec(new byte[16])` |
| CRYPTO-SALT-STATIC | 760 | 상수 솔트 |
| CRYPTO-RNG-INSECURE | 330 | 보안 값에 `java.util.Random` |
| CRYPTO-SEED-PREDICTABLE | 337 | 고정 시드 `SecureRandom` |
| CRYPTO-KDF-WEAK | 916 | PBKDF2 반복 1,000회 미만 |

KISA 참조 구현(`KISA_SEED_CBC`, `KISA_SEED_ECB`, ARIA 래퍼), Hutool 래퍼, 국산 알고리즘(SEED·ARIA·LEA·HIGHT·LSH)을 포함한다.

판정은 네 가지다.

| 판정 | 뜻 | SARIF level |
|---|---|---|
| 위반 | 기준 미달, 상수 키·IV 등 | error |
| 경고 | 112비트(SEED, 3DES, RSA-2048 등) — 2030년 이후 교체 대상 | warning |
| 확인 필요 | 값이 코드 밖에서 오거나 경로마다 다름 | note |
| 정상 | 보고하지 않음 | — |

## 동작

```
코드 받기 → 암호 API 지점 찾기 → 값 출처 추적 → KISA 기준표 비교 → (AI 용도 판단) → 보고서
```

- **지점 찾기**: tree-sitter 구문 분석. 주석·문자열 속 단어는 무시
- **값 출처 추적**: 키·IV·솔트·시드·알고리즘 이름을 선언·필드·다른 파일 호출자·설정 파일까지 역추적.
  상수 / 예측 가능 / 약한 난수 / 안전한 난수 / 외부 입력 / 모름으로 분류 (`src/rag_app/analysis/provenance.py`)
- **기준표 비교**: KISA 안내서 표를 용도별(대칭키·해시·MAC·공개키)로 정리한 82행 (`config/tier1_thresholds.json`)
- **AI 용도 판단(선택)**: 기준표로 결론이 안 나는 자리만. Qwen2.5-Coder-7B + LoRA 어댑터(`adapters/qwen7b-v2`, 19MB), 로컬 실행
- **안전장치**: 값이 확인되지 않은 판정은 '확인 필요'로 되돌림, 테스트 코드 제외
- **근거 인용**: KISA 8권·NIST 3권 조항 색인(`data/`)에서 근거 조항 첨부. 인용에만 쓰고 판정에는 쓰지 않음
- 같은 입력이면 같은 보고서

## 설치

```bash
conda create -n crypto python=3.12 && conda activate crypto
pip install -r requirements.txt
export PYTHONPATH=$PWD/src            # Windows PowerShell: $env:PYTHONPATH="$PWD\src"

# AI 용도 판단을 쓰려면 (선택, Ollama 필요)
python -m rag_app.cli setup
```

## 사용

```bash
python -m rag_app.cli analyze <URL 또는 폴더> --out report.sarif   # report.sarif + report.md
python -m rag_app.cli analyze <폴더> --report pdf                   # PDF 보고서
python -m rag_app.cli analyze <폴더> --no-llm                       # AI 없이(빠름, CI)
python -m rag_app.cli report report.sarif --format pdf              # SARIF → PDF 변환
```

| 옵션 | 설명 |
|---|---|
| `--report md\|pdf\|none` | 사람이 읽는 보고서 형식(기본 md) |
| `--no-llm` / `--llm` | AI 판단 끄기 / 강제. 기본은 설치돼 있으면 사용 |
| `--no-clauses` | 근거 조항 인용 생략 |
| `OLLAMA_HOST` | Ollama 주소 |
| `CRYPTO_REPORT_FONT` | PDF 한글 글꼴 경로(기본: 맑은 고딕, Nanum, Noto CJK 자동 탐색) |

보고서 예:

```
위반 [약한 해시] CounterRequest.java:475
  판정: 코드는 SHA-1, 단순해시·전자서명용 해시 표의 어느 보안강도 행에도 없다.
  근거: 암호 알고리즘 및 키 길이 이용 안내서(KISA, 2018), 표 4
  수정: SHA-256 이상 또는 SHA3-256, LSH-256으로 교체
```

## 성능

재현율은 '확인 필요'를 놓침으로 센 값.

**최종 확인 세트** — 개발 중 보지 않음. 정답·채점 기준을 측정 전에 고정(`training/eval/final/`), 측정 후 수정 없음.

| 세트 | 정적 | AI 포함 |
|---|---|---|
| MASC 최소 예제 (오용 25, 정상 1) | 탐지 14, 확인 필요 11, 놓침 0, 오탐 0 | 탐지 12, 확인 필요 13, 놓침 0, 오탐 0 |
| MASC 변형 앱 — 안드로이드 (2,298) | 재현율 1.00 | 측정 예정 |
| MASC 변형 앱 — Apache qpid (17,550) | 재현율 0.99 | 측정 예정 |
| MASC 변형 전 원본 | 오탐 0 | 측정 예정 |
| GHSA 암호 취약점 수정 22건 | 9건 탐지 | 정적과 동일 |

**공개 벤치마크** — 개발 중 보며 개선(일반화 수치 아님).

| 벤치마크 | 결과 | 비교 |
|---|---|---|
| CryptoAPI-Bench (155) | 재현율 0.916, 정밀도 0.986 | — |
| ApacheCryptoAPI-Bench | 정밀도 0.941(AI 0.960), 재현율 0.857 | CryptoGuard F1 0.773 |
| 실제 GitHub 오용 (27) | 재현율 0.667(AI 0.704) | Semgrep 0.111 |
| NIST Juliet | F1 0.955 | CryptoGuard 0.924 |
| CamBench | F1 0.891 | CogniCrypt 0.833 |
| OWASP Benchmark (975) | F1 1.0 | CryptoGuard 0.929 |

## 한계

- Java 중심(Python은 기본 규칙만)
- 저장소 밖(설정 서버·배포 환경)의 값은 '확인 필요'
- TLS·인증서 검증 등 프로토콜 수준 오용은 범위 밖

## 구조

```
src/rag_app/analysis/   추출·값 추적·기준표 비교·판정·SARIF/보고서
config/                 규칙(tier1_rules.json), KISA 기준표(tier1_thresholds.json)
data/                   KISA·NIST 파싱 결과, 조항 검색 색인
adapters/qwen7b-v2/     AI 판단용 LoRA 어댑터(GGUF)
dataset/                오용 분류, 근거 레지스트리, 학습 데이터
training/               학습 스크립트, 평가 결과
tools/                  벤치마크·평가 도구
tests/unit/             단위 테스트
```

## 테스트

```bash
python -m pytest tests/unit -q
```

## 라이선스

- 소스 코드: [MIT](LICENSE)
- `data/`, `config/tier1_thresholds.json`: KISA·NIST 공개 문서에서 추출. 원 문서 저작권은 각 발행 기관에 있으며 MIT 대상이 아님
  ([KISA 암호이용활성화](https://seed.kisa.or.kr), [NIST CSRC](https://csrc.nist.gov/publications))
- 어댑터: [Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct)(Apache 2.0) 기반
