# crypto-misuse-detector

Java 암호 API 오용 정적 탐지 도구. KISA·NIST 기준에 따라 판정하고 근거 조항을 함께 보고한다.

- 입력: GitHub 저장소 URL 또는 로컬 디렉터리
- 출력: SARIF 2.1.0, Markdown/PDF 보고서
- 판정 기준: KISA 「암호 알고리즘 및 키 길이 이용 안내서」(보안강도 최소 112비트, 권장 128비트), NIST SP 800-38A·57·131A·132

## 탐지 규칙

| 규칙 | CWE | 대상 |
|---|---|---|
| CRYPTO-MODE-ECB | 327 | ECB 운영모드, 모드 미지정(`"AES"`) |
| CRYPTO-CIPHER-OBSOLETE | 327 | DES, RC4, Blowfish |
| CRYPTO-HASH-WEAK | 328 | MD5, SHA-1(전자서명·단순 해시) |
| CRYPTO-KEYSIZE-SHORT | 326 | 보안강도 112비트 미만 키 길이 |
| CRYPTO-KEY-HARDCODED | 321 | 상수 대칭키 |
| CRYPTO-PASSWORD-HARDCODED | 798 | 상수 키 유도 비밀번호 |
| CRYPTO-IV-STATIC | 329 | 고정·예측 가능 IV |
| CRYPTO-SALT-STATIC | 760 | 고정 솔트 |
| CRYPTO-RNG-INSECURE | 330 | 보안 용도의 `java.util.Random` |
| CRYPTO-SEED-PREDICTABLE | 337 | 고정 시드 `SecureRandom` |
| CRYPTO-KDF-WEAK | 916 | PBKDF2 반복 횟수 1,000회 미만 |

지원 범위: JCA, KISA 참조 구현(SEED·ARIA), Hutool, 국산 알고리즘(SEED·ARIA·LEA·HIGHT·LSH·HAS-160).

| 판정 | 조건 | SARIF level |
|---|---|---|
| 위반 | 기준 미달, 상수·예측 가능 값 | error |
| 경고 | 보안강도 112비트(2030년 이후 사용 불가) | warning |
| 확인 필요 | 값이 저장소 외부에서 결정되거나 경로별로 상이 | note |
| 정상 | 기준 충족 | — |

## 구성

```
코드 수집 → 암호 API 사용 지점 추출 → 값 출처 추적 → KISA 기준표 비교 → 용도 판단(선택) → 보고서
```

| 단계 | 내용 |
|---|---|
| 사용 지점 추출 | tree-sitter 구문 분석 |
| 값 출처 추적 | 키·IV·솔트·시드·알고리즘 이름의 출처를 상수, 예측 가능, 약한 난수, 안전한 난수, 외부 입력, 미확인으로 분류. 흐름·문맥·경로·객체·필드·파일 간 추적 |
| 기준표 비교 | KISA 안내서 표 2·3·4·6을 용도별로 정리한 82행(`config/tier1_thresholds.json`) |
| 용도 판단 | 기준표로 결정되지 않는 지점에 한해 Qwen2.5-Coder-7B-Instruct + LoRA 어댑터(`adapters/qwen7b-v2`) 사용. 로컬 실행 |
| 검증 | 값이 확인되지 않은 판정은 '확인 필요'로 처리, 테스트 소스 제외 |
| 근거 인용 | KISA 안내서 8종·NIST 문서 3종의 조항 색인(`data/`). 판정에는 사용하지 않음 |

## 설치

```bash
conda create -n crypto python=3.12 && conda activate crypto
pip install -r requirements.txt
export PYTHONPATH=$PWD/src

python -m rag_app.cli setup    # 선택: 용도 판단 모델 등록(Ollama 필요)
```

## 사용법

```bash
python -m rag_app.cli analyze <URL|DIR> --out report.sarif     # SARIF + Markdown
python -m rag_app.cli analyze <DIR> --report pdf               # PDF 보고서
python -m rag_app.cli analyze <DIR> --no-llm                   # 정적 판정만
python -m rag_app.cli report report.sarif --format pdf         # SARIF 변환
```

| 옵션·환경 변수 | 설명 |
|---|---|
| `--report {md,pdf,none}` | 보고서 형식(기본 md) |
| `--llm`, `--no-llm` | 용도 판단 모델 사용 강제·해제(기본 자동 감지) |
| `--no-clauses` | 근거 조항 인용 생략 |
| `OLLAMA_HOST` | Ollama 서버 주소 |
| `CRYPTO_REPORT_FONT` | PDF용 한글 글꼴 경로 |

```
위반 [CRYPTO-HASH-WEAK] CounterRequest.java:475
  코드는 SHA-1, 단순해시·전자서명용 해시 표의 어느 보안강도 행에도 없음
  근거: 암호 알고리즘 및 키 길이 이용 안내서(KISA, 2018), 표 4
  수정: SHA-256 이상 또는 SHA3-256, LSH-256
```

## 평가

재현율 계산 시 '확인 필요'는 미탐으로 집계하였다.

### 보류 평가 세트

개발 과정에서 사용하지 않은 세트. 정답과 채점 기준은 측정 전에 확정하였다(`training/eval/final/`).

| 세트 | 정적 판정 | 용도 판단 포함 |
|---|---|---|
| MASC minimal (오용 25, 정상 1) | TP 14, 확인 필요 11, FN 0, FP 0 | TP 12, 확인 필요 13, FN 0, FP 0 |
| MASC exhaustive — Android 10종 (2,298) | Recall 1.00 | — |
| MASC exhaustive — Apache Qpid (17,550) | Recall 0.99 | — |
| MASC 변형 전 원본 | FP 0 | — |
| GHSA 암호 취약점 수정 커밋 (22) | 9건 탐지 | 9건 탐지 |

### 개발 평가 세트

| 벤치마크 | 결과 | 비교 도구 |
|---|---|---|
| CryptoAPI-Bench (155) | Recall 0.916, Precision 0.986 | — |
| ApacheCryptoAPI-Bench | Precision 0.941 (용도 판단 포함 0.960), Recall 0.857 | CryptoGuard F1 0.773 |
| GitHub 실제 오용 (27) | Recall 0.667 (용도 판단 포함 0.704) | Semgrep Recall 0.111 |
| NIST Juliet | F1 0.955 | CryptoGuard 0.924 |
| CamBench | F1 0.891 | CogniCrypt 0.833 |
| OWASP Benchmark (975) | F1 1.0 | CryptoGuard 0.929 |

## 제한 사항

- 분석 대상 언어는 Java이며 Python은 기본 규칙만 지원한다.
- 저장소 외부(설정 서버, 배포 환경)에서 결정되는 값은 판정하지 않는다.
- TLS, 인증서 검증 등 프로토콜 수준의 오용은 범위에 포함하지 않는다.

## 디렉터리

```
src/rag_app/analysis/   추출, 값 출처 추적, 기준표 비교, 판정, 보고서
config/                 탐지 규칙, KISA 기준표
data/                   KISA·NIST 문서 파싱 결과 및 조항 색인
adapters/qwen7b-v2/     LoRA 어댑터(GGUF)
dataset/                오용 분류 체계, 근거 레지스트리, 학습 데이터
training/               학습 스크립트, 평가 결과
tools/                  벤치마크 및 평가 도구
tests/unit/             단위 테스트
```

## 라이선스

- 소스 코드: [MIT](LICENSE)
- `data/`, `config/tier1_thresholds.json`: KISA·NIST 공개 문서에서 추출하였으며 원 문서의 저작권은 각 발행 기관에 있다([KISA](https://seed.kisa.or.kr), [NIST CSRC](https://csrc.nist.gov/publications)).
- 어댑터: [Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct)(Apache 2.0) 기반
