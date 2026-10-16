# 합성 데이터 통계

- 샘플 1752건 (운영에서 모델에게 묻지 않아 뺀 것 258건)
- 검토 상태: {'needs_review': 1752}
- 분할: {'test': 354, 'train': 1062, 'validation': 336}
- 정적 판정과 일치: {'pass': 1650, 'disagree': 102}

## 규칙

| 값 | 개수 |
|---|---|
| CRYPTO-CIPHER-OBSOLETE | 112 |
| CRYPTO-HASH-WEAK | 252 |
| CRYPTO-IV-STATIC | 180 |
| CRYPTO-KDF-WEAK | 180 |
| CRYPTO-KEY-HARDCODED | 180 |
| CRYPTO-KEYSIZE-SHORT | 80 |
| CRYPTO-MODE-ECB | 180 |
| CRYPTO-PASSWORD-HARDCODED | 180 |
| CRYPTO-RNG-INSECURE | 108 |
| CRYPTO-SALT-STATIC | 180 |
| CRYPTO-SEED-PREDICTABLE | 120 |

## 판정

| 값 | 개수 |
|---|---|
| clean | 368 |
| undetermined | 640 |
| violation | 744 |

## 역할

| 값 | 개수 |
|---|---|
| crypto_operation | 1384 |
| name_list | 24 |
| non_security | 40 |
| test_fixture | 304 |

## 제공 문맥 깊이

| 값 | 개수 |
|---|---|
| 0 | 504 |
| 1 | 604 |
| 2 | 644 |

## 규칙 × 판정

| 값 | 개수 |
|---|---|
| CRYPTO-CIPHER-OBSOLETE / clean | 42 |
| CRYPTO-CIPHER-OBSOLETE / violation | 70 |
| CRYPTO-HASH-WEAK / clean | 62 |
| CRYPTO-HASH-WEAK / undetermined | 100 |
| CRYPTO-HASH-WEAK / violation | 90 |
| CRYPTO-IV-STATIC / clean | 30 |
| CRYPTO-IV-STATIC / undetermined | 80 |
| CRYPTO-IV-STATIC / violation | 70 |
| CRYPTO-KDF-WEAK / clean | 30 |
| CRYPTO-KDF-WEAK / undetermined | 80 |
| CRYPTO-KDF-WEAK / violation | 70 |
| CRYPTO-KEY-HARDCODED / clean | 30 |
| CRYPTO-KEY-HARDCODED / undetermined | 80 |
| CRYPTO-KEY-HARDCODED / violation | 70 |
| CRYPTO-KEYSIZE-SHORT / clean | 20 |
| CRYPTO-KEYSIZE-SHORT / violation | 60 |
| CRYPTO-MODE-ECB / clean | 30 |
| CRYPTO-MODE-ECB / undetermined | 80 |
| CRYPTO-MODE-ECB / violation | 70 |
| CRYPTO-PASSWORD-HARDCODED / clean | 30 |
| CRYPTO-PASSWORD-HARDCODED / undetermined | 80 |
| CRYPTO-PASSWORD-HARDCODED / violation | 70 |
| CRYPTO-RNG-INSECURE / clean | 44 |
| CRYPTO-RNG-INSECURE / undetermined | 20 |
| CRYPTO-RNG-INSECURE / violation | 44 |
| CRYPTO-SALT-STATIC / clean | 30 |
| CRYPTO-SALT-STATIC / undetermined | 80 |
| CRYPTO-SALT-STATIC / violation | 70 |
| CRYPTO-SEED-PREDICTABLE / clean | 20 |
| CRYPTO-SEED-PREDICTABLE / undetermined | 40 |
| CRYPTO-SEED-PREDICTABLE / violation | 60 |

