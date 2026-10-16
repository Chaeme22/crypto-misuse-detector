"""
운영모드를 적지 않은 변환과 키 객체의 알고리즘 인자를 고정한다.

`Cipher.getInstance("AES")`는 운영모드를 적지 않았다. Java 표준 제공자(SunJCE)는 이때
`AES/ECB/PKCS5Padding`을 쓴다. 이름에 ECB가 없다고 넘기면 가장 흔한 ECB 사용을 놓친다.
실제 Apache 코드(ApacheCryptoAPI-Bench, DeltaSpike)에서 이 모양을 놓쳤다.

`new SecretKeySpec(key, "DESede")`의 두 번째 인자는 그 키로 쓸 알고리즘이다. 키 바이트의 출처만
보고 알고리즘을 보지 않아 DESede·ARCFOUR 키를 놓쳤다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def judged(tmp_path: Path, body: str, tier1, imports: str = "") -> dict[tuple[int, str], Decision]:
    code = ("import javax.crypto.Cipher;\nimport javax.crypto.spec.SecretKeySpec;\n" + imports
            + "public class T {\n    void a(byte[] k) throws Exception {\n" + body + "\n    }\n}\n")
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.extract_sites(state)
    state = pipeline.judge_sites(state, StaticVerdict(), None)
    return {(f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}


LINE = 5  # 본문 첫 줄


def test_block_cipher_without_mode_is_ecb(tmp_path, tier1):
    found = judged(tmp_path, '        Cipher c = Cipher.getInstance("AES");', tier1)
    assert found[(LINE, "CRYPTO-MODE-ECB")] is Decision.VIOLATION


def test_traced_algorithm_without_mode_is_ecb(tmp_path, tier1):
    found = judged(tmp_path, '        String algo = "DESede";\n'
                             '        Cipher c = Cipher.getInstance(algo);', tier1)
    assert found[(LINE + 1, "CRYPTO-MODE-ECB")] is Decision.VIOLATION


@pytest.mark.parametrize("spec", ["AES/GCM/NoPadding", "AES/CBC/PKCS5Padding", "RSA", "RC4",
                                  "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"])
def test_explicit_mode_stream_and_public_key_ciphers_are_not_default_ecb(tmp_path, tier1, spec):
    found = judged(tmp_path, f'        Cipher c = Cipher.getInstance("{spec}");', tier1)
    if spec.startswith("RSA/ECB"):
        # RSA의 ECB 표기는 블록 운영모드가 아니다. 이 규칙의 대상이 아니다.
        assert (LINE, "CRYPTO-MODE-ECB") not in found or \
            found[(LINE, "CRYPTO-MODE-ECB")] is not Decision.VIOLATION
    else:
        assert (LINE, "CRYPTO-MODE-ECB") not in found


def test_secret_key_spec_algorithm_is_measured(tmp_path, tier1):
    # 3TDEA는 112비트 — 최소 기준은 만족하고 2030년에 만료된다. 위반이 아니라 경고다(2026-10-08 결정).
    found = judged(tmp_path, '        SecretKeySpec s = new SecretKeySpec(k, "DESede");', tier1)
    assert found[(LINE, "CRYPTO-CIPHER-OBSOLETE")] is Decision.WARNING


def test_des_key_spec_algorithm_is_a_violation(tmp_path, tier1):
    found = judged(tmp_path, '        SecretKeySpec s = new SecretKeySpec(k, "DES");', tier1)
    assert found[(LINE, "CRYPTO-CIPHER-OBSOLETE")] is Decision.VIOLATION


def test_secret_key_spec_with_approved_algorithm_is_not_a_violation(tmp_path, tier1):
    found = judged(tmp_path, '        SecretKeySpec s = new SecretKeySpec(k, "AES");', tier1)
    assert found.get((LINE, "CRYPTO-CIPHER-OBSOLETE")) in (None, Decision.CLEAN)


def test_hmac_key_goes_to_the_mac_table(tmp_path, tier1):
    found = judged(tmp_path, '        SecretKeySpec s = new SecretKeySpec(k, "HmacSHA256");', tier1)
    assert found.get((LINE, "CRYPTO-CIPHER-OBSOLETE")) is None
    assert found.get((LINE, "CRYPTO-HASH-WEAK")) in (None, Decision.CLEAN)
