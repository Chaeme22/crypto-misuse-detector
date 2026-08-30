"""
표와 견주는 계산을 확인한다.

핵심은 목적에 따라 같은 알고리즘의 답이 갈린다는 것이다. 문서 7쪽 각주가 명시한다.
SHA-1은 전자서명용 충돌저항성을 내지 못해 쓸 수 없지만 메시지인증용으로는 쓸 수 있다.
호출한 API가 목적을 정하므로 `MessageDigest.getInstance("SHA-1")`과
`Mac.getInstance("HmacSHA1")`의 판정이 달라야 한다.

전에는 이 구분이 없어 규칙에 적힌 이름만 보고 둘 다 위반으로 보고했다.
"""

from __future__ import annotations

import pytest

from rag_app.analysis.findings import UsageSite
from rag_app.analysis.thresholds import (Outcome, ThresholdTable, canonical,
                                         purpose_for_call)


@pytest.fixture(scope="module")
def table() -> ThresholdTable:
    return ThresholdTable.load()


def site(call: str, spec: str = "", key_bits: int | None = None) -> UsageSite:
    return UsageSite(file_path="X.java", line=1, call=call,
                     algorithm_spec=spec, key_bits=key_bits, language="java")


@pytest.mark.parametrize("written, expected", [
    ("AES/ECB/PKCS5Padding", "AES"),
    ("AES/CBC/PKCS5Padding", "AES"),
    ("DESede/CBC/PKCS5Padding", "3TDEA"),
    ("DESede", "3TDEA"),
    ("HmacSHA256", "SHA-256"),
    ("HmacMD5", "MD5"),
    ("PBKDF2WithHmacSHA1", "SHA-1"),
    ("SHA1", "SHA-1"),
    ("SHA", "SHA-1"),
    ("SHA-256", "SHA-256"),
    ("SHA-512/256", "SHA-512/256"),
    ("ARCFOUR", "RC4"),
])
def test_canonical_names(written, expected):
    """코드 표기를 표 표기로 옮긴다. `SHA-512/256`을 `SHA-256`으로 뭉개면 안 된다."""
    assert canonical(written) == expected


@pytest.mark.parametrize("call, spec, expected", [
    ("MessageDigest.getInstance", "SHA-1", "hash_signature"),
    ("Mac.getInstance", "HmacSHA1", "hash_mac"),
    ("SecretKeyFactory.getInstance", "PBKDF2WithHmacSHA1", "hash_mac"),
    ("Cipher.getInstance", "AES/CBC/PKCS5Padding", "symmetric_cipher"),
    ("Cipher.getInstance", "RSA", "public_key"),
    ("KeyPairGenerator.getInstance", "RSA", "public_key"),
    ("new Random", "", None),
])
def test_purpose_routing(call, spec, expected):
    assert purpose_for_call(call, spec) == expected


def test_same_hash_different_purpose(table):
    """같은 SHA-1이 목적에 따라 갈린다. 이 프로젝트에서 표를 나눠 읽는 이유다."""
    signing = table.measure(site("MessageDigest.getInstance", "SHA-1"))
    mac = table.measure(site("Mac.getInstance", "HmacSHA1"))
    assert signing.outcome is Outcome.NOT_LISTED
    assert mac.outcome is Outcome.MEETS


@pytest.mark.parametrize("spec, expected", [
    ("MD5", Outcome.NOT_LISTED),
    ("MD4", Outcome.NOT_LISTED),
    ("MD2", Outcome.NOT_LISTED),
    ("SHA-1", Outcome.NOT_LISTED),
    ("SHA-256", Outcome.MEETS),
    ("SHA-512", Outcome.MEETS),
    ("SHA-224", Outcome.EXPIRING),
])
def test_hash_for_signing(table, spec, expected):
    """전자서명용 해시. SHA-224는 112비트라 최소 기준만 만족한다."""
    assert table.measure(site("MessageDigest.getInstance", spec)).outcome is expected


@pytest.mark.parametrize("spec, expected", [
    ("DES", Outcome.NOT_LISTED),
    ("RC2", Outcome.NOT_LISTED),
    ("RC4", Outcome.NOT_LISTED),
    ("IDEA", Outcome.NOT_LISTED),
    ("Blowfish", Outcome.NOT_LISTED),
    ("AES/CBC/PKCS5Padding", Outcome.MEETS),
    ("SEED", Outcome.EXPIRING),
    ("DESede", Outcome.EXPIRING),
])
def test_symmetric_cipher(table, spec, expected):
    """표에 없는 이름은 위반이다. 손으로 적은 목록으로는 매번 새 이름이 새어 나갔다."""
    assert table.measure(site("Cipher.getInstance", spec)).outcome is expected


@pytest.mark.parametrize("bits, expected", [
    (512, Outcome.BELOW),
    (1024, Outcome.BELOW),
    (1536, Outcome.BELOW),
    (2047, Outcome.BELOW),      # 손으로 적은 집합에 없어 통과했던 값
    (2048, Outcome.EXPIRING),
    (3072, Outcome.MEETS),
    (4096, Outcome.MEETS),
])
def test_rsa_key_length(table, bits, expected):
    measured = table.measure(site("KeyPairGenerator.getInstance", "RSA", bits))
    assert measured.outcome is expected


def test_missing_key_length_is_unknown(table):
    """키 길이를 못 찾으면 모른다고 답한다. 기본값을 추측하지 않는다."""
    measured = table.measure(site("KeyPairGenerator.getInstance", "RSA"))
    assert measured.outcome is Outcome.UNKNOWN


def test_measurement_carries_citation(table):
    """판정 근거가 표의 어느 쪽인지 남아야 한다."""
    measured = table.measure(site("KeyPairGenerator.getInstance", "RSA", 1024))
    assert measured.citation is not None
    assert measured.citation.page == 9
    assert "2048" in measured.citation.quote


def test_out_of_scope_returns_none(table):
    """표에 없는 질문은 재지 않는다. 운영모드와 난수 생성이 그렇다."""
    assert table.measure(site("new Random")) is None
    assert table.measure(site("new SecretKeySpec")) is None
