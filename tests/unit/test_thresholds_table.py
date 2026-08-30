"""
표에서 뽑은 임계값이 실제 표준과 맞는지 확인한다.

파서가 표를 그대로 읽었는지는 파서 자신으로 검증할 수 없다. 그래서 표 밖에서 아는
사실로 검사한다. SHA-256의 충돌저항성은 128비트다. RSA는 112비트 보안강도에 2048비트가
필요하다. SHA-1은 전자서명에 쓸 수 없지만 메시지인증에는 쓸 수 있다. 이 값들이 어긋나면
표를 잘못 읽은 것이다.

한 번 틀린 적이 있다. 8쪽에 표 3의 꼬리와 표 4의 머리가 같이 있어 두 표가 섞였고,
`SHA-256이 전자서명용 256비트 보안강도를 만족한다`는 행이 나왔다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

TABLE = Path("config/tier1_thresholds.json")


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    if not TABLE.exists():
        pytest.skip(f"{TABLE} 없음. tools/build_thresholds.py 를 먼저 실행한다.")
    return json.loads(TABLE.read_text(encoding="utf-8"))["rows"]


def strength(rows: list[dict], purpose: str, algorithm: str) -> int | None:
    for row in rows:
        if row["purpose"] == purpose and row["algorithm"] == algorithm:
            return row["security_strength"]
    return None


def key_bits(rows: list[dict], algorithm: str, security_strength: int) -> int | None:
    for row in rows:
        if (row["kind"] == "key_length" and row["algorithm"] == algorithm
                and row["security_strength"] == security_strength):
            return row["min_key_bits"]
    return None


@pytest.mark.parametrize("algorithm, expected", [
    ("SHA-224", 112),
    ("SHA-256", 128),
    ("SHA-384", 192),
    ("SHA-512", 256),
    ("SHA3-256", 128),
    ("SHA3-512", 256),
])
def test_hash_signature_strength(rows, algorithm, expected):
    """전자서명용 해시의 보안강도는 출력 길이의 절반이다. 충돌저항성이 기준이다."""
    assert strength(rows, "hash_signature", algorithm) == expected


def test_sha1_not_allowed_for_signature(rows):
    assert strength(rows, "hash_signature", "SHA-1") is None


def test_sha1_allowed_for_mac(rows):
    """메시지인증에서는 충돌저항성이 아니라 키 길이가 강도를 정한다. 목적이 다르면
    같은 알고리즘의 판정이 달라진다. 이게 표를 나눠 읽는 이유다."""
    assert strength(rows, "hash_mac", "SHA-1") == 128


def test_md5_nowhere(rows):
    assert not [r for r in rows if r["family"] == "MD5"]


def test_truncated_sha_is_separate(rows):
    """`SHA-512/256`은 `SHA-256`과 다른 알고리즘이다. 출력이 256비트인 건 같다."""
    names = {r["algorithm"] for r in rows if r["purpose"] == "hash_signature"}
    assert {"SHA-256", "SHA-512/256"} <= names


@pytest.mark.parametrize("algorithm, expected", [
    ("AES-128", 128),
    ("AES-192", 192),
    ("AES-256", 256),
])
def test_aes_strength(rows, algorithm, expected):
    assert strength(rows, "symmetric_cipher", algorithm) == expected


def test_3tdea_is_112(rows):
    """3키 TDEA는 키가 168비트지만 중간일치 공격 때문에 112비트다."""
    assert strength(rows, "symmetric_cipher", "3TDEA") == 112


def test_single_des_absent(rows):
    assert not [r for r in rows if r["family"] in ("DES", "TDEA")]


@pytest.mark.parametrize("algorithm, security_strength, expected", [
    ("RSA", 112, 2048),
    ("RSA", 128, 3072),
    ("RSA", 192, 7680),
    ("RSA", 256, 15360),
    ("ECC", 112, 224),
    ("ECC", 128, 256),
    ("DH", 112, 2048),
])
def test_public_key_lengths(rows, algorithm, security_strength, expected):
    assert key_bits(rows, algorithm, security_strength) == expected


def test_all_key_length_strengths_present(rows):
    """행 경계를 잘못 잡아 다음 행의 강도 숫자를 열로 삼키면 그 행이 사라진다."""
    found = {r["security_strength"] for r in rows if r["algorithm"] == "RSA"}
    assert found == {112, 128, 192, 256}


def test_every_row_cites_its_table(rows):
    """판정 근거를 표 위치로 되짚을 수 있어야 한다."""
    for row in rows:
        source = row["source"]
        assert source["document"] and source["page"] and source["table"]
