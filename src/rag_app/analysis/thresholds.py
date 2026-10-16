"""
표에서 뽑은 임계값으로 코드의 값을 재는 자리.

여기가 규칙표의 산문을 숫자 비교로 바꾼다. 전에는 `WEAK_PUBLIC_KEY_BITS = {512, 768,
1024, 1536}` 처럼 손으로 적은 집합으로 판정했다. RSA-2047은 그 집합에 없어 통과했다.
이제 표에 적힌 `112비트 보안강도에 2048비트 이상`과 견주므로 목록에 없는 값도 걸린다.

목적을 가린다. 표 3(메시지인증·키유도·난수생성용)과 표 4(단순해시·전자서명용)는 같은
알고리즘에 다른 답을 준다. 문서 7쪽 각주가 명시한다. SHA-1은 전자서명용 충돌저항성을
내지 못해 쓸 수 없지만 메시지인증용으로는 쓸 수 있다. 호출한 API가 목적을 정하므로
`Mac.getInstance("HmacSHA1")`과 `MessageDigest.getInstance("SHA-1")`의 판정이 갈린다.

재는 것은 코드가 하고 판단은 모델이 한다. 이 모듈은 숫자 비교만 하고 그 결과와 표의
위치를 남긴다. 코드의 역할이 무엇인지(테스트 픽스처인지, 이름 목록인지)는 재지 않는다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .findings import Citation, Rule, UsageSite

DEFAULT_PATH = Path("config/tier1_thresholds.json")


class Outcome(str, Enum):
    """비교 결과."""
    BELOW = "below"              # 표 기준에 미달한다
    NOT_LISTED = "not_listed"    # 표의 어느 강도 행에도 없다
    EXPIRING = "expiring"        # 최소 기준은 넘지만 권장 강도에 못 미친다
    MEETS = "meets"              # 권장 강도를 만족한다
    UNKNOWN = "unknown"          # 비교할 값을 코드에서 찾지 못했다


@dataclass(frozen=True, slots=True)
class Measurement:
    """코드가 계산한 비교 결과. 모델에게는 사실로 넘긴다."""
    outcome: Outcome
    purpose: str          # 어떤 표로 쟀는지. hash_mac, hash_signature, ...
    found: str            # 코드에서 읽은 값. `RSA 1024비트`
    requirement: str      # 표가 요구하는 값. `112비트 보안강도에 2048비트 이상`
    citation: Citation | None = None   # 그 요구가 적힌 표의 위치
    note: str = ""

    @property
    def is_conclusive(self) -> bool:
        return self.outcome is not Outcome.UNKNOWN

    def sentence(self) -> str:
        """모델 프롬프트와 보고서에 같은 문장을 쓴다."""
        head = {
            Outcome.BELOW: "표 기준 미달",
            Outcome.NOT_LISTED: "표에 없는 알고리즘",
            Outcome.EXPIRING: "최소 기준만 만족",
            Outcome.MEETS: "표 기준 만족",
            Outcome.UNKNOWN: "비교 불가",
        }[self.outcome]
        text = f"{head}: 코드는 {self.found}, 표는 {self.requirement}"
        if self.note:
            text += f". {self.note}"
        return text


# 호출 이름이 목적을 정한다. 같은 해시라도 무엇에 쓰는지에 따라 판정이 갈린다.
_PURPOSE_BY_CALL = {
    "Mac.getInstance": "hash_mac",
    "SecretKeyFactory.getInstance": "hash_mac",       # PBKDF2. 키유도다.
    "hmac.new": "hash_mac",
    "hmac.HMAC": "hash_mac",
    "MessageDigest.getInstance": "hash_signature",
    "Signature.getInstance": "hash_signature",
    "hashlib.md5": "hash_signature",
    "hashlib.sha1": "hash_signature",
    "hashlib.new": "hash_signature",
    "Crypto.Hash.MD5.new": "hash_signature",
    "Crypto.Hash.SHA1.new": "hash_signature",
    "Cipher.getInstance": "symmetric_cipher",
    "new SecretKeySpec": "symmetric_cipher",          # 두 번째 인자가 그 키의 알고리즘
    "KeyGenerator.getInstance": "symmetric_cipher",
    "AES.new": "symmetric_cipher",
    "DES.new": "symmetric_cipher",
    "DES3.new": "symmetric_cipher",
    "ARC4.new": "symmetric_cipher",
    "Blowfish.new": "symmetric_cipher",
    "KeyPairGenerator.getInstance": "public_key",
    "RSA.generate": "public_key",
    "rsa.generate_private_key": "public_key",
    "dsa.generate_private_key": "public_key",
}

# 코드에 적히는 이름을 표의 이름으로 옮긴다. 표는 표준 표기를, 코드는 API 표기를 쓴다.
_ALIASES = {
    "DESEDE": "3TDEA", "TRIPLEDES": "3TDEA", "3DES": "3TDEA",
    "ARCFOUR": "RC4",
    "SHA": "SHA-1",          # `MessageDigest.getInstance("SHA")`는 SHA-1이다.
    "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
    "SHA384": "SHA-384", "SHA512": "SHA-512",
    "SHA512/224": "SHA-512/224", "SHA512/256": "SHA-512/256",
    "SHA3224": "SHA3-224", "SHA3256": "SHA3-256",
    "SHA3384": "SHA3-384", "SHA3512": "SHA3-512",
    "RIPEMD160": "RIPEMD-160",
}
# 이름을 옮기면서 생기는 가정. 보고서에 드러내야 한다.
_ALIAS_NOTES = {
    "3TDEA": ("Java의 DESede는 24바이트 키면 3TDEA, 16바이트 키면 2TDEA다. "
              "2TDEA는 표에 없다. 실제 키 길이를 확인해야 한다"),
    "SHA-1": "`SHA`와 `SHA1`은 모두 SHA-1이다",
}
# 대칭키 이름이 목적을 되돌리는 경우. `HmacSHA1`은 호출이 무엇이든 메시지인증용이다.
_MAC_PREFIX = re.compile(r"^(HMAC|PBKDF2WITHHMAC|PBEWITHHMAC)", re.IGNORECASE)
_PBE_PREFIX = re.compile(r"^PBEWITH(?:MD5|SHA1?|SHA\d+)AND", re.IGNORECASE)
# 서명 알고리즘 이름. `SHA1withRSA`에서 표와 견줄 것은 해시 부분이다. 공개키 쪽은 키 길이로 따로 잰다.
_SIGNATURE_NAME = re.compile(r"^(.+?)WITH(?:RSA|DSA|ECDSA|PLAIN-ECDSA|CVC-ECDSA|EDDSA|SM2)",
                             re.IGNORECASE)


def canonical(spec: str) -> str:
    """
    코드에 적힌 알고리즘 이름을 표의 이름으로 바꾼다.

    `AES/ECB/PKCS5Padding`처럼 변환 스펙이면 앞부분만 알고리즘이다. `HmacSHA256`처럼
    용도가 접두어로 붙으면 떼낸다.
    """
    text = spec.strip().strip('"').split("/")[0] if "/" not in spec else spec.strip().strip('"')
    if "/" in text:
        head = text.split("/")[0]
        # `SHA-512/256`은 잘린 해시 이름이라 슬래시가 이름의 일부다.
        text = text if re.match(r"^SHA-?512/\d+$", text, re.IGNORECASE) else head
    text = text.strip()
    text = _MAC_PREFIX.sub("", text)
    text = _PBE_PREFIX.sub("", text)
    signature = _SIGNATURE_NAME.match(text)
    if signature:
        text = signature.group(1)
    upper = text.upper().replace("_", "")
    return _ALIASES.get(upper, upper)


# `Cipher.getInstance`는 대칭키도 공개키도 받는다. 이름으로 갈라야 한다.
_ASYMMETRIC = {"RSA", "DH", "ECC", "EC", "ECIES", "ELGAMAL", "DSA", "ECDSA", "ECDH"}


def purpose_for_call(call: str, spec: str = "") -> str | None:
    """
    무엇에 쓰는 값인지. 알 수 없으면 None.

    호출 이름이 목적을 정하되 두 경우는 알고리즘 이름이 되돌린다. `HmacSHA1`은 호출이
    무엇이든 메시지인증용이고, `Cipher.getInstance("RSA")`는 대칭키 표로 재면 안 된다.
    """
    text = (spec or "").strip().strip('"')
    if _MAC_PREFIX.match(text):
        return "hash_mac"
    purpose = _PURPOSE_BY_CALL.get(call)
    if call == "SecretKeyFactory.getInstance" and text and not re.match(r"^(PBKDF|PBE)", text,
                                                                         re.IGNORECASE):
        # `SecretKeyFactory.getInstance("ARIA")`·`("DESede")`는 키 유도가 아니라 대칭키 객체를 만든다
        purpose = "symmetric_cipher"
    if _PBE_PREFIX.match(text):
        # `PBEWithSHA1AndDESede`·`PBEWithMD5AndDES`(PBES1): 유도한 키로 뒤쪽 암호를 쓴다. 강도는 그 암호가 정한다
        purpose = "symmetric_cipher"
    if purpose == "symmetric_cipher" and canonical(text) in _ASYMMETRIC:
        return "public_key"
    return purpose


def purpose_of(site: UsageSite) -> str | None:
    return purpose_for_call(site.call, site.algorithm_spec or "")


@dataclass(frozen=True, slots=True)
class ThresholdTable:
    """`tools/build_thresholds.py`가 만든 표. 읽기만 한다."""
    rows: tuple[dict, ...]
    minimum: int
    recommended: int
    policy: dict

    @classmethod
    def load(cls, path: Path = DEFAULT_PATH) -> ThresholdTable:
        if not path.exists():
            raise FileNotFoundError(
                f"임계값 표가 없다: {path}. tools/build_thresholds.py 를 먼저 실행한다.")
        payload = json.loads(path.read_text(encoding="utf-8"))
        policy = payload["policy"]
        return cls(rows=tuple(payload["rows"]),
                   minimum=int(policy["minimum_security_strength"]),
                   recommended=int(policy["recommended_security_strength"]),
                   policy=policy)

    def _cite(self, row: dict) -> Citation:
        source = row["source"]
        return Citation(document=source["document"], page=source["page"],
                        section_path=(source["table"],),
                        quote=self._quote(row), score=1.0,
                        needs_review=bool(source["needs_review"]))

    @staticmethod
    def _quote(row: dict) -> str:
        if row["kind"] == "key_length":
            return (f"{row['security_strength']}비트 보안강도: "
                    f"{row['algorithm']} {row['min_key_bits']}비트 이상")
        return f"{row['security_strength']}비트 이상: {row['algorithm']}"

    def membership(self, purpose: str, algorithm: str) -> dict | None:
        """그 목적의 표에서 알고리즘 한 건을 찾는다."""
        for row in self.rows:
            if (row["kind"] == "membership" and row["purpose"] == purpose
                    and row["algorithm"] == algorithm):
                return row
        return None

    def family_listed(self, purpose: str, family: str) -> list[dict]:
        """계열 이름만 아는 경우. `AES`처럼 키 길이가 코드에 없을 때 쓴다."""
        return [row for row in self.rows
                if row["kind"] == "membership" and row["purpose"] == purpose
                and row["family"] == family]

    def required_bits(self, family: str, strength: int) -> dict | None:
        for row in self.rows:
            if (row["kind"] == "key_length" and row["family"] == family
                    and row["security_strength"] == strength):
                return row
        return None

    def policy_citation(self) -> Citation:
        """최소 강도 기준이 어디서 온 숫자인지."""
        return Citation(document=self.policy["basis_document"],
                        page=self.policy["basis_page"],
                        section_path=(self.policy["basis_table"],),
                        quote=self.policy["basis"], score=1.0)

    # ------------------------------------------------------------------ 재기

    def measure(self, site: UsageSite) -> Measurement | None:
        """
        사용 지점 하나를 표와 견준다. 잴 수 없으면 None.

        None과 `UNKNOWN`은 다르다. None은 이 표로 답할 질문이 아니라는 뜻이고
        (운영모드나 난수 생성은 표에 없다), `UNKNOWN`은 답할 질문인데 코드에서 값을
        찾지 못했다는 뜻이다.
        """
        purpose = purpose_of(site)
        if purpose is None:
            return None
        if site.call == "new SecretKeySpec" and not site.algorithm_spec:
            # 키 객체의 알고리즘 인자를 따로 재는 지점만 표와 견준다. 키 바이트의 출처를 보는
            # 지점(하드코딩 키 규칙)은 표로 답할 질문이 아니다.
            return None
        if purpose == "public_key":
            return self._measure_public_key(site)
        return self._measure_membership(site, purpose)

    def _measure_membership(self, site: UsageSite, purpose: str) -> Measurement:
        if not site.algorithm_spec:
            return Measurement(
                Outcome.UNKNOWN, purpose, "알고리즘 이름을 찾지 못함",
                f"{purpose} 표와 견주려면 알고리즘 이름이 필요하다")

        name = canonical(site.algorithm_spec)
        row = self.membership(purpose, name)
        if row is not None:
            measured = self._verdict_for(row, purpose, name)
            note = _ALIAS_NOTES.get(name)
            if note and note not in measured.note:
                joined = f"{measured.note} {note}".strip() if measured.note else note
                measured = Measurement(measured.outcome, measured.purpose,
                                       measured.found, measured.requirement,
                                       measured.citation, joined)
            return measured

        # 이름에 길이가 없는 경우. `AES`만 적혀 있으면 계열이 표에 있는지로 답한다.
        family = self.family_listed(purpose, name)
        if family:
            weakest = min(family, key=lambda r: r["security_strength"])
            strongest = max(family, key=lambda r: r["security_strength"])
            measured = self._verdict_for(strongest, purpose, name)
            sizes = ", ".join(sorted(r["algorithm"] for r in family))
            return Measurement(
                measured.outcome, purpose,
                f"{name} (키 길이가 코드에 없음)",
                measured.requirement, measured.citation,
                note=(f"표에 {sizes}가 있다. 키 길이에 따라 보안강도가 "
                      f"{weakest['security_strength']}~{strongest['security_strength']}비트로 "
                      f"갈리므로 실제 키 길이를 확인해야 한다"))

        return Measurement(
            Outcome.NOT_LISTED, purpose, name,
            f"{self._purpose_label(purpose)} 표의 어느 보안강도 행에도 없다",
            self.policy_citation(),
            note="표에 없는 알고리즘은 국내 기준으로 사용할 수 없다")

    def _verdict_for(self, row: dict, purpose: str, name: str) -> Measurement:
        strength = row["security_strength"]
        citation = self._cite(row)
        if strength < self.minimum:
            return Measurement(Outcome.BELOW, purpose, f"{name} ({strength}비트 보안강도)",
                               f"최소 {self.minimum}비트 보안강도", citation)
        if strength < self.recommended:
            return Measurement(
                Outcome.EXPIRING, purpose, f"{name} ({strength}비트 보안강도)",
                f"최소 {self.minimum}비트는 만족, 권장 {self.recommended}비트에 미달",
                citation, note=self.policy["basis"])
        return Measurement(Outcome.MEETS, purpose, f"{name} ({strength}비트 보안강도)",
                           f"권장 {self.recommended}비트 보안강도 만족", citation)

    def _measure_public_key(self, site: UsageSite) -> Measurement:
        family = canonical(site.algorithm_spec or "")
        family = {"EC": "ECC", "ECDSA": "ECC", "ECDH": "ECC",
                  "DSA": "DH", "DIFFIEHELLMAN": "DH"}.get(family, family)
        if family not in ("RSA", "DH", "ECC"):
            return Measurement(
                Outcome.UNKNOWN, "public_key", family or "알고리즘 이름을 찾지 못함",
                "표는 인수분해(RSA), 이산대수(DH/DSA), 타원곡선(ECC)만 다룬다")

        if site.key_bits is None:
            return Measurement(
                Outcome.UNKNOWN, "public_key", f"{family} (키 길이가 코드에 없음)",
                f"{family}는 최소 {self.minimum}비트 보안강도에 "
                f"{self._need(family, self.minimum)}비트 이상 필요",
                self._cite(self.required_bits(family, self.minimum)),
                note="키 길이 지정을 찾지 못해 비교하지 못했다. 기본값이 무엇인지 확인해야 한다")

        bits = site.key_bits
        floor = self.required_bits(family, self.minimum)
        target = self.required_bits(family, self.recommended)
        if floor is not None and bits < floor["min_key_bits"]:
            return Measurement(
                Outcome.BELOW, "public_key", f"{family} {bits}비트",
                f"{self.minimum}비트 보안강도에 {floor['min_key_bits']}비트 이상",
                self._cite(floor))
        if target is not None and bits < target["min_key_bits"]:
            return Measurement(
                Outcome.EXPIRING, "public_key", f"{family} {bits}비트",
                f"{self.minimum}비트 보안강도는 만족, 권장 {self.recommended}비트에는 "
                f"{target['min_key_bits']}비트 필요",
                self._cite(target), note=self.policy["basis"])
        return Measurement(
            Outcome.MEETS, "public_key", f"{family} {bits}비트",
            f"권장 {self.recommended}비트 보안강도 만족", self._cite(target or floor))

    def _need(self, family: str, strength: int) -> int | str:
        row = self.required_bits(family, strength)
        return row["min_key_bits"] if row else "?"

    @staticmethod
    def _purpose_label(purpose: str) -> str:
        return {
            "hash_mac": "메시지인증·키유도·난수생성용 해시",
            "hash_signature": "단순해시·전자서명용 해시",
            "symmetric_cipher": "대칭키 암호",
            "public_key": "공개키 암호",
        }.get(purpose, purpose)


def decides(rule: Rule) -> bool:
    """
    표의 비교만으로 이 규칙의 질문이 끝나는지.

    끝나지 않는 규칙이 있다. `PBKDF2WithHmacSHA1`은 표 3에 따르면 해시 선택이 문제가
    아니다. 문제는 반복 횟수인데 그건 재고 있지 않다. 그래서 표가 만족이라고 해도
    이 규칙은 닫지 않는다.
    """
    return rule.table_decides
