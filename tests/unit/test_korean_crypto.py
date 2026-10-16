"""
국산 암호 사용을 고정한다.

국내 코드는 JCA 제공자(`Cipher.getInstance("SEED/CBC/...")`)뿐 아니라 KISA가 배포한 참조 구현을 그대로 복사해 쓴다.
국산 암호 개발 코퍼스(GitHub, 158개 저장소)에서 `KISA_SEED_CBC.SEED_CBC_Encrypt(key, iv, ...)`가 37건,
`KISA_SEED_ECB.SEED_ECB_Encrypt(key, ...)`가 18건이었다. 이 호출은 어느 규칙의 트리거도 아니어서 하드코딩 키·고정 IV·
ECB를 하나도 잡지 못했다. 관련 연구의 도구와 벤치마크에도 없는 모양이다.

- `KISA_SEED_CBC.SEED_CBC_Encrypt/Decrypt(key, iv, msg, off, len)` — 키 0, IV 1
- `KISA_SEED_CTR.SEED_CTR_Encrypt/Decrypt(key, counter, msg, off, len)` — 키 0, 카운터 1
- `KISA_SEED_ECB.SEED_ECB_Encrypt/Decrypt(key, msg, off, len)` — 키 0, 그리고 운영모드가 ECB
- `KISA_SEED_CBC.SEED_CBC_init(info, enc, key, iv)` — 키 2, IV 3
- KISA ARIA 참조 구현 래퍼: `new ARIAEngine(256, key)`, `engine.setKey(key)`
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict

KEY, IV, ECB, HASH = ("CRYPTO-KEY-HARDCODED", "CRYPTO-IV-STATIC", "CRYPTO-MODE-ECB",
                      "CRYPTO-HASH-WEAK")
OBSOLETE = "CRYPTO-CIPHER-OBSOLETE"


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def judged(tmp_path: Path, body: str, tier1, fields: str = "") -> dict[tuple[int, str], Decision]:
    code = ("import java.security.*;\nimport javax.crypto.*;\n"
            "public class T {\n" + fields + "    byte[] a(byte[] msg) throws Exception {\n"
            + body + "\n        return null;\n    }\n}\n")
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    return {(f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}


LINE = 5
FIELDS = ('    static byte[] KEY_BYTES = {0x2c, 0x11, 0x19, 0x1d, 0x1f, 0x16, 0x12, 0x12,\n'
          '                               0x11, 0x19, 0x1d, 0x1f, 0x10, 0x14, 0x1b, 0x16};\n'
          '    static byte[] IV_BYTES = "1234567890123456".getBytes();\n')


@pytest.mark.parametrize("method", ["SEED_CBC_Encrypt", "SEED_CBC_Decrypt"])
def test_kisa_seed_cbc_hardcoded_key_and_iv(tmp_path, tier1, method):
    found = judged(tmp_path, f"        return KISA_SEED_CBC.{method}(KEY_BYTES, IV_BYTES, msg, 0, msg.length);",
                   tier1, FIELDS)
    line = LINE + 3
    assert found[(line, KEY)] is Decision.VIOLATION
    assert found[(line, IV)] is Decision.VIOLATION


def test_kisa_seed_cbc_random_iv_is_clean(tmp_path, tier1):
    found = judged(tmp_path, "        byte[] iv = new byte[16];\n"
                             "        new SecureRandom().nextBytes(iv);\n"
                             "        byte[] k = System.getenv(\"SEED_KEY\").getBytes();\n"
                             "        return KISA_SEED_CBC.SEED_CBC_Encrypt(k, iv, msg, 0, msg.length);", tier1)
    assert found.get((LINE + 3, IV)) in (None, Decision.CLEAN)
    assert found.get((LINE + 3, KEY)) is not Decision.VIOLATION


def test_kisa_seed_ecb_is_ecb_mode(tmp_path, tier1):
    found = judged(tmp_path, "        byte[] k = System.getenv(\"SEED_KEY\").getBytes();\n"
                             "        return KISA_SEED_ECB.SEED_ECB_Encrypt(k, msg, 0, msg.length);", tier1)
    assert found[(LINE + 1, ECB)] is Decision.VIOLATION


def test_kisa_seed_ecb_hardcoded_key(tmp_path, tier1):
    found = judged(tmp_path, "        return KISA_SEED_ECB.SEED_ECB_Encrypt(KEY_BYTES, msg, 0, msg.length);",
                   tier1, FIELDS)
    assert found[(LINE + 3, KEY)] is Decision.VIOLATION


def test_kisa_seed_ctr_static_counter(tmp_path, tier1):
    found = judged(tmp_path, "        return KISA_SEED_CTR.SEED_CTR_Encrypt(KEY_BYTES, IV_BYTES, msg, 0, msg.length);",
                   tier1, FIELDS)
    assert found[(LINE + 3, IV)] is Decision.VIOLATION


def test_kisa_aria_engine_hardcoded_key(tmp_path, tier1):
    found = judged(tmp_path, '        ARIAEngine e = new ARIAEngine(256, "my-secret-aria-key");\n'
                             "        ARIAEngine f = new ARIAEngine(256);\n"
                             "        f.setKey(KEY_BYTES);", tier1, FIELDS)
    assert found[(LINE + 3, KEY)] is Decision.VIOLATION
    assert found[(LINE + 5, KEY)] is Decision.VIOLATION


def test_bouncycastle_aria_engine_without_key_is_not_a_site(tmp_path, tier1):
    found = judged(tmp_path, "        Object e = new ARIAEngine();", tier1)
    assert (LINE, KEY) not in found


@pytest.mark.parametrize("spec, rule, decision", [
    ("SEED", ECB, Decision.VIOLATION),                    # 운영모드 미지정 → ECB
    ("ARIA", ECB, Decision.VIOLATION),
    ("SEED/ECB/NoPadding", ECB, Decision.VIOLATION),
    ("ARIA/ECB/NoPadding", ECB, Decision.VIOLATION),
])
def test_jca_korean_cipher_modes(tmp_path, tier1, spec, rule, decision):
    found = judged(tmp_path, f'        Cipher c = Cipher.getInstance("{spec}");', tier1)
    assert found[(LINE, rule)] is decision


@pytest.mark.parametrize("spec", ["ARIA/GCM/NoPadding", "ARIA/CBC/PKCS7Padding"])
def test_jca_korean_cipher_with_mode_is_not_a_violation(tmp_path, tier1, spec):
    found = judged(tmp_path, f'        Cipher c = Cipher.getInstance("{spec}");', tier1)
    assert found.get((LINE, ECB)) is None
    assert found.get((LINE, OBSOLETE)) is not Decision.VIOLATION


def test_seed_with_mode_is_a_warning_not_a_violation(tmp_path, tier1):
    # SEED는 112비트 — KISA 기준 최소를 만족하고 2030년까지 유효하다. 위반이 아니라 경고로 따로 보고한다
    # (2026-10-08 사용자 결정, status.md 1.16).
    found = judged(tmp_path, '        Cipher c = Cipher.getInstance("SEED/CBC/PKCS5Padding");', tier1)
    assert found.get((LINE, ECB)) is None
    assert found[(LINE, OBSOLETE)] is Decision.WARNING


def test_warning_is_sarif_warning_level(tmp_path, tier1):
    from rag_app.analysis import sarif
    (tmp_path / "T.java").write_text('import javax.crypto.*;\nclass T { void a() throws Exception {\n'
                                     '    Cipher c = Cipher.getInstance("SEED/CBC/PKCS5Padding");\n}}\n',
                                     encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    warning = next(f for f in state.findings if f.verdict.decision is Decision.WARNING)
    assert sarif._level_of(warning) == "warning"


def test_warning_in_test_sources_is_not_reported(tmp_path, tier1):
    path = tmp_path / "src" / "test" / "java" / "T.java"
    path.parent.mkdir(parents=True)
    path.write_text('import javax.crypto.*;\nclass T { void a() throws Exception {\n'
                    '    Cipher c = Cipher.getInstance("SEED/CBC/PKCS5Padding");\n}}\n', encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    assert all(f.verdict.decision is Decision.CLEAN for f in state.findings)


@pytest.mark.parametrize("creation", ["new LEA.ECB()", "new kr.re.nsr.crypto.symm.LEA.ECB()",
                                      "new ozr.encryption.sym.LEA.symm.LEA.ECB()"])
def test_lea_ecb_mode_object(tmp_path, tier1, creation):
    # KISA LEA 자바 구현(kr.re.nsr.crypto): 운영모드가 클래스다. `new LEA.ECB()`가 곧 ECB 사용이다
    found = judged(tmp_path, f"        BlockCipherMode c = {creation};", tier1)
    assert found[(LINE, ECB)] is Decision.VIOLATION


def test_lea_cbc_mode_is_not_ecb(tmp_path, tier1):
    found = judged(tmp_path, "        BlockCipherMode c = new LEA.CBC();", tier1)
    assert (LINE, ECB) not in found


def test_lea_init_hardcoded_key_and_iv(tmp_path, tier1):
    found = judged(tmp_path, "        BlockCipherMode c = new LEA.CBC();\n"
                             "        c.init(BlockCipher.Mode.ENCRYPT, KEY_BYTES, IV_BYTES);", tier1, FIELDS)
    assert found[(LINE + 4, KEY)] is Decision.VIOLATION
    assert found[(LINE + 4, IV)] is Decision.VIOLATION


# --- 국산 시험용 코퍼스 채점에서 드러난 결함 (2026-10-08). 공식 숫자는 고치기 전 것으로 둔다(status.md 1.16) ---

def test_self_referencing_concatenation_is_not_a_constant(tmp_path, tier1):
    # skrevolve WpayStdSample: `token = "0" + token`을 상수로 보고, 상수 기본값 규칙이 그것을 하드코딩 키로 올렸다
    found = judged(tmp_path, "        byte[] k = new SecretKeySpec(hex(msg).getBytes(), \"AES\").getEncoded();",
                   tier1, fields=("    static String hex(byte[] buf) {\n"
                                  "        String t = \"\";\n"
                                  "        for (int i = 0; i < buf.length; i++) {\n"
                                  "            t = Integer.toHexString(buf[i]);\n"
                                  "            if (t.length() < 2) t = \"0\" + t;\n"
                                  "        }\n"
                                  "        return t;\n"
                                  "    }\n"))
    assert found.get((LINE + 8, KEY)) is not Decision.VIOLATION


@pytest.mark.parametrize("spec", ["ARIA", "DESede", "AES"])
def test_symmetric_secret_key_factory_is_not_a_hash(tmp_path, tier1, spec):
    # QSIGN KeyFactoryDemo: `SecretKeyFactory.getInstance("ARIA")`를 PBKDF2용 해시 표로 재서 위반으로 냈다
    found = judged(tmp_path, f'        SecretKeyFactory f = SecretKeyFactory.getInstance("{spec}");', tier1)
    assert found.get((LINE, HASH)) is None


def test_pbkdf2_secret_key_factory_still_uses_the_mac_table(tmp_path, tier1):
    found = judged(tmp_path, '        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacMD5");', tier1)
    assert any(r in ("CRYPTO-HASH-WEAK", "CRYPTO-KDF-WEAK") and d is Decision.VIOLATION
               for (line, r), d in found.items() if line == LINE)


def test_has160_is_not_in_the_signature_hash_table(tmp_path, tier1):
    found = judged(tmp_path, '        MessageDigest d = MessageDigest.getInstance("HAS-160");', tier1)
    assert found[(LINE, HASH)] is Decision.VIOLATION


def test_lsh256_is_approved(tmp_path, tier1):
    found = judged(tmp_path, '        MessageDigest d = MessageDigest.getInstance("LSH-256");', tier1)
    assert found.get((LINE, HASH)) in (None, Decision.CLEAN)
