"""
비밀 재료(키·IV·솔트·비밀번호·시드)의 출처 판별을 고정한다.

이 규칙들은 호출이 있다는 것만으로 판정이 서지 않는다. `new IvParameterSpec(iv)`는 `iv`가
상수면 위반이고 안전한 난수로 채웠으면 정상이다. 전에는 문자열 리터럴만 따라갔기 때문에
`byte[] k = {1, 2}`도 `nextBytes(k)`로 채운 배열도 모두 `값을 모름`이 되어 확인 필요로
떨어졌다. 출처는 구조로 답할 수 있는 질문이므로 코드가 답한다.

판정 규칙:
  constant        코드에 박힌 값. 위반
  secure_random   SecureRandom이 만든 값. 정상으로 닫는다
  그 밖           외부 입력, 다른 파일, 섞인 경로. 판정하지 않는다
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import extract, pipeline, rules
from rag_app.analysis.findings import Decision, UsageSite
from rag_app.analysis.verdict import StaticVerdict


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def sites(tmp_path: Path, code: str, tier1) -> dict[tuple[int, str], UsageSite]:
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    return {(site.line, rule.rule_id): site
            for site, rule in extract.collect(tmp_path, tier1)}


def decisions(tmp_path: Path, code: str, tier1) -> dict[tuple[int, str], Decision]:
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path)
    state.rules = tier1
    state = pipeline.extract_sites(state)
    state = pipeline.judge_sites(state, StaticVerdict(), None)
    return {(f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}


# --- 키 -----------------------------------------------------------------------

def test_key_from_array_literal_is_constant(tmp_path, tier1):
    found = sites(tmp_path, '''import javax.crypto.spec.SecretKeySpec;
public class T {
    void a() {
        byte[] k = {(byte) 1, (byte) 2, (byte) 3};
        SecretKeySpec s = new SecretKeySpec(k, "AES");
    }
}
''', tier1)
    assert found[(5, "CRYPTO-KEY-HARDCODED")].provenance == "constant"


def test_key_filled_by_secure_random_is_clean(tmp_path, tier1):
    code = '''import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a() {
        SecureRandom sr = new SecureRandom();
        byte[] k = new byte[16];
        sr.nextBytes(k);
        SecretKeySpec s = new SecretKeySpec(k, "AES");
    }
}
'''
    assert sites(tmp_path, code, tier1)[(8, "CRYPTO-KEY-HARDCODED")].provenance == "secure_random"
    assert decisions(tmp_path, code, tier1)[(8, "CRYPTO-KEY-HARDCODED")] is Decision.CLEAN


def test_key_from_unknown_caller_is_not_judged(tmp_path, tier1):
    """밖에서 들어온 값이다. 추측하지 않는다."""
    code = '''import javax.crypto.spec.SecretKeySpec;
public class T {
    void a(byte[] fromCaller) {
        SecretKeySpec s = new SecretKeySpec(fromCaller, "AES");
    }
}
'''
    site = sites(tmp_path, code, tier1)[(4, "CRYPTO-KEY-HARDCODED")]
    assert site.provenance == "unknown"
    assert site.unresolved_args == ("fromCaller",)
    assert decisions(tmp_path, code, tier1)[(4, "CRYPTO-KEY-HARDCODED")] is Decision.UNDETERMINED


def test_key_from_same_file_caller_literal_is_constant(tmp_path, tier1):
    code = '''import javax.crypto.spec.SecretKeySpec;
public class T {
    void run() { a("hunter2".getBytes()); }
    void a(byte[] fromCaller) {
        SecretKeySpec s = new SecretKeySpec(fromCaller, "AES");
    }
}
'''
    assert sites(tmp_path, code, tier1)[(5, "CRYPTO-KEY-HARDCODED")].provenance == "constant"
    assert decisions(tmp_path, code, tier1)[(5, "CRYPTO-KEY-HARDCODED")] is Decision.VIOLATION


def test_mixed_paths_are_not_judged(tmp_path, tier1):
    """한 경로는 상수, 한 경로는 난수면 어느 쪽인지 모른다."""
    code = '''import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void run() {
        a("hunter2".getBytes());
        byte[] r = new byte[16];
        new SecureRandom().nextBytes(r);
        a(r);
    }
    void a(byte[] k) {
        SecretKeySpec s = new SecretKeySpec(k, "AES");
    }
}
'''
    assert sites(tmp_path, code, tier1)[(11, "CRYPTO-KEY-HARDCODED")].provenance == "unknown"


def test_conditional_fill_does_not_clean_the_constant(tmp_path, tier1):
    """
    조건문 안에서만 난수로 채우면 상수가 그대로 쓰이는 경로가 남는다. 정상으로 닫으면
    하드코딩된 키를 조용히 놓친다.
    """
    code = '''import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a(int choice) {
        byte[] k = "defaultkey".getBytes();
        if (choice > 1) {
            new SecureRandom().nextBytes(k);
        }
        SecretKeySpec s = new SecretKeySpec(k, "AES");
    }
}
'''
    assert sites(tmp_path, code, tier1)[(9, "CRYPTO-KEY-HARDCODED")].provenance == "unknown"
    assert decisions(tmp_path, code, tier1)[(9, "CRYPTO-KEY-HARDCODED")] is not Decision.CLEAN


def test_fill_inside_the_same_branch_as_the_declaration_counts(tmp_path, tier1):
    """선언과 채우기가 같은 분기 안이면 그 분기에서 배열은 늘 난수로 채워진다."""
    found = sites(tmp_path, '''import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
public class T {
    void a(boolean on) {
        if (on) {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec s = new IvParameterSpec(iv);
        }
    }
}
''', tier1)
    assert found[(8, "CRYPTO-IV-STATIC")].provenance == "secure_random"


def test_random_stream_object_is_not_random_bytes(tmp_path, tier1):
    """`random.ints()`는 스트림 객체다. 문자열로 바꾸면 클래스 이름과 해시가 나온다."""
    found = sites(tmp_path, '''import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a() {
        SecureRandom random = new SecureRandom();
        String k = String.valueOf(random.ints());
        SecretKeySpec s = new SecretKeySpec(k.getBytes(), "AES");
    }
}
''', tier1)
    assert found[(7, "CRYPTO-KEY-HARDCODED")].provenance != "secure_random"


def test_same_name_with_different_types_is_not_trusted(tmp_path, tier1):
    """한 메서드에서 같은 이름이 Random과 SecureRandom으로 선언되면 어느 쪽인지 모른다."""
    found = sites(tmp_path, '''import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a(boolean on) {
        if (on) { SecureRandom r = new SecureRandom(); }
        else {
            Random r = new Random();
            byte[] k = new byte[16];
            r.nextBytes(k);
            SecretKeySpec s = new SecretKeySpec(k, "AES");
        }
    }
}
''', tier1)
    assert found[(11, "CRYPTO-KEY-HARDCODED")].provenance != "secure_random"


def test_static_verdict_never_violates_undecided_provenance(tier1):
    """판정되지 않은 출처는 enforce에 기대지 않고 판정기에서부터 보류한다."""
    from rag_app.analysis.findings import UsageSite
    rule = next(r for r in tier1 if r.rule_id == "CRYPTO-KEY-HARDCODED")
    for kind in ("unknown", "external_input"):
        site = UsageSite(file_path="T.java", line=1, call="new SecretKeySpec",
                         provenance=kind, provenance_note="x")
        assert StaticVerdict().judge(site, rule, ()).decision is Decision.UNDETERMINED
    # 약한 난수가 만든 재료는 예측할 수 있으므로 위반이다(2026-10-09 변경 — 전에는 보류했다)
    site = UsageSite(file_path="T.java", line=1, call="new SecretKeySpec",
                     provenance="weak_random", provenance_note="java.util.Random")
    assert StaticVerdict().judge(site, rule, ()).decision is Decision.VIOLATION


def test_salt_digested_from_a_constant_is_constant(tmp_path, tier1):
    """상수의 다이제스트도 늘 같은 값이다. 실제 코드(Taverna)에서 솔트를 이렇게 만들었다."""
    found = sites(tmp_path, '''import java.security.MessageDigest;
import javax.crypto.spec.PBEParameterSpec;
public class T {
    private static final String SALT_SEED = "taverna";
    void a() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(SALT_SEED.getBytes());
        byte[] digest = md.digest();
        PBEParameterSpec p = new PBEParameterSpec(digest, 2000);
    }
}
''', tier1)
    assert found[(9, "CRYPTO-SALT-STATIC")].provenance == "constant"


def test_digest_of_random_input_is_not_constant(tmp_path, tier1):
    found = sites(tmp_path, '''import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.spec.PBEParameterSpec;
public class T {
    void a() throws Exception {
        byte[] r = new byte[16];
        new SecureRandom().nextBytes(r);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(r);
        byte[] digest = md.digest();
        PBEParameterSpec p = new PBEParameterSpec(digest, 2000);
    }
}
''', tier1)
    assert found[(11, "CRYPTO-SALT-STATIC")].provenance != "constant"


def test_key_derived_from_a_constant_password_is_constant(tmp_path, tier1):
    """상수 비밀번호로 유도한 키를 꺼내 쓰면 하드코딩 키다(ManifoldCF 모양)."""
    found = sites(tmp_path, '''import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec("NowIsTheTime".toCharArray(), "Salty".getBytes(), 10000, 128);
        SecretKey derived = factory.generateSecret(spec);
        SecretKeySpec key = new SecretKeySpec(derived.getEncoded(), "AES");
    }
}
''', tier1)
    assert found[(10, "CRYPTO-KEY-HARDCODED")].provenance == "constant"


def test_constant_default_that_can_be_configured_is_reported(tmp_path, tier1):
    """설정으로 바꿀 수 있어도 바꾸지 않으면 박힌 키가 쓰인다(Artemis 모양)."""
    code = '''import javax.crypto.spec.SecretKeySpec;
public class T {
    private byte[] internalKey = "clusterpassword".getBytes();
    public void init(String key) { this.internalKey = key.getBytes(); }
    byte[] encode() throws Exception {
        SecretKeySpec k = new SecretKeySpec(internalKey, "Blowfish");
        return null;
    }
}
'''
    site = sites(tmp_path, code, tier1)[(6, "CRYPTO-KEY-HARDCODED")]
    assert site.provenance == "constant"
    assert "기본값" in site.provenance_note


def test_placeholder_overwritten_by_configuration_is_not_reported(tmp_path, tier1):
    """빈 문자열 같은 자리표시 값은 기본 키가 아니다. 설정에서 채울 자리다."""
    found = sites(tmp_path, '''import javax.crypto.spec.SecretKeySpec;
public class T {
    private String secret = "";
    public void configure(String value) { this.secret = value; }
    void a() throws Exception {
        SecretKeySpec k = new SecretKeySpec(secret.getBytes(), "AES");
    }
}
''', tier1)
    assert found[(6, "CRYPTO-KEY-HARDCODED")].provenance != "constant"


def test_copy_length_is_not_part_of_the_value(tmp_path, tier1):
    """`Arrays.copyOf(k, 16)`의 16은 길이다. 값에 섞으면 경로가 섞인 것으로 보인다."""
    found = sites(tmp_path, '''import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a() {
        byte[] r = new byte[32];
        new SecureRandom().nextBytes(r);
        byte[] k = Arrays.copyOf(r, 16);
        SecretKeySpec s = new SecretKeySpec(k, "AES");
    }
}
''', tier1)
    assert found[(9, "CRYPTO-KEY-HARDCODED")].provenance == "secure_random"


def test_self_reassignment_follows_the_original(tmp_path, tier1):
    """`k = Arrays.copyOf(k, 16)`은 k 자신을 다시 넣는다. 원래 값을 따라가야 한다."""
    found = sites(tmp_path, '''import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
public class T {
    static byte[] DEFAULT = {20, 10, 30, 5};
    void a() {
        byte[] k = DEFAULT;
        k = Arrays.copyOf(k, 16);
        SecretKeySpec s = new SecretKeySpec(k, "AES");
    }
}
''', tier1)
    assert found[(8, "CRYPTO-KEY-HARDCODED")].provenance == "constant"


def test_charset_name_is_not_part_of_the_value(tmp_path, tier1):
    code = '''import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
public class T {
    void a() {
        String k = String.valueOf(new SecureRandom().nextLong());
        SecretKeySpec s = new SecretKeySpec(k.getBytes("UTF-8"), "AES");
    }
}
'''
    assert sites(tmp_path, code, tier1)[(6, "CRYPTO-KEY-HARDCODED")].provenance == "secure_random"


# --- IV -----------------------------------------------------------------------

def test_zero_iv_is_constant(tmp_path, tier1):
    """`new byte[16]`을 채우지 않으면 0으로 고정된 IV다."""
    found = sites(tmp_path, '''import javax.crypto.spec.IvParameterSpec;
public class T {
    void a() {
        byte[] iv = new byte[16];
        IvParameterSpec s = new IvParameterSpec(iv);
    }
}
''', tier1)
    assert found[(5, "CRYPTO-IV-STATIC")].provenance == "constant"


def test_iv_read_from_stream_is_not_judged(tmp_path, tier1):
    """입력 스트림에서 읽어 채운 배열은 밖에서 온 값이다. 무엇이 들어왔는지 모른다."""
    found = sites(tmp_path, '''import java.io.InputStream;
import javax.crypto.spec.IvParameterSpec;
public class T {
    void a(InputStream in) throws Exception {
        byte[] iv = new byte[16];
        in.read(iv);
        IvParameterSpec s = new IvParameterSpec(iv);
    }
}
''', tier1)
    assert found[(7, "CRYPTO-IV-STATIC")].provenance == "external_input"


# --- PBE: 비밀번호·솔트·반복 횟수가 한 줄에 함께 온다 -------------------------

def test_pbe_key_spec_reports_each_material(tmp_path, tier1):
    code = '''import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;
public class T {
    void a() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        PBEKeySpec s = new PBEKeySpec("secret".toCharArray(), salt, 500, 256);
    }
}
'''
    found = sites(tmp_path, code, tier1)
    assert found[(7, "CRYPTO-PASSWORD-HARDCODED")].provenance == "constant"
    assert found[(7, "CRYPTO-SALT-STATIC")].provenance == "secure_random"
    assert found[(7, "CRYPTO-KDF-WEAK")].provenance == "below_minimum"

    judged = decisions(tmp_path, code, tier1)
    assert judged[(7, "CRYPTO-PASSWORD-HARDCODED")] is Decision.VIOLATION
    assert judged[(7, "CRYPTO-SALT-STATIC")] is Decision.CLEAN
    assert judged[(7, "CRYPTO-KDF-WEAK")] is Decision.VIOLATION


def test_pbe_parameter_spec_static_salt_enough_iterations(tmp_path, tier1):
    code = '''import javax.crypto.spec.PBEParameterSpec;
public class T {
    void a() {
        byte[] salt = {(byte) 0x0a, (byte) 0x0b};
        int count = 10000;
        PBEParameterSpec p = new PBEParameterSpec(salt, count);
    }
}
'''
    found = sites(tmp_path, code, tier1)
    assert found[(6, "CRYPTO-SALT-STATIC")].provenance == "constant"
    assert found[(6, "CRYPTO-KDF-WEAK")].provenance == "meets_minimum"
    assert decisions(tmp_path, code, tier1)[(6, "CRYPTO-KDF-WEAK")] is Decision.CLEAN


# --- 키 저장소 비밀번호 -------------------------------------------------------

def test_keystore_password_literal_is_constant(tmp_path, tier1):
    found = sites(tmp_path, '''import java.io.InputStream;
import java.security.KeyStore;
public class T {
    void a(InputStream in) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(in, "changeit".toCharArray());
    }
}
''', tier1)
    assert found[(6, "CRYPTO-PASSWORD-HARDCODED")].provenance == "constant"


def test_keystore_password_from_environment_is_external(tmp_path, tier1):
    code = '''import java.io.InputStream;
import java.security.KeyStore;
public class T {
    void a(InputStream in) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(in, System.getenv("KS_PASS").toCharArray());
    }
}
'''
    assert sites(tmp_path, code, tier1)[(6, "CRYPTO-PASSWORD-HARDCODED")].provenance == "external_input"
    assert decisions(tmp_path, code, tier1)[(6, "CRYPTO-PASSWORD-HARDCODED")] is Decision.UNDETERMINED


def test_password_from_program_arguments_is_external(tmp_path, tier1):
    found = sites(tmp_path, '''import javax.crypto.spec.PBEKeySpec;
public class T {
    public static void main(String[] args) {
        String pw = args[0];
        PBEKeySpec s = new PBEKeySpec(pw.toCharArray());
    }
}
''', tier1)
    assert found[(5, "CRYPTO-PASSWORD-HARDCODED")].provenance == "external_input"


# --- 시드 ---------------------------------------------------------------------

def test_constant_seed_is_predictable(tmp_path, tier1):
    found = sites(tmp_path, '''import java.security.SecureRandom;
public class T {
    void a() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(42L);
        SecureRandom fixed = new SecureRandom(new byte[]{1, 2});
    }
}
''', tier1)
    assert found[(5, "CRYPTO-SEED-PREDICTABLE")].provenance == "constant"
    assert found[(6, "CRYPTO-SEED-PREDICTABLE")].provenance == "constant"


def test_seed_from_secure_random_is_clean(tmp_path, tier1):
    code = '''import java.security.SecureRandom;
public class T {
    void a() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(sr.nextLong());
    }
}
'''
    assert sites(tmp_path, code, tier1)[(5, "CRYPTO-SEED-PREDICTABLE")].provenance == "secure_random"
    assert decisions(tmp_path, code, tier1)[(5, "CRYPTO-SEED-PREDICTABLE")] is Decision.CLEAN


def test_unseeded_secure_random_is_not_a_site(tmp_path, tier1):
    """인자 없는 `new SecureRandom()`은 시드를 정하지 않는다. 지점이 아니다."""
    found = sites(tmp_path, '''import java.security.SecureRandom;
public class T {
    void a() {
        SecureRandom sr = new SecureRandom();
    }
}
''', tier1)
    assert (4, "CRYPTO-SEED-PREDICTABLE") not in found
