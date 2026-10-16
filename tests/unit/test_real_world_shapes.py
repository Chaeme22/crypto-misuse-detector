"""
실제 오픈소스에서 추출기가 놓친 호출 모양을 고정한다.

개발 코퍼스(`tools/dev_corpus.py`, 평가 홀드아웃과 겹치지 않는 저장소 30개)에서 정규식으로 찾은 암호 API 호출
1,555줄 중 추출기가 놓친 모양이다. `Signature.getInstance`는 18%, `DigestUtils.md5Hex` 계열은 0%만 잡혔다.

- 패키지까지 적은 호출: `java.security.Signature.getInstance("SHA256withRSA")` (ofbiz, pig)
- 서명 알고리즘 이름: `SHA1withRSA`의 해시는 SHA-1이다. 이름 통째로는 표에 없다
- 변수로 넘어온 서명·MAC 알고리즘: `Signature.getInstance(signAlgo)` (cxf, santuario)
- 메서드 이름이 알고리즘인 래퍼: `DigestUtils.md5Hex(x)` (dolphinscheduler, shardingsphere)
- 키·논스 재료: `new DESKeySpec(...)` (eladmin), `new GCMParameterSpec(128, iv)` (spring-security)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable, canonical
from rag_app.analysis.verdict import StaticVerdict


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def judged(tmp_path: Path, body: str, tier1, fields: str = "") -> dict[tuple[int, str], Decision]:
    code = ("import java.security.*;\nimport javax.crypto.*;\nimport javax.crypto.spec.*;\n"
            "public class T {\n" + fields + "    void a(byte[] k, String algo) throws Exception {\n"
            + body + "\n    }\n}\n")
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.extract_sites(state)
    state = pipeline.judge_sites(state, StaticVerdict(), None)
    return {(f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}


LINE = 6  # 필드가 없을 때 본문 첫 줄
HASH = "CRYPTO-HASH-WEAK"


@pytest.mark.parametrize("spec, hash_name", [
    ("SHA1withRSA", "SHA-1"), ("MD5withRSA", "MD5"), ("SHA256withRSA", "SHA-256"),
    ("SHA256withECDSA", "SHA-256"), ("SHA384withRSA/PSS", "SHA-384"), ("SHA512withDSA", "SHA-512"),
])
def test_signature_algorithm_reduces_to_its_hash(spec, hash_name):
    assert canonical(spec) == hash_name


def test_pbe_and_hmac_names_are_unchanged():
    assert canonical("PBEWithMD5AndDES") == "DES"
    assert canonical("HmacSHA256") == "SHA-256"


def test_weak_signature_hash_is_a_violation(tmp_path, tier1):
    found = judged(tmp_path, '        Signature s = Signature.getInstance("SHA1withRSA");', tier1)
    assert found[(LINE, HASH)] is Decision.VIOLATION


def test_strong_signature_hash_is_not_a_violation(tmp_path, tier1):
    found = judged(tmp_path, '        Signature s = Signature.getInstance("SHA256withRSA");', tier1)
    assert found.get((LINE, HASH)) in (None, Decision.CLEAN)


@pytest.mark.parametrize("call", ["java.security.MessageDigest", "java.security.Signature"])
def test_fully_qualified_call_is_recognized(tmp_path, tier1, call):
    spec = "MD5" if call.endswith("MessageDigest") else "MD5withRSA"
    found = judged(tmp_path, f'        Object o = {call}.getInstance("{spec}");', tier1)
    assert found[(LINE, HASH)] is Decision.VIOLATION


def test_traced_signature_algorithm_is_measured(tmp_path, tier1):
    found = judged(tmp_path, '        String a = "SHA1withRSA";\n'
                             '        Signature s = Signature.getInstance(a);', tier1)
    assert found[(LINE + 1, HASH)] is Decision.VIOLATION


@pytest.mark.parametrize("call", ["Signature", "Mac"])
def test_unknown_signature_or_mac_algorithm_is_left_for_review(tmp_path, tier1, call):
    found = judged(tmp_path, f'        Object o = {call}.getInstance(algo);', tier1)
    assert found[(LINE, HASH)] is Decision.UNDETERMINED


def test_traced_hmac_md5_is_a_violation_and_hmac_sha1_is_not(tmp_path, tier1):
    found = judged(tmp_path, '        String a = "HmacMD5";\n'
                             '        Mac m = Mac.getInstance(a);\n'
                             '        String b = "HmacSHA1";\n'
                             '        Mac n = Mac.getInstance(b);', tier1)
    assert found[(LINE + 1, HASH)] is Decision.VIOLATION
    # 표 3: HMAC용 SHA-1은 쓸 수 있다
    assert found.get((LINE + 3, HASH)) in (None, Decision.CLEAN)


@pytest.mark.parametrize("call, decision", [
    ("DigestUtils.md5Hex(x)", Decision.VIOLATION),
    ("DigestUtils.sha1Hex(x)", Decision.VIOLATION),
    ("DigestUtils.md5(x)", Decision.VIOLATION),
    ("DigestUtils.shaHex(x)", Decision.VIOLATION),
    ("DigestUtils.md5DigestAsHex(x)", Decision.VIOLATION),   # Spring
    ("Hashing.md5()", Decision.VIOLATION),                   # Guava
    ("SecureUtil.md5(x)", Decision.VIOLATION),               # hutool
    ("DigestUtils.sha256Hex(x)", None),
])
def test_digest_wrappers_name_their_algorithm(tmp_path, tier1, call, decision):
    found = judged(tmp_path, f'        String x = "a";\n        Object h = {call};', tier1)
    if decision is None:
        assert found.get((LINE + 1, HASH)) in (None, Decision.CLEAN)
    else:
        assert found[(LINE + 1, HASH)] is decision


def test_unrelated_md5_method_is_not_a_digest_wrapper(tmp_path, tier1):
    found = judged(tmp_path, '        String x = "a";\n        Object h = cache.md5(x);', tier1)
    assert (LINE + 1, HASH) not in found


def test_algorithm_field_set_by_constructor_of_static_instances(tmp_path, tier1):
    # nacos NacosSignatureAlgorithm: 알고리즘 이름이 생성자 인자로 필드에 들어가고, 생성은 같은 파일의 정적 인스턴스
    code = ("import javax.crypto.Mac;\npublic class Alg {\n"
            "    static final Alg HS = new Alg(\"HmacMD5\");\n"
            "    private final String jcaName;\n"
            "    private Alg(String jcaName) { this.jcaName = jcaName; }\n"
            "    Mac mac() throws Exception { return Mac.getInstance(jcaName); }\n}\n")
    (tmp_path / "Alg.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    found = {(f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}
    assert found[(6, HASH)] is Decision.VIOLATION


def test_hmac_output_depends_on_its_key(tmp_path, tier1):
    # nacos CalculateV4SigningKeyUtil: 상수 데이터를 밖에서 온 키로 HMAC한 값은 상수가 아니다
    found = judged(tmp_path, '        Mac mac = Mac.getInstance("HmacSHA256");\n'
                             '        mac.init(new SecretKeySpec(k, "HmacSHA256"));\n'
                             '        byte[] d = mac.doFinal("aliyun_v4_request".getBytes());\n'
                             '        SecretKeySpec s = new SecretKeySpec(d, "AES");', tier1)
    assert found[(LINE + 3, "CRYPTO-KEY-HARDCODED")] is Decision.UNDETERMINED


def test_hmac_with_constant_key_and_data_is_constant(tmp_path, tier1):
    found = judged(tmp_path, '        Mac mac = Mac.getInstance("HmacSHA256");\n'
                             '        mac.init(new SecretKeySpec("k".getBytes(), "HmacSHA256"));\n'
                             '        byte[] d = mac.doFinal("data".getBytes());\n'
                             '        SecretKeySpec s = new SecretKeySpec(d, "AES");', tier1)
    assert found[(LINE + 3, "CRYPTO-KEY-HARDCODED")] is Decision.VIOLATION


@pytest.mark.parametrize("expr", ["new java.util.Random().nextFloat()", "new java.util.Random().nextInt(10)"])
def test_fully_qualified_object_creation_is_recognized(tmp_path, tier1, expr):
    # OWASP Benchmark(약한 난수 493건) 채점에서 드러난 결함(2026-10-09): `new java.util.Random()`처럼 패키지까지
    # 적은 객체 생성을 트리거 `new Random`과 맞추지 못했다. 메서드 호출 쪽은 4차에서 고쳤지만 객체 생성은 빠져 있었다
    found = judged(tmp_path, f"        double r = {expr};", tier1)
    assert found[(LINE, "CRYPTO-RNG-INSECURE")] is Decision.VIOLATION


@pytest.mark.parametrize("fill, rule, sink", [
    ("new java.util.Random().nextBytes(b);", "CRYPTO-IV-STATIC", "IvParameterSpec s = new IvParameterSpec(b);"),
    ("new java.util.Random().nextBytes(b);", "CRYPTO-KEY-HARDCODED",
     'SecretKeySpec s = new SecretKeySpec(b, "AES");'),
])
def test_material_from_weak_random_is_a_violation(tmp_path, tier1, fill, rule, sink):
    # CamBench_Cap(MSR 2022) 채점에서 드러난 결함(2026-10-09): 약한 난수로 만든 IV·키를 "확인 필요"로 보냈다.
    # NIST SP 800-38A는 IV가 예측 불가능해야 한다고 하고, java.util.Random 출력은 예측할 수 있다
    found = judged(tmp_path, f"        byte[] b = new byte[16];\n        {fill}\n        {sink}", tier1)
    assert found[(LINE + 2, rule)] is Decision.VIOLATION


def test_hardcoded_des_key_spec(tmp_path, tier1):
    found = judged(tmp_path, '        DESKeySpec s = new DESKeySpec("12345678".getBytes());', tier1)
    assert found[(LINE, "CRYPTO-KEY-HARDCODED")] is Decision.VIOLATION


def test_static_gcm_nonce(tmp_path, tier1):
    found = judged(tmp_path, '        GCMParameterSpec g = new GCMParameterSpec(128, NONCE);', tier1,
                   fields='    static final byte[] NONCE = "abcdefghijkl".getBytes();\n')
    assert found[(LINE + 1, "CRYPTO-IV-STATIC")] is Decision.VIOLATION


def test_random_gcm_nonce_is_clean(tmp_path, tier1):
    found = judged(tmp_path, '        byte[] iv = new byte[12];\n'
                             '        new SecureRandom().nextBytes(iv);\n'
                             '        GCMParameterSpec g = new GCMParameterSpec(128, iv);', tier1)
    assert found.get((LINE + 2, "CRYPTO-IV-STATIC")) in (None, Decision.CLEAN)
