"""
값 추적의 민감도를 고정한다 (2026-10-09).

- 문맥 민감도: 같은 메서드를 다른 값으로 부를 때, 이 지점에 실제로 흘러온 호출의 인자만 본다
- 흐름 민감도: 값을 쓰는 시점 이전에 실행된 대입·채우기만 본다
- 필드·객체 민감도: 같은 클래스의 다른 객체를 가린다
- 경로 민감도: 상수 조건으로 죽은 분기는 뺀다
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict

HASH, IV, KEY, ECB, OBS = ("CRYPTO-HASH-WEAK", "CRYPTO-IV-STATIC", "CRYPTO-KEY-HARDCODED",
                           "CRYPTO-MODE-ECB", "CRYPTO-CIPHER-OBSOLETE")


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def judged(tmp_path: Path, code: str, tier1) -> dict[tuple[int, str], Decision]:
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    return {(f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}


def line_of(code: str, needle: str) -> int:
    return next(i for i, l in enumerate(code.splitlines(), 1) if needle in l)


HEAD = "import java.security.*;\nimport javax.crypto.*;\nimport javax.crypto.spec.*;\n"


# --- 문맥 민감도 -------------------------------------------------------------------

CONTEXT_HASH = HEAD + """public class T {
    static String identity(String s) { return s; }
    void a() throws Exception {
        String weak = identity("MD5");
        String strong = identity("SHA-256");
        MessageDigest md = MessageDigest.getInstance(strong);
    }
    void b() throws Exception {
        String strong = identity("SHA-256");
        String weak = identity("MD5");
        MessageDigest md = MessageDigest.getInstance(weak);
    }
}
"""


def test_context_return_value_follows_its_own_call(tmp_path, tier1):
    found = judged(tmp_path, CONTEXT_HASH, tier1)
    safe = line_of(CONTEXT_HASH, "getInstance(strong)")
    unsafe = line_of(CONTEXT_HASH, "getInstance(weak)")
    assert found.get((safe, HASH)) in (None, Decision.CLEAN)
    assert found[(unsafe, HASH)] is Decision.VIOLATION


CONTEXT_IV = HEAD + """public class T {
    static byte[] pass(byte[] b) { return b; }
    void a(Cipher c, SecretKey k) throws Exception {
        byte[] fixed = "abcdefghijklmnop".getBytes();
        byte[] fresh = new byte[16];
        new SecureRandom().nextBytes(fresh);
        byte[] unused = pass(fixed);
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(pass(fresh)));
    }
}
"""


def test_context_material_through_helper(tmp_path, tier1):
    found = judged(tmp_path, CONTEXT_IV, tier1)
    line = line_of(CONTEXT_IV, "new IvParameterSpec(pass(fresh))")
    assert found.get((line, IV)) in (None, Decision.CLEAN)


# --- 흐름 민감도 -------------------------------------------------------------------

FLOW_LATE_FILL = HEAD + """public class T {
    void a(Cipher c, SecretKey k) throws Exception {
        byte[] iv = "abcdefghijklmnop".getBytes();
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
        new SecureRandom().nextBytes(iv);
    }
}
"""


def test_flow_fill_after_use_does_not_count(tmp_path, tier1):
    found = judged(tmp_path, FLOW_LATE_FILL, tier1)
    assert found[(line_of(FLOW_LATE_FILL, "new IvParameterSpec(iv)"), IV)] is Decision.VIOLATION


FLOW_REASSIGN = HEAD + """public class T {
    void a() throws Exception {
        String alg = "MD5";
        alg = "SHA-256";
        MessageDigest md = MessageDigest.getInstance(alg);
    }
    void b() throws Exception {
        String alg = "SHA-256";
        MessageDigest first = MessageDigest.getInstance(alg);
        alg = "MD5";
    }
}
"""


def test_flow_only_reaching_assignment_counts(tmp_path, tier1):
    found = judged(tmp_path, FLOW_REASSIGN, tier1)
    lines = [i for i, l in enumerate(FLOW_REASSIGN.splitlines(), 1) if "getInstance(alg)" in l]
    for line in lines:
        assert found.get((line, HASH)) in (None, Decision.CLEAN), line


FLOW_BRANCH = HEAD + """public class T {
    void a(boolean legacy) throws Exception {
        String alg = "SHA-256";
        if (legacy) { alg = "MD5"; }
        MessageDigest md = MessageDigest.getInstance(alg);
    }
}
"""


def test_flow_branch_that_may_run_still_counts(tmp_path, tier1):
    found = judged(tmp_path, FLOW_BRANCH, tier1)
    assert found[(line_of(FLOW_BRANCH, "getInstance(alg)"), HASH)] is Decision.VIOLATION


HELPER_FILL = HEAD + """public class T {
    static void setBit(byte[] data, int pos, int value) { data[pos / 8] |= (byte) (value << (pos % 8)); }
    static byte[] derive(byte[] in) {
        byte[] out = new byte[8];
        for (int i = 0; i < 64; i++) { setBit(out, i, in[i % in.length] & 1); }
        return out;
    }
    void a(byte[] secret) throws Exception {
        SecretKeySpec s = new SecretKeySpec(derive(secret), "DES");
    }
}
"""


def test_array_filled_by_own_helper_is_not_a_zero_constant(tmp_path, tier1):
    # Apache Directory DesStringToKey: 빈 배열을 `setBit(out, ...)`으로 채워 돌려준다. 채우는 도우미를 모르면 0 배열 상수로 오인
    found = judged(tmp_path, HELPER_FILL, tier1)
    assert found.get((line_of(HELPER_FILL, "new SecretKeySpec(derive"), KEY)) is not Decision.VIOLATION


# --- 필드·객체 민감도 ------------------------------------------------------------------

OBJECT = HEAD + """public class T {
    static class Cfg {
        final String alg;
        Cfg(String alg) { this.alg = alg; }
    }
    void a() throws Exception {
        Cfg weak = new Cfg("DES");
        Cfg strong = new Cfg("AES/GCM/NoPadding");
        Cipher c = Cipher.getInstance(strong.alg);
        Cipher d = Cipher.getInstance(weak.alg);
    }
}
"""


def test_object_field_follows_its_own_construction(tmp_path, tier1):
    found = judged(tmp_path, OBJECT, tier1)
    safe = line_of(OBJECT, "getInstance(strong.alg)")
    unsafe = line_of(OBJECT, "getInstance(weak.alg)")
    assert found.get((safe, OBS)) in (None, Decision.CLEAN)
    assert found.get((safe, ECB)) is None
    assert found[(unsafe, OBS)] is Decision.VIOLATION


FIELD_PATH = HEAD + """public class T {
    static class H { public H inner; public String a1; public String a2; }
    void a() throws Exception {
        H h = new H();
        h.a1 = "MD5";
        h.a2 = "SHA-256";
        MessageDigest weak = MessageDigest.getInstance(h.a1);
        MessageDigest strong = MessageDigest.getInstance(h.a2);
    }
    void b() throws Exception {
        H h = new H();
        h.inner = new H();
        h.inner.a1 = "MD5";
        h.inner.a2 = "SHA-256";
        MessageDigest strong = MessageDigest.getInstance(h.inner.a2);
        MessageDigest weak = MessageDigest.getInstance(h.inner.a1);
    }
}
"""


def test_field_access_path_written_in_the_method(tmp_path, tier1):
    found = judged(tmp_path, FIELD_PATH, tier1)
    for needle, bad in (("getInstance(h.a1)", True), ("getInstance(h.a2)", False),
                        ("getInstance(h.inner.a1)", True), ("getInstance(h.inner.a2)", False)):
        decision = found.get((line_of(FIELD_PATH, needle), HASH))
        if bad:
            assert decision is Decision.VIOLATION, needle
        else:
            assert decision in (None, Decision.CLEAN), needle


PREFIX = HEAD + """public class T {
    void a(String alg, String pad) throws Exception {
        Signature s = Signature.getInstance("SHA1with" + alg);
        Signature t = Signature.getInstance("SHA256with" + alg);
        Cipher c = Cipher.getInstance("AES/ECB/" + pad);
        Cipher d = Cipher.getInstance("AES/GCM/" + pad);
    }
}
"""


def test_constant_prefix_decides_when_it_is_enough(tmp_path, tier1):
    found = judged(tmp_path, PREFIX, tier1)
    assert found[(line_of(PREFIX, '"SHA1with"'), HASH)] is Decision.VIOLATION
    assert found.get((line_of(PREFIX, '"SHA256with"'), HASH)) is not Decision.VIOLATION
    assert found[(line_of(PREFIX, '"AES/ECB/"'), ECB)] is Decision.VIOLATION
    assert found.get((line_of(PREFIX, '"AES/GCM/"'), ECB)) is None


KEYSIZE = HEAD + """public class T {
    static int size(int s) { return s; }
    void a() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        int keySize = 1024;
        g.initialize(keySize);
        keySize = 4096;
    }
    void b() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        int small = size(1024);
        int big = size(4096);
        g.initialize(big);
    }
}
"""


def test_key_size_is_flow_and_context_sensitive(tmp_path, tier1):
    found = judged(tmp_path, KEYSIZE, tier1)
    lines = [i for i, l in enumerate(KEYSIZE.splitlines(), 1) if "g.initialize(" in l]
    assert found[(lines[0], "CRYPTO-KEYSIZE-SHORT")] is Decision.VIOLATION   # 쓸 때는 1024
    assert found.get((lines[1], "CRYPTO-KEYSIZE-SHORT")) in (None, Decision.CLEAN)   # big = 4096


# --- 경로 민감도 ----------------------------------------------------------------------

PATH_DEAD = HEAD + """public class T {
    static final boolean LEGACY = false;
    void a() throws Exception {
        String alg = "SHA-256";
        if (false) { alg = "MD5"; }
        if (LEGACY) { alg = "SHA1"; }
        MessageDigest md = MessageDigest.getInstance(alg);
    }
}
"""


RUNTIME_TYPE = HEAD + """import java.util.Random;
public class T {
    static Random identity(Random r) { return r; }
    void a(Cipher c, SecretKey k) throws Exception {
        Random weak = identity(new Random());
        Random strong = identity(new SecureRandom());
        byte[] iv = new byte[16];
        strong.nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
    }
}
"""


def test_receiver_runtime_type_beats_declared_type(tmp_path, tier1):
    found = judged(tmp_path, RUNTIME_TYPE, tier1)
    assert found.get((line_of(RUNTIME_TYPE, "new IvParameterSpec(iv)"), IV)) in (None, Decision.CLEAN)


PATH_COMPARE = HEAD + """public class T {
    void a() throws Exception {
        int condition = 1;
        String alg;
        if (condition > 1) { alg = "MD5"; }
        else { if (condition > 0) { alg = "SHA-256"; } else { alg = "SHA-1"; } }
        MessageDigest md = MessageDigest.getInstance(alg);
    }
    void b(Cipher c, SecretKey k) throws Exception {
        byte[] iv = new byte[16];
        int choice = 0;
        if (choice > 1) { new SecureRandom().nextBytes(iv); } else { new java.util.Random().nextBytes(iv); }
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
    }
}
"""


def test_path_constant_comparison_prunes_branches(tmp_path, tier1):
    found = judged(tmp_path, PATH_COMPARE, tier1)
    assert found.get((line_of(PATH_COMPARE, "getInstance(alg)"), HASH)) in (None, Decision.CLEAN)
    assert found[(line_of(PATH_COMPARE, "new IvParameterSpec(iv)"), IV)] is Decision.VIOLATION


def test_path_dead_branch_is_ignored(tmp_path, tier1):
    found = judged(tmp_path, PATH_DEAD, tier1)
    assert found.get((line_of(PATH_DEAD, "getInstance(alg)"), HASH)) in (None, Decision.CLEAN)


PATH_CALLER = HEAD + """public class T {
    void a() throws Exception {
        int condition = 0;
        if (condition < 1) { digest("SHA-256"); } else { digest("MD5"); }
    }
    void digest(String algo) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo);
    }
}
"""


def test_path_dead_call_site_is_not_an_argument_source(tmp_path, tier1):
    found = judged(tmp_path, PATH_CALLER, tier1)
    assert found.get((line_of(PATH_CALLER, "getInstance(algo)"), HASH)) in (None, Decision.CLEAN)


RUNTIME_FIELD = HEAD + """import java.util.Random;
public class T {
    static class Holder { Random weak; Random strong; }
    void a() throws Exception {
        Holder h = new Holder();
        h.weak = new Random();
        h.strong = new SecureRandom();
        fill(h.strong);
    }
    void fill(Random generator) throws Exception {
        byte[] iv = new byte[16];
        Random r = generator;
        r.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, (SecretKey) null, new IvParameterSpec(iv));
    }
}
"""


def test_receiver_runtime_type_through_field_and_caller(tmp_path, tier1):
    found = judged(tmp_path, RUNTIME_FIELD, tier1)
    assert found.get((line_of(RUNTIME_FIELD, "new IvParameterSpec(iv)"), IV)) in (None, Decision.CLEAN)


FIXED_SEED = HEAD + """public class T {
    void a(Cipher c, SecretKey k) throws Exception {
        byte[] iv = new byte[16];
        SecureRandom r = new SecureRandom();
        r.setSeed(123);
        r.nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
    }
    void b(Cipher c, SecretKey k) throws Exception {
        byte[] nonce = new byte[16];
        SecureRandom r = new SecureRandom();
        r.setSeed(r.generateSeed(16));
        r.nextBytes(nonce);
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(nonce));
    }
}
"""


def test_fixed_seed_makes_secure_random_fill_predictable(tmp_path, tier1):
    found = judged(tmp_path, FIXED_SEED, tier1)
    assert found[(line_of(FIXED_SEED, "new IvParameterSpec(iv)"), IV)] is Decision.VIOLATION
    assert found.get((line_of(FIXED_SEED, "new IvParameterSpec(nonce)"), IV)) in (None, Decision.CLEAN)


RETURNED_OBJECT = HEAD + """public class T {
    static class Holder { String alg; Holder() {} Holder(String a) { alg = a; } }
    static Holder make(String a) { Holder h = new Holder(); h.alg = a; return h; }
    static Holder build(String a) { return new Holder(a); }
    void a() throws Exception {
        Holder weak = make("MD5");
        Holder strong = make("SHA-256");
        MessageDigest one = MessageDigest.getInstance(weak.alg);
        MessageDigest two = MessageDigest.getInstance(strong.alg);
        Holder built = build("SHA-1");
        MessageDigest three = MessageDigest.getInstance(built.alg);
    }
}
"""


def test_field_of_object_returned_by_factory(tmp_path, tier1):
    found = judged(tmp_path, RETURNED_OBJECT, tier1)
    assert found[(line_of(RETURNED_OBJECT, "getInstance(weak.alg)"), HASH)] is Decision.VIOLATION
    assert found.get((line_of(RETURNED_OBJECT, "getInstance(strong.alg)"), HASH)) in (None, Decision.CLEAN)
    assert found[(line_of(RETURNED_OBJECT, "getInstance(built.alg)"), HASH)] is Decision.VIOLATION


PATH_PARAMETER = HEAD + """public class T {
    public void go(int choice, Cipher c, SecretKey k) throws Exception {
        byte[] iv = "abcde".getBytes();
        if (choice > 1) { iv = new byte[16]; new SecureRandom().nextBytes(iv); }
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
    }
    public static void main(String[] args) throws Exception {
        new T().go(2, null, null);
    }
}
"""


def test_public_parameter_condition_is_not_pruned_by_visible_callers(tmp_path, tier1):
    # 이 파일의 호출자는 2만 넘기지만 public 메서드는 다른 곳에서 1로 불릴 수 있다
    found = judged(tmp_path, PATH_PARAMETER, tier1)
    assert found.get((line_of(PATH_PARAMETER, "new IvParameterSpec(iv)"), IV)) not in (None, Decision.CLEAN)


RUNTIME_MADE = HEAD + """import java.util.Random;
public class T {
    static class Box { Random gen; Box() {} Box(Random g) { gen = g; } }
    static Box make(Random r) { Box b = new Box(); b.gen = r; return b; }
    void a(Cipher c, SecretKey k) throws Exception {
        Box strong = new Box(new SecureRandom());
        Box weak = new Box(new Random());
        byte[] iv = new byte[16];
        Random r = strong.gen;
        r.nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
    }
    void b(Cipher c, SecretKey k) throws Exception {
        Box strong = make(new SecureRandom());
        Box weak = make(new Random());
        byte[] nonce = new byte[16];
        weak.gen.nextBytes(nonce);
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(nonce));
    }
}
"""


def test_runtime_type_of_field_set_in_constructor_or_factory(tmp_path, tier1):
    found = judged(tmp_path, RUNTIME_MADE, tier1)
    assert found.get((line_of(RUNTIME_MADE, "new IvParameterSpec(iv)"), IV)) in (None, Decision.CLEAN)
    assert found[(line_of(RUNTIME_MADE, "new IvParameterSpec(nonce)"), IV)] is Decision.VIOLATION


KEY_FIELD = HEAD + """public class T {
    private static final byte[] DATA = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final SecretKeySpec KEY = new SecretKeySpec(DATA, "AES");
    private final SecretKey fresh;
    T() throws Exception { fresh = KeyGenerator.getInstance("AES").generateKey(); }
    byte[] a(byte[] p) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, KEY);
        return c.doFinal(p);
    }
    byte[] b(byte[] p) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, fresh);
        return c.doFinal(p);
    }
}
"""


def test_hardcoded_key_object_is_reported_where_it_is_used(tmp_path, tier1):
    found = judged(tmp_path, KEY_FIELD, tier1)
    assert found[(line_of(KEY_FIELD, "c.init(Cipher.ENCRYPT_MODE, KEY)"), KEY)] is Decision.VIOLATION
    assert (line_of(KEY_FIELD, "c.init(Cipher.ENCRYPT_MODE, fresh)"), KEY) not in found


CTOR_CHAIN = HEAD + """import java.util.Objects;
public class T {
    public static final String DEFAULT = "PBEWithMD5AndDES";
    private final String method;
    public T() { this(DEFAULT); }
    public T(String method) { this.method = Objects.requireNonNull(method, "method"); }
    Cipher make() throws Exception { return Cipher.getInstance(method); }
}
"""


def test_constructor_chain_and_null_check_passthrough(tmp_path, tier1):
    found = judged(tmp_path, CTOR_CHAIN, tier1)
    line = line_of(CTOR_CHAIN, "getInstance(method)")
    assert Decision.VIOLATION in {d for (l, _), d in found.items() if l == line}


VAR_DECL = HEAD + """public class T {
    private static final char[] PASSWORD = "changeit".toCharArray();
    void a(java.io.InputStream in) throws Exception {
        var store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(in, PASSWORD);
        var factory = SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
    }
}
"""


def test_var_declaration_and_pbe_cipher_part(tmp_path, tier1):
    found = judged(tmp_path, VAR_DECL, tier1)
    load = line_of(VAR_DECL, "store.load(in, PASSWORD)")
    assert Decision.VIOLATION in {d for (l, _), d in found.items() if l == load}
    pbe = line_of(VAR_DECL, "PBEWithSHA1AndDESede")
    # 뒤쪽 암호 DESede(112비트)로 잰다 — 깨끗하다고 닫지 않는다
    assert {d for (l, _), d in found.items() if l == pbe} & {Decision.VIOLATION, Decision.WARNING}


PARAM_REASSIGN = HEAD + """public class T {
    byte[] defSalt;
    T(byte[] salt) { defSalt = salt; }
    void use(byte[] passedSalt) {
        passedSalt = defSalt;
        PBEParameterSpec spec = new PBEParameterSpec(passedSalt, 20000);
    }
    static void main(String[] args) {
        byte[] salt = {(byte) 0xa2};
        new T(salt).use(null);
    }
    void stream() throws Exception {
        String k = String.valueOf(new SecureRandom().ints());
        SecretKeySpec spec = new SecretKeySpec(k.getBytes(), "AES");
    }
}
"""


def test_reassigned_parameter_and_random_stream_object(tmp_path, tier1):
    found = judged(tmp_path, PARAM_REASSIGN, tier1)
    assert found[(line_of(PARAM_REASSIGN, "new PBEParameterSpec(passedSalt"), "CRYPTO-SALT-STATIC")] \
        is Decision.VIOLATION
    assert found[(line_of(PARAM_REASSIGN, "new SecretKeySpec(k.getBytes()"), KEY)] is Decision.VIOLATION


COPY_OF = HEAD + """import java.util.Arrays;
public class T {
    void a() throws Exception {
        byte[] keyBytes = "secret".getBytes();
        keyBytes = Arrays.copyOf(keyBytes, 16);
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
    }
}
"""


def test_copy_of_returns_new_array_without_touching_the_argument(tmp_path, tier1):
    found = judged(tmp_path, COPY_OF, tier1)
    assert found[(line_of(COPY_OF, "new SecretKeySpec(keyBytes"), KEY)] is Decision.VIOLATION


MAP_VALUE = HEAD + """import java.util.HashMap;
public class T {
    void a() throws Exception {
        HashMap<String, String> hm = new HashMap<>();
        hm.put("aaa", "abcdefghijklmnop");
        hm.put("bbb", new String(new SecureRandom().generateSeed(16)));
        String key = hm.get("aaa");
        SecretKeySpec one = new SecretKeySpec(key.getBytes(), "AES");
        String other = hm.get("bbb");
        SecretKeySpec two = new SecretKeySpec(other.getBytes(), "AES");
    }
}
"""


def test_map_value_follows_the_same_string_key(tmp_path, tier1):
    found = judged(tmp_path, MAP_VALUE, tier1)
    assert found[(line_of(MAP_VALUE, "new SecretKeySpec(key.getBytes()"), KEY)] is Decision.VIOLATION
    assert found.get((line_of(MAP_VALUE, "new SecretKeySpec(other.getBytes()"), KEY)) is not Decision.VIOLATION


BOXED = HEAD + """public class T {
    void a(byte[] salt) throws Exception {
        Integer count = new Integer(20);
        PBEParameterSpec spec = new PBEParameterSpec(salt, count);
    }
}
"""


def test_boxed_value_is_the_wrapped_constant(tmp_path, tier1):
    found = judged(tmp_path, BOXED, tier1)
    assert found[(line_of(BOXED, "new PBEParameterSpec(salt, count)"), "CRYPTO-KDF-WEAK")] is Decision.VIOLATION


ELEMENTS = HEAD + """public class T {
    void a(boolean flag) throws Exception {
        byte[] key = new byte[16];
        if (flag) { key[0] = 20; key[1] = 30; } else { key[0] = 25; key[1] = 35; }
        SecretKeySpec one = new SecretKeySpec(key, "AES");
    }
    void b(Cipher c, SecretKey k) throws Exception {
        byte[] iv = new byte[16];
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < iv.length; i++) { iv[i] = (byte) r.nextInt(); }
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
    }
}
"""


def test_array_elements_take_the_origin_of_what_is_stored(tmp_path, tier1):
    found = judged(tmp_path, ELEMENTS, tier1)
    assert found[(line_of(ELEMENTS, "new SecretKeySpec(key"), KEY)] is Decision.VIOLATION
    assert found.get((line_of(ELEMENTS, "new IvParameterSpec(iv)"), IV)) is not Decision.VIOLATION


REAL_SHAPES = HEAD + """import java.util.HashMap;
public class T {
    void a(java.io.InputStream in) throws Exception {
        KeyStore empty = KeyStore.getInstance("PKCS12");
        empty.load(null, null);
    }
    void b(byte[] data) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey generated = kg.generateKey();
        SecretKeySpec spec = new SecretKeySpec(generated.getEncoded(), "AES");
    }
    void c(String password, byte[] salt) throws Exception {
        HashMap<String, String> audit = new HashMap<>();
        audit.put("password", password);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 210000, 256);
    }
    void d() throws Exception {
        String password = "changeit";
        HashMap<String, String> audit = new HashMap<>();
        audit.put("password", password);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), new byte[16], 210000, 256);
    }
}
"""


def test_common_real_world_shapes(tmp_path, tier1):
    found = judged(tmp_path, REAL_SHAPES, tier1)
    pw = "CRYPTO-PASSWORD-HARDCODED"
    assert (line_of(REAL_SHAPES, "empty.load(null, null)"), pw) not in found
    assert found.get((line_of(REAL_SHAPES, "new SecretKeySpec(generated.getEncoded()"), KEY)) in (None, Decision.CLEAN)
    # 문자열을 put에 넘겨도 값은 그대로다 — 상수 비밀번호는 상수로 남는다
    d_line = [i for i, l in enumerate(REAL_SHAPES.splitlines(), 1) if "new PBEKeySpec(password.toCharArray()" in l][1]
    assert found[(d_line, pw)] is Decision.VIOLATION


MIXED_NAMES = HEAD + """public class T {
    private static final String[] HASHES = {"SHA-256", "SHA-384", "SHA-512"};
    MessageDigest pick(int i) throws Exception { return MessageDigest.getInstance(HASHES[i % 3]); }
    static MessageDigest digest(String type) throws Exception { return MessageDigest.getInstance(type); }
    void a(String configured) throws Exception {
        digest("SHA");
        digest(configured);
    }
    static Mac mac(String type) throws Exception { return Mac.getInstance(type); }
    void b(String configured) throws Exception {
        mac("HmacSHA1");
        mac(configured);
    }
}
"""


def test_names_from_constant_arrays_and_mixed_paths(tmp_path, tier1):
    found = judged(tmp_path, MIXED_NAMES, tier1)
    pick = line_of(MIXED_NAMES, "HASHES[i % 3]")
    assert {d for (l, _), d in found.items() if l == pick} <= {Decision.CLEAN}
    weak = line_of(MIXED_NAMES, "getInstance(type); }")
    assert found[(weak, HASH)] is Decision.VIOLATION   # 한 경로가 SHA-1
    mac = line_of(MIXED_NAMES, "Mac.getInstance(type)")
    assert Decision.VIOLATION not in {d for (l, _), d in found.items() if l == mac}


STRING_SHAPES = HEAD + """public class T {
    enum Alg { WEAK("MD5"), STRONG("SHA-256"); final String jca; Alg(String j) { jca = j; } }
    void a(boolean c) throws Exception {
        Cipher.getInstance("aes/ecb/pkcs5padding");
        Cipher.getInstance("AES/" + "ECB" + "/PKCS5Padding");
        Cipher.getInstance(String.format("%s/ECB/NoPadding", "AES"));
        Cipher.getInstance(String.join("/", "AES", "ECB", "NoPadding"));
        Cipher.getInstance(new String(new char[]{'R', 'C', '4'}));
        MessageDigest.getInstance(Alg.WEAK.jca);
        MessageDigest.getInstance(Alg.STRONG.jca);
    }
    void b() throws Exception {
        StringBuilder sb = new StringBuilder("AES");
        sb.append("/GCM/NoPadding");
        Cipher.getInstance(sb.toString());
    }
    void c() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(new java.security.spec.RSAKeyGenParameterSpec(1024, java.security.spec.RSAKeyGenParameterSpec.F4));
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    }
}
"""


def test_algorithm_names_built_from_strings(tmp_path, tier1):
    found = judged(tmp_path, STRING_SHAPES, tier1)
    for needle in ('"aes/ecb/pkcs5padding"', '"AES/" + "ECB"', "String.format", "String.join"):
        assert found[(line_of(STRING_SHAPES, needle), ECB)] is Decision.VIOLATION, needle
    assert found[(line_of(STRING_SHAPES, "new char[]"), OBS)] is Decision.VIOLATION
    assert found[(line_of(STRING_SHAPES, "Alg.WEAK.jca"), HASH)] is Decision.VIOLATION
    assert found.get((line_of(STRING_SHAPES, "Alg.STRONG.jca"), HASH)) in (None, Decision.CLEAN)
    # 변수에 담은 StringBuilder는 뒤 문장에서 바뀐다 — 선언 때 값("AES")만 보고 ECB라 하지 않는다
    assert found.get((line_of(STRING_SHAPES, "sb.toString()"), ECB)) is not Decision.VIOLATION


def test_key_size_from_spec_objects_and_per_generator(tmp_path, tier1):
    found = judged(tmp_path, STRING_SHAPES, tier1)
    short = "CRYPTO-KEYSIZE-SHORT"
    assert found[(line_of(STRING_SHAPES, "rsa.initialize("), short)] is Decision.VIOLATION
    assert found.get((line_of(STRING_SHAPES, "ec.initialize("), short)) in (None, Decision.CLEAN)


BASE64_KEY = HEAD + """public class T {
    void a(String fromConfig) throws Exception {
        SecretKeySpec fixed = new SecretKeySpec(java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="), "AES");
        SecretKeySpec outside = new SecretKeySpec(java.util.Base64.getDecoder().decode(fromConfig), "AES");
    }
}
"""


def test_qualified_base64_decoder_of_constant_is_constant(tmp_path, tier1):
    found = judged(tmp_path, BASE64_KEY, tier1)
    assert found[(line_of(BASE64_KEY, "SecretKeySpec fixed"), KEY)] is Decision.VIOLATION
    assert found.get((line_of(BASE64_KEY, "SecretKeySpec outside"), KEY)) is not Decision.VIOLATION


KEY_VIA_PARAMS = HEAD + """public class T {
    KeyPair dh(int keySize) throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(keySize);
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH");
        dh.initialize(paramGen.generateParameters().getParameterSpec(javax.crypto.spec.DHParameterSpec.class));
        return dh.generateKeyPair();
    }
    KeyPair run() throws Exception { return dh(512); }
}
"""


def test_key_size_given_through_parameter_generator(tmp_path, tier1):
    found = judged(tmp_path, KEY_VIA_PARAMS, tier1)
    lines = {l for (l, r), d in found.items() if r == "CRYPTO-KEYSIZE-SHORT" and d is Decision.VIOLATION}
    assert lines, found
