"""
파일 경계를 넘는 출처 판별을 고정한다.

개발 코퍼스에서 지점은 잡았지만 값을 못 찾은 자리가 25%였다(키 0.42, IV 0.21, 비밀번호 0.51만 확인).
원인 대부분이 출처 판별이 파일 하나만 본다는 데 있었다.

- 유틸 메서드의 인자인데 부르는 곳이 다른 파일: "이 파일에 부르는 곳이 없다" (nacos `SignUtil.sign`)
- 다른 클래스의 상수: "`RamConstants.SIGNATURE_V4_PRODUCE`의 출처를 따라가지 않는다"
- 다른 클래스 메서드가 돌려주는 값

클래스가 맞을 때만 잇는다. 이름이 같다는 것만으로 이으면 엉뚱한 값이 섞인다(call_index의 교훈).
테스트 코드에서만 부르는 운영 코드의 유틸은 테스트 값으로 판정하지 않는다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict

KEY = "CRYPTO-KEY-HARDCODED"
IV = "CRYPTO-IV-STATIC"
HEAD = "package p;\nimport javax.crypto.spec.*;\nimport java.security.SecureRandom;\n"


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def judged(root: Path, files: dict[str, str], tier1) -> dict[tuple[str, int, str], Decision]:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(root), root=root, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.extract_sites(state)
    state = pipeline.judge_sites(state, StaticVerdict(), None)
    return {(Path(f.site.file_path).name, f.site.line, f.rule.rule_id): f.verdict.decision
            for f in state.findings}


UTIL = (HEAD + "public class CryptoUtil {\n"
        "    public static SecretKeySpec key(byte[] raw) {\n"
        "        return new SecretKeySpec(raw, \"AES\");\n"      # 줄 6
        "    }\n}\n")
SITE = ("CryptoUtil.java", 6, KEY)


def test_constant_passed_from_another_file(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/CryptoUtil.java": UTIL,
        "src/main/java/p/App.java": HEAD + "class App {\n    void run() {\n"
            "        CryptoUtil.key(\"0123456789abcdef\".getBytes());\n    }\n}\n",
    }, tier1)
    assert found[SITE] is Decision.VIOLATION


def test_secure_random_key_passed_from_another_file(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/CryptoUtil.java": UTIL,
        "src/main/java/p/App.java": HEAD + "class App {\n    void run() {\n"
            "        byte[] k = new byte[16];\n        new SecureRandom().nextBytes(k);\n"
            "        CryptoUtil.key(k);\n    }\n}\n",
    }, tier1)
    assert found.get(SITE) in (None, Decision.CLEAN)


def test_callers_only_in_tests_do_not_decide_production_code(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/CryptoUtil.java": UTIL,
        "src/test/java/p/CryptoUtilTest.java": HEAD + "class CryptoUtilTest {\n    void t() {\n"
            "        CryptoUtil.key(\"0123456789abcdef\".getBytes());\n    }\n}\n",
    }, tier1)
    assert found[SITE] is Decision.UNDETERMINED


def test_same_method_name_on_another_class_is_not_a_caller(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/CryptoUtil.java": UTIL,
        "src/main/java/p/Other.java": HEAD + "class Other {\n"
            "    static Object key(byte[] b) { return b; }\n"
            "    void run() { Other.key(\"0123456789abcdef\".getBytes()); }\n}\n",
    }, tier1)
    assert found[SITE] is Decision.UNDETERMINED


def test_instance_receiver_typed_as_the_class(tmp_path, tier1):
    util = (HEAD + "public class Box {\n"
            "    public SecretKeySpec key(byte[] raw) {\n"
            "        return new SecretKeySpec(raw, \"AES\");\n"
            "    }\n}\n")
    found = judged(tmp_path, {
        "src/main/java/p/Box.java": util,
        "src/main/java/p/App.java": HEAD + "class App {\n    void run() {\n"
            "        Box box = new Box();\n        box.key(\"0123456789abcdef\".getBytes());\n    }\n}\n",
    }, tier1)
    assert found[("Box.java", 6, KEY)] is Decision.VIOLATION


def test_constructor_called_from_another_file(tmp_path, tier1):
    holder = (HEAD + "public class Holder {\n    private final SecretKeySpec spec;\n"
              "    public Holder(String secret) {\n"
              "        this.spec = new SecretKeySpec(secret.getBytes(), \"AES\");\n"   # 줄 7
              "    }\n}\n")
    found = judged(tmp_path, {
        "src/main/java/p/Holder.java": holder,
        "src/main/java/p/App.java": HEAD + "class App {\n"
            "    Holder h = new Holder(\"0123456789abcdef\");\n}\n",
    }, tier1)
    assert found[("Holder.java", 7, KEY)] is Decision.VIOLATION


CONSTS = HEAD + "public class Keys {\n    public static final String KEY = \"0123456789abcdef\";\n}\n"


@pytest.mark.parametrize("use, imports", [
    ("Keys.KEY", ""),
    ("p.Keys.KEY", ""),
    ("KEY", "import static p.Keys.KEY;\n"),
    ("KEY", "import static p.Keys.*;\n"),
])
def test_constant_declared_in_another_class(tmp_path, tier1, use, imports):
    found = judged(tmp_path, {
        "src/main/java/p/Keys.java": CONSTS,
        "src/main/java/p/App.java": HEAD + imports + "class App {\n    void run() {\n"
            f"        SecretKeySpec s = new SecretKeySpec({use}.getBytes(), \"AES\");\n    }}\n}}\n",
    }, tier1)
    line = 6 + (1 if imports else 0)
    assert found[("App.java", line, KEY)] is Decision.VIOLATION


def test_constant_inherited_from_an_interface(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/Consts.java": HEAD + "public interface Consts {\n"
            "    String KEY = \"0123456789abcdef\";\n}\n",
        "src/main/java/p/App.java": HEAD + "class App implements Consts {\n    void run() {\n"
            "        SecretKeySpec s = new SecretKeySpec(KEY.getBytes(), \"AES\");\n    }\n}\n",
    }, tier1)
    assert found[("App.java", 6, KEY)] is Decision.VIOLATION


def test_ambiguous_class_name_is_not_resolved(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/Keys.java": CONSTS,
        "src/main/java/q/Keys.java": "package q;\npublic class Keys {\n"
            "    public static final String KEY = System.getenv(\"K\");\n}\n",
        "src/main/java/p/App.java": HEAD + "class App {\n    void run() {\n"
            "        SecretKeySpec s = new SecretKeySpec(Keys.KEY.getBytes(), \"AES\");\n    }\n}\n",
    }, tier1)
    assert found[("App.java", 6, KEY)] is Decision.UNDETERMINED


def test_algorithm_name_from_another_class_constant(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/Algos.java": HEAD + "public class Algos {\n"
            "    public static final String TRANSFORMATION = \"AES/ECB/PKCS5Padding\";\n}\n",
        "src/main/java/p/App.java": HEAD + "import javax.crypto.Cipher;\nclass App {\n    void run() throws Exception {\n"
            "        Cipher c = Cipher.getInstance(Algos.TRANSFORMATION);\n    }\n}\n",
    }, tier1)
    assert found[("App.java", 7, "CRYPTO-MODE-ECB")] is Decision.VIOLATION


def test_algorithm_name_passed_from_another_file(tmp_path, tier1):
    util = (HEAD + "import java.security.MessageDigest;\npublic class Hasher {\n"
            "    public static byte[] hash(String algorithm, byte[] d) throws Exception {\n"
            "        return MessageDigest.getInstance(algorithm).digest(d);\n"     # 줄 7
            "    }\n}\n")
    found = judged(tmp_path, {
        "src/main/java/p/Hasher.java": util,
        "src/main/java/p/App.java": HEAD + "class App {\n    void run() throws Exception {\n"
            "        Hasher.hash(\"MD5\", new byte[0]);\n    }\n}\n",
    }, tier1)
    assert found[("Hasher.java", 7, "CRYPTO-HASH-WEAK")] is Decision.VIOLATION


def test_value_returned_by_another_class(tmp_path, tier1):
    found = judged(tmp_path, {
        "src/main/java/p/Cfg.java": HEAD + "public class Cfg {\n"
            "    public static byte[] iv() { return new byte[16]; }\n}\n",
        "src/main/java/p/App.java": HEAD + "class App {\n    void run() {\n"
            "        IvParameterSpec s = new IvParameterSpec(Cfg.iv());\n    }\n}\n",
    }, tier1)
    assert found[("App.java", 6, IV)] is Decision.VIOLATION


def test_common_method_name_is_narrowed_by_class_mention(tmp_path, tier1):
    # `go`를 부르는 파일이 아주 많아도 이 클래스를 언급하는 파일만 보면 따라갈 수 있다
    files = {f"src/main/java/p/Noise{i}.java": HEAD + f"class Noise{i} {{ void go(int x) {{}} void r() {{ go(1); }} }}\n"
             for i in range(80)}
    files["src/main/java/p/Util.java"] = (HEAD + "public class Util {\n    public void go(byte[] raw) {\n"
                                          "        new SecretKeySpec(raw, \"AES\");\n    }\n}\n")   # 줄 6
    files["src/main/java/p/Main.java"] = (HEAD + "class Main {\n    void run() {\n"
                                          "        new Util().go(\"0123456789abcdef\".getBytes());\n    }\n}\n")
    found = judged(tmp_path, files, tier1)
    assert found[("Util.java", 6, KEY)] is Decision.VIOLATION
