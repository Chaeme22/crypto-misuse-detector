"""
자바 추출기가 값을 어디까지 따라가는지 고정한다.

판정의 바닥이 값이다. 값을 못 찾으면 `확인 필요`가 맞고, 찾았으면 그 값으로 판정해야
한다. 둘을 뒤집으면 없는 값을 추측하거나 있는 위반을 놓친다.

공개 벤치마크로 재면서 세 군데가 끊긴 것을 찾았다. 여기서 그 세 가지를 고정한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import extract, rules


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def sites(tmp_path: Path, code: str, tier1, name: str = "T.java"):
    (tmp_path / name).write_text(code, encoding="utf-8")
    return {site.line: (site, rule) for site, rule in extract.collect(tmp_path, tier1)}


def test_sees_through_value_preserving_calls(tmp_path, tier1):
    """`secret.getBytes()`는 여전히 `secret`의 값이다. 껍데기에서 멈추면 안 된다."""
    found = sites(tmp_path, '''import javax.crypto.spec.SecretKeySpec;
public class T {
    public void a() throws Exception {
        String secret = "hunter2";
        SecretKeySpec k = new SecretKeySpec(secret.getBytes(), "AES");
    }
}
''', tier1)
    site, rule = found[5]
    assert rule.rule_id == "CRYPTO-KEY-HARDCODED"
    assert site.traced_values == ("hunter2",)
    assert site.unresolved_args == ()


def test_object_creation_traces_values(tmp_path, tier1):
    """객체 생성 인자도 따라간다. 전에는 이 분기에 추적이 아예 없었다."""
    found = sites(tmp_path, '''import javax.crypto.spec.IvParameterSpec;
public class T {
    public void b() throws Exception {
        byte[] iv = "0123456789abcdef".getBytes();
        IvParameterSpec s = new IvParameterSpec(iv);
    }
}
''', tier1)
    assert found[5][0].traced_values == ("0123456789abcdef",)


def test_unknown_caller_stays_unresolved(tmp_path, tier1):
    """밖에서 들어온 값은 모른다고 답해야 한다. 추측하면 오탐이 된다."""
    found = sites(tmp_path, '''import javax.crypto.spec.SecretKeySpec;
public class T {
    public void c(byte[] fromCaller) throws Exception {
        SecretKeySpec k = new SecretKeySpec(fromCaller, "AES");
    }
}
''', tier1)
    site, _ = found[4]
    assert site.traced_values == ()
    assert site.unresolved_args == ("fromCaller",)


def test_traces_variable_passed_to_method(tmp_path, tier1):
    """`String c = "DES"; go(c)` 처럼 변수로 넘기는 모양이 벤치마크에서 가장 흔했다."""
    found = sites(tmp_path, '''import javax.crypto.Cipher;
public class T {
    public static void main(String[] a) throws Exception {
        String crypto = "DES/ECB/PKCS5Padding";
        go(crypto);
    }
    static void go(String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
    }
}
''', tier1)
    site, rule = found[8]
    assert site.traced_values == ("DES/ECB/PKCS5Padding",)
    # 운영모드를 CBC로 바꿔도 DES는 안전해지지 않는다. 알고리즘 규칙이 이긴다.
    assert rule.rule_id == "CRYPTO-CIPHER-OBSOLETE"


def test_mode_rule_wins_when_algorithm_is_allowed(tmp_path, tier1):
    """AES는 표에 있으므로 문제는 운영모드다. 규칙 다툼은 표가 가른다."""
    found = sites(tmp_path, '''import javax.crypto.Cipher;
public class T {
    public void a() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
''', tier1)
    assert found[4][1].rule_id == "CRYPTO-MODE-ECB"


def test_unlisted_algorithm_is_caught_without_a_trigger_list(tmp_path, tier1):
    """`RC2`는 어느 트리거 목록에도 없다. 표에 없다는 사실만으로 걸려야 한다."""
    found = sites(tmp_path, '''import javax.crypto.Cipher;
import java.security.MessageDigest;
public class T {
    public void a() throws Exception {
        Cipher c = Cipher.getInstance("RC2");
        MessageDigest d = MessageDigest.getInstance("MD4");
    }
}
''', tier1)
    assert found[5][1].rule_id == "CRYPTO-CIPHER-OBSOLETE"
    assert found[6][1].rule_id == "CRYPTO-HASH-WEAK"


def test_empty_argument_is_not_a_value(tmp_path, tier1):
    """빈 문자열은 값이 아니다. 값으로 받으면 확인 필요가 잘못된 확정으로 바뀐다."""
    found = sites(tmp_path, '''import javax.crypto.Cipher;
public class T {
    public void a() throws Exception {
        run("");
    }
    void run(String algorithm) throws Exception {
        Cipher c = Cipher.getInstance(algorithm);
    }
}
''', tier1)
    site, _ = found[7]
    assert site.traced_values == ()
    assert site.unresolved_args == ("algorithm",)
