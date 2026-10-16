"""
Hutool(`cn.hutool.crypto`) 래퍼를 JCA 호출과 같은 기준으로 본다 (2026-10-09).

- `SecureUtil.aes(key)`, `new AES(key)`: 운영모드를 안 주면 AES/ECB/PKCS5Padding
- `SecureUtil.des(key)`, `new DES(...)`: 폐기 알고리즘
- `SignAlgorithm.SHA1withRSA`, `DigestAlgorithm.MD5`: 열거 상수가 곧 알고리즘 이름
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict

ECB = "CRYPTO-MODE-ECB"


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def decisions(tmp_path: Path, code: str, tier1) -> dict[int, dict[str, set]]:
    (tmp_path / "T.java").write_text(code, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(tmp_path), root=tmp_path, rules=tier1,
                                   thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    found: dict[int, dict[str, set]] = {}
    for f in state.findings:
        found.setdefault(f.site.line, {}).setdefault(f.rule.rule_id, set()).add(f.verdict.decision)
    return found


def line_of(code: str, needle: str) -> int:
    return next(i for i, l in enumerate(code.splitlines(), 1) if needle in l)


CODE = """import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.asymmetric.Sign;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.digest.DigestAlgorithm;
import cn.hutool.crypto.symmetric.AES;
public class T {
    void a(byte[] key, byte[] iv) {
        AES one = SecureUtil.aes(key);
        AES two = new AES(key);
        AES three = new AES(Mode.CBC, Padding.PKCS5Padding, key, iv);
        AES four = new AES("ECB", "PKCS5Padding", key);
        Object five = SecureUtil.des(key);
        Sign sign = new Sign(SignAlgorithm.SHA1withRSA, null, null);
        Sign good = new Sign(SignAlgorithm.SHA256withRSA, null, null);
        Object digest = new Object[]{DigestAlgorithm.MD5};
    }
}
"""


def violated(found, line) -> bool:
    return any(Decision.VIOLATION in d for d in found.get(line, {}).values())


def test_hutool_default_mode_is_ecb(tmp_path, tier1):
    found = decisions(tmp_path, CODE, tier1)
    assert Decision.VIOLATION in found[line_of(CODE, "SecureUtil.aes(key)")][ECB]
    assert Decision.VIOLATION in found[line_of(CODE, "new AES(key)")][ECB]
    assert Decision.VIOLATION in found[line_of(CODE, '"ECB", "PKCS5Padding"')][ECB]
    assert ECB not in found.get(line_of(CODE, "Mode.CBC"), {})


def test_hutool_weak_algorithms(tmp_path, tier1):
    found = decisions(tmp_path, CODE, tier1)
    assert violated(found, line_of(CODE, "SecureUtil.des(key)"))
    assert violated(found, line_of(CODE, "SignAlgorithm.SHA1withRSA"))
    assert violated(found, line_of(CODE, "DigestAlgorithm.MD5"))
    assert not violated(found, line_of(CODE, "SignAlgorithm.SHA256withRSA"))


def test_same_names_without_hutool_are_ignored(tmp_path, tier1):
    code = CODE.replace("cn.hutool.crypto", "com.example.mine")
    found = decisions(tmp_path, code, tier1)
    assert not violated(found, line_of(code, "new AES(key)"))
    assert not violated(found, line_of(code, "SignAlgorithm.SHA1withRSA"))
