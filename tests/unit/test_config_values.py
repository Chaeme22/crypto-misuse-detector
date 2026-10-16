"""
저장소 안 설정 파일의 값을 따라간다 (2026-10-09).

`props.getProperty("hashAlg1")`, `@Value("${seed.iv}")`처럼 값이 설정 파일에서 오면 전에는 늘 "외부 입력 → 확인 필요"였다.
설정 파일(`*.properties`, `application*.yml`)이 저장소에 함께 있으면 그 값을 쓴다. 저장소에 커밋된 키·IV는 코드에 적은 것과
같이 노출되고 고정된다. 키가 없거나 값이 환경 변수 자리(`${ENV}`)면 예전처럼 외부 입력이다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag_app.analysis import pipeline, rules
from rag_app.analysis.findings import Decision
from rag_app.analysis.thresholds import ThresholdTable
from rag_app.analysis.verdict import StaticVerdict

HASH, IV, KEY = "CRYPTO-HASH-WEAK", "CRYPTO-IV-STATIC", "CRYPTO-KEY-HARDCODED"


@pytest.fixture(scope="module")
def tier1():
    return rules.load()


def judged(root: Path, files: dict[str, str], tier1) -> dict[tuple[str, int, str], Decision]:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    state = pipeline.AnalysisState(target=str(root), root=root, rules=tier1, thresholds=ThresholdTable.load())
    state = pipeline.judge_sites(pipeline.extract_sites(state), StaticVerdict(), None)
    return {(Path(f.site.file_path).name, f.site.line, f.rule.rule_id): f.verdict.decision for f in state.findings}


PROPS_JAVA = """import java.security.MessageDigest;
import java.util.Properties;
public class H {
    void a(Properties props) throws Exception {
        MessageDigest weak = MessageDigest.getInstance(props.getProperty("hashAlg1", "SHA-512"));
        MessageDigest strong = MessageDigest.getInstance(props.getProperty("hashAlg2", "MD5"));
        MessageDigest unknown = MessageDigest.getInstance(props.getProperty("missing"));
    }
}
"""


def test_properties_value_decides(tmp_path, tier1):
    found = judged(tmp_path, {"src/main/java/H.java": PROPS_JAVA,
                              "src/main/resources/app.properties": "hashAlg1=MD5\nhashAlg2=SHA-256\n"}, tier1)
    assert found[("H.java", 5, HASH)] is Decision.VIOLATION
    assert found.get(("H.java", 6, HASH)) in (None, Decision.CLEAN)
    assert found[("H.java", 7, HASH)] is Decision.UNDETERMINED


SPRING_JAVA = """import javax.crypto.spec.*;
import org.springframework.beans.factory.annotation.Value;
public class S {
    @Value("${seed.iv}")
    private String iv;
    @Value("${seed.key}")
    private String key;
    @Value("${seed.env-key}")
    private String envKey;
    void a(byte[] k) {
        IvParameterSpec s = new IvParameterSpec(iv.getBytes());
        SecretKeySpec t = new SecretKeySpec(key.getBytes(), "AES");
        SecretKeySpec u = new SecretKeySpec(envKey.getBytes(), "AES");
    }
}
"""

YAML = """seed:
  iv: "1234567890123456"
  key: myHardcodedKey16
  env-key: ${SEED_KEY}
"""


def test_spring_value_from_application_yml(tmp_path, tier1):
    found = judged(tmp_path, {"src/main/java/S.java": SPRING_JAVA,
                              "src/main/resources/application.yml": YAML}, tier1)
    assert found[("S.java", 11, IV)] is Decision.VIOLATION
    assert found[("S.java", 12, KEY)] is Decision.VIOLATION
    assert found[("S.java", 13, KEY)] is Decision.UNDETERMINED


def test_spring_value_default_is_used_when_key_missing(tmp_path, tier1):
    code = SPRING_JAVA.replace('"${seed.iv}"', '"${seed.iv2:abcdefghabcdefgh}"')
    found = judged(tmp_path, {"src/main/java/S.java": code,
                              "src/main/resources/application.properties": "seed.key=x\n"}, tier1)
    assert found[("S.java", 11, IV)] is Decision.VIOLATION


def test_without_config_file_stays_external(tmp_path, tier1):
    found = judged(tmp_path, {"src/main/java/S.java": SPRING_JAVA}, tier1)
    assert found[("S.java", 11, IV)] is Decision.UNDETERMINED
