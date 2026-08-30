"""
검사 대상의 신원 기록을 확인한다.

보고서는 어느 커밋의 코드에 대한 것인지 증명할 수 있어야 한다. 스냅샷이 틀리면
보고서와 코드를 잇지 못하고, 의존성 파싱이 틀리면 없는 라이브러리를 쓴다고 적게 된다.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from rag_app.analysis import repo_info


def _git(root: Path, *args: str):
    subprocess.run(["git", "-C", str(root), "-c", "user.email=t@t", "-c",
                    "user.name=t", *args], check=True, capture_output=True)


def test_snapshot_records_commit(tmp_path):
    _git(tmp_path, "init", "-b", "main")
    (tmp_path / "a.txt").write_text("x")
    _git(tmp_path, "add", "."); _git(tmp_path, "commit", "-m", "c1")
    info = repo_info.snapshot(tmp_path)
    assert info is not None
    assert len(info["revisionId"]) == 40
    assert info["branch"] == "main"


def test_snapshot_none_outside_git(tmp_path):
    """git이 아니면 스냅샷을 지어내지 않는다. 없다고 답해야 보고서에 그렇게 적힌다."""
    assert repo_info.snapshot(tmp_path) is None


def test_maven_dependencies(tmp_path):
    (tmp_path / "pom.xml").write_text("""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk15on</artifactId>
      <version>1.46</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId><artifactId>junit</artifactId>
      <version>${junit.version}</version>
    </dependency>
  </dependencies>
</project>""")
    found = repo_info.dependencies(tmp_path)
    assert {"ecosystem": "maven", "name": "org.bouncycastle:bcprov-jdk15on",
            "version": "1.46"} in found
    # 속성 참조 버전은 풀지 않고 그대로 적는다. 풀려면 빌드 도구가 필요하다.
    assert any(d["version"] == "${junit.version}" for d in found)


def test_gradle_and_python_dependencies(tmp_path):
    (tmp_path / "build.gradle").write_text(
        'implementation "com.google.guava:guava:31.1-jre"\n'
        "testImplementation('junit:junit:4.13.2')\n")
    (tmp_path / "requirements.txt").write_text(
        "pycryptodome==3.19.0\n# 주석\ncryptography>=41.0\n")
    found = repo_info.dependencies(tmp_path)
    names = {d["name"] for d in found}
    assert {"com.google.guava:guava", "junit:junit",
            "pycryptodome", "cryptography"} <= names


def test_dependencies_deterministic(tmp_path):
    """훑는 순서가 바뀌어도 같은 목록이 나와야 보고서가 diff로 비교된다."""
    (tmp_path / "requirements.txt").write_text("b==1\na==2\n")
    assert repo_info.dependencies(tmp_path) == repo_info.dependencies(tmp_path)
    assert [d["name"] for d in repo_info.dependencies(tmp_path)] == ["a", "b"]
