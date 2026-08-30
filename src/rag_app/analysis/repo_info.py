"""
검사 대상의 신원 기록. 커밋 스냅샷과 선언된 의존성이다.

보고서는 "어느 시점의 어떤 코드"에 대한 것인지 증명할 수 있어야 한다. SARIF를 받은
사람이 코드를 고친 뒤 다시 검사하면 보고서가 달라지는데, 스냅샷이 없으면 어느 보고서가
어느 코드에 대한 것인지 잇지 못한다. SARIF 표준이 이 용도로 `versionControlProvenance`
자리를 두고 있으므로 커밋 해시와 브랜치를 거기 담는다.

의존성은 선언된 것을 그대로 적는 데서 멈춘다. 전이 의존성까지 풀려면 빌드 도구를
돌려야 하는데(mvn, gradle) 그건 남의 빌드 스크립트를 실행하는 일이라 검사 도구가 할
일이 아니다. 선언 목록만으로도 보고서를 읽는 사람이 "이 프로젝트가 BouncyCastle 1.46을
쓴다"는 것을 알 수 있고, 그거면 이 단계의 몫은 된다.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ..observability.logging import get_logger

logger = get_logger(__name__)

SKIP_DIRS = frozenset({".git", "build", "target", "node_modules", ".venv", "venv"})


def snapshot(root: Path) -> dict | None:
    """
    커밋 스냅샷. git 저장소가 아니면 None.

    시각은 넣지 않는다. 같은 입력에 같은 바이트가 나와야 보고서를 diff로 비교할 수
    있는데, 실행 시각이 들어가면 그 성질이 깨진다. 커밋 해시가 이미 시점을 고정한다.
    """
    def ask(*args: str) -> str | None:
        try:
            done = subprocess.run(["git", "-C", str(root), *args],
                                  capture_output=True, text=True, timeout=30)
            return done.stdout.strip() if done.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    revision = ask("rev-parse", "HEAD")
    if not revision:
        return None
    info: dict = {"revisionId": revision}
    branch = ask("rev-parse", "--abbrev-ref", "HEAD")
    if branch and branch != "HEAD":   # detached HEAD면 브랜치 이름이 없다
        info["branch"] = branch
    remote = ask("remote", "get-url", "origin")
    if remote:
        info["repositoryUri"] = remote
    return info


def dependencies(root: Path) -> list[dict]:
    """
    빌드 파일에 선언된 의존성. (생태계, 이름, 버전)으로 정렬해 돌려준다.

    정렬하는 이유는 스냅샷과 같다. 파일을 훑는 순서가 바뀌어도 보고서가 같아야 한다.
    """
    found: set[tuple[str, str, str]] = set()
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        name = path.name
        try:
            if name == "pom.xml":
                found.update(_maven(path))
            elif name in ("build.gradle", "build.gradle.kts"):
                found.update(_gradle(path))
            elif name == "requirements.txt":
                found.update(_requirements(path))
            elif name == "pyproject.toml":
                found.update(_pyproject(path))
        except Exception as e:
            # 깨진 빌드 파일 하나 때문에 검사가 서면 안 된다. 적고 넘어간다.
            logger.warning("dependency_parse_failed", f"{path.name}: {e}")
    return [{"ecosystem": eco, "name": name, "version": version}
            for eco, name, version in sorted(found)]


def _maven(path: Path) -> set[tuple[str, str, str]]:
    """pom.xml의 <dependency> 항목. 버전이 ${속성}이면 그대로 적는다. 풀려면 빌드
    도구가 필요하고, 그대로 적어도 무엇을 쓰는지는 보인다."""
    tree = ET.parse(path)
    # pom은 네임스페이스가 붙기도 하고 안 붙기도 한다. 태그 이름 끝만 본다.
    out = set()
    for dep in tree.iter():
        if not dep.tag.endswith("dependency"):
            continue
        fields = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
                  for child in dep}
        group, artifact = fields.get("groupId", ""), fields.get("artifactId", "")
        if group and artifact:
            out.add(("maven", f"{group}:{artifact}", fields.get("version", "")))
    return out


_GRADLE_DEP = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile)\s*
        [( ]\s*['"]([\w.\-]+):([\w.\-]+):([\w.\-+\[\]()]+)['"]""", re.VERBOSE)


def _gradle(path: Path) -> set[tuple[str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return {("maven", f"{group}:{artifact}", version)
            for group, artifact, version in _GRADLE_DEP.findall(text)}


_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9._\-\[\]]+)\s*(?:([=<>!~]=?)\s*([\w.*]+))?")


def _requirements(path: Path) -> set[tuple[str, str, str]]:
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        matched = _REQUIREMENT.match(line)
        if matched:
            name, op, version = matched.groups()
            out.add(("pypi", name, f"{op}{version}" if op else ""))
    return out


def _pyproject(path: Path) -> set[tuple[str, str, str]]:
    import tomllib

    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    entries = data.get("project", {}).get("dependencies", [])
    out = set()
    for entry in entries:
        matched = _REQUIREMENT.match(entry)
        if matched:
            name, op, version = matched.groups()
            out.add(("pypi", name, f"{op}{version}" if op else ""))
    return out
