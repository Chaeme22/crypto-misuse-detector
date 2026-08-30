"""
암호 사용 지점 추출 — 임시 구현.

목표 설계에서는 tree-sitter로 다중 언어 AST를 훑고 콜그래프까지 만든다. 여기 있는 것은
그 자리에 끼울 인터페이스를 고정하고 종단 흐름을 한 번 돌려보기 위한 최소 구현이며,
Python만 다룬다.

줄 단위 문자열 검색으로 먼저 만들었더니 주석과 독스트링, 토큰 한계 상수(`1024`)까지
걸려 후보가 잡음으로 찼다. 그래서 `ast`로 호출과 문자열 리터럴만 본다. 주석은 AST에
없고, 독스트링은 따로 걸러낸다.

`collect()`의 계약만 지키면 통째로 갈아끼울 수 있다. 파일 경로는 검사 루트 기준 상대
경로이고 줄 번호는 1부터다. SARIF의 위치가 이 값을 그대로 쓴다.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ..observability.logging import get_logger
from .findings import Rule, UsageSite
from .rules import match_api, match_literal

logger = get_logger(__name__)

# 빌드 도구의 표준 규약. Maven과 Gradle은 테스트 소스를 이 경로에 둔다. Python은 파일
# 이름과 디렉터리 규약을 쓴다. 추측이 아니라 규약이므로 코드가 판정한다.
TEST_MARKERS = ("src/test/java", "src/test/kotlin", "src/test/scala",
                "tests/", "test/", "/testing/")


def is_test_path(relative: str) -> bool:
    """빌드 규약으로 테스트 소스인지 본다."""
    normalized = "/" + relative.replace("\\", "/").lstrip("/")
    if any(marker in normalized for marker in TEST_MARKERS):
        return True
    name = normalized.rsplit("/", 1)[-1]
    return name.startswith("test_") or name.startswith("Test") or name.endswith("Test.java")

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache",
             ".mypy_cache", "data", "build", "target", "dist"}
# 언어마다 파서가 다르다. Python은 내장 ast, Java는 tree-sitter를 쓴다.
SUFFIXES = {".py", ".java"}


def dotted_name(node: ast.AST) -> str:
    """`hashlib.md5(...)`의 함수 부분을 `hashlib.md5`로 만든다."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """독스트링 상수의 id 집합. 설명문에 적힌 알고리즘 이름을 사용으로 세지 않는다."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                out.add(id(body[0].value))
    return out


def collect_file(path: Path, relative: str, rules: list[Rule],
                 source: str) -> list[tuple[UsageSite, Rule]]:
    """파일 하나에서 사용 지점을 모은다. 같은 줄에는 한 건만 남긴다."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines = source.splitlines()
    docstrings = _docstring_nodes(tree)
    found: dict[int, tuple[UsageSite, Rule]] = {}

    def record(node: ast.AST, rule: Rule, api: str):
        line = getattr(node, "lineno", 0)
        if line < 1 or line in found:
            return
        window = 6
        start = max(0, line - 1 - window)
        end = min(len(lines), line + window)
        numbered = "\n".join(
            f"{number:>5}{'>' if number == line else ' '} {lines[number - 1]}"
            for number in range(start + 1, end + 1))

        found[line] = (
            UsageSite(
                file_path=relative,
                line=line,
                is_test=is_test_path(relative),
                column=getattr(node, "col_offset", 0) + 1,
                snippet=lines[line - 1].strip()[:300] if line <= len(lines) else "",
                context=numbered,
                api=api,
                language="python",
            ),
            rule,
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name:
                rule = match_api(name, rules)
                if rule is not None:
                    record(node, rule, name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings or len(node.value) > 120:
                continue
            rule = match_literal(node.value, rules)
            if rule is not None:
                record(node, rule, node.value[:60])

    return [found[line] for line in sorted(found)]


def collect(root: Path, rules: list[Rule],
            max_bytes: int = 2_000_000) -> list[tuple[UsageSite, Rule]]:
    """
    검사 루트를 훑어 규칙에 걸리는 사용 지점을 모은다.

    Java 파일이 있으면 먼저 저장소 전체의 호출 지점을 색인한다. 값이 다른 파일에서 오는
    경우가 실제 코드에서 흔하고, 추출 중에 다른 파일을 다시 읽으면 파일 수의 제곱으로 늘어난다.
    """
    out: list[tuple[UsageSite, Rule]] = []

    repo_calls = None
    if any(path.suffix == ".java" for path in root.rglob("*.java")):
        from . import call_index
        repo_calls = call_index.build(root)

    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.suffix not in SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        if path.suffix == ".java":
            from . import extract_java
            try:
                out.extend(extract_java.collect_file(path, relative, rules, source,
                                                     repo_calls))
            except Exception as e:
                # 파서가 못 읽은 파일을 조용히 건너뛰지 않는다. 검사에서 빠진 파일이 있다는
                # 사실을 알아야 커버리지를 말할 수 있다.
                logger.warning("java_parse_failed", f"{relative}: {e}")
        else:
            out.extend(collect_file(path, relative, rules, source))
    return out
