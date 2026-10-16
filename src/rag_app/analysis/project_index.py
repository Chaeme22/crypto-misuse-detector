"""
저장소 단위 색인. 출처 판별이 파일 경계를 넘게 한다.

출처 판별(`provenance.Resolver`)은 파일 하나의 구문 트리만 봤다. 실제 코드에서는 키가 유틸 클래스의
인자로 들어오고, 그 유틸을 부르는 곳은 다른 파일이다. 상수는 `Constants` 클래스에 모여 있다. 개발
코퍼스에서 지점은 잡았지만 값을 못 찾은 자리의 대부분이 이 둘이었다.

색인은 가볍게 둔다. 파일마다 선언한 클래스 이름과 호출하는 이름만 정규식으로 모으고, 실제로 따라갈
때 그 파일만 파싱한다. 따라가야 할 자리는 적고 저장소의 파일은 많다.

**클래스가 맞을 때만 잇는다.** 메서드 이름이 같다는 것은 근거가 아니다(`call_index` 참고). 같은 단순
이름의 클래스가 여럿이면 각 후보의 답이 모두 같을 때만 그 답을 쓴다(`provenance.combine`).
"""

from __future__ import annotations

import re
from collections import OrderedDict
from pathlib import Path

_CLASS_DECL = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Z]\w*)")
_CALLED = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_TYPE_REF = re.compile(r"\b([A-Z]\w*)\b")
SKIP_DIRS = frozenset({".git", "build", "target", "node_modules"})
# 이름이 너무 흔하면 따라가지 않는다. `get`·`init`처럼 수백 파일에서 부르는 이름을 다 파싱하면
# 느리고, 클래스 대조로 걸러도 남는 것이 거의 없다.
MAX_CANDIDATE_FILES = 60
_CACHE_SIZE = 96


def _flatten(node, prefix: str, out: dict[str, str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _flatten(value, f"{prefix}.{key}" if prefix else str(key), out)
    elif node is not None and not isinstance(node, list):
        out[prefix] = str(node)


class Project:
    def __init__(self, root: Path):
        self.root = root
        self._classes: dict[str, list[Path]] = {}
        self._calls: dict[str, set[Path]] = {}
        self._mentions: dict[str, set[Path]] = {}   # 대문자로 시작하는 이름(타입·클래스)이 나오는 파일
        self._resolvers: OrderedDict[Path, object] = OrderedDict()
        self._parser = None
        self._config: dict[str, list[tuple[str, Path]]] = {}

    @classmethod
    def build(cls, root: Path, max_bytes: int = 2_000_000) -> "Project":
        project = cls(root)
        for path in sorted(root.rglob("*")):
            if path.is_dir() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
                continue
            is_config = path.suffix == ".properties" or (
                path.suffix in (".yml", ".yaml") and path.stem.split("-")[0] in ("application", "bootstrap"))
            if path.suffix != ".java" and not is_config:
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if is_config:
                project.add_config(path, text)
            else:
                project.add(path, text)
        return project

    # --- 설정 파일 ------------------------------------------------------------------

    def add_config(self, path: Path, text: str) -> None:
        """`*.properties`, `application*.yml`의 키와 값을 모은다. 값은 문자열로 둔다."""
        pairs: dict[str, str] = {}
        if path.suffix == ".properties":
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                match = re.match(r"([^=:\s]+)\s*[=:]\s*(.*)$", line)
                if match:
                    pairs[match.group(1)] = match.group(2).strip()
        else:
            try:
                import yaml
                for document in yaml.safe_load_all(text):
                    _flatten(document, "", pairs)
            except Exception:
                return
        for key, value in pairs.items():
            self._config.setdefault(key, []).append((value, path))

    def config_values(self, key: str) -> list[tuple[str, Path]]:
        """설정 키의 값들(파일이 여럿이면 모두). Spring의 느슨한 키 이름(`env-key`/`envKey`)도 맞춘다."""
        found = self._config.get(key)
        if found:
            return list(found)
        loose = key.replace("-", "").replace("_", "").lower()
        return [v for k, vs in self._config.items()
                if k.replace("-", "").replace("_", "").lower() == loose for v in vs]

    def add(self, path: Path, text: str) -> None:
        for name in set(_CLASS_DECL.findall(text)):
            self._classes.setdefault(name, []).append(path)
        for name in set(_CALLED.findall(text)):
            self._calls.setdefault(name, set()).add(path)
        for name in set(_TYPE_REF.findall(text)):
            self._mentions.setdefault(name, set()).add(path)

    # --- 조회 ---------------------------------------------------------------------

    def files_declaring(self, class_name: str) -> list[Path]:
        return list(self._classes.get(class_name, ()))

    def files_calling(self, name: str, owner: str = "") -> list[Path]:
        """
        그 이름을 호출하는(또는 `new 이름(`으로 만드는) 파일. 너무 흔하면 빈 목록.

        `owner`를 주면 그 클래스 이름이 나오는 파일만 남긴다. `go`·`init`처럼 흔한 이름도 클래스로 좁히면
        따라갈 수 있다(클래스를 부르려면 그 이름이 파일에 나온다 — 같은 패키지의 상속 호출은 예외라 빠질 수 있다).
        """
        found = self._calls.get(name, set())
        if owner and owner in self._mentions:
            found = found & self._mentions[owner]
        return sorted(found) if len(found) <= MAX_CANDIDATE_FILES else []

    def is_test(self, path: Path | None) -> bool:
        if path is None:
            return False
        from .extract import is_test_path
        try:
            return is_test_path(path.relative_to(self.root).as_posix())
        except ValueError:
            return is_test_path(path.as_posix())

    def resolver(self, path: Path):
        """그 파일의 출처 판별기. 최근에 쓴 것만 남긴다."""
        if path in self._resolvers:
            self._resolvers.move_to_end(path)
            return self._resolvers[path]
        from . import provenance as prov
        if self._parser is None:
            from tree_sitter import Language, Parser
            import tree_sitter_java
            self._parser = Parser(Language(tree_sitter_java.language()))
        try:
            source = path.read_bytes()
        except OSError:
            return None
        resolver = prov.Resolver(self._parser.parse(source).root_node, source,
                                 project=self, path=path)
        self._resolvers[path] = resolver
        if len(self._resolvers) > _CACHE_SIZE:
            self._resolvers.popitem(last=False)
        return resolver
