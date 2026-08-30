"""
저장소 전체의 호출 지점 색인.

값 따라가기를 파일 경계 밖으로 넓히기 위해 둔다. `Cipher.getInstance(transformation)`에서
그 변수가 메서드 인자면 부르는 자리를 봐야 값을 안다. 그 자리가 다른 파일이면 파일 하나만
읽어서는 알 수 없다.

벡터 검색으로 풀지 않는다. "이 메서드를 부르는 자리가 어디인가"는 구조로 정확히 답할 수
있는 질문이고, 유사도로 찾으면 엉뚱한 값을 집어올 수 있다. 값이 하나 틀리면 판정이
뒤집히므로 여기서는 추측을 쓰지 않는다.

같은 이름의 메서드가 여러 클래스에 있으면 값이 섞인다. 그래서 클래스 이름까지 함께 키로
쓰고, **클래스가 맞지 않으면 아무 값도 돌려주지 않는다.**

한동안은 클래스를 모를 때 이름만으로 찾은 값을 모두 돌려줬다. 후보를 보여주는 것이 아무
값도 없다고 하는 것보다 낫다고 봤는데, 재보니 반대였다. 벤치마크에서 IV 인자에
`DES/ECB/PKCS5Padding`, `RC4`, `IDEA` 같은 다른 파일의 암호 알고리즘 이름이 들어가고
`http://www.google.com`까지 섞였다. `go`나 `method1` 같은 흔한 이름이 여러 클래스에
있었기 때문이다.

문제는 값이 하나 섞이는 데서 끝나지 않았다. 값을 찾았다고 보고하는 순간 그 자리는
`확인 필요`가 아니라 확정으로 바뀌고, 값을 못 본 자리를 되돌리는 보호장치가 작동하지
않는다. 그래서 모델이 엉뚱한 값을 보고 정상이라고 답했다. 메서드 이름이 같다는 것은
근거가 아니다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..observability.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CallIndex:
    """(클래스, 메서드, 인자 위치) → 넘겨진 문자열 값."""
    qualified: dict[tuple[str, str, int], list[str]] = field(default_factory=dict)

    def add(self, owner: str, method: str, position: int, value: str) -> None:
        # 클래스를 모르는 호출은 담지 않는다. 그 값은 어느 메서드로 갔는지 알 수 없고,
        # 이름만으로 이어 붙이면 엉뚱한 자리에 흘러든다.
        if not owner:
            return
        if value not in self.qualified.setdefault((owner, method, position), []):
            self.qualified[(owner, method, position)].append(value)

    def lookup(self, owner: str, method: str, position: int) -> list[str]:
        """넘겨진 값들. 클래스가 맞을 때만 돌려준다."""
        if not owner:
            return []
        return list(self.qualified.get((owner, method, position), []))

    def __len__(self) -> int:
        return len(self.qualified)


def build(root: Path, suffixes: tuple[str, ...] = (".java",),
          skip_dirs: frozenset[str] = frozenset({".git", "build", "target", "node_modules"}),
          max_bytes: int = 2_000_000) -> CallIndex:
    """
    저장소를 한 번 훑어 문자열 인자를 넘기는 호출을 모은다.

    추출보다 먼저 돌려야 한다. 추출 중에 다른 파일을 다시 읽으면 파일 수의 제곱으로 늘어난다.
    """
    from tree_sitter import Language, Parser
    import tree_sitter_java

    parser = Parser(Language(tree_sitter_java.language()))
    index = CallIndex()
    files = 0

    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.suffix not in suffixes:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            source = path.read_bytes()
        except OSError:
            continue

        files += 1
        try:
            tree = parser.parse(source)
        except Exception as e:
            logger.warning("call_index_parse_failed", f"{path.name}: {e}")
            continue
        _collect_calls(tree.root_node, source, index)

    logger.info("call_index_built",
                f"파일 {files}개에서 호출 지점 {len(index)}종을 모았다")
    return index


def _collect_calls(root, source: bytes, index: CallIndex) -> None:
    """
    호출 지점에서 넘긴 문자열 값을 모은다.

    리터럴만 보면 안 된다. 벤치마크에서 가장 흔한 모양이 다른 파일의 메서드에 변수를
    넘기는 것이다. `String crypto = "DES/ECB/PKCS5Padding"; bc.go(crypto, key)`가
    그렇고, 리터럴만 세면 여기서 끊겨 값을 못 찾았다고 답하게 된다. 그래서 인자가
    변수면 부르는 쪽 범위에서 한 단계 거슬러 본다.
    """
    from .extract_java import (_declared_types, _enclosing_method,
                               _string_assignments, _string_value, _text, _walk)

    fields = _string_assignments(root, source, ("field_declaration",))
    # 수신 변수의 선언 타입을 클래스 이름으로 쓴다. 변수 이름을 키로 쓰면 클래스 대조가
    # 늘 실패해 이름만으로 찾은 값이 섞인다.
    types = _declared_types(root, source)
    scopes: dict[int, dict[str, list[str]]] = {}

    for node in _walk(root):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name_node is None or args is None:
            continue

        object_node = node.child_by_field_name("object")
        receiver = _text(object_node, source) if object_node is not None else ""
        # `bc.go(...)`의 `bc`는 변수다. 그 변수의 선언 타입이 클래스 이름이다.
        # `Foo.go(...)`처럼 이미 클래스면 그대로 쓴다.
        owner = types.get(receiver, receiver)
        method = _text(name_node, source)
        caller = _enclosing_method(node)

        for position, child in enumerate(args.named_children):
            value = _string_value(child, source)
            if value is not None:
                if value.strip():
                    index.add(owner, method, position, value)
                continue
            if child.type != "identifier":
                continue
            variable = _text(child, source)
            found: list[str] = []
            if caller is not None:
                key = caller.start_byte
                if key not in scopes:
                    scopes[key] = _string_assignments(
                        caller, source, ("local_variable_declaration",))
                found.extend(scopes[key].get(variable, ()))
            found.extend(fields.get(variable, ()))
            for value in found:
                if value.strip():
                    index.add(owner, method, position, value)
