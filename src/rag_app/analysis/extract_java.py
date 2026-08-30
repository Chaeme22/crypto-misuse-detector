"""
Java 암호 사용 지점 추출.

tree-sitter로 구문 트리를 얻어 호출과 객체 생성을 본다. Java에서 판정을 가르는 값은
대개 문자열 인자다. `Cipher.getInstance("AES/ECB/PKCS5Padding")` 한 줄에 알고리즘과
운영모드와 패딩이 함께 들어 있다. 그래서 인자를 먼저 보고, 인자로 안 갈리면 호출 이름으로
본다. `new Random()`처럼 인자가 없는 경우가 그렇다.

인자가 변수면 그 자리에서 판정할 수 없다. `Cipher.getInstance(transformation)`은 그 변수의
출처를 따라가야 한다. 그런 지점은 미결로 표시해 두고 넘긴다. 설계가 provenance slice를
조건부 분기로 둔 이유가 이것이다.

키 길이가 호출과 다른 줄에 있는 경우도 다룬다. `KeyPairGenerator.getInstance("RSA")`
다음 줄의 `initialize(1024)`가 실제 판정 근거다. 같은 메서드 안에서 짝을 찾는다.
"""

from __future__ import annotations

import re
from pathlib import Path

from .findings import Rule, UsageSite
from .extract import is_test_path
from .rules import match_api, match_literal, owner_of

# 보안강도 112비트에 미달하는 공개키 길이. 표준문서 값이며 Tier-1 표가 생기면 그쪽으로 옮긴다.
CONTEXT_WINDOW = 6


def _parser():
    from tree_sitter import Language, Parser
    import tree_sitter_java

    return Parser(Language(tree_sitter_java.language()))


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


# 값을 바꾸지 않고 표현만 바꾸는 호출. 이걸 통과하지 못해 값 추적이 끊겼다.
# `String defaultKey = "changeit"; go(defaultKey.getBytes())` 나
# `DEFAULT_CRYPTO.toCharArray()` 가 벤치마크에서 가장 흔한 모양이고, 벤치마크에서
# 놓친 사례의 큰 몫이 여기였다. `Arrays.copyOf`도 자르기만 하므로 알고리즘 이름이나
# 비밀값이 무엇인지는 그대로 남는다.
_PASSTHROUGH = ("getBytes", "toCharArray", "toString", "trim", "valueOf",
                "copyOf", "copyOfRange", "clone")


def _string_value(node, source: bytes, depth: int = 0,
                  ints: bool = False) -> str | None:
    """
    문자열 리터럴이면 따옴표를 벗긴 값. 아니면 None.

    표현만 바꾸는 호출은 통과한다. `"changeit".getBytes()`는 여전히 `changeit`이고,
    `String.valueOf(crypto)`는 `crypto`가 담고 있던 값이다. 여기서 멈추면 값이 없다고
    답하게 되고, 그러면 하드코딩된 키가 확인 필요로도 남지 않고 사라진다.

    변수를 거슬러 올라가지는 않는다. 그건 부르는 쪽이 범위를 정해서 할 일이다.
    여기서는 리터럴에 씌워진 껍데기만 벗긴다.
    """
    if node.type == "string_literal":
        raw = _text(node, source)
        return raw[1:-1] if len(raw) >= 2 else ""

    # 키 길이는 숫자로 들어온다. `kgp.initialize(keySize)`처럼 변수를 거치면 문자열과
    # 똑같이 따라가야 하는데, 리터럴 판정이 문자열만 받아 여기서 끊겼다. 그래서 키 길이를
    # 모르는 채로 위반이라고 답하고 있었다.
    if ints and node.type == "decimal_integer_literal":
        return _text(node, source)

    # 껍데기가 겹쳐 있을 수 있다. `String.valueOf(x.toCharArray())` 같은 모양이다.
    if depth >= 3:
        return None

    if node.type == "method_invocation":
        name = node.child_by_field_name("name")
        if name is None or _text(name, source) not in _PASSTHROUGH:
            return None
        # `"abc".getBytes()`는 수신 쪽에, `String.valueOf(x)`는 인자 쪽에 값이 있다.
        target = node.child_by_field_name("object")
        if target is not None:
            found = _string_value(target, source, depth + 1, ints)
            if found is not None:
                return found
        args = node.child_by_field_name("arguments")
        for child in (args.named_children if args is not None else ()):
            found = _string_value(child, source, depth + 1, ints)
            if found is not None:
                return found
    return None


def _inner_identifier(node, source: bytes, depth: int = 0) -> str | None:
    """
    표현만 바꾸는 호출 안에 든 변수 이름. 변수가 아니면 None.

    `defaultKey.getBytes()`의 값은 `defaultKey`가 담고 있다. 껍데기를 벗기지 않으면
    리터럴도 변수도 아닌 것으로 보여 값이 없다고 답하게 된다. 그러면 하드코딩된 키가
    확인 필요로도 남지 않고 사라진다.
    """
    if node.type == "identifier":
        return _text(node, source)
    if depth >= 3 or node.type != "method_invocation":
        return None
    name = node.child_by_field_name("name")
    if name is None or _text(name, source) not in _PASSTHROUGH:
        return None
    target = node.child_by_field_name("object")
    if target is not None:
        found = _inner_identifier(target, source, depth + 1)
        if found is not None:
            return found
    args = node.child_by_field_name("arguments")
    for child in (args.named_children if args is not None else ()):
        found = _inner_identifier(child, source, depth + 1)
        if found is not None:
            return found
    return None


def _callee(node, source: bytes) -> str:
    """
    호출을 `MessageDigest.getInstance` 모양으로 만든다.

    `md.digest(...)`처럼 변수에 대고 부르는 경우는 변수 이름이 앞에 붙는다. 규칙 트리거는
    타입 이름 기준이므로 이런 호출은 대개 걸리지 않고, 그게 맞다.
    """
    name = node.child_by_field_name("name")
    obj = node.child_by_field_name("object")
    parts = []
    if obj is not None:
        parts.append(_text(obj, source))
    if name is not None:
        parts.append(_text(name, source))
    return ".".join(parts)


def _arguments(node, source: bytes):
    """(리터럴 값 목록, 변수 이름 목록)."""
    args = node.child_by_field_name("arguments")
    literals: list[str] = []
    variables: list[str] = []
    if args is None:
        return literals, variables
    for child in args.named_children:
        value = _string_value(child, source)
        if value is not None:
            literals.append(value)
            continue
        name = _inner_identifier(child, source)
        if name is not None:
            variables.append(name)
    return literals, variables


def _enclosing_method(node):
    """가장 가까운 메서드 선언 노드. 키 길이 짝을 같은 메서드 안에서만 찾기 위해 쓴다."""
    current = node.parent
    while current is not None:
        if current.type in ("method_declaration", "constructor_declaration"):
            return current
        current = current.parent
    return None


def _key_bits_in(method, source: bytes, root=None,
                 int_fields: dict[str, list[str]] | None = None,
                 int_arguments: dict[tuple[str, int], list[str]] | None = None,
                 repo_calls=None, owner: str = "") -> tuple[int, int] | None:
    """
    메서드 안에서 `initialize(1024)` 같은 키 길이 지정을 찾는다.

    Returns:
        (비트 수, 줄 번호) 또는 None
    """
    if method is None:
        return None
    for node in _walk(method):
        if node.type != "method_invocation":
            continue
        name = node.child_by_field_name("name")
        if name is None or _text(name, source) not in ("initialize", "init", "setKeySize"):
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        for child in args.named_children:
            if child.type == "decimal_integer_literal":
                return int(_text(child, source)), node.start_point[0] + 1
            # 변수로 들어온 키 길이. `bc.go(1024)` → `void go(int keySize)` →
            # `kgp.initialize(keySize)` 를 이어야 값이 보인다.
            name = _inner_identifier(child, source)
            if name is None or root is None:
                continue
            for found in _trace(name, node, root, source, int_fields or {},
                                int_arguments or {}, repo_calls, owner,
                                ints=True):
                if found.isdigit():
                    return int(found), node.start_point[0] + 1
    return None


def variable_hint(variables: list[str]) -> str:
    """보고서에 어느 변수를 따라갔는지 남긴다."""
    return variables[0] if variables else "?"


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _context(lines: list[str], line: int) -> str:
    start = max(0, line - 1 - CONTEXT_WINDOW)
    end = min(len(lines), line + CONTEXT_WINDOW)
    return "\n".join(
        f"{number:>5}{'>' if number == line else ' '} {lines[number - 1]}"
        for number in range(start + 1, end + 1))



def _string_assignments(root, source: bytes, kinds: tuple[str, ...] =
                        ("local_variable_declaration", "field_declaration"),
                        ints: bool = False) -> dict[str, list[str]]:
    """
    이름 → 대입된 문자열 값 목록.

    찾는 범위를 호출한 쪽에서 정한다. 파일 전체에서 이름만으로 찾으면 다른 메서드의 값이
    섞인다. 실제로 그렇게 해서 안전한 `AES/GCM`을 쓰는 메서드가 ECB 위반으로 잡혔다.

    같은 이름이 한 범위에서 여러 값을 받으면 그대로 여러 개를 남긴다. 하나로 줄이면 어느
    쪽이 쓰였는지 모르는 상태를 감추게 된다.
    """
    table: dict[str, list[str]] = {}
    for node in _walk(root):
        if node.type not in kinds:
            continue
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value_node = declarator.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            value = _string_value(value_node, source, ints=ints)
            if value is not None:
                table.setdefault(_text(name_node, source), []).append(value)
    return table


def _declared_types(scope, source: bytes) -> dict[str, str]:
    """
    변수 이름 → 선언된 타입 이름.

    `bc.go(crypto)`에서 색인 키를 `bc`로 쓰면 안 된다. 부르는 쪽의 변수 이름이라
    호출된 메서드가 어느 클래스에 있는지와 아무 관계가 없다. 그래서 클래스 대조가 늘
    실패하고 이름만으로 찾은 값이 섞인다. 실제로 다른 분류의 `go` 메서드 값이 흘러들어
    ECB 사례 세 건이 엉뚱한 규칙으로 뒤집혔다.
    """
    types: dict[str, str] = {}
    for node in _walk(scope):
        if node.type not in ("local_variable_declaration", "field_declaration",
                             "formal_parameter"):
            continue
        type_node = node.child_by_field_name("type")
        if type_node is None:
            continue
        type_name = _text(type_node, source).split("<")[0].strip()
        if node.type == "formal_parameter":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                types[_text(name_node, source)] = type_name
            continue
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            if name_node is not None:
                types[_text(name_node, source)] = type_name
    return types


def _parameter_arguments(root, source: bytes,
                        fields: dict[str, list[str]] | None = None,
                        ints: bool = False
                        ) -> dict[tuple[str, int], list[str]]:
    """
    (메서드 이름, 인자 위치) → 호출하는 쪽이 넘긴 문자열 값.

    메서드 인자로 들어온 값은 이 파일 안에서 부르는 자리를 봐야 안다. 다른 파일에서 부르면
    여기서는 알 수 없고, 그때는 모른다고 답해야 한다.

    인자가 변수면 부르는 쪽 범위에서 한 단계 더 거슬러 본다. 벤치마크에서 흔한 모양이
    `String crypto = "DES/ECB/PKCS5Padding"; bc.go(crypto)`인데, 리터럴만 보면 여기서
    끊겨 스무 건이 확인 필요로 떨어졌다.
    """
    fields = fields or {}
    table: dict[tuple[str, int], list[str]] = {}
    scopes: dict[int, dict[str, list[str]]] = {}

    def add(method: str, position: int, value: str):
        # 빈 문자열은 값이 아니다. 이것을 값으로 받으면 `확인 필요`가 잘못된 확정으로
        # 바뀐다. 실제로 `crypto.method1("")`의 빈 인자가 알고리즘 이름 자리에 들어와
        # 이름 없이 규칙이 배정됐다.
        if value.strip():
            table.setdefault((method, position), []).append(value)

    for node in _walk(root):
        if node.type != "method_invocation":
            continue
        name = node.child_by_field_name("name")
        args = node.child_by_field_name("arguments")
        if name is None or args is None:
            continue
        method = _text(name, source)
        caller = _enclosing_method(node)
        for position, child in enumerate(args.named_children):
            value = _string_value(child, source, ints=ints)
            if value is not None:
                add(method, position, value)
                continue
            variable = _inner_identifier(child, source)
            if variable is None:
                continue
            if caller is not None:
                key = caller.start_byte
                if key not in scopes:
                    scopes[key] = _string_assignments(
                        caller, source, ("local_variable_declaration",), ints)
                for found in scopes[key].get(variable, ()):
                    add(method, position, found)
            for found in fields.get(variable, ()):
                add(method, position, found)
    return table


def _trace(variable: str, node, root, source: bytes,
           fields: dict[str, list[str]],
           call_arguments: dict[tuple[str, int], list[str]],
           repo_calls=None, owner: str = "", ints: bool = False) -> list[str]:
    """
    변수에 들어오는 문자열 값을 찾는다. 못 찾으면 빈 목록.

    가까운 범위부터 본다. 같은 메서드 안의 지역 변수, 그다음 클래스 필드, 그다음 이 변수가
    메서드 인자일 때 같은 파일에서 그 메서드를 부르는 자리가 넘긴 값이다. 다른 파일에서
    부르면 여기서는 알 수 없고, 그때는 모른다고 답해야 한다.
    """
    method = _enclosing_method(node)

    if method is not None:
        locals_ = _string_assignments(method, source,
                                      ("local_variable_declaration",), ints)
        if variable in locals_:
            return list(dict.fromkeys(locals_[variable]))

    if variable in fields:
        return list(dict.fromkeys(fields[variable]))

    if method is None:
        return []
    name_node = method.child_by_field_name("name")
    parameters = method.child_by_field_name("parameters")
    if name_node is None or parameters is None:
        return []

    method_name = _text(name_node, source)
    for position, parameter in enumerate(parameters.named_children):
        parameter_name = parameter.child_by_field_name("name")
        if parameter_name is None or _text(parameter_name, source) != variable:
            continue

        # 같은 파일에서 부르는 자리를 먼저 본다. 없으면 저장소 전체 색인을 본다.
        found = list(call_arguments.get((method_name, position), []))
        if not found and repo_calls is not None:
            found = repo_calls.lookup(owner, method_name, position)
        return list(dict.fromkeys(found))
    return []

def _arbitrate(matched: Rule, callee: str, spec: str,
               rules: list[Rule]) -> Rule:
    """
    한 리터럴에 두 규칙이 걸릴 때 어느 쪽으로 보고할지 정한다.

    `DES/ECB/PKCS5Padding`은 운영모드 규칙과 알고리즘 규칙에 다 걸린다. 전에는 걸린
    트리거가 긴 쪽이 이겼고, 그래서 `/ECB/`가 `DES/`를 눌러 운영모드 문제로 보고됐다.
    길이는 뜻이 없다. 운영모드를 CBC로 바꿔도 DES는 안전해지지 않는다. 알고리즘 자체가
    표에 없으면 그게 먼저다.

    `AES/ECB`는 반대다. AES는 표에 있으므로 문제는 운영모드고 그 규칙이 남는다.
    판단은 표가 한다. 어느 쪽이 중한지 손으로 순위를 매기지 않는다.
    """
    from .thresholds import Outcome, ThresholdTable, purpose_for_call

    purpose = purpose_for_call(callee, spec)
    if purpose is None:
        return matched
    owner = owner_of(purpose, rules)
    if owner is None or owner.rule_id == matched.rule_id:
        return matched
    try:
        table = _table()
    except FileNotFoundError:
        return matched
    site = UsageSite(file_path="_", line=1, call=callee, algorithm_spec=spec)
    measured = table.measure(site)
    if measured is not None and measured.outcome in (Outcome.NOT_LISTED,
                                                     Outcome.BELOW):
        return owner
    return matched


_TABLE_CACHE: list = []


def _table():
    """임계값 표는 한 번만 읽는다. 파일마다 다시 읽으면 저장소 검사가 느려진다."""
    from .thresholds import ThresholdTable

    if not _TABLE_CACHE:
        _TABLE_CACHE.append(ThresholdTable.load())
    return _TABLE_CACHE[0]


def _table_owner(callee: str, spec: str, rules: list[Rule]) -> Rule | None:
    """
    이 호출과 알고리즘 이름을 임계값 표로 잴 수 있으면 그 표를 담당하는 규칙.

    규칙이 걸린 게 아니라 잴 수 있다는 뜻이다. 판정은 표 대조가 한다. 안전한
    알고리즘이면 그 자리에서 닫히고 보고서에 나오지 않는다.
    """
    from .thresholds import purpose_for_call

    # 이름이 없으면 잴 것이 없다. 이름 없이 규칙을 배정하면 확인 필요로 남겨야 할 자리가
    # 엉뚱한 규칙의 위반으로 보고된다.
    if not (spec or "").strip():
        return None
    purpose = purpose_for_call(callee, spec)
    return owner_of(purpose, rules) if purpose else None


def _enclosing_class(node, source: bytes) -> str:
    """가장 가까운 클래스 이름. 저장소 색인에서 동명 메서드를 가리는 데 쓴다."""
    current = node.parent
    while current is not None:
        if current.type in ("class_declaration", "interface_declaration",
                            "enum_declaration", "record_declaration"):
            name = current.child_by_field_name("name")
            return _text(name, source) if name is not None else ""
        current = current.parent
    return ""


def collect_file(path: Path, relative: str, rules: list[Rule],
                 source_text: str, repo_calls=None) -> list[tuple[UsageSite, Rule]]:
    """Java 파일 하나에서 사용 지점을 모은다. 한 줄에는 한 건만 남긴다."""
    source = source_text.encode("utf-8")
    tree = _parser().parse(source)
    lines = source_text.splitlines()
    found: dict[int, tuple[UsageSite, Rule]] = {}
    fields = _string_assignments(tree.root_node, source, ("field_declaration",))
    call_arguments = _parameter_arguments(tree.root_node, source, fields)
    # 키 길이용 표를 따로 둔다. 숫자를 알고리즘 이름과 같은 통에 넣으면 규칙 조회에
    # 숫자가 섞인다.
    int_fields = _string_assignments(tree.root_node, source,
                                     ("field_declaration",), ints=True)
    int_arguments = _parameter_arguments(tree.root_node, source, int_fields,
                                        ints=True)

    def record(line: int, column: int, rule: Rule, api: str,
               unresolved: tuple[str, ...] = (), traced: tuple[str, ...] = (),
               call: str = "", spec: str = "", key_bits: int | None = None):
        if line < 1 or line in found:
            return
        found[line] = (
            UsageSite(
                file_path=relative,
                line=line,
                is_test=is_test_path(relative),
                column=column,
                snippet=lines[line - 1].strip()[:300] if line <= len(lines) else "",
                context=_context(lines, line),
                api=api,
                # 임계값 표와 견줄 수 있게 호출 이름과 알고리즘 이름을 나눠 남긴다.
                call=call,
                algorithm_spec=spec,
                key_bits=key_bits,
                language="java",
                traced_values=traced,
                unresolved_args=unresolved,
            ),
            rule,
        )

    for node in _walk(tree.root_node):
        if node.type == "method_invocation":
            callee = _callee(node, source)
            literals, variables = _arguments(node, source)
            line = node.start_point[0] + 1
            column = node.start_point[1] + 1

            # 인자가 판정을 가른다. `AES/ECB/...`는 운영모드 규칙, `MD5`는 해시 규칙이다.
            matched = None
            for value in literals:
                matched = match_literal(value, rules)
                if matched is not None:
                    matched = _arbitrate(matched, callee, value, rules)
                    record(line, column, matched, f"{callee}(\"{value}\")",
                           call=callee, spec=value)
                    break
            if matched is not None:
                continue

            # 리터럴이 있는데 어느 규칙에도 안 걸리지 않았다. 여기서 호출 이름으로
            # 되돌아가면 `MessageDigest.getInstance("SHA-256")`이 취약 해시로 잡힌다.
            # 그렇다고 그냥 넘기면 목록에 없는 이름이 다 새어 나간다. 실제로 `RC2`,
            # `IDEA`, `MD4`, `MD2`, `HmacMD5`가 전부 통과했다.
            # 그래서 임계값 표가 답할 수 있는 호출이면 표로 넘긴다. 안전한 알고리즘은
            # 표 대조에서 닫히고, 표에 없는 이름은 그때 걸린다.
            api_rule = match_api(callee, rules)
            if literals and not callee.endswith("KeyPairGenerator.getInstance"):
                table_rule = _table_owner(callee, literals[0], rules)
                if table_rule is not None:
                    record(line, column, table_rule,
                           f"{callee}(\"{literals[0]}\")",
                           call=callee, spec=literals[0])
                continue

            if api_rule is not None and callee.endswith("KeyPairGenerator.getInstance"):
                # 약한 키 길이 목록으로 여기서 걸러내지 않는다. 전에는 {512, 768, 1024,
                # 1536}에 없으면 통과시켜 RSA-2047이 새어 나갔다. 키 길이를 찾은 자리를
                # 그대로 넘기고 미달인지는 표와 견주는 쪽에서 정한다.
                pair = _key_bits_in(_enclosing_method(node), source,
                                    tree.root_node, int_fields, int_arguments,
                                    repo_calls, _enclosing_class(node, source))
                algorithm = literals[0] if literals else ""
                if pair is not None:
                    record(pair[1], column, api_rule, f"{algorithm or '?'}-{pair[0]}",
                           call=callee, spec=algorithm, key_bits=pair[0])
                else:
                    # 키 길이 지정이 없으면 기본값이 쓰인다. 무엇인지 알 수 없으므로
                    # 확인 필요로 남긴다.
                    record(line, column, api_rule, f"{callee}(\"{algorithm}\")",
                           unresolved=("키 길이",), call=callee, spec=algorithm)
                continue

            if api_rule is not None:
                # 인자가 변수면 값을 따라가 본다. 찾으면 그 값으로 규칙을 다시 본다.
                traced: list[str] = []
                for variable in variables:
                    traced.extend(_trace(variable, node, tree.root_node, source,
                                         fields, call_arguments, repo_calls,
                                         _enclosing_class(node, source)))
                traced = [v for v in dict.fromkeys(traced) if v.strip()]

                if traced:
                    for value in traced:
                        traced_rule = match_literal(value, rules)
                        if traced_rule is not None:
                            traced_rule = _arbitrate(traced_rule, callee, value,
                                                     rules)
                            record(line, column, traced_rule,
                                   f"{callee}({variable_hint(variables)}=\"{value}\")",
                                   traced=tuple(traced), call=callee, spec=value)
                            break
                    else:
                        # 값을 다 찾았고 어느 규칙에도 안 걸렸다. 리터럴과 같은 이유로
                        # 표가 답할 수 있으면 표로 넘긴다.
                        table_rule = _table_owner(callee, traced[0], rules)
                        if table_rule is not None:
                            record(line, column, table_rule,
                                   f"{callee}({variable_hint(variables)}="
                                   f"\"{traced[0]}\")",
                                   traced=tuple(traced), call=callee,
                                   spec=traced[0])
                        continue
                    continue

                # 값을 못 찾았다. 여기서 억지로 판정하지 않는다.
                record(line, column, api_rule, callee, tuple(variables), call=callee)

        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is None:
                continue
            type_name = _text(type_node, source)
            rule = match_api(type_name, rules) or match_api(f"new {type_name}", rules)
            if rule is not None:
                literals, variables = _arguments(node, source)
                # `new SecretKeySpec(keyBytes, "AES")`의 `keyBytes`를 따라간다. 전에는
                # 객체 생성 분기에 추적이 없어 값을 늘 못 찾았고, 그래서 모델이 볼 것이
                # 없어 하드코딩된 키를 정상으로 판정했다.
                traced: list[str] = []
                for variable in variables:
                    traced.extend(_trace(variable, node, tree.root_node, source,
                                         fields, call_arguments, repo_calls,
                                         _enclosing_class(node, source)))
                traced = [v for v in dict.fromkeys(traced) if v.strip()]
                record(node.start_point[0] + 1, node.start_point[1] + 1, rule,
                       f"new {type_name}",
                       unresolved=() if traced else tuple(variables),
                       traced=tuple(traced), call=f"new {type_name}",
                       spec=literals[0] if literals else "")

    return [found[line] for line in sorted(found)]
