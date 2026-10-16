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
from . import provenance as prov
from ..observability.logging import get_logger

# 보안강도 112비트에 미달하는 공개키 길이. 표준문서 값이며 Tier-1 표가 생기면 그쪽으로 옮긴다.
CONTEXT_WINDOW = 6

logger = get_logger(__name__)


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
        owner = _text(obj, source)
        # `java.security.Signature.getInstance`처럼 패키지까지 적으면 트리거와 어긋난다. 소문자 패키지
        # 경로 뒤의 대문자 타입 이름만 남긴다. `this.md.digest`처럼 필드 경유는 그대로 둔다.
        segments = owner.split(".")
        if (len(segments) > 1 and segments[-1][:1].isupper()
                and all(s[:1].islower() for s in segments[:-1]) and segments[0] != "this"):
            owner = segments[-1]
        parts.append(owner)
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


# 키 길이를 담는 스펙 객체. 첫 인자가 비트 수다
_SIZE_SPECS = {"RSAKeyGenParameterSpec", "DHGenParameterSpec"}
_CURVE_SPECS = {"ECGenParameterSpec", "NamedParameterSpec"}
_CURVE_BITS = re.compile(r"(?:secp|sect|prime|brainpoolP|P-|c2pnb|c2tnb)(\d{3})", re.IGNORECASE)


def _spec_bits(arg, source: bytes, resolver) -> int | None:
    """
    `initialize(new RSAKeyGenParameterSpec(1024, F4))`, `initialize(new ECGenParameterSpec("secp112r1"))`의 키 길이.
    곡선은 이름의 숫자가 키 길이다(`secp112r1` → 112, `prime256v1` → 256). 변수에 담아 넘겨도 그 값을 본다.
    """
    node = arg
    if node.type == "identifier" and resolver is not None:
        values = resolver._value_nodes(_text(node, source), node)
        node = values[0] if len(values) == 1 else node
    if node.type != "object_creation_expression":
        return None
    type_node = node.child_by_field_name("type")
    name = prov._simple_type(_text(type_node, source)) if type_node is not None else ""
    spec_args = _args_of(node)
    if not spec_args:
        return None
    if name in _SIZE_SPECS:
        numbers = resolver.classify_int(spec_args[0]) if resolver is not None else None
        if numbers:
            return min(numbers)
        text = _text(spec_args[0], source)
        return int(text) if text.isdigit() else None
    if name in _CURVE_SPECS:
        names = resolver._strings(spec_args[0], 0) if resolver is not None else None
        if not names and spec_args[0].type == "string_literal":
            names = (_text(spec_args[0], source)[1:-1],)
        bits = [int(m.group(1)) for n in (names or ()) for m in [_CURVE_BITS.search(n)] if m]
        return min(bits) if bits else None
    return None


def _assigned_to(node, source: bytes) -> str:
    """`g = KeyPairGenerator.getInstance(..)`, `KeyPairGenerator g = ..`의 `g`. 바로 담지 않으면 빈 문자열."""
    parent = node.parent
    while parent is not None and parent.type in ("parenthesized_expression", "cast_expression"):
        parent = parent.parent
    if parent is None:
        return ""
    if parent.type == "variable_declarator":
        found = parent.child_by_field_name("name")
        return _text(found, source) if found is not None else ""
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        return " ".join(_text(left, source).split()) if left is not None else ""
    return ""


def _key_bits_in(method, source: bytes, root=None,
                 int_fields: dict[str, list[str]] | None = None,
                 int_arguments: dict[tuple[str, int], list[str]] | None = None,
                 repo_calls=None, owner: str = "", resolver=None,
                 receiver: str = "") -> tuple[int, int] | None:
    """
    메서드 안에서 `initialize(1024)` 같은 키 길이 지정을 찾는다.

    `receiver`(생성기를 담은 변수 이름)를 알면 그 변수에 대한 호출만 본다. 한 메서드에 생성기가 여럿이면
    (`rsa.initialize(1024)`, `ec.initialize(...)`) 첫 호출이 모든 생성기의 키 길이로 붙었다.

    변수로 들어오면 출처 판별(흐름·문맥·필드 민감)로 먼저 값을 정한다. 경로마다 값이 다르면 가장 작은 값을 쓴다 —
    어느 한 경로라도 짧은 키면 문제다. 정해지지 않을 때만 예전 문자열 추적을 쓴다.

    Returns:
        (비트 수, 줄 번호) 또는 None
    """
    if method is None:
        return None
    _SIZERS = ("initialize", "init", "setKeySize")

    def target_of(call) -> str:
        target = call.child_by_field_name("object")
        return _text(target, source).removeprefix("this.") if target is not None else ""

    allowed: set[str] = set()
    if receiver:
        # 생성기에 직접 준 값과, 생성기의 initialize에 넘긴 객체(`paramGen.generateParameters()`의 `paramGen`)에
        # 준 키 길이까지 본다(jenkins: `paramGen.init(512)` → `dh.initialize(paramGen...)`)
        allowed = {receiver.removeprefix("this.")}
        for call in _walk(method):
            name = call.child_by_field_name("name") if call.type == "method_invocation" else None
            if name is not None and _text(name, source) in _SIZERS and target_of(call) in allowed:
                args_node = call.child_by_field_name("arguments")
                for ident in (_walk(args_node) if args_node is not None else ()):
                    if ident.type == "identifier":
                        allowed.add(_text(ident, source))
    for node in _walk(method):
        if node.type != "method_invocation":
            continue
        name = node.child_by_field_name("name")
        if name is None or _text(name, source) not in _SIZERS:
            continue
        if receiver and target_of(node) not in allowed:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        for child in args.named_children:
            if child.type == "decimal_integer_literal":
                return int(_text(child, source)), node.start_point[0] + 1
            spec_bits = _spec_bits(child, source, resolver)
            if spec_bits is not None:
                return spec_bits, node.start_point[0] + 1
            if resolver is not None:
                numbers = resolver.classify_int(child)
                if numbers:
                    return min(numbers), node.start_point[0] + 1
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


# 운영모드를 적지 않으면 Java 표준 제공자(SunJCE)는 ECB를 쓴다. `Cipher.getInstance("AES")`는
# `AES/ECB/PKCS5Padding`과 같다. 블록암호만 해당한다. 스트림 암호(RC4)와 공개키 암호(RSA)는
# 운영모드가 없다.
_BLOCK_CIPHERS = {"AES", "DES", "DESEDE", "TRIPLEDES", "3DES", "SEED", "ARIA", "LEA", "HIGHT",
                  "BLOWFISH", "RC2", "CAMELLIA", "IDEA", "CAST5", "CAST6", "TWOFISH"}


# 메서드 이름이 해시 알고리즘인 래퍼. Apache Commons·Spring `DigestUtils`, hutool `DigestUtil`·`SecureUtil`,
# Guava `Hashing`. 인자에 알고리즘 이름이 없어 리터럴로는 못 잡는다. 받는 쪽 타입을 이 목록으로
# 한정한다. `cache.md5(x)` 같은 임의 메서드는 무엇을 하는지 모른다.
_DIGEST_OWNERS = {"DigestUtils", "DigestUtil", "SecureUtil", "Hashing"}
_DIGEST_METHOD = re.compile(r"^(md2|md5|sha1|sha|sha224|sha256|sha384|sha512)"
                            r"(?:Hex\d*|DigestAsHex|AsHex|Digest|Base64)?$")


# Hutool 열거 상수 → 그 이름을 받는 JCA 호출. `SignAlgorithm.SHA1withRSA` → Signature.getInstance("SHA1withRSA")
_HUTOOL_ENUMS = {"SignAlgorithm": "Signature.getInstance", "DigestAlgorithm": "MessageDigest.getInstance",
                 "HmacAlgorithm": "Mac.getInstance", "SymmetricAlgorithm": "Cipher.getInstance"}
_HUTOOL_CIPHERS = {"aes": "AES", "des": "DES", "desede": "DESede"}
_HUTOOL_CLASSES = {"AES": "AES", "DES": "DES", "DESede": "DESede"}


def _args_of(node) -> list:
    args = node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _digest_wrapper_spec(callee: str) -> str:
    """`DigestUtils.md5Hex` → `MD5`. 래퍼가 아니면 빈 문자열."""
    owner, _, method = callee.rpartition(".")
    if owner.split(".")[-1] not in _DIGEST_OWNERS:
        return ""
    match = _DIGEST_METHOD.match(method)
    return match.group(1).upper() if match else ""


_NAME_VALUE = re.compile(r"^[A-Za-z0-9][\w\-/.]*$")


def _resolved_names(node, resolver) -> list[str]:
    """
    문자열 추적(`_trace`)이 못 찾은 알고리즘 이름을 출처 판별로 다시 찾는다.

    출처 판별은 생성자 인자로 채운 필드, 다른 파일의 호출 자리·상수까지 따라간다(nacos
    `NacosSignatureAlgorithm`: 정적 인스턴스 생성자 인자 → 필드 → `Mac.getInstance(jcaName)`).
    상수로 확정됐고 값이 모두 알고리즘 이름 모양일 때만 쓴다. 계산식 텍스트는 이름이 아니다.
    """
    args = node.child_by_field_name("arguments")
    if resolver is None or args is None or not args.named_children:
        return []
    origin = resolver.classify(args.named_children[0])
    if origin.kind != prov.CONSTANT or not origin.values:
        return []
    values = list(dict.fromkeys(origin.values))
    return values if all(_NAME_VALUE.match(v) for v in values) else []


_WEAK_HASHES = {"MD2", "MD4", "MD5", "SHA-1"}


def _weak_partial_names(node, resolver, rules) -> list[str]:
    """
    값이 경로마다 달라 출처가 "모름"이어도, 상수 경로 중 약한 알고리즘 이름(`MD5`, `SHA`, `DES/...`)이 있으면 그 이름들.
    알고리즘 이름은 한 경로라도 약하면 그 경로로 실행될 때 오용이다. 안전한 이름만 있으면 모른 채로 둔다
    (모르는 경로가 약할 수 있다).
    """
    args = node.child_by_field_name("arguments")
    if resolver is None or args is None or not args.named_children:
        return []
    origin = resolver.classify(args.named_children[0])
    if origin.kind != prov.UNKNOWN or not origin.values:
        return []
    from .thresholds import canonical
    # HMAC·PBKDF2의 SHA-1은 메시지 인증·키 유도라 KISA 표에서 허용된다. 여기서 약하다고 하지 않는다
    weak = [v for v in dict.fromkeys(origin.values) if _NAME_VALUE.match(v)
            and not v.lower().startswith(("hmac", "pbkdf2", "pbewithhmac"))
            and (match_literal(v, rules) is not None or canonical(v) in _WEAK_HASHES)]
    return weak


def _constant_prefix(node, resolver) -> str:
    """첫 인자가 `"상수" + 무엇`이면 그 상수 앞부분. 아니면 빈 문자열."""
    args = node.child_by_field_name("arguments")
    if resolver is None or args is None or not args.named_children:
        return ""
    expr = args.named_children[0]
    if expr.type != "binary_expression":
        return ""   # 덧셈이 아니다
    while expr.type == "binary_expression":
        operator = expr.child_by_field_name("operator")
        if operator is None or _text(operator, resolver.source) != "+":
            return ""
        expr = expr.child_by_field_name("left")
        if expr is None:
            return ""
    origin = resolver.classify(expr)
    if origin.kind == prov.CONSTANT and len(set(origin.values)) == 1:
        return origin.values[0]
    return ""


def _algorithm_name(spec: str) -> str:
    return (spec or "").strip().strip('"').split("/")[0].strip().upper()


def _defaults_to_ecb(callee: str, spec: str) -> bool:
    """`Cipher.getInstance("AES")`처럼 운영모드 없이 블록암호를 지정했는지."""
    return (callee.endswith("Cipher.getInstance") and "/" not in (spec or "")
            and _algorithm_name(spec) in _BLOCK_CIPHERS)


def _is_public_key_transformation(spec: str) -> bool:
    """`RSA/ECB/OAEP...`의 ECB는 관례 표기일 뿐 블록 운영모드가 아니다."""
    from .thresholds import _ASYMMETRIC
    return _algorithm_name(spec) in _ASYMMETRIC


def _material_triggers(rules: list[Rule]) -> dict[str, list[tuple[Rule, int, str]]]:
    """트리거 → (규칙, 인자 위치, 볼 것). 볼 것은 출처(material)나 반복 횟수(iteration)다."""
    table: dict[str, list[tuple[Rule, int, str]]] = {}
    for rule in rules:
        for trigger, position in rule.material_args:
            table.setdefault(trigger, []).append((rule, position, "material"))
        for trigger, position in rule.iteration_args:
            table.setdefault(trigger, []).append((rule, position, "iteration"))
    return table


def _material_name(node, source: bytes, resolver: "prov.Resolver") -> str:
    """
    출처 규칙의 트리거 이름. `new PBEKeySpec`이나 `KeyStore.load` 모양이다.

    `ks.load(...)`는 변수 이름이 아니라 그 변수의 타입으로 본다. 트리거는 타입 기준이고
    변수 이름은 저장소마다 다르다.
    """
    if node.type == "object_creation_expression":
        type_node = node.child_by_field_name("type")
        return f"new {prov._simple_type(_text(type_node, source))}" if type_node else ""
    name = node.child_by_field_name("name")
    if name is None:
        return ""
    owner = resolver.receiver_type(node)
    return f"{owner}.{_text(name, source)}" if owner else ""


def _iteration_origin(resolver: "prov.Resolver", arg, minimum: int) -> "prov.Origin":
    """반복 횟수를 최소값과 견준다. 값을 모르면 판정하지 않는다."""
    numbers = resolver.classify_int(arg)
    if numbers is None:
        origin = resolver.classify(arg)
        return prov.Origin(prov.UNKNOWN, f"반복 횟수 값을 확인하지 못했다({origin.note})")
    shown = ", ".join(str(n) for n in numbers)
    if all(n < minimum for n in numbers):
        return prov.Origin(prov.BELOW_MINIMUM,
                           f"반복 횟수 {shown}회가 최소 기준 {minimum}회에 못 미친다",
                           tuple(str(n) for n in numbers))
    if all(n >= minimum for n in numbers):
        return prov.Origin(prov.MEETS_MINIMUM,
                           f"반복 횟수 {shown}회가 최소 기준 {minimum}회를 만족한다",
                           tuple(str(n) for n in numbers))
    return prov.Origin(prov.UNKNOWN, f"경로마다 반복 횟수가 다르다({shown})")


def collect_file(path: Path, relative: str, rules: list[Rule],
                 source_text: str, repo_calls=None,
                 project=None) -> list[tuple[UsageSite, Rule]]:
    """
    Java 파일 하나에서 사용 지점을 모은다. 한 줄·한 규칙에 한 건만 남긴다.

    전에는 한 줄에 한 건이었다. `new PBEKeySpec(pw, salt, 500, 256)` 한 줄에 비밀번호·솔트·
    반복 횟수 세 문제가 함께 있을 수 있어 규칙별로 남긴다.
    """
    source = source_text.encode("utf-8")
    tree = _parser().parse(source)
    lines = source_text.splitlines()
    found: dict[tuple[int, str], tuple[UsageSite, Rule]] = {}
    materials = _material_triggers(rules)
    resolver = (prov.Resolver(tree.root_node, source, project=project, path=path)
                if materials else None)
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
               call: str = "", spec: str = "", key_bits: int | None = None,
               origin: "prov.Origin | None" = None):
        key = (line, rule.rule_id)
        if line < 1 or key in found:
            return
        found[key] = (
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
                provenance=origin.kind if origin is not None else "",
                provenance_note=origin.note if origin is not None else "",
            ),
            rule,
        )

    ecb_rule = next((r for r in rules if r.rule_id == "CRYPTO-MODE-ECB"), None)

    def record_default_ecb(line: int, column: int, callee: str, spec: str,
                           traced: tuple[str, ...] = ()):
        if ecb_rule is not None and _defaults_to_ecb(callee, spec):
            record(line, column, ecb_rule,
                   f"{callee}(\"{spec}\") — 운영모드 미지정, 기본값 ECB",
                   traced=traced, call=callee, spec=f"{spec}/ECB")

    def record_material(node) -> bool:
        """
        출처 규칙에 걸리는 호출이면 인자마다 출처를 판별해 남긴다.

        트리거에 걸렸으면 볼 인자가 없어도 처리한 것으로 본다. 인자 없는 `new SecureRandom()`은
        시드를 정하지 않으므로 지점이 아니다. 여기서 놓으면 호출 이름만 보는 분기가 받아
        출처 없는 위반으로 남긴다.
        """
        trigger = _material_name(node, source, resolver)
        hits = materials.get(trigger, ())
        if not hits:
            return False
        args = node.child_by_field_name("arguments")
        args = list(args.named_children) if args is not None else []
        for rule, position, mode in hits:
            if position >= len(args):
                continue
            arg = args[position]
            if mode == "iteration":
                origin = _iteration_origin(resolver, arg, rule.min_iterations or 0)
            else:
                origin = resolver.classify(arg)
            if rule.rule_id == "CRYPTO-PASSWORD-HARDCODED" and (
                    arg.type == "null_literal" or origin.note == "null이 넘어간다"):
                # `ks.load(null, null)`(빈 저장소 만들기), `load(in, null)`(무결성 검사 생략): 코드에 박힌 비밀번호가 없다
                continue
            decided = origin.kind in prov.VIOLATING or origin.kind in prov.CLEAN
            arg_text = _text(arg, source)
            record(node.start_point[0] + 1, node.start_point[1] + 1, rule,
                   f"{trigger}({' '.join(arg_text.split())[:60]})",
                   unresolved=() if decided else (arg_text,),
                   traced=origin.values, call=trigger, origin=origin)
        if trigger.startswith("KISA_SEED_ECB.") and ecb_rule is not None:
            # KISA 참조 구현의 ECB 클래스. 호출 자체가 ECB 운영모드다.
            record(node.start_point[0] + 1, node.start_point[1] + 1, ecb_rule,
                   f"{trigger}(...) — KISA SEED 참조 구현의 ECB 모드", call=trigger,
                   spec="SEED/ECB")
        if trigger == "new SecretKeySpec" and len(args) >= 2:
            # 두 번째 인자는 이 키로 쓸 알고리즘이다. 키 출처와 별개로 알고리즘을 표와 견준다.
            algorithm = resolver.classify(args[1])
            if algorithm.kind == prov.CONSTANT and algorithm.values:
                spec = algorithm.values[0]
                table_rule = _table_owner("new SecretKeySpec", spec, rules)
                if table_rule is not None:
                    record(node.start_point[0] + 1, node.start_point[1] + 1, table_rule,
                           f"new SecretKeySpec(..., \"{spec}\")", call="new SecretKeySpec",
                           spec=spec)
        return True

    hutool = b"cn.hutool.crypto" in source
    key_rule = next((r for r in rules if r.rule_id == "CRYPTO-KEY-HARDCODED"), None)

    def record_key_use(node) -> None:
        """
        `cipher.init(mode, KEY)`에 넘긴 키 객체가 다른 곳(필드, 다른 메서드)에서 코드에 박힌 값으로 만들어졌으면
        쓰는 자리에서도 알린다. 키를 만든 자리가 메서드 밖(정적 필드 초기화)이면 그 자리만으로는 어느 암호화에
        쓰이는지 보이지 않는다(tomee StaticDESPasswordCipher). 확정된 위반일 때만 남긴다 — 모르는 키 객체는 흔하다.
        """
        name = node.child_by_field_name("name")
        args = _args_of(node)
        if key_rule is None or name is None or _text(name, source) != "init" or len(args) < 2:
            return
        if resolver.receiver_type(node) not in ("Cipher", "Mac"):
            return
        arg = args[1]
        if arg.type == "identifier" and resolver._value_nodes(_text(arg, source), node):
            return   # 같은 메서드에서 만든 키는 만든 자리에서 이미 판정한다
        origin = resolver.classify(arg)
        if origin.kind in (prov.CONSTANT, prov.PREDICTABLE):
            record(node.start_point[0] + 1, node.start_point[1] + 1, key_rule,
                   f"{_text(node, source)[:60]} — 코드에 박힌 값으로 만든 키",
                   unresolved=(), traced=origin.values, origin=origin,
                   # 판정은 키를 만든 호출 기준이다. `Cipher.init`은 키 규칙의 트리거가 아니다
                   call=next((t for t in key_rule.api_triggers
                              if any(v.startswith(t) for v in origin.values)), "new SecretKeySpec"))

    def record_hutool(node) -> bool:
        """
        Hutool(`cn.hutool.crypto`) 래퍼. 중국계 프로젝트에서 JCA 대신 흔히 쓴다.
        `SecureUtil.aes(key)`·`new AES(key)`는 운영모드를 안 주면 AES/ECB/PKCS5Padding이다.
        `SignAlgorithm.SHA1withRSA` 같은 열거 상수는 그 자체가 알고리즘 이름이다.
        """
        line, column = node.start_point[0] + 1, node.start_point[1] + 1
        if node.type == "field_access":
            owner = node.child_by_field_name("object")
            field = node.child_by_field_name("field")
            if owner is None or field is None:
                return False
            call = _HUTOOL_ENUMS.get(_text(owner, source).split(".")[-1])
            if call is None:
                return False
            spec = _text(field, source)
            table_rule = _table_owner(call, spec, rules)
            if table_rule is not None:
                record(line, column, table_rule, f"{_text(node, source)} — Hutool 알고리즘 상수",
                       call=call, spec=spec)
            return True
        if node.type == "method_invocation":
            callee = _callee(node, source)
            owner, _, method = callee.rpartition(".")
            if owner.split(".")[-1] != "SecureUtil" or method not in _HUTOOL_CIPHERS:
                return False
            algorithm, explicit_mode = _HUTOOL_CIPHERS[method], None
        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            name = _text(type_node, source).split(".")[-1] if type_node is not None else ""
            # 같은 이름의 자체 클래스와 헷갈리지 않게 Hutool에서 가져온 클래스만 본다
            if name not in _HUTOOL_CLASSES or not (
                    f"cn.hutool.crypto.symmetric.{name};".encode() in source
                    or b"cn.hutool.crypto.symmetric.*" in source):
                return False
            algorithm = _HUTOOL_CLASSES[name]
            args = _args_of(node)
            first = " ".join(_text(args[0], source).split()) if args else ""
            # `new AES(Mode.CBC, Padding.PKCS5Padding, key, iv)`, `new AES("CBC", "PKCS5Padding", key, iv)`
            explicit_mode = None
            if first.startswith("Mode."):
                explicit_mode = first.split(".")[-1]
            elif args and args[0].type == "string_literal" and len(args) >= 2 \
                    and args[1].type == "string_literal":
                explicit_mode = first.strip('"')
        else:
            return False
        mode = explicit_mode or "ECB"
        spec = f"{algorithm}/{mode}/PKCS5Padding"
        table_rule = _table_owner("Cipher.getInstance", algorithm, rules)
        if table_rule is not None:
            record(line, column, table_rule, f"{_text(node, source)[:60]} — Hutool {algorithm}",
                   call="Cipher.getInstance", spec=algorithm)
        if mode.upper() == "ECB" and ecb_rule is not None:
            note = "운영모드 미지정, 기본값 ECB" if explicit_mode is None else "ECB 운영모드"
            record(line, column, ecb_rule, f"{_text(node, source)[:60]} — Hutool {note}",
                   call="Cipher.getInstance", spec=spec)
        return True

    def visit(node) -> None:
        if (resolver is not None
                and node.type in ("method_invocation", "object_creation_expression")
                and record_material(node)):
            return
        if hutool and node.type in ("method_invocation", "object_creation_expression", "field_access") \
                and record_hutool(node):
            return
        if resolver is not None and node.type == "method_invocation":
            record_key_use(node)
        if node.type == "method_invocation":
            callee = _callee(node, source)
            literals, variables = _arguments(node, source)
            line = node.start_point[0] + 1
            column = node.start_point[1] + 1

            digest = _digest_wrapper_spec(callee)
            if digest:
                # 단순해시 용도로 표와 견준다. SHA-256 이상이면 표 대조에서 닫힌다.
                table_rule = _table_owner("MessageDigest.getInstance", digest, rules)
                if table_rule is not None:
                    record(line, column, table_rule, f"{callee}(...) — 해시 {digest}",
                           call="MessageDigest.getInstance", spec=digest)
                return

            # 인자가 판정을 가른다. `AES/ECB/...`는 운영모드 규칙, `MD5`는 해시 규칙이다.
            matched = None
            for value in literals:
                matched = match_literal(value, rules)
                if (matched is not None and matched.rule_id == "CRYPTO-MODE-ECB"
                        and _is_public_key_transformation(value)):
                    matched = None   # RSA/ECB/... 는 블록 운영모드가 아니다. 표로 넘긴다
                if matched is not None:
                    matched = _arbitrate(matched, callee, value, rules)
                    record(line, column, matched, f"{callee}(\"{value}\")",
                           call=callee, spec=value)
                    record_default_ecb(line, column, callee, value)
                    break
            if matched is not None:
                return

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
                record_default_ecb(line, column, callee, literals[0])
                return

            if api_rule is not None and callee.endswith("KeyPairGenerator.getInstance"):
                # 약한 키 길이 목록으로 여기서 걸러내지 않는다. 전에는 {512, 768, 1024,
                # 1536}에 없으면 통과시켜 RSA-2047이 새어 나갔다. 키 길이를 찾은 자리를
                # 그대로 넘기고 미달인지는 표와 견주는 쪽에서 정한다.
                pair = _key_bits_in(_enclosing_method(node), source,
                                    tree.root_node, int_fields, int_arguments,
                                    repo_calls, _enclosing_class(node, source), resolver,
                                    _assigned_to(node, source))
                algorithm = literals[0] if literals else ""
                if pair is not None:
                    record(pair[1], column, api_rule, f"{algorithm or '?'}-{pair[0]}",
                           call=callee, spec=algorithm, key_bits=pair[0])
                else:
                    # 키 길이 지정이 없으면 기본값이 쓰인다. 무엇인지 알 수 없으므로
                    # 확인 필요로 남긴다.
                    record(line, column, api_rule, f"{callee}(\"{algorithm}\")",
                           unresolved=("키 길이",), call=callee, spec=algorithm)
                return

            if api_rule is not None:
                # 인자가 변수면 값을 따라가 본다. 찾으면 그 값으로 규칙을 다시 본다.
                # 출처 판별을 먼저 쓴다. 흐름(실행 순서)·문맥(호출 지점)·객체(어느 new) 민감하게 값을 정한다.
                # 그걸로 상수가 확정되지 않을 때만 예전 문자열 추적(흐름 둔감, 모든 호출자 합침)으로 후보를 찾는다.
                traced: list[str] = _resolved_names(node, resolver)
                if not traced:
                    for variable in variables:
                        traced.extend(_trace(variable, node, tree.root_node, source,
                                             fields, call_arguments, repo_calls,
                                             _enclosing_class(node, source)))
                    traced = [v for v in dict.fromkeys(traced) if v.strip()]
                if not traced:
                    # 경로마다 값이 달라 확정은 못 했지만, 한 경로라도 약한 알고리즘 이름이면 그 경로가 오용이다
                    # (ofbiz `HashCrypt.digestHash("SHA", ...)`를 다른 곳은 설정값으로 부른다)
                    traced = _weak_partial_names(node, resolver, rules)

                if traced:
                    for value in traced:
                        traced_rule = match_literal(value, rules)
                        if traced_rule is not None:
                            traced_rule = _arbitrate(traced_rule, callee, value,
                                                     rules)
                            record(line, column, traced_rule,
                                   f"{callee}({variable_hint(variables)}=\"{value}\")",
                                   traced=tuple(traced), call=callee, spec=value)
                            if len(traced) == 1:
                                record_default_ecb(line, column, callee, value, tuple(traced))
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
                        if len(traced) == 1:
                            # 값이 하나로 확정됐을 때만. 경로마다 다르면 운영모드도 모른다.
                            record_default_ecb(line, column, callee, traced[0], tuple(traced))
                        return
                    return

                # 값 전체는 몰라도 앞부분이 상수면 그걸로 정해지는 경우가 있다. `"SHA1with" + alg`의 해시는 SHA-1,
                # `"AES/ECB/" + pad`는 ECB, `"DES/" + mode`는 DES다(실제 코드: jenkins Connection)
                prefix = _constant_prefix(node, resolver)
                if prefix:
                    prefix_rule = match_literal(prefix, rules)
                    if prefix_rule is not None:
                        prefix_rule = _arbitrate(prefix_rule, callee, prefix, rules)
                        record(line, column, prefix_rule, f"{callee}(\"{prefix}…\")",
                               call=callee, spec=prefix)
                        return
                    spec = prefix + "RSA" if re.search(r"with$", prefix, re.IGNORECASE) else prefix
                    if "/" in prefix or spec != prefix:
                        table_rule = _table_owner(callee, spec, rules)
                        if table_rule is not None:
                            record(line, column, table_rule, f"{callee}(\"{prefix}…\")",
                                   call=callee, spec=spec)
                            return

                # 값을 못 찾았다. 여기서 억지로 판정하지 않는다. 인자가 변수가 아니라 호출식(`props.getProperty(k)`)이어도
                # 값을 모르는 것은 같다 — 전에는 변수 목록이 비어 "값을 확인함"으로 보고 위반을 냈다.
                unresolved = tuple(variables)
                if not unresolved:
                    arg_nodes = node.child_by_field_name("arguments")
                    first = arg_nodes.named_children[0] if arg_nodes is not None and \
                        arg_nodes.named_children else None
                    if first is not None:
                        unresolved = (" ".join(_text(first, source).split())[:60],)
                record(line, column, api_rule, callee, unresolved, call=callee)

        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is None:
                return
            type_name = _text(type_node, source)
            # `new java.util.Random()`처럼 패키지까지 적은 생성은 단순 타입 이름으로 맞춘다(OWASP Benchmark에서 드러남)
            segments = type_name.split("<")[0].split(".")
            if len(segments) > 1 and all(s[:1].islower() for s in segments[:-1]):
                type_name = segments[-1]
            # 안쪽 클래스(`LEA.ECB`)는 패키지 경로가 붙어도(`kr.re.nsr.crypto.symm.LEA.ECB`) 마지막 두 마디로 맞춘다
            candidates = [type_name]
            if len(segments) > 2 and segments[-2][:1].isupper():
                candidates.append(".".join(segments[-2:]))
            rule = None
            for candidate in candidates:
                rule = match_api(candidate, rules) or match_api(f"new {candidate}", rules)
                if rule is not None:
                    type_name = candidate
                    break
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

    for node in _walk(tree.root_node):
        try:
            visit(node)
        except RecursionError:
            # 한 지점의 값 추적이 너무 깊어도 그 지점만 건너뛴다. 예외가 새면 파일의 지점 전체가 빠진다
            logger.warning("java_site_skipped",
                           f"{relative}:{node.start_point[0] + 1}: 값 추적이 재귀 한도를 넘어 이 지점을 건너뛴다")

    return [found[key] for key in sorted(found)]
