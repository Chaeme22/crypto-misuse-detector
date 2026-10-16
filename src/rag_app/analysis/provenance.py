"""
비밀 재료의 출처 판별 (Java).

키·IV·솔트·비밀번호·시드 규칙은 호출이 있다는 것만으로 판정이 서지 않는다.
`new IvParameterSpec(iv)`는 `iv`가 상수면 위반이고 `SecureRandom`으로 채웠으면 정상이다.
전에는 문자열 리터럴만 따라갔다. 그래서 `byte[] k = {1, 2}`도 `nextBytes(k)`로 채운 배열도
값을 모르는 자리가 되어 확인 필요로 떨어졌다.

출처는 구조로 답할 수 있는 질문이다. 모델에게 묻지 않는다. 답은 여섯 가지다.

  constant        코드에 박힌 값. 리터럴, 상수 배열, 채우지 않은 `new byte[n]`
  predictable     코드에 박히진 않았지만 예측할 수 있는 값. 현재 시각
  secure_random   SecureRandom이 만든 값
  weak_random     java.util.Random 같은 예측 가능한 난수가 만든 값
  external_input  환경 변수, 시스템 속성, 프로그램 인자, 입력 스트림
  unknown         끝까지 못 따라갔거나 경로마다 답이 다르다

경로가 여럿이면 모두 같은 답일 때만 그 답을 쓴다. 한 경로는 상수, 한 경로는 난수라면
어느 쪽이 쓰이는지 모르므로 unknown이다. 모르는 것을 아는 것처럼 답하지 않는다.

문장 순서는 보지 않는다(흐름 둔감). 대신 배열을 채우는 호출은 순서와 무관하게 출처를
바꾸는 것으로 본다. `new byte[16]` 뒤의 `sr.nextBytes(iv)`가 그렇다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONSTANT = "constant"
PREDICTABLE = "predictable"
SECURE_RANDOM = "secure_random"
WEAK_RANDOM = "weak_random"
EXTERNAL_INPUT = "external_input"
UNKNOWN = "unknown"

# 판정과의 대응. 반복 횟수는 출처가 아니라 값의 크기를 보므로 따로 둔다.
BELOW_MINIMUM = "below_minimum"
MEETS_MINIMUM = "meets_minimum"
# 약한 난수(java.util.Random 등)가 만든 재료도 예측할 수 있으므로 위반 근거다. 전에는 빠져 있어 그런 IV·키를
# "확인 필요"로 보냈다(CamBench_Cap 채점에서 드러남, 2026-10-09). NIST SP 800-38A: IV는 예측 불가능해야 한다
VIOLATING = frozenset({CONSTANT, PREDICTABLE, WEAK_RANDOM, BELOW_MINIMUM})
CLEAN = frozenset({SECURE_RANDOM, MEETS_MINIMUM})

MAX_DEPTH = 10   # 상수 → PBEKeySpec → generateSecret → getEncoded 같은 계산 사슬을 따라간다
# 따라가는 중인 변수를 다시 만났다는 표시. `k = Arrays.copyOf(k, 16)`은 k 자신을 다시
# 넣는 것이라 출처를 더하지 않는다. 합칠 때 뺀다.
_SELF = "_self"

_LITERALS = {"string_literal", "character_literal", "decimal_integer_literal",
             "hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
             "decimal_floating_point_literal", "hex_floating_point_literal",
             "true", "false"}

# 값을 바꾸지 않고 표현만 바꾸는 호출. 껍데기를 벗기고 안을 본다.
# 값을 나르는 쪽은 하나다. 인스턴스 메서드는 수신 객체(`k.getBytes("UTF-8")`의 k), 정적
# 메서드는 첫 인자(`Arrays.copyOf(k, 16)`의 k)다. 나머지 인자는 문자셋 이름이나 길이라서
# 값에 섞으면 상수 경로가 하나 더 있는 것처럼 보인다.
_PASSTHROUGH = {"getBytes", "toCharArray", "toString", "trim", "valueOf", "copyOf",
                "copyOfRange", "clone", "intern", "toLowerCase", "toUpperCase",
                "wrap", "array", "parseInt", "parseLong", "parseShort", "parseByte",
                "decode",
                # 검사하고 그대로 돌려주는 정적 메서드(Objects·Guava Preconditions·commons Validate·wicket Args)
                "requireNonNull", "checkNotNull", "notNull", "notEmpty", "notBlank", "requireNonNullElse"}

# 난수 값을 돌려주는 메서드. `ints()`·`longs()`는 넣지 않는다. 스트림 객체를 돌려주고,
# `String.valueOf(random.ints())`는 클래스 이름과 해시라서 예측할 수 있다.
_RANDOM_OUTPUT = {"nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean",
                  "nextGaussian", "generateSeed"}
# 이 노드 아래에 있으면 실행되지 않을 수도 있다.
_BRANCHES = {"if_statement", "switch_expression", "switch_block_statement_group",
             "while_statement", "for_statement", "enhanced_for_statement",
             "do_statement", "catch_clause", "ternary_expression", "lambda_expression"}
# `_scope_nodes`가 모으는 노드. `_in_scope`가 보는 선언 종류(kinds)는 모두 여기 들어 있어야 한다
_SCOPE_NODE_TYPES = frozenset({"variable_declarator", "assignment_expression", "method_invocation",
                               "local_variable_declaration", "field_declaration", "constant_declaration"})
# 조건 계산이 다른 조건 계산을 부르는 사슬의 최대 깊이. 조건 → 그 값 → 그 값을 정하는 조건 정도면 실제 코드에 충분하다.
# 9로 두었을 때 지점 수백 개의 큰 메서드에서 갈래가 곱으로 불어나 파일 하나에 몇 시간이 걸렸다(MASC qpid)
_CONDITION_CHAIN = 3
_BOXED = {"Integer", "Long", "Short", "Byte", "Character", "Boolean", "Double", "Float", "BigInteger"}
# 문자열을 조립하는 타입과 호출(`_strings`)
_STRING_TYPES = {"String", "StringBuilder", "StringBuffer"}
_STRING_BUILDERS = {"concat", "append", "join", "format", "toString", "toUpperCase", "toLowerCase",
                    "trim", "strip", "intern", "valueOf", "copyValueOf"}
# 바꿀 수 없는 값의 타입. 메서드에 넘겨도 내용이 바뀌지 않는다
_IMMUTABLE = _BOXED | {"String", "int", "long", "short", "boolean", "double", "float", "BigDecimal"}
_SECURE_TYPES = {"SecureRandom"}
_WEAK_TYPES = {"Random", "ThreadLocalRandom", "SplittableRandom"}

# 값을 밖에서 가져오는 호출. 무엇이 들어올지 코드로는 알 수 없다.
_EXTERNAL_CALLS = {"getenv", "getProperty", "readPassword", "readLine", "nextLine",
                   "getParameter", "getHeader", "getInitParameter", "getString",
                   "getProperties", "readAllBytes", "readAllLines", "readString"}
_TIME_CALLS = {"currentTimeMillis", "nanoTime"}
# 설정 객체에서 키로 값을 읽는 호출. 키가 저장소의 설정 파일에 있으면 그 값을 쓴다(`project_index.config_values`).
_CONFIG_CALLS = {"getProperty", "getString", "getRequiredProperty", "getValue"}
_SPRING_VALUE = re.compile(r'@Value\s*\(\s*"\$\{([^}:]+)(?::([^}]*))?\}"\s*\)')
_PLACEHOLDER = re.compile(r"^\$\{[^}]+\}$")

# 입력이 같으면 결과가 같은 계산. 입력이 모두 상수면 결과도 상수다. 상수 비밀번호로 유도한 키나
# 상수의 다이제스트는 소스에 박힌 키·솔트와 다르지 않다(실제 코드: ManifoldCF, Taverna).
_DERIVE = {"generateSecret", "digest", "doFinal", "getEncoded", "toByteArray", "encode",
           "encodeToString", "decode", "encodeHex", "decodeHex", "toHexString", "hash",
           "getPrivate", "getPublic"}
_KEY_GENERATION = {"generateKey", "generateKeyPair", "genKeyPair"}
# 계산을 하는 엔진 객체. 객체 자체가 아니라 넣은 데이터(인자, update로 넣은 값)가 입력이다.
# 엔진에 입력을 넣는 호출. `init(Cipher.ENCRYPT_MODE, key, iv)`의 모드 상수는 입력이 아니다.
_ENGINE_INPUTS = {"update", "init"}
_ENGINE_TYPES = {"MessageDigest", "SecretKeyFactory", "Cipher", "Mac", "KeyFactory",
                 "Encoder", "Decoder", "Base64", "Hex", "DigestUtils"}
# 인자로 값을 담는 객체. 인자가 모두 상수면 그 객체도 상수다.
_VALUE_TYPES = {"PBEKeySpec", "SecretKeySpec", "IvParameterSpec", "PBEParameterSpec",
                "GCMParameterSpec", "DESKeySpec", "DESedeKeySpec", "BigInteger"}

# 배열을 채우는 호출과 그 결과. (메서드 이름, 배열이 들어가는 인자 위치).
_FILL_RANDOM = ("nextBytes", 0)
_FILL_EXTERNAL = {("read", 0), ("readFully", 0), ("readNBytes", 0)}
_FILL_UNKNOWN = {("arraycopy", 2)}
_MUTATOR_PREFIXES = ("set", "fill", "put", "write", "xor", "copy", "load")
_CLASS_KINDS = ("class_declaration", "interface_declaration", "enum_declaration",
                "record_declaration")


@dataclass(frozen=True)
class Origin:
    kind: str
    note: str = ""
    values: tuple[str, ...] = ()   # 상수일 때 코드에 적힌 값. 보고서에 그대로 보인다.


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _short(text: str, limit: int = 60) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def combine(origins: list[Origin]) -> Origin:
    """여러 경로의 답을 합친다. 모두 같을 때만 그 답이다."""
    origins = [o for o in origins if o.kind != _SELF]
    if not origins:
        return Origin(UNKNOWN, "값이 들어오는 경로를 찾지 못했다")
    kinds = {o.kind for o in origins}
    if len(kinds) == 1:
        values = tuple(dict.fromkeys(v for o in origins for v in o.values))
        return Origin(origins[0].kind, origins[0].note, values)
    described = ", ".join(sorted(kinds))
    # 판정은 모름이지만, 상수 경로의 값은 남긴다. 알고리즘 이름은 한 경로라도 MD5면 오용이다(`partial_names`)
    constants = tuple(dict.fromkeys(v for o in origins if o.kind == CONSTANT for v in o.values))
    return Origin(UNKNOWN, f"경로마다 출처가 다르다({described})", constants)


class Resolver:
    """파일 하나의 구문 트리를 두고 표현식의 출처를 판별한다."""

    def __init__(self, root, source: bytes, project=None, path=None):
        self.root = root
        self.source = source
        # 저장소 색인(`project_index.Project`). 없으면 이 파일 안에서만 따라간다.
        self.project = project
        self.path = path
        self._active: set[tuple[int, str, int]] = set()
        self._evaluating: set[tuple[int, int]] = set()   # 지금 계산 중인 분기 조건들
        self._nesting = 0
        self._typing: set[str] = set()   # `var` 선언 타입을 구하는 중인 이름들
        self._decl_index: dict[str, list] | None = None   # 이름 → 선언들(`_declared_type`)
        self._scope_cache: dict[tuple, list] = {}   # 범위 → 선언·대입·호출 노드(`_scope_nodes`)
        self._bool_memo: dict[tuple, bool | None] = {}   # (조건, 상황) → 늘 같은 값인지(`_constant_bool`)
        # 문맥 민감도: 지금 따라가는 호출이 넘긴 인자. 메서드 시작 위치 → [(부른 쪽 판별기, 인자 노드들)] 스택.
        # 반환값을 볼 때 이 호출의 인자만 쓰고, 그 메서드를 부르는 다른 곳의 인자는 섞지 않는다.
        self._bindings: dict[int, list[tuple["Resolver", list]]] = {}
        self._methods: dict[str, list] = {}
        self._invocations: dict[str, list] = {}
        self._creations: dict[str, list] = {}
        self._classes: set[str] = set()
        # 이 파일의 클래스가 상속·구현하는 타입. 상수 인터페이스의 값을 찾을 때 본다.
        self._supertypes: set[str] = set()
        # `import static p.Keys.KEY` → {"KEY": "Keys"}, `import static p.Keys.*` → ["Keys"]
        self._static_imports: dict[str, str] = {}
        self._static_wildcards: list[str] = []
        for node in _walk(root):
            if node.type == "import_declaration":
                self._read_import(node)
            elif node.type in _CLASS_KINDS:
                name = node.child_by_field_name("name")
                if name is not None:
                    self._classes.add(_text(name, source))
                for field in ("superclass", "interfaces"):
                    part = node.child_by_field_name(field)
                    if part is not None:
                        self._supertypes.update(
                            _simple_type(t) for t in
                            re.findall(r"[A-Za-z_][\w.]*", _text(part, source))
                            if t not in ("extends", "implements"))
                for child in node.named_children:
                    if child.type == "extends_interfaces":
                        self._supertypes.update(
                            _simple_type(t) for t in
                            re.findall(r"[A-Za-z_][\w.]*", _text(child, source))
                            if t != "extends")
            if node.type in ("method_declaration", "constructor_declaration"):
                name = node.child_by_field_name("name")
                if name is not None:
                    self._methods.setdefault(_text(name, source), []).append(node)
            elif node.type == "method_invocation":
                name = node.child_by_field_name("name")
                if name is not None:
                    self._invocations.setdefault(_text(name, source), []).append(node)
            elif node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node is not None:
                    self._creations.setdefault(
                        _simple_type(_text(type_node, source)), []).append(node)
            elif node.type == "explicit_constructor_invocation":
                # 생성자 연쇄 `this(DEFAULT)`, `super("DES")`도 생성자를 부르는 자리다
                owner = _enclosing(node, _CLASS_KINDS)
                called = node.child_by_field_name("constructor")
                kind = _text(called, source) if called is not None else ""
                target = ""
                if owner is not None and kind == "this":
                    name = owner.child_by_field_name("name")
                    target = _text(name, source) if name is not None else ""
                elif owner is not None and kind == "super":
                    parent = owner.child_by_field_name("superclass")
                    found = re.findall(r"[A-Za-z_][\w.]*", _text(parent, source)) if parent is not None else []
                    target = _simple_type(next((t for t in found if t != "extends"), ""))
                if target:
                    self._creations.setdefault(target, []).append(node)

    # --- 공개 -------------------------------------------------------------------

    def classify(self, node, depth: int = 0) -> Origin:
        """
        표현식 하나의 출처.

        가장 바깥 호출에서 재귀 한도를 넘으면 이 식만 모른다고 답한다. 예외가 새면 그 파일의 지점 전체가 빠진다.
        """
        if self._nesting:
            return self._classify(node, depth)
        self._nesting += 1
        try:
            return self._classify(node, depth)
        except RecursionError:
            self._active.clear()
            self._evaluating.clear()
            return Origin(UNKNOWN, "값을 따라가다 재귀 한도를 넘었다")
        finally:
            self._nesting -= 1

    def _classify(self, node, depth: int = 0) -> Origin:
        if depth > MAX_DEPTH:
            return Origin(UNKNOWN, "추적 깊이를 넘었다")
        kind = node.type
        text = _text(node, self.source)

        if kind in _LITERALS:
            # 값 목록은 기존 추적과 같은 계약을 따른다. 문자열은 따옴표를 벗긴 값이다.
            value = text[1:-1] if kind == "string_literal" and len(text) >= 2 else text
            return Origin(CONSTANT, f"코드에 적힌 값 `{_short(text)}`", (_short(value),))
        if kind == "null_literal":
            return Origin(UNKNOWN, "null이 넘어간다")
        if kind == "array_initializer":
            return self._array_initializer(node, depth)
        if kind == "array_creation_expression":
            value = node.child_by_field_name("value")
            if value is not None:
                return self._array_initializer(value, depth)
            return Origin(CONSTANT, f"`{_short(text)}`를 채우지 않아 0으로 고정된 값",
                          (_short(text),))
        if kind in ("cast_expression", "parenthesized_expression"):
            inner = node.child_by_field_name("value") or (
                node.named_children[-1] if node.named_children else None)
            return self.classify(inner, depth) if inner is not None else Origin(UNKNOWN)
        if kind == "unary_expression":
            operand = node.child_by_field_name("operand")
            return self.classify(operand, depth) if operand is not None else Origin(UNKNOWN)
        if kind in ("binary_expression", "method_invocation", "object_creation_expression") \
                and self._builds_string(node):
            # `"AES/" + "ECB"`, `sb.append(...).toString()`, `String.format(...)`: 실제 문자열을 계산해 본다
            built = self._strings(node, depth)
            if built:
                return Origin(CONSTANT, f"코드에 적힌 값으로 만든 문자열 `{_short(text)}`", built)
        if kind == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            parts = [self.classify(p, depth) for p in (left, right) if p is not None]
            if any(p.kind == _SELF for p in parts):
                # `t = "0" + t`는 t 자신을 늘리는 것이라 새 출처가 아니다. 상수 쪽만 남기면 상수로 보이고,
                # 상수 기본값 규칙이 그것을 하드코딩 값으로 올린다(국산 시험 skrevolve).
                return Origin(_SELF)
            merged = combine(parts)
            if merged.kind == CONSTANT:
                return Origin(CONSTANT, f"코드에 적힌 값으로 만든 `{_short(text)}`",
                              (_short(text),))
            return merged
        if kind == "ternary_expression":
            branches = [node.child_by_field_name(f) for f in ("consequence", "alternative")]
            return combine([self.classify(b, depth) for b in branches if b is not None])
        if kind == "identifier":
            return self._variable(_text(node, self.source), node, depth)
        if kind == "field_access":
            target = node.child_by_field_name("object")
            field = node.child_by_field_name("field")
            if (target is not None and field is not None
                    and _text(target, self.source) == "this"):
                return self._field(_text(field, self.source), depth)
            if target is not None and field is not None and target.type == "field_access":
                # `Alg.WEAK.jca`: enum 상수의 필드
                owner, constant = target.child_by_field_name("object"), target.child_by_field_name("field")
                if owner is not None and constant is not None and self._is_class_name(owner, node):
                    found = self._enum_field(_simple_type(_text(owner, self.source)),
                                             _text(constant, self.source), _text(field, self.source), depth)
                    if found is not None:
                        return found
            if target is not None and field is not None and self._is_class_name(target, node):
                # `Keys.KEY`, `p.Keys.KEY`. 다른 클래스의 상수다.
                owner = _simple_type(_text(target, self.source))
                found = self._foreign_field(owner, _text(field, self.source), depth)
                if found is not None:
                    return found
            if target is not None and field is not None:
                # 필드 경로 대입: `h.a1 = "MD5"; ... h.a1`, `h.inner.a1` — 경로를 하나의 변수처럼 실행 순서대로 본다
                method = _enclosing(node, ("method_declaration", "constructor_declaration",
                                           "lambda_expression"))
                if method is not None:
                    path = " ".join(text.split())
                    found = self._reaching(path, method, node, depth, need_declaration=False)
                    if found is not None:
                        return found
            if target is not None and field is not None and target.type == "identifier":
                # 객체 민감도: `strong.alg`는 `strong`을 만든 `new Cfg(...)`의 인자로 정해진다
                found = self._object_field(_text(target, self.source), _text(field, self.source),
                                           node, depth)
                if found is not None:
                    return found
            return Origin(UNKNOWN, f"`{_short(text)}`의 출처를 따라가지 않는다")
        if kind == "array_access":
            array = node.child_by_field_name("array")
            if array is None:
                return Origin(UNKNOWN)
            origin = self.classify(array, depth)
            names = self._literal_elements(array, node)
            if origin.kind == CONSTANT and names:
                # `HASHES[i]`: 어느 원소인지 몰라도 후보는 코드에 적힌 원소들이다
                return Origin(CONSTANT, f"코드에 적힌 배열 `{_short(_text(array, self.source))}`의 원소", names)
            return origin
        if kind == "method_invocation":
            return self._invocation(node, depth)
        if kind == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = _simple_type(_text(type_node, self.source)) if type_node else ""
            if type_name == "String":
                args = _args(node)
                return combine([self.classify(a, depth) for a in args]) if args \
                    else Origin(CONSTANT, "빈 문자열", ('""',))
            if type_name in _BOXED and len(_args(node)) == 1:
                # `new Integer(20)`, `new Byte((byte) 100)`: 감싼 값 그대로다
                return self.classify(_args(node)[0], depth + 1)
            if type_name in _VALUE_TYPES and _args(node):
                merged = combine([self.classify(a, depth + 1) for a in _args(node)])
                if merged.kind == CONSTANT:
                    return Origin(CONSTANT, f"코드에 박힌 값으로 만든 `{_short(text)}`",
                                  (_short(text),))
                return merged
            return Origin(UNKNOWN, f"`{_short(text)}`가 만든 값")
        return Origin(UNKNOWN, f"`{_short(text)}`의 출처를 판별하지 못했다")

    def classify_int(self, node) -> tuple[int, ...] | None:
        """정수 값 목록. 하나라도 정수 상수가 아니면 None."""
        origin = self.classify(node)
        if origin.kind != CONSTANT or not origin.values:
            return None
        numbers = []
        for value in origin.values:
            cleaned = value.replace("_", "").rstrip("lL")
            if not cleaned.lstrip("-").isdigit():
                return None
            numbers.append(int(cleaned))
        return tuple(numbers)

    def receiver_type(self, node) -> str:
        """`ks.load(...)`의 `ks`가 무슨 타입인지. 모르면 빈 문자열."""
        target = node.child_by_field_name("object")
        if target is None:
            return ""
        return self._type_of(target, node)

    def runtime_type(self, expr, depth: int = 0) -> str:
        """
        식이 실제로 가리키는 객체의 타입(어느 `new`로 만들었는지). 모르면 빈 문자열.

        선언 타입과 다를 수 있다. `Random r = identity(new SecureRandom())`의 `r`은 SecureRandom이다. 선언 타입만 보면
        약한 난수로 오판한다(CamBench 문맥·객체 민감도 사례).
        """
        if expr is None or depth > MAX_DEPTH:
            return ""
        kind = expr.type
        if kind == "object_creation_expression":
            type_node = expr.child_by_field_name("type")
            return _simple_type(_text(type_node, self.source)) if type_node else ""
        if kind in ("parenthesized_expression", "cast_expression"):
            inner = expr.child_by_field_name("value") or (expr.named_children[-1] if expr.named_children else None)
            return self.runtime_type(inner, depth + 1)
        if kind == "identifier":
            name = _text(expr, self.source)
            values = self._value_nodes(name, expr)
            if values:
                types = {self.runtime_type(v, depth + 1) for v in values}
                return types.pop() if len(types) == 1 else ""
            method = _enclosing(expr, ("method_declaration", "constructor_declaration"))
            if method is None:
                return ""
            names = [_param_name(p, self.source) for p in _params(method)]
            if name not in names:
                return ""
            position = names.index(name)
            stack = self._bindings.get(method.start_byte)
            if stack:
                caller, args = stack[-1]
                return caller.runtime_type(args[position], depth + 1) if position < len(args) else ""
            # 호출 문맥이 없으면 이 파일에서 부르는 곳들의 인자가 모두 같은 타입일 때만 그 타입
            label_node = method.child_by_field_name("name")
            label = _text(label_node, self.source) if label_node is not None else ""
            callers = self._callers(method, label, len(names))
            types = {self.runtime_type(_args(call)[position], depth + 1) for call in callers}
            return types.pop() if len(types) == 1 else ""
        if kind == "field_access":
            path = " ".join(_text(expr, self.source).split())
            values = self._value_nodes(path, expr, need_declaration=False)
            if not values:
                return self._field_runtime_type(expr, depth)
            types = {self.runtime_type(v, depth + 1) for v in values}
            return types.pop() if len(types) == 1 else ""
        if kind == "method_invocation":
            name_node = expr.child_by_field_name("name")
            target = expr.child_by_field_name("object")
            method = _text(name_node, self.source) if name_node is not None else ""
            if method in ("getInstance", "getInstanceStrong") and target is not None:
                return self._type_of(target, expr)
            if target is None or _text(target, self.source) == "this":
                types = set()
                for declaration in self._methods.get(method, []):
                    if declaration.type != "method_declaration" or len(_params(declaration)) != len(_args(expr)):
                        continue
                    self._bindings.setdefault(declaration.start_byte, []).append((self, _args(expr)))
                    try:
                        for child in _walk(declaration):
                            if child.type == "return_statement" and child.named_children:
                                types.add(self.runtime_type(child.named_children[0], depth + 1))
                    finally:
                        self._bindings[declaration.start_byte].pop()
                return types.pop() if len(types) == 1 else ""
        return ""

    # --- 내부 -------------------------------------------------------------------

    def _builds_string(self, node) -> bool:
        """문자열을 조립하는 식인지. 이것만 계산해 본다(다른 계산의 출처 판별은 그대로 둔다)."""
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            return operator is not None and _text(operator, self.source) == "+"
        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            return type_node is not None and _simple_type(_text(type_node, self.source)) in _STRING_TYPES
        name = node.child_by_field_name("name")
        return name is not None and _text(name, self.source) in _STRING_BUILDERS

    def _strings(self, node, depth: int) -> tuple[str, ...] | None:
        """
        식이 만들 수 있는 문자열들. 모르는 조각이 하나라도 있으면 None.

        JCA 알고리즘 이름은 흔히 조각을 이어 만든다: `"AES/" + mode + "/NoPadding"`, `String.format("%s/ECB", alg)`,
        `new StringBuilder(alg).append("/ECB")`, `new String(new char[]{'R','C','4'})`. 이어 붙인 결과를 알아야
        운영모드·알고리즘을 볼 수 있다. 경우의 수가 너무 많으면(16개 초과) 포기한다.
        """
        if node is None or depth > MAX_DEPTH:
            return None
        kind, text = node.type, _text(node, self.source)
        if kind == "string_literal":
            return (text[1:-1],)
        if kind == "character_literal":
            return (text[1:-1],)
        if kind in ("decimal_integer_literal", "true", "false"):
            return (text,)
        if kind in ("parenthesized_expression", "cast_expression"):
            inner = node.child_by_field_name("value") or (node.named_children[-1] if node.named_children else None)
            return self._strings(inner, depth + 1)
        if kind == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is None or _text(operator, self.source) != "+":
                return None
            return _product([self._strings(node.child_by_field_name("left"), depth + 1),
                             self._strings(node.child_by_field_name("right"), depth + 1)])
        if kind == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = _simple_type(_text(type_node, self.source)) if type_node is not None else ""
            if type_name not in _STRING_TYPES:
                return None
            if type_name != "String" and node.parent is not None and \
                    node.parent.type in ("variable_declarator", "assignment_expression"):
                # 변수에 담은 StringBuilder는 뒤 문장의 append로 바뀐다. 한 식 안의 사슬만 계산한다
                return None
            args = _args(node)
            if not args:
                return ("",)
            if len(args) == 1 and args[0].type == "decimal_integer_literal":
                return ("",)   # `new StringBuilder(16)`: 용량일 뿐 내용은 비어 있다
            if len(args) == 1:
                return self._chars(args[0], depth) or self._strings(args[0], depth + 1)
            return None
        if kind == "method_invocation":
            name_node, target, args = node.child_by_field_name("name"), node.child_by_field_name("object"), _args(node)
            method = _text(name_node, self.source) if name_node is not None else ""
            static_string = target is not None and _text(target, self.source).split(".")[-1] == "String"
            if method in ("toUpperCase", "toLowerCase", "trim", "strip", "intern", "toString") and target is not None:
                base = self._strings(target, depth + 1)
                if base is None:
                    return None
                change = {"toUpperCase": str.upper, "toLowerCase": str.lower,
                          "trim": str.strip, "strip": str.strip}.get(method, lambda s: s)
                return tuple(dict.fromkeys(change(s) for s in base))
            if method in ("concat", "append") and target is not None and not static_string and len(args) == 1:
                return _product([self._strings(target, depth + 1), self._strings(args[0], depth + 1)])
            if method == "join" and static_string and len(args) >= 2:
                separator = self._strings(args[0], depth + 1)
                parts = [self._strings(a, depth + 1) for a in args[1:]]
                if separator is None or len(separator) != 1 or any(p is None for p in parts):
                    return None
                joined = _product([p if i == 0 else tuple(separator[0] + v for v in p) for i, p in enumerate(parts)])
                return joined
            if method == "format" and static_string and args:
                pattern = self._strings(args[0], depth + 1)
                values = [self._strings(a, depth + 1) for a in args[1:]]
                if pattern is None or len(pattern) != 1 or any(v is None or len(v) != 1 for v in values):
                    return None
                pieces = re.split(r"%[sd]", pattern[0])
                if len(pieces) != len(values) + 1 or "%" in "".join(pieces).replace("%%", ""):
                    return None
                out = pieces[0]
                for value, piece in zip(values, pieces[1:]):
                    out += value[0] + piece
                return (out.replace("%%", "%"),)
            if method in ("valueOf", "copyValueOf") and static_string and len(args) == 1:
                return self._chars(args[0], depth) or self._strings(args[0], depth + 1)
            # 그 밖의 호출(같은 파일 메서드가 돌려주는 값 등)은 출처 판별의 상수 답을 빌린다
        if kind in ("identifier", "field_access", "array_access", "method_invocation"):
            if kind == "identifier" and self._declared_type(text, node) in _STRING_TYPES - {"String"}:
                return None   # 바뀌는 StringBuilder 변수
            origin = self.classify(node, depth + 1)
            if origin.kind == CONSTANT and origin.values and \
                    not any(c in v for v in origin.values for c in '("{'):
                return tuple(origin.values)
        return None

    def _chars(self, node, depth: int) -> tuple[str, ...] | None:
        """`new char[]{'R','C','4'}` → `("RC4",)`."""
        if node.type == "array_creation_expression":
            node = node.child_by_field_name("value")
        if node is None or node.type != "array_initializer" or not node.named_children:
            return None
        if not all(e.type == "character_literal" for e in node.named_children):
            return None
        return ("".join(_text(e, self.source)[1:-1] for e in node.named_children),)

    def _literal_elements(self, array, at) -> tuple[str, ...]:
        """`String[] HASHES = {"SHA-256", "SHA-384"}`처럼 문자열 원소만으로 된 배열이면 그 원소들."""
        if array.type != "identifier":
            return ()
        name = _text(array, self.source)
        values = self._value_nodes(name, at)
        if not values:
            for node in _walk(self.root):
                if node.type == "variable_declarator" and node.parent is not None \
                        and node.parent.type == "field_declaration":
                    found = node.child_by_field_name("name")
                    if found is not None and _text(found, self.source) == name:
                        value = node.child_by_field_name("value")
                        values = [value] if value is not None else []
                        break
        if len(values) != 1:
            return ()
        value = values[0]
        if value.type == "array_creation_expression":
            value = value.child_by_field_name("value")
        if value is None or value.type != "array_initializer" or not value.named_children:
            return ()
        elements = value.named_children
        if not all(e.type == "string_literal" for e in elements):
            return ()
        return tuple(dict.fromkeys(_text(e, self.source)[1:-1] for e in elements))

    def _array_initializer(self, node, depth: int) -> Origin:
        elements = list(node.named_children)
        if not elements:
            return Origin(CONSTANT, "빈 배열", ("{}",))
        merged = combine([self.classify(e, depth) for e in elements])
        if merged.kind == CONSTANT:
            text = _short(_text(node, self.source))
            return Origin(CONSTANT, f"코드에 적힌 배열 `{text}`", (text,))
        return merged

    def _type_of(self, expr, at) -> str:
        if expr.type == "identifier":
            name = _text(expr, self.source)
            declared = self._declared_type(name, at)
            if declared:
                return declared
            # 선언이 없는 대문자 이름은 클래스 이름이다. `SecureRandom.getInstanceStrong()`
            return name if name[:1].isupper() else ""
        if expr.type == "object_creation_expression":
            type_node = expr.child_by_field_name("type")
            return _simple_type(_text(type_node, self.source)) if type_node else ""
        if expr.type == "method_invocation":
            target = expr.child_by_field_name("object")
            name = expr.child_by_field_name("name")
            owner = self._type_of(target, at) if target is not None else ""
            method = _text(name, self.source) if name is not None else ""
            # 팩터리는 자기 타입을 돌려준다. `SecureRandom.getInstance("SHA1PRNG")`
            if owner and method in ("getInstance", "getInstanceStrong", "current"):
                return owner
            return ""
        if expr.type == "field_access":
            field = expr.child_by_field_name("field")
            return self._declared_type(_text(field, self.source), at) if field else ""
        return ""

    def _declared_type(self, name: str, at) -> str:
        scopes = [s for s in (_enclosing(at, ("method_declaration",
                                               "constructor_declaration")),
                              _enclosing(at, ("class_body",)), self.root) if s is not None]
        # 가까운 범위부터 본다. 한 범위에 같은 이름이 다른 타입으로 여럿 선언돼 있으면
        # (다른 블록의 `Random r`과 `SecureRandom r`) 어느 쪽인지 모르므로 답하지 않는다.
        # 먼저 찾은 쪽을 쓰면 약한 난수를 SecureRandom으로 보고 정상으로 닫을 수 있다.
        # 선언 색인(파일당 한 번 만든다)에서 이 이름의 선언만 본다. 예전에는 부를 때마다 범위 전체를 훑어
        # 큰 파일(7,000줄, 지점 수백 개)에서 몇 분씩 걸렸다. 색인은 같은 순회 순서로 만들어 결과가 같다
        if self._decl_index is None:
            self._decl_index = self._build_decl_index()
        entries = self._decl_index.get(name, ())
        for scope in scopes:
            types: set[str] = set()
            for start, end, kind, type_node, value in entries:
                if not (scope.start_byte <= start and end <= scope.end_byte):
                    continue
                declared = _simple_type(_text(type_node, self.source)) if type_node else ""
                if kind == "declarator" and declared == "var" and value is not None:
                    # Java 10 `var ks = KeyStore.getInstance(...)`: 초기값의 타입이 선언 타입이다.
                    # 다른 블록의 같은 이름(`var f = f.next()`)을 다시 만나면 끝없이 돈다 — 해석 중인 이름은 건너뛴다
                    if name in self._typing:
                        declared = ""
                    else:
                        self._typing.add(name)
                        try:
                            declared = self._type_of(value, value)
                        finally:
                            self._typing.discard(name)
                types.add(declared)
            if types:
                return types.pop() if len(types) == 1 else ""
        return ""

    def _scope_nodes(self, scope) -> list:
        """
        범위 안의 선언·대입·호출 노드를 `_walk(scope)` 순서 그대로 한 번만 모아 둔다. `_writes`·`_in_scope`·`_fills`가
        지점마다 범위 전체(식별자·리터럴까지)를 다시 훑던 것을 줄인다. 보는 노드와 순서가 같아 결과가 같다.
        """
        key = (scope.start_byte, scope.end_byte, scope.type)
        found = self._scope_cache.get(key)
        if found is None:
            found = [n for n in _walk(scope) if n.type in _SCOPE_NODE_TYPES]
            self._scope_cache[key] = found
        return found

    def _build_decl_index(self) -> dict[str, list]:
        """
        이름 → [(선언 시작, 끝, 종류, 타입 노드, 초기값 노드)]. `_walk(self.root)` 순서 그대로 담는다.
        한 범위 안의 노드를 `_walk(범위)`로 돌 때와 같은 상대 순서다(스택 순회는 부분 트리를 이어서 같은 순서로 돈다).
        """
        index: dict[str, list] = {}
        for node in _walk(self.root):
            if node.type in ("local_variable_declaration", "field_declaration"):
                type_node = node.child_by_field_name("type")
                for declarator in node.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    found = declarator.child_by_field_name("name")
                    if found is not None:
                        index.setdefault(_text(found, self.source), []).append(
                            (node.start_byte, node.end_byte, "declarator", type_node,
                             declarator.child_by_field_name("value")))
            elif node.type == "formal_parameter":
                found = node.child_by_field_name("name")
                if found is not None:
                    index.setdefault(_text(found, self.source), []).append(
                        (node.start_byte, node.end_byte, "parameter", node.child_by_field_name("type"), None))
        return index

    def _invocation(self, node, depth: int) -> Origin:
        name_node = node.child_by_field_name("name")
        method = _text(name_node, self.source) if name_node is not None else ""
        target = node.child_by_field_name("object")
        owner = self._type_of(target, node) if target is not None else ""
        args = _args(node)

        if method in _PASSTHROUGH and not (method in _DERIVE and target is not None and args
                                            and not (target is None or self._is_class_name(target, node))):
            # `Base64.getDecoder().decode("...")`처럼 엔진 객체에 값을 넣는 호출은 아래 계산(_derived)으로 본다
            static = target is None or self._is_class_name(target, node)
            carrier = (args[0] if args else None) if static else target
            if carrier is None:
                return Origin(UNKNOWN, f"`{_short(_text(node, self.source))}`의 값을 모른다")
            return self.classify(carrier, depth + 1)
        if method in _RANDOM_OUTPUT:
            if owner in _SECURE_TYPES:
                return Origin(SECURE_RANDOM, f"SecureRandom.{method}()이 만든 값")
            if owner in _WEAK_TYPES:
                return Origin(WEAK_RANDOM, f"{owner}.{method}()이 만든 값")
        if method in ("ints", "longs", "doubles") and owner in _SECURE_TYPES | _WEAK_TYPES:
            # 값이 아니라 스트림 객체다. 문자열로 바꾸면 `IntPipeline$Head@1b6d3586`(클래스 이름과 해시)이 된다
            return Origin(PREDICTABLE, f"`{_short(_text(node, self.source))}`는 난수 값이 아니라 스트림 객체다")
        if method in _KEY_GENERATION and owner in ("KeyGenerator", "KeyPairGenerator"):
            # 키 생성기는 안의 SecureRandom으로 키를 만든다
            return Origin(SECURE_RANDOM, f"{owner}.{method}()이 만든 키")
        if owner == "Math" and method == "random":
            return Origin(WEAK_RANDOM, "Math.random()이 만든 값")
        if method in _TIME_CALLS:
            return Origin(PREDICTABLE, f"현재 시각(`{method}`)은 예측할 수 있다")
        if method in ("get", "getOrDefault") and target is not None and args \
                and args[0].type == "string_literal":
            stored = self._map_value(target, args[0], node, depth)
            if stored is not None:
                return stored
        if method in _CONFIG_CALLS and owner != "System" and args \
                and args[0].type == "string_literal":
            # `props.getProperty("hashAlg1", "SHA-512")`: 키가 저장소의 설정 파일에 있으면 그 값이다
            found = self._config_origin(_text(args[0], self.source)[1:-1])
            if found is not None:
                return found
        if method in _EXTERNAL_CALLS:
            return Origin(EXTERNAL_INPUT, f"`{_short(_text(node, self.source))}`로 밖에서 "
                                          f"가져온 값")

        if method in _DERIVE:
            derived = self._derived(node, target, args, depth)
            if derived is not None:
                return derived

        # 같은 파일에 선언된 메서드면 그 메서드가 돌려주는 값을 본다.
        if target is None or _text(target, self.source) == "this":
            returns = self._returns(method, depth, args, self)
            if returns:
                return combine(returns)
        elif owner and owner not in self._classes:
            # 다른 클래스의 메서드. `Cfg.iv()`, 타입이 `Box`인 변수의 `box.key()`
            found = self._foreign(owner, lambda r: r._returns(method, depth + 1, args, self))
            if found:
                return combine(found)
        return Origin(UNKNOWN, f"`{_short(_text(node, self.source))}`가 돌려주는 값")

    def _returns(self, method: str, depth: int, args: list | None = None,
                 caller: "Resolver | None" = None) -> list[Origin]:
        """
        메서드가 돌려주는 값. 부른 자리의 인자(`args`, 부른 쪽 판별기 `caller`)를 주면 문맥 민감하게 본다 —
        `identity("MD5")`와 `identity("SHA-256")`가 있을 때 이 호출의 반환값은 이 호출의 인자로만 정해진다.
        """
        returns = []
        for declaration in self._methods.get(method, []):
            if declaration.type != "method_declaration":
                continue
            params = _params(declaration)
            bound = args is not None and caller is not None and len(params) == len(args)
            if args is not None and not bound and params and len(params) != len(args):
                continue   # 인자 수가 다른 오버로드는 이 호출이 아니다
            if bound:
                self._bindings.setdefault(declaration.start_byte, []).append((caller, list(args)))
            try:
                for child in _walk(declaration):
                    if child.type == "return_statement" and child.named_children \
                            and _same(_enclosing(child, ("method_declaration", "lambda_expression",
                                                   "constructor_declaration")), declaration):
                        returns.append(self.classify(child.named_children[0], depth + 1))
            finally:
                if bound:
                    self._bindings[declaration.start_byte].pop()
        return returns

    # --- 파일 밖 -------------------------------------------------------------------

    def _read_import(self, node) -> None:
        text = _text(node, self.source)
        match = re.match(r"import\s+static\s+([\w.]+?)(\.\*)?\s*;", text)
        if not match:
            return
        parts = match.group(1).split(".")
        if match.group(2):
            self._static_wildcards.append(parts[-1])
        elif len(parts) >= 2:
            self._static_imports[parts[-1]] = parts[-2]

    def _config_origin(self, key: str, default: str | None = None) -> Origin | None:
        """
        설정 키의 값. 저장소의 설정 파일에 있으면 상수(커밋된 값은 코드에 적은 것과 같이 노출·고정된다), 값이 환경 변수
        자리(`${ENV}`)면 외부 입력, 파일에 없고 기본값(`${key:default}`)이 있으면 그 기본값, 둘 다 없으면 None.
        """
        values = self.project.config_values(key) if self.project is not None else []
        if values:
            if all(_PLACEHOLDER.match(v.strip()) for v, _ in values):
                return Origin(EXTERNAL_INPUT, f"설정 `{key}`가 환경 변수 자리다")
            shown = tuple(dict.fromkeys(v.strip().strip('"').strip("'") for v, _ in values
                                        if not _PLACEHOLDER.match(v.strip())))
            files = ", ".join(sorted({p.name for _, p in values}))
            return Origin(CONSTANT, f"저장소의 설정 파일({files})에 적힌 `{key}` 값", shown)
        if default is not None:
            return Origin(CONSTANT, f"설정 `{key}`의 기본값이 코드에 적혀 있다", (default,))
        return None

    def _spring_value(self, declaration) -> Origin | None:
        """`@Value("${key}")`가 붙은 필드·인자의 값."""
        match = _SPRING_VALUE.search(_text(declaration, self.source))
        if not match:
            return None
        key, default = match.group(1).strip(), match.group(2)
        found = self._config_origin(key, default)
        return found or Origin(EXTERNAL_INPUT, f"설정 `{key}`(저장소에서 값을 찾지 못함)")

    def _foreign(self, owner: str, ask) -> list[Origin]:
        """
        `owner` 클래스를 선언한 다른 파일마다 `ask(resolver)`의 답을 모은다. 답이 없는 후보는 뺀다.

        같은 이름의 클래스가 여럿이면 모든 후보의 답을 함께 돌려준다. 합칠 때 답이 갈리면 모른다가 된다.
        """
        if self.project is None or not owner:
            return []
        found: list[Origin] = []
        for path in self.project.files_declaring(owner):
            if path == self.path:
                continue
            resolver = self.project.resolver(path)
            if resolver is None or owner not in resolver._classes:
                continue
            answer = ask(resolver)
            if isinstance(answer, list):
                found.extend(answer)
            elif answer is not None:
                found.append(answer)
        return found

    def _foreign_field(self, owner: str, name: str, depth: int) -> Origin | None:
        if depth > MAX_DEPTH:
            return None
        # 인터페이스의 상수는 구문 트리에서 `constant_declaration`이다
        found = self._foreign(owner, lambda r: r._in_scope(
            name, r.root, ("field_declaration", "constant_declaration"), depth + 1))
        return combine(found) if found else None

    def _map_value(self, target, key, at, depth: int) -> Origin | None:
        """
        `hm.get("aaa")`: 같은 맵(같은 이름)에 같은 문자열 키로 넣은 값들(`hm.put("aaa", value)`).
        지역 맵이면 그 메서드 안, 필드 맵이면 파일 전체에서 찾는다. 늘 거짓인 분기 안의 넣기는 뺀다.
        """
        receiver = " ".join(_text(target, self.source).split())
        wanted = _text(key, self.source)
        method = _enclosing(at, ("method_declaration", "constructor_declaration", "lambda_expression"))
        local = method is not None and target.type == "identifier" and bool(self._value_nodes(receiver, at))
        scope = method if local else self.root
        origins = []
        for call in _walk(scope):
            if call.type != "method_invocation":
                continue
            name, obj, args = call.child_by_field_name("name"), call.child_by_field_name("object"), _args(call)
            if name is None or obj is None or _text(name, self.source) not in ("put", "putIfAbsent") \
                    or len(args) != 2 or " ".join(_text(obj, self.source).split()) != receiver \
                    or _text(args[0], self.source) != wanted:
                continue
            if self._dead(call, _enclosing(call, ("method_declaration", "constructor_declaration"))):
                continue
            origins.append(self.classify(args[1], depth + 1))
        return combine(origins) if origins else None

    def _parameter_from_other_files(self, method, label: str, arity: int, position: int,
                                    depth: int) -> Origin | None:
        """
        다른 파일에서 이 메서드를 부르는 자리의 인자. 부르는 쪽 수신 객체의 타입이 이 클래스일 때만 잇는다.

        운영 코드의 유틸을 테스트에서만 부른다면 테스트 값으로 판정하지 않는다. 테스트가 넘긴 고정 키가
        운영 코드의 하드코딩 키로 보고된다.
        """
        if self.project is None or depth > MAX_DEPTH:
            return None
        owner_node = _enclosing(method, _CLASS_KINDS)
        name_node = owner_node.child_by_field_name("name") if owner_node is not None else None
        if name_node is None:
            return None
        owner = _text(name_node, self.source)
        skip_tests = not self.project.is_test(self.path)
        constructor = method.type == "constructor_declaration"
        origins: list[Origin] = []
        for path in self.project.files_calling(label, owner):
            if path == self.path or (skip_tests and self.project.is_test(path)):
                continue
            resolver = self.project.resolver(path)
            if resolver is None:
                continue
            for call in resolver._calls_into(owner, label, arity, constructor):
                origins.append(resolver.classify(_args(call)[position], depth + 1))
        return combine(origins) if origins else None

    def _calls_into(self, owner: str, label: str, arity: int, constructor: bool) -> list:
        """이 파일에서 `owner` 클래스의 `label`을 부르는 자리."""
        if constructor:
            return [c for c in self._creations.get(owner, []) if len(_args(c)) == arity]
        out = []
        for call in self._invocations.get(label, []):
            if len(_args(call)) != arity:
                continue
            target = call.child_by_field_name("object")
            if target is None:
                # 상속받은 메서드를 그냥 부르는 경우
                if owner in self._supertypes:
                    out.append(call)
                continue
            if _simple_type(self._type_of(target, call) or "") == owner:
                out.append(call)
        return out

    def _derived(self, node, target, args: list, depth: int) -> Origin | None:
        """결정적 계산의 결과. 입력이 모두 상수면 상수, 입력을 모르면 None(다른 판정에 맡긴다)."""
        inputs = [self.classify(a, depth + 1) for a in args]
        if target is not None:
            owner = self._type_of(target, node)
            target_text = _text(target, self.source)
            # `java.util.Base64.getDecoder()`처럼 패키지를 붙여도 첫 클래스 이름(대문자로 시작)으로 본다
            first_class = re.search(r"(?:^|\.)([A-Z]\w*)", target_text)
            engine = (owner in _ENGINE_TYPES
                      or target_text.split(".")[0].split("(")[0] in _ENGINE_TYPES
                      or (first_class is not None and first_class.group(1) in _ENGINE_TYPES))
            if engine:
                # 다이제스트·암호 객체는 update로 넣은 데이터가 입력이다. MAC·암호는 init으로 넣은 키도
                # 입력이다. 키를 빼면 밖에서 온 키로 상수를 HMAC한 값이 상수로 보인다(nacos 서명 키 유도).
                if target.type == "identifier":
                    scope = _enclosing(node, ("method_declaration", "constructor_declaration"))
                    for call in (_walk(scope) if scope is not None else ()):
                        if call.type != "method_invocation":
                            continue
                        name = call.child_by_field_name("name")
                        obj = call.child_by_field_name("object")
                        if (name is not None and _text(name, self.source) in _ENGINE_INPUTS
                                and obj is not None and _text(obj, self.source) == target_text):
                            inputs.extend(self.classify(a, depth + 1) for a in _args(call)
                                          if a.type not in ("decimal_integer_literal", "field_access")
                                          or _text(name, self.source) == "update")
            else:
                inputs.append(self.classify(target, depth + 1))
        inputs = [o for o in inputs if o.kind != _SELF]
        if not inputs:
            return None
        merged = combine(inputs)
        if merged.kind == CONSTANT:
            text = _short(_text(node, self.source))
            return Origin(CONSTANT, f"코드에 박힌 값에서 계산한 값 `{text}`", (text,))
        return merged

    def _is_class_name(self, expr, at) -> bool:
        """
        `String.valueOf`의 `String`처럼 변수가 아니라 클래스 이름인지.

        `KEY`나 `Keys.KEY`처럼 전부 대문자인 이름은 상수다. 대문자로 시작한다고 클래스로 보면
        `Keys.KEY.getBytes()`가 정적 호출로 읽혀 값을 나르는 쪽을 잃는다.
        """
        if expr.type == "field_access":
            return _looks_like_class(_text(expr, self.source).split(".")[-1])
        if expr.type != "identifier":
            return False
        name = _text(expr, self.source)
        return _looks_like_class(name) and not self._declared_type(name, at)

    def _variable(self, name: str, at, depth: int) -> Origin:
        method = _enclosing(at, ("method_declaration", "constructor_declaration",
                                 "lambda_expression"))
        # 흐름 민감하게 보므로 같은 변수라도 쓰는 위치마다 값이 다르다. `k = Arrays.copyOf(k, 16)`의 오른쪽 `k`는 그
        # 앞까지의 값이다. 같은 위치를 다시 만나면(반복문의 `k = k + x`) 그때만 순환으로 끊는다.
        key = (method.start_byte if method is not None else -1, name,
               at.start_byte if at is not None else -1)
        if key in self._active:
            return Origin(_SELF)
        self._active.add(key)
        try:
            return self._variable_in(name, method, depth, at)
        finally:
            self._active.discard(key)

    # --- 흐름·경로 민감도 -------------------------------------------------------------

    def _writes(self, name: str, method) -> list[tuple[object, str, object]]:
        """메서드 안에서 변수에 값을 넣는 사건들: (노드, 종류, 값 노드 또는 미리 정한 출처). 소스 순서."""
        events: list[tuple[object, str, object]] = []
        for node in self._scope_nodes(method):
            if node.type == "variable_declarator":
                found = node.child_by_field_name("name")
                if found is not None and _text(found, self.source) == name:
                    value = node.child_by_field_name("value")
                    events.append((node, "declare", value))
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                if _assigned_name(left, self.source) == name or (
                        "." in name and " ".join(_text(left, self.source).split()) == name):
                    events.append((node, "assign", right))
                elif left.type == "array_access" and _assigned_name(
                        left.child_by_field_name("array"), self.source) == name:
                    # 원소 하나에 넣는 값의 출처. `key[0] = 20`은 상수, `key[i] = (byte) rnd.nextInt()`는 그 난수다
                    events.append((node, "partial", self._element_origin(name, right)))
            elif node.type == "method_invocation":
                origin = self._fill_origin(name, node)
                if origin is not None:
                    events.append((node, "fill", origin))
                else:
                    helper = self._helper_write(name, node)
                    if helper is not None:
                        events.append((node, "partial", helper))
        events.sort(key=lambda e: e[0].start_byte)
        return events

    def _element_origin(self, name: str, value) -> Origin:
        origin = self.classify(value, MAX_DEPTH - 3)
        if origin.kind == CONSTANT:
            return Origin(CONSTANT, f"`{name}`의 원소에 코드에 적힌 값을 넣는다", origin.values)
        if origin.kind in (UNKNOWN, _SELF):
            return Origin(UNKNOWN, f"`{name}`의 원소를 따로 채운다")
        return origin

    def _fill_origin(self, name: str, node) -> Origin | None:
        method_node = node.child_by_field_name("name")
        if method_node is None:
            return None
        method = _text(method_node, self.source)
        for position, arg in enumerate(_args(node)):
            if arg.type != "identifier" or _text(arg, self.source) != name:
                continue
            if (method, position) == _FILL_RANDOM:
                owner = self.runtime_type(node.child_by_field_name("object")) or self.receiver_type(node)
                if owner in _SECURE_TYPES:
                    seed = self._fixed_seed(node)
                    if seed:
                        return Origin(PREDICTABLE, f"`{name}`을 고정 시드({seed})를 넣은 SecureRandom으로 채운다")
                    return Origin(SECURE_RANDOM, f"`{name}`을 SecureRandom.nextBytes로 채운다")
                if owner in _WEAK_TYPES:
                    return Origin(WEAK_RANDOM, f"`{name}`을 {owner}.nextBytes로 채운다")
                return Origin(UNKNOWN, f"`{name}`을 채우는 난수 생성기 종류를 모른다")
            if (method, position) in _FILL_EXTERNAL:
                return Origin(EXTERNAL_INPUT, f"`{name}`을 입력 스트림에서 읽어 채운다")
            if (method, position) in _FILL_UNKNOWN:
                return Origin(UNKNOWN, f"`{name}`에 다른 배열을 복사해 넣는다")
        return None

    def _fixed_seed(self, fill) -> str:
        """
        `r.nextBytes(x)` 앞에서 같은 메서드 안의 `r`에 상수 시드를 넣었는지(`r.setSeed(123)`, `new SecureRandom(seed)`).
        SHA1PRNG 등은 첫 사용 전에 시드를 받으면 그 시드만으로 출력이 정해진다. 넣었으면 그 시드 문자열.
        """
        target = fill.child_by_field_name("object")
        if target is None or target.type != "identifier":
            return ""
        receiver = _text(target, self.source)
        method = _enclosing(fill, ("method_declaration", "constructor_declaration", "lambda_expression"))
        if method is None:
            return ""
        seeds = []
        for node in _walk(method):
            if node.start_byte >= fill.start_byte or self._dead(node, method):
                continue
            if node.type == "method_invocation":
                obj, called = node.child_by_field_name("object"), node.child_by_field_name("name")
                if obj is not None and called is not None and _text(obj, self.source) == receiver \
                        and _text(called, self.source) == "setSeed" and _args(node):
                    seeds.append(_args(node)[0])
        for value in self._value_nodes(receiver, fill):
            if value.type == "object_creation_expression" and _args(value):
                seeds.append(_args(value)[0])
        for seed in seeds:
            origin = self.classify(seed)
            if origin.kind in (CONSTANT, PREDICTABLE):
                return _text(seed, self.source)
        return ""

    def _helper_write(self, name: str, node) -> Origin | None:
        """
        이 파일의 메서드(`setBit(out, i, 1)`)나 이름이 쓰기인 메서드에 배열을 넘기면 그 안에서 일부를 바꿀 수 있다.
        모르는 채로 두지 않으면 빈 배열이 "0으로 고정된 상수"로 보여 하드코딩 키로 오탐한다(Apache DesStringToKey).
        앞의 값을 지우지는 않는다 — `validate(key)`처럼 읽기만 하는 호출 때문에 진짜 상수 키를 놓치지 않게.
        """
        method_node = node.child_by_field_name("name")
        if method_node is None:
            return None
        method = _text(method_node, self.source)
        if method in _PASSTHROUGH:
            return None   # `Arrays.copyOf(key, 16)`는 새 배열을 돌려줄 뿐 인자를 바꾸지 않는다
        if not (method in self._methods or method.startswith(_MUTATOR_PREFIXES)):
            return None
        if self._declared_type(name, node) in _IMMUTABLE:
            return None   # `map.put("password", password)`: 문자열은 넘겨도 바뀌지 않는다
        if any(a.type == "identifier" and _text(a, self.source) == name for a in _args(node)):
            return Origin(UNKNOWN, f"`{name}`을 `{method}`에 넘겨 바꿀 수 있다")
        return None

    def _constant_bool(self, condition) -> bool | None:
        """
        조건이 늘 같은 값인지. `false`, `!true`, `static final boolean X = false`의 X.

        조건 변수의 값을 따라가다 다시 분기 조건을 계산하게 된다. 같은 조건을 계산하는 중에 또 만나면 모른다고 답한다
        (무한 재귀 방지 — Apache Des3CbcSha1KdEncryption, DataX SecretUtil에서 실제로 났다).
        """
        if condition is None:
            return None
        key = (condition.start_byte, condition.end_byte)
        if key in self._evaluating or len(self._evaluating) >= _CONDITION_CHAIN:
            return None
        # 같은 조건을 같은 상황(계산 중인 조건들, 따라 들어온 호출의 인자)에서 다시 묻는 일이 지점마다 되풀이된다.
        # 큰 파일에서는 이 되풀이가 곱으로 불어나 몇 시간이 걸렸다(MASC qpid). 상황까지 같을 때만 답을 다시 쓴다
        memo_key = (key, frozenset(self._evaluating), self._binding_signature())
        if memo_key in self._bool_memo:
            return self._bool_memo[memo_key]
        self._evaluating.add(key)
        try:
            value = self._constant_bool_inner(condition)
        finally:
            self._evaluating.discard(key)
        self._bool_memo[memo_key] = value
        return value

    def _binding_signature(self) -> tuple:
        """지금 따라 들어와 있는 호출들(메서드 → 맨 위 호출 인자). 문맥에 따라 값이 다르므로 기억의 열쇠에 넣는다."""
        # 부른 쪽은 파일 경로로 가린다(객체 주소는 지워진 뒤 다른 판별기에 다시 쓰일 수 있다)
        return tuple(sorted((start, str(stack[-1][0].path) if stack[-1][0].path is not None else "<self>",
                             tuple(a.start_byte for a in stack[-1][1]))
                            for start, stack in self._bindings.items() if stack))

    def _unbound_parameter(self, node) -> bool:
        """
        조건에 쓰인 이름이 호출 문맥 없이 들어온 매개변수인지. 그렇다면 다른 호출자가 다른 값을 줄 수 있으니
        이 파일의 호출자들만 보고 분기를 지우지 않는다(`public void go(int choice)`).
        """
        if node is None:
            return False
        for child in _walk(node):
            if child.type != "identifier":
                continue
            method = _enclosing(child, ("method_declaration", "constructor_declaration"))
            if method is None or self._bindings.get(method.start_byte):
                continue
            name = _text(child, self.source)
            if name in [_param_name(p, self.source) for p in _params(method)]:
                return True
        return False

    def _constant_bool_inner(self, condition) -> bool | None:
        if self._unbound_parameter(condition):
            return None
        while condition is not None and condition.type == "parenthesized_expression":
            condition = condition.named_children[0] if condition.named_children else None
        if condition is None:
            return None
        text = _text(condition, self.source).strip()
        if text in ("true", "false"):
            return text == "true"
        if condition.type == "unary_expression" and text.startswith("!"):
            inner = self._constant_bool(condition.child_by_field_name("operand"))
            return None if inner is None else not inner
        if condition.type in ("identifier", "field_access"):
            origin = self.classify(condition, MAX_DEPTH - 2)
            if origin.kind == CONSTANT and origin.values and \
                    all(v in ("true", "false") for v in origin.values) and len(set(origin.values)) == 1:
                return origin.values[0] == "true"
        if condition.type == "binary_expression":
            operator = condition.child_by_field_name("operator")
            op = _text(operator, self.source) if operator is not None else ""
            left, right = condition.child_by_field_name("left"), condition.child_by_field_name("right")
            if op in ("&&", "||"):
                a, b = self._constant_bool(left), self._constant_bool(right)
                if op == "&&":
                    return False if False in (a, b) else (True if a and b else None)
                return True if True in (a, b) else (False if a is False and b is False else None)
            if op in ("<", "<=", ">", ">=", "==", "!=") and left is not None and right is not None:
                a, b = self._constant_number(left), self._constant_number(right)
                if a is not None and b is not None:
                    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b,
                            "==": a == b, "!=": a != b}[op]
        return None

    def _constant_number(self, node) -> float | None:
        """조건 비교에 쓰는 숫자 상수. 경로마다 값이 다르면 None."""
        if node.type == "decimal_floating_point_literal":
            return None
        # 깊이를 남은 만큼만 준다. 0부터 다시 세면 조건 → 값 → 조건으로 끝없이 돈다
        origin = self.classify(node, MAX_DEPTH - 2)
        if origin.kind != CONSTANT or len(set(origin.values)) != 1:
            return None
        cleaned = origin.values[0].replace("_", "").rstrip("lL")
        return float(cleaned) if cleaned.lstrip("-").isdigit() else None

    def _dead(self, node, scope) -> bool:
        """늘 거짓인 조건의 분기(또는 늘 참인 조건의 else) 안에 있는지."""
        child, current = node, node.parent
        while current is not None and not _same(current, scope):
            if current.type == "if_statement":
                value = self._constant_bool(current.child_by_field_name("condition"))
                consequence = current.child_by_field_name("consequence")
                alternative = current.child_by_field_name("alternative")
                if value is False and consequence is not None and _contains(consequence, child):
                    return True
                if value is True and alternative is not None and _contains(alternative, child):
                    return True
            child, current = current, current.parent
        return False

    def _unconditional(self, node, at, scope) -> bool:
        """
        `node`가 실행되면 `at`까지 반드시 실행되는 같은 갈래 위에 있는지. 둘을 함께 감싸지 않는 분기 아래면 조건부다.
        조건이 늘 같은 값이라 반드시 들어가는 갈래(`if (0 > 1) {...} else {여기}`)는 조건부가 아니다.
        """
        child, current = node, node.parent
        while current is not None and not _same(current, scope):
            if current.type in _BRANCHES and not _contains(current, at) and not self._always_taken(current, child):
                return False
            child, current = current, current.parent
        return True

    def _always_taken(self, branch, child) -> bool:
        if branch.type != "if_statement":
            return False
        value = self._constant_bool(branch.child_by_field_name("condition"))
        if value is None:
            return False
        arm = branch.child_by_field_name("consequence" if value else "alternative")
        return arm is not None and _contains(arm, child)

    @staticmethod
    def _shared_loop(node, at, scope) -> bool:
        current = at.parent
        while current is not None and not _same(current, scope):
            if current.type in ("for_statement", "enhanced_for_statement", "while_statement",
                                "do_statement") and _contains(current, node):
                return True
            current = current.parent
        return False

    def _reaching_events(self, name: str, method, at, need_declaration: bool = True) -> tuple[bool, list]:
        """(선언이 있나, `at`에 닿을 수 있는 쓰기 사건들). 흐름·경로 민감. 필드 경로(`h.a1`)는 선언 없이 대입만 본다."""
        events = [e for e in self._writes(name, method) if not self._dead(e[0], method)]
        declared = any(kind == "declare" for _, kind, _ in events) if need_declaration else \
            any(e[0].start_byte < at.start_byte for e in events)
        if not declared:
            return False, []
        before = [e for e in events if e[0].start_byte < at.start_byte and not _contains(e[0], at)]
        reaching = []
        for event in reversed(before):
            reaching.append(event)
            node, kind, _ = event
            # 늘 실행되고 전체를 덮어쓰는 쓰기는 그 앞의 쓰기를 가린다. 원소 하나만 바꾸는 쓰기는 가리지 않는다.
            if kind != "partial" and self._unconditional(node, at, method) and \
                    not (kind == "declare" and event[2] is None):
                break
        # 반복문 안에서는 뒤쪽 쓰기가 다음 회차에 닿는다
        reaching += [e for e in events if e[0].start_byte > at.start_byte
                     and self._shared_loop(e[0], at, method)]
        return True, reaching

    def _reaching(self, name: str, method, at, depth: int, need_declaration: bool = True) -> Origin | None:
        declared, reaching = self._reaching_events(name, method, at, need_declaration)
        if not declared:
            return None
        origins = []
        for node, kind, value in reaching:
            if isinstance(value, Origin):
                origins.append(value)
            elif value is not None:
                origins.append(self.classify(value, depth + 1))
        origins = [o for o in origins if o.kind != _SELF]
        if not origins:
            return Origin(UNKNOWN, f"`{name}`에 이 지점까지 값을 넣는 곳이 없다")
        return _with_constant_default(name, origins)

    def _class_node(self, name: str):
        for node in _walk(self.root):
            if node.type in _CLASS_KINDS:
                found = node.child_by_field_name("name")
                if found is not None and _text(found, self.source) == name:
                    return node
        return None

    def _object_field(self, variable: str, field: str, at, depth: int) -> Origin | None:
        """
        `obj.field`의 값. `obj`가 이 지점에서 하나의 `new T(args)`로만 만들어졌다면, `T`의 생성자 인자를 그 `args`로
        묶고 필드에 들어가는 값을 본다. 같은 클래스의 다른 객체(`new Cfg("DES")`)의 값은 섞이지 않는다.
        """
        if depth > MAX_DEPTH:
            return None
        values = self._value_nodes(variable, at)
        if len(values) == 1 and values[0].type == "method_invocation":
            return self._returned_object_field(values[0], field, depth)
        if len(values) != 1 or values[0].type != "object_creation_expression":
            return None
        return self._created_field(values[0], field, depth)

    def _created_field(self, creation, field: str, depth: int) -> Origin | None:
        """`new T(args)`로 만든 객체의 `field` 값. 생성자 인자를 `args`로 묶어 본다."""
        type_node = creation.child_by_field_name("type")
        if type_node is None:
            return None
        return self._constructed_field(_simple_type(_text(type_node, self.source)), _args(creation), field, depth)

    def _enum_field(self, owner: str, constant: str, field: str, depth: int) -> Origin | None:
        """`Alg.WEAK.jca`: enum 상수 `WEAK("MD5")`의 인자로 생성자를 묶어 필드 값을 본다."""
        candidates = [self] if self._class_node(owner) is not None else []
        if not candidates and self.project is not None:
            candidates = [r for r in (self.project.resolver(p) for p in self.project.files_declaring(owner))
                          if r is not None]
        for resolver in candidates:
            enum = resolver._class_node(owner)
            if enum is None or enum.type != "enum_declaration":
                continue
            for node in _walk(enum):
                name = node.child_by_field_name("name") if node.type == "enum_constant" else None
                if name is not None and _text(name, resolver.source) == constant:
                    return resolver._constructed_field(owner, _args(node), field, depth, caller=resolver)
        return None

    def _constructed_field(self, owner: str, args: list, field: str, depth: int,
                           caller: "Resolver | None" = None) -> Origin | None:
        """`owner` 클래스를 `args`로 만들었을 때 `field`에 들어가는 값. 인자는 `caller` 파일의 식이다."""
        caller = caller or self
        candidates = []
        local = self._class_node(owner)
        if local is not None:
            candidates.append((self, local))
        elif self.project is not None:
            for path in self.project.files_declaring(owner):
                resolver = self.project.resolver(path)
                node = resolver._class_node(owner) if resolver is not None else None
                if node is not None:
                    candidates.append((resolver, node))
        origins = []
        for resolver, class_node in candidates:
            constructors = [c for c in _walk(class_node) if c.type == "constructor_declaration"
                            and _same(_enclosing(c, _CLASS_KINDS), class_node) and len(_params(c)) == len(args)]
            for ctor in constructors:
                resolver._bindings.setdefault(ctor.start_byte, []).append((caller, list(args)))
            try:
                found = resolver._in_scope(field, class_node, ("field_declaration",), depth + 1)
            finally:
                for ctor in constructors:
                    resolver._bindings[ctor.start_byte].pop()
            if found is not None:
                origins.append(found)
        return combine(origins) if origins else None

    def _field_runtime_type(self, access, depth: int) -> str:
        """
        `obj.gen`의 실제 타입. `obj`를 만든 `new T(new SecureRandom())`의 생성자나 `make(new SecureRandom())`
        팩토리 안에서 `gen`에 넣는 값을 그 호출 인자로 묶어 본다.
        """
        target, field_node = access.child_by_field_name("object"), access.child_by_field_name("field")
        if target is None or field_node is None or target.type != "identifier":
            return ""
        field = _text(field_node, self.source)
        values = self._value_nodes(_text(target, self.source), access)
        if len(values) != 1:
            return ""
        return self._made_field_type(values[0], field, depth)

    def _made_field_type(self, value, field: str, depth: int) -> str:
        if depth > MAX_DEPTH:
            return ""
        if value.type == "object_creation_expression":
            type_node = value.child_by_field_name("type")
            class_node = self._class_node(_simple_type(_text(type_node, self.source))) if type_node else None
            if class_node is None:
                return ""
            args = _args(value)
            bodies = [c for c in _walk(class_node) if c.type == "constructor_declaration"
                      and _same(_enclosing(c, _CLASS_KINDS), class_node) and len(_params(c)) == len(args)]
            targets = (field, f"this.{field}")
        elif value.type == "method_invocation":
            owner = value.child_by_field_name("object")
            if owner is not None and _text(owner, self.source) != "this":
                return ""
            name_node = value.child_by_field_name("name")
            args = _args(value)
            bodies = [d for d in self._methods.get(_text(name_node, self.source) if name_node else "", [])
                      if d.type == "method_declaration" and len(_params(d)) == len(args)]
            targets = None
        else:
            return ""
        types = set()
        for body in bodies:
            self._bindings.setdefault(body.start_byte, []).append((self, list(args)))
            try:
                if targets is None:   # 팩토리: 돌려주는 지역 객체의 필드에 넣는 값, 또는 `return new T(...)`
                    returned = [r.named_children[0] for r in _walk(body)
                                if r.type == "return_statement" and r.named_children]
                    names = {f"{_text(r, self.source)}.{field}" for r in returned if r.type == "identifier"}
                    for r in returned:
                        if r.type == "object_creation_expression":
                            types.add(self._made_field_type(r, field, depth + 1))
                else:
                    names = set(targets)
                for node in _walk(body):
                    if node.type != "assignment_expression":
                        continue
                    left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                    if left is not None and right is not None and " ".join(_text(left, self.source).split()) in names:
                        types.add(self.runtime_type(right, depth + 1))
            finally:
                self._bindings[body.start_byte].pop()
        return types.pop() if len(types) == 1 else ""

    def _returned_object_field(self, call, field: str, depth: int) -> Origin | None:
        """
        `make("MD5").field` 꼴. 이 파일의 `make`가 돌려주는 지역 객체의 필드를 이 호출의 인자로 묶어 본다.
        `T o = new T(); o.field = arg; return o;`, `return new T(arg);` 둘 다.
        """
        target = call.child_by_field_name("object")
        if target is not None and _text(target, self.source) != "this":
            return None
        name_node = call.child_by_field_name("name")
        args = _args(call)
        origins = []
        for declaration in self._methods.get(_text(name_node, self.source) if name_node is not None else "", []):
            if declaration.type != "method_declaration" or len(_params(declaration)) != len(args):
                continue
            self._bindings.setdefault(declaration.start_byte, []).append((self, list(args)))
            try:
                for ret in _walk(declaration):
                    if ret.type != "return_statement" or not ret.named_children or self._dead(ret, declaration):
                        continue
                    value = ret.named_children[0]
                    if value.type == "object_creation_expression":
                        found = self._created_field(value, field, depth + 1)
                    elif value.type == "identifier":
                        local = _text(value, self.source)
                        found = self._reaching(f"{local}.{field}", declaration, ret, depth + 1,
                                               need_declaration=False)
                        if found is None:
                            found = self._object_field(local, field, ret, depth + 1)
                    else:
                        continue
                    if found is not None:
                        origins.append(found)
            finally:
                self._bindings[declaration.start_byte].pop()
        return combine(origins) if origins else None

    def _value_nodes(self, name: str, at, need_declaration: bool = True) -> list:
        """`at`에 닿는 지역 변수(또는 필드 경로)의 값 식(노드)들. 객체 민감도에서 어느 `new`로 만들었는지 볼 때 쓴다."""
        method = _enclosing(at, ("method_declaration", "constructor_declaration", "lambda_expression"))
        if method is None:
            return []
        declared, reaching = self._reaching_events(name, method, at, need_declaration)
        if not declared:
            return []
        return [value for _, _, value in reaching if value is not None and not isinstance(value, Origin)]

    def _variable_in(self, name: str, method, depth: int, at=None) -> Origin:
        if method is not None and at is not None and \
                name in [_param_name(p, self.source) for p in _params(method)]:
            # 매개변수에 메서드 안에서 다시 넣은 값(`salt = defSalt`). 늘 실행되는 대입이 가리면 그 값만,
            # 아니면 들어온 인자와 함께 본다
            _, reaching = self._reaching_events(name, method, at, need_declaration=False)
            if reaching:
                written = self._reaching(name, method, at, depth, need_declaration=False)
                covered = any(kind != "partial" and self._unconditional(node, at, method)
                              for node, kind, _ in reaching)
                if covered or written is None:
                    return written or Origin(UNKNOWN, f"`{name}`의 값을 모른다")
                incoming = self._parameter(name, method, depth)
                return combine([written] + ([incoming] if incoming is not None else []))
        if method is not None:
            local = (self._reaching(name, method, at, depth) if at is not None
                     else self._in_scope(name, method, ("local_variable_declaration",), depth))
            if local is not None:
                return local
            parameter = self._parameter(name, method, depth)
            if parameter is not None:
                return parameter
        return self._field(name, depth)

    def _field(self, name: str, depth: int) -> Origin:
        found = self._in_scope(name, self.root, ("field_declaration",), depth)
        if found is not None:
            return found
        # 정적 import한 상수, 상속·구현한 타입(상수 인터페이스)의 상수
        owners = ([self._static_imports[name]] if name in self._static_imports
                  else self._static_wildcards + sorted(self._supertypes))
        for owner in owners:
            found = self._foreign_field(owner, name, depth)
            if found is not None:
                return found
        return Origin(UNKNOWN, f"`{name}`의 선언을 이 파일에서 찾지 못했다")

    def _in_scope(self, name: str, scope, kinds, depth: int) -> Origin | None:
        """
        범위 안에서 변수에 들어가는 값을 모두 본다. 선언이 없으면 None.

        배열을 채우는 호출이 있으면 그것이 출처다. 난수로 채웠는데 선언 값이 0 배열이면
        난수가 이긴다. 같은 배열을 상수로도 난수로도 채웠다면 모른다.
        """
        declared = False
        declarations: list = []
        definitions: list[Origin] = []
        for node in self._scope_nodes(scope):
            if node.type in kinds:
                for declarator in node.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    found = declarator.child_by_field_name("name")
                    if found is None or _text(found, self.source) != name:
                        continue
                    declared = True
                    declarations.append(declarator)
                    value = declarator.child_by_field_name("value")
                    if value is not None:
                        definitions.append(self.classify(value, depth + 1))
                    elif node.type == "field_declaration":
                        spring = self._spring_value(node)   # @Value("${key}") 주입 필드
                        if spring is not None:
                            definitions.append(spring)
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                left_name = _assigned_name(left, self.source)
                if left_name == name:
                    definitions.append(self.classify(right, depth + 1))
                elif left.type == "array_access" and _assigned_name(
                        left.child_by_field_name("array"), self.source) == name:
                    definitions.append(Origin(UNKNOWN, f"`{name}`의 원소를 따로 채운다"))
        if not declared:
            return None
        definitions = [d for d in definitions if d.kind != _SELF]

        fills = self._fills(name, scope, declarations)
        if fills:
            # 선언 때 넣은 상수(대개 0 배열)는 늘 실행되는 채우기 호출이 덮어쓴다. 조건문
            # 안에서만 채우면 상수가 그대로 쓰이는 경로가 남으므로 덮어쓰지 않는다.
            always = [origin for origin, conditional in fills if not conditional]
            fill = combine([origin for origin, _ in fills])
            if (always and len(always) == len(fills) and fill.kind != UNKNOWN
                    and all(d.kind in (CONSTANT, fill.kind) for d in definitions)):
                return fill
            return combine([origin for origin, _ in fills] + definitions)
        if not definitions:
            return Origin(UNKNOWN, f"`{name}`에 값을 넣는 곳이 없다")
        return _with_constant_default(name, definitions)

    def _fills(self, name: str, scope, declarations) -> list[tuple[Origin, bool]]:
        """`sr.nextBytes(name)`처럼 배열을 채우는 호출과 그 호출이 조건부인지."""
        fills: list[tuple[Origin, bool]] = []
        for node in self._scope_nodes(scope):
            if node.type != "method_invocation":
                continue
            method_node = node.child_by_field_name("name")
            if method_node is None:
                continue
            method = _text(method_node, self.source)
            args = _args(node)
            for position, arg in enumerate(args):
                if arg.type != "identifier" or _text(arg, self.source) != name:
                    continue
                conditional = self._conditional(node, scope, declarations)
                if (method, position) == _FILL_RANDOM:
                    owner = self.receiver_type(node)
                    if owner in _SECURE_TYPES:
                        origin = Origin(SECURE_RANDOM,
                                        f"`{name}`을 SecureRandom.nextBytes로 채운다")
                    elif owner in _WEAK_TYPES:
                        origin = Origin(WEAK_RANDOM, f"`{name}`을 {owner}.nextBytes로 채운다")
                    else:
                        origin = Origin(UNKNOWN, f"`{name}`을 채우는 난수 생성기 종류를 모른다")
                elif (method, position) in _FILL_EXTERNAL:
                    origin = Origin(EXTERNAL_INPUT, f"`{name}`을 입력 스트림에서 읽어 채운다")
                elif (method, position) in _FILL_UNKNOWN:
                    origin = Origin(UNKNOWN, f"`{name}`에 다른 배열을 복사해 넣는다")
                else:
                    continue
                fills.append((origin, conditional))
        return fills

    @staticmethod
    def _conditional(node, scope, declarations) -> bool:
        """
        이 호출이 변수가 살아 있는 동안 늘 실행되는지.

        분기 아래에 있어도 그 분기가 변수 선언까지 감싸면 변수 입장에서는 늘 실행된다.
        """
        current = node.parent
        while current is not None and not _same(current, scope):
            if current.type in _BRANCHES and not any(
                    current.start_byte <= d.start_byte and d.end_byte <= current.end_byte
                    for d in declarations):
                return True
            current = current.parent
        return False

    def _parameter(self, name: str, method, depth: int) -> Origin | None:
        parameters = method.child_by_field_name("parameters")
        if parameters is None:
            return None
        params = [p for p in parameters.named_children
                  if p.type in ("formal_parameter", "spread_parameter")]
        for position, parameter in enumerate(params):
            found = parameter.child_by_field_name("name")
            if found is None:
                found = next((c for c in parameter.named_children
                              if c.type == "variable_declarator"), None)
                found = found.child_by_field_name("name") if found is not None else None
            if found is None or _text(found, self.source) != name:
                continue

            method_name = method.child_by_field_name("name")
            label = _text(method_name, self.source) if method_name is not None else ""
            if label == "main" and "String" in _text(parameter, self.source):
                return Origin(EXTERNAL_INPUT, f"프로그램 인자 `{name}`")

            spring = self._spring_value(parameter)   # 생성자 주입 `@Value("${key}") String key`
            if spring is not None:
                return spring

            # 문맥 민감도: 지금 이 메서드를 특정 호출을 따라 들어왔으면 그 호출의 인자만 본다
            stack = self._bindings.get(method.start_byte)
            if stack:
                caller, call_args = stack[-1]
                if position < len(call_args):
                    return caller.classify(call_args[position], depth + 1)

            callers = self._callers(method, label, len(params))
            if not callers:
                elsewhere = self._parameter_from_other_files(method, label, len(params),
                                                             position, depth)
                if elsewhere is not None:
                    return elsewhere
                return Origin(UNKNOWN, f"`{label}`의 인자 `{name}`이고 이 파일에 부르는 곳이 없다")
            return combine([self.classify(_args(call)[position], depth + 1)
                            for call in callers])
        return None

    def _callers(self, method, label: str, arity: int) -> list:
        if method.type == "constructor_declaration":
            candidates = self._creations.get(label, [])
        else:
            candidates = self._invocations.get(label, [])
        # 늘 거짓인 조건 안의 호출은 실행되지 않으니 인자 후보에서 뺀다(경로 민감도)
        return [c for c in candidates if len(_args(c)) == arity and
                not self._dead(c, _enclosing(c, ("method_declaration", "constructor_declaration")))]


def _is_placeholder(origin: Origin) -> bool:
    """빈 문자열, 빈 배열, 0으로 채운 배열은 기본 키가 아니라 나중에 채울 자리다."""
    if "0으로 고정" in origin.note or "빈 " in origin.note:
        return True
    if not origin.values:
        return True
    return all(v.strip() in ("", '""', "{}", "null") for v in origin.values)


def _product(parts: list) -> tuple[str, ...] | None:
    """조각마다 가능한 값들을 이어 붙인 모든 경우. 모르는 조각이 있거나 16가지를 넘으면 None."""
    out: tuple[str, ...] = ("",)
    for part in parts:
        if part is None:
            return None
        out = tuple(dict.fromkeys(a + b for a in out for b in part))
        if len(out) > 16:
            return None
    return out


def _with_constant_default(name: str, definitions: list[Origin]) -> Origin:
    """
    상수 하나와 밖에서 오는 값이 섞였으면 그 상수는 기본값이다. 설정으로 바꾸지 않으면 그 값이
    쓰인다(실제 코드: Artemis의 기본 키 "clusterpassword"). 안전한 난수와 섞이면 기본값이라고
    볼 수 없으므로 그대로 둔다.
    """
    merged = combine(definitions)
    if merged.kind != UNKNOWN:
        return merged
    constants = [d for d in definitions if d.kind == CONSTANT and not _is_placeholder(d)]
    others = [d for d in definitions if d.kind != CONSTANT]
    if constants and others and all(d.kind in (EXTERNAL_INPUT, UNKNOWN) for d in others):
        values = tuple(dict.fromkeys(v for d in constants for v in d.values))
        return Origin(CONSTANT, f"`{name}`의 기본값이 코드에 박혀 있다({constants[0].note}). "
                                f"설정으로 바꾸지 않으면 이 값이 쓰인다", values)
    return merged


def _args(node) -> list:
    args = node.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _assigned_name(node, source: bytes) -> str:
    if node is None:
        return ""
    if node.type == "identifier":
        return _text(node, source)
    if node.type == "field_access":
        target = node.child_by_field_name("object")
        field = node.child_by_field_name("field")
        if target is not None and field is not None and _text(target, source) == "this":
            return _text(field, source)
    return ""


def _same(a, b) -> bool:
    """tree-sitter 노드는 꺼낼 때마다 새 파이썬 객체라 `is`로 비교하면 늘 다르다. 위치와 종류로 같은 노드인지 본다."""
    if a is None or b is None:
        return a is None and b is None
    return a.start_byte == b.start_byte and a.end_byte == b.end_byte and a.type == b.type


def _param_name(parameter, source: bytes) -> str:
    found = parameter.child_by_field_name("name")
    if found is None:
        found = next((c for c in parameter.named_children if c.type == "variable_declarator"), None)
        found = found.child_by_field_name("name") if found is not None else None
    return _text(found, source) if found is not None else ""


def _params(method) -> list:
    parameters = method.child_by_field_name("parameters")
    if parameters is None:
        return []
    return [p for p in parameters.named_children if p.type in ("formal_parameter", "spread_parameter")]


def _contains(outer, inner) -> bool:
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


def _enclosing(node, kinds):
    current = node.parent if node is not None else None
    while current is not None:
        if current.type in kinds:
            return current
        current = current.parent
    return None


def _looks_like_class(name: str) -> bool:
    return name[:1].isupper() and not (len(name) > 1 and name.replace("_", "").isupper())


def _simple_type(text: str) -> str:
    """`java.security.SecureRandom` → `SecureRandom`, `List<String>` → `List`."""
    return text.split("<")[0].strip().split(".")[-1].rstrip("[]").strip()
