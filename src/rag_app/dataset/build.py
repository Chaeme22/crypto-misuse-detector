"""
합성 샘플을 학습 데이터(example_manifest + SFT messages)로 만든다.

세 가지를 지킨다.

1. 운영에서 모델이 받는 지점만 담는다. 기준표나 출처 판별이 정상으로 닫은 지점은 운영에서
   모델에게 묻지 않으므로 학습에 넣으면 분포가 어긋난다. 실제 파이프라인을 돌려 판정기가
   불린 지점만 고른다.
2. 프롬프트는 운영과 같은 함수(verdict.build_prompt)로 만든다.
3. 문맥 깊이를 줄인 샘플은 줄인 코드에 탐지기를 다시 돌려 [사실]까지 다시 계산한다. 코드가
   모자라 값을 못 보면 탐지기가 "못 찾았다"고 적고, 그때 정답은 undetermined다. 운영에서
   값이 다른 파일에 있을 때와 같은 상황이다.

깊이: 0 대상 문장 하나, 1 대상 메서드, 2 파일 전체. 3(다른 파일·설정)은 합성 샘플이 한
파일이라 만들지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..analysis import pipeline
from ..analysis import provenance as prov
from ..analysis.findings import Decision, Rule, Verdict
from ..analysis.thresholds import ThresholdTable
from ..analysis.verdict import StaticVerdict, build_prompt, format_answer
from .templates import Sample

PROMPT_VERSION = "verdict-prompt-2026-10-07b"  # non_security 역할 추가
NON_EXECUTING = ("name_list", "test_fixture", "documentation", "non_security")


@dataclass
class Snippet:
    depth: int
    code: str
    line: int


class _Recorder:
    """판정기 대신 끼워 넣어 모델이 받을 입력을 기록한다."""
    name = "recorder"

    def __init__(self):
        self.calls: list[tuple] = []

    def judge(self, site, rule, citations, measurement=None) -> Verdict:
        self.calls.append((site, rule, citations, measurement))
        return Verdict(decision=Decision.UNDETERMINED, reasoning="recorded", role="unknown")


# --- 문맥 깊이 ----------------------------------------------------------------

def _parser():
    from tree_sitter import Language, Parser
    import tree_sitter_java
    return Parser(Language(tree_sitter_java.language()))


def snippets(sample: Sample) -> list[Snippet]:
    """깊이 0·1·2의 코드. 줄인 코드도 구문이 맞도록 클래스로 감싼다."""
    code = sample.code
    lines = code.splitlines()
    tree = _parser().parse(code.encode("utf-8"))
    header = [l for l in lines if l.startswith(("package ", "import "))]
    cls = Path(sample.path).stem

    method = None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if (node.type in ("method_declaration", "constructor_declaration")
                and node.start_point[0] + 1 <= sample.target_line <= node.end_point[0] + 1):
            method = node
        stack.extend(node.children)

    out = [Snippet(2, code, sample.target_line)]
    if method is not None:
        start = method.start_point[0]
        body = lines[start:method.end_point[0] + 1]
        prefix = header + ["", f"public class {cls} {{"]
        out.append(Snippet(1, "\n".join(prefix + body + ["}"]) + "\n",
                           len(prefix) + sample.target_line - start))
    statement = lines[sample.target_line - 1].strip()
    prefix = header + ["", f"public class {cls} {{",
                       "    public void target() throws Exception {"]
    out.append(Snippet(0, "\n".join(prefix + [f"        {statement}", "    }", "}"]) + "\n",
                       len(prefix) + 1))
    return out


# --- 실행 ---------------------------------------------------------------------

def _run(code: str, path: str, rules: list[Rule], table: ThresholdTable):
    """코드 한 파일에 파이프라인을 돌린다. (모델이 받을 입력, 정적 판정 결과)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")

        recorder = _Recorder()
        state = pipeline.AnalysisState(target=str(root), root=root, rules=rules,
                                       thresholds=table)
        state = pipeline.extract_sites(state)
        pipeline.judge_sites(state, recorder, None)

        static = pipeline.AnalysisState(target=str(root), root=root, rules=rules,
                                        thresholds=table)
        static = pipeline.extract_sites(static)
        static = pipeline.judge_sites(static, StaticVerdict(), None)
    return recorder.calls, static.findings


def _label(sample: Sample, site, depth: int = 2) -> tuple[str, str]:
    """
    이 문맥에서의 정답. 비실행 역할은 정상, 값을 못 보면 판정 보류.

    대조 쌍(context)은 결과가 어디에 쓰이는지가 판정을 가른다. 대상 문장 하나(깊이 0)로는 쓰임새가
    보이지 않으므로 정답은 판정 보류다. 메서드(깊이 1)부터 보인다.
    """
    if sample.placement == "context" and depth == 0:
        return "undetermined", "crypto_operation"
    if sample.role in NON_EXECUTING:
        return "clean", sample.role
    if site.unresolved_args:
        return "undetermined", sample.role
    return sample.decision, sample.role


def _reasoning(sample: Sample, site, decision: str, role: str) -> str:
    if role == "name_list":
        return "알고리즘 이름을 목록에서 찾거나 비교할 뿐 그 이름으로 암호 연산을 하지 않는다."
    if role == "non_security":
        return (f"화살표 줄의 결과는 {sample.value.note} 쓰인다. 비밀이나 인증을 지키는 값이 아니라 "
                f"보안과 무관한 용도다.")
    if role == "test_fixture":
        return "테스트 소스에 둔 고정값이다. 운영 코드에서 쓰이는 값이 아니다."
    if decision == "undetermined":
        names = ", ".join(f"`{n}`" for n in site.unresolved_args) or "인자"
        return (f"{names}의 값이 이 코드에서 보이지 않는다. 값이 정해지는 곳을 볼 수 없어 "
                f"위반인지 확인할 수 없다.")
    if sample.placement == "context" and decision == "undetermined":
        return "화살표 줄만으로는 결과가 어디에 쓰이는지 보이지 않는다. 쓰임새를 봐야 위반인지 정할 수 있다."
    if sample.placement == "context":
        return f"화살표 줄의 결과를 보면 {sample.value.note}. 보안 용도에 약한 알고리즘을 썼다."
    if site.provenance_note:
        return (f"화살표 줄은 실제로 호출되는 암호 API이고, {sample.value.note}"
                f"({site.provenance_note}).")
    values = ", ".join(site.traced_values) or site.algorithm_spec or site.api
    return f"화살표 줄은 실제로 호출되는 암호 API이고 값은 `{values}`다. {sample.value.note}."


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- IR -----------------------------------------------------------------------

_SOURCE = {prov.CONSTANT: "literal_constant", prov.PREDICTABLE: "predictable",
           prov.SECURE_RANDOM: "secure_random", prov.WEAK_RANDOM: "weak_random",
           prov.EXTERNAL_INPUT: "external_input", prov.UNKNOWN: "unknown"}
_MATERIAL_FIELD = {"key": "key_source", "iv": "iv_source", "salt": "salt_source",
                   "password": "password_source", "seed": "seed_source"}
_OPERATION = {"CRYPTO-HASH-WEAK": ("hash", "digest"),
              "CRYPTO-MODE-ECB": ("cipher_initialization", "cipher_initialization"),
              "CRYPTO-CIPHER-OBSOLETE": ("cipher_initialization", "cipher_initialization"),
              "CRYPTO-KEYSIZE-SHORT": ("key_generation", "key_spec"),
              "CRYPTO-RNG-INSECURE": ("random_generation", "random_output"),
              "CRYPTO-SEED-PREDICTABLE": ("random_generation", "random_seed"),
              "CRYPTO-KEY-HARDCODED": ("cipher_initialization", "key_spec"),
              "CRYPTO-IV-STATIC": ("cipher_initialization", "key_spec"),
              "CRYPTO-PASSWORD-HARDCODED": ("key_derivation", "key_derivation"),
              "CRYPTO-SALT-STATIC": ("key_derivation", "key_derivation"),
              "CRYPTO-KDF-WEAK": ("key_derivation", "key_derivation")}


def to_ir(site, rule: Rule, material: str | None, code_sha: str) -> dict:
    """사용 지점을 crypto-ir-v1로. 값을 모르는 칸은 unknown, 해당 없는 칸은 not_applicable."""
    spec = site.algorithm_spec or ""
    parts = spec.split("/")
    sources = {f: "not_applicable" for f in ("key_source", "iv_source", "salt_source",
                                             "password_source", "seed_source", "random_source")}
    if material in _MATERIAL_FIELD and site.provenance:
        sources[_MATERIAL_FIELD[material]] = _SOURCE.get(site.provenance, "unknown")
    iterations = None
    if material == "iteration_count" and site.traced_values:
        try:
            iterations = int(site.traced_values[0])
        except ValueError:
            iterations = None
    operation, sink = _OPERATION.get(rule.rule_id, ("unknown", "cipher_initialization"))
    return {"ir_version": "crypto-ir-v1", "language": "java",
            "api": site.call or site.api or "unknown", "library": "JCA",
            "operation": operation, "algorithm": parts[0] or None,
            "mode": parts[1] if len(parts) > 1 else None, "key_bits": site.key_bits,
            **sources, "iteration_count": iterations, "sink": sink,
            "file_path": site.file_path.replace("\\", "/"), "code_sha256": code_sha,
            "line": site.line, "column": site.column}


# --- 조립 ---------------------------------------------------------------------

def build(samples: list[Sample], rules: list[Rule], taxonomy: dict,
          registry: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """(manifest 행, SFT 행, 빠진 샘플과 이유)."""
    table = ThresholdTable.load()
    misuses = {m["misuse_id"]: m for m in taxonomy["misuses"]}
    evidence = {m: sorted(r["evidence_id"] for r in registry if m in r["misuse_ids"])
                for m in misuses}
    counters: dict[str, int] = {}
    manifest, sft, skipped = [], [], []

    for sample in samples:
        rule_id = sample.family.rule_id
        misuse = misuses[sample.family.misuse_id]
        per_depth = []
        for snippet in snippets(sample):
            calls, static = _run(snippet.code, sample.path, rules, table)
            asked = [c for c in calls if c[0].line == snippet.line and c[1].rule_id == rule_id]
            if not asked:
                skipped.append({"template_id": sample.template_id, "depth": snippet.depth,
                                "reason": "운영에서 모델에게 묻지 않는 지점(구조로 닫힘 또는 지점 없음)"})
                continue
            site, rule, citations, measurement = asked[0]
            decision, role = _label(sample, site, snippet.depth)
            static_decision = next((f.verdict.decision.value for f in static
                                    if f.site.line == snippet.line
                                    and f.rule.rule_id == rule_id), None)
            per_depth.append((snippet, site, rule, citations, measurement, decision, role,
                              static_decision))

        if not per_depth:
            continue
        full = next((p for p in per_depth if p[0].depth == 2), per_depth[0])
        required = min((p[0].depth for p in per_depth if p[5] == full[5]), default=2)

        for snippet, site, rule, citations, measurement, decision, role, static_decision in per_depth:
            short = rule_id.removeprefix("CRYPTO-")
            counters[short] = counters.get(short, 0) + 1
            example_id = f"EX-JAVA-{short}-{counters[short]:06d}"
            code_sha = _sha(snippet.code)
            verdict = Verdict(decision=Decision(decision), role=role,
                              reasoning=_reasoning(sample, site, decision, role),
                              suggested_fix=rule.remediation)
            rule_engine = ("not_applicable" if static_decision is None
                           else "pass" if static_decision == decision else "disagree")
            manifest.append({
                "example_id": example_id, "source_type": "synthetic", "source_uri": None,
                "source_revision": None, "license": "project-generated", "language": "java",
                "file_path": sample.path, "code_sha256": code_sha,
                "context_depth_available": snippet.depth,
                "context_depth_required": required if decision != "undetermined"
                else max(required, snippet.depth),
                "ast_format": "tree-sitter", "ir_version": "crypto-ir-v1",
                "ir": to_ir(site, rule, misuse["material"], code_sha),
                "provenance": [_SOURCE.get(site.provenance, "unknown")] if site.provenance
                else (["literal_constant"] if site.traced_values else ["unknown"]),
                "role": role, "decision": decision, "rule_id": rule_id,
                "misuse_id": misuse["misuse_id"], "cwe_ids": [misuse["cwe"]],
                "standard_evidence_ids": evidence[misuse["misuse_id"]], "cve_refs": [],
                "generator": {"kind": "template", "model": None, "prompt_hash": None,
                              "seed": None, "parent_example_id": None},
                "lineage_group": sample.lineage_group,
                "validation": {"parse": "pass", "compile_or_lint": "not_run",
                               "rule_engine": rule_engine, "semgrep": "not_run",
                               "codeql": "not_run", "secrets_scan": "pass",
                               "human_reviewers": 0, "status": "needs_review",
                               "notes": f"template {sample.template_id}"},
                "split": "unassigned",
            })
            sft.append({"example_id": example_id, "prompt_version": PROMPT_VERSION,
                        "messages": [
                            {"role": "user",
                             "content": build_prompt(site, rule, citations, measurement)},
                            {"role": "assistant", "content": format_answer(verdict)}]})
    return manifest, sft, skipped


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                    encoding="utf-8")
