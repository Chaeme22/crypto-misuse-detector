"""
데이터셋 스키마와 교차 검증 규칙을 고정한다.

스키마는 한 행의 모양을 본다. 행과 행, 파일과 파일 사이의 규칙(CWE는 분류에서, 근거
ID는 레지스트리에 있어야 함, 문맥이 모자라면 undetermined)은 tools/validate_dataset.py가
본다. 둘 다 통과해야 학습셋에 들어간다.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

sys.path.insert(0, str(Path("tools").resolve()))
import validate_dataset  # noqa: E402

SCHEMAS = Path("dataset/schemas")


def _example() -> dict:
    """규칙을 모두 지키는 최소 샘플."""
    return {
        "example_id": "EX-JAVA-KEY-HARDCODED-000001",
        "source_type": "synthetic",
        "source_uri": None,
        "source_revision": None,
        "license": "project-generated",
        "language": "java",
        "file_path": "Sample.java",
        "code_sha256": "sha256:" + "0" * 64,
        "context_depth_available": 1,
        "context_depth_required": 1,
        "ast_format": "tree-sitter",
        "ir_version": "crypto-ir-v1",
        "ir": {
            "ir_version": "crypto-ir-v1", "language": "java", "api": "new SecretKeySpec",
            "library": "JCA", "operation": "cipher_initialization", "algorithm": "AES",
            "mode": None, "key_source": "literal_constant", "iv_source": "not_applicable",
            "salt_source": "not_applicable", "password_source": "not_applicable",
            "seed_source": "not_applicable", "random_source": "not_applicable",
            "iteration_count": None, "sink": "key_spec", "file_path": "Sample.java",
            "code_sha256": "sha256:" + "0" * 64, "line": 5,
        },
        "provenance": ["literal_constant", "local_value"],
        "role": "crypto_operation",
        "decision": "violation",
        "rule_id": "CRYPTO-KEY-HARDCODED",
        "misuse_id": "MISUSE-KEY-HARDCODED",
        "cwe_ids": ["CWE-321"],
        "standard_evidence_ids": ["EVID-KISA-KEYMGMT-2014-PROT-001"],
        "cve_refs": [],
        "generator": {"kind": "manual", "model": None, "prompt_hash": None, "seed": None,
                      "parent_example_id": None},
        "lineage_group": "LG-KEY-HARDCODED-0001",
        "validation": {"parse": "pass", "compile_or_lint": "not_run", "rule_engine": "pass",
                       "semgrep": "not_run", "codeql": "not_run", "secrets_scan": "pass",
                       "human_reviewers": 0, "status": "needs_review"},
        "split": "unassigned",
    }


@pytest.fixture(scope="module")
def context():
    return validate_dataset.load_context()


def test_schemas_are_valid_draft_2020_12():
    for path in SCHEMAS.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_taxonomy_and_registry_follow_their_schemas(context):
    assert validate_dataset.check_taxonomy(context) == []
    assert validate_dataset.check_registry(context) == []


def test_valid_example_passes(context):
    assert validate_dataset.check_example(_example(), context) == []


def test_cwe_must_come_from_the_taxonomy(context):
    example = _example()
    example["cwe_ids"] = ["CWE-798"]
    assert any("CWE" in e for e in validate_dataset.check_example(example, context))


def test_rule_and_misuse_must_match(context):
    example = _example()
    example["misuse_id"] = "MISUSE-IV-STATIC"
    assert validate_dataset.check_example(example, context)


def test_unknown_evidence_is_rejected(context):
    example = _example()
    example["standard_evidence_ids"] = ["EVID-DOES-NOT-EXIST"]
    assert any("EVID-DOES-NOT-EXIST" in e for e in validate_dataset.check_example(example, context))


def test_missing_context_must_be_undetermined(context):
    """필요한 문맥보다 적게 줬는데 위반·정상으로 라벨링하면 모델이 추측을 배운다."""
    example = _example()
    example["context_depth_available"] = 0
    example["context_depth_required"] = 2
    assert any("undetermined" in e for e in validate_dataset.check_example(example, context))
    example["decision"] = "undetermined"
    assert validate_dataset.check_example(example, context) == []


def test_approved_needs_verified_evidence_and_a_reviewer(context):
    """승인 데이터의 근거는 검수된 것만 쓴다. 자동 추출 후보로는 승인할 수 없다."""
    example = _example()
    example["validation"]["status"] = "approved"
    example["validation"]["human_reviewers"] = 1
    errors = validate_dataset.check_example(example, context)
    assert any("검수" in e for e in errors)

    verified = copy.deepcopy(_example())
    verified.update(rule_id="CRYPTO-HASH-WEAK", misuse_id="MISUSE-HASH-WEAK",
                    cwe_ids=["CWE-328"], standard_evidence_ids=["EVID-KISA-2018-T4"],
                    example_id="EX-JAVA-HASH-WEAK-000001")
    verified["validation"].update(status="approved", human_reviewers=1)
    assert validate_dataset.check_example(verified, context) == []


def test_non_executing_role_cannot_be_a_violation(context):
    example = _example()
    example["role"] = "test_fixture"
    assert validate_dataset.check_example(example, context)


def test_sft_assistant_output_matches_the_parser_contract(context):
    row = {
        "example_id": "EX-JAVA-KEY-HARDCODED-000001",
        "messages": [
            {"role": "user", "content": "u"},
            {"role": "assistant", "content": "role: crypto_operation\ndecision: violation\n"
                                             "reasoning: 키가 상수다.\nfix: 난수로 만든다."},
        ],
    }
    assert validate_dataset.check_sft(row, context) == []
    row["messages"][1]["content"] = "decision: violation"
    assert validate_dataset.check_sft(row, context)
