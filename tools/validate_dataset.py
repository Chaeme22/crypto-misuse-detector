"""
파인튜닝 데이터셋을 검증한다.

스키마(dataset/schemas)는 한 행의 모양만 본다. 여기서는 파일과 파일 사이의 규칙을 함께 본다.

  - CWE는 분류(misuse_taxonomy.json)에서 온다. 샘플이 따로 적은 CWE가 다르면 거부한다
  - 규칙 ID와 오용 ID는 분류에서 짝지어진 그대로여야 한다
  - 근거 ID는 레지스트리에 있어야 하고, 승인 샘플의 근거는 검수(verified)된 것이어야 한다
  - 필요한 문맥보다 적게 줬으면 정답은 undetermined다
  - 학습 행의 assistant 출력은 판정 parser가 읽는 네 줄 형식이다

사용법:
    python tools/validate_dataset.py                       # 분류·레지스트리만
    python tools/validate_dataset.py manifest.jsonl sft.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
SCHEMAS = DATASET / "schemas"


@dataclass
class Context:
    taxonomy: dict
    registry: dict[str, dict]
    registry_rows: list[dict]
    validators: dict


def load_context() -> Context:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    schemas = {path.name: json.loads(path.read_text(encoding="utf-8"))
               for path in sorted(SCHEMAS.glob("*.schema.json"))}
    refs = Registry().with_resources(
        (name, Resource.from_contents(schema)) for name, schema in schemas.items())
    validators = {name.removesuffix(".schema.json"): Draft202012Validator(schema, registry=refs)
                  for name, schema in schemas.items()}

    taxonomy = json.loads((DATASET / "misuse_taxonomy.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in
            (DATASET / "evidence_registry.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]
    return Context(taxonomy, {r["evidence_id"]: r for r in rows}, rows, validators)


def _schema_errors(validator, data, label: str) -> list[str]:
    return [f"{label}: {'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))]


def check_taxonomy(context: Context) -> list[str]:
    return _schema_errors(context.validators["misuse_taxonomy"], context.taxonomy, "taxonomy")


def check_registry(context: Context) -> list[str]:
    errors = []
    for row in context.registry_rows:
        errors += _schema_errors(context.validators["evidence_registry"], row,
                                 row.get("evidence_id", "?"))
    return errors


def check_example(example: dict, context: Context) -> list[str]:
    label = example.get("example_id", "?")
    errors = _schema_errors(context.validators["example_manifest"], example, label)
    if errors:
        return errors

    misuses = {m["misuse_id"]: m for m in context.taxonomy["misuses"]}
    misuse = misuses.get(example["misuse_id"])
    if misuse is None:
        return [f"{label}: 분류에 없는 오용 ID {example['misuse_id']}"]
    if misuse["rule_id"] != example["rule_id"]:
        errors.append(f"{label}: 규칙 {example['rule_id']}와 오용 {example['misuse_id']}가 짝이 아니다")
    if example["cwe_ids"] != [misuse["cwe"]]:
        errors.append(f"{label}: CWE는 분류의 {misuse['cwe']}여야 한다 (적힌 값 {example['cwe_ids']})")

    for evidence_id in example["standard_evidence_ids"]:
        evidence = context.registry.get(evidence_id)
        if evidence is None:
            errors.append(f"{label}: 레지스트리에 없는 근거 {evidence_id}")
            continue
        if example["misuse_id"] not in evidence["misuse_ids"]:
            errors.append(f"{label}: 근거 {evidence_id}는 {example['misuse_id']}를 뒷받침하지 않는다")
        if example["validation"]["status"] == "approved" and not evidence["verified"]:
            errors.append(f"{label}: 승인 샘플은 검수된 근거만 쓴다 ({evidence_id}는 미검수)")

    if (example["context_depth_available"] < example["context_depth_required"]
            and example["decision"] != "undetermined"):
        errors.append(f"{label}: 필요한 문맥(depth {example['context_depth_required']})보다 적게 "
                      f"줬으므로 정답은 undetermined여야 한다")

    if "ir" in example and example["ir"]["code_sha256"] != example["code_sha256"]:
        errors.append(f"{label}: IR과 샘플의 코드 해시가 다르다")
    return errors


def check_sft(row: dict, context: Context) -> list[str]:
    return _schema_errors(context.validators["sft_messages"], row, row.get("example_id", "?"))


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="파인튜닝 데이터셋을 검증한다")
    ap.add_argument("files", nargs="*", type=Path,
                    help="example_manifest 또는 SFT messages JSONL. 행 모양으로 구분한다")
    args = ap.parse_args()

    context = load_context()
    errors = check_taxonomy(context) + check_registry(context)
    counted = 0
    for path in args.files:
        for row in _read_jsonl(path):
            counted += 1
            errors += check_sft(row, context) if "messages" in row else check_example(row, context)

    verified = sum(1 for r in context.registry_rows if r["verified"])
    print(f"분류 {len(context.taxonomy['misuses'])}종 · 근거 {len(context.registry_rows)}건 "
          f"(검수 {verified}건) · 샘플 {counted}건")
    for error in errors:
        print(f"  ✗ {error}")
    print("통과" if not errors else f"오류 {len(errors)}건")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
