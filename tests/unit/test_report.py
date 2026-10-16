"""사람이 읽는 보고서(Markdown, PDF)는 SARIF를 그대로 옮긴다."""

import pytest

from rag_app.analysis import report


def _result(rule_id, kind="fail", level="error", line=10, message="판정 근거"):
    return {
        "ruleId": rule_id, "kind": kind, "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/A.java"},
            "region": {"startLine": line, "startColumn": 1,
                       "snippet": {"text": 'MessageDigest.getInstance("MD5")'}}}}],
        "properties": {"tableCheck": {"outcome": "absent", "purpose": "hash_signature",
                                      "found": "MD5", "requirement": "112비트 이상"},
                       "citations": [{"document": "암호 알고리즘 및 키 길이 이용 안내서", "page": 8,
                                      "quote": "표 4"}]},
    }


def _document(results):
    rules = [{"id": "CRYPTO-HASH-WEAK", "shortDescription": {"text": "약한 해시 사용"},
              "help": {"text": "SHA-256 이상으로 교체한다."}, "properties": {"cwe": "CWE-328"}},
             {"id": "CRYPTO-IV-STATIC", "shortDescription": {"text": "고정 IV"},
              "help": {"text": "SecureRandom으로 만든다."}, "properties": {"cwe": "CWE-329"}}]
    return {"runs": [{
        "tool": {"driver": {"name": "CryptoMisuse-OSS", "version": "0.1.0", "rules": rules}},
        "originalUriBaseIds": {"SRCROOT": {"uri": "file:///repo/"}},
        "versionControlProvenance": [{"revisionId": "e5fa3dcfe74b0000", "branch": "main"}],
        "results": results,
    }]}


def test_groups_follow_kind_and_level():
    assert report.group_of(_result("X")) == "violation"
    assert report.group_of(_result("X", level="warning")) == "warning"
    assert report.group_of(_result("X", kind="review", level="note")) == "review"


def test_markdown_has_summary_counts_and_evidence():
    doc = _document([_result("CRYPTO-HASH-WEAK"),
                     _result("CRYPTO-HASH-WEAK", level="warning", line=20),
                     _result("CRYPTO-IV-STATIC", kind="review", level="note", line=30)])
    text = report.render_markdown(doc)
    assert "| 위반 | 1 |" in text and "| 경고 | 1 |" in text and "| 확인 필요 | 1 |" in text
    assert "| 약한 해시 | CWE-328 | 1 | 1 | 0 |" in text
    assert "[약한 해시] `src/A.java:10`" in text
    assert "근거 조항: 암호 알고리즘 및 키 길이 이용 안내서 8쪽" in text
    assert "수정 방안: SHA-256 이상으로 교체한다." in text
    assert "`e5fa3dcfe74b` (main)" in text
    # 확인 필요 건에는 수정 방안을 붙이지 않는다. 오용인지 아직 모른다.
    review_part = text.split("## 확인 필요")[1]
    assert "수정 방안" not in review_part


def test_markdown_is_deterministic_and_handles_empty():
    doc = _document([_result("CRYPTO-HASH-WEAK")])
    assert report.render_markdown(doc) == report.render_markdown(doc)
    assert "찾지 못했다" in report.render_markdown(_document([]))


def test_write_md(tmp_path):
    out = report.write(_document([_result("CRYPTO-HASH-WEAK")]), tmp_path / "r.md", "md")
    assert out.read_text(encoding="utf-8").startswith("# 암호 오용 검사 보고서")


def test_write_pdf(tmp_path):
    pytest.importorskip("fpdf")
    if report.find_font() is None:
        pytest.skip("한글 TTF 글꼴 없음")
    out = report.write(_document([_result("CRYPTO-HASH-WEAK")]), tmp_path / "r.pdf", "pdf")
    assert out.read_bytes()[:4] == b"%PDF"
