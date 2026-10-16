"""ApacheCryptoAPI-Bench 채점의 정답↔탐지 매칭 규칙을 고정한다."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path("tools").resolve()))
import apache_bench as ab  # noqa: E402


def _label(**kw):
    base = dict(index=1, project="wicket", type="PBESalt", positive=True,
                cls="org.apache.wicket.util.crypt.SunJceCrypt", method=None, line=None,
                snippet="", explanation="")
    base.update(kw)
    return ab.Label(**base)


def _finding(**kw):
    base = dict(project="wicket", file="x.java", line=56,
                **{"class": "org.apache.wicket.util.crypt.SunJceCrypt"}, method=None,
                rule="CRYPTO-SALT-STATIC", decision="violation", role="", api="")
    base.update(kw)
    return base


def test_inner_and_shaded_class_names_map_to_source_files():
    assert ab._outer("org.apache.spark.TestUtils$$anon$1") == "org.apache.spark.TestUtils"
    assert ab._outer("org.spark_project.jetty.util.security.Credential") == \
        "org.eclipse.jetty.util.security.Credential"


def test_method_match_requires_same_method():
    label = _label(method="doEncryption")
    assert ab.match(label, [_finding(method="doEncryption")])
    assert not ab.match(label, [_finding(method="other")])


def test_static_initializer_matches_code_outside_methods():
    label = _label(method="<clinit>", line=56)
    assert ab.match(label, [_finding(method=None)])
    assert not ab.match(label, [_finding(method="encrypt")])


def test_line_window_when_method_is_missing():
    label = _label(line=100)
    assert ab.match(label, [_finding(line=100 + ab.LINE_WINDOW)])
    assert not ab.match(label, [_finding(line=100 + ab.LINE_WINDOW + 1)])


def test_rule_must_fit_the_benchmark_type():
    label = _label(method="m")
    assert not ab.match(label, [_finding(method="m", rule="CRYPTO-HASH-WEAK")])


def test_scoring_outcomes():
    pos = _label(index=1, method="a")
    neg = _label(index=2, method="b", positive=False)
    review = _label(index=3, method="c")
    out_of_scope = _label(index=4, type="TrustManager", method="d")
    findings = [_finding(method="a"), _finding(method="b"),
                _finding(method="c", decision="undetermined")]
    report = ab.score([pos, neg, review, out_of_scope], findings)
    assert report["totals"] == {"TP": 1, "FP": 1, "review_pos": 1}
    assert report["in_scope_positive"] == 2 and report["in_scope_negative"] == 1
    # 확인 요청은 정밀도에서 빼고 재현율에서는 못 찾은 것으로 센다(확정 경보 기준)
    assert report["precision"] == 0.5 and report["recall"] == 0.5


def test_line_offsets_do_not_break_method_matching():
    """정답 줄이 소스와 100줄 넘게 어긋나도 같은 메서드면 맞춘다."""
    label = _label(method="processCipher", line=161)
    assert ab.match(label, [_finding(method="processCipher", line=273)], [label])


def test_several_cases_in_one_method_pair_by_order():
    """한 메서드에 정답 둘·탐지 둘이면 줄 순서로 짝짓는다. 줄 값은 달라도 순서는 같다."""
    first, second = _label(method="getCipher", line=427), _label(index=2, method="getCipher", line=731)
    found = [_finding(method="getCipher", line=440, decision="clean"),
             _finding(method="getCipher", line=900)]
    assert ab.match(first, found, [first, second]) == [found[0]]
    assert ab.match(second, found, [first, second]) == [found[1]]


def test_partial_class_names_from_the_sheet_match_by_suffix():
    label = _label(cls=ab._outer("utils/DefaultSensitiveStringCodec"), method="decode")
    found = _finding(method="decode", **{"class": "org.apache.activemq.artemis.utils.DefaultSensitiveStringCodec"})
    assert ab.match(label, [found])
