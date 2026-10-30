"""A28: equal counts cannot hide missing, duplicate, misrouted or altered records."""
import json

import pytest

from nifimcp.comparator.records import ComparisonInputError, compare_membership, compare_records, read_records

CASES = [{"id": "a", "expected": ["out_x"]}, {"id": "b", "expected": ["out_y", "out_audit"]},
         {"id": "c", "expected": ["out_unmatched"]}]
GOOD = [{"case_id": "a", "port": "out_x"}, {"case_id": "b", "port": "out_y"}, {"case_id": "b", "port": "out_audit"},
        {"case_id": "c", "port": "out_unmatched"}]


def test_exact_membership_passes():
    assert compare_membership(CASES, GOOD)["status"] == "PASS"


def test_order_does_not_matter():
    assert compare_membership(CASES, list(reversed(GOOD)))["status"] == "PASS"


@pytest.mark.parametrize("observed,why", [
    ([GOOD[0], GOOD[0], GOOD[2], GOOD[3]], "duplicate replaces a missing record, same count"),
    ([{"case_id": "a", "port": "out_y"}, GOOD[1], GOOD[2], GOOD[3]], "misrouted, same count"),
    ([GOOD[0], GOOD[1], GOOD[2], {"case_id": "z", "port": "out_unmatched"}], "unexpected record, same count"),
    ([GOOD[0], GOOD[1], GOOD[2]], "missing record"),
    (GOOD + [GOOD[3]], "extra duplicate"),
    ([GOOD[0], GOOD[1], {"case_id": "b", "port": "out_y"}, GOOD[3]], "copy to wrong port, same count"),
])
def test_equal_counts_cannot_hide_errors(observed, why):
    result = compare_membership(CASES, observed)
    assert result["status"] == "FAIL", why


def test_altered_values_fail():
    cases = [{"id": "a", "expected": ["out_x"], "expected_attributes": {"event.type": "telemetry"}}]
    ok = [{"case_id": "a", "port": "out_x", "attributes": {"event.type": "telemetry", "other": "ignored"}}]
    bad = [{"case_id": "a", "port": "out_x", "attributes": {"event.type": "TELEMETRY"}}]
    assert compare_membership(cases, ok)["status"] == "PASS"
    assert compare_membership(cases, bad)["status"] == "FAIL"


def test_record_comparison_checks():
    base = [{"id": 1, "v": "x"}, {"id": 2, "v": "y"}]
    assert compare_records(base, list(reversed(base)), key="id")["status"] == "PASS"
    assert compare_records(base, [base[0], base[0]], key="id")["status"] == "FAIL"
    assert compare_records(base, [base[0], {"id": 2, "v": "z"}], key="id")["status"] == "FAIL"
    assert compare_records(base, [base[0], {"id": 2, "v": 5}], key="id")["status"] == "FAIL"
    assert compare_records([], [], key="id")["status"] == "FAIL"
    with pytest.raises(ComparisonInputError):
        compare_records(base, base, key="id", ignore=["id"])


def test_bounded_input():
    with pytest.raises(Exception):
        read_records(b'[{"a":1,"a":2}]')
    with pytest.raises(ComparisonInputError):
        read_records(json.dumps([{"i": i} for i in range(20)]).encode(), max_records=10)
    assert read_records(b'{"a":1}\n{"a":2}\n') == [{"a": 1}, {"a": 2}]
