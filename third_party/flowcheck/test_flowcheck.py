import json
import tempfile
import unittest
from pathlib import Path
import flowcheck as fc


class FlowCheckTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"id": "a", "value": 12, "event": "2026-09-23T12:00:00Z", "arrival": "2026-09-23T12:00:02Z"},
            {"id": "b", "value": 15, "event": "2026-09-23T12:01:00Z", "arrival": "2026-09-23T12:01:03Z"},
        ]

    def run_compare(self, a=None, b=None, **kwargs):
        return fc.compare(self.rows if a is None else a, self.rows if b is None else b,
                          key="id", event_field="event", ingest_field="arrival", **kwargs)

    def test_reordering_and_arrival_change_can_pass(self):
        changed = [dict(r) for r in reversed(self.rows)]
        changed[0]["arrival"] = "2026-09-23T12:01:04Z"
        self.assertEqual(self.run_compare(b=changed)["status"], "PASS")

    def test_duplicate_and_missing_cannot_hide_behind_equal_counts(self):
        self.assertEqual(self.run_compare(b=[self.rows[0], self.rows[0]])["status"], "FAIL")

    def test_empty_inputs_fail(self):
        self.assertEqual(self.run_compare(a=[], b=[])["status"], "FAIL")

    def test_missing_id_fails(self):
        changed = [dict(r) for r in self.rows]
        changed[0].pop("id")
        self.assertEqual(self.run_compare(b=changed)["status"], "FAIL")

    def test_content_change_fails(self):
        changed = [dict(r) for r in self.rows]
        changed[1]["value"] = 99
        self.assertEqual(self.run_compare(b=changed)["status"], "FAIL")

    def test_ignored_content_change_passes(self):
        changed = [dict(r) for r in self.rows]
        changed[1]["value"] = 99
        self.assertEqual(self.run_compare(b=changed, ignore=["value"])["status"], "PASS")

    def test_timezone_equivalence_passes(self):
        changed = [dict(r) for r in self.rows]
        changed[0]["event"] = "2026-09-23T08:00:00-04:00"
        self.assertEqual(self.run_compare(b=changed)["status"], "PASS")

    def test_naive_timestamp_fails(self):
        changed = [dict(r) for r in self.rows]
        changed[0]["event"] = "2026-09-23T12:00:00"
        self.assertEqual(self.run_compare(b=changed)["status"], "FAIL")

    def test_negative_delay_fails(self):
        changed = [dict(r) for r in self.rows]
        changed[0]["arrival"] = "2026-09-23T11:59:59Z"
        self.assertEqual(self.run_compare(b=changed)["status"], "FAIL")

    def test_latency_threshold_fails(self):
        self.assertEqual(self.run_compare(max_p95_latency=2)["status"], "FAIL")

    def test_schema_type_change_fails(self):
        changed = [dict(r) for r in self.rows]
        changed[0]["value"] = "12"
        result = self.run_compare(b=changed)
        self.assertEqual(next(c for c in result["checks"] if c["check"] == "Observed top-level schema")["status"], "FAIL")

    def test_invalid_policies_rejected(self):
        for value in [-1, float("nan"), float("inf")]:
            with self.assertRaises(ValueError):
                self.run_compare(max_count_drift_pct=value)
        with self.assertRaises(ValueError):
            self.run_compare(ignore=["id"])

    def test_file_parsing_rejects_ambiguous_input(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "bad.jsonl"
            p.write_text('{"id":"a","id":"b"}\n')
            with self.assertRaises(ValueError):
                fc.read_records(p)
            p = Path(folder) / "bad.csv"
            p.write_text("id,id\na,b\n")
            with self.assertRaises(ValueError):
                fc.read_records(p)
            p.write_text("id,value\na,1,extra\n")
            with self.assertRaises(ValueError):
                fc.read_records(p)

    def test_jsonl_csv_and_multiline_csv_read(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "sample.jsonl"
            p.write_text('\n'.join(json.dumps(r) for r in self.rows))
            self.assertEqual(fc.read_records(p)[0], self.rows)
            p = Path(folder) / "sample.csv"
            p.write_text('id,note\na,"two\nlines"\n')
            self.assertEqual(fc.read_records(p)[0], [{"id": "a", "note": "two\nlines"}])

    def test_input_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "input.json"
            original = json.dumps(self.rows)
            p.write_text(original)
            self.assertEqual(fc.main([str(p), str(p), "--key", "id", "--json-out", str(p)]), 2)
            self.assertEqual(p.read_text(), original)

    def test_html_escapes_metadata(self):
        result = self.run_compare()
        result["checks"][0]["detail"] = '<script>alert(1)</script>'
        rendered = fc.report_html(result)
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)


if __name__ == "__main__":
    unittest.main()

