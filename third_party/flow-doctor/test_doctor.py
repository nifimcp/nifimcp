import json
import unittest
from doctor import inspect_flow, render


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.flow = {'processors': [{'identifier': 'p1', 'type': 'GenerateFlowFile', 'scheduledState': 'STOPPED', 'properties': {'password': 'DO_NOT_EMIT'}}], 'connections': []}

    def test_properties_never_in_report(self):
        self.assertNotIn('DO_NOT_EMIT', json.dumps(inspect_flow(self.flow)))

    def test_snapshot_nested_group(self):
        report = inspect_flow({'flowContents': {'processors': [], 'processGroups': [self.flow]}})
        self.assertEqual(len(report['nodes']), 1)
        self.assertEqual(report['findings'][0]['id'], 'STOPPED:p1')

    def test_duplicate_ids_fail(self):
        self.flow['processors'] *= 2
        with self.assertRaises(ValueError):
            inspect_flow(self.flow)

    def test_unknown_input_fails(self):
        with self.assertRaises(ValueError):
            inspect_flow({'hello': 'world'})

    def test_endpoints_and_expiration(self):
        self.flow['connections'] = [{'identifier': 'c1', 'source': {'id': 'p1'}, 'destination': {'id': 'absent'}, 'flowFileExpiration': '5 min'}]
        codes = {f['code'] for f in inspect_flow(self.flow)['findings']}
        self.assertIn('EXPIRATION', codes)
        self.assertIn('UNRESOLVED_ENDPOINT', codes)

    def test_html_escapes_model_output(self):
        report = inspect_flow(self.flow)
        report['ai_explanation'] = '<script>alert(1)</script>'
        self.assertNotIn('<script>', render(report))

    def test_hash_stable_for_key_order(self):
        self.assertEqual(inspect_flow(self.flow)['input_sha256'], inspect_flow(dict(reversed(list(self.flow.items()))))['input_sha256'])


if __name__ == '__main__':
    unittest.main()

