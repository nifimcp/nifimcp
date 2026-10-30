import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from cli_anything.nifi.checkride import load, inspect, check, diff, main

BASE = {'flowContents': {'identifier': 'root', 'processors': [
    {'identifier': 'source', 'properties': {'endpoint': 'https://example.invalid'}, 'autoTerminatedRelationships': []},
    {'identifier': 'sink', 'properties': {}}], 'connections': [
    {'identifier': 'wire', 'source': {'id': 'source'}, 'destination': {'id': 'sink'},
     'backPressureObjectThreshold': 10000, 'backPressureDataSizeThreshold': '1 GB'}]}}


class CheckrideTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def flow(self, doc):
        p = Path(self.temp.name) / 'flow.json'
        p.write_text(json.dumps(doc))
        return load(p)

    def test_nominal(self):
        f = self.flow(BASE)
        self.assertEqual(check(f)['findings'], [])
        self.assertEqual(inspect(f)['counts']['processors'], 2)

    def test_dangling_connection(self):
        d = copy.deepcopy(BASE)
        d['flowContents']['processors'].pop()
        self.assertEqual(check(self.flow(d))['findings'][0]['rule'], 'unresolved-destination')

    def test_unbounded_queue(self):
        d = copy.deepcopy(BASE)
        c = d['flowContents']['connections'][0]
        c.update(backPressureObjectThreshold=0, backPressureDataSizeThreshold='0 MB')
        self.assertEqual(check(self.flow(d))['findings'][0]['rule'], 'unbounded-queue')
        c['backPressureDataSizeThreshold'] = '1 GB'
        self.assertEqual(check(self.flow(d))['findings'], [])

    def test_nested_and_remote_ports(self):
        d = copy.deepcopy(BASE)
        d['flowContents']['processGroups'] = [{'identifier': 'child', 'inputPorts': [{'identifier': 'child-in'}]}]
        d['flowContents']['remoteProcessGroups'] = [{'identifier': 'remote', 'inputPorts': [{'identifier': 'remote-in'}]}]
        for endpoint in ('child-in', 'remote-in'):
            d['flowContents']['connections'][0]['destination']['id'] = endpoint
            self.assertEqual(check(self.flow(d))['findings'], [])

    def test_redaction(self):
        d = copy.deepcopy(BASE)
        p = d['flowContents']['processors'][0]
        p['name'] = 'PRIVATE-CUSTOMER'
        p['properties']['password'] = 'SENSITIVE-PASSWORD'
        p['properties']['endpoint'] = 'http://PRIVATE-HOST/secret'
        f = self.flow(d)
        out = json.dumps([inspect(f), check(f), diff(self.flow(BASE), f)])
        for text in ('PRIVATE-CUSTOMER', 'SENSITIVE-PASSWORD', 'PRIVATE-HOST'):
            self.assertNotIn(text, out)
        self.assertIn('plaintext-http', out)

    def test_failure_path(self):
        d = copy.deepcopy(BASE)
        d['flowContents']['processors'][0]['autoTerminatedRelationships'] = ['failure']
        self.assertEqual(check(self.flow(d))['findings'][0]['rule'], 'discarded-failure-path')

    def test_diff_ignores_layout_and_component_order(self):
        d = copy.deepcopy(BASE)
        d['flowContents']['processors'].reverse()
        d['flowContents']['processors'][0]['position'] = {'x': 500, 'y': 100}
        self.assertEqual(diff(self.flow(BASE), self.flow(d))['changed'], [])

    def test_diff_preserves_semantic_list_order(self):
        a, b = copy.deepcopy(BASE), copy.deepcopy(BASE)
        a['flowContents']['connections'][0]['prioritizers'] = ['a', 'b']
        b['flowContents']['connections'][0]['prioritizers'] = ['b', 'a']
        self.assertEqual(diff(self.flow(a), self.flow(b))['changed'][0]['fields'], ['prioritizers'])

    def test_diff_changes_and_metadata(self):
        d = copy.deepcopy(BASE)
        d['flowContents']['processors'][0]['properties']['endpoint'] = 'https://new.invalid'
        d['parameterContexts'] = {'secret': {'parameters': []}}
        result = diff(self.flow(BASE), self.flow(d))
        self.assertEqual(result['changed'], [{'componentId': 'source', 'fields': ['properties']}])
        self.assertEqual(result['snapshotFieldsChanged'], ['parameterContexts'])

    def test_invalid_shapes(self):
        bad = [{}, [], {'flowContents': {'identifier': 'root', 'processors': {}}},
               {'flowContents': {'identifier': 'root', 'processors': [{'identifier': 'root'}]}}]
        for doc in bad:
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                self.flow(doc)

    def test_cli_exit_codes_and_json(self):
        d = copy.deepcopy(BASE)
        d['flowContents']['processors'][0]['autoTerminatedRelationships'] = ['failure']
        self.flow(d)
        path = str(Path(self.temp.name) / 'flow.json')
        for args, expected in [(['inspect', path], 0), (['check', path], 0),
                               (['check', path, '--fail-on', 'warning'], 1)]:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(args), expected)
            self.assertIn('schemaVersion', json.loads(out.getvalue()))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['check', 'missing.json']), 2)


if __name__ == '__main__':
    unittest.main()

