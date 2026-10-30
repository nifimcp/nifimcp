"""Reference plans and labeled lab cases for the two supported blueprints.

The labeled cases state the INTENDED route membership for each synthetic record.
Lab verification fails if stock NiFi routes any record differently.
"""
from __future__ import annotations

UPDATE = "org.apache.nifi.processors.attributes.UpdateAttribute"
ROUTE = "org.apache.nifi.processors.standard.RouteOnAttribute"
EJP = "org.apache.nifi.processors.standard.EvaluateJsonPath"


def _port(pid: str, kind: str) -> dict:
    return {"id": pid, "type_id": "nifi:InputPort" if kind == "input_port" else "nifi:OutputPort", "kind": kind,
            "properties": {}, "auto_terminated_relationships": []}


def attribute_router_plan(catalog_hash: str) -> dict:
    return {
        "schema_version": "1", "target_version": "2.12.0", "catalog_hash": catalog_hash,
        "intent": "Route incoming events by their 'severity' attribute: critical events to a critical output, "
                  "low/medium/standard to a standard output, everything with a severity to an audit copy, and "
                  "anything else (including a missing severity) to unmatched.",
        "blueprint": "attribute_router", "automatic_start": False,
        "components": [
            _port("in", "input_port"),
            {"id": "normalize", "type_id": UPDATE, "kind": "processor",
             "properties": {"route.key": "${severity:toLower():trim()}"}, "auto_terminated_relationships": []},
            {"id": "route", "type_id": ROUTE, "kind": "processor",
             "properties": {"critical": "${route.key:equals('critical')}",
                            "standard": "${route.key:in('low','medium','standard')}",
                            "audit": "${severity:isEmpty():not()}"},
             "auto_terminated_relationships": []},
            _port("out_critical", "output_port"), _port("out_standard", "output_port"),
            _port("out_audit", "output_port"), _port("out_unmatched", "output_port"),
        ],
        "connections": [
            {"id": "c_in", "source": "in", "relationship": "port", "destination": "normalize"},
            {"id": "c_norm", "source": "normalize", "relationship": "success", "destination": "route"},
            {"id": "c_crit", "source": "route", "relationship": "critical", "destination": "out_critical"},
            {"id": "c_std", "source": "route", "relationship": "standard", "destination": "out_standard"},
            {"id": "c_audit", "source": "route", "relationship": "audit", "destination": "out_audit"},
            {"id": "c_unm", "source": "route", "relationship": "unmatched", "destination": "out_unmatched"},
        ],
        "parameter_references": [],
        "output_expectations": [
            {"port_id": "out_critical", "condition": "severity equals 'critical' ignoring case and surrounding spaces"},
            {"port_id": "out_standard", "condition": "severity is low, medium or standard (ignoring case and spaces)"},
            {"port_id": "out_audit", "condition": "every record that has a non-empty severity (a copy)"},
            {"port_id": "out_unmatched", "condition": "records with no route match, including a missing severity"},
        ],
    }


def json_field_gate_plan(catalog_hash: str) -> dict:
    return {
        "schema_version": "1", "target_version": "2.12.0", "catalog_hash": catalog_hash,
        "intent": "Accept JSON telemetry events (event.type == 'telemetry' and priority >= 5). Send records without "
                  "an event type to a 'missing' output, invalid JSON to an 'invalid' output and everything else to "
                  "'rejected'.",
        "blueprint": "json_field_gate", "automatic_start": False,
        "components": [
            _port("in", "input_port"),
            {"id": "extract", "type_id": EJP, "kind": "processor",
             "properties": {"Destination": "flowfile-attribute", "Return Type": "scalar",
                            "Path Not Found Behavior": "ignore",
                            "event.type": "$.event.type", "event.priority": "$.priority"},
             "auto_terminated_relationships": ["unmatched"]},
            {"id": "gate", "type_id": ROUTE, "kind": "processor",
             "properties": {"accept": "${event.type:equals('telemetry'):and(${event.priority:toNumber():ge(5)})}",
                            "missing": "${event.type:isEmpty()}"},
             "auto_terminated_relationships": []},
            _port("out_accepted", "output_port"), _port("out_missing", "output_port"),
            _port("out_rejected", "output_port"), _port("out_invalid", "output_port"),
        ],
        "connections": [
            {"id": "c_in", "source": "in", "relationship": "port", "destination": "extract"},
            {"id": "c_matched", "source": "extract", "relationship": "matched", "destination": "gate"},
            {"id": "c_fail", "source": "extract", "relationship": "failure", "destination": "out_invalid"},
            {"id": "c_accept", "source": "gate", "relationship": "accept", "destination": "out_accepted"},
            {"id": "c_missing", "source": "gate", "relationship": "missing", "destination": "out_missing"},
            {"id": "c_reject", "source": "gate", "relationship": "unmatched", "destination": "out_rejected"},
        ],
        "parameter_references": [],
        "output_expectations": [
            {"port_id": "out_accepted", "condition": "event.type == 'telemetry' and numeric priority >= 5"},
            {"port_id": "out_missing", "condition": "no event.type field (or empty)"},
            {"port_id": "out_rejected", "condition": "valid JSON that is neither accepted nor missing"},
            {"port_id": "out_invalid", "condition": "content that is not valid JSON"},
        ],
    }


def example_plans(catalog_hash: str) -> dict[str, dict]:
    return {"attribute_router": attribute_router_plan(catalog_hash),
            "json_field_gate": json_field_gate_plan(catalog_hash)}


# Labeled lab cases. "attributes" become FlowFile attributes; "content" becomes FlowFile content.
# "expected" is the exact set of output ports the record must reach (copies count separately).
ATTRIBUTE_ROUTER_CASES = {
    "blueprint": "attribute_router",
    "key_attribute": "case.id",
    "cases": [
        {"id": "ar-01-critical", "attributes": {"severity": "critical"}, "expected": ["out_critical", "out_audit"]},
        {"id": "ar-02-critical-upper-spaces", "attributes": {"severity": "  CRITICAL "}, "expected": ["out_critical", "out_audit"]},
        {"id": "ar-03-medium", "attributes": {"severity": "medium"}, "expected": ["out_standard", "out_audit"]},
        {"id": "ar-04-low", "attributes": {"severity": "Low"}, "expected": ["out_standard", "out_audit"]},
        {"id": "ar-05-unexpected", "attributes": {"severity": "urgent"}, "expected": ["out_audit"]},
        {"id": "ar-06-missing", "attributes": {}, "expected": ["out_unmatched"]},
        {"id": "ar-07-empty", "attributes": {"severity": ""}, "expected": ["out_unmatched"]},
        {"id": "ar-08-quote", "attributes": {"severity": "crit'ical"}, "expected": ["out_audit"]},
        {"id": "ar-09-duplicate-a", "attributes": {"severity": "standard"}, "expected": ["out_standard", "out_audit"]},
        {"id": "ar-10-duplicate-b", "attributes": {"severity": "standard"}, "expected": ["out_standard", "out_audit"]},
    ],
}

JSON_FIELD_GATE_CASES = {
    "blueprint": "json_field_gate",
    "key_attribute": "case.id",
    "cases": [
        {"id": "jg-01-accept", "content": '{"event":{"type":"telemetry"},"priority":7}', "expected": ["out_accepted"]},
        {"id": "jg-02-accept-string-priority", "content": '{"event":{"type":"telemetry"},"priority":"9"}', "expected": ["out_accepted"]},
        {"id": "jg-03-low-priority", "content": '{"event":{"type":"telemetry"},"priority":2}', "expected": ["out_rejected"]},
        {"id": "jg-04-other-type", "content": '{"event":{"type":"audit"},"priority":9}', "expected": ["out_rejected"]},
        {"id": "jg-05-missing-type", "content": '{"priority":9}', "expected": ["out_missing"]},
        {"id": "jg-06-invalid-json", "content": '{"event": {"type": "telemetry", ', "expected": ["out_invalid"]},
        {"id": "jg-07-escaped-quote", "content": '{"event":{"type":"tele\\"metry"},"priority":7}', "expected": ["out_rejected"]},
        {"id": "jg-08-unicode", "content": '{"event":{"type":"t\\u00e9l\\u00e9metry"},"priority":7}', "expected": ["out_rejected"]},
        {"id": "jg-09-duplicate-a", "content": '{"event":{"type":"telemetry"},"priority":5}', "expected": ["out_accepted"]},
        {"id": "jg-10-duplicate-b", "content": '{"event":{"type":"telemetry"},"priority":5}', "expected": ["out_accepted"]},
    ],
}


def example_cases() -> dict[str, dict]:
    return {"attribute_router": ATTRIBUTE_ROUTER_CASES, "json_field_gate": JSON_FIELD_GATE_CASES}
