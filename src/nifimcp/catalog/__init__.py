"""Pinned NiFi 2.12.0 catalog for the Flow Draft Preview (captured from the real runtime manifest)."""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from ..util import canonical_hash

CATALOG_FILE = "nifi-2.12.0-catalog.json"

BLUEPRINTS = {
    "attribute_router": {
        "description": "Route FlowFiles by attribute conditions. Optional UpdateAttribute steps, exactly one input "
                       "port, one RouteOnAttribute, one or more output ports.",
        "allowed_types": ["nifi:InputPort", "nifi:OutputPort",
                          "org.apache.nifi.processors.attributes.UpdateAttribute",
                          "org.apache.nifi.processors.standard.RouteOnAttribute"],
        "required_types": {"nifi:InputPort": [1, 1], "org.apache.nifi.processors.standard.RouteOnAttribute": [1, 3],
                           "nifi:OutputPort": [1, 10]},
    },
    "json_field_gate": {
        "description": "Extract JSON fields into attributes with EvaluateJsonPath, then gate with RouteOnAttribute. "
                       "Exactly one input port, one or more output ports.",
        "allowed_types": ["nifi:InputPort", "nifi:OutputPort",
                          "org.apache.nifi.processors.attributes.UpdateAttribute",
                          "org.apache.nifi.processors.standard.EvaluateJsonPath",
                          "org.apache.nifi.processors.standard.RouteOnAttribute"],
        "required_types": {"nifi:InputPort": [1, 1], "org.apache.nifi.processors.standard.EvaluateJsonPath": [1, 3],
                           "org.apache.nifi.processors.standard.RouteOnAttribute": [1, 3],
                           "nifi:OutputPort": [1, 10]},
    },
}


class CatalogIntegrityError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    raw = (resources.files(__package__) / CATALOG_FILE).read_bytes()
    catalog = json.loads(raw)
    claimed = catalog.pop("catalog_hash")
    if canonical_hash(catalog) != claimed:
        raise CatalogIntegrityError("packaged catalog does not match its recorded hash")
    catalog["catalog_hash"] = claimed
    catalog["blueprints"] = BLUEPRINTS
    return catalog


def entry(type_id: str) -> dict | None:
    return next((e for e in load_catalog()["entries"] if e["type_id"] == type_id), None)
