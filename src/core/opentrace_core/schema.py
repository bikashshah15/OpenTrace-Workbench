"""Schema-equivalent structural checks using the published contract schemas.

A small interpreter for the JSON Schema 2020-12 keywords that
contracts/evidence/v1/schemas actually uses. Any other keyword raises, so a schema
edit can never be silently skipped. tools/contracts/check_examples.py cross-checks
these results against jsonschema==4.23.0 (dev/test only).
"""
import json
import re
from pathlib import Path

_CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "evidence"
SCHEMA_DIR = _CONTRACTS / "v1" / "schemas"
BASE = "https://schemas.opentrace.invalid/evidence/v1/"
SCHEMA_DIR_V2 = _CONTRACTS / "v2" / "schemas"
BASE_V2 = "https://schemas.opentrace.invalid/evidence/v2/"
SCHEMA_DIR_V3 = _CONTRACTS / "v3" / "schemas"
BASE_V3 = "https://schemas.opentrace.invalid/evidence/v3/"
KINDS = ("capability_request", "capability_response", "task_request", "result", "rejection")
_ANNOTATIONS = {"$schema", "$id", "$defs", "title", "description", "$comment"}
_KEYWORDS = {"type", "required", "properties", "additionalProperties", "enum", "const", "pattern",
             "items", "minItems", "maxItems", "uniqueItems", "minimum", "maximum", "minLength",
             "maxLength", "$ref", "allOf", "if", "then"}


class SchemaError(Exception):
    pass


def _type_ok(value, name):
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    raise SchemaError("unknown type %s" % name)


def _json_equal(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True) and type(a) is type(b)


class SchemaSet:
    def __init__(self, directory=SCHEMA_DIR, base=BASE):
        self.base = base
        self.docs = {}
        for path in sorted(Path(directory).glob("*.schema.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.docs[doc["$id"]] = doc

    def _resolve(self, ref, base):
        uri, _, fragment = ref.partition("#")
        doc_id = self.base + uri if uri else base
        if doc_id not in self.docs:
            raise SchemaError("unresolvable $ref %s" % ref)
        node = self.docs[doc_id]
        for part in [p for p in fragment.split("/") if p]:
            node = node[part]
        return node, doc_id

    def errors(self, kind, instance):
        doc_id = self.base + kind + ".schema.json"
        if doc_id not in self.docs:
            raise SchemaError("no schema for %s" % kind)
        out = []
        self._check(self.docs[doc_id], instance, doc_id, "$", out)
        return out

    def _check(self, schema, value, base, path, out):
        unknown = set(schema) - _KEYWORDS - _ANNOTATIONS
        if unknown:
            raise SchemaError("unsupported keywords %s at %s" % (sorted(unknown), path))
        if "$ref" in schema:
            target, target_base = self._resolve(schema["$ref"], base)
            self._check(target, value, target_base, path, out)
        for sub_schema in schema.get("allOf", []):
            self._check(sub_schema, value, base, path, out)
        if "if" in schema:
            probe = []
            self._check(schema["if"], value, base, path, probe)
            if not probe and "then" in schema:
                self._check(schema["then"], value, base, path, out)
        if "type" in schema:
            names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_type_ok(value, n) for n in names):
                out.append("%s: expected %s" % (path, "/".join(names)))
                return
        if "const" in schema and not _json_equal(value, schema["const"]):
            out.append("%s: must equal %r" % (path, schema["const"]))
        if "enum" in schema and not any(_json_equal(value, e) for e in schema["enum"]):
            out.append("%s: not in enum" % path)
        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0):
                out.append("%s: too short" % path)
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                out.append("%s: too long" % path)
            if "pattern" in schema and not re.search(schema["pattern"], value):
                out.append("%s: does not match pattern" % path)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                out.append("%s: below minimum" % path)
            if "maximum" in schema and value > schema["maximum"]:
                out.append("%s: above maximum" % path)
        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                out.append("%s: too few items" % path)
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                out.append("%s: too many items" % path)
            if schema.get("uniqueItems"):
                seen = [json.dumps(v, sort_keys=True) for v in value]
                if len(seen) != len(set(seen)):
                    out.append("%s: items not unique" % path)
            if "items" in schema:
                for i, item in enumerate(value):
                    self._check(schema["items"], item, base, "%s[%d]" % (path, i), out)
        if isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    out.append("%s: missing required %s" % (path, key))
            props = schema.get("properties", {})
            for key, item in value.items():
                if key in props:
                    self._check(props[key], item, base, "%s.%s" % (path, key), out)
                elif schema.get("additionalProperties", True) is False:
                    out.append("%s: unexpected property %s" % (path, key))


_DEFAULT = {}


def default_schemas(major=1):
    if major not in _DEFAULT:
        if major == 1:
            _DEFAULT[major] = SchemaSet()
        elif major == 2:
            _DEFAULT[major] = SchemaSet(SCHEMA_DIR_V2, BASE_V2)
        else:
            _DEFAULT[major] = SchemaSet(SCHEMA_DIR_V3, BASE_V3)
    return _DEFAULT[major]


def structural_errors(kind, instance, major=1):
    return default_schemas(major).errors(kind, instance)
