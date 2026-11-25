"""I3-REQ-02/08: digest-checked loading of typed tables from validated results (V12 at the cohort layer); tampering is an integrity failure."""
import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from opentrace_core.artifacts import ArtifactStore
from opentrace_core.canon import canonical_bytes, digest_of_bytes
from opentrace_core.cohort import tables as tbl

ROOT = Path(__file__).resolve().parents[3]
EX = ROOT / "contracts" / "evidence" / "v3" / "examples" / "valid"


def example(name):
    return json.loads((EX / name).read_text())


class TablesTest(unittest.TestCase):
    def store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return ArtifactStore(Path(tmp.name) / "s")

    def test_an_occurrence_table_loads_from_the_result_artifacts(self):
        out = tbl.occurrence_tables([example("result_manifest_inventory.json")], self.store())
        (key, table), = out.items()
        self.assertEqual(key, ("modelcontextprotocol/go-sdk", "go.mod"))
        self.assertEqual([r["locator"] for r in table["rows"]], ["/require/5", "/require/7"])
        self.assertEqual(table["status"], "parsed")

    def test_a_table_whose_bytes_no_longer_match_its_digest_is_unavailable_never_read(self):
        res = example("result_manifest_inventory.json")
        res["artifacts"][0]["content_b64"] = base64.b64encode(b'{"tampered":true}\n').decode()
        with self.assertRaises(tbl.TableError) as ctx:
            tbl.occurrence_tables([res], self.store())
        self.assertEqual(ctx.exception.code, "table_unavailable")

    def test_a_table_digest_that_disagrees_with_the_evidence_is_an_integrity_failure(self):
        res = example("result_manifest_inventory.json")
        res["evidence"][1]["details"]["table_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(tbl.TableError) as ctx:
            tbl.occurrence_tables([res], self.store())
        self.assertEqual(ctx.exception.code, "table_integrity")

    def test_a_row_count_that_disagrees_is_an_integrity_failure(self):
        res = example("result_manifest_inventory.json")
        res["evidence"][1]["details"]["occurrence_count"] = 99
        with self.assertRaises(tbl.TableError) as ctx:
            tbl.occurrence_tables([res], self.store())
        self.assertEqual(ctx.exception.code, "table_integrity")

    def test_the_same_manifest_in_two_results_is_refused(self):
        res = example("result_manifest_inventory.json")
        with self.assertRaises(tbl.TableError) as ctx:
            tbl.occurrence_tables([res, copy.deepcopy(res)], self.store())
        self.assertEqual(ctx.exception.code, "duplicate_manifest")

    def test_a_table_can_come_from_the_store_when_the_result_does_not_carry_it(self):
        res = example("result_manifest_inventory.json")
        store = self.store()
        data = base64.b64decode(res["artifacts"][0]["content_b64"])
        store.put(data, media_type="application/json", producer="t", revision_binding="unbound")
        res["artifacts"] = []
        self.assertEqual(len(tbl.occurrence_tables([res], store)), 1)

    def test_hosted_tables_and_scopes_load_with_their_binding_fields(self):
        out = tbl.hosted_tables([example("result_hosted_unbound.json")], self.store())
        (repo, item), = out.items()
        self.assertEqual(item["scope"]["revision_binding"], "unbound")
        self.assertEqual(item["scope"]["document_binding"], "unbound")
        self.assertEqual(item["table"]["lane"], "hosted_unbound")
        failed = tbl.hosted_tables([example("result_hosted_forbidden.json")], self.store())
        self.assertIsNone(next(iter(failed.values()))["table"])

    def test_manifest_statuses_are_keyed_by_repository_and_path(self):
        res = example("result_manifest_inventory.json")
        scope, status = tbl.manifest_statuses([res])
        self.assertIn("modelcontextprotocol/go-sdk", scope)
        self.assertEqual(status, {})


if __name__ == "__main__":
    unittest.main()
