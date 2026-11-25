"""H1-H3, R6/R7 (captures): canonical bytes, non-self-referential set ID, write-once, tamper detection.
The two-entry manifest is a SYNTHETIC test vector (contract section 3.4)."""
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from opentrace_core import canon
from opentrace_core.captures import CaptureBuilder, CaptureError, CaptureSet

REQ = b'{"queries":[]}\n'
RESP = b'{"results":[]}\n'
VECTOR_DIGEST = "sha256:d6ca2efdcd82763d234dfa7b0930b83c185212052c7fd75afeecf839234a33e9"
VECTOR = (
    '{"captures":[{"acquirer":"synthetic-test-vector/0","attempt":1,"bytes":15,"capture_id":"c001",'
    '"captured_at":"2026-01-01T00:00:00Z","headers":{},"kind":"osv_querybatch_request","method":"POST",'
    '"network_phase":"controlled_acquisition","provenance":"synthetic_test_vector","redirect_hops":[],'
    '"request_digest":"sha256:9cfdda95e98ddd0b177f5f4efcf27a8fdb8c1ecac10d2160f2fcf381b3a1fa03","response_digest":null,'
    '"status":null,"url":"https://api.osv.dev/v1/querybatch"},{"acquirer":"synthetic-test-vector/0","attempt":1,"bytes":15,'
    '"capture_id":"c002","captured_at":"2026-01-01T00:00:01Z","headers":{"content-type":"application/json"},'
    '"kind":"osv_querybatch_response","method":"POST","network_phase":"controlled_acquisition",'
    '"provenance":"synthetic_test_vector","redirect_hops":[],'
    '"request_digest":"sha256:9cfdda95e98ddd0b177f5f4efcf27a8fdb8c1ecac10d2160f2fcf381b3a1fa03",'
    '"response_digest":"sha256:250a97e605ccc127d0b54b8d69907118ccd5d0a3352b27819891e2dc8c5b4046","status":200,'
    '"url":"https://api.osv.dev/v1/querybatch"}],"schema":"opentrace.capture_manifest/1"}\n').encode()


def vector_builder():
    b = CaptureBuilder("synthetic-test-vector/0", provenance="synthetic_test_vector")
    b.add("osv_querybatch_request", "POST", "https://api.osv.dev/v1/querybatch", None, {}, "2026-01-01T00:00:00Z", request=REQ)
    b.add("osv_querybatch_response", "POST", "https://api.osv.dev/v1/querybatch", 200, {"Content-Type": "application/json"},
          "2026-01-01T00:00:01Z", request=REQ, response=RESP)
    return b


class CaptureIdentityTest(unittest.TestCase):
    def test_h1_canonical_bytes_and_digest_match_the_contract_vector(self):
        self.assertEqual(vector_builder().manifest_bytes(), VECTOR)
        self.assertEqual(canon.digest_of_bytes(VECTOR), VECTOR_DIGEST)

    def test_h2_set_id_is_not_in_the_preimage_and_the_sidecar_changes_no_digest(self):
        b = vector_builder()
        self.assertNotIn(VECTOR_DIGEST.encode(), b.manifest_bytes())
        self.assertNotIn(b"capture_set_id", b.manifest_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            target = b.write(tmp)
            self.assertEqual(target.name, VECTOR_DIGEST[7:])
            cs = CaptureSet(target)
            self.assertEqual(cs.id, VECTOR_DIGEST)
            self.assertEqual(cs.verify(), [])
            (target / "CAPTURE_SET_ID").chmod(0o644)
            (target / "CAPTURE_SET_ID").write_text("sha256:" + "0" * 64 + "\n")
            codes = [c for c, _ in CaptureSet(target).verify()]
            self.assertEqual(codes, ["capture_set_id_mismatch"])
            self.assertEqual(CaptureSet(target).id, VECTOR_DIGEST)  # the manifest bytes alone define the ID

    def test_h3_any_mutation_changes_the_id_or_a_named_failure(self):
        base = vector_builder().manifest_bytes()
        ids = {canon.digest_of_bytes(base)}
        for mutate in (lambda m: m["captures"][0].update(url="https://api.osv.dev/v1/other"),
                       lambda m: m["captures"][1].update(status=500),
                       lambda m: m["captures"].reverse(),
                       lambda m: m["captures"][0].update(capture_id="c009")):
            m = json.loads(base)
            mutate(m)
            ids.add(canon.digest_of_bytes(canon.canonical_bytes(m)))
        self.assertEqual(len(ids), 5)
        with tempfile.TemporaryDirectory() as tmp:
            target = vector_builder().write(tmp)
            blob = next((target / "blobs").iterdir())
            blob.chmod(0o644)
            blob.write_bytes(b"tampered")
            self.assertIn("capture_integrity_failure", [c for c, _ in CaptureSet(target).verify()])
            blob.unlink()
            self.assertIn("capture_missing", [c for c, _ in CaptureSet(target).verify()])

    def test_r7_sets_are_write_once_and_blobs_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = vector_builder().write(tmp)
            with self.assertRaises(CaptureError) as ctx:
                vector_builder().write(tmp)
            self.assertEqual(ctx.exception.code, "capture_set_exists")
            for blob in (target / "blobs").iterdir():
                self.assertFalse(blob.stat().st_mode & stat.S_IWUSR)
            self.assertFalse((target / "capture_manifest.json").stat().st_mode & stat.S_IWUSR)

    def test_directory_name_must_be_the_manifest_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = vector_builder().write(tmp)
            moved = Path(tmp) / ("0" * 64)
            os.rename(target, moved)
            self.assertIn("capture_set_id_mismatch", [c for c, _ in CaptureSet(moved).verify()])

    def test_real_only_flag_separates_synthetic_from_real(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(CaptureSet(vector_builder().write(tmp)).real_only())


class BundleTest(unittest.TestCase):
    def test_osv_bundle_pairs_rounds_keeps_failures_and_the_last_attempt(self):
        b = CaptureBuilder("t", provenance="synthetic_test_vector")
        b.add("osv_querybatch", "POST", "u", 503, {}, "2026-01-01T00:00:00Z", request=REQ, response=b"err", attempt=1)
        b.add("osv_querybatch", "POST", "u", 200, {}, "2026-01-01T00:00:01Z", request=REQ, response=RESP, attempt=2)
        b.add("osv_vuln", "GET", "https://api.osv.dev/v1/vulns/SYNTH-1", 200, {}, "2026-01-01T00:00:02Z", response=b"{}")
        b.add("osv_vuln", "GET", "https://api.osv.dev/v1/vulns/SYNTH-2", 404, {}, "2026-01-01T00:00:02Z", response=b"nf")
        with tempfile.TemporaryDirectory() as tmp:
            cs = CaptureSet(b.write(tmp))
            bundle = json.loads(cs.osv_bundle([("golang.org/x/text", "0.3.7")], skipped=[("example.com/x", None, "version_missing")]))
            self.assertEqual(bundle["capture_set_id"], cs.id)
            self.assertEqual(len(bundle["rounds"]), 1)
            self.assertEqual(bundle["rounds"][0]["status"], 200)
            self.assertEqual(bundle["records"]["SYNTH-2"]["status"], 404)
            self.assertEqual(bundle["queries"][1]["skip_reason"], "version_missing")


if __name__ == "__main__":
    unittest.main()
