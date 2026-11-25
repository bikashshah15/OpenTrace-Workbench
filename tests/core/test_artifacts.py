import os
import unittest

from opentrace_core.artifacts import ArtifactConflict, IntegrityError, digest_of

from tests.helpers import FIXTURE, FIXTURE_DIGEST, fixture_store


class ArtifactStoreTest(unittest.TestCase):
    def setUp(self):
        self.store, self.tmp = fixture_store(self)

    def test_fixture_digest_matches_contract(self):
        self.assertEqual(digest_of(FIXTURE.read_bytes()), FIXTURE_DIGEST)
        self.assertEqual(self.store.get(FIXTURE_DIGEST), FIXTURE.read_bytes())

    def test_same_bytes_again_is_a_noop(self):
        before = (self.store.root / "sha256" / FIXTURE_DIGEST[7:]).stat().st_mtime_ns
        self.assertEqual(self.store.put(FIXTURE.read_bytes(), "text/plain", "again"), FIXTURE_DIGEST)
        after = (self.store.root / "sha256" / FIXTURE_DIGEST[7:]).stat().st_mtime_ns
        self.assertEqual(before, after)
        self.assertEqual(self.store.meta(FIXTURE_DIGEST)["producer"], "fixture")  # sidecar not rewritten

    def test_different_bytes_for_existing_digest_raise(self):
        path = self.store.root / "sha256" / FIXTURE_DIGEST[7:]
        os.chmod(path, 0o644)
        path.write_bytes(b"tampered")
        with self.assertRaises(ArtifactConflict):
            self.store.put(FIXTURE.read_bytes(), "text/plain", "x")
        with self.assertRaises(IntegrityError):
            self.store.get(FIXTURE_DIGEST)

    def test_files_are_read_only_and_sidecar_records_metadata(self):
        path = self.store.root / "sha256" / FIXTURE_DIGEST[7:]
        self.assertEqual(path.stat().st_mode & 0o222, 0)
        meta = self.store.meta(FIXTURE_DIGEST)
        for key in ("media_type", "producer", "source_ref", "captured_at", "revision_binding"):
            self.assertIn(key, meta)
        self.assertEqual(meta["revision_binding"], "bound_by_digest")
        self.assertEqual(meta["path"], "sha256/" + FIXTURE_DIGEST[7:])  # store-relative only

    def test_put_checked_refuses_mismatched_bytes(self):
        with self.assertRaises(IntegrityError):
            self.store.put_checked("sha256:" + "0" * 64, b"abc", media_type="x", producer="y")
        self.assertFalse(self.store.exists("sha256:" + "0" * 64))

    def test_invalid_revision_binding_rejected(self):
        with self.assertRaises(ValueError):
            self.store.put(b"x", "x", "x", revision_binding="maybe")

    def test_quarantine_is_recorded(self):
        self.store.quarantine("sha256:" + "1" * 64, None, "produced_artifact_integrity_failure", "test")
        self.assertEqual(self.store.quarantined()[0]["reason"], "produced_artifact_integrity_failure")


if __name__ == "__main__":
    unittest.main()
