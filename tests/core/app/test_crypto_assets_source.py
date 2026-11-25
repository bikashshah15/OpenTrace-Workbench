"""Stage 4 increment B (contract S4-CRYPTO-SOURCE v1.0.0): the Crypto tab's projection of hashlib/JWT/TLS source observations.

Inputs come from the real collectors on SYNTHETIC temp trees plus hand-made hostile records. Source observations and inventory-reported CBOM
assets stay separate producers; nothing here turns an algorithm name into a vulnerability.
"""
import copy
import json
import os
import shutil
import tempfile
import unittest

from opentrace_core.app import crypto_assets as ca
from opentrace_core.live import crypto_source, source_declarations as sd
from tests.core.app.test_crypto_assets import ART, binding, build, cbom_doc, comp, oid, original

URL = "https://github.com/acme/widget"
SHA = "e" * 40
TREE = {
    "auth/token.py": 'import jwt\nt = jwt.encode(p, k, algorithm="HS256")\nc = jwt.decode(t, k, algorithms=["HS256", "RS256"])\nu = jwt.encode(p, k)\n',
    "net/mqtt.py": 'import paho.mqtt.client as mqtt\nc = mqtt.Client()\nc.tls_set(ca)\nc.tls_insecure_set(True)\n',
    "net/ctx.py": 'import ssl\nx = ssl.create_default_context()\nx.minimum_version = ssl.TLSVersion.TLSv1_2\n',
    "lib/h.py": 'import hashlib\nd = hashlib.md5(b"x").hexdigest()\nk = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)\n',
}


def collect(files):
    root = tempfile.mkdtemp(prefix="ot-crsrc-")
    try:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as h:
                h.write(data)
        return crypto_source.present(sd.collect(root, URL, SHA))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def inputs(obs, cbom=None):
    return {"cbom": cbom, "source": None, "src_obs": obs, "mode": "live"}


class Projection(unittest.TestCase):
    def setUp(self):
        self.obs = collect(TREE)
        self.b = binding()
        self.p, _ = build(inputs(self.obs), self.b)
        self.by = {a["display_name"]: a for a in self.p["assets"]}

    def test_assets_and_provenance(self):
        self.assertEqual(set(self.by), {"HS256", "RS256", "JWT call (algorithm not stated)", "MQTT TLS configuration", "TLS context configuration (ssl module)",
                                        "md5", "sha256"})
        for a in self.p["assets"]:
            self.assertEqual(a["provenance"]["origin"], "supplemental_observation")
            self.assertTrue(a["provenance"]["experimental"])
            self.assertEqual(a["provenance"]["producer_id"], ca.SOURCE_ID)
        self.assertEqual([x["provenance"]["producer_id"] for x in self.p["producers"]], [ca.SOURCE_ID])
        self.assertEqual(self.p["availability"]["state"], "completed")

    def test_identity_binding_and_occurrence_locations(self):
        hs = self.by["HS256"]
        self.assertEqual(hs["asset_id"], oid("ast", self.b["analysis_digest"], "asset", "src-jwt|HS256"))
        locs = sorted((o["source_location"]["path"], o["source_location"]["line_start"], o["operation"]) for o in hs["occurrences"])
        self.assertEqual(locs, [("auth/token.py", 2, "jwt.encode call"), ("auth/token.py", 3, "jwt.decode call")])
        self.assertTrue(all(len(o["source_location"]["file_sha256"]) == 64 and o["source_location"]["excerpt"] for o in hs["occurrences"]))
        self.assertEqual(hs["attributes"]["algorithm_name"]["state"], "recorded")
        rs = self.by["RS256"]
        self.assertEqual([(o["source_location"]["path"], o["source_location"]["line_start"]) for o in rs["occurrences"]], [("auth/token.py", 3)])

    def test_hashlib_sites_presented_and_distinct_from_cbom(self):
        md5 = self.by["md5"]
        self.assertEqual((md5["kind"], md5["provenance"]["origin"]), ("algorithm", "supplemental_observation"))
        self.assertEqual(md5["occurrences"][0]["source_location"]["line_start"], 2)
        doc = cbom_doc([comp("MD5", [("lib/h.py", 2)])])
        p, _ = build(inputs(self.obs, original(doc)), self.b)
        origins = sorted((a["display_name"], a["provenance"]["origin"]) for a in p["assets"] if a["display_name"].lower() == "md5")
        self.assertEqual(origins, [("MD5", "original_artifact"), ("md5", "supplemental_observation")])      # never merged
        self.assertEqual({x["provenance"]["producer_id"] for x in p["producers"]}, {ca.SOURCE_ID, "cdxgen"})

    def test_tls_review_only_for_the_relaxed_flag_and_never_advisory(self):
        reviews = self.p["review_items"]
        self.assertEqual(len(reviews), 1)
        r = reviews[0]
        self.assertEqual((r["tone"], r["rule_id"], r["asset_id"]), ("review", "source-observation.tls_verification_relaxed", self.by["MQTT TLS configuration"]["asset_id"]))
        self.assertIn("not a confirmed vulnerability", r["bounded_meaning"])
        self.assertEqual(self.p["filter_totals"]["findings"], 1)
        self.assertEqual([a["display_name"] for a in self.p["assets"] if a["display_name"] == "TLS context configuration (ssl module)"].__len__(), 1)
        # the ssl context asset (only create_default_context + a minimum version) carries no review; algorithm names alone never do
        self.assertFalse([x for x in reviews if x["asset_id"] in (self.by["md5"]["asset_id"], self.by["HS256"]["asset_id"])])

    def test_version_is_shown_on_the_occurrence_not_as_an_asset_attribute(self):
        ssl_asset = self.by["TLS context configuration (ssl module)"]
        self.assertEqual(ssl_asset["attributes"]["protocol_version"]["state"], "unavailable")
        self.assertIn("minimum_version = TLSVersion.TLSv1_2", [o["operation"] for o in ssl_asset["occurrences"]])
        self.assertEqual(self.by["MQTT TLS configuration"]["attributes"]["protocol_name"]["state"], "recorded")

    def test_each_relaxed_setting_has_its_own_review_bound_to_its_place(self):
        obs = collect({"s.py": "import ssl\nx = ssl.create_default_context()\nx.check_hostname = False\nx.verify_mode = ssl.CERT_NONE\n"})
        p, _ = build(inputs(obs))
        conds = sorted(r["condition"] for r in p["review_items"])
        self.assertEqual(conds, ["Source sets check_hostname to False at s.py:3", "Source sets verify_mode to CERT_NONE at s.py:4"])
        self.assertEqual(len({r["review_id"] for r in p["review_items"]}), 2)

    def test_ambiguous_hashlib_binding_is_not_claimed_as_an_algorithm(self):
        obs = collect({"h.py": "import hashlib\nhashlib = None\nd = hashlib.md5(b'x')\n"})
        p, _ = build(inputs(obs))
        self.assertEqual([(a["kind"], a["display_name"]) for a in p["assets"]], [("other_crypto", "hashlib call (binding not established)")])

    def test_local_hashlib_module_makes_the_producer_partial(self):
        obs = collect({"hashlib.py": "x = 1\n", "h.py": "import hashlib\nd = hashlib.md5(b'x')\n"})
        p, _ = build(inputs(obs))
        self.assertEqual(p["producers"][0]["outcome"], "partial")

    def test_filters(self):
        p, _ = build(inputs(self.obs), self.b, filter="protocols")
        self.assertEqual(sorted(a["display_name"] for a in p["assets"]), ["MQTT TLS configuration", "TLS context configuration (ssl module)"])
        p, _ = build(inputs(self.obs), self.b, filter="findings")
        self.assertEqual([a["display_name"] for a in p["assets"]], ["MQTT TLS configuration"])

    def test_absent_observations_leave_payload_identical(self):
        doc = cbom_doc([comp("SHA-256", [("a.js", 3)])])
        a, _ = build({"cbom": original(doc), "source": None, "mode": "captured"})
        b2, _ = build({"cbom": original(doc), "source": None, "src_obs": None, "mode": "captured"})
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b2, sort_keys=True))

    def test_complete_empty_scan_lists_nothing_and_incomplete_is_partial(self):
        empty = collect({"a.py": "x = 1\n"})
        p, _ = build(inputs(empty))
        self.assertEqual((p["producers"], p["assets"], p["availability"]["state"]), ([], [], "not_run"))
        part = collect({"bad.py": "def (:\n", "ok.py": 'import jwt\njwt.encode(p,k,algorithm="HS256")\n'})
        p, _ = build(inputs(part))
        self.assertEqual((p["producers"][0]["outcome"], p["availability"]["state"]), ("partial", "partial"))
        self.assertEqual([a["display_name"] for a in p["assets"]], ["HS256"])

    def test_failed_collector_is_failed_not_empty(self):
        p, _ = build(inputs({"state": "failed", "code": "collector_error"}))
        self.assertEqual((p["availability"]["state"], p["assets"], p["producers"][0]["outcome"]), ("failed", [], "failed"))

    def test_hostile_records_dropped(self):
        bad = copy.deepcopy(self.obs)
        bad["jwt"].append(dict(bad["jwt"][0], path="/etc/x.py"))
        bad["jwt"].append(dict(bad["jwt"][0], path="a\\b.py"))
        bad["tls"].append(dict(bad["tls"][0], file_sha256="bad"))
        bad["hashlib"].append(dict(bad["hashlib"][0], line=0))
        p, _ = build(inputs(bad), self.b)
        text = json.dumps(p)
        self.assertNotIn("/etc/x.py", text)
        self.assertEqual(p["producers"][0]["outcome"], "partial")
        self.assertEqual(len(self.by["HS256"]["occurrences"]), 2)

    def test_no_local_paths_or_demo_names(self):
        text = json.dumps(self.p).lower()
        for needle in ("/users/", "/private/", "frigate", "web-new", "hailo8l"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
