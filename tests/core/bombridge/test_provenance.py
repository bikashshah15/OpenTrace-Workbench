import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "src/core/opentrace_core/bombridge"
PROVENANCE = PACKAGE / "PROVENANCE.json"

SOURCE_HASHES = {
    "src/bombridge/__init__.py": "61de4e6bc47b10fd9055e9c52caf07694719acaa95e8913d787e466f6680bed4",
    "src/bombridge/assess.py": "9f34b605286460c973d9ef1fff644aaa3490921e0b63d8dd1bf97f2cf5cd117d",
    "src/bombridge/contract.py": "1ad36406747f41f34f9bf42124f1271e760085fd574feb73aeb6cbef723eec45",
    "src/bombridge/rules.py": "f1b517a996e717d915edec4f4c776299d8d8fd1d43b34e90d174c4f536937b15",
    "src/bombridge/rules_inventory.py": "c2ec5ce45ce88556f71635c2c62926b47e9c568af9b87759363ba85f6d8115d5",
    "src/bombridge/rules_aibom.py": "51894216862cfa215e8497fb8a829fb5a03458106646c3facc208f6a7b70e04b",
    "src/bombridge/rules_cbom.py": "7c4518ad3d8dfa81eade2afa58d880649122863c9a0997910cd2c4c793a60de0",
    "src/bombridge/rules_mapping.py": "14004808bfbc87b70ce8d91ead7ceefb6b2f1e042c15dcbc672662b6534220a1",
    "src/bombridge/graph.py": "cb91ef57d320d82da2dadaeac91a70a154db7c59197ce56a4975511888850c5a",
    "src/bombridge/links.py": "694421c79130154e11ca1feff8382829def73561ce75ea81ae627bdb58584b35",
    "src/bombridge/pipeline.py": "1279bf99d12038afd9409df56119f9d2348ebe93b3689343e24c59e030940c67",
    "src/bombridge/adapters.py": "a3b4d353cb043d0a50e4da61231a99cca289b2255b4d75ef2a234183fee01552",
    "src/bombridge/acquisition.py": "aa5054b7c26a4034f0c3503de380cb0a13e25757482a0278c2ef5b03ad892933",
    "src/bombridge/aibom_bundle.py": "8b6a572e4ed4b23eff412b725b66570015e20a67cfe306d9f9f373787ac71a3a",
    "src/bombridge/cbom_bundle.py": "5bd37e3e3a286c031841464a852e83a2e1c14e2b259d72b41d731aba9861e067",
    "src/bombridge/cryptoscan.py": "79d92b3f21725fd6accb8542ad50722ec2661c3064c717580c111c5cc79ced6f",
    "src/bombridge/cli.py": "dc7f97c6903dc2cc8a4309935a0396bc4941c5deae788d077fcdcffdee081e18",
    "src/bombridge/__main__.py": "935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d",
}

DONOR_FIXTURE_HASHES = {
    "bundles/frigate-v0.18.2-cpu-pilot.json": "27ed6618b5814e4c95c317668b370fcfd536e14a65ed2029a6ae397c7b49b594",
    "bundles/aibom-link-demo.bundle.json": "24e3b74db0fc3dcdbb7e2877a69542dfb26ed09e5bfdb17d1b37a85052db10d6",
    "bundles/viseron-v3.7.0-hailo-detector.json": "5ee26bd0e7937edb8e2b1f8b81f56507f193fb238a4a38f760a48d8cd4b67fee",
    "exports/frigate/frigate-v0.18.2-cpu-pilot.result.json": "c6b60a9d68c37415c449cc0734f591c0ba0ece5bb47e9d6095c85d553bd43dff",
    "exports/illustrative/toy-detector.result.json": "8193cb8ad7181cd1165a10a56b45793db933b4200fe0890f076aa433dcdd5044",
    "exports/illustrative/aibom-link-demo.result.json": "7170b83052f77fab539272199ebfbd88d0f50f3c235ed36d32a07c8f708eab55",
    "exports/viseron/viseron-v3.7.0-hailo-detector.result.json": "32869fe4beb01110d2c24db0a4529799abcfaf2740119da98ff34b584499e7af",
    "fixtures/illustrative/toy-detector.json": "f38586c3d8748c9ca6098c576235055e1d2949ccd64a317ae3dc46fec1bf92d1",
    "fixtures/illustrative/synthetic-mlbom.cdx.json": "8c9acee73ca08ce045c272433f8056168f874375d93046796229be066b1f698c",
    "config/repositories.json": "ccd9a1db1bc9db9719ff45b280c4f4b1ed69b82a9cb8d8d0e90778c25e6d01db",
    "inputs/frigate/raw/syft-source-dir.cdx.json": "b7f24bb62503cfe11a8339a27493029f15da0312c94e9c1a01e76e18f285cee9",
    "inputs/frigate/raw/cdxgen-cbom.cdx.json": "200ca6c7556c5d5ecd918061fc0a15077fe20d6e562ad746da7877ebd3c1b509",
    "inputs/frigate/raw/cisco-aibom.cdx.json": "5d1217e2d3db8ba3d1fb76ff351e236df7e0671c3b629fa7b7c87eaaffe608dd",
    "inputs/frigate/raw/bombridge-crypto-inventory.cdx.json": "edfa6416934747756024139b6f8b7fe905cea502a20e798e2f4b597e59ee06a9",
    "inputs/frigate/aibom-scope.json": "f6ad6426cb28ad23914a9481ee16dcd48cb2ada483748013f47b89493586700e",
    "inputs/frigate/cdxgen-acquisition.json": "659d7bd2dc4c58dcd91f2899513e1c207488d5800726ac1a592c7bfdfd59fdad",
    "inputs/frigate/crypto-acquisition.json": "a5196366a0a18fa9f614dd06704925e4d595631aa86eb8b6147469423540a686",
}

# Export bytes are checked separately from the original donor hashes above. The two raw inputs
# are path-redacted; their related bundles and deterministic results were refreshed from those inputs.
EXPORT_FIXTURE_HASHES = {
    "bundles/frigate-v0.18.2-cpu-pilot.json": "2ff13bd1caa2aa856ac0670b9f7b5b935f5aa548ac8e34f6299a9526faaef86e",
    "bundles/aibom-link-demo.bundle.json": "24e3b74db0fc3dcdbb7e2877a69542dfb26ed09e5bfdb17d1b37a85052db10d6",
    "bundles/viseron-v3.7.0-hailo-detector.json": "b9b79e8993df86b5f391e621c12b3334345e51552892e28eaa00d5539d0b35e0",
    "exports/frigate/frigate-v0.18.2-cpu-pilot.result.json": "c5394af4bfa8f8d0143cec9b9d060a42bd37de2bdef51f76f97f4206901ce64d",
    "exports/illustrative/toy-detector.result.json": "8193cb8ad7181cd1165a10a56b45793db933b4200fe0890f076aa433dcdd5044",
    "exports/illustrative/aibom-link-demo.result.json": "7170b83052f77fab539272199ebfbd88d0f50f3c235ed36d32a07c8f708eab55",
    "exports/viseron/viseron-v3.7.0-hailo-detector.result.json": "8fa992c49add3a3ebbabbcd438c50ddcee281d6f0871425a56b123ca688afc72",
    "fixtures/illustrative/toy-detector.json": "f38586c3d8748c9ca6098c576235055e1d2949ccd64a317ae3dc46fec1bf92d1",
    "fixtures/illustrative/synthetic-mlbom.cdx.json": "8c9acee73ca08ce045c272433f8056168f874375d93046796229be066b1f698c",
    "config/repositories.json": "ccd9a1db1bc9db9719ff45b280c4f4b1ed69b82a9cb8d8d0e90778c25e6d01db",
    "inputs/frigate/raw/syft-source-dir.cdx.json": "8ee39ed7f937158ecc782d5839608079f1750dc9855212c54035b596e03513e7",
    "inputs/frigate/raw/cdxgen-cbom.cdx.json": "200ca6c7556c5d5ecd918061fc0a15077fe20d6e562ad746da7877ebd3c1b509",
    "inputs/frigate/raw/cisco-aibom.cdx.json": "5d1a2885fbd35b67413c8651c84305fef81b9f136d6218b655bd68dedc4526b6",
    "inputs/frigate/raw/bombridge-crypto-inventory.cdx.json": "edfa6416934747756024139b6f8b7fe905cea502a20e798e2f4b597e59ee06a9",
    "inputs/frigate/aibom-scope.json": "f6ad6426cb28ad23914a9481ee16dcd48cb2ada483748013f47b89493586700e",
    "inputs/frigate/cdxgen-acquisition.json": "659d7bd2dc4c58dcd91f2899513e1c207488d5800726ac1a592c7bfdfd59fdad",
    "inputs/frigate/crypto-acquisition.json": "a5196366a0a18fa9f614dd06704925e4d595631aa86eb8b6147469423540a686",
}

# This test was locally adapted to assert the sanitized capture hash and must not be
# compared with the earlier overlay test-file digest in the original provenance record.
EXPORT_TEST_HASHES = {"tests/core/bombridge/test_assess.py": "223b98f9c9f8cb105b81b9edf666b9db1e655b8ad2215787c6c75a925bd5fb1e"}

TEST_DONOR_HASHES = {
    "tests/test_assess.py": "2d4ebe8d1dc9b384beb6b5357471e5979c3b2d49880c5f4a9aa1cf9e79a6bd57",
    "tests/test_requirement_check.py": "2c0cfc0d1ed92769c1d736ccbfb206baf7ea7553fd279fd749f6f735640896e6",
    "tests/test_aibom.py": "cd4a2b91f4ce287256649acda33b36e0102f0ecc87708582ad2ac0e86db0b0f4",
    "tests/test_cbom.py": "6bad707ade32cd2ee154f5bcc9e1d6dd187d46199d6511aaa6fc40e267af78b4",
}


# Imported files OpenTrace has edited since the import. Each must be listed in the manifest's local_changes with its own hash (I5C).
LOCAL_CHANGES = {"src/core/opentrace_core/bombridge/rules.py", "src/core/opentrace_core/bombridge/pipeline.py",
                 "src/core/opentrace_core/bombridge/adapters.py", "src/core/opentrace_core/bombridge/rules_inventory.py"}  # I8 adds adapters and rules_inventory; pipeline gains an I8 change
CHANGE_TASKS = {"rules.py": "I5C, UIP-12", "pipeline.py": "I5C, I8, UIP-12", "adapters.py": "I8", "rules_inventory.py": "I8"}


class Provenance(unittest.TestCase):
    def test_manifest_files_match_recorded_hashes_and_pinned_donor_hashes(self):
        manifest = json.loads(PROVENANCE.read_text())
        self.assertEqual(manifest["donor"], {
            "url": "https://github.com/bikashshah15/BOMBridge",
            "commit": "7195f6eb1743e9fc31368c8234471a268ba51ce4",
        })
        entries = {entry["path"]: entry for entry in manifest["files"]}
        self.assertEqual(len(entries), len(manifest["files"]))
        expected_paths = {f"src/core/opentrace_core/bombridge/{pathlib.Path(path).name}" for path in SOURCE_HASHES}
        expected_paths |= {f"tests/core/bombridge/{pathlib.Path(path).name}" for path in TEST_DONOR_HASHES}
        expected_paths |= {f"tests/core/bombridge/fixtures/{path}" for path in DONOR_FIXTURE_HASHES}
        self.assertEqual(set(entries), expected_paths)
        for path, entry in entries.items():
            actual = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            export_expected = EXPORT_TEST_HASHES.get(path)
            if export_expected is None and path.startswith("tests/core/bombridge/fixtures/"):
                export_expected = EXPORT_FIXTURE_HASHES.get(path.removeprefix("tests/core/bombridge/fixtures/"))
            self.assertEqual(actual, export_expected or entry["sha256"], path)
        for donor_path, expected in SOURCE_HASHES.items():
            entry = entries[f"src/core/opentrace_core/bombridge/{pathlib.Path(donor_path).name}"]
            if entry["path"] in LOCAL_CHANGES:  # recorded OpenTrace edit of an imported file (see local_changes); the donor hash stays pinned
                self.assertEqual((entry["donor_path"], entry["donor_sha256"], entry["kind"], entry["adaptation"]), (donor_path, expected, "source", "local_change"))
                self.assertNotEqual(entry["sha256"], expected)
                continue
            self.assertEqual((entry["donor_path"], entry["donor_sha256"], entry["sha256"], entry["kind"]),
                             (donor_path, expected, expected, "source"))
            self.assertEqual(entry["adaptation"], "none")
        for donor_path, expected in DONOR_FIXTURE_HASHES.items():
            dest = f"tests/core/bombridge/fixtures/{donor_path}"
            entry = entries[dest]
            self.assertEqual((entry["donor_path"], entry["donor_sha256"], entry["sha256"], entry["kind"]),
                             (donor_path, expected, expected, "fixture"))
            self.assertEqual(entry["adaptation"], "none")
            export_sha = EXPORT_FIXTURE_HASHES[donor_path]
            self.assertEqual(hashlib.sha256((ROOT / dest).read_bytes()).hexdigest(), export_sha, dest)
        self.assertNotEqual(EXPORT_FIXTURE_HASHES["inputs/frigate/raw/syft-source-dir.cdx.json"],
                            DONOR_FIXTURE_HASHES["inputs/frigate/raw/syft-source-dir.cdx.json"])
        self.assertNotEqual(EXPORT_FIXTURE_HASHES["inputs/frigate/raw/cisco-aibom.cdx.json"],
                            DONOR_FIXTURE_HASHES["inputs/frigate/raw/cisco-aibom.cdx.json"])
        destinations = {
            "tests/test_assess.py": "tests/core/bombridge/test_assess.py",
            "tests/test_requirement_check.py": "tests/core/bombridge/test_requirement_check.py",
            "tests/test_aibom.py": "tests/core/bombridge/test_aibom.py",
            "tests/test_cbom.py": "tests/core/bombridge/test_cbom.py",
        }
        for donor_path, expected in TEST_DONOR_HASHES.items():
            entry = entries[destinations[donor_path]]
            self.assertEqual(entry["donor_path"], donor_path)
            self.assertEqual(entry["donor_sha256"], expected)
            self.assertEqual(entry["kind"], "test")
            self.assertEqual(entry["adaptation"], "imports+fixture_root+deletions")
        self.assertEqual(manifest["dependency"], {"networkx": "3.4.2"})
        self.assertEqual({c["path"] for c in manifest["local_changes"]}, LOCAL_CHANGES)
        for change in manifest["local_changes"]:
            self.assertEqual(change["donor_sha256"], entries[change["path"]]["donor_sha256"])
            self.assertEqual(change["sha256"], entries[change["path"]]["sha256"])
            self.assertEqual(change["task"], CHANGE_TASKS[pathlib.Path(change["path"]).name])
        self.assertEqual(sorted(f["path"] for f in manifest["opentrace_authored_files"]),
                         ["src/core/opentrace_core/bombridge/discovery.py", "src/core/opentrace_core/bombridge/discovery_crypto.py",
                          "src/core/opentrace_core/bombridge/discovery_models.py", "src/core/opentrace_core/bombridge/rules_cbom3.py", "src/core/opentrace_core/bombridge/rules_cbom4.py"])
        self.assertEqual(manifest["dependency"], {"networkx": "3.4.2"})  # I8 added no dependency
        for path, expected in manifest["overlay_fixtures"].items():  # I8: overlay fixtures are byte-identical to Peiran Shi's captures
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), expected, path)
        self.assertEqual(len(manifest["overlay_fixtures"]), 10)
        self.assertEqual(manifest["donor_overlay"]["credit"].split(" (")[0], "Peiran Shi")
        self.assertEqual(manifest["local_changes"][[c["path"] for c in manifest["local_changes"]].index("src/core/opentrace_core/bombridge/rules_inventory.py")]["overlay_sha256"],
                         entries["src/core/opentrace_core/bombridge/rules_inventory.py"]["sha256"])  # byte-identical to the overlay file
        for f in manifest["opentrace_authored_files"]:
            self.assertTrue((ROOT / f["path"]).is_file())
