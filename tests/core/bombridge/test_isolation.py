import ast
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
CORE = ROOT / "src/core"
PACKAGE_ROOT = CORE / "opentrace_core/bombridge"
CORE_INIT = CORE / "opentrace_core/__init__.py"
DONOR = pathlib.Path.home() / "Desktop/Projects/BOMBridge"


def _under(path, roots):
    return any(path == root or root in path.parents for root in roots)


def _module_origin_allowed(
    name,
    origin,
    *,
    package_root,
    core_init,
    stdlib_roots,
    purelib_roots,
    platlib_roots,
    networkx_roots,
):
    """Classify an origin using both its module namespace and its resolved filesystem root."""
    if not origin:
        return False
    path = pathlib.Path(origin).resolve()
    package_roots = (pathlib.Path(package_root).resolve(),)
    core_init = pathlib.Path(core_init).resolve()
    stdlib_roots = tuple(pathlib.Path(root).resolve() for root in stdlib_roots)
    site_roots = tuple(pathlib.Path(root).resolve() for root in (*purelib_roots, *platlib_roots))
    networkx_roots = tuple(pathlib.Path(root).resolve() for root in networkx_roots)

    # Reserved namespaces require their actual package roots. Names and path fragments alone
    # never grant an exception, even when site-packages is nested below stdlib in a venv.
    if name == "opentrace_core":
        return path == core_init
    if name == "opentrace_core.bombridge" or name.startswith("opentrace_core.bombridge."):
        return _under(path, package_roots)
    if name == "networkx" or name.startswith("networkx."):
        return _under(path, networkx_roots)

    # Reject other module names originating in allowed package roots.
    if _under(path, package_roots) or _under(path, networkx_roots) or path == core_init:
        return False

    # Site-package roots must be classified before stdlib because a venv can nest them.
    if _under(path, site_roots):
        return False
    return _under(path, tuple(pathlib.Path(root).resolve() for root in stdlib_roots))



class ImportIsolation(unittest.TestCase):
    def test_pipeline_import_uses_only_opentrace_stdlib_and_networkx(self):
        script = r'''
import importlib.util, json, pathlib, sys, sysconfig
from tests.core.bombridge.test_isolation import _module_origin_allowed
paths = sysconfig.get_paths()
nx_spec = importlib.util.find_spec("networkx")
roots = {
    "package_root": pathlib.Path.cwd() / "src/core/opentrace_core/bombridge",
    "core_init": pathlib.Path.cwd() / "src/core/opentrace_core/__init__.py",
    "stdlib_roots": (paths["stdlib"], paths["platstdlib"]),
    "purelib_roots": (paths["purelib"],),
    "platlib_roots": (paths["platlib"],),
    "networkx_roots": tuple(nx_spec.submodule_search_locations or ()) if nx_spec else (),
}
before = set(sys.modules)
import opentrace_core.bombridge.pipeline
allowed, violations = [], []
for name in sorted(set(sys.modules) - before):
    module = sys.modules.get(name)
    source = getattr(module, "__file__", None)
    if not source:
        continue
    if _module_origin_allowed(name, source, **roots):
        allowed.append((name, str(pathlib.Path(source).resolve())))
    else:
        violations.append((name, str(pathlib.Path(source).resolve())))
print(json.dumps({"allowed": allowed, "violations": violations, "sys_path": sys.path}))
'''
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(CORE)},
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["violations"], [])
        self.assertTrue(any(name == "opentrace_core.bombridge.pipeline" for name, _ in report["allowed"]))
        self.assertNotIn(str(DONOR.resolve()), [str(pathlib.Path(p).resolve()) for p in report["sys_path"]])

    def test_standalone_package_is_not_importable(self):
        self.assertIsNone(importlib.util.find_spec("bombridge"))

    def test_imported_module_sources_have_no_absolute_bombridge_imports_or_donor_paths(self):
        tests = ROOT / "tests/core/bombridge"
        donor_text = str(DONOR)
        for path in list(PACKAGE_ROOT.rglob("*.py")) + list(tests.rglob("*.py")):
            text = path.read_text()
            self.assertNotIn(donor_text, text, str(path))
            tree = ast.parse(text, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(alias.name == "bombridge" or alias.name.startswith("bombridge."), f"{path}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    self.assertFalse(node.module == "bombridge" or node.module.startswith("bombridge."), f"{path}:{node.lineno}")


class OriginClassifierRejectionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        # Model the common venv layout where site-packages is inside the stdlib root.
        self.stdlib = self.root / "venv/lib/python3.12"
        self.purelib = self.stdlib / "site-packages"
        self.platlib = self.purelib
        self.package = self.root / "checkout/src/core/opentrace_core/bombridge"
        self.core_init = self.root / "checkout/src/core/opentrace_core/__init__.py"
        self.networkx = self.purelib / "networkx"
        self.roots = {
            "package_root": self.package,
            "core_init": self.core_init,
            "stdlib_roots": (self.stdlib,),
            "purelib_roots": (self.purelib,),
            "platlib_roots": (self.platlib,),
            "networkx_roots": (self.networkx,),
        }

    def test_unexpected_third_party_under_nested_site_packages_is_rejected(self):
        path = self.purelib / "surprise_pkg/__init__.py"
        self.assertFalse(_module_origin_allowed("surprise_pkg", path, **self.roots))

    def test_allowed_names_and_path_fragments_need_their_real_roots(self):
        cases = (
            ("networkx.untrusted", self.stdlib / "networkx/untrusted.py"),
            ("networkx", self.root / "other/networkx/__init__.py"),
            ("opentrace_core.bombridge.pipeline", self.root / "lookalike/opentrace_core/bombridge/pipeline.py"),
            ("unrelated", self.root / "lookalike/opentrace_core/bombridge/unrelated.py"),
        )
        for name, path in cases:
            with self.subTest(name=name, path=path):
                self.assertFalse(_module_origin_allowed(name, path, **self.roots))

    def test_expected_roots_and_standard_library_are_allowed(self):
        cases = (
            ("opentrace_core.bombridge.pipeline", self.package / "pipeline.py"),
            ("opentrace_core", self.core_init),
            ("networkx.algorithms", self.networkx / "algorithms/__init__.py"),
            ("json", self.stdlib / "json/__init__.py"),
        )
        for name, path in cases:
            with self.subTest(name=name, path=path):
                self.assertTrue(_module_origin_allowed(name, path, **self.roots))
