"""Stage 4 increment B (contract S4-CRYPTO-SOURCE v1.0.0): the bounded static JWT / TLS-configuration collector. SYNTHETIC trees only; nothing runs."""
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from opentrace_core.live import crypto_source as cs, source_declarations as sd

URL = "https://github.com/acme/widget"
SHA = "d" * 40


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-cx-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def src(self, files, **kw):
        for rel, data in files.items():
            path = os.path.join(self.root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as h:
                h.write(data if isinstance(data, bytes) else data.encode())
        out = sd.collect(self.root, URL, SHA, **kw)
        self.assertEqual(out["status"], "collected")
        return out["record"]["crypto_source"], out


class Jwt(Base):
    def test_encode_decode_literals(self):
        a, _ = self.src({"auth/t.py": 'import jwt\nt = jwt.encode(p, k, algorithm="HS256")\nc = jwt.decode(t, k, algorithms=["HS256", "RS256"])\n'})
        self.assertEqual([(o["call"], o["algorithms"], o["algorithm_source"], o["line"]) for o in a["jwt"]],
                         [("jwt.encode", ["HS256"], "literal", 2), ("jwt.decode", ["HS256", "RS256"], "literal", 3)])
        self.assertEqual(a["jwt"][0]["path"], "auth/t.py")
        self.assertEqual(len(a["jwt"][0]["file_sha256"]), 64)

    def test_not_stated_and_dynamic_are_not_guessed(self):
        a, _ = self.src({"t.py": 'import jwt\njwt.encode(p, k)\njwt.decode(t, k, algorithms=ALGS)\njwt.encode(p, k, algorithm=alg)\n'})
        self.assertEqual([(o["algorithm_source"], o["algorithms"]) for o in a["jwt"]], [("not_stated", None), ("dynamic", None), ("dynamic", None)])

    def test_alias_and_from_import(self):
        a, _ = self.src({"a.py": 'import jwt as J\nJ.encode(p, k, algorithm="HS512")\n', "b.py": 'from jwt import decode as dec\ndec(t, k, algorithms=("ES256",))\n'})
        self.assertEqual(sorted((o["path"], o["algorithms"][0]) for o in a["jwt"]), [("a.py", "HS512"), ("b.py", "ES256")])

    def test_unbound_or_rebound_or_other_object_emit_nothing(self):
        cases = {
            "no_import": 'jwt.encode(p, k, algorithm="HS256")\n',
            "other_module": 'import json\njson.encode(p)\nfoo.encode(p, algorithm="HS256")\n',
            "rebound": 'import jwt\njwt = other()\njwt.encode(p, k, algorithm="HS256")\n',
            "method_on_instance": 'import jwt\nj = jwt.PyJWT()\nj.encode(p, k, algorithm="HS256")\n',
            "other_from": 'from jwt import PyJWT\nPyJWT().encode(p, k, algorithm="HS256")\n',
            "relative": 'from .jwt import encode\nencode(p, algorithm="HS256")\n',
        }
        for name, text in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.root)
                os.makedirs(self.root)
                a, _ = self.src({"x.py": text})
                self.assertEqual(a["jwt"], [], name)

    def test_none_algorithm_is_just_a_literal(self):
        a, _ = self.src({"t.py": 'import jwt\njwt.decode(t, k, algorithms=["none"])\n'})
        self.assertEqual(a["jwt"][0]["algorithms"], ["none"])
        self.assertNotIn("vulnerab", repr(a).lower())


class JwtReview(Base):
    def test_positional_kwargs_empty_and_redaction(self):
        text = ("import jwt\njwt.encode(p, 'hunter2-secret', 'RS256')\njwt.encode(p, k, **opts)\njwt.decode(t, k, algorithms=[])\n"
                "jwt.decode(t, k, ['ES256'])\n")
        a, _ = self.src({"t.py": text})
        got = [(o["call"], o["algorithms"], o["algorithm_source"]) for o in a["jwt"]]
        self.assertEqual(got, [("jwt.encode", ["RS256"], "literal"), ("jwt.encode", None, "dynamic"), ("jwt.decode", None, "empty"),
                               ("jwt.decode", ["ES256"], "literal")])
        self.assertNotIn("hunter2", repr(a))
        self.assertIn("RS256", a["jwt"][0]["excerpt"])

    def test_tls_excerpt_redacts_paths_and_passwords(self):
        a, _ = self.src({"m.py": 'import paho.mqtt.client as mqtt\nc.tls_set(ca_certs="/etc/ssl/ca.pem", keyfile_password="pw1")\n'})
        self.assertNotIn("ca.pem", repr(a))
        self.assertNotIn("pw1", repr(a))

    def test_check_hostname_needs_a_uniquely_bound_ssl_alias(self):
        a, _ = self.src({"a.py": "import ssl\nssl = None\nctx.check_hostname = False\n"})
        self.assertEqual(a["tls"], [])


class Tls(Base):
    def test_mqtt_forms_need_a_paho_import(self):
        a, _ = self.src({"m.py": 'import paho.mqtt.client as mqtt\nc = mqtt.Client()\nc.tls_set(ca)\nc.tls_insecure_set(True)\nc.tls_insecure_set(flag)\n'})
        self.assertEqual([(o["setting"], o["value"], o["line"]) for o in a["tls"]], [("tls_set", None, 3), ("tls_insecure_set", "True", 4), ("tls_insecure_set", None, 5)])
        shutil.rmtree(self.root)
        os.makedirs(self.root)
        b, _ = self.src({"n.py": 'c.tls_set(ca)\nc.tls_insecure_set(True)\n'})
        self.assertEqual(b["tls"], [])

    def test_ssl_forms(self):
        text = ('import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE\n'
                'ctx.minimum_version = ssl.TLSVersion.TLSv1_2\nold = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nctx.verify_mode = mode\nctx.check_hostname = x\n')
        a, _ = self.src({"s.py": text})
        self.assertEqual([(o["setting"], o["value"]) for o in a["tls"]],
                         [("create_default_context", None), ("check_hostname", "False"), ("verify_mode", "CERT_NONE"), ("minimum_version", "TLSVersion.TLSv1_2"),
                          ("SSLContext", "PROTOCOL_TLS_CLIENT")])

    def test_ssl_forms_need_an_ssl_import_and_unique_binding(self):
        a, _ = self.src({"a.py": 'ctx.check_hostname = False\nssl.create_default_context()\n', "b.py": 'import ssl\nssl = fake\nssl.create_default_context()\n'})
        self.assertEqual(a["tls"], [])

    def test_no_secrets_copied_beyond_excerpt_of_call(self):
        a, _ = self.src({"m.py": 'import paho.mqtt.client as mqtt\nc.tls_set(ca_certs="/etc/ssl/ca.pem")\n'})
        self.assertEqual(len(a["tls"]), 1)
        self.assertNotIn("ca.pem", repr(a))


class Bounds(Base):
    def test_cancel(self):
        with open(os.path.join(self.root, "a.py"), "w") as h:
            h.write("import jwt\n")
        ev = threading.Event()
        ev.set()
        self.assertEqual(sd.collect(self.root, URL, SHA, cancel=ev)["status"], "cancelled")
        self.assertIsNone(cs.run_phase([("a.py", os.path.join(self.root, "a.py"))], cancel=ev))

    def test_incomplete_never_exact(self):
        a, _ = self.src({"bad.py": "def (:\n", "ok.py": "import jwt\njwt.encode(p,k,algorithm='HS256')\n"})
        self.assertFalse(a["summary"]["complete"])
        self.assertEqual(a["summary"]["count_kind"], "at_least")
        self.assertEqual(len(a["jwt"]), 1)

    def test_cap(self):
        with mock.patch.object(cs, "MAX_JWT", 1):
            a, _ = self.src({"a.py": "import jwt\njwt.encode(p,k,algorithm='HS256')\njwt.encode(p,k,algorithm='HS256')\n"})
        self.assertEqual((len(a["jwt"]), a["summary"]["over_limit"]["jwt"], a["summary"]["complete"]), (1, 1, False))

    def test_deterministic_and_relative(self):
        files = {"z/a.py": "import jwt\njwt.encode(p,k,algorithm='HS256')\n", "a/b.py": "import ssl\nssl.create_default_context()\n"}
        a1, _ = self.src(files)
        a2 = sd.collect(self.root, URL, SHA)["record"]["crypto_source"]
        self.assertEqual(a1, a2)
        self.assertNotIn(self.root, repr(a1))


if __name__ == "__main__":
    unittest.main()
