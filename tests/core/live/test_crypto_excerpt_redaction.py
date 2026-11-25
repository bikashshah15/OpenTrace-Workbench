"""Stage 4 final correction: crypto excerpts are built from parsed source spans and tokenized; uncertain content is omitted, never patched with regexes.
SYNTHETIC sentinels only (none is a real credential or path)."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from opentrace_core.app import crypto_assets as ca
from opentrace_core.live import crypto_sites, crypto_source as cs, source_declarations as sd

URL = "https://github.com/acme/widget"
SHA = "d" * 40
SENTINELS = ("SENTINEL-SECRET-7", "SENTINEL-PW-8", "/synthetic/sentinel/path.pem", "SENTINEL-TAIL-9", "SENTINEL-CMT-6")


def leaked(value):
    text = repr(value)
    return [s for s in SENTINELS if s in text]


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-xr-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def collect(self, text, rel="m.py"):
        with open(os.path.join(self.root, rel), "w") as h:
            h.write(text)
        out = sd.collect(self.root, URL, SHA)
        self.assertEqual(out["status"], "collected")
        return out["record"]["crypto_source"]


class Redact(unittest.TestCase):
    def test_every_literal_form_is_replaced(self):
        cases = [
            'f(a, "SENTINEL-SECRET-7")', "f(a, 'SENTINEL-SECRET-7')", 'f(a, b"SENTINEL-SECRET-7")', 'f(a, r"SENTINEL-SECRET-7")',
            'f(a, """SENTINEL-SECRET-7\nSENTINEL-PW-8""")', "f(a, '''SENTINEL-SECRET-7\nSENTINEL-PW-8''')",
            'f(a, "x\\"SENTINEL-SECRET-7")', "f(a, 'x\\'SENTINEL-SECRET-7')", 'f(a, "SENTINEL-SECRET-7" "SENTINEL-PW-8")',
            'f(a, f"{b}SENTINEL-SECRET-7{c}")', 'f(a,\n  # SENTINEL-CMT-6\n  "SENTINEL-SECRET-7")', 'f(a, "\\\\", "SENTINEL-SECRET-7")',
            'f(a, "/synthetic/sentinel/path.pem")',
        ]
        for text in cases:
            out = cs._redact(text)
            self.assertIsNotNone(out, text)
            self.assertEqual(leaked(out), [], text)

    def test_only_a_plain_allowed_label_survives(self):
        self.assertEqual(cs._redact('jwt.encode(p, "SENTINEL-SECRET-7", "RS256")', ["RS256"]), 'jwt.encode(p, "…", "RS256")')
        self.assertNotIn("RS256", cs._redact('jwt.encode(p, k, b"RS256")', ["RS256"]))          # prefixed literal is not a plain label
        self.assertEqual(cs._redact('jwt.encode(p, k, "SENTINEL-SECRET-7" "RS256")', ["RS256"]), 'jwt.encode(p, k, "\u2026" "RS256")')   # each token is judged alone
        self.assertNotIn("/synthetic/sentinel/path.pem", cs._redact('f("/synthetic/sentinel/path.pem")', ["/synthetic/sentinel/path.pem"]))   # keep needs the label shape

    def test_uncertain_text_is_omitted(self):
        for text in ['abc"""+ f(a, "SENTINEL-SECRET-7")',             # starts inside a triple-quoted string
                     'x = f(a, "SENTINEL-SECRET-7', "f(a, 'SENTINEL-SE", 'f(a, """SENTINEL-SECRET-7\nmore',      # unterminated / truncated
                     'f(a, "x\\', 'f((a, "b")', 'f(a))', "a\x00b"]:
            self.assertIsNone(cs._redact(text), text)

    def test_stop_at_call_never_examines_the_tail(self):
        out = cs._redact('h(a, "SENTINEL-SECRET-7") + """SENTINEL-TAIL-9', stop_at_call=True)
        self.assertEqual(out, 'h(a, "…")')
        self.assertIsNone(cs._redact('plain_name + "SENTINEL-TAIL-9"', stop_at_call=True))          # no call: nothing safe to show

    def test_every_truncation_boundary_is_safe(self):
        full = 'hashlib.pbkdf2_hmac("sha256", b"SENTINEL-PW-8", f"{x}SENTINEL-SECRET-7", """SENTINEL-TAIL-9\n/synthetic/sentinel/path.pem""") + "SENTINEL-CMT-6"'
        for n in range(len(full) + 1):
            for stop in (True, False):
                self.assertEqual(leaked(cs._redact(full[:n], ["sha256"], stop_at_call=stop)), [], (n, stop))


class HashlibPresentation(Base):
    def test_excerpt_starting_inside_a_string_uses_the_call_column(self):
        text = 's = """SENTINEL-TAIL-9\nSENTINEL-CMT-6""" + hashlib.pbkdf2_hmac("sha256", b"SENTINEL-PW-8", b"SENTINEL-SECRET-7") + "x"\n'
        line2 = text.split("\n")[1]
        col = len(line2.encode()[: line2.index("hashlib")])
        rec = {"excerpt": line2, "col": col, "algorithm": "sha256"}
        out = ca._safe_hashlib_excerpt(rec)
        self.assertEqual(out, 'hashlib.pbkdf2_hmac("sha256", "…", "…")')
        self.assertIsNone(ca._safe_hashlib_excerpt(dict(rec, col=None)))                   # no parsed position: nothing is shown
        self.assertIsNone(ca._safe_hashlib_excerpt(dict(rec, col=10 ** 6)))

    def test_end_to_end_with_the_real_collector_at_every_truncation(self):
        src = ('import hashlib\nbanner = """SENTINEL-TAIL-9\nSENTINEL-CMT-6""" + hashlib.pbkdf2_hmac(\n    "sha256",\n    b"SENTINEL-PW-8",   # SENTINEL-CMT-6\n'
               '    """SENTINEL-SECRET-7\n/synthetic/sentinel/path.pem""", 1000) + "SENTINEL-TAIL-9"\n')
        path = os.path.join(self.root, "h.py")
        with open(path, "w") as h:
            h.write(src)
        shown_any = False
        for limit in list(range(40, 260, 7)) + [2000]:
            with mock.patch.object(crypto_sites, "MAX_EXCERPT", limit):
                phase = crypto_sites.run_phase([("h.py", path)])
            for rec in phase["sites"]:
                out = ca._safe_hashlib_excerpt(rec)
                self.assertEqual(leaked(out), [], limit)
                shown_any = shown_any or out is not None
        self.assertTrue(shown_any)                                          # the full-length excerpt is shown (redacted), not always omitted


class Newlines(Base):
    """FR-01: lines are split as ast counts them; a lone CR must not misalign (line, col) with the physical line."""
    def test_lone_cr_and_mixed_newlines_never_leak(self):
        srcs = [b'import hashlib, jwt\n# SENTINEL-SECRET-7\rh = 1; hashlib.md5(b"z")\nx = "a SENTINEL-SECRET-7 b"\rt = f"{a}SENTINEL-SECRET-7"\rctx.check_hostname = False\x0c\n',
                b'import hashlib\rx = "SENTINEL-SECRET-7"\r\nhashlib.pbkdf2_hmac("sha256", b"SENTINEL-PW-8", b"s")\r',
                b'import jwt\rx = """SENTINEL-TAIL-9\rSENTINEL-CMT-6"""; jwt.encode(p, "SENTINEL-SECRET-7", algorithm="HS256")\r']
        for i, src in enumerate(srcs):
            path = os.path.join(self.root, "n%d.py" % i)
            with open(path, "wb") as h:
                h.write(src)
            phase = crypto_sites.run_phase([("n%d.py" % i, path)])
            for rec in phase["sites"]:
                self.assertEqual(leaked(ca._safe_hashlib_excerpt(rec)), [], i)
            self.assertEqual(leaked(self.collect(src.decode(), "m%d.py" % i)), [], i)

    def test_a_tail_that_is_not_the_call_is_omitted(self):
        self.assertIsNone(ca._safe_hashlib_excerpt({"excerpt": 'SENTINEL-SECRET-7 "x" + h(1)', "col": 0, "algorithm": "md5"}))


class Labels(unittest.TestCase):
    def test_only_known_algorithm_names_survive(self):
        self.assertIn("HS256", cs._redact('jwt.encode(p, k, algorithm="HS256")', ["HS256"]))
        out = cs._redact('jwt.encode(p, k, algorithm="SENTINEL-TAIL-9")', ["SENTINEL-TAIL-9"])
        self.assertEqual(leaked(out), [])

    def test_the_defensive_second_pass_omits_uncertain_text(self):
        self.assertIsNone(ca._final_excerpt({"excerpt": 'jwt.encode(p, "SENTINEL-SE'}))
        self.assertEqual(ca._final_excerpt({"excerpt": 'jwt.encode(p, "\u2026", algorithm="RS256")', "algorithms": ["RS256"]}), 'jwt.encode(p, "\u2026", algorithm="RS256")')


class JwtTlsSpans(Base):
    def test_multiline_and_after_a_multiline_string(self):
        text = ('import jwt\nimport ssl\nbanner = """SENTINEL-TAIL-9\nSENTINEL-CMT-6""" + jwt.encode(p, "SENTINEL-SECRET-7", algorithm="RS256") + "z"\n'
                'tok = jwt.decode(\n    t,\n    """SENTINEL-SECRET-7\nSENTINEL-PW-8""",   # SENTINEL-CMT-6\n    algorithms=["HS256"],\n)\n'
                'ctx = ssl.create_default_context(cafile="/synthetic/sentinel/path.pem", cadata=b"SENTINEL-PW-8")\n')
        a = self.collect(text)
        self.assertEqual(len(a["jwt"]), 2)
        self.assertEqual(leaked(a), [])
        self.assertEqual(a["jwt"][0]["excerpt"], 'jwt.encode(p, "…", algorithm="RS256")')       # the span starts at the call, not at the earlier string
        self.assertIn('algorithms=["HS256"]', a["jwt"][1]["excerpt"])

    def test_escapes_and_prefixes_inside_calls(self):
        text = ('import jwt\njwt.encode(p, "a\\"SENTINEL-SECRET-7", algorithm="HS256")\njwt.encode(p, \'x\\\'SENTINEL-PW-8\', algorithm="HS256")\n'
                'jwt.encode(p, f"{k}SENTINEL-PW-8" "SENTINEL-SECRET-7", algorithm="HS256")\njwt.encode(p, rb"/synthetic/sentinel/path.pem", algorithm="HS256")\n')
        a = self.collect(text)
        self.assertEqual(len(a["jwt"]), 4)
        self.assertEqual(leaked(a), [])

    def test_long_excerpt_is_bounded_and_safe(self):
        text = "import jwt\njwt.encode(p, " + ", ".join('"SENTINEL-SECRET-7"' for _ in range(200)) + ', algorithm="HS256")\n'
        a = self.collect(text)
        self.assertEqual(leaked(a), [])
        self.assertLessEqual(len(a["jwt"][0]["excerpt"] or ""), cs.MAX_EXCERPT)


if __name__ == "__main__":
    unittest.main()
