import unittest

from opentrace_core.intake.url import IntakeError, parse_manual_sha, parse_repository_url


class UrlTest(unittest.TestCase):
    def code(self, text, expected):
        with self.assertRaises(IntakeError) as caught:
            parse_repository_url(text)
        self.assertEqual(caught.exception.code, expected)

    def test_root_tree_and_git_suffix(self):
        a = parse_repository_url(" https://github.com/blakeblackshear/frigate ")
        b = parse_repository_url("https://github.com/blakeblackshear/frigate.git/")
        self.assertEqual(a.name, "frigate")
        self.assertEqual(a.canonical_url, b.canonical_url)
        self.assertIsNone(a.tree_segments)
        self.assertEqual(parse_repository_url("https://github.com/a/b.git/tree/main").name, "b")

    def test_C7_repository_suffix_is_removed_once(self):
        self.assertEqual(parse_repository_url("https://github.com/a/a.git.git").name, "a.git")

    def test_tree_decodes_once_and_preserves_slash_branch(self):
        p = parse_repository_url("https://github.com/a/b/tree/feature/a-b")
        self.assertEqual(p.tree_segments, ("feature", "a-b"))
        self.assertEqual(parse_repository_url("https://github.com/a/b/tree/feature%2Fa-b").tree_segments, ("feature/a-b",))

    def test_C4_non_integer_and_prohibited_numeric_ports_are_controlled_errors(self):
        for url in ("https://github.com:abc/a/b", "https://github.com:443/a/b", "https://github.com:99999/a/b"):
            with self.subTest(url=url), self.assertRaises(IntakeError) as caught:
                parse_repository_url(url)
            self.assertEqual(caught.exception.code, "port_not_allowed")
            self.assertEqual(caught.exception.field, "url")

    def test_R1_R3_R4_R5_R6_R7_R21_named_codes(self):
        cases = [
            ("R1", "http://github.com/a/b", "not_https"),
            ("R3", "https://gitlab.com/a/b", "host_not_github"),
            ("R3", "https://www.github.com/a/b", "host_not_github"),
            ("R4", "https://github.com/a/b?tab=x", "query_or_fragment_not_allowed"),
            ("R4", "https://github.com/a/b#x", "query_or_fragment_not_allowed"),
            ("R5", "https://github.com/a/b/blob/main/x", "unsupported_route"),
            ("R5", "https://github.com/a/b/commit/abcdef0123456", "unsupported_route"),
            ("R6", "https://github.com/-a/b", "malformed_owner"),
            ("R6", "https://github.com/a/..", "malformed_repository"),
            ("R6", "https://github.com/a/b/tree/..", "malformed_reference"),
            ("R7", "https://github.com/a/b/tree/s1/s2/s3/s4/s5/s6/s7/s8/s9", "too_many_segments"),
            ("R21", "https://github.com/a/b/tree/a..b", "malformed_reference"),
            ("R21", "https://github.com/a/b/tree/x.lock", "malformed_reference"),
            ("R21", "https://github.com/a/b/tree/a~1", "malformed_reference"),
            ("R21", "https://github.com/a/b/tree/%GG", "malformed_reference"),
        ]
        for case, text, expected in cases:
            with self.subTest(case=case, text=text):
                self.code(text, expected)

    def test_R2_credentials_redacted_and_R19_manual_sha_codes(self):
        with self.assertRaises(IntakeError) as caught:
            parse_repository_url("https://user:tok@github.com/a/b")
        self.assertNotIn("tok", str(caught.exception))
        self.assertEqual(parse_manual_sha("CFA08C5"), "cfa08c5")
        self.assertIsNone(parse_manual_sha("  "))
        for value in ("xyz", "abc12"):
            with self.subTest(case="R19", value=value):
                with self.assertRaises(IntakeError) as error:
                    parse_manual_sha(value)
                self.assertEqual(error.exception.code, "manual_sha_malformed")
                self.assertEqual(error.exception.field, "manual_sha")


if __name__ == "__main__":
    unittest.main()
