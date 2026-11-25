import json
import os
import unittest
from datetime import datetime, timedelta, timezone

from opentrace_core.intake.resolve import Response, resolve
from opentrace_core.intake.url import IntakeError, parse_manual_sha, parse_repository_url


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "resolution_cases.json")
with open(FIXTURE, encoding="utf-8") as stream:
    SYNTHETIC = json.load(stream)
assert SYNTHETIC["_synthetic"] is True
SHA = SYNTHETIC["commit"]
SHA2 = "1" * 40


def ref(refname, sha=SHA, kind="commit"):
    return {"ref": refname, "object": {"type": kind, "sha": sha}}


def repo(status=200, body=None, location=None):
    return Response(status, body or SYNTHETIC["repository"], location)


def transport_for(mapping):
    def transport(path):
        return mapping.get(path, Response(404, None))
    return transport


def base():
    return {"/repos/blakeblackshear/frigate": repo()}


def run_tree(url, refs=None, commits=None, manual=None):
    mapping = base()
    mapping.update(refs or {})
    mapping.update(commits or {})
    return resolve(parse_repository_url(url), manual, transport_for(mapping),
                   now=lambda: datetime(2026, 11, 4, 22, 0, tzinfo=timezone.utc))


class ResolveTest(unittest.TestCase):
    def test_S1_default_branch_and_S2_git_canonicalization(self):
        mapping = base()
        mapping["/repos/blakeblackshear/frigate/git/ref/heads/dev"] = Response(200, ref("refs/heads/dev"))
        for url in ("https://github.com/blakeblackshear/frigate", "https://github.com/blakeblackshear/frigate.git/"):
            result = resolve(parse_repository_url(url), None, transport_for(mapping), now=lambda: "2026-11-04T22:00:00Z")
            self.assertEqual(result.requested["kind"], "default_branch")
            self.assertEqual(result.commit_sha, SHA)
            self.assertEqual(result.basis, "default_branch_at_resolution")
            self.assertEqual(result.default_branch, "dev")
            self.assertEqual(result.canonical_url, "https://github.com/blakeblackshear/frigate")

    def test_S3_annotated_tag_is_peeled(self):
        url = "https://github.com/blakeblackshear/frigate/tree/v0.18.2"
        mapping = base()
        mapping["/repos/blakeblackshear/frigate/git/ref/tags/v0.18.2"] = Response(200, ref("refs/tags/v0.18.2", "2" * 40, "tag"))
        mapping["/repos/blakeblackshear/frigate/git/tags/" + "2" * 40] = Response(200, {"object": {"type": "commit", "sha": SHA}})
        result = run_tree(url, mapping)
        self.assertEqual(result.requested["kind"], "tag")
        self.assertEqual(result.commit_sha, SHA)

    def test_S4_slash_branch_exact(self):
        result = run_tree("https://github.com/blakeblackshear/frigate/tree/feature/a-b", {
            "/repos/blakeblackshear/frigate/git/ref/heads/feature/a-b": Response(200, ref("refs/heads/feature/a-b"))
        })
        self.assertEqual(result.requested["kind"], "branch")
        self.assertEqual(result.requested["text"], "feature/a-b")

    def test_S5_exact_full_sha_and_S6_short_sha(self):
        full = run_tree("https://github.com/blakeblackshear/frigate/tree/" + SHA, commits={
            "/repos/blakeblackshear/frigate/commits/" + SHA: Response(200, {"sha": SHA})})
        self.assertEqual((full.requested["kind"], full.commit_sha), ("commit", SHA))
        short = run_tree("https://github.com/blakeblackshear/frigate/tree/cfa08c5", commits={
            "/repos/blakeblackshear/frigate/commits/cfa08c5": Response(200, {"sha": SHA})})
        self.assertEqual(short.commit_sha, SHA)

    def test_S7_manual_and_S8_corroborated(self):
        root = parse_repository_url("https://github.com/blakeblackshear/frigate")
        manual = parse_manual_sha(SHA.upper())
        self.assertEqual(manual, SHA)
        result = resolve(root, manual, transport_for({**base(),
            "/repos/blakeblackshear/frigate/commits/" + SHA: Response(200, {"sha": SHA})}), now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual(result.requested["origin"], "advanced_manual")
        self.assertEqual(result.requested["text"], SHA)
        mapping = {"/repos/blakeblackshear/frigate/git/ref/heads/main": Response(200, ref("refs/heads/main")),
                   "/repos/blakeblackshear/frigate/commits/" + SHA: Response(200, {"sha": SHA})}
        corroborated = run_tree("https://github.com/blakeblackshear/frigate/tree/main", mapping, manual=SHA)
        self.assertTrue(corroborated.manual_corroboration)
        self.assertEqual(corroborated.requested["origin"], "url_tree")

    def test_S9_git_suffix_tree_route(self):
        p = parse_repository_url("https://github.com/a/b.git/tree/main")
        mapping = {"/repos/a/b": Response(200, {"full_name": "a/b", "default_branch": "main"}),
                   "/repos/a/b/git/ref/heads/main": Response(200, ref("refs/heads/main"))}
        result = resolve(p, None, transport_for(mapping), now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual(result.name, "b")
        self.assertEqual(result.requested["kind"], "branch")

    def assert_code(self, expected, url, refs=None, commits=None, manual=None):
        with self.assertRaises(IntakeError) as caught:
            run_tree(url, refs, commits, manual)
        self.assertEqual(caught.exception.code, expected)
        return str(caught.exception)

    def test_R8_suffix_R9_and_R10_ambiguity(self):
        msg = self.assert_code("path_suffix_not_supported", "https://github.com/blakeblackshear/frigate/tree/feature/x/y", {
            "/repos/blakeblackshear/frigate/git/ref/heads/feature/x": Response(200, ref("refs/heads/feature/x"))})
        self.assertIn("feature/x", msg)
        self.assertIn("y", msg)
        msg = self.assert_code("ambiguous_reference", "https://github.com/blakeblackshear/frigate/tree/release", {
            "/repos/blakeblackshear/frigate/git/ref/heads/release": Response(200, ref("refs/heads/release")),
            "/repos/blakeblackshear/frigate/git/ref/tags/release": Response(200, ref("refs/tags/release"))})
        self.assertIn("branch release", msg)
        self.assertIn("tag release", msg)
        self.assertIn("manual commit SHA", msg)
        self.assert_code("ambiguous_reference", "https://github.com/blakeblackshear/frigate/tree/rel/1", {
            "/repos/blakeblackshear/frigate/git/ref/tags/rel": Response(200, ref("refs/tags/rel")),
            "/repos/blakeblackshear/frigate/git/ref/heads/rel/1": Response(200, ref("refs/heads/rel/1"))})

    def test_R11_R12_R13_named_outcomes(self):
        self.assert_code("reference_not_found", "https://github.com/blakeblackshear/frigate/tree/nope")
        self.assert_code("short_sha_unresolved", "https://github.com/blakeblackshear/frigate/tree/abc1234",
                         commits={"/repos/blakeblackshear/frigate/commits/abc1234": Response(422, {})})
        msg = self.assert_code("revision_conflict", "https://github.com/blakeblackshear/frigate/tree/main", {
            "/repos/blakeblackshear/frigate/git/ref/heads/main": Response(200, ref("refs/heads/main"))},
            {"/repos/blakeblackshear/frigate/commits/" + SHA2: Response(200, {"sha": SHA2})}, SHA2)
        self.assertIn(SHA, msg)
        self.assertIn(SHA2, msg)

    def test_C2_full_tree_sha_separates_missing_from_retryable_failures(self):
        url = "https://github.com/blakeblackshear/frigate/tree/" + SHA
        path = "/repos/blakeblackshear/frigate/commits/" + SHA
        for status in (404, 422):
            with self.subTest(status=status), self.assertRaises(IntakeError) as caught:
                run_tree(url, commits={path: Response(status, None)})
            self.assertEqual((caught.exception.code, caught.exception.field), ("reference_not_found", "revision"))
        for status in (403, 429, 500, 503, 302):
            with self.subTest(status=status), self.assertRaises(IntakeError) as caught:
                run_tree(url, commits={path: Response(status, None)})
            self.assertEqual((caught.exception.code, caught.exception.field), ("resolution_unavailable", "revision"))
        for body in ({}, {"sha": "not-a-sha"}, {"sha": SHA2}):
            with self.subTest(body=body), self.assertRaises(IntakeError) as caught:
                run_tree(url, commits={path: Response(200, body)})
            self.assertEqual((caught.exception.code, caught.exception.field), ("resolution_unavailable", "revision"))
        def broken(path):
            if path == "/repos/blakeblackshear/frigate": return repo()
            raise OSError("synthetic transport failure")
        with self.assertRaises(IntakeError) as caught:
            resolve(parse_repository_url(url), None, broken, now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual((caught.exception.code, caught.exception.field), ("resolution_unavailable", "revision"))

    def test_C3_full_manual_sha_uses_manual_field_for_lookup_outcomes(self):
        parsed = parse_repository_url("https://github.com/blakeblackshear/frigate")
        path = "/repos/blakeblackshear/frigate/commits/" + SHA
        for status, code in ((404, "reference_not_found"), (422, "reference_not_found"),
                             (503, "resolution_unavailable")):
            with self.subTest(status=status), self.assertRaises(IntakeError) as caught:
                resolve(parsed, SHA, transport_for({**base(), path: Response(status, None)}),
                        now=lambda: "2026-11-04T22:00:00Z")
            self.assertEqual((caught.exception.code, caught.exception.field), (code, "manual_sha"))
        for body in ({}, {"sha": SHA2}):
            with self.subTest(body=body), self.assertRaises(IntakeError) as caught:
                resolve(parsed, SHA, transport_for({**base(), path: Response(200, body)}),
                        now=lambda: "2026-11-04T22:00:00Z")
            self.assertEqual((caught.exception.code, caught.exception.field), ("resolution_unavailable", "manual_sha"))
        def broken(path):
            if path == "/repos/blakeblackshear/frigate": return repo()
            raise OSError("synthetic transport failure")
        with self.assertRaises(IntakeError) as caught:
            resolve(parsed, SHA, broken, now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual((caught.exception.code, caught.exception.field), ("resolution_unavailable", "manual_sha"))

    def test_R14_R15_R16_repo_gates_and_no_redirect_follow(self):
        for response, code in ((Response(404), "unavailable"), (Response(403), "resolution_unavailable"),
                               (Response(429), "resolution_unavailable"), (Response(503), "resolution_unavailable")):
            with self.assertRaises(IntakeError) as caught:
                resolve(parse_repository_url("https://github.com/a/b"), None, transport_for({"/repos/a/b": response}), now=lambda: "2026-11-04T22:00:00Z")
            self.assertEqual(caught.exception.code, code)
        called = []
        def moved(path):
            called.append(path)
            return Response(301, {}, "https://github.com/new/name")
        with self.assertRaises(IntakeError) as caught:
            resolve(parse_repository_url("https://github.com/a/b"), None, moved, now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual(caught.exception.code, "repository_moved")
        self.assertEqual(called, ["/repos/a/b"])
        self.assertIn("new/name", str(caught.exception))

    def test_R17_list_ref_is_no_match_R18_budget_R20_exact_sha_missing(self):
        self.assert_code("reference_not_found", "https://github.com/blakeblackshear/frigate/tree/main", {
            "/repos/blakeblackshear/frigate/git/ref/heads/main": Response(200, [ref("refs/heads/main")])})
        mapping = base()
        for k in range(8, 0, -1):
            name = "/".join("s{}".format(i) for i in range(1, k + 1))
            mapping["/repos/blakeblackshear/frigate/git/ref/heads/" + name] = Response(200, ref("refs/heads/" + name, "2" * 40, "tag"))
        mapping["/repos/blakeblackshear/frigate/git/tags/" + "2" * 40] = Response(200, {"object": {"type": "commit", "sha": SHA}})
        self.assert_code("budget_exceeded", "https://github.com/blakeblackshear/frigate/tree/s1/s2/s3/s4/s5/s6/s7/s8", mapping)
        self.assert_code("reference_not_found", "https://github.com/blakeblackshear/frigate/tree/" + SHA, commits={
            "/repos/blakeblackshear/frigate/commits/" + SHA: Response(404, None)})

    def test_C8_exact_20_calls_succeed_and_21st_is_not_sent(self):
        segments = ["s{}".format(i) for i in range(1, 9)]
        full_ref = "/".join(segments)
        root = "/repos/blakeblackshear/frigate"
        mapping = base()
        mapping[root + "/git/ref/tags/" + full_ref] = Response(200, ref("refs/tags/" + full_ref, "a" * 40, "tag"))
        mapping[root + "/git/tags/" + "a" * 40] = Response(200, {"object": {"type": "tag", "sha": "b" * 40}})
        mapping[root + "/git/tags/" + "b" * 40] = Response(200, {"object": {"type": "commit", "sha": SHA}})
        mapping[root + "/commits/" + SHA] = Response(200, {"sha": SHA})
        calls = []
        def transport(path):
            calls.append(path)
            return mapping.get(path, Response(404, None))
        result = resolve(parse_repository_url("https://github.com/blakeblackshear/frigate/tree/" + full_ref),
                         SHA, transport, now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual(result.calls, 20)
        self.assertEqual(len(calls), 20)
        self.assertEqual(result.commit_sha, SHA)

        mapping[root + "/git/ref/tags/" + "/".join(segments[:7])] = Response(
            200, ref("refs/tags/" + "/".join(segments[:7]), "c" * 40, "tag"))
        mapping[root + "/git/tags/" + "c" * 40] = Response(200, {"object": {"type": "tag", "sha": "d" * 40}})
        mapping[root + "/git/tags/" + "d" * 40] = Response(200, {"object": {"type": "commit", "sha": SHA2}})
        calls.clear()
        with self.assertRaises(IntakeError) as caught:
            resolve(parse_repository_url("https://github.com/blakeblackshear/frigate/tree/" + full_ref),
                    None, transport, now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual((caught.exception.code, caught.exception.field), ("budget_exceeded", "revision"))
        self.assertEqual(len(calls), 20)

    def test_transport_exception_is_retryable(self):
        def offline(_): raise OSError("offline")
        with self.assertRaises(IntakeError) as caught:
            resolve(parse_repository_url("https://github.com/a/b"), None, offline, now=lambda: "2026-11-04T22:00:00Z")
        self.assertEqual(caught.exception.code, "resolution_unavailable")

    def test_C16_clock_is_normalized_and_invalid_values_are_unavailable(self):
        mapping = {"/repos/blakeblackshear/frigate/git/ref/heads/dev": Response(200, ref("refs/heads/dev"))}
        utc = datetime(2026, 11, 4, 22, 0, 0, 123456, tzinfo=timezone.utc)
        result = resolve(parse_repository_url("https://github.com/blakeblackshear/frigate"), None,
                         transport_for({**base(), **mapping}), now=lambda: utc)
        self.assertEqual(result.resolved_at, "2026-11-04T22:00:00.123456Z")
        for value in ("2026-13-40T99:99:99Z", "fooZ", datetime(2026, 11, 4, 22, 0),
                      datetime(2026, 11, 4, 22, 0, tzinfo=timezone(timedelta(hours=1)))):
            with self.subTest(value=value), self.assertRaises(IntakeError) as caught:
                resolve(parse_repository_url("https://github.com/blakeblackshear/frigate"), None,
                        transport_for({**base(), **mapping}), now=lambda: value)
            self.assertEqual((caught.exception.code, caught.exception.field), ("resolution_unavailable", "revision"))


if __name__ == "__main__":
    unittest.main()
