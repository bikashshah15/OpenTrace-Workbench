"""Plumbing smoke test for the E1/E5 HTTP and server-state helpers against the LEGACY bundled demo (``replay=None``).

The legacy demo is an older bundled development fixture; docs/EVALUATION.md states it is not evaluation data. This test only checks
that the client, pagination and server-state access work with the real loopback server; it asserts no counts and records nothing.
The recorded Frigate replay (the actual E1/E5 input) is deliberately NOT opened here.
"""
import os
import shutil
import tempfile
import threading
import unittest

from tools.evaluation import e1_case_study as E1
from tools.evaluation import e5_efficiency as E5


class LegacyDemoPlumbingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from opentrace_core.app import make_server
        cls.dir = tempfile.mkdtemp(prefix="ot-eval-plumb-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600, live=None, replay=None)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_client_demo_pagination_and_server_state(self):
        c = E1.LoopbackClient(self.server.server_address[1])
        c.start()
        body = E1.open_demo(c)
        gen = body["generation"]
        for path, key in (("/api/workbench/v1/bom-candidates", "items"), ("/api/view/gaps", "items"),
                          ("/api/workbench/v1/crypto-assets", "assets"), ("/api/workbench/v1/ai-assets", "assets")):
            with self.subTest(path):
                r = E1.paginate(c, path, gen, items_key=key)
                self.assertIsInstance(r["items"], list)
                self.assertTrue(r["pages"] or r["errors"], "the endpoint answered (a page or a typed error)")
        svc = E1.ReplayService.__new__(E1.ReplayService)
        svc.server = self.server
        self.assertIsNotNone(svc.analysis_for(gen))

    def test_memory_sampler_reports_a_method_or_na(self):
        with E5.MemorySampler(0.005) as m:
            sum(range(10000))
        r = m.result()
        self.assertIn("method", r)


if __name__ == "__main__":
    unittest.main()
