"""Stage 4 increment C: the default dependency focus is a general deterministic rule; no node name is preferred (contract .context/contracts/S4-CRYPTO-SOURCE.md sec. 6)."""
import unittest

from opentrace_core.app.views import Views

focus = Views._default_focus


def n(i, name):
    return {"id": i, "name": name}


class DefaultFocus(unittest.TestCase):
    def test_most_outgoing_root_wins_regardless_of_name(self):
        nodes = [n("a", "web-new"), n("b", "other-root"), n("c", "x"), n("d", "y"), n("e", "z")]
        edges = [{"from": "b", "to": "c"}, {"from": "b", "to": "d"}, {"from": "a", "to": "e"}]
        self.assertEqual(focus(nodes, edges), "b")                   # the literal name "web-new" has no preference

    def test_tie_breaks_by_name_then_id_not_input_order(self):
        edges = [{"from": "p", "to": "x"}, {"from": "q", "to": "y"}]
        nodes = [n("q", "same"), n("p", "same"), n("x", "x"), n("y", "y")]
        self.assertEqual(focus(nodes, edges), "p")
        self.assertEqual(focus(list(reversed(nodes)), edges), "p")

    def test_name_breaks_a_count_tie(self):
        edges = [{"from": "p", "to": "x"}, {"from": "q", "to": "y"}]
        self.assertEqual(focus([n("p", "zeta"), n("q", "alpha"), n("x", "x"), n("y", "y")], edges), "q")

    def test_cycle_without_roots_uses_first_node_and_empty_is_none(self):
        nodes = [n("a", "a"), n("b", "b")]
        self.assertEqual(focus(nodes, [{"from": "a", "to": "b"}, {"from": "b", "to": "a"}]), "a")
        self.assertIsNone(focus([], []))

    def test_source_has_no_node_name_literal(self):
        import inspect
        self.assertNotIn("web-new", inspect.getsource(Views._default_focus))


if __name__ == "__main__":
    unittest.main()
