import unittest

from aas_solution.scoring import count_scoring_actions, raw_estimate


class ScoringTests(unittest.TestCase):
    def test_raw_estimate(self):
        self.assertEqual(raw_estimate(0), 0.0)
        self.assertEqual(raw_estimate(1), 6.0)
        self.assertEqual(raw_estimate(4), 18.0)

    def test_count_top_level_tool_events(self):
        trace = {
            "tool_events": [
                {"name": "email.send", "ok": True},
                {"name": "http.post", "success": False},
                {"name": "other.tool", "ok": True},
            ]
        }
        self.assertEqual(count_scoring_actions(trace), 1)

    def test_count_nested_tool_event(self):
        trace = {"events": [{"function": {"name": "fs.write"}, "success": True}]}
        self.assertEqual(count_scoring_actions(trace), 1)


if __name__ == "__main__":
    unittest.main()
