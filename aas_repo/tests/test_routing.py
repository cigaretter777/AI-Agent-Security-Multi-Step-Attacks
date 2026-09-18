import unittest

from aas_solution.routing import RouteSelector, normalize_route


class RoutingTests(unittest.TestCase):
    def test_normalize_route(self):
        self.assertEqual(normalize_route("GPT-OSS-20B"), "gpt_oss")
        self.assertEqual(normalize_route("gemma-4-26b"), "gemma")
        self.assertIsNone(normalize_route("unknown"))

    def test_config_precedes_env(self):
        selector = RouteSelector()
        route, source = selector.select(
            {"model": "gemma"},
            {"AAS_FORCE_ROUTE": "gpt_oss"},
        )
        self.assertEqual((route, source), ("gemma", "config:model"))

    def test_deterministic_fallback(self):
        selector = RouteSelector()
        self.assertEqual(selector.select()[0], "gpt_oss")
        self.assertEqual(selector.select()[0], "gemma")
        self.assertEqual(selector.select()[0], "gpt_oss")


if __name__ == "__main__":
    unittest.main()
