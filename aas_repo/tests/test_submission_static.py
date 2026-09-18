import ast
import unittest
from pathlib import Path


class SubmissionStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).resolve().parents[1] / "submission" / "attack.py"
        cls.source = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_attack_algorithm_exists(self):
        self.assertTrue(any(isinstance(n, ast.ClassDef) and n.name == "AttackAlgorithm" for n in self.tree.body))

    def test_shape_guard_exists(self):
        self.assertIn("_assert_submission_shape", self.source)
        self.assertIn("FORBIDDEN_MARKER", self.source)

    def test_candidate_cap(self):
        value = None
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MAX_CANDIDATES" for t in node.targets):
                value = ast.literal_eval(node.value)
        self.assertEqual(value, 2000)


if __name__ == "__main__":
    unittest.main()
