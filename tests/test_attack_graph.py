import unittest
from core import attack_graph

class TestAttackGraph(unittest.TestCase):
    def test_build_attack_storyline_structure(self):
        res = attack_graph.build_attack_storyline()
        self.assertIn("nodes", res)
        self.assertIn("relationships", res)
        self.assertIn("attack_paths_count", res)
        self.assertIsInstance(res["nodes"], list)

if __name__ == "__main__":
    unittest.main()
