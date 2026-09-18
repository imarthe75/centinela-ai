import unittest
from agents import agent_harness

class TestAgentHarness(unittest.TestCase):
    def test_list_agents(self):
        agents = agent_harness.list_available_agents()
        self.assertIsInstance(agents, list)
        self.assertGreater(len(agents), 0)
        names = [a["name"] for a in agents]
        self.assertIn("security-reviewer", names)

    def test_get_agent_prompt(self):
        prompt = agent_harness.get_agent_prompt("security-reviewer")
        self.assertIsNotNone(prompt)
        self.assertIn("Security Reviewer", prompt)

    def test_run_agent_review(self):
        res = agent_harness.run_agent_review("code-reviewer", "def foo(): pass")
        self.assertEqual(res["status"], "success")

if __name__ == "__main__":
    unittest.main()
