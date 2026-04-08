import unittest
from data.generator import ScenarioGenerator, scenario_bank
from data.osv_cache import cache
from env.environment import DepVulnEnv
from env.models import Action
from graders.core import grade_task_1, grade_task_2, grade_task_3

class TestDepVuln(unittest.TestCase):
    def test_cache(self):
        info = cache.get_cve_info("CVE-2024-T0001")
        self.assertIn("epss_percentile", info)
        self.assertIn(info["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"))

    def test_gen_determinism(self):
        s = scenario_bank.scenarios[0]
        g1, g2 = ScenarioGenerator(), ScenarioGenerator()
        n1, c1 = g1.generate_graph(s)
        n2, c2 = g2.generate_graph(s)
        self.assertEqual(len(n1), len(n2))
        self.assertEqual(c1[0]["cve_id"], c2[0]["cve_id"])

    def test_env_lifecycle(self):
        env = DepVulnEnv()
        o = env.reset(1)
        self.assertEqual(o.step, 0)
        self.assertFalse(o.done)
        
        # Test rank
        o = env.step(Action(action_type="rank", cve_rankings=[c.cve_id for c in o.active_cves]))
        self.assertIn("h", o.metadata)
        
        # Test done
        o = env.step(Action(action_type="done"))
        self.assertTrue(o.done)
        env.close()

    def test_task_2_logic(self):
        env = DepVulnEnv()
        o = env.reset(2)
        c = o.active_cves[0]
        # Test budget cost for fix
        b0 = o.budget_points
        env.step(Action(action_type="fix", cve_id=c.cve_id, target_node=c.target_node, target_version=c.fixed_version))
        self.assertEqual(env.state.budget_points, b0 - 2)

    def test_task_3_sla(self):
        env = DepVulnEnv()
        o = env.reset(3)
        s0 = o.sla_clock
        env.step(Action(action_type="done"))
        self.assertEqual(env.state.sla_clock, s0 - 1)

    def test_graders(self):
        self.assertGreaterEqual(grade_task_1([], []), 0.0)
        self.assertEqual(grade_task_3(5, 5, 1, 0, 10, 10), 0.0) # Critical left
        self.assertGreater(grade_task_3(5, 5, 0, 0, 1, 1), 0.9) # Success

if __name__ == "__main__":
    unittest.main()
