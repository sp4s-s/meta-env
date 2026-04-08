"""
Verification suite — validates the vulnerability detection pipeline end-to-end
using 42 known-flawed packages (PyPI + npm) from 2024-2026.
Tests vuln classification, severity mapping, CVSS scoring, adapter parsing,
grader logic, and environment lifecycle with fixture data.
"""
import unittest
from unittest.mock import patch
from data.fixtures import (
    FIXTURES, PYPI_FIXTURES, NPM_FIXTURES, VULN_CLASSES,
    get_mock_vulns,
)
from data.osv_client import _severity_label, _parse_cvss_vector, _cvss_from_severity
from data.osv_cache import cache
from data.generator import ScenarioGenerator, scenario_bank
from env.environment import DepVulnEnv
from env.models import Action, CVEInfo
from graders.core import grade_task_1, grade_task_2, grade_task_3
from tasks.task_1 import _priority, _kt_sim


class TestFixtureData(unittest.TestCase):
    """Validate fixture integrity."""

    def test_minimum_count(self):
        self.assertGreaterEqual(len(FIXTURES), 40)
        self.assertGreaterEqual(len(PYPI_FIXTURES), 18)
        self.assertGreaterEqual(len(NPM_FIXTURES), 18)

    def test_unique_cves(self):
        ids = [f["cve_id"] for f in FIXTURES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_vuln_class_coverage(self):
        # must cover at least 10 distinct vuln classes
        self.assertGreaterEqual(len(VULN_CLASSES), 10)
        required = {"rce", "ssrf", "redos", "path_traversal", "dos", "sqli", "xss"}
        self.assertTrue(required.issubset(set(VULN_CLASSES)), f"Missing: {required - set(VULN_CLASSES)}")

    def test_severity_distribution(self):
        by_sev = {}
        for f in FIXTURES:
            by_sev.setdefault(f["severity"], []).append(f["cve_id"])
        self.assertIn("CRITICAL", by_sev)
        self.assertIn("HIGH", by_sev)
        self.assertIn("MEDIUM", by_sev)
        self.assertGreaterEqual(len(by_sev["CRITICAL"]), 4)
        self.assertGreaterEqual(len(by_sev["HIGH"]), 10)

    def test_all_have_fixed_version(self):
        for f in FIXTURES:
            self.assertTrue(f["fixed_version"], f"Missing fix for {f['cve_id']}")

    def test_cvss_range(self):
        for f in FIXTURES:
            self.assertGreaterEqual(f["cvss_score"], 0.0)
            self.assertLessEqual(f["cvss_score"], 10.0)


class TestMockFallback(unittest.TestCase):
    """Verify mock fetcher works when input is None or package absent."""

    def test_known_package(self):
        vulns = get_mock_vulns("jinja2", "3.1.3", "PyPI")
        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["cve_id"], "CVE-2024-56326")

    def test_unknown_package(self):
        self.assertEqual(get_mock_vulns("nonexistent-pkg", "0.0.0"), [])

    def test_ecosystem_filter(self):
        pypi = get_mock_vulns("express", "4.19.1", "PyPI")
        npm = get_mock_vulns("express", "4.19.1", "npm")
        self.assertEqual(len(pypi), 0)
        self.assertTrue(npm)


class TestSeverityLogic(unittest.TestCase):
    """Validate CVSS->severity mapping matches CVE expectations."""

    def test_severity_label(self):
        self.assertEqual(_severity_label(9.8), "CRITICAL")
        self.assertEqual(_severity_label(9.0), "CRITICAL")
        self.assertEqual(_severity_label(7.5), "HIGH")
        self.assertEqual(_severity_label(7.0), "HIGH")
        self.assertEqual(_severity_label(4.0), "MEDIUM")
        self.assertEqual(_severity_label(0.1), "LOW")
        self.assertEqual(_severity_label(0.0), "NONE")

    def test_cvss_vector_parsing(self):
        # network, low-complexity, high-impact → should be high
        score = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertGreaterEqual(score, 8.0)

    def test_cvss_from_severity_list(self):
        sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        score = _cvss_from_severity(sev)
        self.assertGreaterEqual(score, 8.0)

    def test_cvss_numeric_passthrough(self):
        self.assertAlmostEqual(_cvss_from_severity([{"score": 9.8}]), 9.8)

    def test_fixture_severity_consistency(self):
        for f in FIXTURES:
            computed = _severity_label(f["cvss_score"])
            self.assertEqual(computed, f["severity"],
                f"{f['cve_id']}: cvss={f['cvss_score']} expected={f['severity']} got={computed}")


class TestPriorityRanking(unittest.TestCase):
    """Validate ranking logic orders by threat correctly."""

    def _make_cve(self, **kw) -> CVEInfo:
        defaults = {
            "cve_id": "CVE-TEST-0001", "target_node": "pkg", "cvss_score": 5.0,
            "epss_score": 0.1, "epss_percentile": 0.5, "severity": "MEDIUM",
            "reachability_depth": 1, "kev_listed": False, "vex_status": "affected",
            "ssvc_decision": "track",
        }
        defaults.update(kw)
        return CVEInfo(**defaults)

    def test_critical_above_low(self):
        crit = self._make_cve(cve_id="C1", cvss_score=9.8, severity="CRITICAL", epss_score=0.8)
        low = self._make_cve(cve_id="C2", cvss_score=2.0, severity="LOW", epss_score=0.01)
        self.assertGreater(_priority(crit), _priority(low))

    def test_kev_boost(self):
        base = self._make_cve(cve_id="C1", kev_listed=False)
        kev = self._make_cve(cve_id="C2", kev_listed=True)
        self.assertGreater(_priority(kev), _priority(base))

    def test_depth_penalty(self):
        shallow = self._make_cve(cve_id="C1", reachability_depth=0)
        deep = self._make_cve(cve_id="C2", reachability_depth=5)
        self.assertGreater(_priority(shallow), _priority(deep))

    def test_vex_not_affected_demotion(self):
        affected = self._make_cve(cve_id="C1", vex_status="affected")
        not_aff = self._make_cve(cve_id="C2", vex_status="not_affected")
        self.assertGreater(_priority(affected), _priority(not_aff))

    def test_ssvc_act_highest(self):
        act = self._make_cve(cve_id="C1", ssvc_decision="act")
        track = self._make_cve(cve_id="C2", ssvc_decision="track")
        self.assertGreater(_priority(act), _priority(track))

    def test_kendall_tau_perfect(self):
        self.assertAlmostEqual(_kt_sim(["a", "b", "c"], ["a", "b", "c"]), 1.0)

    def test_kendall_tau_reversed(self):
        self.assertAlmostEqual(_kt_sim(["a", "b", "c"], ["c", "b", "a"]), 0.0)

    def test_kendall_tau_empty(self):
        self.assertAlmostEqual(_kt_sim([], []), 0.0)


class TestGraders(unittest.TestCase):
    """Verify grader math for all three tasks."""

    def test_grade_task_1_with_fixtures(self):
        cves = [
            CVEInfo(cve_id=f["cve_id"], target_node=f["package"], cvss_score=f["cvss_score"],
                    epss_score=0.5, severity=f["severity"], reachability_depth=1)
            for f in PYPI_FIXTURES[:6]
        ]
        truth = [c.cve_id for c in sorted(cves, key=_priority, reverse=True)]
        self.assertAlmostEqual(grade_task_1(cves, truth), 1.0)

    def test_grade_task_2_range(self):
        self.assertAlmostEqual(grade_task_2(10, 10, 0), 1.0)
        self.assertAlmostEqual(grade_task_2(10, 0, 0), 0.0)
        self.assertAlmostEqual(grade_task_2(0, 0, 0), 0.0)

    def test_grade_task_2_error_penalty(self):
        clean = grade_task_2(10, 8, 0)
        errored = grade_task_2(10, 8, 3)
        self.assertGreater(clean, errored)

    def test_grade_task_3_critical_remaining(self):
        self.assertEqual(grade_task_3(5, 5, 1, 0, 10, 10), 0.0)

    def test_grade_task_3_success(self):
        sc = grade_task_3(5, 5, 0, 0, 1, 1)
        self.assertGreater(sc, 0.9)

    def test_grader_clamped(self):
        self.assertGreaterEqual(grade_task_1([], []), 0.0)
        self.assertLessEqual(grade_task_2(100, 100, 0), 1.0)


class TestEnvWithFixtures(unittest.TestCase):
    """Run full environment lifecycle with mocked fixture data."""

    def test_all_tasks_lifecycle(self):
        env = DepVulnEnv()
        for tid in (1, 2, 3):
            obs = env.reset(tid)
            self.assertEqual(obs.step, 0)
            self.assertFalse(obs.done)
            self.assertTrue(obs.active_cves)

            if tid == 1:
                obs = env.step(Action(
                    action_type="rank",
                    cve_rankings=[c.cve_id for c in obs.active_cves]
                ))
            obs = env.step(Action(action_type="done"))
            self.assertTrue(obs.done)
            env.close()

    def test_fix_action_budget(self):
        env = DepVulnEnv()
        obs = env.reset(2)
        b0 = obs.budget_points
        c = obs.active_cves[0]
        env.step(Action(
            action_type="fix", cve_id=c.cve_id,
            target_node=c.target_node, target_version=c.fixed_version
        ))
        self.assertEqual(env.state.budget_points, b0 - 2)

    def test_suppress_invalid(self):
        env = DepVulnEnv()
        obs = env.reset(2)
        crit = next((c for c in obs.active_cves if c.severity == "CRITICAL" and c.reachability_depth < 2), None)
        if crit:
            env.step(Action(action_type="suppress", cve_id=crit.cve_id, justification="test"))
            self.assertIsNotNone(env.state.last_action_error)

    def test_accept_medium(self):
        env = DepVulnEnv()
        obs = env.reset(2)
        med = next((c for c in obs.active_cves if c.severity in ("MEDIUM", "LOW")), None)
        if med:
            env.step(Action(action_type="accept", cve_id=med.cve_id, justification="risk accepted"))
            self.assertIn(med.cve_id, env.state.resolved_cves)

    def test_sla_decrement_task3(self):
        env = DepVulnEnv()
        obs = env.reset(3)
        sla0 = obs.sla_clock
        env.step(Action(action_type="done"))
        self.assertEqual(env.state.sla_clock, sla0 - 1)

    def test_score_bounded(self):
        env = DepVulnEnv()
        for tid in (1, 2, 3):
            env.reset(tid)
            sc = env.normalized_score()
            self.assertGreaterEqual(sc, 0.0)
            self.assertLessEqual(sc, 1.0)


class TestSyntheticCache(unittest.TestCase):
    """Verify deterministic CVE cache."""

    def test_cache_lookup(self):
        info = cache.get_cve_info("CVE-2024-T0001")
        self.assertIn("epss_percentile", info)
        self.assertIn(info["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"))

    def test_cache_default(self):
        info = cache.get_cve_info("CVE-DOES-NOT-EXIST")
        self.assertEqual(info["cvss_score"], 5.0)

    def test_sample_determinism(self):
        import random
        s1 = cache.sample_cves(5, "mixed", rng=random.Random(99))
        s2 = cache.sample_cves(5, "mixed", rng=random.Random(99))
        self.assertEqual(s1, s2)


class TestGeneratorDeterminism(unittest.TestCase):
    """Confirm scenario generation is deterministic."""

    def test_graph_reproducibility(self):
        seed = scenario_bank.scenarios[0]
        g1 = ScenarioGenerator()
        g2 = ScenarioGenerator()
        n1, c1 = g1.generate_graph(seed)
        n2, c2 = g2.generate_graph(seed)
        self.assertEqual(len(n1), len(n2))
        if c1 and c2:
            self.assertEqual(c1[0]["cve_id"], c2[0]["cve_id"])

    def test_multi_ecosystem(self):
        for eco in ("PyPI", "npm", "Go"):
            seed = next((s for s in scenario_bank.scenarios if s.ecosystem == eco), None)
            if seed:
                nodes, _ = scenario_bank.generate_graph(seed)
                self.assertTrue(nodes, f"No nodes for {eco}")


class TestVulnClassification(unittest.TestCase):
    """Verify each vuln class from fixtures produces correct risk ordering."""

    def _cve_from_fixture(self, f, depth=1):
        return CVEInfo(
            cve_id=f["cve_id"], target_node=f["package"], cvss_score=f["cvss_score"],
            epss_score=0.5, severity=f["severity"], reachability_depth=depth,
        )

    def test_rce_ranked_highest(self):
        rce = [f for f in FIXTURES if f["vuln_class"] == "rce"]
        info = [f for f in FIXTURES if f["vuln_class"] == "info_leak"]
        if rce and info:
            rce_pri = _priority(self._cve_from_fixture(rce[0]))
            info_pri = _priority(self._cve_from_fixture(info[0]))
            self.assertGreater(rce_pri, info_pri)

    def test_critical_ssrf_above_medium_redos(self):
        ssrf = next((f for f in FIXTURES if f["vuln_class"] == "ssrf" and f["severity"] == "CRITICAL"), None)
        redos = next((f for f in FIXTURES if f["vuln_class"] == "redos" and f["severity"] == "MEDIUM"), None)
        if ssrf and redos:
            self.assertGreater(
                _priority(self._cve_from_fixture(ssrf)),
                _priority(self._cve_from_fixture(redos)),
            )


if __name__ == "__main__":
    unittest.main()
