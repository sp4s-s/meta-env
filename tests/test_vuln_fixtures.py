import random
import unittest

from curriculum.adaptive_sampler import AdaptiveSampler
from data.code_scenarios import CORPUS
from data.fixtures import FIXTURES, NPM_FIXTURES, PYPI_FIXTURES, VULN_CLASSES, get_mock_vulns
from examples.catalog import CURATED_EXAMPLES, sample_curated_example
from env.models import GroundTruthEvidence
from env.verification import version_at_least, weighted_ranking_score
from graders.core import grade_task_1, grade_task_2, grade_task_3


class TestFixtureIntegrity(unittest.TestCase):
    def test_fixture_catalog_is_populated(self):
        self.assertGreaterEqual(len(FIXTURES), 40)
        self.assertGreaterEqual(len(PYPI_FIXTURES), 18)
        self.assertGreaterEqual(len(NPM_FIXTURES), 18)

    def test_fixture_ids_are_unique(self):
        cve_ids = [item["cve_id"] for item in FIXTURES]
        self.assertEqual(len(cve_ids), len(set(cve_ids)))

    def test_fixture_class_coverage(self):
        self.assertGreaterEqual(len(VULN_CLASSES), 10)
        self.assertTrue({"rce", "ssrf", "redos"}.issubset(set(VULN_CLASSES)))

    def test_mock_lookup_matches_fixture(self):
        results = get_mock_vulns("jinja2", "3.1.3", "PyPI")
        self.assertTrue(results)
        self.assertEqual(results[0]["cve_id"], "CVE-2024-56326")


class TestCuratedExamples(unittest.TestCase):
    def test_examples_meet_requested_volume(self):
        self.assertGreaterEqual(len(CURATED_EXAMPLES), 50)

    def test_examples_have_severity_mix(self):
        severities = {item.severity for item in CURATED_EXAMPLES}
        self.assertIn("CRITICAL", severities)
        self.assertIn("HIGH", severities)
        self.assertIn("MEDIUM", severities)

    def test_examples_have_high_risk_pool(self):
        high_risk = [item for item in CURATED_EXAMPLES if item.cvss_score >= 8.8]
        self.assertGreaterEqual(len(high_risk), 10)

    def test_high_risk_sampling_prefers_critical_examples(self):
        example = sample_curated_example(random.Random(7), high_risk_only=True)
        self.assertGreaterEqual(example.cvss_score, 8.8)
        self.assertTrue(example.vuln_lines)

    def test_code_scenarios_are_built_from_curated_examples(self):
        self.assertEqual(len(CORPUS), len(CURATED_EXAMPLES))
        self.assertEqual(CORPUS[0].present_vulns[0], CURATED_EXAMPLES[0].cve_id)
        self.assertTrue(CORPUS[0].vuln_lines)
        self.assertEqual(CORPUS[0].path, CURATED_EXAMPLES[0].path)


class TestGraders(unittest.TestCase):
    def test_grade_task_1_perfect_score(self):
        score = grade_task_1(["CVE-1", "CVE-2"], ["CVE-1", "CVE-2"], 0, 2)
        self.assertAlmostEqual(score, 1.0)

    def test_grade_task_1_penalizes_false_positives(self):
        clean = grade_task_1(["CVE-1"], ["CVE-1"], 0, 1)
        noisy = grade_task_1(["CVE-1"], ["CVE-1"], 2, 1)
        self.assertGreater(clean, noisy)

    def test_grade_task_2_bounds(self):
        self.assertEqual(grade_task_2(0, 0, 0), 0.0)
        self.assertAlmostEqual(grade_task_2(4, 4, 0), 1.0)
        self.assertLess(grade_task_2(4, 4, 3), 1.0)

    def test_grade_task_3_requires_critical_resolution(self):
        self.assertEqual(grade_task_3(5, 5, 1, 0, 3, 3), 0.0)
        self.assertGreater(grade_task_3(5, 5, 0, 0, 3, 3), 0.9)

    def test_version_floor_comparison_handles_patch_levels(self):
        self.assertTrue(version_at_least("4.44.0", "4.44.0"))
        self.assertTrue(version_at_least("4.44.1", "4.44.0"))
        self.assertFalse(version_at_least("4.43.9", "4.44.0"))

    def test_weighted_ranking_rewards_high_risk_ordering(self):
        ranked = sorted(CURATED_EXAMPLES[:4], key=lambda item: (item.cvss_score, item.severity), reverse=True)[:2]
        evidence = {
            item.cve_id: GroundTruthEvidence(
                cve_id=item.cve_id,
                package=item.package,
                severity=item.severity,
                cvss_score=item.cvss_score,
                fixed_version=item.fixed_version,
                summary=item.summary,
                file_path=item.path,
                language=item.language,
                line_numbers=list(item.vuln_lines),
                code_excerpt="",
                context=item.context,
                incident_source=item.incident_source,
            )
            for item in ranked
        }
        correct = weighted_ranking_score([ranked[0].cve_id, ranked[1].cve_id], evidence)
        swapped = weighted_ranking_score([ranked[1].cve_id, ranked[0].cve_id], evidence)
        self.assertGreaterEqual(correct, swapped)


class TestAdaptiveSampling(unittest.TestCase):
    def test_sampler_uses_expected_buckets(self):
        sampler = AdaptiveSampler()
        limits = {1: (0.0, 0.45), 2: (0.25, 0.65), 3: (0.45, 1.0)}
        for task_id, (lower, upper) in limits.items():
            slot = sampler.sample_scenario(task_id)
            difficulty = CORPUS[slot.idx].difficulty
            self.assertGreaterEqual(difficulty, lower)
            self.assertLessEqual(difficulty, upper)

    def test_sampler_updates_skill_after_reward(self):
        sampler = AdaptiveSampler()
        original = sampler.skill
        sampler.sample_scenario(1)
        sampler.update_skill(1.0)
        self.assertGreater(sampler.skill, original)


if __name__ == "__main__":
    unittest.main()
