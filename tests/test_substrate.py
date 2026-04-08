import unittest

import pandas as pd

import server.ui as ui_module
from data.fixtures import FIXTURES
from env.environment import DepVulnEnv
from env.models import Action, RemediationAction, VulnFinding


FIXTURE_BY_CVE = {item["cve_id"]: item for item in FIXTURES}


def _identify_all(env: DepVulnEnv):
    findings = []
    for cve_id in env.state.ground_truth_vulns:
        findings.append(
            VulnFinding(
                cve_id=cve_id,
                file_path=env.state.ground_truth_files[cve_id],
                line_number=env.state.ground_truth_lines[cve_id][0],
                package=FIXTURE_BY_CVE[cve_id]["package"],
                severity=FIXTURE_BY_CVE[cve_id]["severity"],
                explanation="verified in test",
            )
        )
    return env.step(Action(action_type="identify", findings=findings, justification="identify all known findings"))


class TestEnvironmentLifecycle(unittest.TestCase):
    def test_single_file_reset_preserves_curated_path_and_evidence(self):
        env = DepVulnEnv()
        try:
            obs = env.reset(1)
            self.assertTrue(obs.code_files)
            cve_id = env.state.ground_truth_vulns[0]
            evidence = env.state.ground_truth_evidence[cve_id]
            self.assertEqual(obs.code_files[0].path, evidence.file_path)
            self.assertTrue(evidence.line_numbers)
            self.assertTrue(evidence.code_excerpt)
        finally:
            env.close()

    def test_task_1_identify_rank_done(self):
        env = DepVulnEnv()
        try:
            obs = env.reset(1)
            self.assertFalse(obs.done)
            self.assertTrue(obs.code_files)
            obs = _identify_all(env)
            self.assertTrue(obs.known_vulns)
            obs = env.step(Action(action_type="rank", risk_ranking=list(env.state.ground_truth_vulns)))
            self.assertIn("ranking_sim", obs.info)
            obs = env.step(Action(action_type="done"))
            self.assertTrue(obs.done)
        finally:
            env.close()

    def test_task_2_identify_and_remediate(self):
        env = DepVulnEnv()
        try:
            obs = env.reset(2)
            starting_budget = obs.budget_points
            _identify_all(env)
            target = env.state.ground_truth_vulns[0]
            fixture = FIXTURE_BY_CVE[target]
            obs = env.step(
                Action(
                    action_type="remediate",
                    remediation=RemediationAction(
                        cve_id=target,
                        file_path=env.state.ground_truth_files[target],
                        action="upgrade",
                        target_version=fixture["fixed_version"],
                        justification=f"Upgrade to {fixture['fixed_version']}",
                    ),
                )
            )
            self.assertIn(target, env.state.remediated_vulns)
            self.assertEqual(env.state.budget_points, starting_budget - 2)
            self.assertEqual(obs.done, env.state.initial_vuln_count == 1)
        finally:
            env.close()

    def test_task_1_rejects_ungrounded_identification(self):
        env = DepVulnEnv()
        try:
            env.reset(1)
            target = env.state.ground_truth_vulns[0]
            fixture = FIXTURE_BY_CVE[target]
            obs = env.step(
                Action(
                    action_type="identify",
                    findings=[
                        VulnFinding(
                            cve_id=target,
                            file_path="src/elsewhere.py",
                            line_number=999,
                            package=fixture["package"],
                            severity=fixture["severity"],
                            explanation=f"Possible issue in {fixture['package']}",
                        )
                    ],
                )
            )
            self.assertNotIn(target, env.state.identified_vulns)
            self.assertGreaterEqual(env.state.weak_findings, 1)
            self.assertEqual(obs.info["identified"], 0)
        finally:
            env.close()

    def test_task_2_requires_fix_version_floor(self):
        env = DepVulnEnv()
        try:
            env.reset(2)
            _identify_all(env)
            target = env.state.ground_truth_vulns[0]
            fixture = FIXTURE_BY_CVE[target]
            obs = env.step(
                Action(
                    action_type="remediate",
                    remediation=RemediationAction(
                        cve_id=target,
                        file_path=env.state.ground_truth_files[target],
                        action="upgrade",
                        target_version="0.0.1",
                        justification=f"Upgrade {fixture['package']} soon",
                    ),
                )
            )
            self.assertNotIn(target, env.state.remediated_vulns)
            self.assertGreaterEqual(env.state.invalid_remediations, 1)
            self.assertFalse(obs.info["accepted"])
            self.assertLess(obs.info["version"], 1.0)
        finally:
            env.close()

    def test_task_3_sla_decrements(self):
        env = DepVulnEnv()
        try:
            obs = env.reset(3)
            starting_sla = obs.sla_clock
            env.step(Action(action_type="done"))
            self.assertEqual(env.state.sla_clock, starting_sla - 1)
        finally:
            env.close()


class TestCodeReviewIntake(unittest.TestCase):
    def test_no_input_loads_curated_high_risk_example(self):
        status_html, table, preview = ui_module.do_code_intake(None, "", "auto", "")
        self.assertIn("curated high-risk incident", status_html)
        self.assertIsInstance(table, pd.DataFrame)
        self.assertFalse(table.empty)
        self.assertIn("code-shell", preview)

    def test_python_syntax_errors_are_reported(self):
        status_html, table, preview = ui_module.do_code_intake(None, "def broken(:\n    pass\n", "python", "broken.py")
        self.assertIn("syntax error", status_html.lower())
        self.assertIsInstance(table, pd.DataFrame)
        self.assertIn("code-shell", preview)

    def test_state_tables_are_configured_for_scrollable_full_width_layout(self):
        self.assertIn("wide-scroll-table", ui_module.CSS)
        self.assertIn("sticky-action-panel", ui_module.CSS)
        self.assertIn("Action Labels", str(ui_module.ui.config))

    def test_ui_exposes_multiple_step_buttons_and_copy_controls(self):
        labels = []
        copy_enabled = 0
        for component in ui_module.ui.config.get("components", []):
            props = component.get("props", {})
            label = props.get("label") or props.get("value")
            if isinstance(label, str):
                labels.append(label)
            buttons = props.get("buttons") or []
            if "copy" in buttons:
                copy_enabled += 1
        self.assertIn("Run step()", labels)
        self.assertIn("step()", labels)
        self.assertGreaterEqual(copy_enabled, 4)


class TestUiRollouts(unittest.TestCase):
    def test_auto_rollout_smoke(self):
        outputs = ui_module.do_auto_rollout("1: Dependency identification", None, True)
        self.assertEqual(len(outputs), 12)
        self.assertTrue(outputs[0] in {"RUNNING", "COMPLETE"})
        self.assertIsInstance(outputs[8], pd.DataFrame)
        self.assertIsInstance(outputs[9], pd.DataFrame)

    def test_batch_rollout_uses_selected_task_label(self):
        outputs = ui_module.do_batch_rollouts("3: Multi-file constrained remediation", 2, None, True)
        rollouts = outputs[10]
        self.assertFalse(rollouts.empty)
        self.assertTrue((rollouts["Task"].head(2) == "Task 3").all())


if __name__ == "__main__":
    unittest.main()
