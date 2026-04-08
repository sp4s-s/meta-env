"""
Operational Gradio UI for DepVulnEnv.
"""
from __future__ import annotations

import ast
import html
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import gradio as gr
import pandas as pd

from data.adapters import detect_and_parse
from data.fixtures import FIXTURES
from data.osv_client import osv_client
from env.environment import DepVulnEnv
from env.models import Action, CodeFile, RemediationAction, VulnFinding

env = DepVulnEnv()
rollout_history: List[Dict[str, Any]] = []
recorded_rollouts: set[str] = set()
current_reasoning = "Call reset() to load a task, inspect state(), and submit step() actions."
ACTION_LABELS = {
    "Identify finding": "identify",
    "Submit remediation": "remediate",
    "Rank risk": "rank",
    "Complete rollout": "done",
}

FIXTURE_BY_CVE = {item["cve_id"]: item for item in FIXTURES}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
IMPORT_HINTS = {
    "jinja2": ("CVE-2024-56326", "CRITICAL", "3.1.5"),
    "PIL": ("CVE-2024-28219", "CRITICAL", "10.3.0"),
    "pillow": ("CVE-2024-28219", "CRITICAL", "10.3.0"),
    "requests": ("CVE-2024-35195", "MEDIUM", "2.32.0"),
    "tornado": ("CVE-2024-32651", "CRITICAL", "6.4.1"),
    "flask": ("CVE-2023-30861", "HIGH", "3.0.1"),
    "yaml": ("CVE-2024-20060", "HIGH", "6.0.2"),
    "pyyaml": ("CVE-2024-20060", "HIGH", "6.0.2"),
    "django": ("CVE-2024-27351", "HIGH", "5.0.3"),
    "gunicorn": ("CVE-2024-1135", "HIGH", "22.0.0"),
    "transformers": ("CVE-2024-3568", "CRITICAL", "4.38.2"),
    "cryptography": ("CVE-2024-26130", "HIGH", "42.0.4"),
    "express": ("CVE-2024-29041", "MEDIUM", "4.19.2"),
    "body-parser": ("CVE-2024-45590", "HIGH", "1.20.3"),
    "bodyParser": ("CVE-2024-45590", "HIGH", "1.20.3"),
    "axios": ("CVE-2024-39338", "HIGH", "1.7.4"),
    "ws": ("CVE-2024-37890", "HIGH", "8.17.1"),
    "WebSocket": ("CVE-2024-37890", "HIGH", "8.17.1"),
    "elliptic": ("CVE-2024-48949", "CRITICAL", "6.5.6"),
    "ip": ("CVE-2024-29415", "CRITICAL", "2.0.1"),
    "cookie": ("CVE-2024-47764", "MEDIUM", "0.7.0"),
    "cross-spawn": ("CVE-2024-21538", "HIGH", "7.0.5"),
    "json5": ("CVE-2022-46175", "HIGH", "2.2.3"),
}


@dataclass(frozen=True)
class LogicalCheckRule:
    cve_id: str
    languages: Tuple[str, ...]
    patterns: Tuple[str, ...]
    evidence: str


LOGICAL_RULES: Tuple[LogicalCheckRule, ...] = (
    LogicalCheckRule(
        cve_id="CVE-2024-56326",
        languages=("python",),
        patterns=(r"from\s+jinja2\s+import", r"from_string\s*\(", r"user_input"),
        evidence="Jinja2 compiles user-controlled template content at runtime.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-28219",
        languages=("python",),
        patterns=(r"from\s+PIL\s+import\s+Image", r"Image\.open\s*\(", r"BytesIO"),
        evidence="Pillow opens untrusted bytes directly before processing.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-35195",
        languages=("python",),
        patterns=(r"requests\.Session\s*\(", r"urljoin\s*\(", r"session\.(get|post)\s*\("),
        evidence="Requests session performs redirect-capable calls from composed URLs.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-32651",
        languages=("python",),
        patterns=(r"from\s+tornado\.template\s+import\s+Template", r"Template\s*\(", r"get_argument"),
        evidence="Tornado template source is created from request input.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-20060",
        languages=("python",),
        patterns=(r"import\s+yaml", r"yaml\.load\s*\(", r"FullLoader"),
        evidence="PyYAML loads configuration through a full loader instead of a safe loader.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-3568",
        languages=("python",),
        patterns=(r"from\s+transformers\s+import", r"trust_remote_code\s*=\s*True"),
        evidence="Transformers is configured to execute remote model code.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-26130",
        languages=("python",),
        patterns=(r"pkcs12\.load_key_and_certificates", r"open\(", r"SSLContext"),
        evidence="Cryptography loads PKCS12 material from external input into a TLS context.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-45590",
        languages=("javascript",),
        patterns=(r"require\([\"']body-parser[\"']\)", r"bodyParser\.json\s*\(", r"limit\s*:\s*[\"']50mb[\"']"),
        evidence="Body parser accepts oversized JSON payloads in a request path.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-39338",
        languages=("javascript",),
        patterns=(r"require\([\"']axios[\"']\)", r"axios\.get\s*\(", r"(targetUrl|maxRedirects|baseUrl)"),
        evidence="Axios issues redirect-capable requests from attacker-influenced URLs.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-37890",
        languages=("javascript",),
        patterns=(r"require\([\"']ws[\"']\)", r"WebSocket\.Server", r"sec-websocket-protocol"),
        evidence="WebSocket server uses header-derived protocol data in the connection path.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-48949",
        languages=("javascript",),
        patterns=(r"require\([\"']elliptic[\"']\)", r"verifySignature", r"verify\s*\("),
        evidence="Elliptic signature verification is part of the request path.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-29415",
        languages=("javascript",),
        patterns=(r"require\([\"']ip[\"']\)", r"isPrivate\s*\(", r"createConnection"),
        evidence="Private-address validation relies on the vulnerable ip helper before opening a socket.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-47764",
        languages=("javascript",),
        patterns=(r"require\([\"']cookie[\"']\)", r"parse\s*\(", r"req\.headers\.cookie"),
        evidence="Cookie parsing uses raw request headers directly during authentication flow.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2024-21538",
        languages=("javascript",),
        patterns=(r"require\([\"']cross-spawn[\"']\)", r"spawn\s*\(", r"filePath"),
        evidence="Cross-spawn runs commands using attacker-influenced file names.",
    ),
    LogicalCheckRule(
        cve_id="CVE-2022-46175",
        languages=("javascript",),
        patterns=(r"require\([\"']json5[\"']\)", r"JSON5\.parse\s*\(", r"loadConfig"),
        evidence="JSON5 parses external configuration content before merging defaults.",
    ),
)

CSS = """
:root {
    --bg-app: #f5f6f7;
    --bg-panel: #ffffff;
    --bg-muted: #f0f2f5;
    --border: #d9dde3;
    --border-strong: #c9ced6;
    --text-main: #1d2129;
    --text-muted: #57606a;
    --text-soft: #6b7280;
    --blue: #1877f2;
    --blue-dark: #1664d9;
    --green: #137333;
    --red: #b42318;
    --amber: #b54708;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    --sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

body, .gradio-container {
    background: var(--bg-app) !important;
    color: var(--text-main) !important;
    font-family: var(--sans) !important;
    margin: 0 !important;
}

.gradio-container {
    max-width: 1540px !important;
    margin: 0 auto !important;
    padding: 0 !important;
}

.shell {
    min-height: 100vh;
}

.topbar {
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.brand-title {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 0.01em;
}

.brand-subtitle {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 2px;
}

.shell-content {
    padding: 16px;
    gap: 16px;
}

.sidebar {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    padding: 16px;
}

.panel {
    background: var(--bg-panel);
    border: 1px solid var(--border);
    padding: 16px;
}

.section-title {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    margin-bottom: 10px;
}

.section-note {
    color: var(--text-muted);
    font-size: 13px;
    line-height: 1.5;
}

.status-pill {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    border: 1px solid var(--border-strong);
    background: var(--bg-muted);
}

.status-ready {
    color: var(--text-muted);
}

.status-running {
    color: var(--blue-dark);
    border-color: #b9d2fb;
    background: #edf4ff;
}

.status-done {
    color: var(--green);
    border-color: #b7dfc0;
    background: #edf8ef;
}

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 12px;
}

.metric {
    border: 1px solid var(--border);
    background: var(--bg-panel);
    padding: 12px;
}

.metric-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--text-muted);
    margin-bottom: 6px;
}

.metric-value {
    font-size: 18px;
    font-weight: 700;
    color: var(--text-main);
}

.context-block {
    border: 1px solid var(--border);
    background: var(--bg-panel);
    padding: 12px;
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-main);
    margin-bottom: 10px;
}

.context-error {
    border-color: #f2c7c2;
    background: #fff5f4;
    color: var(--red);
}

.file-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-muted);
    border: 1px solid var(--border);
    border-bottom: none;
    padding: 10px 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-muted);
}

.code-shell {
    border: 1px solid var(--border);
    background: #fbfcfd;
    overflow: auto;
    max-height: 760px;
}

.code-row {
    display: grid;
    grid-template-columns: 56px 1fr;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.5;
}

.code-row:hover {
    background: #f7f9fb;
}

.line-number {
    padding: 0 10px 0 0;
    text-align: right;
    color: #8a94a6;
    background: var(--bg-muted);
    border-right: 1px solid var(--border);
    user-select: none;
}

.line-text {
    padding: 0 12px;
    white-space: pre;
    color: var(--text-main);
}

.line-hit {
    background: #fff8db;
}

.empty-state {
    border: 1px dashed var(--border-strong);
    background: var(--bg-panel);
    padding: 24px;
    text-align: center;
    color: var(--text-muted);
    font-size: 14px;
}

.small-note {
    font-size: 12px;
    color: var(--text-soft);
}

.gr-button-primary {
    background: var(--blue) !important;
    border-color: var(--blue) !important;
}

.gr-button-primary:hover {
    background: var(--blue-dark) !important;
}
"""
UI_THEME = gr.themes.Base(primary_hue="blue", spacing_size="sm", radius_size="none")


def _parse_task_id(task_label: str) -> int:
    return int(str(task_label).split(":", 1)[0].strip())


def _status_label(obs: Any) -> str:
    if not obs:
        return "READY"
    return "COMPLETE" if obs.done else "RUNNING"


def _status_html(obs: Any) -> str:
    status = _status_label(obs)
    css_class = {
        "READY": "status-ready",
        "RUNNING": "status-running",
        "COMPLETE": "status-done",
    }[status]
    return f'<span class="status-pill {css_class}">{status}</span>'


def _action_value(action_label: str) -> str:
    return ACTION_LABELS.get(action_label, str(action_label).strip().lower())


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity or "NONE", 99)


def _current_observation():
    if not env.state:
        return None
    last_reward = env.state.action_history[-1]["r"] if env.state.action_history else None
    return env._build_obs(last_reward)


def _line_number_from_index(content: str, index: int) -> int:
    return content[:index].count("\n") + 1


def _extract_imports(code: str, language: str) -> List[str]:
    modules: List[str] = []
    if language == "python":
        for match in re.finditer(r"(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.-]*)", code):
            modules.append(match.group(1).split(".")[0])
    else:
        for match in re.finditer(r"require\([\"']([^\"']+)[\"']\)", code):
            modules.append(match.group(1))
    return sorted(set(modules))


def _run_logical_check(files: Sequence[CodeFile]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for code_file in files:
        for rule in LOGICAL_RULES:
            if code_file.language not in rule.languages:
                continue
            matched_lines: List[int] = []
            matched = True
            for pattern in rule.patterns:
                match = re.search(pattern, code_file.content, re.IGNORECASE | re.MULTILINE)
                if not match:
                    matched = False
                    break
                matched_lines.append(_line_number_from_index(code_file.content, match.start()))
            if not matched:
                continue
            key = (code_file.path, rule.cve_id)
            if key in seen:
                continue
            seen.add(key)
            fixture = FIXTURE_BY_CVE.get(rule.cve_id, {})
            results.append({
                "file_path": code_file.path,
                "language": code_file.language,
                "cve_id": rule.cve_id,
                "package": fixture.get("package", "unknown"),
                "severity": fixture.get("severity", "NONE"),
                "fixed_version": fixture.get("fixed_version", ""),
                "summary": fixture.get("summary", ""),
                "lines": sorted(set(matched_lines)),
                "signal_source": "logical_rule",
                "evidence": rule.evidence,
            })
    results.sort(key=lambda item: (_severity_rank(item["severity"]), item["cve_id"], item["file_path"]))
    return results


def _fallback_import_findings(files: Sequence[CodeFile]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for code_file in files:
        imports = _extract_imports(code_file.content, code_file.language)
        for module in imports:
            hint = IMPORT_HINTS.get(module)
            if not hint:
                continue
            cve_id, severity, fixed_version = hint
            key = (code_file.path, cve_id)
            if key in seen:
                continue
            seen.add(key)
            line = 1
            for idx, text in enumerate(code_file.content.splitlines(), start=1):
                if module in text:
                    line = idx
                    break
            fixture = FIXTURE_BY_CVE.get(cve_id, {})
            results.append({
                "file_path": code_file.path,
                "language": code_file.language,
                "cve_id": cve_id,
                "package": fixture.get("package", module),
                "severity": severity,
                "fixed_version": fixed_version,
                "summary": fixture.get("summary", ""),
                "lines": [line],
                "signal_source": "import_fallback",
                "evidence": f"Imported module `{module}` maps to a known vulnerable package. No stronger code-pattern rule matched.",
            })
    results.sort(key=lambda item: (_severity_rank(item["severity"]), item["cve_id"], item["file_path"]))
    return results


def _candidate_signals(files: Sequence[CodeFile]) -> List[Dict[str, Any]]:
    logical = _run_logical_check(files)
    if logical:
        return logical
    return _fallback_import_findings(files)


def _next_recommendation(obs: Any) -> str:
    if not obs or not env.state:
        return "Call reset() to start a rollout."
    state = env.state
    unresolved = [cve for cve in state.ground_truth_vulns if cve not in state.remediated_vulns]
    if not state.identified_vulns and unresolved:
        return "Start with identify using the strongest code evidence."
    if state.task_id == 1 and state.identified_vulns:
        return "Rank the confirmed findings, then complete the rollout."
    if state.task_id >= 2 and unresolved:
        next_cve = unresolved[0]
        fix = FIXTURE_BY_CVE.get(next_cve, {}).get("fixed_version", "known fixed version")
        return f"Fix {next_cve} next and move the dependency to {fix}."
        return "Complete this rollout or reset() for a new one."


def _record_rollout_if_needed(obs: Any) -> None:
    if not obs or not obs.done or not env.state:
        return
    episode_id = env.state.episode_id
    if episode_id in recorded_rollouts:
        return
    recorded_rollouts.add(episode_id)
    state = env.state
    rollout_history.insert(0, {
        "Rollout": episode_id[:8],
        "Task": f"Task {state.task_id}",
        "Status": "complete",
        "Score": round(env.normalized_score(), 3),
        "Total reward": round(state.total_reward, 3),
        "Steps": f"{state.step}/{state.max_steps}",
        "Identified": len(state.identified_vulns),
        "Remediated": len(state.remediated_vulns),
        "False positives": len(state.false_positives),
        "Budget left": state.budget_points,
        "SLA left": state.sla_clock,
        "Finished": time.strftime("%H:%M:%S"),
    })


def _rollout_dataframe() -> pd.DataFrame:
    columns = [
        "Rollout",
        "Task",
        "Status",
        "Score",
        "Total reward",
        "Steps",
        "Identified",
        "Remediated",
        "False positives",
        "Budget left",
        "SLA left",
        "Finished",
    ]
    return pd.DataFrame(rollout_history, columns=columns)


def _rollout_summary_text() -> str:
    if not rollout_history:
        return "No completed rollouts yet."
    scores = [float(item["Score"]) for item in rollout_history]
    return (
        f"{len(rollout_history)} completed rollouts. "
        f"Best score {max(scores):.3f}. "
        f"Average score {sum(scores) / len(scores):.3f}."
    )


def _ground_truth_dataframe(show_ground_truth: bool) -> pd.DataFrame:
    columns = ["CVE", "Severity", "File", "Lines", "Fixed version", "Status", "Summary"]
    if not show_ground_truth or not env.state:
        return pd.DataFrame(columns=columns)
    state = env.state
    rows: List[Dict[str, Any]] = []
    for cve_id in state.ground_truth_vulns:
        fixture = FIXTURE_BY_CVE.get(cve_id, {})
        if cve_id in state.remediated_vulns:
            status = "remediated"
        elif cve_id in state.identified_vulns:
            status = "identified"
        else:
            status = "pending"
        rows.append({
            "CVE": cve_id,
            "Severity": fixture.get("severity", "NONE"),
            "File": state.ground_truth_files.get(cve_id, ""),
            "Lines": ", ".join(str(line) for line in state.ground_truth_lines.get(cve_id, [])),
            "Fixed version": fixture.get("fixed_version", ""),
            "Status": status,
            "Summary": fixture.get("summary", state.ground_truth_fixes.get(cve_id, "")),
        })
    rows.sort(key=lambda row: (_severity_rank(row["Severity"]), row["CVE"]))
    return pd.DataFrame(rows, columns=columns)


def _trace_dataframe() -> pd.DataFrame:
    columns = ["Step", "Action", "CVE", "File", "Line", "Reward", "Error", "Reasoning"]
    if not env.state:
        return pd.DataFrame(columns=columns)
    rows: List[Dict[str, Any]] = []
    for item in env.state.action_history:
        rows.append({
            "Step": item.get("step"),
            "Action": item.get("type"),
            "CVE": item.get("cve") or "",
            "File": item.get("file_path") or "",
            "Line": item.get("line_number") or "",
            "Reward": item.get("r"),
            "Error": item.get("error") or "",
            "Reasoning": item.get("reasoning") or "",
        })
    return pd.DataFrame(rows, columns=columns)


def _choose_file(obs: Any, selected_file: Optional[str]) -> Optional[str]:
    if not obs or not obs.code_files:
        return None
    available = [code_file.path for code_file in obs.code_files]
    if selected_file in available:
        return selected_file
    return available[0]


def _highlight_lines(obs: Any, selected_file: Optional[str]) -> List[int]:
    if not obs or not selected_file:
        return []
    lines: set[int] = set()
    if env.state:
        for cve_id, path in env.state.ground_truth_files.items():
            if path == selected_file:
                lines.update(env.state.ground_truth_lines.get(cve_id, []))
        if env.state.action_history:
            last = env.state.action_history[-1]
            if last.get("file_path") == selected_file and last.get("line_number"):
                lines.add(int(last["line_number"]))
    for item in _candidate_signals([code_file for code_file in obs.code_files if code_file.path == selected_file]):
        lines.update(item["lines"])
    return sorted(line for line in lines if line > 0)


def _render_code(files: Sequence[CodeFile], selected_file: Optional[str], highlights: Sequence[int]) -> str:
    if not files:
        return '<div class="empty-state">Call reset() or upload code to inspect it here.</div>'
    target = next((item for item in files if item.path == selected_file), files[0])
    lines = target.content.splitlines() or [""]
    highlight_set = set(highlights)
    rows: List[str] = []
    for line_no, text in enumerate(lines, start=1):
        row_class = "code-row"
        if line_no in highlight_set:
            row_class += " line-hit"
        safe_text = html.escape(text) if text else "&nbsp;"
        rows.append(
            f'<div class="{row_class}">'
            f'<div class="line-number">{line_no}</div>'
            f'<div class="line-text">{safe_text}</div>'
            "</div>"
        )
    return (
        f'<div class="file-header"><span>{html.escape(target.path)}</span>'
        f'<span>{html.escape(target.language)}</span></div>'
        f'<div class="code-shell">{"".join(rows)}</div>'
    )


def _episode_header_html(obs: Any) -> str:
    if not obs or not env.state:
        return (
            '<div class="section-title">Active Rollout</div>'
            '<div class="section-note">No active rollout. Use reset() to load code, labels, and constraints.</div>'
        )
    return (
        '<div class="section-title">Active Rollout</div>'
        f'<div style="display:flex; justify-content:space-between; align-items:center;">'
        f'<div><div style="font-size:18px; font-weight:700;">{env.state.episode_id[:8]}</div>'
        f'<div class="small-note">Task {env.state.task_id}</div></div>'
        f'{_status_html(obs)}'
        "</div>"
    )


def _metrics_html(obs: Any) -> str:
    if not obs or not env.state:
        return (
            '<div class="metrics-grid">'
            '<div class="metric"><div class="metric-label">Status</div><div class="metric-value">Ready</div></div>'
            '<div class="metric"><div class="metric-label">Step</div><div class="metric-value">0</div></div>'
            '<div class="metric"><div class="metric-label">Score</div><div class="metric-value">0.00</div></div>'
            '<div class="metric"><div class="metric-label">Reward</div><div class="metric-value">0.000</div></div>'
            '</div>'
        )
    state = env.state
    last_reward = obs.reward if obs.reward is not None else (state.action_history[-1]["r"] if state.action_history else 0.0)
    parts = [
        ("Task", str(state.task_id)),
        ("Step", f"{state.step}/{state.max_steps}"),
        ("Score", f"{env.normalized_score():.3f}"),
        ("Last reward", f"{float(last_reward):+.3f}"),
        ("Total reward", f"{state.total_reward:+.3f}"),
        ("Budget", str(obs.budget_points)),
        ("SLA", str(obs.sla_clock)),
        ("Confirmed / fixed", f"{len(state.identified_vulns)}/{len(state.remediated_vulns)}"),
    ]
    metrics = [
        (
            '<div class="metric">'
            f'<div class="metric-label">{html.escape(label)}</div>'
            f'<div class="metric-value">{html.escape(value)}</div>'
            '</div>'
        )
        for label, value in parts
    ]
    context = f'<div class="context-block">{html.escape(obs.task_context)}</div>'
    if state.last_action_error:
        context += f'<div class="context-block context-error">{html.escape(state.last_action_error)}</div>'
    return f'<div class="metrics-grid">{"".join(metrics)}</div>{context}'


def _reasoning_markdown(obs: Any) -> str:
    if not obs or not env.state:
        return "No active rollout."
    state = env.state
    signals = _candidate_signals(obs.code_files)
    lines: List[str] = [
        f"Current objective: {obs.task_context}",
        f"Score: {env.normalized_score():.3f}. Confirmed findings: {', '.join(obs.known_vulns) if obs.known_vulns else 'none yet'}.",
    ]
    if state.action_history:
        last = state.action_history[-1]
        action_summary = f"Last step {last['step']} used `{last['type']}`"
        if last.get("cve"):
            action_summary += f" on `{last['cve']}`"
        action_summary += f" with reward {last['r']:+.3f}."
        lines.append(action_summary)
        if last.get("reasoning"):
            lines.append(f"Latest analysis: {last['reasoning']}")
        if last.get("error"):
            lines.append(f"Validation issue: {last['error']}")
    elif current_reasoning:
        lines.append(current_reasoning)

    if signals:
        signal_lines = []
        for item in signals[:4]:
            signal_lines.append(
                f"- {item['cve_id']} in `{item['file_path']}` on lines {', '.join(map(str, item['lines']))}: {item['evidence']}"
            )
        lines.append("Evidence from code:\n" + "\n".join(signal_lines))
    else:
        lines.append("No deterministic rule matched the current code yet. Manual review is still required.")

    lines.append(f"Suggested next action: {_next_recommendation(obs)}")
    return "\n\n".join(lines)


def _observation_json(obs: Any) -> Dict[str, Any]:
    return obs.model_dump() if obs else {}


def _state_json() -> Dict[str, Any]:
    return env.state.model_dump() if env.state else {}


def _compose_outputs(selected_file: Optional[str], show_ground_truth: bool):
    obs = _current_observation()
    _record_rollout_if_needed(obs)
    chosen_file = _choose_file(obs, selected_file)
    code_choices = [code_file.path for code_file in obs.code_files] if obs else []
    code_html = _render_code(obs.code_files if obs else [], chosen_file, _highlight_lines(obs, chosen_file))
    return (
        _status_label(obs),
        _episode_header_html(obs),
        _metrics_html(obs),
        _reasoning_markdown(obs),
        gr.update(choices=code_choices, value=chosen_file),
        code_html,
        _observation_json(obs),
        _state_json(),
        _ground_truth_dataframe(show_ground_truth),
        _trace_dataframe(),
        _rollout_dataframe(),
        _rollout_summary_text(),
    )


def do_reset(task_label: str, selected_file: Optional[str], show_ground_truth: bool):
    global current_reasoning
    obs = env.reset(_parse_task_id(task_label))
    current_reasoning = "reset() completed. Review code evidence, inspect state(), then submit step() actions."
    return _compose_outputs(selected_file, show_ground_truth)


def do_state(selected_file: Optional[str], show_ground_truth: bool):
    return _compose_outputs(selected_file, show_ground_truth)


def do_state_view(selected_file: Optional[str], show_ground_truth: bool):
    full = _compose_outputs(selected_file, show_ground_truth)
    return (
        full[0],
        full[1],
        full[2],
        full[3],
        full[5],
        full[6],
        full[7],
        full[8],
        full[9],
        full[10],
        full[11],
    )


def do_step(
    action_type: str,
    cve_id: str,
    file_path: str,
    line_number: str,
    package: str,
    severity: str,
    target_version: str,
    code_fix: str,
    risk_ranking: str,
    reasoning: str,
    selected_file: Optional[str],
    show_ground_truth: bool,
):
    global current_reasoning
    if not env.state:
        current_reasoning = "No active rollout. Call reset() before step()."
        return _compose_outputs(selected_file, show_ground_truth)
    if env.state.done:
        current_reasoning = "This rollout is already complete. Call reset() to start another one."
        return _compose_outputs(selected_file, show_ground_truth)

    action_type = _action_value(action_type)

    normalized_cve = (cve_id or "").strip()
    fixture = FIXTURE_BY_CVE.get(normalized_cve, {})
    chosen_file = file_path.strip() or selected_file or (env.state.code_files[0].path if env.state.code_files else "src/main.py")
    chosen_package = package.strip() or fixture.get("package", "unknown")
    chosen_severity = severity or fixture.get("severity", "HIGH")

    safe_line = 0
    try:
        safe_line = int(str(line_number).strip() or 0)
    except (TypeError, ValueError):
        safe_line = 0

    findings = None
    remediation = None
    ranking = None

    if action_type == "identify":
        findings = [
            VulnFinding(
                cve_id=normalized_cve,
                file_path=chosen_file,
                line_number=safe_line,
                package=chosen_package,
                severity=chosen_severity,
                explanation=reasoning.strip() or "Manual finding submitted from code review.",
            )
        ]
    elif action_type == "remediate":
        remediation = RemediationAction(
            cve_id=normalized_cve,
            file_path=chosen_file,
            action="upgrade",
            target_version=target_version.strip() or fixture.get("fixed_version"),
            code_fix=code_fix.strip() or None,
            justification=reasoning.strip() or "Manual remediation proposal submitted.",
        )
    elif action_type == "rank":
        ranking = [item.strip() for item in risk_ranking.replace("\n", ",").split(",") if item.strip()]

    action = Action(
        action_type=action_type,
        findings=findings,
        remediation=remediation,
        risk_ranking=ranking or None,
        justification=reasoning.strip() or None,
    )

    current_reasoning = reasoning.strip() or f"Manual `{action_type}` step submitted."
    try:
        env.step(action)
    except Exception as exc:
        current_reasoning = f"Action rejected: {exc}"
    return _compose_outputs(selected_file, show_ground_truth)


def _identify_from_candidates(obs: Any) -> Tuple[List[VulnFinding], str]:
    candidates = _candidate_signals(obs.code_files)
    findings: List[VulnFinding] = []
    reasoning_lines: List[str] = []
    for item in candidates:
        findings.append(
            VulnFinding(
                cve_id=item["cve_id"],
                file_path=item["file_path"],
                line_number=item["lines"][0] if item["lines"] else 1,
                package=item["package"],
                severity=item["severity"],
                explanation=item["evidence"],
            )
        )
        reasoning_lines.append(
            f"{item['cve_id']} in {item['file_path']} from {item['signal_source']} on lines {', '.join(map(str, item['lines']))}"
        )
    if not reasoning_lines:
        reasoning_lines.append("No high-confidence signals detected. Completing the rollout.")
    return findings, "\n".join(reasoning_lines)


def _auto_action(task_id: int, obs: Any) -> Tuple[Action, str]:
    state = env.state
    if obs.step == 0 or (task_id >= 2 and not state.identified_vulns):
        findings, reasoning = _identify_from_candidates(obs)
        if findings:
            return Action(action_type="identify", findings=findings, justification=reasoning), reasoning
    if task_id == 1 and state.identified_vulns:
        ranking = sorted(
            state.identified_vulns,
            key=lambda cve: (
                _severity_rank(FIXTURE_BY_CVE.get(cve, {}).get("severity", "NONE")),
                -FIXTURE_BY_CVE.get(cve, {}).get("cvss_score", 0),
            ),
        )
        reasoning = "Ranking confirmed findings by severity and CVSS."
        return Action(action_type="rank", risk_ranking=ranking, justification=reasoning), reasoning
    if task_id >= 2:
        already_remediated = {item.get("cve") for item in state.action_history if item.get("type") == "remediate"}
        for cve in state.identified_vulns:
            if cve in already_remediated:
                continue
            target_file = state.ground_truth_files.get(cve, obs.code_files[0].path if obs.code_files else "src/main.py")
            fix = FIXTURE_BY_CVE.get(cve, {}).get("fixed_version")
            reasoning = f"Applying the known fixed version for {cve}."
            return (
                Action(
                    action_type="remediate",
                    remediation=RemediationAction(
                        cve_id=cve,
                        file_path=target_file,
                        action="upgrade",
                        target_version=fix,
                        justification=reasoning,
                    ),
                    justification=reasoning,
                ),
                reasoning,
            )
    return Action(action_type="done", justification="No further high-confidence step remains."), "No further high-confidence step remains."


def _run_auto_episode(task_id: int):
    global current_reasoning
    obs = env.reset(task_id)
    for _ in range(obs.max_steps):
        action, reasoning = _auto_action(task_id, obs)
        current_reasoning = reasoning
        obs = env.step(action)
        if obs.done:
            break
    _record_rollout_if_needed(obs)
    return obs


def do_auto_rollout(task_label: str, selected_file: Optional[str], show_ground_truth: bool):
    global current_reasoning
    obs = _run_auto_episode(_parse_task_id(task_label))
    current_reasoning = f"Automated rollout finished with score {env.normalized_score():.3f}."
    return _compose_outputs(selected_file, show_ground_truth)


def do_batch_rollouts(task_label: str, rollout_count: float, selected_file: Optional[str], show_ground_truth: bool):
    global current_reasoning
    task_id = _parse_task_id(task_label)
    count = max(1, min(int(rollout_count or 1), 20))
    last_obs = None
    scores: List[float] = []
    for _ in range(count):
        last_obs = _run_auto_episode(task_id)
        scores.append(env.normalized_score())
    if scores:
        current_reasoning = (
            f"Completed {count} automated rollouts. "
            f"Best score {max(scores):.3f}, average score {sum(scores) / len(scores):.3f}."
        )
    return _compose_outputs(selected_file, show_ground_truth)


def _guess_language(path_hint: str, explicit_language: str) -> str:
    if explicit_language and explicit_language != "auto":
        return explicit_language
    lower = (path_hint or "").lower()
    if lower.endswith(".py"):
        return "python"
    if lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return "javascript"
    return "python"


def _file_upload_path(file_obj: Any) -> str:
    if not file_obj:
        return ""
    if isinstance(file_obj, str):
        return file_obj
    return getattr(file_obj, "name", "")


def _validate_python(name: str, content: str) -> Tuple[str, Optional[int]]:
    try:
        ast.parse(content, filename=name or "<input>")
        return "Python syntax check passed.", None
    except SyntaxError as exc:
        line = exc.lineno or 1
        column = exc.offset or 1
        return f"Python syntax error at line {line}, column {column}: {exc.msg}", line


def _validate_javascript(content: str) -> Tuple[str, Optional[int]]:
    stack: List[Tuple[str, int]] = []
    openers = {"(": ")", "[": "]", "{": "}"}
    closers = {value: key for key, value in openers.items()}
    for idx, char in enumerate(content):
        if char in openers:
            stack.append((char, idx))
        elif char in closers:
            if not stack or stack[-1][0] != closers[char]:
                line = _line_number_from_index(content, idx)
                return "JavaScript structural check failed: bracket mismatch.", line
            stack.pop()
    if stack:
        line = _line_number_from_index(content, stack[-1][1])
        return "JavaScript structural check failed: unclosed bracket.", line
    return "JavaScript structural check passed. This is a structural check, not a full parser.", None


def _intake_dataframe(items: List[Dict[str, Any]]) -> pd.DataFrame:
    columns = ["CVE", "Severity", "Package", "File", "Lines", "Fixed version", "Signal source", "Evidence"]
    rows = [
        {
            "CVE": item["cve_id"],
            "Severity": item["severity"],
            "Package": item["package"],
            "File": item["file_path"],
            "Lines": ", ".join(str(line) for line in item["lines"]),
            "Fixed version": item["fixed_version"],
            "Signal source": item["signal_source"],
            "Evidence": item["evidence"],
        }
        for item in items
    ]
    return pd.DataFrame(rows, columns=columns)


def do_code_intake(file_obj: Any, pasted_code: str, language: str, path_hint: str):
    raw_path = path_hint.strip()
    content = ""
    upload_path = _file_upload_path(file_obj)
    if upload_path:
        raw_path = upload_path
        try:
            with open(upload_path, encoding="utf-8") as handle:
                content = handle.read()
        except UnicodeDecodeError:
            with open(upload_path, "rb") as handle:
                content = handle.read().decode("utf-8", errors="replace")
    elif pasted_code.strip():
        content = pasted_code
    if not content:
        empty_df = _intake_dataframe([])
        return (
            '<div class="context-block">Upload a source file or paste code to analyze it.</div>',
            empty_df,
            _render_code([], None, []),
        )

    resolved_path = raw_path or ("snippet.py" if language in ("python", "auto") else "snippet.js")
    resolved_language = _guess_language(resolved_path, language)
    code_file = CodeFile(path=resolved_path, content=content, language=resolved_language)

    if resolved_language == "python":
        validation_text, error_line = _validate_python(resolved_path, content)
    else:
        validation_text, error_line = _validate_javascript(content)

    matches = _candidate_signals([code_file])
    status_blocks = [
        f'<div class="context-block">{html.escape(validation_text)}</div>',
        '<div class="context-block">Ground truth is not available for uploaded code. The results below come from deterministic rules and dependency signals.</div>',
    ]
    if not matches:
        status_blocks.append('<div class="context-block">No known vulnerability rule matched the uploaded code.</div>')

    highlight_lines = [error_line] if error_line else []
    for item in matches:
        highlight_lines.extend(item["lines"])

    return (
        "".join(status_blocks),
        _intake_dataframe(matches),
        _render_code([code_file], code_file.path, sorted(set(line for line in highlight_lines if line))),
    )


def do_scan_file(file_obj: Any) -> str:
    upload_path = _file_upload_path(file_obj)
    if not upload_path:
        return '<div class="context-block">Upload a manifest or lockfile to scan dependencies.</div>'
    try:
        ecosystem, dependencies = detect_and_parse(upload_path)
        rows: List[str] = [
            f'<div class="context-block"><strong>Ecosystem:</strong> {html.escape(ecosystem)}. '
            f'<strong>Dependencies parsed:</strong> {len(dependencies)}</div>'
        ]
        findings = 0
        for dependency in dependencies[:20]:
            vulns = osv_client.query_package(dependency.name, dependency.version, dependency.ecosystem)
            if not vulns:
                continue
            findings += len(vulns)
            vuln_rows = "".join(
                f'<div class="small-note">{html.escape(item["cve_id"])} | fixed {html.escape(item.get("fixed_version", ""))}</div>'
                for item in vulns[:3]
            )
            rows.append(
                '<div class="context-block">'
                f'<strong>{html.escape(dependency.name)}@{html.escape(dependency.version)}</strong>'
                f'{vuln_rows}'
                '</div>'
            )
        if findings == 0:
            rows.append('<div class="context-block">No known issues were returned for the uploaded manifest.</div>')
        return "".join(rows)
    except Exception as exc:
        return f'<div class="context-block context-error">Manifest scan failed: {html.escape(str(exc))}</div>'


def toggle_action_groups(action_type: str):
    action_type = _action_value(action_type)
    return (
        gr.update(visible=(action_type == "identify")),
        gr.update(visible=(action_type == "remediate")),
        gr.update(visible=(action_type == "rank")),
    )


with gr.Blocks(title="Dependency Security RL Console") as ui:
    with gr.Column(elem_classes="shell"):
        with gr.Row(elem_classes="topbar"):
            gr.HTML(
                '<div>'
                '<div class="brand-title">Security RL Evaluation Console</div>'
                '<div class="brand-subtitle">OpenEnv-compatible reset(), state(), step(), reward, and rollout analysis for dependency security tasks.</div>'
                "</div>"
            )
            status_label = gr.Textbox(value="READY", label="Environment status", interactive=False, scale=0)

        with gr.Row(elem_classes="shell-content"):
            with gr.Column(scale=1, elem_classes="sidebar"):
                gr.HTML('<div class="section-title">Runtime Controls</div>')
                task_selector = gr.Dropdown(
                    choices=["1: Dependency identification", "2: Dependency remediation", "3: Multi-file constrained remediation"],
                    value="1: Dependency identification",
                    label="Evaluation task",
                )
                show_ground_truth = gr.Checkbox(value=True, label="Show ground truth labels")
                reset_button = gr.Button("reset()", variant="primary", elem_classes="gr-button-primary")
                state_button = gr.Button("state()")
                auto_button = gr.Button("Auto rollout")
                rollout_count = gr.Slider(minimum=1, maximum=10, step=1, value=3, label="Batch rollout count")
                batch_button = gr.Button("Batch rollouts")

                gr.HTML('<div class="section-title" style="margin-top:20px;">Rollout Summary</div>')
                rollout_summary = gr.Markdown(_rollout_summary_text())

            with gr.Column(scale=4):
                with gr.Tab("Rollout"):
                    episode_header = gr.HTML(_episode_header_html(None))
                    metrics_html = gr.HTML(_metrics_html(None))
                    with gr.Row():
                        with gr.Column(scale=3, elem_classes="panel"):
                            selected_file = gr.Dropdown(choices=[], label="File", interactive=True)
                            code_html = gr.HTML(_render_code([], None, []))
                        with gr.Column(scale=2):
                            with gr.Column(elem_classes="panel"):
                                gr.HTML('<div class="section-title">Agent Analysis</div>')
                                reasoning_md = gr.Markdown("No active rollout.")
                            with gr.Column(elem_classes="panel"):
                                gr.HTML('<div class="section-title">step()</div>')
                                action_type = gr.Radio(
                                    choices=list(ACTION_LABELS.keys()),
                                    value="Identify finding",
                                    label="Action",
                                )
                                with gr.Group(visible=True) as identify_group:
                                    action_cve = gr.Textbox(label="CVE ID", placeholder="CVE-2024-12345")
                                    action_file = gr.Textbox(label="File path", placeholder="src/main.py")
                                    action_line = gr.Textbox(label="Line number", placeholder="12")
                                    action_package = gr.Textbox(label="Package", placeholder="jinja2")
                                    action_severity = gr.Dropdown(
                                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                                        value="HIGH",
                                        label="Severity",
                                    )
                                with gr.Group(visible=False) as remediate_group:
                                    target_version = gr.Textbox(label="Target version", placeholder="3.1.5")
                                    code_fix = gr.TextArea(label="Code patch or fix note", lines=4)
                                with gr.Group(visible=False) as rank_group:
                                    risk_ranking = gr.TextArea(
                                        label="Risk ranking",
                                        placeholder="CVE-2024-1111, CVE-2024-2222",
                                        lines=3,
                                    )
                                action_reasoning = gr.TextArea(
                                    label="Analysis note",
                                    placeholder="Explain the code evidence for this step.",
                                    lines=5,
                                )
                                step_button = gr.Button("step()", variant="primary", elem_classes="gr-button-primary")

                with gr.Tab("State"):
                    with gr.Row():
                        with gr.Column(elem_classes="panel"):
                            gr.HTML('<div class="section-title">Observation</div>')
                            observation_json = gr.JSON(value={})
                        with gr.Column(elem_classes="panel"):
                            gr.HTML('<div class="section-title">State</div>')
                            state_json = gr.JSON(value={})
                    with gr.Row():
                        with gr.Column(elem_classes="panel"):
                            gr.HTML('<div class="section-title">Ground Truth Labels</div>')
                            ground_truth_table = gr.DataFrame(value=_ground_truth_dataframe(True), interactive=False, wrap=True)
                        with gr.Column(elem_classes="panel"):
                            gr.HTML('<div class="section-title">Action Log</div>')
                            trace_table = gr.DataFrame(value=_trace_dataframe(), interactive=False, wrap=True)

                with gr.Tab("Rollouts"):
                    with gr.Column(elem_classes="panel"):
                        gr.HTML('<div class="section-title">Completed Rollouts</div>')
                        rollout_table = gr.DataFrame(value=_rollout_dataframe(), interactive=False, wrap=True)

                with gr.Tab("Code Review"):
                    with gr.Row():
                        with gr.Column(scale=2, elem_classes="panel"):
                            code_upload = gr.File(label="Upload source file")
                            intake_language = gr.Dropdown(
                                choices=["auto", "python", "javascript"],
                                value="auto",
                                label="Language",
                            )
                            intake_path = gr.Textbox(label="Path hint", placeholder="src/service.py")
                            pasted_code = gr.TextArea(label="Or paste code", lines=18)
                            intake_button = gr.Button("Analyze code", variant="primary", elem_classes="gr-button-primary")
                            intake_status = gr.HTML('<div class="context-block">Upload a source file or paste code to analyze it.</div>')
                        with gr.Column(scale=3):
                            with gr.Column(elem_classes="panel"):
                                gr.HTML('<div class="section-title">Detected Issues</div>')
                                intake_table = gr.DataFrame(value=_intake_dataframe([]), interactive=False, wrap=True)
                            with gr.Column(elem_classes="panel"):
                                gr.HTML('<div class="section-title">Code Preview</div>')
                                intake_preview = gr.HTML(_render_code([], None, []))

                with gr.Tab("Dependency Scan"):
                    with gr.Column(elem_classes="panel"):
                        scan_upload = gr.File(label="Upload manifest or lockfile")
                        scan_button = gr.Button("Scan dependencies")
                        scan_results = gr.HTML('<div class="context-block">Scan results will appear here.</div>')

    outputs = [
        status_label,
        episode_header,
        metrics_html,
        reasoning_md,
        selected_file,
        code_html,
        observation_json,
        state_json,
        ground_truth_table,
        trace_table,
        rollout_table,
        rollout_summary,
    ]
    view_outputs = [
        status_label,
        episode_header,
        metrics_html,
        reasoning_md,
        code_html,
        observation_json,
        state_json,
        ground_truth_table,
        trace_table,
        rollout_table,
        rollout_summary,
    ]

    action_type.change(toggle_action_groups, inputs=action_type, outputs=[identify_group, remediate_group, rank_group])
    reset_button.click(do_reset, inputs=[task_selector, selected_file, show_ground_truth], outputs=outputs)
    state_button.click(do_state, inputs=[selected_file, show_ground_truth], outputs=outputs)
    step_button.click(
        do_step,
        inputs=[
            action_type,
            action_cve,
            action_file,
            action_line,
            action_package,
            action_severity,
            target_version,
            code_fix,
            risk_ranking,
            action_reasoning,
            selected_file,
            show_ground_truth,
        ],
        outputs=outputs,
    )
    auto_button.click(do_auto_rollout, inputs=[task_selector, selected_file, show_ground_truth], outputs=outputs)
    batch_button.click(
        do_batch_rollouts,
        inputs=[task_selector, rollout_count, selected_file, show_ground_truth],
        outputs=outputs,
    )
    selected_file.change(do_state_view, inputs=[selected_file, show_ground_truth], outputs=view_outputs)
    show_ground_truth.change(do_state_view, inputs=[selected_file, show_ground_truth], outputs=view_outputs)

    intake_button.click(
        do_code_intake,
        inputs=[code_upload, pasted_code, intake_language, intake_path],
        outputs=[intake_status, intake_table, intake_preview],
    )
    scan_button.click(do_scan_file, inputs=scan_upload, outputs=scan_results)

ui.css = CSS
ui.theme = UI_THEME


if __name__ == "__main__":
    ui.launch(server_name="0.0.0.0", server_port=7861)
