"""
DEP VULN ENV — UI with OSV scanning
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

import gradio as gr

from env.environment import DepVulnEnv
from env.models import Action
from data.osv_client import osv_client
from data.adapters import parse_pip_requirements, parse_npm_lockfile, parse_go_sum

env = DepVulnEnv()
_episode_log: List[Dict[str, Any]] = []

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
:root {
  --bg: #fdfdfc; --fg: #1a1a1a; --border: #eef0f2; --hover: #f3f4f6; --primary: #f97316;
  --font-sans: 'Inter', sans-serif; --font-mono: 'JetBrains Mono', monospace;
}
body, .gradio-container {
  background: var(--bg) !important; color: var(--fg) !important; font-family: var(--font-sans) !important;
  max-width: 860px !important; margin: 0 auto !important; padding: 2rem 1rem !important;
}
h1 { font-weight: 600 !important; font-size: 1.5rem !important; letter-spacing: -0.02em !important; margin-bottom: 0.5rem !important; }
h2 { font-weight: 500 !important; font-size: 1.1rem !important; margin-bottom: 1rem !important; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
.panel, .gr-box, .gr-panel {
  border: 1px solid var(--border) !important; border-radius: 8px !important; background: #fff !important;
  box-shadow: 0 1px 2px rgba(0,0,0,0.02) !important; padding: 1.25rem !important; margin-bottom: 1rem !important;
}
input, select, textarea {
  border: 1px solid var(--border) !important; border-radius: 6px !important; background: #fff !important;
  font-family: var(--font-sans) !important; color: var(--fg) !important; transition: all 0.2s !important;
}
input:focus, select:focus, textarea:focus { border-color: var(--primary) !important; box-shadow: 0 0 0 2px rgba(249, 115, 22, 0.1) !important; outline: none !important; }
button.primary {
  background: var(--primary) !important; color: #fff !important; border-radius: 6px !important;
  font-weight: 500 !important; border: none !important; transition: opacity 0.2s !important;
}
button.primary:hover { opacity: 0.9 !important; }
.code-viewer textarea {
  font-family: var(--font-mono) !important; font-size: 0.85rem !important; background: #fafafa !important;
  color: #333 !important; border: 1px solid var(--border) !important; border-radius: 6px !important;
}
.cve-row { display: flex; gap: 0.75rem; align-items: center; border-bottom: 1px solid var(--border); padding: 0.5rem 0; font-size: 0.82rem; }
.cve-row:last-child { border-bottom: none; }
.node-row { display: flex; gap: 0.75rem; align-items: center; border-bottom: 1px solid var(--border); padding: 0.4rem 0; font-size: 0.82rem; }
.node-row:last-child { border-bottom: none; }
.mono-text { font-family: var(--font-mono); font-size: 0.82rem; }
.sev-badge { padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
.sev-CRITICAL { background: #fee2e2; color: #b91c1c; }
.sev-HIGH { background: #ffedd5; color: #c2410c; }
.sev-MEDIUM { background: #fef9c3; color: #a16207; }
.sev-LOW { background: #dcfce7; color: #15803d; }
.sev-NONE { background: #f3f4f6; color: #6b7280; }
.eco-badge { padding: 1px 5px; border-radius: 3px; font-size: 0.68rem; font-weight: 600; }
.eco-PyPI { background: #dbeafe; color: #1e40af; }
.eco-npm { background: #fce7f3; color: #be185d; }
.eco-Go { background: #d1fae5; color: #065f46; }
.telemetry-row { display: flex; justify-content: space-between; font-size: 0.85rem; color: #666; margin-bottom: 1rem; }
.telemetry-stat { font-family: var(--font-mono); font-weight: 500; color: var(--fg); }
.scan-result { border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; margin: 0.5rem 0; background: #fafafa; }
.scan-result .pkg-name { font-weight: 600; font-size: 0.9rem; }
.scan-result .vuln-count { float: right; font-size: 0.8rem; color: #dc2626; font-weight: 500; }
.gr-accordion { border: 1px solid var(--border) !important; border-radius: 8px !important; overflow: hidden; background: #fff !important;}
summary { font-weight: 500 !important; padding: 0.75rem 1rem !important; cursor: pointer !important; background: #fafafa !important; }
"""

theme = gr.themes.Base(
    font=[gr.themes.GoogleFont("Inter"), "sans-serif"],
).set(block_border_width="1px", block_radius="8px", button_border_width="0px")


def _render_cve_table(cves) -> str:
    if not cves: return '<div class="mono-text" style="color:#888;">No active CVEs</div>'
    rows = []
    for c in cves:
        d = c.model_dump() if hasattr(c, "model_dump") else c
        eco, summary = d.get("ecosystem", "PyPI"), d.get("summary", "")
        summary_html = f'<span style="color:#888; font-size:0.75rem; margin-left:4px;" title="{summary}">{summary[:60]}{"..." if len(summary) > 60 else ""}</span>' if summary else ""
        rows.append(f'''
        <div class="cve-row">
            <span class="mono-text" style="width:140px; font-weight:500;">{d["cve_id"]}</span>
            <span class="sev-badge sev-{d["severity"]}">{d["severity"]}</span>
            <span class="eco-badge eco-{eco}">{eco}</span>
            <span class="mono-text" style="color:#666;">{d.get("target_node", "N/A")}</span>
            {summary_html}
            <span class="mono-text" style="margin-left:auto; white-space:nowrap;">CVSS {d["cvss_score"]}</span>
        </div>''')
    return "".join(rows)


def _render_graph(nodes) -> str:
    if not nodes: return '<div class="mono-text" style="color:#888;">No Topology</div>'
    rows = []
    for n in nodes[:20]:
        d = n.model_dump() if hasattr(n, "model_dump") else n
        eco, ncves = d.get("ecosystem", "PyPI"), len(d.get("cves", []))
        cve_color = "#dc2626" if ncves > 0 else "#888"
        rows.append(f'''
        <div class="node-row">
            <span class="mono-text" style="width:180px; font-weight:500;">{d["name"]}</span>
            <span class="mono-text" style="color:#666; width:60px;">{d["version"]}</span>
            <span class="eco-badge eco-{eco}">{eco}</span>
            <span class="mono-text" style="color:#888;">d={d["depth"]}</span>
            <span class="mono-text" style="margin-left:auto; color:{cve_color}; font-weight:{'600' if ncves else '400'};">{ncves} CVE{"s" if ncves != 1 else ""}</span>
        </div>''')
    if len(nodes) > 20:
        rows.append(f'<div class="node-row mono-text" style="color:#888;">+ {len(nodes)-20} more nodes...</div>')
    return "".join(rows)


def _pack(obs):
    if not obs: return ("Awaiting...", '<div class="telemetry-row"><span>Initialize mission to view telemetry.</span></div>', "<p>No output</p>", "<p>No output</p>")
    tel = f'''
    <div class="telemetry-row">
        <span>Step: <span class="telemetry-stat">{obs.step}/{obs.max_steps}</span></span>
        <span>Budget: <span class="telemetry-stat">{obs.budget_points}</span></span>
        <span>SLA: <span class="telemetry-stat">{obs.sla_clock}</span></span>
        <span>Score: <span class="telemetry-stat">{env.normalized_score():.3f}</span></span>
    </div>
    '''
    return ("Terminated" if obs.done else "Live", tel, _render_cve_table(obs.active_cves), _render_graph(obs.graph))


def do_reset(tid, steps, budget, sla):
    try: t = int(tid.split(" ")[0])
    except: t = 1
    obs = env.reset(t)
    if env.state:
        if steps: env.state.max_steps = int(steps)
        if budget: env.state.budget_points = int(budget)
        if sla: env.state.sla_clock = int(sla)
        obs = env._build_obs()
    return _pack(obs)


def do_step(atype, cid, node, ver, rank, just):
    if not env.state or env.state.done: return _pack(None)
    rankings = [x.strip() for x in rank.split(",")] if rank else None
    try:
        a = Action(action_type=atype, cve_id=cid or None, target_node=node or None, target_version=ver or None, cve_rankings=rankings, justification=just or None)
        return _pack(env.step(a))
    except: return _pack(env._build_obs() if env.state else None)


def do_scan(pkg_name, pkg_version, ecosystem):
    if not pkg_name: return '<div class="mono-text" style="color:#888;">Enter a package name</div>'
    vulns = osv_client.query_package(pkg_name.strip(), pkg_version.strip(), ecosystem)
    if not vulns:
        return f'<div class="scan-result"><span class="pkg-name">{pkg_name}@{pkg_version}</span> — <span style="color:#16a34a; font-weight:500;">No known vulnerabilities</span></div>'

    rows = [f'<div class="scan-result"><span class="pkg-name">{pkg_name}@{pkg_version}</span><span class="vuln-count">{len(vulns)} vulnerabilities</span></div>']
    for v in vulns[:10]:
        sev = v.get("severity", "MEDIUM")
        rows.append(f'''
        <div class="cve-row">
            <span class="mono-text" style="width:140px; font-weight:500;">{v["cve_id"]}</span>
            <span class="sev-badge sev-{sev}">{sev}</span>
            <span class="mono-text" style="color:#888; flex-grow:1;">{v.get("summary", "")[:80]}</span>
            <span class="mono-text" style="white-space:nowrap;">CVSS {v["cvss_score"]}</span>
        </div>''')
    if len(vulns) > 10: rows.append(f'<div class="mono-text" style="color:#888; padding:0.3rem 0;">+ {len(vulns)-10} more...</div>')
    return "".join(rows)


def do_scan_file(file_obj):
    if file_obj is None: return '<div class="mono-text" style="color:#888;">Upload a lock file</div>'
    path = file_obj.name if hasattr(file_obj, "name") else str(file_obj)
    try:
        from data.adapters import detect_and_parse
        eco, deps = detect_and_parse(path)
    except Exception as e: return f'<div style="color:#dc2626;">Error: {e}</div>'

    total_vulns, rows = 0, [f'<div style="margin-bottom:0.5rem; font-weight:500;">{eco} — {len(deps)} packages</div>']
    for dep in deps[:30]:
        vulns = osv_client.query_package(dep.name, dep.version, dep.ecosystem)
        total_vulns += len(vulns)
        if vulns:
            rows.append(f'''
            <div class="cve-row">
                <span class="mono-text" style="width:160px; font-weight:500;">{dep.name}@{dep.version}</span>
                <span class="eco-badge eco-{dep.ecosystem}">{dep.ecosystem}</span>
                <span style="color:#dc2626; font-weight:500; margin-left:auto;">{len(vulns)} CVEs</span>
            </div>''')
    if total_vulns == 0: rows.append('<div class="mono-text" style="color:#16a34a; padding:0.5rem 0;">All dependencies clean</div>')
    else: rows.insert(1, f'<div style="color:#dc2626; font-weight:500; margin-bottom:0.5rem;">{total_vulns} total vulnerabilities found</div>')
    return "".join(rows)


with gr.Blocks(theme=theme, css=CSS, title="DepVulnEnv") as ui:
    gr.HTML('<h1>DepVulnEnv <span style="color:var(--primary); font-weight:400;">v2.0</span></h1>')

    with gr.Tab("Scanner"):
        gr.HTML("<h2>Vulnerability Scanner</h2>")
        with gr.Row():
            scan_pkg = gr.Textbox(label="Package", placeholder="e.g. requests, lodash", scale=3)
            scan_ver = gr.Textbox(label="Version", placeholder="e.g. 2.25.0", scale=2)
            scan_eco = gr.Dropdown(["PyPI", "npm", "Go", "Maven"], value="PyPI", label="Ecosystem", scale=1)
        btn_scan = gr.Button("Scan Package", elem_classes="primary")
        scan_out = gr.HTML('<div class="mono-text" style="color:#888;">Results appear here</div>')
        btn_scan.click(do_scan, [scan_pkg, scan_ver, scan_eco], scan_out)

        gr.HTML("<h2>Lock File Scanner</h2>")
        scan_file = gr.File(label="Upload Lock File", file_types=[".txt", ".json", ".sum"])
        scan_file_out = gr.HTML('<div class="mono-text" style="color:#888;">Upload a file to scan</div>')
        scan_file.change(do_scan_file, scan_file, scan_file_out)

    with gr.Tab("Environment"):
        with gr.Accordion("Mission Config", open=False):
            t_sel = gr.Radio(["1 - Triage", "2 - Fix", "3 - Remediate"], value="1 - Triage", label="Task")
            with gr.Row():
                a_st = gr.Number(label="Max Steps (0=default)", value=0, precision=0)
                a_bu = gr.Number(label="Budget (0=default)", value=0, precision=0)
                a_sl = gr.Number(label="SLA (0=default)", value=0, precision=0)
            btn_start = gr.Button("Initialize Mission", elem_classes="primary")

        out_status = gr.State("Awaiting...")
        out_tel = gr.HTML('<div class="telemetry-row"><span>Initialize mission to view telemetry.</span></div>')

        with gr.Group(elem_classes="panel"):
            gr.HTML("<h2>Current Threats</h2>")
            out_cves = gr.HTML('<div class="mono-text" style="color:#888;">—</div>')

        with gr.Group(elem_classes="panel"):
            gr.HTML("<h2>Topology Overview</h2>")
            out_graph = gr.HTML('<div class="mono-text" style="color:#888;">—</div>')

        with gr.Group(elem_classes="panel"):
            gr.HTML("<h2>Execute Action</h2>")
            with gr.Row():
                a_type = gr.Dropdown(["rank", "fix", "suppress", "accept", "done"], value="rank", label="Type", scale=1)
                i_cid = gr.Textbox(label="CVE ID", scale=2)
                i_node = gr.Textbox(label="Node", scale=2)
            with gr.Row():
                i_ver = gr.Textbox(label="Version", scale=1)
                i_rank = gr.Textbox(label="Rankings (CSV)", scale=3)
            i_just = gr.Textbox(label="Justification")
            btn_exec = gr.Button("Send Action", elem_classes="primary")

        outs = [out_status, out_tel, out_cves, out_graph]
        btn_start.click(do_reset, [t_sel, a_st, a_bu, a_sl], outs)
        btn_exec.click(do_step, [a_type, i_cid, i_node, i_ver, i_rank, i_just], outs)

if __name__ == "__main__":
    ui.launch(server_name="0.0.0.0", server_port=7861)
