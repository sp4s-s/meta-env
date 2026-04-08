from __future__ import annotations

import random
import re
import textwrap
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from data.fixtures import FIXTURES


@dataclass(frozen=True)
class CuratedExample:
    idx: int
    slug: str
    title: str
    path: str
    language: str
    ecosystem: str
    package: str
    cve_id: str
    severity: str
    cvss_score: float
    fixed_version: str
    summary: str
    difficulty: float
    context: str
    code: str
    vuln_lines: Tuple[int, ...]
    incident_source: str


@dataclass(frozen=True)
class ExampleSpec:
    slug: str
    title: str
    path: str
    difficulty: float
    context: str
    build_code: Callable[[], str]
    line_patterns: Tuple[str, ...]


_FIXTURE_BY_CVE = {item["cve_id"]: item for item in FIXTURES}


def _normalize(code: str) -> str:
    return textwrap.dedent(code).strip() + "\n"


def _line_number_from_index(content: str, index: int) -> int:
    return content[:index].count("\n") + 1


def _resolve_lines(code: str, patterns: Sequence[str]) -> Tuple[int, ...]:
    lines: List[int] = []
    for pattern in patterns:
        match = re.search(pattern, code, re.IGNORECASE | re.MULTILINE)
        if match:
            lines.append(_line_number_from_index(code, match.start()))
    return tuple(sorted(set(line for line in lines if line > 0)))


def _build_family(
    cve_id: str,
    language: str,
    ecosystem: str,
    incident_source: str,
    specs: Iterable[ExampleSpec],
) -> List[CuratedExample]:
    fixture = _FIXTURE_BY_CVE[cve_id]
    examples: List[CuratedExample] = []
    for spec in specs:
        code = _normalize(spec.build_code())
        examples.append(
            CuratedExample(
                idx=-1,
                slug=spec.slug,
                title=spec.title,
                path=spec.path,
                language=language,
                ecosystem=ecosystem,
                package=fixture["package"],
                cve_id=cve_id,
                severity=fixture["severity"],
                cvss_score=float(fixture["cvss_score"]),
                fixed_version=fixture["fixed_version"],
                summary=fixture["summary"],
                difficulty=spec.difficulty,
                context=spec.context,
                code=code,
                vuln_lines=_resolve_lines(code, spec.line_patterns),
                incident_source=incident_source,
            )
        )
    return examples


def _jinja2_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-56326",
        "python",
        "PyPI",
        "public advisory: template sandbox escape",
        [
            ExampleSpec(
                slug="jinja2-template-preview",
                title="Template preview endpoint",
                path="src/template_preview.py",
                difficulty=0.22,
                context="Preview service compiles user-supplied templates before rendering account data.",
                build_code=lambda: """
                    from jinja2 import Environment, BaseLoader

                    def render_preview(user_input: str, context: dict) -> str:
                        env = Environment(loader=BaseLoader())
                        template = env.from_string(user_input)
                        return template.render(**context)

                    if __name__ == "__main__":
                        print(render_preview("{{ user }}", {"user": "preview"}))
                """,
                line_patterns=(r"Environment\s*\(", r"from_string\s*\("),
            ),
            ExampleSpec(
                slug="jinja2-email-renderer",
                title="Email renderer",
                path="services/email_renderer.py",
                difficulty=0.28,
                context="Notification job renders attacker-controlled email bodies directly with Jinja2.",
                build_code=lambda: """
                    from jinja2 import Environment, BaseLoader

                    def build_email(template_body: str, recipient: dict) -> str:
                        engine = Environment(loader=BaseLoader())
                        compiled = engine.from_string(template_body)
                        return compiled.render(**recipient)

                    SAMPLE = {"name": "operator"}
                """,
                line_patterns=(r"Environment\s*\(", r"from_string\s*\("),
            ),
            ExampleSpec(
                slug="jinja2-chat-snippet",
                title="Chat snippet formatter",
                path="app/snippets.py",
                difficulty=0.31,
                context="A chat workflow formats snippets from end-user template fragments.",
                build_code=lambda: """
                    from jinja2 import Environment, BaseLoader

                    def format_snippet(user_input: str, session_data: dict) -> str:
                        env = Environment(loader=BaseLoader())
                        snippet = env.from_string(user_input)
                        return snippet.render(**session_data)

                    DEFAULTS = {"channel": "alerts"}
                """,
                line_patterns=(r"Environment\s*\(", r"from_string\s*\("),
            ),
            ExampleSpec(
                slug="jinja2-report-generator",
                title="Report generator",
                path="jobs/report_generator.py",
                difficulty=0.34,
                context="Reporting job compiles a tenant-managed template to produce exports.",
                build_code=lambda: """
                    from jinja2 import Environment, BaseLoader

                    def render_report(source: str, payload: dict) -> str:
                        runtime = Environment(loader=BaseLoader())
                        report_template = runtime.from_string(source)
                        return report_template.render(**payload)

                    DATA = {"tenant": "northwind"}
                """,
                line_patterns=(r"Environment\s*\(", r"from_string\s*\("),
            ),
        ],
    )


def _pillow_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-28219",
        "python",
        "PyPI",
        "public advisory: malformed image parsing",
        [
            ExampleSpec(
                slug="pillow-avatar-processor",
                title="Avatar processor",
                path="media/avatar_processor.py",
                difficulty=0.24,
                context="Avatar service opens user-provided bytes before thumbnail generation.",
                build_code=lambda: """
                    from PIL import Image
                    import io

                    def build_avatar(payload: bytes) -> bytes:
                        image = Image.open(io.BytesIO(payload))
                        image.thumbnail((256, 256))
                        output = io.BytesIO()
                        image.save(output, format="PNG")
                        return output.getvalue()
                """,
                line_patterns=(r"Image\.open\s*\(", r"BytesIO"),
            ),
            ExampleSpec(
                slug="pillow-document-preview",
                title="Document previewer",
                path="preview/image_preview.py",
                difficulty=0.29,
                context="Preview pipeline decodes a file upload into a Pillow image object.",
                build_code=lambda: """
                    from PIL import Image
                    import io

                    def preview_first_page(raw_bytes: bytes) -> str:
                        picture = Image.open(io.BytesIO(raw_bytes))
                        picture.load()
                        return f"{picture.mode}:{picture.size[0]}x{picture.size[1]}"
                """,
                line_patterns=(r"Image\.open\s*\(", r"BytesIO"),
            ),
            ExampleSpec(
                slug="pillow-ticket-attachment",
                title="Ticket attachment inspector",
                path="support/attachments.py",
                difficulty=0.33,
                context="Support tooling inspects raw image attachments supplied by customers.",
                build_code=lambda: """
                    from PIL import Image
                    import io

                    def inspect_attachment(blob: bytes) -> dict:
                        img = Image.open(io.BytesIO(blob))
                        img.verify()
                        return {"format": img.format, "mode": img.mode}
                """,
                line_patterns=(r"Image\.open\s*\(", r"BytesIO"),
            ),
        ],
    )


def _requests_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-35195",
        "python",
        "PyPI",
        "public advisory: redirect verification bug",
        [
            ExampleSpec(
                slug="requests-api-client",
                title="API client",
                path="clients/api_client.py",
                difficulty=0.36,
                context="Service client builds redirect-capable upstream requests from a base URL.",
                build_code=lambda: """
                    import requests
                    from urllib.parse import urljoin

                    class APIClient:
                        def __init__(self, base_url: str, token: str):
                            self.session = requests.Session()
                            self.session.headers["Authorization"] = f"Bearer {token}"
                            self.base = base_url

                        def get_json(self, path: str) -> dict:
                            response = self.session.get(urljoin(self.base, path))
                            response.raise_for_status()
                            return response.json()
                """,
                line_patterns=(r"requests\.Session\s*\(", r"urljoin\s*\(", r"session\.get\s*\("),
            ),
            ExampleSpec(
                slug="requests-webhook-forwarder",
                title="Webhook forwarder",
                path="handlers/webhook_forwarder.py",
                difficulty=0.4,
                context="Webhook relay posts tenant payloads to redirect-capable external endpoints.",
                build_code=lambda: """
                    import requests
                    from urllib.parse import urljoin

                    class WebhookRelay:
                        def __init__(self, origin: str):
                            self.origin = origin
                            self.session = requests.Session()

                        def forward(self, route: str, payload: dict) -> dict:
                            response = self.session.post(urljoin(self.origin, route), json=payload)
                            return response.json()
                """,
                line_patterns=(r"requests\.Session\s*\(", r"urljoin\s*\(", r"session\.post\s*\("),
            ),
            ExampleSpec(
                slug="requests-health-probe",
                title="Health probe worker",
                path="ops/health_probe.py",
                difficulty=0.42,
                context="Health checker probes operator-configured URLs using a shared requests session.",
                build_code=lambda: """
                    import requests
                    from urllib.parse import urljoin

                    class ProbeRunner:
                        def __init__(self, base_url: str):
                            self.base_url = base_url
                            self.session = requests.Session()

                        def ping(self, route: str) -> int:
                            response = self.session.get(urljoin(self.base_url, route))
                            return response.status_code
                """,
                line_patterns=(r"requests\.Session\s*\(", r"urljoin\s*\(", r"session\.get\s*\("),
            ),
        ],
    )


def _tornado_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-32651",
        "python",
        "PyPI",
        "public advisory: server-side template injection",
        [
            ExampleSpec(
                slug="tornado-render-endpoint",
                title="Render endpoint",
                path="web/render.py",
                difficulty=0.24,
                context="Endpoint compiles a tenant-controlled template before responding.",
                build_code=lambda: """
                    from tornado.web import Application, RequestHandler
                    from tornado.template import Template

                    class RenderHandler(RequestHandler):
                        def get(self):
                            user_tpl = self.get_argument("tpl", "{{name}}")
                            template = Template(user_tpl)
                            self.write(template.generate(name="world"))

                    app = Application([(r"/render", RenderHandler)])
                """,
                line_patterns=(r"get_argument", r"Template\s*\("),
            ),
            ExampleSpec(
                slug="tornado-preview-service",
                title="Preview service",
                path="preview/handler.py",
                difficulty=0.3,
                context="Preview route evaluates a request parameter as a Tornado template.",
                build_code=lambda: """
                    from tornado.web import RequestHandler
                    from tornado.template import Template

                    class PreviewHandler(RequestHandler):
                        def get(self):
                            source = self.get_argument("template", "{{ title }}")
                            compiled = Template(source)
                            self.finish(compiled.generate(title="preview"))
                """,
                line_patterns=(r"get_argument", r"Template\s*\("),
            ),
            ExampleSpec(
                slug="tornado-admin-banner",
                title="Admin banner builder",
                path="admin/banner.py",
                difficulty=0.35,
                context="Admin UI lets operators trial banner templates from query parameters.",
                build_code=lambda: """
                    from tornado.web import RequestHandler
                    from tornado.template import Template

                    class BannerHandler(RequestHandler):
                        def get(self):
                            requested = self.get_argument("banner", "{{ body }}")
                            banner = Template(requested)
                            self.write(banner.generate(body="status"))
                """,
                line_patterns=(r"get_argument", r"Template\s*\("),
            ),
        ],
    )


def _pyyaml_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-20060",
        "python",
        "PyPI",
        "public advisory: unsafe YAML loading",
        [
            ExampleSpec(
                slug="pyyaml-config-loader",
                title="Config loader",
                path="config/loader.py",
                difficulty=0.43,
                context="Service loads operator-supplied YAML using a full loader.",
                build_code=lambda: """
                    import yaml

                    def load_config(path: str) -> dict:
                        with open(path, encoding="utf-8") as handle:
                            return yaml.load(handle, Loader=yaml.FullLoader)
                """,
                line_patterns=(r"yaml\.load\s*\(", r"FullLoader"),
            ),
            ExampleSpec(
                slug="pyyaml-job-merge",
                title="Job merge helper",
                path="jobs/merge_config.py",
                difficulty=0.47,
                context="Background job merges untrusted YAML fragments into runtime settings.",
                build_code=lambda: """
                    import yaml

                    def merge_documents(paths: list[str]) -> dict:
                        merged = {}
                        for path in paths:
                            with open(path, encoding="utf-8") as handle:
                                merged.update(yaml.load(handle, Loader=yaml.FullLoader))
                        return merged
                """,
                line_patterns=(r"yaml\.load\s*\(", r"FullLoader"),
            ),
            ExampleSpec(
                slug="pyyaml-tenant-settings",
                title="Tenant settings parser",
                path="tenants/settings.py",
                difficulty=0.5,
                context="Tenant settings parser accepts uploaded YAML and feeds it into application defaults.",
                build_code=lambda: """
                    import yaml

                    def parse_settings(stream: str) -> dict:
                        with open(stream, encoding="utf-8") as payload:
                            return yaml.load(payload, Loader=yaml.FullLoader)
                """,
                line_patterns=(r"yaml\.load\s*\(", r"FullLoader"),
            ),
            ExampleSpec(
                slug="pyyaml-release-manifest",
                title="Release manifest importer",
                path="release/manifest.py",
                difficulty=0.54,
                context="Release tooling imports a deployment manifest with a full YAML loader.",
                build_code=lambda: """
                    import yaml

                    def import_manifest(path: str) -> dict:
                        with open(path, encoding="utf-8") as manifest:
                            return yaml.load(manifest, Loader=yaml.FullLoader)
                """,
                line_patterns=(r"yaml\.load\s*\(", r"FullLoader"),
            ),
        ],
    )


def _transformers_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-3568",
        "python",
        "PyPI",
        "public advisory: trust_remote_code execution path",
        [
            ExampleSpec(
                slug="transformers-model-loader",
                title="Model loader",
                path="ml/model_loader.py",
                difficulty=0.33,
                context="Inference worker loads remote repositories with trust_remote_code enabled.",
                build_code=lambda: """
                    from transformers import AutoModelForCausalLM, AutoTokenizer

                    def load_model(path: str):
                        tokenizer = AutoTokenizer.from_pretrained(path, trust_remote_code=True)
                        model = AutoModelForCausalLM.from_pretrained(path, trust_remote_code=True)
                        return model, tokenizer
                """,
                line_patterns=(r"from\s+transformers\s+import", r"trust_remote_code\s*=\s*True"),
            ),
            ExampleSpec(
                slug="transformers-eval-runner",
                title="Eval runner",
                path="ml/eval_runner.py",
                difficulty=0.37,
                context="Evaluation service accepts a repo path and executes remote model code on load.",
                build_code=lambda: """
                    from transformers import AutoModel, AutoTokenizer

                    def load_eval_model(repository: str):
                        tok = AutoTokenizer.from_pretrained(repository, trust_remote_code=True)
                        mdl = AutoModel.from_pretrained(repository, trust_remote_code=True)
                        return mdl, tok
                """,
                line_patterns=(r"from\s+transformers\s+import", r"trust_remote_code\s*=\s*True"),
            ),
            ExampleSpec(
                slug="transformers-batch-generator",
                title="Batch generator",
                path="workers/batch_generator.py",
                difficulty=0.41,
                context="Batch generation worker lets operators point at remote model repos directly.",
                build_code=lambda: """
                    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

                    def load_generator(source: str):
                        tokenizer = AutoTokenizer.from_pretrained(source, trust_remote_code=True)
                        model = AutoModelForSeq2SeqLM.from_pretrained(source, trust_remote_code=True)
                        return model, tokenizer
                """,
                line_patterns=(r"from\s+transformers\s+import", r"trust_remote_code\s*=\s*True"),
            ),
        ],
    )


def _cryptography_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-26130",
        "python",
        "PyPI",
        "public advisory: PKCS12 parsing crash",
        [
            ExampleSpec(
                slug="cryptography-cert-loader",
                title="Certificate loader",
                path="tls/cert_loader.py",
                difficulty=0.58,
                context="Gateway loads customer PKCS12 blobs into a TLS context.",
                build_code=lambda: """
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives.serialization import pkcs12
                    import ssl

                    def load_context(path: str, password: bytes) -> ssl.SSLContext:
                        with open(path, "rb") as handle:
                            private_key, cert, chain = pkcs12.load_key_and_certificates(
                                handle.read(), password, default_backend()
                            )
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.load_verify_locations(cadata=cert.public_bytes().decode("latin-1", errors="ignore"))
                        return context
                """,
                line_patterns=(r"pkcs12\.load_key_and_certificates", r"SSLContext"),
            ),
            ExampleSpec(
                slug="cryptography-bundle-import",
                title="Bundle importer",
                path="crypto/bundle_import.py",
                difficulty=0.61,
                context="Certificate-management job parses uploaded PKCS12 archives before validation.",
                build_code=lambda: """
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives.serialization import pkcs12

                    def import_bundle(path: str, password: bytes):
                        with open(path, "rb") as payload:
                            return pkcs12.load_key_and_certificates(payload.read(), password, default_backend())
                """,
                line_patterns=(r"pkcs12\.load_key_and_certificates", r"open\s*\("),
            ),
            ExampleSpec(
                slug="cryptography-device-bootstrap",
                title="Device bootstrap",
                path="devices/bootstrap.py",
                difficulty=0.64,
                context="Device bootstrap flow accepts a PKCS12 file to create a client TLS session.",
                build_code=lambda: """
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives.serialization import pkcs12
                    import ssl

                    def create_tls_client(bundle_path: str, password: bytes) -> ssl.SSLContext:
                        with open(bundle_path, "rb") as handle:
                            pkcs12.load_key_and_certificates(handle.read(), password, default_backend())
                        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                """,
                line_patterns=(r"pkcs12\.load_key_and_certificates", r"SSLContext"),
            ),
        ],
    )


def _flask_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2023-30861",
        "python",
        "PyPI",
        "public advisory: session fixation behavior",
        [
            ExampleSpec(
                slug="flask-login-flow",
                title="Login flow",
                path="app/login_flow.py",
                difficulty=0.5,
                context="Session-backed login flow depends on vulnerable Flask cookie behavior.",
                build_code=lambda: """
                    from flask import Flask, redirect, session, url_for
                    import os

                    app = Flask(__name__)
                    app.secret_key = os.urandom(32)

                    @app.route("/login", methods=["POST"])
                    def login():
                        session["user"] = "admin"
                        return redirect(url_for("dashboard"))

                    @app.route("/dashboard")
                    def dashboard():
                        return session.get("user", "anonymous")
                """,
                line_patterns=(r"from\s+flask\s+import", r"session\s*\["),
            ),
            ExampleSpec(
                slug="flask-admin-session",
                title="Admin session bridge",
                path="admin/session_bridge.py",
                difficulty=0.53,
                context="Admin flow keeps identity in Flask session cookies across redirects.",
                build_code=lambda: """
                    from flask import Flask, redirect, session, url_for
                    import os

                    app = Flask(__name__)
                    app.secret_key = os.urandom(32)

                    @app.route("/assume", methods=["POST"])
                    def assume():
                        session["role"] = "operator"
                        return redirect(url_for("panel"))
                """,
                line_patterns=(r"from\s+flask\s+import", r"session\s*\["),
            ),
        ],
    )


def _django_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-27351",
        "python",
        "PyPI",
        "public advisory: email validator ReDoS",
        [
            ExampleSpec(
                slug="django-email-validator",
                title="Email validator",
                path="accounts/validators.py",
                difficulty=0.55,
                context="Account flow validates user-supplied email addresses synchronously.",
                build_code=lambda: """
                    from django.core.validators import validate_email
                    from django.http import JsonResponse
                    from django.views import View

                    class EmailValidationView(View):
                        def post(self, request):
                            email = request.POST.get("email", "")
                            validate_email(email)
                            return JsonResponse({"valid": True})
                """,
                line_patterns=(r"from\s+django\.core\.validators\s+import", r"validate_email\s*\("),
            ),
            ExampleSpec(
                slug="django-contact-form",
                title="Contact form",
                path="contact/views.py",
                difficulty=0.58,
                context="Contact form validates attacker-controlled email addresses in-process.",
                build_code=lambda: """
                    from django.core.validators import validate_email

                    def validate_contact(payload: dict) -> str:
                        address = payload.get("email", "")
                        validate_email(address)
                        return address
                """,
                line_patterns=(r"from\s+django\.core\.validators\s+import", r"validate_email\s*\("),
            ),
        ],
    )


def _gunicorn_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-1135",
        "python",
        "PyPI",
        "public advisory: request smuggling exposure",
        [
            ExampleSpec(
                slug="gunicorn-entrypoint",
                title="Gunicorn entrypoint",
                path="deploy/gunicorn_app.py",
                difficulty=0.6,
                context="Deployment entrypoint runs on a vulnerable Gunicorn version in front of an app server.",
                build_code=lambda: """
                    from gunicorn.app.wsgiapp import WSGIApplication

                    class App(WSGIApplication):
                        def load(self):
                            from myapp import create_app
                            return create_app()

                    if __name__ == "__main__":
                        App("%(prog)s [OPTIONS]").run()
                """,
                line_patterns=(r"from\s+gunicorn\.app\.wsgiapp\s+import", r"WSGIApplication"),
            ),
            ExampleSpec(
                slug="gunicorn-worker-bootstrap",
                title="Worker bootstrap",
                path="runtime/bootstrap.py",
                difficulty=0.63,
                context="Bootstrap code instantiates Gunicorn's WSGI wrapper directly.",
                build_code=lambda: """
                    from gunicorn.app.wsgiapp import WSGIApplication

                    class Bootstrap(WSGIApplication):
                        def load(self):
                            from service import app
                            return app
                """,
                line_patterns=(r"from\s+gunicorn\.app\.wsgiapp\s+import", r"WSGIApplication"),
            ),
        ],
    )


def _body_parser_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-45590",
        "javascript",
        "npm",
        "public advisory: body-parser payload DoS",
        [
            ExampleSpec(
                slug="body-parser-webhook",
                title="Webhook intake",
                path="src/webhook.js",
                difficulty=0.28,
                context="Webhook service accepts oversized JSON payloads through body-parser.",
                build_code=lambda: """
                    const express = require("express");
                    const bodyParser = require("body-parser");

                    const app = express();
                    app.use(bodyParser.json({ limit: "50mb" }));

                    app.post("/webhook", (req, res) => {
                      res.json({ ok: true, bytes: JSON.stringify(req.body).length });
                    });

                    app.listen(3000);
                """,
                line_patterns=(r"require\([\"']body-parser[\"']\)", r"bodyParser\.json\s*\(", r"50mb"),
            ),
            ExampleSpec(
                slug="body-parser-admin-audit",
                title="Admin audit upload",
                path="admin/audit.js",
                difficulty=0.32,
                context="Admin audit endpoint parses very large request bodies through body-parser.",
                build_code=lambda: """
                    const express = require("express");
                    const bodyParser = require("body-parser");

                    const app = express();
                    app.use(bodyParser.json({ limit: "50mb" }));

                    app.post("/audit", (req, res) => {
                      res.json({ records: Array.isArray(req.body) ? req.body.length : 1 });
                    });
                """,
                line_patterns=(r"require\([\"']body-parser[\"']\)", r"bodyParser\.json\s*\(", r"50mb"),
            ),
            ExampleSpec(
                slug="body-parser-sync-hook",
                title="Sync hook receiver",
                path="integrations/sync_hook.js",
                difficulty=0.35,
                context="Sync endpoint accepts unbounded JSON blobs from external systems.",
                build_code=lambda: """
                    const express = require("express");
                    const bodyParser = require("body-parser");

                    const app = express();
                    app.use(bodyParser.json({ limit: "50mb" }));

                    app.post("/sync", (req, res) => {
                      res.sendStatus(202);
                    });
                """,
                line_patterns=(r"require\([\"']body-parser[\"']\)", r"bodyParser\.json\s*\(", r"50mb"),
            ),
            ExampleSpec(
                slug="body-parser-event-gateway",
                title="Event gateway",
                path="gateway/events.js",
                difficulty=0.38,
                context="Event gateway trusts a very large JSON body limit on a public endpoint.",
                build_code=lambda: """
                    const express = require("express");
                    const bodyParser = require("body-parser");

                    const app = express();
                    app.use(bodyParser.json({ limit: "50mb" }));

                    app.post("/events", (req, res) => {
                      res.json({ accepted: true });
                    });
                """,
                line_patterns=(r"require\([\"']body-parser[\"']\)", r"bodyParser\.json\s*\(", r"50mb"),
            ),
        ],
    )


def _axios_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-39338",
        "javascript",
        "npm",
        "public advisory: SSRF through URL handling",
        [
            ExampleSpec(
                slug="axios-proxy-request",
                title="Proxy request helper",
                path="src/proxy.js",
                difficulty=0.31,
                context="Proxy helper performs redirect-capable requests to caller-controlled targets.",
                build_code=lambda: """
                    const axios = require("axios");

                    async function proxyRequest(targetUrl) {
                      const response = await axios.get(targetUrl, { maxRedirects: 5 });
                      return response.data;
                    }

                    module.exports = { proxyRequest };
                """,
                line_patterns=(r"require\([\"']axios[\"']\)", r"axios\.get\s*\(", r"(targetUrl|maxRedirects)"),
            ),
            ExampleSpec(
                slug="axios-user-fetch",
                title="User fetch client",
                path="clients/user_fetch.js",
                difficulty=0.34,
                context="Client combines tenant-provided base URLs with resource paths before issuing requests.",
                build_code=lambda: """
                    const axios = require("axios");

                    async function fetchUser(baseUrl, userId) {
                      const url = `${baseUrl}/api/users/${userId}`;
                      const { data } = await axios.get(url);
                      return data;
                    }
                """,
                line_patterns=(r"require\([\"']axios[\"']\)", r"axios\.get\s*\(", r"baseUrl"),
            ),
            ExampleSpec(
                slug="axios-document-fetch",
                title="Document fetcher",
                path="documents/fetch.js",
                difficulty=0.37,
                context="Document fetcher accepts a target URL and follows redirects by default.",
                build_code=lambda: """
                    const axios = require("axios");

                    async function downloadDocument(targetUrl) {
                      const response = await axios.get(targetUrl, { maxRedirects: 5 });
                      return response.data;
                    }
                """,
                line_patterns=(r"require\([\"']axios[\"']\)", r"axios\.get\s*\(", r"(targetUrl|maxRedirects)"),
            ),
            ExampleSpec(
                slug="axios-metadata-probe",
                title="Metadata probe",
                path="ops/metadata_probe.js",
                difficulty=0.41,
                context="Operations script probes a target URL with axios and follows redirects.",
                build_code=lambda: """
                    const axios = require("axios");

                    async function probe(targetUrl) {
                      const result = await axios.get(targetUrl, { maxRedirects: 5 });
                      return result.status;
                    }
                """,
                line_patterns=(r"require\([\"']axios[\"']\)", r"axios\.get\s*\(", r"(targetUrl|maxRedirects)"),
            ),
        ],
    )


def _ws_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-37890",
        "javascript",
        "npm",
        "public advisory: WebSocket header handling DoS",
        [
            ExampleSpec(
                slug="ws-broadcast-server",
                title="Broadcast server",
                path="realtime/broadcast.js",
                difficulty=0.39,
                context="Realtime service logs the protocol header while handling websocket connections.",
                build_code=lambda: """
                    const WebSocket = require("ws");

                    const wss = new WebSocket.Server({ port: 8080 });

                    wss.on("connection", (ws, req) => {
                      console.log(req.headers["sec-websocket-protocol"]);
                      ws.on("message", (message) => ws.send(message.toString()));
                    });
                """,
                line_patterns=(r"require\([\"']ws[\"']\)", r"WebSocket\.Server", r"sec-websocket-protocol"),
            ),
            ExampleSpec(
                slug="ws-room-gateway",
                title="Room gateway",
                path="gateway/rooms.js",
                difficulty=0.43,
                context="Gateway records websocket protocol headers in the connection path.",
                build_code=lambda: """
                    const WebSocket = require("ws");

                    const roomServer = new WebSocket.Server({ port: 9090 });

                    roomServer.on("connection", (socket, req) => {
                      const protocol = req.headers["sec-websocket-protocol"];
                      socket.send(`connected:${protocol || "none"}`);
                    });
                """,
                line_patterns=(r"require\([\"']ws[\"']\)", r"WebSocket\.Server", r"sec-websocket-protocol"),
            ),
            ExampleSpec(
                slug="ws-notification-hub",
                title="Notification hub",
                path="notifications/hub.js",
                difficulty=0.47,
                context="Notification hub tracks websocket protocol headers during handshake handling.",
                build_code=lambda: """
                    const WebSocket = require("ws");

                    const notificationServer = new WebSocket.Server({ port: 7070 });

                    notificationServer.on("connection", (client, request) => {
                      console.log(request.headers["sec-websocket-protocol"]);
                      client.on("message", () => client.send("ok"));
                    });
                """,
                line_patterns=(r"require\([\"']ws[\"']\)", r"WebSocket\.Server", r"sec-websocket-protocol"),
            ),
        ],
    )


def _elliptic_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-48949",
        "javascript",
        "npm",
        "public advisory: invalid ECDSA signature verification",
        [
            ExampleSpec(
                slug="elliptic-signature-verify",
                title="Signature verify helper",
                path="crypto/verify.js",
                difficulty=0.48,
                context="Verification code depends on elliptic for secp256k1 signature checks.",
                build_code=lambda: """
                    const elliptic = require("elliptic");
                    const crypto = require("crypto");

                    const curve = new elliptic.ec("secp256k1");

                    function verifySignature(publicKey, message, signature) {
                      const digest = crypto.createHash("sha256").update(message).digest();
                      return curve.verify(digest, signature, publicKey, "hex");
                    }

                    module.exports = { verifySignature };
                """,
                line_patterns=(r"require\([\"']elliptic[\"']\)", r"verifySignature", r"verify\s*\("),
            ),
            ExampleSpec(
                slug="elliptic-wallet-approval",
                title="Wallet approval verifier",
                path="wallet/approval.js",
                difficulty=0.52,
                context="Wallet service verifies approvals with elliptic before executing a transfer.",
                build_code=lambda: """
                    const elliptic = require("elliptic");

                    const secp256k1 = new elliptic.ec("secp256k1");

                    function verifySignature(publicKey, payload, signature) {
                      return secp256k1.verify(payload, signature, publicKey, "hex");
                    }
                """,
                line_patterns=(r"require\([\"']elliptic[\"']\)", r"verifySignature", r"verify\s*\("),
            ),
        ],
    )


def _ip_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-29415",
        "javascript",
        "npm",
        "public advisory: private-address bypass",
        [
            ExampleSpec(
                slug="ip-connection-guard",
                title="Connection guard",
                path="net/guard.js",
                difficulty=0.27,
                context="Socket helper gates connections with ip.isPrivate before dialing a host.",
                build_code=lambda: """
                    const net = require("net");
                    const { isPrivate } = require("ip");

                    function connect(host, port) {
                      if (isPrivate(host)) {
                        throw new Error("private addresses blocked");
                      }
                      return net.createConnection({ host, port });
                    }
                """,
                line_patterns=(r"require\([\"']ip[\"']\)", r"isPrivate\s*\(", r"createConnection"),
            ),
            ExampleSpec(
                slug="ip-webhook-relay",
                title="Webhook relay",
                path="relay/webhook.js",
                difficulty=0.31,
                context="Relay checks hosts with ip.isPrivate before opening a raw TCP connection.",
                build_code=lambda: """
                    const net = require("net");
                    const { isPrivate } = require("ip");

                    function openRelay(host, port) {
                      if (isPrivate(host)) {
                        throw new Error("blocked");
                      }
                      return net.createConnection({ host, port });
                    }
                """,
                line_patterns=(r"require\([\"']ip[\"']\)", r"isPrivate\s*\(", r"createConnection"),
            ),
            ExampleSpec(
                slug="ip-metadata-client",
                title="Metadata client",
                path="ops/metadata_client.js",
                difficulty=0.35,
                context="Metadata probe filters destination hosts with the vulnerable ip helper.",
                build_code=lambda: """
                    const net = require("net");
                    const { isPrivate } = require("ip");

                    function fetchMetadata(host, port) {
                      if (isPrivate(host)) {
                        throw new Error("internal host");
                      }
                      return net.createConnection({ host, port });
                    }
                """,
                line_patterns=(r"require\([\"']ip[\"']\)", r"isPrivate\s*\(", r"createConnection"),
            ),
        ],
    )


def _cookie_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-47764",
        "javascript",
        "npm",
        "public advisory: cookie parsing bypass",
        [
            ExampleSpec(
                slug="cookie-profile-loader",
                title="Profile loader",
                path="auth/profile.js",
                difficulty=0.41,
                context="Authentication middleware parses raw cookie headers before checking session state.",
                build_code=lambda: """
                    const { parse } = require("cookie");
                    const express = require("express");

                    const app = express();

                    app.use((req, res, next) => {
                      req.cookies = parse(req.headers.cookie || "");
                      next();
                    });

                    app.get("/profile", (req, res) => res.json({ session: req.cookies.session_id || null }));
                """,
                line_patterns=(r"require\([\"']cookie[\"']\)", r"parse\s*\(", r"req\.headers\.cookie"),
            ),
            ExampleSpec(
                slug="cookie-session-bridge",
                title="Session bridge",
                path="gateway/session_bridge.js",
                difficulty=0.46,
                context="Gateway middleware converts raw cookie headers into a request cookie object.",
                build_code=lambda: """
                    const { parse } = require("cookie");

                    function readSession(req) {
                      const cookies = parse(req.headers.cookie || "");
                      return cookies.session_id || "";
                    }
                """,
                line_patterns=(r"require\([\"']cookie[\"']\)", r"parse\s*\(", r"req\.headers\.cookie"),
            ),
        ],
    )


def _cross_spawn_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-21538",
        "javascript",
        "npm",
        "public advisory: cross-spawn regex DoS",
        [
            ExampleSpec(
                slug="cross-spawn-linter",
                title="Linter runner",
                path="tools/linter.js",
                difficulty=0.53,
                context="Developer tooling shells out to a linter with a caller-controlled file name.",
                build_code=lambda: """
                    const { spawn } = require("cross-spawn");
                    const path = require("path");

                    function runLinter(filePath) {
                      const command = path.extname(filePath) === ".py" ? "ruff" : "eslint";
                      return spawn(command, ["--fix", filePath], { stdio: "pipe" });
                    }
                """,
                line_patterns=(r"require\([\"']cross-spawn[\"']\)", r"spawn\s*\(", r"filePath"),
            ),
            ExampleSpec(
                slug="cross-spawn-formatter",
                title="Formatter runner",
                path="tools/formatter.js",
                difficulty=0.57,
                context="Formatting service shells out with cross-spawn based on a user-provided path.",
                build_code=lambda: """
                    const { spawn } = require("cross-spawn");

                    function runFormatter(filePath) {
                      return spawn("prettier", ["--write", filePath], { stdio: "pipe" });
                    }
                """,
                line_patterns=(r"require\([\"']cross-spawn[\"']\)", r"spawn\s*\(", r"filePath"),
            ),
        ],
    )


def _json5_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2022-46175",
        "javascript",
        "npm",
        "public advisory: JSON5 prototype pollution",
        [
            ExampleSpec(
                slug="json5-config-loader",
                title="Config loader",
                path="config/json5_loader.js",
                difficulty=0.47,
                context="Config loader parses external JSON5 before merging defaults.",
                build_code=lambda: """
                    const JSON5 = require("json5");
                    const fs = require("fs");

                    function loadConfig(configPath) {
                      const raw = fs.readFileSync(configPath, "utf-8");
                      return JSON5.parse(raw);
                    }
                """,
                line_patterns=(r"require\([\"']json5[\"']\)", r"JSON5\.parse\s*\(", r"loadConfig"),
            ),
            ExampleSpec(
                slug="json5-theme-parser",
                title="Theme parser",
                path="ui/theme_parser.js",
                difficulty=0.5,
                context="Theme parser accepts a JSON5 file supplied by a tenant administrator.",
                build_code=lambda: """
                    const JSON5 = require("json5");

                    function parseTheme(raw) {
                      return JSON5.parse(raw);
                    }
                """,
                line_patterns=(r"require\([\"']json5[\"']\)", r"JSON5\.parse\s*\(", r"parseTheme"),
            ),
            ExampleSpec(
                slug="json5-job-options",
                title="Job options parser",
                path="jobs/options.js",
                difficulty=0.54,
                context="Job options parser reads JSON5 configuration before applying defaults.",
                build_code=lambda: """
                    const JSON5 = require("json5");

                    function readOptions(raw) {
                      return JSON5.parse(raw);
                    }
                """,
                line_patterns=(r"require\([\"']json5[\"']\)", r"JSON5\.parse\s*\(", r"readOptions"),
            ),
        ],
    )


def _express_examples() -> List[CuratedExample]:
    return _build_family(
        "CVE-2024-29041",
        "javascript",
        "npm",
        "public advisory: open redirect",
        [
            ExampleSpec(
                slug="express-bounce-route",
                title="Bounce route",
                path="routes/bounce.js",
                difficulty=0.34,
                context="Express route redirects users to a supplied URL parameter.",
                build_code=lambda: """
                    const express = require("express");

                    const app = express();

                    app.get("/bounce", (req, res) => {
                      res.redirect(req.query.next || "/");
                    });
                """,
                line_patterns=(r"require\([\"']express[\"']\)", r"redirect"),
            ),
        ],
    )


def build_curated_examples() -> List[CuratedExample]:
    families = [
        _jinja2_examples(),
        _pillow_examples(),
        _requests_examples(),
        _tornado_examples(),
        _pyyaml_examples(),
        _transformers_examples(),
        _cryptography_examples(),
        _flask_examples(),
        _django_examples(),
        _gunicorn_examples(),
        _body_parser_examples(),
        _axios_examples(),
        _ws_examples(),
        _elliptic_examples(),
        _ip_examples(),
        _cookie_examples(),
        _cross_spawn_examples(),
        _json5_examples(),
        _express_examples(),
    ]
    examples = [item for group in families for item in group]
    with_ids: List[CuratedExample] = []
    for idx, example in enumerate(examples):
        with_ids.append(
            CuratedExample(
                idx=idx,
                slug=example.slug,
                title=example.title,
                path=example.path,
                language=example.language,
                ecosystem=example.ecosystem,
                package=example.package,
                cve_id=example.cve_id,
                severity=example.severity,
                cvss_score=example.cvss_score,
                fixed_version=example.fixed_version,
                summary=example.summary,
                difficulty=example.difficulty,
                context=example.context,
                code=example.code,
                vuln_lines=example.vuln_lines,
                incident_source=example.incident_source,
            )
        )
    return with_ids


CURATED_EXAMPLES = build_curated_examples()


def sample_curated_example(
    rng: Optional[random.Random] = None,
    *,
    high_risk_only: bool = False,
    language: Optional[str] = None,
) -> CuratedExample:
    chooser = rng or random
    pool = CURATED_EXAMPLES
    if language:
        pool = [item for item in pool if item.language == language]
    if high_risk_only:
        pool = [item for item in pool if item.cvss_score >= 8.8] or pool
    if not pool:
        raise ValueError("No curated examples available for the requested filter")
    return chooser.choice(pool)
