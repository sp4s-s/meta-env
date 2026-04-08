"""
Code scenario corpus — realistic code blocks using vulnerable packages.

The agent receives code, must identify vulnerable imports/usage patterns,
reason about reachability, and propose fixes. This forces genuine code
analysis rather than package-name memorization.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .fixtures import FIXTURES


@dataclass(frozen=True)
class CodeScenario:
    """A code block with embedded vulnerable dependency usage."""
    idx: int
    code: str
    language: str                      # python | javascript
    ecosystem: str                     # PyPI | npm
    present_vulns: Tuple[str, ...]     # CVE IDs actually exploitable in this code
    decoy_imports: Tuple[str, ...]     # safe imports mixed in
    difficulty: float                  # 0.0-1.0
    vuln_lines: Tuple[int, ...]        # 1-indexed lines where vuln is triggered
    fix_hint: str                      # expected remediation
    context: str                       # what this code does (brief)


# ── Python code templates ──────────────────────────────────────────────
# Each template: (code, vulns_used, decoys, difficulty, vuln_lines, fix, context)
_PY_TEMPLATES: List[dict] = [
    {
        "code": '''import os
from jinja2 import Environment, BaseLoader

def render_user_template(user_input: str, context: dict) -> str:
    """Render user-supplied template string."""
    env = Environment(loader=BaseLoader())
    template = env.from_string(user_input)
    return template.render(**context)

def main():
    ctx = {"username": "admin", "role": os.getenv("ROLE", "viewer")}
    print(render_user_template("Hello {{ username }}", ctx))
''',
        "vulns": ["CVE-2024-56326"],
        "decoys": ["os"],
        "difficulty": 0.2,
        "vuln_lines": (6, 7),
        "fix": "Upgrade jinja2>=3.1.5; use SandboxedEnvironment",
        "context": "Template rendering service with user-controlled input",
    },
    {
        "code": '''from PIL import Image
import io
import hashlib

def process_upload(data: bytes, max_size: int = 4096) -> dict:
    """Validate and thumbnail an uploaded image."""
    img = Image.open(io.BytesIO(data))
    img.thumbnail((max_size, max_size))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return {
        "hash": hashlib.sha256(buf.getvalue()).hexdigest(),
        "size": buf.tell(),
        "mode": img.mode,
    }
''',
        "vulns": ["CVE-2024-28219"],
        "decoys": ["io", "hashlib"],
        "difficulty": 0.3,
        "vuln_lines": (7,),
        "fix": "Upgrade Pillow>=10.3.0",
        "context": "Image upload processor with untrusted input bytes",
    },
    {
        "code": '''import requests
from urllib.parse import urljoin

class APIClient:
    def __init__(self, base_url: str, token: str):
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.verify = True
        self.base = base_url

    def get(self, path: str) -> dict:
        resp = self.session.get(urljoin(self.base, path))
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, payload: dict) -> dict:
        resp = self.session.post(urljoin(self.base, path), json=payload)
        return resp.json()
''',
        "vulns": ["CVE-2024-35195"],
        "decoys": ["urllib.parse"],
        "difficulty": 0.4,
        "vuln_lines": (7, 8),
        "fix": "Upgrade requests>=2.32.0; session.verify persists across redirects",
        "context": "API client where session cert verification is bypassed on redirect",
    },
    {
        "code": '''from tornado.web import RequestHandler, Application
from tornado.template import Template
import tornado.ioloop

class DynamicPage(RequestHandler):
    def get(self):
        user_tpl = self.get_argument("tpl", "{{name}}")
        t = Template(user_tpl)
        self.write(t.generate(name="world"))

app = Application([(r"/render", DynamicPage)])

if __name__ == "__main__":
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
''',
        "vulns": ["CVE-2024-32651"],
        "decoys": ["tornado.ioloop"],
        "difficulty": 0.25,
        "vuln_lines": (7, 8),
        "fix": "Upgrade tornado>=6.4.1; never pass user input to Template()",
        "context": "Web handler with server-side template injection via user input",
    },
    {
        "code": '''from flask import Flask, session, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

@app.route("/login", methods=["POST"])
def login():
    session["user"] = "admin"
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return f"Welcome {session['user']}"
''',
        "vulns": ["CVE-2023-30861"],
        "decoys": ["os"],
        "difficulty": 0.5,
        "vuln_lines": (4, 9),
        "fix": "Upgrade Flask>=3.0.1; session cookie set on every response",
        "context": "Flask app with session fixation vulnerability",
    },
    {
        "code": '''import yaml
import sys

def load_config(path: str) -> dict:
    """Load YAML configuration file."""
    with open(path) as f:
        return yaml.load(f, Loader=yaml.FullLoader)

def merge_configs(*paths: str) -> dict:
    merged = {}
    for p in paths:
        merged.update(load_config(p))
    return merged

if __name__ == "__main__":
    cfg = merge_configs(*sys.argv[1:])
    print(cfg)
''',
        "vulns": ["CVE-2024-20060"],
        "decoys": ["sys"],
        "difficulty": 0.45,
        "vuln_lines": (7,),
        "fix": "Upgrade PyYAML>=6.0.2; use yaml.safe_load()",
        "context": "Config loader using unsafe YAML deserialization",
    },
    {
        "code": '''from django.core.validators import validate_email
from django.http import JsonResponse
from django.views import View

class ValidateEmailView(View):
    def post(self, request):
        email = request.POST.get("email", "")
        try:
            validate_email(email)
            return JsonResponse({"valid": True})
        except Exception:
            return JsonResponse({"valid": False})
''',
        "vulns": ["CVE-2024-27351"],
        "decoys": [],
        "difficulty": 0.55,
        "vuln_lines": (9,),
        "fix": "Upgrade Django>=5.0.3; truncated unicode ReDoS in EmailValidator",
        "context": "Django email validation endpoint vulnerable to ReDoS",
    },
    {
        "code": '''from gunicorn.app.wsgiapp import WSGIApplication
from gunicorn.config import Config

class App(WSGIApplication):
    def init(self, parser, opts, args):
        cfg = {"bind": "0.0.0.0:8000", "workers": 4}
        return cfg

    def load(self):
        from myapp import create_app
        return create_app()

if __name__ == "__main__":
    App("%(prog)s [OPTIONS]").run()
''',
        "vulns": ["CVE-2024-1135"],
        "decoys": [],
        "difficulty": 0.6,
        "vuln_lines": (1,),
        "fix": "Upgrade gunicorn>=22.0.0; HTTP request smuggling via chunked TE",
        "context": "Gunicorn deployment vulnerable to HTTP smuggling",
    },
    {
        "code": '''from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

def load_model(path: str):
    tokenizer = AutoTokenizer.from_pretrained(path, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        path, torch_dtype=torch.float16, trust_remote_code=True
    )
    return model, tokenizer

def generate(model, tokenizer, prompt: str) -> str:
    inputs = tokenizer(prompt, return_tensors="pt")
    out = model.generate(**inputs, max_new_tokens=256)
    return tokenizer.decode(out[0], skip_special_tokens=True)
''',
        "vulns": ["CVE-2024-3568"],
        "decoys": ["torch"],
        "difficulty": 0.35,
        "vuln_lines": (5, 7),
        "fix": "Upgrade transformers>=4.38.2; do not use trust_remote_code=True with untrusted models",
        "context": "Model loading with trust_remote_code enabling RCE",
    },
    {
        "code": '''from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
import ssl

def load_p12(path: str, password: bytes) -> ssl.SSLContext:
    with open(path, "rb") as f:
        private_key, cert, chain = pkcs12.load_key_and_certificates(
            f.read(), password, default_backend()
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=cert, keyfile=private_key)
    return ctx
''',
        "vulns": ["CVE-2024-26130"],
        "decoys": ["ssl"],
        "difficulty": 0.65,
        "vuln_lines": (7, 8),
        "fix": "Upgrade cryptography>=42.0.4; PKCS12 NULL pointer dereference",
        "context": "TLS cert loading with NULL pointer crash on malformed PKCS12",
    },
]

# ── JavaScript code templates ──────────────────────────────────────────
_JS_TEMPLATES: List[dict] = [
    {
        "code": '''const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json({ limit: "50mb" }));

app.post("/webhook", (req, res) => {
  const payload = req.body;
  console.log("Received:", JSON.stringify(payload).slice(0, 100));
  res.json({ ok: true });
});

app.listen(3000);
''',
        "vulns": ["CVE-2024-45590", "CVE-2024-29041"],
        "decoys": [],
        "difficulty": 0.3,
        "vuln_lines": (5,),
        "fix": "Upgrade body-parser>=1.20.3; upgrade express>=4.19.2",
        "context": "Express webhook with unbounded body parsing DoS",
    },
    {
        "code": '''const axios = require("axios");

async function fetchUser(baseUrl, userId) {
  const url = `${baseUrl}/api/users/${userId}`;
  const { data } = await axios.get(url);
  return data;
}

async function proxyRequest(targetUrl) {
  const resp = await axios.get(targetUrl, { maxRedirects: 5 });
  return resp.data;
}

module.exports = { fetchUser, proxyRequest };
''',
        "vulns": ["CVE-2024-39338"],
        "decoys": [],
        "difficulty": 0.35,
        "vuln_lines": (10,),
        "fix": "Upgrade axios>=1.7.4; SSRF via path traversal in URL",
        "context": "HTTP client with SSRF via path traversal in redirect",
    },
    {
        "code": '''const WebSocket = require("ws");

const wss = new WebSocket.Server({ port: 8080 });

wss.on("connection", (ws, req) => {
  console.log("Client:", req.headers["sec-websocket-protocol"]);
  ws.on("message", (msg) => {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(msg.toString());
      }
    });
  });
});
''',
        "vulns": ["CVE-2024-37890"],
        "decoys": [],
        "difficulty": 0.4,
        "vuln_lines": (3,),
        "fix": "Upgrade ws>=8.17.1; DoS via invalid Sec-WebSocket headers",
        "context": "WebSocket broadcast server vulnerable to header-based DoS",
    },
    {
        "code": '''const { verify } = require("elliptic").ec("secp256k1");
const crypto = require("crypto");

function verifySignature(publicKey, message, signature) {
  const hash = crypto.createHash("sha256").update(message).digest();
  const key = verify(hash, signature, publicKey, "hex");
  return key;
}

function signMessage(privateKey, message) {
  const hash = crypto.createHash("sha256").update(message).digest();
  return privateKey.sign(hash);
}

module.exports = { verifySignature, signMessage };
''',
        "vulns": ["CVE-2024-48949"],
        "decoys": ["crypto"],
        "difficulty": 0.5,
        "vuln_lines": (1, 6),
        "fix": "Upgrade elliptic>=6.5.6; invalid ECDSA signature passes verification",
        "context": "Crypto signature verification with bypass vulnerability",
    },
    {
        "code": '''const net = require("net");
const { isPrivate } = require("ip");

function validateTarget(host) {
  if (isPrivate(host)) {
    throw new Error("Cannot connect to private addresses");
  }
  return host;
}

function connect(host, port) {
  const target = validateTarget(host);
  const socket = net.createConnection({ host: target, port });
  return socket;
}

module.exports = { connect };
''',
        "vulns": ["CVE-2024-29415"],
        "decoys": ["net"],
        "difficulty": 0.3,
        "vuln_lines": (2, 5),
        "fix": "Upgrade ip>=2.0.1; isPrivate bypass allows SSRF to internal hosts",
        "context": "Network client with SSRF bypass via ip module bug",
    },
    {
        "code": '''const { parse } = require("cookie");
const express = require("express");

const app = express();

app.use((req, res, next) => {
  req.cookies = parse(req.headers.cookie || "");
  next();
});

app.get("/profile", (req, res) => {
  const session = req.cookies.session_id;
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  res.json({ session, user: "loaded" });
});

app.listen(3001);
''',
        "vulns": ["CVE-2024-47764"],
        "decoys": [],
        "difficulty": 0.45,
        "vuln_lines": (1, 7),
        "fix": "Upgrade cookie>=0.7.0; attribute parse bypass",
        "context": "Cookie handling with attribute parsing bypass",
    },
    {
        "code": '''const { spawn } = require("cross-spawn");
const path = require("path");

function runLinter(filePath) {
  const ext = path.extname(filePath);
  const cmd = ext === ".py" ? "ruff" : "eslint";
  const child = spawn(cmd, ["--fix", filePath], { stdio: "pipe" });

  let output = "";
  child.stdout.on("data", (d) => (output += d));
  child.on("close", (code) => console.log(`Exit ${code}: ${output}`));
  return child;
}

module.exports = { runLinter };
''',
        "vulns": ["CVE-2024-21538"],
        "decoys": ["path"],
        "difficulty": 0.55,
        "vuln_lines": (1, 7),
        "fix": "Upgrade cross-spawn>=7.0.5; ReDoS via shell metachar injection",
        "context": "Process spawner with ReDoS on crafted filenames",
    },
    {
        "code": '''const JSON5 = require("json5");
const fs = require("fs");

function loadConfig(configPath) {
  const raw = fs.readFileSync(configPath, "utf-8");
  const config = JSON5.parse(raw);
  return config;
}

function mergeDefaults(config) {
  const defaults = { port: 3000, host: "localhost", debug: false };
  return { ...defaults, ...config };
}

module.exports = { loadConfig, mergeDefaults };
''',
        "vulns": ["CVE-2022-46175"],
        "decoys": ["fs"],
        "difficulty": 0.5,
        "vuln_lines": (6,),
        "fix": "Upgrade json5>=2.2.3; prototype pollution via __proto__ in parse",
        "context": "Config loader with prototype pollution via JSON5 parse",
    },
]


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()[:10]


def build_corpus(rng: Optional[random.Random] = None) -> List[CodeScenario]:
    """Build the full code scenario corpus from templates."""
    rng = rng or random.Random(271828)
    scenarios: List[CodeScenario] = []
    idx = 0

    for t in _PY_TEMPLATES:
        scenarios.append(CodeScenario(
            idx=idx, code=t["code"], language="python", ecosystem="PyPI",
            present_vulns=tuple(t["vulns"]), decoy_imports=tuple(t["decoys"]),
            difficulty=t["difficulty"], vuln_lines=tuple(t["vuln_lines"]),
            fix_hint=t["fix"], context=t["context"],
        ))
        idx += 1

    for t in _JS_TEMPLATES:
        scenarios.append(CodeScenario(
            idx=idx, code=t["code"], language="javascript", ecosystem="npm",
            present_vulns=tuple(t["vulns"]), decoy_imports=tuple(t["decoys"]),
            difficulty=t["difficulty"], vuln_lines=tuple(t["vuln_lines"]),
            fix_hint=t["fix"], context=t["context"],
        ))
        idx += 1

    return scenarios


# ── Composite scenario builder (multi-file projects) ──────────────────

def build_composite(base: List[CodeScenario], n_files: int = 3,
                    rng: Optional[random.Random] = None) -> Dict[str, Any]:
    """
    Combine multiple code scenarios into a simulated multi-file project.
    Returns a dict with file paths, combined vulns, and difficulty.
    """
    rng = rng or random.Random(31415)
    picks = rng.sample(base, min(n_files, len(base)))
    files = {}
    all_vulns = []
    total_diff = 0.0

    for i, sc in enumerate(picks):
        ext = "py" if sc.language == "python" else "js"
        fname = f"src/module_{i}.{ext}"
        files[fname] = sc.code
        all_vulns.extend(sc.present_vulns)
        total_diff += sc.difficulty

    return {
        "files": files,
        "vulns": list(set(all_vulns)),
        "difficulty": round(total_diff / len(picks), 2),
        "n_files": len(picks),
    }


# Module-level corpus
CORPUS = build_corpus()
CORPUS_BY_DIFFICULTY = sorted(CORPUS, key=lambda s: s.difficulty)
