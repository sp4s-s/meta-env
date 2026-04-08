from __future__ import annotations

import uvicorn
import gradio as gr
from fastapi import Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

from openenv.core.env_server import create_fastapi_app

from env.environment import DepVulnEnv
from env.models import Action, Observation
from api.routes import router as api_router
from server.ui import ui as gradio_ui

app = create_fastapi_app(DepVulnEnv, Action, Observation)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=3600,
)

# Request body size limit (5 MB)
_MAX_BODY = 5 * 1024 * 1024


@app.middleware("http")
async def body_size_limiter(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BODY:
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return response


app.include_router(api_router)
app = gr.mount_gradio_app(app, gradio_ui, path="/")


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
