from __future__ import annotations

import uvicorn
import gradio as gr
from openenv.core.env_server import create_fastapi_app

from env.environment import DepVulnEnv
from env.models import Action, Observation
from api.routes import router as api_router
from server.ui import ui as gradio_ui


app = create_fastapi_app(DepVulnEnv, Action, Observation)
app.include_router(api_router)
app = gr.mount_gradio_app(app, gradio_ui, path="/")

def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
