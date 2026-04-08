from __future__ import annotations

import uvicorn
from openenv.core.env_server import create_fastapi_app

from env.environment import DepVulnEnv
from env.models import Action, Observation


app = create_fastapi_app(DepVulnEnv, Action, Observation)


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
