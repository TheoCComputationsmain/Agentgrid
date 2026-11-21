"""Run AgentGrid schema creation and immutability migrations once.

Use this before deploying a new AgentGrid version. Do not rely on application
startup for migrations when running on serverless or multi-instance platforms.

By default, production values are read from the local .env.production file so
secrets are never printed or passed on the command line. Set
AGENTGRID_MIGRATION_USE_PROCESS_ENV=1 when the environment is already loaded.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

ENV_FILE = Path(__file__).resolve().parent / ".env.production"
if (
    os.environ.get("AGENTGRID_MIGRATION_USE_PROCESS_ENV") != "1"
    and not os.environ.get("AGENTGRID_DATABASE_URL")
    and ENV_FILE.exists()
):
    load_dotenv(ENV_FILE, override=True)

from main import _ensure_schema, engine


async def run() -> None:
    try:
        await _ensure_schema()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
