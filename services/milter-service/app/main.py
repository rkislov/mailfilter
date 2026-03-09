from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.runtime import start_milter_thread


@asynccontextmanager
async def lifespan(_: FastAPI):
    start_milter_thread()
    yield


app = FastAPI(title="AniSpam Milter Service", version="0.1.0", lifespan=lifespan)


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}
