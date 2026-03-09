from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime

import httpx
from redis import Redis


REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
QUEUE_NAME = os.getenv("SCAN_QUEUE_NAME", "anispam:scan-jobs")
POLICY_API_URL = os.getenv("POLICY_API_URL", "http://policy-api:8080")


def main() -> None:
    redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
    while True:
        item = redis_client.blpop(QUEUE_NAME, timeout=5)
        if item is None:
            continue
        _, payload = item
        job = json.loads(payload)
        asyncio.run(process_job(job))


async def process_job(job: dict) -> None:
    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            await client.get(f"{POLICY_API_URL}/healthz")
            print(
                json.dumps(
                    {
                        "worker": "scan",
                        "status": "processed",
                        "job": job,
                        "processed_at": datetime.utcnow().isoformat(),
                    }
                ),
                flush=True,
            )
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "worker": "scan",
                        "status": "error",
                        "job": job,
                        "error": str(exc),
                        "processed_at": datetime.utcnow().isoformat(),
                    }
                ),
                flush=True,
            )
            time.sleep(2)


if __name__ == "__main__":
    main()
