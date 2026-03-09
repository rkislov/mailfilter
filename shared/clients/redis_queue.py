from __future__ import annotations

import json
from typing import Any

from redis import Redis


class RedisQueue:
    def __init__(self, redis_client: Redis, queue_name: str) -> None:
        self.redis_client = redis_client
        self.queue_name = queue_name

    def push(self, payload: dict[str, Any]) -> None:
        self.redis_client.rpush(self.queue_name, json.dumps(payload))

    def blocking_pop(self, timeout: int = 5) -> dict[str, Any] | None:
        result = self.redis_client.blpop(self.queue_name, timeout=timeout)
        if result is None:
            return None
        _, raw = result
        return json.loads(raw)
