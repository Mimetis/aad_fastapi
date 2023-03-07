import time
from asyncio import Lock, create_task, sleep
from typing import Dict, Optional, Any


class CacheManager:
    cache_db: Dict[Any, Any] = dict()
    _lock = Lock()

    @classmethod
    async def set(cls, key: str, value: Dict[str, any]) -> None:
        async with cls._lock:
            if "__expires_at__" not in value:
                expires_in = 86400
                expires_at = time.time() + expires_in
                value["__expires_at__"] = expires_at

            cls.cache_db.update({key: value})

    @classmethod
    async def get(cls, key: str) -> Optional[Dict[str, any]]:
        async with cls._lock:
            return cls.cache_db.get(key, {})

    @classmethod
    async def remove(cls, key: str) -> None:
        async with cls._lock:
            cls.cache_db.pop(key, None)

    @classmethod
    async def clear(cls) -> None:
        async with cls._lock:
            cls.cache_db.clear()

    @classmethod
    async def check_expiracy(cls) -> None:
        # copy list to prevent changing dict size during iteration
        for key in list(CacheManager.cache_db.keys()):
            value = await cls.get(key)
            if value is not None and "__expires_at__" in value:
                expires_at = int(value["__expires_at__"])
                if expires_at < int(time.time()):
                    value = await cls.get(key)
                    if value is not None:
                        del CacheManager.cache_db[key]

    @classmethod
    async def for_ever_check(cls, interval: int = 3600) -> None:
        """sets a never ending task for checking cache expired tasks"""
        while True:
            # wait until next run
            await sleep(interval)
            await cls.check_expiracy()

    @classmethod
    def start_expiracy_daemon(cls, interval: int = 3600) -> None:
        """starts the daemon task for checking cache expired tasks"""

        create_task(cls.for_ever_check(interval))
