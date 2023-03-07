import time

import pytest

from aad_fastapi import CacheManager


@pytest.mark.asyncio
async def test_aad_cache_manager_set():
    await CacheManager.clear()
    key = "a"
    value = {"key": "value"}
    await CacheManager.set(key, value)

    get_value = await CacheManager.get(key)

    assert get_value.get("key") == "value"


@pytest.mark.asyncio
async def test_aad_cache_manager_expiracy():
    await CacheManager.clear()
    key = "a"
    value = {"key": "value"}
    await CacheManager.set(key, value)

    get_value = await CacheManager.get(key)

    assert get_value.get("__expires_at__") is not None


@pytest.mark.asyncio
async def test_aad_cache_manager_remove():
    await CacheManager.clear()
    key = "a"
    value = {"key": "value"}
    await CacheManager.set(key, value)

    assert len(CacheManager.cache_db) == 1
    await CacheManager.remove(key)
    assert len(CacheManager.cache_db) == 0


@pytest.mark.asyncio
async def test_aad_cache_manager_clear():
    await CacheManager.clear()
    key = "a"
    value = {"key": "value"}
    await CacheManager.set(key, value)
    key = "b"
    await CacheManager.set(key, value)

    assert len(CacheManager.cache_db) == 2
    await CacheManager.clear()
    assert len(CacheManager.cache_db) == 0


@pytest.mark.asyncio
async def test_aad_cache_manager_check_expiracy():
    await CacheManager.clear()
    key = "a"
    value = {"key": "value"}
    await CacheManager.set(key, value)
    value = await CacheManager.get(key)
    expires = int(value["__expires_at__"])
    assert expires > int(time.time())
    expires = int(time.time()) - 1000
    assert expires < int(time.time())
    # override expires
    value["__expires_at__"] = expires
    await CacheManager.set(key, value)
    await CacheManager.check_expiracy()
    assert len(CacheManager.cache_db) == 0
