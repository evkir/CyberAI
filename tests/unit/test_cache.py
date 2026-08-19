import time

import pytest

from cyberai.core.cache import FileCache


@pytest.fixture
def cache(tmp_path):
    return FileCache(cache_dir=tmp_path, ttl=60)


def test_set_and_get(cache):
    cache.set("key1", {"data": 42})
    result = cache.get("key1")
    assert result == {"data": 42}


def test_missing_key_returns_none(cache):
    assert cache.get("nonexistent") is None


def test_expired_returns_none(tmp_path):
    c = FileCache(cache_dir=tmp_path, ttl=1)
    c.set("expiring", "value")
    time.sleep(1.1)
    assert c.get("expiring") is None


def test_delete(cache):
    cache.set("to_delete", "bye")
    cache.delete("to_delete")
    assert cache.get("to_delete") is None


def test_clear(cache):
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    count = cache.clear()
    assert count == 3
    assert cache.get("a") is None


def test_stats(cache):
    cache.set("x", 1)
    cache.set("y", 2)
    stats = cache.stats()
    assert stats["total"] == 2
    assert stats["valid"] == 2
    assert stats["expired"] == 0


def test_stats_expired(tmp_path):
    c = FileCache(cache_dir=tmp_path, ttl=1)
    c.set("old", "data")
    time.sleep(1.1)
    stats = c.stats()
    assert stats["expired"] == 1
    assert stats["valid"] == 0


def test_overwrite_key(cache):
    cache.set("k", "first")
    cache.set("k", "second")
    assert cache.get("k") == "second"


def test_different_keys_dont_collide(cache):
    cache.set("alpha", 1)
    cache.set("beta", 2)
    assert cache.get("alpha") == 1
    assert cache.get("beta") == 2
