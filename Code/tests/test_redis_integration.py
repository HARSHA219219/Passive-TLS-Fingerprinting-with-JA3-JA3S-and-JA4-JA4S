"""Opt-in Redis/Valkey integration test; use a disposable, dedicated test database."""
from __future__ import annotations

import os
import uuid

import pytest

from tlsfp.db import FingerprintDB


@pytest.mark.integration
def test_sync_and_lookup_redis_valkey():
    redis_url = os.environ.get("TLSFP_REDIS_URL")
    if not redis_url:
        pytest.skip("set TLSFP_REDIS_URL to a disposable Redis/Valkey database")
    redis = pytest.importorskip("redis")
    client = redis.Redis.from_url(redis_url, decode_responses=True)
    client.ping()

    marker = uuid.uuid4().hex
    unrelated_key = f"tlsfp:unrelated:{marker}"
    client.set(unrelated_key, "preserve")

    db = FingerprintDB(":memory:")
    value = f"J4-{marker}"
    label = "integration-client"
    try:
        db.add("ja4", value, label, "test")
        assert db.sync_redis(redis_url) == 1

        remote_db = FingerprintDB(":memory:", redis_url)
        match = remote_db.identify(value, None)
        assert (match.status, match.labels) == ("ja4_only", [label])
        assert client.get(unrelated_key) == "preserve"

        db.remove("ja4", value, label)
        db.sync_redis(redis_url)
        assert remote_db.identify(value, None).status == "unknown"
        assert client.get(unrelated_key) == "preserve"
    finally:
        db.remove("ja4", value, label)
        db.sync_redis(redis_url)
        client.delete(unrelated_key)
