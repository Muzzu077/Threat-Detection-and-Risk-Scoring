"""
TrustFlow — Kafka Streaming Producer (Phase 4)

Optionally fans-out every ingested event to a Kafka topic so downstream
analytics, lake jobs, or sibling SOC platforms can consume the same stream.

Enabled by setting KAFKA_BROKERS=host:9092[,host:9092] in the environment.
When unset, every public function is a no-op so the ingest path keeps
running unchanged.

Design notes:
    - We use aiokafka with a singleton producer per process; first call to
      publish_event() lazily starts the producer.
    - Failures are logged once and the latch flips off, so we never spam
      logs or block the API thread.
    - For broker-less local development, callers see {ok: False, skipped: True}.
"""
import os
import json
import asyncio
from datetime import datetime

_TOPIC = os.getenv("KAFKA_EVENTS_TOPIC", "trustflow.events")

_producer = None
_producer_lock = asyncio.Lock()  # async-safe lock (was threading.Lock — caused deadlocks)
_producer_fail_count = 0
_MAX_FAILURES = 5
_RECOVERY_INTERVAL = 60  # seconds — retry after this cooldown
_last_failure_time = 0.0


def _brokers() -> str:
    return os.getenv("KAFKA_BROKERS", "").strip()


def is_enabled() -> bool:
    return bool(_brokers()) and _producer_fail_count < _MAX_FAILURES


async def _ensure_producer():
    """Lazy-start the aiokafka producer with circuit breaker recovery."""
    global _producer, _producer_fail_count, _last_failure_time
    if _producer is not None:
        return _producer
    if not _brokers():
        return None
    # Circuit breaker: if too many failures, wait for cooldown before retrying
    if _producer_fail_count >= _MAX_FAILURES:
        import time as _time
        if _time.time() - _last_failure_time < _RECOVERY_INTERVAL:
            return None
        _producer_fail_count = 0  # cooldown elapsed — reset and retry
    try:
        from aiokafka import AIOKafkaProducer
        async with _producer_lock:  # async lock — yields to event loop while waiting
            if _producer is None:
                p = AIOKafkaProducer(
                    bootstrap_servers=_brokers(),
                    client_id="trustflow-api",
                    acks="1",
                    request_timeout_ms=5000,
                    max_request_size=1048576,
                )
                await p.start()
                _producer = p
        return _producer
    except Exception as e:
        import time as _time
        _producer_fail_count += 1
        _last_failure_time = _time.time()
        if _producer_fail_count >= _MAX_FAILURES:
            print(f"⚠️  Kafka producer failed {_MAX_FAILURES} times: {e} — circuit breaker open for {_RECOVERY_INTERVAL}s")
        return None


async def publish_event_async(event: dict, incident_id: int = 0) -> dict:
    """Publish a single event to the Kafka topic. Best-effort, fail-open."""
    p = await _ensure_producer()
    if p is None:
        return {"ok": False, "skipped": True, "reason": "kafka not configured"}

    payload = json.dumps({
        "schema": "trustflow.event/v1",
        "ingested_at": datetime.utcnow().isoformat() + "Z",
        "incident_id": incident_id,
        "tenant_id": event.get("tenant_id"),
        "application_id": event.get("application_id"),
        "event": {
            "user":        event.get("user"),
            "ip":          event.get("ip"),
            "action":      event.get("action"),
            "status":      event.get("status"),
            "resource":    event.get("resource"),
            "country":     event.get("country"),
            "risk_score":  event.get("risk_score"),
            "attack_type": event.get("attack_type"),
            "explanation": event.get("explanation"),
        },
    }).encode("utf-8")

    # Partition key by tenant_id so per-tenant ordering is preserved
    key = str(event.get("tenant_id") or "global").encode("utf-8")
    try:
        await p.send_and_wait(_TOPIC, payload, key=key)
        return {"ok": True, "topic": _TOPIC}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def publish_event(event: dict, incident_id: int = 0) -> dict:
    """Synchronous shim — runs the async publish on the running event loop."""
    if not is_enabled():
        return {"ok": False, "skipped": True, "reason": "kafka not configured"}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Schedule and don't await — fire-and-forget
            asyncio.ensure_future(publish_event_async(event, incident_id))
            return {"ok": True, "scheduled": True}
        return loop.run_until_complete(publish_event_async(event, incident_id))
    except RuntimeError:
        # No loop in this thread — make one
        return asyncio.run(publish_event_async(event, incident_id))
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def shutdown():
    global _producer
    if _producer is not None:
        try:
            await _producer.stop()
        except Exception:
            pass
        _producer = None
