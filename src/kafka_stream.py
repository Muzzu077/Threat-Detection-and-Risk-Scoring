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
import threading
from datetime import datetime

_TOPIC = os.getenv("KAFKA_EVENTS_TOPIC", "trustflow.events")

_producer = None
_producer_lock = threading.Lock()
_producer_failed = False  # latch — flips on first failure to avoid retry storms


def _brokers() -> str:
    return os.getenv("KAFKA_BROKERS", "").strip()


def is_enabled() -> bool:
    return bool(_brokers()) and not _producer_failed


async def _ensure_producer():
    """Lazy-start the aiokafka producer. Returns the producer or None."""
    global _producer, _producer_failed
    if _producer is not None:
        return _producer
    if _producer_failed or not _brokers():
        return None
    try:
        from aiokafka import AIOKafkaProducer
        with _producer_lock:
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
        print(f"⚠️  Kafka producer failed to start: {e} — disabling for this process")
        _producer_failed = True
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
