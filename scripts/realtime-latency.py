#!/usr/bin/env python3
"""Phase 7 latency & load probe.

Measures the path:
    POST /api/v1/ingest  →  DB insert  →  WebSocket broadcast

Reports p50/p95/max latency over N events. Also fires a 1000-event burst
and confirms no events are lost.

Usage:
    python scripts/realtime-latency.py
    python scripts/realtime-latency.py --burst 1000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import urllib.parse
import urllib.request

import websockets

API_BASE = "http://localhost:8000"
WS_BASE = "ws://localhost:8000"
PASSWORD = "TestPass123!"


def _post(path, data, headers=None, timeout=60):
    body = json.dumps(data).encode("utf-8") if not isinstance(data, bytes) else data
    req = urllib.request.Request(
        f"{API_BASE}{path}",
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _seed_user_and_key():
    email = f"phase7-{int(time.time()*1000)}@trustflow.test"
    reg = _post("/api/auth/register", {"email": email, "password": PASSWORD, "display_name": "P7"})
    tok = reg["access_token"]
    key = _post("/api/keys", {"name": "p7"}, headers={"Authorization": f"Bearer {tok}"})["key"]
    return email, tok, key


async def measure_p95(n_events: int):
    email, access_token, api_key = _seed_user_and_key()
    print(f"User: {email}")

    ws_url = f"{WS_BASE}/ws/live-feed?token={urllib.parse.quote(access_token)}"
    latencies = []

    async with websockets.connect(ws_url, max_size=2**20) as ws:
        # Drain history first
        try:
            for _ in range(20):
                await asyncio.wait_for(ws.recv(), timeout=0.5)
        except asyncio.TimeoutError:
            pass

        for i in range(n_events):
            marker = f"p7marker{i:06d}_{int(time.time()*1e6)}"
            ev = {
                "events": [{
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "user": marker,
                    "ip": "10.0.0.42",
                    "action": "GET",
                    "status": "success",
                    "resource": "/p7",
                }],
            }
            t0 = time.perf_counter()

            # Fire ingest in a thread so we can keep awaiting WS
            await asyncio.get_running_loop().run_in_executor(
                None, lambda: _post("/api/v1/ingest", ev, headers={"X-API-Key": api_key})
            )

            # Wait for broadcast carrying this marker (skip pings/history)
            seen = False
            deadline = time.perf_counter() + 5.0
            while time.perf_counter() < deadline:
                try:
                    msg = json.loads(
                        await asyncio.wait_for(ws.recv(), timeout=deadline - time.perf_counter())
                    )
                except asyncio.TimeoutError:
                    break
                if msg.get("type") == "new_event" and marker in str(msg.get("data", {})):
                    seen = True
                    break
            if not seen:
                print(f"  WARN: never saw {marker} on WS")
                continue
            latencies.append((time.perf_counter() - t0) * 1000)  # ms

    if not latencies:
        print("FAIL: no events delivered to WebSocket")
        raise SystemExit(1)

    p50 = statistics.median(latencies)
    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    p99 = statistics.quantiles(latencies, n=100)[98] if len(latencies) >= 100 else max(latencies)
    print(f"Latency over {len(latencies)} events:")
    print(f"  p50 = {p50:7.1f} ms")
    print(f"  p95 = {p95:7.1f} ms")
    print(f"  p99 = {p99:7.1f} ms")
    print(f"  max = {max(latencies):7.1f} ms")
    target_p95_ms = 1000
    verdict = "PASS" if p95 <= target_p95_ms else "FAIL"
    print(f"Target p95 < {target_p95_ms} ms — {verdict}")
    if verdict == "FAIL":
        raise SystemExit(1)


def burst_test(n: int):
    email, tok, key = _seed_user_and_key()
    print(f"Burst test: {n} events as one batch")

    events = [{
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user": f"burst-{i}",
        "ip": "10.0.0.99",
        "action": "GET",
        "status": "success",
        "resource": "/burst",
    } for i in range(n)]

    t0 = time.perf_counter()
    resp = _post("/api/v1/ingest", {"events": events}, headers={"X-API-Key": key})
    elapsed = time.perf_counter() - t0
    print(f"Batch accepted: {resp.get('accepted')}/{resp.get('total')} in {elapsed*1000:.0f} ms")

    if resp.get("accepted") != n:
        print(f"FAIL: only {resp.get('accepted')} of {n} accepted")
        raise SystemExit(1)

    # Verify all events landed by paginating the events API.
    time.sleep(2.0)
    seen = 0
    page = 1
    PAGE_SIZE = 200  # /api/events caps limit at 200
    while True:
        req = urllib.request.Request(
            f"{API_BASE}/api/events?page={page}&limit={PAGE_SIZE}",
            headers={"Authorization": f"Bearer {tok}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        rows = data.get("data", [])
        seen += sum(1 for e in rows if (e.get("user") or "").startswith("burst-"))
        if len(rows) < PAGE_SIZE or page >= 20:
            break
        page += 1
    print(f"Events queryable for tenant: {seen}")
    if seen < n:
        print(f"FAIL: only {seen} of {n} events queryable")
        raise SystemExit(1)
    print("PASS")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--events", type=int, default=20, help="latency-probe events")
    p.add_argument("--burst", type=int, default=0, help="if >0 also run a burst test")
    args = p.parse_args()

    if args.events > 0:
        asyncio.run(measure_p95(args.events))
    if args.burst > 0:
        burst_test(args.burst)


if __name__ == "__main__":
    main()
