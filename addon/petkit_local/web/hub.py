"""EventHub — in-memory event ring buffer, live pub/sub, and per-device
diagnostics feeding the web panel.

Single asyncio loop, so no locking needed. Nothing here is persisted; it's a
live view of what the add-on is seeing right now.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict, deque
from typing import Any, Container

#: Cap on one MQTT payload in the live log. Same reasoning as
#: `http/middleware/logging.py::_short`: the ring holds these in memory and ships every
#: one of them to every open browser.
_PAYLOAD_LIMIT = 4000

#: How many devices keep diagnostics. Far above any real install — the point is
#: only that the number exists, because the key comes from an unauthenticated
#: request header (see `EventHub._diag`).
MAX_TRACKED_DEVICES = 64

#: Distinct proxy outcomes counted. `error_<code>` is built from an
#: upstream-controlled response body, so it is bounded for the same reason.
MAX_TRACKED_OUTCOMES = 64


def _payload_text(payload: Any) -> str:
    """An MQTT payload as JSON text, capped, marking what was cut.

    Falls back to `repr` for anything json cannot take — a frame worth looking
    at in the log is exactly the one whose shape was unexpected.

    Bytes are decoded rather than repr'd. Frames arrive already encoded on two
    paths — proxy mode relays the cloud's `result.body`, and the bridge captures
    raw wire payloads — and `json.dumps` refuses bytes, so without this the
    panel rendered a cloud command as the Python literal `b'{"method": ...}'`:
    unreadable, and no longer JSON for the expander to pretty-print.
    """
    if isinstance(payload, (bytes, bytearray)):
        text = bytes(payload).decode("utf-8", "replace")
    elif isinstance(payload, str):
        text = payload
    else:
        try:
            text = json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            text = repr(payload)
    if len(text) <= _PAYLOAD_LIMIT:
        return text
    return text[:_PAYLOAD_LIMIT] + f"\n... (+{len(text) - _PAYLOAD_LIMIT} bytes truncated)"


def _short_topic(topic: str) -> str:
    """`/sys/{pk}/{dn}/thing/event/property/post` -> `event/property/post`.

    The product key and device name are identical on every row of a device's
    feed and take up most of the width. The full topic stays in the detail.
    """
    marker = "/thing/"
    i = topic.find(marker)
    return topic[i + len(marker):] if i >= 0 else topic


class EventHub:
    """Live activity feed + per-device diagnostics for the panel.

    Two independent views over the same stream of `publish()` calls:

    * a bounded ring of the most recent events, replayed to a panel that has
      just connected, plus a fan-out to every open WebSocket subscriber; and
    * a per-device diagnostics dict (counters and last-seen snapshots) the
      panel's device page renders.

    Invariants a reader must know: everything is volatile (a restart starts
    empty — this is not the EventStore), the ring is capped so a chatty device
    cannot grow it without bound, and a subscriber whose queue is full has its
    event DROPPED rather than being allowed to block the publisher, since a
    stalled panel tab must never stall the HTTP server or the MQTT bridge.
    """

    def __init__(self, maxlen: int = 800) -> None:
        """`maxlen` caps the replay ring only.

        A subscriber's own queue is bounded separately, in `subscribe()`: the
        ring decides how much history a newly-opened panel gets, the queue
        decides how far behind a live tab may fall before it starts missing
        events. Raising one does not raise the other.
        """
        self._ring: deque[dict] = deque(maxlen=maxlen)
        self._subs: set[asyncio.Queue] = set()
        # An LRU, not a plain dict: the key is a device id taken straight from
        # the `X-Device` header, and the device API binds 0.0.0.0:80 with no
        # registration required — so anything on the LAN could add one entry
        # per id, forever, just by looping curl with an incrementing number. A
        # device that reboots with a fresh id does it accidentally. Real
        # installs have a handful of devices, so a cap loses nothing.
        self._diag: OrderedDict[Any, dict] = OrderedDict()
        self._seq = 0
        self._redactions: dict[str, int] = {}
        # Same shape, same reason: the key is `error_<code>` built from an
        # upstream-controlled response body.
        self._upstream: OrderedDict[str, int] = OrderedDict()

    # --- events -----------------------------------------------------------
    def publish(self, kind: str, device_id: Any = None, summary: str = "",
                detail: Any = None) -> dict:
        """Append an event to the ring and fan it out to live subscribers.

        Returns the stored event: `{seq, ts, kind, device_id, summary}` plus
        `detail` when one was given. `seq` is a per-process monotonic counter
        the panel uses to tell a replayed event from a new one.
        """
        self._seq += 1
        ev = {
            "seq": self._seq,
            "ts": time.time(),
            "kind": kind,
            "device_id": device_id,
            "summary": summary,
        }
        if detail is not None:
            ev["detail"] = detail
        self._ring.append(ev)
        for q in list(self._subs):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                # A panel tab that stopped reading must not stall the publisher
                # (which is the request path); it just misses events.
                pass
        return ev

    def recent(self, limit: int = 200, device_id: Any = None,
               kinds: Container[str] | None = None) -> list[dict]:
        """The newest matching events, oldest-first, at most `limit` of them."""
        evs = list(self._ring)
        if device_id is not None:
            evs = [e for e in evs if e["device_id"] == device_id]
        if kinds:
            evs = [e for e in evs if e["kind"] in kinds]
        return evs[-limit:]

    def subscribe(self) -> asyncio.Queue:
        """Register a live feed for one WebSocket connection.

        The queue is bounded: see the class docstring on why overflow drops
        events instead of applying backpressure. Callers must `unsubscribe()`
        it when the connection ends, or it is retained forever.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Drop a live feed. Idempotent — safe to call from a `finally`."""
        self._subs.discard(q)

    # --- per-device diagnostics ------------------------------------------
    def _d(self, device_id: Any) -> dict:
        """The mutable diagnostics dict for a device, created on first use.

        Touching a device moves it to the end, so the cap evicts whichever
        device has been quiet longest — never the one you are watching.
        """
        entry = self._diag.get(device_id)
        if entry is None:
            entry = {"http_count": 0, "mqtt_count": 0}
            self._diag[device_id] = entry
            while len(self._diag) > MAX_TRACKED_DEVICES:
                self._diag.popitem(last=False)
        else:
            self._diag.move_to_end(device_id)
        return entry

    def record_http(self, device_id: Any, method: str, path: str, status: int,
                    detail: Any = None) -> None:
        """Count one handled HTTP request and publish it to the feed."""
        d = self._d(device_id)
        d["http_count"] += 1
        d["last_http"] = {"ts": time.time(), "method": method, "path": path, "status": status}
        self.publish("http", device_id, f"{method} {path} -> {status}", detail=detail)

    def set_state_report(self, device_id: Any, body: dict) -> None:
        """Remember the last raw dev_state_report body (the panel shows it
        verbatim, since it is the ground truth the state parsers work from)."""
        self._d(device_id)["last_state_report"] = {"ts": time.time(), "body": body}

    def record_mqtt(self, device_id: Any, topic: str, payload: Any, *,
                    outbound: bool = False, client: str = "",
                    origin: str = "") -> None:
        """Publish one MQTT frame to the live log; keep the last property snapshot.

        The payload rides along as the event's `detail`, which is the whole
        reason the row can be expanded in the panel — an event published without
        one renders as a bare summary line and nothing else.

        `client` names the party at the other end — the peer this frame is
        travelling TO for an outbound one, and FROM for an inbound one. Without
        it the only place the device name appears is buried in the middle of the
        topic, which is also the part `_short_topic` cuts for the summary.

        `origin` names where an outbound frame came from when that is not us:
        proxy mode relays the real cloud's commands down to the device, and
        those are outbound (we publish them) while originating elsewhere. Naming
        the origin in `client` instead reads as the destination and renders
        exactly backwards — "to the real cloud" for a frame arriving from it.

        `outbound` frames are ours, on their way to the device, and are
        deliberately NOT counted in `mqtt_count`: that counter answers "is this
        device talking to us", and would otherwise answer yes to our own
        traffic. Only an inbound `property/post` updates the retained snapshot —
        it is the device's full property state, and keeping every topic's would
        turn the diagnostics dict into a second, unbounded ring.
        """
        d = self._d(device_id)
        if not outbound:
            d["mqtt_count"] += 1
            d["last_mqtt"] = {"ts": time.time(), "topic": topic}
            if topic.endswith("/property/post"):
                d["last_property"] = {"ts": time.time(), "payload": payload}
        who = ("to " if outbound else "from ") + (client or "device")
        if origin:
            who += f" (relayed from {origin})"
        self.publish("mqtt", device_id, f"{who}: {_short_topic(topic)}", detail={
            "topic": topic,
            "direction": (f"{origin} → server → device" if origin else "server → device")
                         if outbound else "device → server",
            "client": client,
            "origin": origin,
            "payload": _payload_text(payload),
        })

    def record_connect(self, device_id: Any, info: dict) -> None:
        """Record an MQTT broker connection attempt (see mqtt/auth.py).

        `info` carries at least `ok`; `username`/`client_id` when the
        credentials could be parsed, and `refused` for a refusal that was not
        a mismatch. A failed match is recorded too — it is the single most
        useful thing to see when a device won't connect.
        """
        self._d(device_id)["last_connect"] = {"ts": time.time(), **info}
        who = info.get("username") or info.get("client_id") or "?"
        outcome = "ok" if info.get("ok") else info.get("refused") or "no-match"
        self.publish("connect", device_id, f"MQTT connect: {who} ({outcome})")

    def record_command(self, device_id: Any, transport: str, summary: str) -> None:
        """Publish a command we sent to a device (`transport` = mqtt/local/...)."""
        self.publish("cmd", device_id, f"-> {transport}: {summary}")

    def record_redaction(self, device_id: Any, rule: str, summary: str,
                         detail: Any = None, blocked: bool = False) -> None:
        """Note one thing proxy mode took out of an upstream reply.

        Counted here rather than persisted because most of these are routine:
        the device re-polls `dev_serverinfo`, `dev_device_info` and its STS
        block on their own timers, so an address or timezone substitution is
        background noise that means nothing except "proxy mode is on".
        A `blocked` one — a command, a firmware push, a foreign credential — is
        rare, and `events/store.py::add_blocked_attempts` keeps that one for
        real; the live event published here is only how it reaches an open panel.
        """
        self._redactions[rule] = self._redactions.get(rule, 0) + 1
        self.publish("blocked" if blocked else "redact", device_id, summary, detail=detail)

    def redaction_counts(self) -> dict[str, int]:
        """Per-rule totals since the process started, for the panel's counter."""
        return dict(self._redactions)

    def record_upstream(self, outcome: str) -> None:
        """Count one proxied call by what the upstream actually gave us.

        Counted rather than published, because this fires on EVERY proxied
        request and a live-log entry per call would double the Log tab's volume
        while saying nothing new — the per-request detail already carries it.

        The counters are what makes proxy mode legible: in steady state a
        taken-over device only polls the heartbeat, and PetKit refuses it, so
        nothing is redacted and nothing looks different from proxy being off.
        `{"error_704": 312}` is the answer to "is this doing anything?".
        """
        self._upstream[outcome] = self._upstream.pop(outcome, 0) + 1
        while len(self._upstream) > MAX_TRACKED_OUTCOMES:
            self._upstream.popitem(last=False)

    def upstream_counts(self) -> dict[str, int]:
        """Proxied-call outcomes since start: `ok`, `error_<code>`, `http_<status>`."""
        return dict(self._upstream)

    def diag(self, device_id: Any) -> dict:
        """This device's diagnostics, or `{}` if it has never been seen.

        Shape: `{http_count, mqtt_count}` always, plus `last_http`,
        `last_mqtt`, `last_property`, `last_state_report` and `last_connect`
        once the corresponding `record_*` has fired.
        """
        return self._diag.get(device_id, {})

    def forget_device(self, device_id: int) -> None:
        """Drop all diagnostic state for a deleted device."""
        self._diag.pop(device_id, None)
