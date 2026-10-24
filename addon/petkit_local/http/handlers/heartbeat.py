"""poll/{type}/heartbeat — the device's ~15s poll, and how commands reach it.

This is the slow but always-available command channel. The device asks "anything
for me?" every few seconds over plain HTTP; whatever is in its `command_queue`
comes back in the response and is executed. MQTT delivers the same commands
instantly, but only to a device whose `ctrl` binary trusts our broker, so the
heartbeat is the path that works on stock firmware and the fallback when MQTT
is down.

Producers therefore enqueue in MQTT envelope form and let this module translate:
`ha/publisher.py` falls back to the queue whenever the device has no live MQTT
session, and `web/panel.py` queues the same envelopes. `_to_heartbeat_content`
converts them to the flat `{msgType, payload, type, timestamp}` object the HTTP
path expects, so a caller never has to know which channel will carry its
command. (`patchers/common.py` is the exception: it queues an already-serialized
string, which passes straight through.)

The poll is also where we find out that the *other* channel died: the device
reports its own MQTT state in `?iotStatus=`, and `note_iot_status` is what stops
a lost session from swallowing commands forever.

`carries_commands` lives here too, because it is the same concern seen from the
other side: in proxy mode every other endpoint's local answer is discarded in
favour of the cloud's, but this one has already spent the queue to build itself,
so a reply that is delivering something is sent as-is and never forwarded.

What the device does with the answer, read out of `net_http_heartbeat` (D4SH
867) and its ARM twin (W7H 456), because every rule here is invisible from our
end -- a rejected entry produces no reply, no error and no retry:

  * `result[]` entries carry `time` (ms), `timestamp` (s) and `content`.
  * An entry whose `timestamp` is not greater than the last consumed one is
    discarded as already seen.
  * An entry with `time/1000 - timestamp >= 61` is discarded as expired, on an
    unsigned compare -- so a `timestamp` ahead of `time` expires immediately.
  * `content.msgType` may be 0, 1 or 2. Nothing else is dispatched.
"""
from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web

from petkit_local.http.handlers._common import request_device
from petkit_local.utils.coerce import to_bool

if TYPE_CHECKING:
    from petkit_local.devices.base import Device

log = logging.getLogger(__name__)

#: The device knows three `content.msgType` values and no more.
#:
#: `do_http_web_msg` (W7H 456 ARM `ctrl`) and `net_http_heartbeat` (D4SH 867
#: MIPS) are the same three-way branch, so this is not one model's quirk:
#:
#:   0 -> on_web_recv_from_topic     — `type` is a topic name (ota, state_report,
#:                                     link, unlink, loglevel, user_cmd)
#:   1 -> on_web_recv_property_set   — `payload` IS the settings object
#:   2 -> on_web_recv_service_invoke — `type` is a service name, `payload` its
#:                                     params
#:
#: anything else logs `//***** error msgType (%d) *****//` and is dropped.
#:
#: A wrong value here is invisible from this side: the heartbeat is answered,
#: the queue drains and `wait_for_heartbeat` reports the command delivered,
#: while the device discards it. Only these three exist — do not extend.
#:
#: The only msgType 0 we send is `ota` (`patchers/esp32_ota.py::ota_trigger`),
#: which makes an ESP32 with a firmware job armed ask `dev_ota_check` at once.
MSG_TYPE_TOPIC = 0
MSG_TYPE_PROPERTY_SET = 1
MSG_TYPE_SERVICE_INVOKE = 2

#: The one service that is not a service invoke.
_PROPERTY_SET_SERVICE = "property/set"


def _service_of(cmd: dict[str, Any]) -> str:
    """The service an MQTT envelope invokes, spelled as its topic suffix.

    From the `_service_suffix` marker the producer attached, or from `method`
    when there is none: `thing.service.property.set` -> `property/set`,
    `thing.service.feed_realtime` -> `feed_realtime`. Parsed rather than
    substring-matched against a list, because the list of services is the
    device's, not ours — a new one should travel, not fall through to a
    default.
    """
    service = cmd.pop("_service_suffix", "")
    if service:
        return str(service)
    _, marker, tail = str(cmd.get("method", "")).partition("thing.service.")
    return tail.replace(".", "/") if marker else ""


def _to_heartbeat_content(cmd: Any) -> str:
    """Convert a queued command into the heartbeat `content` string.

    Accepts the several shapes producers queue, in this order: an already
    serialized string (passed through untouched — see `patchers/common.py`);
    a dict already in heartbeat form, i.e. carrying `msgType`, which only gets a
    `timestamp` if it lacks one; and otherwise an MQTT envelope.

    The envelope's own shape is already what the device wants — the firmware
    reads the service name from `type` and the params from `payload` whenever
    `service_id` is absent, which is exactly the HTTP case (over MQTT the
    LinkSDK supplies `service_id` from the topic and the params sit at the
    root). So the only translation is the service name and its `msgType`.

    Returns:
        A JSON string ``{"msgType": int, "payload": ..., "type": str,
        "timestamp": int}`` — without the `type` key for a property set, which
        is what the real cloud sends. An envelope whose service cannot be named
        at all is sent as a `start` rather than dropped — a command that arrives
        mislabelled is diagnosable from the device's reaction, one that
        disappears is not — and says so in the log.
    """
    if isinstance(cmd, str):
        return cmd

    if not isinstance(cmd, dict):
        return json.dumps(cmd)

    # Already in heartbeat format (has msgType)
    if "msgType" in cmd:
        if "timestamp" not in cmd:
            cmd["timestamp"] = int(time.time())
        return json.dumps(cmd)

    service = _service_of(cmd)
    params = cmd.get("params", cmd)

    if service == _PROPERTY_SET_SERVICE:
        # No `type` at all. `web_property_set_recv_parse` reads `payload` and
        # nothing else, so it is inert either way — but a capture of PetKit's
        # own cloud setting a D4's light shows the key simply absent
        # (`{"msgType": 1, "payload": {"lightMode": 0}, "timestamp": …}`, PR
        # #10). Inventing a `"property_set"` here on the grounds that a blank
        # `type` reads like a bug costs the only thing this shape buys: matching
        # the cloud means a capture of ours can be compared with one of theirs.
        return json.dumps({
            "msgType": MSG_TYPE_PROPERTY_SET,
            "payload": params,
            "timestamp": int(time.time()),
        })

    if not service:
        log.warning("Heartbeat command names no service (%s); "
                    "sending it as `start`", sorted(cmd))
        service = "start"

    return json.dumps({
        "msgType": MSG_TYPE_SERVICE_INVOKE,
        "payload": params,
        "type": service,
        "timestamp": int(time.time()),
    })


#: How long after a CONNECT an `iotStatus=0` is treated as a lagging sample
#: rather than a lost session. The device fills the value in before it sends the
#: request, so a poll in flight when the session came up reports the state from
#: just before it — observed 112ms after the CONNECT on a real T5. One poll
#: period plus room to spare; the cost of being wrong is one heartbeat's delay
#: before the backstop can fire.
IOT_STATUS_GRACE = 15.0


def note_iot_status(device: Device, request: web.Request) -> None:
    """Believe the device when it says it has no MQTT session.

    Every heartbeat carries `?iotStatus=`: 1 while the firmware's Aliyun Link
    session is up, 0 while it is not. It is the only report we get from the
    device's own side of the connection, and it arrives every ~10s.

    This is the backstop, not the primary: `mqtt/auth.py` clears the flag the
    moment a session ends. What that hook cannot see is a session that ended
    without the broker noticing — a device that reboots or drops off Wi-Fi
    leaves a half-open socket, and amqtt only reaps it after the CONNECT's
    keepalive expires, which for a keepalive of 0 is never. That is the shape of
    "MQTT stopped working and the add-on had to be restarted".

    It only ever CLEARS `mqtt_connected`, never sets it. `iotStatus=1` says the
    device is on *a* broker; only a CONNECT we authenticated proves it is on
    *ours*, and in proxy mode the other answer is Aliyun's. So setting the flag
    stays with auth, and this is the half that can be believed on its own.
    Clearing on a stale 0 costs little either: the command falls back to the
    heartbeat queue, which is the path that always works.

    No await, and called before `pop_commands`, so it cannot come between the
    pop and the send (see this module's `carries_commands`).
    """
    raw = request.query.get("iotStatus")
    if raw is None or not device.mqtt_connected:
        return
    # Default True on an unparseable value: no news is not bad news.
    if to_bool(raw, True):
        return
    if time.time() - device.mqtt_connected_at < IOT_STATUS_GRACE:
        # Sampled before the session we just accepted; not evidence of a loss.
        return
    device.mqtt_connected = False
    log.info("Heartbeat %s (id=%d): device reports iotStatus=%s - clearing "
             "mqtt_connected, commands go back to the heartbeat queue",
             device.device_type, device.petkit_id, raw)
    hub = request.app.get("event_hub")
    if hub is not None:
        hub.publish("connect", device.petkit_id,
                    f"no MQTT session (device reports iotStatus={raw})")


async def handle_heartbeat(request: web.Request) -> web.Response:
    """Answer the device's poll, delivering any commands queued for it.

    Also the liveness signal for models with no MQTT session: a heartbeat stamps
    `last_heartbeat`. Marking the device online is left to `logging_middleware`,
    which tells HA when that is a change — set here first, the middleware saw a
    device already online and a returning one stayed unavailable in HA.

    Returns:
        ``{"result": [{"time": ms, "timestamp": s, "content": str}, ...]}`` with
        one entry per queued command, or ``{"result": [{"time": ms}]}`` — the
        idle answer — when there is nothing to send. In proxy mode this response
        is not thrown away like the other handlers' when it carries a command:
        see `carries_commands`, because the queue has already been drained by the
        time anything else could decide.

    Delivery is at-most-once: `pop_commands` empties the queue as it builds the
    response, and nothing re-queues a command whose response never arrived.
    `patchers/common.py::wait_for_heartbeat` depends on exactly that — an empty
    queue is its signal that the device picked the command up.
    """
    device = request_device(request)

    ts_ms = int(time.time() * 1000)

    if device:
        device.last_heartbeat = time.time()
        note_iot_status(device, request)

        cmds = device.pop_commands()
        if cmds:
            ts = int(time.time())
            result = []
            # A second apart, entry by entry, and `time` moved with it.
            #
            # The device drops an entry whose `timestamp` is not GREATER than
            # the last one it consumed ("This http_heartbeat_msg has been
            # consumed"), so identical stamps would deliver only the first of a
            # batch. It also drops one where `time/1000 - timestamp >= 61`
            # ("expire more then 60s") — an UNSIGNED compare, so a stamp in the
            # future expires instantly. Advancing both together is the only
            # spacing that satisfies both rules.
            #
            # The first rule spans polls too: a batch of five stamped now..now+4
            # and a command on the next poll two seconds later, stamped now+2,
            # would be dropped silently while `wait_for_heartbeat` saw the queue
            # drain. So a batch starts after the last stamp handed out.
            start = max(ts, device.last_heartbeat_stamp + 1)
            for offset, cmd in enumerate(cmds, start=start - ts):
                result.append({
                    "time": ts_ms + offset * 1000,
                    "timestamp": ts + offset,
                    "content": _to_heartbeat_content(cmd),
                })
            device.last_heartbeat_stamp = result[-1]["timestamp"]
            log.info("Heartbeat %s (id=%d): delivering %d commands",
                     device.device_type, device.petkit_id, len(cmds))
            return web.json_response({"result": result})

    return web.json_response({"result": [{"time": ts_ms}]})


def _is_idle_marker(entry: Any) -> bool:
    """Whether a `result[]` entry is the "nothing to do" filler.

    The idle answer is exactly ``{"time": ms}`` — no `content`, nothing to
    execute. Both sides of a merge produce one, and two of them in a row is a
    shape no device has ever been sent. Matched on the key set rather than on
    "has no content", so an upstream command in a shape we do not recognise is
    kept rather than quietly dropped.
    """
    return isinstance(entry, dict) and set(entry) <= {"time", "timestamp"}


def carries_commands(response: web.StreamResponse) -> bool:
    """Whether this heartbeat reply is actually delivering something.

    `proxy_middleware` asks before it forwards anything: building this response
    already drained `device.command_queue` (`devices/base.py::pop_commands` is
    destructive and at-most-once), and there is no way to put a command back. So
    when the answer carries one, it is sent straight to the device with no await
    in between — no upstream call, no redaction, nothing that a cancellation, a
    timeout or an exception could interrupt.

    That is the whole protection. Merging the two replies, which this module used
    to do, only guards against the upstream's answer *replacing* ours; it does
    nothing about the reply never being sent at all. `patchers/common.py::
    wait_for_heartbeat` watches the queue drain, so a command lost after the pop
    is reported as delivered.

    Returns:
        False for anything unreadable — the safe direction is to forward, and a
        body we cannot parse did not come from `handle_heartbeat`.
    """
    body = bytes(getattr(response, "body", b"") or b"")
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return False
    result = data.get("result") if isinstance(data, dict) else None
    return isinstance(result, list) and any(not _is_idle_marker(e) for e in result)
