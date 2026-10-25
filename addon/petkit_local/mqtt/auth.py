"""Aliyun IoT HMAC-SHA256 authentication plugin for amqtt.

Device connects with:
  clientId: {pk}.{dn}|timestamp=XXXX,_ss=1,_v=sdk-python-1.0,securemode=2,signmethod=hmacsha256,ext=3,...|
  username: {dn}&{pk}
  password: HMAC-SHA256(deviceSecret, "clientId{pk}.{dn}deviceName{dn}productKey{pk}timestamp{ts}")

The signature is computed over the BARE `{pk}.{dn}` client id, not the full
pipe-delimited string the device actually connects with — getting that wrong
produces a mismatch on every device and is the first thing to check if auth
starts failing.

The device secret is ours, not Aliyun's: `http/handlers/iot_device_info.py`
generated it and told the device to use it, so a correct signature proves the
device talked to this add-on, and nothing more.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from typing import TYPE_CHECKING, Any

from amqtt.mqtt.constants import QOS_0
from amqtt.plugins.base import BaseAuthPlugin

from petkit_local.mqtt.topics import downstream_filters

if TYPE_CHECKING:
    from amqtt.plugins.manager import BaseContext
    from amqtt.session import Session

    from petkit_local.devices.base import Device
    from petkit_local.devices.registry import DeviceRegistry
    from petkit_local.web.hub import EventHub

log = logging.getLogger(__name__)

CLIENT_ID_PATTERN = re.compile(
    r"^(?P<pk>[^.]+)\.(?P<dn>[^|]+)\|"
    r"(?P<params>[^|]*)\|$"
)


def parse_client_id(client_id: str) -> dict | None:
    """Split an Aliyun client id into its identity and connection parameters.

    Returns:
        ``{"product_key": str, "device_name": str, "timestamp": str,
        "params": {k: v}}``, or None when the id doesn't have the Aliyun
        shape at all — which is how a non-device client (our own bridge)
        is told apart from a device.
    """
    m = CLIENT_ID_PATTERN.match(client_id)
    if not m:
        return None

    params_str = m.group("params")
    params = {}
    for part in params_str.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = v

    return {
        "product_key": m.group("pk"),
        "device_name": m.group("dn"),
        "timestamp": params.get("timestamp", ""),
        "params": params,
    }


_DIGESTS = {
    "hmacsha256": hashlib.sha256,
    "hmacsha1": hashlib.sha1,
    "hmacmd5": hashlib.md5,
}


def compute_aliyun_sign(
    device_secret: str,
    client_id_raw: str,
    device_name: str,
    product_key: str,
    timestamp: str,
    signmethod: str = "hmacsha256",
) -> str:
    """Reproduce the password the device computes for its CONNECT.

    Args:
        client_id_raw: The BARE `{pk}.{dn}` form, NOT the pipe-delimited client
            id sent on the wire — see this module's header.
        signmethod: Taken from the client id's params. An unrecognised method
            falls back to sha256 rather than raising: the resulting signature
            simply won't match, which the caller already handles (and reports
            with both values), whereas an exception here would kill the
            connection with no diagnostic.

    Returns:
        The lowercase hex digest, directly comparable to `session.password`.
    """
    content = (
        f"clientId{client_id_raw}"
        f"deviceName{device_name}"
        f"productKey{product_key}"
        f"timestamp{timestamp}"
    )
    digest = _DIGESTS.get(signmethod.lower(), hashlib.sha256)
    return hmac.new(
        device_secret.encode(),
        content.encode(),
        digest,
    ).hexdigest()


class AliyunAuthPlugin(BaseAuthPlugin):
    """amqtt auth plugin that validates Aliyun IoT MQTT credentials
    against our device registry.

    amqtt constructs plugins itself from the broker config, so this class must
    be usable with nothing but a context — every collaborator is injected
    afterwards by `mqtt/broker.py::start_broker` through the `set_*` methods.
    Until `set_registry` has run there is nothing to validate against and the
    plugin allows everything, which is also the state a bare instance is in.

    Successful authentication is not read-only: it is where a device is marked
    `online` and `mqtt_connected`, and the latter is what makes HA commands go
    out over MQTT instead of the heartbeat queue. Nothing else sets it, so a
    device that never authenticates keeps receiving commands by heartbeat.

    `on_broker_client_disconnected` takes it back down again, because a flag
    that only ever goes up is worse than no flag: the transport it selects has
    no delivery report, so every command after a lost session disappears.
    """

    def __init__(self, context: BaseContext) -> None:
        """Construct with amqtt's plugin context; collaborators arrive later.

        amqtt instantiates plugins itself, so `context` is the only thing this
        can be handed at construction time. The registry and hub are injected
        afterwards through `set_registry`/`set_hub`, which is why both start as
        None and every use of them is None-guarded.
        """
        super().__init__(context)
        self._registry: DeviceRegistry | None = None
        self._hub: EventHub | None = None
        #: The broker we run in, for subscribing devices on their behalf. None
        #: in the bare plugins the tests build, which is why every use is
        #: guarded rather than assumed.
        self._broker: Any = None
        # Reference broker (localkit-broker) is accept-all. Default to
        # fail-open so a sign/algorithm mismatch never blocks a real device;
        # set strict=True to actually enforce.
        self._strict = False
        #: petkit_id -> the Session we last accepted for it. Only used to tell a
        #: take-over's teardown apart from a real disconnect; see
        #: `on_broker_client_disconnected`.
        self._live_sessions: dict[int, Session] = {}

    def set_registry(self, registry: DeviceRegistry) -> None:
        """Supply the registry every credential is checked against.

        Without it the plugin has no notion of a known device and allows every
        connection, so this is effectively mandatory in production.
        """
        self._registry = registry

    def set_strict(self, strict: bool) -> None:
        """Enable rejection of unknown devices and bad signatures."""
        self._strict = strict

    def set_hub(self, hub: EventHub | None) -> None:
        """Supply the web-panel event hub that receives connection attempts."""
        self._hub = hub

    def set_broker(self, broker: Any) -> None:
        """Supply the broker this plugin runs in, for `_server_subscribe`.

        Injected by `mqtt/broker.py` alongside the registry rather than read off
        the plugin context: `BrokerContext` exposes the instance only as a
        private attribute, and reaching through it would tie us to an amqtt
        internal for something the caller already holds.
        """
        self._broker = broker

    async def on_broker_client_connected(
        self, client_id: str, client_session: Session | None = None,
    ) -> None:
        """Subscribe a device to its own downstream topics, on its behalf.

        Fired after CONNACK, with the session already in the broker's table —
        the earliest point a subscription can be added to something that will
        actually receive.

        Devices are not subscribed by us for convenience; they are subscribed
        because this firmware never subscribes itself. See
        `topics.downstream_filters` for the evidence and for what is left out.
        Our own bridge connects with a client id of no Aliyun shape, so
        `_device_for_client` returns None and it is skipped.
        """
        if self._broker is None or client_session is None:
            return
        device = self._device_for_client(client_id)
        if device is None:
            return
        await self._server_subscribe(device, client_session)

    async def _server_subscribe(self, device: Device, session: Session) -> None:
        """Add the downstream filters for one device's session.

        QoS 0, and this is load-bearing. Subscribing at QoS 1 makes the broker
        deliver at QoS 1, and a T5 that receives a QoS-1 frame PUBACKs it and
        then drops the whole session about two seconds later — turning a
        connection that had been stable for minutes into a ~6s window every
        ~80s, which is far worse than any downgrade. Observed directly on
        hardware, and it costs nothing to avoid: the real cloud publishes these
        same commands at qos=0 (logged in `mqtt/upstream.py`), so there is no
        guarantee to preserve here in the first place.

        A refusal is logged rather than raised. The broker returns 0x80 for a
        malformed filter or one a topic-filtering plugin denies, and a device
        that receives nothing is bad but recoverable; a broker that fails to
        accept the session is worse.
        """
        added = []
        for topic_filter in downstream_filters(device.mqtt_product_key,
                                               device.mqtt_device_name):
            try:
                code = await self._broker.add_subscription((topic_filter, QOS_0), session)
            except Exception:
                log.exception("Could not subscribe device %d to %s",
                              device.petkit_id, topic_filter)
                continue
            if code == 0x80:
                log.warning("Broker refused subscription for device %d: %s",
                            device.petkit_id, topic_filter)
                continue
            added.append(topic_filter)
        if not added:
            return
        device.mqtt_subscriptions = device.mqtt_subscriptions + [
            t for t in added if t not in device.mqtt_subscriptions]
        log.info("Subscribed device %d (%s) on its behalf: %s",
                 device.petkit_id, device.device_type, ", ".join(added))

    def _mark_mqtt_connected(self, device: Device, session: Session,
                             product_key: str) -> None:
        """Mark the device as having a live MQTT session (drives command routing
        and the UI badge).

        The timestamp is what lets the heartbeat's `iotStatus` backstop tell a
        report that lags this CONNECT from one that follows a real loss — see
        `devices/base.py::Device.mqtt_connected_at`. The session is remembered
        for the same reason on the broker's side: `on_broker_client_disconnected`
        has to know which one it is being told about.

        `product_key` is the one the device connected with, and becomes its
        own. They differ only for the shared `payloads.PATCHED_PRODUCT_KEY`,
        which `by_mqtt_name` resolves by device name: every topic sent to the
        device — its server-side subscriptions, commands, proxy mode's
        relaying — is built from `device.mqtt_product_key`, and must name the
        key this session is listening under. Adopted on the same terms as the
        session itself, signature mismatch included under non-strict, because
        this is the session its commands are about to be routed to.
        """
        if product_key != device.mqtt_product_key:
            log.info("Device %d now uses product key %s (was %s)",
                     device.petkit_id, product_key, device.mqtt_product_key)
            device.mqtt_product_key = product_key
            if self._registry is not None:
                self._registry.mark_dirty()
        now = time.time()
        device.mqtt_connected = True
        device.mqtt_connected_at = now
        # The CONNECT is contact in its own right. Without it a device that
        # subscribes and then stays quiet is marked offline before its first
        # frame arrives, because it has already stopped polling HTTP.
        device.last_mqtt = now
        # Subscriptions belong to the session that made them, so a new one
        # starts from nothing rather than inheriting what the last session
        # happened to ask for.
        device.mqtt_subscriptions = []
        self._live_sessions[device.petkit_id] = session

    def _device_for_client(self, client_id: str) -> Device | None:
        """Resolve a broker client id back to the device that owns it.

        Returns None for anything that is not a device — our own bridge
        connects with a client id that has no Aliyun shape at all — and for a
        device name no registry entry claims.
        """
        if not self._registry:
            return None
        parsed = parse_client_id(client_id or "")
        if not parsed:
            return None
        return self._registry.by_mqtt_name(parsed["product_key"], parsed["device_name"])

    async def on_mqtt_packet_received(
        self, packet: Any = None, session: Session | None = None,
    ) -> None:
        """Stamp device liveness from the broker's own view of the wire.

        `mqtt/bridge.py` can only stamp frames it is subscribed to, and an idle
        litter box publishes nothing for minutes at a time — while having
        stopped its HTTP heartbeat the moment it got onto the broker. Judged on
        those two signals a healthy device goes stale, and
        `ha/publisher.py::availability_watchdog` then marks it offline and
        clears `mqtt_connected`, which strands its commands in a queue nothing
        drains.

        This sees every packet, PINGREQ included, so the stamp refreshes at
        least once per keep-alive (62s on the T5) no matter how quiet the device
        is. That in turn is what makes the watchdog a sound last backstop: when
        the session really is gone the stamp stops, and the offline sweep is
        right to fire.

        The scan is over live device sessions only — a handful of entries, and
        our own bridge is not among them, so its traffic costs one identity
        comparison per entry and nothing else.
        """
        if session is None or not self._live_sessions:
            return
        for petkit_id, live in self._live_sessions.items():
            if live is session:
                device = self._registry.get(petkit_id) if self._registry else None
                if device is not None:
                    device.last_mqtt = time.time()
                    self._note_subscriptions(device, packet)
                return

    def _note_subscriptions(self, device: Device, packet: Any) -> None:
        """Record the topic filters a device asks to receive.

        MQTT gives the publisher no delivery report: publishing to a topic
        nobody subscribed to succeeds exactly as publishing to one they did.
        So when a command reported "delivered: mqtt" changes nothing on the
        box, the first question is whether the device was ever listening on the
        topic we chose — and nothing recorded that until this landed. It is the
        observability half of the `mqtt_connected` invariant: knowing the
        session is up says nothing about where its attention is.

        Duck-typed on the packet rather than isinstance-checked against
        `SubscribePacket`: this hook sees every packet type amqtt parses, and
        only a SUBSCRIBE carries `payload.topics`.
        """
        topics = getattr(getattr(packet, "payload", None), "topics", None)
        if not topics:
            return
        try:
            filters = [str(t) for t, _qos in topics]
        except (TypeError, ValueError):
            return
        fresh = [f for f in filters if f not in device.mqtt_subscriptions]
        if not fresh:
            return
        device.mqtt_subscriptions = device.mqtt_subscriptions + fresh
        log.info("MQTT SUBSCRIBE from device %d (%s): %s",
                 device.petkit_id, device.device_type, ", ".join(fresh))

    async def on_broker_client_disconnected(
        self, client_id: str, client_session: Session | None = None,
    ) -> None:
        """Clear `mqtt_connected` the moment a device's session ends.

        amqtt fires this for a clean DISCONNECT and for an abrupt drop alike
        (`Broker._handle_disconnect`), so it is the earliest we can know the
        session is gone. Without it the flag `authenticate` sets never came back
        down on its own, and both command routers — `ha/publisher.py` and
        `web/panel.py` — read it to pick a transport. Publishing to a topic no
        one is subscribed to raises nothing, so a stale True did not fail: it
        silently swallowed every command until the add-on was restarted.

        The heartbeat's `iotStatus` clears it as well
        (`http/handlers/heartbeat.py`) and is the backstop for a session that
        ends without this firing; here it is merely immediate rather than one
        poll late.

        `online` is deliberately untouched. A device off MQTT is still perfectly
        reachable over HTTP, and `ha/publisher.py::availability_watchdog` owns
        that flag.

        The session check is not defensive noise: a device that reconnects while
        the broker still holds its old session triggers amqtt's take-over, which
        authenticates the NEW session first and only then tears the old one down
        (`Broker._handle_client_session`). Both carry the same client id, so
        without comparing the objects this hook would clear the flag it had just
        set and leave a live device permanently on the slow path.
        """
        device = self._device_for_client(client_id)
        if device is None or not device.mqtt_connected:
            return
        live = self._live_sessions.get(device.petkit_id)
        if client_session is not None and live is not None and live is not client_session:
            log.debug("Ignoring take-over teardown of a superseded session for "
                      "device %d", device.petkit_id)
            return
        self._live_sessions.pop(device.petkit_id, None)
        device.mqtt_connected = False
        log.info("MQTT session ended for device %d - commands fall back to the "
                 "HTTP heartbeat queue", device.petkit_id)
        if self._hub is not None:
            self._hub.publish("connect", device.petkit_id, "MQTT session ended")

    def _record(self, device_id: int | None, client_id: str, username: str,
                signmethod: str, ok: bool) -> None:
        """Report one connection attempt to the web panel, if there is one.

        Failures are recorded too — a device that cannot connect is exactly the
        case a user needs to see — hence `device_id` being None for a client
        that matched no registry entry.
        """
        if self._hub is not None:
            self._hub.record_connect(device_id, {
                "client_id": client_id, "username": username,
                "signmethod": signmethod, "ok": ok,
            })

    async def authenticate(self, *, session: Session) -> bool:
        """Decide whether one CONNECT may proceed (amqtt's auth hook).

        A client whose id is not in the Aliyun shape at all is our own bridge,
        and is always allowed: only devices are authenticated here.

        Returns:
            True to accept. False is returned only under `set_strict` — the
            default is fail-open, matching the reference broker, so a signature
            or algorithm mismatch is loudly logged and the device still gets on.
            That is deliberate: locking a physical device out of its only server
            is worse than accepting an unverified one on a LAN-local broker.
        """
        if not self._registry:
            log.warning("No device registry set - allowing connection")
            return True

        client_id = session.client_id or ""
        username = session.username or ""
        password = session.password or ""

        parsed = parse_client_id(client_id)
        if not parsed:
            log.debug("Non-Aliyun client '%s' - allowing (internal)", client_id)
            return True

        pk = parsed["product_key"]
        dn = parsed["device_name"]
        ts = parsed["timestamp"]
        signmethod = parsed["params"].get("signmethod", "hmacsha256")

        device = self._registry.by_mqtt_name(pk, dn)
        if not device:
            # Unknown device: mark diagnostics, but only reject when strict.
            self._record(None, client_id, username, signmethod, False)
            if self._strict:
                log.warning("Unknown MQTT device (rejected): pk=%s dn=%s", pk, dn)
                return False
            log.warning("Unknown MQTT device (allowed, non-strict): pk=%s dn=%s", pk, dn)
            return True

        raw_client_id = f"{pk}.{dn}"
        expected_sign = compute_aliyun_sign(
            device.mqtt_device_secret, raw_client_id, dn, pk, ts, signmethod,
        )

        # Case-insensitive: the T5 sends the digest in UPPERCASE hex, hexdigest()
        # produces lowercase, and a hex digest means the same number either way.
        # Compared exactly, a real device fails on every CONNECT — invisible
        # today only because non-strict lets it in anyway, and an instant
        # lockout the moment mqtt_strict_auth is turned on.
        if password.lower() == expected_sign.lower():
            # keep_alive is logged because it is the whole reaping policy: amqtt
            # uses it verbatim as the read timeout, and 0 means "wait forever",
            # which leaves a rebooted device's socket ESTABLISHED for the life of
            # the process. Observed on a T5 whose reconnect made a second
            # session rather than a take-over — the client id carries a
            # timestamp, so a returning device is never the same client.
            log.info("MQTT auth OK: %s (device id=%d, %s, keep_alive=%ss)",
                     dn, device.petkit_id, signmethod,
                     getattr(session, "keep_alive", "?"))
            device.online = True
            self._mark_mqtt_connected(device, session, pk)
            self._record(device.petkit_id, client_id, username, signmethod, True)
            return True

        self._record(device.petkit_id, client_id, username, signmethod, False)
        if self._strict:
            log.warning("MQTT auth FAILED (strict) for %s: expected=%s got=%s",
                        dn, expected_sign[:16], password[:16] if password else "empty")
            return False

        # Non-strict: accept like the reference broker, but flag the mismatch.
        log.warning("MQTT sign mismatch for %s (%s) - allowing (non-strict). "
                    "expected=%s got=%s", dn, signmethod,
                    expected_sign[:16], password[:16] if password else "empty")
        device.online = True
        self._mark_mqtt_connected(device, session, pk)
        return True
