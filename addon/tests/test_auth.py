import hashlib
import hmac

from amqtt.contexts import BaseContext

from petkit_local.devices.registry import DeviceRegistry
from petkit_local.mqtt.auth import (
    AliyunAuthPlugin,
    compute_aliyun_sign,
    parse_client_id,
)


def test_parse_client_id():
    cid = "a1PK.d_t5_SN1|timestamp=123,_ss=1,signmethod=hmacsha256,securemode=2|"
    p = parse_client_id(cid)
    assert p is not None
    assert p["product_key"] == "a1PK"
    assert p["device_name"] == "d_t5_SN1"
    assert p["timestamp"] == "123"
    assert p["params"]["signmethod"] == "hmacsha256"


def test_parse_client_id_rejects_plain():
    # The bridge's own client uses a plain identifier -> must not parse as
    # Aliyun (so the plugin allows it as an internal client).
    assert parse_client_id("petkit-local-bridge") is None


def test_compute_sign_matches_reference():
    secret = "s3cr3t"
    pk, dn, ts = "a1PK", "d_t5_SN1", "123"
    raw_client_id = f"{pk}.{dn}"
    got = compute_aliyun_sign(secret, raw_client_id, dn, pk, ts)

    content = f"clientId{raw_client_id}deviceName{dn}productKey{pk}timestamp{ts}"
    want = hmac.new(secret.encode(), content.encode(), hashlib.sha256).hexdigest()
    assert got == want


def test_sign_is_deterministic():
    a = compute_aliyun_sign("k", "a.b", "b", "a", "1")
    b = compute_aliyun_sign("k", "a.b", "b", "a", "1")
    assert a == b


def test_sign_selects_digest_by_signmethod():
    sha256 = compute_aliyun_sign("k", "a.b", "b", "a", "1", "hmacsha256")
    sha1 = compute_aliyun_sign("k", "a.b", "b", "a", "1", "hmacsha1")
    assert sha256 != sha1
    assert len(sha1) == 40  # sha1 hex digest
    assert len(sha256) == 64
    # signmethod is extracted from the clientId params
    p = parse_client_id("a1PK.d_t5_SN1|timestamp=1,signmethod=hmacsha1|")
    assert p["params"]["signmethod"] == "hmacsha1"


# --- session lifecycle ---

def _plugin_with_device() -> tuple[AliyunAuthPlugin, object, str]:
    """A plugin holding one registered device, plus that device's client id."""
    reg = DeviceRegistry()
    dev = reg.get_or_create(100, "t5", serial_number="SN100")
    dev.mqtt_product_key = "a1PK"
    dev.mqtt_device_name = "d_t5_SN100"
    dev.mqtt_connected = True

    plugin = AliyunAuthPlugin(BaseContext())
    plugin.set_registry(reg)
    return plugin, dev, "a1PK.d_t5_SN100|timestamp=1,signmethod=hmacsha256|"


async def test_disconnect_clears_mqtt_connected():
    """Nothing else took the flag back down, so a device that dropped off the
    broker kept being handed commands over a topic with no subscriber."""
    plugin, dev, client_id = _plugin_with_device()
    await plugin.on_broker_client_disconnected(client_id)
    assert dev.mqtt_connected is False


async def test_disconnect_leaves_online_alone():
    """A device off MQTT is still reachable over HTTP; `online` belongs to
    ha/publisher.py::availability_watchdog."""
    plugin, dev, client_id = _plugin_with_device()
    dev.online = True
    await plugin.on_broker_client_disconnected(client_id)
    assert dev.online is True


async def test_disconnect_ignores_the_internal_bridge():
    """Our own client has no Aliyun-shaped id and owns no device."""
    plugin, dev, _ = _plugin_with_device()
    await plugin.on_broker_client_disconnected("petkit-local-bridge")
    assert dev.mqtt_connected is True


async def test_disconnect_of_an_unknown_device_is_harmless():
    plugin, dev, _ = _plugin_with_device()
    await plugin.on_broker_client_disconnected("a1PK.d_t5_SOMEONE_ELSE|timestamp=1|")
    assert dev.mqtt_connected is True


async def test_disconnect_without_a_registry_does_not_raise():
    """amqtt builds the plugin itself; collaborators are injected afterwards,
    so a disconnect can arrive before set_registry ever ran."""
    plugin = AliyunAuthPlugin(BaseContext())
    await plugin.on_broker_client_disconnected("a1PK.d_t5_SN100|timestamp=1|")


def test_disconnect_hook_is_named_for_amqtts_event():
    """The plugin manager binds callbacks by `on_{event}` at load time and
    raises if one is not a coroutine — a rename here silently unbinds it."""
    from inspect import iscoroutinefunction

    from amqtt.broker import BrokerEvents

    attr = f"on_{BrokerEvents.CLIENT_DISCONNECTED}"
    assert iscoroutinefunction(getattr(AliyunAuthPlugin, attr))


# --- signature comparison ---

async def test_auth_accepts_an_uppercase_signature():
    """The T5 sends the digest in UPPERCASE hex while hexdigest() is lowercase.
    Compared exactly, a real device fails every CONNECT — harmless while
    non-strict lets it through anyway, an instant lockout under strict."""
    plugin, dev, client_id = _plugin_with_device()
    plugin.set_strict(True)
    dev.mqtt_connected = False

    sign = compute_aliyun_sign(dev.mqtt_device_secret, "a1PK.d_t5_SN100",
                               "d_t5_SN100", "a1PK", "1")

    class _Session:
        pass

    s = _Session()
    s.client_id = client_id
    s.username = "d_t5_SN100&a1PK"
    s.password = sign.upper()

    assert await plugin.authenticate(session=s) is True
    assert dev.mqtt_connected is True


async def test_auth_stamps_the_connect_time():
    """The heartbeat backstop needs it to tell a lagging iotStatus from a loss."""
    plugin, dev, client_id = _plugin_with_device()
    dev.mqtt_connected = False
    dev.mqtt_connected_at = 0.0

    sign = compute_aliyun_sign(dev.mqtt_device_secret, "a1PK.d_t5_SN100",
                               "d_t5_SN100", "a1PK", "1")

    class _Session:
        pass

    s = _Session()
    s.client_id = client_id
    s.username = "d_t5_SN100&a1PK"
    s.password = sign

    await plugin.authenticate(session=s)
    assert dev.mqtt_connected_at > 0


async def test_takeover_teardown_does_not_clear_the_new_session():
    """A device reconnecting while the broker still holds its old session
    triggers amqtt's take-over, which authenticates the NEW session and only
    then tears the old one down — same client id, so a hook that trusted the id
    alone would clear the flag it had just set."""
    plugin, dev, client_id = _plugin_with_device()
    dev.mqtt_connected = False

    sign = compute_aliyun_sign(dev.mqtt_device_secret, "a1PK.d_t5_SN100",
                               "d_t5_SN100", "a1PK", "1")

    class _Session:
        def __init__(self):
            self.client_id = client_id
            self.username = "d_t5_SN100&a1PK"
            self.password = sign

    old, new = _Session(), _Session()
    await plugin.authenticate(session=old)
    await plugin.authenticate(session=new)      # take-over: new one wins
    await plugin.on_broker_client_disconnected(client_id, old)

    assert dev.mqtt_connected is True

    # The surviving session disconnecting for real still clears it.
    await plugin.on_broker_client_disconnected(client_id, new)
    assert dev.mqtt_connected is False


# --- liveness from the wire ---

async def test_packet_from_a_live_session_stamps_liveness():
    """An idle box publishes nothing for minutes but PINGREQs every keep-alive,
    and it has stopped heartbeating over HTTP — so this is the only signal that
    keeps the offline watchdog from stranding its commands."""
    plugin, dev, client_id = _plugin_with_device()
    dev.mqtt_connected = False
    dev.last_mqtt = 0.0

    sign = compute_aliyun_sign(dev.mqtt_device_secret, "a1PK.d_t5_SN100",
                               "d_t5_SN100", "a1PK", "1")

    class _Session:
        pass

    s = _Session()
    s.client_id = client_id
    s.username = "d_t5_SN100&a1PK"
    s.password = sign
    await plugin.authenticate(session=s)

    dev.last_mqtt = 0.0
    await plugin.on_mqtt_packet_received(packet=object(), session=s)
    assert dev.last_mqtt > 0


async def test_packet_from_the_bridge_stamps_nothing():
    """Our own client is not a device; its traffic must not fake device
    liveness."""
    plugin, dev, _ = _plugin_with_device()
    dev.last_mqtt = 0.0

    class _Session:
        client_id = "petkit-local-bridge"

    await plugin.on_mqtt_packet_received(packet=object(), session=_Session())
    assert dev.last_mqtt == 0.0


class _SubPacket:
    """A SUBSCRIBE as the hook sees it: only `payload.topics` distinguishes it."""

    def __init__(self, *topics):
        self.payload = type("P", (), {"topics": [(t, 1) for t in topics]})()


def _authenticated_session(plugin, dev, client_id):
    """Drive a real CONNECT so the session lands in `_live_sessions`."""

    class _Session:
        pass

    s = _Session()
    s.client_id = client_id
    s.username = f"{dev.mqtt_device_name}&{dev.mqtt_product_key}"
    s.password = compute_aliyun_sign(
        dev.mqtt_device_secret, f"{dev.mqtt_product_key}.{dev.mqtt_device_name}",
        dev.mqtt_device_name, dev.mqtt_product_key, "1")
    return s


async def test_a_subscribe_records_where_the_device_is_listening():
    """A publish to an unsubscribed topic succeeds silently, so this is the
    only evidence that a command had anywhere to land."""
    plugin, dev, client_id = _plugin_with_device()
    s = _authenticated_session(plugin, dev, client_id)
    await plugin.authenticate(session=s)

    topic = "/sys/a1PK/d_t5_SN100/thing/service/#"
    await plugin.on_mqtt_packet_received(packet=_SubPacket(topic), session=s)
    assert dev.mqtt_subscriptions == [topic]

    # A repeat must not pile up, and a non-SUBSCRIBE must not disturb the list.
    await plugin.on_mqtt_packet_received(packet=_SubPacket(topic), session=s)
    await plugin.on_mqtt_packet_received(packet=object(), session=s)
    assert dev.mqtt_subscriptions == [topic]


async def test_a_new_session_starts_with_no_subscriptions():
    """Filters belong to the session that asked for them; a reconnecting device
    must not appear to be listening on topics only its last session had."""
    plugin, dev, client_id = _plugin_with_device()
    dev.mqtt_subscriptions = ["/sys/a1PK/d_t5_SN100/thing/service/#"]
    s = _authenticated_session(plugin, dev, client_id)
    await plugin.authenticate(session=s)
    assert dev.mqtt_subscriptions == []


class _FakeBroker:
    """Records what was subscribed, and can refuse like amqtt does (0x80)."""

    def __init__(self, refuse=()):
        self.subscribed = []
        self.refuse = refuse

    async def add_subscription(self, subscription, session):
        topic_filter, qos = subscription
        if topic_filter in self.refuse:
            return 0x80
        self.subscribed.append((topic_filter, qos, session))
        return qos


async def test_a_device_is_subscribed_on_its_own_behalf():
    """The T5 sends no SUBSCRIBE, so without this every command is published
    to a filter nobody holds and dropped by the broker in silence."""
    plugin, dev, client_id = _plugin_with_device()
    broker = _FakeBroker()
    plugin.set_broker(broker)

    await plugin.on_broker_client_connected(client_id, client_session=object())

    got = [t for t, _qos, _s in broker.subscribed]
    assert got == [
        "/sys/a1PK/d_t5_SN100/thing/service/#",
        "/sys/a1PK/d_t5_SN100/thing/event/+/post_reply",
        "/a1PK/d_t5_SN100/user/get",
    ]
    assert dev.mqtt_subscriptions == got
    # QoS 0 is load-bearing: at QoS 1 the T5 PUBACKs and then drops the
    # session ~2s later, and the cloud publishes these commands at qos=0 anyway.
    assert {qos for _t, qos, _s in broker.subscribed} == {0}


async def test_a_device_is_never_subscribed_to_firmware_pushes():
    """Nothing may hand a device firmware — not even by mistake."""
    plugin, _dev, client_id = _plugin_with_device()
    broker = _FakeBroker()
    plugin.set_broker(broker)
    await plugin.on_broker_client_connected(client_id, client_session=object())
    assert not any("ota" in t for t, _q, _s in broker.subscribed)


async def test_our_own_bridge_is_not_subscribed_as_a_device():
    """The bridge's client id has no Aliyun shape and owns no device."""
    plugin, _dev, _client_id = _plugin_with_device()
    broker = _FakeBroker()
    plugin.set_broker(broker)
    await plugin.on_broker_client_connected("petkit-local-bridge",
                                            client_session=object())
    assert broker.subscribed == []


async def test_a_refused_filter_does_not_stop_the_others():
    """A device receiving less is bad; a session that fails to come up is
    worse."""
    plugin, dev, client_id = _plugin_with_device()
    broker = _FakeBroker(refuse=("/sys/a1PK/d_t5_SN100/thing/service/#",))
    plugin.set_broker(broker)
    await plugin.on_broker_client_connected(client_id, client_session=object())
    assert "/a1PK/d_t5_SN100/user/get" in dev.mqtt_subscriptions
    assert "/sys/a1PK/d_t5_SN100/thing/service/#" not in dev.mqtt_subscriptions


async def test_a_patched_esp32_connecting_under_the_shared_key_adopts_it(tmp_path):
    """Every patched ESP32 is handed one key so one DNS name serves them all.
    The CONNECT under it must find the device by name, check the signature
    against the key it actually signed with, and make that key the device's
    own — every topic sent to it is built from `mqtt_product_key`, so a device
    left on its old key would be subscribed, and commanded, where it is not
    listening."""
    from petkit_local.devices.payloads import PATCHED_PRODUCT_KEY

    path = str(tmp_path / "devices.json")
    reg = DeviceRegistry(persist_path=path)
    dev = reg.get_or_create(400, "d4", serial_number="SN400")
    own_key = dev.mqtt_product_key
    plugin = AliyunAuthPlugin(BaseContext())
    plugin.set_registry(reg)
    plugin.set_strict(True)
    broker = _FakeBroker()
    plugin.set_broker(broker)

    dn = dev.mqtt_device_name
    client_id = f"{PATCHED_PRODUCT_KEY}.{dn}|timestamp=1,signmethod=hmacsha256|"

    class _Session:
        pass

    s = _Session()
    s.client_id = client_id
    s.username = f"{dn}&{PATCHED_PRODUCT_KEY}"
    s.password = compute_aliyun_sign(dev.mqtt_device_secret, f"{PATCHED_PRODUCT_KEY}.{dn}",
                                     dn, PATCHED_PRODUCT_KEY, "1")

    assert await plugin.authenticate(session=s) is True
    assert dev.mqtt_connected is True
    assert dev.mqtt_product_key == PATCHED_PRODUCT_KEY != own_key

    await plugin.on_broker_client_connected(client_id, client_session=s)
    assert dev.mqtt_subscriptions[0] == f"/sys/{PATCHED_PRODUCT_KEY}/{dn}/thing/service/#"

    await reg.flush()
    assert DeviceRegistry(persist_path=path).get(400).mqtt_product_key == PATCHED_PRODUCT_KEY

    await plugin.on_broker_client_disconnected(client_id, client_session=s)
    assert dev.mqtt_connected is False


async def test_the_shared_key_signed_with_the_wrong_secret_is_refused_when_strict():
    from petkit_local.devices.payloads import PATCHED_PRODUCT_KEY

    reg = DeviceRegistry()
    dev = reg.get_or_create(400, "d4", serial_number="SN400")
    own_key = dev.mqtt_product_key
    plugin = AliyunAuthPlugin(BaseContext())
    plugin.set_registry(reg)
    plugin.set_strict(True)

    dn = dev.mqtt_device_name

    class _Session:
        pass

    s = _Session()
    s.client_id = f"{PATCHED_PRODUCT_KEY}.{dn}|timestamp=1,signmethod=hmacsha256|"
    s.username = f"{dn}&{PATCHED_PRODUCT_KEY}"
    s.password = compute_aliyun_sign("not-the-secret", f"{PATCHED_PRODUCT_KEY}.{dn}",
                                     dn, PATCHED_PRODUCT_KEY, "1")

    assert await plugin.authenticate(session=s) is False
    assert dev.mqtt_product_key == own_key


async def test_subscribing_without_a_broker_is_not_an_error():
    """The bare plugin the tests build has none, and neither would a broker
    whose injection failed."""
    plugin, _dev, client_id = _plugin_with_device()
    await plugin.on_broker_client_connected(client_id, client_session=object())


def test_connect_hook_is_named_for_amqtts_event():
    from inspect import iscoroutinefunction

    from amqtt.events import BrokerEvents

    attr = f"on_{BrokerEvents.CLIENT_CONNECTED}"
    assert iscoroutinefunction(getattr(AliyunAuthPlugin, attr))


def test_packet_hook_is_named_for_amqtts_event():
    from inspect import iscoroutinefunction

    from amqtt.events import MQTTEvents

    attr = f"on_{MQTTEvents.PACKET_RECEIVED}"
    assert iscoroutinefunction(getattr(AliyunAuthPlugin, attr))
