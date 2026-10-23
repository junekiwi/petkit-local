"""CommandRouter delivery: which way a Home Assistant write leaves.

`mqtt_connected` picks the transport, and the transport has no delivery report:
a publish to a device that is not listening raises nothing. So the routing
decision itself is what has to be right — a command sent over MQTT to a device
polling HTTP is swallowed, and one queued for a heartbeat that a device on MQTT
no longer polls waits forever.

The BLE half is the same question one hop further: an accessory has no session
of its own, so its write is a frame through whichever WiFi device relays for it.
"""
from petkit_local.devices.ble import (
    CMD_RESET_FILTER, CMD_SET_MODE, BLERegistry, w5_mode_payload,
)
from petkit_local.devices.registry import DeviceRegistry
from petkit_local.ha.publisher import HAPublisher
from tests._fakes import FakeMessage, FakeMqttClient

PARENT_ID = 10
FOUNTAIN_ID = 700


class FakeBridge:
    """Stands in for `MQTTBridge` as the router's command sink.

    `publish_to_device` raises when told to, exactly as the real one does when
    it has no broker connection — that exception is the router's only signal to
    fall back to the heartbeat queue.
    """

    def __init__(self, *, fail: bool = False, ble_sent: bool = True) -> None:
        self.fail = fail
        self.ble_sent = ble_sent
        self.to_device: list[tuple[int, str, dict]] = []
        self.ble: list[tuple[int, int, int, bytes]] = []

    async def publish_to_device(self, device, topic_suffix, payload):
        if self.fail:
            raise ConnectionError("the bridge is not connected to the broker")
        self.to_device.append((device.petkit_id, topic_suffix, payload))

    async def publish_ble_command(self, device, ble, cmd, payload):
        self.ble.append((device.petkit_id, ble.petkit_id, cmd, payload))
        return self.ble_sent


async def _device_setup():
    """A publisher with one discovered T5, so its writes route for real."""
    reg = DeviceRegistry()
    dev = reg.get_or_create(petkit_id=1, device_type="t5", serial_number="SN")
    pub = HAPublisher(reg, {})
    pub._client = FakeMqttClient()
    pub._connected = True
    await pub.publish_discovery(dev)
    return dev, pub


def _settings_switch(pub):
    index = pub._commands._entity_index[1]
    return next((suffix, entity) for suffix, entity in index.items()
                if entity.component == "switch" and entity.value_path.startswith("settings."))


async def _send(pub, device_id, suffix, payload):
    await pub._commands.handle_command(
        FakeMessage(f"petkit-local/{device_id}/cmd/{suffix}", payload))


async def test_a_device_holding_a_session_is_written_to_over_mqtt():
    dev, pub = await _device_setup()
    bridge = FakeBridge()
    pub.set_command_sink(bridge)
    dev.mqtt_connected = True
    suffix, _ = _settings_switch(pub)

    await _send(pub, 1, suffix, b"ON")

    assert len(bridge.to_device) == 1
    assert bridge.to_device[0][0] == 1
    assert dev.command_queue == [], "a command delivered live must not also be queued"


async def test_a_device_without_a_session_is_queued_for_its_heartbeat_even_with_a_bridge():
    """The stale-flag case from the other side: with the bridge up but the
    device not on it, an MQTT publish would be accepted and go nowhere."""
    dev, pub = await _device_setup()
    bridge = FakeBridge()
    pub.set_command_sink(bridge)
    dev.mqtt_connected = False
    suffix, _ = _settings_switch(pub)

    await _send(pub, 1, suffix, b"ON")

    assert bridge.to_device == []
    assert len(dev.command_queue) == 1
    assert dev.command_queue[0]["_service_suffix"]


async def test_a_session_with_no_bridge_wired_falls_back_to_the_queue():
    dev, pub = await _device_setup()
    dev.mqtt_connected = True
    suffix, _ = _settings_switch(pub)

    await _send(pub, 1, suffix, b"ON")

    assert len(dev.command_queue) == 1


async def test_a_failed_mqtt_publish_is_queued_under_the_service_it_was_meant_for():
    """The bridge raises when it has lost the broker. The command must survive
    that, and carry the service suffix the heartbeat path will need to send it."""
    dev, pub = await _device_setup()
    pub.set_command_sink(FakeBridge(fail=True))
    dev.mqtt_connected = True
    suffix, _ = _settings_switch(pub)

    await _send(pub, 1, suffix, b"ON")

    assert len(dev.command_queue) == 1
    queued = dev.command_queue[0]
    assert queued["_service_suffix"]
    assert "params" in queued, "the queued command lost its envelope"


async def test_an_out_of_bounds_number_is_refused_and_nothing_is_sent():
    dev, pub = await _device_setup()
    bridge = FakeBridge()
    pub.set_command_sink(bridge)
    dev.mqtt_connected = True
    index = pub._commands._entity_index[1]
    suffix, entity = next(
        (s, e) for s, e in index.items()
        if e.component == "number" and e.value_path.startswith("settings.")
        and e.max_value is not None)
    before = len(pub._client.published)

    await _send(pub, 1, suffix, str(entity.max_value + 1000).encode())

    assert bridge.to_device == [] and dev.command_queue == []
    assert len(pub._client.published) == before, "a refused write must not publish state"


async def test_a_command_for_an_entity_never_discovered_is_dropped():
    dev, pub = await _device_setup()
    before = len(pub._client.published)

    await _send(pub, 1, "no_such_entity", b"ON")

    assert dev.command_queue == []
    assert len(pub._client.published) == before


async def test_a_topic_of_the_wrong_shape_is_ignored():
    dev, pub = await _device_setup()
    suffix, _ = _settings_switch(pub)
    before = len(pub._client.published)

    await pub._commands.handle_command(FakeMessage(f"elsewhere/1/cmd/{suffix}", b"ON"))
    await pub._commands.handle_command(FakeMessage(f"petkit-local/1/set/{suffix}", b"ON"))

    assert dev.command_queue == []
    assert len(pub._client.published) == before


# --- BLE accessories -------------------------------------------------------


async def _fountain_setup(*, bridge: FakeBridge | None = None, link_with: int = PARENT_ID):
    """A W5 fountain relayed by a T5, both discovered.

    `link_with` can name a parent that is not registered, which is what a
    pairing outliving its parent's deletion looks like.
    """
    reg = DeviceRegistry()
    reg.get_or_create(petkit_id=PARENT_ID, device_type="t5", serial_number="SN")
    ble = BLERegistry()
    fountain = ble.register(ble_type="w5", petkit_id=FOUNTAIN_ID, mac="AABBCCDDEEFF",
                            link_with=link_with)
    pub = HAPublisher(reg, {}, ble_registry=ble)
    pub._client = FakeMqttClient()
    pub._connected = True
    if bridge is not None:
        pub.set_command_sink(bridge)
    await pub.publish_ble_discovery(fountain)
    return fountain, pub


def _suffix(pub, key):
    index = pub._commands._entity_index[FOUNTAIN_ID]
    return next(s for s, e in index.items() if e.key == key)


def _state_publishes(pub):
    return [t for t, _, _ in pub._client.published if t == f"petkit-local/{FOUNTAIN_ID}/state"]


async def test_switching_a_fountain_off_goes_through_its_parent():
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_power"), b"OFF")

    assert bridge.ble == [(PARENT_ID, FOUNTAIN_ID, CMD_SET_MODE, w5_mode_payload(0))]
    # Reflected optimistically, into the block the status parser fills.
    assert fountain.state["states"]["powerStatus"] == 0
    assert _state_publishes(pub)


async def test_a_select_label_is_sent_as_its_option_value():
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_mode"), b"smart")

    assert bridge.ble == [(PARENT_ID, FOUNTAIN_ID, CMD_SET_MODE, w5_mode_payload(2))]
    assert fountain.state["states"]["mode"] == 2


async def test_a_button_press_reflects_no_state():
    """A button has no `value_path`; writing one anyway would file the value
    under the empty string."""
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_reset_filter"), b"w5_reset_filter")

    assert bridge.ble == [(PARENT_ID, FOUNTAIN_ID, CMD_RESET_FILTER, b"")]
    assert "" not in fountain.state and "" not in fountain.state.get("states", {})


async def test_an_unusable_value_is_not_guessed_at():
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_power"), b"maybe")
    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_mode"), b"turbo")

    assert bridge.ble == []
    assert not _state_publishes(pub)


async def test_a_write_to_a_block_never_reported_is_refused():
    """Every config write restates the whole block, so without a cmd-211
    reading there is nothing to restate it from."""
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_brightness"), b"5")

    assert bridge.ble == []
    assert not _state_publishes(pub)


async def test_an_accessory_whose_parent_is_gone_is_not_written_to():
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge, link_with=99)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_power"), b"OFF")

    assert bridge.ble == []


async def test_an_accessory_is_unreachable_without_a_bridge():
    fountain, pub = await _fountain_setup(bridge=None)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_power"), b"OFF")

    assert "powerStatus" not in fountain.state.get("states", {})
    assert not _state_publishes(pub)


async def test_an_unsent_frame_is_not_reflected():
    """Optimistic state is only honest if the frame actually left — otherwise
    HA shows a fountain switched off that is still running."""
    bridge = FakeBridge(ble_sent=False)
    fountain, pub = await _fountain_setup(bridge=bridge)

    await _send(pub, FOUNTAIN_ID, _suffix(pub, "w5_power"), b"OFF")

    assert len(bridge.ble) == 1
    assert "powerStatus" not in fountain.state.get("states", {})
    assert not _state_publishes(pub)


async def test_an_unpaired_accessory_with_a_stale_index_is_dropped():
    bridge = FakeBridge()
    fountain, pub = await _fountain_setup(bridge=bridge)
    suffix = _suffix(pub, "w5_power")
    pub._ble_registry.remove(FOUNTAIN_ID)

    await _send(pub, FOUNTAIN_ID, suffix, b"OFF")

    assert bridge.ble == []
