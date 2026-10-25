import asyncio
import json
import os
import tempfile
from pathlib import Path

import petkit_local.utils.jsonio as jsonio
from petkit_local.devices import defaults
from petkit_local.devices.ble import BLERegistry
from petkit_local.devices.registry import DeviceRegistry


def _stored(path) -> dict:
    return json.loads(Path(path).read_text())


async def _stored_eventually(path, device_id: str, field: str, want: str,
                             timeout: float = 5.0) -> None:
    """Wait for the debounced flusher to put `want` on disk.

    A fixed sleep would be asserting how fast a CI runner is, not what the
    flusher does: the interval these tests use is 10ms, and one slow scheduling
    round on a loaded machine is enough to miss it. Polls instead, with a
    deadline long enough that a failure means the write never happened.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            if _stored(path)[device_id][field] == want:
                return
        except (OSError, KeyError, json.JSONDecodeError):
            pass
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(
                f"{device_id}.{field} never reached {want!r} on disk within {timeout}s; "
                f"file holds {_stored(path).get(device_id, '(no such device)')!r}")
        await asyncio.sleep(0.01)


def test_create_seeds_settings():
    reg = DeviceRegistry()
    d = reg.get_or_create(petkit_id=1, device_type="t5", serial_number="SN")
    assert d.config.get("settings"), "new device should have seeded settings"
    assert "autoWork" in d.config["settings"]


def test_seeded_settings_match_the_public_defaults():
    # The registry, ha/publisher.py and the tests all seed from the same
    # defaults.default_settings(); a divergence would show HA one set of values
    # while the device_info response hands the device another.
    reg = DeviceRegistry()
    d = reg.get_or_create(petkit_id=1, device_type="t5", serial_number="SN")
    assert d.config["settings"] == defaults.default_settings(d)


def test_persistence_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        d = reg.get_or_create(petkit_id=5, device_type="d4h", serial_number="SN5", mac="AA:BB")
        pk, secret = d.mqtt_product_key, d.mqtt_device_secret

        # Reload from disk
        reg2 = DeviceRegistry(persist_path=path)
        d2 = reg2.get(5)
        assert d2 is not None
        assert d2.device_type == "d4h"
        assert d2.serial_number == "SN5"
        assert d2.mqtt_product_key == pk  # stable credentials survive restart
        assert d2.mqtt_device_secret == secret
        assert d2.config.get("settings")


def test_settings_added_in_a_later_version_are_backfilled_on_load():
    """`setdefault("settings", ...)` only fires when the whole block is absent,
    so a device registered by an older build never gained a key added later —
    the reference T5 was short ~25 of them."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        d = reg.get_or_create(petkit_id=5, device_type="t5", serial_number="SN5")
        # An older build's stored block: one key, and one the owner has changed
        # away from the default.
        d.config["settings"] = {"autoWork": 0}
        reg.save()

        d2 = DeviceRegistry(persist_path=path).get(5)
        assert d2.config["settings"]["autoWork"] == 0   # owner's value survives
        assert "petDetection" in d2.config["settings"]  # gap filled
        assert set(defaults.default_settings(d2)) <= set(d2.config["settings"])


def test_by_mqtt_name_lookup():
    reg = DeviceRegistry()
    d = reg.get_or_create(petkit_id=3, device_type="t5", serial_number="SN")
    found = reg.by_mqtt_name(d.mqtt_product_key, d.mqtt_device_name)
    assert found is d
    assert reg.by_mqtt_name("nope", "nope") is None


def test_by_mqtt_name_resolves_the_shared_patched_key_by_device_name():
    """Every patched ESP32 connects under one key, so the name decides."""
    from petkit_local.devices.payloads import PATCHED_PRODUCT_KEY

    reg = DeviceRegistry()
    t4 = reg.get_or_create(petkit_id=3, device_type="t4", serial_number="SN3")
    d4 = reg.get_or_create(petkit_id=4, device_type="d4", serial_number="SN4")
    assert reg.by_mqtt_name(PATCHED_PRODUCT_KEY, t4.mqtt_device_name) is t4
    assert reg.by_mqtt_name(PATCHED_PRODUCT_KEY, d4.mqtt_device_name) is d4
    assert reg.by_mqtt_name(PATCHED_PRODUCT_KEY, "d_t4_UNKNOWN") is None
    # Any other key still has to be the device's own.
    assert reg.by_mqtt_name(d4.mqtt_product_key, t4.mqtt_device_name) is None


def test_get_or_create_is_idempotent():
    reg = DeviceRegistry()
    a = reg.get_or_create(petkit_id=1, device_type="t5")
    b = reg.get_or_create(petkit_id=1, device_type="t5")
    assert a is b


def test_load_seeds_settings_for_legacy_data():
    # A device persisted before settings-seeding existed must gain defaults on load.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        path.write_text(json.dumps({
            "1": {"device_type": "t5", "petkit_id": 1, "serial_number": "SN", "config": {}}
        }))
        reg = DeviceRegistry(persist_path=path)
        assert reg.get(1).config.get("settings")


# --- crash-safe persistence -------------------------------------------------

def test_save_leaves_no_temp_files_behind():
    with tempfile.TemporaryDirectory() as tmp:
        reg = DeviceRegistry(persist_path=Path(tmp) / "devices.json")
        reg.get_or_create(petkit_id=1, device_type="t5")
        reg.get_or_create(petkit_id=2, device_type="t4")
        reg.save()

        assert sorted(os.listdir(tmp)) == ["devices.json"]


def test_a_crash_mid_write_cannot_empty_the_registry():
    # The rename is the only step that can publish a partial file, so failing it
    # stands in for "the container was killed while saving".
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        reg.get_or_create(petkit_id=7, device_type="t5", serial_number="SN7")
        secret = reg.get(7).mqtt_device_secret

        def failing_replace(src, dst):
            raise OSError("simulated container kill")

        real_replace = jsonio.os.replace
        jsonio.os.replace = failing_replace
        try:
            reg.get_or_create(petkit_id=8, device_type="t4", serial_number="SN8")
        finally:
            jsonio.os.replace = real_replace

        assert sorted(os.listdir(tmp)) == ["devices.json"], "temp file was left behind"
        reloaded = DeviceRegistry(persist_path=path)
        assert reloaded.get(7) is not None, "an interrupted save must not empty the registry"
        assert reloaded.get(7).mqtt_device_secret == secret
        assert reloaded.get(8) is None  # the interrupted write simply did not land


def test_a_failed_save_stays_pending_and_lands_on_the_next_one():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        reg.get_or_create(petkit_id=1, device_type="t5")

        def failing_replace(src, dst):
            raise OSError("disk full")

        real_replace = jsonio.os.replace
        jsonio.os.replace = failing_replace
        try:
            reg.get_or_create(petkit_id=2, device_type="t4")
        finally:
            jsonio.os.replace = real_replace

        reg.save()
        assert set(_stored(path)) == {"1", "2"}


def test_truncated_registry_starts_empty_without_raising():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        reg.get_or_create(petkit_id=1, device_type="t5")
        path.write_text(path.read_text()[:20])  # a half-written file

        assert DeviceRegistry(persist_path=path).all() == []


def test_one_unreadable_entry_does_not_drop_the_others():
    # A whole-file try/except used to cost every device its credentials as soon
    # as a single record was malformed.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        path.write_text(json.dumps({
            "1": {"device_type": "t5", "petkit_id": 1, "serial_number": "SN1"},
            "2": {"serial_number": "no device_type"},
            "3": "not even an object",
            "4": {"device_type": "t4", "petkit_id": 4, "serial_number": "SN4"},
        }))
        reg = DeviceRegistry(persist_path=path)

        assert sorted(d.petkit_id for d in reg.all()) == [1, 4]


# --- get_or_create updates (FIX 2) ------------------------------------------

def test_get_or_create_updates_survive_a_restart():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        reg.get_or_create(petkit_id=9, device_type="t5")
        reg.get_or_create(petkit_id=9, device_type="t5",
                          serial_number="SN9", mac="AA:BB", firmware="943")

        d = DeviceRegistry(persist_path=path).get(9)
        assert d.serial_number == "SN9"
        assert d.mac == "AA:BB"
        assert d.firmware == "943"
        assert d.mqtt_device_name == "d_t5_SN9"


def test_get_or_create_keeps_credentials_when_fields_are_updated():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        created = reg.get_or_create(petkit_id=9, device_type="t5", serial_number="SN9")
        secret = created.mqtt_device_secret
        reg.get_or_create(petkit_id=9, device_type="t5", firmware="944")

        assert DeviceRegistry(persist_path=path).get(9).mqtt_device_secret == secret


# --- debounced flush (FIX 3) ------------------------------------------------

def test_mark_dirty_writes_immediately_without_an_event_loop():
    # Nothing would ever pick the flag up in sync code, so it must not be queued.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path)
        device = reg.get_or_create(petkit_id=1, device_type="t5")
        device.firmware = "944"
        reg.mark_dirty()

        assert _stored(path)["1"]["firmware"] == "944"


def test_registry_without_a_persist_path_never_writes():
    reg = DeviceRegistry()
    reg.get_or_create(petkit_id=1, device_type="t5")
    reg.mark_dirty()
    reg.save()  # must not raise


async def test_mark_dirty_coalesces_writes_on_the_event_loop():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path, flush_interval=0.01)
        device = reg.get_or_create(petkit_id=1, device_type="t5")
        await reg.start()
        try:
            for firmware in ("941", "942", "943"):
                device.firmware = firmware
                reg.mark_dirty()
            assert _stored(path)["1"]["firmware"] == "", "writes should be coalesced"

            await _stored_eventually(path, "1", "firmware", "943")
        finally:
            await reg.stop()


async def test_get_or_create_update_reaches_disk_via_the_flusher():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path, flush_interval=0.01)
        reg.get_or_create(petkit_id=9, device_type="t5")
        await reg.start()
        try:
            reg.get_or_create(petkit_id=9, device_type="t5", firmware="944")
            await _stored_eventually(path, "9", "firmware", "944")
        finally:
            await reg.stop()


async def test_stop_flushes_a_pending_write():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path, flush_interval=3600)
        device = reg.get_or_create(petkit_id=1, device_type="t5")
        await reg.start()
        device.firmware = "944"
        reg.mark_dirty()
        assert _stored(path)["1"]["firmware"] == ""

        await reg.stop()
        assert _stored(path)["1"]["firmware"] == "944"


async def test_cancelling_the_flusher_still_writes_pending_state():
    # aiohttp's cleanup cancels background tasks; that path must not lose data.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        reg = DeviceRegistry(persist_path=path, flush_interval=3600)
        device = reg.get_or_create(petkit_id=1, device_type="t5")
        await reg.start()
        device.firmware = "944"
        reg.mark_dirty()

        task = reg._flush_task
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert _stored(path)["1"]["firmware"] == "944"


async def test_start_and_stop_are_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        reg = DeviceRegistry(persist_path=Path(tmp) / "devices.json", flush_interval=3600)
        await reg.start()
        first = reg._flush_task
        await reg.start()
        assert reg._flush_task is first

        await reg.stop()
        await reg.stop()  # must not raise


# --- BLE registry (same base class) -----------------------------------------

def test_ble_register_updates_survive_a_restart():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ble_devices.json"
        reg = BLERegistry(persist_path=path)
        reg.register(petkit_id=2, ble_type="k3", link_with=5)
        reg.register(petkit_id=2, ble_type="k3", mac="AA:BB:CC", link_with=5)

        reloaded = BLERegistry(persist_path=path).get(2)
        assert reloaded is not None
        assert reloaded.mac == "AA:BB:CC"
        assert reloaded.link_with == 5


def test_ble_save_leaves_no_temp_files_behind():
    with tempfile.TemporaryDirectory() as tmp:
        reg = BLERegistry(persist_path=Path(tmp) / "ble_devices.json")
        reg.register(petkit_id=2, ble_type="w5", mac="AA")
        reg.save()

        assert sorted(os.listdir(tmp)) == ["ble_devices.json"]


def test_ble_load_skips_an_unreadable_entry():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ble_devices.json"
        path.write_text(json.dumps({
            "2": {"ble_type": "k3", "petkit_id": 2},
            "3": ["not an object"],
        }))
        reg = BLERegistry(persist_path=path)

        assert [d.petkit_id for d in reg.all()] == [2]


def test_every_persisted_field_is_restored():
    """`to_dict` and `from_dict` are written as two explicit lists, so a field
    added to one and forgotten in the other persists and then silently resets at
    the next restart. That happened to `api_secret`: the real PetKit credential
    was written to disk and dropped on load, so the device reverted to a secret
    the cloud rejects and every request started 704ing again."""
    from petkit_local.devices.base import Device

    original = Device(device_type="t5", petkit_id=42, serial_number="SN42",
                      mac="aa:bb", firmware="943")
    original.api_secret = "0123456789abcdef"
    original.config = {"locale": "Europe/Warsaw"}

    stored = original.to_dict()
    restored = Device.from_dict(stored)

    for key, value in stored.items():
        assert getattr(restored, key) == value, f"{key} was persisted but not restored"
