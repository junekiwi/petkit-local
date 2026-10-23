"""Importing a device's configuration from PetKit's own replies.

The replies below have the exact shape PetKit gave a T4 (fw 1.652) and a D4
(fw 1.267) on 2026-10-22 (proxied), with every id, serial and secret replaced.
What matters is what the device is SERVED afterwards, so most tests ask the
device-facing app, not the registry.
"""
import json

from aiohttp.test_utils import TestClient, TestServer

from petkit_local.devices.ble import BLERegistry
from petkit_local.devices.registry import DeviceRegistry
from petkit_local.http.server import create_app
from petkit_local.web.hub import EventHub
from petkit_local.web.panel import create_panel_app

DEVICE_CONFIG = {"api_url": "http://x/6/", "mqtt_port": 1883, "proxy_mode": False,
                 "proxy_upstream": "", "proxy_block_run_cmd": True}

T4_SETTINGS = {
    "sandType": 1, "manualLock": 0, "lightMode": 1, "lightRange": [0, 1440],
    "autoWork": 1, "fixedTimeClear": 1, "stillTime": 60, "language": "fr_FR",
    "avoidRepeat": 0, "disturbRange": [45, 525], "relateK3Switch": 1, "autoSpray": 1,
}
T4 = {
    "type": "t4",
    "dev_signup": {"result": {"id": 300000001, "mac": "aabbccddee01", "sn": "SNT4",
                              "secret": "0123456789abcdef", "timezone": 1.0,
                              "locale": "Europe/Paris", "shareOpen": 0}},
    "dev_device_info": {"result": {
        "id": 300000001, "mac": "aabbccddee01", "sn": "SNT4", "secret": "0123456789abcdef",
        "timezone": 1.0, "locale": "Europe/Paris", "typeCode": 2, "withK3": 1,
        "k3Id": 300000009, "btMac": "aabbccddee03", "settings": T4_SETTINGS,
        "multiConfig": True}},
    "dev_schedule_get": {"result": [
        {"id": 460621, "deviceId": 300000001, "time": 480, "type": 0,
         "repeats": "1,2,3,4,5,6,7", "updatedAt": "2026-06-12T00:48:27.000+0000"},
        {"id": 1023824, "deviceId": 300000009, "time": 180, "type": 1,
         "repeats": "1,2,3,4,5,6,7", "updatedAt": "2026-06-11T07:53:35.000+0000"}]},
    "dev_multi_config": {"result": {
        "lightMultiRange": "{\"lightMultiRange\":[[0,1440]]}",
        "distrubMultiRange": "{\"distrubMultiRange\":[[45,525]]}"}},
    "dev_k3_device_info": {"result": {
        "k3Config": {"config": {"standard": [5, 30], "lightness": 100, "lowVoltage": 5,
                                "refreshTotalTime": 11500, "singleRefreshTime": 25,
                                "singleLightTime": 120}},
        "k3Device": {"id": 300000009, "mac": "aabbccddee09", "sn": "SNK3",
                     "secret": "k3secretk3secret", "hardware": 1, "firmware": 39,
                     "settings": {"liquidLackSwitch": 1, "fixedTimeRefresh": 0},
                     "relateT4": 300000001, "battery": 69, "liquid": 92}}},
}

D4 = {
    "type": "d4",
    "dev_signup": {"result": {
        "id": 300000002, "mac": "aabbccddee02", "sn": "SND4", "secret": "fedcba9876543210",
        "timezone": 1.0, "locale": "Europe/Paris", "btMac": "aabbccddee04", "typeCode": 1,
        "settings": {"foodWarn": 0, "foodWarnRange": [480, 1200], "manualLock": 0,
                     "lightMode": 0, "lightRange": [0, 1440], "factor": 10, "feedSound": 0}}},
    # Given without its wrapper, which is accepted.
    "dev_feed_get": {
        "schedule": [{"re": "1,2,3,4,5,6,7",
                      "it": [{"id": "n_23400", "t": 23400, "a": 10},
                             {"id": "n_43200", "t": 43200, "a": 10},
                             {"id": "n_64800", "t": 64800, "a": 10}],
                      "itemJsonString": "[]"}],
        "nextTick": 100460, "latest": []},
}


async def _apps():
    reg, ble = DeviceRegistry(), BLERegistry()
    panel = TestClient(TestServer(create_panel_app(
        reg, ble, EventHub(), {"api_url": "http://x/6/", "capture": False}, None)))
    device = TestClient(TestServer(create_app(reg, DEVICE_CONFIG)))
    await panel.start_server()
    await device.start_server()
    return panel, device, reg, ble


async def _import(panel, *entries):
    r = await panel.post("/api/import", data=json.dumps({"devices": list(entries)}))
    assert r.status == 200
    return await r.json()


async def test_a_t4_imported_before_first_contact_is_served_its_own_setup():
    """The T4 reads its whole settings block at boot and adopts it, so the
    first answer it gets must already be PetKit's, not our defaults."""
    panel, device, reg, ble = await _apps()
    try:
        out = await _import(panel, T4)
        summary = out["devices"][0]
        assert summary["created"] is True
        assert {"secret", "settings", "schedules", "ranges"} <= set(summary["imported"])
        assert not summary["skipped"]

        hdr = {"X-Device": "id=300000001&sn=SNT4"}
        settings = (await (await device.get("/6/t4/dev_device_info", headers=hdr)).json())["result"]["settings"]
        for key, value in T4_SETTINGS.items():
            assert settings[key] == value, key

        schedules = (await (await device.get("/6/t4/dev_schedule_get", headers=hdr)).json())["result"]
        assert schedules == T4["dev_schedule_get"]["result"]

        ranges = (await (await device.get("/6/t4/dev_multi_config", headers=hdr)).json())["result"]
        assert json.loads(ranges["distrubMultiRange"]) == {"distrubMultiRange": [[45, 525]]}

        # The secret PetKit issued is handed back unchanged at signup.
        signup = (await (await device.post("/6/t4/dev_signup", headers=hdr)).json())["result"]
        assert signup["secret"] == "0123456789abcdef"
    finally:
        await panel.close()
        await device.close()


async def test_the_pura_air_comes_in_from_the_nested_reply():
    """PetKit nests the spray under `k3Device`/`k3Config` on a T4; read flat,
    the reply described nothing and the spray was never paired (issue #17)."""
    panel, device, reg, ble = await _apps()
    try:
        out = await _import(panel, T4)
        k3 = ble.get(300000009)
        assert k3 is not None and k3.ble_type == "k3"
        assert k3.link_with == 300000001
        assert k3.secret == "k3secretk3secret"
        assert any(a["petkit_id"] == 300000009 for a in out["accessories"])
    finally:
        await panel.close()
        await device.close()


async def test_a_d4_keeps_feeding_on_its_imported_schedule():
    """A feeder that fetches an empty schedule stops feeding."""
    panel, device, reg, ble = await _apps()
    try:
        out = await _import(panel, D4)
        assert "feeding schedule" in out["devices"][0]["imported"]
        hdr = {"X-Device": "id=300000002&sn=SND4"}
        feed = (await (await device.get("/6/d4/dev_feed_get", headers=hdr)).json())["result"]
        meals = feed["schedule"][0]["it"]
        assert [(m["t"], m["a"]) for m in meals] == [(23400, 10), (43200, 10), (64800, 10)]
        assert all("a1" not in m for m in meals)
        assert reg.get(300000002).config["bt_mac"] == "aabbccddee04"
    finally:
        await panel.close()
        await device.close()


async def test_importing_onto_a_known_device_adopts_petkit_s_values():
    panel, device, reg, ble = await _apps()
    try:
        hdr = {"X-Device": "id=300000001&sn=SNT4"}
        await device.post("/6/t4/dev_signup", headers=hdr)
        assert reg.get(300000001).config["settings"].get("stillTime") != 60
        out = await _import(panel, T4)
        assert out["devices"][0]["created"] is False
        assert reg.get(300000001).config["settings"]["stillTime"] == 60
    finally:
        await panel.close()
        await device.close()


async def test_a_bad_entry_is_reported_and_the_rest_still_imported():
    panel, device, reg, ble = await _apps()
    try:
        await device.post("/6/t4/dev_signup", headers={"X-Device": "id=300000002&sn=X"})
        out = await _import(panel, {"type": "k3"}, {"type": "t4"},
                            {**D4, "type": "d4"}, T4)
        errors = [d.get("error") for d in out["devices"]]
        assert "Bluetooth-only" in errors[0]
        assert "no device id" in errors[1]
        # Id 300000002 is already a T4 here; the D4 entry must not retype it.
        assert "already registered as a t4" in errors[2]
        assert out["devices"][3]["id"] == 300000001
        assert reg.get(300000002).device_type == "t4"
    finally:
        await panel.close()
        await device.close()


async def test_a_body_that_is_not_an_import_document_is_refused():
    panel, device, reg, ble = await _apps()
    try:
        r = await panel.post("/api/import", data=json.dumps({"devices": []}))
        assert r.status == 400
        r = await panel.post("/api/import", data="[1, 2]")
        assert r.status == 400
    finally:
        await panel.close()
        await device.close()
