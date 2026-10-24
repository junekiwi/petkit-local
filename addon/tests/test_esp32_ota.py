"""Flashing the ESP32 CA swap over OTA, and taking it back.

The store, the offer `dev_ota_check` answers with, the two-pass job the device's
`dev_ota_start` / `dev_ota_complete` reports drive, and the panel's fetch from a
fake PetKit cloud. Images are the hand-built ones `test_patcher_esp32` uses; a
real device has not yet flashed anything this code offered.
"""
from __future__ import annotations

import hashlib
import os

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from petkit_local.devices.base import Device
from petkit_local.devices.ble import BLERegistry
from petkit_local.devices.registry import DeviceRegistry
from petkit_local.http.handlers.ota import firmware_base_url, offers_firmware
from petkit_local.http.proxy import close_proxy_session
from petkit_local.http.server import create_app
from petkit_local.patchers import esp32_ota
from petkit_local.patchers.firmware import (
    FirmwareImageError, find_cert_slot, generate_ca_for_slot, verify_esp_image,
)
from petkit_local.web.hub import EventHub
from petkit_local.web.panel import create_panel_app
from tests.test_patcher_esp32 import _cert_image, _crlf_slot, _slot_for_der

HDR = {"X-Device": "id=100&sn=SN100&type=D4"}


@pytest.fixture(scope="module")
def stock_image() -> bytes:
    """A D4-shaped stock image; its embedded CA stands in for GlobalSign."""
    _, stand_in = generate_ca_for_slot(_crlf_slot())
    return _cert_image(stand_in)


def _md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def _listing(modules: dict[str, bytes], base: str = "http://cdn.example/fw") -> dict:
    """PetKit's `dev_ota_check` result for `modules`, shaped like localkit's
    mirror of it (and like petkit-firmware-tool reads it)."""
    return {
        "firmwareId": 1031,
        "version": "1.267",
        "details": [
            {"id": 1040 + i, "module": name, "version": 2531005 + i,
             "file": {"url": f"{base}/{name}.bin", "size": len(blob), "digest": _md5(blob)}}
            for i, (name, blob) in enumerate(modules.items())
        ],
    }


def _device(device_type: str = "d4") -> Device:
    return Device(device_type=device_type, petkit_id=100, serial_number="SN100")


# --------------------------------------------------------------------------- #
# The store                                                                   #
# --------------------------------------------------------------------------- #


def test_a_release_keeps_stock_verbatim_and_patches_userbin_to_our_ca(tmp_path, stock_image):
    modules = {"userbin": stock_image}
    release = esp32_ota.save_release(str(tmp_path), "d4", _listing(modules), modules)

    stock_path = esp32_ota.module_path(str(tmp_path), "d4", "1.267", "stock", "userbin")
    patched_path = esp32_ota.module_path(str(tmp_path), "d4", "1.267", "patched", "userbin")
    assert open(stock_path, "rb").read() == stock_image
    patched = open(patched_path, "rb").read()
    verify_esp_image(patched)
    s, e = find_cert_slot(patched)
    _key, ca = esp32_ota.load_ca(str(tmp_path))
    assert patched[s:e] == ca

    assert esp32_ota.load_release(str(tmp_path), "d4", "1.267") == release
    module = release.summary()["modules"][0]
    assert module["stock_md5"] == _md5(stock_image)
    assert module["patched_md5"] == _md5(patched)


def test_every_release_trusts_the_same_ca(tmp_path, stock_image):
    # The broker presents one leaf, so a T4 and a D4 must trust one root.
    modules = {"userbin": stock_image}
    esp32_ota.save_release(str(tmp_path), "d4", _listing(modules), modules)
    first = esp32_ota.ca_fingerprint(str(tmp_path))
    esp32_ota.save_release(str(tmp_path), "t4", _listing(modules), modules)
    assert esp32_ota.ca_fingerprint(str(tmp_path)) == first != ""


def test_a_slot_the_ca_cannot_fill_is_refused(tmp_path, stock_image):
    modules = {"userbin": stock_image}
    esp32_ota.save_release(str(tmp_path), "d4", _listing(modules), modules)
    with pytest.raises(FirmwareImageError, match="second CA"):
        esp32_ota.ensure_ca(str(tmp_path), _slot_for_der(889, b"\n"))


def test_a_module_that_is_not_what_petkit_described_is_refused(tmp_path, stock_image):
    listing = _listing({"userbin": stock_image})
    listing["details"][0]["file"]["digest"] = "0" * 32
    with pytest.raises(FirmwareImageError, match="but PetKit described"):
        esp32_ota.save_release(str(tmp_path), "d4", listing, {"userbin": stock_image})
    assert not (tmp_path / "firmware").exists()


@pytest.mark.parametrize("mutate, match", [
    (lambda m: m.update(version="../../etc"), "version"),
    (lambda m: m["details"][0].update(module="a/b"), "module name"),
    (lambda m: m["details"][0].update(module="pics"), "no userbin"),
    (lambda m: m["details"][0]["file"].update(size=10 ** 9), "size"),
    (lambda m: m["details"][0]["file"].update(url="ftp://x"), "URL"),
    (lambda m: m.update(firmwareId="1031"), "firmwareId"),
])
def test_a_listing_of_the_wrong_shape_stops_before_anything_acts_on_it(mutate, match):
    listing = _listing({"userbin": b"x"})
    mutate(listing)
    with pytest.raises(FirmwareImageError, match=match):
        esp32_ota.validate_manifest(listing)


def test_the_offer_points_here_and_carries_the_variant_s_digest(tmp_path, stock_image):
    modules = {"userbin": stock_image, "pics": b"P" * 100}
    release = esp32_ota.save_release(str(tmp_path), "t4", _listing(modules), modules)
    patched_md5 = release.summary()["modules"][0]["patched_md5"]

    offered = esp32_ota.offer(release, "patched", "http://192.0.2.5:80")
    assert offered["firmwareId"] == 1031 and offered["version"] == "1.267"
    userbin, pics = offered["details"]
    assert userbin["file"] == {
        "url": "http://192.0.2.5:80/firmware/t4/1.267/patched/userbin.bin",
        "size": len(stock_image), "digest": patched_md5}
    # Only the module carrying the CA differs; the rest are PetKit's.
    assert pics["file"]["url"].endswith("/firmware/t4/1.267/stock/pics.bin")
    assert pics["file"]["digest"] == _md5(b"P" * 100)
    assert userbin["id"] == 1040 and userbin["version"] == 2531005
    assert "patched" not in userbin

    rollback = esp32_ota.offer(release, "stock", "http://192.0.2.5:80")
    assert rollback["details"][0]["file"]["digest"] == _md5(stock_image)
    assert rollback["details"][0]["file"]["url"].endswith("/stock/userbin.bin")


def test_the_base_url_is_the_api_host_over_plain_http():
    assert firmware_base_url("http://192.168.2.75/6/") == "http://192.168.2.75:80"
    assert firmware_base_url("http://ha.lan:8080/6/") == "http://ha.lan:8080"
    assert firmware_base_url("") == ""


# --------------------------------------------------------------------------- #
# The job                                                                     #
# --------------------------------------------------------------------------- #


def _release() -> esp32_ota.Release:
    return esp32_ota.Release("d4", "1.267", 1031, ())


def test_a_job_is_one_pass_and_leaves_the_other_partition_alone():
    # The other partition keeps the image the device ran before: the
    # bootloader's fallback if ours ever fails verification at boot.
    d = _device()
    esp32_ota.arm(d, _release(), "patched")
    assert d.command_queue == [esp32_ota.ota_trigger(1031)]
    d.command_queue.clear()

    assert esp32_ota.note_started(d) == "device started flashing patched 1.267"
    assert "done" in esp32_ota.note_completed(d, True, "")
    state = esp32_ota.firmware_state(d)
    assert state["job"] is None and state["running"] == "patched"
    assert state["last_result"]["ok"] is True
    assert d.command_queue == []  # no second pass is asked for


def test_a_failed_flash_ends_the_job_and_says_why():
    d = _device()
    esp32_ota.arm(d, _release(), "stock")
    line = esp32_ota.note_completed(d, False, "otafail-3")
    assert "FAILED" in line and "otafail-3" in line
    state = esp32_ota.firmware_state(d)
    assert state["job"] is None
    assert state["last_result"] == {**state["last_result"], "ok": False, "detail": "otafail-3"}
    assert "running" not in state


def test_reports_with_no_job_armed_change_nothing():
    d = _device()
    assert esp32_ota.note_started(d) is None
    assert esp32_ota.note_completed(d, True, "") is None
    assert d.config == {}


# --------------------------------------------------------------------------- #
# What the device sees                                                        #
# --------------------------------------------------------------------------- #


async def _device_client(tmp_path, *, proxy_upstream: str = ""):
    config = {"api_url": "http://192.0.2.5/6/", "data_dir": str(tmp_path),
              "proxy_mode": bool(proxy_upstream), "proxy_upstream": proxy_upstream,
              "proxy_block_ota": True, "capture": False, "capture_dir": str(tmp_path)}
    reg = DeviceRegistry()
    app = create_app(reg, config)
    app["event_hub"] = EventHub()
    client = TestClient(TestServer(app))
    await client.start_server()
    await client.post("/6/d4/dev_signup", headers=HDR)
    return client, reg.get(100)


async def _armed(tmp_path, stock_image, client, device, target="patched"):
    modules = {"userbin": stock_image}
    release = esp32_ota.save_release(str(tmp_path), "d4", _listing(modules), modules)
    esp32_ota.arm(device, release, target)
    return release


async def test_ota_check_says_no_update_until_a_job_is_armed(tmp_path, stock_image):
    client, device = await _device_client(tmp_path)
    try:
        r = await client.post("/6/d4/dev_ota_check", headers=HDR)
        assert await r.json() == {"result": {}}

        await _armed(tmp_path, stock_image, client, device)
        offered = (await (await client.post("/6/d4/dev_ota_check", headers=HDR)).json())["result"]
        url = offered["details"][0]["file"]["url"]
        assert url == "http://192.0.2.5:80/firmware/d4/1.267/patched/userbin.bin"
        # Never on dev_ota_heartbeat, whose meaning nobody has observed.
        r = await client.post("/6/d4/dev_ota_heartbeat", headers=HDR)
        assert await r.json() == {"result": {}}

        esp32_ota.disarm(device)
        r = await client.post("/6/d4/dev_ota_check", headers=HDR)
        assert await r.json() == {"result": {}}
    finally:
        await client.close()


async def test_the_offered_file_is_served_byte_for_byte(tmp_path, stock_image):
    client, device = await _device_client(tmp_path)
    try:
        release = await _armed(tmp_path, stock_image, client, device)
        offered = esp32_ota.offer(release, "patched", "")
        path = offered["details"][0]["file"]["url"]
        r = await client.get(path)
        body = await r.read()
        assert r.status == 200 and _md5(body) == offered["details"][0]["file"]["digest"]
        assert (await client.get("/firmware/d4/1.267/stock/userbin.bin")).status == 200
        assert (await client.get("/firmware/d4/1.267/other/userbin.bin")).status == 404
        assert (await client.get("/firmware/d4/1.267/stock/userbin.txt")).status == 404
        assert (await client.get("/firmware/d4/..%2F..%2F..%2Fetc/stock/passwd.bin")).status in (400, 404)
    finally:
        await client.close()


async def test_progress_reports_drive_the_job(tmp_path, stock_image):
    client, device = await _device_client(tmp_path)
    try:
        await _armed(tmp_path, stock_image, client, device)
        r = await client.post("/6/d4/dev_ota_start", headers=HDR)
        assert await r.json() == {"result": "success"}
        assert esp32_ota.active_job(device)["started_at"] is not None

        r = await client.post("/6/d4/dev_ota_complete", headers=HDR, data="success=1")
        assert await r.json() == {"result": "success"}
        assert esp32_ota.active_job(device) is None
        assert esp32_ota.firmware_state(device)["last_result"]["ok"] is True

        await _armed(tmp_path, stock_image, client, device, target="stock")
        await client.post("/6/d4/dev_ota_complete?errmsg=otafail-3&success=0", headers=HDR)
        assert esp32_ota.firmware_state(device)["last_result"]["detail"] == "otafail-3"
    finally:
        await client.close()


async def test_proxy_mode_does_not_withdraw_an_armed_offer(tmp_path, stock_image):
    # Redaction answers every OTA endpoint "no update", so a forwarded offer
    # would reach the device as nothing at all.
    hits = []

    async def cloud(request):
        hits.append(request.path)
        return web.json_response({"result": {}})

    cloud_app = web.Application()
    cloud_app.router.add_route("*", "/{path:.*}", cloud)
    cloud_client = TestClient(TestServer(cloud_app))
    await cloud_client.start_server()
    client, device = await _device_client(
        tmp_path, proxy_upstream=str(cloud_client.make_url("")).rstrip("/"))
    try:
        await _armed(tmp_path, stock_image, client, device)
        r = await client.post("/6/d4/dev_ota_check", headers=HDR)
        assert (await r.json())["result"]["details"]
        assert not any(p.endswith("dev_ota_check") for p in hits)
    finally:
        await close_proxy_session(client.app)
        await client.close()
        await cloud_client.close()


def test_offers_firmware_reads_only_a_real_offer():
    assert offers_firmware(web.json_response({"result": {"details": [{"module": "userbin"}]}}))
    assert not offers_firmware(web.json_response({"result": {}}))
    assert not offers_firmware(web.Response(body=b"not json"))


# --------------------------------------------------------------------------- #
# The panel                                                                   #
# --------------------------------------------------------------------------- #


async def _fake_petkit(stock_image, *, refuse: bool = False):
    """A PetKit cloud that lists one module and serves it."""
    seen: dict = {}

    async def ota_check(request):
        seen["form"] = dict(await request.post())
        seen["x_device"] = request.headers.get("X-Device", "")
        if refuse:
            return web.json_response({"error": {"code": 704, "msg": "sign"}})
        base = f"http://{request.host}"
        return web.json_response({"result": _listing({"userbin": stock_image}, base + "/f")})

    async def module(request):
        return web.Response(body=stock_image)

    app = web.Application()
    app.router.add_post("/6/d4/dev_ota_check", ota_check)
    app.router.add_get("/f/userbin.bin", module)
    client = TestClient(TestServer(app))
    await client.start_server()
    return client, seen


async def _panel(tmp_path, upstream: str, device_type: str = "d4"):
    reg = DeviceRegistry()
    device = reg.get_or_create(petkit_id=100, device_type=device_type, serial_number="SN100")
    device.wire_type = device_type.upper()
    hub = EventHub()
    app = create_panel_app(reg, BLERegistry(), hub,
                           {"api_url": "http://192.0.2.5/6/", "data_dir": str(tmp_path)},
                           live_config={"proxy_upstream": upstream})
    client = TestClient(TestServer(app))
    await client.start_server()
    return client, device, hub


async def _settle(client):
    for task in list(client.app["background_tasks"]):
        await task


async def test_fetch_then_flash_then_cancel_from_the_panel(tmp_path, stock_image):
    cloud, seen = await _fake_petkit(stock_image)
    client, device, hub = await _panel(tmp_path, str(cloud.make_url("")).rstrip("/"))
    try:
        assert (await (await client.get("/api/devices/100/firmware")).json())["release"] is None
        r = await client.post("/api/devices/100/firmware", json={"action": "fetch"})
        assert (await r.json())["ok"]
        await _settle(client)
        # Asked as the device, for everything: petkit-firmware-tool's request.
        assert seen["form"]["force"] == "1" and "&type=D4&" in seen["x_device"]

        status = await (await client.get("/api/devices/100/firmware")).json()
        assert status["release"]["version"] == "1.267" and status["ca_sha256"]

        r = await client.post("/api/devices/100/firmware", json={"action": "flash"})
        assert (await r.json())["target"] == "patched"
        assert (await (await client.get("/api/devices/100/firmware")).json())["job"]["target"] == "patched"
        assert device.command_queue == [esp32_ota.ota_trigger(1031)]

        await client.post("/api/devices/100/firmware", json={"action": "cancel"})
        assert esp32_ota.active_job(device) is None
    finally:
        await client.close()
        await cloud.close()


async def test_a_refused_fetch_is_narrated_and_stores_nothing(tmp_path, stock_image):
    cloud, _ = await _fake_petkit(stock_image, refuse=True)
    client, device, hub = await _panel(tmp_path, str(cloud.make_url("")).rstrip("/"))
    try:
        await client.post("/api/devices/100/firmware", json={"action": "fetch"})
        await _settle(client)
        lines = [e["summary"] for e in hub.recent() if e["kind"] == "patcher"]
        assert any("FAILED" in s and "704" in s for s in lines), lines
        assert esp32_ota.firmware_state(device) == {}
        assert not os.path.exists(tmp_path / "firmware")
        r = await client.post("/api/devices/100/firmware", json={"action": "flash"})
        assert r.status == 400
    finally:
        await client.close()
        await cloud.close()


async def test_models_the_swap_is_not_offered_for_are_turned_away(tmp_path):
    client, _device, _hub = await _panel(tmp_path, "", device_type="t5")
    try:
        assert await (await client.get("/api/devices/100/firmware")).json() == {"supported": False}
        r = await client.post("/api/devices/100/firmware", json={"action": "fetch"})
        assert r.status == 400
    finally:
        await client.close()
