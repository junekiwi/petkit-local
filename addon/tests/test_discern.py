import os
import tempfile
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

import pytest

from petkit_local.ai.pets import PetRegistry
from petkit_local.devices.registry import DeviceRegistry
from petkit_local.events.store import EventStore
from petkit_local.http.server import create_app

CONFIG = {
    "api_url": "http://192.0.2.50:8080/6/",
    "mqtt_port": 1883,
    "proxy_mode": False,
    "proxy_upstream": "",
    "proxy_block_run_cmd": True,
    "data_dir": "",
}

JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"A" * 60


#: Every store this module's helpers opened, drained by the autouse fixture
#: below. A store holds an aiosqlite pool bound to the test's own event loop,
#: and one left open fails later, in its worker thread, against a closed loop.
_OPEN_STORES: list[EventStore] = []


@pytest.fixture(autouse=True)
async def _close_stores():
    yield
    while _OPEN_STORES:
        await _OPEN_STORES.pop().close()


async def _client(tmp, device_type="t5"):
    reg = DeviceRegistry()
    device = reg.get_or_create(petkit_id=100, device_type=device_type, serial_number="SN100")
    store = EventStore(Path(tmp) / "petkit.db")
    _OPEN_STORES.append(store)
    pet_registry = PetRegistry(store, str(Path(tmp) / "faces"))

    config = dict(CONFIG)
    config["data_dir"] = tmp
    app = create_app(reg, config)
    app["pet_registry"] = pet_registry

    client = TestClient(TestServer(app))
    await client.start_server()
    return client, device, pet_registry


HDR = {"X-Device": "id=100&sn=SN100"}

# A non-numeric id used to reach a bare int() and answer HTTP 500.
HDR_BAD_ID = {"X-Device": "id=t5-100&sn=SN-NOT-REGISTERED"}


async def test_discern_config_is_empty_for_non_ai_device():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="t3")  # ESP32, no NPU
        try:
            r = await client.post("/6/t3/dev_discern_config", headers=HDR)
            assert (await r.json())["result"] == {}
        finally:
            await client.close()


async def test_discern_config_serves_the_cloud_thresholds():
    """The captured cloud body, verbatim: two detector thresholds under `list`,
    and no enable flag — the `aiAnalyse`/`discernPic` pair this used to return
    were state-report field names the firmware never reads here."""
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="t5")
        try:
            r = await client.post("/6/t5/dev_discern_config", headers=HDR)
            assert (await r.json())["result"] == {"list": {"area": 6000, "score": 25.0}}
        finally:
            await client.close()


async def test_discern_config_thresholds_are_per_device_overridable():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="t5")
        try:
            device.config["ai_thresholds"] = {"area": 12000, "score": 40}
            r = await client.post("/6/t5/dev_discern_config", headers=HDR)
            assert (await r.json())["result"]["list"] == {"area": 12000, "score": 40.0}
        finally:
            await client.close()


async def test_discern_config_keeps_thresholds_when_ai_is_off():
    """They gate whether a visit episode opens at all, not just identification,
    so withholding them would suppress toilet visits too."""
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="t5")
        try:
            device.config["ai_enabled"] = False
            r = await client.post("/6/t5/dev_discern_config", headers=HDR)
            assert (await r.json())["result"]["list"] == {"area": 6000, "score": 25.0}
        finally:
            await client.close()


async def test_discern_pic_empty_without_pets():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            r = await client.post("/6/t5/dev_discern_pic", headers=HDR)
            body = await r.json()
            assert body["result"]["list"] == []
        finally:
            await client.close()


async def test_discern_pic_lists_pet_with_photo():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            face = await pet_registry.add_face(pet["id"], JPEG_BYTES)

            r = await client.post("/6/t5/dev_discern_pic", headers=HDR)
            entries = (await r.json())["result"]["list"]
            assert len(entries) == 1
            assert entries[0]["id"] == pet["id"]
            assert entries[0]["discern"][0]["id"] == face["id"]
            assert entries[0]["discern"][0]["url"].startswith("http://192.0.2.50:8080/faces/")
            # the cloud sends no `area` inside a list entry
            assert "area" not in entries[0]
        finally:
            await client.close()


async def test_discern_pic_empty_for_non_ai_device():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="t3")
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            await pet_registry.add_face(pet["id"], JPEG_BYTES)
            r = await client.post("/6/t3/dev_discern_pic", headers=HDR)
            assert (await r.json())["result"]["list"] == []
        finally:
            await client.close()


async def test_discern_pic_is_where_ai_enabled_is_enforced():
    """`dev_discern_config` has no on/off field on the wire, so "recognise
    nobody" can only be expressed by serving no photos."""
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            await pet_registry.add_face(pet["id"], JPEG_BYTES)
            device.config["ai_enabled"] = False
            r = await client.post("/6/t5/dev_discern_pic", headers=HDR)
            assert (await r.json())["result"]["list"] == []
        finally:
            await client.close()


async def test_faces_endpoint_serves_saved_photo():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            face = await pet_registry.add_face(pet["id"], JPEG_BYTES)
            filename = Path(face["photo_path"]).name

            r = await client.get(f"/faces/{filename}")
            assert r.status == 200
            assert await r.read() == JPEG_BYTES
        finally:
            await client.close()


async def test_faces_endpoint_rejects_traversal():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            r = await client.get("/faces/..%2F..%2Fetc%2Fpasswd")
            assert r.status in (400, 404)
        finally:
            await client.close()


async def test_faces_endpoint_404_for_missing_file():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            r = await client.get("/faces/nope.jpg")
            assert r.status == 404
        finally:
            await client.close()


async def test_faces_endpoint_rejects_encoded_and_absolute_paths():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            for path in ("/faces/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                         "/faces/..%5C..%5Cetc%5Cpasswd",
                         "/faces/%2Fetc%2Fpasswd"):
                r = await client.get(path)
                assert r.status in (400, 404), f"{path} -> {r.status}"
                assert b"root:" not in await r.read()
        finally:
            await client.close()


async def test_faces_endpoint_rejects_a_symlink_pointing_outside():
    # The old guard only looked for "/", "\" and ".." in the name, so a
    # symlink placed in the faces dir was served whatever it pointed at.
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            faces_dir = Path(tmp) / "faces"
            faces_dir.mkdir(parents=True, exist_ok=True)
            outside = Path(tmp) / "secret.txt"
            outside.write_bytes(b"not for the device")
            os.symlink(outside, faces_dir / "escape.jpg")

            r = await client.get("/faces/escape.jpg")
            assert r.status == 400
        finally:
            await client.close()


async def test_discern_endpoints_survive_a_malformed_device_id():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            await pet_registry.add_face(pet["id"], JPEG_BYTES)

            r = await client.post("/6/t5/dev_discern_pic", headers=HDR_BAD_ID)
            assert r.status == 200
            assert (await r.json())["result"]["list"] == []

            r = await client.post("/6/t5/dev_discern_config", headers=HDR_BAD_ID)
            assert r.status == 200
            assert (await r.json())["result"] == {}
        finally:
            await client.close()


async def test_discern_pic_resolves_the_device_by_serial():
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            await pet_registry.add_face(pet["id"], JPEG_BYTES)

            r = await client.post("/6/t5/dev_discern_pic",
                                  headers={"X-Device": "id=oops&sn=SN100"})
            entries = (await r.json())["result"]["list"]
            # Resolved by serial -> the photos are still attributed to id 100.
            assert [e["id"] for e in entries] == [pet["id"]]
        finally:
            await client.close()


async def test_discern_pic_coerces_a_persisted_string_flag():
    # ai_enabled round-trips through devices.json; a stringy "false" must not
    # read as enabled (bool("false") is True).
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp)
        try:
            pet = await pet_registry.create("Mruczek", device_ids=[100])
            await pet_registry.add_face(pet["id"], JPEG_BYTES)

            device.config["ai_enabled"] = "false"
            r = await client.post("/6/t5/dev_discern_pic", headers=HDR)
            assert (await r.json())["result"]["list"] == []

            device.config["ai_enabled"] = "true"
            r = await client.post("/6/t5/dev_discern_pic", headers=HDR)
            assert len((await r.json())["result"]["list"]) == 1
        finally:
            await client.close()


async def test_a_camera_device_that_asks_is_remembered_as_ai_capable():
    """Asking IS the capability — firmware without an NPU has no reason to poll
    these endpoints. This is what lets a gen-2 YumShare work despite sharing its
    codename with a model that has none."""
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="d4sh")
        try:
            assert device.supports_ai is False
            await client.post("/6/d4sh/dev_discern_config",
                              headers={"X-Device": "id=100&sn=SN100"})
            assert device.config["ai_observed"] is True
            assert device.supports_ai is True
        finally:
            await client.close()


async def test_a_device_with_no_camera_is_never_marked_ai_capable():
    """Recognition needs something to see with. Without this gate a stray poll —
    or a forged request on an unauthenticated LAN port — would offer face photos
    to hardware that has no camera."""
    with tempfile.TemporaryDirectory() as tmp:
        client, device, pet_registry = await _client(tmp, device_type="t3")
        try:
            await client.post("/6/t3/dev_discern_config", headers=HDR)
            await client.post("/6/t3/dev_discern_pic", headers=HDR)
            assert "ai_observed" not in device.config
            assert device.supports_ai is False
        finally:
            await client.close()
