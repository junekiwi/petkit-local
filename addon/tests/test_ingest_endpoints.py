"""End-to-end HTTP tests for dev_event_report and dev_upload_file_info_v2 —
the two endpoints events/ingest.py normalizers feed."""
import asyncio
import json
import logging
import tempfile
import urllib.parse
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

import pytest

from petkit_local.ai.pets import PetRegistry
from petkit_local.devices.registry import DeviceRegistry
from petkit_local.events.store import EventStore
from petkit_local.http.handlers import upload_file_info
from petkit_local.http.server import create_app
from petkit_local.web.hub import EventHub

CONFIG = {
    "api_url": "http://server/6/",
    "mqtt_port": 1883,
    "proxy_mode": False,
    "proxy_upstream": "",
    "proxy_block_run_cmd": True,
    "capture": False,
}

HDR = {"X-Device": "id=100&sn=SN100"}

# A non-numeric id used to reach a bare int() and answer HTTP 500.
HDR_BAD_ID = {"X-Device": "id=NaN&sn=SN-NOT-REGISTERED"}


def _upload_body(file_id: str, rel: str, module_type: str = "EVENT_PREVIEW") -> str:
    infos = [{"fileId": file_id, "fileUrl": f"https://localhost:9000/{rel}",
              "moduleType": module_type, "eventId": "r1"}]
    return "fileInfos=" + urllib.parse.quote(json.dumps(infos))


def _stage_raw(raw_root: str, rel: str) -> None:
    full = Path(raw_root) / rel
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(b"\xff\xd8\xff\xe0" + b"A" * 60)


#: Every store this module's helpers opened, drained by the autouse fixture
#: below. A store holds an aiosqlite pool bound to the test's own event loop,
#: and one left open fails later, in its worker thread, against a closed loop.
_OPEN_STORES: list[EventStore] = []


@pytest.fixture(autouse=True)
async def _close_stores():
    yield
    while _OPEN_STORES:
        await _OPEN_STORES.pop().close()


async def _client(tmp, config=None, capabilities=None):
    reg = DeviceRegistry()
    device = reg.get_or_create(petkit_id=100, device_type="t5", serial_number="SN100")
    if capabilities is not None:
        device.config["capabilities"] = capabilities
    store = EventStore(Path(tmp) / "petkit.db")
    _OPEN_STORES.append(store)
    hub = EventHub()

    app = create_app(reg, config or CONFIG)
    app["event_store"] = store
    app["event_hub"] = hub
    raw_root = str(Path(tmp) / "raw")
    media_root = str(Path(tmp) / "media")
    app["config"]["media_raw_root"] = raw_root
    app["config"]["media_root"] = media_root
    app["config"]["data_dir"] = tmp

    client = TestClient(TestServer(app))
    await client.start_server()
    return client, reg, store, hub, device, raw_root, media_root


async def test_event_report_persists_event_and_returns_success():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            # eventId IS the session key (related_event) — confirmed on a
            # real T5, see events/ingest.py's module docstring.
            body = 'eventType=10&eventId=e1&content=%7B%22pet_weight%22%3A2200%7D'
            r = await client.post("/6/t5/dev_event_report", headers=HDR, data=body)
            assert r.status == 200
            assert (await r.json())["result"] == "success"

            rows = await store.query_timeline(device_id=100)
            assert len(rows) == 1
            assert rows[0]["event_type"] == "10"
            assert rows[0]["related_event"] == "e1"

            events = hub.recent(10)
            assert any(e["kind"] == "event" for e in events)
        finally:
            await client.close()


async def test_event_report_refreshes_device_state():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            body = 'eventType=other&eventId=e2&state=%7B%22sandPercent%22%3A55%7D'
            r = await client.post("/6/t5/dev_event_report", headers=HDR, data=body)
            assert r.status == 200
            assert device.state.get("sandPercent") == 55
        finally:
            await client.close()


class _FakePetPublisher:
    def __init__(self):
        self.pet_discoveries = []
        self.pet_states = []

    async def publish_event(self, *a, **kw):
        pass

    async def publish_state(self, *a, **kw):
        pass

    async def publish_availability(self, *a, **kw):
        pass

    async def publish_pet_discovery(self, pet):
        self.pet_discoveries.append(pet["id"])

    async def publish_pet_state(self, pet, store):
        self.pet_states.append(pet["id"])


async def test_event_report_with_pet_id_publishes_pet_discovery_and_state():
    with tempfile.TemporaryDirectory() as tmp:
        reg = DeviceRegistry()
        reg.get_or_create(petkit_id=100, device_type="t5", serial_number="SN100")
        store = EventStore(Path(tmp) / "petkit.db")
        _OPEN_STORES.append(store)
        pet_registry = PetRegistry(store, str(Path(tmp) / "faces"))
        pet = await pet_registry.create("Mruczek")
        fake_pub = _FakePetPublisher()

        app = create_app(reg, dict(CONFIG))
        app["event_store"] = store
        app["pet_registry"] = pet_registry
        app["ha_publisher"] = fake_pub

        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            body = ('eventType=pet_out&eventId=e3&content=' +
                    '%7B%22related_event%22%3A%22r3%22%2C%22petId%22%3A' + str(pet["id"]) + '%7D')
            r = await client.post("/6/t5/dev_event_report", headers=HDR, data=body)
            assert r.status == 200
            assert fake_pub.pet_discoveries == [pet["id"]]
            assert fake_pub.pet_states == [pet["id"]]
        finally:
            await client.close()


async def test_event_report_without_body_is_safe():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            r = await client.post("/6/t5/dev_event_report", headers=HDR, data=b"")
            assert r.status == 200
            assert (await r.json())["result"] == "success"
        finally:
            await client.close()


async def test_upload_file_info_creates_media_row_and_schedules_processing():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            rel = "t5/100/eventImage/f1"
            full = Path(raw_root) / rel
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(b"\xff\xd8\xff\xe0" + b"A" * 60)

            import json
            import urllib.parse
            infos = [{"fileId": "f1", "fileUrl": f"https://localhost:9000/{rel}",
                     "cycleType": "eventImage", "eventId": "r1"}]
            body = "fileInfos=" + urllib.parse.quote(json.dumps(infos))

            r = await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR, data=body)
            assert r.status == 200
            assert (await r.json())["result"] == "success"

            media = await store.get_media_by_file_id("f1")
            assert media is not None
            assert media["category"] == "eventImage"

            # let the fire-and-forget pipeline task run
            await asyncio.sleep(0.2)
            media = await store.get_media_by_file_id("f1")
            assert media["status"] == "ready"
            assert Path(media["media_path"]).is_file()
        finally:
            await client.close()


async def test_upload_file_info_keeps_a_strong_reference_to_its_task():
    # asyncio only holds a WEAK reference to a running task: without the
    # module-level set, the pipeline task can be collected mid-flight.
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            _stage_raw(raw_root, "t5/100/eventImage/f10")
            await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR,
                              data=_upload_body("f10", "t5/100/eventImage/f10"))
            assert upload_file_info.pending_count() == 1

            # This is what main.py's cleanup must await before closing the store.
            await upload_file_info.wait_for_pending()
            assert upload_file_info.pending_count() == 0
            assert (await store.get_media_by_file_id("f10"))["status"] == "ready"
        finally:
            await client.close()


async def test_app_cleanup_drains_media_tasks():
    # create_app registers the drain FIRST, so it runs before main.py's own
    # cleanup closes the event store the tasks write to.
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        _stage_raw(raw_root, "t5/100/eventImage/f15")
        await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR,
                          data=_upload_body("f15", "t5/100/eventImage/f15"))
        assert upload_file_info.pending_count() == 1

        await client.close()
        assert upload_file_info.pending_count() == 0
        assert (await store.get_media_by_file_id("f15"))["status"] == "ready"


async def test_wait_for_pending_cancels_a_straggler():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        from petkit_local.media import pipeline

        started = asyncio.Event()

        async def _never_finishes(*a, **kw):
            started.set()
            await asyncio.sleep(3600)

        real = pipeline.process_file_info
        pipeline.process_file_info = _never_finishes
        try:
            _stage_raw(raw_root, "t5/100/eventImage/f11")
            await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR,
                              data=_upload_body("f11", "t5/100/eventImage/f11"))
            await started.wait()
            assert upload_file_info.pending_count() == 1

            await upload_file_info.wait_for_pending(timeout=0.01)
            assert upload_file_info.pending_count() == 0
        finally:
            pipeline.process_file_info = real
            await client.close()


async def test_upload_file_info_task_failure_is_logged():
    # Nothing awaits the task, so an escaping exception would otherwise only
    # surface as asyncio's "exception was never retrieved", if at all.
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        from petkit_local.media import pipeline

        async def _boom(*a, **kw):
            raise RuntimeError("pipeline exploded")

        records = []

        class _Collector(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = _Collector()
        log = logging.getLogger(upload_file_info.__name__)
        log.addHandler(handler)
        real = pipeline.process_file_info
        pipeline.process_file_info = _boom
        try:
            _stage_raw(raw_root, "t5/100/eventImage/f12")
            r = await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR,
                                  data=_upload_body("f12", "t5/100/eventImage/f12"))
            assert r.status == 200
            await upload_file_info.wait_for_pending()

            assert any(rec.levelno >= logging.ERROR and rec.exc_info for rec in records)
        finally:
            pipeline.process_file_info = real
            log.removeHandler(handler)
            await client.close()


async def test_ingest_endpoints_survive_a_malformed_device_id():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            r = await client.post("/6/t5/dev_event_report", headers=HDR_BAD_ID,
                                  data="eventType=10&eventId=e9")
            assert r.status == 200
            assert (await r.json())["result"] == "success"

            _stage_raw(raw_root, "t5/100/eventImage/f13")
            r = await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR_BAD_ID,
                                  data=_upload_body("f13", "t5/100/eventImage/f13"))
            assert r.status == 200
            assert (await r.json())["result"] == "success"

            # Unidentified requester -> nothing was attributed to a device.
            assert await store.query_timeline(device_id=100) == []
            assert await store.get_media_by_file_id("f13") is None
        finally:
            await client.close()


async def test_upload_file_info_resolves_the_device_by_serial():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(tmp)
        try:
            _stage_raw(raw_root, "t5/100/eventImage/f14")
            r = await client.post("/6/t5/dev_upload_file_info_v2",
                                  headers={"X-Device": "id=oops&sn=SN100"},
                                  data=_upload_body("f14", "t5/100/eventImage/f14"))
            assert r.status == 200
            await upload_file_info.wait_for_pending()
            assert (await store.get_media_by_file_id("f14"))["device_id"] == 100
        finally:
            await client.close()


async def test_upload_file_info_skips_disabled_capability():
    with tempfile.TemporaryDirectory() as tmp:
        client, reg, store, hub, device, raw_root, media_root = await _client(
            tmp, capabilities={"eventImage": False})
        try:
            rel = "t5/100/eventImage/f2"
            full = Path(raw_root) / rel
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(b"\xff\xd8\xff\xe0" + b"A" * 60)

            import json
            import urllib.parse
            infos = [{"fileId": "f2", "fileUrl": f"https://localhost:9000/{rel}",
                     "cycleType": "eventImage"}]
            body = "fileInfos=" + urllib.parse.quote(json.dumps(infos))
            await client.post("/6/t5/dev_upload_file_info_v2", headers=HDR, data=body)
            await asyncio.sleep(0.2)

            media = await store.get_media_by_file_id("f2")
            assert media["status"] == "skipped"
        finally:
            await client.close()
