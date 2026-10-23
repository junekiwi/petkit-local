"""A device must never be given a 4xx or 5xx, whatever goes wrong behind it.

The firmware reads an error status as a server fault and retries forever, so a
transient problem on our side — a full disk, an HA broker restart, a corrupt
payload — turns into a permanent request storm from every device at once. That
rule used to be enforced by each handler catching its own failures, and several
could still escape.

The failures here are induced through real dependencies rather than a fake
route, because a fake route cannot reproduce the thing being tested: the
catch-all is registered last and would shadow it, and the router is frozen once
the server starts.
"""
import tempfile
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from petkit_local.devices.registry import DeviceRegistry
from petkit_local.http.middleware import never_fail_middleware
from petkit_local.http.server import create_app

CONFIG = {"api_url": "http://server/6/", "mqtt_port": 1883, "proxy_mode": False,
          "proxy_upstream": "", "proxy_block_run_cmd": True, "capture": False}
HDR = {"X-Device": "id=100&sn=SN100"}


class _BrokenStore:
    """An event store on a full or read-only disk."""

    def __init__(self, exc):
        self._exc = exc

    async def upsert_event(self, row):
        raise self._exc

    async def record_event(self, row):
        raise self._exc

    async def upsert_media(self, row):
        raise self._exc


async def _client(store_exc=None):
    reg = DeviceRegistry()
    reg.get_or_create(petkit_id=100, device_type="t5", serial_number="SN100")
    app = create_app(reg, dict(CONFIG))
    if store_exc is not None:
        app["event_store"] = _BrokenStore(store_exc)
    c = TestClient(TestServer(app))
    await c.start_server()
    return c


@pytest.mark.parametrize("exc", [
    RuntimeError("sqlalchemy: attempt to write a readonly database"),
    OSError(28, "No space left on device"),
    RecursionError("maximum recursion depth exceeded"),
    ValueError("malformed payload"),
    KeyError("missing"),
])
async def test_a_failing_event_store_still_answers_the_device_a_success(exc):
    """`upsert_event` on a full or read-only disk used to become aiohttp's
    default 500, i.e. exactly the retry loop the never-404 rule exists to
    prevent."""
    c = await _client(store_exc=exc)
    try:
        r = await c.post("/6/t5/dev_event_report", headers=HDR,
                         data={"event_type": "10", "event_id": "e1", "content": "{}"})
        assert r.status == 200, f"{type(exc).__name__} reached the device as {r.status}"
    finally:
        await c.close()


async def test_the_failure_is_logged_loudly_rather_than_hidden(caplog):
    """Answering success is for the device's benefit; the operator still has to
    be able to find out that something broke."""
    c = await _client(store_exc=RuntimeError("kaboom"))
    try:
        with caplog.at_level("ERROR"):
            await c.post("/6/t5/dev_event_report", headers=HDR,
                         data={"event_type": "10", "event_id": "e1", "content": "{}"})
        assert any("kaboom" in str(r.exc_info) or "kaboom" in r.getMessage()
                   for r in caplog.records)
    finally:
        await c.close()


async def test_a_deliberate_http_status_is_not_swallowed():
    """The backstop must not turn an intentional response into a fake success.
    Exercised on a bare app, since every device route answers 200 by design."""
    app = web.Application(middlewares=[never_fail_middleware])

    async def redirect(request):
        raise web.HTTPFound(location="/elsewhere")

    async def boom(request):
        raise RuntimeError("unhandled")

    app.router.add_get("/redir", redirect)
    app.router.add_get("/boom", boom)
    c = TestClient(TestServer(app))
    await c.start_server()
    try:
        assert (await c.get("/redir", allow_redirects=False)).status == 302
        r = await c.get("/boom")
        assert r.status == 200 and await r.json() == {"result": {}}
    finally:
        await c.close()


# --- the bucket half: a full disk must not become a retry storm -------------

async def test_a_write_failure_refuses_the_key_instead_of_erroring(monkeypatch):
    """`_store_upload` used to catch only IsADirectoryError/NotADirectoryError,
    so ENOSPC escaped as a 500 — and per `_denied`, a 5xx makes the cloud
    process retry the same key forever. A full /media took every device with it."""
    from petkit_local.http import bucket

    def full_disk(dest, body):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(bucket, "_store_upload_sync", full_disk)
    with tempfile.TemporaryDirectory() as tmp:
        app = bucket.create_bucket_app(str(Path(tmp) / "media"))
        c = TestClient(TestServer(app))
        await c.start_server()
        try:
            r = await c.put("/t5/1/fullVideo/clip.ts", data=b"x" * 100)
            assert r.status < 500, "a write failure must never be a 5xx to the device"
        finally:
            await c.close()


async def test_a_key_whose_parent_is_a_file_is_refused_not_a_500(monkeypatch):
    """`Path.mkdir(exist_ok=True)` raises FileExistsError when a parent path
    component is an existing regular file — neither of the two types the old
    handler caught. The device can produce such a key on its own."""
    from petkit_local.http import bucket

    with tempfile.TemporaryDirectory() as tmp:
        app = bucket.create_bucket_app(str(Path(tmp) / "media"))
        c = TestClient(TestServer(app))
        await c.start_server()
        try:
            assert (await c.put("/t5/1/fullVideo/x", data=b"file")).status < 400
            # Now store *under* that file.
            assert (await c.put("/t5/1/fullVideo/x/y", data=b"nested")).status < 500
        finally:
            await c.close()
