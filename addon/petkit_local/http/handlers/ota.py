"""dev_ota_check / dev_ota_start / dev_ota_complete, and the firmware they name.

For every device this server has ever answered, `dev_ota_check` meant "no
update", and it still does — unless an ESP32 firmware job was armed for that
device from the panel (`patchers/esp32_ota.py`). Then it answers with the
release the job targets, its URLs pointing at `handle_firmware_download` here,
and the device's `dev_ota_start` / `dev_ota_complete` reports drive the job on.
They used to be routed to `dev_event_report`, which stored them as events of no
known kind.

`dev_ota_heartbeat` is never answered with firmware. What a device does with it
is unobserved, and the `ota` heartbeat topic plus the boot-time check already
reach every device a job could be for.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import parse_qsl, urlparse

from aiohttp import web

from petkit_local.http.handlers._common import request_device
from petkit_local.patchers import esp32_ota
from petkit_local.utils.capture import capture_record
from petkit_local.utils.coerce import to_int
from petkit_local.utils.paths import UnsafePathError

log = logging.getLogger(__name__)

#: "No update" — an OBJECT. This was an array, documented as "the real cloud's
#: shape"; proxying the endpoint to PetKit on 2026-07-27 showed the cloud
#: answers `{"result":{}}` every time.
NO_UPDATE: dict[str, Any] = {"result": {}}


def _endpoint(request: web.Request) -> str:
    return request.path.rstrip("/").rsplit("/", 1)[-1]


def firmware_base_url(api_url: str) -> str:
    """Where a device fetches firmware from: this server, over plain HTTP.

    The host and port the device already reaches the API on, so a device that
    can ask for an update can also download it. "" when `api_url` names no
    host, and then nothing is offered at all.
    """
    parsed = urlparse(api_url)
    if not parsed.hostname:
        return ""
    return f"http://{parsed.hostname}:{parsed.port or 80}"


def _narrate(request: web.Request, device_id: int, line: str) -> None:
    """Put a job's progress where the panel's firmware card shows it."""
    hub = request.app.get("event_hub")
    if hub is not None:
        hub.publish("patcher", device_id, f"[esp32fw] {line}")


async def _form(request: web.Request) -> dict[str, str]:
    """Query string and form body, merged; the body wins. Never raises."""
    fields = dict(request.query)
    try:
        raw = await request.read()
        fields.update(parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True))
    except Exception:  # noqa: BLE001 - device input never raises
        pass
    return fields


async def handle_ota_check(request: web.Request) -> web.Response:
    """`dev_ota_check` / `dev_ota_heartbeat` — "no update", unless a job is armed.

    Returns:
        `NO_UPDATE`, or for an armed job `{"result": esp32_ota.offer(...)}`.
        A job whose release has gone missing, or with no `api_url` host to put
        in the URLs, is answered "no update" and said so in the panel — an
        offer the device cannot download is worse than none.
    """
    device = request_device(request)
    if device is None or _endpoint(request) != "dev_ota_check":
        return web.json_response(NO_UPDATE)
    job = esp32_ota.active_job(device)
    if job is None:
        return web.json_response(NO_UPDATE)

    config = request.app["config"]
    form = await _form(request)
    log.info("dev_ota_check from %d with a job armed: %s", device.petkit_id, form)
    release = esp32_ota.load_release(config.get("data_dir", "/data"),
                                     device.device_type, job["version"])
    base = firmware_base_url(config.get("api_url", ""))
    if release is None or not base:
        why = "its stored firmware is missing" if release is None else "api_url names no host"
        log.warning("Not offering firmware to %d: %s", device.petkit_id, why)
        _narrate(request, device.petkit_id, f"device asked for firmware, but {why}")
        return web.json_response(NO_UPDATE)

    _narrate(request, device.petkit_id,
             f"device asked for firmware — offered {job['target']} {job['version']}")
    return web.json_response({"result": esp32_ota.offer(release, job["target"], base)})


def offers_firmware(response: web.StreamResponse) -> bool:
    """Whether this `dev_ota_check` reply is handing the device firmware.

    `proxy_middleware` asks before it forwards: redaction answers every OTA
    endpoint with "no update" whatever the cloud said, so forwarding an offer
    of ours would withdraw it. False for anything unreadable.
    """
    try:
        data = json.loads(bytes(getattr(response, "body", b"") or b""))
    except (ValueError, TypeError):
        return False
    result = data.get("result") if isinstance(data, dict) else None
    return isinstance(result, dict) and bool(result.get("details"))


async def handle_ota_progress(request: web.Request) -> web.Response:
    """`dev_ota_start` / `dev_ota_complete` — the device reporting on a flash.

    `dev_ota_complete` carries `success=1`, or `errmsg=otafail-<code>` on
    failure (localkit, which surfaces the code as the device error). Recorded
    against the armed job; a report with no job of ours is logged and nothing
    else, because the device was updated on some other authority.

    Returns:
        ``{"result": "success"}``, always.
    """
    ok = web.json_response({"result": "success"})
    device = request_device(request)
    if device is None:
        return ok
    form = await _form(request)
    endpoint = _endpoint(request)
    config = request.app["config"]
    if config.get("capture"):
        capture_record(config.get("capture_dir", "/data/capture"), endpoint,
                       {"id": device.petkit_id, "form": form})
    log.info("%s from %d: %s", endpoint, device.petkit_id, form)

    if endpoint == "dev_ota_start":
        line = esp32_ota.note_started(device)
    else:
        line = esp32_ota.note_completed(device, to_int(form.get("success"), 0) == 1,
                                        form.get("errmsg", ""))
    if line is None:
        log.info("%s from %d with no firmware job armed", endpoint, device.petkit_id)
        return ok
    request.app["registry"].mark_dirty()
    _narrate(request, device.petkit_id, line)
    return ok


async def handle_firmware_download(request: web.Request) -> web.StreamResponse:
    """`/firmware/{device_type}/{version}/{variant}/{module}.bin` — a stored module.

    Served to whoever asks, like the rest of the device API: the stock images
    are PetKit's own downloads, and the patched one differs from stock only by
    a public certificate.
    """
    mi = request.match_info
    filename = mi["filename"]
    if mi["variant"] not in esp32_ota.VARIANTS or not filename.endswith(".bin"):
        return web.Response(status=404, text="not found")
    try:
        path = esp32_ota.module_path(request.app["config"].get("data_dir", "/data"),
                                     mi["device_type"], mi["version"], mi["variant"],
                                     filename[:-len(".bin")])
    except UnsafePathError:
        return web.Response(status=400, text="bad path")
    if not os.path.isfile(path):
        return web.Response(status=404, text="not found")
    log.info("Serving firmware %s to %s", request.path, request.remote)
    return web.FileResponse(path)
