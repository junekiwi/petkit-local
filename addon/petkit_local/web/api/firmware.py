"""The ESP32 firmware card: fetch a release, flash it, roll it back.

`patchers/esp32_ota.py` holds the store and the job; this is the panel's way in.
Every action is a button: `fetch` is the one call to PetKit (signed as the
device, like every other `http/cloud_fetch.py` request), and `flash` /
`rollback` only arm a job — the device does the rest the next time it asks
`dev_ota_check`, and reports back through `http/handlers/ota.py`. Progress is
narrated on the hub as `patcher` events prefixed `[esp32fw]`, which the
Patchers tab follows the way it follows a Linux patcher's run.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp
from aiohttp import web

from petkit_local.http.cloud_fetch import (
    FIRMWARE_TIMEOUT, CloudRefused, download_firmware_module, fetch_firmware_listing,
)
from petkit_local.http.dns import UpstreamResolver
from petkit_local.http.proxy import resolve_upstream
from petkit_local.patchers import esp32_ota
from petkit_local.patchers.firmware import FirmwareImageError
from petkit_local.web.api._common import _device_or_404, _json_body

log = logging.getLogger(__name__)

#: One fetch per device at a time: two would download the same release twice
#: and race over its files.
_FETCH_LOCKS: dict[int, asyncio.Lock] = {}

_ACTIONS = ("fetch", "flash", "rollback", "cancel")


def _data_dir(request: web.Request) -> str:
    return request.app["cfg"].get("data_dir", "/data")


async def api_firmware_status(request: web.Request) -> web.Response:
    """What the firmware card shows for one device.

    `supported` is False for every model the CA swap is not offered for, with
    nothing else; the card is not drawn for those.
    """
    d = _device_or_404(request)
    if d.device_type.lower() not in esp32_ota.PATCHABLE_TYPES:
        return web.json_response({"supported": False})
    data_dir = _data_dir(request)
    state = esp32_ota.firmware_state(d)
    release = (esp32_ota.load_release(data_dir, d.device_type, state["release"])
               if state.get("release") else None)
    return web.json_response({
        "supported": True,
        "firmware": d.firmware,
        "release": release.summary() if release else None,
        "running": state.get("running", ""),
        "job": esp32_ota.active_job(d),
        "last_result": state.get("last_result"),
        "mqtt_connected": d.mqtt_connected,
        "ca_sha256": esp32_ota.ca_fingerprint(data_dir),
    })


async def api_firmware_action(request: web.Request) -> web.Response:
    """`{"action": "fetch" | "flash" | "rollback" | "cancel"}` for one device.

    `fetch` answers at once and runs in the background, narrated on the hub;
    the others take effect before they answer.
    """
    d = _device_or_404(request)
    if d.device_type.lower() not in esp32_ota.PATCHABLE_TYPES:
        return web.json_response(
            {"error": f"firmware patching is not offered for a {d.device_type.upper()}"},
            status=400)
    body = await _json_body(request)
    action = body.get("action")
    if action not in _ACTIONS:
        return web.json_response({"error": f"unknown action {action!r}"}, status=400)

    reg = request.app["registry"]
    hub = request.app["hub"]
    did = d.petkit_id

    def say(line: str) -> None:
        hub.publish("patcher", did, f"[esp32fw] {line}")

    if action == "fetch":
        from petkit_local.web.panel import _spawn_background  # noqa: PLC0415 - see patchers.py

        _spawn_background(request.app, _fetch(request.app, d, say),
                          name=f"esp32fw-fetch-{did}")
        say("fetch started")
        return web.json_response({"ok": True, "action": action})

    if action == "cancel":
        had = esp32_ota.disarm(d)
        reg.save()
        say("job cancelled" if had else "no job was armed")
        return web.json_response({"ok": True, "action": action})

    state = esp32_ota.firmware_state(d)
    release = (esp32_ota.load_release(_data_dir(request), d.device_type, state["release"])
               if state.get("release") else None)
    if release is None:
        return web.json_response(
            {"error": "no firmware stored for this device — fetch it first"}, status=400)
    target = esp32_ota.PATCHED if action == "flash" else esp32_ota.STOCK
    esp32_ota.arm(d, release, target)
    reg.save()
    where = ("it takes MQTT now, so power-cycle it to start" if d.mqtt_connected
             else "it is told on its next heartbeat; power-cycling it also starts it")
    say(f"armed: {target} {release.version} — {where}")
    return web.json_response({"ok": True, "action": action, "target": target})


async def _fetch(app: web.Application, device: Any, say) -> None:
    """Download this model's firmware from PetKit, patch it and store both.

    The CA is minted, and the image patched, off the event loop: RSA keygen
    and a 1.4 MB rewrite are not things a WebSocket should wait behind.
    """
    lock = _FETCH_LOCKS.setdefault(device.petkit_id, asyncio.Lock())
    if lock.locked():
        say("a fetch is already running for this device")
        return
    async with lock:
        try:
            release = await _download_and_store(app, device, say)
        except asyncio.CancelledError:
            say("fetch cancelled (shutting down)")
            raise
        except (CloudRefused, FirmwareImageError) as e:
            say(f"fetch FAILED: {e}")
            return
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            say(f"fetch FAILED: PetKit could not be reached ({e or type(e).__name__})")
            return
        except Exception as e:
            log.exception("ESP32 firmware fetch failed for %d", device.petkit_id)
            say(f"fetch FAILED: {e}")
            return
        esp32_ota.set_release(device, release)
        app["registry"].save()
        patched = next(m for m in release.summary()["modules"]
                       if m["module"] == esp32_ota.CA_MODULE)
        say(f"done: {release.version} stored, stock and patched "
            f"(patched {esp32_ota.CA_MODULE} md5 {patched['patched_md5']})")


async def _download_and_store(app: web.Application, device: Any, say) -> esp32_ota.Release:
    """The network half of `_fetch`, then the CPU half on a worker thread.

    Upstream and resolver are proxy mode's (`live_config`), as for every cloud
    fetch: a LAN that points PetKit's names here needs the same DNS override.
    """
    live = app.get("live_config") or {}
    dns = live.get("proxy_dns", "")
    connector = aiohttp.TCPConnector(resolver=UpstreamResolver(dns)) if dns else None
    async with aiohttp.ClientSession(timeout=FIRMWARE_TIMEOUT, connector=connector) as session:
        say("asking PetKit for this model's current firmware...")
        listing = await fetch_firmware_listing(
            session, resolve_upstream(live.get("proxy_upstream", "")), device)
        manifest = esp32_ota.validate_manifest(listing)
        say(f"PetKit lists {manifest['version']} (the device runs "
            f"{device.firmware or 'an unknown version'}): "
            + ", ".join(d["module"] for d in manifest["details"]))
        modules: dict[str, bytes] = {}
        for d in manifest["details"]:
            file = d["file"]
            say(f"downloading {d['module']} ({file['size']} bytes)...")
            modules[d["module"]] = await download_firmware_module(
                session, file["url"], size=file["size"], digest=file["digest"])
    say("verifying and patching...")
    return await asyncio.to_thread(
        esp32_ota.save_release, app["cfg"].get("data_dir", "/data"),
        device.device_type, manifest, modules)

