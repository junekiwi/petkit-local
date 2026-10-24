"""Asking PetKit a question as one of our devices would ask it.

Everywhere else in this package the traffic runs the other way: a device asks
us, and `http/proxy.py` may relay that exact request onward. Nothing here
relays anything — this builds a request of our own, signs it the way the
firmware signs its own, and sends it because somebody pressed a button.

The signature is not reverse-engineered guesswork. T4 firmware 1.652 carries
the two format strings side by side, in the function that builds the header::

    id%snonce%stimestamp%utype%s%s
    id=%s&nonce=%s&timestamp=%u&type=%s&sign=%s

The first is the string that goes into MD5 — the four fields concatenated with
their own names and no separators, with the signing secret appended — and the
second is the header. `signature` below is those two lines and nothing else.

Two fields must come from the device rather than from us, and both are why
`Device` records them instead of deriving them:

* `secret` is `Device.signing_secret`. Ours is accepted only by us; PetKit
  answers `{"error": {"code": 704}}` to a signature made with a secret it does
  not know. A real one is learned from a proxied `dev_signup`, or by asking for
  one here (`signup`).
* `type` is `Device.wire_type`, the spelling the firmware itself uses. It is
  hashed, so `T5` and `t5` are different requests and only one authenticates.

What this is NOT allowed to become: a poller. Every call here is a button in
the panel. The add-on talking to PetKit on its own schedule is the thing proxy
mode already avoids by only ever relaying what a device sent anyway.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

#: Shorter than a device would wait. This runs behind a panel button with
#: somebody watching it, and a request that has not answered in this long is
#: better reported than waited on.
CLOUD_TIMEOUT = aiohttp.ClientTimeout(total=15)

#: How the firmware names itself. Ours has no business claiming to be a
#: browser, and PetKit's own logs are easier to read for whoever gets asked
#: about this later.
USER_AGENT = "PetKit-Local"


def signature(device_id: int, nonce: str, timestamp: int, wire_type: str,
              secret: str) -> str:
    """The `sign` field of an `X-Device` header.

    `md5("id" + id + "nonce" + nonce + "timestamp" + ts + "type" + type + secret)`,
    which is T4 firmware 1.652's `id%snonce%stimestamp%utype%s%s` filled in.
    """
    raw = f"id{device_id}nonce{nonce}timestamp{timestamp}type{wire_type}{secret}"
    return hashlib.md5(raw.encode()).hexdigest()


def x_device_header(device, *, nonce: str | None = None,
                    timestamp: int | None = None) -> str:
    """Build a signed `X-Device` header for one of our devices.

    `nonce` and `timestamp` are ours to choose — the firmware picks a fresh
    pair per request and PetKit is verifying the signature over them, not
    recognising them. They are arguments only so a test can pin them.
    """
    nonce = nonce or secrets.token_hex(8)
    timestamp = int(time.time()) if timestamp is None else timestamp
    wire_type = device.wire_type or device.device_type
    sign = signature(device.petkit_id, nonce, timestamp, wire_type,
                     device.signing_secret)
    return (f"id={device.petkit_id}&nonce={nonce}&timestamp={timestamp}"
            f"&type={wire_type}&sign={sign}")


class CloudRefused(Exception):
    """PetKit answered, and the answer was a refusal.

    Separate from a transport failure because the two need different words in
    front of a user: one means "try again", the other means "this account or
    this credential will never answer, whatever you do".

    `status` is the HTTP status when there was one, so a caller can tell the
    refusals apart without reading the message. 404 is the one worth telling
    apart: it means this model does not have that endpoint at all, which is not
    a failure and should not be reported as one.
    """

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


async def fetch_as_device(session: aiohttp.ClientSession, upstream: str, device,
                          endpoint: str) -> dict[str, Any]:
    """GET one PetKit endpoint as `device`, and return the decoded body.

    Args:
        upstream: A base URL from `proxy.resolve_upstream` — scheme and host.
        endpoint: The last path segment, e.g. `dev_ble_device`. The path is
            built the way the firmware builds it: `/6/{type}/{endpoint}`.

    Raises:
        CloudRefused: on a non-200, on a body that is not a JSON object, or on
            a PetKit `error` object. `704` is called out by name because it is
            the one a user can act on: it means the signing secret is ours
            rather than the device's.
        aiohttp.ClientError / asyncio.TimeoutError: the upstream was not
            reached. Left to propagate — the caller knows whether it is fetching
            one endpoint or eight, and only it can say what that means.
    """
    url = f"{upstream}/6/{device.device_type}/{endpoint}"
    headers = {"X-Device": x_device_header(device), "User-Agent": USER_AGENT}

    async with session.get(url, headers=headers, ssl=True) as resp:
        raw = await resp.read()
        status = resp.status
    payload = _decode_reply(endpoint, status, raw)
    log.info("Asked PetKit for %s as device %d", endpoint, device.petkit_id)
    return payload


def _decode_reply(endpoint: str, status: int, raw: bytes) -> dict[str, Any]:
    """PetKit's reply as a JSON object, or the refusal it amounts to.

    Raises:
        CloudRefused: on a non-200, on a body that is not a JSON object, or on
            a PetKit `error` object (704 by name — see `fetch_as_device`).
    """
    if status != 200:
        raise CloudRefused(f"{endpoint}: PetKit answered HTTP {status}", status=status)
    try:
        payload = json.loads(raw)
    except ValueError:
        raise CloudRefused(f"{endpoint}: PetKit sent something that is not JSON") from None
    if not isinstance(payload, dict):
        raise CloudRefused(f"{endpoint}: PetKit sent no result object")

    error = payload.get("error")
    if isinstance(error, dict) and error:
        code = error.get("code")
        if code == 704:
            raise CloudRefused(
                f"{endpoint}: PetKit rejected the signature (704). This device's "
                "credential is one we issued, not one PetKit knows — sign it up "
                "with PetKit first.")
        raise CloudRefused(f"{endpoint}: PetKit refused with {code} "
                           f"{error.get('msg', '')}".strip())
    return payload


#: What makes PetKit list a model's whole current firmware rather than only
#: what is newer than the device's: every version claimed as 1, and `force`.
#: This is petkit-firmware-tool's request, which is how the stock D4 1.267
#: image this project's patcher is proven against was obtained. `app` is that
#: tool's module name for every ESP32 model, and the answer lists the real
#: ones (`userbin`, and on a T4 `pics` and `lans`) regardless.
_FIRMWARE_LISTING = {
    "hardware": "1",
    "firmware": "1",
    "firmwareDetails": json.dumps([{"module": "app", "version": 1}]),
    "force": "1",
}

#: Firmware is megabytes, not a JSON reply, and comes from a CDN.
FIRMWARE_TIMEOUT = aiohttp.ClientTimeout(total=180)


async def fetch_firmware_listing(session: aiohttp.ClientSession, upstream: str,
                                 device) -> dict[str, Any]:
    """Ask PetKit, as `device`, for its model's current firmware.

    Returns:
        The `result` object: `firmwareId`, `version` and `details[]`, each
        detail naming a module and the `file` (url, size, MD5 digest) to fetch
        it from. Not validated here — `patchers/esp32_ota.validate_manifest`
        owns what a usable one looks like.

    Raises:
        CloudRefused: as `fetch_as_device`, or when PetKit lists no modules.
    """
    url = f"{upstream}/6/{device.device_type}/dev_ota_check"
    params = {"id": str(device.petkit_id), "mac": device.mac, "sn": device.serial_number,
              "hardware": "1", "firmware": "1"}
    headers = {"X-Device": x_device_header(device), "User-Agent": USER_AGENT}
    async with session.post(url, params=params, data=_FIRMWARE_LISTING,
                            headers=headers, ssl=True) as resp:
        raw = await resp.read()
        status = resp.status
    result = _decode_reply("dev_ota_check", status, raw).get("result")
    if not isinstance(result, dict) or not result.get("details"):
        raise CloudRefused(
            "dev_ota_check: PetKit listed no firmware for this device. If PetKit's "
            "names point at this add-on, set an upstream DNS server in Setup.")
    log.info("Asked PetKit for the firmware of device %d: %s", device.petkit_id,
             result.get("version"))
    return result


async def download_firmware_module(session: aiohttp.ClientSession, url: str, *,
                                   size: int, digest: str) -> bytes:
    """Download one firmware module and prove it is the one PetKit described.

    Read in chunks and abandoned the moment it exceeds `size`, so a server that
    sends more than it promised cannot make us hold more than one module's
    worth.

    Raises:
        CloudRefused: a non-200, or a body whose size or MD5 is not the one
            the listing gave.
        aiohttp.ClientError / asyncio.TimeoutError: the download failed.
    """
    received = bytearray()
    async with session.get(url, ssl=True) as resp:
        if resp.status != 200:
            raise CloudRefused(f"{url}: HTTP {resp.status}", status=resp.status)
        async for chunk in resp.content.iter_chunked(65536):
            received += chunk
            if len(received) > size:
                raise CloudRefused(f"{url}: more than the {size} bytes PetKit listed")
    body = bytes(received)
    got = hashlib.md5(body).hexdigest()
    if len(body) != size or got != digest.lower():
        raise CloudRefused(
            f"{url}: {len(body)} bytes with MD5 {got}, but PetKit listed "
            f"{size} bytes with MD5 {digest}")
    return body
