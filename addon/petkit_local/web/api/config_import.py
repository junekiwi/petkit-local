"""Importing a device's configuration from PetKit's own replies.

A device moved here keeps what it had only if this add-on already holds it when
the device first asks. A T4 reads its whole settings block from
`dev_device_info` at boot and adopts whatever it is given, so a block of our
defaults silently changes the owner's settings; a feeder that fetches an empty
`dev_feed_get` stops feeding. Importing before the device is redirected closes
that window, without proxy mode and without asking PetKit anything.

The document is PetKit's own replies, per device, keyed by the endpoint that
produced them -- exactly what a capture of the device talking to PetKit holds:

    {"devices": [{"type": "t4",
                  "dev_signup": {"result": {...}},
                  "dev_device_info": {"result": {...}},
                  "dev_schedule_get": {"result": [...]},
                  "dev_multi_config": {"result": {...}},
                  "dev_k3_device_info": {"result": {...}}},
                 {"type": "d4", "dev_signup": ..., "dev_feed_get": ...}]}

A reply may be given with or without its `{"result": ...}` wrapper, and any of
them may be left out. Each lands where the endpoint is answered from, so what a
device is served afterwards is what PetKit served it.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from aiohttp import web

from petkit_local.devices.ble import cloud_bindings
from petkit_local.devices.registry import DeviceRegistry
from petkit_local.utils.coerce import to_float, to_int
from petkit_local.utils.const import (
    DEVICE_TYPES_ALL, DEVICE_TYPES_BLE_ONLY, DEVICE_TYPES_FEEDER_DUAL,
)
from petkit_local.web.api._common import _json_body
from petkit_local.web.api.ble import _announce_pairing, _ble_view
from petkit_local.web.api.schedules import _clean_feed_schedule

log = logging.getLogger(__name__)

#: The endpoints an import reads, and nothing else.
IMPORT_ENDPOINTS = (
    "dev_signup", "dev_device_info", "dev_feed_get", "dev_schedule_get",
    "dev_multi_config", "dev_k3_device_info", "dev_ble_device",
)

#: Same bounds `http/handlers/signup.py` puts on a device's own report.
_TZ_MIN, _TZ_MAX = -12.0, 14.0


class ImportRefused(ValueError):
    """A device entry that cannot be imported at all."""


def _result(reply: Any) -> Any:
    """A reply's `result`, whether or not it came with its wrapper."""
    if isinstance(reply, dict) and "result" in reply:
        return reply["result"]
    return reply


def _decode_ranges(result: Any) -> dict[str, list] | None:
    """`dev_multi_config` as the lists `config["multi_config"]` stores.

    PetKit sends each range as a JSON string that wraps its own key again,
    `"{\\"lightMultiRange\\":[[0,1440]]}"` (`devices/base.py::encode_multi_range`
    builds the same); a plain list is accepted too.
    """
    if not isinstance(result, dict):
        return None
    ranges: dict[str, list] = {}
    for key, value in result.items():
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                continue
            if isinstance(value, dict):
                value = value.get(key)
        if isinstance(value, list):
            ranges[key] = value
    return ranges or None


def import_device(registry: DeviceRegistry, ble: Any, entry: Any) -> tuple[Any, dict[str, Any]]:
    """Store one device's PetKit replies, registering it if it is new.

    Returns:
        `(device, summary)`. The summary names every part that was stored and
        every one that was not, with the reason -- an import that quietly drops
        a schedule is worse than one that says so.

    Raises:
        ImportRefused: no usable type or id, or the id belongs to a device of
            another type.
    """
    if not isinstance(entry, dict):
        raise ImportRefused("a device entry must be an object")
    device_type = str(entry.get("type", "")).strip().lower()
    if device_type not in DEVICE_TYPES_ALL or device_type in DEVICE_TYPES_BLE_ONLY:
        raise ImportRefused(f"unknown or Bluetooth-only type {device_type!r}")

    replies = {name: _result(entry[name]) for name in IMPORT_ENDPOINTS if name in entry}
    signup = replies.get("dev_signup") if isinstance(replies.get("dev_signup"), dict) else {}
    info = replies.get("dev_device_info") if isinstance(replies.get("dev_device_info"), dict) else {}
    petkit_id = to_int(info.get("id") or signup.get("id"), 0) or 0
    if petkit_id <= 0:
        raise ImportRefused("no device id in dev_signup or dev_device_info")

    existing = registry.get(petkit_id)
    if existing is not None and existing.device_type != device_type:
        raise ImportRefused(
            f"id {petkit_id} is already registered as a {existing.device_type}")
    device = registry.get_or_create(
        petkit_id=petkit_id, device_type=device_type,
        serial_number=str(info.get("sn") or signup.get("sn") or ""),
        mac=str(info.get("mac") or signup.get("mac") or ""),
    )
    summary: dict[str, Any] = {"id": petkit_id, "type": device_type,
                               "created": existing is None, "imported": [], "skipped": []}

    def skip(part: str, reason: str) -> None:
        summary["skipped"].append({"part": part, "reason": reason})

    # The signing secret PetKit issued, so the device is handed back the one it
    # already signs with, and `http/cloud_fetch.py` can ask PetKit as it.
    secret = signup.get("secret") or info.get("secret")
    if isinstance(secret, str) and secret:
        device.api_secret = secret
        summary["imported"].append("secret")
    bt_mac = info.get("btMac") or signup.get("btMac")
    if isinstance(bt_mac, str) and bt_mac:
        device.config["bt_mac"] = bt_mac
    locale = info.get("locale") or signup.get("locale")
    if isinstance(locale, str) and locale:
        device.config["locale"] = locale
    tz = to_float(info.get("timezone", signup.get("timezone")), None)
    if tz is not None and _TZ_MIN <= tz <= _TZ_MAX:
        device.config["reported_timezone"] = tz

    if "dev_device_info" in replies:
        settings = info.get("settings")
        if isinstance(settings, dict) and settings:
            # Over what is stored rather than instead of it: a key PetKit does
            # not send keeps its seeded default, as `to_device_info` would.
            device.config["settings"] = {**device.config.get("settings", {}), **settings}
            summary["imported"].append("settings")
        else:
            skip("dev_device_info", "no settings block")

    if "dev_feed_get" in replies:
        result = replies["dev_feed_get"]
        dual = device_type in DEVICE_TYPES_FEEDER_DUAL
        feed = (_clean_feed_schedule({"schedule": result.get("schedule")}, dual)
                if isinstance(result, dict) and device.is_feeder else None)
        if feed is None:
            skip("dev_feed_get", "not a feeding schedule for this model")
        else:
            device.config["feed_schedule"] = feed
            summary["imported"].append("feeding schedule")

    if "dev_schedule_get" in replies:
        result = replies["dev_schedule_get"]
        if isinstance(result, list) and all(isinstance(s, dict) for s in result):
            # Served verbatim by `http/handlers/schedule.py`, as PetKit's is.
            device.config["schedule"] = result
            summary["imported"].append("schedules")
        else:
            skip("dev_schedule_get", "not a list of schedules")

    if "dev_multi_config" in replies:
        ranges = _decode_ranges(replies["dev_multi_config"])
        if ranges is None:
            skip("dev_multi_config", "no ranges")
        else:
            device.config["multi_config"] = {**device.config.get("multi_config", {}), **ranges}
            summary["imported"].append("ranges")

    accessories = []
    for endpoint in ("dev_device_info", "dev_k3_device_info", "dev_ble_device"):
        if endpoint not in replies:
            continue
        for fields in cloud_bindings(endpoint, {"result": replies[endpoint]}, petkit_id):
            if registry.get(fields["petkit_id"]) is not None:
                skip(endpoint, f"accessory {fields['petkit_id']} is a real device here")
                continue
            if ble is None:
                skip(endpoint, "no BLE registry")
                continue
            dev, outcome = ble.apply_cloud_binding(fields)
            if dev is None:
                skip(endpoint, f"accessory {fields['petkit_id']}: {outcome}")
                continue
            if dev not in accessories:
                accessories.append(dev)
                summary["imported"].append(f"{dev.ble_type} {dev.petkit_id} ({outcome})")
    summary["_accessories"] = accessories

    registry.mark_dirty()
    return device, summary


async def api_import_config(request: web.Request) -> web.Response:
    """Import devices' configuration from PetKit's replies (module docstring).

    Body: `{"devices": [...]}`, or a single device entry. Answers
    `{"devices": [summary, ...]}` with one summary per entry, refusals included.
    """
    registry = request.app["registry"]
    ble = request.app["ble_registry"]
    body = await _json_body(request)
    entries = body.get("devices") if "devices" in body else [body]
    if not isinstance(entries, list) or not entries:
        return web.json_response({"error": "expected {\"devices\": [...]}"}, status=400)

    summaries, imported = [], []
    for entry in entries:
        try:
            device, summary = import_device(registry, ble, entry)
        except ImportRefused as e:
            summaries.append({"error": str(e), "type": (entry or {}).get("type")
                              if isinstance(entry, dict) else None})
            continue
        accessories = summary.pop("_accessories")
        summaries.append(summary)
        imported.append((device, summary["created"], accessories))
        log.info("Imported %s %d: %s", summary["type"], summary["id"],
                 ", ".join(summary["imported"]) or "nothing")

    registry.save()
    publisher = request.app.get("ha_publisher")
    for device, created, accessories in imported:
        if publisher is not None:
            if created:
                await publisher.publish_discovery(device)
            await publisher.publish_state(device)
        for dev in accessories:
            await _announce_pairing(request, dev)

    return web.json_response({
        "devices": summaries,
        "accessories": [_ble_view(d, registry) for d in ble.all()] if ble else [],
    })
