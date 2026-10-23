"""Local camera streaming patcher.

Replaces the Agora P2P client with tserver (local HTTP video streamer, port
80, zero auth) by bind-mounting one over the other, so the stock app_start.sh
line `./agora &` starts the local streamer instead. tserver reads frames from
the same POSIX shm `media` writes to, so it needs media running and nothing
else.

No binary patching and no file of ours on the device — the whole patch is one
line in the /system/app_init.sh wrapper.

**Never point Home Assistant's Generic Camera straight at the device.** HA's
`stream` component opens the URL with PyAV and `av.open()` segfaults inside
libav, killing the whole HA process. Put go2rtc in between; `STREAM_PATHS`
below records the evidence and the second reason for it.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from petkit_local.devices.base import Device

log = logging.getLogger(__name__)

#: What tserver serves, on port 80. Measured against a T5 on 2026-07-31:
#:
#: * `main.flv?audio=1` / `sub.flv?audio=1` — H.264 (1056² and 528²) plus AAC at
#:   16 kHz mono, verified over sustained reads both directly and through
#:   go2rtc. These are the ones to hand out.
#: * `main.ts` / `sub.ts` — dropped. They announce `sample_rate=0, channels=0`
#:   and list every stream twice, so nothing loads them. The FLV endpoints
#:   reported a valid `16000/1` every time they were sampled.
#: * The `audio` parameter is required, not optional — `sub.flv` with no query
#:   at all resets the connection.
#:
#: The PyAV segfault in the module docstring was observed twice, with and
#: without audio, so audio is not the trigger; it is not reproducible with
#: `av.open` in isolation, so it needs HA's threading context. go2rtc reads
#: this FLV and republishes clean RTSP.
#:
#: tserver also needs **seconds between connections**: opened back to back it
#: refuses the second, the same pair six seconds apart both succeed, and three
#: concurrent opens serve one and refuse two. So one long-lived reader in front
#: of it is not a nicety — it is what makes the camera usable for more than one
#: viewer.
#:
#: These are paths rather than one URL because tserver answers the same stream on
#: every path it is given: `/snapshot.jpg`, `/jpeg` and `/cgi-bin/snapshot.cgi`
#: all return `video/x-flv`. There is no still-image endpoint to point anything
#: at, which is why HA gets a URL for its own camera stack rather than an MQTT
#: camera entity fed with JPEGs.
STREAM_PATHS = {
    "flv": "main.flv?audio=1",
    "sub_flv": "sub.flv?audio=1",
}

#: Per model, what replaces `STREAM_PATHS`; the first entry is the one go2rtc
#: republishes. A D4H (YumShare Solo 2, fw 813) crashes tserver on `main.flv`
#: (upstream issue #38): tserver packs FLV tags into a static 200 KB buffer
#: with no bounds check, the D4H's main channel is 1728x1080 with ~204 KB
#: keyframes, and the SIGSEGV is final because nothing respawns tserver -- the
#: camera stays dead until a power cycle. Its `main.ts` does not use that
#: buffer and, unlike the T5's, carries real 16 kHz mono AAC: it ran for over a
#: day through go2rtc, reconnects included. Its 576x360 `sub.flv` is stable.
MODEL_STREAM_PATHS = {
    "d4h": {
        "ts": "main.ts?audio=1",
        "sub_flv": "sub.flv?audio=1",
    },
}

#: What `media/go2rtc.py::probe_stream` reads. It tests for the FLV signature,
#: so it has to be an FLV path, and `sub` is the one every model serves
#: without falling over.
PROBE_PATH = STREAM_PATHS["sub_flv"]


def stream_paths(device: Device) -> dict[str, str]:
    """`STREAM_PATHS`, or this model's replacement for them."""
    return MODEL_STREAM_PATHS.get(device.device_type.lower(), STREAM_PATHS)


def main_stream_path(device: Device) -> str:
    """The full-resolution path, the one go2rtc republishes."""
    return next(iter(stream_paths(device).values()))


def stream_urls(device: Device) -> dict[str, str]:
    """This device's local stream URLs, or `{}` when they would not answer.

    Gated on `state["streamAvailable"]` — the verdict of an actual probe, from
    `media/go2rtc.py::probe_stream` — and NOT on `config["active_patchers"]`.
    That distinction is the point: `active_patchers` is what we recorded, and a
    factory reset or an app OTA wipes /system and the patch with it while our
    JSON still says applied. Equally, a device could be serving a stream nobody
    recorded. Publishing a URL that then refuses the connection is worse than
    publishing none — it reads as a broken camera rather than as a patch that
    was never applied.

    The IP is checked too, because it only ever arrives in a state report, so a
    device we have not heard from has no address to build.
    """
    ip = (device.state or {}).get("ip", "")
    if not ip or not (device.state or {}).get("streamAvailable"):
        return {}
    return {name: f"http://{ip}/{path}" for name, path in stream_paths(device).items()}


PATCHER_INFO = {
    "id": "camera",
    "name": "Local Camera Streaming",
    "description": (
        "Replaces the Agora cloud video streaming client with tserver, a local "
        "HTTP video server built into the firmware. This gives you direct LAN "
        "access to the camera feed without going through PetKit's cloud.\n\n"
        "Once applied, the add-on's bundled go2rtc republishes the feed as RTSP "
        "and the URL to use appears above - that is the one to give Home "
        "Assistant's Generic Camera, and it is also the Camera Stream URL "
        "sensor.\n\n"
        "The device's own addresses are listed too, for VLC or your own tooling. "
        "Do NOT give those to Home Assistant: its stream component opens them "
        "with PyAV, which segfaults inside libav and restarts the whole of HA. "
        "go2rtc exists here to stand between the two, and it also spares "
        "the device a connection per viewer by keeping just one open.\n\n"
        "What it does: bind-mounts /app/bin/tserver over /app/bin/agora, so the "
        "stock startup line './agora &' launches the local streamer. Nothing is "
        "written to the device - removing the patch and rebooting restores "
        "Agora exactly.\n\n"
        "Known side effect: the firmware watchdog logs 'kill agora' and 'reboot "
        "agora' once a minute. Every stock process feeds the watchdog by calling "
        "its own *_feed_dog; tserver is a different binary and never does, so "
        "the watchdog decides Agora died. Measured on a T5 over 16 minutes: the "
        "kill never lands, tserver keeps the same PID, its memory stays flat and "
        "the device does not reboot - but the log says otherwise once a minute.\n\n"
        "The PetKit app's live view will stop working - use the RTSP URL above "
        "instead.\n\n"
        "One rough edge: the device needs a few seconds between connections, so "
        "reopening the stream immediately after closing it can fail once. "
        "Waiting a moment and retrying works, and normal viewing does not hit "
        "it."
    ),
    # Pure bind-mount: no file of ours lands on the device, so removal is just
    # dropping the line from the wrapper and rebooting.
    "files": [],
    # No architecture: this bind-mounts one binary the device already ships
    # over another. Both are whatever the device was built with.
    "arch": None,
    # Conservative UI figure: what to tell the user BEFORE we know the model.
    # writes no file of its own, but every patcher rewrites
    # /system/app_init.sh — so the floor is the wrapper plus margin, not zero.
    "needs_bytes": 131072,
}
