"""Delivering the ESP32 CA swap over OTA — and taking it back.

`patchers/firmware.py` turns a stock image into a patched one and nothing more.
This module decides which of the two a device is offered, when, and remembers
what the device said about it. The reflash is the one operation in this project
that can brick hardware, so three rules shape everything below:

* **Nothing is offered unless somebody armed it.** `dev_ota_check` answers
  "no update" exactly as it always has until a job is armed from the panel, and
  again as soon as the job ends.
* **The stock image is kept, verbatim, for as long as the release is.** It is
  what a rollback serves, and it is the only image whose provenance is PetKit's
  rather than ours.
* **Every job flashes ONCE, and the other partition is left alone.** An ESP32
  has two app partitions and boots the one the last OTA selected; the other
  keeps the image the device ran before, which the bootloader falls back to
  only if the selected one fails verification at boot. Nothing else switches
  back: the D4 1.267 and T4 1.652 apps are built without app rollback (no
  `ESP_OTA_IMG_PENDING_VERIFY` handling, so no image waits to be confirmed).
  That fallback is the safety net — an image known to boot on this very device
  — and a second pass would overwrite it. localkit advises flashing twice "or
  the device may boot back into the original firmware"; nothing in these
  images explains how, and flashing again from the panel is the remedy if it
  is ever seen.

The protocol comes from localkit, which flashes real D4, T4 and D3 units this
way, and from PetKit's own answers (petkit-firmware-tool reads the same keys):

* `dev_ota_check` is answered `{"result": {"firmwareId", "version", "details":
  [{"id", "module", "version", "file": {"url", "size", "digest"}}]}}` — `digest`
  is an MD5, `url` plain HTTP. A D4 has one module (`userbin`); a T4 has three
  (`userbin`, `pics`, `lans`), and only `userbin` carries the CA.
* A heartbeat entry `{"msgType": 0, "payload": {"firmwareId": N}, "type":
  "ota"}` makes the device check at once. It also checks when it boots, which is
  why power-cycling it starts a job too.
* It reports `dev_ota_start`, then `dev_ota_complete` with `success=1` or with
  `errmsg=otafail-<code>`.

None of that has yet been watched on a device by this code. The store, the
offer and the bookkeeping are tested; whether the firmware accepts them is not.

On disk, one release per (model, version), shared by every device of the model:

    {data_dir}/firmware/{type}/{version}/manifest.json   PetKit's `result`, plus
                                                         the patched module's
                                                         size and digest
    {data_dir}/firmware/{type}/{version}/stock/{module}.bin
    {data_dir}/firmware/{type}/{version}/patched/userbin.bin
    {data_dir}/certs/esp32-ca.pem, esp32-ca.key          the CA every patched
                                                         image trusts
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from petkit_local.devices.base import aliyun_broker_name
from petkit_local.patchers.common import md5hex
from petkit_local.patchers.firmware import (
    FirmwareImageError, find_cert_slot, format_cert_pem, generate_ca_for_slot,
    issue_server_cert, patch_firmware_cert, verify_esp_image,
)
from petkit_local.utils.const import DEVICE_TYPES_DERIVED_BROKER
from petkit_local.utils.jsonio import atomic_write_bytes, atomic_write_json, read_json
from petkit_local.utils.paths import safe_join

if TYPE_CHECKING:
    from petkit_local.devices.base import Device

log = logging.getLogger(__name__)

#: The models this is offered for: the ones that build their broker name from
#: the product key and so can only reach our broker once they trust our CA.
PATCHABLE_TYPES = frozenset(DEVICE_TYPES_DERIVED_BROKER)

STOCK = "stock"
PATCHED = "patched"
VARIANTS = (STOCK, PATCHED)

#: The module holding the MQTT root. The others are served as PetKit sent them.
CA_MODULE = "userbin"

#: Larger than any module seen (T4 `userbin` 1.5 MB, `lans` 0.7 MB) by a wide
#: margin, small enough that a hostile or broken download cannot fill /data.
MAX_MODULE_BYTES = 8 * 1024 * 1024

#: Where `device.config` keeps this module's bookkeeping.
STATE_KEY = "esp32_firmware"

#: Both become path components, so both are held to a shape that cannot climb
#: out of the store (`safe_join` is still the check that counts).
_VERSION_RE = re.compile(r"^[0-9A-Za-z._-]{1,32}$")
_MODULE_RE = re.compile(r"^[0-9A-Za-z_-]{1,32}$")
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


# --------------------------------------------------------------------------- #
# The CA                                                                      #
# --------------------------------------------------------------------------- #


def ca_paths(data_dir: str) -> tuple[str, str]:
    """`(cert_path, key_path)` of the CA every patched image trusts."""
    certs = os.path.join(data_dir, "certs")
    return os.path.join(certs, "esp32-ca.pem"), os.path.join(certs, "esp32-ca.key")


def load_ca(data_dir: str) -> tuple[bytes, bytes] | None:
    """`(key_pem, cert_pem)`, or None before the first release was prepared."""
    cert_path, key_path = ca_paths(data_dir)
    try:
        with open(cert_path, "rb") as f:
            cert = f.read()
        with open(key_path, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        return None
    return key, cert


def ca_fingerprint(data_dir: str) -> str:
    """SHA-256 of the CA's DER, as the panel shows it, or "" if there is none."""
    ca = load_ca(data_dir)
    if ca is None:
        return ""
    from cryptography import x509  # noqa: PLC0415 - optional dependency, probed at use
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415

    return x509.load_pem_x509_certificate(ca[1]).fingerprint(hashes.SHA256()).hex()


def ensure_ca(data_dir: str, template_slot: bytes) -> tuple[bytes, bytes]:
    """The CA for `template_slot`, minted on first use and reused ever after.

    ONE CA, because the broker presents one leaf: every patched device must
    trust the same root. It is sized to the first slot it meets, and a later
    image whose slot differs in length or framing is refused rather than given
    a second CA the broker cannot serve. The D4 1.267 and T4 1.652 slots are
    identical (1280 bytes, CRLF), so that refusal is for a model nobody has
    examined yet.

    Raises:
        FirmwareImageError: the stored CA cannot fill this slot.
    """
    existing = load_ca(data_dir)
    if existing is not None:
        from cryptography import x509  # noqa: PLC0415 - optional dependency, probed at use
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        key, cert = existing
        der = x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)
        # Framed the way this slot is framed, the stored CA must come out as
        # the very bytes on disk: same length, same line endings, same width.
        if format_cert_pem(der, template_slot) != cert:
            raise FirmwareImageError(
                f"this firmware's certificate slot ({len(template_slot)} bytes) is "
                f"not shaped like the one the CA already flashed to other devices "
                f"was sized for ({len(cert)} bytes) — a second CA would need a "
                "second broker certificate, which is not supported")
        return key, cert

    key, cert = generate_ca_for_slot(template_slot)
    cert_path, key_path = ca_paths(data_dir)
    atomic_write_bytes(key_path, key)
    os.chmod(key_path, 0o600)
    atomic_write_bytes(cert_path, cert)
    log.info("Minted the ESP32 firmware CA at %s", cert_path)
    ensure_broker_leaf(data_dir)
    return key, cert


# --------------------------------------------------------------------------- #
# The broker's half of the chain                                              #
# --------------------------------------------------------------------------- #

#: What a patched ESP32 dials, and so the name it sends as SNI and checks the
#: certificate against: `<productKey>.iot-as-mqtt.<region>.aliyuncs.com`, built
#: by the firmware from the key it is handed (`devices/base.aliyun_broker_name`).
#: The Linux models are handed this add-on's own address instead, so no other
#: device asks for a name of this shape.
BROKER_NAME_RE = re.compile(r"^[^.]+\.iot-as-mqtt\.[^.]+\.aliyuncs\.com$", re.IGNORECASE)

#: One wildcard covers every device's name: mbedTLS matches a leading `*.` against
#: exactly one label, which is all the product key is. localkit's broker
#: certificate is the same wildcard, on the same firmware.
BROKER_LEAF_NAME = aliyun_broker_name("*")


def broker_leaf_paths(data_dir: str) -> tuple[str, str]:
    """`(cert_path, key_path)` of the leaf the broker shows a patched ESP32."""
    certs = os.path.join(data_dir, "certs")
    return os.path.join(certs, "esp32-broker.crt"), os.path.join(certs, "esp32-broker.key")


def ensure_broker_leaf(data_dir: str) -> tuple[str, str] | None:
    """The broker leaf signed by the current CA, issued if missing or stale.

    Stale means signed by some other key — a CA that was re-minted after the
    store was cleared. Returns None while there is no CA at all.
    """
    ca = load_ca(data_dir)
    if ca is None:
        return None
    from cryptography import x509  # noqa: PLC0415 - optional dependency, probed at use
    from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415

    ca_key, ca_cert = ca
    cert_path, key_path = broker_leaf_paths(data_dir)
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        try:
            with open(cert_path, "rb") as f:
                leaf = x509.load_pem_x509_certificate(f.read())
            issuer = x509.load_pem_x509_certificate(ca_cert)
            issuer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                       padding.PKCS1v15(), leaf.signature_hash_algorithm)
            return cert_path, key_path
        except Exception:  # noqa: BLE001 - unreadable or foreign: issue a fresh one
            log.info("ESP32 broker certificate is not signed by the current CA; re-issuing")
    leaf_key, leaf_cert = issue_server_cert(ca_key, ca_cert, BROKER_LEAF_NAME)
    atomic_write_bytes(key_path, leaf_key)
    os.chmod(key_path, 0o600)
    atomic_write_bytes(cert_path, leaf_cert)
    log.info("Issued the ESP32 broker certificate (%s) at %s", BROKER_LEAF_NAME, cert_path)
    return cert_path, key_path


# --------------------------------------------------------------------------- #
# Releases                                                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Release:
    """One firmware version for one model, stock and patched, as stored."""

    device_type: str
    version: str
    firmware_id: int
    details: tuple[dict[str, Any], ...]

    def summary(self) -> dict[str, Any]:
        """What the panel shows: per module, both variants' size and digest."""
        return {
            "version": self.version,
            "firmware_id": self.firmware_id,
            "modules": [
                {"module": d["module"], "version": d["version"],
                 "size": d["file"]["size"], "stock_md5": d["file"]["digest"],
                 "patched_md5": (d.get(PATCHED) or {}).get("digest", "")}
                for d in self.details
            ],
        }


def _release_dir(data_dir: str, device_type: str, version: str) -> str:
    return safe_join(os.path.join(data_dir, "firmware"), device_type.lower(), version)


def validate_manifest(result: Any) -> dict[str, Any]:
    """PetKit's `dev_ota_check` result, checked before anything acts on it.

    Every field is used for something — `version` and `module` become path
    components, `size` and `digest` are how the download is verified — so a
    field of the wrong shape stops here rather than wherever it would first
    bite.

    Raises:
        FirmwareImageError: anything missing or of the wrong shape, or no
            `userbin` module to patch.
    """
    if not isinstance(result, dict):
        raise FirmwareImageError("PetKit's firmware answer is not an object")
    version = result.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise FirmwareImageError(f"PetKit's firmware version {version!r} is not usable")
    firmware_id = result.get("firmwareId")
    if not isinstance(firmware_id, int) or isinstance(firmware_id, bool):
        raise FirmwareImageError(f"PetKit's firmwareId {firmware_id!r} is not a number")
    details = result.get("details")
    if not isinstance(details, list) or not details:
        raise FirmwareImageError("PetKit's firmware answer lists no modules")
    seen: set[str] = set()
    for d in details:
        if not isinstance(d, dict):
            raise FirmwareImageError("a firmware module entry is not an object")
        module, file = d.get("module"), d.get("file")
        if not isinstance(module, str) or not _MODULE_RE.match(module) or module in seen:
            raise FirmwareImageError(f"firmware module name {module!r} is not usable")
        seen.add(module)
        if not isinstance(file, dict):
            raise FirmwareImageError(f"module {module} has no file")
        size, digest, url = file.get("size"), file.get("digest"), file.get("url")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_MODULE_BYTES:
            raise FirmwareImageError(f"module {module} has an unusable size {size!r}")
        if not isinstance(digest, str) or not _MD5_RE.match(digest):
            raise FirmwareImageError(f"module {module} has an unusable digest {digest!r}")
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            raise FirmwareImageError(f"module {module} has no download URL")
    if CA_MODULE not in seen:
        raise FirmwareImageError(
            f"PetKit's firmware has no {CA_MODULE} module (it has {sorted(seen)}), "
            "so there is nothing to patch")
    return {"firmwareId": firmware_id, "version": version, "details": details}


def save_release(data_dir: str, device_type: str, manifest: Any,
                 modules: dict[str, bytes]) -> Release:
    """Verify, patch and store one release. Idempotent for the same bytes.

    Each module must be exactly what the manifest describes (size and MD5);
    `userbin` must also verify as an intact ESP image, which `patch_firmware_cert`
    checks before swapping the CA in. Everything is checked before the first
    byte is written, so a refusal leaves the store as it was.

    Raises:
        FirmwareImageError: a module is missing, differs from the manifest, or
            the image cannot be patched.
    """
    m = validate_manifest(manifest)
    for d in m["details"]:
        blob = modules.get(d["module"])
        file = d["file"]
        if blob is None:
            raise FirmwareImageError(f"module {d['module']} was not downloaded")
        if len(blob) != file["size"] or md5hex(blob) != file["digest"].lower():
            raise FirmwareImageError(
                f"module {d['module']} is {len(blob)} bytes with MD5 {md5hex(blob)}, "
                f"but PetKit described {file['size']} bytes with MD5 {file['digest']}")

    stock = modules[CA_MODULE]
    what = f"{device_type.upper()} {m['version']} {CA_MODULE}"
    image = verify_esp_image(stock, what)
    start, end = find_cert_slot(stock, image)
    _key, ca = ensure_ca(data_dir, stock[start:end])
    patched = patch_firmware_cert(stock, ca)

    root = _release_dir(data_dir, device_type, m["version"])
    details = []
    for d in m["details"]:
        atomic_write_bytes(safe_join(root, STOCK, f"{d['module']}.bin"), modules[d["module"]])
        entry = dict(d)
        if d["module"] == CA_MODULE:
            atomic_write_bytes(safe_join(root, PATCHED, f"{CA_MODULE}.bin"), patched)
            entry[PATCHED] = {"size": len(patched), "digest": md5hex(patched),
                              "ca_sha256": hashlib.sha256(ca).hexdigest()}
        details.append(entry)
    atomic_write_json(os.path.join(root, "manifest.json"),
                      {"firmwareId": m["firmwareId"], "version": m["version"],
                       "details": details})
    log.info("Stored %s %s firmware: %s", device_type.upper(), m["version"],
             ", ".join(d["module"] for d in details))
    return Release(device_type.lower(), m["version"], m["firmwareId"], tuple(details))


def load_release(data_dir: str, device_type: str, version: str) -> Release | None:
    """A stored release, or None if it is absent or its manifest is damaged."""
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        return None
    root = _release_dir(data_dir, device_type, version)
    m = read_json(os.path.join(root, "manifest.json"), None)
    try:
        valid = validate_manifest(m)
    except FirmwareImageError:
        return None
    if not all(os.path.isfile(module_path(data_dir, device_type, version, STOCK, d["module"]))
               for d in valid["details"]):
        return None
    if not os.path.isfile(module_path(data_dir, device_type, version, PATCHED, CA_MODULE)):
        return None
    # `offer()` reads the patched size and digest straight off the userbin detail,
    # so a manifest whose userbin lost its `patched` block — hand-edited, or a
    # partial write — must read as "no release" here rather than reach `offer()`
    # and 500 a device mid-`dev_ota_check`, which it would then retry forever.
    userbin = next((d for d in valid["details"] if d["module"] == CA_MODULE), None)
    patched = (userbin or {}).get(PATCHED)
    if not isinstance(patched, dict) or "size" not in patched or "digest" not in patched:
        return None
    return Release(device_type.lower(), valid["version"], valid["firmwareId"],
                   tuple(valid["details"]))


def module_path(data_dir: str, device_type: str, version: str, variant: str,
                module: str) -> str:
    """Where one stored module lives. Every argument may come from a request.

    Raises:
        UnsafePathError: the result would leave the store.
    """
    return safe_join(_release_dir(data_dir, device_type, version), variant, f"{module}.bin")


def offer(release: Release, variant: str, base_url: str) -> dict[str, Any]:
    """The `dev_ota_check` result that hands a device `variant` of `release`.

    PetKit's entries are passed through as they came, with only `file`
    replaced: its URL now points here, and for the patched `userbin` its size
    and digest are the patched image's.
    """
    details = []
    for d in release.details:
        patched = variant == PATCHED and d["module"] == CA_MODULE
        source = d[PATCHED] if patched else d["file"]
        entry = {k: v for k, v in d.items() if k != PATCHED}
        entry["file"] = {
            "url": (f"{base_url}/firmware/{release.device_type}/{release.version}/"
                    f"{PATCHED if patched else STOCK}/{d['module']}.bin"),
            "size": source["size"],
            "digest": source["digest"],
        }
        details.append(entry)
    return {"firmwareId": release.firmware_id, "version": release.version,
            "details": details}


# --------------------------------------------------------------------------- #
# Jobs                                                                        #
# --------------------------------------------------------------------------- #
#
# `device.config[STATE_KEY]`:
#
#   release      the version stored for this device
#   running      "stock" / "patched" once a job has completed, else absent —
#                what we flashed, not what we observed
#   job          the armed job, or None: target, version, firmware_id,
#                armed_at, started_at
#   last_result  how the last job ended: target, ok, detail, at


def firmware_state(device: Device) -> dict[str, Any]:
    """This device's bookkeeping, read-only. Empty for a device never touched."""
    state = device.config.get(STATE_KEY)
    return state if isinstance(state, dict) else {}


def _state(device: Device) -> dict[str, Any]:
    state = device.config.get(STATE_KEY)
    if not isinstance(state, dict):
        state = device.config[STATE_KEY] = {}
    return state


def active_job(device: Device) -> dict[str, Any] | None:
    """The armed job, if there is one."""
    job = firmware_state(device).get("job")
    return job if isinstance(job, dict) else None


def uses_local_broker(device: Device) -> bool:
    """Whether this device should be handed its own broker name.

    True once a job of ours flashed it patched — it now trusts our CA — and
    while no job is armed. An armed job needs the device on the HTTP heartbeat,
    where the offer and the nudge reach it, so it is kept there until the job
    ends, exactly like an unpatched one.
    """
    return firmware_state(device).get("running") == PATCHED and active_job(device) is None


def http_only(device: Device, option: bool) -> bool:
    """`esp32_http_only` as it applies to this device: on, unless patched here.

    The one decision for both places a device is handed MQTT credentials —
    `dev_iot_device_info` and proxy mode's rewrite of PetKit's — passed to
    `devices/payloads.http_only_broker`, which cannot ask this module itself.
    """
    return option and not uses_local_broker(device)


def ota_trigger(firmware_id: int) -> dict[str, Any]:
    """The heartbeat entry that makes the device ask for firmware right away.

    msgType 0 is `on_web_recv_from_topic`, and `ota` is one of the topics it
    dispatches (`http/handlers/heartbeat.py`). The timestamp is added when the
    entry is sent, not now: one older than 61 seconds is discarded as expired.
    """
    return {"msgType": 0, "payload": {"firmwareId": firmware_id}, "type": "ota"}


def set_release(device: Device, release: Release) -> None:
    """Record which stored release belongs to this device."""
    _state(device)["release"] = release.version


def arm(device: Device, release: Release, target: str) -> None:
    """Arm a job flashing `target` from `release`, and nudge the device.

    The nudge only reaches a device polling the HTTP heartbeat. One that is not
    (on MQTT, or switched off) takes the offer the next time it boots.

    Raises:
        ValueError: `target` is not a variant.
    """
    if target not in VARIANTS:
        raise ValueError(f"unknown firmware variant {target!r}")
    state = _state(device)
    state["release"] = release.version
    state["job"] = {"target": target, "version": release.version,
                    "firmware_id": release.firmware_id,
                    "armed_at": time.time(), "started_at": None}
    device.command_queue.append(ota_trigger(release.firmware_id))


def disarm(device: Device) -> bool:
    """Cancel the armed job. True if there was one."""
    state = _state(device)
    had = bool(state.get("job"))
    state["job"] = None
    return had


def note_started(device: Device) -> str | None:
    """`dev_ota_start` arrived. Returns a line for the panel, or None if no
    job of ours is armed (the device is updating on some other authority)."""
    job = active_job(device)
    if job is None:
        return None
    job["started_at"] = time.time()
    return f"device started flashing {job['target']} {job['version']}"


def note_completed(device: Device, success: bool, detail: str) -> str | None:
    """`dev_ota_complete` arrived. Ends the job either way.

    Returns a line for the panel, or None if no job of ours is armed.
    """
    job = active_job(device)
    if job is None:
        return None
    state = _state(device)
    target = job["target"]
    state["job"] = None
    if not success:
        detail = detail or "no reason given"
        state["last_result"] = {"target": target, "ok": False, "detail": detail,
                                "at": time.time()}
        return f"flashing {target} {job['version']} FAILED: {detail}"
    state["running"] = target
    state["last_result"] = {"target": target, "ok": True, "detail": "", "at": time.time()}
    return f"{target} {job['version']} flashed — done"
