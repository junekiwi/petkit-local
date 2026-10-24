"""The rules themselves: what each one matches, and what it substitutes.

One function per rule, each taking a decoded object and returning either its
replacement or — for the two that remove rather than rewrite — whether the
object should disappear. The rule-id constants, `BLOCKING_RULES` and the
endpoint sets live here too, beside the rules that name them. The walker
(`walker.py`) decides *where* these run; the package `__init__` decides *when*.
"""
from __future__ import annotations

from typing import Any

from petkit_local.devices import payloads
from petkit_local.http.redact import Redaction, RedactionPolicy, RedactionResult
from petkit_local.patchers import esp32_ota

RULE_RCE = "rce"
RULE_OTA = "ota"
RULE_SECRET = "secret"
RULE_SERVER = "server"
RULE_MQTT = "mqtt"
RULE_OSS_STS = "oss_sts"
RULE_LOG_UPLOAD = "log_upload"
RULE_LOCALE = "locale"

#: Rules whose firing means the upstream tried something, as opposed to us
#: routinely substituting our own address into its answer. Only these are
#: written to the database; the rest would be thousands of rows a day of
#: entirely expected traffic.
#:
#: `secret` is deliberately NOT here, tempting though it looks. Every ordinary
#: `dev_signup` and `dev_device_info` reply carries one (`payloads.to_signup` /
#: `to_device_info`), so the rule fires on routine polling — and persisting it
#: would put the device's real PetKit credential in a table the panel serves.
BLOCKING_RULES = frozenset({RULE_RCE, RULE_OTA})

#: `dev_ota_check` / `dev_ota_heartbeat` are answered with this literal, exactly
#: as `http/handlers/ota.py::NO_UPDATE` does. An OBJECT — confirmed by
#: proxying the endpoint to PetKit on 2026-07-27, which corrected a long-
#: standing claim that the array was the cloud's shape. A bad answer here is
#: the one way this server could brick a device.
OTA_CHECK_EMPTY: dict[str, Any] = {"result": {}}

#: Endpoints whose whole body is replaced rather than walked. Matched on the
#: last path segment, so both `/6/t5/dev_ota_check` and `/6/dev_ota_check` hit.
OTA_ENDPOINTS = frozenset({"dev_ota_check", "dev_ota_heartbeat"})

#: The device's own debug log, and the STS token it needs to upload it. Observed
#: on hardware: `dev_upload_log_token` returns a real Aliyun token, the device
#: PUTs `devRun.log` straight to `petkit-storage-binary-prod-eu.oss-eu-central-1
#: .aliyuncs.com`, then reports the object URL via `dev_upload_log`.
#:
#: That log is a full transcript — every request URL, the LAN address of this
#: add-on, and the `X-Device` signatures — so an upload tells PetKit precisely
#: how the device has been taken over. Blocked by default, and what "blocked"
#: substitutes depends on whether the device collects locally
#: (`handlers/upload_log.py`): with collection off it gets the same empty result
#: it has always had here, and with it on it gets OUR token instead of the
#: cloud's. Both withhold the upstream credential completely; the second also
#: denies PetKit the log itself, so neither weakens the guard.
LOG_UPLOAD_ENDPOINTS = frozenset({"dev_upload_log_token", "dev_upload_log"})

#: What those endpoints are answered with — the same empty success our own
#: handler sends, so the device sees nothing new and stops asking.
LOG_UPLOAD_EMPTY: dict[str, Any] = {"result": {}}

#: `dev_upload_log`'s own answer: a bare STRING result, not an object. Same
#: literal as `handlers/upload_log.py::UPLOAD_LOG_DONE`, which records why.
LOG_UPLOAD_DONE: dict[str, Any] = {"result": "success"}


def _log_upload_answer(name: str, policy: RedactionPolicy) -> dict[str, Any]:
    """The local body that replaces upstream's on a log-upload endpoint.

    `dev_upload_log` is only an acknowledgement, so it gets the fidelity-correct
    one whatever else is configured. `dev_upload_log_token` gets our own bucket's
    token when the device has collection switched on and the bucket address can
    be split into a virtual-host authority, and the empty result otherwise.
    """
    if name == "dev_upload_log":
        return LOG_UPLOAD_DONE
    device = policy.device
    if device is None or not device.config.get("log_upload_enabled", False):
        return LOG_UPLOAD_EMPTY
    body = payloads.to_log_upload_token(device, policy.bucket_endpoint)
    return body if body.get("result") else LOG_UPLOAD_EMPTY

#: `dev_serverinfo` is answered from OUR values whatever the upstream said —
#: the only endpoint forced rather than merely corrected. The content rule below
#: can replace an `apiServers` it finds, but it cannot repair an answer that
#: OMITS one, and a device handed a serverinfo with no server list restarts its
#: whole boot sequence in a loop. Observed on real hardware: PetKit answers this
#: with `{"error": {"code": 704}}` for a device whose session it does not know,
#: which is every device this add-on has taken over.
SERVERINFO_ENDPOINTS = frozenset({"dev_serverinfo"})

#: An unambiguous firmware URL: no other endpoint has a reason to send this key.
_OTA_EXPLICIT_KEYS = ("otaUrl", "firmwareUrl", "upgradeUrl")
#: Generic URL keys, which are only evidence when what they point AT is an
#: image. `dev_discern_pic` sends `{"faceId", "url"}` and a media listing sends
#: `{"url", "size"}` — dropping either would break a working feature and file a
#: false "firmware push" against the cloud.
_OTA_URL_KEYS = ("url", "downloadUrl", "fileUrl", "packageUrl")
#: Extensions a firmware image actually has. Checked on the URL's path, and
#: still gated by a sibling from `_OTA_SIBLING_KEYS` — `.zip` and `.tar.gz` are
#: common firmware containers but also common everything-else, so neither is
#: evidence on its own.
_OTA_SUFFIXES = (".bin", ".img", ".ota", ".pkg", ".fw", ".rom",
                 ".tar", ".tar.gz", ".gz", ".zip")
#: Even with a matching extension, something must describe the artifact.
_OTA_SIBLING_KEYS = ("md5", "size", "fileSize", "version", "firmwareVersion")

#: Fields that repoint the device's API base. `dns` is here because it is a
#: device-level resolver override, not just an informational string.
_SERVER_KEYS = ("apiServers", "ipServers", "dns")

#: The MQTT credential trio. Present together in both the `ali`-wrapped and the
#: flat shape (`devices/payloads.py::to_iot_device_info` / `_flat`).
_MQTT_CRED_KEYS = ("productKey", "deviceName", "deviceSecret")


# --- the rules --------------------------------------------------------------


def _match_rce(node: dict, path: str, policy: RedactionPolicy,
               out: RedactionResult) -> bool:
    """`user_cmd.run_cmd` — a shell command the firmware runs as root.

    `patchers/common.py::queue_run_cmd` documents the receiving end: PATH 2 of
    the firmware's handling is a direct `system()` call with no uptime guard and
    no length limit. It is a legitimate tool when WE queue it; it is the single
    worst thing an upstream could send.
    """
    if not policy.block_rce:
        return False
    cmd = node.get("user_cmd")
    if not isinstance(cmd, dict) or "run_cmd" not in cmd:
        return False
    out.records.append(Redaction(
        rule=RULE_RCE, path=path or "user_cmd", original=cmd.get("run_cmd"),
        note="shell command from upstream",
    ))
    return True


def _match_ota_shape(node: dict, path: str, policy: RedactionPolicy,
                     out: RedactionResult) -> bool:
    """A firmware image offered somewhere other than the OTA endpoints.

    UNVERIFIED and deliberately narrow: we have never seen the cloud push an
    OTA, so this is additive belt-and-braces and the endpoint rule is the real
    guard. Narrow matters more than thorough here, because a false positive
    DELETES a working payload: `dev_discern_pic` sends `{"faceId", "url"}` per
    face and a media listing sends `{"url", "size"}`, and an over-eager rule
    silently breaks face recognition while filing a "firmware push" against the
    cloud that never happened.

    So either the key is unambiguous (`otaUrl` and friends — nothing else has a
    reason to send one), or the URL has to point at something that actually
    looks like an image AND be described by a sibling. A bare `firmware` or
    `version` key is never enough: `Device.firmware` and every state report
    carry exactly those.
    """
    if not policy.block_ota:
        return False

    key = next((k for k in _OTA_EXPLICIT_KEYS if _is_http_url(node.get(k))), None)
    if key is None:
        key = next(
            (k for k in _OTA_URL_KEYS
             if _is_http_url(node.get(k)) and _looks_like_firmware(node[k])
             and any(sibling in node for sibling in _OTA_SIBLING_KEYS)),
            None,
        )
    if key is None:
        return False

    out.records.append(Redaction(
        rule=RULE_OTA, path=f"{path}.{key}" if path else key,
        original=node, note="firmware image offered outside the OTA endpoints",
    ))
    return True


def _is_http_url(value: Any) -> bool:
    """Whether a value is a string naming an http(s) URL."""
    return isinstance(value, str) and value.lower().startswith(("http://", "https://"))


def _looks_like_firmware(url: str) -> bool:
    """Whether a URL's PATH ends in something a firmware image is packaged as.

    The path only, so a query string full of parameters cannot smuggle a match
    in and, more importantly, a signed media URL ending `?...&x=a.bin` is not
    mistaken for one.
    """
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith(_OTA_SUFFIXES)


def _match_server(node: dict, path: str, policy: RedactionPolicy,
                  out: RedactionResult) -> dict:
    """`apiServers` / `ipServers` / `dns` — where the device goes next.

    The one rule that cannot be switched off. `handlers/serverinfo.py` puts it
    plainly: the official cloud answers with its own address, and a device that
    believes it hands itself back to PetKit at the next poll and never returns.
    """
    if policy.device is None or not any(k in node for k in _SERVER_KEYS):
        return node

    ours = payloads.to_serverinfo(policy.device, policy.api_url)["result"]
    patched = dict(node)
    original = {}
    for key in _SERVER_KEYS:
        if key not in node:
            continue
        original[key] = node[key]
        patched[key] = ours[key]

    out.records.append(Redaction(
        rule=RULE_SERVER, path=path, original=original,
        replacement={k: ours[k] for k in original},
        note="upstream tried to repoint the device's API base",
    ))
    return patched


def _match_mqtt(node: dict, path: str, policy: RedactionPolicy,
                out: RedactionResult) -> dict:
    """`mqttHost` and the credential trio — where the device's MQTT goes.

    Keyed on the containing object, which covers the `ali`-wrapped and the flat
    shape with one rule. The upstream values are CAPTURED rather than merely
    dropped: they are the real Aliyun endpoint and credentials, and this is the
    only place they can be learned, because the ones the device actually uses
    were minted by us (`http/handlers/iot_device_info.py`).
    """
    device = policy.device
    if device is None:
        return node
    has_host = "mqttHost" in node
    has_creds = all(k in node for k in _MQTT_CRED_KEYS)
    if not has_host and not has_creds:
        return node

    # MERGED, never overwritten. The host and the credential trio can arrive in
    # two different objects of one reply — `mqttHost` beside an `ali` block that
    # holds the rest — and this rule matches either alone, so assigning would let
    # the second match blank out what the first found. A half-captured identity
    # is worse than none: `mqtt/upstream.py` would dial an empty host forever.
    found = {
        "mqtt_host": node.get("mqttHost", ""),
        "product_key": node.get("productKey", ""),
        "device_name": node.get("deviceName", ""),
        "device_secret": node.get("deviceSecret", ""),
        "region_id": node.get("regionId", ""),
        "iot_instance_id": node.get("iotInstanceId", ""),
    }
    if any(found.values()):
        captured = out.captured.setdefault("mqtt", {})
        for key, value in found.items():
            if value or key not in captured:
                captured[key] = value

    ours = {
        "mqttHost": device.resolve_mqtt_host(policy.mqtt_host),
        "productKey": device.mqtt_product_key,
        "deviceName": device.mqtt_device_name,
        "deviceSecret": device.mqtt_device_secret,
        "iotInstanceId": device.mqtt_product_key,
    }
    http_only = payloads.http_only_broker(
        device, esp32_ota.http_only(device, policy.esp32_http_only))
    if http_only:
        product_key, ours["mqttHost"] = http_only
        ours["productKey"] = ours["iotInstanceId"] = product_key
    patched = dict(node)
    original = {}
    for key, value in ours.items():
        if key not in node:
            continue
        original[key] = node[key]
        patched[key] = value

    out.records.append(Redaction(
        rule=RULE_MQTT, path=path, original=original,
        replacement={k: ours[k] for k in original},
        note="upstream tried to repoint the device's broker",
    ))
    return patched


def _match_oss_sts(node: dict, path: str, policy: RedactionPolicy,
                   out: RedactionResult) -> dict:
    """`capability[]` — where media is uploaded, and with which key.

    The whole list is replaced rather than six fields per entry: `capability[]`
    is the media control plane, and a type the user switched off is ABSENT from
    ours (`Device.enabled_capabilities`). Patching URLs in place would let
    upstream re-enable an upload the user turned off at the source.

    Skipped entirely when `media_to_real_oss` is set, which is the toggle that
    lets a device record to PetKit's OSS so the real upload path can be watched.
    The original is captured either way.
    """
    device = policy.device
    caps = node.get("capability")
    if device is None or not isinstance(caps, list) or not caps:
        return node
    # Shape-gated, because `dev_device_info`'s cloud-subscription list is ALSO
    # keyed `capability[]` and carries `name`/`workTime`/`indate` instead. Both
    # used to land here, so a subscription window was replaced with an upload
    # credential list. That one is `_match_cvr_capacity`.
    sample = caps[0] if isinstance(caps[0], dict) else None
    if sample is None or not ("cycleType" in sample or "primaryParUrl" in sample):
        return node

    out.captured["oss_sts"] = node["capability"]
    if policy.media_to_real_oss:
        return node

    sts = payloads.to_oss_sts(device, policy.bucket_endpoint,
                              policy.aes_key)["result"]
    patched = dict(node)
    patched["capability"] = sts["capability"]
    patched["type"] = sts["type"]
    out.records.append(Redaction(
        rule=RULE_OSS_STS, path=f"{path}.capability" if path else "capability",
        original=node["capability"], replacement=sts["capability"],
        note="upstream tried to repoint media uploads",
    ))
    return patched


def _match_cvr_capacity(node: dict, path: str, policy: RedactionPolicy,
                        out: RedactionResult) -> dict:
    """`capacity[]` / `cloudProduct` — the cloud-storage subscription window.

    The firmware arms continuous recording only while now falls between an
    entry's `workTime` and its `indate`. An EXPIRED PetKit billing window
    therefore arrives looking like a perfectly valid configuration and quietly
    leaves the device recording nothing, with no error anywhere.

    OFF by default, and that is deliberate rather than timid: overriding it
    means telling a device its subscription is live when PetKit says it is not,
    which is a decision about somebody else's account, not a transport detail.
    `proxy_local_cvr_window` in the panel turns it on.

    Shape-gated on `name`+`indate` so the STS `capability[]`
    (`cycleType`/`primaryParUrl`) is left to `_match_oss_sts`.
    """
    device = policy.device
    if device is None or not device.is_camera or not policy.local_cvr_window:
        return node

    ours = payloads.to_device_info(device)["result"]
    patched = dict(node)
    changed = False

    caps = node.get("capacity")
    if isinstance(caps, list) and caps and isinstance(caps[0], dict) \
            and "indate" in caps[0] and ours.get("capacity"):
        patched["capacity"] = ours["capacity"]
        out.records.append(Redaction(
            rule=RULE_OSS_STS, path=f"{path}.capacity" if path else "capacity",
            original=caps, replacement=ours["capacity"],
            note="upstream CVR window replaced with our standing one"))
        changed = True

    product = node.get("cloudProduct")
    if isinstance(product, dict) and "workIndate" in product and ours.get("cloudProduct"):
        patched["cloudProduct"] = ours["cloudProduct"]
        out.records.append(Redaction(
            rule=RULE_OSS_STS,
            path=f"{path}.cloudProduct" if path else "cloudProduct",
            original=product, replacement=ours["cloudProduct"],
            note="upstream cloudProduct window replaced with our standing one"))
        changed = True

    return patched if changed else node


def _match_secret(node: dict, path: str, policy: RedactionPolicy,
                  out: RedactionResult) -> dict:
    """A `secret` for OUR device — the credential it signs its requests with.

    This rule ADOPTS rather than substitutes, and it is the one place in this
    module that does. The firmware signs every request with the secret
    `dev_signup` gave it (`X-Device: id=…&nonce=…&timestamp=…&sign=<md5>`), and
    PetKit verifies that signature. Hand the device a secret we invented and the
    real cloud answers `{"error": {"code": 704}}` to everything — which makes
    proxy mode a tool that can only ever watch itself being refused.

    So the upstream value is captured and PASSED THROUGH. The device then signs
    with a credential PetKit accepts, and we never had to reproduce the
    signature algorithm, because the device computes it. This is safe locally
    for a specific reason: nothing here verifies that signature — see
    `Device.signing_secret`. What keeps the device OURS is the addresses
    (`apiServers`, `mqttHost`, the STS bucket), all still substituted.

    `id` is still forced: a device that adopts a different one stops resolving
    against our registry entirely.

    Narrowed to objects ABOUT our device (`dev_signup`'s result, or
    `dev_device_info`'s), because a nested accessory block carries its own
    `secret` and adopting a K3's as the parent's would be a new bug.
    """
    device = policy.device
    if device is None or not isinstance(node.get("secret"), str):
        return node

    about_us = (
        "signupAt" in node
        or node.get("id") == device.petkit_id
        or (bool(device.serial_number) and node.get("sn") == device.serial_number)
    )
    if not about_us:
        return node

    out.captured["api_secret"] = node["secret"]

    patched = dict(node)
    if "id" in node and node["id"] != device.petkit_id:
        out.records.append(Redaction(
            rule=RULE_SECRET, path=path, original={"id": node["id"]},
            replacement={"id": device.petkit_id},
            note="upstream reported a different device id",
        ))
        patched["id"] = device.petkit_id
    return patched


def _match_locale(node: dict, path: str, policy: RedactionPolicy,
                  out: RedactionResult) -> dict:
    """`timezone` / `locale` for OUR device — keep ours, not PetKit's.

    Both fields ride along on `dev_signup` and `dev_device_info`, which
    `_match_secret` deliberately passes through whole. Proxied unchanged, the
    device adopts the account's cloud-side values — on the reference install
    that meant `timezone: 0.0, locale: "Etc/UTC"` replacing our `2.0`, visible
    in its state reports minutes later. The device has no timezone of its own
    beyond what it is told (`ctrl` takes one from BLE provisioning only), and a
    wrong one is burned into video watermarks.

    Same shape as `_match_server`: only keys ALREADY PRESENT are overwritten, so
    this never adds a field to a body that had none. Routine, so it is not in
    `BLOCKING_RULES` — `dev_device_info` is polled often and a row per poll
    would bury the attempts that matter.
    """
    device = policy.device
    if device is None:
        return node

    about_us = (
        "signupAt" in node
        or node.get("id") == device.petkit_id
        or (bool(device.serial_number) and node.get("sn") == device.serial_number)
    )
    if not about_us:
        return node

    ours = {"timezone": device.timezone_offset, "locale": device.config.get("locale", "")}
    patched = dict(node)
    for key, value in ours.items():
        if key not in node or node[key] == value:
            continue
        out.records.append(Redaction(
            rule=RULE_LOCALE, path=f"{path}.{key}" if path else key,
            original=node[key], replacement=value,
            note="upstream would overwrite the device's local time settings",
        ))
        patched[key] = value
    return patched
