"""What a proxied cloud response is allowed to contain by the time a device sees it.

Proxy mode forwards everything, so the upstream — PetKit's real cloud — gets to
put a body in front of firmware we are meant to be shielding. This module is the
one place that decides what survives that trip.

**Content-keyed, not endpoint-keyed.** There is deliberately no list of "safe
endpoints": every rule matches on the SHAPE of a decoded object wherever it
appears, so an `apiServers` block returned from an endpoint nobody expected it
on is caught anyway. The walker also descends into JSON encoded as a *string*,
which is how the heartbeat carries its commands — a rule that matched only
decoded objects would never see them.

Two very different kinds of rule live here, and the difference is what
`BLOCKING_RULES` encodes:

* **Routine substitutions** (`server`, `mqtt`, `oss_sts`, `locale`) replace the
  cloud's address — or the device's own local-time settings — with ours. They
  fire constantly, on every `dev_serverinfo` and `dev_device_info` poll, and
  mean nothing except "proxy mode is on". They are logged, not persisted.
* **Blocked attempts** (`rce`, `ota`, `secret`) mean the upstream tried to run a
  command, push firmware, or re-credential the device. These are rare, and each
  one is persisted (`events/models.py::BlockedAttempt`).

The values every substitution uses come from `payloads.to_*` — the same functions
that build our own responses — so a redacted body cannot drift from the body the
local handler would have produced.

This file holds the models and the two entry points; `rules.py` holds the rules
and the constants that name them, and `walker.py` the descent that carries them
to every object in a body. Both import back from here, so the models below are
defined before either is imported.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from petkit_local.devices import payloads

if TYPE_CHECKING:  # pragma: no cover - typing only
    from petkit_local.devices.base import Device

log = logging.getLogger(__name__)


class _Drop:
    """Sentinel meaning "remove me from whatever contains me"."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<DROP>"


_DROP = _Drop()


@dataclass
class Redaction:
    """One thing that was replaced or removed, and what it was.

    `original` is kept in full: it is the payload worth reading afterwards, and
    for a blocked attempt it is the entire point of the record. Callers that
    surface these outside `/data` are responsible for masking it — see
    `web/api/settings.py`'s `/api/blocked`.
    """

    rule: str
    path: str
    original: Any = None
    replacement: Any = None
    note: str = ""

    @property
    def blocking(self) -> bool:
        """Whether this is an upstream attempt rather than a routine rewrite."""
        return self.rule in BLOCKING_RULES


@dataclass
class RedactionResult:
    """The body to hand the device, plus everything learned on the way.

    `captured` holds values we WANT from the upstream even though the device
    must not see them: the real Aliyun credentials (which is the only way to
    learn them, since the ones the device uses are ours — `mqtt/auth.py`) and
    the real STS block.
    """

    body: bytes
    records: list[Redaction] = field(default_factory=list)
    captured: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> list[Redaction]:
        """Just the records worth persisting."""
        return [r for r in self.records if r.blocking]


@dataclass
class RedactionPolicy:
    """The substitute values and the switches, resolved once per request.

    `device` is required for every substitution rule — without a registered
    device there is nothing to substitute, and the caller should not forward at
    all rather than hand a device someone else's credentials.
    """

    device: Device | None = None
    api_url: str = ""
    mqtt_host: str = ""
    bucket_endpoint: str = ""
    aes_key: str = ""
    block_rce: bool = True
    block_ota: bool = True
    block_log_upload: bool = True
    media_to_real_oss: bool = False
    #: Replace an upstream cloud-storage window with our standing one.
    #: Off by default: an expired window from PetKit is a fact about
    #: somebody's account, and overriding it is a decision rather than a
    #: transport detail. On, a device whose subscription lapsed keeps
    #: recording locally instead of silently stopping.
    local_cvr_window: bool = False
    #: The `esp32_http_only` option: hand a model that builds its broker name
    #: from the product key the key that keeps it on HTTP
    #: (`payloads.http_only_broker`), as our own `dev_iot_device_info` does.
    esp32_http_only: bool = True


# Below the models on purpose: both submodules import them back from here, so
# they have to be bound on this module before either one is loaded.
from petkit_local.http.redact.rules import (
    _MQTT_CRED_KEYS,
    _OTA_EXPLICIT_KEYS,
    _OTA_SIBLING_KEYS,
    _OTA_SUFFIXES,
    _OTA_URL_KEYS,
    _SERVER_KEYS,
    BLOCKING_RULES,
    LOG_UPLOAD_DONE,
    LOG_UPLOAD_EMPTY,
    LOG_UPLOAD_ENDPOINTS,
    OTA_CHECK_EMPTY,
    OTA_ENDPOINTS,
    RULE_LOCALE,
    RULE_LOG_UPLOAD,
    RULE_MQTT,
    RULE_OSS_STS,
    RULE_OTA,
    RULE_RCE,
    RULE_SECRET,
    RULE_SERVER,
    SERVERINFO_ENDPOINTS,
    _is_http_url,
    _log_upload_answer,
    _looks_like_firmware,
    _match_locale,
    _match_mqtt,
    _match_oss_sts,
    _match_ota_shape,
    _match_rce,
    _match_secret,
    _match_server,
)
from petkit_local.http.redact.walker import (
    _walk,
    _walk_dict,
    _walk_json_string,
)

#: Everything importable from this package, whether it is public API or a name
#: a test or another module reaches for. Listed so the re-exports above are not
#: read as unused imports.
__all__ = [
    "BLOCKING_RULES",
    "Redaction",
    "RedactionPolicy",
    "RedactionResult",
    "LOG_UPLOAD_DONE",
    "LOG_UPLOAD_EMPTY",
    "LOG_UPLOAD_ENDPOINTS",
    "OTA_CHECK_EMPTY",
    "OTA_ENDPOINTS",
    "RULE_LOCALE",
    "RULE_LOG_UPLOAD",
    "RULE_MQTT",
    "RULE_OSS_STS",
    "RULE_OTA",
    "RULE_RCE",
    "RULE_SECRET",
    "RULE_SERVER",
    "SERVERINFO_ENDPOINTS",
    "cloud_error",
    "redact_body",
    "redact_mqtt",
    "_DROP",
    "_Drop",
    "_MQTT_CRED_KEYS",
    "_OTA_EXPLICIT_KEYS",
    "_OTA_SIBLING_KEYS",
    "_OTA_SUFFIXES",
    "_OTA_URL_KEYS",
    "_SERVER_KEYS",
    "_decode",
    "_is_http_url",
    "_last_segment",
    "_log_upload_answer",
    "_looks_like_firmware",
    "_match_locale",
    "_match_mqtt",
    "_match_oss_sts",
    "_match_ota_shape",
    "_match_rce",
    "_match_secret",
    "_match_server",
    "_offers_an_update",
    "_walk",
    "_walk_dict",
    "_walk_json_string",
]


def redact_body(body: bytes, *, endpoint: str, policy: RedactionPolicy) -> RedactionResult:
    """Make one proxied HTTP response body safe to hand to the device.

    Args:
        endpoint: The request path, used only by the OTA endpoint rule.

    Returns:
        A `RedactionResult` whose `body` is what the device should receive. A
        body that is not JSON is returned BYTE-FOR-BYTE — the rules all operate
        on decoded structures, and re-framing something we cannot read would be
        a worse risk than the one we are guarding against. A body that IS JSON
        is re-serialized even when nothing changed, so byte-level formatting can
        differ from upstream's; only the decoded value is preserved.
    """
    data = _decode(body)
    if data is None:
        return RedactionResult(body)

    result = RedactionResult(body)

    if policy.block_ota and _last_segment(endpoint) in OTA_ENDPOINTS:
        # Recorded only when the cloud actually offered something. "No update"
        # is the answer on every poll, and `dev_ota_heartbeat` is polled — a row
        # per poll would bury the one time it said yes.
        if _offers_an_update(data):
            result.records.append(Redaction(
                rule=RULE_OTA, path="", original=data, replacement=OTA_CHECK_EMPTY,
                note=f"{_last_segment(endpoint)} answered locally",
            ))
        result.body = json.dumps(OTA_CHECK_EMPTY).encode()
        return result

    if policy.block_log_upload and _last_segment(endpoint) in LOG_UPLOAD_ENDPOINTS:
        # Counted, not persisted: the device asks periodically, so this is
        # routine housekeeping rather than the cloud attempting something.
        #
        # RULE_LOG_UPLOAD stays out of BLOCKING_RULES for a second reason too:
        # `original` here is the upstream body, and upstream's version of this
        # answer contains a real 720-character Aliyun STS token. Persisting it
        # would put a live cloud credential in a table the panel serves — the
        # same trap documented for `secret` above.
        replacement = _log_upload_answer(_last_segment(endpoint), policy)
        note = f"{_last_segment(endpoint)} withheld — the device's log stays local"
        if replacement is not LOG_UPLOAD_EMPTY and replacement != LOG_UPLOAD_DONE:
            note = f"{_last_segment(endpoint)} answered with our own bucket — the log comes here"
        result.records.append(Redaction(
            rule=RULE_LOG_UPLOAD, path="", original=data, replacement=replacement,
            note=note,
        ))
        result.body = json.dumps(replacement).encode()
        return result

    if policy.device is not None and _last_segment(endpoint) in SERVERINFO_ENDPOINTS:
        ours = payloads.to_serverinfo(policy.device, policy.api_url)
        if data != ours:
            result.records.append(Redaction(
                rule=RULE_SERVER, path="", original=data, replacement=ours,
                note="dev_serverinfo answered locally",
            ))
        result.body = json.dumps(ours).encode()
        return result

    cleaned = _walk(data, "", policy, result, in_list=False)
    if cleaned is _DROP:
        # The whole body was one hostile object. Answer the way an unhandled
        # endpoint is answered rather than sending nothing: firmware treats a
        # missing/!2xx answer as a server fault and retries forever.
        cleaned = {"result": {}}
    elif isinstance(data, dict) and "result" in data and "result" not in cleaned:
        # The entire `result` value was hostile and got dropped. Put the key
        # back empty rather than shipping a body with no `result` at all —
        # every endpoint's answer has one, and firmware reads it positionally.
        cleaned["result"] = {}
    result.body = json.dumps(cleaned).encode()
    return result


def redact_mqtt(payload: bytes, *, topic: str, policy: RedactionPolicy) -> RedactionResult:
    """Make one frame coming down from the real cloud safe to republish locally.

    Same rules as `redact_body` minus the OTA *endpoint* rule, which has no
    meaning here — an upgrade arrives on its own topic and is blocked by the
    caller before it ever reaches this function (`mqtt/upstream.py`).
    """
    data = _decode(payload)
    if data is None:
        return RedactionResult(payload)

    result = RedactionResult(payload)
    cleaned = _walk(data, "", policy, result, in_list=False)
    if cleaned is _DROP:
        cleaned = {}
    # COMPACT, no whitespace: this frame is republished to the device, whose
    # LinkSDK data-model parser silently drops a spaced `thing/service/*` frame
    # (see `mqtt/bridge.py::_dumps`). `redact_mqtt` re-serialises EVERY relayed
    # frame — even one it changed nothing in — so without this a byte-perfect
    # cloud command was re-spaced on the way through and never actuated.
    result.body = json.dumps(cleaned, separators=(",", ":")).encode()
    return result


# --- helpers ----------------------------------------------------------------


def cloud_error(body: bytes) -> dict | None:
    """PetKit's refusal envelope, if that is what this body is.

    The cloud reports a refusal as ``{"error": {"code": 704, "msg": "..."}}``
    with **HTTP 200**, so a status check cannot see it. Observed on real
    hardware: every session-bearing endpoint answers this way for a device the
    add-on has taken over, because the session the device presents is one WE
    issued and PetKit has never seen. Only the serial-addressed endpoints
    (`dev_signup`, `dev_only_iot_device_info_v2`, `dev_video_device_info`)
    answer normally.

    Handing that body to a device is what a `dev_serverinfo` with no server list
    does to it: the boot sequence restarts, every ~2.4s, forever.

    Returns:
        The error object, or None for anything else — including a body that is
        not JSON, since `redact_body` passes those through untouched and the
        caller's fallback would be the wrong response to a shape we cannot read.
    """
    data = _decode(body)
    if not isinstance(data, dict):
        return None
    error = data.get("error")
    if isinstance(error, dict) and "code" in error:
        return error
    return None


def _decode(body: bytes) -> Any | None:
    """Decode a body, or None when it is not JSON we can walk.

    None means "hand it back untouched": every rule works on decoded structures,
    so a body we cannot read is one we cannot reason about, and re-framing it
    would risk more than it protects.
    """
    if not body:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    if not isinstance(data, (dict, list)):
        return None
    return data


def _last_segment(path: str) -> str:
    """The endpoint name from a request path, ignoring a trailing slash."""
    return path.rstrip("/").rsplit("/", 1)[-1]


def _offers_an_update(data: Any) -> bool:
    """Whether an OTA-endpoint reply contains anything at all.

    Deliberately looser than "is it byte-identical to our own answer": the cloud
    may spell "nothing for you" as `{"result": []}`, `{"result": null}` or with
    extra envelope fields, and none of those is an attempt worth recording.
    """
    if not isinstance(data, dict):
        return bool(data)
    return bool(data.get("result"))
