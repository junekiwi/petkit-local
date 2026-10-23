"""The stream URLs we hand out, and what gates them.

Two things are being defended here. The URL that reaches Home Assistant must be
the RTSP one, because HA opens whatever it is given with PyAV and the device's
own FLV segfaults libav and restarts the whole of HA. And the gate must be an
observation of the device, not our own record of having patched it.
"""
from petkit_local.devices.base import Device
from petkit_local.ha.entities.camera import CAMERA_ENTITIES
from petkit_local.patchers.camera import stream_urls


def _t5(*, ip="192.0.2.10", available=True, patchers=("camera",)):
    d = Device(device_type="t5", petkit_id=1, serial_number="SN")
    if ip:
        d.state["ip"] = ip
    if available:
        d.state["streamAvailable"] = True
    d.config["active_patchers"] = list(patchers)
    return d


def test_the_urls_are_built_from_the_reported_ip():
    urls = stream_urls(_t5())
    assert urls["flv"] == "http://192.0.2.10/main.flv?audio=1"
    assert urls["sub_flv"] == "http://192.0.2.10/sub.flv?audio=1"


def test_a_d4h_is_offered_main_ts_instead_of_main_flv():
    """`main.flv` crashes a D4H's tserver (upstream issue #38). Its `main.ts`
    is stable and carries real audio, unlike the T5's."""
    d = _t5()
    d.device_type = "d4h"
    assert stream_urls(d) == {"ts": "http://192.0.2.10/main.ts?audio=1",
                              "sub_flv": "http://192.0.2.10/sub.flv?audio=1"}


def test_every_url_asks_for_audio_explicitly():
    """`audio` is not optional: `sub.flv` with no query resets the connection.

    Audio is ON. It was off for a while on the suspicion that it caused the Home
    Assistant segfault, which turned out to be false — HA crashed with audio
    disabled too — and nothing now opens these directly anyway, because go2rtc
    stands in front. The FLV endpoints report a valid 16 kHz mono AAC; the
    broken `sample_rate=0` audio is on the `.ts` ones, which are not offered."""
    for name, url in stream_urls(_t5()).items():
        assert "audio=1" in url, name


def test_the_broken_ts_endpoints_are_not_offered():
    """They announce AAC with sample_rate=0 and list every stream twice, so
    nothing loads them."""
    assert not [u for u in stream_urls(_t5()).values() if u.endswith(".ts")]


def test_no_url_before_the_device_has_reported_an_ip():
    """The IP only ever arrives in a state report, so a fresh device has none."""
    assert stream_urls(_t5(ip="")) == {}


# --- the gate: observation, not bookkeeping ---------------------------------

def test_a_recorded_patch_is_not_enough_without_a_confirmed_stream():
    """`active_patchers` is what WE wrote down. A factory reset or an app OTA
    wipes /system and the patch with it while that record survives, and the URL
    would then refuse the connection — which reads as a broken camera rather
    than an unapplied patch."""
    assert stream_urls(_t5(available=False)) == {}


def test_a_confirmed_stream_is_enough_without_a_recorded_patch():
    """The other half of the same argument: a device may be serving a stream we
    did not set up, and there is no reason to withhold its URL."""
    assert stream_urls(_t5(patchers=()))["flv"].startswith("http://192.0.2.10/")


def test_the_url_reaches_ha_as_a_sensor_not_a_camera():
    """A camera entity here could never carry it: HA's MQTT camera takes image
    bytes on a topic, and there is no still-image endpoint to give it anyway —
    tserver answers every path with the same stream."""
    entity = {e.key: e for e in CAMERA_ENTITIES}["stream_url"]
    assert entity.component == "sensor"
    assert entity.value_path == "state.streamUrl"
    assert entity.entity_category == "diagnostic"


class _FakeSidecar:
    def __init__(self, url=""):
        self._url = url

    def stream_url_for(self, device):
        return self._url


def test_the_state_document_carries_the_rtsp_url_and_never_the_flv():
    """The whole point of the sidecar: HA must never be handed the FLV."""
    from petkit_local.ha.publisher import HAPublisher

    d = _t5()
    pub = HAPublisher.__new__(HAPublisher)
    pub.go2rtc = _FakeSidecar("rtsp://local-petkitlocal:8554/1")

    built = HAPublisher._build_state(pub, d)
    assert built["state"]["streamUrl"] == "rtsp://local-petkitlocal:8554/1"
    assert "flv" not in built["state"]["streamUrl"]


def test_the_state_document_retracts_the_url_when_the_sidecar_stops():
    from petkit_local.ha.publisher import HAPublisher

    d = _t5()
    d.state["streamUrl"] = "rtsp://stale:8554/1"
    pub = HAPublisher.__new__(HAPublisher)
    pub.go2rtc = _FakeSidecar("")

    built = HAPublisher._build_state(pub, d)
    assert "streamUrl" not in built["state"]


def test_no_sidecar_at_all_is_not_an_error():
    """The publisher is built before the sidecar and runs fine headless."""
    from petkit_local.ha.publisher import HAPublisher

    pub = HAPublisher.__new__(HAPublisher)
    pub.go2rtc = None
    assert "streamUrl" not in HAPublisher._build_state(pub, _t5())["state"]
