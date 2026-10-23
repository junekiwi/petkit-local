"""Tests for events/decode.py, built from real captured payloads.

The payloads below are verbatim from the reference corpus (268 events, real T5
id=10000001 firmware 943), with the bucket host rewritten to an RFC 5737
documentation address the way `test_events_ingest_real_t5.py` already does.
"""
import pytest

from petkit_local.events import codes, decode

_IMG = "https://192.0.2.199/petkit-local/t5/10000001/even/3_278EVENT_PREVIEW1784745589"

#: One payload per distinct event code seen on the wire.
REAL_CONTENT: dict[str, dict] = {
    "1": {"err": "hallB", "msg": "", "detail": ""},
    "2": {"start_time": 1784827076, "err": "hallB", "msg": "", "detail": ""},
    "3": {"pos": 0, "reason": 0, "item_id": 0, "action": 2},
    "4": {"pos": 0, "reason": 0, "action": 0, "err": 256},
    "5": {"img": _IMG, "aesKey": "83359820a8a860dc", "mark": 1784745583,
          "start_time": 1784745583, "start_reason": 0, "result": 0, "err": "NULL",
          "litter_weight": 0, "litter_percent": 100, "box": 0, "clean_weight": 0,
          "upload": 1, "media": 1, "relate_event": "5_10000001_1784745527",
          "ph_reason": 5},
    "7": {"start_time": 1785068088, "over_time": 1785068411, "start_reason": 3,
          "pos": 0, "current": 0, "result": 5, "err": "", "components": 0,
          "litter_weight": 0},
    "8": {"start_time": 1784745558, "start_reason": 0, "result": 0, "err": "",
          "from_clear": 0, "relate_event": "5_10000001_1784745527", "clean_flag": 1},
    "9": {"pet_weight": 2320, "mark": 1784745527},
    "10": {"img": _IMG, "aesKey": "83359820a8a860dc", "mark": 1784745527,
           "upload": 1, "media": 1, "time_out": 1784745547, "time_in": 1784745533,
           "start_time": 1784745527, "auto_clear": 1, "is_shit": 1, "interval": 0,
           "pet_weight": 2320, "shit_weight": 10, "count": 1, "area": 336720,
           "toiletDetection": 1, "score_info": [{"id": 101392625, "score": 131}],
           "petVoice": 0, "voice_reason": 0, "voice_time": []},
    "13": {"pos": 0, "reason": 3, "action": 0},
    "14": {"pos": 0, "reason": 2, "action": 9},
    "15": {"pos": 0, "reason": 0, "action": 9, "err": 128},
    "16": {"pos": 0, "reason": 3, "action": 9},
    "17": {"start_time": 1784745583, "start_reason": 0, "result": 0, "err": "",
           "from_clear": 1},
    "20": {"img": _IMG, "aesKey": "83359820a8a860dc", "mark": 1784746411,
           "start_time": 1784746411, "upload": 1, "media": 1},
    "24": {"related_event": "6_10000001_1784746411", "count": 1, "area": 8687,
           "score_info": []},
}


# --- totality --------------------------------------------------------------

@pytest.mark.parametrize("event_type", sorted(REAL_CONTENT, key=int))
def test_every_content_key_produces_a_row(event_type):
    """Nothing the device sends may vanish.

    This is the property the Debug view rests on: a firmware that starts
    sending a new field has to become visible, not silently disappear because
    no one added a spec for it.
    """
    content = REAL_CONTENT[event_type]
    fields = decode.decode_content(event_type, content)
    assert {f.key for f in fields} == set(content)
    assert all(f.text for f in fields), "a field rendered as empty text"


def test_unspecced_keys_are_passed_through_and_marked_unknown():
    fields = {f.key: f for f in decode.decode_content("10", {"brandNewField": 42})}
    assert fields["brandNewField"].raw == 42
    assert fields["brandNewField"].grade == decode.UNKNOWN


def test_decode_content_tolerates_junk():
    for junk in (None, {}, "not a dict", 7):
        assert decode.decode_content("10", junk) == []


# --- the polymorphic err field ---------------------------------------------

@pytest.mark.parametrize("value,cause", [
    ("", None),          # 69 captures
    ("NULL", None),      # 22 captures - a literal string, not JSON null
    ("null", None),
    (None, None),
    (0, None),
    ("full", "bin full"),
    ("hallL", "hall sensor (L)"),
    ("hallB", "hall sensor (B)"),   # 16 captures, in no reference table
    ("wat", "wat"),                 # unrecognised -> verbatim, not swallowed
    (256, "code 256 (0x100)"),      # integer form, meaning unknown
    (128, "code 128 (0x80)"),
])
def test_decode_err_covers_every_observed_form(value, cause):
    assert decode.decode_err(value)[0] == cause


def test_decode_err_never_raises():
    for junk in ([], {}, object(), 1.5, True, False):
        decode.decode_err(junk)


def test_no_error_means_no_error():
    """All 22 captured code-5 events carry err="NULL". Reading that as a fault
    would stamp a cause on every healthy cleaning cycle."""
    assert decode.event_label("5", REAL_CONTENT["5"]) == "Auto cleaning completed"


def test_error_cause_reaches_the_label_without_needing_result_2():
    """The old rule only surfaced a cause when result == 2, which held in ZERO
    of 268 events -- so every reported fault was invisible."""
    assert "hall sensor (B)" in decode.event_label("1", REAL_CONTENT["1"])
    assert "hall sensor (B)" in decode.event_label("2", REAL_CONTENT["2"])


def test_opaque_integer_err_stays_out_of_the_label():
    """Both captured code-4 events carry err=256. Appending "code 256" would
    put an alarming suffix on a routine mechanism step while asserting a
    meaning we have no evidence for."""
    label = decode.event_label("4", REAL_CONTENT["4"])
    assert "256" not in label
    # ...but it is still visible in the decoded table.
    fields = {f.key: f for f in decode.decode_content("4", REAL_CONTENT["4"])}
    assert fields["err"].text == "code 256 (0x100)"
    assert fields["err"].grade == decode.UNKNOWN


# --- results and modes -----------------------------------------------------

def test_unmapped_result_stays_visible():
    """Values 5 and 7 occur in the captures and are outside the documented
    0..4. The old decoder bailed to a generic label, so a maintenance session
    that ended in result 5 read as a plain "Reset done"."""
    assert "result 5" in decode.event_label("7", REAL_CONTENT["7"])


@pytest.mark.parametrize("action,expected", [
    (0, "cleaning"), (2, "odor removal"), (9, "maintenance"),
])
def test_work_mode_qualifies_the_mechanism_label(action, expected):
    assert expected in decode.event_label("3", {"action": action}).lower()


def test_unmapped_work_mode_is_not_invented():
    assert decode.work_mode_name(99) is None
    assert "mode 99" in decode.event_label("3", {"action": 99}).lower()


# --- weights ---------------------------------------------------------------

@pytest.mark.parametrize("grams,text", [
    (2320, "2.32 kg"),   # a cat
    (10, "10 g"),        # its waste, in the same payload
    (0, "0 g"),
    ("2320", "2.32 kg"),  # string-typed numbers arrive too
    (999, "999 g"),
    (1000, "1.00 kg"),
])
def test_weight_promotes_to_kg_only_when_it_reads_better(grams, text):
    fields = {f.key: f for f in decode.decode_content("10", {"pet_weight": grams})}
    assert fields["pet_weight"].text == text


def test_weight_of_junk_does_not_raise():
    for junk in (None, "x", [], {}):
        decode.decode_content("10", {"pet_weight": junk})


# --- card summary ----------------------------------------------------------

def test_summary_bits_surface_confirmed_facts_only():
    assert decode.summary_bits("10", REAL_CONTENT["10"]) == ["waste 10 g"]
    # The fault cause is NOT repeated here; event_label already carries it.
    assert decode.summary_bits("1", REAL_CONTENT["1"]) == []


# --- per-category labelling ------------------------------------------------

def test_the_same_code_reads_differently_per_device_category():
    payload = {"start_time": 1784827076, "err": "hallB"}
    assert decode.event_label("2", payload, "t5").startswith("Error cleared")
    assert decode.event_label("2", {"id": 7, "day": 20260727}, "d4h") == "Feeding done"


def test_a_d4h_holding_back_a_meal_for_a_full_bowl_is_a_skip_not_a_failure():
    """Upstream issue #36: a D4H reports its surplus-control skip as
    `result: 8` with `err_code: 10`, and `result` alone reads as a failed
    dispense. The same `result` with any other `err_code` still does."""
    skip = {"manual": 0, "id": "s_20260916_48300", "real_amount": 0,
            "result": 8, "err_code": 10, "surplus_standard": 2}
    for event_type in ("feed_over", "2"):
        assert decode.event_label(event_type, skip, "d4h") == \
            "Feeding skipped (bowl not empty)"
    assert decode.event_label("feed_over", {**skip, "err_code": 8}, "d4h") == \
        "Feeding failed (nothing dispensed)"


def test_unknown_code_still_reads_as_something():
    assert decode.event_label("999", {}) == "Event 999"
    assert decode.event_label("", {}) == "Event"
    assert decode.event_label(None, None) == "Event"


# --- grades ----------------------------------------------------------------

def test_grades_are_from_the_known_set():
    allowed = set(codes.GRADES) | {decode.UNKNOWN}
    for event_type, content in REAL_CONTENT.items():
        for field in decode.decode_content(event_type, content):
            assert field.grade in allowed, f"{event_type}.{field.key}: {field.grade}"


# --- direction from state, for codes whose content cannot say -------------

LIGHT = {"start_time": 1785155078, "start_reason": 3, "result": 0,
         "err": "", "from_clear": 0}


def test_the_light_reports_the_same_payload_on_and_off():
    """The two manual presses captured from the panel are byte-identical
    apart from start_time, so no amount of content decoding can tell them
    apart. That is why `state_label` exists."""
    on = dict(LIGHT, start_time=1785155078)
    off = dict(LIGHT, start_time=1785155091)
    assert {k: v for k, v in on.items() if k != "start_time"} == \
           {k: v for k, v in off.items() if k != "start_time"}


def test_light_direction_comes_from_the_attached_state():
    on = decode.event_label("17", LIGHT, "t5", {"lightState": {"workProcess": 1, "workReason": 0}})
    off = decode.event_label("17", LIGHT, "t5", {"box": 0})   # no lightState
    assert on == "Manual light on"
    assert off == "Manual light off"


def test_an_auto_light_cycle_reads_the_same_way():
    auto = dict(LIGHT, start_reason=0, from_clear=1)
    assert decode.event_label("17", auto, "t5", {"lightState": {"workProcess": 1}}) == "Auto light on"
    assert decode.event_label("17", auto, "t5", {}) == "Auto light off"


def test_no_state_never_invents_a_direction():
    """A missing snapshot must degrade to the generic wording, not guess."""
    label = decode.event_label("17", LIGHT, "t5")
    assert "on" not in label.split() and "off" not in label.split()
    assert label == "Manual light cycle completed"


def test_direction_does_not_leak_into_other_codes():
    """Only a code carrying `state_label` consults the state."""
    state = {"lightState": {"workProcess": 1}}
    assert decode.event_label("5", {"start_reason": 0, "result": 0}, "t5", state) \
        == "Auto cleaning completed"


def test_result_4_is_a_full_bin_not_kitten_mode():
    """`4` arrives with `err: "full"` and nothing else, on two families.

    It used to render "canceled (kitten mode)" because that slot was borrowed
    as a lookup constant for `result == 3` + a `kitten` flag. A box that stops
    because its bin is full is not a box in kitten mode.
    """
    text, _ = decode._result_field(4)
    assert "kitten" not in text
    assert "full" in text


def test_kitten_mode_still_reads_off_result_3():
    """The case the borrowed slot existed for keeps working, on its own value."""
    label = decode.event_label(
        "5", {"start_reason": 2, "result": 3, "kitten": 1}, "t5")
    assert "kitten" in label
    assert decode.event_label("5", {"start_reason": 2, "result": 3}, "t5") \
        .endswith("canceled")


def test_a_result_outside_the_cleaning_table_is_not_dressed_up():
    """`ble_relay_over` sends 1, 2 and 6; `add_water_over` reaches 18.

    None of those mean what the cleaning table says, so an unmapped value has
    to stay a number rather than borrow a label.
    """
    for value in (6, 18):
        text, grade = decode._result_field(value)
        assert str(value) in text
        assert grade == decode.UNKNOWN
