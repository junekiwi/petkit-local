import json
from dataclasses import dataclass

from petkit_local.events import ingest


@dataclass
class _Dev:
    petkit_id: int
    device_type: str = "t5"


def test_classify_event_kind_from_event_type():
    assert ingest.classify_event_kind("pet_in") == "toilet_visit"
    assert ingest.classify_event_kind("pet_out") == "toilet_visit"
    assert ingest.classify_event_kind("clean_over") == "cleaning"
    assert ingest.classify_event_kind("error_start") == "error"
    assert ingest.classify_event_kind("feed_over") == "feeding"
    assert ingest.classify_event_kind("move_detect") == "motion"
    assert ingest.classify_event_kind("something_unknown") == "other"


def test_classify_event_kind_content_flags_take_priority():
    assert ingest.classify_event_kind("dynamicVideo", {"cvrEvent": True}) == "motion"
    assert ingest.classify_event_kind("", {"cleanEvent": True}) == "cleaning"
    # `toiletEvent` means the box was USED; `petEvent` alone only means the
    # pet was seen — an "appeared" episode carries petEvent=1/toiletEvent=0
    # throughout, so petEvent must not imply a visit.
    assert ingest.classify_event_kind("", {"toiletEvent": True}) == "toilet_visit"
    assert ingest.classify_event_kind("", {"petEvent": True}) == "pet"
    assert ingest.classify_event_kind("", {"petEvent": True, "toiletEvent": True}) == "toilet_visit"


def test_parse_event_report_form_urlencoded():
    form = ingest.parse_event_report_form(
        'eventType=pet_out&eventId=10000001_1784726595&content=%7B%22related_event%22%3A%221_10000001_1784726530%22%7D'
    )
    assert form["eventType"] == "pet_out"
    assert form["eventId"] == "10000001_1784726595"
    assert form["content"] == {"related_event": "1_10000001_1784726530"}


def test_parse_event_report_form_bare_json():
    form = ingest.parse_event_report_form('{"eventType": "pet_in", "eventId": "1"}')
    assert form == {"eventType": "pet_in", "eventId": "1"}


def test_parse_event_report_form_empty_and_garbage():
    assert ingest.parse_event_report_form("") == {}
    assert ingest.parse_event_report_form("   ") == {}


#: A D4's meal report, verbatim from PetKit's own traffic (fw 1.267, proxied
#: 2026-10-22): both fields wrapped in one more pair of unescaped quotes, and
#: the meal id an unquoted token inside.
D4_MEAL_REPORT = (
    'event_type=4&event_id=400017498_1792684834&timestamp=1792684839'
    '&content="{"start_time":1792684834,"id":s_20261022_64800,"day":20261022,'
    '"manual":0,"time":64838,"real_amount":10,"online_state":1,'
    '"completed_at":1792684839,"result":0,"err_code":0}"'
    '&state="{"err":{"DC":0,"sys":0,"rtc_c":0,"moto":0,"grat":0,"blk_f":0,'
    '"blk_d":0,"ir":0},"batV":4675,"DCV":5157,"runtime":16394,"ubat":0,'
    '"feeding":0,"other":"heap:113304,res:7,rl=871,wlp=10,tswd=0_0,boffw=1,'
    'won=0,inff=0,wres=0,valid:1,snxt:0,cntd:44961,rpts=2"}"'
)


def test_a_d4_meal_report_keeps_its_content_and_state():
    """Both fields used to decode to nothing, so a meal arrived with no amount,
    no result and no error code, and the feeder's state was never refreshed."""
    form = ingest.parse_event_report_form(D4_MEAL_REPORT)
    row = ingest.from_event_report(_Dev(petkit_id=400017498, device_type="d4"), form)
    assert row["event_kind"] == "feeding"
    content = json.loads(row["content_json"])
    assert content["id"] == "s_20261022_64800"
    assert (content["real_amount"], content["result"], content["err_code"]) == (10, 0, 0)
    assert json.loads(row["state_json"])["batV"] == 4675


def test_a_quoted_field_that_is_not_an_object_still_decodes_to_nothing():
    """The extra quotes are undone only to reach an object; a plain quoted
    string is not content."""
    form = ingest.parse_event_report_form('event_type=4&event_id=1_2&content="hello"')
    row = ingest.from_event_report(_Dev(petkit_id=1, device_type="d4"), form)
    assert row["content_json"] is None


def test_from_event_report_builds_row_and_extracts_state():
    # event_id is the SESSION key (see the real-capture tests below) — it
    # becomes related_event directly, and event_uid is event_id+event_type
    # so sibling reports in the same session don't collide/overwrite.
    dev = _Dev(petkit_id=7)
    form = {
        "eventType": "10",
        "eventId": "10000001_1784726595",
        "content": {"pet_weight": 2200, "time_in": 1784726530, "time_out": 1784726595},
        "state": {"sandPercent": 80},
    }
    row = ingest.from_event_report(dev, form)
    assert row["device_id"] == 7
    assert row["event_type"] == "10"
    assert row["event_uid"] == "10000001_1784726595:10"
    assert row["related_event"] == "10000001_1784726595"
    assert row["event_kind"] == "toilet_visit"
    assert row["source"] == "http"
    assert row["_state"] == {"sandPercent": 80}


def test_from_event_report_missing_fields_is_safe():
    dev = _Dev(petkit_id=1)
    row = ingest.from_event_report(dev, {})
    assert row["event_type"] == ""
    assert row["event_uid"] is None
    assert row["related_event"] is None
    assert row["event_kind"] == "other"


def test_from_mqtt_decodes_json_string_content():
    dev = _Dev(petkit_id=2)
    params = {"content": '{"related_event": "rel1", "pet_weight": 3000}'}
    row = ingest.from_mqtt(dev, "pet_out", params)
    # `content.related_event` is the CROSS-episode link, not this row's own
    # episode -- reading it as the latter is what left MQTT cards unparented.
    assert row["parent_event"] == "rel1"
    assert row["related_event"] is None  # no params.event_id in this frame
    assert row["source"] == "mqtt"
    assert row["event_kind"] == "toilet_visit"


def test_from_mqtt_reads_the_same_envelope_as_http():
    """An MQTT event frame carries `{XDevice, event_id, timestamp, content,
    state}` — the HTTP form over a different transport (live T5, 2026-07-29).
    So `event_id` is the session key and `event_uid` its dedup key, exactly as
    in `from_event_report`."""
    dev = _Dev(petkit_id=10000001)
    params = {
        "XDevice": "id=10000001&nonce=x&timestamp=1785276756&type=T5&sign=y",
        "event_id": "2_10000001_1785276736",
        "timestamp": 1785276756,
        "content": '{"img":"https://h/x","upload":1,"media":1,'
                   '"mark":1785276736,"start_time":1785276736}',
        "state": '{"sensor":{"weight":0}}',
    }
    row = ingest.from_mqtt(dev, "pet_detect", params)
    assert row["related_event"] == "2_10000001_1785276736"
    assert row["event_uid"] == "2_10000001_1785276736:pet_detect"
    assert row["parent_event"] is None          # an anchor links to nobody
    assert row["state_json"] == json.dumps({"sensor": {"weight": 0}})


def test_mqtt_detection_result_groups_with_its_pet_detect():
    """The reported bug: over MQTT, "Pet detected" and "Detection result" were
    two separate Timeline cards while the HTTP codes 20/24 were one.

    Verbatim frames from the live capture. The anchor's own `event_id` is the
    episode; the follow-up gets an `event_id` of its OWN and names the episode
    in `content.related_event`, so it attaches as a sub-event via the parent
    link rather than by sharing a key."""
    dev = _Dev(petkit_id=10000001)
    detect = ingest.from_mqtt(dev, "pet_detect", {
        "event_id": "2_10000001_1785276736",
        "content": '{"mark":1785276736,"start_time":1785276736,"media":1}',
    })
    discern = ingest.from_mqtt(dev, "pet_discern", {
        "event_id": "10000001_1785276796",
        "content": '{"related_event":"2_10000001_1785276736","count":1,'
                   '"area":8820,"score_info":[{"id":101392625,"score":48}]}',
    })
    detect.update(id=1, ts=1785276757.0, media=[])
    discern.update(id=2, ts=1785276797.0, media=[])

    sessions = ingest.group_sessions([detect, discern])
    assert len(sessions) == 1, [s["event_type"] for s in sessions]
    card = sessions[0]
    assert card["event_type"] == "pet_detect"
    assert [s["event_type"] for s in card["sub_events"]] == ["pet_discern"]


def test_a_manual_cleans_light_tail_folds_into_its_card():
    """One clean press must be ONE card.

    The illuminator reports twice per cleaning and the device files the "off"
    under its own event_id with no link back. After a VISIT-triggered clean the
    proximity pass already swept it into the visit card (26 of 30 in the
    reference corpus); a MANUAL clean has no visit, so it stranded into a
    second card reading only "light off". Timestamps and episode ids are
    verbatim from the T5 press that reported this."""
    dev = _Dev(petkit_id=10000001)
    cycle, tail = "10000001_1785278470", "10000001_1785278584"
    rows = []
    for i, (et, ep, ts) in enumerate((
        ("light_over", cycle, 1785278471.2),   # light on, inside the cycle
        ("work_start", cycle, 1785278477.5),
        ("clean_over", cycle, 1785278585.0),   # completion -> heads the card
        ("light_over", tail, 1785278585.1),    # light off, its OWN episode
    )):
        row = ingest.from_mqtt(dev, et, {"event_id": ep})
        row.update(id=i + 1, ts=ts, media=[])
        rows.append(row)

    sessions = ingest.group_sessions(rows)
    assert len(sessions) == 1, [s["event_type"] for s in sessions]
    assert sessions[0]["event_type"] == "clean_over"
    assert [s["event_type"] for s in sessions[0]["sub_events"]] == [
        "light_over", "work_start", "light_over"]


def test_a_distant_light_cycle_keeps_its_own_card():
    """The counterweight to the pass above: it must absorb a cycle's own tail,
    not any light report that happens to share the day. A solo light episode
    outside the window stays a card of its own rather than being back-dated
    into an unrelated cleaning."""
    dev = _Dev(petkit_id=10000001)
    rows = []
    for i, (et, ep, ts) in enumerate((
        ("work_start", "10000001_1785278470", 1785278477.5),
        ("clean_over", "10000001_1785278470", 1785278585.0),
        ("light_over", "10000001_1785279900", 1785279900.0),  # ~22min later
    )):
        row = ingest.from_mqtt(dev, et, {"event_id": ep})
        row.update(id=i + 1, ts=ts, media=[])
        rows.append(row)

    sessions = ingest.group_sessions(rows)
    assert len(sessions) == 2, [s["event_type"] for s in sessions]
    assert {s["event_type"] for s in sessions} == {"clean_over", "light_over"}


def test_mqtt_cleaning_cycle_is_one_card():
    """The same fix for cleaning: `work_start`, `clean_over` and `light_over`
    share one `event_id` (live capture), so they are one cycle. The completion
    step heads the card and the rest fold under it."""
    dev = _Dev(petkit_id=10000001)
    rows = []
    for i, et in enumerate(("light_over", "work_start", "clean_over")):
        row = ingest.from_mqtt(dev, et, {"event_id": "10000001_1785276612"})
        row.update(id=i + 1, ts=1785276612.0 + i, media=[])
        rows.append(row)

    sessions = ingest.group_sessions(rows)
    assert len(sessions) == 1, [s["event_type"] for s in sessions]
    assert sessions[0]["event_type"] == "clean_over"
    assert sorted(s["event_type"] for s in sessions[0]["sub_events"]) == [
        "light_over", "work_start"]


def test_from_file_info_requires_file_id():
    dev = _Dev(petkit_id=1)
    try:
        ingest.from_file_info(dev, {})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_from_file_info_maps_fields():
    dev = _Dev(petkit_id=1)
    info = {
        "fileId": "abc123", "eventId": "1_10000001_1784726530",
        "cycleType": "highLight", "fileType": "video",
        "encrypt": "1", "aesIv": "0x61616161616161616161616161616161",
        "startTime": "1784726530", "endTime": "1784726590",
        "size": "204800",
    }
    row = ingest.from_file_info(dev, info)
    assert row["file_id"] == "abc123"
    assert row["related_event"] == "1_10000001_1784726530"
    assert row["category"] == "highLight"
    assert row["encrypted"] == 1
    assert row["start_ts"] == 1784726530.0
    # Numeric columns are coerced, not passed through: the device sends `size`
    # (and `duration`) as decimal STRINGS, but media/retention.py sums
    # size_bytes and media/stitch.py sums duration_ms, and SQLite's dynamic
    # typing will happily keep text in an INTEGER column until one of those
    # sweepers hits it. This assertion used to pin the raw "204800" string,
    # which contradicted the already-coerced start_ts on the line above.
    assert row["size_bytes"] == 204800
    assert row["duration_ms"] is None


def test_from_event_report_skips_empty_alternative_spellings():
    # The device pads the spellings it didn't use rather than omitting them, so
    # scanning the alternatives must not stop at a null/empty one.
    dev = _Dev(petkit_id=3)
    row = ingest.from_event_report(dev, {
        "eventType": "", "event_type": "5",
        "eventId": None, "event_id": "10000001_1784726595",
    })
    assert row["event_type"] == "5"
    assert row["related_event"] == "10000001_1784726595"
    assert row["event_uid"] == "10000001_1784726595:5"


def test_from_file_info_rejects_unusable_timestamps():
    # start/end come off the wire as strings. A non-numeric one must become
    # NULL, and "1e400" must NOT become inf — an infinite start_ts poisons
    # every duration and retention comparison downstream and cannot be stored
    # as JSON either.
    dev = _Dev(petkit_id=1)
    row = ingest.from_file_info(dev, {
        "fileId": "f1", "startTime": "not a time", "endTime": "1e400",
    })
    assert row["start_ts"] is None
    assert row["end_ts"] is None


def test_cleaning_label_decodes_string_typed_result_fields():
    # result/start_reason arrive as JSON numbers on a real T5, but a string
    # form must decode identically — the label is the only thing the Timeline
    # shows for a cleaning cycle.
    assert ingest.cleaning_label("5", {"result": 0, "start_reason": 2}) == "Manual cleaning completed"
    assert ingest.cleaning_label("5", {"result": "0", "start_reason": "2"}) == "Manual cleaning completed"
    assert ingest.cleaning_label("5", {"result": 2, "err": "full"}) == "Cleaning failed - bin full"
    # No decodable result -> the plain static label, never invented wording.
    assert ingest.cleaning_label("5", {"result": "n/a"}) == "Cleaning done"
    assert ingest.cleaning_label("5", {}) == "Cleaning done"
    # Code 8 is the DEODORIZING cycle's completion, not a cleaning start: it
    # co-occurs with action=2 (odor removal) in 23 of 23 captured episodes and
    # never with any other mode, and the firmware packs it in
    # pk_event_pack_spray_and_liquid_reset_over. The old "Cleaning started"
    # was a guess from before either source was checked.
    assert ingest.cleaning_label("8", {"result": 0, "start_reason": 0}) \
        == "Auto deodorizing completed"


def _ev(id, device_id, ts, event_type, event_kind, related_event=None, media=None,
        content=None, parent_event=None, pet_id=None):
    return {
        "id": id, "device_id": device_id, "ts": ts, "event_type": event_type,
        "event_kind": event_kind, "related_event": related_event,
        "parent_event": parent_event,
        "media": media or [], "content_json": None if content is None else __import__("json").dumps(content),
        "pet_id": pet_id,
    }


def test_a_session_takes_pet_identity_from_an_attached_sub_event():
    """An "appeared" card is anchored by code 20, which carries no identity —
    the recognition arrives on code 24, a detail code that can never head a
    card. Without the fill-up the cat is named on visits and anonymous on
    every sighting."""
    events = [
        _ev(1, 100, 1000.0, "20", "pet", related_event="e20"),
        _ev(2, 100, 1010.0, "24", "pet", related_event="e24",
            parent_event="e20", pet_id=7),
    ]
    sessions = ingest.group_sessions(events)
    assert len(sessions) == 1
    assert sessions[0]["event_type"] == "20"
    assert sessions[0]["pet_id"] == 7
    # the line itself stays identity-free; only the card gets it
    assert "pet_id" not in sessions[0]["sub_events"][0]


def test_an_anchor_identity_is_not_overwritten_by_a_sub_event():
    events = [
        _ev(1, 100, 1000.0, "20", "pet", related_event="e20", pet_id=7),
        _ev(2, 100, 1010.0, "24", "pet", related_event="e24",
            parent_event="e20", pet_id=9),
    ]
    assert ingest.group_sessions(events)[0]["pet_id"] == 7


def test_group_sessions_pairs_pet_in_and_pet_out():
    events = [
        _ev(1, 1, 100.0, "pet_in", "toilet_visit", related_event="r1"),
        _ev(2, 1, 156.0, "pet_out", "toilet_visit", related_event="r1", content={"pet_weight": 2200}),
    ]
    sessions = ingest.group_sessions(events)
    assert len(sessions) == 1
    s = sessions[0]
    assert s["kind"] == "visit"
    assert s["id"] == 2  # anchored on pet_out
    assert s["duration_sec"] == 56.0
    assert s["weight"] == 2200.0


def test_group_sessions_falls_back_to_ts_pairing_on_unusable_time_fields():
    # An undecodable time_in/time_out pair must not yield a bogus duration —
    # it falls through to the pet_in/pet_out timestamp pairing, as before.
    events = [
        _ev(1, 1, 100.0, "pet_in", "toilet_visit", related_event="r1"),
        _ev(2, 1, 156.0, "pet_out", "toilet_visit", related_event="r1",
            content={"time_in": "x", "time_out": "y", "pet_weight": "2200"}),
    ]
    s = ingest.group_sessions(events)[0]
    assert s["duration_sec"] == 56.0
    assert s["weight"] == 2200.0   # string weights off the wire still decode


def test_group_sessions_attaches_nearby_cleaning_as_sub_event():
    events = [
        _ev(1, 1, 100.0, "pet_out", "toilet_visit", related_event="r1"),
        _ev(2, 1, 160.0, "clean_over", "cleaning"),
        _ev(3, 1, 5000.0, "clean_over", "cleaning"),  # too far away — standalone
    ]
    sessions = ingest.group_sessions(events)
    visit = next(s for s in sessions if s["kind"] == "visit")
    assert [e["id"] for e in visit["sub_events"]] == [2]
    standalone_ids = {s["id"] for s in sessions if s["kind"] == "event"}
    assert 3 in standalone_ids
    assert 2 not in standalone_ids


def test_group_sessions_passes_through_unrelated_events():
    events = [_ev(1, 1, 100.0, "move_detect", "motion")]
    sessions = ingest.group_sessions(events)
    assert len(sessions) == 1
    assert sessions[0]["kind"] == "event"
    assert sessions[0]["event_kind"] == "motion"


def test_group_sessions_loose_toilet_event_without_related_event():
    events = [_ev(1, 1, 100.0, "pet_out", "toilet_visit", related_event=None)]
    sessions = ingest.group_sessions(events)
    assert len(sessions) == 1
    assert sessions[0]["kind"] == "visit"
    assert sessions[0]["duration_sec"] is None


def test_event_type_label_known_and_unknown_codes():
    assert ingest.event_type_label("10") == "Toilet visit"
    assert ingest.event_type_label("8") == "Deodorizing"
    assert ingest.event_type_label("pet_out") == "Pet left"
    assert ingest.event_type_label("999") == "Event 999"
    assert ingest.event_type_label("") == "Event"
    assert ingest.event_type_label(None) == "Event"


def test_cleaning_media_never_leaks_into_the_visit():
    """A cleaning cycle's media belongs to the cleaning, not to the visit —
    mixing them is what made photos appear under the wrong event."""
    visit_photo = {"category": "eventImage", "file_id": "v1"}
    cleaning_video = {"category": "fullVideo", "file_id": "c1"}
    cleaning_waste = {"category": "wasteCheck", "file_id": "c2"}
    events = [
        _ev(1, 1, 100.0, "pet_out", "toilet_visit", related_event="r1", media=[visit_photo]),
        _ev(2, 1, 160.0, "clean_over", "cleaning", related_event="r2",
            media=[cleaning_video, cleaning_waste]),
    ]
    sessions = ingest.group_sessions(events)
    visit = next(s for s in sessions if s["kind"] == "visit")

    assert visit["media"] == [visit_photo]
    for leaked in (cleaning_video, cleaning_waste):
        assert leaked not in visit["media"]
    # ...it rides on the cleaning sub-event instead
    sub = visit["sub_events"][0]
    assert cleaning_waste in sub["media"] and cleaning_video in sub["media"]


def test_episode_media_lands_on_one_line_only():
    """Several steps share a cleaning episode; the gallery must not repeat on
    each of them. It goes on the completion step (type "5")."""
    waste = {"category": "wasteCheck", "file_id": "w1"}
    events = [
        _ev(1, 1, 100.0, "10", "toilet_visit", related_event="visit"),
        _ev(2, 1, 110.0, "3", "cleaning", related_event="ep", parent_event="visit", media=[waste]),
        _ev(3, 1, 120.0, "5", "cleaning", related_event="ep", parent_event="visit", media=[waste]),
        _ev(4, 1, 130.0, "17", "cleaning", related_event="ep", parent_event="visit"),
    ]
    sessions = ingest.group_sessions(events)
    subs = sessions[0]["sub_events"]
    carriers = [s for s in subs if s["media"]]
    assert len(carriers) == 1
    assert carriers[0]["event_type"] == "5"


def test_sub_events_are_flagged_primary_vs_detail():
    events = [
        _ev(1, 1, 100.0, "10", "toilet_visit", related_event="visit"),
        _ev(2, 1, 110.0, "3", "cleaning", related_event="ep", parent_event="visit"),
        _ev(3, 1, 120.0, "5", "cleaning", related_event="ep", parent_event="visit"),
    ]
    subs = {s["event_type"]: s for s in ingest.group_sessions(events)[0]["sub_events"]}
    assert subs["3"]["detail"] is True     # mechanism noise, collapsed in the UI
    assert subs["5"]["detail"] is False    # completion, always shown


def test_filter_counts_and_matches_filter():
    """Pet and Toileting are disjoint, as in the official app. A device fault is
    a FAULT, not a health alert — that chip is about the cat."""
    sessions = [
        {"event_kind": "toilet_visit", "pet_id": None},
        {"event_kind": "error", "pet_id": None},
        {"event_kind": "pet", "pet_id": None},
    ]
    counts = ingest.filter_counts(sessions)
    assert counts == {"all": 3, "pet": 1, "toileting": 1, "drinking": 0,
                      "feeding": 0, "cleaning": 0, "health_alert": 0, "fault": 1}

    assert ingest.matches_filter(sessions[0], "toileting") is True
    assert ingest.matches_filter(sessions[1], "toileting") is False
    # a real visit is NOT also counted as "pet"
    assert ingest.matches_filter(sessions[0], "pet") is False
    assert ingest.matches_filter(sessions[2], "pet") is True
    assert ingest.matches_filter(sessions[1], "fault") is True
    assert ingest.matches_filter(sessions[1], "health_alert") is False
    assert ingest.matches_filter(sessions[0], "all") is True


def test_a_yowling_visit_is_both_a_visit_and_a_health_alert():
    """PetKit frames meowing in the box as a possible sign of discomfort, so it
    belongs under the health chip without ceasing to be a toilet visit."""
    quiet = {"event_kind": "toilet_visit", "content": {"petVoice": 0}}
    yowled = {"event_kind": "toilet_visit", "content": {"petVoice": 1}}
    assert ingest.filter_counts([quiet, yowled]) == {
        "all": 2, "pet": 0, "toileting": 2, "drinking": 0, "feeding": 0,
        "cleaning": 0, "health_alert": 1, "fault": 0}
    assert ingest.matches_filter(yowled, "toileting") is True
    assert ingest.matches_filter(yowled, "health_alert") is True
    assert ingest.matches_filter(quiet, "health_alert") is False


def test_from_file_info_coerces_numeric_columns():
    # duration/size come off the wire as strings and feed arithmetic in two
    # background sweepers (media/stitch.py sums duration_ms,
    # media/retention.py sums size_bytes). SQLite's dynamic typing stores text
    # in an INTEGER column without complaint, so an uncoerced value only
    # surfaces later, far from the request that caused it.
    dev = _Dev(petkit_id=1)
    row = ingest.from_file_info(dev, {
        "fileId": "f1", "duration": "4000", "size": "204800",
    })
    assert row["duration_ms"] == 4000
    assert row["size_bytes"] == 204800

    bad = ingest.from_file_info(dev, {
        "fileId": "f2", "duration": "4000ms", "size": "1e400",
    })
    assert bad["duration_ms"] is None
    assert bad["size_bytes"] is None


def test_the_visits_own_media_is_not_repeated_on_a_sub_event():
    """The weight sample shares the visit's event_id, so once sibling steps
    started rendering it was handed the card's own recording a second time --
    the same video appeared at the top of the card and again beside
    "Weight check". Episode media belongs to a LINE only when the episode is
    not the card's own.
    """
    video = {"category": "fullVideo", "status": "ready", "media_path": "/v.mp4",
             "stitch_state": "stitched", "created_at": 0}
    visit = _ev(1, 1, 1000.0, "10", "toilet_visit", related_event="v", media=[video])
    sample = _ev(2, 1, 995.0, "9", "toilet_visit", related_event="v", media=[video])

    card = ingest.group_sessions([visit, sample])[0]
    assert card["media"] == [video]
    assert [s["event_type"] for s in card["sub_events"]] == ["9"]
    assert card["sub_events"][0]["media"] == [], "the card's own video was duplicated"


def test_a_cleaning_episodes_media_still_lands_on_its_line():
    """The guard above must not stop a DIFFERENT episode's media attaching."""
    waste = {"category": "wasteCheck", "status": "ready", "media_path": "/w.jpg",
             "created_at": 0}
    visit = _ev(1, 1, 1000.0, "10", "toilet_visit", related_event="v")
    done = _ev(2, 1, 1100.0, "5", "cleaning", related_event="c", parent_event="v",
               media=[waste])
    card = ingest.group_sessions([visit, done])[0]
    assert card["media"] == []
    assert card["sub_events"][0]["media"] == [waste]


def test_a_visit_is_shown_at_the_time_the_pet_entered():
    """A visit is anchored on the pet_out summary, which the device can only
    send once the visit is over -- so the anchor's arrival `ts` is the END,
    plus three to five seconds of report latency. Showing that put the card's
    header LATER than the steps listed under it.
    """
    visit = _ev(1, 1, 2000.0, "10", "toilet_visit", related_event="v",
                content={"time_in": 1900, "time_out": 1995, "pet_weight": 2000})
    card = ingest.group_sessions([visit])[0]
    assert card["display_ts"] == 1900          # the pet entered
    assert card["ts"] == 2000.0                # arrival is untouched
    assert card["duration_sec"] == 95


def test_bucketing_and_ordering_still_key_off_arrival_time():
    """`ts` must not move: the day window, the newest-first sort and the
    sub-event proximity window all use it, so changing it would shift events
    between days."""
    early = _ev(1, 1, 5000.0, "10", "toilet_visit", related_event="a",
                content={"time_in": 1, "time_out": 2})       # ancient time_in
    late = _ev(2, 1, 6000.0, "10", "toilet_visit", related_event="b",
               content={"time_in": 5990, "time_out": 5999})
    ids = [s["id"] for s in ingest.group_sessions([early, late])]
    assert ids == [2, 1], "sort order must follow ts, not display_ts"


def test_display_time_falls_back_when_the_device_reports_no_span():
    # MQTT pairing: no time_in field, but a pet_in event carries the entry.
    pet_in = _ev(1, 1, 1000.0, "pet_in", "toilet_visit", related_event="v")
    pet_out = _ev(2, 1, 1100.0, "pet_out", "toilet_visit", related_event="v")
    card = ingest.group_sessions([pet_in, pet_out])[0]
    assert card["display_ts"] == 1000.0

    # Nothing at all to go on -> arrival time, never None.
    bare = _ev(1, 1, 1234.0, "10", "toilet_visit", related_event="v")
    assert ingest.group_sessions([bare])[0]["display_ts"] == 1234.0


def test_a_feeding_heads_its_own_card_with_its_start_folded_in():
    """`feed_start` and `feed_over` share an `event_id`, so they are one meal.

    Grouping begins at the anchors, and feeding was not among the kinds allowed
    to anchor — so on a feeder every event fell through to a flat standalone
    row and `related_event` went unused, even though `codes.py` had marked
    `feed_over` an anchor all along.
    """
    ep = "300004258_1786227910"
    rows = [
        _ev(1, 7, 1786227913, "feed_start", "feeding", related_event=ep,
            content={"id": "r_20260808_80712_80712-1", "time": 80709}),
        _ev(2, 7, 1786227916, "feed_over", "feeding", related_event=ep,
            content={"start_time": 1786227910, "result": 0, "real_amount2": 1}),
    ]
    sessions = ingest.group_sessions(rows)
    assert len(sessions) == 1, "a meal split into unrelated rows"
    assert sessions[0]["event_kind"] == "feeding"
    assert [s["id"] for s in sessions[0]["sub_events"]] == [1]


def test_a_card_is_headed_by_the_DEVICE_time_not_our_arrival():
    """`ts` is when the report reached us; `start_time` is when it happened.

    Measured on a reported T6: both `start_time` and `mark` said 14:19:58 while
    the card said 14:20:19 — 21 seconds of network and ingest presented as the
    moment the cat was seen. Only a toilet visit carries `time_in`, so looking
    for that alone left every other kind of card showing arrival.
    """
    rows = [_ev(1, 7, 1786450819, "pet_detect", "motion",
                related_event="7_30000005_1786450798",
                content={"start_time": 1786450798, "mark": 1786450798})]
    assert ingest.group_sessions(rows)[0]["display_ts"] == 1786450798


def test_feeding_drinking_and_cleaning_are_filterable():
    """Each had no bucket at all, so a feeder's and a fountain's cards showed
    under "All" and were reachable from no other chip — a water refill could
    only be found by scrolling past it."""
    rows = [{"event_kind": k} for k in ("feeding", "drinking", "cleaning")]
    counts = ingest.filter_counts(rows)
    assert counts["feeding"] == counts["drinking"] == counts["cleaning"] == 1
    for row, chip in zip(rows, ("feeding", "drinking", "cleaning"), strict=True):
        assert ingest.matches_filter(row, chip) is True
        assert ingest.matches_filter(row, "toileting") is False
