"""Regression tests built from a real T5 --capture (2026-07-22, device
id=10000001, firmware 943) — one full toilet-visit + cleaning cycle. These
lock in the bug found live: multiple *distinct* dev_event_report event_types
share the same top-level `event_id` (it's a session key, not a per-report
unique id), which used to make EventStore.upsert_event's dedup silently
overwrite earlier reports in the same session. See events/ingest.py's module
docstring and CLAUDE.md's "Known limitations" for what's confirmed vs. still
inferred.
"""
from dataclasses import dataclass

from petkit_local.events import ingest

REAL_EVENT_REPORTS = [
    # "9": mid-visit weight sample
    {"event_type": "9", "event_id": "4_10000001_1784736135",
     "content": {"pet_weight": 2128, "mark": 1784736135}},
    # "10": visit summary — the session's anchor, carries time_in/time_out
    {"event_type": "10", "event_id": "4_10000001_1784736135",
     "content": {"time_in": 1784736141, "time_out": 1784736158, "is_shit": 1,
                 "pet_weight": 2128, "count": 1, "score_info": [{"id": 101392625, "score": 116}]}},
    # "3": mechanism action, paired with the first cleaning episode
    {"event_type": "3", "event_id": "10000001_1784736169",
     "content": {"pos": 0, "reason": 0, "item_id": 0, "action": 2}},
    # "8": cleaning start — relate_event cross-references the visit's event_id
    {"event_type": "8", "event_id": "10000001_1784736169",
     "content": {"start_time": 1784736169, "result": 0, "err": "",
                 "relate_event": "4_10000001_1784736135", "clean_flag": 1}},
    # "17": second cleaning episode
    {"event_type": "17", "event_id": "10000001_1784736194",
     "content": {"start_time": 1784736194, "result": 0, "err": "", "from_clear": 1}},
    # "3" again, different session — the mechanism action closing the cycle
    {"event_type": "3", "event_id": "10000001_1784736194",
     "content": {"pos": 0, "reason": 0, "item_id": 0, "action": 0}},
]


@dataclass
class _Dev:
    petkit_id: int = 10000001
    device_type: str = "t5"


def _form(rec):
    return {"eventType": rec["event_type"], "eventId": rec["event_id"], "content": rec["content"]}


def _ev(id, device_id, ts, event_type, event_kind, related_event=None,
        parent_event=None, media=None, content=None):
    """A stored-event row as `query_timeline` hands it to `group_sessions`."""
    import json as _json
    return {
        "id": id, "device_id": device_id, "ts": ts, "event_type": event_type,
        "event_kind": event_kind, "related_event": related_event,
        "parent_event": parent_event, "media": media or [],
        "content_json": None if content is None else _json.dumps(content),
        "pet_id": None,
    }


def test_classify_numeric_event_type_codes():
    assert ingest.classify_event_kind("9") == "toilet_visit"
    assert ingest.classify_event_kind("10") == "toilet_visit"
    assert ingest.classify_event_kind("8") == "cleaning"
    assert ingest.classify_event_kind("17") == "cleaning"
    assert ingest.classify_event_kind("3") == "cleaning"
    assert ingest.classify_event_kind("99") == "other"  # unknown code, safe fallback


def test_from_event_report_uses_event_id_as_session_key():
    dev = _Dev()
    row9 = ingest.from_event_report(dev, _form(REAL_EVENT_REPORTS[0]))
    row10 = ingest.from_event_report(dev, _form(REAL_EVENT_REPORTS[1]))
    assert row9["related_event"] == row10["related_event"] == "4_10000001_1784736135"
    assert row9["event_uid"] != row10["event_uid"]  # distinct dedup keys


def test_from_event_report_extracts_list_shaped_score_info():
    dev = _Dev()
    row = ingest.from_event_report(dev, _form(REAL_EVENT_REPORTS[1]))
    assert row["score"] == 116


def test_from_event_report_keeps_the_reported_identity():
    """`score_info[].id` is the pet id we handed out in dev_discern_pic — the
    firmware copies it from the outer list entry. It used to be discarded,
    which is why nothing was ever attributed to a pet."""
    dev = _Dev()
    row = ingest.from_event_report(dev, _form(REAL_EVENT_REPORTS[1]))
    assert row["pet_ref"] == 101392625
    # transport does not decide who that is — resolution needs the pets table
    assert "pet_id" not in row


def test_pet_ref_falls_back_to_the_legacy_petid_key():
    dev = _Dev()
    row = ingest.from_event_report(dev, _form(
        {"event_type": "10", "event_id": "e1", "content": {"petId": 7}}))
    assert row["pet_ref"] == 7


def test_pet_ref_and_score_take_the_best_match_not_the_first():
    """The firmware builds score_info as an array with no ordering we could
    confirm, so "first" is only right in a one-cat household."""
    dev = _Dev()
    row = ingest.from_event_report(dev, _form({
        "event_type": "10", "event_id": "e1",
        "content": {"score_info": [{"id": 1, "score": 40}, {"id": 2, "score": 900}]}}))
    assert (row["pet_ref"], row["score"]) == (2, 900)


def test_an_empty_score_info_reports_no_identity():
    """31 of 33 captured code-24 events look exactly like this: an animal was
    detected, nobody was recognised."""
    dev = _Dev()
    row = ingest.from_event_report(dev, _form(
        {"event_type": "24", "event_id": "e1",
         "content": '{"related_event":3_10000001_1784741818,"count":1,"area":25181,"score_info":[]}'}))
    assert row["pet_ref"] is None
    assert row["score"] is None
    # ...and the malformed-JSON repair still recovered the parent link
    assert row["parent_event"] == "3_10000001_1784741818"


async def test_upsert_event_no_longer_collapses_sibling_reports_in_one_session(event_store):
    """The actual bug: 6 real reports collapsing to 3 stored rows because
    "9"+"10" (and "3"+"8", and "17"+"3") shared one event_id."""
    store = event_store
    dev = _Dev()
    for rec in REAL_EVENT_REPORTS:
        row = ingest.from_event_report(dev, _form(rec))
        row.pop("_state", None)
        row.pop("_content", None)
        await store.upsert_event(row)

    rows = await store.query_timeline(device_id=dev.petkit_id, limit=100)
    assert len(rows) == len(REAL_EVENT_REPORTS), \
        "every distinct event_type report must survive, even when event_id repeats"
    event_types_stored = sorted(r["event_type"] for r in rows)
    assert event_types_stored == ["10", "17", "3", "3", "8", "9"]


async def test_group_sessions_from_real_capture_forms_one_visit_with_cleaning_sub_events(event_store):
    store = event_store
    dev = _Dev()
    for rec in REAL_EVENT_REPORTS:
        row = ingest.from_event_report(dev, _form(rec))
        row.pop("_state", None)
        row.pop("_content", None)
        await store.upsert_event(row)

    rows = await store.query_timeline(device_id=dev.petkit_id, limit=100)
    sessions = ingest.group_sessions(rows)

    visits = [s for s in sessions if s["kind"] == "visit"]
    assert len(visits) == 1, f"expected exactly one visit session, got {len(visits)}: {sessions}"
    visit = visits[0]
    assert visit["event_type"] == "10"  # anchored on the visit-summary report
    assert visit["duration_sec"] == 17.0  # time_out(1784736158) - time_in(1784736141)
    assert visit["weight"] == 2128.0

    # The four cleaning-family reports (3, 8, 17, 3) attach as sub-events
    # rather than standalone rows, since they're within the sub-event time
    # window -- and so does the "9" weight sample. "9" shares the visit's
    # event_id with the "10" that anchors the card, and group_sessions used
    # to mark every member of the anchor's episode used while rendering
    # only the anchor, which silently discarded all 23 weight samples in
    # the reference corpus.
    sub_event_types = sorted(e["event_type"] for e in visit["sub_events"])
    assert sub_event_types == ["17", "3", "3", "8", "9"]

    standalone = [s for s in sessions if s["kind"] == "event"]
    assert standalone == [], f"nothing should be left standalone: {standalone}"


def test_resolve_category_from_module_type_real_values():
    dev = _Dev()
    for module_type, expected in [
        ("CLOUD_STORAGE", "fullVideo"),
        # NOT fullVideo — it's the 528x528/20fps silent substream, ffprobed
        # on real files; mixing it with the 1056x1056/25fps main stream would
        # stitch into garbage.
        ("CLOUD_DOUBLE", "cloudDouble"),
        ("EVENT_PREVIEW", "eventImage"), ("EVENT_VIDEO", "dynamicVideo"),
    ]:
        info = {"fileId": "x", "moduleType": module_type, "eventId": "e1"}
        row = ingest.from_file_info(dev, info)
        assert row["category"] == expected, f"{module_type} -> expected {expected}, got {row['category']}"


def test_cloud_double_is_not_an_sts_capability():
    """It must not be gated by the capability toggles — the device never
    negotiates it by name, so treating it as a disabled capability would
    silently discard every substream upload."""
    from petkit_local.devices.base import Device
    assert ingest.CATEGORY_CLOUD_DOUBLE not in Device.CAPABILITY_TYPES


def test_parent_event_extracted_from_relate_event():
    dev = _Dev()
    row = ingest.from_event_report(dev, _form(REAL_EVENT_REPORTS[3]))  # type "8"
    assert row["parent_event"] == "4_10000001_1784736135"
    assert row["related_event"] == "10000001_1784736169"  # its OWN episode


def test_cleaning_attaches_to_visit_via_explicit_parent_link_not_timing():
    """The device says which visit a cleaning belongs to; grouping must use
    that rather than the ±window fallback. Timestamps here are deliberately
    far apart so a timing-only implementation would fail this."""
    visit = _ev(1, 1, 1000.0, "10", "toilet_visit", related_event="visitA")
    # cleaning episode, hours later, but explicitly linked to visitA
    clean_linked = _ev(2, 1, 90000.0, "8", "cleaning",
                       related_event="epB", parent_event="visitA")
    clean_sibling = _ev(3, 1, 90005.0, "3", "cleaning", related_event="epB")
    sessions = ingest.group_sessions([visit, clean_linked, clean_sibling])

    visits = [s for s in sessions if s["kind"] == "visit"]
    assert len(visits) == 1
    # both the linked event AND its episode sibling (which carries no link of
    # its own) attach to the visit
    assert sorted(e["id"] for e in visits[0]["sub_events"]) == [2, 3]
    assert [s for s in sessions if s["kind"] == "event"] == []


def test_type_5_cleaning_done_is_not_a_standalone_card():
    """Regression: event_type "5" used to fall outside the cleaning set, so
    it rendered as its own bare "Event 5" card next to the visit."""
    assert ingest.classify_event_kind("5") == "cleaning"
    assert ingest.event_type_label("5") == "Cleaning done"

    visit = _ev(1, 1, 1000.0, "10", "toilet_visit", related_event="visitA")
    done = _ev(2, 1, 1100.0, "5", "cleaning", related_event="epB", parent_event="visitA")
    sessions = ingest.group_sessions([visit, done])
    assert [s for s in sessions if s["kind"] == "event"] == []
    assert [e["id"] for e in sessions[0]["sub_events"]] == [2]


def test_resolve_category_unknown_module_type_is_empty_not_crash():
    dev = _Dev()
    info = {"fileId": "x", "moduleType": "SOMETHING_NEW", "eventId": "e1"}
    row = ingest.from_file_info(dev, info)
    assert row["category"] == ""


async def test_backfill_repairs_stale_event_kind_and_parent_link(event_store):
    """Rows stored before a code was recognised keep a stale event_kind, so
    they never attach to their visit. The backfill must repair them from the
    untouched content_json."""
    import json

    store = event_store
    # as an older version would have written it: type "5" unrecognised,
    # no parent_event column value, related_event lost
    await store.upsert_event({
        "event_uid": "10000001_1784737195", "related_event": None,
        "device_id": 1, "event_type": "5", "event_kind": "other", "ts": 100.0,
        "content_json": json.dumps({"relate_event": "visitA", "clean_weight": 0}),
    })
    fixed = await ingest.backfill_event_rows(store)
    assert fixed == 1

    row = (await store.query_timeline(device_id=1))[0]
    assert row["event_kind"] == "cleaning"
    assert row["parent_event"] == "visitA"
    assert row["related_event"] == "10000001_1784737195"

    # idempotent — a second run changes nothing
    assert await ingest.backfill_event_rows(store) == 0


async def test_backfill_leaves_correct_rows_untouched(event_store):
    import json

    store = event_store
    await store.upsert_event({
        "event_uid": "e:10", "related_event": "e", "parent_event": None,
        "device_id": 1, "event_type": "10", "event_kind": "toilet_visit", "ts": 1.0,
        "content_json": json.dumps({"pet_weight": 2000}),
    })
    assert await ingest.backfill_event_rows(store) == 0


# --- "appeared" motion events (types 20/24), captured 2026-07-22 ------------
# Verbatim except for the bucket host in `img`, replaced with the RFC 5737
# documentation address so no real LAN address is committed to a public repo.

REAL_MOTION_REPORTS = [
    # "20": the detection itself — a still + a start time, nothing else
    {"event_type": "20", "event_id": "4_10000001_1784743819",
     "content": {"img": "https://192.0.2.1/petkit-local/t5/10000001/even/20_216EVENT_PREVIEW1784743822",
                 "aesKey": "83359820a8a860dc", "mark": 1784743819,
                 "start_time": 1784743819, "upload": 1, "media": 1}},
    # "24": the result for it. NOTE the device emits INVALID JSON here —
    # `related_event` value is an unquoted bare token.
    {"event_type": "24", "event_id": "10000001_1784743889",
     "content": '{"related_event":4_10000001_1784743819,"count":1,'
                '"area":428314,"score_info":[{"id":101392625,"score":48}]}'},
]


def test_malformed_json_content_is_repaired_not_discarded():
    """The unquoted value made json.loads fail, so the whole content — parent
    link, pet score, area — was silently dropped."""
    import json as _json
    raw = REAL_MOTION_REPORTS[1]["content"]
    try:
        _json.loads(raw)
        assert False, "fixture should be invalid JSON"
    except _json.JSONDecodeError:
        pass

    parsed = ingest._as_dict(raw)
    assert parsed["related_event"] == "4_10000001_1784743819"
    assert parsed["count"] == 1
    assert parsed["area"] == 428314
    assert parsed["score_info"][0]["score"] == 48


def test_repair_never_invents_content_for_truly_broken_json():
    assert ingest._as_dict('{"a": ') == {}
    assert ingest._as_dict("not json at all") == {}


def test_repair_leaves_valid_json_untouched():
    assert ingest._as_dict('{"a": 1, "b": "x", "c": true, "d": null}') == {
        "a": 1, "b": "x", "c": True, "d": None}


def test_motion_codes_are_classified_and_labelled():
    # A pet episode, NOT a toilet visit and not generic motion: every chunk
    # carries petEvent=1 with toiletEvent=0 and cvrEvent=0.
    assert ingest.classify_event_kind("20") == "pet"
    assert ingest.classify_event_kind("24") == "pet"
    assert ingest.event_type_label("20") == "Appeared"
    assert ingest.is_detail_event("24") is True   # folded under the card
    assert ingest.is_detail_event("20") is False


def test_appeared_event_becomes_its_own_card_with_the_result_attached():
    """Previously these rendered as two bare "Event 20"/"Event 24" rows."""
    dev = _Dev()
    rows = []
    for i, rec in enumerate(REAL_MOTION_REPORTS, start=1):
        r = ingest.from_event_report(dev, _form(rec))
        r.pop("_state", None); r.pop("_content", None)
        r["id"] = i
        r["media"] = []
        rows.append(r)

    sessions = ingest.group_sessions(rows)
    assert len(sessions) == 1, f"expected one card, got {sessions}"
    card = sessions[0]
    assert card["kind"] == "pet"
    assert card["event_type"] == "20"
    assert card["duration_sec"] is None and card["weight"] is None
    assert [s["event_type"] for s in card["sub_events"]] == ["24"]


# --- HEALTH_PRED (6th moduleType) + rich cleaning labels -------------------

def test_health_pred_maps_to_health_category_under_event_image_capability():
    dev = _Dev()
    row = ingest.from_file_info(dev, {"fileId": "h", "moduleType": "HEALTH_PRED",
                                      "fileType": "jpeg", "eventId": "e1"})
    assert row["category"] == ingest.CATEGORY_HEALTH
    # rides the eventImage capability (the device negotiates no "healthPic")
    assert ingest.capability_for_category(ingest.CATEGORY_HEALTH) == "eventImage"


def test_all_firmware_module_types_are_mapped():
    """The firmware emits exactly these six; none should fall through to an
    uncategorised 'Other' file."""
    dev = _Dev()
    for mt in ("CLOUD_STORAGE", "CLOUD_DOUBLE", "EVENT_PREVIEW", "EVENT_VIDEO",
               "SHIT_PICTURE", "HEALTH_PRED"):
        row = ingest.from_file_info(dev, {"fileId": "x", "moduleType": mt, "eventId": "e"})
        assert row["category"], f"{mt} is unmapped"


def test_cleaning_label_decodes_reason_and_result():
    # our real type-5 content shape: start_reason=0 (auto), result=0 (completed)
    assert ingest.cleaning_label("5", {"start_reason": 0, "result": 0}) == "Auto cleaning completed"
    assert ingest.cleaning_label("5", {"start_reason": 2, "result": 3}) == "Manual cleaning canceled"
    assert ingest.cleaning_label("5", {"start_reason": 1, "result": 1}) == "Periodic cleaning terminated"


def test_cleaning_label_surfaces_failure_cause():
    assert ingest.cleaning_label("5", {"start_reason": 0, "result": 2, "err": "full"}) \
        == "Auto cleaning failed - bin full"


def test_cleaning_label_falls_back_without_subfields():
    # no result/start_reason -> the plain static label, never invented text
    assert ingest.cleaning_label("5", {}) == ingest.event_type_label("5")
    assert ingest.cleaning_label("5", None) == "Cleaning done"
    # a non-cleaning code is unaffected
    assert ingest.cleaning_label("10", {"result": 0}) == ingest.event_type_label("10")


def test_cross_namespace_codes_6_7_read_sensibly():
    assert ingest.classify_event_kind("6") == "cleaning"
    assert ingest.classify_event_kind("7") == "cleaning"
    assert ingest.event_type_label("6") == "Litter emptied"
    # "7" was a low-confidence cross-namespace guess until a capture landed
    # whose content matched the documented {start_time, over_time,
    # start_reason, result, err, components, litter_weight} exactly, closing
    # the action=9 maintenance session.
    assert ingest.event_type_label("7") == "Reset done"
    # and with sub-fields they get the richer form
    assert ingest.cleaning_label("6", {"result": 0}) == "Litter empty completed"
    assert ingest.cleaning_label("7", {"result": 1}) == "Reset terminated"


def test_each_completion_code_names_its_own_operation():
    """The three completion codes a visit emits close three DIFFERENT cycles,
    so each must name its own operation rather than all reading "cleaning".

    This replaces an assertion that 8 and 17 must NOT get a rich label. That
    rule existed to stop three identical "Auto cleaning completed" lines
    appearing on one card -- but the duplication came from mislabelling, not
    from the rich form: 8 closes the deodorizing cycle (action=2 in 23 of 23
    episodes) and 17 the light cycle, per the firmware.
    """
    assert ingest.cleaning_label("5", {"start_reason": 0, "result": 0}) \
        == "Auto cleaning completed"
    assert ingest.cleaning_label("8", {"start_reason": 0, "result": 0, "clean_flag": 1}) \
        == "Auto deodorizing completed"
    assert ingest.cleaning_label("17", {"start_reason": 0, "result": 0, "from_clear": 1}) \
        == "Auto light cycle completed"
    # 17 stays folded behind the expander; a light cycle is not something the
    # official app surfaces.
    assert ingest.is_detail_event("17") is True
    assert ingest.is_detail_event("8") is False


def test_one_primary_line_per_cycle_not_per_step():
    """A visit's follow-up shows one primary line per CYCLE, and the real T5
    runs two: a cleaning (action=0, episode "c") and a deodorizing
    (action=2, episode "d"). The mechanism and light steps stay detail.

    Episode composition over the reference corpus is what pins this down --
    ('17','3','5') appears 21 times and ('3','8') 23 times, i.e. 8 never
    shares an episode with 5, so they are not two labels for one cycle.
    """
    visit = _ev(1, 1, 1000.0, "10", "toilet_visit", related_event="v")
    cleaning = [
        _ev(2, 1, 1005.0, "17", "cleaning", related_event="c", parent_event="v"),
        _ev(3, 1, 1010.0, "3", "cleaning", related_event="c", parent_event="v"),
        _ev(4, 1, 1020.0, "5", "cleaning", related_event="c", parent_event="v"),
    ]
    deodorizing = [
        _ev(5, 1, 1030.0, "3", "cleaning", related_event="d", parent_event="v"),
        _ev(6, 1, 1040.0, "8", "cleaning", related_event="d", parent_event="v"),
    ]
    card = ingest.group_sessions([visit] + cleaning + deodorizing)[0]
    primary = [s for s in card["sub_events"] if not s["detail"]]
    assert [p["event_type"] for p in primary] == ["5", "8"]
    assert sorted(s["event_type"] for s in card["sub_events"] if s["detail"]) \
        == ["17", "3", "3"]
