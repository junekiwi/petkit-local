"""The constant tables the state parsers read, and the evidence behind each one.

Nothing here is a preference. Every table records something a device was
observed doing — a field that appears only while a cycle runs, the hall switches
one firmware family names, how long a cartridge lasts — and the comment above it
is the record of how that was established: a capture count, a string in `ctrl`,
an experiment run against the box. A parser is cheap to re-derive; this is not.
"""
from __future__ import annotations

# A litter box has two independent deodorant consumables, and the countdown for
# both is OURS to compute: the device reports only the reset timestamps
# (`sprayResetTime`, `liquidReset`) and never a remaining count.
# `deodorantLeftDays` and `sprayLeftDays` appear in zero of 685 captured state
# reports and nowhere in the `ctrl` or `ble` binaries — they are the cloud's
# vocabulary, and here the cloud is us.
#
#   N60  the ACTIVE one: the box's own sprayer, which fires for ~2 minutes after
#        a visit. Manufacturer's replacement interval is 45 days.
#   N50  the PASSIVE one: sits in the waste bin and needs no mechanism.
#        Manufacturer's replacement interval is 30 days.
#
# Mind the vocabulary, which is inverted from the products: `deodorantLeftDays`
# is the N50 even though the N60 is the active deodorant, and `sprayLeftDays` is
# the N60. Those are pypetkitapi's cloud names, kept because they are already
# the entities' `value_path`. Do not "correct" one into the other.
#
# Why the cloud vocabulary says "spray" rather than "N60": the deodorizing
# FUNCTION is not tied to the N60. Models with no built-in unit can take an
# optional K3 (Pura Air) over BLE instead, so one field name has to cover both.
# On a T5 it is unambiguously the built-in N60 — `ctrl` holds no `k3` string at
# all and drives the sprayer off its own motor controller
# (`_pki_transmit_spray_over_event_from_mot`, `pk_hmi_get_spray_percent`), while
# `k3LightSwitch` turns up in a T4 property post and the T4 has no N60.
#
# The substitution is functional, NOT a shared data source: a K3 reports
# `battery`/`liquid` LEVELS on its parent's report (`bridge._update_linked_k3`),
# never a reset date, so these date-based countdowns cannot be fed from a K3 and
# a K3-equipped box cannot be assumed to populate them.

#: The N60's lifetime, CONFIRMED: PetKit's own cloud answers `dev_device_info`
#: with `sprayDays: 45` alongside `sprayResetTime` (captured in proxy mode), the
#: same 45 the manufacturer's replacement interval gives. It is also what
#: `payloads.to_device_info` advertises to the device, which the firmware stores
#: (`set sprayDays (%d)` in `ctrl`) — so both sites must read THIS constant and
#: neither may hardcode a number of its own. Independent literals drift, and HA
#: then burns a cartridge down on a schedule the device was never told about.
SPRAY_TOTAL_DAYS = 45

#: The N50's lifetime: the manufacturer's interval and nothing more, because the
#: field it would count from never arrives.
#:
#: The N50 has NO representation in the device protocol, established by
#: experiment on a T5 (2026-07-30). Resetting the N60 from PetKit's app sends
#: `thing.service.start {"start_action":10}`, the box answers `liquid_reset_over`
#: and its `sprayResetTime` becomes the reset moment. Resetting the N50 from the
#: app sends ONLY `thing.service.errState {"show":1,"err_state":1}` -- no start,
#: no date, no device reply, and `liquidReset` does not move. PetKit's own
#: `dev_device_info` reply carries no N50 field either: just `sprayDays`,
#: `sprayResetTime` and the `deodorantTip`/`purificationTip` notify flags. So
#: PetKit keeps the N50 replacement date in their account database and only tells
#: the box what to display.
#:
#: Consequence: `deodorantLeftDays` can never be filled from telemetry. Its
#: source `liquidReset` has been 0 in every one of 983+ captured reports and
#: nothing in any transport ever writes it. For "N50 Days Left" to read anything
#: we have to record the replacement date ourselves -- being the cloud is the
#: whole point of this add-on, and this is one of the places that has to mean it.
DEODORANT_TOTAL_DAYS = 30

#: Where a replacement date WE recorded lives, inside `Device.config`. It has to
#: be config rather than `state`: state is rebuilt from the device's next
#: contact and does not survive a restart, and for the N50 there is no next
#: contact that would ever carry it.
CONSUMABLE_RECORD_KEY = "consumables"

#: A camera feeder's desiccant pack. Like the N50 it has no countdown anywhere
#: in the protocol -- the reset is all the device knows about -- so 30 days is
#: the pack life PetKit's own app counts down from.
DESICCANT_TOTAL_DAYS = 30

#: The consumables a "replaced" action can stamp, and what each one fills.
#:
#: `apply_consumable_state` writes these into `device.state`, so a value WE
#: derived wins over one the device reported. That is right for all three:
#: each is filled from a replacement date, and the only way one gets recorded
#: is somebody pressing the button, which is newer information than whatever
#: count the device was carrying.
CONSUMABLE_TOTALS = {
    "n50": ("deodorantLeftDays", DEODORANT_TOTAL_DAYS),
    "n60": ("sprayLeftDays", SPRAY_TOTAL_DAYS),
    "desiccant": ("desiccantLeftDays", DESICCANT_TOTAL_DAYS),
}

#: OURS, not the device's: no work-mode code means "idle", because the device
#: says so by omitting `workState` entirely. Deliberately negative so it can
#: never collide with a real `WORK_MODES` code, and deliberately NOT added to
#: that table, which is the device's vocabulary and not ours. `sensors.py` pairs
#: it with the label; nothing else should read it as a protocol value.
WORK_MODE_IDLE = -1

#: Fields the device sends ONLY while the thing they describe is happening.
#: Presence is the whole signal — the payload never carries an "off" value, it
#: just stops appearing. Measured over 1254 captured snapshots (both
#: transports): the report is a fixed 29-key dump plus at most these extras,
#: `workState` (166), `lightState` (166) and `refreshState` (32).
#:
#: They MUST be turned into a real 0/1 here, because `device.state` is only ever
#: merged into and never pruned: a key that stops being sent keeps its last
#: value forever. `refreshState` is also an object, and a non-empty dict is
#: truthy — so the "Deodorization Running" sensor latched ON at the box's first
#: spray and stayed on for good. `lightState` is mapped too, since it has the
#: identical shape and would repeat the bug the moment anyone gives it an entity.
PRESENCE_FLAGS = {
    "refreshState": "deodorizing",
    "lightState": "lightOn",
}


#: Proof that a payload is a whole-device snapshot rather than a fragment.
#: `litter` was present in all 1254 captured litter-box reports across both
#: transports, so its absence means we are looking at something partial (a
#: hand-built dict in a test, a device that frames its report differently) and
#: must not conclude anything from a key not being there.
SNAPSHOT_MARKER = "litter"


#: Models whose reports carry the W7H field set. A codename, NOT a payload
#: marker: `sensor` looked like one — it holds the hall block and no other
#: fountain sends it — but a live T5 carries a `sensor` block of its own
#: (`open_hall`, `dump_hall`, `prox_raw`, ...), so keying off its presence would
#: have run the fountain branch over every litter box. Both call sites already
#: know the codename; per CLAUDE.md, pass it rather than infer it.
W7H_MODELS = frozenset({"w7h"})

#: W7H top-level state fields, from the reverse-engineered `property/post` map
#: supplied 2026-07-31 and present key-for-key in a real capture from the same
#: device. Copied under their own names: this IS the device's vocabulary, the
#: panel renders `device.state` verbatim, and inventing a second spelling for
#: `stgFullState` would only create something to keep in sync.
#:
#: Every one of these is a plain scalar the device sends on every report, so
#: unlike the litter box's presence-signalled trio there is no absence to read.
W7H_STATE_FIELDS = (
    # install / seating
    "stgInstall", "stgFullState", "cwtInstall", "wtInstall", "wtLock",
    "heatInstall",
    # level / state codes (integers; the code meanings are NOT known, so they
    # are published raw rather than decoded into labels we would be inventing)
    "cwtState", "wtState",
    # work states
    "heatState", "liftValveState", "pumpState", "waterPumpState",
    "addWaterState", "flushState", "liftResetState", "liftLiveState",
    "disinfectState", "addWaterFrequent",
    # timers / measurements
    "disinfectTime", "heatLeftTime", "heatStatusTime", "heatRealTemp",
    # camera + housekeeping
    "cameraStatus", "ota", "rebootReason",
)

#: The ten hall switches a W7H reports under `sensor{}`, in the order the
#: device sends them. Digital reed switches, NOT ADC readings — the supplied
#: map correlated each against the BLE log's own `hall_data` lines
#: (`CLEAN_WATER_H`, `LOCK_INSTALL_R`, `WATER_TRAY_INSTALL`, ...).
#:
#: Listed explicitly rather than copied by `hall_` prefix so that the set an
#: entity may bind to is the set a source names. It is also what lets
#: `tests/test_entity_backing.py` see a producer for each one; a prefix match
#: is invisible to it, and an entity it cannot see a producer for is exactly
#: the "reads unknown forever" case that test exists to catch.
#:
#: Names are the device's, kept verbatim so one string follows an entity
#: through the panel into a firmware log.
W7H_HALLS = (
    "hall_CH", "hall_CL",       # clean-water tank, high / low level
    "hall_CKL", "hall_CKR",     # waste lock, left / right
    "hall_DH",                  # sewage tank full
    "hall_DKL", "hall_DKR",     # sewage tank seated, left / right
    "hall_LTU", "hall_LTD",     # lift travel, upper / lower
    "hall_TY",                  # drinking tray seated
)

#: The `device{}` block's unix timestamps, and the state key each becomes.
#: These are TIMESTAMPS, not counters — `drink_time` is "when the pet last
#: drank", not "how many times". Reading it as a count is how it ended up
#: behind a "Drink Times" sensor that would have displayed 1785531049.
W7H_DEVICE_TIMESTAMPS = {
    "drink_time": "lastDrink",
    "pet_time": "lastPetDetect",
    "pet_close_time": "lastPetLeft",
}

#: The T5-family litter box has a `sensor{}` block too, and it is NOT the same
#: one — different names, different mechanism. Read live from a running T5
#: (firmware 943) on 2026-07-31:
#:
#:     {"weight":0, "stdby_hall":0, "smooth_hall":1, "dump_hall":1,
#:      "open_hall":1, "close_hall":0, "top_hall":0, "prox_raw":99,
#:      "around_pos":0}
#:
#: Only the six `*_hall` switches are taken. `weight` duplicates `sandWeight`,
#: and `prox_raw`/`around_pos` are a raw ADC and a position code whose scale
#: and enum no source gives — publishing either would mean inventing a unit.
#:
#: Unlike the W7H's, these names have NO external map behind them, so the
#: entities carry the device's own wording rather than an interpretation of it.
#: What does corroborate them is the same device's `err{}` block, which carries
#: a matching fault bit per hall (`hallT`, `hallD`, `hallS`, `hallO`, `hallC`) —
#: the firmware itself treating each as a distinct sensor.
LITTER_CAMERA_HALLS = (
    "stdby_hall", "smooth_hall", "dump_hall",
    "open_hall", "close_hall", "top_hall",
)

#: Litter models that report `LITTER_CAMERA_HALLS`. Seen on a T5; T6 and T7 run
#: the same firmware family and share every other field, so they are included
#: rather than left publishing nothing, and an absent key simply never fills.
LITTER_CAMERA_MODELS = frozenset({"t5", "t6", "t7"})

#: The hall switches a next-gen feeder reports in its `sensor{}` block, in the
#: device's own wording. Named rather than copied wholesale for the same reason
#: as the litter box's: a blanket copy would also drag in raw ADC readings whose
#: scale nobody here knows.
FEEDER_HALLS = ("left_hall", "home_hall", "right_hall", "left_sub_hall")

#: Flat keys a D4H/D4SH report carries that no other feeder does. Every one is
#: present in the two real D4SH 867 reports in issue #2 (one per transport) and
#: is a JSON key in the state builder of that firmware's `ctrl`.
#:
#: What each MEANS is a separate question from whether it is there, and most of
#: these are only the second. `door` read 1 through the lid being opened, the
#: hoppers being pulled and the battery cover coming off, so it is not the lid;
#: `ir_b_1`/`ir_b_2`/`ir_c` never moved, though blocking a sensor did raise a
#: "feed chute blocked" fault. They are carried so the values are visible in the
#: panel and in diagnostics -- an entity that names them is a different decision,
#: made per key in `ha/entities/sensors.py`.
FEEDER_NEXT_GEN_FIELDS = (
    # Hopper contents, one per hopper. 2 = has food and 0 = empty, reported by
    # the owner in #2; 1 was never observed and is deliberately not guessed at.
    "food1", "food2",
    # Leftover food in the bowl. -1 is "not measured", not a level: the firmware
    # logs `recv feed start leftover set(-1)` as it begins a feed, and the one
    # real reading seen (46) appeared while surplus control was being changed.
    # Related to `surplusControl`/`surplusStandard`, both strings in `ctrl`.
    "bowl",
    "door", "feeding", "eating",
    "ir_b_1", "ir_b_2", "ir_c",
    # Backup batteries and the DC line. `batV` reads 0 with no batteries fitted
    # (confirmed by the owner), which is why it must not be read as a fault.
    "batV", "ubat", "DCV",
    "ultra_sta",
    # Five slots of sound readiness, NOT the feeding schedule -- the firmware
    # logs `clean sound_list[%d], id = %d, ready[%d]=%d` and takes a `soundId`
    # in its `play_sound` service. The owner confirmed the list does not track
    # how many meals are scheduled.
    "ready",
)

#: Flat keys of a D4's (fw 1.267) own report that the family's cloud names do
#: not cover. Two D4s sent `batV` in every one of 77 state reports and in their
#: meal reports (captured 2026-10-23/24), reading 3862-3868 and 4669-4678: the
#: backup batteries, in millivolts. Whether 0 means "none fitted", as it does
#: on a D4SH, is not known for this model -- both units read non-zero.
FEEDER_D4_FIELDS = ("batV",)
