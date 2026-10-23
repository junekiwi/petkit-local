"""What a BLE accessory IS, and the store that holds every one of them.

`BLEDevice` is the record — identity, pairing, last reading — and `BLERegistry`
persists them all to `ble_devices.json`. The type tables belong here because
they are part of that identity: which number a parent is told to scan for, and
which of those numbers is evidence rather than a guess. `cloud_bindings` reads
the same accessories back out of a proxied cloud reply.

Nothing here decodes a frame; that is `framing.py`, `w5.py` and `ctw3.py`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from petkit_local.devices.registry import PersistedRegistry
from petkit_local.utils.coerce import to_int
from petkit_local.utils.dicts import dig

log = logging.getLogger(__name__)

# The `type` int the firmware expects in a `dev_ble_device` list entry. K3 is 0
# because it is never listed there at all (it travels inside the parent's
# device_info instead), so its value is only ever a placeholder.
#
# Two of these are evidence. 14 was read off a real W5 pairing; 24 came from a
# CTW3 owner who captured their own `dev_ble_device` list (issue #4).
#
# `w4` and `ctw2` are still assumptions, and the assumption is that a model
# shares its number with its own product line rather than with the other one:
# `ctw2` sits with `ctw3` (both cordless CT-series EverSweets), `w4` with `w5`.
# Nothing in the parent's firmware settles it — `pk_schmg_parse_ble_dev_list`
# (D4SH `ctrl`, `ble_relay_network.c`) reads `type` straight out of the JSON,
# logs `dev[%d],type:%d` and stores it, and the parent then scans by MAC. The
# value only picks which protocol it speaks once connected.
#
# A wrong guess fails silently at both ends, which is why `BLEDevice.scan_type`
# exists: the owner of the hardware can override it without a code change, the
# panel shows the exact entry that will be sent, and whatever value turns out to
# work can be brought back here as a real one — which is exactly how 24 arrived.
#
# NOT the same number as the `typeCode` in mr-ransel's protocol notes, which
# gives W5 1, W5C 2 and W5N 3. That one is the accessory's own idea of what it
# is, read over its BLE session; this one is what a PARENT is told to scan for.
# Two namespaces, and the resemblance is a trap: "correcting" 14 to 1 from that
# table would throw away the only value anybody has confirmed.
BLE_TYPE_MAP = {"w5": 14, "w4": 14, "ctw3": 24, "ctw2": 24, "k3": 0}

#: Which of those values is evidence and which is a working assumption.
#: Read by the panel so the guess is visible where somebody can act on it.
BLE_TYPE_CONFIRMED = frozenset({"w5", "ctw3"})

#: The reverse of `BLE_TYPE_MAP`, for reading a PetKit account's OWN pairing
#: list back out of a proxied reply.
#:
#: Deliberately only the two confirmed numbers. Inverting the whole table would
#: have to pick one of the two names sharing each value, and the wrong pick is
#: not a cosmetic error: `ble_type` selects the frame parser, so a CTW2 imported
#: as a CTW3 would have its status block read at the wrong offsets and produce
#: confident nonsense. An unrecognised number imports with no type at all and
#: waits for the owner to name it, which is the same position `scan_type` takes.
CLOUD_BLE_TYPES = {14: "w5", 24: "ctw3"}

#: The accessory kinds that produce HA entities. Anything else registers fine
#: and then appears nowhere, so callers validate against this rather than
#: letting a typo create an invisible device.
BLE_TYPES = tuple(BLE_TYPE_MAP)


def normalize_mac(mac: str) -> str:
    """A MAC in one canonical form: uppercase hex, no separators.

    A BLE MAC reaches us from two directions that do not agree on formatting —
    typed by a person when pairing, and read out of a relayed frame's
    `content.device.mac` — and the only thing that matters is that the two
    match. Comparing canonical forms means `aa:bb:cc:dd:ee:ff`,
    `AA-BB-CC-DD-EE-FF` and `aabbccddeeff` are the same accessory, which is
    what a user means and what avoids a silently dropped frame.

    Returns "" for anything that is not 12 hex digits, so a caller can reject
    it rather than store a MAC no frame will ever match.
    """
    cleaned = "".join(c for c in (mac or "") if c.isalnum()).upper()
    if len(cleaned) != 12 or any(c not in "0123456789ABCDEF" for c in cleaned):
        return ""
    return cleaned


@dataclass
class BLEDevice:
    """A BLE-only accessory, reachable only through the WiFi device it is paired to.

    `link_with` is the `petkit_id` of that parent, and is what every lookup here
    keys on: the accessory has no network identity of its own, so it has no
    credentials, no heartbeat and no liveness of its own either — `state` is
    only ever updated as a side effect of the parent reporting. `last_seen` is
    the one exception and is about the accessory itself: when it last said
    anything at all, through whoever relayed it.
    """

    ble_type: str
    petkit_id: int
    serial_number: str = ""
    mac: str = ""
    secret: str = ""
    link_with: int = 0
    interval: int = 240
    #: Overrides `BLE_TYPE_MAP` for this one accessory. 0 means "use the table".
    #:
    #: Two of the table's values are evidence; the rest are a working
    #: assumption (see `BLE_TYPE_MAP`). A wrong one produces a pairing
    #: that fails with no symptom at either end, and the person who can find out
    #: which value is right is the one holding the fountain — not us. So it is
    #: settable per accessory, and persisted with the rest.
    scan_type: int = 0
    #: When a frame from this accessory last decoded. Not a network liveness —
    #: it has no network — but the answer to the only question worth asking
    #: about a relayed device: has it ever spoken, and how long ago. With a
    #: `scan_type` that may be a guess, "never" is the symptom to look for.
    last_seen: float = 0.0
    state: dict[str, Any] = field(default_factory=dict)
    #: The K3's operating parameters, served as the parent's
    #: `settings.k3Config.config` (see `K3_DEFAULT_CONFIG`). Unused by the
    #: fountains, which carry their settings in their own status frames.
    config: dict[str, Any] = field(default_factory=dict)
    #: The K3's own settings block (`K3_SETTING_KEYS`), served by
    #: `dev_k3_device_info`. Separate from `config` because the firmware parses
    #: the two in different places for different things.
    settings: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Canonicalise the MAC at the point it is stored, not at each caller.

        Two call sites normalise before handing one over, and that was the whole
        guarantee: a third that forgot would put `aa:bb:cc:dd:ee:01` on the wire
        where the cloud sends `aabbccddee01`, and nothing here would notice.
        `get_by_mac` normalises both sides, so every lookup would keep working
        and the only thing that ever saw the malformed value would be the device
        — which would simply never find the accessory. That is the exact failure
        this class already warns about elsewhere, one layer further out.

        A value that does not parse is LEFT ALONE rather than blanked: it is
        already unmatchable, and keeping it is what lets the panel show the
        owner the MAC they actually typed instead of an empty box.
        """
        canonical = normalize_mac(self.mac)
        if canonical:
            self.mac = canonical

    @property
    def wire_mac(self) -> str:
        """The MAC as the cloud puts it on the wire: lowercase, no separators.

        Stored uppercase because that is the canonical form for COMPARING one
        (`normalize_mac`), and a frame's MAC reaches us in whatever shape the
        firmware felt like. Outbound is the other question, and the answer is
        the real cloud's: every captured `dev_ble_device` entry and every
        `connect` carries lowercase. Nothing says the parent compares case
        sensitively — but nothing says it does not, and matching the cloud
        costs nothing.
        """
        return self.mac.lower()

    @property
    def ble_type_int(self) -> int:
        """This accessory's `type` code for the `dev_ble_device` list."""
        return self.scan_type or BLE_TYPE_MAP.get(self.ble_type, 0)

    @property
    def scan_type_is_guessed(self) -> bool:
        """Whether this accessory is being scanned for on an invented number."""
        return not self.scan_type and self.ble_type not in BLE_TYPE_CONFIRMED \
            and self.ble_type != "k3"

    def to_ble_list_entry(self) -> dict[str, Any]:
        """One entry of the `dev_ble_device` response: what the parent must scan for."""
        return {
            "id": self.petkit_id,
            "secret": self.secret,
            "type": self.ble_type_int,
            "mac": self.wire_mac,
            "interval": self.interval,
        }

    def to_dict(self) -> dict[str, Any]:
        """The persisted form. Unlike `Device`, `state` IS kept.

        An accessory only reports when its parent happens to poll it, so
        dropping the last reading would leave its HA entities unknown for
        minutes after every restart.
        """
        return {
            "ble_type": self.ble_type,
            "petkit_id": self.petkit_id,
            "serial_number": self.serial_number,
            "mac": self.mac,
            "secret": self.secret,
            "link_with": self.link_with,
            "interval": self.interval,
            "scan_type": self.scan_type,
            "last_seen": self.last_seen,
            "state": self.state,
            "config": self.config,
            "settings": self.settings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BLEDevice:
        """Rebuild from `to_dict`, ignoring keys this version no longer has."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


#: The K3's operating parameters, as the parent's `settings.k3Config.config`.
#:
#: Every key here is one the T4 parses by name: firmware 1.652's
#: `parse item k3 config w` branch reads `standard`, `lightness`,
#: `singleLightTime`, `singleRefreshTime`, `refreshTotalTime` and `lowVoltage`,
#: each with its own `=%d` log line — except `standard`, which has none because
#: it arrives as a two-element array. The values are a real PetKit reply to a
#: real T4, not an invention.
#:
#: Seeded when a K3 is paired because the alternative is what we served before:
#: `{"config": {}}`, which parses to nothing and leaves the spray on whatever
#: its flash happens to hold. Only applied to a K3 whose config is still empty,
#: so a value that arrived from the cloud or from the owner is never overwritten.
K3_DEFAULT_CONFIG: dict[str, Any] = {
    "standard": [5, 30],
    "lightness": 100,
    "lowVoltage": 5,
    "refreshTotalTime": 11500,
    "singleRefreshTime": 25,
    "singleLightTime": 120,
}

#: The two keys of `dev_k3_device_info`'s `settings` block, in the order the
#: parent's single `liquidLackSwitch,fixedTimeRefresh:%d_%d` log line prints
#: them. No default: nothing has ever shown us what PetKit sends here, so the
#: block is served only once a real value exists (imported, or set by the
#: owner) and omitted entirely until then — every key in that parser is looked
#: up individually, so an absent one is skipped rather than read as zero.
K3_SETTING_KEYS = ("liquidLackSwitch", "fixedTimeRefresh")


#: The cloud replies that name a BLE accessory, and nothing else is read.
#:
#: `dev_ble_device` carries the relayed fountains; the K3 is not in it — it
#: travels inside `dev_device_info` (`k3Device`) with its parameters in
#: `settings.k3Config`, and answers a dedicated `dev_k3_device_info` of its own.
#: Which is why importing bindings and serving a K3 are the same problem: both
#: need a `secret` that only the account has ever held.
CLOUD_BINDING_ENDPOINTS = frozenset({
    "dev_ble_device", "dev_device_info", "dev_k3_device_info",
})


def _cloud_binding(entry: Any, parent_id: int, ble_type: str = "") -> dict[str, Any] | None:
    """One cloud list entry as `BLERegistry.register` kwargs, or None if unusable.

    The MAC is the test, not the id: an entry without one cannot be matched
    against a relayed frame later (`get_by_mac`), so importing it would create
    an accessory nothing can ever reach.
    """
    if not isinstance(entry, dict):
        return None
    mac = normalize_mac(str(entry.get("mac", "")))
    petkit_id = to_int(entry.get("id"), 0) or 0
    if not mac or petkit_id <= 0:
        return None

    cloud_type = to_int(entry.get("type"), 0) or 0
    fields: dict[str, Any] = {
        "ble_type": ble_type or CLOUD_BLE_TYPES.get(cloud_type, ""),
        "petkit_id": petkit_id,
        "mac": mac,
        "secret": str(entry.get("secret", "")),
        "link_with": parent_id,
        "interval": to_int(entry.get("interval"), 240) or 240,
    }
    sn = entry.get("sn")
    if isinstance(sn, str) and sn:
        fields["serial_number"] = sn
    # Kept verbatim even when it maps to a known name, so an unrecognised
    # number survives the round trip and the parent is later told to scan for
    # exactly what the account said — the one field we must not "improve".
    if cloud_type:
        fields["scan_type"] = cloud_type
    return fields


def cloud_bindings(endpoint: str, payload: Any, parent_id: int) -> list[dict[str, Any]]:
    """Every BLE accessory a proxied cloud reply describes, as register kwargs.

    Args:
        endpoint: The last path segment of the request that produced `payload`.
        payload: The decoded upstream JSON body.
        parent_id: The device whose request this answered — the `link_with` for
            everything found. The same account list is returned to EVERY online
            parent, so the requester is the only sound attribution available.

    Returns:
        Zero or more kwargs dicts. K3 entries carry `ble_type="k3"` because the
        payloads that describe one never carry a scan `type` — it is not a
        relayed accessory and is never scanned for.
    """
    if not isinstance(payload, dict):
        return []
    result = payload.get("result")
    if not isinstance(result, dict):
        return []

    if endpoint == "dev_ble_device":
        entries = result.get("list")
        if not isinstance(entries, list):
            return []
        found = (_cloud_binding(e, parent_id) for e in entries)
        return [f for f in found if f]

    # Both remaining shapes describe one K3. `dev_device_info` nests it under
    # `k3Device` beside the parent's own fields, with its parameters in
    # `settings.k3Config`. PetKit's `dev_k3_device_info` to a T4 nests it too,
    # `{"k3Config": {"config": ...}, "k3Device": {...}}` (proxied 2026-10-22);
    # the flat shape, the K3's fields at the top of `result`, is what this
    # add-on serves and is still read.
    nested = result.get("k3Device")
    node = nested if endpoint == "dev_device_info" or isinstance(nested, dict) else result
    binding = _cloud_binding(node, parent_id, ble_type="k3")
    if not binding:
        return []
    binding.pop("scan_type", None)

    config = (dig(result, "settings", "k3Config", "config")
              or dig(result, "k3Config", "config"))
    if isinstance(config, dict) and config:
        binding["config"] = dict(config)

    # Kept apart from `config` on purpose: these two are the K3's OWN settings
    # block, and the six keys of `k3Config.config` are the parent's copy of its
    # operating parameters. Merging them would put `liquidLackSwitch` inside a
    # `k3Config` the firmware parses key by key for something else.
    settings = node.get("settings") if endpoint == "dev_k3_device_info" else None
    if isinstance(settings, dict):
        held = {k: settings[k] for k in K3_SETTING_KEYS if k in settings}
        if held:
            binding["settings"] = held
    return [binding]


class BLERegistry(PersistedRegistry):
    """Every BLE accessory, keyed by its PetKit id, persisted to ble_devices.json.

    Separate from `DeviceRegistry` because the two have different lifecycles: an
    accessory is created from whatever its parent reports, has no credentials of
    its own, and is looked up by parent (`link_with`) far more often than by id.
    """

    _label = "BLE registry"

    def __init__(self, persist_path: str | Path | None = None, *,
                 flush_interval: float | None = None) -> None:
        """See `PersistedRegistry.__init__` for the arguments."""
        self._devices: dict[int, BLEDevice] = {}
        super().__init__(persist_path, flush_interval=flush_interval)

    def get(self, petkit_id: int) -> BLEDevice | None:
        """The accessory with this id, or None."""
        return self._devices.get(petkit_id)

    def get_by_mac(self, mac: str) -> BLEDevice | None:
        """The accessory with this BLE MAC, or None.

        Compared in canonical form (see `normalize_mac`) rather than verbatim,
        because an exact string match makes the single most likely pairing
        mistake invisible: a MAC typed as `aa:bb:...` never matches a frame
        carrying `AA-BB-...`, and the frame is then dropped by a `log.debug` in
        `mqtt/bridge.py` with nothing to show for it.
        """
        wanted = normalize_mac(mac)
        if not wanted:
            return None
        for d in self._devices.values():
            if normalize_mac(d.mac) == wanted:
                return d
        return None

    def remove(self, petkit_id: int) -> bool:
        """Unpair an accessory. Returns whether it existed.

        The parent stops being told to scan for it on its next
        `dev_ble_device`, which is the whole of "unpairing" from the device's
        point of view — there is no command that revokes one.
        """
        if petkit_id not in self._devices:
            return False
        dev = self._devices.pop(petkit_id)
        log.info("BLE device removed: %s id=%d mac=%s", dev.ble_type, petkit_id, dev.mac)
        self.save()
        return True

    def get_linked(self, parent_id: int) -> list[BLEDevice]:
        """Every accessory paired to this WiFi device."""
        return [d for d in self._devices.values() if d.link_with == parent_id]

    def get_linked_k3(self, parent_id: int) -> BLEDevice | None:
        """This device's K3 purifier, if it has one.

        Its own lookup because K3 is the one accessory that is NOT served
        through `dev_ble_device`: it is embedded in the parent's device_info
        (`withK3`/`k3Device`) instead. Only the first is returned — the firmware
        has one K3 slot.
        """
        for d in self._devices.values():
            if d.link_with == parent_id and d.ble_type == "k3":
                return d
        return None

    def register(self, **kwargs: Any) -> BLEDevice:
        """Create the accessory, or update the one already stored under this id.

        On update, only TRUTHY values overwrite: the parent re-reports the whole
        accessory on every poll and pads fields it did not read this time with
        empty values, which must not erase what we already know.

        Args:
            kwargs: `BLEDevice` field values; `petkit_id` is the key and
                defaults to 0 if absent.
        """
        pid = kwargs.get("petkit_id", 0)
        if pid in self._devices:
            dev = self._devices[pid]
            changed = False
            for k, v in kwargs.items():
                if v and hasattr(dev, k) and getattr(dev, k) != v:
                    setattr(dev, k, v)
                    changed = True
            if changed:
                # Same bug as DeviceRegistry.get_or_create had: the update was
                # only ever written by some later, unrelated save().
                self.mark_dirty()
            return dev
        dev = BLEDevice(**kwargs)
        if dev.ble_type == "k3" and not dev.config:
            dev.config = dict(K3_DEFAULT_CONFIG)
        self._devices[pid] = dev
        log.info("BLE device registered: %s id=%d mac=%s linked=%d",
                 dev.ble_type, pid, dev.mac, dev.link_with)
        self.save()
        return dev

    def all(self) -> list[BLEDevice]:
        """A snapshot list of every accessory, safe to iterate while mutating."""
        return list(self._devices.values())

    def apply_cloud_binding(self, fields: dict[str, Any]) -> tuple[BLEDevice | None, str]:
        """Register (or update) one accessory the account reported.

        Args:
            fields: One `cloud_bindings` entry.

        Returns:
            `(device, outcome)` where outcome is `imported`, `updated`,
            `unchanged`, or a reason it was refused. The caller reports the
            reason rather than silently dropping it — an import that quietly
            covers four of five accessories is worse than one that says so.

        A `secret` the account disagrees with overwrites ours, and that is the
        point of asking: a hand-typed one produces an accessory that pairs,
        relays nothing, and looks perfectly healthy in the panel.
        """
        pid = to_int(fields.get("petkit_id"), 0) or 0
        if pid <= 0:
            return None, "no usable id"
        if not fields.get("ble_type"):
            return None, f"type {fields.get('scan_type') or '?'} has no parser here"

        existing = self._devices.get(pid)
        clash = self.get_by_mac(fields.get("mac", ""))
        if clash is not None and clash.petkit_id != pid:
            return None, f"MAC already paired to id {clash.petkit_id}"

        before = existing.to_dict() if existing else None
        dev = self.register(**fields)
        # `register` only overwrites truthy values, which is right for a parent
        # re-reporting an accessory but not for parameters the account is
        # authoritative on — those are replaced wholesale when they arrive.
        for key in ("config", "settings"):
            value = fields.get(key)
            if isinstance(value, dict) and value and getattr(dev, key) != value:
                setattr(dev, key, dict(value))
                self.mark_dirty()

        if before is None:
            return dev, "imported"
        return dev, "unchanged" if before == dev.to_dict() else "updated"

    def non_k3_for_parent(self, parent_id: int) -> list[BLEDevice]:
        """The accessories that belong in this device's `dev_ble_device` list.

        K3 is excluded on purpose: listing it there as well as in the parent's
        device_info makes the firmware treat it as a second, unpaired device.
        """
        return [d for d in self._devices.values()
                if d.link_with == parent_id and d.ble_type != "k3"]

    def _serialize(self) -> dict[str, Any]:
        """`{"<petkit_id>": BLEDevice.to_dict()}` — the shape of ble_devices.json."""
        return {str(pid): d.to_dict() for pid, d in self._devices.items()}

    def _restore(self, data: Any) -> None:
        """Load `_serialize`'s shape, skipping entries that cannot be read."""
        if not isinstance(data, dict):
            log.error("BLE registry at %s is not a JSON object - starting empty",
                      self._persist_path)
            return
        for key, d_data in data.items():
            try:
                dev = BLEDevice.from_dict(d_data)
            except (AttributeError, KeyError, TypeError, ValueError) as e:
                log.warning("Skipping unreadable BLE device entry %r: %s", key, e)
                continue
            self._devices[dev.petkit_id] = dev
        log.info("BLE registry loaded: %d devices", len(self._devices))
