"""ESP32 firmware patcher — swap the one CA an ESP32 model trusts for MQTT TLS.

The T3/T4/D3/D4/D4S (and the other ESP32 models) are NOT the Ingenic/Axera Linux
boxes the rest of `patchers/` targets. They are a single monolithic ESP-IDF
application image (`userbin.bin`), with no filesystem to shell into, so none of
`common.py`'s run_cmd / bind-mount / boot-wrapper machinery applies. The only way
to change one is to rebuild the image and reflash it, and these devices accept a
reflash the way they accept any firmware update: over OTA, through the very
`dev_ota_check` our server already answers (`http/handlers/stubs.py`).

What the patch itself does is deliberately tiny, and it is the SAME thing the
device's firmware already does with PetKit's cloud: establish MQTT over TLS to a
broker it trusts. A stock image trusts exactly one root — `GlobalSign Root CA`,
embedded as PEM text in a read-only data segment — and builds its broker
hostname from the product key (`<pk>.iot-as-mqtt.<region>.aliyuncs.com`). Replace
that one embedded root with a CA WE hold the key to, and a broker presenting a
leaf signed by it (CN matching that hostname, which DNS redirects to us) is
trusted exactly as PetKit's was. No code is changed and TLS verification is NOT
disabled — the trust anchor moves, nothing else.

Everything here is pure: bytes in, bytes out, raise on anything unexpected. That
keeps it unit-testable against a hand-built image (see tests) and lets the
delivery layer (OTA serving, the panel, rollback) own the device side. The
reflash is the one operation that can brick a device, so the discipline is:
produce the patched image, VERIFY it re-parses and its integrity fields check out
before it is ever offered to a device, and keep the untouched stock image so
"rollback" is just serving that back.

Image format (ESP-IDF v1, which `userbin.bin` is):

    byte 0        magic 0xE9
    byte 1        segment count
    bytes 8..23   16-byte extended header; byte 23 is `hash_appended`
    then N × (load_addr u32, length u32, data[length])
    then pad so the next byte lands on a 16-byte boundary; its LAST byte is
        the 1-byte checksum = 0xEF XOR (all segment data bytes)
    then, iff hash_appended, a 32-byte SHA-256 over everything before it

Both the checksum byte and the appended SHA-256 cover the cert bytes, so both are
recomputed after the swap. This was proven byte-for-byte: fed the stock D4 1.267
image and the CA from a known-working third-party patched image, `patch_firmware_cert`
reproduces that image's exact MD5 (see tests/test_patcher_esp32.py).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import logging
import re
import struct

log = logging.getLogger(__name__)

#: First byte of every ESP-IDF image.
ESP_IMAGE_MAGIC = 0xE9
#: `hash_appended` is the last byte of the 16-byte extended header, which itself
#: follows the 8-byte common header.
_EXTENDED_HEADER_END = 24
_HASH_APPENDED_OFFSET = 23
#: Length of the trailing SHA-256 when `hash_appended` is set.
_APPENDED_HASH_LEN = 32
#: The XOR seed the bootloader starts its segment checksum from.
_CHECKSUM_SEED = 0xEF

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class FirmwareImageError(ValueError):
    """The bytes we were handed are not a patchable ESP-IDF image.

    A `ValueError` on purpose: the same family as `patchers/verify.py`'s
    refusals, and for the same reason — a download that is truncated, an HTML
    error page, or a firmware from an unexpected build must stop here with a
    message naming what arrived, not sail into the byte surgery below.
    """


class _EspImage:
    """Parsed layout of an ESP-IDF image: where the segments, checksum and
    appended hash live. Just enough to recompute the two integrity fields the
    cert swap invalidates — not a general loader."""

    __slots__ = ("segments", "checksum_offset", "hash_appended", "length")

    def __init__(self, segments: list[tuple[int, int]], checksum_offset: int,
                 hash_appended: bool, length: int) -> None:
        self.segments = segments          # list of (data_offset, data_length)
        self.checksum_offset = checksum_offset
        self.hash_appended = hash_appended
        self.length = length

    @property
    def hash_offset(self) -> int:
        """Where the appended SHA-256 starts (== end of the hashed body)."""
        return self.checksum_offset + 1


def parse_esp_image(data: bytes) -> _EspImage:
    """Walk the segment table and locate the checksum byte and appended hash.

    The segment walk is bounded by the declared segment count and the buffer
    length; a count or a segment length that runs past the end raises rather
    than reading out of bounds, because that is exactly what a truncated or
    non-ESP download looks like.

    Raises:
        FirmwareImageError: Not an ESP image, or its segment table does not fit
            the bytes we have.
    """
    if len(data) < _EXTENDED_HEADER_END:
        raise FirmwareImageError(
            f"too short to be an ESP image ({len(data)} bytes)")
    if data[0] != ESP_IMAGE_MAGIC:
        head = data[:8].hex()
        raise FirmwareImageError(
            f"not an ESP image (first byte 0x{data[0]:02x}, expected "
            f"0x{ESP_IMAGE_MAGIC:02x}; starts {head})")

    segment_count = data[1]
    hash_appended = bool(data[_HASH_APPENDED_OFFSET])
    offset = _EXTENDED_HEADER_END
    segments: list[tuple[int, int]] = []
    for i in range(segment_count):
        if offset + 8 > len(data):
            raise FirmwareImageError(
                f"segment header {i} runs past the end of the image")
        _load_addr, length = struct.unpack_from("<II", data, offset)
        offset += 8
        if offset + length > len(data):
            raise FirmwareImageError(
                f"segment {i} ({length} bytes) runs past the end of the image")
        segments.append((offset, length))
        offset += length

    # Checksum byte sits at the last byte of the 16-byte block the segment data
    # is padded up into — i.e. the next 16-aligned position after `offset`,
    # minus one. (If `offset` is already 16-aligned a full 16-byte pad follows.)
    checksum_offset = ((offset // 16) + 1) * 16 - 1
    expected_end = checksum_offset + 1 + (_APPENDED_HASH_LEN if hash_appended else 0)
    if checksum_offset >= len(data) or len(data) < expected_end:
        raise FirmwareImageError(
            f"image ends before its checksum/hash (have {len(data)} bytes, "
            f"segments imply at least {expected_end})")
    return _EspImage(segments, checksum_offset, hash_appended, len(data))


def assert_esp_image(data: bytes, what: str) -> None:
    """Raise unless `data` parses as an ESP-IDF image.

    The twin of `verify.assert_mips_elf` for the ESP32 models: it names `what`
    so a failed firmware fetch reads as a transport problem, not as a mystery
    deeper in the patcher.
    """
    parse_esp_image(data)  # raises FirmwareImageError with the detail
    _ = what  # named in the raised message by the caller's context; kept for symmetry


def _segment_checksum(data: bytes, image: _EspImage) -> int:
    """The bootloader's 1-byte segment checksum: 0xEF XOR of all segment data."""
    xor = _CHECKSUM_SEED
    for offset, length in image.segments:
        for b in data[offset:offset + length]:
            xor ^= b
    return xor


def find_cert_slot(data: bytes) -> tuple[int, int]:
    """Return the (start, end) byte span of the ONE embedded CA certificate.

    A stock ESP32 image trusts exactly one root, embedded as a single PEM block.
    Requiring exactly one is the guard: zero means this build embeds its trust
    differently (DER, a bundle, a different segment) and the swap below would be
    wrong; more than one means the same, and silently patching the first would
    leave the device trusting a cloud root we do not control. Either way we
    refuse rather than mis-patch — the T4/D3/other models are validated here, not
    assumed to match the D4.

    Raises:
        FirmwareImageError: If the image does not contain exactly one PEM cert.
    """
    spans = [m.span() for m in _PEM_BLOCK.finditer(data)]
    if len(spans) != 1:
        raise FirmwareImageError(
            f"expected exactly one embedded CA certificate, found {len(spans)} "
            "— this firmware embeds its trust anchor differently and is not "
            "supported by the CA swap")
    return spans[0]


def patch_firmware_cert(stock: bytes, replacement_pem: bytes) -> bytes:
    """Swap the embedded CA for `replacement_pem`, fixing the image's integrity.

    The replacement MUST be exactly the same byte length as the embedded slot:
    the firmware passes a compiled-in length to its PEM parser, so a shorter or
    longer cert would be read against the old length and either truncate ours or
    trail garbage from the one it replaced. `generate_ca_for_slot` exists to
    produce a CA sized to this exact slot.

    After the swap the two integrity fields the cert bytes feed into are
    recomputed — the 1-byte segment checksum and, when present, the appended
    SHA-256 — and the result is re-parsed and re-checked before it is returned.
    Nothing here reaches a device; it only produces the bytes the delivery layer
    will offer over OTA, and a device must never be offered an image we have not
    confirmed is well-formed.

    Raises:
        FirmwareImageError: The input is not an ESP image, does not hold exactly
            one cert, or the replacement is the wrong length.
    """
    image = parse_esp_image(stock)
    start, end = find_cert_slot(stock)
    slot_len = end - start
    if len(replacement_pem) != slot_len:
        raise FirmwareImageError(
            f"replacement certificate is {len(replacement_pem)} bytes but the "
            f"embedded slot is {slot_len} bytes; it must match exactly "
            "(use generate_ca_for_slot to size a CA to this image)")

    patched = bytearray(stock)
    patched[start:end] = replacement_pem

    patched[image.checksum_offset] = _segment_checksum(patched, image)
    if image.hash_appended:
        body = bytes(patched[:image.hash_offset])
        patched[image.hash_offset:] = hashlib.sha256(body).digest()

    out = bytes(patched)
    _assert_patch_consistent(out, replacement_pem)
    log.info("Patched ESP32 firmware: swapped CA in slot [%d:%d], image %d bytes, "
             "md5=%s", start, end, len(out), hashlib.md5(out).hexdigest())
    return out


def _assert_patch_consistent(patched: bytes, replacement_pem: bytes) -> None:
    """Self-check a freshly patched image before anyone can flash it.

    Re-derives the checksum and hash the same way the bootloader would and
    confirms they match what we wrote, and that the one embedded cert is now
    ours. A mismatch here is a bug in this module, caught before a device ever
    sees the bytes rather than as a boot failure in the field.
    """
    image = parse_esp_image(patched)
    if patched[image.checksum_offset] != _segment_checksum(patched, image):
        raise FirmwareImageError("internal: segment checksum mismatch after patch")
    if image.hash_appended:
        body = patched[:image.hash_offset]
        if patched[image.hash_offset:] != hashlib.sha256(body).digest():
            raise FirmwareImageError("internal: appended SHA-256 mismatch after patch")
    start, end = find_cert_slot(patched)
    if patched[start:end] != replacement_pem:
        raise FirmwareImageError("internal: embedded cert is not the replacement")


# --------------------------------------------------------------------------- #
# Sizing a CA to the embedded slot                                            #
# --------------------------------------------------------------------------- #
#
# The swap is length-locked (see patch_firmware_cert), so the CA we mint has to
# serialise to a PEM of the slot's EXACT byte count, framed the way the firmware
# framed the original (line terminator and wrap width copied from it — the D4
# uses CRLF and 64-char lines, which is NOT what `cryptography` emits). The DER
# length is tuned to land the formatted PEM on the target by padding the DN with
# filler and nudging the serial-number length; the signing key is generated once
# and reused across attempts, so the search is fast.


def _slot_framing(slot: bytes) -> tuple[bytes, int]:
    """Infer (line-terminator, base64 wrap width) from an embedded PEM slot.

    Copied from the stock bytes rather than assumed, because the byte length we
    must match depends on both: the D4's slot is CRLF-terminated, so emitting
    `cryptography`'s LF would be 20 bytes short of the same cert.
    """
    eol = b"\r\n" if b"\r\n" in slot else b"\n"
    body = slot.split(b"-----BEGIN CERTIFICATE-----" + eol, 1)[-1]
    first_line = body.split(eol, 1)[0]
    width = len(first_line) if first_line and not first_line.startswith(b"-----") else 64
    return eol, width


def format_cert_pem(cert_der: bytes, template_slot: bytes) -> bytes:
    """Frame a DER certificate as PEM matching `template_slot`'s layout.

    Same markers, same line terminator and wrap width, and NO trailing
    terminator after the END line — the embedded slot ends exactly at the END
    marker, with the NUL the firmware relies on living just past it, outside the
    span we overwrite.
    """
    eol, width = _slot_framing(template_slot)
    b64 = base64.b64encode(cert_der)
    lines = [b64[i:i + width] for i in range(0, len(b64), width)]
    return (b"-----BEGIN CERTIFICATE-----" + eol
            + eol.join(lines) + eol
            + b"-----END CERTIFICATE-----")


def _dn_with_filler(common_name: str, filler_chars: int):
    """A self-signed CA's name (subject == issuer) padded by `filler_chars`.

    The filler is how the DER length is tuned onto the target. It is split into
    organizational-unit attributes of at most 64 characters, because X.509
    caps a single attribute value at 64. The exact text is irrelevant; only its
    length moves the needle.
    """
    from cryptography import x509  # noqa: PLC0415 - optional dependency, probed at use
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    remaining = filler_chars
    while remaining > 0:
        chunk = min(remaining, 64)
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "x" * chunk))
        remaining -= chunk
    return x509.Name(attrs)


#: Extension sets tried from richest to leanest. A leaner set is a smaller DER,
#: so a model whose embedded slot is tighter than the D4's can still be fitted.
#: All include BasicConstraints(CA:TRUE) critical — the one thing the device's
#: mbedTLS actually keys trust-anchor validation off; KeyUsage is deliberately
#: absent, matching the known-working anchor these models already ship.
_EXT_RICH = 0    # BasicConstraints + Subject + Authority Key Identifier
_EXT_SKI = 1     # BasicConstraints + Subject Key Identifier
_EXT_MINIMAL = 2  # BasicConstraints only
_EXT_LEVELS = (_EXT_RICH, _EXT_SKI, _EXT_MINIMAL)


def _build_ca_der(key, common_name: str, filler_chars: int, serial_len: int,
                  years: int, ext_level: int = _EXT_RICH) -> bytes:
    """Build and self-sign a CA with the given tuning knobs; return its DER.

    `ext_level` selects how many identifier extensions to include (see
    `_EXT_LEVELS`); fewer means a shorter certificate, which is how a slot
    smaller than the D4's is reached.
    """
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415

    name = _dn_with_filler(common_name, filler_chars)
    # A positive, DER-minimal serial of an exact byte length: high bit of the
    # top byte clear (so it is not negative and needs no leading 0x00 pad), and
    # a non-zero top byte so the length is really `serial_len`.
    serial = int.from_bytes(bytes([0x10]) + b"\xab" * (serial_len - 1), "big")
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if ext_level in (_EXT_RICH, _EXT_SKI):
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        builder = builder.add_extension(ski, critical=False)
        if ext_level == _EXT_RICH:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def generate_ca_for_slot(template_slot: bytes, *, common_name: str = "petkit-local CA",
                         years: int = 98) -> tuple[bytes, bytes]:
    """Mint a CA whose PEM, framed like `template_slot`, is its EXACT length.

    Returns `(ca_key_pem, ca_cert_pem)`, where `ca_cert_pem` is ready to hand to
    `patch_firmware_cert` (same byte length as the slot, same framing) and
    `ca_key_pem` is the private key the broker's leaf certificate is later signed
    with. The key is 2048-bit RSA (what the stock anchor is, and what these
    devices' TLS offers), generated once; the DER length is walked onto the
    target by padding the DN and nudging the serial length, which is pure
    signing and therefore cheap.

    Raises:
        FirmwareImageError: If no combination within the search bounds hits the
            exact length — which would mean the slot is implausibly small, not a
            normal condition.
    """
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

    target = len(template_slot)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Try each extension set from richest to leanest; a leaner set is a shorter
    # certificate, so it reaches a smaller slot. Within a set, estimate the DN
    # filler needed (each DN char is ~2 DER bytes, ~2.7 PEM bytes after base64)
    # then search a tight band, with the serial length giving the odd-byte
    # adjustment that lands the formatted PEM on the target exactly.
    for ext_level in _EXT_LEVELS:
        base_len = len(format_cert_pem(
            _build_ca_der(key, common_name, 0, 12, years, ext_level), template_slot))
        estimate = max(0, round((target - base_len) / 2.7))
        for filler in range(max(0, estimate - 24), estimate + 48):
            for serial_len in range(8, 21):
                der = _build_ca_der(key, common_name, filler, serial_len, years, ext_level)
                cert_pem = format_cert_pem(der, template_slot)
                if len(cert_pem) == target:
                    key_pem = key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                    log.info("Generated 2048-bit CA fitting the %d-byte cert slot "
                             "(ext_level=%d, filler=%d, serial_len=%d)",
                             target, ext_level, filler, serial_len)
                    return key_pem, cert_pem

    raise FirmwareImageError(
        f"could not size a CA to the {target}-byte certificate slot — the slot "
        "is smaller than a minimal 2048-bit CA certificate")


def issue_server_cert(ca_key_pem: bytes, ca_cert_pem: bytes, common_name: str,
                      *, dns_names: tuple[str, ...] = (),
                      ip_addresses: tuple[str, ...] = (),
                      years: int = 10) -> tuple[bytes, bytes]:
    """Issue a TLS server (leaf) certificate signed by the slot CA.

    This is the other half of the swap: the patched firmware trusts the CA, and
    the device-facing MQTT broker presents THIS leaf — its CN/SAN matching the
    `<pk>.iot-as-mqtt.<region>.aliyuncs.com` hostname the firmware builds and DNS
    redirects to us. Kept here, beside the CA that signs it, so the trust chain
    is defined in one place.

    Returns `(leaf_key_pem, leaf_cert_pem)`. No framing games — this cert is
    served from disk, not embedded, so it is ordinary LF PEM.
    """
    import ipaddress  # noqa: PLC0415
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    ca_cert = x509.load_pem_x509_certificate(_ensure_lf(ca_cert_pem))
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san: list[x509.GeneralName] = [x509.DNSName(n) for n in dns_names]
    for ip in ip_addresses:
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    leaf = builder.sign(ca_key, hashes.SHA256())
    return (
        leaf_key.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption()),
        leaf.public_bytes(serialization.Encoding.PEM),
    )


def _ensure_lf(pem: bytes) -> bytes:
    """Normalise a (possibly CRLF, possibly un-terminated) PEM for loading.

    `generate_ca_for_slot` returns the CA framed for the firmware slot — CRLF,
    no trailing newline. `cryptography`'s loader is happy with that, but
    normalising first keeps this robust if a CA loaded from elsewhere is framed
    differently.
    """
    return pem.replace(b"\r\n", b"\n") if not pem.endswith(b"\n") else pem.replace(b"\r\n", b"\n")
