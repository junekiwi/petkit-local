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
verify the stock image's own integrity fields BEFORE touching it (a corrupted
download must be refused, not re-signed into one that looks valid), produce the
patched image, then verify it changed in the slot and the two integrity fields
and nowhere else — and keep the untouched stock image so "rollback" is just
serving that back.

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
reproduces that image's exact MD5 (see tests/test_patcher_esp32.py). The same
third party's patched T4 1.652 image passes `verify_esp_image` and has the D4's
layout: six segments, hash appended, the root in a 1280-byte CRLF slot.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import logging
import re
import secrets
import struct
from dataclasses import dataclass

from petkit_local.patchers.common import md5hex
from petkit_local.utils.tls import subject_alt_names

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

_PEM_END = b"-----END CERTIFICATE-----"

#: One PEM certificate, anchored to PEM's own structure: the BEGIN line ends in
#: a line break, and nothing but base64 and line breaks may follow it until END.
#: An ESP32 image holds mbedTLS's own `-----BEGIN CERTIFICATE-----\0` string as
#: well as the embedded root, and a lazy `BEGIN.*?END` happily starts at that
#: string and runs through whatever rodata lies between it and the next END —
#: a "certificate" that is really strings the firmware needs. The NUL after the
#: marker is what this refuses.
#:
#: Deliberately NOT `patchers/cacert.py`'s pattern, which is lazy on purpose: a
#: CA bundle block it cannot parse must still be found so it can be KEPT, while
#: here a block that is not clean PEM must not be found, so it is never patched.
_PEM_CERT_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+" + re.escape(_PEM_END))


class FirmwareImageError(ValueError):
    """The bytes we were handed are not a patchable ESP-IDF image.

    A `ValueError` on purpose: the same family as `patchers/verify.py`'s
    refusals, and for the same reason — a download that is truncated, an HTML
    error page, or a firmware from an unexpected build must stop here with a
    message naming what arrived, not sail into the byte surgery below.
    """


@dataclass(frozen=True, slots=True)
class _EspImage:
    """Parsed layout of an ESP-IDF image: where the segments, checksum and
    appended hash live. Just enough to verify and recompute the two integrity
    fields the cert swap invalidates — not a general loader."""

    segments: tuple[tuple[int, int], ...]  # (data_offset, data_length)
    checksum_offset: int
    hash_appended: bool

    @property
    def hash_offset(self) -> int:
        """Where the appended SHA-256 starts (== end of the hashed body)."""
        return self.checksum_offset + 1

    @property
    def end(self) -> int:
        """Where the image ends: after the hash, or after the checksum byte."""
        return self.hash_offset + (_APPENDED_HASH_LEN if self.hash_appended else 0)


def parse_esp_image(data: bytes) -> _EspImage:
    """Walk the segment table and locate the checksum byte and appended hash.

    The segment walk is bounded by the declared segment count and the buffer
    length; a count or a segment length that runs past the end raises rather
    than reading out of bounds, because that is exactly what a truncated or
    non-ESP download looks like.

    Bytes AFTER the image are refused too. ESP-IDF can append a Secure Boot
    signature block there, which the swap would invalidate, and anything else
    found there is a layout this module does not account for. Both real images
    examined (D4 1.267, T4 1.652) end exactly at the hash.

    Raises:
        FirmwareImageError: Not an ESP image, its segment table does not fit
            the bytes we have, or bytes follow the image.
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
    image = _EspImage(segments=tuple(segments),
                      checksum_offset=((offset // 16) + 1) * 16 - 1,
                      hash_appended=bool(data[_HASH_APPENDED_OFFSET]))
    if len(data) < image.end:
        raise FirmwareImageError(
            f"image ends before its checksum/hash (have {len(data)} bytes, "
            f"segments imply {image.end})")
    if len(data) > image.end:
        raise FirmwareImageError(
            f"{len(data) - image.end} bytes follow the image's "
            f"{'hash' if image.hash_appended else 'checksum'} — a signature "
            "block or padding this patcher cannot preserve across the swap")
    return image


def _xor_fold(buf: bytes) -> int:
    """XOR of every byte in `buf`, folded in C rather than looped in Python.

    The halves of a byte string XORed together have the same byte-wise XOR as
    the whole, so the buffer is read as one integer and folded in half until a
    single byte is left — ~20 big-int operations for a 1.4 MB image instead of
    1.4 M interpreter iterations.
    """
    width = len(buf)
    value = int.from_bytes(buf, "little")
    while width > 1:
        half = (width + 1) // 2
        value = (value & ((1 << (8 * half)) - 1)) ^ (value >> (8 * half))
        width = half
    return value


def _segment_checksum(data: bytes, image: _EspImage) -> int:
    """The bootloader's 1-byte segment checksum: 0xEF XOR of all segment data."""
    xor = _CHECKSUM_SEED
    for offset, length in image.segments:
        xor ^= _xor_fold(data[offset:offset + length])
    return xor


def verify_esp_image(data: bytes, what: str = "image") -> _EspImage:
    """Parse `data` and check its checksum and appended hash, as a device would.

    `what` names the bytes in the error ("stock firmware", "the PetKit
    download"), so a failed fetch reads as a transport problem rather than a
    mystery deeper in the patcher. This is the only integrity check a
    downloaded image gets: the patcher REGENERATES both fields, so anything it
    does not catch here leaves as a corrupted image with valid checksums.

    Raises:
        FirmwareImageError: Unparseable, or an integrity field does not match.
    """
    try:
        image = parse_esp_image(data)
    except FirmwareImageError as e:
        raise FirmwareImageError(f"{what}: {e}") from None
    if data[image.checksum_offset] != _segment_checksum(data, image):
        raise FirmwareImageError(
            f"{what}: segment checksum does not match its contents — the image "
            "is corrupted (a bad transfer, or bytes altered after it was built)")
    if image.hash_appended:
        body = data[:image.hash_offset]
        if data[image.hash_offset:image.end] != hashlib.sha256(body).digest():
            raise FirmwareImageError(
                f"{what}: appended SHA-256 does not match its contents — the "
                "image is corrupted (a bad transfer, or bytes altered after it "
                "was built)")
    return image


def find_cert_slot(data: bytes, image: _EspImage | None = None) -> tuple[int, int]:
    """Return the (start, end) byte span of the ONE embedded CA certificate.

    A stock ESP32 image trusts exactly one root, embedded as a single PEM block.
    Requiring exactly one is the guard: zero means this build embeds its trust
    differently (DER, a bundle, a different segment) and the swap below would be
    wrong; more than one means the same, and silently patching the first would
    leave the device trusting a cloud root we do not control. Either way we
    refuse rather than mis-patch.

    The match is anchored to PEM structure (`_PEM_CERT_BLOCK`), because
    the image also holds mbedTLS's own `-----BEGIN CERTIFICATE-----\\0` string
    (on the D4 1.267 at offset 223348, after the root only by link order) and a
    looser pattern starting there would span unrelated rodata. The span must
    also lie inside one segment's data: a match that crosses a segment header is
    not a string the firmware ever reads.

    Raises:
        FirmwareImageError: If the image does not contain exactly one PEM cert,
            or the one it holds is not inside a segment.
    """
    spans = [m.span() for m in _PEM_CERT_BLOCK.finditer(data)]
    if len(spans) != 1:
        raise FirmwareImageError(
            f"expected exactly one embedded CA certificate, found {len(spans)} "
            "— this firmware embeds its trust anchor differently and is not "
            "supported by the CA swap")
    start, end = spans[0]
    image = image or parse_esp_image(data)
    if not any(off <= start and end <= off + length for off, length in image.segments):
        raise FirmwareImageError(
            f"the embedded certificate at [{start}:{end}] is not inside one "
            "segment's data")
    return start, end


def _assert_usable_ca(pem: bytes) -> None:
    """Refuse a replacement that could not serve as the device's trust anchor.

    It becomes the ONLY root the device trusts, so a body that does not parse,
    or a certificate that is not a CA, leaves a device that can never complete
    MQTT TLS again — well-formed image, valid checksums, and no way back except
    the HTTP heartbeat.
    """
    from cryptography import x509  # noqa: PLC0415 - optional dependency, probed at use

    if _PEM_CERT_BLOCK.fullmatch(pem) is None:
        raise FirmwareImageError(
            "replacement is not a single PEM certificate (BEGIN line, base64, "
            "END line, nothing after it)")
    try:
        cert = x509.load_pem_x509_certificate(pem)
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except (ValueError, x509.ExtensionNotFound) as e:
        raise FirmwareImageError(
            f"replacement is not a usable CA certificate: {e}") from None
    if not constraints.ca:
        raise FirmwareImageError(
            "replacement certificate is not a CA (BasicConstraints CA:FALSE)")


def patch_firmware_cert(stock: bytes, replacement_pem: bytes) -> bytes:
    """Swap the embedded CA for `replacement_pem`, fixing the image's integrity.

    The replacement MUST be exactly the same byte length as the embedded slot.
    The slot sits in rodata between other strings and is terminated by the NUL
    after its END line, so a longer cert overwrites a neighbour and a shorter
    one leaves the old tail behind. And the END line itself must stay where it
    was: the linker merged mbedTLS's own `-----END CERTIFICATE-----` string into
    the slot's last 25 bytes (the D4 and T4 images hold that string nowhere
    else), so the PEM reader every certificate goes through finds its END marker
    there. A same-length PEM ending in that marker keeps both intact.
    `generate_ca_for_slot` exists to produce a CA sized to this exact slot.

    The stock image's own checksum and hash are verified first, the two fields
    are recomputed after the swap, and the result is checked to differ from the
    stock image in the slot, the checksum byte and the hash and nowhere else.
    Nothing here reaches a device; it only produces the bytes the delivery layer
    will offer over OTA, and a device must never be offered an image we have not
    confirmed is well-formed.

    Raises:
        FirmwareImageError: The stock image is not an intact ESP image or does
            not hold exactly one cert, or the replacement is not a CA of the
            slot's exact length.
    """
    image = verify_esp_image(stock, "stock firmware")
    start, end = find_cert_slot(stock, image)
    slot_len = end - start
    if len(replacement_pem) != slot_len:
        raise FirmwareImageError(
            f"replacement certificate is {len(replacement_pem)} bytes but the "
            f"embedded slot is {slot_len} bytes; it must match exactly "
            "(use generate_ca_for_slot to size a CA to this image)")
    _assert_usable_ca(replacement_pem)

    patched = bytearray(stock)
    patched[start:end] = replacement_pem
    # Only the slot changed, so the checksum moves by exactly the difference.
    patched[image.checksum_offset] = (stock[image.checksum_offset]
                                      ^ _xor_fold(stock[start:end])
                                      ^ _xor_fold(replacement_pem))
    if image.hash_appended:
        patched[image.hash_offset:image.end] = hashlib.sha256(
            bytes(patched[:image.hash_offset])).digest()

    out = bytes(patched)
    _assert_patch_consistent(stock, out, replacement_pem, (start, end), image)
    log.info("Patched ESP32 firmware: swapped CA in slot [%d:%d], image %d bytes, "
             "md5=%s", start, end, len(out), md5hex(out))
    return out


def _assert_patch_consistent(stock: bytes, patched: bytes, replacement_pem: bytes,
                             slot: tuple[int, int], image: _EspImage) -> None:
    """Self-check a freshly patched image before anyone can flash it.

    Re-verifies the checksum and hash from scratch, the way the bootloader
    would, and confirms the image changed in the slot and the two integrity
    fields and nowhere else. A mismatch here is a bug in this module, caught
    before a device ever sees the bytes rather than as a boot failure in the
    field.
    """
    start, end = slot
    try:
        verify_esp_image(patched, "patched image")
    except FirmwareImageError as e:
        raise FirmwareImageError(f"internal: {e}") from None
    if len(patched) != len(stock):
        raise FirmwareImageError("internal: patched image changed length")
    if (patched[:start] != stock[:start]
            or patched[end:image.checksum_offset] != stock[end:image.checksum_offset]):
        raise FirmwareImageError("internal: bytes outside the cert slot changed")
    if find_cert_slot(patched) != slot or patched[start:end] != replacement_pem:
        raise FirmwareImageError("internal: embedded cert is not the replacement")


# --------------------------------------------------------------------------- #
# Sizing a CA to the embedded slot                                            #
# --------------------------------------------------------------------------- #
#
# The swap is length-locked (see patch_firmware_cert), so the CA we mint has to
# serialise to a PEM of the slot's EXACT byte count, framed the way the firmware
# framed the original (line terminator and wrap width copied from it — the D4
# and T4 use CRLF and 64-char lines, which is NOT what `cryptography` emits).
# The DER length is tuned to land the formatted PEM on the target by padding
# the DN with filler and nudging the serial-number length; the signing key is
# generated once and reused across attempts, so the search is fast.


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
            + _PEM_END)


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

#: Serial-number lengths, in bytes, the search may use. Each extra byte is one
#: more DER byte, which is what fills the gap one filler character cannot.
_SERIAL_MIN = 8
_SERIAL_MAX = 20
#: Upper bound on DN filler. The name is in the certificate twice (subject and
#: issuer), so this reaches ~15 KB of PEM — far beyond any root a firmware
#: would embed (a 4096-bit RSA root is ~1.9 KB).
_FILLER_MAX = 3000


def _random_serial(serial_len: int) -> int:
    """A random positive serial of EXACTLY `serial_len` DER bytes.

    The top byte is drawn from 0x10..0x7f: non-zero, so the length is really
    `serial_len`, and with the high bit clear, so DER needs no 0x00 pad to keep
    it positive. Random rather than fixed because a re-minted CA (lost key,
    rotation) would otherwise repeat the old one's issuer and serial with a
    different key — which RFC 5280 forbids and NSS-based clients reject.
    """
    top = 0x10 + secrets.randbelow(0x70)
    return int.from_bytes(bytes([top]) + secrets.token_bytes(serial_len - 1), "big")


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
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_random_serial(serial_len))
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


def _fit_ca_der(key, common_name: str, years: int, ext_level: int,
                template_slot: bytes) -> bytes | None:
    """The DER of a CA at `ext_level` whose framed PEM is the slot's length.

    Framed length only grows with filler (each character is a DER byte, every
    64th a whole new attribute) and with serial length, so the search bisects
    for the first filler whose LONGEST serial reaches the target, then walks up
    until even the SHORTEST serial overshoots — a dozen fillers at most, each
    trying every serial length. Returns None when this extension set cannot
    land on the target at all.
    """
    target = len(template_slot)

    def framed_len(filler: int, serial_len: int) -> int:
        der = _build_ca_der(key, common_name, filler, serial_len, years, ext_level)
        return len(format_cert_pem(der, template_slot))

    if (framed_len(0, _SERIAL_MIN) > target
            or framed_len(_FILLER_MAX, _SERIAL_MAX) < target):
        return None
    lo, hi = 0, _FILLER_MAX
    while lo < hi:
        mid = (lo + hi) // 2
        if framed_len(mid, _SERIAL_MAX) >= target:
            hi = mid
        else:
            lo = mid + 1
    for filler in range(lo, _FILLER_MAX + 1):
        for serial_len in range(_SERIAL_MIN, _SERIAL_MAX + 1):
            der = _build_ca_der(key, common_name, filler, serial_len, years, ext_level)
            framed = len(format_cert_pem(der, template_slot))
            if framed == target:
                log.info("Generated 2048-bit CA fitting the %d-byte cert slot "
                         "(ext_level=%d, filler=%d, serial_len=%d)",
                         target, ext_level, filler, serial_len)
                return der
            if framed > target:
                if serial_len == _SERIAL_MIN:
                    return None  # every longer filler overshoots too
                break
    return None


def generate_ca_for_slot(template_slot: bytes, *, common_name: str = "petkit-local CA",
                         years: int = 98) -> tuple[bytes, bytes]:
    """Mint a CA whose PEM, framed like `template_slot`, is its EXACT length.

    Returns `(ca_key_pem, ca_cert_pem)`, where `ca_cert_pem` is ready to hand to
    `patch_firmware_cert` (same byte length as the slot, same framing) and
    `ca_key_pem` is the private key the broker's leaf certificate is later signed
    with. The key is 2048-bit RSA (what the stock anchor is, and what these
    devices' TLS offers), generated once; the DER length is walked onto the
    target by padding the DN and nudging the serial length, which is pure
    signing and therefore cheap. Extension sets are tried richest first.

    Raises:
        FirmwareImageError: If no extension set lands on the exact length —
            the slot is smaller than a minimal CA, or larger than the filler
            bound reaches.
    """
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for ext_level in _EXT_LEVELS:
        der = _fit_ca_der(key, common_name, years, ext_level, template_slot)
        if der is not None:
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            return key_pem, format_cert_pem(der, template_slot)

    raise FirmwareImageError(
        f"could not size a CA to the {len(template_slot)}-byte certificate slot "
        f"— it is either smaller than a minimal 2048-bit CA or larger than "
        f"{_FILLER_MAX} characters of name padding can reach")


def issue_server_cert(ca_key_pem: bytes, ca_cert_pem: bytes, common_name: str,
                      *, hosts: tuple[str, ...] = (),
                      years: int = 10) -> tuple[bytes, bytes]:
    """Issue a TLS server (leaf) certificate signed by the slot CA.

    This is the other half of the swap: the patched firmware trusts the CA, and
    the device-facing MQTT broker presents THIS leaf — its CN and SAN naming the
    `<pk>.iot-as-mqtt.<region>.aliyuncs.com` hostname the firmware builds and DNS
    redirects to us. `common_name` is always in the SAN as well (a client that
    checks the SAN ignores the CN), followed by `hosts`, each an address or a
    name. Kept here, beside the CA that signs it, so the trust chain is defined
    in one place.

    Returns `(leaf_key_pem, leaf_cert_pem)`. No framing games — this cert is
    served from disk, not embedded, so it is ordinary LF PEM.
    """
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    # `cryptography` reads the slot framing (CRLF, no trailing newline) as is.
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(
            subject_alt_names([common_name, *hosts])), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf_key.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption()),
        leaf.public_bytes(serialization.Encoding.PEM),
    )
