"""ESP32 firmware patcher — the CA swap, image integrity, and slot-fit CA.

Everything here runs in the default suite with no firmware blob: a minimal but
real ESP-IDF image is assembled in-process (the same header, segment, 16-aligned
checksum byte and appended SHA-256 the bootloader expects), so the checksum/hash
recompute is exercised against the layout a device actually verifies, not a mock.

A `--firmware`-gated test additionally runs against a real `userbin.bin` if one
is dropped in tests/firmware/ (gitignored), including reproducing a known
third-party patched image byte-for-byte when its CA is supplied — the oracle that
proved the assembler.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from petkit_local.patchers.firmware import (
    FirmwareImageError,
    find_cert_slot,
    generate_ca_for_slot,
    issue_server_cert,
    parse_esp_image,
    patch_firmware_cert,
)

#: The real D4 1.267 embedded-cert slot is exactly this many bytes (GlobalSign
#: root, DER 889, framed CRLF + 64-wide). Using the true size keeps the default
#: suite honest about what a device actually asks the CA generator to fit.
_D4_SLOT_LEN = 1280


def _crlf_slot(total_len: int = _D4_SLOT_LEN) -> bytes:
    """A PEM cert block of exactly `total_len` bytes, framed as the firmware
    frames it: CRLF line endings, 64-char base64 lines, no trailing newline past
    the END marker. The base64 is filler — only the framing and length matter,
    which is all `_slot_framing`/`generate_ca_for_slot` read from a template."""
    begin, end, eol = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----", b"\r\n"
    avail = total_len - (len(begin) + len(eol) + len(end))  # body incl. its EOLs
    full, rem = divmod(avail, 64 + len(eol))
    rem_line = rem - len(eol)
    assert rem_line > 0, "pick a total_len that frames cleanly"
    lines = [b"A" * 64] * full + [b"A" * rem_line]
    slot = begin + eol + eol.join(lines) + eol + end
    assert len(slot) == total_len
    return slot


def _make_esp_image(cert_pem: bytes, *, hash_appended: bool = True,
                    lead: bytes = b"\x00" * 128, trail: bytes = b"\x00" * 64) -> bytes:
    """Assemble a minimal valid single-segment ESP-IDF image embedding `cert_pem`.

    Layout mirrors the real one so the parser and the integrity recompute are
    tested against what a device checks: 8-byte common header, 16-byte extended
    header (byte 23 = hash_appended), one segment, a pad up to the 16-aligned
    checksum byte, then (optionally) the SHA-256 of everything before it.
    """
    seg_data = lead + cert_pem + b"\x00" + trail  # NUL after END, like the firmware
    common = bytes([0xE9, 1, 0x02, 0x1f]) + struct.pack("<I", 0x40080000)
    ext = bytearray(16)
    ext[15] = 1 if hash_appended else 0  # overall byte 23
    img = bytearray(common + bytes(ext))
    img += struct.pack("<II", 0x3F400000, len(seg_data)) + seg_data

    offset = len(img)
    checksum_off = ((offset // 16) + 1) * 16 - 1
    img += b"\x00" * (checksum_off - offset)
    xor = 0xEF
    for b in seg_data:
        xor ^= b
    img.append(xor)
    if hash_appended:
        img += hashlib.sha256(bytes(img)).digest()
    return bytes(img)


def test_generate_ca_fits_slot_exactly():
    template = _crlf_slot()
    key_pem, ca_pem = generate_ca_for_slot(template)
    assert len(ca_pem) == len(template)
    # It is framed like the slot: CRLF, no trailing newline past END.
    assert b"\r\n" in ca_pem
    assert ca_pem.endswith(b"-----END CERTIFICATE-----")
    # And it is a usable CA whose key we hold (it can sign a leaf that verifies).
    from cryptography import x509
    ca = x509.load_pem_x509_certificate(ca_pem.replace(b"\r\n", b"\n"))
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True


def test_issue_server_cert_chains_to_the_slot_ca():
    template = _crlf_slot()
    ca_key_pem, ca_pem = generate_ca_for_slot(template)
    leaf_key_pem, leaf_pem = issue_server_cert(
        ca_key_pem, ca_pem, "petkit4203e6.iot-as-mqtt.eu-central-1.aliyuncs.com",
        dns_names=("petkit4203e6.iot-as-mqtt.eu-central-1.aliyuncs.com",),
        ip_addresses=("192.168.2.75",))

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding
    ca = x509.load_pem_x509_certificate(ca_pem.replace(b"\r\n", b"\n"))
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    assert leaf.issuer == ca.subject
    # The CA's public key verifies the leaf's signature — i.e. the chain is real.
    ca.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes,
        padding.PKCS1v15(), leaf.signature_hash_algorithm)
    assert leaf_key_pem.startswith(b"-----BEGIN")


def test_patch_swaps_cert_and_fixes_integrity():
    template = _crlf_slot()
    _, original_ca = generate_ca_for_slot(template)
    _, replacement_ca = generate_ca_for_slot(template)
    assert original_ca != replacement_ca  # different keys/serials
    assert len(original_ca) == len(replacement_ca)

    img = _make_esp_image(original_ca)
    patched = patch_firmware_cert(img, replacement_ca)

    assert len(patched) == len(img)
    start, end = find_cert_slot(patched)
    assert patched[start:end] == replacement_ca
    # Integrity fields the swap invalidated were recomputed: the self-check in
    # patch_firmware_cert already asserts this, but prove it independently here.
    image = parse_esp_image(patched)
    body = patched[:image.hash_offset]
    assert patched[image.hash_offset:] == hashlib.sha256(body).digest()


def test_patch_without_appended_hash():
    template = _crlf_slot()
    _, ca_a = generate_ca_for_slot(template)
    _, ca_b = generate_ca_for_slot(template)
    img = _make_esp_image(ca_a, hash_appended=False)
    assert parse_esp_image(img).hash_appended is False
    patched = patch_firmware_cert(img, ca_b)
    start, end = find_cert_slot(patched)
    assert patched[start:end] == ca_b


def test_wrong_length_replacement_is_refused():
    template = _crlf_slot()
    _, ca = generate_ca_for_slot(template)
    img = _make_esp_image(ca)
    with pytest.raises(FirmwareImageError, match="must match exactly"):
        patch_firmware_cert(img, ca + b"extra")


def test_non_esp_image_is_refused():
    with pytest.raises(FirmwareImageError, match="not an ESP image"):
        parse_esp_image(b"\x7fELF" + b"\x00" * 1000)


def test_truncated_segment_table_is_refused():
    # Claims 3 segments but carries no segment data.
    header = bytes([0xE9, 3, 0x02, 0x1f]) + struct.pack("<I", 0) + b"\x00" * 16
    with pytest.raises(FirmwareImageError, match="runs past the end"):
        parse_esp_image(header + struct.pack("<II", 0, 999999))


def test_zero_or_multiple_certs_refused():
    img = _make_esp_image(b"no cert here, just filler bytes for the segment body")
    with pytest.raises(FirmwareImageError, match="found 0"):
        find_cert_slot(img)

    template = _crlf_slot()
    _, ca = generate_ca_for_slot(template)
    two = _make_esp_image(ca, trail=b"\x00" + ca + b"\x00" * 16)
    with pytest.raises(FirmwareImageError, match="found 2"):
        find_cert_slot(two)


# --------------------------------------------------------------------------- #
# Optional: against a real userbin.bin if one is present (gitignored).        #
# --------------------------------------------------------------------------- #
_FIRMWARE_DIR = Path(__file__).parent / "firmware"


@pytest.mark.firmware
def test_patch_real_userbin_roundtrips():
    """Patch a real ESP32 image with a freshly minted CA and re-verify it.

    Drop a stock image at tests/firmware/<model>/userbin.bin. The test sizes a
    CA to its embedded slot, swaps it in, and confirms the result re-parses with
    valid integrity fields and exactly our CA embedded.
    """
    images = sorted(_FIRMWARE_DIR.glob("*/userbin*.bin"))
    if not images:
        pytest.skip("no tests/firmware/*/userbin*.bin present")
    for path in images:
        stock = path.read_bytes()
        start, end = find_cert_slot(stock)
        _, ca = generate_ca_for_slot(stock[start:end])
        patched = patch_firmware_cert(stock, ca)
        assert len(patched) == len(stock)
        s2, e2 = find_cert_slot(patched)
        assert patched[s2:e2] == ca


@pytest.mark.firmware
def test_reproduces_known_patched_image():
    """Oracle: stock + a known patched image's own CA == that patched image.

    Drop both at tests/firmware/oracle/{stock,patched}.bin. Proves the assembler
    (checksum + appended hash) matches an image that actually boots on hardware.
    """
    stock_p = _FIRMWARE_DIR / "oracle" / "stock.bin"
    patched_p = _FIRMWARE_DIR / "oracle" / "patched.bin"
    if not (stock_p.exists() and patched_p.exists()):
        pytest.skip("no tests/firmware/oracle/{stock,patched}.bin present")
    stock = stock_p.read_bytes()
    patched = patched_p.read_bytes()
    s, e = find_cert_slot(patched)
    out = patch_firmware_cert(stock, patched[s:e])
    assert hashlib.md5(out).hexdigest() == hashlib.md5(patched).hexdigest()
