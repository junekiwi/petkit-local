"""ESP32 firmware patcher — the CA swap, image integrity, and slot-fit CA.

Everything here runs in the default suite with no firmware blob: minimal but
real ESP-IDF images are assembled in-process (the same header, segments,
16-aligned checksum byte and appended SHA-256 the bootloader expects), so the
checksum/hash recompute is exercised against the layout a device actually
verifies, not a mock — multi-segment, with mbedTLS's own PEM marker strings
beside the embedded root, as the real images have them.

`--firmware`-gated tests additionally run against real images dropped in
tests/firmware/ (gitignored): every `*/userbin*.bin` is verified and patched,
and every `oracle*/{stock,patched}.bin` pair is reproduced byte-for-byte from
the stock image and the patched image's own CA — the oracle that proved the
assembler. Populated so far with a D4 1.267 stock image + oracle pair and a
third party's patched T4 1.652.
"""
from __future__ import annotations

import functools
import hashlib
import operator
import os
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from petkit_local.patchers.firmware import (
    FirmwareImageError,
    _xor_fold,
    find_cert_slot,
    format_cert_pem,
    generate_ca_for_slot,
    issue_server_cert,
    parse_esp_image,
    patch_firmware_cert,
    verify_esp_image,
)

#: The real D4 1.267 and T4 1.652 embedded-cert slots are exactly this many
#: bytes (GlobalSign root, DER 889, framed CRLF + 64-wide). Using the true size
#: keeps the default suite honest about what a device asks the generator to fit.
_D4_SLOT_LEN = 1280

_BEGIN = b"-----BEGIN CERTIFICATE-----"
_END = b"-----END CERTIFICATE-----"
#: mbedTLS's own PEM marker strings, as they sit in the firmware's rodata.
_MBEDTLS_BEGIN = _BEGIN + b"\x00"
_MBEDTLS_END = _END + b"\x00"


def _crlf_slot(total_len: int = _D4_SLOT_LEN) -> bytes:
    """A PEM cert block of exactly `total_len` bytes, framed as the firmware
    frames it: CRLF line endings, 64-char base64 lines, no trailing newline past
    the END marker. The base64 is filler — only the framing and length matter,
    which is all `_slot_framing`/`generate_ca_for_slot` read from a template."""
    eol = b"\r\n"
    avail = total_len - (len(_BEGIN) + len(eol) + len(_END))  # body incl. its EOLs
    full, rem = divmod(avail, 64 + len(eol))
    rem_line = rem - len(eol)
    assert rem_line > 0, "pick a total_len that frames cleanly"
    lines = [b"A" * 64] * full + [b"A" * rem_line]
    slot = _BEGIN + eol + eol.join(lines) + eol + _END
    assert len(slot) == total_len
    return slot


def _slot_for_der(der_len: int, eol: bytes = b"\r\n") -> bytes:
    """The slot a `der_len`-byte certificate occupies, framed with `eol`."""
    template = _BEGIN + eol + b"A" * 64 + eol + _END
    return format_cert_pem(bytes(der_len), template)


def _make_esp_image(*segments: bytes, hash_appended: bool = True) -> bytes:
    """Assemble a valid ESP-IDF image from `segments`' data.

    Layout mirrors the real one so the parser and the integrity recompute are
    tested against what a device checks: 8-byte common header, 16-byte extended
    header (byte 23 = hash_appended), the segments, a pad up to the 16-aligned
    checksum byte, then (optionally) the SHA-256 of everything before it. The
    checksum is computed byte by byte here, independently of `_xor_fold`.
    """
    common = bytes([0xE9, len(segments), 0x02, 0x1f]) + struct.pack("<I", 0x40080000)
    ext = bytearray(16)
    ext[15] = 1 if hash_appended else 0  # overall byte 23
    img = bytearray(common + bytes(ext))
    for i, seg in enumerate(segments):
        img += struct.pack("<II", 0x3F400000 + 0x10000 * i, len(seg)) + seg

    offset = len(img)
    checksum_off = ((offset // 16) + 1) * 16 - 1
    img += b"\x00" * (checksum_off - offset)
    xor = 0xEF
    for seg in segments:
        for b in seg:
            xor ^= b
    img.append(xor)
    if hash_appended:
        img += hashlib.sha256(bytes(img)).digest()
    return bytes(img)


def _cert_image(cert_pem: bytes, *, hash_appended: bool = True,
                before: bytes = b"\x00" * 128, after: bytes = b"\x00" * 64) -> bytes:
    """A one-segment image embedding `cert_pem` with a NUL after it, as the
    firmware does."""
    return _make_esp_image(before + cert_pem + b"\x00" + after, hash_appended=hash_appended)


def _assert_only_slot_and_integrity_changed(stock: bytes, patched: bytes) -> None:
    """The patch's contract, checked from the outside."""
    image = parse_esp_image(stock)
    start, end = find_cert_slot(stock)
    assert len(patched) == len(stock)
    assert patched[:start] == stock[:start]
    assert patched[end:image.checksum_offset] == stock[end:image.checksum_offset]
    verify_esp_image(patched)


@pytest.fixture(scope="module")
def ca_pair():
    """Two independently minted CAs sized to the D4 slot (keygen is slow)."""
    template = _crlf_slot()
    return generate_ca_for_slot(template), generate_ca_for_slot(template)


# --------------------------------------------------------------------------- #
# Sizing a CA to the slot                                                     #
# --------------------------------------------------------------------------- #


def test_generate_ca_fits_slot_exactly(ca_pair):
    (_key_pem, ca_pem), _ = ca_pair
    assert len(ca_pem) == _D4_SLOT_LEN
    # It is framed like the slot: CRLF, no trailing newline past END.
    assert b"\r\n" in ca_pem
    assert ca_pem.endswith(_END)
    ca = x509.load_pem_x509_certificate(ca_pem)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True


@pytest.mark.parametrize("eol", [b"\r\n", b"\n"], ids=["crlf", "lf"])
@pytest.mark.parametrize("der_len", [889, 1100, 1391, 1600, 2000])
def test_generate_ca_fits_slots_of_any_plausible_size(der_len, eol):
    # 889 is the GlobalSign root the D4 and T4 embed; 1391 is ISRG Root X1, a
    # 4096-bit root; the rest bracket them. The search used to stop short of
    # anything much larger than the D4's slot and blame the slot for being small.
    slot = _slot_for_der(der_len, eol)
    _, ca_pem = generate_ca_for_slot(slot)
    assert len(ca_pem) == len(slot)
    assert (b"\r\n" in ca_pem) == (eol == b"\r\n")


def test_generate_ca_refuses_a_slot_too_small_for_any_ca():
    with pytest.raises(FirmwareImageError, match="smaller than a minimal"):
        generate_ca_for_slot(_slot_for_der(300))


def test_minted_cas_never_share_a_serial(ca_pair):
    (_, a), (_, b) = ca_pair
    cert_a = x509.load_pem_x509_certificate(a)
    cert_b = x509.load_pem_x509_certificate(b)
    assert cert_a.public_key() != cert_b.public_key()
    assert cert_a.serial_number != cert_b.serial_number


def test_issue_server_cert_chains_to_the_slot_ca(ca_pair):
    (ca_key_pem, ca_pem), _ = ca_pair
    name = "petkit4203e6.iot-as-mqtt.eu-central-1.aliyuncs.com"
    leaf_key_pem, leaf_pem = issue_server_cert(
        ca_key_pem, ca_pem, name, hosts=("192.168.2.75",))

    from cryptography.hazmat.primitives.asymmetric import padding
    ca = x509.load_pem_x509_certificate(ca_pem)
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    assert leaf.issuer == ca.subject
    # The CA's public key verifies the leaf's signature — i.e. the chain is real.
    ca.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes,
        padding.PKCS1v15(), leaf.signature_hash_algorithm)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [name]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["192.168.2.75"]
    assert serialization.load_pem_private_key(leaf_key_pem, password=None)


def test_issue_server_cert_names_its_cn_in_the_san(ca_pair):
    # A client that checks the SAN ignores the CN, so a leaf with no SAN is one
    # that only mbedTLS's CN fallback accepts.
    (ca_key_pem, ca_pem), _ = ca_pair
    _, leaf_pem = issue_server_cert(ca_key_pem, ca_pem, "*.iot-as-mqtt.eu-central-1.aliyuncs.com")
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["*.iot-as-mqtt.eu-central-1.aliyuncs.com"]


# --------------------------------------------------------------------------- #
# The swap                                                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("length", [0, 1, 2, 3, 7, 16, 1001])
def test_xor_fold_matches_a_bytewise_xor(length):
    buf = os.urandom(length)
    assert _xor_fold(buf) == functools.reduce(operator.xor, buf, 0)


def test_patch_swaps_cert_and_fixes_integrity(ca_pair):
    (_, original_ca), (_, replacement_ca) = ca_pair
    img = _cert_image(original_ca)
    patched = patch_firmware_cert(img, replacement_ca)

    start, end = find_cert_slot(patched)
    assert patched[start:end] == replacement_ca
    _assert_only_slot_and_integrity_changed(img, patched)
    # The appended hash is over everything before it, recomputed independently.
    image = parse_esp_image(patched)
    assert patched[image.hash_offset:] == hashlib.sha256(patched[:image.hash_offset]).digest()


def test_patch_covers_every_segment_in_the_checksum(ca_pair):
    # The real images have six segments, and the cert is not in the first. A
    # checksum over only the segment holding the cert would pass a one-segment
    # test and fail every device.
    (_, original_ca), (_, replacement_ca) = ca_pair
    segments = (os.urandom(301), b"\x00" * 40 + original_ca + b"\x00" + os.urandom(77),
                os.urandom(4096), os.urandom(15))
    img = _make_esp_image(*segments)
    patched = patch_firmware_cert(img, replacement_ca)
    _assert_only_slot_and_integrity_changed(img, patched)

    image = parse_esp_image(patched)
    xor = 0xEF
    for off, length in image.segments:
        for b in patched[off:off + length]:
            xor ^= b
    assert patched[image.checksum_offset] == xor


def test_patch_without_appended_hash(ca_pair):
    (_, ca_a), (_, ca_b) = ca_pair
    img = _cert_image(ca_a, hash_appended=False)
    assert parse_esp_image(img).hash_appended is False
    patched = patch_firmware_cert(img, ca_b)
    start, end = find_cert_slot(patched)
    assert patched[start:end] == ca_b
    _assert_only_slot_and_integrity_changed(img, patched)


def test_wrong_length_replacement_is_refused(ca_pair):
    (_, ca), _ = ca_pair
    img = _cert_image(ca)
    _, lf_ca = generate_ca_for_slot(_slot_for_der(889, b"\n"))
    with pytest.raises(FirmwareImageError, match="must match exactly"):
        patch_firmware_cert(img, lf_ca)


def test_a_replacement_that_is_not_a_certificate_is_refused(ca_pair):
    # Right length, right markers, base64 of nothing: flashed, the device's only
    # root would not parse and MQTT TLS could never complete again.
    (_, ca), _ = ca_pair
    with pytest.raises(FirmwareImageError, match="not a usable CA"):
        patch_firmware_cert(_cert_image(ca), _crlf_slot())


def test_a_replacement_that_is_not_a_ca_is_refused(ca_pair):
    (ca_key_pem, ca_pem), _ = ca_pair
    _, leaf_pem = issue_server_cert(ca_key_pem, ca_pem, "leaf.example")
    leaf_der = x509.load_pem_x509_certificate(leaf_pem).public_bytes(serialization.Encoding.DER)
    leaf_slot = format_cert_pem(leaf_der, _crlf_slot())
    with pytest.raises(FirmwareImageError, match="not a CA"):
        patch_firmware_cert(_cert_image(leaf_slot), leaf_slot)


def test_mbedtls_begin_string_before_the_root_is_left_alone(ca_pair):
    # mbedTLS's BEGIN string sits AFTER the root on the D4 only by link order. A
    # build that puts it first must still patch the root, and only the root.
    (_, ca), (_, replacement) = ca_pair
    rodata = b"\x00" * 16 + _MBEDTLS_BEGIN + b"other strings the firmware needs\x00"
    img = _cert_image(ca, before=rodata)
    start, end = find_cert_slot(img)
    assert img[start:end] == ca

    patched = patch_firmware_cert(img, replacement)
    _assert_only_slot_and_integrity_changed(img, patched)
    assert rodata in patched


def test_separate_mbedtls_strings_are_not_a_second_certificate(ca_pair):
    (_, ca), _ = ca_pair
    img = _cert_image(ca, after=_MBEDTLS_BEGIN + _MBEDTLS_END + b"\x00" * 16)
    start, end = find_cert_slot(img)
    assert img[start:end] == ca


def test_zero_or_multiple_certs_refused(ca_pair):
    img = _make_esp_image(b"no cert here, just filler bytes for the segment body")
    with pytest.raises(FirmwareImageError, match="found 0"):
        find_cert_slot(img)

    (_, ca), _ = ca_pair
    two = _cert_image(ca, after=b"\x00" + ca + b"\x00" * 16)
    with pytest.raises(FirmwareImageError, match="found 2"):
        find_cert_slot(two)


# --------------------------------------------------------------------------- #
# What is refused before any byte is touched                                  #
# --------------------------------------------------------------------------- #


def test_non_esp_image_is_refused():
    with pytest.raises(FirmwareImageError, match="not an ESP image"):
        parse_esp_image(b"\x7fELF" + b"\x00" * 1000)


def test_a_refusal_names_what_was_checked():
    with pytest.raises(FirmwareImageError, match="^the PetKit download: not an ESP image"):
        verify_esp_image(b"<html>502 Bad Gateway</html>", "the PetKit download")


def test_truncated_segment_table_is_refused():
    # Claims 3 segments but carries no segment data.
    header = bytes([0xE9, 3, 0x02, 0x1f]) + struct.pack("<I", 0) + b"\x00" * 16
    with pytest.raises(FirmwareImageError, match="runs past the end"):
        parse_esp_image(header + struct.pack("<II", 0, 999999))


def test_bytes_after_the_image_are_refused(ca_pair):
    # 0xFF sector padding or a Secure Boot signature block: the swap would
    # silently drop or invalidate either, so neither is patched.
    (_, ca), (_, replacement) = ca_pair
    img = _cert_image(ca) + b"\xff" * 4064
    with pytest.raises(FirmwareImageError, match="4064 bytes follow the image's hash"):
        patch_firmware_cert(img, replacement)


def test_a_corrupted_segment_is_refused_not_re_signed(ca_pair):
    (_, ca), (_, replacement) = ca_pair
    img = bytearray(_cert_image(ca))
    img[40] ^= 0x01  # inside the segment, before the cert
    with pytest.raises(FirmwareImageError, match="stock firmware: segment checksum"):
        patch_firmware_cert(bytes(img), replacement)


def test_a_corrupted_hash_is_refused(ca_pair):
    (_, ca), (_, replacement) = ca_pair
    img = bytearray(_cert_image(ca))
    img[-1] ^= 0x01
    with pytest.raises(FirmwareImageError, match="stock firmware: appended SHA-256"):
        patch_firmware_cert(bytes(img), replacement)


# --------------------------------------------------------------------------- #
# Optional: against real images, if present (gitignored).                     #
# --------------------------------------------------------------------------- #
_FIRMWARE_DIR = Path(__file__).parent / "firmware"


def _real_images() -> list[Path]:
    return sorted(_FIRMWARE_DIR.glob("*/userbin*.bin")) + sorted(_FIRMWARE_DIR.glob("oracle*/*.bin"))


@pytest.mark.firmware
def test_real_images_are_intact_and_share_the_d4_slot():
    """Every real image verifies as its bootloader would, and holds one root in
    a 1280-byte CRLF slot — so one CA fits the D4 and the T4 alike.

    A third party's PATCHED image counts as much as a stock one here: it boots
    on real hardware, so our checksum/hash model agreeing with it is evidence.
    """
    images = _real_images()
    if not images:
        pytest.skip("no tests/firmware/*/userbin*.bin or oracle*/ images present")
    for path in images:
        data = path.read_bytes()
        verify_esp_image(data, str(path))
        start, end = find_cert_slot(data)
        assert end - start == _D4_SLOT_LEN, path
        assert b"\r\n" in data[start:end], path
        # mbedTLS's own END string was merged into the root's tail: it exists
        # nowhere else, which is why the END line must not move.
        assert data.count(_END) == 1, path


@pytest.mark.firmware
def test_patch_real_userbin_roundtrips():
    """Patch each real image with a freshly minted CA and re-verify it.

    Drop an image at tests/firmware/<model>/userbin.bin. The test sizes a CA to
    its embedded slot, swaps it in, and confirms the result changed only in the
    slot and the integrity fields, with mbedTLS's own PEM strings intact.
    """
    images = sorted(_FIRMWARE_DIR.glob("*/userbin*.bin"))
    if not images:
        pytest.skip("no tests/firmware/*/userbin*.bin present")
    for path in images:
        stock = path.read_bytes()
        start, end = find_cert_slot(stock)
        _, ca = generate_ca_for_slot(stock[start:end])
        patched = patch_firmware_cert(stock, ca)
        _assert_only_slot_and_integrity_changed(stock, patched)
        assert patched[start:end] == ca
        assert patched.count(_MBEDTLS_BEGIN) == stock.count(_MBEDTLS_BEGIN) == 1, path
        assert patched.count(_END) == 1, path


@pytest.mark.firmware
def test_reproduces_known_patched_images():
    """Oracle: stock + a known patched image's own CA == that patched image.

    Drop pairs at tests/firmware/oracle*/{stock,patched}.bin (`oracle/` holds
    the D4 1.267 pair). Proves the assembler (checksum + appended hash) matches
    an image that actually boots on hardware.
    """
    pairs = [d for d in sorted(_FIRMWARE_DIR.glob("oracle*"))
             if (d / "stock.bin").exists() and (d / "patched.bin").exists()]
    if not pairs:
        pytest.skip("no tests/firmware/oracle*/{stock,patched}.bin present")
    for pair in pairs:
        stock = (pair / "stock.bin").read_bytes()
        patched = (pair / "patched.bin").read_bytes()
        s, e = find_cert_slot(patched)
        out = patch_firmware_cert(stock, patched[s:e])
        assert hashlib.md5(out).hexdigest() == hashlib.md5(patched).hexdigest(), pair
