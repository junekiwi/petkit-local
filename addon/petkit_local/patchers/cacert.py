"""CA certificate patcher.

Appends the add-on's self-signed TLS certificate to the device's Mozilla CA
bundle (/app/bin/ca.crt) so the cloud binary trusts our local bucket for media
uploads.

All patching is done server-side: download ca.crt → append our cert PEM → upload
back → bind-mount + restart cloud.
"""
from __future__ import annotations

import logging
import os
import re

from petkit_local.patchers.common import md5hex
from petkit_local.patchers.verify import assert_ca_bundle

log = logging.getLogger(__name__)


#: Lazy on purpose, unlike `patchers/firmware.py`'s anchored pattern: a block in
#: the device's bundle that is not clean PEM must still be FOUND, because
#: `patch_ca_bundle` keeps every block it cannot parse rather than dropping a CA.
_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def _subject_of(pem: bytes) -> bytes | None:
    """A certificate's subject, or None if it cannot be read.

    None is the honest answer for both "cryptography is not installed" and
    "this block is not a certificate we can parse", and both callers treat it
    the same way: keep the block. Losing a real CA is far worse than leaving a
    stale copy of ours behind.
    """
    try:
        from cryptography import x509  # noqa: PLC0415 - optional dependency
        return x509.load_pem_x509_certificate(pem).subject.public_bytes()
    except Exception:  # noqa: BLE001 - any failure means "cannot tell"
        return None


def patch_ca_bundle(original: bytes | None, our_cert_pem: bytes) -> bytes:
    """Put exactly ONE copy of our current cert in the device's CA bundle.

    Raises:
        ValueError: If either side is not a PEM bundle.

    Both inputs are validated because an empty `original` must not read as "the
    device has no CA bundle": that would write a /app/bin/ca.crt holding ONLY
    our certificate and leave the device unable to verify any other TLS peer.
    Every device ships a bundle (226 KB on a T5, 11 KB on a D4SH), so an empty
    read means the download failed, not that there is nothing to keep.

    Why strip-then-append rather than a blind append. Our certificate can be
    regenerated -- a new SAN, a new key -- and appending every time left the
    OLD ones in the bundle. The device's OpenSSL picks the FIRST certificate
    whose subject matches the one it was served as the trust anchor, so a
    stale copy with a different key fails verification even though the right
    certificate is also present, a few entries further down. Every certificate
    sharing our current subject is therefore removed and ours appended, leaving
    one.

    A block we cannot parse is kept, because "unreadable" must never mean
    "discard a CA". And re-applying the patch is now idempotent rather than an
    error: the second run simply replaces the copy the first one left.
    """
    if b"-----BEGIN CERTIFICATE-----" not in our_cert_pem:
        raise ValueError("our_cert_pem is not valid PEM")

    assert_ca_bundle(original or b"", "device ca.crt")
    assert original is not None  # narrowed by assert_ca_bundle

    blocks = _PEM_BLOCK.findall(original)
    original_count = len(blocks)
    ours = _subject_of(our_cert_pem)

    kept: list[bytes] = []
    dropped = 0
    for block in blocks:
        subject = _subject_of(block)
        # With `cryptography` unavailable both subjects are None, and the
        # comparison degrades to the exact-bytes check this used to do.
        same = (subject == ours) if (ours is not None and subject is not None) \
            else (block.strip() == our_cert_pem.strip())
        if same:
            dropped += 1
            continue
        kept.append(block.strip())
    kept.append(our_cert_pem.strip())

    patched = b"\n\n".join(kept) + b"\n"
    patched_count = len(_PEM_BLOCK.findall(patched))

    if patched_count != len(kept) or our_cert_pem.strip() not in patched:
        raise RuntimeError("CA bundle patch produced an unusable result")

    log.info("Patched CA bundle: %d -> %d certs (dropped %d stale copies of "
             "ours), %d -> %d bytes (md5 %s -> %s)",
             original_count, patched_count, dropped, len(original), len(patched),
             md5hex(original), md5hex(patched))
    return patched


def load_our_cert(data_dir: str = "/data") -> bytes:
    """Load the add-on's self-signed cert (generated for the MQTT TLS listener)."""
    cert_path = os.path.join(data_dir, "certs", "broker.crt")
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Add-on cert not found at {cert_path} - "
                                "start the add-on once to auto-generate it")
    with open(cert_path, "rb") as f:
        return f.read()


PATCHER_INFO = {
    "id": "cacert",
    "name": "CA Certificate (Bucket TLS)",
    "description": (
        "Required for local storage - the cloud binary verifies the bucket "
        "server's TLS certificate against /app/bin/ca.crt (Mozilla CA bundle). "
        "This patch appends the add-on's self-signed certificate to that bundle "
        "so uploads to our local bucket succeed.\n\n"
        "Apply this together with the Local Storage patch.\n\n"
        "What it does: copies /app/bin/ca.crt to writable storage, appends "
        "the add-on's certificate, then updates the boot wrapper to "
        "bind-mount the patched bundle before the stock init starts cloud."
    ),
    "files": ["ca_patched.crt"],
    # No architecture: this appends PEM text to a certificate bundle and
    # bind-mounts the result. Nothing here is machine code.
    "arch": None,
    # Conservative UI figure: what to tell the user BEFORE we know the model.
    # ca.crt is 226,168 B on a T5 and 11,171 B on a D4SH, plus our PEM.
    "needs_bytes": 524288,
}
