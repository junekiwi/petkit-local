"""A patched ESP32 on the local broker: its certificate, and its credentials.

The firmware patched by `patchers/firmware.py` trusts one CA and checks the
broker certificate against the `<productKey>.iot-as-mqtt...` name it dialled.
These tests run a real TLS handshake against a context configured the way the
broker configures its own (`mqtt/broker.py::configure_device_tls`), with a
client verifying the way the device does: our CA, that hostname.
"""
from __future__ import annotations

import socket
import ssl
import threading

import pytest
from cryptography import x509

from petkit_local.mqtt.broker import configure_device_tls, ensure_self_signed
from petkit_local.patchers import esp32_ota
from tests.test_esp32_ota import _listing
from tests.test_patcher_esp32 import _cert_image, _crlf_slot

ESP32_NAME = "a1b2c3d4e5.iot-as-mqtt.eu-central-1.aliyuncs.com"


@pytest.fixture(scope="module")
def stock_image() -> bytes:
    from petkit_local.patchers.firmware import generate_ca_for_slot

    _, stand_in = generate_ca_for_slot(_crlf_slot())
    return _cert_image(stand_in)


def _store(data_dir, stock_image):
    modules = {"userbin": stock_image}
    return esp32_ota.save_release(str(data_dir), "d4", _listing(modules), modules)


# --------------------------------------------------------------------------- #
# The leaf                                                                    #
# --------------------------------------------------------------------------- #


def test_no_leaf_until_there_is_a_ca(tmp_path):
    assert esp32_ota.ensure_broker_leaf(str(tmp_path)) is None


def test_minting_the_ca_issues_a_wildcard_leaf_it_signed(tmp_path, stock_image):
    _store(tmp_path, stock_image)
    cert_path, _key = esp32_ota.broker_leaf_paths(str(tmp_path))
    leaf = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["*.iot-as-mqtt.eu-central-1.aliyuncs.com"]
    _, ca_pem = esp32_ota.load_ca(str(tmp_path))
    assert leaf.issuer == x509.load_pem_x509_certificate(ca_pem).subject

    before = open(cert_path, "rb").read()
    assert esp32_ota.ensure_broker_leaf(str(tmp_path))
    assert open(cert_path, "rb").read() == before  # reused, not re-issued


def test_a_leaf_from_a_different_ca_is_re_issued(tmp_path, stock_image):
    _store(tmp_path, stock_image)
    cert_path, _ = esp32_ota.broker_leaf_paths(str(tmp_path))
    old_leaf = open(cert_path, "rb").read()
    for path in esp32_ota.ca_paths(str(tmp_path)):
        (tmp_path / "certs" / path.rsplit("/", 1)[1]).unlink()
    esp32_ota.ensure_ca(str(tmp_path), _crlf_slot())  # a new CA, with a new key
    assert open(cert_path, "rb").read() != old_leaf


@pytest.mark.parametrize("name, matches", [
    (ESP32_NAME, True),
    ("PETKIT-LOCAL-HTTP.IOT-AS-MQTT.EU-CENTRAL-1.ALIYUNCS.COM", True),
    ("a1b2.iot-as-mqtt.us-west-1.aliyuncs.com", True),
    ("petkit-local", False),
    ("192.168.2.75", False),
    ("x.a1b2.iot-as-mqtt.eu-central-1.aliyuncs.com", False),
])
def test_only_a_product_key_broker_name_asks_for_the_esp32_leaf(name, matches):
    assert bool(esp32_ota.BROKER_NAME_RE.match(name)) is matches


# --------------------------------------------------------------------------- #
# The handshake                                                               #
# --------------------------------------------------------------------------- #


def _server_context(data_dir) -> ssl.SSLContext:
    """A listener context set up exactly as the broker sets its own up."""
    cert = str(data_dir / "certs" / "broker.crt")
    key = str(data_dir / "certs" / "broker.key")
    assert ensure_self_signed(cert, key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return configure_device_tls(ctx, str(data_dir))


def _device_context(data_dir) -> ssl.SSLContext:
    """What the patched firmware verifies with: our CA, hostname checked."""
    _, ca_pem = esp32_ota.load_ca(str(data_dir))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.load_verify_locations(cadata=ca_pem.decode())
    return ctx


def _handshake(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext,
               server_name: str) -> str:
    """Complete one TLS handshake in-process; return the peer cert's CN.

    The client sends `server_name` as SNI and verifies the hostname against it,
    exactly as the device does. Raises `ssl.SSLError`/`ssl.CertificateError` on
    a chain or name mismatch — which is what a device rejecting us looks like.
    """
    srv_sock, cli_sock = socket.socketpair()
    result: dict = {}

    def serve():
        try:
            with server_ctx.wrap_socket(srv_sock, server_side=True) as ss:
                ss.recv(16)
        except Exception as e:  # noqa: BLE001 - surfaced via the client side
            result["server_error"] = e

    t = threading.Thread(target=serve)
    t.start()
    try:
        with client_ctx.wrap_socket(cli_sock, server_hostname=server_name) as cs:
            der = cs.getpeercert(binary_form=True)
            cs.send(b"hello")
        # Parsed from the DER so this works whether or not the client verified.
        cert = x509.load_der_x509_certificate(der)
        return cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    finally:
        t.join()


def test_a_patched_device_dialling_its_broker_name_gets_the_ca_signed_leaf(tmp_path, stock_image):
    _store(tmp_path, stock_image)
    cn = _handshake(_server_context(tmp_path), _device_context(tmp_path), ESP32_NAME)
    assert cn == esp32_ota.BROKER_LEAF_NAME  # the wildcard the device trusts


def test_the_default_cert_does_not_satisfy_the_device(tmp_path, stock_image):
    # Proves the SNI switch is load-bearing: the self-signed broker cert the
    # Linux models trust is not signed by the ESP32 CA, so a device verifying
    # against that CA must reject it.
    _store(tmp_path, stock_image)
    cert = str(tmp_path / "certs" / "broker.crt")
    key = str(tmp_path / "certs" / "broker.key")
    assert ensure_self_signed(cert, key)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # no SNI callback
    server_ctx.load_cert_chain(cert, key)
    server_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with pytest.raises(ssl.SSLError):
        _handshake(server_ctx, _device_context(tmp_path), ESP32_NAME)


def test_a_name_that_is_not_an_esp32_broker_keeps_the_default_cert(tmp_path, stock_image):
    # A Linux model (or anything else) sending some other SNI is served the
    # self-signed broker cert, unchanged by this feature.
    _store(tmp_path, stock_image)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.set_ciphers("DEFAULT:@SECLEVEL=0")
    cn = _handshake(_server_context(tmp_path), client, "petkit-local")
    assert cn == "petkit-local"  # the self-signed broker cert


def test_the_leaf_appears_when_the_ca_does_not_at_startup(tmp_path, stock_image):
    # The broker starts before any firmware is fetched, so the context has no
    # ESP32 leaf yet; it is picked up once a release mints the CA.
    from petkit_local.mqtt.broker import Esp32Certificate
    picker = Esp32Certificate(str(tmp_path))
    assert picker.context() is None
    _store(tmp_path, stock_image)
    assert picker.context() is not None
