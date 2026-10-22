"""The command line: the flag table, and turning the parsed flags into a `Config`.

Nothing here reads the network or touches disk beyond the config file — parsing
and overriding only, so `main()` has a finished `Config` before it builds a
single service.
"""
from __future__ import annotations

import argparse

from petkit_local.config import Config


def _build_parser() -> argparse.ArgumentParser:
    """Every flag the process accepts, in the order `--help` prints them."""
    parser = argparse.ArgumentParser(description="petkit-local: local PetKit cloud replacement")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--port", type=int, default=None, help="HTTP port override")
    parser.add_argument("--mqtt-port", type=int, default=None, help="MQTT broker port")
    parser.add_argument("--api-url", default=None, help="API URL the device sees")
    parser.add_argument("--data-dir", default=None, help="Data directory for persistence")
    parser.add_argument("--ha-mqtt-host", default=None, help="HA MQTT broker host")
    parser.add_argument("--ha-mqtt-port", type=int, default=None, help="HA MQTT broker port")
    parser.add_argument("--ha-mqtt-user", default=None)
    parser.add_argument("--ha-mqtt-pass", default=None)
    parser.add_argument("--no-ha", action="store_true", help="Disable HA MQTT publishing")
    parser.add_argument("--no-mqtt", action="store_true", help="Disable embedded MQTT broker")
    parser.add_argument("--offline-timeout", type=int, default=None, help="Seconds without contact before a device is marked offline")
    parser.add_argument("--mqtt-tls", action="store_true", help="Enable device-facing MQTT TLS listener")
    parser.add_argument("--mqtt-tls-port", type=int, default=None, help="MQTT TLS listener port (default 443)")
    parser.add_argument("--mqtt-cert", default=None, help="TLS cert path (self-signed generated if missing)")
    parser.add_argument("--mqtt-key", default=None, help="TLS key path")
    parser.add_argument("--mqtt-strict-auth", action="store_true", help="Enforce Aliyun HMAC sign (default accept-all)")
    parser.add_argument("--esp32-mqtt", action="store_true",
                        help="Hand T3/T4/D4 their own MQTT product key instead of keeping "
                             "them on HTTP (only for reflashed devices)")
    # Every other port has a flag; these two did not, so a standalone run could
    # not move the panel or the media bucket off their defaults without hand-
    # writing a config file. That matters outside the add-on: Home Assistant
    # Container and Core have no add-on system at all, so those users run this
    # as a plain container beside HA and configure it entirely from the command
    # line.
    parser.add_argument("--web-port", type=int, default=None, help="Web panel port (default 8099)")
    parser.add_argument("--bucket-port", type=int, default=None, help="Media upload bucket port (default 9000)")
    parser.add_argument("--bucket-endpoint", default=None,
                        help="Media bucket base URL the device is told to use "
                             "(default: https://<api-url host>:<bucket-port>)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--ha-addon", action="store_true", help="Self-configure from /data/options.json + Supervisor (HA add-on mode)")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command line (the process's own arguments by default)."""
    return _build_parser().parse_args(argv)


def build_config(args: argparse.Namespace) -> Config:
    """Turn the parsed flags into the one `Config` the whole process reads.

    Two entry paths converge here: `--ha-addon` reads the add-on options file
    written by the Supervisor, while the individual flags are the way the
    add-on is run outside Home Assistant. Flags always win over the add-on
    options, so a bad option file can be overridden without editing it.
    """
    if args.ha_addon:
        config = Config.from_ha_addon()
    else:
        config = Config.from_file(args.config)
        if args.port:
            config.http_port = args.port
        if args.mqtt_port:
            config.mqtt_port = args.mqtt_port
        if args.api_url:
            config.api_url = args.api_url
        if args.data_dir:
            config.data_dir = args.data_dir
        if args.ha_mqtt_host:
            config.ha_mqtt_host = args.ha_mqtt_host
        if args.ha_mqtt_port:
            config.ha_mqtt_port = args.ha_mqtt_port
        if args.ha_mqtt_user:
            config.ha_mqtt_user = args.ha_mqtt_user
        if args.ha_mqtt_pass:
            config.ha_mqtt_pass = args.ha_mqtt_pass
        if args.offline_timeout is not None:
            config.offline_timeout = args.offline_timeout
        if args.mqtt_tls:
            config.mqtt_tls = True
        if args.mqtt_tls_port is not None:
            config.mqtt_tls_port = args.mqtt_tls_port
        if args.mqtt_cert:
            config.mqtt_cert = args.mqtt_cert
        if args.mqtt_key:
            config.mqtt_key = args.mqtt_key
        if args.mqtt_strict_auth:
            config.mqtt_strict_auth = True
        if args.esp32_mqtt:
            config.esp32_http_only = False
        if args.web_port is not None:
            config.web_port = args.web_port
        if args.bucket_port is not None:
            config.bucket_port = args.bucket_port
        if args.bucket_endpoint is not None:
            config.bucket_endpoint = args.bucket_endpoint
        if args.debug:
            config.log_level = "DEBUG"

        # Re-read the panel's overrides now that --data-dir has been applied.
        # `from_file` already read them, but from wherever `data_dir` pointed
        # BEFORE the flag moved it — and proxy mode and capture now live only in
        # that file, so a standalone run with --data-dir would otherwise start
        # with them silently off however the panel was left.
        config.apply_panel_overrides()

    # After the flags, because --api-url and --bucket-port both feed it. The
    # add-on path already has an endpoint from the Supervisor, so this is a
    # no-op there.
    config.resolve_bucket_endpoint()
    return config
