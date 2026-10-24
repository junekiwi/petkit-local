"""Refusing a firmware fetch that would loop back to this add-on.

A LAN that redirects PetKit's names to petkit-local answers the add-on's OWN
lookup with this host too, so a fetch would dial itself on 443 — the MQTT port,
not an HTTP API — and fail with an opaque connect error that says nothing about
the cause. `_refuse_if_upstream_is_self` turns that into one actionable line,
before the connection is attempted — but only when the fetch will use the system
resolver (no `proxy_dns`), because a resolver that is set is the one doing the
real lookup and asking the system one would answer for a different view.
"""
import pytest

from petkit_local.http.cloud_fetch import CloudRefused
from petkit_local.web.api import firmware


def _app(api_url="http://192.168.2.75/6/"):
    return {"cfg": {"api_url": api_url}}


def _resolver(mapping):
    async def resolve(name):
        return list(mapping.get(name, []))

    return resolve


async def test_a_fetch_that_would_reach_this_add_on_is_refused(monkeypatch):
    monkeypatch.setattr(firmware, "resolve", _resolver({
        "192.168.2.75": ["192.168.2.75"],
        "api-eu.petkt.com": ["192.168.2.75"],
    }))
    with pytest.raises(CloudRefused) as e:
        await firmware._refuse_if_upstream_is_self(
            _app(), "https://api-eu.petkt.com/6/", "")
    msg = str(e.value)
    assert "resolves to this add-on" in msg
    # The two things a user can act on: the setting to change and a value to use.
    assert "DNS for upstream lookups" in msg
    assert "1.1.1.1" in msg


async def test_a_resolver_setting_skips_the_check(monkeypatch):
    """With `proxy_dns` set, that resolver does the lookup — not the system one
    this check consults — so the check must not fire, nor even resolve."""
    called = False

    async def resolve(name):
        nonlocal called
        called = True
        return ["192.168.2.75"]

    monkeypatch.setattr(firmware, "resolve", resolve)
    await firmware._refuse_if_upstream_is_self(
        _app(), "https://api-eu.petkt.com/6/", "1.1.1.1")
    assert not called


async def test_a_name_that_reaches_the_real_cloud_is_left_alone(monkeypatch):
    monkeypatch.setattr(firmware, "resolve", _resolver({
        "192.168.2.75": ["192.168.2.75"],
        "api-eu.petkt.com": ["47.91.73.251"],
    }))
    await firmware._refuse_if_upstream_is_self(
        _app(), "https://api-eu.petkt.com/6/", "")  # no raise


async def test_a_name_that_also_resolves_elsewhere_is_reachable(monkeypatch):
    """Refuse only when EVERY answer is us; a name that also points at a real IP
    is reachable, so the fetch should be allowed to try it."""
    monkeypatch.setattr(firmware, "resolve", _resolver({
        "192.168.2.75": ["192.168.2.75"],
        "api-eu.petkt.com": ["192.168.2.75", "47.91.73.251"],
    }))
    await firmware._refuse_if_upstream_is_self(
        _app(), "https://api-eu.petkt.com/6/", "")  # no raise
