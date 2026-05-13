"""F115.A — TDD contract for OOB payload generator."""

from __future__ import annotations

import re

import pytest

from kryon.tools.oob.payloads import (
    OOB_PAYLOAD_KINDS,
    OobPayload,
    correlation_id,
    correlate_payload_with_interactions,
    generate_oob_payloads,
)


CB = "my-interactsh.lab"  # canary callback domain for tests


# =====================================================================
# correlation_id
# =====================================================================


def test_correlation_id_default_prefix():
    cid = correlation_id()
    assert cid.startswith("k")
    assert len(cid) == 9  # "k" + 8 hex chars


def test_correlation_id_custom_prefix():
    cid = correlation_id(prefix="x")
    assert cid.startswith("x")


def test_correlation_id_unique_across_calls():
    ids = {correlation_id() for _ in range(50)}
    assert len(ids) == 50  # all unique


def test_correlation_id_url_safe():
    """No characters that need URL-encoding in subdomains."""
    cid = correlation_id()
    assert re.match(r"^[a-z0-9]+$", cid)


# =====================================================================
# generate_oob_payloads
# =====================================================================


def test_generates_one_payload_per_kind():
    payloads = generate_oob_payloads(CB)
    assert len(payloads) == len(OOB_PAYLOAD_KINDS)
    kinds_seen = {p.kind for p in payloads}
    assert kinds_seen == set(OOB_PAYLOAD_KINDS)


def test_each_payload_has_unique_correlation_id():
    payloads = generate_oob_payloads(CB)
    cids = [p.correlation_id for p in payloads]
    assert len(set(cids)) == len(cids)


def test_correlation_id_embedded_in_subdomain():
    payloads = generate_oob_payloads(CB)
    for p in payloads:
        assert p.correlation_id in p.callback_subdomain
        assert p.callback_subdomain.endswith(CB)


def test_correlation_id_embedded_in_payload():
    """Each payload string should contain its correlation ID (via the
    callback subdomain) so the operator can grep."""
    payloads = generate_oob_payloads(CB)
    for p in payloads:
        # The cid appears as part of the subdomain, which appears
        # somewhere in the payload string for every kind.
        assert p.callback_subdomain in p.payload


def test_empty_callback_domain_returns_empty():
    assert generate_oob_payloads("") == ()
    assert generate_oob_payloads("   ") == ()


def test_strips_leading_dot_from_callback_domain():
    payloads = generate_oob_payloads(".dotted.example")
    assert payloads
    for p in payloads:
        assert p.callback_subdomain.endswith("dotted.example")


def test_kind_filter():
    payloads = generate_oob_payloads(CB, kinds=("ssrf-http", "log4j-jndi"))
    assert len(payloads) == 2
    kinds = {p.kind for p in payloads}
    assert kinds == {"ssrf-http", "log4j-jndi"}


def test_unknown_kind_is_silently_skipped():
    payloads = generate_oob_payloads(CB, kinds=("ssrf-http", "this-is-fake"))
    assert len(payloads) == 1
    assert payloads[0].kind == "ssrf-http"


def test_ssrf_http_payload_shape():
    p = generate_oob_payloads(CB, kinds=("ssrf-http",))[0]
    assert p.payload.startswith("http://")
    assert p.payload.endswith("/")
    assert p.callback_subdomain in p.payload


def test_log4j_payload_shape():
    p = generate_oob_payloads(CB, kinds=("log4j-jndi",))[0]
    assert p.payload.startswith("${jndi:ldap://")
    assert p.callback_subdomain in p.payload


def test_xxe_payload_shape():
    p = generate_oob_payloads(CB, kinds=("xxe-system",))[0]
    assert "<!DOCTYPE" in p.payload
    assert "<!ENTITY" in p.payload
    assert p.callback_subdomain in p.payload


def test_blind_xss_img_payload_shape():
    p = generate_oob_payloads(CB, kinds=("blind-xss-img",))[0]
    assert "<img" in p.payload
    assert "onerror" in p.payload
    assert p.callback_subdomain in p.payload


def test_ssrf_dns_payload_is_bare_subdomain():
    """The DNS-only payload should be just the subdomain itself, no
    scheme — many SSRF fetchers resolve DNS before validating."""
    p = generate_oob_payloads(CB, kinds=("ssrf-dns",))[0]
    assert p.payload == p.callback_subdomain
    assert "://" not in p.payload


def test_payload_is_frozen_dataclass():
    from dataclasses import FrozenInstanceError

    p = OobPayload(
        kind="ssrf-http",
        correlation_id="abc",
        payload="x",
        callback_subdomain="y",
    )
    with pytest.raises(FrozenInstanceError):
        p.kind = "other"  # type: ignore[misc]


# =====================================================================
# correlate_payload_with_interactions
# =====================================================================


def test_correlate_matches_observed_interactions():
    payloads = generate_oob_payloads(CB, kinds=("ssrf-http", "log4j-jndi"))
    # Simulate: the log4j payload triggered, the SSRF didn't
    log4j = next(p for p in payloads if p.kind == "log4j-jndi")
    observed = [log4j.callback_subdomain]
    mapping = correlate_payload_with_interactions(payloads, observed)
    assert mapping[log4j.correlation_id] == observed
    ssrf = next(p for p in payloads if p.kind == "ssrf-http")
    assert mapping[ssrf.correlation_id] == []


def test_correlate_handles_uppercase_dns():
    """DNS callbacks may be uppercased by some resolvers. Match
    case-insensitively."""
    payloads = generate_oob_payloads(CB, kinds=("ssrf-dns",))
    p = payloads[0]
    observed = [p.callback_subdomain.upper()]
    mapping = correlate_payload_with_interactions(payloads, observed)
    assert mapping[p.correlation_id] == observed


def test_correlate_handles_partial_match():
    """An interaction subdomain that wraps the correlation ID — e.g.
    `cid.full-subdomain.lab.tld` — should match the cid."""
    payloads = generate_oob_payloads(CB, kinds=("ssrf-http",))
    p = payloads[0]
    # Simulate a wrapped subdomain (some interactsh deployments add
    # extra labels)
    observed = [f"sub.{p.callback_subdomain}.extra"]
    mapping = correlate_payload_with_interactions(payloads, observed)
    assert len(mapping[p.correlation_id]) == 1


def test_correlate_empty_observations():
    payloads = generate_oob_payloads(CB, kinds=("ssrf-http",))
    mapping = correlate_payload_with_interactions(payloads, [])
    assert mapping[payloads[0].correlation_id] == []
