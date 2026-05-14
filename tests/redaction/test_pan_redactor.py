"""F119 — Sensitive-data redactor tests.

Banca-safe baseline: any PAN, CVV, track data, or PY government ID
must be masked before findings/logs/LLM I/O. PCI-DSS 3.3 demands no
full PAN in logs.

Test data uses synthetic / public test PANs only:
- 4242 4242 4242 4242  (Stripe test, Luhn-valid)
- 4005 5500 0000 0001  (Bancard PY test, Luhn-valid)
- 5555 5555 5555 4444  (Mastercard test, Luhn-valid)
- 3782 822463 10005    (Amex test, Luhn-valid)
"""

from __future__ import annotations

import os

import pytest

from kryon.redaction.pan_redactor import (
    RedactionResult,
    is_luhn_valid,
    redact_sensitive,
)

# ---------------------------------------------------------------------------
# Luhn validation primitive
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pan",
    [
        "4242424242424242",
        "4005550000000001",
        "5555555555554444",
        "378282246310005",
        "4111111111111111",
    ],
)
def test_luhn_accepts_valid_pans(pan):
    assert is_luhn_valid(pan) is True


@pytest.mark.parametrize(
    "not_pan",
    [
        "4242424242424243",  # one digit off
        "1234567890123456",
        "0000000000000000",
        "abc1234567890123",  # not numeric
        "12345",  # too short
    ],
)
def test_luhn_rejects_invalid(not_pan):
    assert is_luhn_valid(not_pan) is False


# ---------------------------------------------------------------------------
# PAN redaction
# ---------------------------------------------------------------------------


def test_redacts_visa_pan_with_spaces():
    text = "card on file: 4242 4242 4242 4242 expires 12/26"
    result = redact_sensitive(text)
    assert "4242 4242 4242 4242" not in result.text
    assert "4242" not in result.text or "[PAN-REDACTED]" in result.text or "**" in result.text
    assert result.counts.get("pan", 0) >= 1


def test_redacts_visa_pan_no_spaces():
    text = "PAN=4242424242424242"
    result = redact_sensitive(text)
    assert "4242424242424242" not in result.text
    assert result.counts.get("pan", 0) >= 1


def test_redacts_bancard_test_pan():
    text = "intent: paid via 4005-5500-0000-0001 on 2026-05-14"
    result = redact_sensitive(text)
    assert "4005-5500-0000-0001" not in result.text
    assert "4005" not in result.text or "[PAN-REDACTED]" in result.text or "**" in result.text


def test_redacts_amex_15_digit():
    text = "amex test: 3782 822463 10005"
    result = redact_sensitive(text)
    assert "378282246310005" not in result.text and "3782 822463 10005" not in result.text
    assert result.counts.get("pan", 0) >= 1


def test_redacts_multiple_pans_in_one_string():
    text = "primary 4242424242424242 backup 5555 5555 5555 4444"
    result = redact_sensitive(text)
    assert "4242424242424242" not in result.text
    assert "5555 5555 5555 4444" not in result.text
    assert result.counts.get("pan", 0) >= 2


def test_does_not_redact_random_16_digit_number():
    # Luhn-invalid → not a PAN. Common in IDs, timestamps, hashes.
    text = "request id 1234567890123456 processed"
    result = redact_sensitive(text)
    assert "1234567890123456" in result.text
    assert result.counts.get("pan", 0) == 0


def test_does_not_redact_ipv4_or_timestamps():
    text = "host 192.168.1.10 at 2026-05-14T13:42:55Z"
    result = redact_sensitive(text)
    assert "192.168.1.10" in result.text
    assert "2026-05-14T13:42:55Z" in result.text


def test_preserves_pan_last_4_when_configured_visible_last4():
    # PCI-DSS 3.3 permits showing last 4 digits — make sure that path
    # is reachable even if not the default.
    text = "card 4242424242424242 last4 only"
    result = redact_sensitive(text, mask_style="last4")
    assert "4242424242424242" not in result.text
    assert "4242" in result.text  # last 4 visible


# ---------------------------------------------------------------------------
# CVV / track data
# ---------------------------------------------------------------------------


def test_redacts_cvv_in_context():
    text = "card 4242424242424242 cvv 123 exp 12/26"
    result = redact_sensitive(text)
    assert " 123 " not in result.text or "[CVV-REDACTED]" in result.text or "***" in result.text
    assert result.counts.get("cvv", 0) >= 1


def test_redacts_track2_data():
    # Track 2: ;PAN=YYMM<service>CVV?
    text = "stripe dump: ;4242424242424242=2612101000000000?"
    result = redact_sensitive(text)
    assert ";4242424242424242=" not in result.text
    assert result.counts.get("track", 0) >= 1 or result.counts.get("pan", 0) >= 1


# ---------------------------------------------------------------------------
# Paraguay government IDs
# ---------------------------------------------------------------------------


def test_redacts_py_cedula_with_dots():
    text = "cliente CI 1.234.567-8 confirmó"
    result = redact_sensitive(text)
    assert "1.234.567-8" not in result.text
    assert result.counts.get("py_ci", 0) >= 1


def test_redacts_py_cedula_no_dots():
    text = "cedula 1234567 del titular"
    result = redact_sensitive(text)
    assert "1234567" not in result.text
    assert result.counts.get("py_ci", 0) >= 1


def test_redacts_py_ruc():
    text = "RUC 80012345-6 de la empresa"
    result = redact_sensitive(text)
    assert "80012345-6" not in result.text
    assert result.counts.get("py_ruc", 0) >= 1


def test_redacts_iban():
    text = "IBAN PY58BANC1234567890123456 transferencia"
    result = redact_sensitive(text)
    assert "PY58BANC1234567890123456" not in result.text
    assert result.counts.get("iban", 0) >= 1


# ---------------------------------------------------------------------------
# Env toggle + edge cases
# ---------------------------------------------------------------------------


def test_redaction_disabled_via_env(monkeypatch):
    monkeypatch.setenv("KRYON_REDACT_PAN", "false")
    text = "card 4242424242424242"
    result = redact_sensitive(text)
    # When disabled, text passes through verbatim.
    assert "4242424242424242" in result.text
    assert result.counts == {} or all(c == 0 for c in result.counts.values())


def test_empty_text_returns_empty():
    result = redact_sensitive("")
    assert result.text == ""
    assert result.counts == {} or all(c == 0 for c in result.counts.values())


def test_text_without_sensitive_data_unchanged():
    text = "Phase 1 nmap detected port 22/tcp ssh OpenSSH 8.9p1"
    result = redact_sensitive(text)
    assert result.text == text
    assert all(v == 0 for v in result.counts.values()) if result.counts else True


def test_redaction_result_total_sums_categories():
    text = "card 4242424242424242 cedula 1.234.567-8"
    result = redact_sensitive(text)
    expected = result.counts.get("pan", 0) + result.counts.get("py_ci", 0)
    assert result.total() == expected
    assert result.total() >= 2


def test_non_string_input_does_not_crash():
    # The helper should be tolerant — callers shouldn't have to
    # type-check before calling it.
    result = redact_sensitive(None)  # type: ignore[arg-type]
    assert result.text == ""
