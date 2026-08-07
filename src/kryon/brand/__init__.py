"""F90 — Brand protection package.

Defensive surveillance over a client's brand: typosquatting, IDN
homoglyph attacks, certificate transparency monitoring, basic
similarity detection. Banking customers are the #1 phishing target,
and the attacks routinely depend on doppelgänger domains that the
bank's own brand team didn't pre-register.

Module layout:
  typosquat.py        — F90.1: pure generator + DNS resolver (read-only).
  ct_monitor.py       — F90.2 (planned): crt.sh / Google CT log
                        aggregator for newly-issued certs.
  reputation.py       — F90.3 (planned): risk-score aggregator over
                        typosquat + CT + WHOIS age signals.

Banca-safety:
  - All probes are read-only. No domain registration, no takedown
    requests — those are downstream operator decisions.
  - Live DNS / HTTP gated behind KRYON_BRAND_FIRE=true env + fire=True
    kwarg (same contract as F87 / F88).
  - Stdlib only.
"""
