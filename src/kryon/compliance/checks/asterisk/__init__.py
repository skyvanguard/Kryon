"""F198 — Asterisk (VoIP) compliance checks.

Explicitly import every submodule so `from kryon.compliance.checks import
asterisk` triggers the side-effect `register_check` calls.
"""

from kryon.compliance.checks.asterisk import (  # noqa: F401 — side-effect
    c_voip_1_1_anon_register,
    c_voip_1_2_ami_default_secret,
    c_voip_2_1_allowguest,
    c_voip_2_2_alwaysauthreject,
    c_voip_2_3_ami_wan_exposure,
    c_voip_3_1_srtp_disabled,
    c_voip_3_2_sip_tls_disabled,
    c_voip_3_3_asterisk_version,
)
