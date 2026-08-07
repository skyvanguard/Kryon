"""Voice / VoIP / SIP / unified communications tools.

F198 introduces Asterisk SIP+AMI discovery for internal testing.
"""

from .asterisk_discover import AsteriskFingerprint, asterisk_discover

__all__ = ["asterisk_discover", "AsteriskFingerprint"]
