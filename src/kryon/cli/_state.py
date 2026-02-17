"""Centralized global state for the KRYON CLI module."""

import os
import time

from kryon.compat import is_pentestperf_available
from kryon.util import setup_ctf

# CTF global state
ctf_global = None
messages_ctf = ""
ctf_init = 1
previous_ctf_name = os.getenv("CTF_NAME", None)
if is_pentestperf_available() and os.getenv("CTF_NAME", None):
    ctf, messages_ctf = setup_ctf()
    ctf_global = ctf
    ctf_init = 0

# Global variables for timing tracking
START_TIME = time.time()


def set_ctf_global(value):
    """Setter for ctf_global to allow mutation from other modules."""
    global ctf_global
    ctf_global = value
