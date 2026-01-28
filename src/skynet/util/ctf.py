"""
CTF (Capture The Flag) utilities for SKYNET.

This module provides functions for setting up and interacting with
CTF environments for security testing.
"""

import os
import sys

from mako.template import Template
from wasabi import color

from skynet.compat import is_pentestperf_available

if is_pentestperf_available():
    import pentestperf as ptt


def check_flag(output, ctf, challenge=None):
    """
    Check if the CTF flag is present in the output.

    Args:
        output (str): The output to check for the flag.
        ctf: The CTF environment object.
        challenge (str, optional): The specific challenge to check.
            Defaults to None.

    Returns:
        tuple: A tuple containing a boolean indicating if the flag was
            found and the flag itself if found, otherwise None.
    """
    # Get the challenge from the environment variable or default to the first
    # challenge
    challenge_key = os.getenv("CTF_CHALLENGE")
    challenges = list(ctf.get_challenges().keys())
    challenge = challenge_key if challenge_key in challenges else (challenges[0] if len(challenges) > 0 else None)
    if ctf:
        if ctf.check_flag(output, challenge):  # check if the flag is in the output
            flag = ctf.flags[challenge]
            print(color(f"Flag found: {flag}", fg="green") + " in output " + color(f"{output}", fg="blue"))
            return True, flag
    else:
        print(color("CTF environment not found or provided", fg="yellow"))
    return False, None


def setup_ctf():
    """Setup CTF environment if CTF_NAME is provided"""
    ctf_name = os.getenv("CTF_NAME", None)
    if not ctf_name:
        print(color("CTF name not provided, necessary to run CTF", fg="white", bg="red"))
        sys.exit(1)

    print(color("Setting up CTF: ", fg="black", bg="yellow") + color(ctf_name, fg="black", bg="yellow"))

    ctf = ptt.ctf(  # pylint: disable=I1101  # noqa
        ctf_name,
        subnet=os.getenv("CTF_SUBNET", "192.168.3.0/24"),
        container_name="ctf_target",
        ip_address=os.getenv("CTF_IP", "192.168.3.100"),
    )
    ctf.start_ctf()

    # Get the challenge from the environment variable or default to the first challenge
    # CTF_CHALLENGE env var can be set to target a specific challenge by key
    challenge_key = os.getenv("CTF_CHALLENGE")
    challenges = list(ctf.get_challenges().keys())

    # Validate challenge key if provided
    if challenge_key and challenge_key not in challenges:
        available = ", ".join(challenges) if challenges else "none"
        raise ValueError(f"Invalid CTF_CHALLENGE '{challenge_key}'. Available challenges: {available}")

    # Select challenge: env var > first available > None
    challenge = challenge_key if challenge_key in challenges else (challenges[0] if len(challenges) > 0 else None)

    # Use the user master template
    messages = Template(filename="src/skynet/prompts/core/user_master_template.md").render(
        ctf=ctf,
        challenge=challenge,
        ip=ctf.get_ip() if ctf else None,
    )

    print(color("Testing CTF: ", fg="black", bg="yellow") + color(ctf.name, fg="black", bg="yellow"))
    if not challenge_key or challenge_key not in challenges:
        print(
            color(
                "No challenge provided or challenge not found. Attempting to use the first challenge.",
                fg="white",
                bg="blue",
            )
        )
    if challenge:
        print(
            color("Testing challenge: ", fg="white", bg="blue")
            + color("'" + challenge + "' (" + repr(ctf.flags[challenge]) + ")", fg="white", bg="blue")
        )

    return ctf, messages
