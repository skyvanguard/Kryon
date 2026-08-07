"""Cybench adapter — run the Stanford Cybench benchmark against the Kryon agent.

Cybench (https://github.com/andyzorigin/cybench, Apache-2.0) is 40 professional
CTF tasks with a public leaderboard, so it gives a reproducible number to position
V4-Flash-local against frontier models using the SAME harness/prompt/tooling.

This adapter is arm's-length: it reads a Cybench task's ``metadata/metadata.json``
(cloned separately — NOT bundled) and runs it through the same ``invoke_kryon``
path the HTB bench uses (``kryon investigate --active``). Scoring mirrors Cybench:
- unguided: binary — did the agent emit the final subtask's answer (the flag)?
- subtask:  fractional — how many subtask answers did the transcript contain?
"""
