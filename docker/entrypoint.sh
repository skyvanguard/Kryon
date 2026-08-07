#!/bin/bash
# =============================================================================
# KRYON Docker Entrypoint
# =============================================================================
# Fixes Windows→Linux path issues in Claude Code config files that are
# bind-mounted from the host, then executes the original CMD.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Fix Claude Code plugin paths (Windows → Linux)
# ---------------------------------------------------------------------------
# When ~/.claude is bind-mounted from a Windows host, known_marketplaces.json
# contains Windows paths (e.g., C:\Users\...) that cause the CLI to silently
# fail in pipe mode. This patches the paths to their Linux equivalents.
# ---------------------------------------------------------------------------
MARKETPLACE_FILE="$HOME/.claude/plugins/known_marketplaces.json"
if [ -f "$MARKETPLACE_FILE" ]; then
    if grep -q 'C:\\' "$MARKETPLACE_FILE" 2>/dev/null; then
        # Replace Windows installLocation with Linux equivalent
        python3 -c "
import json, os

mp_file = os.path.expanduser('~/.claude/plugins/known_marketplaces.json')
try:
    with open(mp_file) as f:
        data = json.load(f)
    changed = False
    for name, info in data.items():
        loc = info.get('installLocation', '')
        if '\\\\' in loc or loc.startswith('C:'):
            # Convert to Linux path under ~/.claude/plugins/marketplaces/
            info['installLocation'] = os.path.expanduser(
                f'~/.claude/plugins/marketplaces/{name}'
            )
            changed = True
    if changed:
        with open(mp_file, 'w') as f:
            json.dump(data, f, indent=2)
        print('entrypoint: patched known_marketplaces.json (Windows → Linux paths)')
except Exception as e:
    print(f'entrypoint: warning: could not patch {mp_file}: {e}')
" 2>&1 || true
    fi
fi

# ---------------------------------------------------------------------------
# Execute CMD
# ---------------------------------------------------------------------------
exec "$@"
