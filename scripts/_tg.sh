#!/usr/bin/env bash
# Telegram bridge for Kryon/Claude Code — reuses the hermes-agent @Sailspy_bot.
# Token is read fresh from the hermes-gateway container env (never persisted to disk).
# Usage:
#   _tg.sh send "message"     -> send a plain-text (ASCII-safe) message
#   _tg.sh sendfile <path>    -> send a UTF-8 file body (robust for accents)
#   _tg.sh poll               -> one getUpdates pass; append replies to inbox, advance offset
#   _tg.sh watch              -> continuous long-poll; emit each new reply to stdout (Monitor)
#   _tg.sh set-offset <N>     -> manually set the getUpdates offset
#
# NOTE (Windows): the Python snippets compute their own state paths via
# expanduser("~") so they get a native Windows path. Passing Git Bash MSYS
# paths (/c/Users/...) into Python on Windows breaks (FileNotFoundError).
set -uo pipefail

CHAT_ID="8820325412"   # operator (Francisco) private chat

# Python helper: resolves ~/.kryon/<name> as a native path.
_PYPATHS='
import os
STATE = os.path.join(os.path.expanduser("~"), ".kryon")
os.makedirs(STATE, exist_ok=True)
INBOX = os.path.join(STATE, "tg_inbox.log")
OFFSET = os.path.join(STATE, "tg_offset")
'

_token() {
  docker inspect hermes-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | grep -E "^TELEGRAM_BOT_TOKEN=" | head -1 | cut -d= -f2-
}

_offset() {
  python -c "${_PYPATHS}
print(open(OFFSET).read().strip() if os.path.exists(OFFSET) else '0')"
}

cmd="${1:-}"; shift || true
TOKEN="$(_token)"
[ -n "${TOKEN}" ] || { echo "ERROR: no TELEGRAM_BOT_TOKEN (is hermes-gateway present?)" >&2; exit 1; }
API="https://api.telegram.org/bot${TOKEN}"

case "${cmd}" in
  send)
    curl -s "${API}/sendMessage" --data-urlencode "chat_id=${CHAT_ID}" --data-urlencode "text=${1:-}" \
      | python -c "import sys,json;d=json.load(sys.stdin);print('sent' if d.get('ok') else 'FAIL: '+str(d.get('description')))"
    ;;
  sendfile)
    curl -s "${API}/sendMessage" --data-urlencode "chat_id=${CHAT_ID}" \
      --data-urlencode "text@${1:?usage: _tg.sh sendfile <path>}" \
      | python -c "import sys,json;d=json.load(sys.stdin);print('sent' if d.get('ok') else 'FAIL: '+str(d.get('description')))"
    ;;
  set-offset)
    python -c "${_PYPATHS}
open(OFFSET,'w').write('${1:?usage: _tg.sh set-offset <N>}')"
    echo "offset set to ${1}"
    ;;
  poll|watch)
    loop=1; [ "${cmd}" = "poll" ] && loop=0
    while : ; do
      off="$(_offset)"
      curl -s "${API}/getUpdates?timeout=50&offset=${off}" 2>/dev/null | python -c "
${_PYPATHS}
import sys, json, datetime
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
last = None
for u in d.get('result', []):
    last = u['update_id']
    m = u.get('message') or u.get('edited_message') or {}
    ch = m.get('chat', {})
    if str(ch.get('id')) != '${CHAT_ID}':
        continue
    txt = m.get('text', '')
    if not txt:
        continue
    ts = datetime.datetime.fromtimestamp(m.get('date', 0)).isoformat(timespec='seconds')
    with open(INBOX, 'a', encoding='utf-8') as f:
        f.write(ts + '\t' + txt + '\n')
    sys.stdout.buffer.write(('REPLY [' + ts + ']: ' + txt + '\n').encode('utf-8'))
    sys.stdout.flush()
if last is not None:
    open(OFFSET, 'w').write(str(last + 1))
" || true
      [ "${loop}" = "0" ] && break
    done
    ;;
  *)
    echo "usage: _tg.sh {send <msg>|sendfile <path>|poll|watch|set-offset <N>}" >&2; exit 2;;
esac
