# 🔐 AD CS Security Auditing with Locksmith

> A practical guide to understanding **Active Directory Certificate Services (AD CS)**, identifying misconfigurations, and auditing certificate templates using **Locksmith** — covering ESC1–ESC8 attack vectors.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows_Server-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>
  <img src="https://img.shields.io/badge/Tool-Locksmith-8B0000?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Focus-AD_CS_Security-critical?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Shell-PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white"/>
</p>

---

## 📋 Table of Contents

- [What is AD CS?](#-what-is-ad-cs)
- [AD CS Components](#-ad-cs-components)
- [Common Uses](#-common-uses)
- [Why This Matters — ESC Attacks](#️-why-this-matters--esc-attacks)
- [What is Locksmith?](#-what-is-locksmith)
- [adeleg vs Locksmith](#-adeleg-vs-locksmith)
- [Running Locksmith](#️-running-locksmith)
- [Output Modes](#-output-modes)
- [Generating Reports](#-generating-reports)
- [Available Scans](#-available-scans)
- [Troubleshooting](#-troubleshooting)

---

## 🏛 What is AD CS?

**Active Directory Certificate Services (AD CS)** is a Microsoft server role that lets organizations build a **Public Key Infrastructure (PKI)** — providing public key cryptography, digital certificates, and digital signature capabilities.

At its core, AD CS issues, manages, validates, and revokes digital certificates used for:

| Use Case | Description |
|---|---|
| **Authentication** | Authenticating users, computers, and devices |
| **Secure Email** | S/MIME encryption and digital signatures |
| **File Encryption** | Encrypting files and data (EFS) |
| **SSL/TLS** | Securing internal web servers |
| **VPN / Wi-Fi** | 802.1x certificate-based network access |
| **Smart Card Login** | Certificate-based domain logins |
| **Code Signing** | Signing internal scripts and applications |

---

## 🧩 AD CS Components

### Certification Authority (CA) Types

| CA Type | Role |
|---|---|
| **Root CA** | Top-level authority — usually kept offline |
| **Subordinate CA** | Issues certificates on behalf of the Root CA |
| **Enterprise CA** | Integrated with Active Directory — supports auto-enrollment |
| **Standalone CA** | Manual approval — not AD-integrated |

### Supporting Services

- **Enrollment Web Services** — Allow external/non-domain devices to request certificates via HTTPS
- **Web Enrollment** — Browser-based manual certificate request portal
- **Online Responder (OCSP)** — Real-time certificate status (replaces CRL polling)
- **NDES** — Issues certificates to network devices (routers, printers, etc.)
- **Certificate Templates** — Define rules for permissions, validity periods, and key settings

---

## 🎯 Common Uses

- **Domain Authentication** — Smart card & certificate-based logins
- **Secure Email** — S/MIME signing & encryption
- **Internal SSL/TLS** — Issue certs for internal apps without public CA costs
- **VPN / Wi-Fi Auth** — Certificates for 802.1x authentication
- **Code Signing** — Sign internal scripts and applications

---

## ⚠️ Why This Matters — ESC Attacks

Misconfigured AD CS is one of the most critical attack surfaces in an Active Directory environment.

> [!WARNING]
> Misconfigured certificate templates can lead to **full domain compromise** — no credentials required in some scenarios.

Known attack classes are categorized as **ESC (Enterprise Security Configuration)** vulnerabilities:

| Attack | Risk |
|---|---|
| **ESC1–ESC8** | Privilege escalation via certificate template abuse |
| **Kerberos Abuse** | Certificates used to forge Kerberos tickets (Pass-the-Certificate) |
| **Domain Admin Takeover** | Full forest compromise from a low-privileged user |

---

## 🔍 What is Locksmith?

**Locksmith** is an AD CS security auditor — it scans your environment for certificate misconfigurations that could be exploited.

It focuses on:

- Certificate Templates
- Enrollment permissions
- ESC1–ESC8 attack vectors

```
CN=Certificate Templates ⚠️  ← Locksmith targets exactly this
```

---

## 🧠 adeleg vs Locksmith

| Tool | Purpose |
|---|---|
| **adeleg** | Delegation / ACL analysis across AD objects |
| **Locksmith** | AD CS / Certificate template abuse detection |

> Together these tools provide **complete Active Directory security visibility**.

---

## ▶️ Running Locksmith

### Prerequisites

- PowerShell running **as Administrator**
- Must be executed on a **domain-joined machine**
- AD PowerShell module available

### Basic Execution

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module .\Invoke-Locksmith.ps1
Invoke-Locksmith
```

> [!NOTE]
> If the script is blocked by Windows, unblock it first:
> ```powershell
> Unblock-File .\Invoke-Locksmith.ps1
> ```

---

## 📊 Output Modes

Locksmith has 4 output modes:

| Mode | Output | File Generated |
|---|---|---|
| `0` *(default)* | Console — Table format | ❌ No file |
| `1` | Console — List format with fix suggestions | ❌ No file |
| `2` | CSV — Issues only | ✅ `ADCSIssues.CSV` |
| `3` | CSV — Issues + Remediation scripts | ✅ `ADCSRemediation.CSV` + `.PS1` |

> [!TIP]
> Mode 0 is for quick triage. Use **Mode 3** for full audits — it generates both a CSV report and a ready-to-run remediation script.

---

## 📁 Generating Reports

### Mode 2 — Issues-Only CSV

```powershell
# Basic scan
.\Invoke-Locksmith.ps1 -Mode 2

# With custom output path
Invoke-Locksmith -Mode 2 -Scans All -OutputPath 'C:\Reports'
```

Outputs all discovered AD CS issues to `ADCSIssues.CSV` in the current directory.

---

### Mode 3 — Issues + Remediation (Recommended)

```powershell
# Basic scan
.\Invoke-Locksmith.ps1 -Mode 3

# Full scan with custom output path
Invoke-Locksmith -Mode 3 -Scans All -OutputPath 'C:\Reports'
```

Outputs:
- `ADCSRemediation.CSV` — all discovered issues with fix descriptions
- `.PS1` remediation script — environment-specific, ready to review and run

---

### Full Command Example

```powershell
# Full scan, all checks, save to C:\Temp
Invoke-Locksmith -Mode 3 -Scans All -OutputPath 'C:\Temp'
```

> If `-OutputPath` is not specified, reports are saved to the **current working directory** (`$PWD`). Run `Get-Location` to confirm.

---

## 🔎 Available Scans

The `-Scans` parameter accepts the following values:

| Value | Description |
|---|---|
| `All` | Run every available check |
| `Auditing` | Auditing configuration checks |
| `ESC1` – `ESC8` | Individual ESC attack checks |
| `PromptMe` | Interactive picker — choose checks at runtime |

```powershell
# Example: scan only for ESC1 and ESC4
Invoke-Locksmith -Mode 3 -Scans ESC1,ESC4 -OutputPath 'C:\Reports'
```

---

## 🛠 Troubleshooting

| Issue | Fix |
|---|---|
| Script blocked by execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Script file blocked by Windows | `Unblock-File .\Invoke-Locksmith.ps1` |
| No AD module / access errors | Run PowerShell **as Administrator** on a **domain-joined** machine |
| Can't find the output CSV | Didn't specify `-OutputPath` — check `Get-Location` for current directory |
| Running Mode 0 and seeing no file | Expected — Mode 0 is console only. Re-run with `-Mode 3 -OutputPath 'C:\Reports'` |

---

## 📚 References

| Resource | Link |
|---|---|
| 🔐 Locksmith on GitHub | [github.com/jakehildreth/locksmith](https://github.com/jakehildreth/locksmith) |
| 📘 Microsoft AD CS Docs | [learn.microsoft.com — AD CS Overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview) |
| 🧠 ESC Attack Research | [SpecterOps — Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) |
| 🔍 adeleg | [github.com/zecops/adeleg](https://github.com/zecops/adeleg) |
