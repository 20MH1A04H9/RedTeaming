# Cordova Apps — Mobile Pentesting Notes

Reference notes on attacking Apache Cordova (formerly PhoneGap) hybrid mobile applications. Based on community research, primarily [HackTricks - Cordova Apps](https://hacktricks.wiki/en/mobile-pentesting/cordova-apps.html), with additional context from public CVE/OSV advisories.

## Why Cordova Apps Are Different

Apache Cordova lets developers ship a single HTML/CSS/JavaScript codebase as a native Android, iOS, or other platform app, wrapped in a native WebView shell. Unlike React Native — which runs JS through a JS VM and offers some protection against casual inspection — Cordova does **not compile or obfuscate the web assets by default**. This means:

- The entire `www/` folder (HTML, JS, CSS, config) ships inside the APK/IPA largely as-is.
- Anyone who extracts the package can read the app's logic, API endpoints, hardcoded secrets, and client-side validation/business logic.
- The app is fundamentally a WebView rendering local files, so WebView-based attack techniques (JS bridge abuse, deeplink injection, debugging exposure) apply directly.

## Attack Surface Overview

| Area | Risk |
|---|---|
| `www/` source code | Full disclosure of app logic, API keys, endpoints, comments |
| `cordova_plugins.js` | Reveals exact plugin list + versions in use — map directly to known CVEs |
| WebView JS bridge | Native functionality exposed to JS; abuse depends on `@JavascriptInterface` exposure |
| Remote debugging | Chrome DevTools can attach to WebView if debugging is enabled (debug builds, or forced via Frida/LSPosed on release builds) |
| Deeplinks/custom URI schemes | Plugins handling deeplinks may pass unsanitized input into the WebView, leading to JS injection |
| Repackaging/code tampering | No default integrity check means modified app code can be recompiled and resigned |

## Recon: Extracting and Reading the Source

1. Confirm the target is a Cordova app — look for `cordova.js`, `cordova_plugins.js`, and a `www/` directory after unpacking the APK (`apktool d` or unzipping the APK directly works since assets aren't compiled).
2. Read `assets/www/cordova_plugins.js` — this enumerates **every plugin and version** bundled with the app. Treat this as your dependency manifest for vulnerability lookups.
3. Grep the `www/` tree for:
   - API endpoints / base URLs
   - Hardcoded keys, tokens, credentials
   - Debug flags or feature toggles left enabled
   - Any `eval()`, `innerHTML`, or dynamic script injection patterns
4. Check `config.xml` for `<access>` / `<allow-navigation>` rules — overly permissive whitelists can allow loading attacker-controlled remote content inside the privileged WebView.

## Cloning / Repackaging for Testing

A common workflow when you need to modify or instrument the app's JS for testing:

1. **Prerequisites**: Node.js, Android SDK, Java JDK, Gradle, and the Cordova CLI (`npm install -g cordova`).
2. Create a new Cordova project targeting the same platform (Android/iOS).
3. Match the Cordova platform version to the original. Check `PLATFORM_VERSION_BUILD_LABEL` inside the original app's `cordova.js` to identify the correct Cordova Android platform version — this does **not** map 1:1 to Android API levels, so cross-reference the Cordova docs.
4. Install each plugin listed in `cordova_plugins.js` individually, matching versions where possible.
5. Replace the generated `www/` directory with the original app's `www/` contents.
6. Build a debug APK (`cordova build android --debug`) — debug builds enable WebView debugging via Chrome DevTools by default.

For automating this process, **MobSecco** is a community tool built specifically to streamline cloning Cordova Android apps and avoid doing the above steps manually.

## Enabling/Forcing WebView Debugging

- **App-side (debug builds)**: `WebView.setWebContentsDebuggingEnabled(true)` is typically set automatically.
- **Release builds**: Frameworks like LSPosed, or a Frida script, can force-enable debugging on a release build without rebuilding it. The Frida CodeShare entry "Cordova - enable WebView debugging" covers this.
- Once attached via `chrome://inspect`, inspect the global scope for the Cordova exec bridge object (commonly named things like `cordova`, `_cordovaNative`, or app-specific bridge names). Enumerate its members to find exposed native methods.
- Methods exposed to JS without the `@JavascriptInterface` annotation (Android) are not callable from JS — this annotation is the primary boundary preventing arbitrary native method invocation from a compromised WebView context.

## Plugin-Based Attack Surface — Known Issues to Check For

Cordova's security posture is largely a function of **which plugins are bundled** and their versions. Treat `cordova_plugins.js` as a vulnerability checklist:

- **Malicious/compromised npm packages**: Cordova plugins are pulled from npm at build time. Build pipelines and developer machines that installed a since-flagged malicious plugin package should be considered compromised — review `package.json` / `package-lock.json` for unexpected or unpinned Cordova plugin dependencies and verify against OSV/npm advisories.
- **Deeplink/custom URL scheme plugins**: Plugins that pass deeplink parameters into the WebView without sanitization can allow injected JavaScript to execute in the app's main context (XSS → potential RCE depending on exposed bridge methods). Always test custom URI scheme handlers with crafted payloads.
- General rule: for every plugin + version found, search CVE databases and OSV for known advisories before assuming the app is "just a webpage."

## Suggested Testing Checklist

- [ ] Extract APK/IPA, confirm Cordova via `cordova.js` / `cordova_plugins.js`
- [ ] Enumerate plugins + versions, cross-reference CVE/OSV databases
- [ ] Review `config.xml` whitelist/access rules
- [ ] Grep `www/` for secrets, endpoints, debug flags
- [ ] Attempt to attach Chrome DevTools (debug build or via Frida/LSPosed on release)
- [ ] Enumerate JS bridge object members; check for methods missing `@JavascriptInterface`
- [ ] Fuzz any custom URL scheme / deeplink handlers for JS injection
- [ ] Attempt repackage/clone with MobSecco or manual Cordova project to test modified `www/`

## References

- [HackTricks — Cordova Apps](https://hacktricks.wiki/en/mobile-pentesting/cordova-apps.html)
- [HackTricks — WebView Attacks](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/mobile-pentesting/android-app-pentesting/webview-attacks.md)
- [Recreating Cordova Mobile Apps to Bypass Security Implementations](https://infosecwriteups.com/recreating-cordova-mobile-apps-to-bypass-security-implementations-8845ff7bdc58)
- [Payatu — Effortless Pentesting of Apache Cordova Applications](https://payatu.com/blog/effortless-pentesting-of-apache-cordova-applications/)
- MobSecco (Cordova app cloning automation)
- CVE-2023-2507 — CleverTap Cordova Plugin deeplink XSS
- OSV-ID MAL-2024-7845 — malicious `cordova-plugin-acuant` npm package

---

*Notes for personal/authorized testing use only. Always operate within scope and legal authorization.*
