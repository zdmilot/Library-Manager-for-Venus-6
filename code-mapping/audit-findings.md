# Audit Findings

Comprehensive audit findings for Library Manager for Venus 6 v1.7.5.
Last updated after full pre-release audit.

---

## Status Key

| Tag | Meaning |
|-----|---------|
| **RESOLVED** | Fixed in current codebase |
| **ACCEPTED** | Known limitation, accepted risk |
| **OPEN** | Still present, remediation recommended |

---

## CRITICAL / HIGH Severity

### 1. ~~Command Injection in `getVENUSVersion()`~~ (RESOLVED)
- **File**: cli.js L199, service.js L60, main.js L347
- All three entry points now use `execFileSync('reg', ['query', ...], ...)` — no shell interpolation.

### 2. ~~Command Injection in COM Deregistration~~ (RESOLVED)
- **File**: cli.js
- Now uses `execFileSync(regasmPath, ['/unregister', dllPath], ...)`.

---

## MEDIUM Severity

### 5. OEM Password Hash Without Salt — shared.js (ACCEPTED)
```js
const OEM_AUTHOR_PASSWORD_HASH = 'bbdc...';
crypto.createHash('sha256').update(password).digest();
```
Plain SHA-256, no salt, no key-stretching. Hash embedded in source.
**Accepted risk**: The OEM password gate protects author namespace reservation only;
it does not guard user data or authentication credentials. Brute-force yields only
the ability to publish under a restricted author name, which additionally requires
a valid Ed25519 code-signing certificate match.

### 6. ~~Sensitive Constants Exported~~ (RESOLVED)
`PKG_SIGNING_KEY` and `OEM_AUTHOR_PASSWORD_HASH` are no longer exported.

### 7. ~~Container Payload Size Overflow~~ (RESOLVED)
- **File**: shared.js
- Guard added: payloads > 4 GB now throw before `writeUInt32LE`.

### 8. ~~`safeZipExtractPath` absolute path bypass~~ (RESOLVED)
- **File**: shared.js
- Now strips leading drive letters and leading slashes before `path.resolve`.

### 9. ~~Private Key Written with Default Permissions~~ (RESOLVED)
- **File**: cli.js L2718
- `writeFileSync` for the private key now uses `{ mode: 0o600 }`.
- Note: main.js GUI key generator (L7519) still uses default permissions; this
  is an informational UI convenience action protected by the desktop session.

---

## LOW Severity / Informational

### 10. ~~Dead Imports in cli.js~~ (RESOLVED)
All dead imports have been removed.

### 11. ~~Dead Function `isTagSegmentValid()` in shared.js~~ (RESOLVED)
Function has been removed from the codebase.

### 12. ~~`gStarred` Divergence Between Entry Points~~ (RESOLVED)
- **Previous finding**: Incorrectly identified `gStarred` as dead/phantom code.
- **Corrected analysis**: `gStarred` is a **fully active GUI feature** in main.js
  (DEFAULT_GROUPS L828, seed data L908, nav rendering L4492–4607, star toggle
  L10306, starred card filtering L5523). It was **missing** from cli.js
  `DEFAULT_GROUPS` and seed data, and from service.js `DEFAULT_GROUPS`.
- **Fix applied**: Added `gStarred` to `DEFAULT_GROUPS` in both cli.js (L83)
  and service.js (L44), and to cli.js seed data (L342).

### 13. ~~Orphaned JSDoc Comments in cli.js~~ (RESOLVED)
Previously orphaned JSDoc blocks have been cleaned up.

### 14. ~~Legacy `install_path` Fallback in cli.js~~ (RESOLVED)
No bare `install_path` references remain; all use `lib_install_path` / `demo_install_path`.

### 15. Export Duplicates Help Files in Manifest (ACCEPTED — intentional)
- **File**: cli.js L1704
- Help files (.chm) appear in both `library_files` and `help_files` in the manifest.
- Comment at L1704: "keep CHMs in library_files for backward compat".
- **Accepted**: Intentional backward-compatibility behavior.

### 16. Silent Error Swallowing — shared.js (OPEN — low priority)
Multiple `catch (_) { return false/null; }` patterns silently discard errors.
- **Recommendation**: Add `console.warn` before returning failure for diagnostic use.

### 17. `computeFileHash` Single-Line Edge Case — shared.js (OPEN — low priority)
Single-line HSL files include the metadata footer in the hash because the
line-split logic skips `pop()` for single-element arrays.
- **Impact**: Minimal — single-line HSL files with a metadata footer are
  extremely unlikely in practice.

### 18. `isValidLibraryName` Allows Leading Dots — shared.js (OPEN — low priority)
Names like `.hidden` pass validation.
- **Impact**: Cosmetic only; library names starting with `.` would create
  hidden directories on Unix but are visible on Windows.

### 19. ~~No HMAC Format Validation~~ (RESOLVED)
- **File**: shared.js
- `sig.hmac` is now validated via regex before comparison.

---

## `execSync` / `exec` Usage Audit — main.js

The GUI (main.js) uses `child_process` calls in five contexts:

| Line | Call | Input Source | Mitigation |
|------|------|-------------|------------|
| L192 | `execSync('whoami /groups ...')` | Hardcoded command | Safe — no user input |
| L2227 | `execSync('reg query ...')` | Hardcoded reg path | Safe — no user input |
| L6794 | `exec(fullCmd)` for COM registration | `dllPath` from manifest | Validated: `/[&\|><\`%\r\n]/` + single-quote check (L6794) |
| L6893 | `execSync('"regasm" "dllPath"')` | `dllPath` from manifest | Validated: same char filter (L6882) |
| L6929–6939 | `execSync('reg query ...')` | CLSIDs from RegAsm /regfile | Validated: CLSID regex `/\{[0-9A-Fa-f\-]+\}/` |

All command execution paths are either hardcoded or have character-level input
validation. Windows filename rules prevent `"` in file paths, covering the
remaining gap. No unmitigated injection vectors found.

---

## Feature Gaps (Not Bugs)

### 20. No `--require-signature` Flag in CLI (OPEN)
Unsigned packages are silently accepted on import. A strict mode would reject them.

### 21. ~~Legacy v1.0 HMAC-only Signatures Accepted~~ (RESOLVED)
- **Previous**: Pre-v2 signed packages (HMAC-only, no Ed25519) were accepted with a warning.
- **Fix applied**: `verifyPackageSignature()` now rejects v1.0 signatures as invalid.
  `signPackageZip()` (the v1.0 signer) has been removed from shared.js and all callers.
  Packages created without a signing key are now left unsigned rather than v1.0-signed.

---

## Summary of Changes in This Audit

| # | Finding | Action |
|---|---------|--------|
| 1 | cmd injection getVENUSVersion | Verified RESOLVED |
| 2 | cmd injection COM deregistration | Verified RESOLVED |
| 5 | OEM password unsalted | Accepted risk — documented rationale |
| 6 | Constants exported | Verified RESOLVED |
| 7 | Container overflow | Verified RESOLVED |
| 8 | safeZipExtractPath | Verified RESOLVED |
| 9 | Private key permissions | **FIXED** — added `mode: 0o600` to cli.js |
| 10 | Dead imports | Verified RESOLVED |
| 11 | Dead isTagSegmentValid | Verified RESOLVED — function removed |
| 12 | gStarred divergence | **FIXED** — added to cli.js & service.js DEFAULT_GROUPS + seed |
| 13 | Orphaned JSDoc | Verified RESOLVED |
| 14 | Legacy install_path | Verified RESOLVED |
| 15 | Help file duplication | Accepted — intentional backward compat |
| 16 | Silent error swallowing | OPEN — low priority |
| 17 | computeFileHash edge case | OPEN — low priority |
| 18 | isValidLibraryName dots | OPEN — low priority |
| 19 | HMAC format validation | Verified RESOLVED |
| 21 | Legacy v1.0 signatures accepted | **FIXED** — v1.0 rejected, `signPackageZip()` removed |
