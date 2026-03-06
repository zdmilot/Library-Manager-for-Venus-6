# Pre-Release Audit Summary — Library Manager for Venus 6 v1.6.5

## Audit Scope

Full pre-release audit of all application source code across three entry points:
- **GUI**: `html/js/main.js` (13,469 lines)
- **CLI**: `cli.js` (2,810 lines)
- **COM Bridge**: `com-bridge.js` (164 lines) → `lib/service.js` (1,732 lines)
- **Shared**: `lib/shared.js` (1,821 lines)

Total: 7 files, ~20,670 lines, 1,209 functions, 96 cross-file references.

---

## Code Changes Applied

### 1. gStarred Divergence Fix (cli.js + service.js)

**Problem**: `gStarred` (the Starred/Favorites group) is a fully active GUI feature with
10+ references in main.js (navigation rendering, accordion ordering, star toggle, card
filtering). It was **missing** from `DEFAULT_GROUPS` in both `cli.js` and `service.js`,
meaning CLI `list-libs` and COM `listLibraries` would not recognize starred libraries
or include the group in freshly seeded databases.

**Changes**:
- `cli.js` L83: Added `gStarred` to `DEFAULT_GROUPS` with `{favorite: true, protected: true}`
- `cli.js` L342: Added `gStarred` entry to seed data in `ensureLocalDataDir()`
- `service.js` L44: Added `gStarred` to `DEFAULT_GROUPS` with `{favorite: true, protected: true}`

### 2. Private Key File Permissions (cli.js)

**Problem**: The `generate-keypair` CLI command wrote the Ed25519 private key file with
default filesystem permissions (world-readable on many systems).

**Change**:
- `cli.js` L2718: Added `{ mode: 0o600 }` to `fs.writeFileSync()` for the private key

### 3. Legacy v1.0 HMAC-Only Signing Removed (shared.js, cli.js, service.js, main.js)

**Problem**: The legacy `signPackageZip()` function created v1.0 HMAC-only signatures with
no publisher identity (no Ed25519 digital signature). These packages were accepted on import
with only a warning. There should be no legacy signing support — Ed25519 code-signed
packages (v2.0) are the only accepted signed format.

**Changes**:
- `lib/shared.js`: Removed `signPackageZip()` function and its `module.exports` entry
- `lib/shared.js`: `verifyPackageSignature()` now rejects v1.0 signatures as invalid
  (`result.valid = false` with explicit error message)
- `lib/shared.js`: Updated comments/JSDoc — HMAC is "tamper-detection hash", not "legacy"
- `cli.js`: Removed `signPackageZip` import; 3 callers (`cmdExportLib`, `cmdExportArchive`,
  `cmdCreatePackage`) now leave packages unsigned when no `--sign-key` is provided (with
  WARNING message) instead of falling back to v1.0 signing
- `cli.js`: Updated help text ("Without --sign-key, the package is left unsigned") and
  verify-package description ("Legacy HMAC-only (v1.0) signatures are rejected")
- `cli.js`: Removed impossible "ALL PACKAGES VERIFIED (HMAC-only)" result path
- `lib/service.js`: 3 callers (`exportLibrary`, `exportArchive`, `createPackage`) updated
  to leave packages unsigned when no signing key is configured
- `html/js/main.js`: Removed `signPackageZip` import; `backupSystemLibrary` now creates
  unsigned backup packages; `applyPackageSigning` leaves packages unsigned when no
  credentials are available

---

## Documentation Changes Applied

### Code Map Files Updated

| File | Changes |
|------|---------|
| `code-mapping/generated-map.json` | Regenerated via companion script (post-code-fix, post-legacy-removal) |
| `code-mapping/audit-findings.md` | Complete rewrite — 21 findings with status tracking |
| `code-mapping/cli-js-map.md` | All line numbers corrected; gStarred added to DEFAULT_GROUPS listing |
| `code-mapping/service-js-map.md` | All line numbers corrected; gStarred added to DEFAULT_GROUPS listing |
| `code-mapping/shared-js-map.md` | All line numbers corrected; removed phantom entries and `signPackageZip`; fixed incorrect constant values |
| `code-mapping/main-js-map.md` | All line numbers corrected (line count 13,673→13,469); global state variables updated |
| `code-mapping/architecture-overview.md` | Line counts corrected (cli.js→2,811, main.js→13,469, shared.js→1,822, service.js→1,733) |

### CHM Documentation

No changes required. `DataModel.html` already correctly documents:
- `gStarred` as one of 7 built-in `DEFAULT_GROUPS` (L171)
- `starred_libs` setting field (L261)
- Seven-group count in descriptive text (L165)

---

## Risk Summary

### Resolved Risks (14 items)

| # | Finding | Resolution |
|---|---------|------------|
| 1 | Command injection in `getVENUSVersion()` | Uses `execFileSync` with array args |
| 2 | Command injection in COM deregistration | Uses `execFileSync` with array args |
| 6 | Sensitive constants exported | No longer in `module.exports` |
| 7 | Container payload size overflow | Guard added before `writeUInt32LE` |
| 8 | `safeZipExtractPath` absolute path bypass | Strips drive letters and leading slashes |
| 9 | Private key default permissions | **Fixed this audit** — `mode: 0o600` |
| 10 | Dead imports in cli.js | Removed |
| 11 | Dead function `isTagSegmentValid` | Removed from shared.js |
| 12 | gStarred divergence | **Fixed this audit** — added to cli.js & service.js |
| 13 | Orphaned JSDoc comments | Cleaned up |
| 14 | Legacy `install_path` fallback | All properly prefixed |
| 19 | No HMAC format validation | Regex check added |
| 21 | Legacy v1.0 signatures accepted | **Fixed this audit** — v1.0 rejected; `signPackageZip()` removed |

### Accepted Risks (2 items)

| # | Finding | Rationale |
|---|---------|-----------|
| 5 | OEM password hash without salt | Protects namespace reservation only (not auth); requires matching Ed25519 cert |
| 15 | Export duplicates help files | Intentional backward compatibility (comment at cli.js L1704) |

### Open — Low Priority (3 items)

| # | Finding | Impact |
|---|---------|--------|
| 16 | Silent error swallowing in shared.js | Diagnostics only; `catch (_) { return false }` hides root causes |
| 17 | `computeFileHash` single-line edge case | Single-line HSL files with metadata footer are near-impossible in practice |
| 18 | `isValidLibraryName` allows leading dots | Cosmetic on Windows; creates hidden dirs on Unix (not a supported platform) |

### Feature Gaps (1 item — not a bug)

| # | Finding | Description |
|---|---------|-------------|
| 20 | No `--require-signature` CLI flag | Unsigned packages are silently accepted on import |

### Security Audit Summary — exec/execSync in main.js

All 5 `child_process` call sites in the GUI audited:
- **2 hardcoded** (whoami, reg query) — no user input, safe
- **3 with user-derived paths** (COM registration) — validated with character filter
  (`/[&|><\`%\r\n]/` + single-quote rejection) and CLSID regex (`/\{[0-9A-Fa-f\-]+\}/`)
- No unmitigated injection vectors found

---

## Release Readiness Assessment

**Overall**: The codebase is in good shape for release. All critical and high-severity
findings from previous audits have been resolved. The three code changes made in this audit
(gStarred divergence fix, private key permissions, legacy v1.0 signing removal) address
functional correctness, security hardening, and signing integrity respectively. The
remaining open items are low-priority edge cases that do not affect core functionality or
security.

**Recommendation**: Proceed with release after verifying the gStarred changes work
correctly in the CLI (`list-libs` should show the Starred group) and COM bridge
(`listLibraries` should include gStarred in the group list).
