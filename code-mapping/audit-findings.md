# Audit Findings

Comprehensive audit findings for Library Manager for Venus 6, organized by severity.

---

## CRITICAL / HIGH Severity

### 1. Command Injection in `getVENUSVersion()` — cli.js L199, service.js L68
```js
const subkeysRaw = execSync('reg query "' + rp + '"', ...);
const entryRaw = execSync('reg query "' + sk + '" /v DisplayName', ...);
```
**Issue**: Registry subkey paths from `reg query` output are interpolated into shell commands. A malicious registry key name could contain shell metacharacters (e.g., `& calc.exe`).
**Fix**: Use `execFileSync('reg', ['query', sk, '/v', 'DisplayName'], ...)` — direct process invocation, no shell.

### 2. Command Injection in COM Deregistration — cli.js L1582
```js
execSync(`"${regasmPath}" /unregister "${dllPath}"`, { ... });
```
**Issue**: `dllPath` includes manifest-supplied DLL names. A malicious package could inject shell commands.
**Fix**: Use `execFileSync(regasmPath, ['/unregister', dllPath], ...)`.

### 3. Missing `trustedCerts` in `import-archive` — cli.js L1101
```js
const sigResult = verifyPackageSignature(innerZip);  // missing trustedCerts!
```
**Issue**: Archive-imported packages never have `trust_status === 'trusted'`. Publisher trust evaluation is skipped entirely.
**Fix**: Load trusted certs before the loop and pass: `verifyPackageSignature(innerZip, trustedCerts)`.

### 4. Missing `trustedCerts` in `rollback-lib` — cli.js L2184
Same issue as #3 — rollback verification doesn't load trusted certificates.

---

## MEDIUM Severity

### 5. OEM Password Hash Without Salt — shared.js L985
```js
const OEM_AUTHOR_PASSWORD_HASH = 'bbdc525497de1c19c57767e36b4f01dadcc05348664eea071ac984fd955bc207';
function validateAuthorPassword(password) {
    var inputHash = crypto.createHash('sha256').update(password).digest();
```
**Issue**: Plain SHA-256, no salt, no key-stretching. Hash embedded in source. Trivially brute-forceable.
**Fix**: Use PBKDF2 or scrypt with salt. Stop exporting the raw hash constant.

### 6. Sensitive Constants Exported — shared.js L1836, L1843
`PKG_SIGNING_KEY` and `OEM_AUTHOR_PASSWORD_HASH` are exported. No consumer uses them directly.
**Fix**: Remove from exports; route all usage through wrapper functions.

### 7. Container Payload Size Overflow — shared.js L308
```js
header.writeUInt32LE(scrambled.length, 12);
```
**Issue**: UInt32 overflow for payloads > 4 GB (unlikely but unguarded).
**Fix**: Add check: `if (scrambled.length > 0xFFFFFFFF) throw new Error('...')`.

### 8. `safeZipExtractPath` doesn't strip absolute paths — shared.js L386
```js
var resolved = path.resolve(baseDir, fname);
```
**Issue**: ZIP entries with absolute paths (e.g., `C:\Windows\foo`) could resolve outside baseDir on Windows.
**Fix**: Strip leading drive letters and slashes: `fname = fname.replace(/^[a-zA-Z]:/, '').replace(/^[\\/]+/, '')`.

### 9. Private key written with default permissions — cli.js L2752
**Fix**: Add `{ mode: 0o600 }` to writeFileSync options.

---

## LOW Severity / Dead Code

### 10. Dead Imports in cli.js
| Line | Import | Status |
|------|--------|--------|
| L44  | `computeZipEntryHashes` | Never used |
| L55  | `saveTrustedCertificate` | Never used |
| L135 | `OEM_AUTHOR_PASSWORD_HASH` | Never used |
| L435 | `sanitizeHslForParsing` | Never used |
| L436 | `splitHslArgs` | Never used |
| L437 | `parseHslParameter` | Never used |
| L438 | `extractHslDocComment` | Never used |
| L439 | `parseHslFunctions` | Never used |

### 11. Dead Function in shared.js
| Line | Function | Status |
|------|----------|--------|
| L1047| `isTagSegmentValid()` | Defined but never called, never exported |

### 12. Phantom `gStarred` Group — cli.js L341
```json
{"group-id":"gStarred","method-ids":[],"locked":false}
```
`gStarred` is in seed data but NOT in `DEFAULT_GROUPS`. This is a leftover from a removed feature.
**Fix**: Remove from seed data.

### 13. Orphaned JSDoc Comments — cli.js L413-434
Full JSDoc blocks for functions that were moved to shared.js. The comments remain but have no code.
**Fix**: Remove orphaned comments.

### 14. Legacy `install_path` Fallback — cli.js L1545
```js
const libPath = lib.lib_install_path || lib.install_path || '';
```
`install_path` is a legacy field name. Only appears in this one location.
**Fix**: Remove fallback or add migration.

### 15. Export Duplicates Help Files — cli.js L1218, L1340
Help files appear in both `library_files` and `help_files` in the manifest.
**Fix**: Document as intentional or exclude from one.

### 16. Silent Error Swallowing — shared.js (multiple locations)
Catch blocks with `catch (_) { return false/null; }` at L209, L460, L520, L757, L818, L999.
**Fix**: Add diagnostic logging before returning failure.

### 17. `computeFileHash` Single-Line Edge Case — shared.js L451
Single-line HSL files include the metadata footer in the hash (the `pop` is skipped).
**Fix**: Update comment or check for footer pattern.

### 18. `isValidLibraryName` allows leading dots — shared.js L411
Names like `.hidden` are allowed. Could be unexpected.
**Fix**: Consider rejecting leading dots.

### 19. No HMAC format validation — shared.js L667
`sig.hmac` is not validated as 64-char hex before comparison.
**Fix**: Add regex check: `/^[a-f0-9]{64}$/`.

---

## Feature Gaps (Not Bugs)

### 20. No `--require-signature` flag in CLI
Unsigned packages are silently accepted. Only `--require-trust` exists.

### 21. No `--reject-legacy` flag in CLI
Old-format packages are detected but always accepted.

### 22. `trustPublisher` not exposed via REST API
Available in service.js but no REST route exists.
