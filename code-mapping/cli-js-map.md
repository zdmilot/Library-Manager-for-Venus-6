# Code Map: cli.js

**File**: `cli.js` | **Lines**: 2827 | **Purpose**: CLI entry point for library management commands

## Imports

| Line | Module |
|------|--------|
| L35  | `fs` |
| L36  | `path` |
| L37  | `os` |
| L38  | `adm-zip` |
| L39  | `crypto` |
| L40  | `./lib/shared` |

### Shared Module Re-exports (L43–62)
`safeZipExtractPath`, `isValidLibraryName`, `computeZipEntryHashes`*,
`signPackageZip`, `signPackageZipWithCert`, `verifyPackageSignature`,
`parseHslMetadataFooter`, `generateSigningKeyPair`, `buildPublisherCertificate`,
`validatePublisherCertificate`, `loadTrustedCertificates`, `saveTrustedCertificate`*,
`CONTAINER_MAGIC_PKG`, `CONTAINER_MAGIC_ARC`, `packContainer`, `unpackContainer`,
`OEM_AUTHOR_PASSWORD_HASH`*, `isRestrictedAuthor`, `validateAuthorPassword`,
`sanitizeHslForParsing`*, `splitHslArgs`*, `parseHslParameter`*,
`extractHslDocComment`*, `parseHslFunctions`*, `extractPublicFunctions`,
`extractHslIncludes`, `computeLibraryHashes`

\* = Dead imports (never used directly)

## Constants

| Line | Name | Value |
|------|------|-------|
| L68  | `MIME_MAP` | `shared.IMAGE_MIME_MAP` |
| L70  | `HSL_METADATA_EXTS` | `shared.HSL_METADATA_EXTS` |
| L72  | `DEFAULT_LIB_PATH` | `C:\Program Files (x86)\HAMILTON\Library` |
| L73  | `DEFAULT_MET_PATH` | `C:\Program Files (x86)\HAMILTON\Methods` |
| L76  | `LOCAL_DATA_DIR` | `path.join(__dirname, 'local')` |
| L77  | `PACKAGE_STORE_DIR` | `path.join(LOCAL_DATA_DIR, 'packages')` |
| L82  | `DEFAULT_GROUPS` | `{gAll, gRecent, gFolders, gEditors, gHistory, gOEM}` |

## Utility Functions

| Line | Function | Purpose |
|------|----------|---------|
| L95  | `getGroupById(db, id)` | Look up group by ID |
| L102 | `loadSystemLibIds()` | Load system lib IDs (cached) |
| L115 | `loadSystemLibNames()` | Load system lib names (cached) |
| L121 | `isSystemLibrary(libId)` | Check system lib by ID |
| L125 | `isSystemLibraryByName(libName)` | Check system lib by name |
| L152 | `parseArgs(argv)` | Minimal --key value argument parser |
| L183 | `getWindowsUsername()` | Get current Windows username |
| L199 | `getVENUSVersion()` | Detect VENUS version from registry (**command injection risk**) |
| L240 | `appendAuditTrailEntry(userDataDir, entry)` | Append to audit trail JSON |
| L282 | `buildAuditTrailEntry(eventType, details)` | Build audit entry with env fields |
| L298 | `connectDB(dbDir)` | Connect diskdb |
| L305 | `resolveDBPath(args)` | Resolve DB path from CLI args |
| L319 | `ensureLocalDataDir(dirPath)` | Create local data dir with seeds |
| L355 | `warnIfSystemPath(dirPath, label)` | Warn if path is system-critical |
| L368 | `getInstallPaths(db, libDirOvr, metDirOvr)` | Resolve install paths |
| L395 | `extractRequiredDependencies(libFiles, libBasePath)` | Extract HSL dependencies |

## Core Package Operations

| Line | Function | Purpose |
|------|----------|---------|
| L482 | `autoAddToGroup(db, savedLibId, authorName)` | Add lib to nav tree group |
| L549 | `installPackage(manifest, zip, libDestDir, demoDestDir, ...)` | Core installer (9 params) |
| L706 | `ensureOutDir(filePath)` | Create parent directories |
| L736 | `resolvePublisherRegistryPath(args)` | Resolve publisher registry path |
| L746 | `getPackageStoreDir(args)` | Resolve package store directory |
| L780 | `findLibrary(db, nameOrId)` | Find lib by _id or name |

## Command Handlers

| Line | Function | CLI Command | Purpose |
|------|----------|-------------|---------|
| L790 | `cmdListLibs(args)` | `list-libs` | List installed libraries |
| L827 | `cmdImportLib(args)` | `import-lib` | Import single .hxlibpkg |
| L1064 | `cmdImportArchive(args)` | `import-archive` | Import .hxlibarch archive |
| L1189 | `cmdExportLib(args)` | `export-lib` | Export library as .hxlibpkg |
| L1268 | `cmdExportArchive(args)` | `export-archive` | Export libraries as .hxlibarch |
| L1432 | `cmdDeleteLib(args)` | `delete-lib` | Delete installed library |
| L1630 | `cmdCreatePackage(args)` | `create-package` | Create .hxlibpkg from spec |
| L1874 | `cmdGenerateSyslibHashes(args)` | `generate-syslib-hashes` | Generate system lib baseline |
| L1952 | `cmdVerifySyslibHashes(args)` | `verify-syslib-hashes` | Verify system lib integrity |
| L2101 | `cmdListVersions(args)` | `list-versions` | List cached package versions |
| L2136 | `cmdRollbackLib(args)` | `rollback-lib` | Rollback to cached version |
| L2261 | `printHelp()` | `help` | Print usage/help text |
| L2518 | `cmdVerifyPackage(args)` | `verify-package` | Verify package signatures |
| L2700 | `cmdGenerateKeypair(args)` | `generate-keypair` | Generate Ed25519 keypair |
| L2765 | `cmdListPublishers(args)` | `list-publishers` | List publisher certificates |

## Main Dispatcher

| Line | Purpose |
|------|---------|
| L2799 | `die(msg, code)` — exit with error |
| L2806 | Main dispatcher switch on `process.argv[2]` |

## Known Issues

| Line | Issue | Severity |
|------|-------|----------|
| L44  | `computeZipEntryHashes` imported but never used | Dead code |
| L55  | `saveTrustedCertificate` imported but never used | Dead code |
| L135 | `OEM_AUTHOR_PASSWORD_HASH` imported but never used | Dead code |
| L435-439 | 5 HSL parser functions imported but never used | Dead code |
| L199 | `execSync('reg query "' + sk + '"')` — command injection risk | HIGH |
| L1582 | `execSync(\`"${regasmPath}" /unregister "${dllPath}"\`)` — command injection risk | MEDIUM |
| L341 | `gStarred` in seed data but not in DEFAULT_GROUPS | Bug |
| L1101 | `import-archive` missing trustedCerts arg to verifyPackageSignature | Bug |
| L2184 | `rollback-lib` missing trustedCerts arg to verifyPackageSignature | Bug |
