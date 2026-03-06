# Code Map: cli.js

**File**: `cli.js` | **Lines**: 2810 | **Purpose**: CLI entry point for library management commands

## Imports

| Line | Module |
|------|--------|
| L34  | `fs` |
| L35  | `path` |
| L36  | `os` |
| L37  | `adm-zip` |
| L38  | `./lib/shared` |

### Shared Module Re-exports (L41–56)
`safeZipExtractPath`, `isValidLibraryName`,
`signPackageZipWithCert`, `verifyPackageSignature`,
`parseHslMetadataFooter`, `generateSigningKeyPair`, `buildPublisherCertificate`,
`validatePublisherCertificate`,
`CONTAINER_MAGIC_PKG`, `CONTAINER_MAGIC_ARC`, `packContainer`, `unpackContainer`,
`isRestrictedAuthor`, `validateAuthorPassword`,
`extractPublicFunctions`, `extractHslIncludes`, `computeLibraryHashes`

## Constants

| Line | Name | Value |
|------|------|-------|
| L62  | `MIME_MAP` | `shared.IMAGE_MIME_MAP` |
| L64  | `HSL_METADATA_EXTS` | `shared.HSL_METADATA_EXTS` |
| L66  | `DEFAULT_LIB_PATH` | `C:\Program Files (x86)\HAMILTON\Library` |
| L67  | `DEFAULT_MET_PATH` | `C:\Program Files (x86)\HAMILTON\Methods` |
| L71  | `LOCAL_DATA_DIR` | `path.join(__dirname, 'local')` |
| L72  | `PACKAGE_STORE_DIR` | `path.join(LOCAL_DATA_DIR, 'packages')` |
| L77  | `DEFAULT_GROUPS` | `{gAll, gRecent, gStarred, gFolders, gEditors, gHistory, gOEM}` |

## Utility Functions

| Line | Function | Purpose |
|------|----------|---------|
| L91  | `getGroupById(db, id)` | Look up group by ID |
| L99  | `loadSystemLibIds()` | Load system lib IDs (cached) |
| L113 | `loadSystemLibNames()` | Load system lib names (cached) |
| L119 | `isSystemLibrary(libId)` | Check system lib by ID |
| L123 | `isSystemLibraryByName(libName)` | Check system lib by name |
| L146 | `parseArgs(argv)` | Minimal --key value argument parser |
| L184 | `getWindowsUsername()` | Get current Windows username |
| L198 | `getVENUSVersion()` | Detect VENUS version from registry (uses `execFileSync`) |
| L239 | `appendAuditTrailEntry(userDataDir, entry)` | Append to audit trail JSON |
| L276 | `buildAuditTrailEntry(eventType, details)` | Build audit entry with env fields |
| L296 | `connectDB(dbDir)` | Connect diskdb |
| L306 | `resolveDBPath(args)` | Resolve DB path from CLI args |
| L320 | `ensureLocalDataDir(dirPath)` | Create local data dir with seeds |
| L349 | `warnIfSystemPath(dirPath, label)` | Warn if path is system-critical |
| L363 | `getInstallPaths(db, libDirOvr, metDirOvr)` | Resolve install paths |
| L406 | `extractRequiredDependencies(libFiles, libBasePath)` | Extract HSL dependencies |

## Core Package Operations

| Line | Function | Purpose |
|------|----------|---------|
| L456 | `autoAddToGroup(db, savedLibId, authorName)` | Add lib to nav tree group |
| L539 | `installPackage(manifest, zip, libDestDir, demoDestDir, ...)` | Core installer (7 params) |
| L671 | `ensureOutDir(filePath)` | Create parent directories |
| L687 | `getPackageStoreDir(args)` | Resolve package store directory |
| L700 | `buildCachedPackageName(libName, version)` | Build versioned package filename |
| L724 | `cachePackage(pkgBuffer, libName, version, args)` | Cache package for rollback |
| L743 | `listCachedVersions(libName, args)` | List cached package versions |
| L796 | `findLibrary(db, args)` | Find lib by _id or name |

## Command Handlers

| Line | Function | CLI Command | Purpose |
|------|----------|-------------|---------|
| L809 | `cmdListLibs(args)` | `list-libs` | List installed libraries |
| L862 | `cmdImportLib(args)` | `import-lib` | Import single .hxlibpkg |
| L1025 | `cmdImportArchive(args)` | `import-archive` | Import .hxlibarch archive |
| L1162 | `cmdExportLib(args)` | `export-lib` | Export library as .hxlibpkg |
| L1255 | `cmdExportArchive(args)` | `export-archive` | Export libraries as .hxlibarch |
| L1405 | `cmdDeleteLib(args)` | `delete-lib` | Delete installed library |
| L1581 | `cmdCreatePackage(args)` | `create-package` | Create .hxlibpkg from spec |
| L1799 | `cmdGenerateSyslibHashes(args)` | `generate-syslib-hashes` | Generate system lib baseline |
| L1914 | `cmdVerifySyslibHashes(args)` | `verify-syslib-hashes` | Verify system lib integrity |
| L2064 | `cmdListVersions(args)` | `list-versions` | List cached package versions |
| L2100 | `cmdRollbackLib(args)` | `rollback-lib` | Rollback to cached version |
| L2226 | `printHelp()` | `help` | Print usage/help text |
| L2496 | `cmdVerifyPackage(args)` | `verify-package` | Verify package signatures |
| L2662 | `cmdGenerateKeypair(args)` | `generate-keypair` | Generate Ed25519 keypair |
| L2728 | `cmdListPublishers(args)` | `list-publishers` | List publisher certificates |

## Signing Helpers

| Line | Function | Purpose |
|------|----------|---------|
| L2605 | `resolvePublisherRegistryPath()` | Get publisher registry file path |
| L2615 | `loadSigningCredentials(keyPath, certPath)` | Load key + cert from disk |
| L2641 | `resolveSigningArgs(args)` | Resolve signing CLI args |

## Main Dispatcher

| Line | Purpose |
|------|---------|
| L2774 | `die(msg)` — exit with error |
| L2781 | Main dispatcher switch on `process.argv[2]` |

## Known Issues — None Remaining

All previously identified issues in cli.js have been resolved.
