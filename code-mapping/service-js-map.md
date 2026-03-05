# Code Map: lib/service.js

**File**: `lib/service.js` | **Lines**: 1543 | **Purpose**: Service layer used by REST API

## Imports

| Line | Module | Alias |
|------|--------|-------|
| L28  | `fs` | `fs` |
| L29  | `path` | `path` |
| L30  | `os` | `os` |
| L31  | `crypto` | `crypto` |
| L32  | `adm-zip` | `AdmZip` |
| L33  | `./shared` | `shared` |
| L68  | `child_process` (lazy) | `execSync` |
| L121 | `diskdb` (lazy) | `diskdb` |

## Constants

| Line | Name | Value |
|------|------|-------|
| L38  | `DEFAULT_LIB_PATH` | `C:\Program Files (x86)\HAMILTON\Library` |
| L39  | `DEFAULT_MET_PATH` | `C:\Program Files (x86)\HAMILTON\Methods` |
| L40  | `LOCAL_DATA_DIR` | `path.join(__dirname, '..', 'local')` |
| L41  | `PACKAGE_STORE_DIR` | `path.join(LOCAL_DATA_DIR, 'packages')` |
| L42  | `MIME_MAP` | `shared.IMAGE_MIME_MAP` |
| L43  | `HSL_METADATA_EXTS` | `shared.HSL_METADATA_EXTS` |
| L45  | `DEFAULT_GROUPS` | `{gAll, gRecent, gFolders, gEditors, gHistory, gOEM}` |

## Internal Functions

| Line | Function | Parameters | Purpose |
|------|----------|------------|---------|
| L58  | `getVENUSVersion()` | — | Detect VENUS version from registry (cached) |
| L87  | `loadSystemLibIds()` | — | Load system library ID set from db/system_libraries.json |
| L100 | `loadSystemLibNames()` | — | Load system library name set |
| L104 | `isSystemLibrary(libId)` | `libId` | Check if ID is a system library |
| L105 | `isSystemLibraryByName(libName)` | `libName` | Check if name is a system library |
| L110 | `ensureLocalDataDir(dirPath)` | `dirPath` | Create data dir + seed files |
| L120 | `connectDB(dbDir)` | `dbDir` | Connect diskdb to 5 collections |
| L125 | `resolveDBPath(dbPathOverride)` | `dbPathOverride` | Resolve + ensure DB path |
| L131 | `resolvePublisherRegistryPath()` | — | Return publisher_registry.json path |
| L138 | `getWindowsUsername()` | — | Get current OS username |
| L148 | `buildAuditTrailEntry(eventType, details)` | `eventType, details` | Build audit entry with environment fields |
| L161 | `appendAuditTrailEntry(userDataDir, entry)` | `userDataDir, entry` | Append and rotate audit trail |
| L181 | `getInstallPaths(db, libDirOvr, metDirOvr)` | `db, libDirOverride, metDirOverride` | Resolve install base paths |
| L199 | `getGroupById(db, id)` | `db, id` | Look up group by ID |
| L204 | `autoAddToGroup(db, savedLibId, authorName)` | `db, savedLibId, authorName` | Add lib to navigation group |
| L260 | `extractRequiredDependencies(libFiles, libBasePath)` | `libFiles, libBasePath` | Parse HSL #include dependencies |
| L295 | `installPackage(manifest, zip, libDestDir, demoDestDir, ...)` | 8 params | Core installer: extract, hash, DB save, group |
| L401 | `getPackageStoreDir(storeDirOverride)` | `storeDirOverride` | Resolve package cache dir |
| L405 | `buildCachedPackageName(libName, version)` | `libName, version` | Build cache filename |
| L418 | `cachePackage(pkgBuffer, libName, version, storeDirOvr)` | 4 params | Write package to cache |
| L428 | `listCachedVersions(libName, storeDirOverride)` | `libName, storeDirOverride` | List cached package versions |
| L448 | `findLibrary(db, nameOrId)` | `db, nameOrId` | Find lib by _id or library_name |
| L454 | `ensureOutDir(filePath)` | `filePath` | Create parent dirs for output |
| L462 | `loadSigningCredentials(keyPath, certPath)` | `keyPath, certPath` | Load Ed25519 key + cert |
| L474 | `resolveSigningCredentials(signKeyPath, signCertPath)` | `signKeyPath, signCertPath` | Resolve signing creds from paths |

## Public Service API (module.exports)

| # | Function | Line | Parameters | Purpose |
|---|----------|------|------------|---------|
| — | `createContext` | L504 | `opts?{dbPath,storeDir,libDir,metDir}` | Create service context (DB + paths) |
| 1 | `listLibraries` | L529 | `ctx, opts?{includeDeleted}` | List all installed libraries |
| 2 | `getLibrary` | L543 | `ctx, nameOrId` | Get single library by name/ID |
| 3 | `importLibrary` | L556 | `ctx, opts{filePath,force,noGroup,noCache,...}` | Import .hxlibpkg |
| 4 | `importArchive` | L662 | `ctx, opts{filePath,force,noGroup,noCache,...}` | Import .hxlibarch |
| 5 | `exportLibrary` | L764 | `ctx, opts{name/id,output,signKey,signCert}` | Export as .hxlibpkg |
| 6 | `exportArchive` | L852 | `ctx, opts{output,all,names,ids,...}` | Export as .hxlibarch |
| 7 | `deleteLibrary` | L953 | `ctx, opts{name/id,hard,keepFiles}` | Delete library |
| 8 | `createPackage` | L1017 | `ctx, opts{specPath,output,...}` | Create .hxlibpkg from spec |
| 9 | `listVersions` | L1178 | `ctx, opts{name}` | List cached versions |
| 10 | `rollbackLibrary` | L1186 | `ctx, opts{name,version,index,...}` | Rollback to cached version |
| 11 | `verifyPackage` | L1253 | `ctx, opts{filePath}` | Verify package signatures |
| 12 | `generateSyslibHashes` | L1310 | `ctx, opts{sourceDir,output}` | Generate system lib baseline |
| 13 | `verifySyslibHashes` | L1368 | `ctx, opts{hashFile,libDir}` | Verify system lib integrity |
| 14 | `generateKeypair` | L1399 | `ctx, opts{publisher,org,outputDir,...}` | Generate Ed25519 keypair |
| 15 | `trustPublisher` | L1439 | `ctx, opts{certPath,revoke}` | Trust/revoke publisher cert |
| 16 | `listPublishers` | L1462 | `ctx` | List publisher certs |
| 17 | `getAuditTrail` | L1477 | `ctx, opts{limit}` | Read audit trail |
| 18 | `getSettings` | L1491 | `ctx` | Get app settings |
| 19 | `getSystemLibraries` | L1500 | — | Read system_libraries.json |

## Call Graph

```
createContext ──► resolveDBPath ──► ensureLocalDataDir
             ──► connectDB
             ──► getInstallPaths

importLibrary ──► shared.unpackContainer
              ──► shared.verifyPackageSignature (with trusted certs)
              ──► shared.isRestrictedAuthor / validateAuthorPassword
              ──► shared.validateOemCertificateMatch
              ──► installPackage ──► computeLibraryHashes
              │                  ──► extractPublicFunctions
              │                  ──► extractRequiredDependencies
              │                  ──► autoAddToGroup
              ──► appendAuditTrailEntry
              ──► cachePackage

exportLibrary ──► findLibrary
              ──► resolveSigningCredentials
              ──► shared.signPackageZipWithCert / signPackageZip
              ──► shared.packContainer

deleteLibrary ──► findLibrary
              ──► appendAuditTrailEntry

rollbackLibrary ──► listCachedVersions
                ──► installPackage
                ──► appendAuditTrailEntry
```
