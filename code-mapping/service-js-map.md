# Code Map: lib/service.js

**File**: `lib/service.js` | **Lines**: 1732 | **Purpose**: Service layer used by COM bridge

## Imports

| Line | Module | Alias |
|------|--------|-------|
| L26  | `fs` | `fs` |
| L27  | `path` | `path` |
| L28  | `os` | `os` |
| L29  | `adm-zip` | `AdmZip` |
| L30  | `./shared` | `shared` |

## Constants

| Line | Name | Value |
|------|------|-------|
| L35  | `DEFAULT_LIB_PATH` | `C:\Program Files (x86)\HAMILTON\Library` |
| L36  | `DEFAULT_MET_PATH` | `C:\Program Files (x86)\HAMILTON\Methods` |
| L37  | `LOCAL_DATA_DIR` | `path.join(__dirname, '..', 'local')` |
| L38  | `PACKAGE_STORE_DIR` | `path.join(LOCAL_DATA_DIR, 'packages')` |
| L39  | `MIME_MAP` | `shared.IMAGE_MIME_MAP` |
| L40  | `HSL_METADATA_EXTS` | `shared.HSL_METADATA_EXTS` |
| L42  | `DEFAULT_GROUPS` | `{gAll, gRecent, gStarred, gFolders, gEditors, gHistory, gOEM}` |

## Internal Functions

| Line | Function | Parameters | Purpose |
|------|----------|------------|---------|
| L60  | `getVENUSVersion()` | — | Detect VENUS version from registry (cached, `execFileSync`) |
| L98  | `loadSystemLibIds()` | — | Load system library ID set from db/system_libraries.json |
| L116 | `loadSystemLibNames()` | — | Load system library name set |
| L122 | `isSystemLibrary(libId)` | `libId` | Check if ID is a system library |
| L124 | `isSystemLibraryByName(libName)` | `libName` | Check if name is a system library |
| L133 | `ensureLocalDataDir(dirPath)` | `dirPath` | Create data dir + seed files |
| L157 | `connectDB(dbDir)` | `dbDir` | Connect diskdb to 5 collections |
| L167 | `resolveDBPath(dbPathOverride)` | `dbPathOverride` | Resolve + ensure DB path |
| L177 | `resolvePublisherRegistryPath()` | — | Return publisher_registry.json path |
| L188 | `getWindowsUsername()` | — | Get current OS username |
| L205 | `buildAuditTrailEntry(eventType, details)` | `eventType, details` | Build audit entry with environment fields |
| L222 | `appendAuditTrailEntry(userDataDir, entry)` | `userDataDir, entry` | Append and rotate audit trail |
| L251 | `getInstallPaths(db, libDirOvr, metDirOvr)` | `db, libDirOverride, metDirOverride` | Resolve install base paths |
| L276 | `getGroupById(db, id)` | `db, id` | Look up group by ID |
| L287 | `autoAddToGroup(db, savedLibId, authorName)` | `db, savedLibId, authorName` | Add lib to navigation group |
| L333 | `extractRequiredDependencies(libFiles, libBasePath)` | `libFiles, libBasePath` | Parse HSL #include dependencies |
| L382 | `installPackage(manifest, zip, libDestDir, demoDestDir, ...)` | 8 params | Core installer: extract, hash, DB save, group |
| L491 | `getPackageStoreDir(storeDirOverride)` | `storeDirOverride` | Resolve package cache dir |
| L501 | `buildCachedPackageName(libName, version)` | `libName, version` | Build cache filename |
| L515 | `cachePackage(pkgBuffer, libName, version, storeDirOvr)` | 4 params | Write package to cache |
| L526 | `listCachedVersions(libName, storeDirOverride)` | `libName, storeDirOverride` | List cached package versions |
| L555 | `findLibrary(db, nameOrId)` | `db, nameOrId` | Find lib by _id or library_name |
| L566 | `ensureOutDir(filePath)` | `filePath` | Create parent dirs for output |
| L574 | `loadSigningCredentials(keyPath, certPath)` | `keyPath, certPath` | Load Ed25519 key + cert |
| L586 | `resolveSigningCredentials(signKeyPath, signCertPath)` | `signKeyPath, signCertPath` | Resolve signing creds from paths |

## Public Service API (module.exports)

| # | Function | Line | Parameters | Purpose |
|---|----------|------|------------|---------|
| — | `createContext` | L611 | `opts?{dbPath,storeDir,libDir,metDir}` | Create service context (DB + paths) |
| 1 | `listLibraries` | L635 | `ctx, opts?{includeDeleted}` | List all installed libraries |
| 2 | `getLibrary` | L651 | `ctx, nameOrId` | Get single library by name/ID |
| 3 | `importLibrary` | L671 | `ctx, opts{filePath,force,noGroup,noCache,...}` | Import .hxlibpkg |
| 4 | `importArchive` | L790 | `ctx, opts{filePath,force,noGroup,noCache,...}` | Import .hxlibarch |
| 5 | `exportLibrary` | L884 | `ctx, opts{name/id,output,signKey,signCert}` | Export as .hxlibpkg |
| 6 | `exportArchive` | L981 | `ctx, opts{output,all,names,ids,...}` | Export as .hxlibarch |
| 7 | `deleteLibrary` | L1094 | `ctx, opts{name/id,hard,keepFiles}` | Delete library |
| 8 | `createPackage` | L1168 | `ctx, opts{specPath,output,...}` | Create .hxlibpkg from spec |
| 9 | `listVersions` | L1322 | `ctx, opts{name}` | List cached versions |
| 10 | `rollbackLibrary` | L1343 | `ctx, opts{name,version,index,...}` | Rollback to cached version |
| 11 | `verifyPackage` | L1428 | `ctx, opts{filePath}` | Verify package signatures |
| 12 | `generateSyslibHashes` | L1491 | `ctx, opts{sourceDir,output}` | Generate system lib baseline |
| 13 | `verifySyslibHashes` | L1552 | `ctx, opts{hashFile,libDir}` | Verify system lib integrity |
| 14 | `generateKeypair` | L1601 | `ctx, opts{publisher,org,outputDir,...}` | Generate Ed25519 keypair |
| 15 | `listPublishers` | L1641 | `ctx` | List publisher certs |
| 16 | `getAuditTrail` | L1663 | `ctx, opts{limit}` | Read audit trail |
| 17 | `getSettings` | L1683 | `ctx` | Get app settings |
| 18 | `getSystemLibraries` | L1697 | — | Read system_libraries.json |

## Call Graph

```
createContext ──► resolveDBPath ──► ensureLocalDataDir
             ──► connectDB
             ──► getInstallPaths

importLibrary ──► shared.unpackContainer
              ──► shared.verifyPackageSignature
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
              ──► shared.signPackageZipWithCert
              ──► shared.packContainer

deleteLibrary ──► findLibrary
              ──► appendAuditTrailEntry

rollbackLibrary ──► listCachedVersions
                ──► installPackage
                ──► appendAuditTrailEntry
```
