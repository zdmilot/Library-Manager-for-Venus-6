# Code Map: html/js/main.js

**File**: `html/js/main.js` | **Lines**: 13,469 | **Purpose**: NW.js GUI application logic

## Imports

| Line | Module | Purpose |
|------|--------|---------|
| L5   | `nw.gui` | NW.js GUI API |
| L7   | `path` | Node.js path utilities |
| L8   | `child_process.spawn` | Process spawning |
| L111 | `fs` | Filesystem |
| L113 | `os` | OS info |
| L114 | `crypto` | Hashing |
| L115 | `../lib/shared` | Shared utilities |
| L824 | `diskdb` | JSON database |
| L5727| `adm-zip` | ZIP handling |
| L5728| `child_process.execSync` | Synchronous command execution |

## Global State Variables

| Line | Name | Purpose |
|------|------|---------|
| L176 | `_cachedGroups` | Windows security group cache |
| L441 | `_isImporting` | Import concurrency guard |
| L448 | `_cachedVENUSVersion` | Cached VENUS version |
| L555 | `_evtHistoryEntries` | Loaded audit trail events |
| L869 | `APP_ROOT` | Application root directory |
| L887 | `LOCAL_DATA_DIR` | Data storage directory |
| L923 | `db_settings` | DiskDB settings handle |
| L1057| `db_links` | DiskDB links handle |
| L1058| `db_groups` | DiskDB groups handle |
| L1059| `db_tree` | DiskDB tree handle |
| L1060| `db_installed_libs` | DiskDB installed libs handle |
| L1061| `db_unsigned_libs` | DiskDB unsigned libs handle |
| L1070| `_publisherRegistryPath` | Publisher registry file path |
| L1290| `systemLibraries` | System library definitions |
| L1866| `bool_treeChanged` | Navigation tree dirty flag |
| L2399| `_searchTimeout` | Search debounce timer |
| L5729| `pkg_*` | Package creator form state (7+ vars) |
| L6985| `imp_*` | Importer state (3 vars) |
| L7643| `_integrityCache`, `_depCache` | Verification caches |
| L11335| `AUDIT_SIGNING_KEY` | Audit log HMAC key |
| L12215| `ulib_*` | Unsigned library modal state (6+ vars) |

## Function Sections

### Error Handling & Security (L1–330)
| Line | Function | Purpose |
|------|----------|---------|
| L13  | `window.onerror` | Global error handler |
| L133 | `getWindowsUsername()` | Get Windows username |
| L163 | `isWindowsAdmin()` | Check admin status |
| L185 | `getWindowsGroups()` | Get user's Windows groups |
| L222 | `isInAnyGroup(targets)` | Group membership check |
| L252 | `canManageLibraries()` | Access control gate |
| L318 | `showAccessDeniedModal(action, reason)` | Show access denied dialog |

### VENUS Integration (L333–455)
| Line | Function | Purpose |
|------|----------|---------|
| L333 | `getVENUSInstallInfo()` | Query registry for VENUS install |
| L403 | `ensureSystemLibraryMetadata()` | First-run system lib metadata |

### Audit Trail (L459–815)
| Line | Function | Purpose |
|------|----------|---------|
| L459 | `appendAuditTrailEntry(entry)` | Write audit entry |
| L498 | `buildAuditTrailEntry(type, details)` | Build audit entry |
| L561 | `loadAuditTrail()` | Read audit trail |
| L596 | `buildEventDetailHtml(entry)` | Render event detail HTML |
| L619 | `renderEventRow(entry)` | Render event row |
| L667 | `filterEventHistory()` | Filter events by search/category |
| L701 | `openEventHistoryModal()` | Open event history dialog |
| L760 | `exportEventHistoryCsv()` | Export events to CSV |

### Data Layer & Migration (L824–1290)
| Line | Function | Purpose |
|------|----------|---------|
| L841 | `getGroupById(id)` | Look up group by ID |
| L890 | `ensureLocalDataDir(dirPath)` | Create/seed data directory |
| L932 | `migrateToLocalDir()` | Legacy data migration (IIFE) |
| L1073| `loadPublisherRegistry()` | Load publisher/tag registry |
| L1101| `registerPublisher(name)` | Register a publisher name |
| L1121| `registerTags(tags)` | Register tag names |
| L1169| `rebuildPublisherRegistry()` | Full registry rebuild |
| L1214| `migrateDefaultGroups()` | Remove defaults from DB (IIFE) |

### System Libraries (L1290–1866)
| Line | Function | Purpose |
|------|----------|---------|
| L1356| `buildOemVerifiedBadge(author, large, cert)` | OEM badge HTML |
| L1416| `addToOemTreeGroup(libId)` | Add lib to OEM group |
| L1453| `promptAuthorPassword()` | Password prompt (Promise) |
| L1493| `isSystemLibrary(libId)` | Check system lib |
| L1520| `getPackageStoreDir()` | Get package cache dir |
| L1550| `cachePackageToStore(buf, name, ver)` | Cache package |
| L1567| `listCachedVersions(libName)` | List cached versions |
| L1620| `backupSystemLibrary(sLib)` | Backup single system lib |
| L1726| `backupAllSystemLibraries()` | Backup all system libs |
| L1774| `repairSystemLibraryFromCache(name, silent)` | Repair from cache |

### Window & Layout (L1904–4290)
| Line | Function | Purpose |
|------|----------|---------|
| L1904| `_windowLoadInit()` | Window initialization (IIFE) |
| L4249| `waitForFinalEvent` | Debounce utility |
| L4265| `fitMainDivHeight()` | Adjust content height |
| L4279| `fitNavBarItems()` | Responsive navbar |

### Search System (L2399–3570)
| Line | Function | Purpose |
|------|----------|---------|
| L2419| `_buildSysLibFnCache()` | Build function name cache |
| L2447| `renderSearchInlineTokens()` | Render search chips |
| L2538| `insertSearchTagToken(tag, opts)` | Insert #tag token |
| L2551| `insertSearchAuthorToken(author, opts)` | Insert @author token |
| L2741| `getSearchStateFromInput()` | Parse search state |
| L2850| `refreshLibrarySearchFromInput()` | Refresh search results |
| L2888| `updateSearchAutocomplete()` | Update autocomplete |
| L3413| `impEnterSearchMode(query, opts)` | Enter search mode |
| L3549| `impExitSearchMode()` | Exit search mode |

### Library Cards (L3572–3700, L7643–8090)
| Line | Function | Purpose |
|------|----------|---------|
| L3572| `impBuildSingleCardHtml(lib)` | Build single card HTML |
| L7643| `impBuildLibraryCards(groupId, ...)` | Build all cards from DB |
| L7933| `resolveSystemLibIcon(sLib, size)` | Resolve system lib icon |
| L8025| `buildSystemLibraryCard(sLib)` | Build system lib card |

### Navigation & Groups (L4348–5000)
| Line | Function | Purpose |
|------|----------|---------|
| L4348| `createGroups()` | Build navbar tabs |
| L4735| `updateSortableDivs()` | Init jQuery UI sortable |
| L4758| `saveTree()` | Save nav tree |
| L4912| `groupNew()` | Create new group |
| L4915| `groupEdit(id)` | Edit group |
| L4918| `groupDelete(id)` | Delete group |
| L4993| `saveModalData()` | Save modal form data |

### Settings & Utilities (L5364–5727)
| Line | Function | Purpose |
|------|----------|---------|
| L5364| `loadSettings()` | Load + apply all settings |
| L5495| `saveSetting(key, val)` | Save single setting |
| L5515| `getStarredLibIds()` | Get starred library IDs |
| L5523| `toggleStarLib(libId)` | Toggle star status |
| L5572| `historyCleanup()` | Clean up VENUS log files |
| L5674| `initVENUSData()` | Initialize VENUS paths |

### Packager (L5727–6740)
| Line | Function | Purpose |
|------|----------|---------|
| L6099| `pkgDetectLibraryName()` | Auto-detect library name |
| L6127| `pkgAutoDetectBmpImage()` | Auto-detect BMP icon |
| L6220| `pkgUpdateLibFileList()` | Render lib file list |
| L6463| `pkgCompositeLibraryIcon(b64, mime)` | Composite icon overlay |
| L6538| `pkgCreatePackageFile(savePath)` | Core packaging function |

### COM Registration (L6740–6985)
| Line | Function | Purpose |
|------|----------|---------|
| L6740| `findRegAsmPath()` | Find 32-bit RegAsm.exe |
| L6780| `comRegisterDll(dllPath, register)` | Register/unregister DLL |
| L6853| `comRegisterMultipleDlls(paths, reg)` | Register multiple DLLs |
| L6876| `checkCOMRegistrationStatus(path)` | Check COM status |

### Code Signing (L7291–7640)
| Line | Function | Purpose |
|------|----------|---------|
| L7291| `getSigningConfig()` | Read key/cert from settings |
| L7303| `loadDefaultSigningCredentials()` | Load signing credentials |
| L7346| `refreshSigningUI()` | Update signing UI |
| L7389| `applyPackageSigning(zip, useCert)` | Sign ZIP package |

### Integrity (L7224–7645)
| Line | Function | Purpose |
|------|----------|---------|
| L7224| `verifySystemLibraryIntegrity(sLib)` | Verify system lib |
| L7583| `verifyLibraryIntegrity(lib)` | Verify installed lib hashes |
| L7640| `invalidateLibCaches()` | Clear caches |

### Detail Modals (L8090–8770)
| Line | Function | Purpose |
|------|----------|---------|
| L8090| `impShowLibDetail(libId)` | Library detail modal |
| L8768| `impShowSystemLibDetail(libId)` | System lib detail modal |

### Export (L9172–9900)
| Line | Function | Purpose |
|------|----------|---------|
| L9172| `exportSingleLibrary(id, path, sign)` | Export single .hxlibpkg |
| L9309| `resolveAllDependencyLibIds(rootId)` | Resolve dependency tree |
| L9357| `exportLibraryWithDependencies(id, path, sign)` | Export with deps |
| L9566| `expArchPopulateModal()` | Populate archive export modal |
| L9713| `expArchCreateArchive(ids, path, sign)` | Create .hxlibarch |

### Archive Import (L9900–10360)
| Line | Function | Purpose |
|------|----------|---------|
| L9900| `impArchImportArchive(archivePath)` | Import .hxlibarch |

### Delete & Rollback (L10360–10668)
| Line | Function | Purpose |
|------|----------|---------|
| L10360| `showDeleteConfirmModal(name, dlls)` | Delete confirmation |
| L10413| `showRegulatedModeConfirmModal(enabling)` | Regulated mode confirm |

### Import (L10663–11335)
| Line | Function | Purpose |
|------|----------|---------|
| L10663| `impLoadAndInstall(filePath)` | Load + preview .hxlibpkg |

### Audit Log (L11335–11730)
| Line | Function | Purpose |
|------|----------|---------|
| L11369| `generateLibraryAuditLog(savePath)` | Generate full audit log |
| L11648| `verifyAuditLogIntegrity(filePath)` | Verify audit HMAC |

### Verify & Repair (L11731–12169)
| Line | Function | Purpose |
|------|----------|---------|
| L11731| `repairPopulateModal()` | Populate repair modal |
| L12019| `repairLibraryFromCache(name, silent)` | Repair from cache |
| L12169| `showGenericSuccessModal(opts)` | Success result modal |

### Unsigned Libraries (L12215–13469)
| Line | Function | Purpose |
|------|----------|---------|
| L12296| `scanUnsignedLibraries(showFeedback)` | Scan for unsigned libs |
| L12563| `buildUnsignedLibraryCard(uLib)` | Build unsigned lib card |
| L12624| `showUnsignedLibDetail(ulibId)` | Unsigned lib detail modal |
| L13106| `registerUnsignedLibrary(ulibId, opts)` | Register unsigned lib |
| L13282| `exportUnsignedLibrary(ulibId, path)` | Export unsigned lib |

## Event Handler Summary

- **Window**: close, maximize, restore, resize
- **Navigation**: brand-logo click, nav-item click, tab switching
- **Library Actions**: card click, star toggle, export, delete, rollback, repair
- **Search**: input, keydown (Tab/Enter/Esc/Backspace/arrows), autocomplete, chip management
- **Packager**: file inputs, icon picker, create button, reset
- **Settings**: all setting checkboxes, code signing config, folder pickers
- **Menu**: help, about, privacy, terms, groups, settings, export, history, audit, repair
- **Unsigned libs**: card click, file management, register, remove, export

## Patterns

- jQuery delegation: `$(document).on("event", "selector", fn)`
- Bootstrap modals for all dialogs
- DiskDB for JSON persistence
- NW.js APIs for file dialogs, shell operations
- Promise-based async for COM registration, password prompts
- Debounced search with inline token/chip system
