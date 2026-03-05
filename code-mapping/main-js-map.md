# Code Map: html/js/main.js

**File**: `html/js/main.js` | **Lines**: 13,523 | **Purpose**: NW.js GUI application logic

## Imports

| Line | Module | Purpose |
|------|--------|---------|
| L4   | `nw.gui` | NW.js GUI API |
| L6   | `path` | Node.js path utilities |
| L7   | `child_process.spawn` | Process spawning |
| L37  | `fs` | Filesystem |
| L39  | `os` | OS info |
| L40  | `crypto` | Hashing |
| L41  | `../lib/shared` | Shared utilities |
| L755 | `diskdb` | JSON database |
| L5676| `adm-zip` | ZIP handling |
| L5677| `child_process.execSync` | Synchronous command execution |

## Global State Variables

| Line | Name | Purpose |
|------|------|---------|
| L108 | `_cachedGroups` | Windows security group cache |
| L380 | `_isImporting` | Import concurrency guard |
| L388 | `_cachedVENUSVersion` | Cached VENUS version |
| L484 | `_evtHistoryEntries` | Loaded audit trail events |
| L800 | `APP_ROOT` | Application root directory |
| L813 | `LOCAL_DATA_DIR` | Data storage directory |
| L854 | `db_*` | DiskDB collection handles (6 collections) |
| L997 | `_publisherRegistryPath` | Publisher registry file path |
| L1225| `systemLibraries` | System library definitions |
| L1805| `bool_treeChanged` | Navigation tree dirty flag |
| L2330| `_searchTimeout` | Search debounce timer |
| L5678| `pkg_*` | Package creator form state (7 vars) |
| L7148| `imp_*` | Importer state (3 vars) |
| L7667| `_integrityCache`, `_depCache` | Verification caches |
| L11422| `AUDIT_SIGNING_KEY` | Audit log HMAC key |
| L12308| `ulib_*` | Unsigned library modal state (7 vars) |

## Function Sections

### Error Handling & Security (L13–256)
| Line | Function | Purpose |
|------|----------|---------|
| L13  | `window.onerror` | Global error handler |
| L58  | `getWindowsUsername()` | Get Windows username |
| L88  | `isWindowsAdmin()` | Check admin status |
| L110 | `getWindowsGroups()` | Get user's Windows groups |
| L151 | `isInAnyGroup(targets)` | Group membership check |
| L177 | `canManageLibraries()` | Access control gate |
| L243 | `showAccessDeniedModal(action, reason)` | Show access denied dialog |

### VENUS Integration (L258–378)
| Line | Function | Purpose |
|------|----------|---------|
| L258 | `getVENUSInstallInfo()` | Query registry for VENUS install |
| L328 | `ensureSystemLibraryMetadata()` | First-run system lib metadata |

### Audit Trail (L384–735)
| Line | Function | Purpose |
|------|----------|---------|
| L384 | `appendAuditTrailEntry(entry)` | Write audit entry |
| L423 | `buildAuditTrailEntry(type, details)` | Build audit entry |
| L486 | `loadAuditTrail()` | Read audit trail |
| L521 | `buildEventDetailHtml(entry)` | Render event detail HTML |
| L544 | `renderEventRow(entry)` | Render event row |
| L592 | `filterEventHistory()` | Filter events by search/category |
| L626 | `openEventHistoryModal()` | Open event history dialog |
| L685 | `exportEventHistoryCsv()` | Export events to CSV |

### Data Layer & Migration (L766–1190)
| Line | Function | Purpose |
|------|----------|---------|
| L766 | `getGroupById(id)` | Look up group by ID |
| L816 | `ensureLocalDataDir(dirPath)` | Create/seed data directory |
| L858 | `migrateToLocalDir()` | Legacy data migration (IIFE) |
| L999 | `loadPublisherRegistry()` | Load publisher/tag registry |
| L1027| `registerPublisher(name)` | Register a publisher name |
| L1047| `registerTags(tags)` | Register tag names |
| L1103| `rebuildPublisherRegistry()` | Full registry rebuild |
| L1148| `migrateDefaultGroups()` | Remove defaults from DB (IIFE) |

### System Libraries (L1225–1700)
| Line | Function | Purpose |
|------|----------|---------|
| L1291| `buildOemVerifiedBadge(author, large, cert)` | OEM badge HTML |
| L1350| `addToOemTreeGroup(libId)` | Add lib to OEM group |
| L1387| `promptAuthorPassword()` | Password prompt (Promise) |
| L1427| `isSystemLibrary(libId)` | Check system lib |
| L1454| `getPackageStoreDir()` | Get package cache dir |
| L1484| `cachePackageToStore(buf, name, ver)` | Cache package |
| L1501| `listCachedVersions(libName)` | List cached versions |
| L1554| `backupSystemLibrary(sLib)` | Backup single system lib |
| L1663| `backupAllSystemLibraries()` | Backup all system libs |
| L1711| `repairSystemLibraryFromCache(name, silent)` | Repair from cache |

### Window & Layout (L1838–4260)
| Line | Function | Purpose |
|------|----------|---------|
| L1838| `_windowLoadInit()` | Window initialization (IIFE) |
| L4236| `waitForFinalEvent` | Debounce utility |
| L4249| `fitMainDivHeight()` | Adjust content height |
| L4260| `fitNavBarItems()` | Responsive navbar |

### Search System (L2336–3500)
| Line | Function | Purpose |
|------|----------|---------|
| L2350| `_buildSysLibFnCache()` | Build function name cache |
| L2378| `renderSearchInlineTokens()` | Render search chips |
| L2469| `insertSearchTagToken(tag, opts)` | Insert #tag token |
| L2482| `insertSearchAuthorToken(author, opts)` | Insert @author token |
| L2672| `getSearchStateFromInput()` | Parse search state |
| L2781| `refreshLibrarySearchFromInput()` | Refresh search results |
| L2819| `updateSearchAutocomplete()` | Update autocomplete |
| L3344| `impEnterSearchMode(query, opts)` | Enter search mode |
| L3480| `impExitSearchMode()` | Exit search mode |

### Library Cards (L3501–3620, L7675–8100)
| Line | Function | Purpose |
|------|----------|---------|
| L3501| `impBuildSingleCardHtml(lib)` | Build single card HTML |
| L7675| `impBuildLibraryCards(groupId, ...)` | Build all cards from DB |
| L7926| `resolveSystemLibIcon(sLib, size)` | Resolve system lib icon |
| L8057| `buildSystemLibraryCard(sLib)` | Build system lib card |

### Navigation & Groups (L4334–4920)
| Line | Function | Purpose |
|------|----------|---------|
| L4340| `createGroups()` | Build navbar tabs |
| L4681| `updateSortableDivs()` | Init jQuery UI sortable |
| L4702| `saveTree()` | Save nav tree |
| L4842| `groupNew()` | Create new group |
| L4845| `groupEdit(id)` | Edit group |
| L4848| `groupDelete(id)` | Delete group |
| L4920| `saveModalData()` | Save modal form data |

### Settings & Utilities (L5231–5684)
| Line | Function | Purpose |
|------|----------|---------|
| L5297| `loadSettings()` | Load + apply all settings |
| L5443| `saveSetting(key, val)` | Save single setting |
| L5461| `getStarredLibIds()` | Get starred library IDs |
| L5471| `toggleStarLib(libId)` | Toggle star status |
| L5521| `historyCleanup()` | Clean up VENUS log files |
| L5627| `initVENUSData()` | Initialize VENUS paths |

### Packager (L5688–6650)
| Line | Function | Purpose |
|------|----------|---------|
| L6028| `pkgDetectLibraryName()` | Auto-detect library name |
| L6057| `pkgAutoDetectBmpImage()` | Auto-detect BMP icon |
| L6152| `pkgUpdateLibFileList()` | Render lib file list |
| L6377| `pkgCompositeLibraryIcon(b64, mime)` | Composite icon overlay |
| L6441| `pkgCreatePackageFile(savePath)` | Core packaging function |

### COM Registration (L6650–6900)
| Line | Function | Purpose |
|------|----------|---------|
| L6660| `findRegAsmPath()` | Find 32-bit RegAsm.exe |
| L6699| `comRegisterDll(dllPath, register)` | Register/unregister DLL |
| L6780| `comRegisterMultipleDlls(paths, reg)` | Register multiple DLLs |
| L6800| `checkCOMRegistrationStatus(path)` | Check COM status |

### Code Signing (L7400–7660)
| Line | Function | Purpose |
|------|----------|---------|
| L7401| `getSigningConfig()` | Read key/cert from settings |
| L7416| `loadDefaultSigningCredentials()` | Load signing credentials |
| L7462| `refreshSigningUI()` | Update signing UI |
| L7502| `applyPackageSigning(zip, useCert)` | Sign ZIP package |

### Integrity (L7327–7670)
| Line | Function | Purpose |
|------|----------|---------|
| L7335| `verifySystemLibraryIntegrity(sLib)` | Verify system lib |
| L7637| `verifyLibraryIntegrity(lib)` | Verify installed lib hashes |
| L7669| `invalidateLibCaches()` | Clear caches |

### Detail Modals (L8120–8800)
| Line | Function | Purpose |
|------|----------|---------|
| L8126| `impShowLibDetail(libId)` | Library detail modal |
| L8801| `impShowSystemLibDetail(libId)` | System lib detail modal |

### Export (L9143–9800)
| Line | Function | Purpose |
|------|----------|---------|
| L9240| `exportSingleLibrary(id, path, sign)` | Export single .hxlibpkg |
| L9360| `resolveAllDependencyLibIds(rootId)` | Resolve dependency tree |
| L9415| `exportLibraryWithDependencies(id, path, sign)` | Export with deps |
| L9600| `expArchPopulateModal()` | Populate archive export modal |
| L9777| `expArchCreateArchive(ids, path, sign)` | Create .hxlibarch |

### Archive Import (L9950–10200)
| Line | Function | Purpose |
|------|----------|---------|
| L9955| `impArchImportArchive(archivePath)` | Import .hxlibarch |

### Delete & Rollback (L10370–10700)
| Line | Function | Purpose |
|------|----------|---------|
| L10371| `showDeleteConfirmModal(name, dlls)` | Delete confirmation |
| L10446| `showRegulatedModeConfirmModal(enabling)` | Regulated mode confirm |

### Import (L10700–11200)
| Line | Function | Purpose |
|------|----------|---------|
| L10707| `impLoadAndInstall(filePath)` | Load + preview .hxlibpkg |

### Audit Log (L11422–11730)
| Line | Function | Purpose |
|------|----------|---------|
| L11460| `generateLibraryAuditLog(savePath)` | Generate full audit log |
| L11683| `verifyAuditLogIntegrity(filePath)` | Verify audit HMAC |

### Verify & Repair (L11740–12100)
| Line | Function | Purpose |
|------|----------|---------|
| L11795| `repairPopulateModal()` | Populate repair modal |
| L12059| `repairLibraryFromCache(name, silent)` | Repair from cache |
| L12199| `showGenericSuccessModal(opts)` | Success result modal |

### Unsigned Libraries (L12300–13500)
| Line | Function | Purpose |
|------|----------|---------|
| L12405| `scanUnsignedLibraries(showFeedback)` | Scan for unsigned libs |
| L12596| `buildUnsignedLibraryCard(uLib)` | Build unsigned lib card |
| L12658| `showUnsignedLibDetail(ulibId)` | Unsigned lib detail modal |
| L13246| `registerUnsignedLibrary(ulibId, opts)` | Register unsigned lib |
| L13402| `exportUnsignedLibrary(ulibId, path)` | Export unsigned lib |

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
