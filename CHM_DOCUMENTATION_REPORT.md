# CHM Documentation Comprehensive Analysis Report

## Table of Contents
1. [Per-File Summary](#1-per-file-summary)
2. [Image Placeholder Inventory](#2-image-placeholder-inventory)
3. [Undocumented Features Found in App Code](#3-undocumented-features-found-in-app-code)
4. [Recommended New Image Placeholders](#4-recommended-new-image-placeholders)
5. [General Observations](#5-general-observations)

---

## 1. Per-File Summary

### 1.1 index.html (CHM Welcome Page)
| | |
|---|---|
| **Title** | Library Manager for Venus 6 Help - Index |
| **Sections** | Welcome, Getting Started (links), Core Concepts (links), Workflows (links), CLI Reference (links), Support (links) |
| **Image Placeholders** | 1 — "PLACE IMAGE OF THE Library Manager for Venus 6 MAIN WINDOW HERE" |
| **Assessment** | **Adequate** — serves as a TOC/landing page; links to all other pages. Does its job. |

### 1.2 Overview.html
| | |
|---|---|
| **Title** | Library Manager for Venus 6 Overview |
| **Sections** | Overview (intro paragraph), Key Capabilities (12 bullet points), System Requirements, Documentation Sections (full TOC with 30+ links) |
| **Image Placeholders** | 1 — "PLACE IMAGE OF Library Manager for Venus 6 MAIN WINDOW HERE" |
| **Assessment** | **Thorough** — Good high-level overview. |

### 1.3 GettingStarted.html
| | |
|---|---|
| **Title** | Getting Started |
| **Sections** | Introduction, Installation, Directory Structure, Launching the Application (GUI + CLI), First-Time Setup (User Data Directory, Package Store), Basic Workflows (Import, Export, Create), Next Steps |
| **Image Placeholders** | 1 — "PLACE IMAGE OF APPLICATION LAUNCH / MAIN WINDOW HERE" |
| **Assessment** | **Thorough** — Well-structured onboarding. |

### 1.4 GUIOverview.html
| | |
|---|---|
| **Title** | GUI Overview |
| **Sections** | Main Window Layout, Navigation Tabs, Library Cards, Search Improvements, Search Mode Behavior, Card Styling States, Library Detail Modal, Actions Available in Detail Modal, Import Workflow (Single Package + Archive), Library Packager, Settings, Tag Editing Rules, VENUS Tool Shortcuts, Help Menu, Verify & Repair Tool, First-Run System Library Backup, Repair from Detail Modal |
| **Image Placeholders** | 7 — Main Window, Navigation Tabs, Library Card, Library Detail Modal, Pre-Install Preview Modal, Library Packager UI, Settings Panel |
| **Assessment** | **Very Thorough** — Most comprehensive GUI documentation. |

### 1.5 SearchFeatures.html
| | |
|---|---|
| **Title** | Search & Filtering |
| **Sections** | Overview, Basic Text Search, Tag Chips (#tag), Author Chips (@author), Inline Text Editing, Autocomplete Suggestions, Publisher Registry, Keyboard Shortcuts Reference (Global, While Typing, While Editing Inline Text, While Editing Chip), Search Token Order, Search Mode Behavior, Combined Filtering Logic, Quick-Start Examples |
| **Image Placeholders** | 2 — "PLACE IMAGE OF SEARCH BAR WITH TAG AND AUTHOR CHIPS HERE", "PLACE IMAGE OF SEARCH AUTOCOMPLETE DROPDOWN WITH SUGGESTIONS HERE" |
| **Assessment** | **Extremely Thorough** — Exceptional detail on search mechanics. |

### 1.6 SplashScreen.html
| | |
|---|---|
| **Title** | Splash Screen & Startup Architecture |
| **Sections** | Overview, What the User Sees, Performance Design (Instant First Paint, Smooth Animation), Startup Sequence (7-phase table), Worker Process Architecture (Input/Output messages), Gating Behavior |
| **Image Placeholders** | 1 — "PLACE IMAGE OF THE SPLASH SCREEN WITH ANIMATED LOGO AND STATUS TEXT HERE" |
| **Assessment** | **Extremely Thorough** — Deep technical architecture. |

### 1.7 PackageFormats.html
| | |
|---|---|
| **Title** | Package Formats |
| **Sections** | Overview, Single Library Package (.hxlibpkg) structure (ZIP, Manifest, Signature), Multi-Library Archive (.hxlibarch) structure (ZIP, Archive Manifest), Supported Image Formats, File Type Reference |
| **Image Placeholders** | 0 |
| **Assessment** | **Very Thorough** — Technical reference, no screenshots needed. |

### 1.8 BinaryContainerFormat.html
| | |
|---|---|
| **Title** | Binary Container Format |
| **Sections** | Overview, Container Layout (48-byte header), Visual Layout, Magic Bytes, XOR Scrambling, HMAC-SHA256 Integrity, Fail-Closed Design, Dual Integrity, Nested Containers in Archives, What Standard Tools See, Error Messages, Technical Implementation, Key Constants, Relationship to Other Formats |
| **Image Placeholders** | 0 |
| **Assessment** | **Extremely Thorough** — Deep technical reference. |

### 1.9 PackageSpecSchema.html
| | |
|---|---|
| **Title** | Package Spec JSON Schema |
| **Sections** | Overview, Required Fields, Optional Fields, Additional Properties, Reserved Tag Keywords, Minimal + Full Examples, Library Name Auto-Detection Priority, Image Handling, MIME types |
| **Image Placeholders** | 0 |
| **Assessment** | **Very Thorough** |

### 1.10 HSLFileArchitecture.html
| | |
|---|---|
| **Title** | HSL File Architecture |
| **Sections** | Overview, HSL File Extensions, The Metadata Footer, Footer Fields, Examples, valid Flag, checksum Field, Files Without Footer, Footer Parsing Regex, Summary Table |
| **Image Placeholders** | 0 |
| **Assessment** | **Thorough** |

### 1.11 DataModel.html
| | |
|---|---|
| **Title** | Data Model |
| **Sections** | Overview, Collections table, installed_libs (Record Fields, file_hashes, public_functions), links Collection, groups Collection, tree Collection, settings Collection, User Data Directory |
| **Image Placeholders** | 1 — "PLACE IMAGE OF THE DB FOLDER STRUCTURE HERE" |
| **Assessment** | **Very Thorough** |

### 1.12 IntegrityVerification.html
| | |
|---|---|
| **Title** | Integrity Verification |
| **Sections** | Overview (4 mechanisms), User-Installed Libraries SHA-256, System Libraries Hamilton Footer, Package Signing HMAC-SHA256, First-Run System Library Backup, Repair, Verify & Repair Tool, Package Store, Relationship Between Mechanisms, End-to-End Integrity Lifecycle, CLI Commands, Practical Recommendations, Troubleshooting |
| **Image Placeholders** | 2 — Library Card Integrity Error Styling, Verify and Repair Modal |
| **Assessment** | **Extremely Thorough** |

### 1.13 VisualIdentity.html
| | |
|---|---|
| **Title** | Visual Identity & Assets |
| **Sections** | Overview, Assets Folder (table), Asset Generation (Archive Icon, Grayscale Logo), Package Icon Compositing (with/without user image), Archive Icon embedding, Font Awesome Icons |
| **Image Placeholders** | 1 — "PLACE IMAGE OF COMPOSITED PACKAGE ICON EXAMPLE SHOWING LOGO OVERLAY HERE" |
| **Assessment** | **Thorough** |

### 1.14 SuccessDialogs.html
| | |
|---|---|
| **Title** | Success Dialogs |
| **Sections** | Overview, Success Events (9-operation table), Implementation (#importSuccessModal, #genericSuccessModal, helper function, #auditSuccessModal), CSS Classes |
| **Image Placeholders** | 1 — "PLACE IMAGE OF A SUCCESS DIALOG EXAMPLE SHOWING GREEN CHECKMARK AND DETAILS HERE" |
| **Assessment** | **Thorough** |

### 1.15 ImportingLibraries.html
| | |
|---|---|
| **Title** | Importing Libraries |
| **Sections** | Overview, Single Package Import GUI Workflow, What Happens During Import (9 steps), Post-Install Summary, Archive Import GUI + Processing, CLI Import, Overwrite Behavior, Audit Comment/Signature, COM DLL Registration, Audit Trail |
| **Image Placeholders** | 2 — Import Preview Modal, Post-Import Success Modal |
| **Assessment** | **Very Thorough** |

### 1.16 ExportingLibraries.html
| | |
|---|---|
| **Title** | Exporting Libraries |
| **Sections** | Overview, Export Choice Modal, Dependency Summary, Disabled State, Single Library Export, What Is Included, Restrictions, Export with All Dependencies, Multi-Library Archive Export, Archive Contents, CLI Export, Mutable Export, Exporting Unsigned Libraries |
| **Image Placeholders** | 4 — Export Choice Modal, Export Button, Export Choice with Dependencies, Archive Export Modal |
| **Assessment** | **Very Thorough** |

### 1.17 CreatingPackages.html
| | |
|---|---|
| **Title** | Creating Packages |
| **Sections** | Overview, GUI Library Packager (8 steps), Package Icon Compositing, Protected Author Name, Packager Reset, CLI create-package, Spec File examples, Validation, Output Structure, Audit Trail |
| **Image Placeholders** | 2 — Library Packager Main View, Packager with Filled Metadata |
| **Assessment** | **Very Thorough** |

### 1.18 GitHubRepository.html
| | |
|---|---|
| **Title** | GitHub Repository Link |
| **Sections** | Overview, Where the Field Appears (Input/Output), Data Flow (4 steps), Validation Rules (Accepted Formats, Rejection Criteria, Reserved Routes), Manifest Schema, Examples (GUI, CLI, Detail Modal, Display Setting) |
| **Image Placeholders** | 0 |
| **Assessment** | **Extremely Thorough** — Comprehensive validation documentation. |

### 1.19 DeletingLibraries.html
| | |
|---|---|
| **Title** | Deleting Libraries |
| **Sections** | Overview, GUI Delete Workflow, Audit Field Validation, What Happens During Deletion (4 areas), Soft Delete vs Hard Delete, CLI Delete, System Library Protection, Recovery, Audit Trail |
| **Image Placeholders** | 1 — Delete Confirmation Dialog |
| **Assessment** | **Thorough** |

### 1.20 VersionRollback.html
| | |
|---|---|
| **Title** | Version Rollback |
| **Sections** | Overview, Package Store (Organization, Automatic Caching), Listing Cached Versions, Rolling Back (What Happens, Audit Field Validation), Use Cases, Audit Trail |
| **Image Placeholders** | 2 — Cached Versions List in Detail Modal, Rollback Confirmation Dialog |
| **Assessment** | **Thorough** |

### 1.21 LibraryGrouping.html
| | |
|---|---|
| **Title** | Library Grouping |
| **Sections** | Overview, Default Groups (Hardcoded), Hamilton Group (Protection, Password, Empty State), Managing Groups (Create, Rename/Delete, Reorder), Assigning Libraries, Group Visibility, Data Persistence, Group Record Structure, Tree Assignment, Unsigned Group |
| **Image Placeholders** | 2 — Group Creation in Settings, Drag-and-Drop Group Assignment |
| **Assessment** | **Thorough** |

### 1.22 VENUSIntegration.html
| | |
|---|---|
| **Title** | VENUS Integration |
| **Sections** | Overview, VENUS Tool Shortcuts (7-tool table), VENUS Directory Shortcuts (6-folder table), Simulation Mode, Path Resolution, User Authentication & Authorization (Security Groups, Authorization Precedence, Regulated Environment Mode, Protected Operations), VENUS Not Installed |
| **Image Placeholders** | 1 — "PLACE IMAGE OF VENUS TOOL SHORTCUTS IN SIDEBAR HERE" |
| **Assessment** | **Very Thorough** — Includes auth & regulated environment mode. |

### 1.23 UnsignedLibraries.html
| | |
|---|---|
| **Title** | Unsigned Libraries |
| **Sections** | Overview, Enabling the Feature, Scanning (Steps, Excluded Files, Visual Feedback), Scan on Launch, The Unsigned Group, Library Cards, Detail & Edit Modal (Editable Fields, Tag Rules, Library Icon, Library Files, COM Registration, Demo Method Files, Actions), Registering Libraries (10-step process), Exporting as a Package (10-step process), Dependency Resolution, Data Model (full record schema), Limitations |
| **Image Placeholders** | 3 — Settings Checkboxes/Scan Button, Unsigned Library Cards, Unsigned Library Detail Modal |
| **Assessment** | **Extremely Thorough** — Most detailed single-feature page. |

### 1.24 LibraryAuditLog.html
| | |
|---|---|
| **Title** | Library Audit Log |
| **Sections** | Overview, Running an Audit, Save Location, Audit Log Contents (Header, Summary, Installed Libraries, System Libraries, Footer), Integrity Signature (How Signing Works), Checking an Audit File, Verification Results, Practical Recommendations, Audit Trail (Events, Entry Fields, Destructive Fields, Storage, Traceability, Visibility) |
| **Image Placeholders** | 2 — Run Library Audit Menu Item, Audit Verification Result Dialog |
| **Assessment** | **Very Thorough** |

### 1.25 Troubleshooting.html
| | |
|---|---|
| **Title** | Troubleshooting |
| **Sections** | 15+ Common Issues with cause/solution pairs, Getting Help |
| **Image Placeholders** | 0 |
| **Assessment** | **Very Thorough** |

### 1.26-1.37 CLI Command Pages (12 pages)
All CLI pages follow a consistent template: Description, Usage, Options table, Process steps, Examples, Error Conditions, Related Topics.

| Page | Title | Placeholders | Assessment |
|---|---|---|---|
| CLIReference.html | CLI Reference | 0 | Thorough |
| CLICreatePackage.html | CLI: create-package | 0 | Thorough |
| CLIDeleteLib.html | CLI: delete-lib | 0 | Thorough |
| CLIExportLib.html | CLI: export-lib | 0 | Thorough |
| CLIExportArchive.html | CLI: export-archive | 0 | Thorough |
| CLIImportLib.html | CLI: import-lib | 0 | Thorough |
| CLIImportArchive.html | CLI: import-archive | 0 | Thorough |
| CLIListLibs.html | CLI: list-libs | 0 | Thorough |
| CLIListVersions.html | CLI: list-versions | 0 | Thorough |
| CLIRollbackLib.html | CLI: rollback-lib | 0 | Thorough |
| CLIGenerateSyslibHashes.html | CLI: generate-syslib-hashes | 0 | Thorough |
| CLIVerifySyslibHashes.html | CLI: verify-syslib-hashes | 0 | Thorough |
| CLIVerifyPackage.html | CLI: verify-package | 0 | Thorough |

---

## 2. Image Placeholder Inventory

Total `<div class="image-placeholder">` elements found across all 38 HTML files: **28**

| # | File | Placeholder Text |
|---|---|---|
| 1 | index.html | PLACE IMAGE OF THE Library Manager for Venus 6 MAIN WINDOW HERE |
| 2 | Overview.html | PLACE IMAGE OF Library Manager for Venus 6 MAIN WINDOW HERE |
| 3 | GUIOverview.html | PLACE IMAGE OF MAIN WINDOW WITH LABELED REGIONS |
| 4 | GUIOverview.html | PLACE IMAGE OF NAVIGATION TABS HERE |
| 5 | GUIOverview.html | PLACE IMAGE OF A LIBRARY CARD WITH ANNOTATIONS HERE |
| 6 | GUIOverview.html | PLACE IMAGE OF LIBRARY DETAIL MODAL HERE |
| 7 | GUIOverview.html | PLACE IMAGE OF PRE-INSTALL PREVIEW MODAL WITH SIGNATURE STATUS HERE |
| 8 | GUIOverview.html | PLACE IMAGE OF LIBRARY PACKAGER UI HERE |
| 9 | GUIOverview.html | PLACE IMAGE OF SETTINGS PANEL HERE |
| 10 | SearchFeatures.html | PLACE IMAGE OF SEARCH BAR WITH TAG AND AUTHOR CHIPS HERE |
| 11 | SearchFeatures.html | PLACE IMAGE OF SEARCH AUTOCOMPLETE DROPDOWN WITH SUGGESTIONS HERE |
| 12 | SplashScreen.html | PLACE IMAGE OF THE SPLASH SCREEN WITH ANIMATED LOGO AND STATUS TEXT HERE |
| 13 | DataModel.html | PLACE IMAGE OF THE DB FOLDER STRUCTURE HERE |
| 14 | IntegrityVerification.html | PLACE IMAGE OF LIBRARY CARD INTEGRITY ERROR STYLING HERE |
| 15 | IntegrityVerification.html | PLACE IMAGE OF VERIFY AND REPAIR MODAL WITH LIBRARY STATUS LIST HERE |
| 16 | VisualIdentity.html | PLACE IMAGE OF COMPOSITED PACKAGE ICON EXAMPLE SHOWING LOGO OVERLAY HERE |
| 17 | SuccessDialogs.html | PLACE IMAGE OF A SUCCESS DIALOG EXAMPLE SHOWING GREEN CHECKMARK AND DETAILS HERE |
| 18 | ImportingLibraries.html | PLACE IMAGE OF IMPORT PREVIEW MODAL WITH LIBRARY METADATA AND SIGNATURE STATUS HERE |
| 19 | ImportingLibraries.html | PLACE IMAGE OF POST-IMPORT SUCCESS MODAL HERE |
| 20 | ExportingLibraries.html | PLACE IMAGE OF EXPORT CHOICE MODAL HERE |
| 21 | ExportingLibraries.html | PLACE IMAGE OF EXPORT BUTTON IN LIBRARY DETAIL MODAL HERE |
| 22 | ExportingLibraries.html | PLACE IMAGE OF EXPORT CHOICE MODAL WITH DEPENDENCIES LISTED HERE |
| 23 | ExportingLibraries.html | PLACE IMAGE OF ARCHIVE EXPORT MODAL WITH LIBRARY CHECKBOXES HERE |
| 24 | CreatingPackages.html | PLACE IMAGE OF LIBRARY PACKAGER MAIN VIEW HERE |
| 25 | CreatingPackages.html | PLACE IMAGE OF PACKAGER WITH FILLED METADATA AND FILE LIST HERE |
| 26 | DeletingLibraries.html | PLACE IMAGE OF DELETE CONFIRMATION DIALOG HERE |
| 27 | VersionRollback.html | PLACE IMAGE OF CACHED VERSIONS LIST IN LIBRARY DETAIL MODAL HERE |
| 28 | VersionRollback.html | PLACE IMAGE OF ROLLBACK CONFIRMATION DIALOG HERE |
| 29 | VENUSIntegration.html | PLACE IMAGE OF VENUS TOOL SHORTCUTS IN SIDEBAR HERE |
| 30 | UnsignedLibraries.html | PLACE IMAGE OF UNSIGNED LIBRARIES SETTINGS CHECKBOXES AND SCAN BUTTON HERE |
| 31 | UnsignedLibraries.html | PLACE IMAGE OF UNSIGNED LIBRARY CARDS ON THE MAIN SCREEN HERE |
| 32 | UnsignedLibraries.html | PLACE IMAGE OF UNSIGNED LIBRARY DETAIL AND EDIT MODAL HERE |
| 33 | LibraryAuditLog.html | PLACE IMAGE OF RUN LIBRARY AUDIT MENU ITEM IN OVERFLOW MENU HERE |
| 34 | LibraryAuditLog.html | PLACE IMAGE OF AUDIT VERIFICATION RESULT DIALOG HERE |

---

## 3. Undocumented Features Found in App Code

### 3.1 Event History Modal (UNDOCUMENTED)
**Source:** `main.js` lines 255-620, `index.html` `#eventHistoryModal`

The overflow menu has a **"History"** item (`overflow-history`) that opens an `#eventHistoryModal`. This is a full-featured modal with:
- A searchable, filterable list of all audit trail events
- Category filter dropdown (Create, Import, Delete, Rollback, System)
- User filter dropdown (populated from event data)
- Free-text search
- Expandable detail rows per event (click "Details" to expand)
- Event count and date range display
- **CSV Export** button that exports visible/filtered events to a `.csv` file

This feature is **completely undocumented**. No CHM help page mentions the History modal, the overflow menu History item, or CSV export capability. The `LibraryAuditLog.html` page mentions the audit trail stored in `audit_trail.json` and says "The audit trail is not displayed in the library detail view or any GUI panel" — this statement is now **incorrect** since the Event History modal does display the trail in the GUI.

**Recommendation:** Create a new page `EventHistory.html` or add a major section to `LibraryAuditLog.html` documenting this feature.

---

### 3.2 Starred / Favorites Navigation Tab (UNDOCUMENTED)
**Source:** `main.js` lines 572, 3833-3838, 4953-4970

A **"Starred"** navigation tab (`gStarred`) exists in the navigation bar between "All" and "Recent". Users can:
- Click a star icon on any library card to star/unstar it
- Navigate to the Starred tab to see only starred libraries
- Starred state is persisted in settings (`settings.starredLibIds` array)

The `LibraryGrouping.html` page lists default groups as All, Recent, System, Hamilton, and Unsigned — but **does not mention the Starred group**. The `GUIOverview.html` page also does not describe the star/favorite functionality.

**Recommendation:** Add Starred to the Default Groups table in `LibraryGrouping.html` and document the star interaction on library cards.

---

### 3.3 `library_registered` Audit Event Type (UNDOCUMENTED)
**Source:** `main.js` line 11862

When an unsigned library is registered via the "Register to Library Manager" button, a `library_registered` audit trail event is recorded. However:
- The `EVENT_TYPE_LABELS` map (line 258) does **not** include `library_registered`
- The `LibraryAuditLog.html` page lists only 5 audit event types: `package_created`, `library_imported`, `archive_imported`, `library_deleted`, `library_rollback`
- The `UnsignedLibraries.html` page does mention the event but the audit log page doesn't

**Recommendation:** Add `library_registered` to the event types table in `LibraryAuditLog.html`.

---

### 3.4 Run Log Cleanup Feature (PARTIALLY DOCUMENTED)
**Source:** `main.js` lines 5010-5099, `index.html` cleanup progress bar

The app has a **run log cleanup** feature (`historyCleanup()`) that can:
- Automatically delete or archive VENUS run log files older than N days
- Show a progress bar in the navbar during cleanup
- Archive files to a configurable directory

This feature is controlled by settings: `chk_settingHistoryCleanup`, `history-days`, `cleanup-action`, `history-archive-folder`.

The Settings UI for this is referenced but the feature is not documented in any CHM help page. `GUIOverview.html` briefly mentions settings but doesn't cover this. No `Settings` dedicated documentation page exists (Settings is a section within `GUIOverview.html`).

**Recommendation:** Document the run log cleanup feature in a Settings section or a new dedicated page.

---

### 3.5 File Association / Double-Click-to-Open (PARTIALLY DOCUMENTED)
**Source:** `main.js` lines 70-128 (`_handleStartupFileArgs`, `_openFileByPath`)

The app handles `.hxlibpkg` and `.hxlibarch` files passed as command-line arguments (for Windows file association / double-click). When a user double-clicks a `.hxlibpkg` file in Explorer, the app opens and immediately begins the import flow.

This is mentioned briefly in `GettingStarted.html` but the actual file association setup and behavior is not documented.

**Recommendation:** Document file association behavior and how to set it up (the installer handles this).

---

### 3.6 Overflow Menu Items (PARTIALLY DOCUMENTED)
**Source:** `index.html` lines 107-120

The overflow menu (three dots `⋮`) contains these items:
1. **Package Library** → Opens the Library Packager
2. **Verify & Repair** → Opens the Verify & Repair modal
3. **Library Groups** → Opens the Groups modal
4. **History** → Opens the Event History modal (**UNDOCUMENTED**)
5. **Run Library Audit** → Generates an audit log
6. **Check Audit File** → Verifies an audit log file
7. **Export Archive** → Opens the archive export modal
8. **Settings** → Opens Settings modal
9. **Help** → Opens the CHM help file

The `GUIOverview.html` page mentions several of these but not in a systematic list, and the **History** item is not mentioned at all.

**Recommendation:** Add a complete overflow menu reference table to `GUIOverview.html`.

---

### 3.7 Audit Trail Enforcement Settings (PARTIALLY DOCUMENTED)
**Source:** `index.html` lines 1318-1328

Settings modal has an "Audit Trail Enforcement" section with two checkboxes:
- `chk_requireActionComment` — "Require comment for destructive and impactful actions"
- `chk_requireActionSignature` — "Require user signature for destructive and impactful actions"

These are documented as behaviors in several pages (DeletingLibraries, VersionRollback, ImportingLibraries) but the **Settings section itself** and these specific toggles are not documented as a standalone concept. The `GUIOverview.html` mentions "Audit comment and signature enforcement" briefly but doesn't detail the settings.

**Recommendation:** Ensure the Settings panel documentation in `GUIOverview.html` explicitly lists and explains these two checkboxes.

---

### 3.8 Data Location Setting (PARTIALLY DOCUMENTED)
**Source:** `index.html` lines 1345-1356

Settings has a **Data Location** section with a path input, Browse button, and Apply button for configuring the user data directory. `GettingStarted.html` and `DataModel.html` mention the user data directory but don't document this Settings UI for changing it.

**Recommendation:** Document the Data Location setting explicitly.

---

### 3.9 System Library Detail Modal (CODE-LEVEL DETAIL NOT DOCUMENTED)
**Source:** `main.js` `impShowSystemLibDetail()` (line 7900)

System libraries have their own detail modal that shows:
- Library metadata (author, organization, file count, resource types)
- Integrity status with color-coded indicators
- Individual file integrity results with footer values
- Repair button when integrity failures are detected
- File list with hash/checksum verification details

While `IntegrityVerification.html` and `GUIOverview.html` reference this indirectly, there is no documentation of the system library detail modal layout and features.

**Recommendation:** Add an image placeholder and description of the system library detail modal.

---

### 3.10 `chk_hideSystemLibraries` Setting (PARTIALLY DOCUMENTED)
**Source:** `index.html` line 1335, `main.js` line 6789

Settings has "Hide system libraries on the front page" with a note: "System libraries with warnings or errors will still be shown."

This behavior is not documented in any help page.

**Recommendation:** Document this setting in the Settings section of `GUIOverview.html` or a dedicated Settings page.

---

### 3.11 Recent Tab Configuration (PARTIALLY DOCUMENTED)
**Source:** `index.html` lines 1371-1392

Settings has a "Recent" section with:
- "Display last: N" dropdown (5, 10, 20, 50, 100)
- "Clear Recent List" button

This is partially implied in various pages but the specific settings are not documented.

**Recommendation:** Document the Recent settings.

---

### 3.12 `syslib_integrity_check` Audit Event Type (UNDOCUMENTED)
**Source:** `main.js` line 265

The event type `syslib_integrity_check` ("System Library Integrity Check") is defined in the Event History UI but is not listed in `LibraryAuditLog.html`'s audit trail event types.

**Recommendation:** Add this event type to the audit trail documentation.

---

### 3.13 CLI `verify-package` Command (MISSING FROM INDEX)
**Source:** `CLIVerifyPackage.html` exists but `index.html` (CHM landing page) does not list it

The CLI Reference section in `index.html` lists 12 CLI commands but omits `verify-package`. The `CLIReference.html` page itself lists all 12 commands correctly including `verify-package`, but the landing page index is missing it.

**Recommendation:** Add `verify-package` to the CLI Reference links list in `index.html`.

---

### 3.14 Public Functions Parsing & Display (PARTIALLY DOCUMENTED)
**Source:** `main.js` lines 6264-6465

The app parses HSL files to extract public function signatures, parameter types, doc comments, and displays them in the library detail modal. While mentioned in `GUIOverview.html` and `DataModel.html`, the parsing mechanics (sanitization, parameter extraction, doc comment extraction) and the visual display (expandable accordion with function signatures) are not documented in detail.

**Recommendation:** Consider expanding documentation on public function display in library details.

---

### 3.15 Dependency Resolution Display (PARTIALLY DOCUMENTED)
**Source:** `main.js` lines 6465-6705

The library detail modal shows resolved dependencies with status badges:
- Green check for satisfied dependencies
- Yellow warning for unsigned dependencies
- Red X for missing dependencies
- Links to dependency libraries (clickable)

While `UnsignedLibraries.html` documents unsigned dependency behavior, the general dependency resolution UI is not fully documented.

**Recommendation:** Add a section in `GUIOverview.html` about the dependency status display.

---

### 3.16 Import Overwrite Confirmation with Audit Fields (PARTIALLY DOCUMENTED)
**Source:** `index.html` lines 1736-1760

When importing a library that already exists, an overwrite confirmation modal appears with:
- Type-to-confirm library name field
- Audit comment field (when enabled)
- Audit signature field (when enabled)
- Warning about overwriting existing data

`ImportingLibraries.html` mentions overwrite behavior but the specific modal UI with audit fields is documented only partially.

---

## 4. Recommended New Image Placeholders

These are locations where image placeholders **should be added** but currently do not exist:

| # | File | Recommended Placeholder |
|---|---|---|
| 1 | **GUIOverview.html** | "PLACE IMAGE OF OVERFLOW MENU DROPDOWN HERE" — The three-dot menu is a major navigation element |
| 2 | **GUIOverview.html** | "PLACE IMAGE OF STARRED LIBRARY CARD WITH STAR ICON HERE" — Star/favorite UI is undocumented |
| 3 | **SearchFeatures.html** | "PLACE IMAGE OF TAG CHIP EDIT MODE (CLICK-TO-EDIT) HERE" |
| 4 | **SearchFeatures.html** | "PLACE IMAGE OF BACKSPACE-TO-DELETE RED HIGHLIGHT ON CHIP HERE" |
| 5 | **LibraryGrouping.html** | "PLACE IMAGE OF NAVIGATION BAR WITH ALL TABS (All, Starred, Recent, System, Hamilton, Unsigned, User Groups) HERE" |
| 6 | **LibraryGrouping.html** | "PLACE IMAGE OF GROUPS MODAL / LIBRARY GROUPS MANAGEMENT HERE" |
| 7 | **IntegrityVerification.html** | "PLACE IMAGE OF SYSTEM LIBRARY DETAIL MODAL WITH INTEGRITY STATUS HERE" |
| 8 | **VersionRollback.html** | "PLACE IMAGE OF ROLLBACK VERSION SELECTION IN CLI OUTPUT HERE" |
| 9 | **VENUSIntegration.html** | "PLACE IMAGE OF VENUS DIRECTORY SHORTCUTS IN SIDEBAR HERE" |
| 10 | **VENUSIntegration.html** | "PLACE IMAGE OF SIMULATION MODE TOGGLE HERE" |
| 11 | **LibraryAuditLog.html** | "PLACE IMAGE OF EVENT HISTORY MODAL WITH FILTERS AND EVENT LIST HERE" |
| 12 | **LibraryAuditLog.html** | "PLACE IMAGE OF EVENT HISTORY CSV EXPORT HERE" |
| 13 | **GitHubRepository.html** | "PLACE IMAGE OF GITHUB URL FIELD IN LIBRARY PACKAGER HERE" |
| 14 | **GitHubRepository.html** | "PLACE IMAGE OF GITHUB LINK DISPLAYED IN LIBRARY DETAIL MODAL HERE" |
| 15 | **GettingStarted.html** | "PLACE IMAGE OF FIRST-RUN SYSTEM LIBRARY VERIFICATION SPLASH SCREEN HERE" |
| 16 | **DeletingLibraries.html** | "PLACE IMAGE OF TYPE-TO-CONFIRM FIELD IN DELETE DIALOG HERE" |
| 17 | **ImportingLibraries.html** | "PLACE IMAGE OF ARCHIVE IMPORT PROGRESS OR SUMMARY HERE" |
| 18 | **ImportingLibraries.html** | "PLACE IMAGE OF OVERWRITE CONFIRMATION MODAL WITH AUDIT FIELDS HERE" |
| 19 | **UnsignedLibraries.html** | "PLACE IMAGE OF REGISTER TO LIBRARY MANAGER SUCCESS DIALOG HERE" |
| 20 | **UnsignedLibraries.html** | "PLACE IMAGE OF EXPORT AND REGISTER SUCCESS DIALOG HERE" |
| 21 | **SuccessDialogs.html** | Additional success dialog variants (Rollback, Repair, Archive Import) |
| 22 | **DataModel.html** | "PLACE IMAGE OF AUDIT_TRAIL.JSON EXAMPLE ENTRY STRUCTURE HERE" |
| 23 | **ExportingLibraries.html** | "PLACE IMAGE OF EXPORT WITH DEPENDENCIES SUCCESS DIALOG HERE" |

---

## 5. General Observations

### Strengths
1. **Exceptional depth** — Most pages are very thorough with step-by-step processes, tables, and code examples.
2. **Consistent structure** — All pages follow a uniform template with breadcrumbs, headers, and related links.
3. **CLI documentation** — All 13 CLI commands are thoroughly documented with options tables, examples, and error conditions.
4. **Cross-referencing** — Pages link to related topics extensively.
5. **Technical accuracy** — The documented behavior closely matches the code implementation.

### Gaps Summary
1. **Event History Modal** — Completely undocumented major GUI feature.
2. **Starred/Favorites** — Navigation tab and star icons are undocumented.
3. **Settings page detail** — No dedicated Settings reference; settings are scattered across `GUIOverview.html` and other pages. A consolidated Settings reference would be valuable.
4. **Run Log Cleanup** — Potentially significant feature that is undocumented.
5. **System Library Detail Modal** — UI for inspecting system library integrity is only indirectly referenced.
6. **Missing audit event types** — `library_registered` and `syslib_integrity_check` are used in code but not documented.
7. **`verify-package` missing from CHM index** — The landing page index omits this CLI command.
8. **34 image placeholders** need actual screenshots — no images have been placed yet.

### Recommendations
1. **Priority 1:** Document the Event History modal (new page or major section).
2. **Priority 2:** Add Starred/Favorites to the grouping and GUI documentation.
3. **Priority 3:** Add `verify-package` to the CHM index page CLI links.
4. **Priority 4:** Update `LibraryAuditLog.html` to include all 7 audit event types and correct the "not displayed in any GUI panel" statement.
5. **Priority 5:** Create a consolidated Settings reference page or expand the Settings section in `GUIOverview.html`.
6. **Priority 6:** Document the Run Log Cleanup feature.
7. **Priority 7:** Fill in the 34 existing image placeholders with actual screenshots.
8. **Priority 8:** Add the 23 recommended new image placeholders.
