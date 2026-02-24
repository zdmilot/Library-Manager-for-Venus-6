# Library Manager

Library Manager is a desktop tool (NW.js + Node.js) for managing Hamilton VENUS libraries and related assets.
It supports full package lifecycle workflows for `.hxlibpkg` and `.hxlibarch` files, including package creation, import, export, archive bundling, integrity checks, COM registration workflows, grouping, and visualization of installed libraries.

---

## What this software can do (detailed capability list)

## 1) Library management and visualization

- Displays installed libraries as visual cards with:
  - Library icon/image (embedded image if available, fallback icon otherwise)
  - Name, version, author, short description, and tags
  - Status badges (COM badge, COM warning, deleted state)
  - Integrity status indicator (error/warning/info)
- Provides a **library detail modal** for each installed library showing:
  - Full metadata (name, version, author, organization, VENUS compatibility, created date, installed date)
  - Full description and tags
  - Library image preview
  - Complete lists of installed library files and demo method files
  - Install paths for library and demo folders
  - COM registration details and warning/success state
  - File integrity verification results (missing/modified files, warnings)
- Supports visualization modes/tabs:
  - **All** installed libraries
  - **Recent** imported libraries (limited by configurable max)
  - **Import** tab view
  - **Custom group filtered views**
- Shows empty-state guidance in each view (no libraries, no recent imports, no group assignments).
- Uses card styling to surface health/quality states:
  - Integrity error style
  - COM warning style
  - Deleted style

## 2) Importing a single library package (`.hxlibpkg`)

- Lets the user browse and select one package file.
- Reads package contents and validates required `manifest.json`.
- Shows a **pre-install preview modal** including:
  - Library metadata
  - Embedded icon/image
  - Library/demo file lists
  - COM DLL indicators and COM notice
  - Destination install paths
  - Existing-library overwrite/update warning if same library name already exists
- Installs package content to VENUS paths:
  - Library files -> `...\Hamilton\Library\<LibraryName>`
  - Demo files -> `...\Hamilton\Methods\Library Demo Methods\<LibraryName>`
- Registers selected COM DLLs during import (UAC elevation flow).
- Handles COM registration failures with user decision:
  - Continue import with warning status, or
  - Cancel import and clean up extracted files.
- Updates installed library database record with:
  - Metadata + file lists + install paths
  - COM registration list and warning state
  - Source package filename
  - Install timestamp
  - Integrity hash map for tracked files
- Auto-assigns newly installed libraries into a custom group (or creates a default `Libraries` group if needed).
- Shows a post-install success modal with:
  - Installed file count
  - Output paths
  - COM registration outcome summary

## 3) Importing a library archive (`.hxlibarch`) with multiple libraries

- Supports archive selection via dedicated **Import Archive** workflow.
- Validates archive exists and contains at least one `.hxlibpkg` entry.
- Shows pre-install confirmation listing all contained packages.
- Extracts and installs each package sequentially.
- For each package, performs:
  - Manifest load
  - File extraction to library/demo destinations
  - Database upsert of installed record
  - Integrity hash computation
  - Optional auto-group assignment based on settings
- Produces aggregate completion summary with per-library success/failure entries.
- Refreshes library card visualization after import completes.

## 4) Exporting a single installed library (`.hxlibpkg`)

- Exports directly from an installed library detail modal.
- Uses a save dialog with suggested `<LibraryName>.hxlibpkg` filename.
- Rebuilds package from currently installed files and metadata.
- Includes:
  - `manifest.json`
  - `library/` payload
  - `demo_methods/` payload
  - Metadata including tags, image base64, COM DLL list
- Verifies expected library files exist before export; aborts with message if missing.

## 5) Exporting mutable libraries to an archive (`.hxlibarch`)

- Provides archive export modal listing all non-deleted installed libraries.
- Supports selection workflows:
  - Individual checkbox selection
  - Select all
  - Select none
- Exports selected libraries into one `.hxlibarch` file.
- For each selected library, builds an inner `.hxlibpkg` from **current installed state** (supports mutable/changed installations).
- Produces an archive with:
  - Multiple embedded `.hxlibpkg` files
  - `archive_manifest.json` (archive metadata, count, included library names)
- Displays export summary including included libraries and file counts.

## 6) Deleting a library

- Supports delete action from library detail modal.
- Shows explicit irreversible confirmation with:
  - Library and demo install paths
  - COM DLL deregistration implications
- Performs optional COM deregistration before file removal.
- Handles deregistration failures with continue/cancel decision.
- Deletes installed library files and demo method files from disk.
- Removes now-empty library/demo directories when possible.
- Soft-deletes database entry (marks `deleted=true` and stores `deleted_date`) so deletion history can persist.
- Removes deleted library from group assignment tree.

## 7) Creating a library package from raw files

- Built-in **Library Packager** UI creates `.hxlibpkg` from selected raw files.
- Captures metadata fields:
  - Author (required)
  - Organization
  - Library version (required)
  - VENUS compatibility string
  - Description
  - Tags
- Supports adding payload from:
  - Individual files
  - Whole folders
- Supports separate payload categories:
  - Library files
  - Demo method files
- Auto-detects library name based on file priority:
  - `.hsl` -> `.hs_` -> `.smt`
- Supports manual override of detected library name with warning UI.
- Supports optional custom icon/image selection with size/type handling.
- Auto-detects matching `.bmp` when custom image not supplied.
- Supports per-DLL **COM Register** selection inside package payload.
- Writes package with standardized structure (`manifest.json`, `library/`, `demo_methods/`, optional `icon/`).
- Includes package reset workflow to clear all staged metadata/files.

## 8) File integrity and change visualization

- Computes SHA-256 hashes for tracked files during install:
  - `.hsl`, `.hs_`, `.sub` (hashes all except last line)
  - COM-registered `.dll` files (full-file hash)
- Stores file hash map in installed library records.
- Verifies integrity when building library cards/detail view.
- Surfaces integrity states visually:
  - Modified file
  - Missing file
  - Legacy/no-hash warning
  - “All tracked files pass” success

## 9) Library grouping and organization

- Supports custom library groups (create, rename, delete).
- Supports drag-and-drop reorder of groups and group contents in settings.
- Supports drag-and-drop assignment/movement of libraries across groups.
- Provides “Unassigned Libraries” pseudo-group in settings for ungrouped items.
- Supports favorite/show-hide behavior for custom group visibility in navigation.
- Persists group + assignment tree structure via local DB JSON.

## 10) Recent/history and housekeeping

- Tracks recent imports and exposes Recent view.
- Supports configurable recent list size.
- Supports clearing recent list.
- Includes run-log cleanup progress UI and configurable history archive folder behavior in logic.

## 11) VENUS integration and utility launching

- Resolves VENUS install paths dynamically from registry via helper DLL interop.
- Updates internal path references (bin/config/library/log/methods/labware).
- Exposes launch/open actions for VENUS tools and folders (from configured links database):
  - Method Editor
  - Liquid Class Editor
  - Labware Editor
  - HSL Editor
  - System Configuration Editor
  - Run Control / Version / core VENUS directories
- Supports simulation mode toggle through helper interop (`GetSimulation` / `SetSimulation`).
- Supports user/auth role display and function-protection handling integration through helper calls.

## 12) Help and UX support

- Opens local compiled help file (`Library Manager.chm`) from overflow menu.
- Includes video modal infrastructure for in-app help/tutorial playback.
- Responsive UI behavior for window resize + nav overflow handling.

## 13) Local persistence and data model

- Uses local JSON-backed storage (`diskdb`) under `db/` for:
  - Groups
  - Links
  - Settings
  - Group tree assignments
  - Installed library records
- Persists key library lifecycle metadata:
  - Source package
  - Install and delete timestamps
  - COM registration state
  - Integrity hash data

## 14) Supported package/archive formats

- `.hxlibpkg` (single library package)
  - ZIP-based container
  - `manifest.json` + payload directories
- `.hxlibarch` (multi-library archive)
  - ZIP containing multiple `.hxlibpkg`
  - `archive_manifest.json`

---

## Command Line Interface (CLI)

Library Manager ships a full-featured command-line tool (`cli.js`) that mirrors the GUI workflows, enabling scripted automation, CI/CD integration, and headless testing.

### Prerequisites

Node.js must be installed independently of NW.js (or use the NW.js `nw` binary from the project directory). All Node.js dependencies (`adm-zip`, `diskdb`) are satisfied by the project's existing `node_modules`.

```
cd "Library Manager"
node cli.js help
```

> **COM DLL registration** is not performed by the CLI (it requires a live Windows COM context). The CLI records COM DLL intent in the database. Run `RegAsm.exe /codebase` with administrator rights manually after importing a package that requires COM registration.

---

### Global option

| Flag | Description |
|------|-------------|
| `--db-path <dir>` | Override path to the `db/` directory (default: `<app-root>/db`). Useful for testing against a scratch database. |

---

### `list-libs` — List installed libraries

Prints a summary of every installed library record in the database.

```
node cli.js list-libs [options]
```

| Flag | Description |
|------|-------------|
| `--include-deleted` | Include soft-deleted entries in output |
| `--json` | Print raw JSON array (useful for scripting / piping) |

**Examples**
```bat
:: Human-readable summary
node cli.js list-libs

:: JSON output for scripting
node cli.js list-libs --json

:: Include deleted libraries
node cli.js list-libs --include-deleted --json
```

---

### `import-lib` — Import a single `.hxlibpkg`

Reads a `.hxlibpkg` file, extracts payload files to the configured VENUS library and demo-methods directories, and registers the library record in the database.

```
node cli.js import-lib --file <path> [options]
```

| Flag | Description |
|------|-------------|
| `--file <path>` | **Required.** Path to the `.hxlibpkg` file |
| `--lib-dir <path>` | Override library install root (default: read from DB settings, fallback `C:\Program Files (x86)\HAMILTON\Library`) |
| `--met-dir <path>` | Override methods (demo) install root (default: read from DB settings, fallback `...\Methods`) |
| `--force` | Overwrite an already-installed library without returning an error |
| `--no-group` | Skip auto-assigning the new library to a group |

**Examples**
```bat
:: Basic import
node cli.js import-lib --file MyLibrary.hxlibpkg

:: Force overwrite
node cli.js import-lib --file MyLibrary.hxlibpkg --force

:: Custom install paths
node cli.js import-lib --file MyLibrary.hxlibpkg ^
    --lib-dir D:\Hamilton\Library ^
    --met-dir D:\Hamilton\Methods
```

---

### `import-archive` — Import a `.hxlibarch` (multiple libraries)

Extracts every `.hxlibpkg` embedded inside a `.hxlibarch` zip archive and installs each one sequentially.

```
node cli.js import-archive --file <path> [options]
```

| Flag | Description |
|------|-------------|
| `--file <path>` | **Required.** Path to the `.hxlibarch` file |
| `--lib-dir <path>` | Override library install root |
| `--met-dir <path>` | Override methods (demo) install root |
| `--force` | Overwrite already-installed libraries without error |
| `--no-group` | Skip auto-assigning libraries to groups |

**Examples**
```bat
:: Import all libraries in bundle
node cli.js import-archive --file bundle.hxlibarch

:: Force overwrite all
node cli.js import-archive --file bundle.hxlibarch --force
```

---

### `export-lib` — Export a single installed library as `.hxlibpkg`

Rebuilds a `.hxlibpkg` from the currently installed files on disk for the named library. This captures any changes made since the original install ("mutable export").

```
node cli.js export-lib (--name <name> | --id <id>) --output <path>
```

| Flag | Description |
|------|-------------|
| `--name <name>` | Library name (as shown in `list-libs`) |
| `--id <id>` | Library database ID |
| `--output <path>` | **Required.** Output `.hxlibpkg` file path |

**Examples**
```bat
node cli.js export-lib --name "MyLibrary" --output MyLibrary.hxlibpkg

node cli.js export-lib --id e5c6a701 --output dist\MyLibrary.hxlibpkg
```

---

### `export-archive` — Export libraries as `.hxlibarch`

Bundles one or more installed libraries into a single `.hxlibarch` file. Each library is re-packed from current disk state, so the archive reflects any post-install modifications.

```
node cli.js export-archive (--all | --names <n1,n2,...> | --ids <id1,id2,...>) --output <path>
```

| Flag | Description |
|------|-------------|
| `--all` | Export every non-deleted installed library |
| `--names <n1,n2,...>` | Comma-separated library names to export |
| `--ids <id1,id2,...>` | Comma-separated library database IDs to export |
| `--output <path>` | **Required.** Output `.hxlibarch` file path |

**Examples**
```bat
:: Full backup of all installed libraries
node cli.js export-archive --all --output backup\all-libs.hxlibarch

:: Named subset
node cli.js export-archive --names "LibA,LibB" --output release\subset.hxlibarch

:: By IDs
node cli.js export-archive --ids "abc123,def456" --output out\specific.hxlibarch
```

---

### `delete-lib` — Delete a library

Removes library files from disk and soft-deletes the database record (history is preserved unless `--hard` is specified). **Requires `--yes` to prevent accidental deletion.**

> COM DLLs are **not** automatically deregistered by the CLI. Run `RegAsm.exe /unregister <dll>` manually with administrator rights if needed.

```
node cli.js delete-lib (--name <name> | --id <id>) --yes [options]
```

| Flag | Description |
|------|-------------|
| `--name <name>` | Library name |
| `--id <id>` | Library database ID |
| `--yes` / `--force` | **Required.** Explicit confirmation |
| `--hard` | Permanently remove the DB record (no history retained) |
| `--keep-files` | Remove from DB only; leave installed files on disk |

**Examples**
```bat
:: Soft-delete (default — history preserved)
node cli.js delete-lib --name "MyLibrary" --yes

:: Hard delete (record removed from DB entirely)
node cli.js delete-lib --name "MyLibrary" --yes --hard

:: Remove DB entry but leave disk files intact
node cli.js delete-lib --name "MyLibrary" --yes --keep-files
```

---

### `create-package` — Build a `.hxlibpkg` from raw files

Creates a `.hxlibpkg` from library source files and metadata defined in a JSON spec file. This is the CLI equivalent of the GUI Library Packager.

```
node cli.js create-package --spec <spec.json> --output <output.hxlibpkg>
```

| Flag | Description |
|------|-------------|
| `--spec <path>` | **Required.** Path to the JSON spec file (see schema below) |
| `--output <path>` | **Required.** Output `.hxlibpkg` file path |

**Example**
```bat
node cli.js create-package --spec MyLibrary.spec.json --output dist\MyLibrary.hxlibpkg
```

#### Package spec JSON schema

The spec file is validated against [`cli-schema.json`](cli-schema.json). A full worked example is in [`cli-spec-example.json`](cli-spec-example.json).

All **file paths** inside the spec are resolved **relative to the directory containing the spec file**.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `author` | `string` | **Yes** | Library author name |
| `version` | `string` | **Yes** | Library version string (e.g. `"1.0.0"`) |
| `library_files` | `string[]` | **Yes** | Paths to library payload files (`.hsl`, `.hs_`, `.hsi`, `.dll`, `.bmp`, etc.) |
| `library_name` | `string` | No | Override library name. Auto-detected from `.hsl`/`.hs_`/`.smt` if omitted |
| `organization` | `string` | No | Author's organization |
| `venus_compatibility` | `string` | No | VENUS version compatibility description |
| `description` | `string` | No | Human-readable library description |
| `tags` | `string[]` | No | Search tags |
| `library_image` | `string` | No | Path to icon/image file. Falls back to matching `.bmp` if omitted |
| `demo_method_files` | `string[]` | No | Paths to demo/example method files |
| `com_register_dlls` | `string[]` | No | Basenames of DLLs in `library_files` that require COM registration |

**Minimal spec example**
```json
{
  "author": "Jane Smith",
  "version": "1.0.0",
  "library_files": ["MyLibrary.hsl", "MyLibrary.hs_", "MyLibrary.bmp"]
}
```

**Full spec example**
```json
{
  "$schema": "./cli-schema.json",
  "library_name": "MyVenusLibrary",
  "author": "Jane Smith",
  "organization": "Acme Pharma",
  "version": "1.0.0",
  "venus_compatibility": "4.7+",
  "description": "High-level pipetting helpers for the ML600 syringe pump.",
  "tags": ["pipetting", "ML600", "syringe"],
  "library_image": "MyVenusLibrary.png",
  "library_files": [
    "MyVenusLibrary.hsl",
    "MyVenusLibrary.hs_",
    "MyVenusLibrary.hsi",
    "MyVenusLibrary.bmp"
  ],
  "demo_method_files": [
    "demo/Demo_MyVenusLibrary.hsl"
  ],
  "com_register_dlls": []
}
```

---

### Automated testing / CI usage

The CLI is designed for use in automated test pipelines. A typical round-trip test sequence:

```bat
@REM 1. Create a package from raw sources
node cli.js create-package --spec tests\MyLib.spec.json --output tests\out\MyLib.hxlibpkg

@REM 2. Import it (against a test DB to avoid touching production data)
node cli.js import-lib --file tests\out\MyLib.hxlibpkg ^
    --db-path tests\scratch-db ^
    --lib-dir tests\scratch-lib ^
    --met-dir tests\scratch-met

@REM 3. Verify it appears in the library list
node cli.js list-libs --db-path tests\scratch-db --json

@REM 4. Re-export the installed library
node cli.js export-lib --name "MyLib" ^
    --db-path tests\scratch-db ^
    --output tests\out\MyLib-roundtrip.hxlibpkg

@REM 5. Bundle everything into an archive
node cli.js export-archive --all ^
    --db-path tests\scratch-db ^
    --output tests\out\archive.hxlibarch

@REM 6. Import the archive into a second scratch environment
node cli.js import-archive --file tests\out\archive.hxlibarch ^
    --db-path tests\scratch-db2 ^
    --lib-dir tests\scratch-lib2 ^
    --met-dir tests\scratch-met2

@REM 7. Clean up
node cli.js delete-lib --name "MyLib" --db-path tests\scratch-db --yes
```

All commands exit with code `0` on success and non-zero on failure, making them suitable for use with any test runner or CI system that checks process exit codes.

---

## Companion tools included in repository

The repository also includes Python desktop tools under `Library Packager/`:

- `packager.py` – standalone Tkinter packager for building `.hxlibpkg` from raw files.
- `reader.py` – standalone package reader/viewer/extractor for `.hxlibpkg`.
- `test_roundtrip.py` – package roundtrip test helper.
- C# reference projects under `Library Packager/CSharp/` for packaging/reading interop classes and testing.

---

## Notes on current behavior (important)

- The setting `chk_autoAddToGroup` is actively used during archive import grouping behavior.
- The settings `chk_confirmBeforeInstall` and `chk_overwriteWithoutAsking` are stored and surfaced in UI, but current install flow still uses preview/confirmation and explicit overwrite/update handling in code paths reviewed.
- Deleted libraries are soft-deleted in DB (kept for history state) while files are removed from disk.

---

## In short

This software provides complete library lifecycle management for Hamilton VENUS:

- Visual library management and status visualization
- Single-package import/export
- Multi-package archive import/export
- Export of mutable installed libraries to archive
- Safe deletion with COM-aware workflow
- Package creation from raw files
- Grouping, metadata, integrity validation, and local persistence
