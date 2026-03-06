# Architecture Overview

## Project Structure

```
Library-Manager-for-Venus-6/
├── package.json              # NW.js manifest + npm config (v1.7.5)
├── cli.js                    # CLI entry point (2810 lines)
├── com-bridge.js             # COM bridge dispatcher (164 lines)
├── lib/
│   ├── shared.js             # Shared crypto, validation, signing (1821 lines)
│   └── service.js            # Service layer — COM bridge backend (1732 lines)
├── html/
│   ├── index.html            # GUI shell (NW.js main window)
│   ├── js/
│   │   ├── main.js           # GUI logic (13469 lines)
│   │   ├── syscheck-worker.js# System library check web worker
│   │   ├── bootstrap.min.js  # Bootstrap 4 JS
│   │   ├── jquery-2.1.3.min.js
│   │   ├── jquery-ui.min.js
│   │   └── popper.min.js
│   ├── css/
│   │   ├── main.css          # Custom styles
│   │   ├── bootstrap.min.css
│   │   └── all.min.css       # FontAwesome
│   ├── img/                  # UI images / icons
│   └── webfonts/             # FontAwesome webfonts
├── db/                       # Default/seed database files
│   ├── system_libraries.json # Hamilton system library definitions
│   ├── system_library_hashes.json
│   ├── installed_libs.json   # (seed)
│   ├── groups.json           # (seed)
│   ├── settings.json         # (seed)
│   ├── tree.json             # (seed)
│   ├── links.json            # (seed)
│   └── unsigned_libs.json    # (seed)
├── local/                    # User data directory (runtime)
│   ├── packages/             # Cached .hxlibpkg files for rollback
│   ├── exports/              # Export staging area
│   ├── installed_libs.json   # Live installed libraries DB
│   ├── groups.json           # Live groups DB
│   ├── settings.json         # Live settings DB
│   ├── tree.json             # Navigation tree DB
│   ├── links.json            # Links DB
│   ├── unsigned_libs.json    # Unsigned libraries DB
│   └── publisher_registry.json # Publisher/tag registry
├── com/                      # COM automation component (C#)
│   ├── LibraryManager.cs     # COM-visible C# class
│   ├── VenusLibraryManager.csproj
│   ├── build.bat
│   ├── register-com.bat
│   ├── unregister-com.bat
│   └── verify-com.bat
├── CHM Help Source Files/    # Help documentation sources (HTML)
├── docs/                     # GitHub Pages / installer
├── assets/                   # Build/branding assets
├── icons/                    # Application icons
├── installer.iss             # Inno Setup installer script
└── store_assets/             # Store listing assets
```

## Dependency Graph

```
                    ┌──────────────┐
                    │  package.json│ (NW.js manifest)
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼────────┐ ┌─▼──────────┐
       │  cli.js     │ │com-bridge │ │html/index   │
       │  (CLI)      │ │    .js    │ │ (GUI)       │
       └──────┬──────┘ └──┬────────┘ └─┬──────────┘
              │            │            │
              │      ┌─────▼──────┐    │
              │      │lib/service │    │
              │      │ .js        │    │
              │      └─────┬──────┘    │
              │            │           │
              └────────────┼───────────┘
                           │
                    ┌──────▼──────┐
                    │ lib/shared  │
                    │    .js      │
                    └─────────────┘
                           │
                    ┌──────▼──────┐
                    │   diskdb    │
                    │   adm-zip   │
                    │   crypto    │
                    └─────────────┘
```

### Entry Points

| Entry Point | Consumer | Purpose |
|-------------|----------|---------|
| `html/index.html` → `html/js/main.js` | NW.js GUI | Desktop application |
| `cli.js` | `node cli.js <command>` | Command-line interface |
| `com-bridge.js` | `node com-bridge.js <cmd> <json>` | COM object bridge dispatcher |
| `lib/service.js` | `com-bridge.js` only | Service layer (shared backend) |
| `lib/shared.js` | All three above | Crypto, validation, signing |

### Data Flow

```
1. IMPORT (.hxlibpkg):
   File → unpackContainer(MAGIC_PKG) → ZIP → verifyPackageSignature()
   → manifest.json → extract files to Library/Methods dirs
   → computeLibraryHashes() → DB save → cachePackageToStore()

2. IMPORT (.hxlibarch):
   File → unpackContainer(MAGIC_ARC) → outer ZIP → forEach .hxlibpkg entry
   → unpackContainer(MAGIC_PKG) → inner ZIP → manifest → extract → DB save

3. EXPORT (.hxlibpkg):
   DB record → gather files → build manifest → AdmZip
   → signPackageZip[WithCert]() → packContainer(MAGIC_PKG) → binary file

4. EXPORT (.hxlibarch):
   Multiple libs → forEach: inner ZIP → packContainer(PKG)
   → outer ZIP → packContainer(ARC) → binary file

5. CREATE PACKAGE:
   JSON spec → validate → gather files → build manifest → AdmZip
   → sign → packContainer(MAGIC_PKG) → binary file

6. VERIFY:
   File → detect magic → unpackContainer() → verifyPackageSignature()
   → check HMAC + Ed25519 signature → report (OEM verified badge)
```

### Binary Container Format

```
Offset   Size    Field
[0..7]   8 B     Magic identifier (HXLPKG\x01\x00 or HXLARC\x01\x00)
[8..11]  4 B     Flags (uint32 LE, reserved = 0)
[12..15] 4 B     Payload length (uint32 LE)
[16..47] 32 B    HMAC-SHA256 of scrambled payload
[48..]   N B     XOR-scrambled ZIP buffer
```

### Security Model

1. **Binary container**: XOR scramble + HMAC-SHA256 (tamper detection, not encryption)
2. **Package signing (v1.0)**: HMAC-SHA256 of ZIP entry hashes (tamper detection only)
3. **Code signing (v2.0)**: Ed25519 publisher certificate + digital signature (OEM verified badge)
4. **OEM author protection**: Restricted author names require password + matching certificate
5. **Access control (GUI)**: Windows security group membership (ALLOW/DENY lists)
6. **Audit trail**: JSON event log with HMAC-SHA256 integrity signatures

### Database (diskdb JSON files)

| Collection | Purpose |
|------------|---------|
| `installed_libs` | Installed library records with metadata, file lists, hashes |
| `groups` | Custom navigation groups (hardcoded defaults are NOT in DB) |
| `tree` | Navigation tree structure (group → library assignments) |
| `links` | Links records + folder path mappings (lib-folder, met-folder) |
| `settings` | Application settings (single record, _id=0) |
| `unsigned_libs` | Scanned unsigned libraries from the VENUS Library folder |
