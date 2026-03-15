The CLI already has everything needed. The `Library-Manager-Packages` repo would include a GitHub Actions workflow that runs your own cli.js to unpack packages and extract metadata. Since shared.js contains all the container constants (scramble key, HMAC key, magic bytes) and cli.js + `adm-zip` are pure Node.js with no native dependencies, it runs perfectly on a GitHub Actions `ubuntu-latest` or `windows-latest` runner.

### How it would work

```
Trigger: push to main (new/updated .hxlibpkg files)
    │
    ▼
GitHub Action runner (Node.js)
    │
    ├── 1. Checkout Library-Manager-Packages repo
    ├── 2. Checkout Library-Manager repo (for cli.js + shared.js + adm-zip)
    ├── 3. npm install (just adm-zip, diskdb — no native deps)
    ├── 4. For each .hxlibpkg in packages/:
    │       ├── unpackContainer() → get ZIP buffer
    │       ├── AdmZip → read manifest.json
    │       ├── Extract metadata fields + library_image_base64
    │       ├── SHA-256 hash the raw .hxlibpkg file
    │       └── Run verifyPackageSignature() → get signing info
    ├── 5. Build catalog.json from collected metadata
    ├── 6. Commit & push updated catalog.json
    └── Done (no temp files survive — the runner is ephemeral)
```

You don't even need to "copy to temp and delete" — GitHub Actions runners are **ephemeral VMs** that are destroyed after each run. Everything is temp by default.

### Example workflow

```yaml
# .github/workflows/build-catalog.yml (in Library-Manager-Packages repo)
name: Build Package Catalog

on:
  push:
    branches: [main]
    paths: ['packages/**']

jobs:
  catalog:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout packages repo
        uses: actions/checkout@v4

      - name: Checkout Library Manager (for cli tools)
        uses: actions/checkout@v4
        with:
          repository: zdmilot/Library-Manager
          path: _tools

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: cd _tools && npm install --production

      - name: Build catalog
        run: node _tools/scripts/build-catalog.js packages/ catalog.json

      - name: Commit catalog
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add catalog.json
          git diff --cached --quiet || git commit -m "Update catalog.json [skip ci]"
          git push
```

### The build-catalog script

You'd add a small script to Library-Manager (e.g., `scripts/build-catalog.js`) that does the extraction. It would reuse your existing code directly:

```js
// scripts/build-catalog.js
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const shared = require('../lib/shared');

const unpackContainer      = shared.unpackContainer;
const CONTAINER_MAGIC_PKG  = shared.CONTAINER_MAGIC_PKG;
const verifyPackageSignature = shared.verifyPackageSignature;

const CATALOG_FIELDS = [
    'library_name', 'author', 'organization', 'version',
    'description', 'tags', 'venus_compatibility', 'created_date',
    'library_image_base64', 'library_image_mime', 'format_version',
    'github_url', 'dependencies'
];

var packagesDir = process.argv[2];
var outputFile  = process.argv[3];
if (!packagesDir || !outputFile) {
    console.error('Usage: node build-catalog.js <packages-dir> <output.json>');
    process.exit(1);
}

var catalog = { catalog_version: '1.0', updated: new Date().toISOString(), packages: [] };

var files = fs.readdirSync(packagesDir).filter(f => f.toLowerCase().endsWith('.hxlibpkg'));

files.forEach(function (filename) {
    var filePath = path.join(packagesDir, filename);
    try {
        var rawBuf  = fs.readFileSync(filePath);
        var zipBuf  = unpackContainer(rawBuf, CONTAINER_MAGIC_PKG);
        var zip     = new AdmZip(zipBuf);
        var me      = zip.getEntry('manifest.json');
        if (!me) { console.warn('SKIP (no manifest): ' + filename); return; }

        var manifest = JSON.parse(me.getData().toString('utf8'));
        var entry = { package_file: 'packages/' + filename };

        // Copy relevant metadata fields
        CATALOG_FIELDS.forEach(function (key) {
            if (manifest[key] !== undefined) entry[key] = manifest[key];
        });

        // File size & hash
        entry.package_size   = rawBuf.length;
        entry.package_sha256 = crypto.createHash('sha256').update(rawBuf).digest('hex');

        // Signature info
        var sigResult = verifyPackageSignature(zip);
        entry.signed      = sigResult.signed;
        entry.code_signed = sigResult.code_signed;
        if (sigResult.code_signed && sigResult.publisher_cert) {
            entry.publisher             = sigResult.publisher_cert.publisher;
            entry.publisher_fingerprint = sigResult.publisher_cert.fingerprint;
        }

        catalog.packages.push(entry);
        console.log('OK: ' + filename);
    } catch (e) {
        console.error('ERROR (' + filename + '): ' + e.message);
    }
});

// Sort by library name for stable diffs
catalog.packages.sort(function (a, b) {
    return (a.library_name || '').localeCompare(b.library_name || '');
});

fs.writeFileSync(outputFile, JSON.stringify(catalog, null, 2));
console.log('Catalog written: ' + catalog.packages.length + ' packages');
```

### Key points

| Concern | Answer |
|---|---|
| **Does the Action need the XOR key / HMAC key?** | Yes, but they're already in shared.js which is in the public Library-Manager repo. The Action just checks out that repo and `require()`s it directly. |
| **Native dependencies?** | None — `adm-zip` and `crypto` are pure JS / built-in Node. Runs on any runner OS. |
| **Temp file cleanup?** | Unnecessary. GitHub Actions runners are ephemeral; destroyed after every run. |
| **Security of extracted data?** | The catalog only contains metadata that the package author already chose to include. The actual library files (HSL, DLLs, etc.) are never extracted. |
| **Incremental vs. full rebuild?** | Full rebuild is simplest and fine for hundreds of packages (takes seconds). You could optimize to incremental later if the catalog gets huge. |
| **`[skip ci]` in commit message?** | Prevents the catalog commit from re-triggering the workflow in an infinite loop. |

### What the client side looks like

On the Library Manager side, you'd add a function in a new marketplace module (or in `updater.js` since it already has the GitHub HTTPS plumbing):

```js
function fetchCatalog() {
    // Single GET to raw.githubusercontent.com
    // Returns the full catalog — one request, all metadata + images
}
```

Then render it in a new Marketplace tab in the UI. When the user clicks "Install", download the `.hxlibpkg` via the `package_file` URL, verify that `SHA-256(downloaded) === entry.package_sha256`, then feed it into the existing import flow.