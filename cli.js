#!/usr/bin/env node
/**
 * Library Manager for Venus 6 CLI  v1.4.8
 * Command-line interface for managing Hamilton VENUS libraries.
 *
 * Author: Zachary Milot
 *
 * Usage:
 *   node cli.js <command> [options]
 *
 * Commands:
 *   list-libs        List installed libraries
 *   import-lib       Import a single .hxlibpkg
 *   import-archive   Import a .hxlibarch (multiple libraries)
 *   export-lib       Export a single installed library as .hxlibpkg
 *   export-archive   Export installed libraries as .hxlibarch
 *   delete-lib       Delete an installed library
 *   create-package   Create a .hxlibpkg from a JSON spec file
 *   list-versions    List cached package versions for a library
 *   rollback-lib     Reinstall a previously cached version of a library
 *   verify-package   Verify integrity signature of a .hxlibpkg or .hxlibarch
 *
 * Run `node cli.js help` for full usage.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const AdmZip = require('adm-zip');
const crypto = require('crypto');
const shared = require('./lib/shared');

// Re-export shared helpers so the rest of the file can use short names
const safeZipExtractPath     = shared.safeZipExtractPath;
const isValidLibraryName     = shared.isValidLibraryName;
const computeZipEntryHashes  = shared.computeZipEntryHashes;
const signPackageZip         = shared.signPackageZip;
const verifyPackageSignature = shared.verifyPackageSignature;
const parseHslMetadataFooter = shared.parseHslMetadataFooter;

// Binary container format helpers
const CONTAINER_MAGIC_PKG    = shared.CONTAINER_MAGIC_PKG;
const CONTAINER_MAGIC_ARC    = shared.CONTAINER_MAGIC_ARC;
const packContainer          = shared.packContainer;
const unpackContainer        = shared.unpackContainer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MIME_MAP = shared.IMAGE_MIME_MAP;

const HSL_METADATA_EXTS = shared.HSL_METADATA_EXTS;

const DEFAULT_LIB_PATH  = 'C:\\Program Files (x86)\\HAMILTON\\Library';
const DEFAULT_MET_PATH  = 'C:\\Program Files (x86)\\HAMILTON\\Methods';

// Package store - persists all imported .hxlibpkg files for repair & rollback
// Now stored under local/packages/ within the app directory
const LOCAL_DATA_DIR = path.join(__dirname, 'local');
const PACKAGE_STORE_DIR = path.join(LOCAL_DATA_DIR, 'packages');

// ---------------------------------------------------------------------------
// Default Groups (hardcoded - never stored in external JSON)
// ---------------------------------------------------------------------------
const DEFAULT_GROUPS = {
    gAll:      { _id: 'gAll',      name: 'All',      'icon-class': 'fa-home',         'default': true, navbar: 'left',  favorite: true  },
    gRecent:   { _id: 'gRecent',   name: 'Recent',   'icon-class': 'fa-history',      'default': true, navbar: 'left',  favorite: true  },
    gFolders:  { _id: 'gFolders',  name: 'Import',   'icon-class': 'fa-download',     'default': true, navbar: 'right', favorite: false },
    gEditors:  { _id: 'gEditors',  name: 'Export',   'icon-class': 'fa-upload',       'default': true, navbar: 'right', favorite: true  },
    gHistory:  { _id: 'gHistory',  name: 'History',  'icon-class': 'fa-list',         'default': true, navbar: 'right', favorite: true  },
    gHamilton: { _id: 'gHamilton', name: 'Hamilton', 'icon-class': 'fa-check-circle', 'default': true, navbar: 'left',  favorite: true, 'protected': true }
};

/**
 * Look up a group by _id.  Hardcoded defaults take priority;
 * falls back to the external groups database (custom groups).
 */
function getGroupById(db, id) {
    if (DEFAULT_GROUPS[id]) return DEFAULT_GROUPS[id];
    try { return db.groups.findOne({ _id: id }); } catch(e) { return null; }
}

// System libraries (Hamilton built-in, read-only)
let _systemLibIds = null;
let _systemLibNames = null;
function loadSystemLibIds() {
    if (_systemLibIds) return _systemLibIds;
    try {
        const sysPath = path.join(__dirname, 'db', 'system_libraries.json');
        const data = JSON.parse(fs.readFileSync(sysPath, 'utf8'));
        _systemLibIds = new Set(data.map(function(e) { return e._id; }));
        _systemLibNames = new Set(data.map(function(e) { return e.canonical_name; }));
    } catch (_) {
        _systemLibIds = new Set();
        _systemLibNames = new Set();
    }
    return _systemLibIds;
}

function loadSystemLibNames() {
    if (_systemLibNames) return _systemLibNames;
    loadSystemLibIds();
    return _systemLibNames;
}

function isSystemLibrary(libId) {
    return loadSystemLibIds().has(libId);
}

function isSystemLibraryByName(libName) {
    return loadSystemLibNames().has(libName);
}

// ---------------------------------------------------------------------------
// Restricted Author Protection
// ---------------------------------------------------------------------------
// Password required to use "Hamilton" (case-insensitive) as author on
// non-system packages. Prevents spoofing and acts as an additional signing
// mechanism for first-party libraries.
//
// The password is stored as a SHA-256 hash to avoid exposing the plaintext
// in source control.  Comparison uses crypto.timingSafeEqual to resist
// timing side-channel analysis.
const HAMILTON_AUTHOR_PASSWORD_HASH = 'bbdc525497de1c19c57767e36b4f01dadcc05348664eea071ac984fd955bc207';

/**
 * Check if an author name is restricted (i.e. "Hamilton" in any case).
 */
function isRestrictedAuthor(author) {
    if (!author) return false;
    return author.trim().toLowerCase() === 'hamilton';
}

/**
 * Validate CLI --author-password against the restricted author password.
 * Uses SHA-256 hashing and timing-safe comparison.
 */
function validateAuthorPassword(password) {
    if (!password || typeof password !== 'string') return false;
    var inputHash  = crypto.createHash('sha256').update(password).digest();
    var storedHash = Buffer.from(HAMILTON_AUTHOR_PASSWORD_HASH, 'hex');
    try {
        return crypto.timingSafeEqual(inputHash, storedHash);
    } catch (_) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Minimal argument parser
// Supports:  --flag           (boolean true)
//            --key value      (string)
//            --key=value      (string, alternate form)
// ---------------------------------------------------------------------------
function parseArgs(argv) {
    const args = { _: [] };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg.startsWith('--')) {
            // Handle --key=value form
            const eqIdx = arg.indexOf('=');
            if (eqIdx !== -1) {
                const key = arg.slice(2, eqIdx);
                args[key] = arg.slice(eqIdx + 1);
                continue;
            }
            const key  = arg.slice(2);
            const next = argv[i + 1];
            if (next !== undefined && !next.startsWith('--')) {
                args[key] = next;
                i++;
            } else {
                args[key] = true;
            }
        } else if (arg.startsWith('-') && arg.length === 2) {
            // Short flags: -h, -y, etc.
            args[arg.slice(1)] = true;
        } else {
            args._.push(arg);
        }
    }
    return args;
}

// ---------------------------------------------------------------------------
// Environment / identity helpers
// ---------------------------------------------------------------------------

/**
 * Get the current Windows username.
 * Uses os.userInfo() or falls back to environment variables.
 */
function getWindowsUsername() {
    try {
        return os.userInfo().username || process.env.USERNAME || process.env.USER || 'Unknown';
    } catch (_) {
        return process.env.USERNAME || process.env.USER || 'Unknown';
    }
}

/**
 * Get a concise Windows version string (e.g. "Windows_NT 10.0.19045 x64").
 */
function getWindowsVersion() {
    try {
        return os.type() + ' ' + os.release() + ' (' + os.arch() + ')';
    } catch (_) {
        return 'Unknown';
    }
}

/**
 * Query the Windows registry for the Hamilton VENUS software version.
 * Returns the version string (e.g. "6.2.2.4006") or null.
 */
function getVENUSVersion() {
    try {
        const execSync = require('child_process').execSync;
        const regPaths = [
            'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        ];
        for (const rp of regPaths) {
            try {
                const subkeysRaw = execSync('reg query "' + rp + '"', { encoding: 'utf8', timeout: 10000 });
                const subkeys = subkeysRaw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
                for (const sk of subkeys) {
                    try {
                        const entryRaw = execSync('reg query "' + sk + '" /v DisplayName', { encoding: 'utf8', timeout: 5000 });
                        if (!/Hamilton\s+VENUS\s+\d/i.test(entryRaw)) continue;
                        const allVals = execSync('reg query "' + sk + '"', { encoding: 'utf8', timeout: 5000 });
                        const verMatch = allVals.match(/DisplayVersion\s+REG_SZ\s+(.+)/i);
                        if (verMatch) return verMatch[1].trim();
                    } catch (_) { /* skip subkey */ }
                }
            } catch (_) { /* skip registry path */ }
        }
    } catch (_) { /* registry query failed */ }
    return null;
}

// ---------------------------------------------------------------------------
// Audit trail logging
// ---------------------------------------------------------------------------

/**
 * Append an entry to the audit trail JSON log stored in the user data directory.
 * The audit trail records packaging, import, and other lifecycle events with
 * environmental context (Windows version, VENUS version, username) for
 * traceability purposes.
 *
 * @param {string} userDataDir - Path to the user data directory
 * @param {object} entry       - Audit trail entry object
 */
function appendAuditTrailEntry(userDataDir, entry) {
    try {
        var filePath = path.join(userDataDir, 'audit_trail.json');
        var trail = [];
        if (fs.existsSync(filePath)) {
            try {
                trail = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                if (!Array.isArray(trail)) trail = [];
            } catch (_) {
                trail = [];
            }
        }
        trail.push(entry);

        // Rotate audit trail when it exceeds 10,000 entries to prevent unbounded growth
        var MAX_AUDIT_ENTRIES = 10000;
        if (trail.length > MAX_AUDIT_ENTRIES) {
            var archivePath = filePath.replace(/\.json$/, '_' + new Date().toISOString().replace(/[:.]/g, '-') + '.json');
            try {
                fs.writeFileSync(archivePath, JSON.stringify(trail.slice(0, trail.length - MAX_AUDIT_ENTRIES), null, 2), 'utf8');
            } catch (_) { /* rotation archive is best-effort */ }
            trail = trail.slice(trail.length - MAX_AUDIT_ENTRIES);
        }

        fs.writeFileSync(filePath, JSON.stringify(trail, null, 2), 'utf8');
    } catch (e) {
        process.stderr.write('  Warning: could not write audit trail entry: ' + e.message + '\n');
    }
}

/**
 * Build a standard audit trail entry with common environmental fields.
 *
 * @param {string} eventType    - e.g. "package_created", "library_imported", "archive_imported"
 * @param {object} details      - Event-specific details (library_name, version, etc.)
 * @returns {object} Complete audit trail entry
 */
function buildAuditTrailEntry(eventType, details) {
    return {
        event:            eventType,
        timestamp:        new Date().toISOString(),
        username:         getWindowsUsername(),
        windows_version:  getWindowsVersion(),
        venus_version:    getVENUSVersion() || 'N/A',
        hostname:         os.hostname(),
        details:          details || {}
    };
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/**
 * Legacy: Connect diskdb to the given directory with all collections.
 * Returns a db object with collections: installed_libs, links, groups, settings, tree.
 */
function connectDB(dbDir) {
    const diskdb = require('diskdb');
    return diskdb.connect(dbDir, ['installed_libs', 'links', 'groups', 'settings', 'tree']);
}

/**
 * Resolve the data directory from CLI args or local/ default.
 * Priority: --db-path flag > local/ directory
 * Also ensures the directory exists with seed files.
 */
function resolveDBPath(args) {
    let dbPath;
    if (args['db-path']) {
        dbPath = path.resolve(args['db-path']);
    } else {
        dbPath = LOCAL_DATA_DIR;
    }
    ensureLocalDataDir(dbPath);
    return dbPath;
}

/**
 * Ensure local data directory exists with seed files and subdirectories.
 */
function ensureLocalDataDir(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
    // Ensure subdirectories
    ['packages', 'exports'].forEach(function(sub) {
        const subPath = path.join(dirPath, sub);
        if (!fs.existsSync(subPath)) {
            fs.mkdirSync(subPath, { recursive: true });
        }
    });
    const seeds = {
        'settings.json': '[{"_id":"0"}]',
        'installed_libs.json': '[]',
        'groups.json': '[]',
        'tree.json': '[{"group-id":"gAll","method-ids":[],"locked":false},{"group-id":"gRecent","method-ids":[],"locked":false},{"group-id":"gFolders","method-ids":[],"locked":false},{"group-id":"gEditors","method-ids":[],"locked":false},{"group-id":"gHistory","method-ids":[],"locked":false},{"group-id":"gHamilton","method-ids":[],"locked":true}]',
        'links.json': '[]'
    };
    for (const [fname, content] of Object.entries(seeds)) {
        const fpath = path.join(dirPath, fname);
        if (!fs.existsSync(fpath)) {
            fs.writeFileSync(fpath, content, 'utf8');
        }
    }
}

/**
 * Warn if a path points to a system-critical directory.
 */
function warnIfSystemPath(dirPath, label) {
    const resolved = path.resolve(dirPath).toLowerCase();
    const dangerous = ['c:\\windows', 'c:\\program files\\windows', 'c:\\system'];
    for (const prefix of dangerous) {
        if (resolved.startsWith(prefix)) {
            process.stderr.write(`  WARNING: ${label} points to a system-critical location: ${dirPath}\n`);
            return;
        }
    }
}

/**
 * Get library/methods root install paths from DB settings (or overrides).
 */
function getInstallPaths(db, libDirOverride, metDirOverride) {
    let libBasePath = DEFAULT_LIB_PATH;
    let metBasePath = DEFAULT_MET_PATH;

    if (libDirOverride) {
        libBasePath = libDirOverride;
        warnIfSystemPath(libBasePath, '--lib-dir');
    } else {
        try {
            const rec = db.links.findOne({ _id: 'lib-folder' });
            if (rec && rec.path) libBasePath = rec.path;
        } catch (_) {}
    }

    if (metDirOverride) {
        metBasePath = metDirOverride;
        warnIfSystemPath(metBasePath, '--met-dir');
    } else {
        try {
            const rec = db.links.findOne({ _id: 'met-folder' });
            if (rec && rec.path) metBasePath = rec.path;
        } catch (_) {}
    }

    return { libBasePath, metBasePath };
}

// ---------------------------------------------------------------------------
// Integrity hashing
// ---------------------------------------------------------------------------

/**
 * Parse the Hamilton HSL metadata footer from the last non-empty line of a file.
 * Footer format: // $$author=NAME$$valid=0|1$$time=TIMESTAMP$$checksum=HEX$$length=NNN$$
 *
 * The $$valid=1$$ flag marks a file as Hamilton-validated/protected.
 * The $$checksum$$ is Hamilton's own CRC computed over the file body.
 * Together these form the authoritative integrity indicator for system libraries.
 *
 * @param {string} filePath - full path to the file
 * @returns {Object|null} { author, valid, time, checksum, length, raw } or null
 */
// parseHslMetadataFooter is imported from shared module above



// computeLibraryHashes is imported from shared module
const computeLibraryHashes = shared.computeLibraryHashes;

// ---------------------------------------------------------------------------
// Package signing - HMAC-SHA256 integrity signatures for .hxlibpkg files
// ---------------------------------------------------------------------------

// computeZipEntryHashes, signPackageZip, verifyPackageSignature are
// imported from the shared module above.

// ---------------------------------------------------------------------------
// HSL function parser - extracts public function signatures from .hsl files
// Ported from the VS Code HSL IntelliSense extension.
// ---------------------------------------------------------------------------

/**
 * Strip string literals and comments from HSL source so that keyword searches
 * (namespace, function) are not confused by content inside strings / comments.
 */
function sanitizeHslForParsing(text) {
    const chars = text.split('');
    let i = 0;
    while (i < chars.length) {
        const ch = chars[i];
        const next = (i + 1 < chars.length) ? chars[i + 1] : '';

        // String literal
        if (ch === '"') {
            chars[i] = ' ';
            let j = i + 1;
            while (j < chars.length) {
                const c = chars[j];
                if (c === '\\' && j + 1 < chars.length) {
                    chars[j] = ' '; chars[j + 1] = ' '; j += 2; continue;
                }
                chars[j] = (c === '\n' || c === '\r') ? c : ' ';
                if (c === '"') { j++; break; }
                j++;
            }
            i = j; continue;
        }
        // Line comment
        if (ch === '/' && next === '/') {
            chars[i] = ' '; chars[i + 1] = ' '; i += 2;
            while (i < chars.length && chars[i] !== '\n') { chars[i] = ' '; i++; }
            continue;
        }
        // Block comment
        if (ch === '/' && next === '*') {
            chars[i] = ' '; chars[i + 1] = ' '; i += 2;
            while (i < chars.length) {
                if (chars[i] === '*' && i + 1 < chars.length && chars[i + 1] === '/') {
                    chars[i] = ' '; chars[i + 1] = ' '; i += 2; break;
                }
                chars[i] = (chars[i] === '\n' || chars[i] === '\r') ? chars[i] : ' ';
                i++;
            }
            continue;
        }
        i++;
    }
    return chars.join('');
}

/**
 * Split a comma-separated parameter list respecting nested parentheses.
 */
function splitHslArgs(paramList) {
    const parts = [];
    let current = '';
    let depth = 0;
    for (let ci = 0; ci < paramList.length; ci++) {
        const c = paramList[ci];
        if (c === '(') { depth++; current += c; continue; }
        if (c === ')') { depth = Math.max(0, depth - 1); current += c; continue; }
        if (c === ',' && depth === 0) { parts.push(current.trim()); current = ''; continue; }
        current += c;
    }
    if (current.trim().length > 0) parts.push(current.trim());
    return parts;
}

/**
 * Parse a single HSL parameter string like "variable& name[]" into a descriptor.
 */
function parseHslParameter(param) {
    const trimmed = param.trim();
    const rawNoDefault = trimmed.indexOf('=') !== -1 ? trimmed.slice(0, trimmed.indexOf('=')).trim() : trimmed;
    const isArray = /\[\]\s*$/.test(rawNoDefault);
    const noArray = rawNoDefault.replace(/\[\]\s*$/, '').trim();
    const nameMatch = /([A-Za-z_]\w*)\s*$/.exec(noArray);
    const nameText = nameMatch ? nameMatch[1] : noArray;
    let beforeName = nameMatch ? noArray.slice(0, nameMatch.index).trim() : '';
    const isByRef = beforeName.indexOf('&') !== -1;
    beforeName = beforeName.replace(/&/g, '').trim();
    return {
        type: beforeName || 'variable',
        name: nameText,
        byRef: isByRef,
        array: isArray
    };
}

/**
 * Extract the doc-comment block immediately above a function definition.
 */
function extractHslDocComment(originalLines, functionStartLine) {
    let i = functionStartLine - 1;
    while (i >= 0 && originalLines[i].trim() === '') i--;
    if (i < 0) return '';

    const line = originalLines[i].trim();
    // Single-line comment block
    if (line.indexOf('//') === 0) {
        const buf = [];
        while (i >= 0 && originalLines[i].trim().indexOf('//') === 0) {
            buf.push(originalLines[i].trim().replace(/^\/\/\s?/, ''));
            i--;
        }
        buf.reverse();
        return buf.join('\n').trim();
    }
    // Block comment
    if (line.indexOf('*/') !== -1) {
        const buf = [];
        while (i >= 0) {
            buf.push(originalLines[i]);
            if (originalLines[i].indexOf('/*') !== -1) break;
            i--;
        }
        buf.reverse();
        return buf.join('\n')
            .replace(/^\s*\/\*+/, '')
            .replace(/\*+\/\s*$/, '')
            .split(/\r?\n/)
            .map(function(s) { return s.replace(/^\s*\*\s?/, ''); })
            .join('\n')
            .trim();
    }
    return '';
}

/**
 * Parse all public functions from an HSL source string.
 * Returns an array of { name, qualifiedName, params, returnType, doc, isPrivate }.
 * params is an array of { type, name, byRef, array }.
 */
function parseHslFunctions(text, fileName) {
    const sanitized = sanitizeHslForParsing(text);
    const originalLines = text.split(/\r?\n/);
    const cleanLines = sanitized.split(/\r?\n/);
    const functions = [];

    const namespaceStack = [];
    let braceDepth = 0;
    let pendingNamespace = null;

    let collectingFunction = false;
    let functionStartLine = -1;
    let functionHeaderParts = [];

    for (let lineIndex = 0; lineIndex < cleanLines.length; lineIndex++) {
        const cleanLine = cleanLines[lineIndex];
        const originalLine = originalLines[lineIndex] || '';

        if (!collectingFunction) {
            const nsMatch = /^\s*(?:(?:private|public|static|global|const|synchronized)\s+)*namespace\s+([A-Za-z_]\w*)\b/.exec(cleanLine);
            if (nsMatch) {
                pendingNamespace = nsMatch[1];
            }
            if (/^\s*(?:(?:private|public|static|global|const|synchronized)\s+)*function\b/.test(cleanLine)) {
                collectingFunction = true;
                functionStartLine = lineIndex;
                functionHeaderParts = [originalLine];
            }
        } else {
            functionHeaderParts.push(originalLine);
        }

        if (collectingFunction) {
            const joinedClean = sanitizeHslForParsing(functionHeaderParts.join('\n'));
            const openCount  = (joinedClean.match(/\(/g) || []).length;
            const closeCount = (joinedClean.match(/\)/g) || []).length;
            const parenDelta = openCount - closeCount;
            const hasTerminator = /[;{]/.test(joinedClean);
            if (parenDelta <= 0 && hasTerminator) {
                const joinedOriginal = functionHeaderParts.join('\n');
                const fnMatch = /^\s*((?:(?:private|public|static|global|const|synchronized)\s+)*)function\s+([A-Za-z_]\w*)\s*\(([\s\S]*?)\)\s*([A-Za-z_]\w*)\s*(?:;|\{)/m.exec(joinedOriginal);
                if (fnMatch) {
                    const modifiers = fnMatch[1] || '';
                    const name = fnMatch[2];
                    const paramsRaw = fnMatch[3] || '';
                    const returnType = fnMatch[4] || 'variable';
                    const isPrivate = /\bprivate\b/.test(modifiers);

                    const params = splitHslArgs(paramsRaw)
                        .filter(function(p) { return p.length > 0; })
                        .map(parseHslParameter);

                    const nsPrefix = namespaceStack.map(function(n) { return n.name; }).join('::');
                    const qualifiedName = nsPrefix.length > 0 ? nsPrefix + '::' + name : name;
                    const doc = extractHslDocComment(originalLines, functionStartLine);

                    functions.push({
                        name:          name,
                        qualifiedName: qualifiedName,
                        params:        params,
                        returnType:    returnType,
                        doc:           doc,
                        isPrivate:     isPrivate,
                        file:          fileName || ''
                    });
                }
                collectingFunction = false;
                functionStartLine = -1;
                functionHeaderParts = [];
            }
        }

        // Track brace depth for namespace scoping
        for (let ci = 0; ci < cleanLine.length; ci++) {
            const ch = cleanLine[ci];
            if (ch === '{') {
                braceDepth++;
                if (pendingNamespace) {
                    namespaceStack.push({ name: pendingNamespace, depth: braceDepth });
                    pendingNamespace = null;
                }
            } else if (ch === '}') {
                while (namespaceStack.length > 0 && namespaceStack[namespaceStack.length - 1].depth >= braceDepth) {
                    namespaceStack.pop();
                }
                braceDepth = Math.max(0, braceDepth - 1);
            }
        }
    }
    return functions;
}

/**
 * Extract public functions from all .hsl files in the given directory.
 * Returns an array of function descriptors suitable for storing in the DB.
 */
function extractPublicFunctions(libFiles, libBasePath) {
    const allFunctions = [];
    libFiles.forEach(function(fname) {
        const ext = path.extname(fname).toLowerCase();
        if (ext !== '.hsl') return;
        const fullPath = path.join(libBasePath, fname);
        try {
            const text = fs.readFileSync(fullPath, 'utf8');
            const fns = parseHslFunctions(text, fname);
            fns.forEach(function(fn) {
                if (!fn.isPrivate) {
                    allFunctions.push({
                        name:          fn.name,
                        qualifiedName: fn.qualifiedName,
                        params:        fn.params,
                        returnType:    fn.returnType,
                        doc:           fn.doc,
                        file:          fn.file
                    });
                }
            });
        } catch (_) { /* skip unreadable files */ }
    });
    return allFunctions;
}

/**
 * Extract #include directives from HSL source text.
 */
function extractHslIncludes(text) {
    const includes = [];
    const pattern = /^\s*#include\s+"([^"]+)"/gm;
    let m;
    while ((m = pattern.exec(text)) !== null) {
        includes.push(m[1].trim());
    }
    return includes;
}

/**
 * Extract required dependencies from a library's .hsl files.
 * Returns a deduplicated list of include targets that are external to this library.
 */
function extractRequiredDependencies(libFiles, libBasePath) {
    const ownFiles = {};
    (libFiles || []).forEach(function(f) {
        ownFiles[f.toLowerCase()] = true;
        ownFiles[path.basename(f).toLowerCase()] = true;
    });

    const allIncludes = [];
    (libFiles || []).forEach(function(fname) {
        const ext = path.extname(fname).toLowerCase();
        if (ext !== '.hsl' && ext !== '.hs_') return;
        const fullPath = path.join(libBasePath, fname);
        try {
            const text = fs.readFileSync(fullPath, 'utf8');
            extractHslIncludes(text).forEach(function(inc) {
                allIncludes.push({ include: inc, sourceFile: fname });
            });
        } catch (_) { /* skip unreadable files */ }
    });

    // Deduplicate
    const seen = {};
    const dependencies = [];
    allIncludes.forEach(function(item) {
        const normalized = item.include.replace(/\\/g, '/').toLowerCase();
        if (seen[normalized]) return;
        seen[normalized] = true;
        const targetFileName = normalized.split('/').pop();
        if (ownFiles[targetFileName]) return; // skip self-references
        dependencies.push({
            include:     item.include,
            sourceFile:  item.sourceFile,
            libraryName: null,
            type:        'unknown'
        });
    });
    return dependencies;
}

// ---------------------------------------------------------------------------
// Group auto-assignment
// ---------------------------------------------------------------------------

function autoAddToGroup(db, savedLibId, authorName) {
    try {
        const navtree = db.tree.find();
        let targetGroupId = null;

        // If author is Hamilton, auto-assign to the Hamilton group
        if (isRestrictedAuthor(authorName)) {
            let hamiltonTreeEntry = null;
            for (let i = 0; i < navtree.length; i++) {
                if (navtree[i]['group-id'] === 'gHamilton') {
                    hamiltonTreeEntry = navtree[i];
                    break;
                }
            }
            if (hamiltonTreeEntry) {
                targetGroupId = 'gHamilton';
                const ids = hamiltonTreeEntry['method-ids'] || [];
                ids.push(savedLibId);
                db.tree.update(
                    { 'group-id': 'gHamilton' },
                    { 'method-ids': ids },
                    { multi: false, upsert: false }
                );
            } else {
                // Hamilton group is hardcoded; just create the tree entry
                db.tree.save({
                    'group-id': 'gHamilton',
                    'method-ids': [savedLibId],
                    locked: true
                });
                targetGroupId = 'gHamilton';
            }
        } else {
            // Non-Hamilton: add to first custom group
            for (let i = 0; i < navtree.length; i++) {
                const gEntry = getGroupById(db, navtree[i]['group-id']);
                if (gEntry && !gEntry['default']) {
                    targetGroupId = navtree[i]['group-id'];
                    const ids = navtree[i]['method-ids'] || [];
                    ids.push(savedLibId);
                    db.tree.update(
                        { 'group-id': targetGroupId },
                        { 'method-ids': ids },
                        { multi: false, upsert: false }
                    );
                    break;
                }
            }
        }

        if (!targetGroupId) {
            const newGroup = db.groups.save({
                name: 'Libraries',
                'icon-class': 'fa-book',
                'default': false,
                navbar: 'left',
                favorite: true
            });
            db.tree.save({
                'group-id': newGroup._id,
                'method-ids': [savedLibId],
                locked: false
            });
        }
    } catch (e) {
        process.stderr.write('  Warning: could not auto-assign to group: ' + e.message + '\n');
    }
}

// ---------------------------------------------------------------------------
// Core: install a single parsed package into the filesystem + DB
// ---------------------------------------------------------------------------

/**
 * @param {object}  manifest   - Parsed manifest.json content
 * @param {AdmZip}  zip        - AdmZip instance for the .hxlibpkg
 * @param {string}  libDestDir - Target library directory on disk
 * @param {string}  demoDestDir- Target demo methods directory on disk
 * @param {string}  sourceName - Name of the source .hxlibpkg / archive entry
 * @param {object}  db         - Connected diskdb instance
 * @param {boolean} skipGroup  - If true, skip auto-group assignment
 * @returns {{ extractedCount: number, libName: string }}
 */
function installPackage(manifest, zip, libDestDir, demoDestDir, sourceName, db, skipGroup) {
    const libFiles  = manifest.library_files     || [];
    const demoFiles = manifest.demo_method_files || [];
    const comDlls   = manifest.com_register_dlls || [];

    // Auto-detect .chm help files: separate them from library_files
    // Also check manifest.help_files for packages that already have them declared
    const declaredHelp = manifest.help_files || [];
    const helpFiles = declaredHelp.slice();
    const filteredLibFiles = [];
    libFiles.forEach(function (f) {
        if (path.extname(f).toLowerCase() === '.chm') {
            if (helpFiles.indexOf(f) === -1) helpFiles.push(f);
        } else {
            filteredLibFiles.push(f);
        }
    });

    // Ensure destination directories exist
    if ((filteredLibFiles.length > 0 || helpFiles.length > 0) && !fs.existsSync(libDestDir)) {
        fs.mkdirSync(libDestDir, { recursive: true });
    }
    if (demoFiles.length > 0 && !fs.existsSync(demoDestDir)) {
        fs.mkdirSync(demoDestDir, { recursive: true });
    }

    // Extract payload files - CHM files are extracted to the library directory
    let extractedCount = 0;
    zip.getEntries().forEach(function (entry) {
        if (entry.isDirectory || entry.entryName === 'manifest.json' || entry.entryName === 'signature.json') return;

        if (entry.entryName.startsWith('library/')) {
            const fname = entry.entryName.substring('library/'.length);
            if (fname) {
                const safePath = safeZipExtractPath(libDestDir, fname);
                if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
                const parentDir = path.dirname(safePath);
                if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
                fs.writeFileSync(safePath, entry.getData());
                extractedCount++;
            }
        } else if (entry.entryName.startsWith('demo_methods/')) {
            const fname = entry.entryName.substring('demo_methods/'.length);
            if (fname) {
                const safePath = safeZipExtractPath(demoDestDir, fname);
                if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
                const parentDir = path.dirname(safePath);
                if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
                fs.writeFileSync(safePath, entry.getData());
                extractedCount++;
            }
        } else if (entry.entryName.startsWith('help_files/')) {
            // Legacy/explicit help_files folder - extract to library directory
            const fname = entry.entryName.substring('help_files/'.length);
            if (fname) {
                const safePath = safeZipExtractPath(libDestDir, fname);
                if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
                const parentDir = path.dirname(safePath);
                if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
                fs.writeFileSync(safePath, entry.getData());
                extractedCount++;
            }
        }
        // icon/ entries are not extracted to disk - they remain embedded in manifest base64
    });

    // Upsert DB record - remove old entry if it exists
    const existing = db.installed_libs.findOne({ library_name: manifest.library_name });
    if (existing) {
        db.installed_libs.remove({ _id: existing._id });
    }

    const fileHashes = computeLibraryHashes(filteredLibFiles, libDestDir, comDlls);

    // Parse public functions from .hsl files for indexing & display
    const publicFunctions = extractPublicFunctions(filteredLibFiles, libDestDir);

    // Extract required dependencies from #include directives
    const requiredDependencies = extractRequiredDependencies(filteredLibFiles, libDestDir);

    const dbRecord = {
        library_name:        manifest.library_name        || '',
        author:              manifest.author               || '',
        organization:        manifest.organization         || '',
        version:             manifest.version              || '',
        venus_compatibility: manifest.venus_compatibility  || '',
        description:         manifest.description          || '',
        github_url:          manifest.github_url           || '',
        tags:                manifest.tags                 || [],
        created_date:        manifest.created_date         || '',
        library_image:       manifest.library_image        || null,
        library_image_base64:manifest.library_image_base64 || null,
        library_image_mime:  manifest.library_image_mime   || null,
        library_files:       filteredLibFiles,
        demo_method_files:   demoFiles,
        help_files:          helpFiles,
        com_register_dlls:   comDlls,
        com_warning:         false,
        lib_install_path:    libDestDir,
        demo_install_path:   demoDestDir,
        installed_date:      new Date().toISOString(),
        installed_by:        getWindowsUsername(),
        source_package:      sourceName,
        file_hashes:         fileHashes,
        public_functions:    publicFunctions,
        required_dependencies: requiredDependencies
    };

    const saved = db.installed_libs.save(dbRecord);

    if (!skipGroup) {
        autoAddToGroup(db, saved._id, manifest.author);
    }

    return { extractedCount, libName: manifest.library_name };
}

// ---------------------------------------------------------------------------
// Helper: ensure parent directory exists for an output file
// ---------------------------------------------------------------------------
function ensureOutDir(filePath) {
    const dir = path.dirname(path.resolve(filePath));
    if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// Package store helpers - cache .hxlibpkg files for repair & version rollback
// ---------------------------------------------------------------------------

/**
 * Resolve the package store root directory.
 * Uses --store-dir override if provided, otherwise the default under local/packages.
 */
function getPackageStoreDir(args) {
    if (args && args['store-dir']) return path.resolve(args['store-dir']);
    return PACKAGE_STORE_DIR;
}

/**
 * Build a deterministic filename for a cached package:
 *   <LibraryName>_v<version>_<YYYYMMDD-HHmmss>.hxlibpkg
 */
function buildCachedPackageName(libName, version) {
    const safe   = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
    const ver    = (version || '0.0.0').replace(/[<>:"\/\\|?*]/g, '_');
    const now    = new Date();
    const stamp  = now.getFullYear().toString()
                 + String(now.getMonth() + 1).padStart(2, '0')
                 + String(now.getDate()).padStart(2, '0')
                 + '-'
                 + String(now.getHours()).padStart(2, '0')
                 + String(now.getMinutes()).padStart(2, '0')
                 + String(now.getSeconds()).padStart(2, '0');
    return safe + '_v' + ver + '_' + stamp + '.hxlibpkg';
}

/**
 * Cache a .hxlibpkg buffer (or file) into the package store.
 * Organises into subdirectories by library name.
 *
 * @param {Buffer}  pkgBuffer   - Raw bytes of the .hxlibpkg file
 * @param {string}  libName     - Library name from the manifest
 * @param {string}  version     - Version string from the manifest
 * @param {object}  [args]      - CLI args (optional, for --store-dir override)
 * @returns {string} The full path where the package was stored
 */
function cachePackage(pkgBuffer, libName, version, args) {
    const storeRoot = getPackageStoreDir(args);
    const safeName  = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
    const libDir    = path.join(storeRoot, safeName);

    if (!fs.existsSync(libDir)) {
        fs.mkdirSync(libDir, { recursive: true });
    }

    const fileName  = buildCachedPackageName(libName, version);
    const destPath  = path.join(libDir, fileName);
    fs.writeFileSync(destPath, pkgBuffer);
    return destPath;
}

/**
 * List all cached package versions for a given library name.
 * Returns an array of { file, version, date, fullPath } sorted newest-first.
 */
function listCachedVersions(libName, args) {
    const storeRoot = getPackageStoreDir(args);
    const safeName  = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
    const libDir    = path.join(storeRoot, safeName);

    if (!fs.existsSync(libDir)) return [];

    const files = fs.readdirSync(libDir)
        .filter(function (f) { return f.toLowerCase().endsWith('.hxlibpkg'); });

    const entries = files.map(function (f) {
        const fullPath = path.join(libDir, f);
        // Try to read manifest for accurate version info
        var version = '?';
        var createdDate = '';
        var author = '';
        try {
            var rawBuf = fs.readFileSync(fullPath);
            var zipBuf = unpackContainer(rawBuf, CONTAINER_MAGIC_PKG);
            var zip = new AdmZip(zipBuf);
            var me  = zip.getEntry('manifest.json');
            if (me) {
                var m = JSON.parse(zip.readAsText(me));
                version     = m.version      || '?';
                createdDate = m.created_date  || '';
                author      = m.author        || '';
            }
        } catch (_) {}

        var stat = fs.statSync(fullPath);
        return {
            file:       f,
            version:    version,
            author:     author,
            created:    createdDate,
            cached:     stat.mtime.toISOString(),
            size:       stat.size,
            fullPath:   fullPath
        };
    });

    // Sort newest cached first
    entries.sort(function (a, b) { return b.cached.localeCompare(a.cached); });
    return entries;
}

// ---------------------------------------------------------------------------
// Helper: find a library record by --name or --id
// ---------------------------------------------------------------------------
function findLibrary(db, args) {
    if (args.id) {
        return db.installed_libs.findOne({ _id: args.id });
    } else if (args.name) {
        return db.installed_libs.findOne({ library_name: args.name });
    }
    return null;
}

// ===========================================================================
// COMMAND: list-libs
// ===========================================================================
function cmdListLibs(args) {
    const db = connectDB(resolveDBPath(args));
    const includeDeleted = !!(args['include-deleted']);
    const asJson         = !!(args['json'] || args['j']);

    let libs = db.installed_libs.find() || [];
    if (!includeDeleted) libs = libs.filter(l => !l.deleted);

    if (asJson) {
        console.log(JSON.stringify(libs, null, 2));
        return;
    }

    if (libs.length === 0) {
        console.log('No installed libraries found.');
        return;
    }

    const line = '-'.repeat(64);
    console.log('\nInstalled Libraries');
    console.log('='.repeat(64));
    libs.forEach(function (lib) {
        const status = lib.deleted ? ` [DELETED ${lib.deleted_date || ''}]` : '';
        console.log(`  ID:          ${lib._id}`);
        console.log(`  Name:        ${lib.library_name || '(unknown)'}${status}`);
        console.log(`  Version:     ${lib.version      || '-'}`);
        console.log(`  Author:      ${lib.author        || '-'}`);
        console.log(`  Tags:        ${(lib.tags || []).join(', ') || '-'}`);
        console.log(`  Lib path:    ${lib.lib_install_path  || '-'}`);
        console.log(`  Demo path:   ${lib.demo_install_path || '-'}`);
        console.log(`  Installed:   ${lib.installed_date    || '-'}`);
        console.log(`  Installed By: ${lib.installed_by      || '-'}`);
        if ((lib.com_register_dlls || []).length > 0)
            console.log(`  COM DLLs:    ${lib.com_register_dlls.join(', ')}`);
        const pubFns = lib.public_functions || [];
        if (pubFns.length > 0) {
            console.log(`  Functions (${pubFns.length}):`);
            pubFns.forEach(function(fn) {
                const paramStr = (fn.params || []).map(function(p) {
                    return (p.type || 'variable') + (p.byRef ? '& ' : ' ') + p.name + (p.array ? '[]' : '');
                }).join(', ');
                console.log(`    ${fn.qualifiedName}(${paramStr}) ${fn.returnType || 'void'}`);
            });
        }
        console.log(line);
    });
    console.log(`Total: ${libs.length} librar${libs.length === 1 ? 'y' : 'ies'}`);
}

// ===========================================================================
// COMMAND: import-lib
// ===========================================================================
function cmdImportLib(args) {
    const filePath = args['file'];
    if (!filePath)               { die('--file is required'); }
    if (!fs.existsSync(filePath)) { die('File not found: ' + filePath); }

    const db = connectDB(resolveDBPath(args));
    const { libBasePath, metBasePath } = getInstallPaths(db, args['lib-dir'], args['met-dir']);

    console.log('Importing: ' + filePath);

    let zip, manifest;
    try {
        var rawPkgBuf = fs.readFileSync(filePath);
        var zipBuf = unpackContainer(rawPkgBuf, CONTAINER_MAGIC_PKG);
        zip = new AdmZip(zipBuf);
        const me = zip.getEntry('manifest.json');
        if (!me) die('Invalid package: manifest.json not found');
        manifest = JSON.parse(zip.readAsText(me));
    } catch (e) {
        die('Failed to read package: ' + e.message);
    }

    // ---- Verify package signature ----
    const sigResult = verifyPackageSignature(zip);
    if (sigResult.signed) {
        if (sigResult.valid) {
            console.log('  Signature: VALID');
        } else {
            console.log('  Signature: FAILED');
            sigResult.errors.forEach(e => process.stderr.write('    ' + e + '\n'));
            if (!args['force']) {
                die('Package signature verification failed. Use --force to import anyway.');
            }
            console.log('  WARNING: Importing despite failed signature (--force)');
        }
    } else {
        console.log('  Signature: unsigned (legacy package)');
    }

    const libName = manifest.library_name || 'Unknown';

    // ---- Library name validation (matches GUI behaviour) ----
    if (!isValidLibraryName(libName)) {
        die('Invalid library name: "' + libName + '". Library names cannot contain path separators, \'..\', trailing dots/spaces, or reserved characters.');
    }

    // ---- Restricted author check ----
    // If the package claims "Hamilton" as author or organization but is NOT a known system library,
    // require --author-password for authorization
    const importAuthor = (manifest.author || '').trim();
    const importOrg = (manifest.organization || '').trim();
    if ((isRestrictedAuthor(importAuthor) || isRestrictedAuthor(importOrg)) && !isSystemLibraryByName(libName)) {
        if (!args['author-password']) {
            die('This package uses the restricted author name "Hamilton". Use --author-password <password> to authorize.');
        }
        if (!validateAuthorPassword(args['author-password'])) {
            die('Incorrect author password. Import of Hamilton-authored packages requires valid authorization.');
        }
    }

    // Check for existing installation
    const existing = db.installed_libs.findOne({ library_name: libName });
    if (existing && !existing.deleted && !args['force']) {
        die(`Library "${libName}" is already installed. Use --force to overwrite.`);
    }

    const libDestDir  = path.join(libBasePath, libName);
    const demoDestDir = path.join(metBasePath, 'Library Demo Methods', libName);

    const result = installPackage(
        manifest, zip, libDestDir, demoDestDir,
        path.basename(filePath), db, !!(args['no-group'])
    );

    console.log(`\nSuccess: "${libName}" installed (${result.extractedCount} files)`);
    console.log(`  Library files  -> ${libDestDir}`);
    console.log(`  Demo methods   -> ${demoDestDir}`);

    // ---- Audit trail entry ----
    try {
        const userDataDir = resolveDBPath(args);
        appendAuditTrailEntry(userDataDir, buildAuditTrailEntry('library_imported', {
            library_name:    libName,
            version:         manifest.version || '',
            author:          manifest.author || '',
            organization:    manifest.organization || '',
            source_file:     path.resolve(filePath),
            lib_install_path: libDestDir,
            demo_install_path: demoDestDir,
            files_extracted: result.extractedCount,
            signature_status: sigResult.signed ? (sigResult.valid ? 'valid' : 'failed') : 'unsigned'
        }));
    } catch (_) { /* non-critical */ }

    // Cache the package file for repair & rollback
    if (!args['no-cache']) {
        try {
            const pkgBuffer = fs.readFileSync(filePath);
            const cachedPath = cachePackage(pkgBuffer, libName, manifest.version, args);
            console.log(`  Package cached -> ${cachedPath}`);
        } catch (e) {
            process.stderr.write('  Warning: could not cache package: ' + e.message + '\n');
        }
    }

    const comDlls = manifest.com_register_dlls || [];
    if (comDlls.length > 0) {
        console.log(`\n  NOTE: COM registration required for: ${comDlls.join(', ')}`);
        console.log(`  Use the GUI import or run the 32-bit RegAsm manually:`);
        console.log(`    C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /codebase <dll>`);
        console.log(`  IMPORTANT: Do NOT use Framework64 — VENUS is a 32-bit application.`);
    }
}

// ===========================================================================
// COMMAND: import-archive
// ===========================================================================
function cmdImportArchive(args) {
    const filePath = args['file'];
    if (!filePath)                { die('--file is required'); }
    if (!fs.existsSync(filePath)) { die('File not found: ' + filePath); }

    const db = connectDB(resolveDBPath(args));
    const { libBasePath, metBasePath } = getInstallPaths(db, args['lib-dir'], args['met-dir']);

    console.log('Importing archive: ' + filePath);

    let archiveZip;
    try {
        var rawArchBuf = fs.readFileSync(filePath);
        var outerZipBuf = unpackContainer(rawArchBuf, CONTAINER_MAGIC_ARC);
        archiveZip = new AdmZip(outerZipBuf);
    } catch (e) {
        die('Failed to open archive: ' + e.message);
    }

    const pkgEntries = archiveZip.getEntries().filter(
        e => !e.isDirectory && e.entryName.toLowerCase().endsWith('.hxlibpkg')
    );

    if (pkgEntries.length === 0) {
        die('No .hxlibpkg packages found in this archive.');
    }

    console.log(`Found ${pkgEntries.length} package(s):`);
    pkgEntries.forEach(e => console.log('  - ' + e.entryName));
    console.log('');

    const results = { success: [], failed: [] };

    pkgEntries.forEach(function (pkgEntry) {
        const label = pkgEntry.entryName;
        try {
            const innerZipBuf = unpackContainer(pkgEntry.getData(), CONTAINER_MAGIC_PKG);
            const innerZip = new AdmZip(innerZipBuf);
            const me       = innerZip.getEntry('manifest.json');
            if (!me) throw new Error('manifest.json missing');

            const manifest = JSON.parse(innerZip.readAsText(me));
            const libName  = manifest.library_name || 'Unknown';

            // ---- Library name validation (matches GUI behaviour) ----
            if (!isValidLibraryName(libName)) {
                throw new Error('Invalid library name: "' + libName + '"');
            }

            // Verify inner package signature
            const sigResult = verifyPackageSignature(innerZip);
            if (sigResult.signed && !sigResult.valid) {
                console.log(`  ! ${libName}: signature verification FAILED`);
                sigResult.errors.forEach(e => process.stderr.write('      ' + e + '\n'));
                if (!args['force']) {
                    throw new Error('Signature verification failed (use --force to override)');
                }
                console.log(`    WARNING: Importing despite failed signature (--force)`);
            } else if (sigResult.signed) {
                console.log(`    ${libName}: signature OK`);
            }

            // ---- Restricted author check ----
            const importAuthor = (manifest.author || '').trim();
            const importOrg = (manifest.organization || '').trim();
            if ((isRestrictedAuthor(importAuthor) || isRestrictedAuthor(importOrg)) && !isSystemLibraryByName(libName)) {
                if (!args['author-password']) {
                    throw new Error(`Package "${libName}" uses restricted author "${importAuthor}". Use --author-password to authorize.`);
                }
                if (!validateAuthorPassword(args['author-password'])) {
                    throw new Error(`Incorrect author password for restricted package "${libName}".`);
                }
            }

            const existing = db.installed_libs.findOne({ library_name: libName });
            if (existing && !existing.deleted && !args['force']) {
                throw new Error(`"${libName}" already installed (use --force to overwrite)`);
            }

            const libDestDir  = path.join(libBasePath, libName);
            const demoDestDir = path.join(metBasePath, 'Library Demo Methods', libName);

            const result = installPackage(
                manifest, innerZip, libDestDir, demoDestDir,
                label, db, !!(args['no-group'])
            );

            results.success.push(`${libName} (${result.extractedCount} files)`);
            console.log(`  + ${libName} - ${result.extractedCount} files extracted`);

            // Cache each package for repair & rollback
            if (!args['no-cache']) {
                try {
                    const cachedPath = cachePackage(pkgEntry.getData(), libName, manifest.version, args);
                    console.log(`    cached -> ${cachedPath}`);
                } catch (ce) {
                    process.stderr.write(`    Warning: could not cache ${libName}: ${ce.message}\n`);
                }
            }
        } catch (e) {
            results.failed.push(`${label}: ${e.message}`);
            process.stderr.write(`  ! ${label}: ${e.message}\n`);
        }
    });

    console.log('\nArchive Import Summary:');
    console.log(`  Succeeded : ${results.success.length}`);
    console.log(`  Failed    : ${results.failed.length}`);

    // ---- Audit trail entry ----
    try {
        const userDataDir = resolveDBPath(args);
        appendAuditTrailEntry(userDataDir, buildAuditTrailEntry('archive_imported', {
            archive_file:    path.resolve(filePath),
            packages_total:  pkgEntries.length,
            succeeded:       results.success,
            failed:          results.failed
        }));
    } catch (_) { /* non-critical */ }

    if (results.failed.length > 0) {
        results.failed.forEach(f => process.stderr.write('    ' + f + '\n'));
        process.exit(1);
    }
}

// ===========================================================================
// COMMAND: export-lib
// ===========================================================================
function cmdExportLib(args) {
    if (!args['name'] && !args['id']) { die('--name or --id is required'); }
    if (!args['output'])              { die('--output is required'); }

    const db  = connectDB(resolveDBPath(args));
    const lib = findLibrary(db, args);
    if (!lib) die(`Library "${args.name || args.id}" not found.`);
    if (isSystemLibrary(lib._id)) die(`SYSTEM_LIBRARY_READ_ONLY: "${lib.library_name || args.name || args.id}" is a Hamilton system library and cannot be exported.`);
    if (lib.deleted) die(`Library "${lib.library_name}" is deleted and cannot be exported.`);

    const libraryFiles = lib.library_files     || [];
    const demoFiles    = lib.demo_method_files  || [];
    const helpFiles    = lib.help_files         || [];
    const libBasePath  = lib.lib_install_path   || '';
    const demoBasePath = lib.demo_install_path  || '';

    // Verify source files are present
    for (const f of libraryFiles) {
        const fp = path.join(libBasePath, f);
        if (!fs.existsSync(fp)) die(`Library file not found: ${fp}\nExport aborted.`);
    }

    console.log(`Exporting: ${lib.library_name}`);

    const manifest = {
        format_version:      '1.0',
        library_name:        lib.library_name        || '',
        author:              lib.author               || '',
        organization:        lib.organization         || '',
        version:             lib.version              || '',
        venus_compatibility: lib.venus_compatibility  || '',
        description:         lib.description          || '',
        github_url:          lib.github_url           || '',
        tags:                lib.tags                 || [],
        created_date:        new Date().toISOString(),
        library_image:       lib.library_image        || null,
        library_image_base64:lib.library_image_base64 || null,
        library_image_mime:  lib.library_image_mime   || null,
        library_files:       libraryFiles.concat(helpFiles),
        demo_method_files:   demoFiles.slice(),
        help_files:          helpFiles.slice(),
        com_register_dlls:   (lib.com_register_dlls   || []).slice()
    };

    const zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));

    // Pack all library files + help files into library/ (CHMs live in the library folder)
    libraryFiles.concat(helpFiles).forEach(f => {
        const fp = path.join(libBasePath, f);
        if (fs.existsSync(fp)) zip.addLocalFile(fp, 'library');
    });

    demoFiles.forEach(f => {
        const fp = path.join(demoBasePath, f);
        if (fs.existsSync(fp)) zip.addLocalFile(fp, 'demo_methods');
    });

    // Sign the package for integrity verification
    signPackageZip(zip);

    ensureOutDir(args['output']);
    fs.writeFileSync(args['output'], packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

    console.log(`\nSuccess: exported to ${args['output']}`);
    console.log(`  Library files    : ${libraryFiles.length}`);
    console.log(`  Demo method files: ${demoFiles.length}`);
}

// ===========================================================================
// COMMAND: export-archive
// ===========================================================================
function cmdExportArchive(args) {
    if (!args['output']) { die('--output is required'); }
    if (!args['all'] && !args['names'] && !args['ids']) {
        die('Specify --all, --names <n1,n2,...>, or --ids <id1,id2,...>');
    }

    const db = connectDB(resolveDBPath(args));
    let targetLibs = [];

    if (args['all']) {
        targetLibs = (db.installed_libs.find() || []).filter(l => !l.deleted && !isSystemLibrary(l._id));
    } else if (args['names']) {
        args['names'].split(',').map(n => n.trim()).forEach(n => {
            const found = db.installed_libs.findOne({ library_name: n });
            if (found && !found.deleted && !isSystemLibrary(found._id)) {
                targetLibs.push(found);
            } else if (found && isSystemLibrary(found._id)) {
                process.stderr.write(`Warning: "${n}" is a system library and cannot be exported - skipping\n`);
            } else {
                process.stderr.write(`Warning: library "${n}" not found or is deleted - skipping\n`);
            }
        });
    } else if (args['ids']) {
        args['ids'].split(',').map(i => i.trim()).forEach(id => {
            const found = db.installed_libs.findOne({ _id: id });
            if (found && !found.deleted && !isSystemLibrary(found._id)) {
                targetLibs.push(found);
            } else if (found && isSystemLibrary(found._id)) {
                process.stderr.write(`Warning: library ID "${id}" is a system library and cannot be exported - skipping\n`);
            } else {
                process.stderr.write(`Warning: library ID "${id}" not found or is deleted - skipping\n`);
            }
        });
    }

    if (targetLibs.length === 0) die('No valid libraries selected for export.');

    console.log(`Exporting ${targetLibs.length} librar${targetLibs.length === 1 ? 'y' : 'ies'} to archive:`);
    targetLibs.forEach(l => console.log(`  - ${l.library_name}`));
    console.log('');

    const archiveZip  = new AdmZip();
    const exportedLibs = [];
    const errors       = [];

    targetLibs.forEach(function (lib) {
        try {
            const libBasePath  = lib.lib_install_path  || '';
            const demoBasePath = lib.demo_install_path || '';
            const libraryFiles = lib.library_files     || [];
            const demoFiles    = lib.demo_method_files  || [];
            const helpFiles    = lib.help_files         || [];
            const comDlls      = lib.com_register_dlls  || [];

            const manifest = {
                format_version:      '1.0',
                library_name:        lib.library_name        || '',
                author:              lib.author               || '',
                organization:        lib.organization         || '',
                version:             lib.version              || '',
                venus_compatibility: lib.venus_compatibility  || '',
                description:         lib.description          || '',
                github_url:          lib.github_url           || '',
                tags:                lib.tags                 || [],
                created_date:        new Date().toISOString(),
                library_image:       lib.library_image        || null,
                library_image_base64:lib.library_image_base64 || null,
                library_image_mime:  lib.library_image_mime   || null,
                library_files:       libraryFiles.concat(helpFiles),
                demo_method_files:   demoFiles.slice(),
                help_files:          helpFiles.slice(),
                com_register_dlls:   comDlls.slice()
            };

            const innerZip = new AdmZip();
            innerZip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));

            let libAdded = 0, demoAdded = 0;
            libraryFiles.concat(helpFiles).forEach(f => {
                const fp = path.join(libBasePath, f);
                if (fs.existsSync(fp)) { innerZip.addLocalFile(fp, 'library');      libAdded++;  }
            });
            demoFiles.forEach(f => {
                const fp = path.join(demoBasePath, f);
                if (fs.existsSync(fp)) { innerZip.addLocalFile(fp, 'demo_methods'); demoAdded++; }
            });

            // Sign the inner package
            signPackageZip(innerZip);

            archiveZip.addFile(lib.library_name + '.hxlibpkg', packContainer(innerZip.toBuffer(), CONTAINER_MAGIC_PKG));
            exportedLibs.push({ name: lib.library_name, libFiles: libAdded, demoFiles: demoAdded });
            console.log(`  + ${lib.library_name} (${libAdded} lib files, ${demoAdded} demo files)`);
        } catch (e) {
            errors.push(`${lib.library_name}: ${e.message}`);
            process.stderr.write(`  ! ${lib.library_name}: ${e.message}\n`);
        }
    });

    if (exportedLibs.length === 0) die('No libraries could be exported.');

    // Embed archive manifest
    const archManifest = {
        format_version: '1.0',
        archive_type:   'hxlibarch',
        created_date:   new Date().toISOString(),
        library_count:  exportedLibs.length,
        libraries:      exportedLibs.map(l => l.name)
    };
    archiveZip.addFile(
        'archive_manifest.json',
        Buffer.from(JSON.stringify(archManifest, null, 2), 'utf8')
    );

    ensureOutDir(args['output']);
    fs.writeFileSync(args['output'], packContainer(archiveZip.toBuffer(), CONTAINER_MAGIC_ARC));

    console.log(`\nArchive created: ${args['output']}`);
    console.log(`  Libraries included: ${exportedLibs.length}`);
    if (errors.length > 0) {
        console.log(`  Warnings          : ${errors.length}`);
        errors.forEach(e => process.stderr.write('    ' + e + '\n'));
    }
}

// ===========================================================================
// COMMAND: delete-lib
// ===========================================================================
function cmdDeleteLib(args) {
    if (!args['name'] && !args['id']) { die('--name or --id is required'); }

    // Safety gate: require explicit --yes or --force
    if (!args['yes'] && !args['force'] && !args['y']) {
        die(
            'Deletion requires --yes to confirm. This cannot be undone.\n' +
            'Re-run with --yes to proceed.'
        );
    }

    const db  = connectDB(resolveDBPath(args));
    const lib = findLibrary(db, args);
    if (!lib) die(`Library "${args.name || args.id}" not found.`);
    if (isSystemLibrary(lib._id)) die(`SYSTEM_LIBRARY_READ_ONLY: "${lib.library_name || args.name || args.id}" is a Hamilton system library and cannot be deleted.`);

    const displayName = lib.library_name || args.name || args.id;
    console.log(`Deleting: ${displayName}`);

    // ---- Delete files from disk (unless --keep-files) ----
    if (!args['keep-files']) {
        const libFiles  = lib.library_files   || [];
        const helpFiles = lib.help_files      || [];
        const libPath   = lib.lib_install_path || '';

        if (libPath && (libFiles.length > 0 || helpFiles.length > 0)) {
            libFiles.concat(helpFiles).forEach(f => {
                try {
                    const fp = path.join(libPath, f);
                    if (fs.existsSync(fp)) fs.unlinkSync(fp);
                } catch (e) {
                    process.stderr.write(`  Warning: could not delete ${f}: ${e.message}\n`);
                }
            });
            try {
                if (fs.existsSync(libPath) && fs.readdirSync(libPath).length === 0) {
                    fs.rmdirSync(libPath);
                }
            } catch (_) {}
        }

        const demoFiles = lib.demo_method_files || [];
        const demoPath  = lib.demo_install_path  || '';

        if (demoPath && demoFiles.length > 0) {
            demoFiles.forEach(f => {
                try {
                    const fp = path.join(demoPath, f);
                    if (fs.existsSync(fp)) fs.unlinkSync(fp);
                } catch (e) {
                    process.stderr.write(`  Warning: could not delete demo ${f}: ${e.message}\n`);
                }
            });
            try {
                if (fs.existsSync(demoPath) && fs.readdirSync(demoPath).length === 0) {
                    fs.rmdirSync(demoPath);
                }
            } catch (_) {}
        }

        console.log('  Disk files removed.');
    } else {
        console.log('  --keep-files set: disk files left in place.');
    }

    // ---- DB: hard or soft delete ----
    if (args['hard']) {
        db.installed_libs.remove({ _id: lib._id });
        console.log('  DB record permanently removed (hard delete).');
    } else {
        db.installed_libs.update(
            { _id: lib._id },
            { deleted: true, deleted_date: new Date().toISOString() },
            { multi: false, upsert: false }
        );
        console.log('  DB record soft-deleted (history preserved).');
    }

    // ---- Remove from group tree ----
    try {
        const navtree = db.tree.find() || [];
        for (let i = 0; i < navtree.length; i++) {
            const mids = navtree[i]['method-ids'] || [];
            const idx  = mids.indexOf(lib._id);
            if (idx !== -1) {
                mids.splice(idx, 1);
                db.tree.update(
                    { 'group-id': navtree[i]['group-id'] },
                    { 'method-ids': mids },
                    { multi: false, upsert: false }
                );
            }
        }
    } catch (_) {}

    console.log(`\nSuccess: "${displayName}" deleted.`);

    // ---- Audit trail entry ----
    try {
        const userDataDir = resolveDBPath(args);
        appendAuditTrailEntry(userDataDir, buildAuditTrailEntry('library_deleted', {
            library_name:    displayName,
            version:         lib.version || '',
            author:          lib.author || '',
            delete_type:     args['hard'] ? 'hard' : 'soft',
            keep_files:      !!(args['keep-files'])
        }));
    } catch (_) { /* non-critical */ }

    const comDlls = lib.com_register_dlls || [];
    if (comDlls.length > 0) {
        console.log(`\n  NOTE: COM DLLs were NOT automatically deregistered: ${comDlls.join(', ')}`);
        console.log(`  Run the 32-bit RegAsm with elevated privileges if needed:`);
        console.log(`    C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /unregister <dll>`);
        console.log(`  IMPORTANT: Do NOT use Framework64 — VENUS is a 32-bit application.`);
    }
}

// ===========================================================================
// COMMAND: create-package
// ===========================================================================
function cmdCreatePackage(args) {
    if (!args['spec'])   { die('--spec <json-spec-file> is required'); }
    if (!args['output']) { die('--output <path.hxlibpkg> is required'); }

    const specPath = path.resolve(args['spec']);
    if (!fs.existsSync(specPath)) die('Spec file not found: ' + specPath);

    let spec;
    try {
        spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
    } catch (e) {
        die('Failed to parse spec file: ' + e.message);
    }

    // ---- Validate required fields ----
    const validationErrors = [];
    if (!spec.author)                              validationErrors.push('"author" is required');
    if (!spec.version)                             validationErrors.push('"version" is required');
    if (!spec.venus_compatibility)                 validationErrors.push('"venus_compatibility" is required');
    if (!spec.description)                         validationErrors.push('"description" is required');
    if (!spec.library_files || spec.library_files.length === 0)
                                                   validationErrors.push('"library_files" must contain at least one entry');
    if (validationErrors.length > 0) {
        die('Spec validation failed:\n  ' + validationErrors.join('\n  '));
    }

    // ---- Restricted author/organization check ----
    if (isRestrictedAuthor(spec.author) || isRestrictedAuthor(spec.organization)) {
        if (!args['author-password']) {
            die('The author name "Hamilton" is restricted. Use --author-password <password> to authorize.');
        }
        if (!validateAuthorPassword(args['author-password'])) {
            die('Incorrect author password. Creating packages with author "Hamilton" requires valid authorization.');
        }
    }

    // ---- Sanitize & validate tags ----
    if (spec.tags && Array.isArray(spec.tags)) {
        spec.tags = shared.sanitizeTags(spec.tags);
        var tagCheck = shared.filterReservedTags(spec.tags);
        if (tagCheck.removed.length > 0) {
            die('Tags contain reserved keywords that cannot be used: ' + tagCheck.removed.join(', ') +
                '\nThe reserved tag keywords are: ' + shared.RESERVED_TAGS.join(', '));
        }
    }

    const specDir = path.dirname(specPath);

    // ---- Resolve and validate file paths (relative to spec directory) ----
    const resolvedLibFiles  = (spec.library_files    || []).map(f => path.resolve(specDir, f));
    const resolvedDemoFiles = (spec.demo_method_files || []).map(f => path.resolve(specDir, f));
    const resolvedImagePath = spec.library_image ? path.resolve(specDir, spec.library_image) : null;

    for (const fp of resolvedLibFiles)  {
        if (!fs.existsSync(fp)) die(`Library file not found: ${fp}`);
    }
    for (const fp of resolvedDemoFiles) {
        if (!fs.existsSync(fp)) die(`Demo method file not found: ${fp}`);
    }

    // ---- Auto-detect library name ----
    let libName = spec.library_name || null;
    if (!libName) {
        const priority = ['.hsl', '.hs_', '.smt'];
        for (const ext of priority) {
            const match = resolvedLibFiles.find(f => path.extname(f).toLowerCase() === ext);
            if (match) { libName = path.basename(match, path.extname(match)); break; }
        }
        if (!libName) {
            libName = path.basename(path.dirname(resolvedLibFiles[0])) || 'Unknown';
        }
    }

    if (!isValidLibraryName(libName)) {
        die('Invalid library name: "' + libName + '". Library names cannot contain path separators, \'..\', trailing dots/spaces, or reserved characters.');
    }

    console.log(`Creating package: ${libName}`);

    // ---- Image handling ----
    let libraryImageFilename = null;
    let libraryImageBase64   = null;
    let libraryImageMime     = null;
    let iconSourcePath       = null;

    if (resolvedImagePath && fs.existsSync(resolvedImagePath)) {
        // Explicit image provided in spec
        iconSourcePath       = resolvedImagePath;
        libraryImageFilename = path.basename(resolvedImagePath);
        libraryImageMime     = MIME_MAP[path.extname(resolvedImagePath).toLowerCase()] || 'image/png';
        libraryImageBase64   = fs.readFileSync(resolvedImagePath).toString('base64');
    } else {
        // Try to auto-detect a matching .bmp among library files
        const bmpName  = libName.toLowerCase() + '.bmp';
        const bmpFound = resolvedLibFiles.find(f => path.basename(f).toLowerCase() === bmpName);
        if (bmpFound) {
            libraryImageFilename = path.basename(bmpFound);
            libraryImageMime     = 'image/bmp';
            libraryImageBase64   = fs.readFileSync(bmpFound).toString('base64');
        }
    }

    const comDlls = spec.com_register_dlls || [];
    const specHelpFiles = spec.help_files || [];

    // Resolve help files (optional - basenames that should match library files)
    const resolvedHelpFiles = specHelpFiles.map(f => path.resolve(specDir, f));
    for (const fp of resolvedHelpFiles) {
        if (!fs.existsSync(fp)) die(`Help file not found: ${fp}`);
    }

    // Build manifest - include help_files and keep CHMs in library_files for backward compat
    const libBasenames = resolvedLibFiles.map(f => path.basename(f));
    const helpBasenames = resolvedHelpFiles.map(f => path.basename(f));
    const manifestLibFiles = libBasenames.slice();
    helpBasenames.forEach(hf => {
        if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
    });

    const manifest = {
        format_version:      '1.0',
        library_name:        libName,
        author:              spec.author              || '',
        organization:        spec.organization         || '',
        version:             spec.version,
        venus_compatibility: spec.venus_compatibility  || '',
        description:         spec.description          || '',
        github_url:          spec.github_url           || '',
        tags:                spec.tags                 || [],
        created_date:        new Date().toISOString(),
        library_image:       libraryImageFilename,
        library_image_base64:libraryImageBase64,
        library_image_mime:  libraryImageMime,
        library_files:       manifestLibFiles,
        demo_method_files:   resolvedDemoFiles.map(f => path.basename(f)),
        help_files:          helpBasenames,
        com_register_dlls:   comDlls
    };

    const zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));
    resolvedLibFiles.forEach(f  => zip.addLocalFile(f, 'library'));
    resolvedHelpFiles.forEach(f => zip.addLocalFile(f, 'library'));
    resolvedDemoFiles.forEach(f => zip.addLocalFile(f, 'demo_methods'));
    if (iconSourcePath) zip.addLocalFile(iconSourcePath, 'icon');

    // Sign the package for integrity verification
    signPackageZip(zip);

    ensureOutDir(args['output']);
    fs.writeFileSync(args['output'], packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

    console.log(`\nSuccess: ${args['output']}`);
    console.log(`  Library name      : ${libName}`);
    console.log(`  Author            : ${spec.author}`);
    console.log(`  Version           : ${spec.version}`);
    console.log(`  Library files     : ${resolvedLibFiles.length}`);
    console.log(`  Help files        : ${resolvedHelpFiles.length}`);
    console.log(`  Demo method files : ${resolvedDemoFiles.length}`);
    if (comDlls.length > 0) console.log(`  COM DLLs          : ${comDlls.join(', ')}`);
    if (libraryImageFilename) console.log(`  Icon              : ${libraryImageFilename}`);

    // ---- Audit trail entry ----
    try {
        const dbPath = resolveDBPath(args);
        appendAuditTrailEntry(dbPath, buildAuditTrailEntry('package_created', {
            library_name:    libName,
            version:         spec.version || '',
            author:          spec.author || '',
            organization:    spec.organization || '',
            output_file:     path.resolve(args['output']),
            library_files:   resolvedLibFiles.length,
            demo_files:      resolvedDemoFiles.length,
            help_files:      resolvedHelpFiles.length,
            com_dlls:        comDlls
        }));
    } catch (_) { /* non-critical */ }
}

// ===========================================================================
// COMMAND: generate-syslib-hashes
// ===========================================================================
function cmdGenerateSyslibHashes(args) {
    const sourceDir = args['source-dir'];
    if (!sourceDir) {
        die('--source-dir is required (path to known-good Library folder)');
    }
    if (!fs.existsSync(sourceDir)) {
        die('Source directory not found: ' + sourceDir);
    }

    // Load system_libraries.json to know which files belong to system libs
    const sysLibPath = path.join(__dirname, 'db', 'system_libraries.json');
    if (!fs.existsSync(sysLibPath)) {
        die('system_libraries.json not found at: ' + sysLibPath);
    }

    let sysLibs;
    try {
        sysLibs = JSON.parse(fs.readFileSync(sysLibPath, 'utf8'));
    } catch (e) {
        die('Failed to parse system_libraries.json: ' + e.message);
    }

    console.log(`Generating system library baseline from: ${sourceDir}`);
    console.log(`System libraries defined: ${sysLibs.length}`);
    console.log(`Strategy: Hamilton metadata footer ($$valid$$/$$checksum$$) only.\n`);

    const baselineData = {
        _meta: {
            generated_at:   new Date().toISOString(),
            source_dir:     sourceDir,
            strategy:       'hamilton-footer',
            hsl_extensions: HSL_METADATA_EXTS.slice(),
            description:    'Integrity baseline for Hamilton system libraries. '
                          + 'Only HSL-type files (' + HSL_METADATA_EXTS.join(', ') + ') with Hamilton\'s '
                          + 'metadata footer are tracked. Binary files are not baselined.'
        },
        libraries: {}
    };

    let totalFiles     = 0;
    let totalBaselined = 0;
    let skippedBinary  = 0;
    let noFooter       = [];
    let missing        = [];

    sysLibs.forEach(function (lib) {
        const libName = lib.canonical_name || lib.library_name;
        const files   = lib.discovered_files || [];

        const libFiles = {};

        files.forEach(function (relPath) {
            const fname    = relPath.replace(/^Library\\/i, '');
            const fullPath = path.join(sourceDir, fname);
            totalFiles++;

            const ext = path.extname(fname).toLowerCase();

            // Only track HSL-type files with metadata footers
            if (HSL_METADATA_EXTS.indexOf(ext) === -1) {
                skippedBinary++;
                return;
            }

            if (!fs.existsSync(fullPath)) {
                missing.push({ library: libName, file: fname });
                return;
            }

            const footer = parseHslMetadataFooter(fullPath);
            if (footer) {
                libFiles[fname] = {
                    valid:    footer.valid,
                    checksum: footer.checksum,
                    author:   footer.author,
                    time:     footer.time,
                    length:   footer.length
                };
                totalBaselined++;
            } else {
                noFooter.push({ library: libName, file: fname });
            }
        });

        if (Object.keys(libFiles).length > 0) {
            baselineData.libraries[libName] = {
                _id:   lib._id,
                files: libFiles
            };
        }
    });

    // Write the baseline file
    const outputPath = args['output'] || path.join(__dirname, 'db', 'system_library_hashes.json');
    ensureOutDir(outputPath);
    fs.writeFileSync(outputPath, JSON.stringify(baselineData, null, 2), 'utf8');

    console.log(`Baselined ${totalBaselined} / ${totalFiles} files across ${Object.keys(baselineData.libraries).length} libraries.`);
    console.log(`  Footer tracked  : ${totalBaselined} files`);
    console.log(`  Binary skipped  : ${skippedBinary} files`);
    if (noFooter.length > 0) {
        console.log(`\nNote: ${noFooter.length} HSL-type file(s) had no metadata footer (not tracked):`);
        noFooter.forEach(e => console.log(`  [${e.library}] ${e.file}`));
    }
    if (missing.length > 0) {
        console.log(`\nWarning: ${missing.length} file(s) not found in source directory:`);
        missing.forEach(m => console.log(`  [${m.library}] ${m.file}`));
    }
    console.log(`\nBaseline file written: ${outputPath}`);
}

// ===========================================================================
// COMMAND: verify-syslib-hashes
// ===========================================================================
function cmdVerifySyslibHashes(args) {
    // Load the baseline file
    const hashFilePath = args['hash-file'] || path.join(__dirname, 'db', 'system_library_hashes.json');
    if (!fs.existsSync(hashFilePath)) {
        die('System library baseline file not found: ' + hashFilePath
          + '\nRun  generate-syslib-hashes  first to create it.');
    }

    let baselineData;
    try {
        baselineData = JSON.parse(fs.readFileSync(hashFilePath, 'utf8'));
    } catch (e) {
        die('Failed to parse baseline file: ' + e.message);
    }

    // Determine the library directory to verify against
    const db = connectDB(resolveDBPath(args));
    let libBasePath = DEFAULT_LIB_PATH;
    if (args['lib-dir']) {
        libBasePath = args['lib-dir'];
    } else {
        try {
            const rec = db.links.findOne({ _id: 'lib-folder' });
            if (rec && rec.path) libBasePath = rec.path;
        } catch (_) {}
    }

    if (!fs.existsSync(libBasePath)) {
        die('Library directory not found: ' + libBasePath);
    }

    const asJson = !!(args['json'] || args['j']);
    const strategy = (baselineData._meta || {}).strategy || 'unknown';

    console.log('Verifying system library integrity...');
    console.log(`  Library dir : ${libBasePath}`);
    console.log(`  Baseline    : ${hashFilePath}`);
    console.log(`  Generated   : ${(baselineData._meta || {}).generated_at || 'unknown'}`);
    console.log(`  Strategy    : ${strategy}`);
    console.log('');

    const results = { ok: [], tampered: [], missing: [], errors: [] };

    const libNames = Object.keys(baselineData.libraries);
    libNames.forEach(function (libName) {
        const entry = baselineData.libraries[libName];
        const files = entry.files || {};

        Object.keys(files).forEach(function (fname) {
            const stored   = files[fname];
            const fullPath = path.join(libBasePath, fname);

            if (!fs.existsSync(fullPath)) {
                results.missing.push({ library: libName, file: fname });
                return;
            }

            try {
                const footer = parseHslMetadataFooter(fullPath);
                if (!footer) {
                    results.tampered.push({
                        library: libName, file: fname,
                        reason:  'Metadata footer removed',
                        expected: `valid=${stored.valid} checksum=${stored.checksum}`,
                        actual:   'No footer'
                    });
                    return;
                }
                if (stored.valid === 1 && footer.valid !== 1) {
                    results.tampered.push({
                        library: libName, file: fname,
                        reason:  'Valid flag changed (1\u21920)',
                        expected: `valid=1 checksum=${stored.checksum}`,
                        actual:   `valid=${footer.valid} checksum=${footer.checksum}`
                    });
                    return;
                }
                if (stored.checksum && footer.checksum !== stored.checksum) {
                    results.tampered.push({
                        library: libName, file: fname,
                        reason:  'Checksum changed',
                        expected: `checksum=${stored.checksum}`,
                        actual:   `checksum=${footer.checksum}`
                    });
                    return;
                }
                results.ok.push({ library: libName, file: fname });
            } catch (e) {
                results.errors.push({ library: libName, file: fname, error: e.message });
            }
        });
    });

    if (asJson) {
        console.log(JSON.stringify(results, null, 2));
        if (results.tampered.length > 0 || results.missing.length > 0 || results.errors.length > 0) {
            process.exit(1);
        }
    } else {
        const totalChecked = results.ok.length + results.tampered.length
                           + results.missing.length + results.errors.length;

        if (results.tampered.length > 0) {
            console.log('TAMPERED FILES:');
            results.tampered.forEach(function (t) {
                console.log(`  [${t.library}] ${t.file}`);
                if (t.reason)   console.log(`    Reason   : ${t.reason}`);
                if (t.expected) console.log(`    Expected : ${t.expected}`);
                if (t.actual)   console.log(`    Actual   : ${t.actual}`);
            });
            console.log('');
        }

        if (results.missing.length > 0) {
            console.log('MISSING FILES:');
            results.missing.forEach(function (m) {
                console.log(`  [${m.library}] ${m.file}`);
            });
            console.log('');
        }

        if (results.errors.length > 0) {
            console.log('ERRORS:');
            results.errors.forEach(function (e) {
                console.log(`  [${e.library}] ${e.file}: ${e.error}`);
            });
            console.log('');
        }

        console.log('System Library Integrity Summary');
        console.log('='.repeat(40));
        console.log(`  Total checked : ${totalChecked}`);
        console.log(`  OK            : ${results.ok.length}`);
        console.log(`  Tampered      : ${results.tampered.length}`);
        console.log(`  Missing       : ${results.missing.length}`);
        console.log(`  Errors        : ${results.errors.length}`);

        if (results.tampered.length === 0 && results.missing.length === 0 && results.errors.length === 0) {
            console.log('\n  All system libraries verified OK.');
        } else {
            console.log('\n  WARNING: System library integrity issues detected!');
            process.exit(1);
        }
    }
}

// ===========================================================================
// COMMAND: list-versions
// ===========================================================================
function cmdListVersions(args) {
    if (!args['name']) { die('--name is required'); }

    const libName = args['name'];
    const asJson  = !!(args['json'] || args['j']);
    const entries = listCachedVersions(libName, args);

    if (entries.length === 0) {
        console.log(`No cached packages found for "${libName}".`);
        return;
    }

    if (asJson) {
        console.log(JSON.stringify(entries, null, 2));
        return;
    }

    console.log(`\nCached packages for "${libName}"`);
    console.log('='.repeat(64));
    entries.forEach(function (e, i) {
        const sizeKB = (e.size / 1024).toFixed(1);
        console.log(`  [${i + 1}] Version: ${e.version}`);
        console.log(`      Author:  ${e.author || '-'}`);
        console.log(`      Created: ${e.created || '-'}`);
        console.log(`      Cached:  ${e.cached}`);
        console.log(`      Size:    ${sizeKB} KB`);
        console.log(`      File:    ${e.file}`);
        console.log('');
    });
    console.log(`Total: ${entries.length} cached version${entries.length === 1 ? '' : 's'}`);
}

// ===========================================================================
// COMMAND: rollback-lib
// ===========================================================================
function cmdRollbackLib(args) {
    if (!args['name']) { die('--name is required'); }

    const libName = args['name'];
    const entries = listCachedVersions(libName, args);

    if (entries.length === 0) {
        die(`No cached packages found for "${libName}". Nothing to roll back to.`);
    }

    // Determine which cached version to install
    let target = null;

    if (args['version']) {
        // Find by version string
        const matches = entries.filter(function (e) { return e.version === args['version']; });
        if (matches.length === 0) {
            die(`Version "${args['version']}" not found in cache for "${libName}".\n`
              + `Available versions: ${entries.map(function(e) { return e.version; }).join(', ')}`);
        }
        target = matches[0]; // newest cache of that version
    } else if (args['index']) {
        // Select by 1-based index from list-versions output
        const idx = parseInt(args['index'], 10);
        if (isNaN(idx) || idx < 1 || idx > entries.length) {
            die(`Invalid index ${args['index']}. Use list-versions to see available entries (1 to ${entries.length}).`);
        }
        target = entries[idx - 1];
    } else {
        // Default: show available and ask them to pick
        console.log(`Available cached versions for "${libName}":\n`);
        entries.forEach(function (e, i) {
            console.log(`  [${i + 1}] v${e.version}  (cached ${e.cached})`);
        });
        die('\nSpecify which version to rollback to with --version <ver> or --index <n>');
    }

    console.log(`Rolling back "${libName}" to version ${target.version} ...`);
    console.log(`  Source: ${target.fullPath}`);

    // Re-use the import-lib flow with the cached package
    const db = connectDB(resolveDBPath(args));
    const { libBasePath, metBasePath } = getInstallPaths(db, args['lib-dir'], args['met-dir']);

    let zip, manifest;
    try {
        var rawCacheBuf = fs.readFileSync(target.fullPath);
        var cacheBuf = unpackContainer(rawCacheBuf, CONTAINER_MAGIC_PKG);
        zip = new AdmZip(cacheBuf);
        const me = zip.getEntry('manifest.json');
        if (!me) die('Cached package is corrupt: manifest.json not found');
        manifest = JSON.parse(zip.readAsText(me));
    } catch (e) {
        die('Failed to read cached package: ' + e.message);
    }

    const libDestDir  = path.join(libBasePath, libName);
    const demoDestDir = path.join(metBasePath, 'Library Demo Methods', libName);

    const result = installPackage(
        manifest, zip, libDestDir, demoDestDir,
        target.file, db, !!(args['no-group'])
    );

    console.log(`\nSuccess: "${libName}" rolled back to version ${target.version} (${result.extractedCount} files)`);
    console.log(`  Library files  -> ${libDestDir}`);
    console.log(`  Demo methods   -> ${demoDestDir}`);

    // ---- Audit trail entry ----
    try {
        const userDataDir = resolveDBPath(args);
        appendAuditTrailEntry(userDataDir, buildAuditTrailEntry('library_rollback', {
            library_name:     libName,
            version:          target.version || '',
            author:           manifest.author || '',
            source_file:      target.fullPath,
            lib_install_path: libDestDir,
            demo_install_path: demoDestDir,
            files_extracted:  result.extractedCount
        }));
    } catch (_) { /* non-critical */ }

    const comDlls = manifest.com_register_dlls || [];
    if (comDlls.length > 0) {
        console.log(`\n  NOTE: COM registration required for: ${comDlls.join(', ')}`);
        console.log(`  Use the GUI import or run the 32-bit RegAsm manually:`);
        console.log(`    C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /codebase <dll>`);
        console.log(`  IMPORTANT: Do NOT use Framework64 — VENUS is a 32-bit application.`);
    }
}

// ===========================================================================
// Help
// ===========================================================================
function printHelp() {
    console.log(`
Library Manager for Venus 6 CLI  v1.4.8
Hamilton VENUS Library Package Management

USAGE
  node cli.js <command> [options]

COMMANDS
  list-libs          List all installed libraries
  import-lib         Import a single .hxlibpkg file
  import-archive     Import a .hxlibarch archive (multiple libraries)
  export-lib         Export a single installed library as .hxlibpkg
  export-archive     Export one or more installed libraries as .hxlibarch
  delete-lib         Delete (remove) an installed library
  create-package     Create a .hxlibpkg package from a JSON spec file
  list-versions      List cached package versions for a library
  rollback-lib       Reinstall a previously cached version of a library
  generate-syslib-hashes   Generate integrity baseline for system libraries
  verify-syslib-hashes     Verify system libraries against baseline
  help               Show this help text

GLOBAL OPTIONS
  --db-path <dir>    Path to user data directory (default: from settings.json
                     or <Hamilton Library>\\LibraryManagerForVenus6)
  --store-dir <dir>  Override package store location
                     (default: <app_root>\\local\\packages)

──────────────────────────────────────────────────────────────────────────────
list-libs
  List installed libraries.

  --include-deleted  Include soft-deleted entries
  --json             Output raw JSON (useful for scripting)

  Examples:
    node cli.js list-libs
    node cli.js list-libs --json
    node cli.js list-libs --include-deleted --json

──────────────────────────────────────────────────────────────────────────────
import-lib
  Import a single .hxlibpkg into the VENUS library tree.
  The package file is automatically cached in the package store for
  future repair or rollback.

  --file   <path>    [required]  Path to the .hxlibpkg file
  --lib-dir <path>              Override library install root
  --met-dir <path>              Override methods (demo) install root
  --force                       Overwrite without error if already installed
  --no-group                    Skip auto-assigning to a library group
  --no-cache                    Skip caching the package in the store
  --author-password <pw>        Authorize importing packages with restricted
                                author name "Hamilton"

  Examples:
    node cli.js import-lib --file MyLib.hxlibpkg
    node cli.js import-lib --file MyLib.hxlibpkg --force
    node cli.js import-lib --file MyLib.hxlibpkg --lib-dir D:\\Hamilton\\Library

──────────────────────────────────────────────────────────────────────────────
import-archive
  Import all libraries contained in a .hxlibarch archive.
  Each package is automatically cached in the package store.

  --file   <path>    [required]  Path to the .hxlibarch file
  --lib-dir <path>              Override library install root
  --met-dir <path>              Override methods (demo) install root
  --force                       Overwrite without error if already installed
  --no-group                    Skip auto-assigning to library groups
  --no-cache                    Skip caching packages in the store
  --author-password <pw>        Authorize importing packages with restricted
                                author name "Hamilton"

  Examples:
    node cli.js import-archive --file bundle.hxlibarch
    node cli.js import-archive --file bundle.hxlibarch --force

──────────────────────────────────────────────────────────────────────────────
export-lib
  Export one installed library as a .hxlibpkg file.

  --name   <name>    [required*] Library name  (* or use --id)
  --id     <id>      [required*] Library DB ID (* or use --name)
  --output <path>    [required]  Output .hxlibpkg file path

  Examples:
    node cli.js export-lib --name "MyLibrary" --output ./MyLibrary.hxlibpkg
    node cli.js export-lib --id abc123 --output ./out/MyLibrary.hxlibpkg

──────────────────────────────────────────────────────────────────────────────
export-archive
  Bundle installed libraries into a single .hxlibarch file.

  --all                         Export all non-deleted installed libraries
  --names  <n1,n2,...>          Comma-separated library names
  --ids    <id1,id2,...>        Comma-separated library DB IDs
  --output <path>    [required]  Output .hxlibarch file path

  Examples:
    node cli.js export-archive --all --output ./all-libs.hxlibarch
    node cli.js export-archive --names "LibA,LibB" --output ./subset.hxlibarch

──────────────────────────────────────────────────────────────────────────────
delete-lib
  Delete an installed library (disk files + DB record).
  Requires --yes to confirm. Default is soft-delete (history preserved).

  --name   <name>    [required*] Library name  (* or use --id)
  --id     <id>      [required*] Library DB ID (* or use --name)
  --yes  / --force               Confirm deletion  [required]
  --hard                         Hard-delete DB record (removes history)
  --keep-files                   Remove from DB only; leave disk files intact

  NOTE: COM DLL deregistration must be done manually via the 32-bit RegAsm.exe.
        Use: C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe /unregister <dll>
        Do NOT use Framework64 — VENUS is a 32-bit application.

  Examples:
    node cli.js delete-lib --name "MyLibrary" --yes
    node cli.js delete-lib --name "MyLibrary" --yes --hard
    node cli.js delete-lib --id abc123 --yes --keep-files

──────────────────────────────────────────────────────────────────────────────
create-package
  Build a .hxlibpkg from raw library files using a JSON spec.

  --spec   <path>    [required]  Path to JSON spec file (see cli-schema.json)
  --output <path>    [required]  Output .hxlibpkg file path
  --author-password <pw>        Required when author is "Hamilton"

  The spec file describes all metadata and which files to bundle.
  See cli-schema.json for the full JSON Schema definition.
  See cli-spec-example.json for a worked example.

  Examples:
    node cli.js create-package --spec MyLib.spec.json --output MyLib.hxlibpkg
    node cli.js create-package --spec specs/proj.json --output dist/proj.hxlibpkg

──────────────────────────────────────────────────────────────────────────────
list-versions
  List all cached package versions for a library.
  Packages are cached automatically on import in the package store at
  ${PACKAGE_STORE_DIR}

  --name   <name>    [required]  Library name
  --json                         Output raw JSON

  Examples:
    node cli.js list-versions --name "MyLibrary"
    node cli.js list-versions --name "MyLibrary" --json

──────────────────────────────────────────────────────────────────────────────
rollback-lib
  Reinstall a previously cached version of a library from the package store.
  Use list-versions to see available cached versions first.

  --name    <name>     [required]  Library name
  --version <ver>                  Target version string (installs newest cache of that version)
  --index   <n>                    1-based index from list-versions output
  --lib-dir <path>                 Override library install root
  --met-dir <path>                 Override methods (demo) install root
  --no-group                       Skip auto-assigning to a library group

  If neither --version nor --index is given, available versions are listed.

  Examples:
    node cli.js rollback-lib --name "MyLibrary" --version "1.0.0"
    node cli.js rollback-lib --name "MyLibrary" --index 2

──────────────────────────────────────────────────────────────────────────────
generate-syslib-hashes
  Generate an integrity baseline from a known-good Hamilton Library folder.
  Only tracks HSL-type files (.hsl, .hs_, .smt) that carry Hamilton's
  built-in $$valid$$ flag and $$checksum$$ in the metadata footer.
  Binary files are skipped. The baseline is used by verify-syslib-hashes
  to detect tampered system libraries.

  --source-dir <path>  [required]  Path to the known-good Library folder
  --output <path>                  Output baseline file (default: db/system_library_hashes.json)

  Examples:
    node cli.js generate-syslib-hashes --source-dir "D:\\Venus\\Library"
    node cli.js generate-syslib-hashes --source-dir "D:\\Venus\\Library" --output baseline.json

──────────────────────────────────────────────────────────────────────────────
verify-syslib-hashes
  Verify installed system library files against the known-good baseline.
  Checks Hamilton's $$valid$$ and $$checksum$$ metadata footer on each
  tracked HSL file. Reports tampered, missing, or unreadable files.

  --hash-file <path>   Path to baseline file (default: db/system_library_hashes.json)
  --lib-dir <path>     Override library root to verify
  --json               Output results as JSON

  Examples:
    node cli.js verify-syslib-hashes
    node cli.js verify-syslib-hashes --lib-dir "C:\\Hamilton\\Library"
    node cli.js verify-syslib-hashes --json

──────────────────────────────────────────────────────────────────────────────
verify-package
  Verify the integrity signature of a .hxlibpkg or .hxlibarch file.
  Checks that all files match the embedded HMAC-SHA256 signature.
  Unsigned (legacy) packages are reported but not treated as errors.

  --file <path>   [required]  Path to the .hxlibpkg or .hxlibarch file
  --json                      Output results as JSON

  Examples:
    node cli.js verify-package --file MyLib.hxlibpkg
    node cli.js verify-package --file archive.hxlibarch --json

──────────────────────────────────────────────────────────────────────────────
`);
}

// ===========================================================================
// COMMAND: verify-package
// ===========================================================================
function cmdVerifyPackage(args) {
    const filePath = args['file'];
    if (!filePath)                { die('--file is required'); }
    if (!fs.existsSync(filePath)) { die('File not found: ' + filePath); }

    const ext = path.extname(filePath).toLowerCase();
    const results = [];

    if (ext === '.hxlibarch') {
        // Verify each inner .hxlibpkg
        let archiveZip;
        try {
            const rawArchBuf2 = fs.readFileSync(filePath);
            const outerZipBuf2 = unpackContainer(rawArchBuf2, CONTAINER_MAGIC_ARC);
            archiveZip = new AdmZip(outerZipBuf2);
        } catch (e) {
            die('Failed to read archive: ' + e.message);
        }
        const pkgEntries = archiveZip.getEntries().filter(
            e => !e.isDirectory && e.entryName.toLowerCase().endsWith('.hxlibpkg')
        );
        if (pkgEntries.length === 0) die('No .hxlibpkg packages found in archive.');

        pkgEntries.forEach(function (pkgEntry) {
            try {
                const innerZipBuf2 = unpackContainer(pkgEntry.getData(), CONTAINER_MAGIC_PKG);
                const innerZip = new AdmZip(innerZipBuf2);
                const sigResult = verifyPackageSignature(innerZip);
                results.push({ package: pkgEntry.entryName, signed: sigResult.signed, valid: sigResult.valid, errors: sigResult.errors, warnings: sigResult.warnings });
            } catch (e) {
                results.push({ package: pkgEntry.entryName, signed: false, valid: false, errors: ['Failed to read: ' + e.message], warnings: [] });
            }
        });
    } else {
        // Single .hxlibpkg
        try {
            const rawPkgBuf2 = fs.readFileSync(filePath);
            const zipBuf2 = unpackContainer(rawPkgBuf2, CONTAINER_MAGIC_PKG);
            const zip = new AdmZip(zipBuf2);
            const sigResult = verifyPackageSignature(zip);
            results.push({ package: path.basename(filePath), signed: sigResult.signed, valid: sigResult.valid, errors: sigResult.errors, warnings: sigResult.warnings });
        } catch (e) {
            die('Failed to read package: ' + e.message);
        }
    }

    if (args['json']) {
        console.log(JSON.stringify(results, null, 2));
        const anyFailed = results.some(r => r.signed && !r.valid);
        if (anyFailed) {
            process.exit(1);
        }
    } else {
        results.forEach(function (r) {
            const status = !r.signed ? 'UNSIGNED' : (r.valid ? 'VALID' : 'FAILED');
            console.log(`${r.package}: ${status}`);
            r.errors.forEach(e   => console.log(`  [ERROR]   ${e}`));
            r.warnings.forEach(w => console.log(`  [WARNING] ${w}`));
        });
        const anySigned = results.some(r => r.signed);
        const anyFailed = results.some(r => r.signed && !r.valid);
        const allSignedValid = anySigned && results.every(r => !r.signed || r.valid);
        if (anyFailed) {
            console.log('\nResult: INTEGRITY CHECK FAILED');
            process.exit(1);
        } else if (allSignedValid) {
            console.log('\nResult: ALL PACKAGES VERIFIED');
        } else {
            console.log('\nResult: NO SIGNED PACKAGES FOUND');
        }
    }
}

// ===========================================================================
// Fatal error helper
// ===========================================================================
function die(msg) {
    process.stderr.write('Error: ' + msg + '\n');
    process.exit(1);
}

// ===========================================================================
// Entry point
// ===========================================================================
const args    = parseArgs(process.argv.slice(2));
const command = args._[0];

switch (command) {
    case 'list-libs':       cmdListLibs(args);       break;
    case 'import-lib':      cmdImportLib(args);      break;
    case 'import-archive':  cmdImportArchive(args);  break;
    case 'export-lib':      cmdExportLib(args);      break;
    case 'export-archive':  cmdExportArchive(args);  break;
    case 'delete-lib':      cmdDeleteLib(args);      break;
    case 'create-package':  cmdCreatePackage(args);  break;
    case 'list-versions':   cmdListVersions(args);   break;
    case 'rollback-lib':    cmdRollbackLib(args);    break;
    case 'generate-syslib-hashes':  cmdGenerateSyslibHashes(args);  break;
    case 'verify-syslib-hashes':    cmdVerifySyslibHashes(args);    break;
    case 'verify-package':          cmdVerifyPackage(args);          break;
    case 'help':
    case '--help':
    case '-h':
    case undefined:
        printHelp();
        break;
    default:
        process.stderr.write(`Unknown command: "${command}"\n`);
        printHelp();
        process.exit(1);
}
