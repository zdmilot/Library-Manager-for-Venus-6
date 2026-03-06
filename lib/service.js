// SPDX-License-Identifier: Apache-2.0
/**
 * Library Manager for Venus 6 - Service Layer  v1.8.6
 *
 * Copyright (c) 2026 Zachary Milot
 * Author: Zachary Milot
 *
 * Unified business-logic layer that provides structured, presentation-agnostic
 * access to all library management operations.  This module is consumed by:
 *
 *   - cli.js        (command-line interface)
 *   - com-bridge.js  (COM object bridge dispatcher)
 *
 * Every public function returns a plain JS result object — never writes to
 * stdout/stderr and never calls process.exit().  Callers decide how to
 * present results or propagate errors.
 *
 * Usage:
 *   const service = require('./lib/service');
 *   const ctx = service.createContext();          // or with overrides
 *   const libs = service.listLibraries(ctx);
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const AdmZip = require('adm-zip');
const shared = require('./shared');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const DEFAULT_LIB_PATH  = 'C:\\Program Files (x86)\\HAMILTON\\Library';
const DEFAULT_MET_PATH  = 'C:\\Program Files (x86)\\HAMILTON\\Methods';
const LOCAL_DATA_DIR    = path.join(__dirname, '..', 'local');
const PACKAGE_STORE_DIR = path.join(LOCAL_DATA_DIR, 'packages');
const MIME_MAP          = shared.IMAGE_MIME_MAP;
const HSL_METADATA_EXTS = shared.HSL_METADATA_EXTS;

const DEFAULT_GROUPS = {
    gAll:      { _id: 'gAll',      name: 'All',      'icon-class': 'fa-home',         'default': true, navbar: 'left',  favorite: true  },
    gRecent:   { _id: 'gRecent',   name: 'Recent',   'icon-class': 'fa-history',      'default': true, navbar: 'left',  favorite: true  },
    gStarred:  { _id: 'gStarred',  name: 'Starred',  'icon-class': 'fa-star',         'default': true, navbar: 'left',  favorite: true, 'protected': true },
    gFolders:  { _id: 'gFolders',  name: 'Import',   'icon-class': 'fa-download',     'default': true, navbar: 'right', favorite: false },
    gEditors:  { _id: 'gEditors',  name: 'Export',   'icon-class': 'fa-upload',       'default': true, navbar: 'right', favorite: true  },
    gHistory:  { _id: 'gHistory',  name: 'History',  'icon-class': 'fa-list',         'default': true, navbar: 'right', favorite: true  },
    gOEM:      { _id: 'gOEM',      name: 'OEM',      'icon-class': 'fa-check-circle', 'default': true, navbar: 'left',  favorite: true, 'protected': true }
};

// ---------------------------------------------------------------------------
// VENUS version detection (cached)
// ---------------------------------------------------------------------------
let _cachedVENUSVersion = undefined;
/**
 * Detect the installed Hamilton VENUS version from the Windows registry (cached).
 * @returns {string|null} Version string or null if not found.
 */
function getVENUSVersion() {
    if (_cachedVENUSVersion !== undefined) return _cachedVENUSVersion;
    _cachedVENUSVersion = null;
    try {
        var execFileSync = require('child_process').execFileSync;
        var regPaths = [
            'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        ];
        for (var rp of regPaths) {
            try {
                var subkeysRaw = execFileSync('reg', ['query', rp], { encoding: 'utf8', timeout: 10000 });
                var subkeys = subkeysRaw.split('\n').map(function(l){return l.trim();}).filter(function(l){return l.length > 0;});
                for (var sk of subkeys) {
                    try {
                        var entryRaw = execFileSync('reg', ['query', sk, '/v', 'DisplayName'], { encoding: 'utf8', timeout: 5000 });
                        if (!/Hamilton\s+VENUS\s+\d/i.test(entryRaw)) continue;
                        var allVals = execFileSync('reg', ['query', sk], { encoding: 'utf8', timeout: 5000 });
                        var verMatch = allVals.match(/DisplayVersion\s+REG_SZ\s+(.+)/i);
                        if (verMatch) { _cachedVENUSVersion = verMatch[1].trim(); return _cachedVENUSVersion; }
                    } catch (_) {}
                }
            } catch (_) {}
        }
    } catch (_) {}
    return _cachedVENUSVersion;
}

// ---------------------------------------------------------------------------
// System library helpers
// ---------------------------------------------------------------------------
let _systemLibIds = null;
let _systemLibNames = null;

/**
 * Load system library IDs from the bundled JSON catalog (cached).
 * @returns {Set<string>} Set of system library ID strings.
 */
function loadSystemLibIds() {
    if (_systemLibIds) return _systemLibIds;
    try {
        var sysPath = path.join(__dirname, '..', 'db', 'system_libraries.json');
        var data = JSON.parse(fs.readFileSync(sysPath, 'utf8'));
        _systemLibIds   = new Set(data.map(function(e){ return e._id; }));
        _systemLibNames = new Set(data.map(function(e){ return e.canonical_name; }));
    } catch (_) {
        _systemLibIds   = new Set();
        _systemLibNames = new Set();
    }
    return _systemLibIds;
}

/**
 * Load system library canonical names (cached).
 * @returns {Set<string>} Set of system library name strings.
 */
function loadSystemLibNames() {
    if (!_systemLibNames) loadSystemLibIds();
    return _systemLibNames;
}

/** @param {string} libId @returns {boolean} True if the ID belongs to a system library. */
function isSystemLibrary(libId)        { return loadSystemLibIds().has(libId); }
/** @param {string} libName @returns {boolean} True if the name belongs to a system library. */
function isSystemLibraryByName(libName){ return loadSystemLibNames().has(libName); }

// ---------------------------------------------------------------------------
// ZIP helpers
// ---------------------------------------------------------------------------
/** Computes ZIP directory for a file, preserving subfolder structure. */
function zipSubdir(baseZipDir, relPath) {
    var relDir = path.dirname(relPath).replace(/\\/g, '/');
    return relDir && relDir !== '.' ? baseZipDir + '/' + relDir : baseZipDir;
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------
/**
 * Create the local data directory with required subdirectories and seed files.
 * @param {string} dirPath - Directory path to initialize.
 */
function ensureLocalDataDir(dirPath) {
    if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
    ['packages', 'exports'].forEach(function(sub) {
        var subPath = path.join(dirPath, sub);
        if (!fs.existsSync(subPath)) fs.mkdirSync(subPath, { recursive: true });
    });
    var seeds = {
        'settings.json':       '[{"_id":"0"}]',
        'installed_libs.json': '[]',
        'groups.json':         '[]',
        'tree.json':           '[{"group-id":"gAll","method-ids":[],"locked":false},{"group-id":"gRecent","method-ids":[],"locked":false},{"group-id":"gFolders","method-ids":[],"locked":false},{"group-id":"gEditors","method-ids":[],"locked":false},{"group-id":"gHistory","method-ids":[],"locked":false},{"group-id":"gOEM","method-ids":[],"locked":true}]',
        'links.json':          '[]'
    };
    for (var fname in seeds) {
        var fpath = path.join(dirPath, fname);
        if (!fs.existsSync(fpath)) fs.writeFileSync(fpath, seeds[fname], 'utf8');
    }
}

/**
 * Connect to the local diskdb database.
 * @param {string} dbDir - Path to the database directory.
 * @returns {object} Connected diskdb instance.
 */
function connectDB(dbDir) {
    var diskdb = require('diskdb');
    return diskdb.connect(dbDir, ['installed_libs', 'links', 'groups', 'settings', 'tree']);
}

/**
 * Resolve and initialize the database directory path.
 * @param {string} [dbPathOverride] - Optional override; defaults to LOCAL_DATA_DIR.
 * @returns {string} Resolved database directory path.
 */
function resolveDBPath(dbPathOverride) {
    var dbPath = dbPathOverride ? path.resolve(dbPathOverride) : LOCAL_DATA_DIR;
    ensureLocalDataDir(dbPath);
    return dbPath;
}

/**
 * Get the file path to the local publisher certificate registry.
 * @returns {string} Absolute path to publisher_registry.json.
 */
function resolvePublisherRegistryPath() {
    return path.join(LOCAL_DATA_DIR, 'publisher_registry.json');
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------
/**
 * Retrieve the current Windows username.
 * @returns {string} Username or 'Unknown' if unavailable.
 */
function getWindowsUsername() {
    try {
        return os.userInfo().username || process.env.USERNAME || process.env.USER || 'Unknown';
    } catch (_) {
        return process.env.USERNAME || process.env.USER || 'Unknown';
    }
}

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------
/**
 * Build a structured audit trail entry with environment metadata.
 * @param {string} eventType - Event identifier (e.g. 'library_imported').
 * @param {object} [details] - Additional event-specific details.
 * @returns {object} Audit trail entry object.
 */
function buildAuditTrailEntry(eventType, details) {
    return {
        event:           eventType,
        timestamp:       new Date().toISOString(),
        username:        getWindowsUsername(),
        windows_version: shared.getWindowsVersion(),
        venus_version:   getVENUSVersion() || 'N/A',
        hostname:        os.hostname(),
        details:         details || {}
    };
}

/**
 * Append an entry to the audit trail JSON file, rotating if over 10 000 entries.
 * @param {string} userDataDir - Directory containing audit_trail.json.
 * @param {object} entry - Audit trail entry from buildAuditTrailEntry().
 */
function appendAuditTrailEntry(userDataDir, entry) {
    try {
        var filePath = path.join(userDataDir, 'audit_trail.json');
        var trail = [];
        if (fs.existsSync(filePath)) {
            try { trail = JSON.parse(fs.readFileSync(filePath, 'utf8')); if (!Array.isArray(trail)) trail = []; }
            catch (_) { trail = []; }
        }
        trail.push(entry);
        var MAX = 10000;
        if (trail.length > MAX) {
            var archivePath = filePath.replace(/\.json$/, '_' + new Date().toISOString().replace(/[:.]/g, '-') + '.json');
            try { fs.writeFileSync(archivePath, JSON.stringify(trail.slice(0, trail.length - MAX), null, 2), 'utf8'); } catch (_) {}
            trail = trail.slice(trail.length - MAX);
        }
        fs.writeFileSync(filePath, JSON.stringify(trail, null, 2), 'utf8');
    } catch (_) { /* best-effort */ }
}

// ---------------------------------------------------------------------------
// Install paths
// ---------------------------------------------------------------------------
/**
 * Resolve library and methods base install directories.
 * @param {object} db - Connected diskdb instance.
 * @param {string} [libDirOverride] - Override for library directory.
 * @param {string} [metDirOverride] - Override for methods directory.
 * @returns {{ libBasePath: string, metBasePath: string }}
 */
function getInstallPaths(db, libDirOverride, metDirOverride) {
    var libBasePath = DEFAULT_LIB_PATH;
    var metBasePath = DEFAULT_MET_PATH;
    if (libDirOverride) {
        libBasePath = libDirOverride;
    } else {
        try { var rec = db.links.findOne({ _id: 'lib-folder' }); if (rec && rec.path) libBasePath = rec.path; } catch(_){}
    }
    if (metDirOverride) {
        metBasePath = metDirOverride;
    } else {
        try { var rec2 = db.links.findOne({ _id: 'met-folder' }); if (rec2 && rec2.path) metBasePath = rec2.path; } catch(_){}
    }
    return { libBasePath: libBasePath, metBasePath: metBasePath };
}

// ---------------------------------------------------------------------------
// Group helpers
// ---------------------------------------------------------------------------
/**
 * Find a navigation group by ID, checking defaults first then the database.
 * @param {object} db - Connected diskdb instance.
 * @param {string} id - Group ID.
 * @returns {object|null} Group record or null.
 */
function getGroupById(db, id) {
    if (DEFAULT_GROUPS[id]) return DEFAULT_GROUPS[id];
    try { return db.groups.findOne({ _id: id }); } catch(_) { return null; }
}

/**
 * Automatically assign a library to the appropriate navigation group.
 * @param {object} db - Connected diskdb instance.
 * @param {string} savedLibId - Database ID of the saved library record.
 * @param {string} authorName - Library author name (used for OEM grouping).
 */
function autoAddToGroup(db, savedLibId, authorName) {
    try {
        var navtree = db.tree.find();
        var targetGroupId = null;
        if (shared.isRestrictedAuthor(authorName)) {
            var oemTreeEntry = null;
            for (var i = 0; i < navtree.length; i++) {
                if (navtree[i]['group-id'] === 'gOEM') { oemTreeEntry = navtree[i]; break; }
            }
            if (oemTreeEntry) {
                targetGroupId = 'gOEM';
                var ids = oemTreeEntry['method-ids'] || [];
                ids.push(savedLibId);
                db.tree.update({ 'group-id': 'gOEM' }, { 'method-ids': ids }, { multi: false, upsert: false });
            } else {
                db.tree.save({ 'group-id': 'gOEM', 'method-ids': [savedLibId], locked: true });
                targetGroupId = 'gOEM';
            }
        } else {
            for (var j = 0; j < navtree.length; j++) {
                var gEntry = getGroupById(db, navtree[j]['group-id']);
                if (gEntry && !gEntry['default']) {
                    targetGroupId = navtree[j]['group-id'];
                    var mids = navtree[j]['method-ids'] || [];
                    mids.push(savedLibId);
                    db.tree.update({ 'group-id': targetGroupId }, { 'method-ids': mids }, { multi: false, upsert: false });
                    break;
                }
            }
        }
        if (!targetGroupId) {
            var newGroup = db.groups.save({ name: 'Libraries', 'icon-class': 'fa-book', 'default': false, navbar: 'left', favorite: true });
            db.tree.save({ 'group-id': newGroup._id, 'method-ids': [savedLibId], locked: false });
        }
    } catch (_) { /* non-critical */ }
}

// ---------------------------------------------------------------------------
// HSL dependency extraction
// ---------------------------------------------------------------------------
/**
 * Extract external HSL include dependencies from library source files.
 * @param {string[]} libFiles - Relative paths of library files.
 * @param {string} libBasePath - Base directory containing the library files.
 * @returns {Array<{include: string, sourceFile: string, libraryName: string|null, type: string}>}
 */
function extractRequiredDependencies(libFiles, libBasePath) {
    var ownFiles = {};
    (libFiles || []).forEach(function(f) {
        ownFiles[f.toLowerCase()] = true;
        ownFiles[path.basename(f).toLowerCase()] = true;
    });
    var allIncludes = [];
    (libFiles || []).forEach(function(fname) {
        var ext = path.extname(fname).toLowerCase();
        if (ext !== '.hsl' && ext !== '.hs_' && ext !== '.hsi') return;
        var fullPath = path.join(libBasePath, fname);
        try {
            var text = fs.readFileSync(fullPath, 'utf8');
            shared.extractHslIncludes(text).forEach(function(inc) {
                allIncludes.push({ include: inc, sourceFile: fname });
            });
        } catch (_) {}
    });
    var seen = {};
    var dependencies = [];
    allIncludes.forEach(function(item) {
        var normalized = item.include.replace(/\\/g, '/').toLowerCase();
        if (seen[normalized]) return;
        seen[normalized] = true;
        var targetFileName = normalized.split('/').pop();
        if (ownFiles[targetFileName]) return;
        dependencies.push({ include: item.include, sourceFile: item.sourceFile, libraryName: null, type: 'unknown' });
    });
    return dependencies;
}

// ---------------------------------------------------------------------------
// Package install core
// ---------------------------------------------------------------------------
/**
 * Install a validated package on disk and register it in the database.
 * Extracts library files and demo methods, computes integrity hashes,
 * parses public HSL functions, and writes the database record.
 *
 * @param {object}  manifest    - Parsed manifest.json from the package.
 * @param {object}  zip         - AdmZip instance of the unpacked package.
 * @param {string}  libDestDir  - Target install directory for library files.
 * @param {string}  demoDestDir - Target install directory for demo methods.
 * @param {string}  sourceName  - Display name of the import source (e.g. filename).
 * @param {object}  db          - diskdb database instance.
 * @param {boolean} skipGroup   - If true, skip auto-assigning library groups.
 * @param {object}  sigResult   - Signature verification result from shared.verifyPackageSignature().
 * @returns {{ libraryName: string, version: string, author: string, filesExtracted: number, libInstallPath: string, demoInstallPath: string, signatureStatus: string, comDlls: string[] }}
 */
function installPackage(manifest, zip, libDestDir, demoDestDir, sourceName, db, skipGroup, sigResult) {
    var libFiles  = manifest.library_files     || [];
    var demoFiles = manifest.demo_method_files || [];
    var comDlls   = manifest.com_register_dlls || [];
    var declaredHelp = manifest.help_files || [];
    var helpFiles = declaredHelp.slice();
    var filteredLibFiles = [];
    libFiles.forEach(function(f) {
        if (path.extname(f).toLowerCase() === '.chm') {
            if (helpFiles.indexOf(f) === -1) helpFiles.push(f);
        } else {
            filteredLibFiles.push(f);
        }
    });
    if ((filteredLibFiles.length > 0 || helpFiles.length > 0) && !fs.existsSync(libDestDir)) {
        fs.mkdirSync(libDestDir, { recursive: true });
    }
    if (demoFiles.length > 0 && !fs.existsSync(demoDestDir)) {
        fs.mkdirSync(demoDestDir, { recursive: true });
    }
    var extractedCount = 0;
    zip.getEntries().forEach(function(entry) {
        if (entry.isDirectory || entry.entryName === 'manifest.json' || entry.entryName === 'signature.json') return;
        if (entry.entryName.startsWith('library/')) {
            var fname = entry.entryName.substring('library/'.length);
            if (fname) {
                var safePath = shared.safeZipExtractPath(libDestDir, fname);
                if (!safePath) return;
                var parentDir = path.dirname(safePath);
                if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
                fs.writeFileSync(safePath, entry.getData());
                extractedCount++;
            }
        } else if (entry.entryName.startsWith('demo_methods/')) {
            var fname2 = entry.entryName.substring('demo_methods/'.length);
            if (fname2) {
                var safePath2 = shared.safeZipExtractPath(demoDestDir, fname2);
                if (!safePath2) return;
                var parentDir2 = path.dirname(safePath2);
                if (!fs.existsSync(parentDir2)) fs.mkdirSync(parentDir2, { recursive: true });
                fs.writeFileSync(safePath2, entry.getData());
                extractedCount++;
            }
        } else if (entry.entryName.startsWith('help_files/')) {
            var fname3 = entry.entryName.substring('help_files/'.length);
            if (fname3) {
                var safePath3 = shared.safeZipExtractPath(libDestDir, fname3);
                if (!safePath3) return;
                var parentDir3 = path.dirname(safePath3);
                if (!fs.existsSync(parentDir3)) fs.mkdirSync(parentDir3, { recursive: true });
                fs.writeFileSync(safePath3, entry.getData());
                extractedCount++;
            }
        }
    });
    var existing = db.installed_libs.findOne({ library_name: manifest.library_name });
    if (existing) db.installed_libs.remove({ _id: existing._id });
    var fileHashes = shared.computeLibraryHashes(filteredLibFiles, libDestDir, comDlls);
    var publicFunctions = shared.extractPublicFunctions(filteredLibFiles, libDestDir);
    var requiredDependencies = extractRequiredDependencies(filteredLibFiles, libDestDir);
    var dbRecord = {
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
        required_dependencies: requiredDependencies,
        app_version:         manifest.app_version         || '',
        format_version:      manifest.format_version      || '1.0',
        windows_version:     manifest.windows_version     || '',
        venus_version:       manifest.venus_version       || '',
        package_lineage:     manifest.package_lineage     || [],
        publisher_cert:      (sigResult && sigResult.code_signed && sigResult.valid && sigResult.publisher_cert) ? sigResult.publisher_cert : null
    };
    Object.keys(manifest).forEach(function(k) {
        if (shared.KNOWN_MANIFEST_KEYS.indexOf(k) === -1 && !(k in dbRecord)) dbRecord[k] = manifest[k];
    });
    var saved = db.installed_libs.save(dbRecord);
    if (!skipGroup) autoAddToGroup(db, saved._id, manifest.author);
    return { extractedCount: extractedCount, libName: manifest.library_name };
}

// ---------------------------------------------------------------------------
// Package store helpers
// ---------------------------------------------------------------------------
/**
 * Resolve the package store directory path.
 * @param {string} [storeDirOverride] - Override path; defaults to PACKAGE_STORE_DIR.
 * @returns {string} Resolved package store directory.
 */
function getPackageStoreDir(storeDirOverride) {
    return storeDirOverride ? path.resolve(storeDirOverride) : PACKAGE_STORE_DIR;
}

/**
 * Build a timestamped filename for a cached package.
 * @param {string} libName - Library name.
 * @param {string} version - Library version string.
 * @returns {string} Filename in the form `Name_vX.Y.Z_YYYYMMDD-HHMMSS.hxlibpkg`.
 */
function buildCachedPackageName(libName, version) {
    var safe = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
    var ver  = (version || '0.0.0').replace(/[<>:"\/\\|?*]/g, '_');
    var now  = new Date();
    var stamp = now.getFullYear().toString()
              + String(now.getMonth() + 1).padStart(2, '0')
              + String(now.getDate()).padStart(2, '0')
              + '-'
              + String(now.getHours()).padStart(2, '0')
              + String(now.getMinutes()).padStart(2, '0')
              + String(now.getSeconds()).padStart(2, '0');
    return safe + '_v' + ver + '_' + stamp + '.hxlibpkg';
}

function cachePackage(pkgBuffer, libName, version, storeDirOverride) {
    var storeRoot = getPackageStoreDir(storeDirOverride);
    var safeName  = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
    var libDir    = path.join(storeRoot, safeName);
    if (!fs.existsSync(libDir)) fs.mkdirSync(libDir, { recursive: true });
    var fileName = buildCachedPackageName(libName, version);
    var destPath = path.join(libDir, fileName);
    fs.writeFileSync(destPath, pkgBuffer);
    return destPath;
}

function listCachedVersions(libName, storeDirOverride) {
    var storeRoot = getPackageStoreDir(storeDirOverride);
    var safeName  = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
    var libDir    = path.join(storeRoot, safeName);
    if (!fs.existsSync(libDir)) return [];
    var files = fs.readdirSync(libDir).filter(function(f){ return f.toLowerCase().endsWith('.hxlibpkg'); });
    var entries = files.map(function(f) {
        var fullPath = path.join(libDir, f);
        var version = '?', createdDate = '', author = '';
        try {
            var rawBuf = fs.readFileSync(fullPath);
            var zipBuf = shared.unpackContainer(rawBuf, shared.CONTAINER_MAGIC_PKG);
            var z = new AdmZip(zipBuf);
            var me = z.getEntry('manifest.json');
            if (me) { var m = JSON.parse(z.readAsText(me)); version = m.version || '?'; createdDate = m.created_date || ''; author = m.author || ''; }
        } catch (_) {}
        var stat = fs.statSync(fullPath);
        return { file: f, version: version, author: author, created: createdDate, cached: stat.mtime.toISOString(), size: stat.size, fullPath: fullPath };
    });
    entries.sort(function(a, b){ return b.cached.localeCompare(a.cached); });
    return entries;
}

/**
 * Find a library record by name or database ID.
 * @param {object} db - Connected diskdb instance.
 * @param {string} nameOrId - Library name or _id.
 * @returns {object|null} Library record or null.
 */
function findLibrary(db, nameOrId) {
    if (!nameOrId) return null;
    var byId = db.installed_libs.findOne({ _id: nameOrId });
    if (byId) return byId;
    return db.installed_libs.findOne({ library_name: nameOrId });
}

/**
 * Create parent directories for an output file path if they don't exist.
 * @param {string} filePath - Target file path.
 */
function ensureOutDir(filePath) {
    var dir = path.dirname(path.resolve(filePath));
    if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------
function loadSigningCredentials(keyPath, certPath) {
    if (!fs.existsSync(keyPath))  throw new Error('Signing key not found: ' + keyPath);
    if (!fs.existsSync(certPath)) throw new Error('Publisher certificate not found: ' + certPath);
    var privateKeyPem = fs.readFileSync(keyPath, 'utf8');
    var cert;
    try { cert = JSON.parse(fs.readFileSync(certPath, 'utf8')); }
    catch (e) { throw new Error('Failed to parse publisher certificate: ' + e.message); }
    var certCheck = shared.validatePublisherCertificate(cert);
    if (!certCheck.valid) throw new Error('Invalid publisher certificate: ' + certCheck.errors.join('; '));
    return { privateKeyPem: privateKeyPem, cert: cert };
}

function resolveSigningCredentials(signKeyPath, signCertPath) {
    if (!signKeyPath && !signCertPath) return null;
    if (signKeyPath && !signCertPath) {
        var kp = path.resolve(signKeyPath);
        var cp = kp.replace(/\.key\.pem$/i, '.cert.json');
        if (!fs.existsSync(cp)) throw new Error('--sign-key specified but no matching .cert.json found.');
        return loadSigningCredentials(kp, cp);
    }
    if (!signKeyPath && signCertPath) throw new Error('--sign-cert requires --sign-key.');
    return loadSigningCredentials(path.resolve(signKeyPath), path.resolve(signCertPath));
}

// ===========================================================================
// PUBLIC SERVICE API
// ===========================================================================

/**
 * Create a service context with optional overrides.
 * @param {object} [opts]
 * @param {string} [opts.dbPath]    - Override local data directory
 * @param {string} [opts.storeDir]  - Override package store directory
 * @param {string} [opts.libDir]    - Override library install directory
 * @param {string} [opts.metDir]    - Override methods install directory
 * @returns {{ db, dbPath, storeDir, libDir, metDir }}
 */
function createContext(opts) {
    opts = opts || {};
    var dbPath   = resolveDBPath(opts.dbPath);
    var db       = connectDB(dbPath);
    var paths    = getInstallPaths(db, opts.libDir, opts.metDir);
    return {
        db:        db,
        dbPath:    dbPath,
        storeDir:  opts.storeDir || null,
        libBasePath: paths.libBasePath,
        metBasePath: paths.metBasePath
    };
}

// ---------------------------------------------------------------------------
// 1. listLibraries
// ---------------------------------------------------------------------------
/**
 * List installed libraries.
 * @param {object} ctx - Service context from createContext()
 * @param {object} [opts]
 * @param {boolean} [opts.includeDeleted=false]
 * @returns {{ success: boolean, data: object[] }}
 */
function listLibraries(ctx, opts) {
    opts = opts || {};
    var libs = ctx.db.installed_libs.find() || [];
    if (!opts.includeDeleted) libs = libs.filter(function(l){ return !l.deleted; });
    return { success: true, data: libs };
}

// ---------------------------------------------------------------------------
// 2. getLibrary
// ---------------------------------------------------------------------------
/**
 * Get a single library by name or ID.
 * @param {object} ctx
 * @param {string} nameOrId
 * @returns {{ success: boolean, data: object|null, error: string|undefined }}
 */
function getLibrary(ctx, nameOrId) {
    var lib = findLibrary(ctx.db, nameOrId);
    if (!lib) return { success: false, error: 'Library not found: ' + nameOrId };
    return { success: true, data: lib };
}

// ---------------------------------------------------------------------------
// 3. importLibrary
// ---------------------------------------------------------------------------
/**
 * Import a single .hxlibpkg file.
 * @param {object} ctx
 * @param {object} opts
 * @param {string} opts.filePath      - Path to .hxlibpkg file
 * @param {boolean} [opts.force=false]
 * @param {boolean} [opts.noGroup=false]
 * @param {boolean} [opts.noCache=false]
 * @param {string}  [opts.authorPassword]
 * @returns {{ success, data, warnings, error }}
 */
function importLibrary(ctx, opts) {
    opts = opts || {};
    var filePath = opts.filePath;
    if (!filePath) return { success: false, error: '--file is required' };
    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found: ' + filePath };

    var warnings = [];
    var rawPkgBuf;
    try { rawPkgBuf = fs.readFileSync(filePath); } catch(e) { return { success: false, error: 'Cannot read file: ' + e.message }; }

    var zip, manifest;
    try {
        var zipBuf = shared.unpackContainer(rawPkgBuf, shared.CONTAINER_MAGIC_PKG);
        zip = new AdmZip(zipBuf);
        var me = zip.getEntry('manifest.json');
        if (!me) return { success: false, error: 'Invalid package: manifest.json not found' };
        manifest = JSON.parse(zip.readAsText(me));
    } catch (e) {
        return { success: false, error: 'Failed to read package: ' + e.message };
    }

    // Signature verification
    var sigResult = shared.verifyPackageSignature(zip);
    var signatureStatus = 'unsigned';

    if (sigResult.signed) {
        if (sigResult.valid) {
            signatureStatus = 'valid';
        } else {
            signatureStatus = 'failed';
            if (!opts.force) {
                return { success: false, error: 'Package signature verification failed: ' + (sigResult.errors || []).join('; ') };
            }
            warnings.push('Importing despite failed signature (force mode)');
        }
    }

    var libName = manifest.library_name || 'Unknown';
    if (!shared.isValidLibraryName(libName)) {
        return { success: false, error: 'Invalid library name: "' + libName + '"' };
    }

    var importAuthor = (manifest.author || '').trim();
    var importOrg    = (manifest.organization || '').trim();
    if (importAuthor && importAuthor.length < shared.AUTHOR_MIN_LENGTH)
        return { success: false, error: 'Author must be at least ' + shared.AUTHOR_MIN_LENGTH + ' characters.' };
    if (importAuthor && importAuthor.length > shared.AUTHOR_MAX_LENGTH)
        return { success: false, error: 'Author cannot exceed ' + shared.AUTHOR_MAX_LENGTH + ' characters.' };

    if ((shared.isRestrictedAuthor(importAuthor) || shared.isRestrictedAuthor(importOrg)) && !isSystemLibraryByName(libName)) {
        if (!opts.authorPassword) return { success: false, error: 'Restricted OEM author. Provide authorPassword.' };
        if (!shared.validateAuthorPassword(opts.authorPassword)) return { success: false, error: 'Incorrect author password.' };

        // OEM certificate verification: restricted-author packages must be code-signed
        // with a certificate whose holder name encompasses the OEM identity.
        var pubCert = (sigResult.code_signed && sigResult.valid) ? sigResult.publisher_cert : null;
        var certMatch = shared.validateOemCertificateMatch(importAuthor, importOrg, pubCert);
        if (!certMatch.valid) {
            return { success: false, error: certMatch.error };
        }
    }

    var existingLib = ctx.db.installed_libs.findOne({ library_name: libName });
    if (existingLib && !existingLib.deleted && !opts.force) {
        return { success: false, error: 'Library "' + libName + '" is already installed. Use force to overwrite.' };
    }

    var libDestDir  = path.join(ctx.libBasePath, libName);
    var demoDestDir = path.join(ctx.metBasePath, 'Library Demo Methods', libName);

    var result = installPackage(manifest, zip, libDestDir, demoDestDir, path.basename(filePath), ctx.db, !!opts.noGroup, sigResult);

    // Audit
    try {
        appendAuditTrailEntry(ctx.dbPath, buildAuditTrailEntry('library_imported', {
            library_name: libName, version: manifest.version || '', author: manifest.author || '',
            source_file: path.resolve(filePath), lib_install_path: libDestDir,
            demo_install_path: demoDestDir, files_extracted: result.extractedCount,
            signature_status: signatureStatus
        }));
    } catch (_) {}

    // Cache
    var cachedPath = null;
    if (!opts.noCache) {
        try { cachedPath = cachePackage(rawPkgBuf, libName, manifest.version, ctx.storeDir); } catch(_){}
    }

    return {
        success: true,
        data: {
            libraryName:     libName,
            version:         manifest.version || '',
            author:          manifest.author || '',
            filesExtracted:  result.extractedCount,
            libInstallPath:  libDestDir,
            demoInstallPath: demoDestDir,
            cachedPath:      cachedPath,
            signatureStatus: signatureStatus,
            comDlls:         manifest.com_register_dlls || []
        },
        warnings: warnings
    };
}

// ---------------------------------------------------------------------------
// 4. importArchive
// ---------------------------------------------------------------------------
/**
 * Import a .hxlibarch archive containing multiple packages.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.filePath - Path to .hxlibarch file.
 * @param {boolean} [opts.force=false] - Overwrite existing libraries / ignore signature failures.
 * @param {boolean} [opts.noGroup=false] - Skip automatic group assignment.
 * @param {boolean} [opts.noCache=false] - Skip caching imported packages.
 * @param {string}  [opts.authorPassword] - Password for restricted OEM authors.
 * @returns {{ success: boolean, data: {succeeded: object[], failed: object[]}, error: string|undefined }}
 */
function importArchive(ctx, opts) {
    opts = opts || {};
    var filePath = opts.filePath;
    if (!filePath) return { success: false, error: '--file is required' };
    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found: ' + filePath };

    var archiveZip;
    try {
        var rawArchBuf = fs.readFileSync(filePath);
        var outerZipBuf = shared.unpackContainer(rawArchBuf, shared.CONTAINER_MAGIC_ARC);
        archiveZip = new AdmZip(outerZipBuf);
    } catch (e) {
        return { success: false, error: 'Failed to open archive: ' + e.message };
    }

    var pkgEntries = archiveZip.getEntries().filter(function(e) {
        return !e.isDirectory && e.entryName.toLowerCase().endsWith('.hxlibpkg');
    });
    if (pkgEntries.length === 0) return { success: false, error: 'No .hxlibpkg packages found in archive.' };

    var results = { succeeded: [], failed: [] };

    pkgEntries.forEach(function(pkgEntry) {
        var label = pkgEntry.entryName;
        try {
            var innerZipBuf = shared.unpackContainer(pkgEntry.getData(), shared.CONTAINER_MAGIC_PKG);
            var innerZip = new AdmZip(innerZipBuf);
            var me = innerZip.getEntry('manifest.json');
            if (!me) throw new Error('manifest.json missing');
            var manifest = JSON.parse(innerZip.readAsText(me));
            var libName = manifest.library_name || 'Unknown';
            if (!shared.isValidLibraryName(libName)) throw new Error('Invalid library name: "' + libName + '"');

            var sigRes = shared.verifyPackageSignature(innerZip);
            if (sigRes.signed && !sigRes.valid && !opts.force) throw new Error('Signature verification failed');

            var importAuthor = (manifest.author || '').trim();
            var importOrg    = (manifest.organization || '').trim();
            if ((shared.isRestrictedAuthor(importAuthor) || shared.isRestrictedAuthor(importOrg)) && !isSystemLibraryByName(libName)) {
                if (!opts.authorPassword) throw new Error('Restricted author. Provide authorPassword.');
                if (!shared.validateAuthorPassword(opts.authorPassword)) throw new Error('Incorrect author password.');

                // OEM certificate verification for archive entries
                var pubCert = (sigRes.code_signed && sigRes.valid) ? sigRes.publisher_cert : null;
                var certMatch = shared.validateOemCertificateMatch(importAuthor, importOrg, pubCert);
                if (!certMatch.valid) throw new Error(certMatch.error);
            }

            var existing = ctx.db.installed_libs.findOne({ library_name: libName });
            if (existing && !existing.deleted && !opts.force) throw new Error('"' + libName + '" already installed');

            var libDestDir  = path.join(ctx.libBasePath, libName);
            var demoDestDir = path.join(ctx.metBasePath, 'Library Demo Methods', libName);
            var result = installPackage(manifest, innerZip, libDestDir, demoDestDir, label, ctx.db, !!opts.noGroup, sigRes);

            results.succeeded.push({ libraryName: libName, filesExtracted: result.extractedCount });

            if (!opts.noCache) {
                try { cachePackage(pkgEntry.getData(), libName, manifest.version, ctx.storeDir); } catch(_){}
            }
        } catch (e) {
            results.failed.push({ package: label, error: e.message });
        }
    });

    try {
        appendAuditTrailEntry(ctx.dbPath, buildAuditTrailEntry('archive_imported', {
            archive_file: path.resolve(filePath), packages_total: pkgEntries.length,
            succeeded: results.succeeded.map(function(s){return s.libraryName;}),
            failed: results.failed.map(function(f){return f.package + ': ' + f.error;})
        }));
    } catch (_) {}

    return {
        success: results.failed.length === 0,
        data: results,
        error: results.failed.length > 0 ? results.failed.length + ' package(s) failed' : undefined
    };
}

// ---------------------------------------------------------------------------
// 5. exportLibrary
// ---------------------------------------------------------------------------
/**
 * Export a single installed library as a .hxlibpkg package.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} [opts.name] - Library name (name or id required).
 * @param {string} [opts.id] - Library database ID.
 * @param {string} opts.output - Output file path.
 * @param {string} [opts.signKey] - Path to Ed25519 signing key.
 * @param {string} [opts.signCert] - Path to publisher certificate.
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function exportLibrary(ctx, opts) {
    opts = opts || {};
    var nameOrId = opts.name || opts.id;
    if (!nameOrId) return { success: false, error: 'name or id is required' };
    if (!opts.output) return { success: false, error: 'output path is required' };

    var lib = findLibrary(ctx.db, nameOrId);
    if (!lib) return { success: false, error: 'Library not found: ' + nameOrId };
    if (isSystemLibrary(lib._id)) return { success: false, error: 'System library cannot be exported.' };
    if (lib.deleted) return { success: false, error: 'Deleted library cannot be exported.' };

    var libraryFiles = lib.library_files     || [];
    var demoFiles    = lib.demo_method_files  || [];
    var helpFiles    = lib.help_files         || [];
    var libBasePath  = lib.lib_install_path   || '';
    var demoBasePath = lib.demo_install_path  || '';

    for (var i = 0; i < libraryFiles.length; i++) {
        var fp = path.join(libBasePath, libraryFiles[i]);
        if (!fs.existsSync(fp)) return { success: false, error: 'Library file not found: ' + fp };
    }

    var manifest = {
        format_version:       shared.FORMAT_VERSION,
        library_name:         lib.library_name        || '',
        author:               lib.author               || '',
        organization:         lib.organization         || '',
        version:              lib.version              || '',
        venus_compatibility:  lib.venus_compatibility  || '',
        description:          lib.description          || '',
        github_url:           lib.github_url           || '',
        tags:                 lib.tags                 || [],
        created_date:         new Date().toISOString(),
        library_image:        lib.library_image        || null,
        library_image_base64: lib.library_image_base64 || null,
        library_image_mime:   lib.library_image_mime   || null,
        library_files:        libraryFiles.concat(helpFiles),
        demo_method_files:    demoFiles.slice(),
        help_files:           helpFiles.slice(),
        com_register_dlls:    (lib.com_register_dlls   || []).slice(),
        app_version:          shared.getAppVersion(),
        windows_version:      lib.windows_version      || shared.getWindowsVersion(),
        venus_version:        lib.venus_version         || getVENUSVersion() || '',
        package_lineage:      (lib.package_lineage || []).concat([shared.buildLineageEvent('exported', {
            username: getWindowsUsername(), hostname: os.hostname(), venusVersion: getVENUSVersion() || ''
        })])
    };
    Object.keys(lib).forEach(function(k) {
        if (shared.KNOWN_LIB_DB_KEYS.indexOf(k) === -1 && !(k in manifest)) manifest[k] = lib[k];
    });

    var zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));
    libraryFiles.concat(helpFiles).forEach(function(f) {
        var fp2 = path.join(libBasePath, f);
        if (fs.existsSync(fp2)) zip.addLocalFile(fp2, zipSubdir('library', f));
    });
    demoFiles.forEach(function(f) {
        var fp3 = path.join(demoBasePath, f);
        if (fs.existsSync(fp3)) zip.addLocalFile(fp3, zipSubdir('demo_methods', f));
    });

    var sigCreds = null;
    try { sigCreds = resolveSigningCredentials(opts.signKey, opts.signCert); } catch(e) { return { success: false, error: e.message }; }
    if (sigCreds) shared.signPackageZipWithCert(zip, sigCreds.privateKeyPem, sigCreds.cert);

    ensureOutDir(opts.output);
    fs.writeFileSync(opts.output, shared.packContainer(zip.toBuffer(), shared.CONTAINER_MAGIC_PKG));

    return {
        success: true,
        data: {
            libraryName:   lib.library_name,
            outputPath:    path.resolve(opts.output),
            libraryFiles:  libraryFiles.length,
            demoFiles:     demoFiles.length,
            codeSigned:    !!sigCreds,
            publisher:     sigCreds ? sigCreds.cert.publisher : null
        }
    };
}

// ---------------------------------------------------------------------------
// 6. exportArchive
// ---------------------------------------------------------------------------
/**
 * Export multiple libraries into a single .hxlibarch archive.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.output - Output archive file path.
 * @param {boolean} [opts.all] - Export all non-system libraries.
 * @param {string|string[]} [opts.names] - Comma-separated or array of library names.
 * @param {string|string[]} [opts.ids] - Comma-separated or array of library IDs.
 * @param {string} [opts.signKey] - Path to Ed25519 signing key.
 * @param {string} [opts.signCert] - Path to publisher certificate.
 * @returns {{ success: boolean, data: {outputPath: string, exported: object[], errors: object[]}, error: string|undefined }}
 */
function exportArchive(ctx, opts) {
    opts = opts || {};
    if (!opts.output) return { success: false, error: 'output path is required' };
    if (!opts.all && !opts.names && !opts.ids) return { success: false, error: 'Specify all, names, or ids' };

    var targetLibs = [];
    if (opts.all) {
        targetLibs = (ctx.db.installed_libs.find() || []).filter(function(l){ return !l.deleted && !isSystemLibrary(l._id); });
    } else if (opts.names) {
        var nameList = Array.isArray(opts.names) ? opts.names : opts.names.split(',').map(function(n){return n.trim();});
        nameList.forEach(function(n) {
            var found = ctx.db.installed_libs.findOne({ library_name: n });
            if (found && !found.deleted && !isSystemLibrary(found._id)) targetLibs.push(found);
        });
    } else if (opts.ids) {
        var idList = Array.isArray(opts.ids) ? opts.ids : opts.ids.split(',').map(function(i){return i.trim();});
        idList.forEach(function(id) {
            var found = ctx.db.installed_libs.findOne({ _id: id });
            if (found && !found.deleted && !isSystemLibrary(found._id)) targetLibs.push(found);
        });
    }
    if (targetLibs.length === 0) return { success: false, error: 'No valid libraries selected for export.' };

    var archiveZip   = new AdmZip();
    var exportedLibs = [];
    var errors       = [];
    var sigCreds     = null;
    try { sigCreds = resolveSigningCredentials(opts.signKey, opts.signCert); } catch(e) { return { success: false, error: e.message }; }

    targetLibs.forEach(function(lib) {
        try {
            var libBasePath2 = lib.lib_install_path || '';
            var demoBasePath2 = lib.demo_install_path || '';
            var libraryFiles2 = lib.library_files     || [];
            var demoFiles2    = lib.demo_method_files  || [];
            var helpFiles2    = lib.help_files         || [];

            var manifest2 = {
                format_version:       shared.FORMAT_VERSION,
                library_name:         lib.library_name        || '',
                author:               lib.author               || '',
                organization:         lib.organization         || '',
                version:              lib.version              || '',
                venus_compatibility:  lib.venus_compatibility  || '',
                description:          lib.description          || '',
                github_url:           lib.github_url           || '',
                tags:                 lib.tags                 || [],
                created_date:         new Date().toISOString(),
                library_image:        lib.library_image        || null,
                library_image_base64: lib.library_image_base64 || null,
                library_image_mime:   lib.library_image_mime   || null,
                library_files:        libraryFiles2.concat(helpFiles2),
                demo_method_files:    demoFiles2.slice(),
                help_files:           helpFiles2.slice(),
                com_register_dlls:    (lib.com_register_dlls || []).slice(),
                app_version:          shared.getAppVersion(),
                windows_version:      lib.windows_version || shared.getWindowsVersion(),
                venus_version:        lib.venus_version   || getVENUSVersion() || '',
                package_lineage:      (lib.package_lineage || []).concat([shared.buildLineageEvent('exported', {
                    username: getWindowsUsername(), hostname: os.hostname(), venusVersion: getVENUSVersion() || ''
                })])
            };
            Object.keys(lib).forEach(function(k) {
                if (shared.KNOWN_LIB_DB_KEYS.indexOf(k) === -1 && !(k in manifest2)) manifest2[k] = lib[k];
            });
            var innerZip = new AdmZip();
            innerZip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest2, null, 2), 'utf8'));
            libraryFiles2.concat(helpFiles2).forEach(function(f) {
                var fp4 = path.join(libBasePath2, f);
                if (fs.existsSync(fp4)) innerZip.addLocalFile(fp4, zipSubdir('library', f));
            });
            demoFiles2.forEach(function(f) {
                var fp5 = path.join(demoBasePath2, f);
                if (fs.existsSync(fp5)) innerZip.addLocalFile(fp5, zipSubdir('demo_methods', f));
            });
            if (sigCreds) shared.signPackageZipWithCert(innerZip, sigCreds.privateKeyPem, sigCreds.cert);
            archiveZip.addFile(lib.library_name + '.hxlibpkg', shared.packContainer(innerZip.toBuffer(), shared.CONTAINER_MAGIC_PKG));
            exportedLibs.push({ name: lib.library_name, libraryFiles: (libraryFiles2).length, demoFiles: demoFiles2.length });
        } catch (e) {
            errors.push({ name: lib.library_name || '?', error: e.message });
        }
    });

    if (exportedLibs.length === 0) return { success: false, error: 'No libraries could be exported.' };

    var archManifest = {
        format_version: shared.FORMAT_VERSION, archive_type: 'hxlibarch',
        created_date: new Date().toISOString(), library_count: exportedLibs.length,
        libraries: exportedLibs.map(function(l){return l.name;}),
        app_version: shared.getAppVersion(), windows_version: shared.getWindowsVersion(),
        venus_version: getVENUSVersion() || ''
    };
    archiveZip.addFile('archive_manifest.json', Buffer.from(JSON.stringify(archManifest, null, 2), 'utf8'));

    ensureOutDir(opts.output);
    fs.writeFileSync(opts.output, shared.packContainer(archiveZip.toBuffer(), shared.CONTAINER_MAGIC_ARC));

    return { success: true, data: { outputPath: path.resolve(opts.output), exported: exportedLibs, errors: errors } };
}

// ---------------------------------------------------------------------------
// 7. deleteLibrary
// ---------------------------------------------------------------------------
/**
 * Delete an installed library (soft-delete by default).
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} [opts.name] - Library name (name or id required).
 * @param {string} [opts.id] - Library database ID.
 * @param {boolean} [opts.keepFiles=false] - Keep library files on disk.
 * @param {boolean} [opts.hard=false] - Permanently remove the database record.
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function deleteLibrary(ctx, opts) {
    opts = opts || {};
    var nameOrId = opts.name || opts.id;
    if (!nameOrId) return { success: false, error: 'name or id is required' };

    var lib = findLibrary(ctx.db, nameOrId);
    if (!lib) return { success: false, error: 'Library not found: ' + nameOrId };
    if (isSystemLibrary(lib._id)) return { success: false, error: 'System library cannot be deleted.' };

    var displayName = lib.library_name || nameOrId;

    if (!opts.keepFiles) {
        var libFiles  = lib.library_files || [];
        var helpFiles = lib.help_files    || [];
        var libPath   = lib.lib_install_path || '';
        if (libPath && (libFiles.length > 0 || helpFiles.length > 0)) {
            libFiles.concat(helpFiles).forEach(function(f) {
                try { var fp = path.join(libPath, f); if (fs.existsSync(fp)) fs.unlinkSync(fp); } catch(_){}
            });
            try { if (fs.existsSync(libPath) && fs.readdirSync(libPath).length === 0) fs.rmdirSync(libPath); } catch(_){}
        }
        var demoFiles = lib.demo_method_files || [];
        var demoPath  = lib.demo_install_path || '';
        if (demoPath && demoFiles.length > 0) {
            demoFiles.forEach(function(f) {
                try { var fp2 = path.join(demoPath, f); if (fs.existsSync(fp2)) fs.unlinkSync(fp2); } catch(_){}
            });
            try { if (fs.existsSync(demoPath) && fs.readdirSync(demoPath).length === 0) fs.rmdirSync(demoPath); } catch(_){}
        }
    }

    if (opts.hard) {
        ctx.db.installed_libs.remove({ _id: lib._id });
    } else {
        ctx.db.installed_libs.update({ _id: lib._id }, { deleted: true, deleted_date: new Date().toISOString() }, { multi: false, upsert: false });
    }

    // Remove from navigation tree
    try {
        var navtree = ctx.db.tree.find() || [];
        for (var i = 0; i < navtree.length; i++) {
            var mids = navtree[i]['method-ids'] || [];
            var idx  = mids.indexOf(lib._id);
            if (idx !== -1) {
                mids.splice(idx, 1);
                ctx.db.tree.update({ 'group-id': navtree[i]['group-id'] }, { 'method-ids': mids }, { multi: false, upsert: false });
            }
        }
    } catch(_){}

    try {
        appendAuditTrailEntry(ctx.dbPath, buildAuditTrailEntry('library_deleted', {
            library_name: displayName, version: lib.version || '', author: lib.author || '',
            delete_type: opts.hard ? 'hard' : 'soft', keep_files: !!opts.keepFiles
        }));
    } catch (_) {}

    return { success: true, data: { libraryName: displayName, deleteType: opts.hard ? 'hard' : 'soft', keepFiles: !!opts.keepFiles, comDlls: lib.com_register_dlls || [] } };
}

// ---------------------------------------------------------------------------
// 8. createPackage
// ---------------------------------------------------------------------------
/**
 * Create a .hxlibpkg package from a spec file.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.specPath - Path to the JSON spec file.
 * @param {string} opts.output - Output package file path.
 * @param {string} [opts.signKey] - Path to Ed25519 signing key.
 * @param {string} [opts.signCert] - Path to publisher certificate.
 * @param {string} [opts.authorPassword] - Password for restricted OEM authors.
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function createPackage(ctx, opts) {
    opts = opts || {};
    if (!opts.specPath)  return { success: false, error: 'specPath is required' };
    if (!opts.output)    return { success: false, error: 'output path is required' };

    var specPath = path.resolve(opts.specPath);
    if (!fs.existsSync(specPath)) return { success: false, error: 'Spec file not found: ' + specPath };

    var spec;
    try { spec = JSON.parse(fs.readFileSync(specPath, 'utf8')); }
    catch (e) { return { success: false, error: 'Failed to parse spec file: ' + e.message }; }

    var errs = [];
    if (!spec.author) errs.push('"author" is required');
    if (spec.author && spec.author.trim().length < shared.AUTHOR_MIN_LENGTH) errs.push('"author" too short');
    if (spec.author && spec.author.trim().length > shared.AUTHOR_MAX_LENGTH) errs.push('"author" too long');
    if (!spec.version) errs.push('"version" is required');
    if (!spec.venus_compatibility) errs.push('"venus_compatibility" is required');
    if (!spec.description) errs.push('"description" is required');
    if (!spec.library_files || spec.library_files.length === 0) errs.push('"library_files" is required');
    if (errs.length > 0) return { success: false, error: 'Spec validation failed: ' + errs.join('; ') };

    if (shared.isRestrictedAuthor(spec.author) || shared.isRestrictedAuthor(spec.organization)) {
        if (!opts.authorPassword) return { success: false, error: 'Restricted OEM author. Provide authorPassword.' };
        if (!shared.validateAuthorPassword(opts.authorPassword)) return { success: false, error: 'Incorrect author password.' };
    }

    if (spec.tags && Array.isArray(spec.tags)) {
        spec.tags = shared.sanitizeTags(spec.tags);
        var tagCheck = shared.filterReservedTags(spec.tags);
        if (tagCheck.removed.length > 0) return { success: false, error: 'Reserved tags not allowed: ' + tagCheck.removed.join(', ') };
    }

    var specDir = path.dirname(specPath);
    var resolvedLibFiles  = (spec.library_files    || []).map(function(f){return path.resolve(specDir, f);});
    var resolvedDemoFiles = (spec.demo_method_files || []).map(function(f){return path.resolve(specDir, f);});
    var resolvedImagePath = spec.library_image ? path.resolve(specDir, spec.library_image) : null;

    for (var i = 0; i < resolvedLibFiles.length; i++) {
        if (!fs.existsSync(resolvedLibFiles[i])) return { success: false, error: 'Library file not found: ' + resolvedLibFiles[i] };
    }
    for (var j = 0; j < resolvedDemoFiles.length; j++) {
        if (!fs.existsSync(resolvedDemoFiles[j])) return { success: false, error: 'Demo file not found: ' + resolvedDemoFiles[j] };
    }

    var libName = spec.library_name || null;
    if (!libName) {
        var priority = ['.hsl', '.hs_', '.smt'];
        for (var ext of priority) {
            var match = resolvedLibFiles.find(function(f){return path.extname(f).toLowerCase() === ext;});
            if (match) { libName = path.basename(match, path.extname(match)); break; }
        }
        if (!libName) libName = path.basename(path.dirname(resolvedLibFiles[0])) || 'Unknown';
    }
    if (!shared.isValidLibraryName(libName)) return { success: false, error: 'Invalid library name: "' + libName + '"' };

    var libraryImageFilename = null, libraryImageBase64 = null, libraryImageMime = null, iconSourcePath = null;
    if (resolvedImagePath && fs.existsSync(resolvedImagePath)) {
        iconSourcePath       = resolvedImagePath;
        libraryImageFilename = path.basename(resolvedImagePath);
        libraryImageMime     = MIME_MAP[path.extname(resolvedImagePath).toLowerCase()] || 'image/png';
        libraryImageBase64   = fs.readFileSync(resolvedImagePath).toString('base64');
    } else {
        var bmpName = libName.toLowerCase() + '.bmp';
        var bmpFound = resolvedLibFiles.find(function(f){return path.basename(f).toLowerCase() === bmpName;});
        if (bmpFound) {
            libraryImageFilename = path.basename(bmpFound);
            libraryImageMime = 'image/bmp';
            libraryImageBase64 = fs.readFileSync(bmpFound).toString('base64');
        }
    }

    var comDlls = spec.com_register_dlls || [];
    var specHelpFiles = spec.help_files || [];
    var resolvedHelpFiles = specHelpFiles.map(function(f){return path.resolve(specDir, f);});
    for (var k = 0; k < resolvedHelpFiles.length; k++) {
        if (!fs.existsSync(resolvedHelpFiles[k])) return { success: false, error: 'Help file not found: ' + resolvedHelpFiles[k] };
    }

    var libRelPaths = (spec.library_files || []).map(function(f){ return f.replace(/\\/g, '/'); });
    var helpRelPaths = (spec.help_files || []).map(function(f){ return f.replace(/\\/g, '/'); });
    var demoRelPaths = (spec.demo_method_files || []).map(function(f){ return f.replace(/\\/g, '/'); });
    var manifestLibFiles = libRelPaths.slice();
    helpRelPaths.forEach(function(hf){ if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf); });

    var manifest = {
        format_version:       shared.FORMAT_VERSION,
        library_name:         libName,
        author:               spec.author || '',
        organization:         spec.organization || '',
        version:              spec.version,
        venus_compatibility:  spec.venus_compatibility || '',
        description:          spec.description || '',
        github_url:           spec.github_url || '',
        tags:                 spec.tags || [],
        created_date:         new Date().toISOString(),
        library_image:        libraryImageFilename,
        library_image_base64: libraryImageBase64,
        library_image_mime:   libraryImageMime,
        library_files:        manifestLibFiles,
        demo_method_files:    demoRelPaths,
        help_files:           helpRelPaths,
        com_register_dlls:    comDlls,
        app_version:          shared.getAppVersion(),
        windows_version:      shared.getWindowsVersion(),
        venus_version:        getVENUSVersion() || '',
        package_lineage:      [shared.buildLineageEvent('created', {
            username: getWindowsUsername(), hostname: os.hostname(), venusVersion: getVENUSVersion() || ''
        })]
    };

    var zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));
    resolvedLibFiles.forEach(function(f, i){ zip.addLocalFile(f, zipSubdir('library', libRelPaths[i] || path.basename(f))); });
    resolvedHelpFiles.forEach(function(f, i){ zip.addLocalFile(f, zipSubdir('library', helpRelPaths[i] || path.basename(f))); });
    resolvedDemoFiles.forEach(function(f, i){ zip.addLocalFile(f, zipSubdir('demo_methods', demoRelPaths[i] || path.basename(f))); });
    if (iconSourcePath) zip.addLocalFile(iconSourcePath, 'icon');

    var sigCreds = null;
    try { sigCreds = resolveSigningCredentials(opts.signKey, opts.signCert); } catch(e) { return { success: false, error: e.message }; }
    if (sigCreds) shared.signPackageZipWithCert(zip, sigCreds.privateKeyPem, sigCreds.cert);

    ensureOutDir(opts.output);
    fs.writeFileSync(opts.output, shared.packContainer(zip.toBuffer(), shared.CONTAINER_MAGIC_PKG));

    try {
        appendAuditTrailEntry(ctx.dbPath, buildAuditTrailEntry('package_created', {
            library_name: libName, version: spec.version || '', author: spec.author || '',
            output_file: path.resolve(opts.output), library_files: resolvedLibFiles.length,
            demo_files: resolvedDemoFiles.length, help_files: resolvedHelpFiles.length, com_dlls: comDlls
        }));
    } catch (_) {}

    return {
        success: true,
        data: {
            libraryName:  libName, author: spec.author, version: spec.version,
            outputPath:   path.resolve(opts.output),
            libraryFiles: resolvedLibFiles.length, demoFiles: resolvedDemoFiles.length,
            helpFiles:    resolvedHelpFiles.length, comDlls: comDlls,
            codeSigned:   !!sigCreds, publisher: sigCreds ? sigCreds.cert.publisher : null
        }
    };
}

// ---------------------------------------------------------------------------
// 9. listVersions
// ---------------------------------------------------------------------------
/**
 * List cached package versions for a library.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.name - Library name.
 * @returns {{ success: boolean, data: object[], error: string|undefined }}
 */
function listVersions(ctx, opts) {
    opts = opts || {};
    if (!opts.name) return { success: false, error: 'name is required' };
    var entries = listCachedVersions(opts.name, ctx.storeDir);
    return { success: true, data: entries };
}

// ---------------------------------------------------------------------------
// 10. rollbackLibrary
// ---------------------------------------------------------------------------
/**
 * Rollback a library to a previously cached package version.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.name - Library name.
 * @param {string} [opts.version] - Target version string.
 * @param {string|number} [opts.index] - 1-based index into cached versions.
 * @param {boolean} [opts.noGroup=false] - Skip automatic group assignment.
 * @param {string}  [opts.authorPassword] - Password for restricted OEM authors.
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function rollbackLibrary(ctx, opts) {
    opts = opts || {};
    if (!opts.name) return { success: false, error: 'name is required' };

    var entries = listCachedVersions(opts.name, ctx.storeDir);
    if (entries.length === 0) return { success: false, error: 'No cached packages found for "' + opts.name + '".' };

    var target = null;
    if (opts.version) {
        var matches = entries.filter(function(e){return e.version === opts.version;});
        if (matches.length === 0) return { success: false, error: 'Version "' + opts.version + '" not found in cache.' };
        target = matches[0];
    } else if (opts.index) {
        var idx = parseInt(opts.index, 10);
        if (isNaN(idx) || idx < 1 || idx > entries.length) return { success: false, error: 'Invalid index: ' + opts.index };
        target = entries[idx - 1];
    } else {
        return { success: false, error: 'Specify version or index', data: entries };
    }

    var zip, manifest;
    try {
        var rawCacheBuf = fs.readFileSync(target.fullPath);
        var cacheBuf = shared.unpackContainer(rawCacheBuf, shared.CONTAINER_MAGIC_PKG);
        zip = new AdmZip(cacheBuf);
        var me = zip.getEntry('manifest.json');
        if (!me) return { success: false, error: 'Cached package is corrupt' };
        manifest = JSON.parse(zip.readAsText(me));
    } catch (e) {
        return { success: false, error: 'Failed to read cached package: ' + e.message };
    }

    var rollbackLibName = manifest.library_name || opts.name;
    if (!shared.isValidLibraryName(rollbackLibName)) return { success: false, error: 'Invalid library name in cached package.' };

    var sigResult = shared.verifyPackageSignature(zip);
    if (sigResult.signed && !sigResult.valid) return { success: false, error: 'Cached package signature failed: ' + sigResult.errors.join('; ') };

    var rollbackAuthor = (manifest.author || '').trim();
    var rollbackOrg    = (manifest.organization || '').trim();
    if ((shared.isRestrictedAuthor(rollbackAuthor) || shared.isRestrictedAuthor(rollbackOrg)) && !isSystemLibraryByName(rollbackLibName)) {
        if (!opts.authorPassword) return { success: false, error: 'Restricted author. Provide authorPassword.' };
        if (!shared.validateAuthorPassword(opts.authorPassword)) return { success: false, error: 'Incorrect author password.' };

        // OEM certificate verification for rollback
        var pubCert = (sigResult.code_signed && sigResult.valid) ? sigResult.publisher_cert : null;
        var certMatch = shared.validateOemCertificateMatch(rollbackAuthor, rollbackOrg, pubCert);
        if (!certMatch.valid) return { success: false, error: certMatch.error };
    }

    var libDestDir  = path.join(ctx.libBasePath, opts.name);
    var demoDestDir = path.join(ctx.metBasePath, 'Library Demo Methods', opts.name);
    var result = installPackage(manifest, zip, libDestDir, demoDestDir, target.file, ctx.db, !!opts.noGroup, sigResult);

    try {
        appendAuditTrailEntry(ctx.dbPath, buildAuditTrailEntry('library_rollback', {
            library_name: opts.name, version: target.version || '', author: manifest.author || '',
            source_file: target.fullPath, lib_install_path: libDestDir,
            demo_install_path: demoDestDir, files_extracted: result.extractedCount
        }));
    } catch (_) {}

    return {
        success: true,
        data: {
            libraryName:     opts.name,
            version:         target.version,
            filesExtracted:  result.extractedCount,
            libInstallPath:  libDestDir,
            demoInstallPath: demoDestDir,
            comDlls:         manifest.com_register_dlls || []
        }
    };
}

// ---------------------------------------------------------------------------
// 11. verifyPackage
// ---------------------------------------------------------------------------
/**
 * Verify code-signing signatures on a .hxlibpkg or .hxlibarch file.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.filePath - Path to the package or archive file.
 * @returns {{ success: boolean, data: object[], error: string|undefined }}
 */
function verifyPackage(ctx, opts) {
    opts = opts || {};
    var filePath = opts.filePath;
    if (!filePath) return { success: false, error: 'filePath is required' };
    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found: ' + filePath };

    var ext = path.extname(filePath).toLowerCase();
    var results = [];

    if (ext === '.hxlibarch') {
        var archiveZip;
        try {
            var rawArchBuf = fs.readFileSync(filePath);
            var outerZipBuf = shared.unpackContainer(rawArchBuf, shared.CONTAINER_MAGIC_ARC);
            archiveZip = new AdmZip(outerZipBuf);
        } catch (e) { return { success: false, error: 'Failed to read archive: ' + e.message }; }

        var pkgEntries = archiveZip.getEntries().filter(function(e){ return !e.isDirectory && e.entryName.toLowerCase().endsWith('.hxlibpkg'); });
        if (pkgEntries.length === 0) return { success: false, error: 'No packages found in archive.' };

        pkgEntries.forEach(function(pkgEntry) {
            try {
                var innerZipBuf = shared.unpackContainer(pkgEntry.getData(), shared.CONTAINER_MAGIC_PKG);
                var innerZip = new AdmZip(innerZipBuf);
                var sigResult = shared.verifyPackageSignature(innerZip);
                results.push({
                    package: pkgEntry.entryName, signed: sigResult.signed, valid: sigResult.valid,
                    code_signed: sigResult.code_signed, publisher_cert: sigResult.publisher_cert,
                    oem_verified: sigResult.oem_verified, errors: sigResult.errors, warnings: sigResult.warnings
                });
            } catch (e) {
                results.push({ package: pkgEntry.entryName, signed: false, valid: false, code_signed: false, publisher_cert: null, oem_verified: false, errors: ['Failed to read: ' + e.message], warnings: [] });
            }
        });
    } else {
        try {
            var rawPkgBuf = fs.readFileSync(filePath);
            var zipBuf = shared.unpackContainer(rawPkgBuf, shared.CONTAINER_MAGIC_PKG);
            var zip = new AdmZip(zipBuf);
            var sigResult2 = shared.verifyPackageSignature(zip);
            results.push({
                package: path.basename(filePath), signed: sigResult2.signed, valid: sigResult2.valid,
                code_signed: sigResult2.code_signed, publisher_cert: sigResult2.publisher_cert,
                oem_verified: sigResult2.oem_verified, errors: sigResult2.errors, warnings: sigResult2.warnings
            });
        } catch (e) { return { success: false, error: 'Failed to read package: ' + e.message }; }
    }

    var anyFailed = results.some(function(r){ return r.signed && !r.valid; });
    return { success: !anyFailed, data: results };
}

// ---------------------------------------------------------------------------
// 12. generateSyslibHashes
// ---------------------------------------------------------------------------
/**
 * Generate integrity baseline hashes for Hamilton system libraries.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.sourceDir - Directory containing system library files.
 * @param {string} [opts.output] - Output JSON path; defaults to db/system_library_hashes.json.
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function generateSyslibHashes(ctx, opts) {
    opts = opts || {};
    if (!opts.sourceDir) return { success: false, error: 'sourceDir is required' };
    if (!fs.existsSync(opts.sourceDir)) return { success: false, error: 'Source directory not found: ' + opts.sourceDir };

    var sysLibPath = path.join(__dirname, '..', 'db', 'system_libraries.json');
    if (!fs.existsSync(sysLibPath)) return { success: false, error: 'system_libraries.json not found' };

    var sysLibs;
    try { sysLibs = JSON.parse(fs.readFileSync(sysLibPath, 'utf8')); }
    catch(e) { return { success: false, error: 'Failed to parse system_libraries.json: ' + e.message }; }

    var baselineData = {
        _meta: {
            generated_at: new Date().toISOString(), source_dir: opts.sourceDir,
            strategy: 'hamilton-footer', hsl_extensions: HSL_METADATA_EXTS.slice(),
            description: 'Integrity baseline for Hamilton system libraries.'
        },
        libraries: {}
    };

    var totalFiles = 0, totalBaselined = 0, skippedBinary = 0, noFooter = [], missing = [];

    sysLibs.forEach(function(lib) {
        var libName = lib.canonical_name || lib.library_name;
        var files   = lib.discovered_files || [];
        var libFiles = {};
        files.forEach(function(relPath) {
            var fname    = relPath.replace(/^Library\\/i, '');
            var fullPath = path.join(opts.sourceDir, fname);
            totalFiles++;
            var ext2 = path.extname(fname).toLowerCase();
            if (HSL_METADATA_EXTS.indexOf(ext2) === -1) { skippedBinary++; return; }
            if (!fs.existsSync(fullPath)) { missing.push({ library: libName, file: fname }); return; }
            var footer = shared.parseHslMetadataFooter(fullPath);
            if (footer) {
                libFiles[fname] = { valid: footer.valid, checksum: footer.checksum, author: footer.author, time: footer.time, length: footer.length };
                totalBaselined++;
            } else { noFooter.push({ library: libName, file: fname }); }
        });
        if (Object.keys(libFiles).length > 0) baselineData.libraries[libName] = { _id: lib._id, files: libFiles };
    });

    var outputPath = opts.output || path.join(__dirname, '..', 'db', 'system_library_hashes.json');
    ensureOutDir(outputPath);
    fs.writeFileSync(outputPath, JSON.stringify(baselineData, null, 2), 'utf8');

    return { success: true, data: { outputPath: outputPath, totalFiles: totalFiles, baselined: totalBaselined, skipped: skippedBinary, noFooter: noFooter, missing: missing } };
}

// ---------------------------------------------------------------------------
// 13. verifySyslibHashes
// ---------------------------------------------------------------------------
/**
 * Verify installed system libraries against the integrity baseline.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} [opts.hashFile] - Path to baseline JSON; defaults to db/system_library_hashes.json.
 * @param {string} [opts.libDir] - Override library directory to check.
 * @returns {{ success: boolean, data: {ok: object[], tampered: object[], missing: object[], errors: object[]}, error: string|undefined }}
 */
function verifySyslibHashes(ctx, opts) {
    opts = opts || {};
    var hashFilePath = opts.hashFile || path.join(__dirname, '..', 'db', 'system_library_hashes.json');
    if (!fs.existsSync(hashFilePath)) return { success: false, error: 'Baseline file not found: ' + hashFilePath };

    var baselineData;
    try { baselineData = JSON.parse(fs.readFileSync(hashFilePath, 'utf8')); }
    catch(e) { return { success: false, error: 'Failed to parse baseline file: ' + e.message }; }

    var libBasePath = opts.libDir || ctx.libBasePath;
    if (!fs.existsSync(libBasePath)) return { success: false, error: 'Library directory not found: ' + libBasePath };

    var results = { ok: [], tampered: [], missing: [], errors: [] };

    Object.keys(baselineData.libraries).forEach(function(libName) {
        var entry = baselineData.libraries[libName];
        var files = entry.files || {};
        Object.keys(files).forEach(function(fname) {
            var stored   = files[fname];
            var fullPath = path.join(libBasePath, fname);
            if (!fs.existsSync(fullPath)) { results.missing.push({ library: libName, file: fname }); return; }
            try {
                var footer = shared.parseHslMetadataFooter(fullPath);
                if (!footer) { results.tampered.push({ library: libName, file: fname, reason: 'Metadata footer removed' }); return; }
                if (stored.valid === 1 && footer.valid !== 1) { results.tampered.push({ library: libName, file: fname, reason: 'Valid flag changed' }); return; }
                results.ok.push({ library: libName, file: fname });
            } catch (e) { results.errors.push({ library: libName, file: fname, error: e.message }); }
        });
    });

    var hasIssues = results.tampered.length > 0 || results.missing.length > 0 || results.errors.length > 0;
    return { success: !hasIssues, data: results };
}

// ---------------------------------------------------------------------------
// 14. generateKeypair
// ---------------------------------------------------------------------------
/**
 * Generate an Ed25519 signing keypair and publisher certificate.
 * @param {object} ctx - Service context from createContext().
 * @param {object} opts
 * @param {string} opts.publisher - Publisher display name.
 * @param {string} [opts.organization] - Organization name.
 * @param {string} [opts.outputDir] - Output directory; defaults to cwd.
 * @param {boolean} [opts.force=false] - Overwrite existing key/cert files.
 * @param {string}  [opts.authorPassword] - Password for restricted OEM names.
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function generateKeypair(ctx, opts) {
    opts = opts || {};
    if (!opts.publisher) return { success: false, error: 'publisher is required' };
    if (opts.publisher.trim().length < shared.AUTHOR_MIN_LENGTH) return { success: false, error: 'Publisher name too short.' };
    if (opts.publisher.trim().length > shared.AUTHOR_MAX_LENGTH) return { success: false, error: 'Publisher name too long.' };

    if (shared.isRestrictedAuthor(opts.publisher) || shared.isRestrictedAuthor(opts.organization || '')) {
        if (!opts.authorPassword) return { success: false, error: 'Restricted OEM name. Provide authorPassword.' };
        if (!shared.validateAuthorPassword(opts.authorPassword)) return { success: false, error: 'Incorrect author password.' };
    }

    var keypair   = shared.generateSigningKeyPair();
    var cert      = shared.buildPublisherCertificate(opts.publisher, opts.organization || '', keypair.publicKeyRaw);
    var safeName  = opts.publisher.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
    var outputDir = opts.outputDir ? path.resolve(opts.outputDir) : process.cwd();

    var keyFilePath  = path.join(outputDir, safeName + '.key.pem');
    var certFilePath = path.join(outputDir, safeName + '.cert.json');

    if (fs.existsSync(keyFilePath)  && !opts.force) return { success: false, error: 'Key file already exists: ' + keyFilePath };
    if (fs.existsSync(certFilePath) && !opts.force) return { success: false, error: 'Cert file already exists: ' + certFilePath };

    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(keyFilePath, keypair.privateKeyPem, 'utf8');
    fs.writeFileSync(certFilePath, JSON.stringify(cert, null, 2), 'utf8');

    return {
        success: true,
        data: { keyFilePath: keyFilePath, certFilePath: certFilePath, keyId: cert.key_id, fingerprint: cert.fingerprint, publisher: opts.publisher }
    };
}

// ---------------------------------------------------------------------------
// 15. listPublishers
// ---------------------------------------------------------------------------
/**
 * List all publishers in the local certificate registry.
 * @param {object} ctx - Service context from createContext().
 * @returns {{ success: boolean, data: object[], error: string|undefined }}
 */
function listPublishers(ctx) {
    var regPath = resolvePublisherRegistryPath();
    var data;
    try {
        if (!fs.existsSync(regPath)) data = { publishers: [] };
        else data = JSON.parse(fs.readFileSync(regPath, 'utf8'));
    } catch(e) { return { success: false, error: 'Failed to read publisher registry: ' + e.message }; }

    var pubs = (data.publishers || []).filter(function(p){ return p.certificates && p.certificates.length > 0; });
    return { success: true, data: pubs };
}

// ---------------------------------------------------------------------------
// 16. getAuditTrail
// ---------------------------------------------------------------------------
/**
 * Retrieve the audit trail log entries.
 * @param {object} ctx - Service context from createContext().
 * @param {object} [opts]
 * @param {number} [opts.limit] - Return only the last N entries.
 * @returns {{ success: boolean, data: object[], error: string|undefined }}
 */
function getAuditTrail(ctx, opts) {
    opts = opts || {};
    var filePath = path.join(ctx.dbPath, 'audit_trail.json');
    if (!fs.existsSync(filePath)) return { success: true, data: [] };
    try {
        var trail = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (!Array.isArray(trail)) trail = [];
        if (opts.limit) trail = trail.slice(-opts.limit);
        return { success: true, data: trail };
    } catch(e) { return { success: false, error: 'Failed to read audit trail: ' + e.message }; }
}

// ---------------------------------------------------------------------------
// 17. getSettings
// ---------------------------------------------------------------------------
/**
 * Retrieve application settings.
 * @param {object} ctx - Service context from createContext().
 * @returns {{ success: boolean, data: object, error: string|undefined }}
 */
function getSettings(ctx) {
    try {
        var settings = ctx.db.settings.findOne({ _id: '0' }) || {};
        return { success: true, data: settings };
    } catch(e) { return { success: false, error: e.message }; }
}

// ---------------------------------------------------------------------------
// 18. getSystemLibraries
// ---------------------------------------------------------------------------
/**
 * Return the bundled list of Hamilton system libraries.
 * @returns {{ success: boolean, data: object[], error: string|undefined }}
 */
function getSystemLibraries() {
    var sysPath = path.join(__dirname, '..', 'db', 'system_libraries.json');
    try {
        var data = JSON.parse(fs.readFileSync(sysPath, 'utf8'));
        return { success: true, data: data };
    } catch(e) { return { success: false, error: e.message }; }
}

// ===========================================================================
// Module exports
// ===========================================================================
module.exports = {
    createContext:          createContext,
    // Read operations
    listLibraries:         listLibraries,
    getLibrary:            getLibrary,
    listVersions:          listVersions,
    listPublishers:        listPublishers,
    getAuditTrail:         getAuditTrail,
    getSettings:           getSettings,
    getSystemLibraries:    getSystemLibraries,
    // Mutating operations
    importLibrary:         importLibrary,
    importArchive:         importArchive,
    exportLibrary:         exportLibrary,
    exportArchive:         exportArchive,
    deleteLibrary:         deleteLibrary,
    createPackage:         createPackage,
    rollbackLibrary:       rollbackLibrary,
    // Package verification
    verifyPackage:         verifyPackage,
    verifySyslibHashes:    verifySyslibHashes,
    generateSyslibHashes:  generateSyslibHashes,
    // Signing
    generateKeypair:       generateKeypair
};
