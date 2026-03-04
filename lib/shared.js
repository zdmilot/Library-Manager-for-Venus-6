// SPDX-License-Identifier: Apache-2.0
/**
 * Library Manager for Venus 6 - Shared Module
 *
 * Copyright (c) 2026 Zachary Milot
 * Author: Zachary Milot
 *
 * Common validation, hashing, signing, and security routines used by both
 * the GUI (main.js) and the CLI (cli.js).  Keeping these in one place
 * eliminates behavioural drift between the two entry-points.
 *
 * Usage:
 *   const shared = require('../lib/shared');   // from cli.js
 *   const shared = require('./lib/shared');     // from html/js (NW.js)
 */

'use strict';

const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');
const os     = require('os');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Current manifest format version. Increment on breaking manifest changes. */
const FORMAT_VERSION = '2.0';

/** Valid lineage event type strings. */
const VALID_LINEAGE_EVENTS = ['created', 'exported', 'repackaged'];

/**
 * Known manifest fields - keys expected in a package manifest.json.
 * Used by import/rollback to identify and preserve unknown forward-compat fields.
 */
const KNOWN_MANIFEST_KEYS = [
    'format_version','library_name','author','organization','version',
    'venus_compatibility','description','github_url','tags','created_date',
    'library_image','library_image_base64','library_image_mime',
    'library_files','demo_method_files','help_files','com_register_dlls',
    'app_version','windows_version','venus_version','package_lineage',
    'is_system_backup'
];

/**
 * Known installed-library DB record fields.
 * Used by export to identify and preserve unknown forward-compat fields.
 */
const KNOWN_LIB_DB_KEYS = [
    '_id','library_name','author','organization','version','venus_compatibility',
    'description','github_url','tags','created_date','library_image',
    'library_image_base64','library_image_mime','library_files',
    'demo_method_files','help_files','com_register_dlls','com_warning','com_registered',
    'lib_install_path','demo_install_path','installed_date','installed_by',
    'source_package','file_hashes','public_functions','required_dependencies',
    'deleted','deleted_date','app_version','format_version','windows_version',
    'venus_version','package_lineage','is_system_backup'
];

/** File extensions whose content is tracked for integrity hashing */
const HASH_EXTENSIONS = ['.hsl', '.hs_', '.sub'];

/** Extensions that carry Hamilton's metadata footer */
const HSL_METADATA_EXTS = ['.hsl', '.hs_', '.smt'];

/** MIME types for image file extensions (both dot-prefixed and bare) */
const IMAGE_MIME_MAP = {
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.bmp':  'image/bmp',
    '.gif':  'image/gif',
    '.ico':  'image/x-icon',
    '.svg':  'image/svg+xml',
    'png':   'image/png',
    'jpg':   'image/jpeg',
    'jpeg':  'image/jpeg',
    'bmp':   'image/bmp',
    'gif':   'image/gif',
    'ico':   'image/x-icon',
    'svg':   'image/svg+xml'
};

// ---------------------------------------------------------------------------
// Package signing key
// ---------------------------------------------------------------------------
// NOTE: This key is embedded in client-side source and provides tamper-
// *detection* only ("did the package change since it was built?"), NOT
// cryptographic authenticity.  Anyone with access to this source can
// forge a valid signature.  For stronger guarantees, move signing to a
// server-side service or use asymmetric (public/private) key signing.
const PKG_SIGNING_KEY = 'VenusLibMgr::PackageIntegrity::a7e3f9d1c6b2';

// ---------------------------------------------------------------------------
// Binary container format
// ---------------------------------------------------------------------------
// .hxlibpkg and .hxlibarch files are wrapped in a custom binary envelope
// that makes them opaque to standard tools (Notepad, 7-Zip, WinRAR, etc.).
// The internal ZIP payload is XOR-scrambled with a repeating key and
// protected by an HMAC-SHA256 over the scrambled bytes.  Any accidental
// edit or corruption is detected and the import fails closed.
//
// Container layout (header = 48 bytes):
//   [0..7]   8 B   Magic identifier
//   [8..11]  4 B   Flags  (uint32 LE, reserved = 0)
//   [12..15] 4 B   Payload length (uint32 LE)
//   [16..47] 32 B  HMAC-SHA256 of scrambled payload
//   [48..]   N B   XOR-scrambled ZIP buffer
// ---------------------------------------------------------------------------

/** 8-byte magic for single-library packages (.hxlibpkg) */
const CONTAINER_MAGIC_PKG = Buffer.from([0x48, 0x58, 0x4C, 0x50, 0x4B, 0x47, 0x01, 0x00]); // "HXLPKG\x01\x00"

/** 8-byte magic for library archives (.hxlibarch) */
const CONTAINER_MAGIC_ARC = Buffer.from([0x48, 0x58, 0x4C, 0x41, 0x52, 0x43, 0x01, 0x00]); // "HXLARC\x01\x00"

/** 32-byte XOR scramble key - makes the ZIP payload unrecognisable */
const CONTAINER_SCRAMBLE_KEY = Buffer.from([
    0x7A, 0x3F, 0xC1, 0xD8, 0x4E, 0x92, 0xB5, 0x16,
    0xA3, 0x0D, 0xE7, 0x68, 0xF4, 0x2C, 0x59, 0x8B,
    0x31, 0xCA, 0x75, 0x0E, 0x96, 0xAF, 0xD2, 0x43,
    0xBC, 0x1A, 0x67, 0xE0, 0x58, 0x84, 0x3B, 0xF9
]);

/** Size of the fixed binary container header in bytes */
const CONTAINER_HEADER_SIZE = 48;

/**
 * Wrap a raw ZIP buffer into a binary container.
 *
 * The ZIP bytes are XOR-scrambled so the output cannot be opened by
 * standard archive tools, then protected with an HMAC-SHA256 so that
 * any accidental edit or truncation is detected on import.
 *
 * @param {Buffer} zipBuffer - The raw ZIP data (from AdmZip.toBuffer())
 * @param {Buffer} magic     - 8-byte magic identifier (CONTAINER_MAGIC_PKG or _ARC)
 * @returns {Buffer} The complete binary container
 */
function packContainer(zipBuffer, magic) {
    // XOR-scramble the payload
    var scrambled = Buffer.alloc(zipBuffer.length);
    for (var i = 0; i < zipBuffer.length; i++) {
        scrambled[i] = zipBuffer[i] ^ CONTAINER_SCRAMBLE_KEY[i % CONTAINER_SCRAMBLE_KEY.length];
    }

    // HMAC over scrambled bytes
    var hmac = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(scrambled).digest();

    // Build header: magic(8) + flags(4) + payloadLen(4) + hmac(32) = 48 bytes
    var header = Buffer.alloc(CONTAINER_HEADER_SIZE);
    magic.copy(header, 0);                        // [0..7]
    header.writeUInt32LE(0, 8);                    // [8..11]  flags (reserved)
    header.writeUInt32LE(scrambled.length, 12);    // [12..15] payload length
    hmac.copy(header, 16);                         // [16..47] HMAC

    return Buffer.concat([header, scrambled]);
}

/**
 * Unwrap a binary container, verify its integrity, and return the
 * original ZIP buffer.  Throws on any error (fail closed).
 *
 * @param {Buffer} containerBuffer - The raw file bytes
 * @param {Buffer} magic           - Expected 8-byte magic identifier
 * @returns {Buffer} The recovered ZIP buffer
 * @throws {Error} If the container is invalid, corrupted, or tampered with
 */
function unpackContainer(containerBuffer, magic) {
    if (!Buffer.isBuffer(containerBuffer) || containerBuffer.length < CONTAINER_HEADER_SIZE) {
        throw new Error('Invalid package: file is too small or not a valid container.');
    }

    // Check magic bytes
    if (containerBuffer.compare(magic, 0, magic.length, 0, magic.length) !== 0) {
        throw new Error('Invalid package: unrecognized file format.');
    }

    // Read header fields
    // var flags = containerBuffer.readUInt32LE(8);   // reserved - ignored for now
    var payloadLen = containerBuffer.readUInt32LE(12);
    var storedHmac = containerBuffer.slice(16, CONTAINER_HEADER_SIZE);

    if (containerBuffer.length < CONTAINER_HEADER_SIZE + payloadLen) {
        throw new Error('Invalid package: file is truncated or corrupted.');
    }

    var scrambled = containerBuffer.slice(CONTAINER_HEADER_SIZE, CONTAINER_HEADER_SIZE + payloadLen);

    // Verify HMAC (timing-safe comparison)
    var computedHmac = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(scrambled).digest();
    if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
        throw new Error('Package integrity check failed: the file has been corrupted or tampered with.');
    }

    // De-scramble to recover the ZIP buffer
    var zipBuffer = Buffer.alloc(scrambled.length);
    for (var i = 0; i < scrambled.length; i++) {
        zipBuffer[i] = scrambled[i] ^ CONTAINER_SCRAMBLE_KEY[i % CONTAINER_SCRAMBLE_KEY.length];
    }

    return zipBuffer;
}

// ---------------------------------------------------------------------------
// HTML escaping
// ---------------------------------------------------------------------------

/**
 * Escape a string for safe insertion into HTML.
 * Prevents XSS when inserting user/package-supplied text into the DOM.
 *
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ---------------------------------------------------------------------------
// Filesystem safety
// ---------------------------------------------------------------------------

/**
 * Sanitize a ZIP entry filename to prevent path traversal.
 * Returns null if the resolved path escapes the target directory.
 *
 * @param {string} baseDir - The target extraction directory
 * @param {string} fname   - The ZIP entry filename
 * @returns {string|null}  Resolved safe path, or null if unsafe
 */
function safeZipExtractPath(baseDir, fname) {
    var resolved = path.resolve(baseDir, fname);
    var base = path.resolve(baseDir) + path.sep;
    if (!resolved.startsWith(base) && resolved !== path.resolve(baseDir)) return null;
    return resolved;
}

/**
 * Validate that a library name is safe for use in filesystem paths.
 * Rejects names containing path separators, '..' traversal, reserved
 * characters, and names that are empty or whitespace-only.
 * Also rejects trailing dots and spaces (invalid on Windows).
 *
 * @param {string} name
 * @returns {boolean} true if safe
 */
function isValidLibraryName(name) {
    if (!name || typeof name !== 'string') return false;
    // Path separators or traversal
    if (/[\\\/]|\.\./.test(name)) return false;
    // Reserved characters (Windows-unsafe)
    if (/[<>:"|?*]/.test(name)) return false;
    // Trailing dots or spaces (Windows path normalisation traps)
    if (/[. ]$/.test(name)) return false;
    // Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    if (/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i.test(name)) return false;
    // Empty / whitespace-only
    if (name.trim().length === 0) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Integrity hashing
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 hash of a file.
 * For .hsl, .hs_, .sub files: hashes ALL BUT THE LAST LINE (the last line
 * may contain a mutable Hamilton metadata footer / timestamp).
 * For all other files (.dll, etc.): hashes the entire file.
 *
 * @param {string} filePath - Full path to the file
 * @returns {string|null} hex hash string or null on error
 */
function computeFileHash(filePath) {
    try {
        if (!fs.existsSync(filePath)) return null;
        var ext = path.extname(filePath).toLowerCase();
        var hash = crypto.createHash('sha256');

        if (ext === '.hsl' || ext === '.hs_' || ext === '.sub') {
            // Hash all but the last line
            var content = fs.readFileSync(filePath, 'utf8');
            var lines = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
            if (lines.length > 1) {
                lines.pop();
            }
            hash.update(lines.join('\n'), 'utf8');
        } else {
            var buf = fs.readFileSync(filePath);
            hash.update(buf);
        }
        return hash.digest('hex');
    } catch (_) {
        return null;
    }
}

/**
 * Computes hashes for tracked library files (.hsl, .hs_, .sub) and
 * registered COM DLL files.
 *
 * @param {Array<string>} libraryFiles - filenames array
 * @param {string}        libBasePath  - base directory for library files
 * @param {Array<string>} comDlls      - COM registered DLL filenames
 * @returns {Object} map of filename -> sha256 hex hash
 */
function computeLibraryHashes(libraryFiles, libBasePath, comDlls) {
    var hashes = {};
    (libraryFiles || []).forEach(function (fname) {
        var ext     = path.extname(fname).toLowerCase();
        var isDll   = (comDlls || []).indexOf(fname) !== -1;
        var tracked = HASH_EXTENSIONS.indexOf(ext) !== -1 || isDll;
        if (tracked) {
            var h = computeFileHash(path.join(libBasePath, fname));
            if (h) hashes[fname] = h;
        }
    });
    return hashes;
}

/**
 * Parse the Hamilton HSL metadata footer from the last non-empty line of
 * a file.
 * Footer format:
 *   // $$author=NAME$$valid=0|1$$time=TIMESTAMP$$checksum=HEX$$length=NNN$$
 *
 * @param {string} filePath - full path to the file
 * @returns {Object|null} { author, valid, time, checksum, length, raw } or null
 */
function parseHslMetadataFooter(filePath) {
    try {
        if (!fs.existsSync(filePath)) return null;
        var text = fs.readFileSync(filePath, 'utf8');
        var lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
        for (var i = lines.length - 1; i >= Math.max(0, lines.length - 5); i--) {
            var line = lines[i].trim();
            if (line === '') continue;
            var m = line.match(/\$\$author=(.+?)\$\$valid=(\d)\$\$time=(.+?)\$\$checksum=([a-f0-9]+)\$\$length=(\d+)\$\$/);
            if (m) {
                return {
                    author:   m[1],
                    valid:    parseInt(m[2], 10),
                    time:     m[3],
                    checksum: m[4],
                    length:   parseInt(m[5], 10),
                    raw:      line
                };
            }
            break; // first non-empty line wasn't a footer
        }
        return null;
    } catch (_) {
        return null;
    }
}

// ---------------------------------------------------------------------------
// Package signing - HMAC-SHA256 integrity signatures for .hxlibpkg files
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 hashes of all entries in an AdmZip instance (excluding
 * signature.json).  Returns a sorted object of { entryName: sha256hex }.
 *
 * @param {AdmZip} zip
 * @returns {Object}
 */
function computeZipEntryHashes(zip) {
    var hashes = {};
    zip.getEntries().forEach(function (entry) {
        if (entry.isDirectory) return;
        if (entry.entryName === 'signature.json') return;
        var hash = crypto.createHash('sha256').update(entry.getData()).digest('hex');
        hashes[entry.entryName] = hash;
    });
    var sorted = {};
    Object.keys(hashes).sort().forEach(function (k) { sorted[k] = hashes[k]; });
    return sorted;
}

/**
 * Sign a package ZIP by computing HMAC-SHA256 over all file hashes and
 * embedding a signature.json entry.  Must be called AFTER all other entries
 * have been added and BEFORE writing the ZIP to disk.
 *
 * @param {AdmZip} zip - The AdmZip instance to sign (modified in place)
 * @returns {Object} The signature object that was embedded
 */
function signPackageZip(zip) {
    var fileHashes = computeZipEntryHashes(zip);
    var payload    = JSON.stringify(fileHashes);
    var hmac       = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(payload).digest('hex');

    var signature = {
        signature_format_version: '1.0',
        algorithm:      'HMAC-SHA256',
        signed_date:    new Date().toISOString(),
        file_hashes:    fileHashes,
        hmac:           hmac
    };

    try { zip.deleteFile('signature.json'); } catch (_) {}
    zip.addFile('signature.json', Buffer.from(JSON.stringify(signature, null, 2), 'utf8'));
    return signature;
}

/**
 * Verify the integrity signature of a package ZIP.
 *
 * @param {AdmZip} zip
 * @returns {Object} { valid: boolean, signed: boolean, errors: string[], warnings: string[] }
 */
function verifyPackageSignature(zip) {
    var result = { valid: true, signed: false, errors: [], warnings: [] };

    var sigEntry = zip.getEntry('signature.json');
    if (!sigEntry) {
        result.signed = false;
        result.warnings.push('Package is unsigned (no signature.json). Integrity cannot be verified.');
        return result;
    }

    result.signed = true;
    var sig;
    try {
        sig = JSON.parse(zip.readAsText(sigEntry));
    } catch (e) {
        result.valid = false;
        result.errors.push('signature.json is malformed: ' + e.message);
        return result;
    }

    if (!sig.file_hashes || !sig.hmac) {
        result.valid = false;
        result.errors.push('signature.json is missing required fields (file_hashes or hmac).');
        return result;
    }

    // Recompute HMAC over stored file_hashes (timing-safe comparison)
    var storedPayload = JSON.stringify(sig.file_hashes);
    var expectedHmac  = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(storedPayload).digest('hex');
    var expectedBuf = Buffer.from(expectedHmac, 'hex');
    var storedBuf   = Buffer.from(sig.hmac, 'hex');
    if (expectedBuf.length !== storedBuf.length || !crypto.timingSafeEqual(storedBuf, expectedBuf)) {
        result.valid = false;
        result.errors.push('HMAC mismatch - signature.json has been tampered with.');
        return result;
    }

    // Verify each file hash against actual ZIP content
    var actualHashes = computeZipEntryHashes(zip);
    var sigFiles     = Object.keys(sig.file_hashes);
    var actualFiles  = Object.keys(actualHashes);

    // Files in signature but missing from ZIP
    sigFiles.forEach(function (f) {
        if (!actualHashes[f]) {
            result.valid = false;
            result.errors.push('File listed in signature but missing from package: ' + f);
        } else if (actualHashes[f] !== sig.file_hashes[f]) {
            result.valid = false;
            result.errors.push('File hash mismatch (corrupted or modified): ' + f);
        }
    });

    // Files in ZIP but not in signature (injected)
    actualFiles.forEach(function (f) {
        if (!sig.file_hashes[f]) {
            result.valid = false;
            result.errors.push('File present in package but not in signature (injected): ' + f);
        }
    });

    return result;
}

// ---------------------------------------------------------------------------
// Author / Organization field constraints
// ---------------------------------------------------------------------------
const AUTHOR_MIN_LENGTH = 3;
const AUTHOR_MAX_LENGTH = 29;

// ---------------------------------------------------------------------------
// Restricted Author / Organization Keywords (single source of truth)
// ---------------------------------------------------------------------------

/**
 * Restricted OEM keywords.  The input is normalized (lowercased, all
 * non-alphanumeric characters removed) and tested for whether it
 * **contains** any of these keywords anywhere in the string.
 * Example: "NotHamilton" is blocked because it contains "hamilton".
 */
const RESTRICTED_AUTHOR_KEYWORDS = [
    'hamilton',
    'tecan',
    'thermofisher', 'thermoscientific', 'fisherscientific',
    'danaher',
    'beckmancoulter',
    'roche', 'rochediagnostics',
    'siemens', 'healthineers',
    'inheco',
    'agilent',
    'revvity', 'perkinelmer',
    'biorad',
    'qiagen',
    'hudsonrobotics',
    'sptlabtech',
    'ttplabtech',
    'swisslog',
    'bectondickinson', 'bdbiosciences', 'bdkiestra',
    'labvantage',
    'labware',
    'automata',
    'opentrons',
    'biosero',
    'greenbuttongo',
    'liconic',
    'sony',
    'azenta', 'brooksautomation',
    'slas', 'societyforlaboratoryautomationandscreening',
    'highresbio',
    'moleculardevices', 'moldev',
    'bmglabtech',
    'aurorabiomed',
    'abcontrols',
    'biotek', 'bioteck'
];

/**
 * Check if an author/organization name is restricted.
 * Normalizes the input by lowercasing and stripping all non-alphanumeric
 * characters, then checks whether the result contains any restricted
 * OEM keyword as a substring.
 * @param {string} author
 * @returns {boolean}
 */
function isRestrictedAuthor(author) {
    if (!author) return false;
    var normalized = author.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!normalized) return false;
    for (var i = 0; i < RESTRICTED_AUTHOR_KEYWORDS.length; i++) {
        if (normalized.indexOf(RESTRICTED_AUTHOR_KEYWORDS[i]) !== -1) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// OEM Author Password
// ---------------------------------------------------------------------------
// The password is stored as a SHA-256 hash to avoid exposing the plaintext
// in source control.  Comparison uses crypto.timingSafeEqual to resist
// timing side-channel analysis.
const OEM_AUTHOR_PASSWORD_HASH = 'bbdc525497de1c19c57767e36b4f01dadcc05348664eea071ac984fd955bc207';

/**
 * Validate a password against the restricted author password hash.
 * Uses SHA-256 hashing and timing-safe comparison.
 * @param {string} password
 * @returns {boolean}
 */
function validateAuthorPassword(password) {
    if (!password || typeof password !== 'string') return false;
    var inputHash  = crypto.createHash('sha256').update(password).digest();
    var storedHash = Buffer.from(OEM_AUTHOR_PASSWORD_HASH, 'hex');
    try {
        return crypto.timingSafeEqual(inputHash, storedHash);
    } catch (_) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Reserved tag keywords
// ---------------------------------------------------------------------------

/**
 * Tags that are reserved for internal/system use and must not be entered by
 * users.  Comparison is case-insensitive.
 * Includes OEM / restricted company keywords to prevent unauthorized tagging.
 */
const RESERVED_TAGS = [
    'system', 'hamilton', 'oem', 'read-only', 'stared', 'starred', 'signed', 'unsigned', 'registered', 'unregistered',
    'tecan', 'thermofisher', 'thermo-fisher', 'thermoscientific', 'thermo-scientific',
    'fisherscientific', 'fisher-scientific', 'danaher', 'beckmancoulter', 'beckman-coulter',
    'roche', 'rochediagnostics', 'roche-diagnostics',
    'siemens', 'healthineers',
    'inheco', 'agilent', 'revvity', 'perkinelmer', 'perkin-elmer',
    'biorad', 'bio-rad', 'qiagen',
    'hudsonrobotics', 'hudson-robotics',
    'sptlabtech', 'spt-labtech', 'ttplabtech', 'ttp-labtech',
    'swisslog',
    'bectondickinson', 'becton-dickinson', 'bdbiosciences', 'bd-biosciences', 'bdkiestra', 'bd-kiestra',
    'labvantage', 'labware',
    'automata', 'opentrons', 'biosero',
    'greenbuttongo', 'green-button-go', 'gbg',
    'liconic', 'sony', 'azenta', 'brooksautomation', 'brooks-automation',
    'slas', 'highresbio', 'highres-bio',
    'moleculardevices', 'molecular-devices', 'moldev',
    'bmglabtech', 'bmg-labtech',
    'aurorabiomed', 'aurora-biomed',
    'abcontrols', 'ab-controls',
    'biotek', 'bioteck'
];

/** Tag policy constraints */
const TAG_MIN_LENGTH = 2;
const TAG_MAX_LENGTH = 24;
const TAG_MAX_COUNT = 12;
const TAG_UNDERSCORE_EXCEPTIONS = ['ml_star'];

function isNumericOnlyTag(tag) {
    return /^\d+$/.test(tag || '');
}

function isTagSegmentValid(segment) {
    if (!segment) return false;
    if (!/^[a-z0-9-]+$/.test(segment)) return false;
    if (segment.indexOf('--') !== -1) return false;
    if (segment.charAt(0) === '-' || segment.charAt(segment.length - 1) === '-') return false;
    return true;
}

function canonicalizeTagForDedup(tag) {
    return (tag || '').replace(/[-:]/g, '');
}

function buildTagBlockReason(code) {
    switch (code) {
        case 'empty': return 'empty';
        case 'empty_after_cleanup': return 'empty after removing invalid characters';
        case 'too_short': return 'too short';
        case 'too_long': return 'too long';
        case 'numeric_only': return 'numbers only';
        case 'restricted_word': return 'contains restricted word';
        case 'max_count': return 'exceeds max tag count';
        default: return 'invalid';
    }
}

/**
 * Sanitize a single tag with detailed feedback used by GUI warning/error modals.
 * - spaces are removed
 * - invalid characters are removed (not silently rejected)
 * - repeated/edge hyphens are normalized
 * - restricted words are blocked if found anywhere in the final tag
 *
 * @param {string} tag
 * @returns {{ input:string, value:string, adjusted:boolean, adjustments:string[], blocked:boolean, blockCode:string, blockReason:string, restrictedWords:string[] }}
 */
function sanitizeTagDetailed(tag) {
    var input = (typeof tag === 'string') ? tag : '';
    var result = {
        input: input,
        value: '',
        adjusted: false,
        adjustments: [],
        blocked: false,
        blockCode: '',
        blockReason: '',
        restrictedWords: []
    };

    if (typeof tag !== 'string') {
        result.blocked = true;
        result.blockCode = 'empty';
        result.blockReason = buildTagBlockReason('empty');
        return result;
    }

    var normalized = tag.trim().toLowerCase();
    if (!normalized) {
        result.blocked = true;
        result.blockCode = 'empty';
        result.blockReason = buildTagBlockReason('empty');
        return result;
    }

    var noSpaces = normalized.replace(/\s+/g, '');
    if (noSpaces !== normalized) {
        result.adjusted = true;
        result.adjustments.push('removed spaces');
    }

    if (TAG_UNDERSCORE_EXCEPTIONS.indexOf(noSpaces) !== -1) {
        result.value = noSpaces;
        return result;
    }

    var removedChars = noSpaces.match(/[^a-z0-9-]/g) || [];
    var cleaned = noSpaces.replace(/[^a-z0-9-]/g, '');
    if (removedChars.length > 0) {
        result.adjusted = true;
        var uniq = [];
        removedChars.forEach(function(ch) { if (uniq.indexOf(ch) === -1) uniq.push(ch); });
        result.adjustments.push('removed invalid characters: ' + uniq.join(' '));
    }

    var collapsed = cleaned.replace(/-+/g, '-');
    if (collapsed !== cleaned) {
        result.adjusted = true;
        result.adjustments.push('collapsed repeated hyphens');
    }

    var trimmedHyphen = collapsed.replace(/^-+|-+$/g, '');
    if (trimmedHyphen !== collapsed) {
        result.adjusted = true;
        result.adjustments.push('trimmed leading/trailing hyphens');
    }

    if (!trimmedHyphen) {
        result.blocked = true;
        result.blockCode = 'empty_after_cleanup';
        result.blockReason = buildTagBlockReason('empty_after_cleanup');
        return result;
    }

    if (trimmedHyphen.length < TAG_MIN_LENGTH) {
        result.blocked = true;
        result.blockCode = 'too_short';
        result.blockReason = buildTagBlockReason('too_short');
        return result;
    }

    if (trimmedHyphen.length > TAG_MAX_LENGTH) {
        result.blocked = true;
        result.blockCode = 'too_long';
        result.blockReason = buildTagBlockReason('too_long');
        return result;
    }

    if (isNumericOnlyTag(trimmedHyphen)) {
        result.blocked = true;
        result.blockCode = 'numeric_only';
        result.blockReason = buildTagBlockReason('numeric_only');
        return result;
    }

    var restrictedMatches = RESERVED_TAGS.filter(function(w) {
        return trimmedHyphen.indexOf(w) !== -1;
    });
    if (restrictedMatches.length > 0) {
        result.blocked = true;
        result.blockCode = 'restricted_word';
        result.blockReason = buildTagBlockReason('restricted_word');
        result.restrictedWords = restrictedMatches;
        return result;
    }

    result.value = trimmedHyphen;
    return result;
}

/**
 * Sanitize a list of tags and return both accepted tags and human-friendly
 * feedback about adjusted and blocked items.
 * @param {string[]} tags
 * @returns {{ tags:string[], adjusted:Array, blocked:Array }}
 */
function sanitizeTagsWithFeedback(tags) {
    if (!Array.isArray(tags)) return { tags: [], adjusted: [], blocked: [] };
    var seen = {};
    var result = [];
    var adjusted = [];
    var blocked = [];

    tags.forEach(function(t) {
        var details = sanitizeTagDetailed(t);
        if (details.adjusted && !details.blocked) {
            adjusted.push({ input: details.input, output: details.value, adjustments: details.adjustments.slice() });
        }
        if (details.blocked) {
            blocked.push({ input: details.input, reason: details.blockReason, restrictedWords: details.restrictedWords || [] });
            return;
        }
        var canonical = canonicalizeTagForDedup(details.value);
        if (canonical && !seen[canonical]) {
            seen[canonical] = true;
            result.push(details.value);
        }
    });

    if (result.length > TAG_MAX_COUNT) {
        for (var i = TAG_MAX_COUNT; i < result.length; i++) {
            blocked.push({ input: result[i], reason: buildTagBlockReason('max_count'), restrictedWords: [] });
        }
        result = result.slice(0, TAG_MAX_COUNT);
    }

    return { tags: result, adjusted: adjusted, blocked: blocked };
}

/**
 * Group names that are reserved for built-in/system groups and cannot be
 * used when creating or editing custom groups.  Comparison is case-insensitive.
 */
const RESERVED_GROUP_NAMES = [
    'starred', 'oem', 'hamilton', 'system', 'signed', 'unsigned', 'registered', 'unregistered',
    'all', 'recent', 'import', 'export', 'history'
];

/**
 * Check whether a group name matches a reserved keyword (case-insensitive).
 * @param {string} name
 * @returns {boolean}
 */
function isReservedGroupName(name) {
    if (!name || typeof name !== 'string') return false;
    return RESERVED_GROUP_NAMES.indexOf(name.trim().toLowerCase()) !== -1;
}

/**
 * Check whether a single tag string matches a reserved keyword
 * (case-insensitive).
 *
 * @param {string} tag
 * @returns {boolean}
 */
function isReservedTag(tag) {
    if (!tag || typeof tag !== 'string') return false;
    var lower = tag.trim().toLowerCase();
    return RESERVED_TAGS.indexOf(lower) !== -1;
}

/**
 * Filter an array of tag strings, removing any that match reserved keywords.
 * Returns an object with the cleaned array and the list of removed tags.
 *
 * @param {string[]} tags
 * @returns {{ filtered: string[], removed: string[] }}
 */
function filterReservedTags(tags) {
    if (!Array.isArray(tags)) return { filtered: [], removed: [] };
    var filtered = [];
    var removed  = [];
    tags.forEach(function (t) {
        if (isReservedTag(t)) {
            removed.push(t);
        } else {
            filtered.push(t);
        }
    });
    return { filtered: filtered, removed: removed };
}

/**
 * Sanitize a single tag string:
 *  - trim whitespace
 *  - lowercase
 *  - remove all internal spaces (so multi-word input becomes one token)
 *
 * @param {string} tag
 * @returns {string}
 */
function sanitizeTag(tag) {
    return sanitizeTagDetailed(tag).value;
}

/**
 * Sanitize an array of tag strings: trim, lowercase, strip spaces,
 * and remove empty / duplicate entries.
 *
 * @param {string[]} tags
 * @returns {string[]}
 */
function sanitizeTags(tags) {
    return sanitizeTagsWithFeedback(tags).tags;
}

// ---------------------------------------------------------------------------
// GitHub Repository URL validation
// ---------------------------------------------------------------------------

/**
 * Reserved top-level path segments on GitHub that are NOT user/owner names.
 * If the first path segment (case-insensitive) is one of these, the URL
 * cannot be a valid /{owner}/{repo} URL.
 */
const GITHUB_RESERVED_TOPLEVEL = new Set([
    'settings', 'organizations', 'orgs', 'users', 'sessions', 'login',
    'logout', 'join', 'pricing', 'features', 'marketplace', 'topics',
    'explore', 'trending', 'collections', 'events', 'sponsors', 'security',
    'site', 'about', 'contact', 'customer-stories', 'readme', 'codespaces',
    'copilot', 'enterprises', 'enterprise', 'account', 'notifications',
    'inbox', 'watch', 'pulls', 'issues', 'search', 'apps', 'new', 'gist',
    'gists', 'blog', 'discussions', 'actions', 'support'
]);

/**
 * Non-repo path prefixes that are invalid anywhere before we have identified
 * /{owner}/{repo}.  Each is checked as a case-insensitive prefix of the path.
 */
const GITHUB_NONREPO_PREFIXES = [
    '/settings/', '/login/', '/logout/', '/sessions/', '/account/',
    '/organizations/', '/orgs/', '/users/', '/search/', '/marketplace/',
    '/topics/', '/explore/', '/trending/'
];

/**
 * If the third path segment (after /{owner}/{repo}) is one of these, the
 * URL is considered NOT a repo-root context.
 */
const GITHUB_NONREPO_THIRD_SEGMENTS = new Set([
    'settings', 'organizations', 'users', 'search', 'marketplace'
]);

/**
 * Valid sub-routes under /{owner}/{repo}/ that confirm we are viewing a
 * repository page.
 */
const GITHUB_REPO_ROUTES = new Set([
    'issues', 'pull', 'pulls', 'wiki', 'projects', 'actions', 'security',
    'insights', 'settings', 'branches', 'tags', 'releases', 'commits',
    'commit', 'compare', 'graphs', 'network', 'stargazers', 'watchers',
    'forks', 'contributors', 'discussions', 'blob', 'tree', 'raw'
]);

/**
 * Validate that a string is a plausible GitHub repository URL.
 *
 * Returns an object `{ valid: boolean, reason?: string }`.
 *
 * @param {string} url  The candidate URL string.
 * @returns {{ valid: boolean, reason?: string }}
 */
function validateGitHubRepoUrl(url) {
    if (typeof url !== 'string' || !url.trim()) {
        return { valid: false, reason: 'URL is empty.' };
    }
    url = url.trim();

    // --- scheme check ---
    var parsed;
    try { parsed = new URL(url); } catch (_) {
        return { valid: false, reason: 'Not a valid URL.' };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { valid: false, reason: 'URL scheme must be http or https.' };
    }

    // --- hostname ---
    if (!parsed.hostname) {
        return { valid: false, reason: 'URL has no hostname.' };
    }

    // --- must have a path with content ---
    var rawPath = parsed.pathname || '/';

    // --- reject fragment-only or query-only without meaningful path ---
    // (parsed.pathname is always at least "/" for valid URLs)

    // strip trailing slash for segment splitting, but keep root
    var trimmedPath = rawPath.replace(/\/+$/, '') || '/';

    // split into segments (first element is '' before the leading /)
    var segments = trimmedPath.split('/');
    // segments[0] is always '' (before leading /); real segments start at [1]
    var realSegments = segments.slice(1).filter(function(s) { return s !== ''; });

    if (realSegments.length < 2) {
        return { valid: false, reason: 'URL must include at least /{owner}/{repo}.' };
    }

    var owner = realSegments[0];
    var repo  = realSegments[1];

    // --- reject if either segment has spaces or URL-encoded control chars ---
    // %20 = space, %0x = C0 control chars, %1x = more control chars, %7F = DEL
    var controlCharRe = /\s|%20|%0[0-9a-fA-F]|%1[0-9a-fA-F]|%7[fF]/;
    if (controlCharRe.test(owner)) {
        return { valid: false, reason: 'Owner segment contains spaces or control characters.' };
    }
    if (controlCharRe.test(repo)) {
        return { valid: false, reason: 'Repo segment contains spaces or control characters.' };
    }

    // --- reject "@" in candidate owner/repo (prevents email-like tokens) ---
    if (owner.indexOf('@') !== -1) {
        return { valid: false, reason: 'Owner segment must not contain "@".' };
    }
    if (repo.indexOf('@') !== -1) {
        return { valid: false, reason: 'Repo segment must not contain "@".' };
    }

    // --- owner dot rules ---
    if (owner.charAt(0) === '.' || owner.charAt(owner.length - 1) === '.') {
        return { valid: false, reason: 'Owner segment must not start or end with a dot.' };
    }
    if (owner.indexOf('..') !== -1) {
        return { valid: false, reason: 'Owner segment must not contain consecutive dots.' };
    }

    // --- repo after stripping trailing .git ---
    var repoStripped = repo.replace(/\.git$/i, '');
    if (!repoStripped) {
        return { valid: false, reason: 'Repo segment is empty after removing trailing ".git".' };
    }

    // --- reject if first segment is a reserved top-level route ---
    if (GITHUB_RESERVED_TOPLEVEL.has(owner.toLowerCase())) {
        return { valid: false, reason: '"' + owner + '" is a reserved GitHub route, not a repository owner.' };
    }

    // --- reject if repo segment is also a reserved word ---
    if (GITHUB_RESERVED_TOPLEVEL.has(repo.toLowerCase())) {
        return { valid: false, reason: '"' + repo + '" is a reserved GitHub route, not a repository name.' };
    }

    // --- reject known non-repo prefix patterns (case-insensitive) ---
    var lowerPath = rawPath.toLowerCase();
    for (var i = 0; i < GITHUB_NONREPO_PREFIXES.length; i++) {
        if (lowerPath === GITHUB_NONREPO_PREFIXES[i].slice(0, -1) || lowerPath.indexOf(GITHUB_NONREPO_PREFIXES[i]) === 0) {
            return { valid: false, reason: 'URL matches a reserved non-repository path.' };
        }
    }

    // --- exactly /{owner}/{repo} or /{owner}/{repo}/ → accept ---
    if (realSegments.length === 2) {
        return { valid: true };
    }

    // --- /{owner}/{repo}.git → accept (already length 2 handled above,
    //     but /{owner}/{repo}.git/ would also be length 2 after trim) ---

    // --- third segment checks ---
    var third = realSegments[2].toLowerCase();

    // if third segment is a known repo-scoped route → accept
    if (GITHUB_REPO_ROUTES.has(third)) {
        return { valid: true };
    }

    // if third segment indicates a non-repo context → reject
    if (GITHUB_NONREPO_THIRD_SEGMENTS.has(third)) {
        return { valid: false, reason: 'URL path after /{owner}/{repo} indicates a non-repository page.' };
    }

    // Otherwise still accept - the first two segments look like owner/repo
    // and the rest could be a deep-link into the repo.
    return { valid: true };
}

// ---------------------------------------------------------------------------
// Application version helper
// ---------------------------------------------------------------------------

/**
 * Read the application version from package.json.
 * Works in both NW.js (GUI) and plain Node.js (CLI) contexts.
 * @returns {string} Version string e.g. "1.6.5", or "" on failure.
 */
function getAppVersion() {
    try {
        // NW.js context
        if (typeof nw !== 'undefined' && nw.App && nw.App.manifest && nw.App.manifest.version) {
            return nw.App.manifest.version;
        }
    } catch (_) {}
    try {
        var pkgPath = path.join(__dirname, '..', 'package.json');
        var pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        return pkgData.version || '';
    } catch (_) {}
    return '';
}

/**
 * Get a concise Windows version string (e.g. "Windows_NT 10.0.19045 (x64)").
 * Centralised here to eliminate duplication between CLI and GUI.
 *
 * @returns {string}
 */
function getWindowsVersion() {
    try {
        return os.type() + ' ' + os.release() + ' (' + os.arch() + ')';
    } catch (_) {
        return 'Unknown';
    }
}

/**
 * Build a lineage event record that captures the environmental context
 * at the time of a packaging or export/repackage operation.
 *
 * @param {string} eventType    - 'created' | 'exported' | 'repackaged'
 * @param {object} opts         - { username, hostname, venusVersion }
 * @returns {object} A lineage event record
 */
function buildLineageEvent(eventType, opts) {
    if (VALID_LINEAGE_EVENTS.indexOf(eventType) === -1) {
        throw new Error('Invalid lineage event type: "' + eventType + '". Must be one of: ' + VALID_LINEAGE_EVENTS.join(', '));
    }
    opts = opts || {};
    var evt = {
        event:           eventType,
        timestamp:       new Date().toISOString(),
        app_version:     getAppVersion(),
        format_version:  FORMAT_VERSION,
        username:        opts.username  || '',
        hostname:        opts.hostname  || '',
        windows_version: getWindowsVersion(),
        venus_version:   opts.venusVersion   || ''
    };
    return evt;
}

// ---------------------------------------------------------------------------
// HSL Parser Functions
// ---------------------------------------------------------------------------

/**
 * Strip string literals and comments from HSL source so that keyword
 * searches (namespace, function) are not confused by content inside strings/comments.
 * @param {string} text - raw HSL source
 * @returns {string} sanitized text with strings/comments replaced by spaces
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
 * @param {string} paramList
 * @returns {string[]}
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
 * @param {string} param
 * @returns {{type: string, name: string, byRef: boolean, array: boolean}}
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
 * @param {string[]} originalLines - source lines
 * @param {number} functionStartLine - 0-based line index
 * @returns {string}
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
 * Returns an array of { name, qualifiedName, params, returnType, doc, isPrivate, file }.
 * @param {string} text - HSL source
 * @param {string} [fileName] - source filename for labelling
 * @returns {Array<Object>}
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
 * Extract public (non-private) functions from HSL files.
 * @param {string[]} libFiles - filenames
 * @param {string} libBasePath - directory containing the files
 * @returns {Array<Object>} array of public function descriptors
 */
function extractPublicFunctions(libFiles, libBasePath) {
    const allFunctions = [];
    (libFiles || []).forEach(function(fname) {
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
 * @param {string} text - HSL source code
 * @returns {string[]} array of raw include target strings
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

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
    // Constants
    FORMAT_VERSION:     FORMAT_VERSION,
    VALID_LINEAGE_EVENTS: VALID_LINEAGE_EVENTS,
    KNOWN_MANIFEST_KEYS:  KNOWN_MANIFEST_KEYS,
    KNOWN_LIB_DB_KEYS:    KNOWN_LIB_DB_KEYS,
    HASH_EXTENSIONS:    HASH_EXTENSIONS,
    HSL_METADATA_EXTS:  HSL_METADATA_EXTS,
    IMAGE_MIME_MAP:     IMAGE_MIME_MAP,
    PKG_SIGNING_KEY:    PKG_SIGNING_KEY,
    AUTHOR_MIN_LENGTH:  AUTHOR_MIN_LENGTH,
    AUTHOR_MAX_LENGTH:  AUTHOR_MAX_LENGTH,
    RESTRICTED_AUTHOR_KEYWORDS: RESTRICTED_AUTHOR_KEYWORDS,
    isRestrictedAuthor: isRestrictedAuthor,
    OEM_AUTHOR_PASSWORD_HASH: OEM_AUTHOR_PASSWORD_HASH,
    validateAuthorPassword: validateAuthorPassword,
    RESERVED_TAGS:      RESERVED_TAGS,
    RESERVED_GROUP_NAMES: RESERVED_GROUP_NAMES,
    TAG_MIN_LENGTH:     TAG_MIN_LENGTH,
    TAG_MAX_LENGTH:     TAG_MAX_LENGTH,
    TAG_MAX_COUNT:      TAG_MAX_COUNT,

    // Container format constants
    CONTAINER_MAGIC_PKG:    CONTAINER_MAGIC_PKG,
    CONTAINER_MAGIC_ARC:    CONTAINER_MAGIC_ARC,
    CONTAINER_HEADER_SIZE:  CONTAINER_HEADER_SIZE,

    // HTML escaping
    escapeHtml:         escapeHtml,

    // Filesystem safety
    safeZipExtractPath:     safeZipExtractPath,
    isValidLibraryName:     isValidLibraryName,

    // Tag validation
    isReservedTag:          isReservedTag,
    filterReservedTags:     filterReservedTags,
    sanitizeTag:            sanitizeTag,
    sanitizeTags:           sanitizeTags,
    sanitizeTagDetailed:    sanitizeTagDetailed,
    sanitizeTagsWithFeedback: sanitizeTagsWithFeedback,
    isReservedGroupName:    isReservedGroupName,

    // Integrity hashing
    computeFileHash:        computeFileHash,
    computeLibraryHashes:   computeLibraryHashes,
    parseHslMetadataFooter: parseHslMetadataFooter,

    // Package signing
    computeZipEntryHashes:    computeZipEntryHashes,
    signPackageZip:           signPackageZip,
    verifyPackageSignature:   verifyPackageSignature,

    // Binary container
    packContainer:            packContainer,
    unpackContainer:          unpackContainer,

    // GitHub URL validation
    validateGitHubRepoUrl:    validateGitHubRepoUrl,

    // Version & lineage
    getAppVersion:            getAppVersion,
    getWindowsVersion:        getWindowsVersion,
    buildLineageEvent:        buildLineageEvent,

    // HSL parser
    sanitizeHslForParsing:    sanitizeHslForParsing,
    splitHslArgs:             splitHslArgs,
    parseHslParameter:        parseHslParameter,
    extractHslDocComment:     extractHslDocComment,
    parseHslFunctions:        parseHslFunctions,
    extractPublicFunctions:   extractPublicFunctions,
    extractHslIncludes:       extractHslIncludes
};
