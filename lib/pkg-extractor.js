/**
 * Hamilton VENUS .pkg Package Extractor
 * ======================================
 * Extracts files from Hamilton VENUS .pkg binary package files.
 *
 * The .pkg format uses "HamPkg" magic bytes, a 46-byte header, an entry table
 * (36 bytes per entry), zlib-compressed data blocks, and an HxPars manifest
 * that maps entry IDs to installation file paths.
 *
 * Based on the Hamilton_PKG_Format.md specification.
 */

'use strict';

var zlib = require('zlib');
var path = require('path');

// ── Constants ─────────────────────────────────────────────────────────────────

var MAGIC = Buffer.from('HamPkg', 'ascii');
var HEADER_SIZE = 46;
var ENTRY_SIZE = 36;
var KEY_ENTRY_ID = Buffer.from('347734013', 'ascii');
var KEY_REL_PATH = Buffer.from('347734014', 'ascii');
var KEY_ABS_PATH = Buffer.from('347734015', 'ascii');

// Windows FILETIME epoch: 100-nanosecond intervals since Jan 1, 1601 UTC
var FILETIME_UNIX_EPOCH_DIFF = 116444736000000000;

// File category definitions for grouping extracted files
var FILE_CATEGORIES = {
    'hsl': { label: 'HSL Source', icon: 'fa-code', group: 'library' },
    'hs_': { label: 'HSL Header', icon: 'fa-code', group: 'library' },
    'sub': { label: 'HSL Submethod', icon: 'fa-code', group: 'library' },
    'smt': { label: 'Smart Step', icon: 'fa-puzzle-piece', group: 'library' },
    'stp': { label: 'Step File', icon: 'fa-puzzle-piece', group: 'library' },
    'chm': { label: 'Help File', icon: 'fa-question-circle', group: 'help' },
    'bmp': { label: 'Image (BMP)', icon: 'fa-image', group: 'library' },
    'png': { label: 'Image (PNG)', icon: 'fa-image', group: 'library' },
    'jpg': { label: 'Image (JPG)', icon: 'fa-image', group: 'library' },
    'jpeg': { label: 'Image (JPEG)', icon: 'fa-image', group: 'library' },
    'dll': { label: 'DLL', icon: 'fa-cog', group: 'library' },
    'hsi': { label: 'Instrument Config', icon: 'fa-sliders-h', group: 'config' },
    'cfg': { label: 'Configuration', icon: 'fa-sliders-h', group: 'config' },
    'rck': { label: 'Rack Definition', icon: 'fa-th', group: 'labware' },
    'ctr': { label: 'Container', icon: 'fa-flask', group: 'labware' },
    'tml': { label: 'Labware Template', icon: 'fa-th', group: 'labware' },
    'dck': { label: 'Deck Layout', icon: 'fa-th-large', group: 'labware' },
    'lay': { label: 'Layout', icon: 'fa-th-large', group: 'labware' },
    'res': { label: 'Resource', icon: 'fa-file', group: 'library' },
    'tpl': { label: 'Template', icon: 'fa-file', group: 'library' },
    'adp': { label: 'Adapter', icon: 'fa-plug', group: 'config' },
    'med': { label: 'Method', icon: 'fa-project-diagram', group: 'demo' },
    'mth': { label: 'Method', icon: 'fa-project-diagram', group: 'demo' },
    'wfl': { label: 'Workflow', icon: 'fa-project-diagram', group: 'demo' },
    'csv': { label: 'CSV Data', icon: 'fa-table', group: 'demo' },
    'txt': { label: 'Text', icon: 'fa-file-alt', group: 'library' },
    'xls': { label: 'Excel (XLS)', icon: 'fa-file-excel', group: 'demo' },
    'xlsx': { label: 'Excel (XLSX)', icon: 'fa-file-excel', group: 'demo' },
    'fdb': { label: 'File DB', icon: 'fa-database', group: 'library' },
    'sii': { label: 'SII File', icon: 'fa-file', group: 'library' },
    'dec': { label: 'Declaration', icon: 'fa-file', group: 'library' }
};


// ── Format Parsing ────────────────────────────────────────────────────────────

/**
 * Convert a Windows FILETIME (as a Buffer at given offset) to a JS Date.
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {Date|null}
 */
function filetimeToDate(buf, offset) {
    var lo = buf.readUInt32LE(offset);
    var hi = buf.readUInt32LE(offset + 4);
    var ticks = (hi * 0x100000000) + lo;
    if (ticks === 0) return null;
    var ms = (ticks - FILETIME_UNIX_EPOCH_DIFF) / 10000;
    return new Date(ms);
}

/**
 * Validate and parse a .pkg file buffer.
 * @param {Buffer} buf - The entire .pkg file contents
 * @returns {Object} Parsed package info
 * @throws {Error} If the buffer is not a valid .pkg file
 */
function parsePkg(buf) {
    if (!Buffer.isBuffer(buf)) {
        throw new Error('Input must be a Buffer');
    }
    if (buf.length < HEADER_SIZE) {
        throw new Error('File too small (' + buf.length + ' bytes) to contain a valid .pkg header');
    }
    if (buf.compare(MAGIC, 0, 6, 0, 6) !== 0) {
        throw new Error('Not a Hamilton .pkg file (expected "HamPkg" magic bytes)');
    }

    // Parse header
    var fmtVer = buf.readUInt16LE(8);
    var fmtSub = buf.readUInt16LE(10);
    var entryCount = buf.readUInt16LE(14);
    if (entryCount > 10000) {
        throw new Error('Unreasonable entry count (' + entryCount + ') - file may be corrupted');
    }
    var created = filetimeToDate(buf, 18);
    var venusVersion = buf.toString('ascii', 26, 46).replace(/\0+$/, '');

    // Parse entry table
    var entries = [];
    for (var i = 0; i < entryCount; i++) {
        var off = HEADER_SIZE + i * ENTRY_SIZE;
        if (off + ENTRY_SIZE > buf.length) {
            throw new Error('Entry table extends past end of file at entry ' + i);
        }
        entries.push({
            index: i,
            id: buf.toString('ascii', off, off + 7).replace(/\0+$/, ''),
            flags: buf.readUInt32LE(off + 8),
            created: filetimeToDate(buf, off + 12),
            modified: filetimeToDate(buf, off + 20),
            dataOffset: buf.readUInt32LE(off + 28),
            dataSize: buf.readUInt32LE(off + 32)
        });
    }

    // Find manifest entry (flags === 0)
    var manifestEntry = null;
    for (var m = 0; m < entries.length; m++) {
        if (entries[m].flags === 0) {
            manifestEntry = entries[m];
            break;
        }
    }
    if (!manifestEntry) {
        throw new Error('No manifest entry found (no entry with flags=0)');
    }

    // Decompress manifest
    var manifestData = decompressEntry(buf, manifestEntry);
    var fileMap = parseManifest(manifestData);

    // Parse trailer
    var trailer = parseTrailer(buf);

    return {
        formatVersion: fmtVer + '.' + fmtSub,
        entryCount: entryCount,
        created: created,
        venusVersion: venusVersion,
        entries: entries,
        fileMap: fileMap,
        manifestEntry: manifestEntry,
        trailer: trailer
    };
}

/**
 * Decompress a single entry's zlib data block.
 * @param {Buffer} buf - Full .pkg file buffer
 * @param {Object} entry - Entry object from parsePkg
 * @returns {Buffer} Decompressed data
 */
function decompressEntry(buf, entry) {
    var off = entry.dataOffset;
    if (off + 8 > buf.length) {
        throw new Error('Data block header for entry ' + entry.id + ' extends past file end');
    }
    var uncompressedSize = buf.readUInt32LE(off);
    var compressedSize = buf.readUInt32LE(off + 4);
    if (off + 8 + compressedSize > buf.length) {
        throw new Error('Compressed data for entry ' + entry.id + ' extends past file end');
    }
    var data = zlib.inflateSync(buf.slice(off + 8, off + 8 + compressedSize));
    if (data.length !== uncompressedSize) {
        console.warn('Entry ' + entry.id + ' size mismatch: expected ' +
            uncompressedSize + ', got ' + data.length);
    }
    return data;
}

/**
 * Parse the HxPars,McListData manifest to build entry ID → absolute path mapping.
 * @param {Buffer} manifest - Decompressed manifest data
 * @returns {Object} Map of entry hex ID → absolute file path
 */
function parseManifest(manifest) {
    var map = {};
    var pos = 0;
    while (pos < manifest.length) {
        var idIdx = manifest.indexOf(KEY_ENTRY_ID, pos);
        if (idIdx === -1) break;

        var afterId = idIdx + KEY_ENTRY_ID.length;
        if (afterId >= manifest.length) break;

        var idLen = manifest[afterId];
        if (idLen > 0 && idLen < 20 && afterId + 1 + idLen <= manifest.length) {
            var entryId = manifest.toString('ascii', afterId + 1, afterId + 1 + idLen);
            if (/^[0-9a-f]+$/.test(entryId)) {
                // Search for abs path key within 300 bytes forward
                var searchEnd = Math.min(afterId + 300, manifest.length);
                var searchBuf = manifest.slice(afterId, searchEnd);
                var pathIdx = searchBuf.indexOf(KEY_ABS_PATH);
                if (pathIdx !== -1) {
                    var pathStart = afterId + pathIdx + KEY_ABS_PATH.length;
                    var pathLen = manifest[pathStart];
                    if (pathLen > 0 && pathStart + 1 + pathLen <= manifest.length) {
                        var absPath = manifest.toString('utf8', pathStart + 1, pathStart + 1 + pathLen);
                        map[entryId] = absPath;
                    }
                }
            }
        }
        pos = afterId + 1;
    }
    return map;
}

/**
 * Parse the $$key=value$$ trailer at the end of the .pkg file.
 * @param {Buffer} buf - Full .pkg file buffer
 * @returns {Object|null} Trailer fields or null if not found
 */
function parseTrailer(buf) {
    var tailLen = Math.min(150, buf.length);
    var tail = buf.slice(buf.length - tailLen).toString('ascii');
    var match = tail.match(/\$\$author=(.+?)\$\$valid=(.+?)\$\$time=(.+?)\$\$checksum=(.+?)\$\$length=(.+?)\$\$/);
    if (match) {
        return {
            author: match[1],
            valid: match[2],
            time: match[3],
            checksum: match[4],
            length: match[5]
        };
    }
    return null;
}

/**
 * Convert an absolute Hamilton install path to a relative path.
 * @param {string} absPath
 * @returns {string} Relative path from the Hamilton directory
 */
function absPathToRelative(absPath) {
    var lower = absPath.toLowerCase();
    var hamiltonIdx = lower.indexOf('\\hamilton\\');
    if (hamiltonIdx >= 0) {
        return absPath.substring(hamiltonIdx + '\\hamilton\\'.length);
    }
    // Fall back: strip drive letter
    if (absPath.length > 2 && absPath[1] === ':') {
        return absPath.substring(2).replace(/^[\\/]+/, '');
    }
    return path.basename(absPath);
}

/**
 * Detect content type of decompressed data from magic bytes.
 * @param {Buffer} data
 * @returns {string} Content type label
 */
function detectContentType(data) {
    if (data.length < 4) return 'unknown';
    var b = data.slice(0, 4);
    if (b[0] === 0x03 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return 'HxPars';
    if (b[0] === 0x02 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return 'Metadata';
    if (b[0] === 0x89 && b[1] === 0x50) return 'PNG';
    if (b[0] === 0x42 && b[1] === 0x4D) return 'BMP';
    if (b.toString('ascii') === 'ITSF') return 'CHM';
    if (b[0] === 0xD0 && b[1] === 0xCF && b[2] === 0x11 && b[3] === 0xE0) return 'OLE/XLS';
    if (b.toString('ascii') === 'PK\x03\x04') return 'ZIP/XLSX';
    if (b[0] === 0xFF && b[1] === 0xFE) return 'UTF-16LE';
    var text = data.slice(0, 20).toString('ascii');
    if (/^(\/\/|\/\*|#pragma|#include|function|namespace|variable|method|global|static)/i.test(text)) {
        return 'HSL Source';
    }
    return 'Text/Other';
}

/**
 * Get the file category info for a given file extension.
 * @param {string} ext - File extension without dot (e.g. 'hsl')
 * @returns {Object} Category info with label, icon, group
 */
function getFileCategory(ext) {
    var lower = (ext || '').toLowerCase();
    return FILE_CATEGORIES[lower] || { label: lower.toUpperCase() || 'Unknown', icon: 'fa-file', group: 'library' };
}

/**
 * Determine the Hamilton subdirectory category from an absolute path.
 * @param {string} absPath
 * @returns {string} Category: 'library', 'labware', 'config', 'methods', 'system', or 'other'
 */
function getPathCategory(absPath) {
    var rel = absPathToRelative(absPath).toLowerCase();
    if (rel.indexOf('library\\') === 0 || rel.indexOf('library/') === 0) return 'library';
    if (rel.indexOf('labware\\') === 0 || rel.indexOf('labware/') === 0) return 'labware';
    if (rel.indexOf('config\\') === 0 || rel.indexOf('config/') === 0) return 'config';
    if (rel.indexOf('methods\\') === 0 || rel.indexOf('methods/') === 0) return 'methods';
    if (rel.indexOf('system\\') === 0 || rel.indexOf('system/') === 0) return 'system';
    return 'other';
}

/**
 * Extract and categorize all files from a parsed .pkg package.
 * Returns a structured object with file entries grouped by category.
 *
 * @param {Buffer} buf - Full .pkg file buffer
 * @param {Object} pkgInfo - Parsed package info from parsePkg()
 * @returns {Array} Array of file entry objects
 */
function extractAllFiles(buf, pkgInfo) {
    var results = [];
    var entries = pkgInfo.entries;
    var fileMap = pkgInfo.fileMap;

    for (var i = 0; i < entries.length; i++) {
        var entry = entries[i];
        if (entry.flags !== 1) continue; // skip manifest and non-file entries

        var data;
        try {
            data = decompressEntry(buf, entry);
        } catch (e) {
            results.push({
                id: entry.id,
                index: entry.index,
                relPath: 'unmapped/' + entry.id + '.bin',
                ext: '',
                category: { label: 'Error', icon: 'fa-exclamation-triangle', group: 'other' },
                pathCategory: 'other',
                size: 0,
                contentType: 'Error',
                data: null,
                error: 'Decompression failed: ' + e.message
            });
            continue;
        }
        var absPath = fileMap[entry.id] || null;
        var relPath = absPath ? absPathToRelative(absPath) : ('unmapped/' + entry.id + '.bin');
        var ext = path.extname(relPath).replace(/^\./, '').toLowerCase();
        var category = getFileCategory(ext);
        var pathCat = absPath ? getPathCategory(absPath) : 'other';
        var contentType = detectContentType(data);

        results.push({
            entryId: entry.id,
            entryIndex: entry.index,
            absPath: absPath,
            relPath: relPath,
            fileName: path.basename(relPath),
            extension: ext,
            category: category,
            pathCategory: pathCat,
            contentType: contentType,
            size: data.length,
            data: data,
            created: entry.created,
            modified: entry.modified,
            selected: false
        });
    }

    return results;
}

/**
 * Group file entries by their Hamilton subdirectory category.
 * @param {Array} files - Array of file entry objects from extractAllFiles()
 * @returns {Object} Grouped files: { library: [], labware: [], config: [], methods: [], system: [], other: [] }
 */
function groupFilesByCategory(files) {
    var groups = { library: [], labware: [], config: [], methods: [], system: [], other: [] };
    for (var i = 0; i < files.length; i++) {
        var cat = files[i].pathCategory;
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(files[i]);
    }
    return groups;
}

/**
 * Detect the likely library name from a set of file entries.
 * Looks for primary .hsl or .hs_ files in the Library subdirectory.
 * @param {Array} files - Array of file entry objects
 * @returns {string} Detected library name or empty string
 */
function detectLibraryName(files) {
    // Look for .hsl or .hs_ files in the Library path category
    var candidates = [];
    for (var i = 0; i < files.length; i++) {
        var f = files[i];
        if (f.pathCategory === 'library' && (f.extension === 'hsl' || f.extension === 'hs_')) {
            candidates.push(f);
        }
    }

    if (candidates.length === 0) return '';

    // If there's exactly one, use its basename without extension
    if (candidates.length === 1) {
        return path.basename(candidates[0].fileName, path.extname(candidates[0].fileName));
    }

    // Look for a common subdirectory name
    var subdirs = {};
    for (var j = 0; j < candidates.length; j++) {
        var rel = candidates[j].relPath;
        // Library\SubDir\File.hsl -> SubDir
        var parts = rel.replace(/\//g, '\\').split('\\');
        if (parts.length >= 3 && parts[0].toLowerCase() === 'library') {
            var subdir = parts[1];
            subdirs[subdir] = (subdirs[subdir] || 0) + 1;
        }
    }

    // Return the most common subdirectory name
    var best = '';
    var bestCount = 0;
    for (var key in subdirs) {
        if (subdirs[key] > bestCount) {
            bestCount = subdirs[key];
            best = key;
        }
    }

    return best || path.basename(candidates[0].fileName, path.extname(candidates[0].fileName));
}

/**
 * Detect the library subdirectory from file paths.
 * @param {Array} files - Selected file entries
 * @returns {string} Detected subdirectory name under Library\ or empty string
 */
function detectLibrarySubdir(files) {
    for (var i = 0; i < files.length; i++) {
        var f = files[i];
        if (f.pathCategory === 'library') {
            var parts = f.relPath.replace(/\//g, '\\').split('\\');
            // Library\SubDir\... -> SubDir
            if (parts.length >= 3 && parts[0].toLowerCase() === 'library') {
                return parts[1];
            }
        }
    }
    return '';
}


// ── .hamPackage (ZIP) Format Support ──────────────────────────────────────────

var AdmZip = require('adm-zip');

/**
 * Check whether a file buffer is a ZIP archive (.hamPackage).
 * @param {Buffer} buf
 * @returns {boolean}
 */
function isHamPackage(buf) {
    return Buffer.isBuffer(buf) && buf.length >= 4 &&
        buf[0] === 0x50 && buf[1] === 0x4B && buf[2] === 0x03 && buf[3] === 0x04;
}

/**
 * Map a .hamPackage manifest ItemType to a Hamilton path category.
 * ItemType values from the manifest:
 *   1 = config, 2 = instrument, 3 = labware, 4 = method/user files,
 *   5 = library, 6 = labware, 7 = system
 * @param {number} itemType
 * @param {string} absPath - Original absolute path for fallback classification
 * @returns {string} path category
 */
function hamPkgItemTypeToCategory(itemType, absPath) {
    switch (itemType) {
        case 1: return 'config';
        case 2: return 'config';
        case 3: return 'labware';
        case 4: return 'methods';
        case 5: return 'library';
        case 6: return 'labware';
        case 7: return 'system';
        default:
            // Fall back to path-based detection
            return absPath ? getPathCategory(absPath) : 'other';
    }
}

/**
 * Parse a .hamPackage (ZIP) file buffer and extract all files into the same
 * format that extractAllFiles() returns for .pkg files.
 *
 * @param {Buffer|string} bufOrPath - ZIP buffer or file path
 * @returns {Object} { pkgInfo, files } matching the .pkg workflow shape
 */
function parseHamPackage(bufOrPath) {
    var zip = new AdmZip(bufOrPath);
    var zipEntries = zip.getEntries();

    // Read manifest.json
    var manifestEntry = zip.getEntry('manifest.json');
    var manifest = null;
    if (manifestEntry) {
        try {
            manifest = JSON.parse(manifestEntry.getData().toString('utf8'));
        } catch (e) {
            throw new Error('Failed to parse manifest.json in .hamPackage: ' + e.message);
        }
    }

    // Build a lookup from file name → manifest metadata
    var manifestFileLookup = {};
    if (manifest) {
        var allRefs = [];
        // CommonFileReferences
        if (Array.isArray(manifest.CommonFileReferences)) {
            allRefs = allRefs.concat(manifest.CommonFileReferences);
        }
        // InstrumentReferences may contain embedded file references
        if (manifest.MethodFileReference && manifest.MethodFileReference.SystemDeckFile) {
            var sysRef = manifest.MethodFileReference.SystemDeckFile;
            if (sysRef.FileReferences) {
                allRefs = allRefs.concat(sysRef.FileReferences);
            }
        }
        for (var ri = 0; ri < allRefs.length; ri++) {
            var ref = allRefs[ri];
            if (ref && ref.Name) {
                manifestFileLookup[ref.Name.toLowerCase()] = ref;
            }
        }
    }

    // Find files in the ZIP (skip directories and manifest.json itself)
    var files = [];
    var entryIdx = 0;
    for (var i = 0; i < zipEntries.length; i++) {
        var ze = zipEntries[i];
        if (ze.isDirectory) continue;
        if (ze.entryName === 'manifest.json') continue;

        var data;
        try {
            data = ze.getData();
        } catch (e) {
            files.push({
                entryId: String(entryIdx),
                entryIndex: entryIdx,
                absPath: null,
                relPath: ze.entryName,
                fileName: path.basename(ze.entryName),
                extension: path.extname(ze.entryName).replace(/^\./, '').toLowerCase(),
                category: { label: 'Error', icon: 'fa-exclamation-triangle', group: 'other' },
                pathCategory: 'other',
                contentType: 'Error',
                size: 0,
                data: null,
                error: 'Extract failed: ' + e.message,
                selected: false
            });
            entryIdx++;
            continue;
        }

        var fileName = path.basename(ze.entryName);
        var ext = path.extname(fileName).replace(/^\./, '').toLowerCase();
        var category = getFileCategory(ext);

        // Determine path category from manifest metadata or ZIP path
        var pathCat = 'other';
        var absPath = null;
        var mRef = manifestFileLookup[fileName.toLowerCase()];
        if (mRef) {
            absPath = mRef.FullName || null;
            pathCat = hamPkgItemTypeToCategory(mRef.ItemType, absPath);
        } else if (absPath) {
            pathCat = getPathCategory(absPath);
        } else {
            // Infer from zip folder structure
            var topFolder = ze.entryName.split('/')[0].toLowerCase();
            if (topFolder === 'dependencies') {
                // Dependencies folder: classify by extension
                if (category.group === 'library' || category.group === 'help') pathCat = 'library';
                else if (category.group === 'labware') pathCat = 'labware';
                else if (category.group === 'config') pathCat = 'config';
                else if (category.group === 'demo') pathCat = 'methods';
                else pathCat = 'library';
            } else {
                // Other top-level folders are likely method/user folders
                pathCat = 'methods';
            }
        }

        var contentType = detectContentType(data);

        // Build relPath from manifest absPath if available, else use ZIP entry name
        var relPath = absPath ? absPathToRelative(absPath) : ze.entryName;

        files.push({
            entryId: String(entryIdx),
            entryIndex: entryIdx,
            absPath: absPath,
            relPath: relPath,
            fileName: fileName,
            extension: ext,
            category: category,
            pathCategory: pathCat,
            contentType: contentType,
            size: data.length,
            data: data,
            created: ze.header.time ? new Date(ze.header.time) : null,
            modified: ze.header.time ? new Date(ze.header.time) : null,
            selected: false
        });
        entryIdx++;
    }

    // Build a pkgInfo-like object for compatibility with the main.js UI
    var venusVersion = '';
    var authorName = '';
    var createdDate = null;

    if (manifest) {
        // Try to extract VENUS version from instrument references
        if (manifest.CommonInstrumentReferences && manifest.CommonInstrumentReferences.length > 0) {
            // No explicit version in manifest, but we can note the instrument type
        }
        // Try to extract author from method file reference
        if (manifest.MethodFileReference && manifest.MethodFileReference.SystemDeckFile) {
            var sdRef = manifest.MethodFileReference.SystemDeckFile;
            if (sdRef.FileReferences && sdRef.FileReferences.length > 0) {
                // Use earliest creation time as created date
                for (var ci = 0; ci < sdRef.FileReferences.length; ci++) {
                    var cr = sdRef.FileReferences[ci];
                    if (cr.CreationTimeUtc) {
                        var d = new Date(cr.CreationTimeUtc);
                        if (!createdDate || d < createdDate) createdDate = d;
                    }
                }
            }
        }
        // Also check CommonFileReferences for creation time
        if (manifest.CommonFileReferences) {
            for (var cf = 0; cf < manifest.CommonFileReferences.length; cf++) {
                var cfr = manifest.CommonFileReferences[cf];
                if (cfr.CreationTimeUtc) {
                    var cd = new Date(cfr.CreationTimeUtc);
                    if (!createdDate || cd < createdDate) createdDate = cd;
                }
            }
        }
    }

    var pkgInfo = {
        formatVersion: 'hamPackage',
        entryCount: files.length,
        created: createdDate,
        venusVersion: venusVersion,
        entries: files.map(function(f, idx) {
            return { index: idx, flags: 1 };
        }),
        fileMap: {},
        manifestEntry: null,
        trailer: authorName ? { author: authorName } : null,
        isHamPackage: true
    };

    return { pkgInfo: pkgInfo, files: files };
}

// ── Module Exports ────────────────────────────────────────────────────────────

module.exports = {
    parsePkg: parsePkg,
    decompressEntry: decompressEntry,
    absPathToRelative: absPathToRelative,
    detectContentType: detectContentType,
    getFileCategory: getFileCategory,
    getPathCategory: getPathCategory,
    extractAllFiles: extractAllFiles,
    groupFilesByCategory: groupFilesByCategory,
    detectLibraryName: detectLibraryName,
    detectLibrarySubdir: detectLibrarySubdir,
    isHamPackage: isHamPackage,
    parseHamPackage: parseHamPackage,
    FILE_CATEGORIES: FILE_CATEGORIES
};
