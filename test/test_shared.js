/**
 * Venus Library Manager - Shared Module Tests
 *
 * Minimal smoke tests for the shared validation, hashing, and signing
 * routines.  Run with:  npm test  (or  node test/test_shared.js)
 */

'use strict';

const path   = require('path');
const assert = require('assert');
const shared = require('../lib/shared');

let passed = 0;
let failed = 0;

function test(label, fn) {
    try {
        fn();
        passed++;
        console.log('  \u2714 ' + label);
    } catch (e) {
        failed++;
        console.error('  \u2718 ' + label);
        console.error('    ' + e.message);
    }
}

// -----------------------------------------------------------------------
console.log('\n=== isValidLibraryName ===');
// -----------------------------------------------------------------------

test('rejects empty string', function () {
    assert.strictEqual(shared.isValidLibraryName(''), false);
});

test('rejects null', function () {
    assert.strictEqual(shared.isValidLibraryName(null), false);
});

test('rejects undefined', function () {
    assert.strictEqual(shared.isValidLibraryName(undefined), false);
});

test('rejects name with backslash', function () {
    assert.strictEqual(shared.isValidLibraryName('foo\\bar'), false);
});

test('rejects name with forward slash', function () {
    assert.strictEqual(shared.isValidLibraryName('foo/bar'), false);
});

test('rejects name with .. traversal', function () {
    assert.strictEqual(shared.isValidLibraryName('..'), false);
    assert.strictEqual(shared.isValidLibraryName('foo..bar'), false);
});

test('rejects Windows reserved device names', function () {
    assert.strictEqual(shared.isValidLibraryName('CON'), false);
    assert.strictEqual(shared.isValidLibraryName('PRN'), false);
    assert.strictEqual(shared.isValidLibraryName('AUX'), false);
    assert.strictEqual(shared.isValidLibraryName('NUL'), false);
    assert.strictEqual(shared.isValidLibraryName('COM1'), false);
    assert.strictEqual(shared.isValidLibraryName('COM9'), false);
    assert.strictEqual(shared.isValidLibraryName('LPT1'), false);
    assert.strictEqual(shared.isValidLibraryName('LPT9'), false);
});

test('rejects reserved names case-insensitively', function () {
    assert.strictEqual(shared.isValidLibraryName('con'), false);
    assert.strictEqual(shared.isValidLibraryName('Con'), false);
    assert.strictEqual(shared.isValidLibraryName('nul'), false);
    assert.strictEqual(shared.isValidLibraryName('Prn'), false);
});

test('rejects reserved names with extensions', function () {
    assert.strictEqual(shared.isValidLibraryName('CON.txt'), false);
    assert.strictEqual(shared.isValidLibraryName('NUL.lib'), false);
    assert.strictEqual(shared.isValidLibraryName('COM1.hsl'), false);
});

test('accepts names containing reserved words as substrings', function () {
    assert.strictEqual(shared.isValidLibraryName('MyCONtroller'), true);
    assert.strictEqual(shared.isValidLibraryName('CONTROLLER'), true);
    assert.strictEqual(shared.isValidLibraryName('NullHandler'), true);
    assert.strictEqual(shared.isValidLibraryName('Aux-Helper'), true);
});

test('rejects name with reserved chars', function () {
    assert.strictEqual(shared.isValidLibraryName('lib<>name'), false);
    assert.strictEqual(shared.isValidLibraryName('lib:name'), false);
    assert.strictEqual(shared.isValidLibraryName('lib"name'), false);
    assert.strictEqual(shared.isValidLibraryName('lib|name'), false);
    assert.strictEqual(shared.isValidLibraryName('lib?name'), false);
    assert.strictEqual(shared.isValidLibraryName('lib*name'), false);
});

test('rejects trailing dot', function () {
    assert.strictEqual(shared.isValidLibraryName('MyLib.'), false);
});

test('rejects trailing space', function () {
    assert.strictEqual(shared.isValidLibraryName('MyLib '), false);
});

test('rejects whitespace-only name', function () {
    assert.strictEqual(shared.isValidLibraryName('   '), false);
});

test('accepts simple library name', function () {
    assert.strictEqual(shared.isValidLibraryName('MyLibrary'), true);
});

test('accepts name with dots (non-trailing)', function () {
    assert.strictEqual(shared.isValidLibraryName('My.Library.v2'), true);
});

test('accepts name with spaces (non-trailing)', function () {
    assert.strictEqual(shared.isValidLibraryName('My Library'), true);
});

test('accepts name with hyphens and underscores', function () {
    assert.strictEqual(shared.isValidLibraryName('My-Library_v2'), true);
});

// -----------------------------------------------------------------------
console.log('\n=== escapeHtml ===');
// -----------------------------------------------------------------------

test('escapes angle brackets', function () {
    assert.strictEqual(shared.escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
});

test('escapes ampersand', function () {
    assert.strictEqual(shared.escapeHtml('a&b'), 'a&amp;b');
});

test('escapes quotes', function () {
    assert.strictEqual(shared.escapeHtml('"hello"'), '&quot;hello&quot;');
    assert.strictEqual(shared.escapeHtml("'hi'"), '&#39;hi&#39;');
});

test('returns empty string for non-string', function () {
    assert.strictEqual(shared.escapeHtml(null), '');
    assert.strictEqual(shared.escapeHtml(123), '');
    assert.strictEqual(shared.escapeHtml(undefined), '');
});

// -----------------------------------------------------------------------
console.log('\n=== safeZipExtractPath ===');
// -----------------------------------------------------------------------

test('allows normal relative path', function () {
    var result = shared.safeZipExtractPath('C:\\target', 'file.txt');
    assert.ok(result !== null);
    assert.ok(result.startsWith('C:\\target'));
});

test('allows nested relative path', function () {
    var result = shared.safeZipExtractPath('C:\\target', 'subdir/file.txt');
    assert.ok(result !== null);
    assert.ok(result.startsWith('C:\\target'));
});

test('allows filenames containing double-dot substring', function () {
    // file..data.txt does not escape the target dir; the old code
    // false-positived on this because it checked for ".." as a substring
    var result = shared.safeZipExtractPath('C:\\target', 'file..data.txt');
    assert.ok(result !== null, 'should not reject benign double-dot in filename');
    assert.ok(result.startsWith('C:\\target'));
});

test('rejects .. traversal', function () {
    assert.strictEqual(shared.safeZipExtractPath('C:\\target', '../etc/passwd'), null);
});

test('rejects backslash traversal', function () {
    assert.strictEqual(shared.safeZipExtractPath('C:\\target', '..\\Windows\\system32'), null);
});

test('rejects traversal with nested ..', function () {
    assert.strictEqual(shared.safeZipExtractPath('C:\\target', 'subdir/../../etc/passwd'), null);
});

test('rejects absolute paths', function () {
    assert.strictEqual(shared.safeZipExtractPath('C:\\target', 'C:\\Windows\\system32\\cmd.exe'), null);
});

// -----------------------------------------------------------------------
console.log('\n=== computeFileHash ===');
// -----------------------------------------------------------------------

test('returns null for non-existent file', function () {
    assert.strictEqual(shared.computeFileHash('C:\\nonexistent\\file.txt'), null);
});

test('produces consistent hash for same content', function () {
    var fs = require('fs');
    var os = require('os');
    var tmpFile = path.join(os.tmpdir(), 'vlm_test_hash_' + Date.now() + '.txt');
    fs.writeFileSync(tmpFile, 'hello world');
    try {
        var h1 = shared.computeFileHash(tmpFile);
        var h2 = shared.computeFileHash(tmpFile);
        assert.ok(h1 !== null);
        assert.strictEqual(h1, h2);
        assert.strictEqual(h1.length, 64); // SHA-256 hex = 64 chars
    } finally {
        fs.unlinkSync(tmpFile);
    }
});

// -----------------------------------------------------------------------
console.log('\n=== parseHslMetadataFooter ===');
// -----------------------------------------------------------------------

test('returns null for non-existent file', function () {
    assert.strictEqual(shared.parseHslMetadataFooter('C:\\nonexistent\\file.hsl'), null);
});

test('returns null for file without footer', function () {
    var fs = require('fs');
    var os = require('os');
    var tmpFile = path.join(os.tmpdir(), 'vlm_test_nometa_' + Date.now() + '.hsl');
    fs.writeFileSync(tmpFile, 'function main() {}\n// just a comment\n');
    try {
        assert.strictEqual(shared.parseHslMetadataFooter(tmpFile), null);
    } finally {
        fs.unlinkSync(tmpFile);
    }
});

test('parses valid metadata footer', function () {
    var fs = require('fs');
    var os = require('os');
    var tmpFile = path.join(os.tmpdir(), 'vlm_test_meta_' + Date.now() + '.hsl');
    var footer = '// $$author=TestUser$$valid=1$$time=2024-01-01$$checksum=abcdef01$$length=42$$';
    fs.writeFileSync(tmpFile, 'function main() {}\n' + footer + '\n');
    try {
        var result = shared.parseHslMetadataFooter(tmpFile);
        assert.ok(result !== null);
        assert.strictEqual(result.author, 'TestUser');
        assert.strictEqual(result.valid, 1);
        assert.strictEqual(result.time, '2024-01-01');
        assert.strictEqual(result.checksum, 'abcdef01');
        assert.strictEqual(result.length, 42);
    } finally {
        fs.unlinkSync(tmpFile);
    }
});

// -----------------------------------------------------------------------
console.log('\n=== computeZipEntryHashes ===');
// -----------------------------------------------------------------------

test('hashes all non-directory entries except signature.json', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('file1.txt', Buffer.from('content1'));
    zip.addFile('file2.txt', Buffer.from('content2'));
    zip.addFile('signature.json', Buffer.from('{}'));

    var hashes = shared.computeZipEntryHashes(zip);
    assert.ok(hashes['file1.txt']);
    assert.ok(hashes['file2.txt']);
    assert.strictEqual(hashes['signature.json'], undefined);
});

test('returns sorted keys', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('z_file.txt', Buffer.from('z'));
    zip.addFile('a_file.txt', Buffer.from('a'));
    zip.addFile('m_file.txt', Buffer.from('m'));

    var hashes = shared.computeZipEntryHashes(zip);
    var keys = Object.keys(hashes);
    assert.deepStrictEqual(keys, ['a_file.txt', 'm_file.txt', 'z_file.txt']);
});

// -----------------------------------------------------------------------
console.log('\n=== signPackageZip / verifyPackageSignature ===');
// -----------------------------------------------------------------------

test('sign and verify round-trip succeeds', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from('{"library_name":"Test"}'));
    zip.addFile('library/test.hsl', Buffer.from('function main() {}'));

    shared.signPackageZip(zip);
    var result = shared.verifyPackageSignature(zip);
    assert.strictEqual(result.signed, true);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.errors.length, 0);
});

test('verify detects tampering', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from('{"library_name":"Test"}'));
    zip.addFile('library/test.hsl', Buffer.from('function main() {}'));
    shared.signPackageZip(zip);

    // Tamper with a file after signing
    zip.addFile('library/test.hsl', Buffer.from('TAMPERED'));
    var result = shared.verifyPackageSignature(zip);
    assert.strictEqual(result.signed, true);
    assert.strictEqual(result.valid, false);
    assert.ok(result.errors.length > 0);
});

test('verify reports unsigned package', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from('{}'));
    var result = shared.verifyPackageSignature(zip);
    assert.strictEqual(result.signed, false);
});

// -----------------------------------------------------------------------
console.log('\n=== Constants ===');
// -----------------------------------------------------------------------

test('HASH_EXTENSIONS contains expected values', function () {
    assert.ok(shared.HASH_EXTENSIONS.indexOf('.hsl') !== -1);
    assert.ok(shared.HASH_EXTENSIONS.indexOf('.hs_') !== -1);
    assert.ok(shared.HASH_EXTENSIONS.indexOf('.sub') !== -1);
});

test('HSL_METADATA_EXTS contains expected values', function () {
    assert.ok(shared.HSL_METADATA_EXTS.indexOf('.hsl') !== -1);
    assert.ok(shared.HSL_METADATA_EXTS.indexOf('.smt') !== -1);
});

test('IMAGE_MIME_MAP has PNG entry', function () {
    assert.strictEqual(shared.IMAGE_MIME_MAP['.png'], 'image/png');
});

// -----------------------------------------------------------------------
console.log('\n=== isReservedTag ===');
// -----------------------------------------------------------------------

test('detects "system" as reserved (lowercase)', function () {
    assert.strictEqual(shared.isReservedTag('system'), true);
});

test('detects "System" as reserved (mixed case)', function () {
    assert.strictEqual(shared.isReservedTag('System'), true);
});

test('detects "SYSTEM" as reserved (uppercase)', function () {
    assert.strictEqual(shared.isReservedTag('SYSTEM'), true);
});

test('detects "hamilton" as reserved (lowercase)', function () {
    assert.strictEqual(shared.isReservedTag('hamilton'), true);
});

test('detects "Hamilton" as reserved (mixed case)', function () {
    assert.strictEqual(shared.isReservedTag('Hamilton'), true);
});

test('detects "HAMILTON" as reserved (uppercase)', function () {
    assert.strictEqual(shared.isReservedTag('HAMILTON'), true);
});

test('detects reserved tag with surrounding whitespace', function () {
    assert.strictEqual(shared.isReservedTag('  system  '), true);
    assert.strictEqual(shared.isReservedTag(' Hamilton '), true);
});

test('does not flag non-reserved tags', function () {
    assert.strictEqual(shared.isReservedTag('pipetting'), false);
    assert.strictEqual(shared.isReservedTag('assay'), false);
    assert.strictEqual(shared.isReservedTag('systemtools'), false);
    assert.strictEqual(shared.isReservedTag('myhamilton'), false);
});

test('returns false for null/undefined/empty', function () {
    assert.strictEqual(shared.isReservedTag(null), false);
    assert.strictEqual(shared.isReservedTag(undefined), false);
    assert.strictEqual(shared.isReservedTag(''), false);
});

// -----------------------------------------------------------------------
console.log('\n=== filterReservedTags ===');
// -----------------------------------------------------------------------

test('filters out reserved tags and reports them', function () {
    var result = shared.filterReservedTags(['pipetting', 'System', 'Hamilton', 'PCR']);
    assert.deepStrictEqual(result.filtered, ['pipetting', 'PCR']);
    assert.deepStrictEqual(result.removed, ['System', 'Hamilton']);
});

test('returns all tags when none are reserved', function () {
    var result = shared.filterReservedTags(['pipetting', 'assay', 'PCR']);
    assert.deepStrictEqual(result.filtered, ['pipetting', 'assay', 'PCR']);
    assert.deepStrictEqual(result.removed, []);
});

test('returns empty arrays for empty input', function () {
    var result = shared.filterReservedTags([]);
    assert.deepStrictEqual(result.filtered, []);
    assert.deepStrictEqual(result.removed, []);
});

test('handles non-array input gracefully', function () {
    var result = shared.filterReservedTags(null);
    assert.deepStrictEqual(result.filtered, []);
    assert.deepStrictEqual(result.removed, []);
});

test('is case-insensitive for mixed-case reserved tags', function () {
    var result = shared.filterReservedTags(['sYsTeM', 'hAmIlToN']);
    assert.deepStrictEqual(result.filtered, []);
    assert.deepStrictEqual(result.removed, ['sYsTeM', 'hAmIlToN']);
});

// -----------------------------------------------------------------------
console.log('\n=== RESERVED_TAGS constant ===');
// -----------------------------------------------------------------------

test('RESERVED_TAGS contains system and hamilton', function () {
    assert.ok(shared.RESERVED_TAGS.indexOf('system') !== -1);
    assert.ok(shared.RESERVED_TAGS.indexOf('hamilton') !== -1);
});

test('RESERVED_TAGS contains all expanded reserved keywords', function () {
    ['stared', 'starred', 'signed', 'unsigned', 'registered', 'unregistered'].forEach(function(t) {
        assert.ok(shared.RESERVED_TAGS.indexOf(t) !== -1, 'Missing reserved tag: ' + t);
    });
});

test('filterReservedTags removes new reserved tags', function () {
    var result = shared.filterReservedTags(['pipetting', 'stared', 'Starred', 'unsigned', 'PCR', 'Registered']);
    assert.deepStrictEqual(result.filtered, ['pipetting', 'PCR']);
    assert.deepStrictEqual(result.removed, ['stared', 'Starred', 'unsigned', 'Registered']);
});

// -----------------------------------------------------------------------
console.log('\n=== isReservedGroupName ===');
// -----------------------------------------------------------------------

test('detects reserved group names (case-insensitive)', function () {
    ['Starred', 'Hamilton', 'System', 'Signed', 'Unsigned', 'Registered', 'Unregistered',
     'All', 'Recent', 'Import', 'Export', 'History'].forEach(function(n) {
        assert.strictEqual(shared.isReservedGroupName(n), true, 'Should be reserved: ' + n);
        assert.strictEqual(shared.isReservedGroupName(n.toUpperCase()), true, 'Should be reserved (upper): ' + n);
        assert.strictEqual(shared.isReservedGroupName(n.toLowerCase()), true, 'Should be reserved (lower): ' + n);
    });
});

test('does not flag non-reserved group names', function () {
    assert.strictEqual(shared.isReservedGroupName('My Custom Group'), false);
    assert.strictEqual(shared.isReservedGroupName('Pipetting'), false);
    assert.strictEqual(shared.isReservedGroupName('Assay Methods'), false);
});

test('isReservedGroupName returns false for null/undefined/empty', function () {
    assert.strictEqual(shared.isReservedGroupName(null), false);
    assert.strictEqual(shared.isReservedGroupName(undefined), false);
    assert.strictEqual(shared.isReservedGroupName(''), false);
});

test('isReservedGroupName handles whitespace', function () {
    assert.strictEqual(shared.isReservedGroupName('  Starred  '), true);
    assert.strictEqual(shared.isReservedGroupName(' All '), true);
});

// -----------------------------------------------------------------------
console.log('\n=== sanitizeTag ===');
// -----------------------------------------------------------------------

test('lowercases and strips spaces from a tag', function () {
    assert.strictEqual(shared.sanitizeTag('Pipetting'), 'pipetting');
    assert.strictEqual(shared.sanitizeTag('My Tag'), 'mytag');
    assert.strictEqual(shared.sanitizeTag('  2D Array  '), '2darray');
    assert.strictEqual(shared.sanitizeTag('PCR'), 'pcr');
});

test('collapses multiple internal spaces', function () {
    assert.strictEqual(shared.sanitizeTag('multi   word   tag'), 'multiwordtag');
});

test('returns empty string for null/undefined/empty', function () {
    assert.strictEqual(shared.sanitizeTag(null), '');
    assert.strictEqual(shared.sanitizeTag(undefined), '');
    assert.strictEqual(shared.sanitizeTag(''), '');
    assert.strictEqual(shared.sanitizeTag('   '), '');
});

test('returns empty string for non-string input', function () {
    assert.strictEqual(shared.sanitizeTag(123), '');
    assert.strictEqual(shared.sanitizeTag(true), '');
});

test('removes underscore and invalid punctuation', function () {
    assert.strictEqual(shared.sanitizeTag('my_tag'), 'mytag');
    assert.strictEqual(shared.sanitizeTag('my.tag'), 'mytag');
    assert.strictEqual(shared.sanitizeTag('my/tag'), 'mytag');
});

test('normalizes invalid hyphen placement and repeated separators', function () {
    assert.strictEqual(shared.sanitizeTag('-start'), 'start');
    assert.strictEqual(shared.sanitizeTag('end-'), 'end');
    assert.strictEqual(shared.sanitizeTag('double--dash'), 'double-dash');
});

test('rejects numeric-only tags', function () {
    assert.strictEqual(shared.sanitizeTag('1234'), '');
});

test('enforces min/max length', function () {
    assert.strictEqual(shared.sanitizeTag('a'), '');
    assert.strictEqual(shared.sanitizeTag('averyveryveryveryverylongtag'), '');
    assert.strictEqual(shared.sanitizeTag('ab'), 'ab');
});

test('removes colon from tags', function () {
    assert.strictEqual(shared.sanitizeTag('domain:liquid-handling'), 'domainliquid-handling');
    assert.strictEqual(shared.sanitizeTag('domain:1234'), 'domain1234');
    assert.strictEqual(shared.sanitizeTag('domain::value'), 'domainvalue');
});

test('blocks restricted words anywhere inside a tag', function () {
    assert.strictEqual(shared.sanitizeTag('myhamiltontool'), '');
    assert.strictEqual(shared.sanitizeTag('prestarredtag'), '');
    assert.strictEqual(shared.sanitizeTag('core-read-only-lib'), '');
});

test('allows star substrings when not restricted words', function () {
    assert.strictEqual(shared.sanitizeTag('mlstar'), 'mlstar');
    assert.strictEqual(shared.sanitizeTag('starassist'), 'starassist');
});

test('allows ml_star underscore exception only', function () {
    assert.strictEqual(shared.sanitizeTag('ml_star'), 'ml_star');
    assert.strictEqual(shared.sanitizeTag('ML_STAR'), 'ml_star');
    assert.strictEqual(shared.sanitizeTag('ml_star_tool'), 'mlstartool');
});

test('provides feedback for adjusted and blocked tags', function () {
    var feedback = shared.sanitizeTagsWithFeedback(['my_tag', 'myhamiltontool', 'mlstar']);
    assert.deepStrictEqual(feedback.tags, ['mytag', 'mlstar']);
    assert.ok(feedback.adjusted.length >= 1);
    assert.ok(feedback.blocked.length >= 1);
    assert.ok((feedback.blocked[0].restrictedWords || []).length >= 1);
});

// -----------------------------------------------------------------------
console.log('\n=== sanitizeTags ===');
// -----------------------------------------------------------------------

test('sanitizes an array of tags (lowercase, no spaces, deduped)', function () {
    var result = shared.sanitizeTags(['Pipetting', ' 2D Array ', 'PCR', 'pipetting']);
    assert.deepStrictEqual(result, ['pipetting', '2darray', 'pcr']);
});

test('removes empty entries after sanitization', function () {
    var result = shared.sanitizeTags(['  ', '', 'valid']);
    assert.deepStrictEqual(result, ['valid']);
});

test('returns empty array for non-array input', function () {
    assert.deepStrictEqual(shared.sanitizeTags(null), []);
    assert.deepStrictEqual(shared.sanitizeTags(undefined), []);
    assert.deepStrictEqual(shared.sanitizeTags('not-an-array'), []);
});

test('deduplicates case-insensitive duplicates', function () {
    var result = shared.sanitizeTags(['Assay', 'ASSAY', 'assay']);
    assert.deepStrictEqual(result, ['assay']);
});

test('deduplicates canonical near-duplicates', function () {
    var result = shared.sanitizeTags(['arraytable', 'array-table', 'array:table']);
    assert.deepStrictEqual(result, ['arraytable']);
});

test('limits to TAG_MAX_COUNT tags', function () {
    var tags = [];
    for (var i = 0; i < 20; i++) tags.push('tag' + i);
    var result = shared.sanitizeTags(tags);
    assert.strictEqual(result.length, shared.TAG_MAX_COUNT);
});

// -----------------------------------------------------------------------
console.log('\n=== Binary Container (packContainer / unpackContainer) ===');
// -----------------------------------------------------------------------

test('round-trip: pack then unpack recovers original ZIP buffer', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('hello.txt', Buffer.from('Hello, world!', 'utf8'));
    var original = zip.toBuffer();

    var container = shared.packContainer(original, shared.CONTAINER_MAGIC_PKG);
    var recovered = shared.unpackContainer(container, shared.CONTAINER_MAGIC_PKG);
    assert.ok(Buffer.isBuffer(recovered), 'unpackContainer should return a Buffer');
    assert.ok(original.equals(recovered), 'recovered buffer must equal original');
});

test('round-trip with ARC magic', function () {
    var payload = Buffer.from('arbitrary archive payload data', 'utf8');
    var container = shared.packContainer(payload, shared.CONTAINER_MAGIC_ARC);
    var recovered = shared.unpackContainer(container, shared.CONTAINER_MAGIC_ARC);
    assert.ok(payload.equals(recovered));
});

test('container header starts with correct magic bytes', function () {
    var payload = Buffer.alloc(64, 0xAB);
    var container = shared.packContainer(payload, shared.CONTAINER_MAGIC_PKG);
    assert.ok(container.slice(0, 8).equals(shared.CONTAINER_MAGIC_PKG), 'first 8 bytes must be PKG magic');
});

test('container is NOT a valid ZIP (no PK\\x03\\x04 header)', function () {
    var AdmZip = require('adm-zip');
    var zip = new AdmZip();
    zip.addFile('test.txt', Buffer.from('test', 'utf8'));
    var container = shared.packContainer(zip.toBuffer(), shared.CONTAINER_MAGIC_PKG);
    // ZIP files start with PK\x03\x04 (0x50 0x4B 0x03 0x04)
    var hasZipMagic = container[0] === 0x50 && container[1] === 0x4B && container[2] === 0x03 && container[3] === 0x04;
    assert.ok(!hasZipMagic, 'container must NOT start with ZIP magic');
    // Also verify the scrambled payload portion doesn't start with ZIP magic
    var payloadStart = shared.CONTAINER_HEADER_SIZE;
    var hasZipMagicInPayload = container[payloadStart] === 0x50 && container[payloadStart+1] === 0x4B;
    assert.ok(!hasZipMagicInPayload, 'scrambled payload must NOT start with ZIP signature');
});

test('single-byte corruption is detected', function () {
    var payload = Buffer.from('integrity test data', 'utf8');
    var container = shared.packContainer(payload, shared.CONTAINER_MAGIC_PKG);
    // Flip a byte in the payload portion
    var corrupted = Buffer.from(container);
    corrupted[shared.CONTAINER_HEADER_SIZE + 5] ^= 0xFF;
    assert.throws(function () {
        shared.unpackContainer(corrupted, shared.CONTAINER_MAGIC_PKG);
    }, /integrity|corrupt|tamper/i, 'should reject corrupted container');
});

test('wrong magic is rejected', function () {
    var payload = Buffer.from('magic mismatch test', 'utf8');
    var container = shared.packContainer(payload, shared.CONTAINER_MAGIC_PKG);
    assert.throws(function () {
        shared.unpackContainer(container, shared.CONTAINER_MAGIC_ARC);
    }, /unrecognized|invalid|format/i, 'should reject container with wrong magic');
});

test('truncated container is rejected', function () {
    var payload = Buffer.from('truncation test data', 'utf8');
    var container = shared.packContainer(payload, shared.CONTAINER_MAGIC_PKG);
    var truncated = container.slice(0, shared.CONTAINER_HEADER_SIZE + 2);
    assert.throws(function () {
        shared.unpackContainer(truncated, shared.CONTAINER_MAGIC_PKG);
    }, /truncat|corrupt|too small/i, 'should reject truncated container');
});

test('buffer too small (< header size) is rejected', function () {
    assert.throws(function () {
        shared.unpackContainer(Buffer.alloc(10), shared.CONTAINER_MAGIC_PKG);
    }, /too small|invalid/i, 'should reject undersized buffer');
});

test('HMAC corruption in header is detected', function () {
    var payload = Buffer.from('hmac header test', 'utf8');
    var container = shared.packContainer(payload, shared.CONTAINER_MAGIC_PKG);
    var corrupted = Buffer.from(container);
    // Flip a byte in the HMAC (bytes 16-47)
    corrupted[20] ^= 0xFF;
    assert.throws(function () {
        shared.unpackContainer(corrupted, shared.CONTAINER_MAGIC_PKG);
    }, /integrity|corrupt|tamper/i, 'should reject HMAC-corrupted container');
});

// -----------------------------------------------------------------------
console.log('\n=== validateGitHubRepoUrl ===');
// -----------------------------------------------------------------------

// --- accept valid URLs ---

test('accepts basic https://github.com/owner/repo', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world');
    assert.strictEqual(r.valid, true);
});

test('accepts http scheme', function () {
    var r = shared.validateGitHubRepoUrl('http://github.com/octocat/hello-world');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with trailing slash', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world/');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with .git suffix', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world.git');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with .git and trailing slash', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world.git/');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with repo-scoped route (issues)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world/issues');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with repo-scoped route (tree)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world/tree/main');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with repo-scoped route (blob)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world/blob/main/README.md');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with repo-scoped route (pull)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world/pull/42');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with repo-scoped route (releases)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat/hello-world/releases');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with non-github hostname', function () {
    var r = shared.validateGitHubRepoUrl('https://gitlab.com/owner/repo');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with query string', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/repo?tab=readme');
    assert.strictEqual(r.valid, true);
});

test('accepts URL with fragment', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/repo#readme');
    assert.strictEqual(r.valid, true);
});

test('accepts owner with hyphens and digits', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/my-org-123/my-repo');
    assert.strictEqual(r.valid, true);
});

// --- reject empty / non-URL ---

test('rejects empty string', function () {
    var r = shared.validateGitHubRepoUrl('');
    assert.strictEqual(r.valid, false);
});

test('rejects null', function () {
    var r = shared.validateGitHubRepoUrl(null);
    assert.strictEqual(r.valid, false);
});

test('rejects undefined', function () {
    var r = shared.validateGitHubRepoUrl(undefined);
    assert.strictEqual(r.valid, false);
});

test('rejects non-URL string', function () {
    var r = shared.validateGitHubRepoUrl('not a url');
    assert.strictEqual(r.valid, false);
});

// --- reject wrong scheme ---

test('rejects ftp scheme', function () {
    var r = shared.validateGitHubRepoUrl('ftp://github.com/owner/repo');
    assert.strictEqual(r.valid, false);
    assert.ok(/scheme/i.test(r.reason));
});

test('rejects ssh scheme', function () {
    var r = shared.validateGitHubRepoUrl('ssh://git@github.com/owner/repo');
    assert.strictEqual(r.valid, false);
});

// --- reject missing segments ---

test('rejects domain only (no path segments)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com');
    assert.strictEqual(r.valid, false);
});

test('rejects single path segment (owner only)', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/octocat');
    assert.strictEqual(r.valid, false);
    assert.ok(/owner.*repo/i.test(r.reason));
});

// --- reject reserved top-level routes as owner ---

test('rejects /settings as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/settings/something');
    assert.strictEqual(r.valid, false);
    assert.ok(/reserved/i.test(r.reason));
});

test('rejects /Settings (case-insensitive) as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/Settings/something');
    assert.strictEqual(r.valid, false);
});

test('rejects /organizations as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/organizations/myorg');
    assert.strictEqual(r.valid, false);
});

test('rejects /login as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/login/oauth');
    assert.strictEqual(r.valid, false);
});

test('rejects /explore as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/explore/topics');
    assert.strictEqual(r.valid, false);
});

test('rejects /marketplace as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/marketplace/actions');
    assert.strictEqual(r.valid, false);
});

test('rejects /pricing as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/pricing/team');
    assert.strictEqual(r.valid, false);
});

test('rejects /copilot as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/copilot/plans');
    assert.strictEqual(r.valid, false);
});

test('rejects /gist as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/gist/something');
    assert.strictEqual(r.valid, false);
});

test('rejects /actions as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/actions/checkout');
    assert.strictEqual(r.valid, false);
});

test('rejects /new as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/new/import');
    assert.strictEqual(r.valid, false);
});

test('rejects /enterprise as owner', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/enterprise/contact');
    assert.strictEqual(r.valid, false);
});

// --- reject reserved repo name (second segment) ---

test('rejects reserved word as repo name', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/validowner/settings');
    assert.strictEqual(r.valid, false);
    assert.ok(/reserved/i.test(r.reason));
});

test('rejects "login" as repo name', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/login');
    assert.strictEqual(r.valid, false);
});

test('rejects "marketplace" as repo name', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/marketplace');
    assert.strictEqual(r.valid, false);
});

// --- reject non-repo prefix patterns ---

test('rejects /settings/ prefix path', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/settings/profile/edit');
    assert.strictEqual(r.valid, false);
});

test('rejects /users/ prefix path', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/users/someone/repos');
    assert.strictEqual(r.valid, false);
});

test('rejects /orgs/ prefix path', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/orgs/myorg/repos');
    assert.strictEqual(r.valid, false);
});

// --- reject third-segment non-repo context ---

test('rejects third segment /organizations after owner/repo', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/repo/organizations');
    assert.strictEqual(r.valid, false);
});

test('rejects third segment /search after owner/repo', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/repo/search');
    assert.strictEqual(r.valid, false);
});

// --- reject owner dot rules ---

test('rejects owner starting with dot', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/.hidden/repo');
    assert.strictEqual(r.valid, false);
    assert.ok(/dot/i.test(r.reason));
});

test('rejects owner ending with dot', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner./repo');
    assert.strictEqual(r.valid, false);
});

test('rejects owner with consecutive dots', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/ow..ner/repo');
    assert.strictEqual(r.valid, false);
    assert.ok(/consecutive/i.test(r.reason));
});

// --- reject @ in segments ---

test('rejects @ in owner segment', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/user@host/repo');
    assert.strictEqual(r.valid, false);
    assert.ok(/@/.test(r.reason));
});

test('rejects @ in repo segment', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/re@po');
    assert.strictEqual(r.valid, false);
});

// --- reject spaces / control characters ---

test('rejects space in owner segment', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/my%20owner/repo');
    assert.strictEqual(r.valid, false);
});

test('rejects control char in repo segment', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/re%00po');
    assert.strictEqual(r.valid, false);
});

// --- reject empty repo after .git stripping ---

test('rejects repo that is only .git', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/.git');
    assert.strictEqual(r.valid, false);
    assert.ok(/empty/i.test(r.reason));
});

// --- reject query-only with no real path ---

test('rejects query-only URL without path segments', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/?q=test');
    assert.strictEqual(r.valid, false);
});

// --- reject exact /settings or /organizations path ---

test('rejects exact /settings path', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/settings');
    assert.strictEqual(r.valid, false);
});

test('rejects /settings/ with segments', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/settings/profile');
    assert.strictEqual(r.valid, false);
});

test('rejects exact /organizations path', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/organizations');
    assert.strictEqual(r.valid, false);
});

test('rejects /organizations/ with segments', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/organizations/myorg/settings');
    assert.strictEqual(r.valid, false);
});

test('rejects /users with segments', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/users/someone');
    assert.strictEqual(r.valid, false);
});

test('rejects /search path', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/search/advanced');
    assert.strictEqual(r.valid, false);
});

// --- accept deep-linked repo URLs with unknown third segment ---

test('accepts unknown third segment under owner/repo', function () {
    var r = shared.validateGitHubRepoUrl('https://github.com/owner/repo/some-random-path');
    assert.strictEqual(r.valid, true);
});

// -----------------------------------------------------------------------
// Summary
// -----------------------------------------------------------------------
console.log('\n' + (passed + failed) + ' tests: ' + passed + ' passed, ' + failed + ' failed\n');
process.exit(failed > 0 ? 1 : 0);
