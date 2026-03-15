#!/usr/bin/env node
/**
 * create-test-packages.js
 *
 * Generates dummy .hxlibpkg test packages with a dependency chain:
 *   TestLibA  → depends on [TestLibB]
 *   TestLibB  → depends on [TestLibC]
 *   TestLibC  → no dependencies (leaf)
 *
 * Also writes a catalog.json that the store can consume.
 *
 * Usage:
 *   node tools/create-test-packages.js [output-dir]
 *
 * Default output-dir: ./tools/test-store/
 */

'use strict';

var path    = require('path');
var fs      = require('fs');
var crypto  = require('crypto');
var AdmZip  = require(path.join(__dirname, '..', 'node_modules', 'adm-zip'));

// ---- constants (mirrored from lib/shared.js) ----

var PKG_SIGNING_KEY = 'VenusLibMgr::PackageIntegrity::a7e3f9d1c6b2';
var CONTAINER_MAGIC_PKG = Buffer.from([0x48, 0x58, 0x4C, 0x50, 0x4B, 0x47, 0x01, 0x00]);
var CONTAINER_SCRAMBLE_KEY = Buffer.from([
    0x7A, 0x3F, 0xC1, 0xD8, 0x4E, 0x92, 0xB5, 0x16,
    0xA3, 0x0D, 0xE7, 0x68, 0xF4, 0x2C, 0x59, 0x8B,
    0x31, 0xCA, 0x75, 0x0E, 0x96, 0xAF, 0xD2, 0x43,
    0xBC, 0x1A, 0x67, 0xE0, 0x58, 0x84, 0x3B, 0xF9
]);
var CONTAINER_HEADER_SIZE = 48;

// ---- pack helper ----

function packContainer(zipBuffer) {
    var scrambled = Buffer.alloc(zipBuffer.length);
    for (var i = 0; i < zipBuffer.length; i++) {
        scrambled[i] = zipBuffer[i] ^ CONTAINER_SCRAMBLE_KEY[i % CONTAINER_SCRAMBLE_KEY.length];
    }
    var hmac = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(scrambled).digest();
    var header = Buffer.alloc(CONTAINER_HEADER_SIZE);
    CONTAINER_MAGIC_PKG.copy(header, 0);
    header.writeUInt32LE(0, 8);
    header.writeUInt32LE(scrambled.length, 12);
    hmac.copy(header, 16);
    return Buffer.concat([header, scrambled]);
}

// ---- define test packages ----

var now = new Date().toISOString();

var packages = [
    {
        library_name: 'TestLibC',
        author: 'Test Author',
        organization: 'Test Org',
        version: '1.0.0',
        venus_compatibility: '4.7+',
        description: 'Test leaf library with no dependencies.',
        tags: ['test', 'leaf'],
        dependencies: [],
        library_files: ['TestLibC.hsl']
    },
    {
        library_name: 'TestLibB',
        author: 'Test Author',
        organization: 'Test Org',
        version: '1.0.0',
        venus_compatibility: '4.7+',
        description: 'Test library that depends on TestLibC.',
        tags: ['test', 'mid-level'],
        dependencies: ['TestLibC'],
        library_files: ['TestLibB.hsl']
    },
    {
        library_name: 'TestLibA',
        author: 'Test Author',
        organization: 'Test Org',
        version: '1.0.0',
        venus_compatibility: '4.7+',
        description: 'Test top-level library that depends on TestLibB.',
        tags: ['test', 'top-level'],
        dependencies: ['TestLibB'],
        library_files: ['TestLibA.hsl']
    }
];

// ---- build each package ----

var outDir = process.argv[2] || path.join(__dirname, 'test-store');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

var catalogEntries = [];

packages.forEach(function (pkg) {
    // stub HSL file
    var hslContent = '// ' + pkg.library_name + ' - test stub\n';
    if (pkg.dependencies.length > 0) {
        pkg.dependencies.forEach(function (dep) {
            hslContent += '#include "' + dep + '.hsl"\n';
        });
    }
    hslContent += 'namespace ' + pkg.library_name + ' { }\n';

    // manifest
    var manifest = {
        format_version: '2.0',
        library_name: pkg.library_name,
        author: pkg.author,
        organization: pkg.organization,
        version: pkg.version,
        venus_compatibility: pkg.venus_compatibility,
        description: pkg.description,
        tags: pkg.tags,
        dependencies: pkg.dependencies,
        created_date: now,
        library_files: pkg.library_files,
        demo_method_files: [],
        help_files: [],
        com_register_dlls: [],
        labware_files: [],
        app_version: '1.9.14',
        windows_version: 'Windows_NT 10.0.19045 (x64)',
        venus_version: '6.1',
        package_lineage: [{
            event: 'created',
            timestamp: now,
            app_version: '1.9.14',
            format_version: '2.0',
            username: 'test',
            hostname: 'TEST',
            windows_version: 'Windows_NT 10.0.19045 (x64)',
            venus_version: '6.1'
        }]
    };

    var manifestStr = JSON.stringify(manifest, null, 2);
    var hslBuffer   = Buffer.from(hslContent, 'utf8');
    var manBuffer   = Buffer.from(manifestStr, 'utf8');

    // file hashes for signature
    var fileHashes = {};
    fileHashes['manifest.json'] = crypto.createHash('sha256').update(manBuffer).digest('hex');
    fileHashes['library/' + pkg.library_files[0]] = crypto.createHash('sha256').update(hslBuffer).digest('hex');

    var hashesStr = JSON.stringify(fileHashes);
    var sigHmac   = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(hashesStr).digest('hex');

    var signature = {
        signature_format_version: '2.0',
        algorithm: 'HMAC-SHA256',
        signed_date: now,
        file_hashes: fileHashes,
        hmac: sigHmac
    };

    // build ZIP
    var zip = new AdmZip();
    zip.addFile('manifest.json', manBuffer);
    zip.addFile('library/' + pkg.library_files[0], hslBuffer);
    zip.addFile('signature.json', Buffer.from(JSON.stringify(signature, null, 2), 'utf8'));
    zip.addZipComment(pkg.library_name + ' | v' + pkg.version + ' | ' + pkg.author + ' | ' + pkg.organization + ' | ' + pkg.description);

    var zipBuffer = zip.toBuffer();

    // wrap in binary container
    var containerBuffer = packContainer(zipBuffer);

    var pkgFileName = pkg.library_name + '_v' + pkg.version + '.hxlibpkg';
    var pkgPath = path.join(outDir, pkgFileName);
    fs.writeFileSync(pkgPath, containerBuffer);
    console.log('Created: ' + pkgPath + ' (' + containerBuffer.length + ' bytes)');

    // catalog entry
    catalogEntries.push({
        package_file: pkgFileName,
        library_name: pkg.library_name,
        author: pkg.author,
        organization: pkg.organization,
        version: pkg.version,
        description: pkg.description,
        tags: pkg.tags,
        dependencies: pkg.dependencies,
        venus_compatibility: pkg.venus_compatibility,
        created_date: now,
        format_version: '2.0',
        signed: false,
        code_signed: false,
        package_size: containerBuffer.length,
        package_sha256: crypto.createHash('sha256').update(containerBuffer).digest('hex')
    });
});

// sort by name
catalogEntries.sort(function (a, b) { return a.library_name.localeCompare(b.library_name); });

var catalogPath = path.join(outDir, 'catalog.json');
fs.writeFileSync(catalogPath, JSON.stringify(catalogEntries, null, 2));
console.log('Wrote catalog: ' + catalogPath);
console.log('Done. ' + catalogEntries.length + ' test packages created.');
