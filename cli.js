#!/usr/bin/env node
/**
 * Library Manager CLI  v1.0
 * Command-line interface for managing Hamilton VENUS libraries.
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
 *
 * Run `node cli.js help` for full usage.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MIME_MAP = {
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.bmp':  'image/bmp',
    '.gif':  'image/gif',
    '.ico':  'image/x-icon',
    '.svg':  'image/svg+xml'
};

const HASH_EXTENSIONS = ['.hsl', '.hs_', '.sub'];

const DEFAULT_LIB_PATH  = 'C:\\Program Files (x86)\\HAMILTON\\Library';
const DEFAULT_MET_PATH  = 'C:\\Program Files (x86)\\HAMILTON\\Methods';

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
// Database helpers
// ---------------------------------------------------------------------------

/**
 * Connect diskdb to the given directory.
 * Returns a db object with collections: installed_libs, links, groups, settings, tree.
 */
function connectDB(dbDir) {
    const diskdb = require('diskdb');
    return diskdb.connect(dbDir, ['installed_libs', 'links', 'groups', 'settings', 'tree']);
}

/**
 * Resolve the db directory from CLI args.
 * Falls back to <appRoot>/db where appRoot = location of this script.
 */
function resolveDBPath(args) {
    if (args['db-path']) return path.resolve(args['db-path']);
    return path.join(__dirname, 'db');
}

/**
 * Get library/methods root install paths from DB settings (or overrides).
 */
function getInstallPaths(db, libDirOverride, metDirOverride) {
    let libBasePath = DEFAULT_LIB_PATH;
    let metBasePath = DEFAULT_MET_PATH;

    if (libDirOverride) {
        libBasePath = libDirOverride;
    } else {
        try {
            const rec = db.links.findOne({ _id: 'lib-folder' });
            if (rec && rec.path) libBasePath = rec.path;
        } catch (_) {}
    }

    if (metDirOverride) {
        metBasePath = metDirOverride;
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

function hashFile(filePath) {
    try {
        const data = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(data).digest('hex');
    } catch (_) {
        return null;
    }
}

function computeLibraryHashes(libraryFiles, libBasePath, comDlls) {
    const hashes = {};
    libraryFiles.forEach(function (fname) {
        const ext      = path.extname(fname).toLowerCase();
        const isDll    = comDlls.indexOf(fname) !== -1;
        const tracked  = HASH_EXTENSIONS.indexOf(ext) !== -1 || isDll;
        if (tracked) {
            const h = hashFile(path.join(libBasePath, fname));
            if (h) hashes[fname] = h;
        }
    });
    return hashes;
}

// ---------------------------------------------------------------------------
// Group auto-assignment
// ---------------------------------------------------------------------------

function autoAddToGroup(db, savedLibId) {
    try {
        const navtree = db.tree.find();
        let targetGroupId = null;

        for (let i = 0; i < navtree.length; i++) {
            const gEntry = db.groups.findOne({ _id: navtree[i]['group-id'] });
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

    // Ensure destination directories exist
    if (libFiles.length > 0 && !fs.existsSync(libDestDir)) {
        fs.mkdirSync(libDestDir, { recursive: true });
    }
    if (demoFiles.length > 0 && !fs.existsSync(demoDestDir)) {
        fs.mkdirSync(demoDestDir, { recursive: true });
    }

    // Extract payload files
    let extractedCount = 0;
    zip.getEntries().forEach(function (entry) {
        if (entry.isDirectory || entry.entryName === 'manifest.json') return;

        if (entry.entryName.startsWith('library/')) {
            const fname = entry.entryName.substring('library/'.length);
            if (fname) {
                fs.writeFileSync(path.join(libDestDir, fname), entry.getData());
                extractedCount++;
            }
        } else if (entry.entryName.startsWith('demo_methods/')) {
            const fname = entry.entryName.substring('demo_methods/'.length);
            if (fname) {
                fs.writeFileSync(path.join(demoDestDir, fname), entry.getData());
                extractedCount++;
            }
        }
        // icon/ entries are not extracted to disk — they remain embedded in manifest base64
    });

    // Upsert DB record — remove old entry if it exists
    const existing = db.installed_libs.findOne({ library_name: manifest.library_name });
    if (existing) {
        db.installed_libs.remove({ _id: existing._id });
    }

    const fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls);

    const dbRecord = {
        library_name:        manifest.library_name        || '',
        author:              manifest.author               || '',
        organization:        manifest.organization         || '',
        version:             manifest.version              || '',
        venus_compatibility: manifest.venus_compatibility  || '',
        description:         manifest.description          || '',
        tags:                manifest.tags                 || [],
        created_date:        manifest.created_date         || '',
        library_image:       manifest.library_image        || null,
        library_image_base64:manifest.library_image_base64 || null,
        library_image_mime:  manifest.library_image_mime   || null,
        library_files:       libFiles,
        demo_method_files:   demoFiles,
        com_register_dlls:   comDlls,
        com_warning:         false,
        lib_install_path:    libDestDir,
        demo_install_path:   demoDestDir,
        installed_date:      new Date().toISOString(),
        source_package:      sourceName,
        file_hashes:         fileHashes
    };

    const saved = db.installed_libs.save(dbRecord);

    if (!skipGroup) {
        autoAddToGroup(db, saved._id);
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
        console.log(`  Version:     ${lib.version      || '—'}`);
        console.log(`  Author:      ${lib.author        || '—'}`);
        console.log(`  Tags:        ${(lib.tags || []).join(', ') || '—'}`);
        console.log(`  Lib path:    ${lib.lib_install_path  || '—'}`);
        console.log(`  Demo path:   ${lib.demo_install_path || '—'}`);
        console.log(`  Installed:   ${lib.installed_date    || '—'}`);
        if ((lib.com_register_dlls || []).length > 0)
            console.log(`  COM DLLs:    ${lib.com_register_dlls.join(', ')}`);
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
        zip = new AdmZip(fs.readFileSync(filePath));
        const me = zip.getEntry('manifest.json');
        if (!me) die('Invalid package: manifest.json not found');
        manifest = JSON.parse(zip.readAsText(me));
    } catch (e) {
        die('Failed to read package: ' + e.message);
    }

    const libName = manifest.library_name || 'Unknown';

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

    const comDlls = manifest.com_register_dlls || [];
    if (comDlls.length > 0) {
        console.log(`\n  NOTE: COM registration required for: ${comDlls.join(', ')}`);
        console.log(`  Use the GUI import or run RegAsm.exe /codebase manually.`);
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
        archiveZip = new AdmZip(filePath);
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
            const innerZip = new AdmZip(pkgEntry.getData());
            const me       = innerZip.getEntry('manifest.json');
            if (!me) throw new Error('manifest.json missing');

            const manifest = JSON.parse(innerZip.readAsText(me));
            const libName  = manifest.library_name || 'Unknown';

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
            console.log(`  + ${libName} — ${result.extractedCount} files extracted`);
        } catch (e) {
            results.failed.push(`${label}: ${e.message}`);
            process.stderr.write(`  ! ${label}: ${e.message}\n`);
        }
    });

    console.log('\nArchive Import Summary:');
    console.log(`  Succeeded : ${results.success.length}`);
    console.log(`  Failed    : ${results.failed.length}`);
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
    if (lib.deleted) die(`Library "${lib.library_name}" is deleted and cannot be exported.`);

    const libraryFiles = lib.library_files     || [];
    const demoFiles    = lib.demo_method_files  || [];
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
        tags:                lib.tags                 || [],
        created_date:        new Date().toISOString(),
        library_image:       lib.library_image        || null,
        library_image_base64:lib.library_image_base64 || null,
        library_image_mime:  lib.library_image_mime   || null,
        library_files:       libraryFiles.slice(),
        demo_method_files:   demoFiles.slice(),
        com_register_dlls:   (lib.com_register_dlls   || []).slice()
    };

    const zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));

    libraryFiles.forEach(f => {
        const fp = path.join(libBasePath, f);
        if (fs.existsSync(fp)) zip.addLocalFile(fp, 'library');
    });

    demoFiles.forEach(f => {
        const fp = path.join(demoBasePath, f);
        if (fs.existsSync(fp)) zip.addLocalFile(fp, 'demo_methods');
    });

    ensureOutDir(args['output']);
    zip.writeZip(args['output']);

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
        targetLibs = (db.installed_libs.find() || []).filter(l => !l.deleted);
    } else if (args['names']) {
        args['names'].split(',').map(n => n.trim()).forEach(n => {
            const found = db.installed_libs.findOne({ library_name: n });
            if (found && !found.deleted) {
                targetLibs.push(found);
            } else {
                process.stderr.write(`Warning: library "${n}" not found or is deleted — skipping\n`);
            }
        });
    } else if (args['ids']) {
        args['ids'].split(',').map(i => i.trim()).forEach(id => {
            const found = db.installed_libs.findOne({ _id: id });
            if (found && !found.deleted) {
                targetLibs.push(found);
            } else {
                process.stderr.write(`Warning: library ID "${id}" not found or is deleted — skipping\n`);
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
            const comDlls      = lib.com_register_dlls  || [];

            const manifest = {
                format_version:      '1.0',
                library_name:        lib.library_name        || '',
                author:              lib.author               || '',
                organization:        lib.organization         || '',
                version:             lib.version              || '',
                venus_compatibility: lib.venus_compatibility  || '',
                description:         lib.description          || '',
                tags:                lib.tags                 || [],
                created_date:        new Date().toISOString(),
                library_image:       lib.library_image        || null,
                library_image_base64:lib.library_image_base64 || null,
                library_image_mime:  lib.library_image_mime   || null,
                library_files:       libraryFiles.slice(),
                demo_method_files:   demoFiles.slice(),
                com_register_dlls:   comDlls.slice()
            };

            const innerZip = new AdmZip();
            innerZip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));

            let libAdded = 0, demoAdded = 0;
            libraryFiles.forEach(f => {
                const fp = path.join(libBasePath, f);
                if (fs.existsSync(fp)) { innerZip.addLocalFile(fp, 'library');      libAdded++;  }
            });
            demoFiles.forEach(f => {
                const fp = path.join(demoBasePath, f);
                if (fs.existsSync(fp)) { innerZip.addLocalFile(fp, 'demo_methods'); demoAdded++; }
            });

            archiveZip.addFile(lib.library_name + '.hxlibpkg', innerZip.toBuffer());
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
    archiveZip.writeZip(args['output']);

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

    const displayName = lib.library_name || args.name || args.id;
    console.log(`Deleting: ${displayName}`);

    // ---- Delete files from disk (unless --keep-files) ----
    if (!args['keep-files']) {
        const libFiles = lib.library_files   || [];
        const libPath  = lib.lib_install_path || '';

        if (libPath && libFiles.length > 0) {
            libFiles.forEach(f => {
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
                break;
            }
        }
    } catch (_) {}

    console.log(`\nSuccess: "${displayName}" deleted.`);

    const comDlls = lib.com_register_dlls || [];
    if (comDlls.length > 0) {
        console.log(`\n  NOTE: COM DLLs were NOT automatically deregistered: ${comDlls.join(', ')}`);
        console.log(`  Run  RegAsm.exe /unregister <dll>  with elevated privileges if needed.`);
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
    if (!spec.library_files || spec.library_files.length === 0)
                                                   validationErrors.push('"library_files" must contain at least one entry');
    if (validationErrors.length > 0) {
        die('Spec validation failed:\n  ' + validationErrors.join('\n  '));
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

    const manifest = {
        format_version:      '1.0',
        library_name:        libName,
        author:              spec.author              || '',
        organization:        spec.organization         || '',
        version:             spec.version,
        venus_compatibility: spec.venus_compatibility  || '',
        description:         spec.description          || '',
        tags:                spec.tags                 || [],
        created_date:        new Date().toISOString(),
        library_image:       libraryImageFilename,
        library_image_base64:libraryImageBase64,
        library_image_mime:  libraryImageMime,
        library_files:       resolvedLibFiles.map(f  => path.basename(f)),
        demo_method_files:   resolvedDemoFiles.map(f => path.basename(f)),
        com_register_dlls:   comDlls
    };

    const zip = new AdmZip();
    zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));
    resolvedLibFiles.forEach(f  => zip.addLocalFile(f, 'library'));
    resolvedDemoFiles.forEach(f => zip.addLocalFile(f, 'demo_methods'));
    if (iconSourcePath) zip.addLocalFile(iconSourcePath, 'icon');

    ensureOutDir(args['output']);
    zip.writeZip(args['output']);

    console.log(`\nSuccess: ${args['output']}`);
    console.log(`  Library name      : ${libName}`);
    console.log(`  Author            : ${spec.author}`);
    console.log(`  Version           : ${spec.version}`);
    console.log(`  Library files     : ${resolvedLibFiles.length}`);
    console.log(`  Demo method files : ${resolvedDemoFiles.length}`);
    if (comDlls.length > 0) console.log(`  COM DLLs          : ${comDlls.join(', ')}`);
    if (libraryImageFilename) console.log(`  Icon              : ${libraryImageFilename}`);
}

// ===========================================================================
// Help
// ===========================================================================
function printHelp() {
    console.log(`
Library Manager CLI  v1.0
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
  help               Show this help text

GLOBAL OPTIONS
  --db-path <dir>    Path to the db/ directory  (default: <app-root>/db)

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

  --file   <path>    [required]  Path to the .hxlibpkg file
  --lib-dir <path>              Override library install root
  --met-dir <path>              Override methods (demo) install root
  --force                       Overwrite without error if already installed
  --no-group                    Skip auto-assigning to a library group

  Examples:
    node cli.js import-lib --file MyLib.hxlibpkg
    node cli.js import-lib --file MyLib.hxlibpkg --force
    node cli.js import-lib --file MyLib.hxlibpkg --lib-dir D:\\Hamilton\\Library

──────────────────────────────────────────────────────────────────────────────
import-archive
  Import all libraries contained in a .hxlibarch archive.

  --file   <path>    [required]  Path to the .hxlibarch file
  --lib-dir <path>              Override library install root
  --met-dir <path>              Override methods (demo) install root
  --force                       Overwrite without error if already installed
  --no-group                    Skip auto-assigning to library groups

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

  NOTE: COM DLL deregistration must be done manually via RegAsm.exe.

  Examples:
    node cli.js delete-lib --name "MyLibrary" --yes
    node cli.js delete-lib --name "MyLibrary" --yes --hard
    node cli.js delete-lib --id abc123 --yes --keep-files

──────────────────────────────────────────────────────────────────────────────
create-package
  Build a .hxlibpkg from raw library files using a JSON spec.

  --spec   <path>    [required]  Path to JSON spec file (see cli-schema.json)
  --output <path>    [required]  Output .hxlibpkg file path

  The spec file describes all metadata and which files to bundle.
  See cli-schema.json for the full JSON Schema definition.
  See cli-spec-example.json for a worked example.

  Examples:
    node cli.js create-package --spec MyLib.spec.json --output MyLib.hxlibpkg
    node cli.js create-package --spec specs/proj.json --output dist/proj.hxlibpkg

──────────────────────────────────────────────────────────────────────────────
`);
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
