/**
 * syscheck-worker.js
 * 
 * Runs system library integrity checks in a separate child process
 * to keep the main UI thread (and splash animation) completely smooth.
 *
 * Receives via IPC message:
 *   { type: 'run', payload: { sysLibDir, systemLibraries, baseline, packageStoreDir, settingsFlags } }
 *
 * Sends back via IPC message:
 *   { type: 'result', payload: { integrityResults, missingPackages, metadataNeeded, backupsNeeded, error } }
 */

'use strict';

var fs = require('fs');
var path = require('path');

/**
 * Parse Hamilton's $$valid$$/$$checksum$$ metadata footer from an HSL file.
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
					length:   parseInt(m[5], 10)
				};
			}
			break;
		}
		return null;
	} catch(e) {
		return null;
	}
}

/**
 * Verify integrity of a single system library against its baseline.
 */
function verifySystemLibraryIntegrity(sLib, baseline, sysLibDir) {
	var result = { valid: true, errors: [], warnings: [] };
	var libName = sLib.canonical_name || sLib.library_name;
	var baselineEntry = baseline[libName];

	if (!baselineEntry || !baselineEntry.files || Object.keys(baselineEntry.files).length === 0) {
		var HSL_BASELINE_EXTS = ['.hsl', '.hs_', '.smt'];
		var discoveredFiles = sLib.discovered_files || [];
		var hasBaselinableFiles = discoveredFiles.some(function(f) {
			var ext = path.extname(f).toLowerCase();
			return HSL_BASELINE_EXTS.indexOf(ext) !== -1;
		});
		if (hasBaselinableFiles) {
			result.warnings.push('No integrity baseline stored for system library: ' + libName);
		}
		return result;
	}

	var storedFiles = baselineEntry.files;
	var fileNames = Object.keys(storedFiles);

	fileNames.forEach(function(fname) {
		var fullPath = path.join(sysLibDir, fname);

		if (!fs.existsSync(fullPath)) {
			result.valid = false;
			result.errors.push('File missing: ' + fname);
			return;
		}

		var stored = storedFiles[fname];
		var footer = parseHslMetadataFooter(fullPath);

		if (!footer) {
			if (stored.valid === 1) {
				result.valid = false;
				result.errors.push('Metadata footer removed: ' + fname);
			} else {
				result.warnings.push('No metadata footer found: ' + fname);
			}
			return;
		}
		if (stored.valid === 1 && footer.valid !== 1) {
			result.valid = false;
			result.errors.push('Valid flag changed (1→0): ' + fname);
			return;
		}
		if (stored.checksum && footer.checksum !== stored.checksum) {
			result.valid = false;
			result.errors.push('Checksum changed: ' + fname);
		}
	});

	return result;
}

/**
 * Generate integrity baseline from current files on disk.
 * Returns the baseline data object (libraries map).
 */
function generateBaseline(systemLibraries, sysLibDir) {
	var HSL_EXTS = ['.hsl', '.hs_', '.smt'];
	var baselineData = {};

	systemLibraries.forEach(function(lib) {
		var libName = lib.canonical_name || lib.library_name;
		var files = lib.discovered_files || [];
		var libFiles = {};

		files.forEach(function(relPath) {
			var fname = relPath.replace(/^Library[\\\/]/i, '');
			var ext = path.extname(fname).toLowerCase();
			if (HSL_EXTS.indexOf(ext) === -1) return;

			var fullPath = path.join(sysLibDir, fname);
			if (!fs.existsSync(fullPath)) return;

			var footer = parseHslMetadataFooter(fullPath);
			if (footer) {
				libFiles[fname] = {
					valid:    footer.valid,
					checksum: footer.checksum,
					author:   footer.author,
					time:     footer.time,
					length:   footer.length
				};
			}
		});

		if (Object.keys(libFiles).length > 0) {
			baselineData[libName] = {
				_id:   lib._id,
				files: libFiles
			};
		}
	});

	return baselineData;
}

/**
 * Check which libraries are missing backup packages.
 */
function findMissingBackups(systemLibraries, packageStoreDir) {
	var missing = [];
	systemLibraries.forEach(function(sLib) {
		var libName = sLib.canonical_name || sLib.library_name;
		var safeName = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
		var libDir = path.join(packageStoreDir, safeName);

		var hasPackage = false;
		if (fs.existsSync(libDir)) {
			try {
				var files = fs.readdirSync(libDir).filter(function(f) {
					return f.toLowerCase().endsWith('.hxlibpkg');
				});
				hasPackage = files.length > 0;
			} catch(e) {}
		}

		if (!hasPackage) {
			missing.push(libName);
		}
	});
	return missing;
}

// ---- IPC message handler ----
process.on('message', function(msg) {
	if (msg.type !== 'run') return;

	var payload = msg.payload;
	var sysLibDir = payload.sysLibDir;
	var systemLibraries = payload.systemLibraries;
	var baseline = payload.baseline;
	var packageStoreDir = payload.packageStoreDir;
	var settingsFlags = payload.settingsFlags || {};

	var result = {
		integrityResults: {},    // { libName: { valid, errors[], warnings[] } }
		missingPackages: [],     // library names that need backup packages created
		baselineGenerated: null, // new baseline data if we had to generate it
		metadataNeeded: !settingsFlags.sysLibMetadataComplete,
		backupsNeeded: !settingsFlags.sysLibBackupComplete,
		error: null
	};

	try {
		// Step 1: Generate baseline if empty
		if (!baseline || Object.keys(baseline).length === 0) {
			baseline = generateBaseline(systemLibraries, sysLibDir);
			result.baselineGenerated = baseline;
		}

		// Step 2: Check for missing packages
		result.missingPackages = findMissingBackups(systemLibraries, packageStoreDir);

		// Step 3: Verify integrity of each library
		systemLibraries.forEach(function(sLib) {
			var libName = sLib.canonical_name || sLib.library_name;
			var intResult = verifySystemLibraryIntegrity(sLib, baseline, sysLibDir);
			// Only include in results if there's something to report
			if (!intResult.valid || intResult.errors.length > 0 || intResult.warnings.length > 0) {
				result.integrityResults[libName] = intResult;
			}
		});

	} catch(e) {
		result.error = e.message;
	}

	process.send({ type: 'result', payload: result });
	process.exit(0);
});
