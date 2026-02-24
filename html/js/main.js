
		// main.js v1.0 

		var gui = require('nw.gui');
		var win = gui.Window.get();
		var path = require('path');
		var spawn = require('child_process').spawn; 

		/// Default VENUS executables. 
        var HxRun = "HxRun.exe";
		var HxMethodEditor = "HxMetEd.exe";
		var HxLiquidEditor = "HxCoreLiquidEditor.exe";
		var HxLabwareEditor = "HxLabwrEd.exe";
		var HxHSLEditor = "HxHSLMetEd.exe";
		var HxConfigEditor = "Hamilton.HxConfigEditor.exe";
		var HxVersion = "HxVersion.exe";

		//Default VENUS folders.
		var HxFolder_LogFiles = "C:\\Program Files (x86)\\HAMILTON\\LogFiles";
		var HxFolder_Methods = "C:\\Program Files (x86)\\HAMILTON\\Methods";
		var HxFolder_Bin = "C:\\Program Files (x86)\\HAMILTON\\Bin";

		const fs = require('fs');
		const sizeOf = require('image-size');
		const os = require("os");
		const crypto = require('crypto');

		/** Shared MIME type lookup for image file extensions */
		var IMAGE_MIME_MAP = {
			'png':'image/png', 'jpg':'image/jpeg', 'jpeg':'image/jpeg',
			'bmp':'image/bmp', 'gif':'image/gif', 'ico':'image/x-icon', 'svg':'image/svg+xml',
			// keyed with leading dot for convenience (used by some callers)
			'.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
			'.bmp':'image/bmp', '.gif':'image/gif', '.ico':'image/x-icon', '.svg':'image/svg+xml'
		};

		/**
		 * Sanitize a ZIP entry filename to prevent path traversal.
		 * Returns null if the resolved path escapes the target directory.
		 */
		function safeZipExtractPath(baseDir, fname) {
			// Reject entries with '..' path components
			var normalized = fname.replace(/\\/g, '/');
			if (normalized.indexOf('..') !== -1) return null;
			var resolved = path.resolve(baseDir, fname);
			// Ensure resolved path starts with the target directory
			var base = path.resolve(baseDir) + path.sep;
			if (!resolved.startsWith(base) && resolved !== path.resolve(baseDir)) return null;
			return resolved;
		}

		/**
		 * Escape a string for safe insertion into HTML.
		 * Prevents XSS when inserting user/package-supplied text into the DOM.
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

		/**
		 * Validate that a library name is safe for use in filesystem paths.
		 * Rejects names containing path separators, '..' traversal, or invalid characters.
		 * @param {string} name
		 * @returns {boolean} true if safe
		 */
		function isValidLibraryName(name) {
			if (!name || typeof name !== 'string') return false;
			if (/[\\\/]|\.\./.test(name)) return false;
			if (/[<>:"|?*]/.test(name)) return false;
			if (name.trim().length === 0) return false;
			return true;
		}

		/** Concurrency guard for import operations */
		var _isImporting = false;
    
        // Diskdb init
		var db = require('diskdb');

		// ---- Default Groups (hardcoded — never stored in external JSON) ----
		var DEFAULT_GROUPS = {
			"gAll":      { "_id": "gAll",      "name": "All",      "icon-class": "fa-home",         "default": true, "navbar": "left",  "favorite": true  },
			"gRecent":   { "_id": "gRecent",   "name": "Recent",   "icon-class": "fa-history",      "default": true, "navbar": "left",  "favorite": true  },
			"gFolders":  { "_id": "gFolders",  "name": "Import",   "icon-class": "fa-download",     "default": true, "navbar": "right", "favorite": false },
			"gEditors":  { "_id": "gEditors",  "name": "Export",   "icon-class": "fa-upload",       "default": true, "navbar": "right", "favorite": true  },
			"gHistory":  { "_id": "gHistory",  "name": "History",  "icon-class": "fa-list",         "default": true, "navbar": "right", "favorite": true  },
			"gHamilton": { "_id": "gHamilton", "name": "Hamilton", "icon-class": "fa-check-circle", "default": true, "navbar": "left",  "favorite": true, "protected": true }
		};

		/**
		 * Look up a group by _id.  Hardcoded defaults take priority;
		 * falls back to the external groups database (custom groups).
		 */
		function getGroupById(id) {
			if (DEFAULT_GROUPS[id]) return DEFAULT_GROUPS[id];
			try { return db_groups.groups.findOne({"_id": id}); } catch(e) { return null; }
		}

		// ---- Settings DB (always in app's db/ folder — portable) ----
		var db_settings = db.connect('db', ['settings']);

		// ---- User Data Path ----
		// User data (installed libs, groups, tree, links) is stored OUTSIDE the app
		// in a configurable folder so the app stays portable and lightweight.
		var DEFAULT_USER_DATA_PATH = path.join("C:\\Program Files (x86)\\HAMILTON\\Library", "VenusLibraryManager");

		function resolveUserDataPath() {
			var settings = db_settings.settings.find();
			if (settings && settings.length > 0 && settings[0]["userDataPath"]) {
				var saved = settings[0]["userDataPath"];
				// Migrate old hidden dot-folder path to visible name
				if (saved.indexOf('.VenusLibraryManager') !== -1) {
					saved = saved.replace('.VenusLibraryManager', 'VenusLibraryManager');
				}
				return saved;
			}
			return DEFAULT_USER_DATA_PATH;
		}

		function ensureUserDataDir(dirPath) {
			if (!fs.existsSync(dirPath)) {
				fs.mkdirSync(dirPath, { recursive: true });
			}
			// Seed empty collections if they don't exist
			var seedFiles = {
				'installed_libs.json': '[]',
				'groups.json': '[]',
				'tree.json': '[{"group-id":"gAll","method-ids":[],"locked":false},{"group-id":"gRecent","method-ids":[],"locked":false},{"group-id":"gFolders","method-ids":[],"locked":false},{"group-id":"gEditors","method-ids":[],"locked":false},{"group-id":"gHistory","method-ids":[],"locked":false},{"group-id":"gHamilton","method-ids":[],"locked":true}]',
				'links.json': '[{"_id":"method-editor","name":"Method Editor","description":"","icon-customImage":"HxMet.png","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxMetEd.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lc-editor","name":"Liquid Class Editor","description":"","icon-customImage":"HxLiq.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxCoreLiquidEditor.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lbw-editor","name":"Labware Editor","description":"","icon-customImage":"HxLbw.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxLabwrEd.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"hsl-editor","name":"HSL Editor","description":"","icon-customImage":"HxHSL.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxHSLMetEd.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"sysCfg-editor","name":"System Configuration Editor","description":"","icon-customImage":"HxCfg.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\Hamilton.HxConfigEditor.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"run-control","group-id":"gEditors","name":"Run Control","description":"","icon-customImage":"HxRun.png","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxRun.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"ham-version","group-id":"gEditors","name":"Hamilton Version","description":"","icon-customImage":"HxVer.png","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxVersion.exe","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"bin-folder","name":"Bin","description":"VENUS software executables and dlls","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"cfg-folder","name":"Config","description":"VENUS software configuration files","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Config","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lbw-folder","name":"Labware","description":"VENUS software labware definitions for carriers, racks, tubes and consumables","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Labware","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lib-folder","name":"Library","description":"VENUS software library files","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Library","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"log-folder","name":"LogFiles","description":"Run traces and STAR communication logs","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Logfiles","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"met-folder","name":"Methods","description":"Method files","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Methods","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0}]'
			};
			for (var fname in seedFiles) {
				var fpath = path.join(dirPath, fname);
				if (!fs.existsSync(fpath)) {
					fs.writeFileSync(fpath, seedFiles[fname], 'utf8');
				}
			}
		}

		/**
		 * Migrate old db/ user data files to the new user data directory.
		 * Only migrates if old files exist and new files are empty/default.
		 */
		function migrateOldDbData(userDataDir) {
			var filesToMigrate = ['installed_libs.json', 'groups.json', 'tree.json', 'links.json'];
			filesToMigrate.forEach(function(fname) {
				var oldPath = path.join('db', fname);
				var newPath = path.join(userDataDir, fname);
				try {
					if (!fs.existsSync(oldPath)) return;
					var oldData = fs.readFileSync(oldPath, 'utf8').trim();
					if (!oldData || oldData === '[]') return; // nothing to migrate
					var oldArr = JSON.parse(oldData);
					if (!Array.isArray(oldArr) || oldArr.length === 0) return;

					// Only migrate if the new file is empty/default (not yet customized)
					var newData = fs.readFileSync(newPath, 'utf8').trim();
					var newArr = JSON.parse(newData);

					// For installed_libs, only migrate if new is empty
					if (fname === 'installed_libs.json') {
						if (newArr.length === 0) {
							fs.writeFileSync(newPath, oldData, 'utf8');
							console.log('Migrated ' + fname + ' to user data directory (' + oldArr.length + ' records)');
						}
					}
					// For groups, migrate if new has only default groups
					else if (fname === 'groups.json') {
						var hasCustom = newArr.some(function(g) { return !g["default"]; });
						if (!hasCustom && oldArr.some(function(g) { return !g["default"]; })) {
							fs.writeFileSync(newPath, oldData, 'utf8');
							console.log('Migrated ' + fname + ' to user data directory');
						}
					}
					// For tree and links, migrate if old has more data
					else {
						if (oldArr.length > newArr.length) {
							fs.writeFileSync(newPath, oldData, 'utf8');
							console.log('Migrated ' + fname + ' to user data directory');
						}
					}
				} catch(e) {
					console.warn('Migration warning for ' + fname + ': ' + e.message);
				}
			});
		}

		// Resolve user data path, ensure directory exists, migrate old data
		var USER_DATA_DIR = resolveUserDataPath();
		ensureUserDataDir(USER_DATA_DIR);

		// Migrate from old hidden .VenusLibraryManager folder if it exists
		var OLD_HIDDEN_DIR = path.join("C:\\Program Files (x86)\\HAMILTON\\Library", ".VenusLibraryManager");
		if (fs.existsSync(OLD_HIDDEN_DIR) && OLD_HIDDEN_DIR !== USER_DATA_DIR) {
			try {
				var oldFiles = ['installed_libs.json', 'groups.json', 'tree.json', 'links.json'];
				oldFiles.forEach(function(fname) {
					var src = path.join(OLD_HIDDEN_DIR, fname);
					var dst = path.join(USER_DATA_DIR, fname);
					if (fs.existsSync(src)) {
						var srcData = fs.readFileSync(src, 'utf8').trim();
						var dstData = fs.readFileSync(dst, 'utf8').trim();
						// Only copy if destination is still default/empty seed data
						if (dstData === '[]' || JSON.parse(dstData).length === 0) {
							if (srcData !== '[]' && JSON.parse(srcData).length > 0) {
								fs.writeFileSync(dst, srcData, 'utf8');
								console.log('Migrated ' + fname + ' from .VenusLibraryManager');
							}
						}
					}
				});
			} catch(e) {
				console.warn('Warning migrating from .VenusLibraryManager: ' + e.message);
			}
		}

		migrateOldDbData(USER_DATA_DIR);

		// Connect user data databases to the external directory
		var db_links = db.connect(USER_DATA_DIR, ['links']);
		var db_groups = db.connect(USER_DATA_DIR, ['groups']);
		var db_tree = db.connect(USER_DATA_DIR, ['tree']); // contains the tree of group ids and method ids
		var db_installed_libs = db.connect(USER_DATA_DIR, ['installed_libs']); // tracks installed .hxlibpkg libraries

		console.log('App settings: db/');
		console.log('User data:    ' + USER_DATA_DIR);

		// ---- Migration: strip hardcoded default groups from external groups.json ----
		// Default groups are now defined in DEFAULT_GROUPS and should not live in the JSON.
		(function migrateDefaultGroups() {
			try {
				var groupsPath = path.join(USER_DATA_DIR, 'groups.json');
				var groupsRaw = fs.readFileSync(groupsPath, 'utf8');
				var groupsData = JSON.parse(groupsRaw);
				var defaultIds = Object.keys(DEFAULT_GROUPS);
				var before = groupsData.length;
				// Also remove orphan Hamilton entries with random _ids
				groupsData = groupsData.filter(function(g) {
					if (defaultIds.indexOf(g._id) !== -1) return false;
					if (g.name === 'Hamilton' && g['protected']) return false;
					return true;
				});
				if (groupsData.length !== before) {
					fs.writeFileSync(groupsPath, JSON.stringify(groupsData), 'utf8');
					db_groups = db.connect(USER_DATA_DIR, ['groups']);
					console.log('Migrated: removed ' + (before - groupsData.length) + ' default group(s) from external groups.json');
				}

				// Ensure tree entries exist for all default groups
				var treePath = path.join(USER_DATA_DIR, 'tree.json');
				var treeRaw = fs.readFileSync(treePath, 'utf8');
				var treeData = JSON.parse(treeRaw);
				var treeChanged = false;
				defaultIds.forEach(function(gid) {
					var found = treeData.some(function(t){ return t["group-id"] === gid; });
					if (!found) {
						treeData.push({ "group-id": gid, "method-ids": [], "locked": (gid === 'gHamilton') });
						treeChanged = true;
						console.log('Created tree entry for default group: ' + gid);
					}
				});
				if (treeChanged) {
					fs.writeFileSync(treePath, JSON.stringify(treeData), 'utf8');
					db_tree = db.connect(USER_DATA_DIR, ['tree']);
				}
			} catch(e) {
				console.warn('Could not migrate default groups: ' + e.message);
			}
		})();

		// ---- System Libraries (hardcoded Hamilton base libraries) ----
		var systemLibraries = [];
		try {
			var _sysLibRaw = fs.readFileSync(path.join('db', 'system_libraries.json'), 'utf8');
			systemLibraries = JSON.parse(_sysLibRaw);
		} catch(e) {
			console.warn('Could not load system_libraries.json: ' + e.message);
		}

		// ---- System Library Baseline (integrity baseline from clean VENUS install) ----
		// Uses Hamilton's built-in $$valid$$ / $$checksum$$ metadata footer instead of SHA-256.
		var systemLibraryBaseline = {};
		try {
			var _sysHashRaw = fs.readFileSync(path.join('db', 'system_library_hashes.json'), 'utf8');
			var _sysHashData = JSON.parse(_sysHashRaw);
			systemLibraryBaseline = _sysHashData.libraries || {};
		} catch(e) {
			console.warn('Could not load system_library_hashes.json: ' + e.message);
		}

		// ---- Restricted Author Protection ----
		// Password required to use "Hamilton" (case-insensitive) as author on non-system packages.
		// This prevents spoofing and acts as an additional signing mechanism for first-party libraries.
		var HAMILTON_AUTHOR_PASSWORD = 'password123';

		/**
		 * Check if an author name is restricted (i.e. "Hamilton" in any case).
		 * @param {string} author
		 * @returns {boolean}
		 */
		function isRestrictedAuthor(author) {
			if (!author) return false;
			return author.trim().toLowerCase() === 'hamilton';
		}

		/**
		 * Validate the password for using a restricted author name.
		 * @param {string} password
		 * @returns {boolean}
		 */
		function validateAuthorPassword(password) {
			return password === HAMILTON_AUTHOR_PASSWORD;
		}

		/**
		 * Show a password prompt modal for restricted author usage.
		 * Returns a Promise that resolves to true if password is correct, false otherwise.
		 */
		function promptAuthorPassword() {
			return new Promise(function(resolve) {
				var $modal = $("#authorPasswordModal");
				$modal.find("#author-password-input").val('');
				$modal.find(".author-password-error").addClass("d-none");
				$modal.data('resolved', false);

				// Confirm button
				$modal.find(".btn-author-password-confirm").off('click').on('click', function() {
					var pw = $modal.find("#author-password-input").val();
					if (validateAuthorPassword(pw)) {
						$modal.data('resolved', true);
						$modal.modal('hide');
						resolve(true);
					} else {
						$modal.find(".author-password-error").removeClass("d-none");
						$modal.find("#author-password-input").val('').focus();
					}
				});

				// Allow Enter key to submit
				$modal.find("#author-password-input").off('keydown').on('keydown', function(e) {
					if (e.keyCode === 13) {
						$modal.find(".btn-author-password-confirm").trigger('click');
					}
				});

				// Modal dismissed without confirming
				$modal.off('hidden.bs.modal.authorpw').on('hidden.bs.modal.authorpw', function() {
					if (!$modal.data('resolved')) {
						resolve(false);
					}
				});

				$modal.modal('show');
				setTimeout(function() { $modal.find("#author-password-input").focus(); }, 300);
			});
		}

		/** Check if a library ID belongs to a system library */
		function isSystemLibrary(libId) {
			if (!libId) return false;
			if (typeof libId === 'string' && libId.indexOf('sys_') === 0) return true;
			for (var i = 0; i < systemLibraries.length; i++) {
				if (systemLibraries[i]._id === libId) return true;
			}
			return false;
		}

		/** Get a system library by ID */
		function getSystemLibrary(libId) {
			for (var i = 0; i < systemLibraries.length; i++) {
				if (systemLibraries[i]._id === libId) return systemLibraries[i];
			}
			return null;
		}

		/** Get all system libraries */
		function getAllSystemLibraries() {
			return systemLibraries.slice();
		}

		// ---- Package Store — cache .hxlibpkg files for repair & version rollback ----
		function getPackageStoreDir() {
			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var libPath = (libFolderRec && libFolderRec.path) ? libFolderRec.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
			return path.join(libPath, "LibraryPackages");
		}

		/**
		 * Build a deterministic filename for a cached package:
		 *   <LibraryName>_v<version>_<YYYYMMDD-HHmmss>.hxlibpkg
		 */
		function buildCachedPackageName(libName, version) {
			var safe   = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
			var ver    = (version || '0.0.0').replace(/[<>:"\/\\|?*]/g, '_');
			var now    = new Date();
			var stamp  = now.getFullYear().toString()
			           + String(now.getMonth() + 1).padStart(2, '0')
			           + String(now.getDate()).padStart(2, '0')
			           + '-'
			           + String(now.getHours()).padStart(2, '0')
			           + String(now.getMinutes()).padStart(2, '0')
			           + String(now.getSeconds()).padStart(2, '0');
			return safe + '_v' + ver + '_' + stamp + '.hxlibpkg';
		}

		/**
		 * Cache a .hxlibpkg buffer into the package store.
		 * Organises into subdirectories by library name.
		 * @param {Buffer}  pkgBuffer - Raw bytes of the .hxlibpkg file
		 * @param {string}  libName   - Library name from the manifest
		 * @param {string}  version   - Version string from the manifest
		 * @returns {string} The full path where the package was stored
		 */
		function cachePackageToStore(pkgBuffer, libName, version) {
			var safeName = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
			var libDir   = path.join(getPackageStoreDir(), safeName);
			if (!fs.existsSync(libDir)) {
				fs.mkdirSync(libDir, { recursive: true });
			}
			var fileName = buildCachedPackageName(libName, version);
			var destPath = path.join(libDir, fileName);
			fs.writeFileSync(destPath, pkgBuffer);
			return destPath;
		}

		/**
		 * List all cached package versions for a given library name.
		 * Returns an array of { file, version, author, created, cached, size, fullPath }
		 * sorted newest-first by cache date.
		 */
		function listCachedVersions(libName) {
			var safeName = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
			var libDir   = path.join(getPackageStoreDir(), safeName);
			if (!fs.existsSync(libDir)) return [];

			var files = fs.readdirSync(libDir).filter(function(f) {
				return f.toLowerCase().endsWith('.hxlibpkg');
			});

			var entries = files.map(function(f) {
				var fullPath = path.join(libDir, f);
				var version = '?';
				var createdDate = '';
				var author = '';
				try {
					var zip = new AdmZip(fullPath);
					var me  = zip.getEntry('manifest.json');
					if (me) {
						var m = JSON.parse(zip.readAsText(me));
						version     = m.version      || '?';
						createdDate = m.created_date  || '';
						author      = m.author        || '';
					}
				} catch(e) {}
				var stat = fs.statSync(fullPath);
				return {
					file:     f,
					version:  version,
					author:   author,
					created:  createdDate,
					cached:   stat.mtime.toISOString(),
					size:     stat.size,
					fullPath: fullPath
				};
			});

			entries.sort(function(a, b) { return b.cached.localeCompare(a.cached); });
			return entries;
		}

		// ---- First-Run System Library Backup ----
		// On first run, package every system library into the package store so
		// they can be repaired later if files are modified or corrupted.
		// The flag 'sysLibBackupComplete' in settings tracks whether this has run.

		/**
		 * Package a single system library into a .hxlibpkg backup in the package store.
		 * System libraries have no demo methods — only library files and help files.
		 * @param {Object} sLib - system library record from system_libraries.json
		 * @returns {{ success: boolean, path: string, error: string }}
		 */
		function backupSystemLibrary(sLib) {
			try {
				var libName = sLib.canonical_name || sLib.library_name;
				var discoveredFiles = sLib.discovered_files || [];
				if (discoveredFiles.length === 0) {
					return { success: false, path: '', error: 'No discovered files for ' + libName };
				}

				// Resolve the VENUS Library directory
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

				// Separate library files and help files (CHMs)
				var libFiles = [];
				var helpFiles = [];
				discoveredFiles.forEach(function(f) {
					var relPath = f.replace(/^Library[\\\/]/i, '');
					var ext = path.extname(relPath).toLowerCase();
					if (ext === '.chm') {
						helpFiles.push(relPath);
					} else {
						libFiles.push(relPath);
					}
				});

				// Build a library image if a BMP exists
				var libImageFilename = null;
				var libImageBase64 = null;
				var libImageMime = null;
				libFiles.forEach(function(f) {
					if (!libImageFilename && path.extname(f).toLowerCase() === '.bmp') {
						var bmpPath = path.join(sysLibDir, f);
						if (fs.existsSync(bmpPath)) {
							libImageFilename = f;
							try {
								libImageBase64 = fs.readFileSync(bmpPath).toString('base64');
								libImageMime = 'image/bmp';
							} catch(e) {}
						}
					}
				});

				// Build manifest
				var manifest = {
					format_version: "1.0",
					library_name: libName,
					author: sLib.author || "Hamilton",
					organization: sLib.organization || "Hamilton",
					version: "system",
					venus_compatibility: "",
					description: "System library backup created on first run. Contains " + discoveredFiles.length + " file(s).",
					tags: ["system", "hamilton", "backup"],
					created_date: new Date().toISOString(),
					library_image: libImageFilename,
					library_image_base64: libImageBase64,
					library_image_mime: libImageMime,
					library_files: libFiles.slice(),
					demo_method_files: [],
					help_files: helpFiles.slice(),
					com_register_dlls: [],
					is_system_backup: true
				};

				// Create ZIP package
				var zip = new AdmZip();
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files
				libFiles.forEach(function(f) {
					var fullPath = path.join(sysLibDir, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, "library");
					}
				});

				// Add help files (CHMs) — packed into help_files/ folder
				helpFiles.forEach(function(f) {
					var fullPath = path.join(sysLibDir, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, "help_files");
					}
				});

				// Sign the package
				signPackageZip(zip);

				// Cache to package store
				var pkgBuffer = zip.toBuffer();
				var storedPath = cachePackageToStore(pkgBuffer, libName, "system");
				return { success: true, path: storedPath, error: '' };

			} catch(e) {
				return { success: false, path: '', error: e.message };
			}
		}

		/**
		 * Run system library backup for all system libraries that don't already
		 * have a cached package. Called once on first run.
		 * @returns {{ total: number, backed: number, skipped: number, errors: string[] }}
		 */
		function backupAllSystemLibraries() {
			var result = { total: 0, backed: 0, skipped: 0, errors: [] };
			var allSys = getAllSystemLibraries();
			result.total = allSys.length;

			allSys.forEach(function(sLib) {
				var libName = sLib.canonical_name || sLib.library_name;
				var existing = listCachedVersions(libName);
				if (existing.length > 0) {
					result.skipped++;
					return;
				}
				var r = backupSystemLibrary(sLib);
				if (r.success) {
					result.backed++;
					console.log('Backed up system library: ' + libName + ' -> ' + r.path);
				} else {
					result.errors.push(libName + ': ' + r.error);
					console.warn('Failed to backup system library: ' + libName + ' - ' + r.error);
				}
			});
			return result;
		}

		/**
		 * Check if the first-run system library backup has been completed.
		 * If not, run it and set the flag.
		 */
		function ensureSystemLibraryBackups() {
			if (getSettingValue('sysLibBackupComplete')) {
				return; // Already backed up
			}
			console.log('First run detected — backing up system libraries to package store...');
			var result = backupAllSystemLibraries();
			console.log('System library backup complete: ' + result.backed + ' backed up, ' +
				result.skipped + ' already cached, ' + result.errors.length + ' errors.');
			if (result.errors.length > 0) {
				console.warn('Backup errors: ' + result.errors.join('; '));
			}
			saveSetting('sysLibBackupComplete', true);
		}

		/**
		 * Repair a system library by re-extracting files from its cached backup package.
		 * @param {string} libName - canonical name of the system library
		 * @param {boolean} [silent] - If true, suppress alerts (for batch repair)
		 * @returns {{ success: boolean, error: string }}
		 */
		function repairSystemLibraryFromCache(libName, silent) {
			try {
				var cached = listCachedVersions(libName);
				if (cached.length === 0) {
					var msg = 'No backup package found for system library "' + libName + '".';
					if (!silent) alert(msg);
					return { success: false, error: msg };
				}

				// Use the newest cached version
				var newest = cached[0];
				var zip;
				try {
					zip = new AdmZip(newest.fullPath);
				} catch(e) {
					var msg2 = 'Failed to read backup package: ' + e.message;
					if (!silent) alert(msg2);
					return { success: false, error: msg2 };
				}

				// Verify the cached package signature
				var sigResult = verifyPackageSignature(zip);
				if (sigResult.signed && !sigResult.valid) {
					var msg3 = 'Backup package signature verification FAILED.\nThe backup package itself may be corrupted.\n\n' + sigResult.errors.join('\n');
					if (!silent) alert(msg3);
					return { success: false, error: 'Backup package signature failed' };
				}

				var manifestEntry = zip.getEntry('manifest.json');
				if (!manifestEntry) {
					var msg4 = 'Backup package is invalid (no manifest.json).';
					if (!silent) alert(msg4);
					return { success: false, error: msg4 };
				}

				// Resolve the VENUS Library directory
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

				// Re-extract library files
				var extractedCount = 0;
				var zipEntries = zip.getEntries();
				zipEntries.forEach(function(entry) {
					if (entry.isDirectory || entry.entryName === 'manifest.json' || entry.entryName === 'signature.json') return;
					if (entry.entryName.indexOf('library/') === 0) {
						var fname = entry.entryName.substring('library/'.length);
						if (fname) {
							var safePath = safeZipExtractPath(sysLibDir, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf('help_files/') === 0) {
						var fname3 = entry.entryName.substring('help_files/'.length);
						if (fname3) {
							var safePath3 = safeZipExtractPath(sysLibDir, fname3);
							if (!safePath3) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir3 = path.dirname(safePath3);
							if (!fs.existsSync(parentDir3)) fs.mkdirSync(parentDir3, { recursive: true });
							fs.writeFileSync(safePath3, entry.getData());
							extractedCount++;
						}
					}
				});

				if (!silent) {
					alert('System library "' + libName + '" repaired successfully!\n\n' +
						extractedCount + ' files re-extracted from backup package.' +
						(sigResult.signed ? '\nPackage signature: verified' : ''));
					impBuildLibraryCards();
				}

				return { success: true, error: '' };

			} catch(e) {
				var errMsg = 'System library repair failed: ' + e.message;
				if (!silent) alert(errMsg);
				return { success: false, error: errMsg };
			}
		}

		var bool_treeChanged = false; //tracks if the tree of groups/methods has been edited to re-create groups when coming back to Home screen from Settings screen.

		var int_maxRecent = 10;

		
		//**********************************************************************
        //******  EVENTS *******************************************************
        //**********************************************************************
        // Track whether window is maximized (used to persist across sessions)
		var _windowIsMaximized = false;
		win.on('maximize', function () { _windowIsMaximized = true; });
		win.on('restore',  function () { _windowIsMaximized = false; });
		win.on('unmaximize', function () { _windowIsMaximized = false; });

        //Window close.   Ensure to close any background running nw.exe
		win.on('close', function () {
			// Persist maximized state for next launch
			try {
				saveSetting('windowMaximized', _windowIsMaximized);
			} catch(e) { console.log('Could not save window state: ' + e); }

			gui.App.closeAllWindows();
			win.close(true);
		});

        //Window resize
		$(window).resize(function () {
			waitForFinalEvent(function () {
				fitNavBarItems();
				fitMainDivHeight();
				fitExporterHeight();
				fitImporterHeight();
			}, 150, "window-resize");
		});

        //Window load
		$(window).on('load', function () {
			// Restore maximized state from previous session
			try {
				if (getSettingValue('windowMaximized')) {
					win.maximize();
					_windowIsMaximized = true;
				}
			} catch(e) { console.log('Could not restore window state: ' + e); }

			// Use setTimeout instead of waitForFinalEvent so that an async
			// resize triggered by win.maximize() cannot cancel this init.
			setTimeout(function () {
				try {
					initVENUSData();
					createGroups();
					setTimeout(function(){historyCleanup()},100);
				} catch(e) {
					console.log("Error in startup chain: " + e);
					try { createGroups(); } catch(e2) { console.log("Error in createGroups: " + e2); }
				}
				// Ensure we always navigate to home screen after startup
				try { navigateHome(); } catch(e3) { console.log("Error navigating home: " + e3); }
			}, 150);
        });

        //Click Hamilton logo to go home
		$(document).on("click", ".brand-logo", function () {
			// Close any open modals
			$("#groupsModal").modal("hide");
			$("#settingsModal").modal("hide");
			// Activate the All (home) nav item
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
			$('.navbar-custom .nav-item[data-group-id="gAll"]').addClass("active");
			$('.group-container').addClass('d-none');
			$(".links-container").addClass("d-none");
			$(".exporter-container").addClass("d-none");
			$(".importer-container").removeClass("d-none");
			$("#imp-header").removeClass("d-none").addClass("d-flex");
			impBuildLibraryCards();
			fitImporterHeight();
		});

        //Method groups -  navigation bar events
		$(document).on("click", ".navbar-custom .nav-item:not('.dropdown'), .navbar-custom .dropdown-navitem", function () { 
            
            //change active nav item
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
            $(this).addClass("active");

			// Clear search bar when switching tabs
			$("#imp-search-input").val("");
			$(".imp-search-clear-wrap").addClass("d-none");
			_searchActive = false;
			_preSearchGroupId = null;
            
			//display links group
			var group_id = $(this).attr('data-group-id');
			$('.group-container').addClass('d-none');

			// Show/hide containers based on active tab
			if(group_id == "gEditors"){
				$(".links-container").addClass("d-none");
				$(".exporter-container").removeClass("d-none");
				$(".importer-container").addClass("d-none");
				fitExporterHeight();
			} else if(group_id == "gAll"){
				// All (home) shows installed library cards with header
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-none").addClass("d-flex");
				impBuildLibraryCards();
				fitImporterHeight();
			} else if(group_id == "gRecent"){
				// Recent tab - show recently imported libraries (exclude system)
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-flex").addClass("d-none");
				impBuildLibraryCards(null, true);
				fitImporterHeight();
			} else if(group_id == "gFolders"){
				// Import tab - show library cards without header
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-flex").addClass("d-none");
				impBuildLibraryCards();
				fitImporterHeight();
			} else if(group_id == "gSystem"){
				// System Libraries tab - show only system (Hamilton base) libraries
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-flex").addClass("d-none");
				impBuildLibraryCards(null, false, true);
				fitImporterHeight();
			} else {
				// Custom group or other tab - show filtered library cards
				var groupData = getGroupById(group_id);
				if(groupData && (!groupData["default"] || group_id === "gHamilton")){
					$(".links-container").addClass("d-none");
					$(".exporter-container").addClass("d-none");
					$(".importer-container").removeClass("d-none");
					$("#imp-header").removeClass("d-flex").addClass("d-none");
					impBuildLibraryCards(group_id);
					fitImporterHeight();
				} else {
					$(".links-container").removeClass("d-none");
					$(".exporter-container").addClass("d-none");
					$(".importer-container").addClass("d-none");
					$('.group-container[data-group-id="' + group_id + '"').removeClass('d-none');
				}
			}

			//startup tab is always "All" - no longer saving last opened tab
			
			
        });
        
        //Open detail modal when clicking a card body
		$(document).on("click", ".link-detail-trigger", function () {
			var id = $(this).attr("data-id") || $(this).closest(".link-card-container").attr("data-id");
			if(id){ showDetailModal(id); }
		});

		//Open HSL Definition file
		$(document).on("click", ".link-OpenHSL", function () {
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			if(file_path && file_path !== ""){
				nw.Shell.openItem(file_path);
			}
		});

        //Run a method when clicking a card in the main div
		$(document).on("click", ".link-run-trigger", function () {
			var file_type = $(this).closest(".link-card-container").attr("data-type");
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			var id = $(this).closest(".link-card-container").attr("data-id");
			var isCustomLink= ($(this).closest(".link-card-container").attr("data-default") == 'false');

			if(isCustomLink){
				addLinkToRecent(id);
				updateLastStarted(id);
			}
			

			if(file_type=="method"){
				var args = [file_path];
				if($("#chk_run-autoclose").prop("checked")){ args.push("-t"); } //Run method immediately and terminate when method is complete.
				else if($("#chk_run-autoplay").prop("checked")){ args.push("-r"); } //Run method immediately.
    
				 var child =  spawn(HxRun, args, { detached: true, stdio: [ 'ignore', 'ignore', 'ignore' ] });
				 child.unref();
			}
			if(file_type=="folder"){
				nw.Shell.openItem(file_path);
				// nw.Shell.showItemInFolder(file_path);

			}
			if(file_type=="file"){
				nw.Shell.openItem(file_path);
			}
		});


		//Open attachment of a link card in the main div
		$(document).on("click", ".link-attachment", function () {
			var file_path = $(this).attr("data-filepath");	
			if(file_path!=""){
				nw.Shell.openItem(file_path);
			}	
		});

		//Open In Method Editor link card in the main div
		$(document).on("click", ".link-OpenMethEditor", function () {
			
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			// console.log("Open in Method Editor " + file_path)
			if(file_path!=""){
				file_path = file_path.substr(0, file_path.lastIndexOf(".")) + ".med";
				nw.Shell.openItem(file_path);
			}	
		});

		//Open Method Location link card in the main div
		$(document).on("click", ".link-OpenMethLocation", function () {
			
			var file_path = path.dirname($(this).closest(".link-card-container").attr("data-filepath"));
			// console.log("Open Location " + file_path);
			if(file_path!=""){
				nw.Shell.openItem(file_path);
			}	
		});

		




		//Click "help" from overflow menu.
		$(document).on("click", ".overflow-help", function () {
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			var chmPath = path.join(path.dirname(process.execPath), 'Library Manager.chm');
			if (fs.existsSync(chmPath)) {
				nw.Shell.openItem(chmPath);
			} else {
				alert('Help file not found: ' + chmPath);
			}
		});

		//Click "Library Groups" from overflow menu.
		$(document).on("click", ".overflow-groups", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			bool_treeChanged = false;
			createGroups();
			$("#groupsModal").modal("show");
			return false;
		});

		// When groups modal is closed, refresh groups if tree changed
		$("#groupsModal").on("hidden.bs.modal", function () {
			if (bool_treeChanged) {
				createGroups();
			}
		});

		//Click "Settings" from overflow menu.
		$(document).on("click", ".overflow-settings", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			$("#settingsModal").modal("show");
			return false;
		});

		// New group button inside the groups modal
		$(document).on("click", ".btn-newgroup-modal", function () {
			groupNew();
		});

		//Click "Export" from overflow menu
		$(document).on("click", ".overflow-export", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			// Activate the Export nav item
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
			$('.navbar-custom .nav-item[data-group-id="gEditors"]').addClass("active");
			$('.group-container').addClass('d-none');
			$(".links-container").addClass("d-none");
			$(".exporter-container").removeClass("d-none");
			$(".importer-container").addClass("d-none");
			fitExporterHeight();
			return false;
		});

		//Click "History" from overflow menu
		$(document).on("click", ".overflow-history", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			// Activate the History nav item
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
			$('.navbar-custom .nav-item[data-group-id="gHistory"]').addClass("active");
			$('.group-container').addClass('d-none');
			$(".links-container").removeClass("d-none");
			$(".exporter-container").addClass("d-none");
			$(".importer-container").addClass("d-none");
			$('.group-container[data-group-id="gHistory"]').removeClass('d-none');
			fitMainDivHeight();
			return false;
		});

		// ---- Library Search Bar ----
		var _searchTimeout = null;
		var _searchActive = false;
		var _preSearchGroupId = null; // remembers which tab was active before search

		// Lazily-built cache: maps system library _id → space-separated public function names
		var _sysLibFnCache = null;

		/**
		 * Build (or return existing) cache of public function names for every system library.
		 * Parses .hsl files once, so subsequent searches are instantaneous.
		 */
		function _buildSysLibFnCache() {
			if (_sysLibFnCache) return _sysLibFnCache;
			_sysLibFnCache = {};
			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';
			var sysLibs = getAllSystemLibraries();
			sysLibs.forEach(function(sLib) {
				var fnNames = [];
				(sLib.discovered_files || []).forEach(function(f) {
					if (path.extname(f).toLowerCase() !== '.hsl') return;
					var relPath = f.replace(/^Library[\\\/]/i, '');
					var fullPath = path.join(sysLibDir, relPath);
					try {
						var text = fs.readFileSync(fullPath, 'utf8');
						var fileName = f.replace(/\\/g, '/').split('/').pop();
						var fns = parseHslFunctions(text, fileName);
						fns.forEach(function(fn) {
							if (!fn.isPrivate) {
								fnNames.push(fn.qualifiedName || fn.name || '');
							}
						});
					} catch(e) { /* file may not be readable */ }
				});
				_sysLibFnCache[sLib._id] = fnNames.join(' ');
			});
			return _sysLibFnCache;
		}

		$(document).on("input", "#imp-search-input", function() {
			var query = $(this).val().trim().toLowerCase();
			// Show/hide clear button
			if (query.length > 0) {
				$(".imp-search-clear-wrap").removeClass("d-none");
			} else {
				$(".imp-search-clear-wrap").addClass("d-none");
			}
			// Debounce the filter
			clearTimeout(_searchTimeout);
			_searchTimeout = setTimeout(function() {
				if (query.length > 0) {
					impEnterSearchMode(query);
				} else {
					impExitSearchMode();
				}
			}, 150);
		});

		$(document).on("click", ".imp-search-clear", function() {
			$("#imp-search-input").val("").trigger("input");
		});

		// Keyboard shortcut: Ctrl+F focuses search bar
		$(document).on("keydown", function(e) {
			if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
				// Only intercept if importer or system view is visible
				if (!$(".importer-container").hasClass("d-none") || !$('.group-container').not('.d-none').length) {
					e.preventDefault();
					$("#imp-search-input").focus().select();
				}
			}
			// Escape clears search
			if (e.key === 'Escape' && $("#imp-search-input").is(":focus")) {
				$("#imp-search-input").val("").trigger("input").blur();
			}
		});

		function impEnterSearchMode(query) {
			// Remember current tab before entering search mode
			if (!_searchActive) {
				var activeNav = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active");
				_preSearchGroupId = activeNav.attr("data-group-id") || "gAll";
				_searchActive = true;
			}

			// Switch to importer container, hide header & nav highlight
			$(".links-container").addClass("d-none");
			$(".exporter-container").addClass("d-none");
			$(".importer-container").removeClass("d-none");
			$("#imp-header").removeClass("d-flex").addClass("d-none");
			$('.group-container').addClass('d-none');

			// Deactivate all nav tabs to signal search mode
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");

			// Build combined search results: all user libs + all system libs
			var $container = $("#imp-cards-container");
			$container.empty();

			// Gather all user-installed libraries (non-deleted)
			var userLibs = db_installed_libs.installed_libs.find() || [];
			userLibs = userLibs.filter(function(l) { return !l.deleted && !isSystemLibrary(l._id); });

			// Gather all system libraries
			var sysLibs = getAllSystemLibraries();

			// Build combined list of {name, html} for filtering
			var allCards = [];

			// User library cards
			userLibs.forEach(function(lib) {
				var fnNames = (lib.public_functions || []).map(function(fn) { return fn.qualifiedName || fn.name || ''; }).join(' ');
				var searchText = ((lib.library_name || '') + ' ' + (lib.author || '') + ' ' + (lib.description || '') + ' ' + (lib.tags || []).join(' ') + ' ' + fnNames).toLowerCase();
				if (searchText.indexOf(query) === -1) return;
				allCards.push({ type: 'user', html: impBuildSingleCardHtml(lib) });
			});

			// System library cards — include public function names in search
			var fnCache = _buildSysLibFnCache();
			sysLibs.forEach(function(sLib) {
				var fnNames = fnCache[sLib._id] || '';
				var searchText = ((sLib.display_name || sLib.canonical_name || '') + ' ' + (sLib.author || '') + ' ' + (sLib.resource_types || []).join(' ') + ' ' + fnNames).toLowerCase();
				if (searchText.indexOf(query) === -1) return;
				allCards.push({ type: 'system', html: buildSystemLibraryCard(sLib) });
			});

			if (allCards.length === 0) {
				$container.html(
					'<div class="w-100 text-center py-5 imp-search-no-results">' +
						'<i class="fas fa-search fa-2x color-lightgray"></i>' +
						'<p class="text-muted mt-2">No libraries matching "<b>' + $("<span>").text(query).html() + '</b>"</p>' +
					'</div>'
				);
			} else {
				// Search results header
				$container.append(
					'<div class="col-md-12 mb-2">' +
						'<span class="text-muted text-sm"><i class="fas fa-search mr-1"></i>' + allCards.length + ' result' + (allCards.length !== 1 ? 's' : '') + ' for "<b>' + $("<span>").text(query).html() + '</b>"</span>' +
					'</div>'
				);
				allCards.forEach(function(c) {
					$container.append(c.html);
				});
				$container.append('<div class="col-md-12 my-3"></div>');
			}

			fitImporterHeight();
		}

		function impExitSearchMode() {
			if (!_searchActive) return;
			_searchActive = false;

			// Restore the previous tab
			var gid = _preSearchGroupId || "gAll";
			_preSearchGroupId = null;

			// Re-activate the nav item and trigger its view
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
			var $navItem = $('.navbar-custom .nav-item[data-group-id="' + gid + '"], .navbar-custom .dropdown-navitem[data-group-id="' + gid + '"]');
			if ($navItem.length) {
				$navItem.addClass("active").trigger("click");
			} else {
				// Fallback to All
				$('.navbar-custom .nav-item[data-group-id="gAll"]').addClass("active").trigger("click");
			}
		}

		/**
		 * Build HTML for a single user-installed library card (used by search).
		 * Mirrors the rendering in impBuildLibraryCards() but returns an HTML string.
		 */
		function impBuildSingleCardHtml(lib) {
			var libName = escapeHtml(lib.library_name || "Unknown");
			var version = escapeHtml(lib.version || "");
			var author = escapeHtml(lib.author || "");
			var description = escapeHtml(lib.description || "");
			var tags = (lib.tags || []).map(function(t) { return escapeHtml(t); });
			var hasImage = !!lib.library_image_base64;
			var hasComWarning = lib.com_warning === true;
			var comDlls = (lib.com_register_dlls || []).map(function(d) { return escapeHtml(d); });
			var isDeleted = lib.deleted === true;

			var integrity = verifyLibraryIntegrity(lib);
			var hasIntegrityError = !integrity.valid;
			var hasIntegrityWarning = integrity.warnings.length > 0;

			var imgMime = lib.library_image_mime || 'image/bmp';
			if (!lib.library_image_mime && lib.library_image) {
				var extLower = (lib.library_image || '').split('.').pop().toLowerCase();
				if (IMAGE_MIME_MAP[extLower]) imgMime = IMAGE_MIME_MAP[extLower];
			}

			var iconHtml;
			if (hasImage) {
				iconHtml = '<img src="data:' + imgMime + ';base64,' + lib.library_image_base64 + '" style="max-width:48px; max-height:48px; border-radius:4px;">';
			} else {
				iconHtml = '<i class="fas fa-book fa-3x color-medium"></i>';
			}

			var shortDesc = description;
			if (shortDesc.length > 80) { shortDesc = shortDesc.substring(0, 80) + "..."; }

			var tagsHtml = "";
			if (tags.length > 0) {
				tags.forEach(function(t) {
					tagsHtml += '<span class="badge badge-light mr-1" style="font-size:0.7rem;">' + t + '</span>';
				});
			}

			var comWarningBadge = "";
			if (hasComWarning && comDlls.length > 0) {
				comWarningBadge = '<span class="badge badge-warning ml-2" title="COM registration failed for: ' + comDlls.join(', ') + '."><i class="fas fa-exclamation-triangle mr-1"></i>COM</span>';
			} else if (comDlls.length > 0) {
				comWarningBadge = '<span class="badge badge-info ml-2" title="COM registered DLLs: ' + comDlls.join(', ') + '"><i class="fas fa-cog mr-1"></i>COM</span>';
			}

			var deletedBadge = "";
			if (isDeleted) {
				deletedBadge = '<span class="badge badge-secondary ml-2"><i class="fas fa-trash-alt mr-1"></i>Deleted</span>';
			}

			var deps = extractRequiredDependencies(lib.library_files || [], lib.lib_install_path || '');
			var depStatus = checkDependencyStatus(deps);
			var hasMissingDeps = !depStatus.valid;

			var cardExtraClass = '';
			if (hasIntegrityError || hasMissingDeps) { cardExtraClass = ' imp-lib-card-integrity-error'; }
			else if (hasComWarning) { cardExtraClass = ' imp-lib-card-warning'; }
			if (isDeleted) cardExtraClass += ' imp-lib-card-deleted';

			var cardTooltipAttr = '';
			if (hasIntegrityError || hasMissingDeps) {
				var errParts = [];
				if (hasIntegrityError) errParts = errParts.concat(integrity.errors).concat(integrity.warnings);
				if (hasMissingDeps) errParts.push('Missing dependencies: ' + depStatus.missing.map(function(d) { return d.libraryName || d.include; }).join(', '));
				cardTooltipAttr = ' title="' + errParts.join('\n').replace(/"/g, '&quot;') + '"';
			} else if (hasIntegrityWarning) {
				var warnTooltip = integrity.warnings.join('\n');
				cardTooltipAttr = ' title="' + warnTooltip.replace(/"/g, '&quot;') + '"';
			}

			return '<div class="col-md-4 col-xl-3 d-flex align-items-stretch imp-lib-card-container" data-lib-id="' + lib._id + '">' +
				'<div class="m-2 pl-3 pr-3 pt-3 pb-2 link-card imp-lib-card w-100' + cardExtraClass + '"' + cardTooltipAttr + '>' +
					'<div class="d-flex align-items-start">' +
						'<div class="mr-3 mt-1 imp-lib-card-icon">' + iconHtml + '</div>' +
						'<div class="flex-grow-1" style="min-width:0;">' +
							'<h6 class="mb-0 imp-lib-card-name cursor-pointer" style="color:var(--medium2);">' + libName + comWarningBadge + deletedBadge + '</h6>' +
							(version ? '<span class="text-muted text-sm">v' + version + '</span>' : '') +
							(author ? '<div class="text-muted text-sm">' + author + '</div>' : '') +
						'</div>' +
					'</div>' +
					(shortDesc ? '<p class="text-muted mt-2 mb-1" style="font-size:0.85em;">' + shortDesc + '</p>' : '') +
					(tagsHtml ? '<div class="mt-1 mb-2">' + tagsHtml + '</div>' : '') +
					'<div class="d-flex justify-content-between align-items-center mt-2 pt-2" style="border-top:1px solid #eee;">' +
						'<a href="#" class="text-sm imp-lib-card-details cursor-pointer" style="color:var(--medium);">View Details</a>' +
					'</div>' +
				'</div>' +
			'</div>';
		}

		//Settings screen menu navigation
		//Settings > Installation checkboxes
		$(document).on("click", "#chk_confirmBeforeInstall, #chk_overwriteWithoutAsking, #chk_autoAddToGroup", function(){
			saveSetting($(this).attr("id"), $(this).prop("checked"));
		});

		//Settings > Display checkboxes
		$(document).on("click", "#chk_hideSystemLibraries", function(){
			saveSetting($(this).attr("id"), $(this).prop("checked"));
			// Refresh front page cards if currently on All tab
			var activeGroup = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id");
			if (activeGroup === 'gAll') {
				impBuildLibraryCards();
			}
		});

		//Settings - Recent dropdown change text
		$(document).on("click", ".dd-maxRecent a", function () {
			var txt = $(this).text();
			$("#dd-maxRecent").text(txt);
			saveSetting("recent-max",txt);
		});

		// Settings > Data Location — browse and apply
		$(document).on("click", ".btn-browseDataPath", function() {
			// Use a hidden nwdirectory input to pick a folder
			var $picker = $("#input-dataPathBrowse");
			if ($picker.length === 0) {
				$picker = $('<input type="file" id="input-dataPathBrowse" nwdirectory style="display:none">');
				$("body").append($picker);
			}
			$picker.val('');
			$picker.off('change').on('change', function() {
				var chosen = $(this).val();
				if (chosen) {
					$(".txt-userDataPath").val(chosen);
				}
			});
			$picker.trigger('click');
		});

		$(document).on("click", ".btn-applyDataPath", function() {
			var newPath = $(".txt-userDataPath").val().trim();
			if (!newPath) return;
			if (newPath === USER_DATA_DIR) return; // no change

			// Save the new path to settings
			saveSetting("userDataPath", newPath);

			// Ensure the new directory exists and has seed files
			try {
				ensureUserDataDir(newPath);
				// Offer to copy existing data to the new location
				var shouldCopy = confirm("Data location changed to:\n" + newPath +
					"\n\nDo you want to copy your existing data to the new location?\n" +
					"(Installed libraries, groups, and links will be copied.)");
				if (shouldCopy) {
					var filesToCopy = ['installed_libs.json', 'groups.json', 'tree.json', 'links.json'];
					filesToCopy.forEach(function(fname) {
						var src = path.join(USER_DATA_DIR, fname);
						var dst = path.join(newPath, fname);
						try {
							if (fs.existsSync(src)) {
								fs.copyFileSync(src, dst);
								console.log('Copied ' + fname + ' to new data location');
							}
						} catch(e) {
							console.warn('Could not copy ' + fname + ': ' + e.message);
						}
					});
				}
				alert("Data location updated. Please restart the application for changes to take full effect.");
			} catch(e) {
				alert("Error setting up new data location: " + e.message);
			}
		});

		$(document).on("click", ".btn-clearRecentList", function () {
			clearRecentList();
			$(".txt-recentCleared").text("Recent list has been cleared!");
			setTimeout(function(){ 
				$(".txt-recentCleared").text("");
			 }, 3000);
		});

		// Settings > Links > favorite icon click
		$(document).on("click", ".favorite-icon", function (e) {
			bool_favorite = false;
			if($(this).hasClass("favorite")){
				//it´s already a favorite , deselect
				$(this).removeClass("favorite");
				$(this).find("i").removeClass("fas").addClass("far");
			}else{
				//make  favorite, select
				bool_favorite = true;
				$(this).addClass("favorite");
				$(this).find("i").removeClass("far").addClass("fas");
				
			}

			//Update favorite state in database
			if($(this).parent().attr("data-id")){
				// method / link
				id = $(this).parent().attr("data-id");
				updateFavorite(id, bool_favorite, "link");
			}else{
				// group
				id = $(this).parent().parent().attr("data-group-id");
				updateFavorite(id, bool_favorite, "group");
			}
			bool_treeChanged = true;
			e.stopPropagation();
		});


		//Edit Modal window events
		// $(document).on("click", "#editModal .inputType-radio input", function (e) {
		// 	$("#btn-filebrowse").attr("data-type", $(this).attr("data-type"));
		// });

		$(document).on("click", ".btn-filebrowse", function (e) {
			$("#" + $(this).attr("data-type") ).trigger("click");
			$("#editModal .filetype-tmpselection").attr("data-fileType",$(this).attr("data-filetype"));
		});

		$(document).on("change", "input[type='file']", function() {
			// Skip packager-specific file inputs (handled separately)
			if($(this).attr('id') && $(this).attr('id').indexOf('pkg-') === 0){ return; }

			var text_control = $(this).attr("data-text-input");
			var str = $(this).val();
			$("." + text_control).val(str);
			$("." + text_control).tooltip({
				title: str,
				delay: { show: 500, hide: 100 }
			});
			
			if(str!=""){
				//Remove any red styling when setting a string.
				$("." + text_control).css({
					"border": "",
					"background": ""
				});

				//Show X to clear the field
				$("." + text_control).closest(".form-group").find(".clear-field").removeClass("d-none");
				var filetype = $("#editModal .filetype-tmpselection").attr("data-fileType");
				$("#editModal .filetype-selection").attr("data-fileType",filetype);
			}else{
				//Hide X to clear the field
				$("." + text_control).closest(".form-group").find(".clear-field").addClass("d-none");
			}

			if($(this).attr('id')=='input-image'){
				if(str!=""){
					//show image
					$(".editModal-image").attr("src", str);
					$(".editModal-image").removeClass("d-none");
					$(".image-placeholder").addClass("d-none");
				}
			}
			if($(this).attr("id")=="input-history-archiveDir"){
				saveSetting("history-archive-folder",str);
			}

		  });

		

		  $('#editModal .btn-save').click(function (e) {
            var isValid = true;
			var str_selector="#editModal .txt-linkName";
			if($("#editModal .modal-content").attr("data-linkOrGroup") == "link"){
				str_selector += ",.txt-filepath"; //if it´s a link, add this field to the validation
			}

            $(str_selector).each(function () {
                if ($.trim($(this).val()) == '') {
                    isValid = false;
                    $(this).css({
                        "border": "1px solid red",
                        "background": "#FFCECE"
                    });
					$("#editModal .div-form").removeClass("d-none");
					$("#editModal .div-iconselect").addClass("d-none");
					$("#editModal .a-choose").removeClass("d-none");
                }
                else {
                    $(this).css({
                        "border": "",
                        "background": ""
                    });
                }
            });
            if (isValid == false){
				e.preventDefault();
			}else{
				saveModalData();
			}
        });

		$(document).on("change keydown keyup", "#editModal .txt-linkName",function(e){
			if ($.trim($(this).val()) != ''){
				//Remove any red styling when setting a string in this field
				$(this).css({
					"border": "",
					"background": ""
				});
				$(this).parent().find(".clear-text").removeClass("d-none");
			} else{
				$(this).parent().find(".clear-text").addClass("d-none");
			}
			if(e.type=="keydown" && e.keyCode==13){ //pressed enter
				$("#editModal .btn-save").trigger("click");
			}
		});

		$(document).on("click", "#editModal .clear-text",function(){
			$("#editModal .txt-linkName").val('');
			$(this).addClass("d-none");
		});

		$(document).on("click", ".clear-field",function(e){
			$(this).closest(".form-group").find("input[type='file']").val('');
			$(this).closest(".form-group").find("input[type='text']").val('');
			//remove tooltip
			$(this).closest(".form-group").find("input[type='text']").tooltip("dispose");
			$(this).addClass("d-none");

			
			if($(this).closest(".form-group").find("input[type='file']").attr('id')=='input-image'){
					//show placeholder
					$(".editModal-image").attr("src", '');
					$(".editModal-image").addClass("d-none");
					$(".image-placeholder").removeClass("d-none");
			}
			
		});

		$(document).on("click", ".icon-container, .image-container, .a-choose , .close-imagediv", function(){
			if($("#editModal .div-form").hasClass("d-none")){
				//The dialog is not showing the form, need to go back to the form
				$("#editModal .div-form").removeClass("d-none");
				$("#editModal .div-iconselect").addClass("d-none");
				$("#editModal .a-choose").removeClass("d-none");
			}else{

				$("#editModal .div-form").addClass("d-none");
				$("#editModal .div-iconselect").removeClass("d-none");
				$("#editModal .a-choose").addClass("d-none");
				$("#inputImg-image, #inputImg-icon").prop("checked",false);

				//The dialog is  showing the form, need to switch to image/icon edit view
				if($("#editModal .icon-container").hasClass("d-none")){
					//Show image editing
					$("#inputImg-image").prop("checked",true);
					$("#inputImg-image").trigger("click");
				}else{
					//Show icon editing
					$("#inputImg-icon").prop("checked",true);
					$("#inputImg-icon").trigger("click");
					$("#editModal .icons-list").scrollTop(0); //reset div scroll
					//Scroll icons-list to view the selected icon
					var icon = $(".editModal-icon").attr("data-iconClass");
					var containerOffset = $("#editModal .icons-list").offset().top;
					var childOffset = $("#editModal .icons-list i." + icon).parent().offset().top;
					var calcScrollOffset = childOffset - containerOffset;
					$("#editModal .icons-list").scrollTop(calcScrollOffset - 30);
				}
			}

			
		})


		//MODAL WINDOW - ICON Color Selection
		$(document).on("mouseover", "#editModal .color-circle", function(){
			var new_color = $(this).attr("data-colorClass")
			var current_color = $(".editModal-icon").attr("data-colorClass");
			if(new_color != current_color){
				$(".editModal-icon").removeClass (current_color);
				$(".editModal-icon").addClass(new_color);
			}
		});

		$(document).on("mouseout", "#editModal .color-circle", function(){
			var new_color = $(this).attr("data-colorClass")
			var current_color = $(".editModal-icon").attr("data-colorClass");
			if(new_color != current_color){
				$(".editModal-icon").removeClass(new_color);
				$(".editModal-icon").addClass (current_color);
			}
			
		});

		$(document).on("click", "#editModal .color-circle", function(){
			var new_color = $(this).attr("data-colorClass")
			var current_color = $(".editModal-icon").attr("data-colorClass");
			if(new_color != current_color){
				$(".editModal-icon").removeClass (current_color);
				$(".editModal-icon").addClass(new_color);
				$(".editModal-icon").attr("data-colorClass", new_color);
				$("#editModal .color-circle").removeClass("color-circle-active");
				$(this).addClass("color-circle-active");
			}

		});

		

		//MODAL WINDOW - ICON type Selection
		$(document).on("mouseover", "#editModal .select-icon", function(){
			var new_icon= $(this).find("i").attr('class').replace("fas fa-1x ","");
			var current_icon = $(".editModal-icon").attr("data-iconClass");
			if(new_icon != current_icon){
				$(".editModal-icon").removeClass (current_icon);
				$(".editModal-icon").addClass(new_icon);
			}
		});

		$(document).on("mouseout", "#editModal .select-icon", function(){
			var new_icon = $(this).find("i").attr('class').replace("fas fa-1x ","");
			var current_icon = $(".editModal-icon").attr("data-iconClass");
			if(new_icon != current_icon){
				$(".editModal-icon").removeClass(new_icon);
				$(".editModal-icon").addClass (current_icon);
			}
			
		});

		$(document).on("click", "#editModal .select-icon", function(){
			var new_icon = $(this).find("i").attr('class').replace("fas fa-1x ","");
			var current_icon = $(".editModal-icon").attr("data-iconClass");
			if(new_icon != current_icon){
				$(".editModal-icon").removeClass (current_icon);
				$(".editModal-icon").addClass(new_icon);
				$(".editModal-icon").attr("data-iconClass", new_icon);
				$("#editModal .select-icon").removeClass("icon-active");
				$(this).addClass("icon-active");
			}

		});
		

		//MODAL WINDOW - Radio selection Icon / Image
		$(document).on("click","#inputImg-image",function(e){
			$("#image-selection").removeClass("d-none");
			$("#icon-selection").addClass("d-none");
			$(".image-container").removeClass("d-none");
			$(".icon-container").addClass("d-none");
			if($("#editModal .txt-image").val()==''){
				//no path selected for image. Display icon placeholder
				$(".editModal-image").addClass("d-none");
				$(".image-placeholder").removeClass("d-none");
			}else{
				//img path selected . Display image
				$(".editModal-image").removeClass("d-none");
				$(".image-placeholder").addClass("d-none");
			}
		});


		$(document).on("click","#inputImg-icon",function(){
			$("#image-selection").addClass("d-none");
			$("#icon-selection").removeClass("d-none");
			$(".image-container").addClass("d-none");
			$(".icon-container").removeClass("d-none");
			$("#editModal .icons-list").scrollTop(0); //reset div scroll
			//Scroll icons-list to view the selected icon
			var icon = $(".editModal-icon").attr("data-iconClass");
			$("#editModal .select-icon").removeClass("icon-active");
			$("#editModal .icons-list i." + icon).parent().addClass("icon-active");
			var containerOffset = $("#editModal .icons-list").offset().top;
			var childOffset = $("#editModal .icons-list i." + icon).parent().offset().top;
			var calcScrollOffset = childOffset - containerOffset;
			$("#editModal .icons-list").scrollTop(calcScrollOffset - 30);
			//hightlight color
			var color=$(".editModal-icon").attr("data-colorClass");
			$("#editModal .color-circle").removeClass("color-circle-active");
			$("#editModal .color-circle."+color).addClass("color-circle-active");

		});
		


		// Link creation removed - libraries are managed via Import

		$(document).on("click", ".group-name",function (e){
			var id=$(this).closest("[data-group-id]").attr("data-group-id");
			editModal("group","edit",id);
			e.stopPropagation();
		})

		// Settings library items are now read-only (no editModal on click)

		$(document).on("click", "#editModal .btn-delete",function (e){
			var id=$("#editModal .modal-content").attr("data-id");
			var linkOrGroup = $("#editModal .modal-content").attr("data-linkOrGroup");
			$("#editModal").modal("hide");
			confirmDeleteModal(id, linkOrGroup);
		})
		

		$(document).on('shown.bs.modal', '#editModal', function () {
			if($("#editModal .txt-linkName").val()==''){
				$("#editModal .txt-linkName").focus();
			}
		});

		
        //*************************************************************************
        //******  EVENTS END*******************************************************
        //*************************************************************************



        //**************************************************************************************
        //******  FUNCTION DECLARATIONS  *******************************************************
        //**************************************************************************************
		var waitForFinalEvent = (function () {
			var timers = {};
			return function (callback, ms, uniqueId) {
				if (!uniqueId) {
					uniqueId = "Don't call this twice without a uniqueId";
				}
				if (timers[uniqueId]) {
					clearTimeout(timers[uniqueId]);
				}
				timers[uniqueId] = setTimeout(callback, ms);
			};
		})();



        // Adjusts the main div height to the window size and display a y-scrollbar only in that section
		function fitMainDivHeight() {
			if($(".methods-page").hasClass("d-none")){return;} //exit function if settings page is not visible
			var linksDiv = $(".links-container");
			var linksDiv_height = window.innerHeight - $(".header2").outerHeight();
			var linksDiv_padding = parseInt($(linksDiv).css('padding-top')) + parseInt($(linksDiv).css('padding-bottom')) + parseInt($(linksDiv).css('margin-bottom'));
			linksDiv_height -= linksDiv_padding;
			$(linksDiv).height(linksDiv_height);
		}


		//fitSettingsDivHeight removed – groups and settings are now modals with their own scrolling


        // Adjusts the elements in the nav bar and hides the ones that exceed the total width available
		function fitNavBarItems() {
			if($(".methods-page").hasClass("d-none")){return;} //exit function if settings page is not visible
			// horizontal room we have to work with (the container)
			// this value doesn't change until we resize again
			var navSpace = $('.navbar-custom').width();
			// calc the combined width of all nav-items
			var linksWidth = 0;
			$('.nav-subgroup').each(function () {
				linksWidth += $(this).outerWidth();
			});
			// now let's compare them to see if all the links fit in the container...
			if (linksWidth > navSpace) {
				// the width of the links is greater than the width of their container...
				// keep moving links from the menu to the overflow until the combined width is less than the container...
				while (linksWidth > navSpace) {
					var lastLink = $('.navblock-collapsable > li:last'); // get the last link
					
						var lastLinkWidth = lastLink.outerWidth(); // get its width
						var lastLinkIconClass = $(lastLink).find('i').attr("class").toString().replace("fa-1x", "fa-sm");
						$(lastLink).data('foo', lastLinkWidth); // store the width (so that we can see if it fits back in the space available later)
						var str = $(lastLink).find('.nav-item-text').text();

						$('.hidden-nav-items').prepend(lastLink);
						
						var strClass = ""
						if($(lastLink).hasClass("d-none")){ strClass = " d-none"}
						
						$('#nav-overflow').prepend(
							'<a class="dropdown-item dropdown-navitem'+ strClass +'" href="#"><i class="' + lastLinkIconClass + ' mr-2"></i>' + str + '</a>'
						); // pop the link and push it to the overflow
						// recalc the linksWidth since we removed one
						linksWidth = 0;
						$('.nav-subgroup').each(function () {
							linksWidth += $(this).outerWidth();
						});
	
				}
				$('#nav-more').removeClass("d-none"); // make sure we can see the overflow menu
				$('#navbarDropdownMenuLink').text('+' + $('#nav-overflow > a').length); // update the hidden link count
			} else {
				// shazam, the width of the links is less than the width of their container...
				// let's move links from the overflow back into the menu until we run out of room again...
				while (linksWidth <= navSpace) {
					var firstOverflowLink = $('.hidden-nav-items > li:first');
					var firstOverflowLinkWidth = firstOverflowLink.data('foo');
					if ($('#nav-overflow > a').length == 1) {
						linksWidth -= $('#nav-more').outerWidth();
					}
					if (navSpace - linksWidth > firstOverflowLinkWidth) {
						$('.navblock-collapsable').append(firstOverflowLink);
						$('#nav-overflow > a:first').remove();
					}
					linksWidth = linksWidth + firstOverflowLinkWidth; // recalc the linksWidth since we added one
				}
				$('#navbarDropdownMenuLink').text('+' + $('#nav-overflow > a').length);  // update the hidden link count
				// should we hide the overflow menu?
				if ($('#nav-overflow > a').length == 0) {
					$('#nav-more').addClass("d-none");
				}
			} // end else
		}

		//Generate a unique ID, used for methods and method groups.
		function uniqueID() {
			return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
		}

		
		//Create the method groups in the nav bar and the method cards in the main div
		function createGroups() {
			$(".navbarLeft>li").remove(); // delete all groups in left nav bar except the first 2 (All, Recent)
			$(".navbarRight>li").remove(); // delete all groups in right nav bar 
			$("#nav-overflow").empty();		 // delete all links added to dropdown div that handles the nav bar overflow
			$('.hidden-nav-items').empty();  // delete all links added to the hidden div to handle the nav bar overflow
			$(".links-container>.row").empty(); // delete all group containers in the main view
			
			//Empty Settings screen > Libraries
			$(".settings-links #accordion").empty();

			
			var navtree = db_tree.tree.find(); //loads tree of custom groups/methods structure. This excludes the system groups and links for editors & folders

			

			for (var i = 0; i < navtree.length; ++i) {

				var group_id = navtree[i]["group-id"];
				var navgroup = getGroupById(group_id); // loads default or custom group
				//find group data

				if(navgroup){
					var group_name = navgroup["name"];
					var group_icon = navgroup["icon-class"];
					
					var group_default = navgroup["default"];
					var group_navbar = navgroup["navbar"];
					var group_favorite = navgroup["favorite"];
					var group_protected = navgroup["protected"] || false;

					// Skip Export, History, and Hamilton from normal nav rendering
					// Hamilton nav item is injected after System below
					var skipNavItem = (group_id === "gEditors" || group_id === "gHistory" || group_id === "gHamilton");

					var classCustomGroup = "";
					if(!group_default || group_protected){
						classCustomGroup = " custom-group ";
					}

					//add nav groups to nav bar (skip overflow menu items)
					if(!skipNavItem){
						var str = '<li class="nav-item' ;
						if(!group_favorite){str+=' d-none';}
						
						str +=  classCustomGroup + '" data-group-id="' + group_id + '">' +
										'<div class="navitem-content"><div><i class="far fa-1x ' + group_icon + '"></i></div>' +
										'<div><span class="nav-item-text">' + group_name + '</span></div></div></li>';

						(group_navbar==="left") ?  $(".navbarLeft").append(str) : $(".navbarRight").append(str);
					}

					//add nav groups to main div. This groups will be filled with the method cards
					var str = '<div class="row no-gutters d-none group-container w-100 '+ classCustomGroup + '" data-group-id="' + group_id + '"></div>';
					$(".links-container>.row").append(str);



					// add groups to settings > links
					// Hamilton/protected groups are always visible but without edit/delete
					var displayClass = "";
					if(group_default && !group_protected){displayClass = " d-none";}

					if (group_protected) {
						// Protected group: show in accordion with read-only badge, no edit/delete
						str = '<div class="card mb-2 settings-links-group cursor-pointer'+displayClass+'" data-group-id="'+ group_id +'">' +
								'<div class="card-header collapsed" role="tab" id="heading_'+group_id +'" data-toggle="collapse" href="#collapse_'+ group_id+'" aria-expanded="true" aria-controls="collapse_'+ group_id+'">' +
										'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
										'<span class="color-medium2"><i class="fas '+ group_icon +' fa-md ml-2 mr-2"></i><span class="group-name">'+ group_name +' </span></span>'+
										'<span class="badge badge-warning ml-2" style="font-size:0.7rem;">Protected</span>';
										if(group_favorite){
											str+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon favorite tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="fas fa-star fa-md"></i>'+
											'</span>';
										}else{
											str+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="far fa-star fa-md"></i>'+
											'</span>';
										}
								str+='</div>'+  
								'<div id="collapse_'+ group_id+'" class="collapse" role="tabpanel" aria-labelledby="heading_'+group_id +'">'+
									'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">'+
									'</div>'+
								'</div>'+
							'</div>';
					} else {
						str = '<div class="card mb-2 settings-links-group cursor-pointer'+displayClass+'" data-group-id="'+ group_id +'">' +
								'<div class="card-header collapsed" role="tab" id="heading_'+group_id +'" data-toggle="collapse" href="#collapse_'+ group_id+'" aria-expanded="true" aria-controls="collapse_'+ group_id+'">' +
										'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
										'<span class="color-medium2"><i class="fas '+ group_icon +' fa-md ml-2 mr-2"></i><span class="group-name">'+ group_name +' </span></span>'+
										'<span class="cursor-pointer float-right pl-2 pr-2 " id="ddg_'+group_id+'" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">'+
											'<i class="far fa-ellipsis-v fa-md color-grayblue"></i>'+
											'<div class="dropdown-menu" aria-labelledby="ddg_'+group_id+'">'+
												'<a class="dropdown-item dropdown-navitem-clearbg" href="#" onclick="groupEdit(\''+group_id+'\');"><i class="far fa-pencil fa-sm mr-2 color-blue"></i>Edit</a>'+
												'<a class="dropdown-item dropdown-navitem-clearbg" href="#" onclick="groupDelete(\''+ group_id +'\');"><i class="far fa-trash fa-sm mr-2 color-blue"></i>Delete</a>'+
											'</div>'+
										'</span>';
										if(group_favorite){
											str+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon favorite tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="fas fa-star fa-md"></i>'+
											'</span>';
										}else{
											str+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="far fa-star fa-md"></i>'+
											'</span>';
										}
								str+='</div>'+  
								'<div id="collapse_'+ group_id+'" class="collapse" role="tabpanel" aria-labelledby="heading_'+group_id +'">'+
									'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">'+

									'</div>'+
								'</div>'+
							'</div>';
					} // end if group_protected else
					$(".settings-links #accordion").append(str);


				    //Add installed libraries to this group's accordion body in Settings > Libraries
					var lib_ids = navtree[i]["method-ids"] || [];

					for (var j = 0; j < lib_ids.length; ++j) {
						var lib = db_installed_libs.installed_libs.findOne({"_id":lib_ids[j]});
						if(lib){
							var libName = escapeHtml(lib.library_name || "Unknown");
							var libVersion = lib.version ? " v" + escapeHtml(lib.version) : "";
							var libAuthor = escapeHtml(lib.author || "");
						var libIcon = '<i class="fas fa-book fa-lg ml-2 mr-2 mb-2 align-top pt-2" style="color:var(--medium)"></i>';
							if(lib.library_image_base64){
								var libMime = lib.library_image_mime || 'image/bmp';
								if (!lib.library_image_mime && lib.library_image) {
									var extLower = (lib.library_image || '').split('.').pop().toLowerCase();
									if (IMAGE_MIME_MAP[extLower]) libMime = IMAGE_MIME_MAP[extLower];
								}
								libIcon = '<img src="data:' + libMime + ';base64,' + lib.library_image_base64 + '" class="ml-2 mr-2 mb-2 align-top pt-2" style="max-width:20px; max-height:20px; border-radius:3px;">';
							}

							var str = '<div class="settings-links-method w-100 pt-2" data-id="'+lib._id+'">' +
								libIcon +
								'<div class="d-inline-block pb-2 link-namepath">' +
									'<div class="name">' + libName + libVersion + '</div>' +
									'<div class="path">' + (libAuthor ? libAuthor : '') + '</div>' +
								'</div>' +
							'</div>';
							$("#collapse_"+ group_id + " .card-body").append(str);
						}
					}

				} //end if navgroup
			} //end for groups

			// ---- Inject the static "System" group nav item ----
			if (systemLibraries.length > 0) {
				var sysNavStr = '<li class="nav-item system-group-nav" data-group-id="gSystem">' +
					'<div class="navitem-content"><div><i class="far fa-1x fa-lock"></i></div>' +
					'<div><span class="nav-item-text">System</span></div></div></li>';
				$(".navbarLeft").append(sysNavStr);

				// Add System group to Settings accordion (read-only, no edit/delete)
				var sysAccStr = '<div class="card mb-2 settings-links-group system-group-settings" data-group-id="gSystem">' +
					'<div class="card-header collapsed" role="tab" id="heading_gSystem" data-toggle="collapse" href="#collapse_gSystem" aria-expanded="false" aria-controls="collapse_gSystem">' +
						'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
						'<span class="color-medium2"><i class="fas fa-lock fa-md ml-2 mr-2"></i><span class="group-name">System </span></span>' +
						'<span class="badge badge-secondary ml-2" style="font-size:0.7rem;">Read-Only</span>' +
					'</div>' +
					'<div id="collapse_gSystem" class="collapse" role="tabpanel" aria-labelledby="heading_gSystem">' +
						'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">' +
						'</div>' +
					'</div>' +
				'</div>';
				$(".settings-links #accordion").append(sysAccStr);

				// Add system library items into the System accordion
				for (var si = 0; si < systemLibraries.length; si++) {
					var sLib = systemLibraries[si];
					var sLibName = sLib.display_name || sLib.canonical_name;
					var sLibIcon = '<i class="fas fa-lock fa-lg ml-2 mr-2 mb-2 align-top pt-2" style="color:#adb5bd"></i>';
					var sItemStr = '<div class="settings-links-method w-100 pt-2 system-lib-item" data-id="' + sLib._id + '">' +
						sLibIcon +
						'<div class="d-inline-block pb-2 link-namepath">' +
							'<div class="name" style="color:#6c757d;">' + sLibName + ' <span class="badge badge-light" style="font-size:0.65rem;">System</span></div>' +
							'<div class="path" style="color:#adb5bd;">Hamilton</div>' +
						'</div>' +
					'</div>';
					$("#collapse_gSystem .card-body").append(sItemStr);
				}
			}

			// ---- Inject the Hamilton group nav item (after System) ----
			{
				var hamiltonGrp = getGroupById("gHamilton");
				if (hamiltonGrp) {
					var hamFav = hamiltonGrp["favorite"];
					var hamIcon = hamiltonGrp["icon-class"] || "fa-check-circle";
					var hamNavStr = '<li class="nav-item custom-group' + (hamFav ? '' : ' d-none') + '" data-group-id="gHamilton">' +
						'<div class="navitem-content"><div><i class="fas fa-1x ' + hamIcon + '"></i></div>' +
						'<div><span class="nav-item-text">' + hamiltonGrp["name"] + '</span></div></div></li>';
					$(".navbarLeft").append(hamNavStr);
				}
			}

			// Add "Unassigned Libraries" section - shows libraries not in any custom group
			var allAssignedIds = [];
			for (var t = 0; t < navtree.length; t++) {
				var treeGroup = getGroupById(navtree[t]["group-id"]);
				if(treeGroup && !treeGroup["default"]) {
					allAssignedIds = allAssignedIds.concat(navtree[t]["method-ids"] || []);
				}
			}
			var allLibs = db_installed_libs.installed_libs.find();
			var unassignedLibs = allLibs.filter(function(lib) {
				return allAssignedIds.indexOf(lib._id) === -1;
			});

			var strUnassigned = '<div class="card mb-2 settings-links-group" data-group-id="unassigned">' +
				'<div class="card-header collapsed" role="tab" id="heading_unassigned" data-toggle="collapse" href="#collapse_unassigned" aria-expanded="true" aria-controls="collapse_unassigned">' +
					'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
					'<span class="color-medium2"><i class="fas fa-inbox fa-md ml-2 mr-2"></i><span class="group-name">Unassigned Libraries</span></span>' +
				'</div>' +
				'<div id="collapse_unassigned" class="collapse" role="tabpanel" aria-labelledby="heading_unassigned">' +
					'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">';

			unassignedLibs.forEach(function(lib) {
				var libName = escapeHtml(lib.library_name || "Unknown");
				var libVersion = lib.version ? " v" + escapeHtml(lib.version) : "";
				var libAuthor = escapeHtml(lib.author || "");
				var libIcon = '<i class="fas fa-book fa-lg ml-2 mr-2 mb-2 align-top pt-2" style="color:var(--medium)"></i>';
				if(lib.library_image_base64){
					var libMime = lib.library_image_mime || 'image/bmp';
					if (!lib.library_image_mime && lib.library_image) {
						var extLower = (lib.library_image || '').split('.').pop().toLowerCase();
						if (IMAGE_MIME_MAP[extLower]) libMime = IMAGE_MIME_MAP[extLower];
					}
					libIcon = '<img src="data:' + libMime + ';base64,' + lib.library_image_base64 + '" class="ml-2 mr-2 mb-2 align-top pt-2" style="max-width:20px; max-height:20px; border-radius:3px;">';
				}
				strUnassigned += '<div class="settings-links-method w-100 pt-2" data-id="' + lib._id + '">' +
					libIcon +
					'<div class="d-inline-block pb-2 link-namepath">' +
						'<div class="name">' + libName + libVersion + '</div>' +
						'<div class="path">' + (libAuthor ? libAuthor : '') + '</div>' +
					'</div>' +
				'</div>';
			});

			strUnassigned += '</div></div></div>';
			$(".settings-links #accordion").append(strUnassigned);


			// add bottom divs for the groups container, after the group divs. This creates the needed margin to properly stretch the cards
			var str = '<div class="col-md-12 my-3"></div>';
			$(".links-container>.row").append(str);


			//add groups to dropdown menu in the Settings > Settings > Start up section 
			$(".dd-navgroups").empty()  // delete all groups in the dropdown menu in the Settings > Settings > Start up section  
			$(".navbarLeft .nav-item-text").each(function() {
				$(".dd-navgroups").append('<a class="dropdown-item dropdown-navitem-clearbg" href="#" data-group-id="'+ $(this).closest("li").attr("data-group-id") +'">' + $(this).text() + '</a>');
			  });

			loadSettings();


			//Activate tooltips
			$('.tooltip-delay500').tooltip({
				delay: { show: 500, hide: 100 } //used for short paths in the link details
			});
			$('.tooltip-delay1000').tooltip({
				delay: { show: 1000, hide: 100 }  //used for prompt over method link
			});


			//reset nav bar and hide overflowing nav bar items
			fitNavBarItems();
			fitMainDivHeight();
			updateSortableDivs();
		}

		function updateSortableDivs(){
			//Sortable lists of groups and methods
			$( "#accordion" ).sortable({
				items: '> .settings-links-group:not([data-group-id="unassigned"]):not([data-group-id="gSystem"])',
				update: function(evet, ui){
					//recreate the tree.json
					saveTree();
				}
			});
			$( ".settings-links-group:not([data-group-id='gSystem']) .card-body" ).sortable({
				connectWith: ".settings-links-group:not([data-group-id='gSystem']) .card-body",
				items: '> .settings-links-method:not(.system-lib-item)',
				update: function(event, ui ) {
					if (this === ui.item.parent()[0]) { // this avoids the update to be triggerd twice when moving between groups
						//recreate the tree.json
						saveTree();
					}
					
						
				}
			});
		}

		function saveTree(){
			console.log("save tree..");
			try {
			db_tree.tree.remove({"locked":false},true); //clean up tree.json
			var tree =[];
			var groups = $(".settings-links-group");
			for (var i = 0; i < groups.length; ++i) {
				var group_id = $(groups[i]).attr('data-group-id');
				if(group_id === "unassigned") continue; // skip the unassigned pseudo-group
				if(group_id === "gSystem") continue; // skip the system group (hardcoded, not persisted)
				var methods = $(groups[i]).find(".settings-links-method");
				var method_ids=[]
				for (var j = 0; j < methods.length; ++j) {
					var id= $(methods[j]).attr("data-id");
					method_ids.push(id); //get method id
				}
				var obj = {};
				obj["group-id"] =$(groups[i]).attr('data-group-id'); // get group id
				obj["method-ids"] = method_ids;
				obj["locked"] = false;  // added to be used as a filter with the diskdb remove function to clear the tree.json without deleting the file.
				tree.unshift(obj); //pushes obj to the beginning of the array. This allows showing the groups in order when diskdb saves it.
			}
			db_tree.tree.save(tree);
			bool_treeChanged = true;
			} catch(e) {
				console.error('saveTree failed: ' + e.message);
				alert('Error saving navigation tree. Your changes may not have been saved.\n\n' + e.message);
			}
		}

		function updateFavorite(id , bool_favorite , linkOrGroup){
			var query = { "_id" : id};
			var dataToBeUpdate = {"favorite": bool_favorite};
			var options = {multi: false,upsert: false};
			if(linkOrGroup=="link"){
				var updated = db_links.links.update(query, dataToBeUpdate, options);
				//console.log(updated); // { updated: 1, inserted: 0 }
			}
			if(linkOrGroup=="group"){
				var updated = db_groups.groups.update(query, dataToBeUpdate, options);
				//console.log(updated); // { updated: 1, inserted: 0 }
			}
		}

		// Link editing functions removed - libraries are managed via Import

		function showDetailModal(id){
			var method = db_links.links.findOne({"_id": id});
			if(!method) return;

			var name = method["name"] || "";
			var description = method["description"] || "";
			var icon_customImage = method["icon-customImage"] || "";
			var icon_class = method["icon-class"] || "fa-file";
			var icon_color = method["icon-color"] || "color-dark";
			var method_path = method["path"] || "";
			var method_type = method["type"] || "";
			var attachments = method["attachments"] || [];
			var version = method["version"] || "—";
			var buildNumber = method["build-number"] || "—";
			var customFields = method["custom-fields"] || {};

			// Set icon or image
			var $icon = $("#detailModal .detail-modal-icon");
			$icon.empty();
			if(icon_customImage && icon_customImage !== "" && icon_customImage !== "placeholder"){
				var imgExists = false;
				try { imgExists = fs.existsSync(icon_customImage); } catch(e){}
				if(!imgExists && method["default"]){
					try { imgExists = fs.existsSync("html/img/" + icon_customImage); } catch(e){}
					if(imgExists) icon_customImage = "img/" + icon_customImage;
				}
				if(imgExists){
					$icon.html('<img src="' + icon_customImage + '">');
				} else {
					$icon.html('<i class="fad fa-image fa-3x color-gray"></i>');
				}
			} else {
				$icon.html('<i class="fad ' + icon_class + ' fa-3x ' + icon_color + '"></i>');
			}

			// Set name and type
			$("#detailModal .detail-modal-name").text(name);
			$("#detailModal .detail-modal-type").text(method_type);

			// Set description
			if(description){
				$("#detailModal .detail-modal-description").text(description).closest(".detail-section").removeClass("d-none");
			} else {
				$("#detailModal .detail-modal-description").closest(".detail-section").addClass("d-none");
			}

			// Set file path
			$("#detailModal .detail-modal-path").text(method_path);

			// Set version and build number
			$("#detailModal .detail-modal-version").text(version);
			$("#detailModal .detail-modal-buildnumber").text(buildNumber);

			// Build custom fields
			var $customList = $("#detailModal .detail-custom-fields-list");
			$customList.empty();
			var hasCustom = false;
			if(customFields && typeof customFields === "object"){
				var keys = Object.keys(customFields);
				for(var c = 0; c < keys.length; c++){
					hasCustom = true;
					$customList.append(
						'<div class="detail-field-row">' +
							'<span class="detail-field-key">' + escapeHtml(keys[c]) + '</span>' +
							'<span class="detail-field-value">' + escapeHtml(customFields[keys[c]]) + '</span>' +
						'</div>'
					);
				}
			}
			if(hasCustom){
				$("#detailModal .detail-custom-fields").removeClass("d-none");
			} else {
				$("#detailModal .detail-custom-fields").addClass("d-none");
			}

			// Build attachments
			var $attList = $("#detailModal .detail-attachments-list");
			$attList.empty();
			if(attachments && attachments.length > 0){
				for(var a = 0; a < attachments.length; a++){
					$attList.append(
						'<a href="#" class="link-attachment" data-filepath="' + attachments[a].replace(/"/g, '&quot;') + '">' +
							'<i class="far fa-paperclip fa-sm mr-2 color-blue"></i>' + escapeHtml(path.basename(attachments[a])) +
						'</a>'
					);
				}
				$("#detailModal .detail-attachments-section").removeClass("d-none");
			} else {
				$("#detailModal .detail-attachments-section").addClass("d-none");
			}

			$("#detailModal").modal("show");
		}

		function groupNew(){
			editModal("group","new","");
		}
		function groupEdit(id){
			editModal("group","edit",id);
		}
		function groupDelete(id){
			// Prevent deletion of the protected Hamilton group
			var grp = getGroupById(id);
			if (grp && grp["protected"]) {
				alert('The "' + grp.name + '" group is protected and cannot be deleted.');
				return;
			}
			confirmDeleteModal(id, "group");
		}

		function confirmDeleteModal(id, linkOrGroup){
			$('#deleteModal').modal();
			$('#deleteModal .btn-delete').attr("onclick", "deleteData('"+id+"','"+ linkOrGroup + "')");
			$("#deleteModal .linkorgroup").text(linkOrGroup);
			
			var str="";
			if(linkOrGroup == "link"){
				str = $(".settings-links-method[data-id='" +id+"'] .name").text();
			}
			if(linkOrGroup == "group"){
				str = $(".settings-links-group[data-group-id='" +id+"'] .group-name").text();
			}

			$("#deleteModal .name").text(str);
		}     


		function deleteData(id , linkOrGroup,callback){
				if(linkOrGroup == "link"){
					var el = $(".settings-links-method[data-id='" +id+"']");
				}
				if(linkOrGroup == "group"){
					var el = $(".settings-links-group[data-group-id='" +id+"']");
				}

				if(el){
					var highlight_color = getComputedStyle(document.body).getPropertyValue('--medium');
					el.effect( "highlight", {color: highlight_color}, 500, 
					function(){
						el.hide( "drop", { direction: "right" }, 500, function(){
							el.remove();
							saveTree()
						});
					});
					//remove from db
					if(linkOrGroup == "group"){
						 db_groups.groups.remove({"_id": id });
						// Libraries in this group become unassigned (not deleted from db)
					}
				}
				
				$('#deleteModal').modal('hide'); // now close modal
		} 

		function saveModalData(){

			var linkOrGroup = $("#editModal .modal-content").attr("data-linkOrGroup");
			var newOrEdit = $("#editModal .modal-content").attr("data-newOrEdit");
			var name = $('#editModal .txt-linkName').val()
			var icon_class = $("#editModal .editModal-icon").attr("data-iconClass");
			var icon_color = $("#editModal .editModal-icon").attr("data-colorClass");

			if(linkOrGroup == "group"){
				var dataToSave = {
					"name": name,
					"icon-class": icon_class,
					"default": false, 
					"navbar": "left",
					"favorite": true
				};

				if(newOrEdit =="edit"){
					//SAVE GROUP DATA
					var id = $("#editModal .modal-content").attr("data-id");
					var group_id = id;
					var query = { "_id" : id };
					
					var options = {
						multi: false,
						upsert: false
					};
					var updated = db_groups.groups.update(query, dataToSave, options);
					// console.log(updated); // { updated: 1, inserted: 0 }
				}
				if(newOrEdit =="new"){
					var saved = db_groups.groups.save(dataToSave);
					var group_id = saved._id;					

					//**********************save group id into tree.json
					//**********************
					//Add new group dummy div with group id to the tree and regenerate the tree.json. All links will be recreated after saving the modal.
					var str='<div class="settings-links-group" data-group-id="'+group_id+'"></div>'
					$("#accordion").append(str);
					
					saveTree();
				}
			}
		
			createGroups();
			$("#editModal").modal('hide');
			// console.log("group_id =" + group_id );
			$("#collapse_"+group_id).collapse("show"); //expand the group 
			

		}

		function editModal(linkOrGroup, newOrEdit, id){

			$("#editModal .modal-content").attr("data-linkOrGroup",linkOrGroup);
			$("#editModal .modal-content").attr("data-newOrEdit",newOrEdit);
			$("#editModal .modal-content").attr("data-id",id);
			$("#editModal .modal-title").text(newOrEdit + " " + linkOrGroup);

			$('#editModal .txt-linkName,.txt-filepath').each(function () {
               //clear any red styles
                    $(this).css({
                        "border": "",
                        "background": ""
                    });
            });

			$("#editModal .clear-field").addClass("d-none"); //hide all 'X' icons next to a file input field.
			$("#editModal .clear-text").addClass("d-none"); //hide X inside text input field
			$("#editModal .a-choose").removeClass("d-none"); //show "Choose..." under the icon/image

			//get data from database
			if(linkOrGroup == "link"){
				
				//hide link or image related divs
				$("#editModal .image-container").addClass("d-none");
				$("#editModal .icon-container").addClass("d-none");
				$("#editModal .div-form").removeClass("d-none");
				$("#editModal .link-inputs").removeClass("d-none");
				$("#editModal .div-iconselect").addClass("d-none");
				$("#inputImg-image").parent().removeClass("d-none").addClass("d-inline");
				$("#editModal .image-selection").removeClass("d-none");
				$("#editModal .icon-selection").removeClass("d-none");
				$("#editModal .color-circle").removeClass("d-none");

				if(newOrEdit == "edit"){
					
					//get data from the database and populate fields
					var method = db_links.links.findOne({"_id":id}); // load link with the given id
					var name = method["name"];
					var description = method["description"];
					var icon_customImage = method["icon-customImage"];  //the path to a custom image, if empty use icon.
					var icon_class = method["icon-class"];
					var icon_color = method["icon-color"];
					var method_path = method["path"];
					var attachments = method["attachments"];
					var method_default = method["default"];
					var method_type = method["type"];

					//fill input fields
					$("#editModal .txt-linkName").val(name);
					$("#editModal .txt-linkName").closest(".form-group").find(".clear-text").removeClass("d-none");
					
					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass(icon_class);
					$("#editModal .editModal-icon").attr("data-iconClass",icon_class);
					
					var old_color = $("#editModal .editModal-icon").attr("data-colorClass");
					$("#editModal .editModal-icon").removeClass(old_color).addClass(icon_color);
					$("#editModal .editModal-icon").attr("data-colorClass",icon_color);

					$("#editModal .txt-description").val(description);
				

					//check if the given icon_customImage exists, otherwise set placeholder icon
					if(icon_customImage!="" && icon_customImage!="placeholder"){
						try {
							if(fs.existsSync(icon_customImage)) {
								//console.log("The file exists.");
							} else {
								//console.log('The file does not exist.');
								icon_customImage = "placeholder";
							}
						} catch (err) {
							//console.error(err);
						}
					}

					if(icon_customImage == "placeholder"){
						//show image container
						$("#editModal .image-container").removeClass("d-none");
						//hide image
						$("#editModal .editModal-image").addClass("d-none");
						//show placeholder
						$("#editModal .image-placeholder").removeClass("d-none");
						$("#inputImg-image").prop("checked",true);
						$("#inputImg-icon").prop("checked",false);
						$("#editModal .icon-selection").addClass("d-none");
					}

					//Select radio buttom image or icon
					if(icon_customImage =="" && icon_class!=""){
						//show icon
						$("#editModal .icon-container").removeClass("d-none");
						$("#inputImg-image").prop("checked",false);
						$("#inputImg-icon").prop("checked",true);
						$("#editModal .image-selection").addClass("d-none");

						//select icon and color
						var icon = $("#editModal .editModal-icon").attr("data-iconClass");
						$("#editModal .select-icon").removeClass("icon-active");
						$("#editModal .select-icon").find("i." + icon).parent().addClass("icon-active");

						var color = $("#editModal .editModal-icon").attr("data-colorClass");
						$("#editModal .color-circle").removeClass("color-circle-active");
						$("#editModal .color-circle." + color).addClass("color-circle-active");

					}
					if(icon_customImage!="" && icon_customImage!="placeholder"){
						//show image
						$("#editModal .image-container").removeClass("d-none");
						$("#editModal .editModal-image").removeClass("d-none");
						$("#editModal .image-placeholder").addClass("d-none");
						$("#editModal .editModal-image").attr("src", icon_customImage);
						$("#inputImg-image").prop("checked",true);
						$("#inputImg-icon").prop("checked",false);
						$("#editModal .icon-selection").addClass("d-none");
						//fill image input field and show 'X' icon
						$("#input-image").val('');
						$("#editModal .txt-image").val(icon_customImage); 
						$("#editModal .txt-image").closest(".form-group").find(".clear-field").removeClass("d-none");
					}


					//CLEAR file input fields and type
					$("#input-methodfile").val('');
					$("#input-anyfile").val('');
					$("#input-folder").val('');
					$(".inputType-radio input[type='radio']").prop("checked", false);
					$("#editModal .txt-filepath").closest(".form-group").find(".clear-field").removeClass("d-none");

					
					//SET file input fields and type
					$("#editModal .filetype-selection").attr("data-filetype",method_type);
					$("#editModal .filetype-tmpselection").attr("data-filetype",method_type)					
					$("#editModal .txt-filepath").val(method_path);
					

					//CLEAR Attachment fields
					for (i = 1; i < 4; i++) {
						$("#input-attach"+i).val('');
						$("#editModal .txt-attach"+i).val('');
					}

					//SET Attachment fields
					if (attachments) {
						for (var k = 0; k < attachments.length; ++k) {
							var index = k+1
							$("#editModal .txt-attach"+index).val(attachments[k]);
							$("#editModal .txt-attach"+index).closest(".form-group").find(".clear-field").removeClass("d-none");
						}
					}

					//SET Version, Build Number and Custom Fields
					$("#editModal .txt-version").val(method["version"] || "");
					$("#editModal .txt-buildnumber").val(method["build-number"] || "");
					var cfObj = method["custom-fields"] || {};
					var cfLines = [];
					var cfKeys = Object.keys(cfObj);
					for(var cf = 0; cf < cfKeys.length; cf++){
						cfLines.push(cfKeys[cf] + "=" + cfObj[cfKeys[cf]]);
					}
					$("#editModal .txt-customfields").val(cfLines.join("\n"));
				}
				if(newOrEdit == "new"){
					var group_id = id;
					//show icon
					$("#editModal .icon-container").removeClass("d-none");
					$("#editModal .editModal-icon").removeClass("d-none");
					$("#inputImg-image").prop("checked",false);
					$("#inputImg-icon").prop("checked",true);
					$("#editModal .image-selection").addClass("d-none");

					//select icon and color
					var icon_class = "fa-dna";
					var icon_color = "color-dark";

					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass(icon_class);
					$("#editModal .editModal-icon").attr("data-iconClass",icon_class);
					
					var old_color = $("#editModal .editModal-icon").attr("data-colorClass");
					$("#editModal .editModal-icon").removeClass(old_color).addClass(icon_color);
					$("#editModal .editModal-icon").attr("data-colorClass",icon_color);

					
					$("#editModal .select-icon").removeClass("icon-active");
					$("#editModal .select-icon").find("i." + icon_class).parent().addClass("icon-active");

					$("#editModal .color-circle").removeClass("color-circle-active");
					$("#editModal .color-circle." + icon_color).addClass("color-circle-active");

					//RESET all input fields
					$("#editModal input[type=file], #editModal input[type=text]").val('');
					$("#editModal .txt-linkName,#editModal .txt-description, #editModal .txt-image").val('');
					$("#editModal .txt-version, #editModal .txt-buildnumber").val('');
					$("#editModal .txt-customfields").val('');
					$("#editModal .clear-text, #editModal .clear-field").addClass("d-none");
				}

				
			}
			if(linkOrGroup == "group"){

				//hide link or image related divs
				$("#editModal .image-container").addClass("d-none");
				$("#editModal .icon-container").removeClass("d-none");
				$("#editModal .div-form").removeClass("d-none");
				$("#editModal .link-inputs").addClass("d-none");
				$("#editModal .div-iconselect").addClass("d-none");
				$("#inputImg-image").parent().removeClass("d-inline").addClass("d-none");
				$("#inputImg-image").prop("checked", false);
				$("#inputImg-icon").prop("checked", true);
				$("#editModal .image-selection").addClass("d-none");
				$("#editModal .icon-selection").removeClass("d-none");
				$("#editModal .color-circle").addClass("d-none");

				var old_color = $("#editModal .editModal-icon").attr("data-colorClass");
				$("#editModal .editModal-icon").removeClass(old_color).addClass("color-dark");
				$("#editModal .color-circle").removeClass("color-circle-active");
				$("#editModal .color-circle.color-dark").addClass("color-circle-active");
				$("#editModal .editModal-icon").attr("data-colorClass","color-dark");

				if(newOrEdit =="edit"){
					//get data from the database and populate fields
					var navgroup = getGroupById(id); // loads default or custom group
					var group_name = navgroup["name"];
					var group_icon = navgroup["icon-class"];

					//fill input fields
					$("#editModal .txt-linkName").val(group_name);
					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass(group_icon);
					$("#editModal .editModal-icon").attr("data-iconClass",group_icon);

				}
				else{
					//NEW
					//clear fields and default icon
					$("#editModal .txt-linkName").val("");
					var old_icon = $("#editModal .editModal-icon").attr("data-iconClass");
					$("#editModal .editModal-icon").removeClass(old_icon).addClass("fa-dna");
					$("#editModal .editModal-icon").attr("data-iconClass","fa-dna");

				
				}
				
				//update icon selected in the list
				var icon = $("#editModal .editModal-icon").attr("data-iconClass");
				$("#editModal .select-icon").removeClass("icon-active");
				$("#editModal .select-icon").find("i." + icon).parent().addClass("icon-active");
				
				
			}
					
			 $('#editModal').modal();	 

		}
		

		function getDateTime(){
			var tzoffset = (new Date()).getTimezoneOffset() * 60000;
			var localISOTime = (new Date(Date.now() - tzoffset))
			.toISOString()
			.slice(0, 19)
			.replace('T', ' ');
			return ([localISOTime, Date.now()]);
		}

		function addLinkToRecent(id){
			//do not display in the Recent group if the link´s parent group is not favorite/not displayed in the navbar
			var group_id = $(".align-items-stretch[data-id='"+ id + "']").attr("data-group-id");
			var parent_navitem = $(".navbarLeft>.custom-group[data-group-id='"+ group_id+"']:not('.d-none'), hidden-nav-items>.custom-group[data-group-id='"+ group_id+"']:not('.d-none')");

			if(parent_navitem.length > 0){
				var thisLinkInRecent = $(".group-container[data-group-id='gRecent'] div.align-items-stretch[data-id='"+ id + "']");
				//Add only if it´s not added yet
				if(thisLinkInRecent.length==0){
					var cloneDiv = $(".align-items-stretch[data-id='"+ id + "']").clone();
					$(".group-container[data-group-id='gRecent']").prepend(cloneDiv);
				}
				//limit the amount of recent links to the max setting...
				$(".group-container[data-group-id='gRecent'] div.align-items-stretch:gt(" + int_maxRecent + ")").remove();
			}

			
		}


		function updateLastStarted(id){
			//update started only for non-default links. This is filtered in the link-run-trigger click event
			var arr1 = getDateTime();
			var formattedDateTime = arr1[0];
			var UTCDateTime = arr1[1];

			var dataToSave = {
				"last-started": formattedDateTime,
				"last-startedUTC": UTCDateTime
			};
			//SAVE LINK DATA
			var query = { "_id" : id };
			var options = {
				multi: false,
				upsert: false
			};
			var updated = db_links.links.update(query, dataToSave, options);
		}

        /** Navigate directly to the All (home) screen */
		function navigateHome() {
			// Activate the All nav item
			$(".navbar-custom .nav-item, .navbar-custom .dropdown-navitem").removeClass("active");
			$('.navbar-custom .nav-item[data-group-id="gAll"]').addClass("active");
			$('.group-container').addClass('d-none');
			// Switch from loading/links to home (importer) container
			$(".links-container").addClass("d-none");
			$(".exporter-container").addClass("d-none");
			$(".importer-container").removeClass("d-none");
			$("#imp-header").removeClass("d-none").addClass("d-flex");
			impBuildLibraryCards();
			fitImporterHeight();
		}

		function loadSettings(){
			var settings = db_settings.settings.find()[0]; //get all settings data from settings.json

			// Guard: if settings record is missing, create a default one
			if (!settings) {
				console.warn('Settings record not found — initializing defaults.');
				var defaults = {
					"_id": "0",
					"recent-max": 20,
					"chk_confirmBeforeInstall": true,
					"chk_overwriteWithoutAsking": false,
					"chk_autoAddToGroup": true,
					"chk_hideSystemLibraries": false
				};
				db_settings.settings.save(defaults);
				settings = defaults;
			}

			//Always start on the "All" screen
			navigateHome();

			//setting - Recent
			int_maxRecent = parseInt(settings["recent-max"], 10) || 20;
			console.log("int_maxRecent=" + int_maxRecent);
			$("#dd-maxRecent").text(int_maxRecent);

			//setting - Installation checkboxes
			$("#chk_confirmBeforeInstall").prop("checked", settings["chk_confirmBeforeInstall"] !== false);
			$("#chk_overwriteWithoutAsking").prop("checked", !!settings["chk_overwriteWithoutAsking"]);
			$("#chk_autoAddToGroup").prop("checked", settings["chk_autoAddToGroup"] !== false);

			//setting - Display: hide system libraries
			$("#chk_hideSystemLibraries").prop("checked", !!settings["chk_hideSystemLibraries"]);

			//setting - Data Location
			$(".txt-userDataPath").val(USER_DATA_DIR);

			//reset nav bar and hide overflowing nav bar items
			fitNavBarItems();
			fitMainDivHeight();
			updateSortableDivs();
		}

		function saveSetting(key,val){
			var dataToSave = { [key] : val};
			//SAVE LINK DATA
			var query = {"_id":"0"};
			var options = {
				multi: false,
				upsert: false
			};
			var updated = db_settings.settings.update(query, dataToSave, options);
			//  console.log(dataToSave);
			//  console.log(updated);
		}

		/** Read a single setting value from the settings DB */
		function getSettingValue(key) {
			var settings = db_settings.settings.find()[0];
			return settings ? settings[key] : undefined;
		}

		function saveLinkKey(id,key,val){
			var dataToSave = { [key] : val};
			//SAVE LINK DATA
			var query = {"_id":id};
			var options = {
				multi: false,
				upsert: false
			};
			var updated = db_links.links.update(query, dataToSave, options);
			//  console.log(dataToSave);
			//  console.log(updated);
		}

		function clearRecentList(){

			//reset last-started keys in the links.json database
			var tmp_arr =  db_links.links.find();	
			var arrlaststarted = tmp_arr.filter(function (object) { return object["last-startedUTC"] != 0;});
			
			var dataToSave={
				"last-startedUTC":0, 
				"last-started":""
			};
			var options = {
				multi: false,
				upsert: false
			};
			for(i=0; i< arrlaststarted.length ; i++){
				var query ={"_id": arrlaststarted[i]["_id"]};
				var updated = db_links.links.update(query, dataToSave, options);
			}
							
			// empty the Recent group
			$(".group-container[data-group-id='gRecent']").empty();

		}

		function historyCleanup(){
			var settings = db_settings.settings.find()[0]; //get all settings data from settings.json
			var archiveDir = settings["history-archive-folder"];
			if(archiveDir==""){archiveDir=os.tmpdir();} //if no dir is given use the default OS temp folder.
			$(".txt-history-archiveDir").val(archiveDir);
			//Set working dir for the method file browse
			$("#input-history-archiveDir").attr("nwworkingdir",archiveDir);
			if(settings["chk_settingHistoryCleanup"]==true){
				var days= parseInt(settings["history-days"]);
				var cleanup_action = settings["cleanup-action"];
				console.log("performing run history cleanup older than "+days+" days...");

				if (cleanup_action == "archive"){
					if(!fs.existsSync(archiveDir)){
						console.log("Aborted cleanup. Destination " + archiveDir + " does not exist");
						return;
					}
				}

				var counter = 0;
				fs.readdir(HxFolder_LogFiles, function(err, files) {
				if (err) {
					console.warn('Could not read log directory: ' + HxFolder_LogFiles + ' — ' + err.message);
					return;
				}
				$(".cleanup-progress-bar").text("0%").css("width","0%").attr("aria-valuenow", 0);
				$(".cleanup-progress-text").text("Cleaning up run logs");
				$(".cleanup-progress").css("display","inline"); //force display after JQuery fadeout if a previous cleanup was run
					// console.log(files.length);

					files.forEach(function(file, index) {
						var ext = path.extname(file);
							var currentPath = path.join(HxFolder_LogFiles,file);
							var bool_processFile = false;
							fs.stat(currentPath, function(err, stats) {
										if (err) {
												console.log( "error getting stat from file :" + currentPath);
										}else{
										  bool_processFile = true;
										}

									if(bool_processFile){
											var today = new Date();
											var endtime = new Date(stats.mtime);
											endtime.setDate(endtime.getDate() + days);

										if (today > endtime) {
											//   console.log(currentPath);
											  if(cleanup_action=="delete"){
												fs.unlink(currentPath, (err) => {
													counter++;
													cleanupProgress(counter, files.length);
												  if (err) {
													console.log( "error deleting file :" + currentPath);
												  }
												  //file deleted OK
												//   console.log(currentPath);
												  });
											  }
											  if(cleanup_action=="archive"){
													var destinationPath = path.join(archiveDir,file);
													fs.rename(currentPath, destinationPath, function (err) {
														counter++;
														cleanupProgress(counter, files.length);
													  if (err) {
														console.log("error moving file :" + currentPath);
													  } else {
														//file moved OK
														 console.log("Moved at first try = " + destinationPath);
													  }
													});
											  }
										}else{
											counter++;
											cleanupProgress(counter, files.length);
										}
									}else{
										counter++;
										cleanupProgress(counter, files.length);
									}
							 }); //end fs.stat						
			       });//end forEach loop
			});//end fs.readdir
			}
		}


		

		function cleanupProgress(count, total){
			var percentage = (100*count/total).toFixed(0);
			$(".cleanup-progress-bar").text(percentage + "%").css("width",percentage + "%").attr("aria-valuenow", percentage);
			if(count==total){
				$(".cleanup-progress-text").text("Run log cleanup completed!");
				setTimeout(function (){
					$(".cleanup-progress").fadeOut();
				},4000);
				
			}
		}

		function initVENUSData(){
			// VENUS paths are hardcoded — no DLL/registry lookup needed
			var HxBin = "C:\\Program Files (x86)\\HAMILTON\\Bin";

			// Helper: only set a link key if it has no value yet (preserve user customizations)
			function setDefaultLink(id, key, defaultVal) {
				var existing = db_links.links.findOne({"_id": id});
				if (!existing || !existing[key]) {
					saveLinkKey(id, key, defaultVal);
				}
			}

			setDefaultLink("bin-folder","path", HxBin);
			setDefaultLink("cfg-folder","path","C:\\Program Files (x86)\\HAMILTON\\Config");
			setDefaultLink("lbw-folder","path","C:\\Program Files (x86)\\HAMILTON\\Labware");
			setDefaultLink("lib-folder","path","C:\\Program Files (x86)\\HAMILTON\\Library");
			setDefaultLink("log-folder","path","C:\\Program Files (x86)\\HAMILTON\\LogFiles");
			setDefaultLink("met-folder","path","C:\\Program Files (x86)\\HAMILTON\\Methods");

			HxRun = HxBin + "\\" + HxRun;

			setDefaultLink("method-editor","path", HxBin + "\\" + HxMethodEditor);
			setDefaultLink("lc-editor","path",     HxBin + "\\" + HxLiquidEditor);
			setDefaultLink("lbw-editor","path",    HxBin + "\\" + HxLabwareEditor);
			setDefaultLink("hsl-editor","path",    HxBin + "\\" + HxHSLEditor);
			setDefaultLink("sysCfg-editor","path", HxBin + "\\" + HxConfigEditor);
			setDefaultLink("run-control","path",   HxRun);
			setDefaultLink("ham-version","path",   HxBin + "\\" + HxVersion);

			// Set working dir for the method file browse
			$("#input-methodfile").attr("nwworkingdir", HxFolder_Methods);

			// First-run: backup system libraries to package store for repair
			try {
				ensureSystemLibraryBackups();
			} catch(e) {
				console.warn('Error during system library backup: ' + e.message);
			}
		}


		
		//**************************************************************************************
		//******  LIBRARY PACKAGER / EXPORTER **************************************************
		//**************************************************************************************

		var AdmZip = require('adm-zip');
		var execSync = require('child_process').execSync;
		var pkg_libraryFiles = [];
		var pkg_demoMethodFiles = [];
		var pkg_iconFilePath = null;   // custom icon/image path chosen by user
		var pkg_iconAutoDetected = false;     // true if current preview is from auto-detected BMP
		var pkg_iconAutoDetectedPath = null;  // file path of the auto-detected BMP
		var pkg_iconDismissedAuto = false;    // true if user explicitly dismissed the auto-detected image
		var pkg_comRegisterDlls = [];  // DLL filenames selected for COM registration via RegAsm

		// Fit exporter container height to window
		function fitExporterHeight() {
			if($(".methods-page").hasClass("d-none")){return;}
			var exporterDiv = $(".exporter-container");
			var height = window.innerHeight - $(".header2").outerHeight();
			exporterDiv.height(height);
		}

		// ---- File input button triggers ----
		$(document).on("click", "#pkg-addLibFiles", function() {
			$("#pkg-input-libfiles").trigger("click");
		});
		$(document).on("click", "#pkg-addLibFolder", function() {
			$("#pkg-input-libfolder").trigger("click");
		});
		$(document).on("click", "#pkg-addDemoFiles", function() {
			$("#pkg-input-demofiles").trigger("click");
		});
		$(document).on("click", "#pkg-addDemoFolder", function() {
			$("#pkg-input-demofolder").trigger("click");
		});

		// ---- Icon / image picker ----
		$(document).on("click", "#pkg-pickIcon", function() {
			$("#pkg-input-icon").trigger("click");
		});

		$(document).on("change", "#pkg-input-icon", function() {
			var fileInput = this;
			if (!fileInput.files || fileInput.files.length === 0) return;
			var filePath = fileInput.files[0].path;
			$(this).val('');
			if (!filePath) return;

			try {
				// Validate it's a readable image file
				if (!fs.existsSync(filePath)) {
					alert("File not found: " + filePath);
					return;
				}
				var stats = fs.statSync(filePath);
				if (stats.size > 2 * 1024 * 1024) {
					alert("Image file is too large (max 2 MB).");
					return;
				}

				pkg_iconFilePath = filePath;
				pkg_iconAutoDetected = false;
				pkg_iconAutoDetectedPath = null;
				pkg_iconDismissedAuto = false;
				var ext = path.extname(filePath).toLowerCase();
				var mimeMap = IMAGE_MIME_MAP;
				var mime = mimeMap[ext] || 'image/png';
				var b64 = fs.readFileSync(filePath).toString('base64');

				$("#pkg-icon-preview").html('<img src="data:' + mime + ';base64,' + b64 + '">').addClass('has-image');
				$("#pkg-icon-name").text(path.basename(filePath));
				$("#pkg-removeIcon").show();
			} catch(e) {
				alert("Error loading image: " + e.message);
			}
		});

		$(document).on("click", "#pkg-removeIcon", function() {
			var wasAutoDetected = pkg_iconAutoDetected;
			pkg_iconFilePath = null;
			pkg_iconAutoDetected = false;
			pkg_iconAutoDetectedPath = null;

			$("#pkg-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
			$("#pkg-icon-name").text("No image selected");
			$("#pkg-removeIcon").hide();

			if (wasAutoDetected) {
				// User dismissed the auto-detected image — suppress re-detection until files change
				pkg_iconDismissedAuto = true;
			} else {
				// User removed a manually-chosen image — allow auto-detect to run again
				pkgAutoDetectBmpImage();
			}
		});

		// ---- Library file inputs ----
		$(document).on("change", "#pkg-input-libfiles", function() {
			var fileInput = this;
			var newDlls = [];
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && pkg_libraryFiles.indexOf(filePath) === -1) {
					pkg_libraryFiles.push(filePath);
					var baseName = path.basename(filePath);
					if (baseName.toLowerCase().endsWith('.dll')) {
						newDlls.push(baseName);
					}
				}
			}
			// Auto-check for COM registration if exactly one DLL was added in this batch
			if (newDlls.length === 1 && pkg_comRegisterDlls.indexOf(newDlls[0]) === -1) {
				pkg_comRegisterDlls.push(newDlls[0]);
			}
			pkgUpdateLibFileList();
			$(this).val('');
		});

		$(document).on("change", "#pkg-input-libfolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var files = fs.readdirSync(folderPath);
					var newDlls = [];
					files.forEach(function(file) {
						var filePath = path.join(folderPath, file);
						try {
							if (fs.statSync(filePath).isFile() && pkg_libraryFiles.indexOf(filePath) === -1) {
								pkg_libraryFiles.push(filePath);
								if (file.toLowerCase().endsWith('.dll')) {
									newDlls.push(file);
								}
							}
						} catch(e) {}
					});
					// Auto-check for COM registration if exactly one DLL was added in this batch
					if (newDlls.length === 1 && pkg_comRegisterDlls.indexOf(newDlls[0]) === -1) {
						pkg_comRegisterDlls.push(newDlls[0]);
					}
					pkgUpdateLibFileList();
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Demo method file inputs ----
		$(document).on("change", "#pkg-input-demofiles", function() {
			var fileInput = this;
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && pkg_demoMethodFiles.indexOf(filePath) === -1) {
					pkg_demoMethodFiles.push(filePath);
				}
			}
			pkgUpdateDemoFileList();
			$(this).val('');
		});

		$(document).on("change", "#pkg-input-demofolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var files = fs.readdirSync(folderPath);
					files.forEach(function(file) {
						var filePath = path.join(folderPath, file);
						try {
							if (fs.statSync(filePath).isFile() && pkg_demoMethodFiles.indexOf(filePath) === -1) {
								pkg_demoMethodFiles.push(filePath);
							}
						} catch(e) {}
					});
					pkgUpdateDemoFileList();
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Remove selected files ----
		$(document).on("click", "#pkg-removeLibFiles", function() {
			var selected = [];
			$("#pkg-lib-list .pkg-file-item.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) { return; }
			pkg_libraryFiles = pkg_libraryFiles.filter(function(f) {
				return selected.indexOf(f) === -1;
			});
			pkgUpdateLibFileList();
		});

		$(document).on("click", "#pkg-removeDemoFiles", function() {
			var selected = [];
			$("#pkg-demo-list .pkg-file-item.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) { return; }
			pkg_demoMethodFiles = pkg_demoMethodFiles.filter(function(f) {
				return selected.indexOf(f) === -1;
			});
			pkgUpdateDemoFileList();
		});

		// ---- Toggle file selection (click to select, ctrl+click for multi) ----
		$(document).on("click", ".pkg-file-item", function(e) {
			if (e.ctrlKey || e.metaKey) {
				$(this).toggleClass("selected");
			} else {
				$(this).siblings().removeClass("selected");
				$(this).toggleClass("selected");
			}
		});

		// ---- Detect library name from library files (.hsl > .hs_ > .smt hierarchy) ----
		var pkg_autoDetectedName = ""; // tracks the auto-detected name
		var pkg_nameOverridden = false; // tracks if user has overridden the name

		function pkgDetectLibraryName() {
			var libName = "";
			var extPriority = [".hsl", ".hs_", ".smt"];
			for (var p = 0; p < extPriority.length; p++) {
				for (var i = 0; i < pkg_libraryFiles.length; i++) {
					if (pkg_libraryFiles[i].toLowerCase().endsWith(extPriority[p])) {
						libName = path.basename(pkg_libraryFiles[i], path.extname(pkg_libraryFiles[i]));
						break;
					}
				}
				if (libName) break;
			}
			pkg_autoDetectedName = libName;
			if(!pkg_nameOverridden){
				$("#pkg-library-name").val(libName);
				pkgUpdatePathPlaceholders(libName);
			}
		}

		function pkgUpdatePathPlaceholders(name) {
			if(name){
				$(".pkg-path-libname").text(name);
			} else {
				$(".pkg-path-libname").html("&lt;libraryname&gt;");
			}
		}

		// ---- Auto-detect BMP image from library files ----
		function pkgAutoDetectBmpImage() {
			// Don't auto-detect if user has manually set an image
			if (pkg_iconFilePath) return;
			// Don't auto-detect if user explicitly dismissed the auto-detected image
			if (pkg_iconDismissedAuto) return;

			var libName = $("#pkg-library-name").val().trim();
			if (!libName) {
				// Clear auto-detected preview if library name is gone
				if (pkg_iconAutoDetected) {
					pkg_iconAutoDetected = false;
					pkg_iconAutoDetectedPath = null;
					$("#pkg-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
					$("#pkg-icon-name").text("No image selected");
					$("#pkg-removeIcon").hide();
				}
				return;
			}

			var targetBmp = libName + ".bmp";
			var foundPath = null;
			for (var i = 0; i < pkg_libraryFiles.length; i++) {
				if (path.basename(pkg_libraryFiles[i]).toLowerCase() === targetBmp.toLowerCase()) {
					foundPath = pkg_libraryFiles[i];
					break;
				}
			}

			if (foundPath) {
				// Already showing this exact auto-detected image — skip
				if (pkg_iconAutoDetected && pkg_iconAutoDetectedPath === foundPath) return;

				try {
					if (!fs.existsSync(foundPath)) return;
					var stats = fs.statSync(foundPath);
					if (stats.size > 2 * 1024 * 1024) return; // skip if > 2 MB

					var b64 = fs.readFileSync(foundPath).toString('base64');
					$("#pkg-icon-preview").html('<img src="data:image/bmp;base64,' + b64 + '">').addClass('has-image');
					$("#pkg-icon-name").text(path.basename(foundPath) + " (auto-detected)");
					$("#pkg-removeIcon").show();
					pkg_iconAutoDetected = true;
					pkg_iconAutoDetectedPath = foundPath;
				} catch(e) {
					// silently ignore read errors
				}
			} else if (pkg_iconAutoDetected) {
				// BMP was removed from file list — clear auto-detected preview
				pkg_iconAutoDetected = false;
				pkg_iconAutoDetectedPath = null;
				$("#pkg-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
				$("#pkg-icon-name").text("No image selected");
				$("#pkg-removeIcon").hide();
			}
		}

		// ---- Toggle name override editing ----
		$(document).on("click", "#pkg-toggle-name-edit", function() {
			var $input = $("#pkg-library-name");
			if($input.prop("readonly")){
				// Enable editing
				$input.prop("readonly", false).css({"background-color": "", "cursor": ""}).focus();
				$(this).html('<i class="fas fa-undo"></i>').attr("title", "Revert to auto-detected name");
				pkg_nameOverridden = true;
				if(pkg_autoDetectedName && $input.val() !== pkg_autoDetectedName){
					$("#pkg-name-warning").removeClass("d-none");
					$("#pkg-name-hint").addClass("d-none");
				}
			} else {
				// Revert to auto-detected
				$input.val(pkg_autoDetectedName).prop("readonly", true).css({"background-color": "#e9ecef", "cursor": "default"});
				$(this).html('<i class="fas fa-pencil-alt"></i>').attr("title", "Override auto-detected name");
				pkg_nameOverridden = false;
				$("#pkg-name-warning").addClass("d-none");
				$("#pkg-name-hint").removeClass("d-none");
				pkgUpdatePathPlaceholders(pkg_autoDetectedName);
			}
		});

		// ---- Update placeholders and warning on manual name change ----
		$(document).on("input", "#pkg-library-name", function() {
			var val = $(this).val().trim();
			pkgUpdatePathPlaceholders(val);
			if(pkg_autoDetectedName && val !== pkg_autoDetectedName){
				$("#pkg-name-warning").removeClass("d-none");
				$("#pkg-name-hint").addClass("d-none");
			} else {
				$("#pkg-name-warning").addClass("d-none");
				$("#pkg-name-hint").removeClass("d-none");
			}
		});

		// ---- Update file list displays ----
		function pkgUpdateLibFileList() {
			var $list = $("#pkg-lib-list");
			$list.empty();
			if (pkg_libraryFiles.length === 0) {
				$list.html('<div class="text-muted text-center py-3 pkg-empty-msg"><i class="fas fa-inbox mr-2"></i>No library files added</div>');
			} else {
				pkg_libraryFiles.forEach(function(f) {
					var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
					var baseName = path.basename(f);
					var isDll = baseName.toLowerCase().endsWith('.dll');
					var isChecked = pkg_comRegisterDlls.indexOf(baseName) !== -1;
					var comCheckbox = '';
					if (isDll) {
						comCheckbox = '<label class="pkg-com-checkbox-label mb-0 ml-auto mr-2" title="Register this DLL as a COM object using RegAsm.exe /codebase during import. Requires administrator rights.">' +
							'<input type="checkbox" class="pkg-com-checkbox mr-1" data-dll="' + baseName.replace(/"/g, '&quot;') + '"' + (isChecked ? ' checked' : '') + '>' +
							'<span class="text-xs text-muted">COM Register</span>' +
						'</label>';
					}
					$list.append(
						'<div class="pkg-file-item" data-path="' + escapedPath + '">' +
						'<i class="far fa-file pkg-file-icon"></i>' +
						'<span class="pkg-file-name">' + baseName + '</span>' +
						 comCheckbox +
						'<span class="pkg-file-dir">' + path.dirname(f) + '</span>' +
						'</div>'
					);
				});
			}
			$("#pkg-lib-count").text(pkg_libraryFiles.length + " file" + (pkg_libraryFiles.length !== 1 ? "s" : ""));
			pkgDetectLibraryName();
			// Reset dismiss flag when file list changes, then try auto-detect
			pkg_iconDismissedAuto = false;
			pkgAutoDetectBmpImage();
		}

		// ---- COM register checkbox handler ----
		$(document).on("change", ".pkg-com-checkbox", function(e) {
			e.stopPropagation();
			var dllName = $(this).attr("data-dll");
			if ($(this).is(":checked")) {
				if (pkg_comRegisterDlls.indexOf(dllName) === -1) {
					pkg_comRegisterDlls.push(dllName);
				}
			} else {
				pkg_comRegisterDlls = pkg_comRegisterDlls.filter(function(d) { return d !== dllName; });
			}
		});

		// Prevent checkbox click from toggling file selection
		$(document).on("click", ".pkg-com-checkbox-label", function(e) {
			e.stopPropagation();
		});

		function pkgUpdateDemoFileList() {
			var $list = $("#pkg-demo-list");
			$list.empty();
			if (pkg_demoMethodFiles.length === 0) {
				$list.html('<div class="text-muted text-center py-3 pkg-empty-msg"><i class="fas fa-inbox mr-2"></i>No demo method files added</div>');
			} else {
				pkg_demoMethodFiles.forEach(function(f) {
					var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
					$list.append(
						'<div class="pkg-file-item" data-path="' + escapedPath + '">' +
						'<i class="far fa-file pkg-file-icon"></i>' +
						'<span class="pkg-file-name">' + path.basename(f) + '</span>' +
						'<span class="pkg-file-dir">' + path.dirname(f) + '</span>' +
						'</div>'
					);
				});
			}
			$("#pkg-demo-count").text(pkg_demoMethodFiles.length + " file" + (pkg_demoMethodFiles.length !== 1 ? "s" : ""));
		}

		// ---- Reset form ----
		// Track whether Hamilton author was already authorized for this session
		var pkg_hamiltonAuthorized = false;

		// ---- Author field restriction: prompt for password when "Hamilton" is entered ----
		$(document).on("blur", "#pkg-author", async function() {
			var authorVal = $(this).val().trim();
			if (isRestrictedAuthor(authorVal) && !pkg_hamiltonAuthorized) {
				var pwOk = await promptAuthorPassword();
				if (pwOk) {
					pkg_hamiltonAuthorized = true;
				} else {
					$(this).val('');
					$(this).focus();
					pkg_hamiltonAuthorized = false;
				}
			} else if (!isRestrictedAuthor(authorVal)) {
				pkg_hamiltonAuthorized = false;
			}
		});

		$(document).on("click", "#pkg-reset", function() {
			$("#pkg-author").val('');
			$("#pkg-organization").val('');
			$("#pkg-version").val('');
			$("#pkg-venus-compat").val('');
			$("#pkg-description").val('');
			$("#pkg-tags").val('');
			$("#pkg-library-name").val('').prop("readonly", true).css({"background-color": "#e9ecef", "cursor": "default"});
			$("#pkg-toggle-name-edit").html('<i class="fas fa-pencil-alt"></i>').attr("title", "Override auto-detected name");
			$("#pkg-name-warning").addClass("d-none");
			$("#pkg-name-hint").removeClass("d-none");
			pkg_autoDetectedName = "";
			pkg_nameOverridden = false;
			pkg_hamiltonAuthorized = false;
			pkg_libraryFiles = [];
			pkg_demoMethodFiles = [];
			pkg_iconFilePath = null;
			pkg_iconAutoDetected = false;
			pkg_iconAutoDetectedPath = null;
			pkg_iconDismissedAuto = false;
			pkg_comRegisterDlls = [];
			pkgUpdateLibFileList();
			pkgUpdateDemoFileList();
			$("#pkg-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
			$("#pkg-icon-name").text("No image selected");
			$("#pkg-removeIcon").hide();
		});

		// ---- Create Package button ----
		$(document).on("click", "#pkg-create", function() {
			// Validate required fields
			var author = $("#pkg-author").val().trim();
			var version = $("#pkg-version").val().trim();

			if (!author) {
				alert("Author Name is required.");
				$("#pkg-author").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (!version) {
				alert("Library Version Number is required.");
				$("#pkg-version").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (pkg_libraryFiles.length === 0) {
				alert("Please add at least one library file.");
				return;
			}

			// Verify all files still exist
			for (var i = 0; i < pkg_libraryFiles.length; i++) {
				if (!fs.existsSync(pkg_libraryFiles[i])) {
					alert("Library file not found:\n" + pkg_libraryFiles[i]);
					return;
				}
			}
			for (var i = 0; i < pkg_demoMethodFiles.length; i++) {
				if (!fs.existsSync(pkg_demoMethodFiles[i])) {
					alert("Demo method file not found:\n" + pkg_demoMethodFiles[i]);
					return;
				}
			}

			// Warn if DLLs exist in library files but none are selected for COM registration
			var dllsInLibrary = pkg_libraryFiles.filter(function(f) {
				return path.basename(f).toLowerCase().endsWith('.dll');
			});
			if (dllsInLibrary.length > 0 && pkg_comRegisterDlls.length === 0) {
				if (!confirm("No DLL files are targeted to be registered as COM objects. Are you sure you want to continue?")) {
					return;
				}
			}

			// Use library name from the detected field
			var libName = $("#pkg-library-name").val().trim() || "Unknown";

			// Set default filename and trigger save dialog
			$("#pkg-save-dialog").attr("nwsaveas", libName + ".hxlibpkg");
			$("#pkg-save-dialog").trigger("click");
		});

		// Clear red styling when user types in required fields
		$(document).on("input", "#pkg-author, #pkg-version", function() {
			$(this).css({"border": "", "background": ""});
		});

		// ---- Save dialog result ----
		$(document).on("change", "#pkg-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			pkgCreatePackageFile(savePath);
		});

		// ---- Static asset paths ----
		var ASSETS_DIR = path.join(nw.__dirname, 'assets');
		var LM_LOGO_GRAY_PATH = path.join(ASSETS_DIR, 'app_logo_gray_128.png');
		var ARCHIVE_ICON_PATH = path.join(ASSETS_DIR, 'archive_icon_128.png');

		// ---- Composite library icon: overlay grayscale LM logo on bottom 1/3 ----
		// Returns a Promise that resolves to { base64, mime } (always PNG output).
		// If sourceB64/sourceMime are provided, the user's image fills the canvas
		// and the pre-rendered grayscale logo is drawn in the bottom-right corner.
		// If no source image is provided, the grayscale logo fills the full canvas.
		function pkgCompositeLibraryIcon(sourceB64, sourceMime) {
			return new Promise(function(resolve, reject) {
				var SIZE = 128;

				if (!fs.existsSync(LM_LOGO_GRAY_PATH)) {
					// No logo asset — pass through source image as-is
					resolve({ base64: sourceB64 || null, mime: sourceMime || null });
					return;
				}

				var logoB64 = fs.readFileSync(LM_LOGO_GRAY_PATH).toString('base64');
				var logoImg = new Image();
				logoImg.onload = function() {
					if (sourceB64 && sourceMime) {
						// User provided an image — composite with logo overlay
						var userImg = new Image();
						userImg.onload = function() {
							try {
								var canvas = document.createElement('canvas');
								canvas.width = SIZE;
								canvas.height = SIZE;
								var ctx = canvas.getContext('2d');

								// Draw user image scaled to fill
								ctx.drawImage(userImg, 0, 0, SIZE, SIZE);

								// Draw pre-rendered grayscale logo in bottom-right corner
								var logoSize = Math.round(SIZE / 3);
								var x = SIZE - logoSize - 2;
								var y = SIZE - logoSize - 2;

								// Semi-transparent white backing for readability
								ctx.globalAlpha = 0.55;
								ctx.fillStyle = '#ffffff';
								ctx.beginPath();
								ctx.arc(x + logoSize / 2, y + logoSize / 2, logoSize / 2 + 2, 0, Math.PI * 2);
								ctx.fill();
								ctx.globalAlpha = 1.0;

								ctx.drawImage(logoImg, x, y, logoSize, logoSize);

								var dataUrl = canvas.toDataURL('image/png');
								var b64 = dataUrl.replace(/^data:image\/png;base64,/, '');
								resolve({ base64: b64, mime: 'image/png' });
							} catch(e) {
								reject(e);
							}
						};
						userImg.onerror = function() { reject(new Error('Failed to load user image')); };
						userImg.src = 'data:' + sourceMime + ';base64,' + sourceB64;
					} else {
						// No user image — use grayscale logo at full size
						try {
							var canvas = document.createElement('canvas');
							canvas.width = SIZE;
							canvas.height = SIZE;
							var ctx = canvas.getContext('2d');
							ctx.drawImage(logoImg, 0, 0, SIZE, SIZE);

							var dataUrl = canvas.toDataURL('image/png');
							var b64 = dataUrl.replace(/^data:image\/png;base64,/, '');
							resolve({ base64: b64, mime: 'image/png' });
						} catch(e) {
							reject(e);
						}
					}
				};
				logoImg.onerror = function() {
					resolve({ base64: sourceB64 || null, mime: sourceMime || null });
				};
				logoImg.src = 'data:image/png;base64,' + logoB64;
			});
		}

		// ---- Core packaging function ----
		async function pkgCreatePackageFile(savePath) {
			try {
				var author = $("#pkg-author").val().trim();

				// Check restricted author name
				if (isRestrictedAuthor(author)) {
					var pwOk = await promptAuthorPassword();
					if (!pwOk) {
						alert('Package creation cancelled. The author name "Hamilton" requires authorization.');
						return;
					}
				}
				var organization = $("#pkg-organization").val().trim();
				var version = $("#pkg-version").val().trim();
				var venusCompat = $("#pkg-venus-compat").val().trim();
				var description = $("#pkg-description").val().trim();
				var tagsRaw = $("#pkg-tags").val().trim();

				// Parse tags
				var tags = [];
				if (tagsRaw) {
					tagsRaw.split(",").forEach(function(t) {
						t = t.trim();
						if (t) tags.push(t);
					});
				}

				// Use library name from the detected field
				var libName = $("#pkg-library-name").val().trim() || "Unknown";

				// Find matching BMP image (same name as .hsl file) — auto-detect fallback
				var libImageFilename = null;
				var libImageBase64 = null;
				var libImageMime = null;

				// Priority 1: custom icon chosen by user
				if (pkg_iconFilePath && fs.existsSync(pkg_iconFilePath)) {
					try {
						libImageFilename = path.basename(pkg_iconFilePath);
						libImageBase64 = fs.readFileSync(pkg_iconFilePath).toString('base64');
						var ext = path.extname(pkg_iconFilePath).toLowerCase();
						libImageMime = IMAGE_MIME_MAP[ext] || 'image/png';
					} catch(e) {
						libImageFilename = null;
						libImageBase64 = null;
						libImageMime = null;
					}
				}

				// Priority 2: auto-detect BMP matching .hsl name
				if (!libImageBase64 && libName !== "Unknown") {
					var targetBmp = libName + ".bmp";
					for (var i = 0; i < pkg_libraryFiles.length; i++) {
						if (path.basename(pkg_libraryFiles[i]).toLowerCase() === targetBmp.toLowerCase()) {
							try {
								libImageFilename = path.basename(pkg_libraryFiles[i]);
								libImageBase64 = fs.readFileSync(pkg_libraryFiles[i]).toString('base64');
								libImageMime = 'image/bmp';
							} catch(e) {}
							break;
						}
					}
				}

				// ---- Composite the library icon with grayscale LM logo overlay ----
				// If user provided an image: overlay grayscale logo on bottom-right 1/3.
				// If no image: use full-size grayscale logo.
				try {
					var composited = await pkgCompositeLibraryIcon(libImageBase64, libImageMime);
					if (composited && composited.base64) {
						libImageBase64 = composited.base64;
						libImageMime = composited.mime || 'image/png';
						libImageFilename = libImageFilename || (libName + '_icon.png');
						// Ensure filename ends in .png since composite always outputs PNG
						if (libImageFilename && !libImageFilename.toLowerCase().endsWith('.png')) {
							libImageFilename = libImageFilename.replace(/\.[^.]+$/, '.png');
						}
					}
				} catch(e) {
					// Compositing failed — use the raw image as-is (non-critical)
					console.warn('Icon compositing failed:', e);
				}

				// Build manifest JSON (matches C# HxLibPkgManifest.ToJson() format)
				var manifest = {
					format_version: "1.0",
					library_name: libName,
					author: author,
					organization: organization,
					version: version,
					venus_compatibility: venusCompat,
					description: description,
					tags: tags,
					created_date: new Date().toISOString(),
					library_image: libImageFilename,
					library_image_base64: libImageBase64,
					library_image_mime: libImageMime,
					library_files: pkg_libraryFiles.map(function(f) { return path.basename(f); }),
					demo_method_files: pkg_demoMethodFiles.map(function(f) { return path.basename(f); }),
					com_register_dlls: pkg_comRegisterDlls.slice()
				};

				// Create ZIP package using adm-zip
				var zip = new AdmZip();

				// Add manifest.json
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files under library/ directory
				pkg_libraryFiles.forEach(function(fpath) {
					zip.addLocalFile(fpath, "library");
				});

				// Add custom icon under icon/ directory (composited PNG)
				if (libImageBase64) {
					var iconFilename = libImageFilename || (libName + '_icon.png');
					zip.addFile("icon/" + iconFilename, Buffer.from(libImageBase64, 'base64'));
				}

				// Add demo method files under demo_methods/ directory
				pkg_demoMethodFiles.forEach(function(fpath) {
					zip.addLocalFile(fpath, "demo_methods");
				});

				// Sign the package for integrity verification
				signPackageZip(zip);

				// Write the ZIP file
				zip.writeZip(savePath);

				alert("Package created successfully!\n\n" +
					savePath + "\n\n" +
					"Library: " + libName + "\n" +
					"Library files: " + pkg_libraryFiles.length + "\n" +
					"Demo method files: " + pkg_demoMethodFiles.length);

			} catch(e) {
				alert("Error creating package:\n" + e.message);
			}
		}

		//**************************************************************************************
		//******  COM REGISTRATION HELPERS *****************************************************
		//**************************************************************************************

		/**
		 * Finds RegAsm.exe from the .NET Framework directory.
		 * Returns the full path to RegAsm.exe or null if not found.
		 */
		function findRegAsmPath() {
			// Always use the 32-bit (x86) .NET Framework – Hamilton VENUS is a 32-bit application
			var frameworkDir = "C:\\Windows\\Microsoft.NET\\Framework\\";
			if (!fs.existsSync(frameworkDir)) return null;

			// Find the latest version directory containing RegAsm.exe
			var dirs = fs.readdirSync(frameworkDir).filter(function(d) {
				return d.match(/^v\d/);
			}).sort().reverse();

			for (var i = 0; i < dirs.length; i++) {
				var regasm = path.join(frameworkDir, dirs[i], "RegAsm.exe");
				if (fs.existsSync(regasm)) return regasm;
			}
			return null;
		}

		/**
		 * Registers or unregisters a DLL using RegAsm.exe /codebase with UAC elevation.
		 * Uses a temporary batch script to avoid nested shell-escaping issues and to
		 * capture RegAsm output for meaningful error messages.
		 * @param {string} dllPath - Full path to the DLL file
		 * @param {boolean} register - true to register, false to unregister
		 * @returns {Promise<{success: boolean, error: string}>}
		 */
		function comRegisterDll(dllPath, register) {
			return new Promise(function(resolve) {
				var regasm = findRegAsmPath();
				if (!regasm) {
					resolve({success: false, error: "RegAsm.exe not found in .NET Framework directory."});
					return;
				}

				if (!fs.existsSync(dllPath)) {
					resolve({success: false, error: "DLL file not found: " + dllPath});
					return;
				}

				var os = require('os');
				var tmpDir = os.tmpdir();
				var stamp = Date.now() + '_' + Math.random().toString(36).slice(2, 8);
				var outFile = path.join(tmpDir, 'lm_regasm_' + stamp + '.log');
				var scriptFile = path.join(tmpDir, 'lm_regasm_' + stamp + '.cmd');

				// Build a batch script that runs RegAsm and captures all output.
				// This avoids deeply nested escaping of paths with spaces / parentheses.
				var regasmArgs = register
					? '"' + dllPath + '" /codebase'
					: '/u "' + dllPath + '" /codebase';

				var batContent = '@echo off\r\n"' + regasm + '" ' + regasmArgs + ' > "' + outFile + '" 2>&1\r\nexit /b %errorlevel%\r\n';
				fs.writeFileSync(scriptFile, batContent, 'utf8');

				// Elevate the batch script via PowerShell Start-Process -Verb RunAs.
				// The script path is in %TEMP% which should never contain single-quote chars.
				var psScript = "try { $p = Start-Process -FilePath '" + scriptFile + "' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode } catch { exit 1 }";
				var fullCmd = 'powershell.exe -NoProfile -Command "' + psScript + '"';

				var exec = require('child_process').exec;
				exec(fullCmd, {timeout: 30000}, function(error, stdout, stderr) {
					// Read captured RegAsm output
					var regasmOutput = '';
					try { regasmOutput = fs.readFileSync(outFile, 'utf8').trim(); } catch(e) { /* file may not exist if UAC was cancelled */ }
					// Clean up temp files
					try { fs.unlinkSync(outFile); } catch(e) {}
					try { fs.unlinkSync(scriptFile); } catch(e) {}

					if (error) {
						var errMsg = "COM " + (register ? "registration" : "deregistration") + " failed for " + path.basename(dllPath) + ".\n";
						if (error.killed) {
							errMsg += "Operation timed out.";
						} else if (error.code === 1 && !regasmOutput) {
							errMsg += "The operation was cancelled or requires administrator rights.";
						} else if (regasmOutput) {
							errMsg += regasmOutput;
						} else {
							errMsg += "Exit code: " + error.code + ". " + (stderr || stdout || "No additional details available.");
						}
						resolve({success: false, error: errMsg});
					} else {
						resolve({success: true, error: null});
					}
				});
			});
		}

		/**
		 * Registers multiple DLLs sequentially. Returns result summary.
		 * @param {Array<string>} dllPaths - Full paths to DLL files
		 * @param {boolean} register - true to register, false to unregister
		 * @returns {Promise<{allSuccess: boolean, results: Array}>}
		 */
		async function comRegisterMultipleDlls(dllPaths, register) {
			var results = [];
			var allSuccess = true;
			for (var i = 0; i < dllPaths.length; i++) {
				var result = await comRegisterDll(dllPaths[i], register);
				results.push({dll: dllPaths[i], success: result.success, error: result.error});
				if (!result.success) allSuccess = false;
			}
			return {allSuccess: allSuccess, results: results};
		}

		//**************************************************************************************
		//******  LIBRARY IMPORTER *************************************************************
		//**************************************************************************************

		var imp_manifest = null;
		var imp_zipData = null;
		var imp_filePath = null;

		// ---- HSL function parser — extracts public function signatures ----
		// Ported from the VS Code HSL IntelliSense extension.

		/**
		 * Strip string literals and comments from HSL source so that keyword
		 * searches (namespace, function) are not confused by content inside strings/comments.
		 */
		function sanitizeHslForParsing(text) {
			var chars = text.split('');
			var i = 0;
			while (i < chars.length) {
				var ch = chars[i];
				var next = (i + 1 < chars.length) ? chars[i + 1] : '';

				if (ch === '"') {
					chars[i] = ' ';
					var j = i + 1;
					while (j < chars.length) {
						var c = chars[j];
						if (c === '\\' && j + 1 < chars.length) { chars[j] = ' '; chars[j + 1] = ' '; j += 2; continue; }
						chars[j] = (c === '\n' || c === '\r') ? c : ' ';
						if (c === '"') { j++; break; }
						j++;
					}
					i = j; continue;
				}
				if (ch === '/' && next === '/') {
					chars[i] = ' '; chars[i + 1] = ' '; i += 2;
					while (i < chars.length && chars[i] !== '\n') { chars[i] = ' '; i++; }
					continue;
				}
				if (ch === '/' && next === '*') {
					chars[i] = ' '; chars[i + 1] = ' '; i += 2;
					while (i < chars.length) {
						if (chars[i] === '*' && i + 1 < chars.length && chars[i + 1] === '/') { chars[i] = ' '; chars[i + 1] = ' '; i += 2; break; }
						chars[i] = (chars[i] === '\n' || chars[i] === '\r') ? chars[i] : ' ';
						i++;
					}
					continue;
				}
				i++;
			}
			return chars.join('');
		}

		function splitHslArgs(paramList) {
			var parts = [];
			var current = '';
			var depth = 0;
			for (var ci = 0; ci < paramList.length; ci++) {
				var c = paramList[ci];
				if (c === '(') { depth++; current += c; continue; }
				if (c === ')') { depth = Math.max(0, depth - 1); current += c; continue; }
				if (c === ',' && depth === 0) { parts.push(current.trim()); current = ''; continue; }
				current += c;
			}
			if (current.trim().length > 0) parts.push(current.trim());
			return parts;
		}

		function parseHslParameter(param) {
			var trimmed = param.trim();
			var rawNoDefault = trimmed.indexOf('=') !== -1 ? trimmed.slice(0, trimmed.indexOf('=')).trim() : trimmed;
			var isArray = /\[\]\s*$/.test(rawNoDefault);
			var noArray = rawNoDefault.replace(/\[\]\s*$/, '').trim();
			var nameMatch = /([A-Za-z_]\w*)\s*$/.exec(noArray);
			var nameText = nameMatch ? nameMatch[1] : noArray;
			var beforeName = nameMatch ? noArray.slice(0, nameMatch.index).trim() : '';
			var isByRef = beforeName.indexOf('&') !== -1;
			beforeName = beforeName.replace(/&/g, '').trim();
			return { type: beforeName || 'variable', name: nameText, byRef: isByRef, array: isArray };
		}

		function extractHslDocComment(originalLines, functionStartLine) {
			var i = functionStartLine - 1;
			while (i >= 0 && originalLines[i].trim() === '') i--;
			if (i < 0) return '';
			var line = originalLines[i].trim();
			if (line.indexOf('//') === 0) {
				var buf = [];
				while (i >= 0 && originalLines[i].trim().indexOf('//') === 0) {
					buf.push(originalLines[i].trim().replace(/^\/\/\s?/, ''));
					i--;
				}
				buf.reverse();
				return buf.join('\n').trim();
			}
			if (line.indexOf('*/') !== -1) {
				var buf = [];
				while (i >= 0) {
					buf.push(originalLines[i]);
					if (originalLines[i].indexOf('/*') !== -1) break;
					i--;
				}
				buf.reverse();
				return buf.join('\n').replace(/^\s*\/\*+/, '').replace(/\*+\/\s*$/, '')
					.split(/\r?\n/).map(function(s) { return s.replace(/^\s*\*\s?/, ''); }).join('\n').trim();
			}
			return '';
		}

		/**
		 * Parse all functions from an HSL source string.
		 * Returns array of { name, qualifiedName, params, returnType, doc, isPrivate, file }.
		 */
		function parseHslFunctions(text, fileName) {
			var sanitized = sanitizeHslForParsing(text);
			var originalLines = text.split(/\r?\n/);
			var cleanLines = sanitized.split(/\r?\n/);
			var functions = [];
			var namespaceStack = [];
			var braceDepth = 0;
			var pendingNamespace = null;
			var collectingFunction = false;
			var functionStartLine = -1;
			var functionHeaderParts = [];

			for (var lineIndex = 0; lineIndex < cleanLines.length; lineIndex++) {
				var cleanLine = cleanLines[lineIndex];
				var originalLine = originalLines[lineIndex] || '';

				if (!collectingFunction) {
					var nsMatch = /^\s*(?:(?:private|public|static|global|const|synchronized)\s+)*namespace\s+([A-Za-z_]\w*)\b/.exec(cleanLine);
					if (nsMatch) pendingNamespace = nsMatch[1];
					if (/^\s*(?:(?:private|public|static|global|const|synchronized)\s+)*function\b/.test(cleanLine)) {
						collectingFunction = true;
						functionStartLine = lineIndex;
						functionHeaderParts = [originalLine];
					}
				} else {
					functionHeaderParts.push(originalLine);
				}

				if (collectingFunction) {
					var joinedClean = sanitizeHslForParsing(functionHeaderParts.join('\n'));
					var openCount = (joinedClean.match(/\(/g) || []).length;
					var closeCount = (joinedClean.match(/\)/g) || []).length;
					if (openCount - closeCount <= 0 && /[;{]/.test(joinedClean)) {
						var joinedOriginal = functionHeaderParts.join('\n');
						var fnMatch = /^\s*((?:(?:private|public|static|global|const|synchronized)\s+)*)function\s+([A-Za-z_]\w*)\s*\(([\s\S]*?)\)\s*([A-Za-z_]\w*)\s*(?:;|\{)/m.exec(joinedOriginal);
						if (fnMatch) {
							var modifiers = fnMatch[1] || '';
							var name = fnMatch[2];
							var paramsRaw = fnMatch[3] || '';
							var returnType = fnMatch[4] || 'variable';
							var isPrivate = /\bprivate\b/.test(modifiers);
							var params = splitHslArgs(paramsRaw).filter(function(p) { return p.length > 0; }).map(parseHslParameter);
							var nsPrefix = namespaceStack.map(function(n) { return n.name; }).join('::');
							var qualifiedName = nsPrefix.length > 0 ? nsPrefix + '::' + name : name;
							var doc = extractHslDocComment(originalLines, functionStartLine);
							functions.push({ name: name, qualifiedName: qualifiedName, params: params, returnType: returnType, doc: doc, isPrivate: isPrivate, file: fileName || '' });
						}
						collectingFunction = false;
						functionStartLine = -1;
						functionHeaderParts = [];
					}
				}

				for (var ci = 0; ci < cleanLine.length; ci++) {
					var ch = cleanLine[ci];
					if (ch === '{') {
						braceDepth++;
						if (pendingNamespace) { namespaceStack.push({ name: pendingNamespace, depth: braceDepth }); pendingNamespace = null; }
					} else if (ch === '}') {
						while (namespaceStack.length > 0 && namespaceStack[namespaceStack.length - 1].depth >= braceDepth) namespaceStack.pop();
						braceDepth = Math.max(0, braceDepth - 1);
					}
				}
			}
			return functions;
		}

		/**
		 * Extract public functions from all .hsl files in the given directory.
		 * @param {Array<string>} libFiles - filenames array
		 * @param {string} libBasePath - base directory for library files
		 * @returns {Array} array of public function descriptors
		 */
		function extractPublicFunctions(libFiles, libBasePath) {
			var allFunctions = [];
			(libFiles || []).forEach(function(fname) {
				var ext = path.extname(fname).toLowerCase();
				if (ext !== '.hsl') return;
				var fullPath = path.join(libBasePath, fname);
				try {
					var text = fs.readFileSync(fullPath, 'utf8');
					var fns = parseHslFunctions(text, fname);
					fns.forEach(function(fn) {
						if (!fn.isPrivate) {
							allFunctions.push({
								name: fn.name, qualifiedName: fn.qualifiedName,
								params: fn.params, returnType: fn.returnType,
								doc: fn.doc, file: fn.file
							});
						}
					});
				} catch(e) { /* skip unreadable files */ }
			});
			return allFunctions;
		}

		// ---- Required dependency scanning ----
		/**
		 * Extract all #include directives from an HSL source string.
		 * Returns array of raw include targets (the path inside the quotes).
		 * @param {string} text - HSL source code
		 * @returns {Array<string>} raw include target strings
		 */
		function extractHslIncludes(text) {
			var includes = [];
			var pattern = /^\s*#include\s+"([^"]+)"/gm;
			var m;
			while ((m = pattern.exec(text)) !== null) {
				includes.push(m[1].trim());
			}
			return includes;
		}

		/**
		 * Extract all required dependencies from a library's .hsl files.
		 * Scans every .hsl file for #include directives, resolves each to a
		 * library name (user-installed, system, or unknown), and returns a
		 * deduplicated list of dependency descriptors.
		 *
		 * @param {Array<string>} libFiles   - filenames array for this library
		 * @param {string}        libBasePath - base directory for library files
		 * @returns {Array<Object>} array of { include, resolvedFile, libraryName, type }
		 *   type: "self" | "user" | "system" | "unknown"
		 */
		function extractRequiredDependencies(libFiles, libBasePath) {
			// Resolve the library root folder
			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

			// Build set of this library's own filenames (lowercase for matching)
			var ownFiles = {};
			(libFiles || []).forEach(function(f) {
				ownFiles[f.toLowerCase()] = true;
				// Also store just the filename without extension for matching
				var baseName = path.basename(f).toLowerCase();
				ownFiles[baseName] = true;
			});

			// Collect all includes across all .hsl files in this library
			var allIncludes = [];
			(libFiles || []).forEach(function(fname) {
				var ext = path.extname(fname).toLowerCase();
				if (ext !== '.hsl' && ext !== '.hs_') return;
				var fullPath = path.join(libBasePath, fname);
				try {
					var text = fs.readFileSync(fullPath, 'utf8');
					var includes = extractHslIncludes(text);
					includes.forEach(function(inc) {
						allIncludes.push({ include: inc, sourceFile: fname });
					});
				} catch(e) { /* skip unreadable files */ }
			});

			// Deduplicate by normalized include target
			var seen = {};
			var uniqueIncludes = [];
			allIncludes.forEach(function(item) {
				var normalized = item.include.replace(/\\/g, '/').toLowerCase();
				if (!seen[normalized]) {
					seen[normalized] = true;
					uniqueIncludes.push(item);
				}
			});

			// Resolve each include to a library
			var dependencies = [];
			uniqueIncludes.forEach(function(item) {
				var rawTarget = item.include;
				var normalizedTarget = rawTarget.replace(/\\/g, '/');
				var targetFileName = normalizedTarget.split('/').pop().toLowerCase();

				// Skip self-references (includes pointing to files within this library)
				if (ownFiles[targetFileName]) return;
				var relLower = rawTarget.replace(/\\/g, '/').toLowerCase();
				var isSelf = false;
				for (var key in ownFiles) {
					if (relLower.indexOf(key) !== -1 && key.indexOf('.') !== -1) {
						isSelf = true;
						break;
					}
				}
				if (isSelf) return;

				// Try to resolve the actual file on disk
				var resolvedPath = null;
				var isAbsolute = /^[A-Za-z]:[\\/]/.test(rawTarget);
				if (isAbsolute) {
					var candidate = path.normalize(rawTarget);
					if (fs.existsSync(candidate)) resolvedPath = candidate;
				} else {
					// Try relative to library root
					var candidate = path.join(sysLibDir, rawTarget);
					if (fs.existsSync(candidate)) resolvedPath = candidate;
				}

				// Determine which library this include belongs to
				var libraryName = null;
				var depType = 'unknown';

				// 1) Check user-installed libraries
				var installedLibs = db_installed_libs.installed_libs.find() || [];
				for (var i = 0; i < installedLibs.length; i++) {
					var uLib = installedLibs[i];
					if (uLib.deleted) continue;
					var uLibFiles = uLib.library_files || [];
					var uBasePath = uLib.lib_install_path || '';
					for (var j = 0; j < uLibFiles.length; j++) {
						var uFullPath = path.join(uBasePath, uLibFiles[j]);
						var uNorm = uFullPath.replace(/\\/g, '/').toLowerCase();
						if (resolvedPath && resolvedPath.replace(/\\/g, '/').toLowerCase() === uNorm) {
							libraryName = uLib.library_name;
							depType = 'user';
							break;
						}
						// Also check by filename match
						if (uLibFiles[j].toLowerCase() === targetFileName) {
							libraryName = uLib.library_name;
							depType = 'user';
							break;
						}
					}
					if (libraryName) break;
				}

				// 2) Check system libraries
				if (!libraryName) {
					var sysLibs = getAllSystemLibraries();
					for (var si = 0; si < sysLibs.length; si++) {
						var sLib = sysLibs[si];
						var discoveredFiles = sLib.discovered_files || [];
						for (var di = 0; di < discoveredFiles.length; di++) {
							var sRelPath = discoveredFiles[di].replace(/^Library[\\\/]/i, '');
							var sNorm = sRelPath.replace(/\\/g, '/').toLowerCase();
							var sFileName = sNorm.split('/').pop();
							if (sFileName === targetFileName) {
								libraryName = sLib.display_name || sLib.canonical_name;
								depType = 'system';
								break;
							}
							// Also compare full resolved path
							if (resolvedPath) {
								var sFullPath = path.join(sysLibDir, sRelPath).replace(/\\/g, '/').toLowerCase();
								if (resolvedPath.replace(/\\/g, '/').toLowerCase() === sFullPath) {
									libraryName = sLib.display_name || sLib.canonical_name;
									depType = 'system';
									break;
								}
							}
						}
						if (libraryName) break;
					}
				}

				dependencies.push({
					include: rawTarget,
					resolvedFile: resolvedPath,
					libraryName: libraryName || targetFileName,
					type: depType,
					fileExists: !!resolvedPath
				});
			});

			// Deduplicate by libraryName (keep unique dependency libraries)
			var depByLib = {};
			var result = [];
			dependencies.forEach(function(dep) {
				var key = (dep.libraryName || dep.include).toLowerCase();
				if (!depByLib[key]) {
					depByLib[key] = dep;
					result.push(dep);
				} else {
					// If we already have this library, accumulate includes
					if (!depByLib[key].allIncludes) {
						depByLib[key].allIncludes = [depByLib[key].include];
					}
					depByLib[key].allIncludes.push(dep.include);
				}
			});

			return result;
		}

		/**
		 * Check if any required dependencies are missing (file not found on disk).
		 * @param {Array<Object>} deps - dependency list from extractRequiredDependencies
		 * @returns {Object} { valid: boolean, missing: Array<Object>, found: Array<Object> }
		 */
		function checkDependencyStatus(deps) {
			var result = { valid: true, missing: [], found: [] };
			(deps || []).forEach(function(dep) {
				if (dep.type === 'unknown' || !dep.fileExists) {
					result.valid = false;
					result.missing.push(dep);
				} else {
					result.found.push(dep);
				}
			});
			return result;
		}

		// ---- Library integrity hashing ----
		/**
		 * Computes SHA-256 hash of a file.
		 * For .hsl, .hs_, .sub files: hashes ALL BUT THE LAST LINE.
		 * For .dll files: hashes the entire file.
		 * @param {string} filePath - Full path to the file
		 * @returns {string|null} hex hash string or null if file not found
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
					// Remove last line (may contain timestamp or checksum that changes)
					if (lines.length > 1) {
						lines.pop();
					}
					hash.update(lines.join('\n'), 'utf8');
				} else {
					// Hash entire file (for .dll and others)
					var buf = fs.readFileSync(filePath);
					hash.update(buf);
				}
				return hash.digest('hex');
			} catch(e) {
				console.error('Hash error for ' + filePath + ': ' + e.message);
				return null;
			}
		}

		/**
		 * Extensions that carry Hamilton's metadata footer ($$author=...$$valid=...$$checksum=...$$).
		 */
		var HSL_METADATA_EXTS = ['.hsl', '.hs_', '.smt'];

		/**
		 * Parse the Hamilton HSL metadata footer from the last non-empty line of a file.
		 * The footer format: // $$author=NAME$$valid=0|1$$time=TIMESTAMP$$checksum=HEX$$length=NNN$$
		 *
		 * @param {string} filePath - full path to the file
		 * @returns {Object|null} { author, valid, time, checksum, length, raw } or null if no footer
		 */
		function parseHslMetadataFooter(filePath) {
			try {
				if (!fs.existsSync(filePath)) return null;
				var text = fs.readFileSync(filePath, 'utf8');
				var lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
				// Walk backwards to find the footer line
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
			} catch(e) {
				console.error('Footer parse error for ' + filePath + ': ' + e.message);
				return null;
			}
		}

		/**
		 * Verifies the integrity of a system library by checking Hamilton's
		 * built-in $$valid$$ flag and $$checksum$$ in the metadata footer.
		 * Only HSL-type files (.hsl, .hs_, .smt) with footers are tracked.
		 *
		 * @param {Object} sLib - system library record from system_libraries.json
		 * @returns {Object} { valid: boolean, errors: Array<string>, warnings: Array<string> }
		 */
		function verifySystemLibraryIntegrity(sLib) {
			var result = { valid: true, errors: [], warnings: [] };
			var libName = sLib.canonical_name || sLib.library_name;
			var baselineEntry = systemLibraryBaseline[libName];

			if (!baselineEntry || !baselineEntry.files || Object.keys(baselineEntry.files).length === 0) {
				result.warnings.push('No integrity baseline stored for system library: ' + libName);
				return result;
			}

			// Resolve the VENUS Library directory
			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

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
					result.errors.push('Valid flag changed (1\u21920): ' + fname);
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
		 * Computes hashes for all library files (.hsl, .hs_, .sub) and registered .dll files.
		 * @param {Array<string>} libraryFiles - filenames array
		 * @param {string} libBasePath - base directory for library files
		 * @param {Array<string>} comDlls - COM registered DLL filenames
		 * @returns {Object} map of filename -> sha256 hex hash
		 */
		function computeLibraryHashes(libraryFiles, libBasePath, comDlls) {
			var hashes = {};
			var hashableExts = ['.hsl', '.hs_', '.sub'];
			(libraryFiles || []).forEach(function(f) {
				var ext = path.extname(f).toLowerCase();
				var isDll = (comDlls || []).indexOf(f) !== -1;
				if (hashableExts.indexOf(ext) !== -1 || isDll) {
					var fullPath = path.join(libBasePath, f);
					var h = computeFileHash(fullPath);
					if (h) hashes[f] = h;
				}
			});
			return hashes;
		}

		// ---------------------------------------------------------------------------
		// Package signing — HMAC-SHA256 integrity signatures for .hxlibpkg files
		// ---------------------------------------------------------------------------

		var PKG_SIGNING_KEY = 'VenusLibMgr::PackageIntegrity::a7e3f9d1c6b2';

		/**
		 * Compute SHA-256 hashes of all entries in an AdmZip instance (excluding signature.json).
		 * Returns a sorted object of { entryName: sha256hex }.
		 */
		function computeZipEntryHashes(zip) {
			var hashes = {};
			zip.getEntries().forEach(function(entry) {
				if (entry.isDirectory) return;
				if (entry.entryName === 'signature.json') return;
				var hash = crypto.createHash('sha256').update(entry.getData()).digest('hex');
				hashes[entry.entryName] = hash;
			});
			var sorted = {};
			Object.keys(hashes).sort().forEach(function(k) { sorted[k] = hashes[k]; });
			return sorted;
		}

		/**
		 * Sign a package ZIP by computing HMAC-SHA256 over all file hashes and embedding
		 * a signature.json entry. Call AFTER all entries are added and BEFORE writing.
		 * @param {AdmZip} zip - The AdmZip instance to sign (modified in place)
		 * @returns {Object} The signature object that was embedded
		 */
		function signPackageZip(zip) {
			var fileHashes = computeZipEntryHashes(zip);
			var payload = JSON.stringify(fileHashes);
			var hmac = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(payload).digest('hex');

			var signature = {
				format_version: '1.0',
				algorithm:      'HMAC-SHA256',
				signed_date:    new Date().toISOString(),
				file_hashes:    fileHashes,
				hmac:           hmac
			};

			try { zip.deleteFile('signature.json'); } catch(e) {}
			zip.addFile('signature.json', Buffer.from(JSON.stringify(signature, null, 2), 'utf8'));
			return signature;
		}

		/**
		 * Verify the integrity signature of a package ZIP.
		 * @param {AdmZip} zip - The AdmZip instance to verify
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
			} catch(e) {
				result.valid = false;
				result.errors.push('signature.json is malformed: ' + e.message);
				return result;
			}

			if (!sig.file_hashes || !sig.hmac) {
				result.valid = false;
				result.errors.push('signature.json is missing required fields (file_hashes or hmac).');
				return result;
			}

			// Recompute HMAC over stored file_hashes
			var storedPayload = JSON.stringify(sig.file_hashes);
			var expectedHmac  = crypto.createHmac('sha256', PKG_SIGNING_KEY).update(storedPayload).digest('hex');
			if (sig.hmac !== expectedHmac) {
				result.valid = false;
				result.errors.push('HMAC mismatch \u2014 signature.json has been tampered with.');
				return result;
			}

			// Verify each file hash against actual ZIP content
			var actualHashes = computeZipEntryHashes(zip);
			var sigFiles = Object.keys(sig.file_hashes);
			var actualFiles = Object.keys(actualHashes);

			sigFiles.forEach(function(f) {
				if (!actualHashes[f]) {
					result.valid = false;
					result.errors.push('File listed in signature but missing from package: ' + f);
				} else if (actualHashes[f] !== sig.file_hashes[f]) {
					result.valid = false;
					result.errors.push('File hash mismatch (corrupted or modified): ' + f);
				}
			});

			actualFiles.forEach(function(f) {
				if (!sig.file_hashes[f]) {
					result.valid = false;
					result.errors.push('File present in package but not in signature (injected): ' + f);
				}
			});

			return result;
		}

		/**
		 * Verifies the integrity of installed library files against stored hashes.
		 * @param {Object} lib - installed library DB record
		 * @returns {Object} { valid: boolean, errors: Array<string>, warnings: Array<string> }
		 */
		function verifyLibraryIntegrity(lib) {
			var result = { valid: true, errors: [], warnings: [] };
			var storedHashes = lib.file_hashes || {};
			var libBasePath = lib.lib_install_path || "";
			var libraryFiles = lib.library_files || [];
			var comDlls = lib.com_register_dlls || [];
			var hashableExts = ['.hsl', '.hs_', '.sub'];

			// If no hashes stored, mark as warning (legacy library)
			if (Object.keys(storedHashes).length === 0) {
				result.warnings.push('No integrity hashes stored (imported before hashing was enabled)');
				return result;
			}

			libraryFiles.forEach(function(f) {
				var ext = path.extname(f).toLowerCase();
				var isDll = comDlls.indexOf(f) !== -1;
				if (hashableExts.indexOf(ext) === -1 && !isDll) return;

				var fullPath = path.join(libBasePath, f);

				// Check file exists
				if (!fs.existsSync(fullPath)) {
					result.valid = false;
					result.errors.push('File missing: ' + f);
					return;
				}

				// Check hash
				var storedHash = storedHashes[f];
				if (!storedHash) {
					result.warnings.push('No stored hash for: ' + f);
					return;
				}

				var currentHash = computeFileHash(fullPath);
				if (currentHash && currentHash !== storedHash) {
					result.valid = false;
					result.errors.push('File modified: ' + f);
				}
			});

			return result;
		}

		// Fit importer container height to window
		function fitImporterHeight() {
			if($(".methods-page").hasClass("d-none")){return;}
			var importerDiv = $(".importer-container");
			var height = window.innerHeight - $(".header2").outerHeight();
			importerDiv.height(height);
		}

		// ---- Build installed library cards from DB ----
		function impBuildLibraryCards(groupId, recentMode, systemMode) {
			var $container = $("#imp-cards-container");
			$container.empty();

			// ---- System-only mode: render only system library cards ----
			if (systemMode) {
				var sysLibs = getAllSystemLibraries();
				if (!sysLibs || sysLibs.length === 0) {
					$container.html(
						'<div class="w-100 text-center py-5 imp-empty-state">' +
							'<i class="fas fa-lock fa-3x color-lightgray"></i>' +
							'<p class="text-muted mt-3">No system libraries found.</p>' +
						'</div>'
					);
					return;
				}
				sysLibs.forEach(function(sLib) {
					$container.append(buildSystemLibraryCard(sLib));
				});
				$container.append('<div class="col-md-12 my-3"></div>');
				return;
			}

			var libs;
			if (recentMode) {
				// Recent mode: show all libraries (including deleted) sorted by installed_date (newest first), limited to max recent setting
				// EXCLUDE system libraries from Recent
				libs = db_installed_libs.installed_libs.find();
				libs = libs.filter(function(l) { return !isSystemLibrary(l._id); });
				libs.sort(function(a, b) {
					var dateA = a.installed_date ? new Date(a.installed_date).getTime() : 0;
					var dateB = b.installed_date ? new Date(b.installed_date).getTime() : 0;
					return dateB - dateA;
				});
				libs = libs.slice(0, int_maxRecent);
			} else if (groupId) {
				// Show only libraries assigned to this group (exclude deleted)
				var treeEntry = db_tree.tree.findOne({"group-id": groupId});
				var libIds = treeEntry ? treeEntry["method-ids"] : [];
				libs = [];
				libIds.forEach(function(id) {
					var lib = db_installed_libs.installed_libs.findOne({"_id": id});
					if (lib && !lib.deleted) libs.push(lib);
				});
			} else {
				libs = db_installed_libs.installed_libs.find();
				// Filter out deleted libraries from "All" view
				libs = libs.filter(function(l) { return !l.deleted; });
			}

			// Determine which system libraries to show in "All" mode
			var visibleSysLibs = [];
			if (!groupId && !recentMode && systemLibraries.length > 0) {
				var hideSystemLibs = getSettingValue('chk_hideSystemLibraries');
				var sysLibsAll = getAllSystemLibraries();
				for (var si = 0; si < sysLibsAll.length; si++) {
					if (hideSystemLibs) {
						// Still show system libraries that have warnings or errors
						var sysIntegrity = verifySystemLibraryIntegrity(sysLibsAll[si]);
						if (!sysIntegrity.valid || sysIntegrity.warnings.length > 0) {
							visibleSysLibs.push(sysLibsAll[si]);
						}
					} else {
						visibleSysLibs.push(sysLibsAll[si]);
					}
				}
			}
			var hasSystemCards = visibleSysLibs.length > 0;

			if ((!libs || libs.length === 0) && !hasSystemCards) {
				var emptyMsg;
				if (recentMode) {
					emptyMsg = 'No recent imports.<br>Import a <b>.hxlibpkg</b> package to see it here.';
				} else if (groupId === 'gHamilton') {
					emptyMsg = 'No Hamilton packages installed yet.<br>Import an official Hamilton <b>.hxlibpkg</b> to see it here.';
				} else if (groupId) {
					emptyMsg = 'No libraries assigned to this group.<br>Drag libraries into this group from <b>Settings &gt; Library Groups</b>.';
				} else {
					emptyMsg = 'No libraries installed yet.<br>Click <b>Import</b> to install a .hxlibpkg or .hxlibarch file.';
				}
				$container.html(
					'<div class="w-100 text-center py-5 imp-empty-state">' +
						'<i class="fas fa-inbox fa-3x color-lightgray"></i>' +
						'<p class="text-muted mt-3">' + emptyMsg + '</p>' +
					'</div>'
				);
				return;
			}

			libs.forEach(function(lib) {
				var libName = escapeHtml(lib.library_name || "Unknown");
				var version = escapeHtml(lib.version || "");
				var author = escapeHtml(lib.author || "");
				var description = escapeHtml(lib.description || "");
				var tags = (lib.tags || []).map(function(t) { return escapeHtml(t); });
				var hasImage = !!lib.library_image_base64;
				var hasComWarning = lib.com_warning === true;
				var comDlls = (lib.com_register_dlls || []).map(function(d) { return escapeHtml(d); });
				var isDeleted = lib.deleted === true;

				// Verify library integrity
				var integrity = verifyLibraryIntegrity(lib);
				var hasIntegrityError = !integrity.valid;
				var hasIntegrityWarning = integrity.warnings.length > 0;

				// Determine MIME type from stored mime or filename extension
				var imgMime = lib.library_image_mime || 'image/bmp';
				if (!lib.library_image_mime && lib.library_image) {
					var extLower = (lib.library_image || '').split('.').pop().toLowerCase();
					if (IMAGE_MIME_MAP[extLower]) imgMime = IMAGE_MIME_MAP[extLower];
				}

				// Build card icon
				var iconHtml;
				if (hasImage) {
					iconHtml = '<img src="data:' + imgMime + ';base64,' + lib.library_image_base64 + '" style="max-width:48px; max-height:48px; border-radius:4px;">';
				} else {
					iconHtml = '<i class="fas fa-book fa-3x color-medium"></i>';
				}

				// Truncate description
				var shortDesc = description;
				if (shortDesc.length > 80) { shortDesc = shortDesc.substring(0, 80) + "..."; }

				var tagsHtml = "";
				if (tags.length > 0) {
					tags.forEach(function(t) {
						tagsHtml += '<span class="badge badge-light mr-1" style="font-size:0.7rem;">' + t + '</span>';
					});
				}

				// COM warning badge
				var comWarningBadge = "";
				if (hasComWarning && comDlls.length > 0) {
					comWarningBadge = '<span class="badge badge-warning ml-2" title="COM registration failed for: ' + comDlls.join(', ') + '. This library may not function correctly."><i class="fas fa-exclamation-triangle mr-1"></i>COM</span>';
				} else if (comDlls.length > 0) {
					comWarningBadge = '<span class="badge badge-info ml-2" title="COM registered DLLs: ' + comDlls.join(', ') + '"><i class="fas fa-cog mr-1"></i>COM</span>';
				}

				// Help badge (optional, only if help file exists)
				var helpBadge = "";

				// Deleted badge
				var deletedBadge = "";
				if (isDeleted) {
					deletedBadge = '<span class="badge badge-secondary ml-2" title="This library has been deleted"><i class="fas fa-trash-alt mr-1"></i>Deleted</span>';
				}

				// Card styling - red for integrity error or missing deps, yellow for COM warning, faded for deleted
				var deps = extractRequiredDependencies(lib.library_files || [], lib.lib_install_path || '');
				var depStatus = checkDependencyStatus(deps);
				var hasMissingDeps = !depStatus.valid;

				var cardExtraClass = '';
				if (hasIntegrityError || hasMissingDeps) {
					cardExtraClass = ' imp-lib-card-integrity-error';
				} else if (hasComWarning) {
					cardExtraClass = ' imp-lib-card-warning';
				}
				if (isDeleted) cardExtraClass += ' imp-lib-card-deleted';

				var cardTooltipAttr = '';
				if (hasIntegrityError || hasMissingDeps) {
					var errParts = [];
					if (hasIntegrityError) errParts = errParts.concat(integrity.errors).concat(integrity.warnings);
					if (hasMissingDeps) errParts.push('Missing dependencies: ' + depStatus.missing.map(function(d) { return d.libraryName || d.include; }).join(', '));
					cardTooltipAttr = ' title="' + errParts.join('\n').replace(/"/g, '&quot;') + '"';
				} else if (hasIntegrityWarning) {
					var warnTooltip = integrity.warnings.join('\n');
					cardTooltipAttr = ' title="' + warnTooltip.replace(/"/g, '&quot;') + '"';
				}

				var str =
					'<div class="col-md-4 col-xl-3 d-flex align-items-stretch imp-lib-card-container" data-lib-id="' + lib._id + '">' +
						'<div class="m-2 pl-3 pr-3 pt-3 pb-2 link-card imp-lib-card w-100' + cardExtraClass + '"' + cardTooltipAttr + '>' +
							'<div class="d-flex align-items-start">' +
								'<div class="mr-3 mt-1 imp-lib-card-icon">' + iconHtml + '</div>' +
								'<div class="flex-grow-1" style="min-width:0;">' +
									'<h6 class="mb-0 imp-lib-card-name cursor-pointer" style="color:var(--medium2);">' + libName + comWarningBadge + helpBadge + deletedBadge + '</h6>' +
									(version ? '<span class="text-muted text-sm">v' + version + '</span>' : '') +
									(author ? '<div class="text-muted text-sm">' + author + '</div>' : '') +
								'</div>' +
							'</div>' +
							(shortDesc ? '<p class="text-muted mt-2 mb-1" style="font-size:0.85em;">' + shortDesc + '</p>' : '') +
							(tagsHtml ? '<div class="mt-1 mb-2">' + tagsHtml + '</div>' : '') +
							'<div class="d-flex justify-content-between align-items-center mt-2 pt-2" style="border-top:1px solid #eee;">' +
								'<a href="#" class="text-sm imp-lib-card-details cursor-pointer" style="color:var(--medium);">View Details</a>' +
							'</div>' +
						'</div>' +
					'</div>';

				$container.append(str);
			});

			// In "All" mode, render system library cards after user libraries
			if (hasSystemCards) {
				// Separator between user and system libraries
				if (libs && libs.length > 0) {
					$container.append(
						'<div class="col-md-12 mt-3 mb-2">' +
							'<hr style="border-color:#dee2e6;">' +
							'<span class="text-muted text-sm"><i class="fas fa-lock mr-1"></i>System Libraries</span>' +
						'</div>'
					);
				} else {
					$container.append(
						'<div class="col-md-12 mb-2">' +
							'<span class="text-muted text-sm"><i class="fas fa-lock mr-1"></i>System Libraries</span>' +
						'</div>'
					);
				}
				visibleSysLibs.forEach(function(sLib) {
					$container.append(buildSystemLibraryCard(sLib));
				});
			}

			// Bottom spacer
			$container.append('<div class="col-md-12 my-3"></div>');
		}

		// ---- Resolve system library icon: .bmp or .ico, with tiled submethod fallback ----
		function resolveSystemLibIcon(sLib, size) {
			size = size || 48;
			var fallbackHtml = '<i class="fas fa-lock fa-3x" style="color:#adb5bd;"></i>';
			var canonLower = (sLib.canonical_name || '').toLowerCase();
			var discovered = sLib.discovered_files || [];
			var iconExts = ['.bmp', '.ico'];
			var mimeForExt = {'.bmp': 'image/bmp', '.ico': 'image/x-icon', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml'};

			// Resolve lib folder once
			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var libDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

			// 1) Search for root icon: {canonicalName}.bmp or {canonicalName}.ico
			var primaryIconPath = null;
			var primaryMime = null;
			for (var ei = 0; ei < iconExts.length; ei++) {
				var targetName = canonLower + iconExts[ei];
				for (var fi = 0; fi < discovered.length; fi++) {
					var fname = discovered[fi].replace(/\\/g, '/');
					var baseName = fname.split('/').pop().toLowerCase();
					if (baseName === targetName) {
						primaryIconPath = discovered[fi];
						primaryMime = mimeForExt[iconExts[ei]];
						break;
					}
				}
				if (primaryIconPath) break;
			}

			if (primaryIconPath) {
				try {
					var relPath = primaryIconPath.replace(/^Library[\\\/]/i, '');
					var fullPath = path.join(libDir, relPath);
					if (fs.existsSync(fullPath)) {
						var imgData = fs.readFileSync(fullPath);
						var imgBase64 = imgData.toString('base64');
						return '<div class="imp-sys-icon-wrap" style="width:' + size + 'px;height:' + size + 'px;">' +
							'<img src="data:' + primaryMime + ';base64,' + imgBase64 + '" class="imp-sys-icon-img" style="width:' + size + 'px;height:' + size + 'px;object-fit:contain;">' +
						'</div>';
					}
				} catch(e) { /* fall through */ }
			}

			// 2) No root icon found — collect submethod icons and tile them
			var subIcons = [];
			var canonDot = canonLower + '.';
			for (var si = 0; si < discovered.length; si++) {
				var sfname = discovered[si].replace(/\\/g, '/');
				var sbaseName = sfname.split('/').pop().toLowerCase();
				// Match {canonicalName}.{submethod}.bmp or .ico (has 2+ dots)
				if (sbaseName.indexOf(canonDot) === 0 && sbaseName !== canonLower + '.bmp' && sbaseName !== canonLower + '.ico') {
					var sext = '.' + sbaseName.split('.').pop();
					if (sext === '.bmp' || sext === '.ico') {
						// Deduplicate: prefer .bmp over .ico for the same submethod
						var subMethodKey = sbaseName.replace(/\.(bmp|ico)$/, '');
						var alreadyHave = false;
						for (var di = 0; di < subIcons.length; di++) {
							if (subIcons[di].key === subMethodKey) { alreadyHave = true; break; }
						}
						if (!alreadyHave) {
							subIcons.push({ key: subMethodKey, path: discovered[si], mime: mimeForExt[sext] || 'image/bmp' });
						}
					}
				}
			}

			if (subIcons.length > 0) {
				// Determine grid dimensions: square grid that fits all icons
				var gridCols = Math.ceil(Math.sqrt(subIcons.length));
				var cellSize = Math.floor(size / gridCols);
				var tilesHtml = '';
				var maxTiles = gridCols * gridCols; // fill only grid cells
				for (var ti = 0; ti < Math.min(subIcons.length, maxTiles); ti++) {
					try {
						var trelPath = subIcons[ti].path.replace(/^Library[\\\/]/i, '');
						var tfullPath = path.join(libDir, trelPath);
						if (fs.existsSync(tfullPath)) {
							var tdata = fs.readFileSync(tfullPath);
							var tb64 = tdata.toString('base64');
							tilesHtml += '<img src="data:' + subIcons[ti].mime + ';base64,' + tb64 + '" class="imp-sys-tile-icon" style="width:' + cellSize + 'px;height:' + cellSize + 'px;">';
						}
					} catch(e) { /* skip unreadable */ }
				}
				if (tilesHtml) {
					return '<div class="imp-sys-icon-wrap imp-sys-icon-tiled" style="width:' + size + 'px;height:' + size + 'px;">' + tilesHtml + '</div>';
				}
			}

			return fallbackHtml;
		}

		// ---- Build a single system library card HTML ----
		function buildSystemLibraryCard(sLib) {
			var libName = escapeHtml(sLib.display_name || sLib.canonical_name || "Unknown");
			var author = escapeHtml(sLib.author || "Hamilton");
			var fileCount = (sLib.discovered_files || []).length;
			var resTypes = escapeHtml((sLib.resource_types || []).join(', '));
			var hasPrimary = sLib.has_primary_definition;

			var iconHtml = resolveSystemLibIcon(sLib, 48);

			// Integrity check for system library
			var integrity = verifySystemLibraryIntegrity(sLib);
			var hasIntegrityError = !integrity.valid;
			var hasIntegrityWarning = integrity.warnings.length > 0;

			var typeBadges = '';
			if (hasPrimary) {
				typeBadges = '<span class="badge badge-light mr-1" style="font-size:0.7rem;">System</span>';
			} else {
				typeBadges = '<span class="badge badge-light mr-1" style="font-size:0.7rem;">System Resource</span>';
			}

			var shortDesc = fileCount + ' file' + (fileCount !== 1 ? 's' : '') + ' (' + resTypes + ')';

			var cardExtraClass = '';
			if (hasIntegrityError) { cardExtraClass = ' imp-lib-card-integrity-error'; }

			var cardTooltipAttr = '';
			if (hasIntegrityError) {
				var errTooltip = integrity.errors.concat(integrity.warnings).join('\n');
				cardTooltipAttr = ' title="' + errTooltip.replace(/"/g, '&quot;') + '"';
			} else if (hasIntegrityWarning) {
				var warnTooltip = integrity.warnings.join('\n');
				cardTooltipAttr = ' title="' + warnTooltip.replace(/"/g, '&quot;') + '"';
			}

			var str =
				'<div class="col-md-4 col-xl-3 d-flex align-items-stretch imp-lib-card-container imp-lib-card-system-container" data-lib-id="' + sLib._id + '" data-system="true">' +
					'<div class="m-2 pl-3 pr-3 pt-3 pb-2 link-card imp-lib-card imp-lib-card-system w-100' + cardExtraClass + '"' + cardTooltipAttr + '>' +
						'<div class="d-flex align-items-start">' +
							'<div class="mr-3 mt-1 imp-lib-card-icon">' + iconHtml + '</div>' +
							'<div class="flex-grow-1" style="min-width:0;">' +
								'<h6 class="mb-0 imp-lib-card-name imp-lib-card-name-system" style="color:#6c757d;" title="' + libName.replace(/"/g, '&quot;') + '">' + libName + '</h6>' +
								'<div class="text-muted text-sm">' + author + '</div>' +
								'<span class="badge badge-secondary mt-1" style="font-size:0.6rem;"><i class="fas fa-lock mr-1"></i>Read-Only</span>' +
							'</div>' +
						'</div>' +
						'<p class="text-muted mt-2 mb-1" style="font-size:0.85em;">' + shortDesc + '</p>' +
						'<div class="mt-1 mb-1">' + typeBadges + '</div>' +
						'<div class="d-flex justify-content-between align-items-center mt-2 pt-2" style="border-top:1px solid #eee;">' +
							'<a href="#" class="text-sm imp-lib-card-details cursor-pointer" style="color:var(--medium);">View Details</a>' +
							'<span class="text-muted text-sm"><i class="fas fa-lock"></i></span>' +
						'</div>' +
					'</div>' +
				'</div>';
			return str;
		}

		// ---- Show library detail modal ----
		function impShowLibDetail(libId) {
			// ---- Handle system library detail view ----
			if (isSystemLibrary(libId)) {
				impShowSystemLibDetail(libId);
				return;
			}

			var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
			if (!lib) return;

			// Icon/image
			var $icon = $("#libDetailModal .lib-detail-modal-icon");
			$icon.empty();

			// Determine MIME type for detail view
			var detailMime = lib.library_image_mime || 'image/bmp';
			if (!lib.library_image_mime && lib.library_image) {
				var extLower = (lib.library_image || '').split('.').pop().toLowerCase();
				if (IMAGE_MIME_MAP[extLower]) detailMime = IMAGE_MIME_MAP[extLower];
			}

			if (lib.library_image_base64) {
				$icon.html('<img src="data:' + detailMime + ';base64,' + lib.library_image_base64 + '" style="width:56px; height:56px; object-fit:contain; border-radius:6px;">');
			} else {
				$icon.html('<i class="fas fa-book fa-3x" style="color:var(--medium)"></i>');
			}

			// Metadata
			$("#libDetailModal .lib-detail-name").text(lib.library_name || "Unknown");
			$("#libDetailModal .lib-detail-version").text(lib.version ? "v" + lib.version : "");
			$("#libDetailModal .lib-detail-author").text(lib.author || "\u2014");
			$("#libDetailModal .lib-detail-organization").text(lib.organization || "\u2014");
			$("#libDetailModal .lib-detail-venus").text(lib.venus_compatibility || "\u2014");
			$("#libDetailModal .lib-detail-installed-date").text(lib.installed_date ? new Date(lib.installed_date).toLocaleString() : "\u2014");

			// Description
			if (lib.description) {
				$("#libDetailModal .lib-detail-description").text(lib.description);
				$("#libDetailModal .lib-detail-desc-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-desc-section").addClass("d-none");
			}

			// Tags
			var tags = lib.tags || [];
			if (tags.length > 0) {
				$("#libDetailModal .lib-detail-tags").text(tags.join(", "));
				$("#libDetailModal .lib-detail-tags-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-tags-section").addClass("d-none");
			}

			// Library image in body
			if (lib.library_image_base64) {
				$("#libDetailModal .lib-detail-image").attr("src", "data:" + detailMime + ";base64," + lib.library_image_base64);
				$("#libDetailModal .lib-detail-image-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-image-section").addClass("d-none");
			}

			// Library files list
			var $libFiles = $("#libDetailModal .lib-detail-lib-files");
			$libFiles.empty();
			var libFiles = lib.library_files || [];
			var libBasePath = lib.lib_install_path || "";
			if (libFiles.length === 0) {
				$libFiles.html('<div class="text-muted text-center py-2 pkg-empty-msg"><i class="fas fa-inbox mr-1"></i>None</div>');
			} else {
				libFiles.forEach(function(f) {
					var fullPath = libBasePath ? path.join(libBasePath, f) : f;
					$libFiles.append(
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + fullPath.replace(/"/g, '&quot;') + '" title="Open: ' + fullPath.replace(/"/g, '&quot;') + '"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + f + '</span></div>'
					);
				});
			}

			// Demo files list
			var $demoFiles = $("#libDetailModal .lib-detail-demo-files");
			$demoFiles.empty();
			var demoFiles = lib.demo_method_files || [];
			var demoBasePath = lib.demo_install_path || "";
			if (demoFiles.length === 0) {
				$demoFiles.html('<div class="text-muted text-center py-2 pkg-empty-msg"><i class="fas fa-inbox mr-1"></i>None</div>');
			} else {
				demoFiles.forEach(function(f) {
					var fullPath = demoBasePath ? path.join(demoBasePath, f) : f;
					$demoFiles.append(
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + fullPath.replace(/"/g, '&quot;') + '" title="Open: ' + fullPath.replace(/"/g, '&quot;') + '"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + f + '</span></div>'
					);
				});
			}

			// Help files list
			var $helpFiles = $("#libDetailModal .lib-detail-help-files");
			$helpFiles.empty();
			var helpFiles = lib.help_files || [];
			if (helpFiles.length > 0) {
				$("#libDetailModal .lib-detail-help-section").removeClass("d-none");
				helpFiles.forEach(function(f) {
					var fullPath = libBasePath ? path.join(libBasePath, f) : f;
					$helpFiles.append(
						'<div class="pkg-file-item pkg-file-link imp-help-file-open" data-filepath="' + fullPath.replace(/"/g, '&quot;') + '" title="Open help: ' + fullPath.replace(/"/g, '&quot;') + '" style="cursor:pointer;"><i class="fas fa-question-circle pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + f + '</span><span class="badge badge-info ml-2" style="font-size:0.7rem;">Open</span></div>'
					);
				});
			} else {
				$("#libDetailModal .lib-detail-help-section").addClass("d-none");
			}

			// Install paths
			$("#libDetailModal .lib-detail-lib-path").text("Library: " + (lib.lib_install_path || "\u2014"));
			$("#libDetailModal .lib-detail-demo-path").text("Demo Methods: " + (lib.demo_install_path || "\u2014"));

			// Required dependencies section
			var deps = extractRequiredDependencies(lib.library_files || [], lib.lib_install_path || '');
			var depStatus = checkDependencyStatus(deps);
			var $depSection = $("#libDetailModal .lib-detail-dependencies-section");
			var $depStatus = $("#libDetailModal .lib-detail-dependencies-status");
			var $depList = $("#libDetailModal .lib-detail-dependencies-list");
			$depStatus.empty();
			$depList.empty();

			if (deps.length > 0) {
				$depSection.removeClass("d-none");

				// Summary status
				if (!depStatus.valid) {
					$depStatus.append('<div class="text-sm mb-1" style="color:#d9534f;"><i class="fas fa-times-circle mr-1"></i>' + depStatus.missing.length + ' missing dependenc' + (depStatus.missing.length !== 1 ? 'ies' : 'y') + '</div>');
				} else {
					$depStatus.append('<div class="text-sm mb-1" style="color:#5cb85c;"><i class="fas fa-check-circle mr-1"></i>All ' + deps.length + ' dependenc' + (deps.length !== 1 ? 'ies' : 'y') + ' found</div>');
				}

				// List each dependency
				deps.forEach(function(dep) {
					var statusIcon, statusColor, statusText;
					if (!dep.fileExists || dep.type === 'unknown') {
						statusIcon = 'fa-times-circle';
						statusColor = '#d9534f';
						statusText = 'Missing';
					} else if (dep.type === 'system') {
						statusIcon = 'fa-lock';
						statusColor = '#6c757d';
						statusText = 'System';
					} else {
						statusIcon = 'fa-check-circle';
						statusColor = '#5cb85c';
						statusText = 'Installed';
					}
					var typeBadge = '<span class="badge badge-' + (dep.type === 'system' ? 'secondary' : dep.type === 'user' ? 'info' : 'danger') + ' ml-1" style="font-size:0.6rem;">' + statusText + '</span>';
					$depList.append(
						'<div class="dep-item" style="padding:3px 0; border-bottom:1px solid rgba(128,128,128,0.1);">' +
							'<div style="display:flex; align-items:center;">' +
								'<i class="fas ' + statusIcon + '" style="color:' + statusColor + '; font-size:0.8rem; margin-right:6px; min-width:14px;"></i>' +
								'<span style="font-family:Consolas,monospace; font-size:0.82rem; font-weight:600;">' + escapeHtml(dep.libraryName || dep.include) + '</span>' +
								typeBadge +
							'</div>' +
							'<div class="text-muted" style="font-family:Consolas,monospace; font-size:0.7rem; margin-left:20px; word-break:break-all;">' + escapeHtml(dep.include) + '</div>' +
						'</div>'
					);
				});
			} else {
				$depSection.addClass("d-none");
			}

			// Public functions section
			var pubFns = lib.public_functions || [];
			var $fnSection = $("#libDetailModal .lib-detail-functions-section");
			var $fnList = $("#libDetailModal .lib-detail-functions-list");
			$fnList.empty();
			if (pubFns.length > 0) {
				$fnSection.removeClass("d-none");
				pubFns.forEach(function(fn) {
					var paramStr = (fn.params || []).map(function(p) {
						return '<span class="fn-param-type">' + escapeHtml(p.type || 'variable') + '</span>' +
							(p.byRef ? '<span class="fn-param-ref">&amp;</span> ' : ' ') +
							'<span class="fn-param-name">' + escapeHtml(p.name) + '</span>' +
							(p.array ? '<span class="fn-param-array">[]</span>' : '');
					}).join(', ');
					var retBadge = fn.returnType && fn.returnType !== 'void'
						? '<span class="badge badge-light ml-1" style="font-size:0.65rem; vertical-align:middle;">' + escapeHtml(fn.returnType) + '</span>'
						: '<span class="badge badge-light ml-1" style="font-size:0.65rem; vertical-align:middle; opacity:0.5;">void</span>';
					var docHtml = fn.doc
						? '<div class="fn-doc text-muted text-sm" style="margin-left:22px; font-size:0.75rem; white-space:pre-wrap;">' + $("<span>").text(fn.doc.split('\n')[0]).html() + '</div>'
						: '';
					$fnList.append(
						'<div class="fn-item" style="padding:3px 0; border-bottom:1px solid rgba(128,128,128,0.1);">' +
							'<div><i class="fas fa-cube fn-icon" style="color:var(--medium); font-size:0.7rem; margin-right:5px;"></i>' +
							'<span class="fn-name" style="font-family:Consolas,monospace; font-weight:600; font-size:0.82rem;">' + escapeHtml(fn.qualifiedName) + '</span>' +
							'<span style="font-family:Consolas,monospace; font-size:0.78rem; color:#888;">(' + paramStr + ')</span>' +
							retBadge + '</div>' +
							docHtml +
						'</div>'
					);
				});
				$fnList.prepend('<div class="text-muted text-sm mb-1"><i class="fas fa-info-circle mr-1"></i>' + pubFns.length + ' public function' + (pubFns.length !== 1 ? 's' : '') + '</div>');
			} else {
				$fnSection.addClass("d-none");
			}

			// COM DLL section
			var comDlls = lib.com_register_dlls || [];
			var hasComWarning = lib.com_warning === true;
			if (comDlls.length > 0) {
				$("#libDetailModal .lib-detail-com-section").removeClass("d-none");
				var comHtml = comDlls.map(function(d) {
					return '<span class="badge badge-light mr-1">' + d + '</span>';
				}).join('');
				$("#libDetailModal .lib-detail-com-dlls").html(comHtml);
				if (hasComWarning) {
					$("#libDetailModal .lib-detail-com-warning-badge").html(
						'<span class="badge badge-warning"><i class="fas fa-exclamation-triangle mr-1"></i>COM registration failed - library may not function correctly</span>'
					);
				} else {
					$("#libDetailModal .lib-detail-com-warning-badge").html(
						'<span class="badge badge-success"><i class="fas fa-check mr-1"></i>Registered successfully</span>'
					);
				}
			} else {
				$("#libDetailModal .lib-detail-com-section").addClass("d-none");
			}

			// Integrity verification in detail modal
			var integrity = verifyLibraryIntegrity(lib);
			var $intSection = $("#libDetailModal .lib-detail-integrity-section");
			var $intStatus = $("#libDetailModal .lib-detail-integrity-status");
			var $intRepair = $("#libDetailModal .lib-detail-integrity-repair");
			$intStatus.empty();
			$intRepair.addClass("d-none");

			if (Object.keys(lib.file_hashes || {}).length > 0 || integrity.errors.length > 0 || integrity.warnings.length > 0) {
				$intSection.removeClass("d-none");

				if (!integrity.valid) {
					// Errors
					integrity.errors.forEach(function(err) {
						$intStatus.append('<div class="text-sm mb-1" style="color:#d9534f;"><i class="fas fa-times-circle mr-1"></i>' + err + '</div>');
					});
					// Show repair button if a cached package exists
					var cachedUser = listCachedVersions(lib.library_name);
					if (cachedUser.length > 0) {
						$intRepair.removeClass("d-none");
						$intRepair.find(".lib-detail-repair-btn").attr("data-sys-lib-name", "").attr("data-user-lib-name", lib.library_name);
					}
				}
				if (integrity.warnings.length > 0) {
					integrity.warnings.forEach(function(warn) {
						$intStatus.append('<div class="text-sm mb-1" style="color:#f0ad4e;"><i class="fas fa-exclamation-triangle mr-1"></i>' + warn + '</div>');
					});
				}
				if (integrity.valid && integrity.warnings.length === 0) {
					$intStatus.append('<div class="text-sm mb-1" style="color:#5cb85c;"><i class="fas fa-check-circle mr-1"></i>All tracked files pass integrity check</div>');
				}
			} else {
				$intSection.addClass("d-none");
			}

			// Show/hide delete button based on deleted status
			if (lib.deleted) {
				$("#libDetailModal .lib-detail-delete-btn").addClass("d-none");
				$("#libDetailModal .lib-detail-export-btn").addClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-delete-btn").removeClass("d-none");
				$("#libDetailModal .lib-detail-export-btn").removeClass("d-none");
			}

			// Cached package versions section
			var $versSection = $("#libDetailModal .lib-detail-versions-section");
			var $versList = $("#libDetailModal .lib-detail-versions-list");
			$versList.empty();
			try {
				var cachedVersions = listCachedVersions(lib.library_name);
				if (cachedVersions.length > 0) {
					$versSection.removeClass("d-none");
					cachedVersions.forEach(function(cv, idx) {
						var isCurrent = (cv.version === lib.version);
						var currentBadge = isCurrent ? ' <span class="badge badge-success" style="font-size:0.65rem;">current</span>' : '';
						var sizeKB = (cv.size / 1024).toFixed(1);
						var cachedDate = cv.cached ? new Date(cv.cached).toLocaleString() : '\u2014';
						var rollbackBtn = !isCurrent
							? '<button class="btn btn-sm btn-outline-primary lib-detail-rollback-btn ml-auto" style="font-size:0.7rem; padding:1px 8px;" data-fullpath="' + cv.fullPath.replace(/"/g, '&quot;') + '" data-version="' + (cv.version || '?') + '" data-libname="' + (lib.library_name || '').replace(/"/g, '&quot;') + '"><i class="fas fa-undo-alt mr-1"></i>Rollback</button>'
							: '<span class="badge badge-light ml-auto" style="font-size:0.65rem;">installed</span>';
						$versList.append(
							'<div class="d-flex align-items-center" style="padding:5px 0; border-bottom:1px solid rgba(128,128,128,0.1);">' +
								'<div style="min-width:0; flex:1;">' +
									'<div style="font-family:Consolas,monospace; font-size:0.82rem; font-weight:600;">v' + (cv.version || '?') + currentBadge + '</div>' +
									'<div class="text-muted" style="font-size:0.72rem;">Cached: ' + cachedDate + ' &middot; ' + sizeKB + ' KB</div>' +
								'</div>' +
								rollbackBtn +
							'</div>'
						);
					});
				} else {
					$versSection.addClass("d-none");
				}
			} catch(e) {
				$versSection.addClass("d-none");
			}

			// Store library id on the modal so delete button can use it
			$("#libDetailModal").attr("data-lib-id", libId);
			$("#libDetailModal").attr("data-system", "false");
			$("#libDetailModal").modal("show");
		}

		// ---- Rollback to a cached package version from detail modal ----
		$(document).on("click", ".lib-detail-rollback-btn", function(e) {
			e.preventDefault();
			var fullPath = $(this).attr("data-fullpath");
			var version  = $(this).attr("data-version");
			var libName  = $(this).attr("data-libname");

			if (!fullPath || !libName) return;

			if (!confirm('Roll back "' + libName + '" to version ' + version + '?\n\nThis will replace the currently installed files with the selected version.')) {
				return;
			}

			if (!confirm('Are you sure? This will overwrite all current library files for "' + libName + '".')) {
				return;
			}

			try {
				var zipBuffer = fs.readFileSync(fullPath);
				var zip = new AdmZip(zipBuffer);
				var manifestEntry = zip.getEntry("manifest.json");
				if (!manifestEntry) {
					alert("Cached package is corrupt: manifest.json not found.");
					return;
				}
				var manifest = JSON.parse(zip.readAsText(manifestEntry));

				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				var rLibName = manifest.library_name || libName;
				var libDestDir = path.join(libBasePath, rLibName);
				var demoDestDir = path.join(metBasePath, "Library Demo Methods", rLibName);

				var origLibFiles = manifest.library_files || [];
				var demoFiles = manifest.demo_method_files || [];
				var comDlls = manifest.com_register_dlls || [];

				// Auto-detect .chm help files
				var declaredHelp = manifest.help_files || [];
				var helpFiles = declaredHelp.slice();
				var libFiles = [];
				origLibFiles.forEach(function(f) {
					if (path.extname(f).toLowerCase() === '.chm') {
						if (helpFiles.indexOf(f) === -1) helpFiles.push(f);
					} else {
						libFiles.push(f);
					}
				});

				// Create destination directories
				if ((libFiles.length > 0 || helpFiles.length > 0) && !fs.existsSync(libDestDir)) {
					fs.mkdirSync(libDestDir, { recursive: true });
				}
				if (demoFiles.length > 0 && !fs.existsSync(demoDestDir)) {
					fs.mkdirSync(demoDestDir, { recursive: true });
				}

				// Extract files
				var extractedCount = 0;
				var zipEntries = zip.getEntries();
				zipEntries.forEach(function(entry) {
					if (entry.entryName === "manifest.json" || entry.entryName === "signature.json") return;
					if (entry.entryName.indexOf("library/") === 0) {
						var fname = entry.entryName.substring("library/".length);
						if (fname) {
							var safePath = safeZipExtractPath(libDestDir, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("demo_methods/") === 0) {
						var fname = entry.entryName.substring("demo_methods/".length);
						if (fname) {
							var safePath = safeZipExtractPath(demoDestDir, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("help_files/") === 0) {
						var fname = entry.entryName.substring("help_files/".length);
						if (fname) {
							var safePath = safeZipExtractPath(libDestDir, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					}
				});

				// Update DB record
				var existing = db_installed_libs.installed_libs.findOne({"library_name": rLibName});
				if (existing) {
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				var fileHashes = {};
				try { fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls); } catch(e) {}

				var dbRecord = {
					library_name: manifest.library_name || "",
					author: manifest.author || "",
					organization: manifest.organization || "",
					version: manifest.version || "",
					venus_compatibility: manifest.venus_compatibility || "",
					description: manifest.description || "",
					tags: manifest.tags || [],
					created_date: manifest.created_date || "",
					library_image: manifest.library_image || null,
					library_image_base64: manifest.library_image_base64 || null,
					library_image_mime: manifest.library_image_mime || null,
					library_files: libFiles,
					demo_method_files: demoFiles,
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: false,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: path.basename(fullPath),
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFiles, libDestDir),
					required_dependencies: extractRequiredDependencies(libFiles, libDestDir)
				};
				var saved = db_installed_libs.installed_libs.save(dbRecord);

				// Re-add to group tree if needed
				var navtree = db_tree.tree.find();
				var inGroup = false;
				for (var ti = 0; ti < navtree.length; ti++) {
					var mids = navtree[ti]["method-ids"] || [];
					if (mids.indexOf(saved._id) !== -1) { inGroup = true; break; }
				}
				if (!inGroup) {
					var targetGroupId = null;
					for (var ti = 0; ti < navtree.length; ti++) {
						var gEntry = getGroupById(navtree[ti]["group-id"]);
						if (gEntry && !gEntry["default"]) {
							targetGroupId = navtree[ti]["group-id"];
							var existingIds = navtree[ti]["method-ids"] || [];
							existingIds.push(saved._id);
							db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
							break;
						}
					}
				}

				// Close modal, refresh, and show success
				$("#libDetailModal").modal("hide");
				impBuildLibraryCards();

				alert('Successfully rolled back "' + rLibName + '" to version ' + (manifest.version || '?') + '.\n\n' + extractedCount + ' files installed.');

				if (comDlls.length > 0) {
					alert('NOTE: This library has COM DLLs that may need re-registration:\n\n' + comDlls.join(', ') + '\n\nUse RegAsm.exe /codebase manually or re-import via the GUI for automatic COM registration.');
				}

			} catch(e) {
				alert("Error rolling back:\n" + e.message);
			}
		});

		// ---- Show detail modal for a system library ----
		function impShowSystemLibDetail(libId) {
			var sLib = getSystemLibrary(libId);
			if (!sLib) return;

			var $icon = $("#libDetailModal .lib-detail-modal-icon");
			$icon.empty();
			$icon.html(resolveSystemLibIcon(sLib, 56));

			// Metadata
			$("#libDetailModal .lib-detail-name").text(sLib.display_name || sLib.canonical_name || "Unknown");
			$("#libDetailModal .lib-detail-version").text("System Library");
			$("#libDetailModal .lib-detail-author").text(sLib.author || "Hamilton");
			$("#libDetailModal .lib-detail-organization").text(sLib.organization || "Hamilton");
			$("#libDetailModal .lib-detail-venus").text("\u2014");
			$("#libDetailModal .lib-detail-installed-date").text("Included with VENUS");

			// Description
			var resTypes = (sLib.resource_types || []).join(', ');
			var sysDesc = "Built-in Hamilton system library. Contains " +
				(sLib.discovered_files || []).length + " file(s) with resource types: " + resTypes + ".";
			$("#libDetailModal .lib-detail-description").text(sysDesc);
			$("#libDetailModal .lib-detail-desc-section").removeClass("d-none");

			// Tags
			$("#libDetailModal .lib-detail-tags").text("system, hamilton, read-only");
			$("#libDetailModal .lib-detail-tags-section").removeClass("d-none");

			// No image
			$("#libDetailModal .lib-detail-image-section").addClass("d-none");

			// Library files list (from discovered_files) — separate CHMs into help section
			var $libFiles = $("#libDetailModal .lib-detail-lib-files");
			$libFiles.empty();
			var discoveredFiles = sLib.discovered_files || [];

			// Resolve the VENUS Library directory for opening files
			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

			// Split into regular files and help files (.chm)
			var sysRegularFiles = [];
			var sysHelpFiles = [];
			discoveredFiles.forEach(function(f) {
				var fileName = f.replace(/\\/g, '/').split('/').pop();
				if (path.extname(fileName).toLowerCase() === '.chm') {
					sysHelpFiles.push(f);
				} else {
					sysRegularFiles.push(f);
				}
			});

			if (sysRegularFiles.length === 0) {
				$libFiles.html('<div class="text-muted text-center py-2 pkg-empty-msg"><i class="fas fa-inbox mr-1"></i>None</div>');
			} else {
				sysRegularFiles.forEach(function(f) {
					var fileName = f.replace(/\\/g, '/').split('/').pop();
					$libFiles.append(
						'<div class="pkg-file-item"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name" style="color:#6c757d;">' + fileName + '</span>' +
						'<span class="pkg-file-dir">' + f + '</span></div>'
					);
				});
			}

			// Help files section for system libraries
			var $helpFiles = $("#libDetailModal .lib-detail-help-files");
			$helpFiles.empty();
			if (sysHelpFiles.length > 0) {
				$("#libDetailModal .lib-detail-help-section").removeClass("d-none");
				sysHelpFiles.forEach(function(f) {
					var fileName = f.replace(/\\/g, '/').split('/').pop();
					var relPath = f.replace(/^Library[\\\/]/i, '');
					var fullPath = path.join(sysLibDir, relPath);
					$helpFiles.append(
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + fullPath.replace(/"/g, '&quot;') + '" title="Open help: ' + fullPath.replace(/"/g, '&quot;') + '" style="cursor:pointer;"><i class="fas fa-question-circle pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + fileName + '</span><span class="badge badge-info ml-2" style="font-size:0.7rem;">Open</span></div>'
					);
				});
			} else {
				$("#libDetailModal .lib-detail-help-section").addClass("d-none");
			}

			// Demo files - none for system libraries
			var $demoFiles = $("#libDetailModal .lib-detail-demo-files");
			$demoFiles.empty();
			$demoFiles.html('<div class="text-muted text-center py-2 pkg-empty-msg"><i class="fas fa-inbox mr-1"></i>None</div>');

			// Install paths
			$("#libDetailModal .lib-detail-lib-path").text("Source: " + (sLib.source_root || "Library"));
			$("#libDetailModal .lib-detail-demo-path").text("");

			// Hide COM section
			$("#libDetailModal .lib-detail-com-section").addClass("d-none");

			// Required dependencies section for system libraries
			var sysDiscFiles = sLib.discovered_files || [];
			var sysHslFiles = sysDiscFiles.filter(function(f) {
				var ext = path.extname(f).toLowerCase();
				return ext === '.hsl' || ext === '.hs_';
			}).map(function(f) { return f.replace(/^Library[\\\/]/i, ''); });
			var sysDeps = extractRequiredDependencies(sysHslFiles, sysLibDir);
			var sysDepStatus = checkDependencyStatus(sysDeps);
			var $sysDepSection = $("#libDetailModal .lib-detail-dependencies-section");
			var $sysDepStatus = $("#libDetailModal .lib-detail-dependencies-status");
			var $sysDepList = $("#libDetailModal .lib-detail-dependencies-list");
			$sysDepStatus.empty();
			$sysDepList.empty();

			if (sysDeps.length > 0) {
				$sysDepSection.removeClass("d-none");

				if (!sysDepStatus.valid) {
					$sysDepStatus.append('<div class="text-sm mb-1" style="color:#d9534f;"><i class="fas fa-times-circle mr-1"></i>' + sysDepStatus.missing.length + ' missing dependenc' + (sysDepStatus.missing.length !== 1 ? 'ies' : 'y') + '</div>');
				} else {
					$sysDepStatus.append('<div class="text-sm mb-1" style="color:#5cb85c;"><i class="fas fa-check-circle mr-1"></i>All ' + sysDeps.length + ' dependenc' + (sysDeps.length !== 1 ? 'ies' : 'y') + ' found</div>');
				}

				sysDeps.forEach(function(dep) {
					var statusIcon, statusColor, statusText;
					if (!dep.fileExists || dep.type === 'unknown') {
						statusIcon = 'fa-times-circle';
						statusColor = '#d9534f';
						statusText = 'Missing';
					} else if (dep.type === 'system') {
						statusIcon = 'fa-lock';
						statusColor = '#6c757d';
						statusText = 'System';
					} else {
						statusIcon = 'fa-check-circle';
						statusColor = '#5cb85c';
						statusText = 'Installed';
					}
					var typeBadge = '<span class="badge badge-' + (dep.type === 'system' ? 'secondary' : dep.type === 'user' ? 'info' : 'danger') + ' ml-1" style="font-size:0.6rem;">' + statusText + '</span>';
					$sysDepList.append(
						'<div class="dep-item" style="padding:3px 0; border-bottom:1px solid rgba(128,128,128,0.1);">' +
							'<div style="display:flex; align-items:center;">' +
								'<i class="fas ' + statusIcon + '" style="color:' + statusColor + '; font-size:0.8rem; margin-right:6px; min-width:14px;"></i>' +
								'<span style="font-family:Consolas,monospace; font-size:0.82rem; font-weight:600;">' + (dep.libraryName || dep.include) + '</span>' +
								typeBadge +
							'</div>' +
							'<div class="text-muted" style="font-family:Consolas,monospace; font-size:0.7rem; margin-left:20px; word-break:break-all;">' + dep.include + '</div>' +
						'</div>'
					);
				});
			} else {
				$sysDepSection.addClass("d-none");
			}

			// Public functions section — parse .hsl files from discovered_files
			var sysPubFns = [];
			(discoveredFiles || []).forEach(function(f) {
				if (path.extname(f).toLowerCase() !== '.hsl') return;
				var relPath = f.replace(/^Library[\\\/]/i, '');
				var fullPath = path.join(sysLibDir, relPath);
				try {
					var text = fs.readFileSync(fullPath, 'utf8');
					var fileName = f.replace(/\\/g, '/').split('/').pop();
					var fns = parseHslFunctions(text, fileName);
					fns.forEach(function(fn) {
						if (!fn.isPrivate) {
							sysPubFns.push(fn);
						}
					});
				} catch(e) { /* file may not be readable */ }
			});
			var $fnSection = $("#libDetailModal .lib-detail-functions-section");
			var $fnList = $("#libDetailModal .lib-detail-functions-list");
			$fnList.empty();
			if (sysPubFns.length > 0) {
				$fnSection.removeClass("d-none");
				sysPubFns.forEach(function(fn) {
					var paramStr = (fn.params || []).map(function(p) {
						return '<span class="fn-param-type">' + (p.type || 'variable') + '</span>' +
							(p.byRef ? '<span class="fn-param-ref">&amp;</span> ' : ' ') +
							'<span class="fn-param-name">' + p.name + '</span>' +
							(p.array ? '<span class="fn-param-array">[]</span>' : '');
					}).join(', ');
					var retBadge = fn.returnType && fn.returnType !== 'void'
						? '<span class="badge badge-light ml-1" style="font-size:0.65rem; vertical-align:middle;">' + fn.returnType + '</span>'
						: '<span class="badge badge-light ml-1" style="font-size:0.65rem; vertical-align:middle; opacity:0.5;">void</span>';
					var docHtml = fn.doc
						? '<div class="fn-doc text-muted text-sm" style="margin-left:22px; font-size:0.75rem; white-space:pre-wrap;">' + $("<span>").text(fn.doc.split('\n')[0]).html() + '</div>'
						: '';
					$fnList.append(
						'<div class="fn-item" style="padding:3px 0; border-bottom:1px solid rgba(128,128,128,0.1);">' +
							'<div><i class="fas fa-cube fn-icon" style="color:var(--medium); font-size:0.7rem; margin-right:5px;"></i>' +
							'<span class="fn-name" style="font-family:Consolas,monospace; font-weight:600; font-size:0.82rem;">' + fn.qualifiedName + '</span>' +
							'<span style="font-family:Consolas,monospace; font-size:0.78rem; color:#888;">(' + paramStr + ')</span>' +
							retBadge + '</div>' +
							docHtml +
						'</div>'
					);
				});
				$fnList.prepend('<div class="text-muted text-sm mb-1"><i class="fas fa-info-circle mr-1"></i>' + sysPubFns.length + ' public function' + (sysPubFns.length !== 1 ? 's' : '') + '</div>');
			} else {
				$fnSection.addClass("d-none");
			}

			// Integrity verification for system libraries
			var integrity = verifySystemLibraryIntegrity(sLib);
			var $intSection = $("#libDetailModal .lib-detail-integrity-section");
			var $intStatus = $("#libDetailModal .lib-detail-integrity-status");
			var $intRepair = $("#libDetailModal .lib-detail-integrity-repair");
			$intStatus.empty();
			$intRepair.addClass("d-none");

			var libName = sLib.canonical_name || sLib.library_name;
			var baselineEntry = systemLibraryBaseline[libName];
			if ((baselineEntry && Object.keys(baselineEntry.files || {}).length > 0) || integrity.errors.length > 0 || integrity.warnings.length > 0) {
				$intSection.removeClass("d-none");

				if (!integrity.valid) {
					integrity.errors.forEach(function(err) {
						$intStatus.append('<div class="text-sm mb-1" style="color:#d9534f;"><i class="fas fa-times-circle mr-1"></i>' + err + '</div>');
					});
					// Show repair button if a backup package exists
					var cachedSys = listCachedVersions(libName);
					if (cachedSys.length > 0) {
						$intRepair.removeClass("d-none");
						$intRepair.find(".lib-detail-repair-btn").attr("data-sys-lib-name", libName);
					}
				}
				if (integrity.warnings.length > 0) {
					integrity.warnings.forEach(function(warn) {
						$intStatus.append('<div class="text-sm mb-1" style="color:#f0ad4e;"><i class="fas fa-exclamation-triangle mr-1"></i>' + warn + '</div>');
					});
				}
				if (integrity.valid && integrity.warnings.length === 0) {
					$intStatus.append('<div class="text-sm mb-1" style="color:#5cb85c;"><i class="fas fa-check-circle mr-1"></i>All tracked files pass integrity check</div>');
				}
			} else {
				$intSection.addClass("d-none");
			}

			// HIDE Delete and Export buttons for system libraries
			$("#libDetailModal .lib-detail-delete-btn").addClass("d-none");
			$("#libDetailModal .lib-detail-export-btn").addClass("d-none");

			// Store library id and mark as system
			$("#libDetailModal").attr("data-lib-id", libId);
			$("#libDetailModal").attr("data-system", "true");
			$("#libDetailModal").modal("show");
		}

		// ---- Repair from detail modal (works for both system and user libraries) ----
		$(document).on("click", ".lib-detail-repair-btn", function(e) {
			e.preventDefault();
			var sysLibName = $(this).attr("data-sys-lib-name");
			var userLibName = $(this).attr("data-user-lib-name");

			if (sysLibName) {
				// System library repair
				if (!confirm('Repair system library "' + sysLibName + '" from backup package?\n\nThis will restore all library files to their original state.')) return;
				var result = repairSystemLibraryFromCache(sysLibName);
				if (result.success) {
					// Refresh the detail modal
					var libId = $("#libDetailModal").attr("data-lib-id");
					if (libId) {
						$("#libDetailModal").modal("hide");
						setTimeout(function() { impShowSystemLibDetail(libId); }, 300);
					}
				}
			} else if (userLibName) {
				// User library repair
				if (!confirm('Repair library "' + userLibName + '" from cached package?\n\nThis will restore all library files from the newest cached version.')) return;
				repairLibraryFromCache(userLibName);
				// Refresh the detail modal
				var libId = $("#libDetailModal").attr("data-lib-id");
				if (libId) {
					$("#libDetailModal").modal("hide");
					setTimeout(function() { impShowLibDetail(libId); }, 300);
				}
			}
		});

		// ---- Export single library from detail modal ----
		$(document).on("click", ".lib-detail-export-btn", function(e) {
			e.preventDefault();
			var libId = $("#libDetailModal").attr("data-lib-id");
			if (!libId) return;
			// Block export for system libraries
			if (isSystemLibrary(libId)) {
				alert("System libraries are read-only and cannot be exported.");
				return;
			}
			var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
			if (!lib) { alert("Library not found."); return; }

			var libName = lib.library_name || "Unknown";
			$("#lib-export-save-dialog").attr("nwsaveas", libName + ".hxlibpkg");
			$("#lib-export-save-dialog").trigger("click");
		});

		$(document).on("change", "#lib-export-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			var libId = $("#libDetailModal").attr("data-lib-id");
			if (!libId) return;
			exportSingleLibrary(libId, savePath);
		});

		function exportSingleLibrary(libId, savePath) {
			try {
				var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
				if (!lib) { alert("Library not found."); return; }

				var libName = lib.library_name || "Unknown";
				var libBasePath = lib.lib_install_path || "";
				var demoBasePath = lib.demo_install_path || "";
				var libraryFiles = lib.library_files || [];
				var demoFiles = lib.demo_method_files || [];
				var helpFiles = lib.help_files || [];
				var comDlls = lib.com_register_dlls || [];

				// Verify library files exist
				for (var i = 0; i < libraryFiles.length; i++) {
					var fp = path.join(libBasePath, libraryFiles[i]);
					if (!fs.existsSync(fp)) {
						alert("Library file not found:\n" + fp + "\n\nExport aborted.");
						return;
					}
				}

				// Build library image data
				var libImageFilename = lib.library_image || null;
				var libImageBase64 = lib.library_image_base64 || null;
				var libImageMime = lib.library_image_mime || null;

				// Build manifest — include help_files for the importer
				// Also include CHMs in library_files for backward compatibility
				var manifestLibFiles = libraryFiles.slice();
				helpFiles.forEach(function(hf) {
					if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
				});

				var manifest = {
					format_version: "1.0",
					library_name: libName,
					author: lib.author || "",
					organization: lib.organization || "",
					version: lib.version || "",
					venus_compatibility: lib.venus_compatibility || "",
					description: lib.description || "",
					tags: lib.tags || [],
					created_date: new Date().toISOString(),
					library_image: libImageFilename,
					library_image_base64: libImageBase64,
					library_image_mime: libImageMime,
					library_files: manifestLibFiles,
					demo_method_files: demoFiles.slice(),
					help_files: helpFiles.slice(),
					com_register_dlls: comDlls.slice()
				};

				// Create ZIP package
				var zip = new AdmZip();

				// Add manifest
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files
				libraryFiles.forEach(function(f) {
					var fullPath = path.join(libBasePath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, "library");
					}
				});

				// Add help files (CHMs — packed into library/ folder)
				helpFiles.forEach(function(f) {
					var fullPath = path.join(libBasePath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, "library");
					}
				});

				// Add demo method files
				demoFiles.forEach(function(f) {
					var fullPath = path.join(demoBasePath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, "demo_methods");
					}
				});

				// Sign the package for integrity verification
				signPackageZip(zip);

				// Write ZIP
				zip.writeZip(savePath);

				alert("Library exported successfully!\n\n" +
					savePath + "\n\n" +
					"Library: " + libName + "\n" +
					"Library files: " + libraryFiles.length + "\n" +
					"Help files: " + helpFiles.length + "\n" +
					"Demo method files: " + demoFiles.length);

			} catch(e) {
				alert("Error exporting library:\n" + e.message);
			}
		}

		//**************************************************************************************
		//****** EXPORT ARCHIVE (.hxlibarch) - Bundle multiple libraries ***********************
		//**************************************************************************************

		// Click "Export Archive" from overflow menu
		$(document).on("click", ".overflow-export-archive", function(e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			expArchPopulateModal();
			$("#exportArchiveModal").modal("show");
		});

		// Populate the export archive modal with installed libraries
		function expArchPopulateModal() {
			var $list = $("#exp-arch-lib-list");
			$list.empty();

			var libs = db_installed_libs.installed_libs.find();
			// Filter out deleted and system libraries (system cannot be exported)
			libs = libs.filter(function(l) { return !l.deleted && !isSystemLibrary(l._id); });

			if (!libs || libs.length === 0) {
				$list.html(
					'<div class="text-muted text-center py-4">' +
						'<i class="fas fa-inbox fa-2x color-lightgray"></i>' +
						'<p class="mt-2">No installed libraries found.</p>' +
					'</div>'
				);
				$("#exp-arch-export").prop("disabled", true);
				expArchUpdateCount();
				return;
			}

			libs.forEach(function(lib) {
				var libName = lib.library_name || "Unknown";
				var version = lib.version || "";
				var author = lib.author || "";
				var libFiles = (lib.library_files || []).length;
				var demoFiles = (lib.demo_method_files || []).length;
				var hasImage = !!lib.library_image_base64;

				// Determine MIME type
				var imgMime = lib.library_image_mime || 'image/bmp';
				if (!lib.library_image_mime && lib.library_image) {
					var extLower = (lib.library_image || '').split('.').pop().toLowerCase();
					if (IMAGE_MIME_MAP[extLower]) imgMime = IMAGE_MIME_MAP[extLower];
				}

				// Build icon
				var iconHtml;
				if (hasImage) {
					iconHtml = '<img src="data:' + imgMime + ';base64,' + lib.library_image_base64 + '" style="max-width:36px; max-height:36px; border-radius:4px;">';
				} else {
					iconHtml = '<i class="fas fa-book fa-2x color-medium"></i>';
				}

				var str =
					'<div class="exp-arch-lib-item d-flex align-items-center p-2" data-lib-id="' + lib._id + '">' +
						'<div class="custom-control custom-checkbox mr-3">' +
							'<input type="checkbox" class="custom-control-input exp-arch-checkbox" id="exp-arch-chk-' + lib._id + '" data-lib-id="' + lib._id + '">' +
							'<label class="custom-control-label" for="exp-arch-chk-' + lib._id + '"></label>' +
						'</div>' +
						'<div class="mr-3 exp-arch-lib-icon">' + iconHtml + '</div>' +
						'<div class="flex-grow-1" style="min-width:0;">' +
							'<div class="font-weight-bold" style="color:var(--medium2);">' + libName + '</div>' +
							'<div class="text-muted text-sm">' +
								(version ? 'v' + version : '') +
								(author ? (version ? ' &middot; ' : '') + author : '') +
								' &middot; ' + libFiles + ' lib file' + (libFiles !== 1 ? 's' : '') +
								(demoFiles > 0 ? ', ' + demoFiles + ' demo file' + (demoFiles !== 1 ? 's' : '') : '') +
							'</div>' +
						'</div>' +
					'</div>';

				$list.append(str);
			});

			expArchUpdateCount();
		}

		// Update selected count display
		function expArchUpdateCount() {
			var count = $(".exp-arch-checkbox:checked").length;
			$("#exp-arch-selected-count").text(count + " selected");
			$("#exp-arch-export").prop("disabled", count === 0);
		}

		// Checkbox change
		$(document).on("change", ".exp-arch-checkbox", function() {
			expArchUpdateCount();
		});

		// Click on row to toggle checkbox
		$(document).on("click", ".exp-arch-lib-item", function(e) {
			if ($(e.target).hasClass("custom-control-input") || $(e.target).hasClass("custom-control-label")) return;
			var $chk = $(this).find(".exp-arch-checkbox");
			$chk.prop("checked", !$chk.prop("checked"));
			expArchUpdateCount();
		});

		// Select All
		$(document).on("click", "#exp-arch-select-all", function() {
			$(".exp-arch-checkbox").prop("checked", true);
			expArchUpdateCount();
		});

		// Select None
		$(document).on("click", "#exp-arch-select-none", function() {
			$(".exp-arch-checkbox").prop("checked", false);
			expArchUpdateCount();
		});

		// Export button click
		$(document).on("click", "#exp-arch-export", function() {
			var selectedIds = [];
			$(".exp-arch-checkbox:checked").each(function() {
				selectedIds.push($(this).attr("data-lib-id"));
			});
			if (selectedIds.length === 0) {
				alert("Please select at least one library to export.");
				return;
			}
			// Suggest a filename
			var suggestedName = "libraries";
			if (selectedIds.length === 1) {
				var singleLib = db_installed_libs.installed_libs.findOne({"_id": selectedIds[0]});
				if (singleLib) suggestedName = (singleLib.library_name || "library");
			}
			$("#exp-arch-save-dialog").attr("nwsaveas", suggestedName + ".hxlibarch");
			// Store selected ids for use in save handler
			$("#exp-arch-save-dialog").data("selectedIds", selectedIds);
			$("#exp-arch-save-dialog").trigger("click");
		});

		// Save dialog change
		$(document).on("change", "#exp-arch-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			var selectedIds = $(this).data("selectedIds") || [];
			if (selectedIds.length === 0) return;
			expArchCreateArchive(selectedIds, savePath);
			$("#exportArchiveModal").modal("hide");
		});

		// Core archive creation function
		// ---- Load static archive icon PNG ----
		function getArchiveIconPng() {
			try {
				if (!fs.existsSync(ARCHIVE_ICON_PATH)) return { base64: null, mime: null };
				var b64 = fs.readFileSync(ARCHIVE_ICON_PATH).toString('base64');
				return { base64: b64, mime: 'image/png' };
			} catch(e) {
				return { base64: null, mime: null };
			}
		}

		// Core archive creation function
		async function expArchCreateArchive(libIds, savePath) {
			try {
				var archiveZip = new AdmZip();
				var exportedLibs = [];
				var errors = [];

				libIds.forEach(function(libId) {
					var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
					if (!lib) {
						errors.push("Library ID " + libId + " not found in database.");
						return;
					}

					var libName = lib.library_name || "Unknown";
					var libBasePath = lib.lib_install_path || "";
					var demoBasePath = lib.demo_install_path || "";
					var libraryFiles = lib.library_files || [];
					var demoFiles = lib.demo_method_files || [];
					var helpFiles = lib.help_files || [];
					var comDlls = lib.com_register_dlls || [];

					// Include CHMs in manifest library_files for backward compatibility
					var manifestLibFiles = libraryFiles.slice();
					helpFiles.forEach(function(hf) {
						if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
					});

					// Build manifest for this library
					var manifest = {
						format_version: "1.0",
						library_name: libName,
						author: lib.author || "",
						organization: lib.organization || "",
						version: lib.version || "",
						venus_compatibility: lib.venus_compatibility || "",
						description: lib.description || "",
						tags: lib.tags || [],
						created_date: new Date().toISOString(),
						library_image: lib.library_image || null,
						library_image_base64: lib.library_image_base64 || null,
						library_image_mime: lib.library_image_mime || null,
						library_files: manifestLibFiles,
						demo_method_files: demoFiles.slice(),
						help_files: helpFiles.slice(),
						com_register_dlls: comDlls.slice()
					};

					// Create an inner zip for this library (.hxlibpkg)
					var innerZip = new AdmZip();

					// Add manifest
					innerZip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

					// Add library files
					var libFilesAdded = 0;
					libraryFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, "library");
							libFilesAdded++;
						}
					});

					// Add help files (CHMs — packed into library/ folder)
					helpFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, "library");
						}
					});

					// Add demo method files
					var demoFilesAdded = 0;
					demoFiles.forEach(function(f) {
						var fullPath = path.join(demoBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, "demo_methods");
							demoFilesAdded++;
						}
					});

					// Sign the inner package
					signPackageZip(innerZip);

					// Convert inner zip to buffer and add to archive
					var innerBuffer = innerZip.toBuffer();
					var innerFileName = libName.replace(/[<>:"\\\/|?*]/g, '_') + ".hxlibpkg";
					archiveZip.addFile(innerFileName, innerBuffer);

					exportedLibs.push({
						name: libName,
						libFiles: libFilesAdded,
						demoFiles: demoFilesAdded
					});
				});

				if (exportedLibs.length === 0) {
					alert("No libraries could be exported.\n\n" + errors.join("\n"));
					return;
				}

				// Load the static purple archive icon
				var archiveIconBase64 = null;
				var archiveIconMime = null;
				var iconResult = getArchiveIconPng();
				if (iconResult && iconResult.base64) {
					archiveIconBase64 = iconResult.base64;
					archiveIconMime = iconResult.mime || 'image/png';
				}

				// Add archive manifest
				var archManifest = {
					format_version: "1.0",
					archive_type: "hxlibarch",
					created_date: new Date().toISOString(),
					library_count: exportedLibs.length,
					libraries: exportedLibs.map(function(l) { return l.name; }),
					archive_icon: archiveIconBase64 ? 'archive_icon.png' : null,
					archive_icon_base64: archiveIconBase64,
					archive_icon_mime: archiveIconMime
				};
				archiveZip.addFile("archive_manifest.json", Buffer.from(JSON.stringify(archManifest, null, 2), "utf8"));

				// Add rendered archive icon to the zip
				if (archiveIconBase64) {
					archiveZip.addFile("icon/archive_icon.png", Buffer.from(archiveIconBase64, 'base64'));
				}

				// Write the archive
				archiveZip.writeZip(savePath);

				var summary = "Archive exported successfully!\n\n" +
					savePath + "\n\n" +
					"Libraries included (" + exportedLibs.length + "):\n";
				exportedLibs.forEach(function(l) {
					summary += "  - " + l.name + " (" + l.libFiles + " lib files, " + l.demoFiles + " demo files)\n";
				});

				if (errors.length > 0) {
					summary += "\nWarnings:\n" + errors.join("\n");
				}

				alert(summary);

			} catch(e) {
				alert("Error creating archive:\n" + e.message);
			}
		}

		//**************************************************************************************
		//****** IMPORT ARCHIVE (.hxlibarch) - Import multiple libraries at once ****************
		//**************************************************************************************

		// Import archive: extract each .hxlibpkg and install sequentially
		function impArchImportArchive(archivePath) {
			if (_isImporting) {
				alert("An import is already in progress. Please wait for it to complete.");
				return;
			}
			_isImporting = true;
			try {
				if (!fs.existsSync(archivePath)) {
					alert("Archive file not found:\n" + archivePath);
					return;
				}

				var archiveZip = new AdmZip(archivePath);
				var entries = archiveZip.getEntries();

				// Find all .hxlibpkg entries
				var pkgEntries = [];
				entries.forEach(function(entry) {
					if (!entry.isDirectory && entry.entryName.toLowerCase().endsWith('.hxlibpkg')) {
						pkgEntries.push(entry);
					}
				});

				if (pkgEntries.length === 0) {
					alert("No .hxlibpkg packages found in this archive.\n\nThe .hxlibarch file appears to be empty or invalid.");
					return;
				}

				var confirmMsg = "This archive contains " + pkgEntries.length + " library package" + (pkgEntries.length !== 1 ? "s" : "") + ":\n\n";
				pkgEntries.forEach(function(entry) {
					confirmMsg += "  - " + entry.entryName.replace('.hxlibpkg', '') + "\n";
				});
				confirmMsg += "\nDo you want to install all " + pkgEntries.length + " libraries?";

				if (!confirm(confirmMsg)) return;

				var results = { success: [], failed: [] };

				// Determine base install paths
				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";

				// Process each package
				pkgEntries.forEach(function(pkgEntry) {
					try {
						var pkgBuffer = pkgEntry.getData();
						var innerZip = new AdmZip(pkgBuffer);
						var manifestEntry = innerZip.getEntry("manifest.json");
						if (!manifestEntry) {
							results.failed.push(pkgEntry.entryName + ": manifest.json not found");
							return;
						}

						var manifestJson = innerZip.readAsText(manifestEntry);
						var manifest = JSON.parse(manifestJson);
						var libName = manifest.library_name || "Unknown";

						if (!isValidLibraryName(libName)) {
							results.failed.push(pkgEntry.entryName + ": invalid library name");
							return;
						}

						// Verify inner package signature
						var innerSig = verifyPackageSignature(innerZip);
						if (innerSig.signed && !innerSig.valid) {
							results.failed.push(libName + ": signature verification FAILED (" + innerSig.errors.join("; ") + ")");
							return;
						}

						var origLibFiles = manifest.library_files || [];
						var demoFiles = manifest.demo_method_files || [];
						var comDlls = manifest.com_register_dlls || [];

						// Auto-detect .chm help files from library_files
						var declaredHelp = manifest.help_files || [];
						var helpFiles = declaredHelp.slice();
						var libFiles = [];
						origLibFiles.forEach(function(f) {
							if (path.extname(f).toLowerCase() === '.chm') {
								if (helpFiles.indexOf(f) === -1) helpFiles.push(f);
							} else {
								libFiles.push(f);
							}
						});

						var libDestDir = path.join(libBasePath, libName);
						var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);
						var extractedCount = 0;

						// Create destination directories
						if ((libFiles.length > 0 || helpFiles.length > 0) && !fs.existsSync(libDestDir)) {
							fs.mkdirSync(libDestDir, { recursive: true });
						}
						if (demoFiles.length > 0 && !fs.existsSync(demoDestDir)) {
							fs.mkdirSync(demoDestDir, { recursive: true });
						}

						// Extract files
						var zipEntries = innerZip.getEntries();
						zipEntries.forEach(function(entry) {
							if (entry.entryName === "manifest.json" || entry.entryName === "signature.json") return;
							if (entry.entryName.indexOf("library/") === 0) {
								var fname = entry.entryName.substring("library/".length);
								if (fname) {
									var outPath = safeZipExtractPath(libDestDir, fname);
									if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("demo_methods/") === 0) {
								var fname = entry.entryName.substring("demo_methods/".length);
								if (fname) {
									var outPath = safeZipExtractPath(demoDestDir, fname);
									if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("help_files/") === 0) {
								var fname = entry.entryName.substring("help_files/".length);
								if (fname) {
									var outPath = safeZipExtractPath(libDestDir, fname);
									if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							}
						});

						// Update or insert DB record
						var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
						if (existing) {
							db_installed_libs.installed_libs.remove({"_id": existing._id});
						}

						// Compute integrity hashes
						var fileHashes = {};
						try { fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls); } catch(e) {}

						var dbRecord = {
							library_name: manifest.library_name || "",
							author: manifest.author || "",
							organization: manifest.organization || "",
							version: manifest.version || "",
							venus_compatibility: manifest.venus_compatibility || "",
							description: manifest.description || "",
							tags: manifest.tags || [],
							created_date: manifest.created_date || "",
							library_image: manifest.library_image || null,
							library_image_base64: manifest.library_image_base64 || null,
							library_image_mime: manifest.library_image_mime || null,
							library_files: libFiles,
							demo_method_files: manifest.demo_method_files || [],
							help_files: helpFiles,
							com_register_dlls: comDlls,
							com_warning: false,
							lib_install_path: libDestDir,
							demo_install_path: demoDestDir,
							installed_date: new Date().toISOString(),
							source_package: pkgEntry.entryName,
							file_hashes: fileHashes,
							public_functions: extractPublicFunctions(libFiles, libDestDir),
							required_dependencies: extractRequiredDependencies(libFiles, libDestDir)
						};
						var saved = db_installed_libs.installed_libs.save(dbRecord);

						// Auto-add to group if setting enabled
						var settings = db_settings.settings.findOne({"_id":"0"});
						if (!settings || settings.chk_autoAddToGroup !== false) {
							var navtree = db_tree.tree.find();
							var targetGroupId = null;
							for (var ti = 0; ti < navtree.length; ti++) {
								var gEntry = getGroupById(navtree[ti]["group-id"]);
								if (gEntry && !gEntry["default"]) {
									targetGroupId = navtree[ti]["group-id"];
									var existingIds = navtree[ti]["method-ids"] || [];
									existingIds.push(saved._id);
									db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
									break;
								}
							}
							if (!targetGroupId) {
								var newGroup = db_groups.groups.save({
									"name": "Libraries",
									"icon-class": "fa-book",
									"default": false,
									"navbar": "left",
									"favorite": true
								});
								db_tree.tree.save({
									"group-id": newGroup._id,
									"method-ids": [saved._id],
									"locked": false
								});
							}
						}

						results.success.push(libName + " (" + extractedCount + " files)");

						// Cache the package for repair & version rollback
						try {
							cachePackageToStore(pkgBuffer, libName, manifest.version);
						} catch(cacheErr) {
							console.warn('Could not cache package ' + libName + ': ' + cacheErr.message);
						}

					} catch(e) {
						results.failed.push(pkgEntry.entryName + ": " + e.message);
					}
				});

				// Show results
				var resultMsg = "Archive Import Complete\n\n";
				if (results.success.length > 0) {
					resultMsg += "Successfully installed (" + results.success.length + "):\n";
					results.success.forEach(function(n) { resultMsg += "  \u2705 " + n + "\n"; });
				}
				if (results.failed.length > 0) {
					resultMsg += "\nFailed (" + results.failed.length + "):\n";
					results.failed.forEach(function(n) { resultMsg += "  \u274C " + n + "\n"; });
				}

				alert(resultMsg);

				// Refresh the library cards
				impBuildLibraryCards();
				fitImporterHeight();

			} catch(e) {
				alert("Error importing archive:\n" + e.message);
			} finally {
				_isImporting = false;
			}
		}
		$(document).on("click", ".imp-lib-card-details, .imp-lib-card-name", function(e) {
			e.preventDefault();
			var libId = $(this).closest(".imp-lib-card-container").attr("data-lib-id");
			if (libId) impShowLibDetail(libId);
		});

		// ---- Open library/demo file when clicking a file link in the detail modal ----
		$(document).on("click", ".pkg-file-link", function(e) {
			e.preventDefault();
			var filePath = $(this).attr("data-filepath");
			if (filePath) {
				if (fs.existsSync(filePath)) {
					nw.Shell.openItem(filePath);
				} else {
					alert("File not found:\n" + filePath);
				}
			}
		});

		// ---- Show GitHub-style delete confirmation modal ----
		function showDeleteConfirmModal(libName, comDlls) {
			return new Promise(function(resolve) {
				var $modal = $("#deleteLibConfirmModal");
				var expectedText = libName;
				var resolved = false;

				// Set the library name in the header and the expected confirmation text
				$modal.find(".delete-confirm-libname-header").text(libName);
				$modal.find(".delete-confirm-expected-text").text(expectedText);
				$modal.find(".delete-confirm-input").val("");
				$modal.find(".delete-confirm-btn").prop("disabled", true);

				// Show consequences
				$modal.find(".delete-confirm-consequences").text(
					'This will delete "' + libName + '" and all associated files.'
				);

				// Show COM DLLs section if applicable
				if (comDlls && comDlls.length > 0) {
					$modal.find(".delete-confirm-com-section").removeClass("d-none");
					$modal.find(".delete-confirm-com-dlls").text(comDlls.join(", "));
				} else {
					$modal.find(".delete-confirm-com-section").addClass("d-none");
				}

				// Enable/disable the confirm button based on typed input
				$modal.find(".delete-confirm-input").off("input.deleteConfirm").on("input.deleteConfirm", function() {
					var typed = $(this).val().trim();
					$modal.find(".delete-confirm-btn").prop("disabled", typed !== expectedText);
				});

				// Confirm button handler
				$modal.find(".delete-confirm-btn").off("click.deleteConfirm").on("click.deleteConfirm", function() {
					if (!resolved) {
						resolved = true;
						$modal.modal("hide");
						resolve(true);
					}
				});

				// Cancel / dismiss handler
				$modal.off("hidden.bs.modal.deleteConfirm").on("hidden.bs.modal.deleteConfirm", function() {
					if (!resolved) {
						resolved = true;
						resolve(false);
					}
				});

				$modal.modal("show");
			});
		}

		// ---- Delete library from detail modal ----
		$(document).on("click", ".lib-detail-delete-btn", async function(e) {
			e.preventDefault();
			var libId = $("#libDetailModal").attr("data-lib-id");
			if (!libId) return;
			// Block delete for system libraries
			if (isSystemLibrary(libId)) {
				alert("System libraries are read-only and cannot be deleted.");
				return;
			}
			var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
			if (!lib) return;

			var libName = lib.library_name || "Unknown";
			var comDlls = lib.com_register_dlls || [];
			var hasComWarning = lib.com_warning === true;

			// Show styled delete confirmation modal (GitHub-style with name typing)
			var deleteConfirmed = await showDeleteConfirmModal(libName, comDlls);
			if (!deleteConfirmed) return;

			// --- COM deregistration FIRST (before deleting files) ---
			if (comDlls.length > 0) {
				var libPath = lib.lib_install_path || "";
				var shouldDeregister = true;

				// If the library has a COM warning (registration never succeeded), ask the user
				if (hasComWarning) {
					shouldDeregister = confirm(
						"This library has a COM registration warning (registration may not have completed successfully).\n\n" +
						"Would you like to attempt to COM deregister the following DLLs from the system?\n\n" +
						comDlls.join(", ") + "\n\n" +
						"Click OK to attempt deregistration, or Cancel to skip."
					);
				}

				if (shouldDeregister && libPath) {
					var comDllPaths = [];
					for (var ci = 0; ci < comDlls.length; ci++) {
						var dllFullPath = path.join(libPath, comDlls[ci]);
						if (fs.existsSync(dllFullPath)) {
							comDllPaths.push(dllFullPath);
						}
					}

					if (comDllPaths.length > 0) {
						var deregResult = await comRegisterMultipleDlls(comDllPaths, false);
						if (!deregResult.allSuccess) {
							var failedDlls = [];
							var errDetails = "";
							for (var ri = 0; ri < deregResult.results.length; ri++) {
								if (!deregResult.results[ri].success) {
									failedDlls.push(path.basename(deregResult.results[ri].dll));
									errDetails += "\n- " + path.basename(deregResult.results[ri].dll) + ": " + deregResult.results[ri].error;
								}
							}

							var continueMsg = "COM deregistration failed for:" + errDetails + "\n\n" +
								"Do you still want to proceed with deleting the library?\n" +
								"(The COM objects may remain registered on the system)";

							if (!confirm(continueMsg)) return;
						}
					}
				}
			}

			// --- Delete library files from disk ---
			var libFiles = lib.library_files || [];
			var libPath = lib.lib_install_path || "";
			if (libPath && libFiles.length > 0) {
				libFiles.forEach(function(f) {
					try {
						var fp = path.join(libPath, f);
						if (fs.existsSync(fp)) fs.unlinkSync(fp);
					} catch (ex) { console.warn("Could not delete lib file: " + f, ex); }
				});
			}

			// --- Delete help files from disk ---
			var helpFiles = lib.help_files || [];
			if (libPath && helpFiles.length > 0) {
				helpFiles.forEach(function(f) {
					try {
						var fp = path.join(libPath, f);
						if (fs.existsSync(fp)) fs.unlinkSync(fp);
					} catch (ex) { console.warn("Could not delete help file: " + f, ex); }
				});
			}

			// Remove the library folder if it is now empty
			if (libPath) {
				try {
					if (fs.existsSync(libPath)) {
						var remaining = fs.readdirSync(libPath);
						if (remaining.length === 0) fs.rmdirSync(libPath);
					}
				} catch (ex) { console.warn("Could not remove lib folder: " + libPath, ex); }
			}

			// --- Delete demo method files from disk ---
			var demoFiles = lib.demo_method_files || [];
			var demoPath = lib.demo_install_path || "";
			if (demoPath && demoFiles.length > 0) {
				demoFiles.forEach(function(f) {
					try {
						var fp = path.join(demoPath, f);
						if (fs.existsSync(fp)) fs.unlinkSync(fp);
					} catch (ex) { console.warn("Could not delete demo file: " + f, ex); }
				});
				// Remove the demo folder if it is now empty
				try {
					if (fs.existsSync(demoPath)) {
						var remaining = fs.readdirSync(demoPath);
						if (remaining.length === 0) fs.rmdirSync(demoPath);
					}
				} catch (ex) { console.warn("Could not remove demo folder: " + demoPath, ex); }
			}

			// --- Soft-delete: mark as deleted but keep in history ---
			db_installed_libs.installed_libs.update({"_id": libId}, {
				deleted: true,
				deleted_date: new Date().toISOString()
			}, {multi: false, upsert: false});

			// --- Remove from tree ---
			var navtree = db_tree.tree.find();
			for (var ti = 0; ti < navtree.length; ti++) {
				var mids = navtree[ti]["method-ids"] || [];
				var idx = mids.indexOf(libId);
				if (idx !== -1) {
					mids.splice(idx, 1);
					db_tree.tree.update({"group-id": navtree[ti]["group-id"]}, {"method-ids": mids}, {multi: false, upsert: false});
					break;
				}
			}

			// Close the modal and rebuild the card list
			$("#libDetailModal").modal("hide");
			impBuildLibraryCards();
		});

		// ---- Browse for .hxlibpkg or .hxlibarch file ----
		$(document).on("click", "#imp-browse", function() {
			$("#imp-input-file").trigger("click");
		});

		$(document).on("change", "#imp-input-file", function() {
			var fileInput = this;
			var filePath = "";
			if (fileInput.files && fileInput.files.length > 0) {
				filePath = fileInput.files[0].path;
			} else {
				filePath = $(this).val();
			}
			$(this).val('');
			if (!filePath) return;

			var ext = path.extname(filePath).toLowerCase();
			if (ext === ".hxlibarch") {
				impArchImportArchive(filePath);
			} else {
				impLoadAndInstall(filePath);
			}
		});

		// ---- Load, preview, confirm and install package ----
		async function impLoadAndInstall(filePath) {
			if (_isImporting) {
				alert("An import is already in progress. Please wait for it to complete.");
				return;
			}
			_isImporting = true;
			try {
				var zipBuffer = fs.readFileSync(filePath);
				var zip = new AdmZip(zipBuffer);
				var manifestEntry = zip.getEntry("manifest.json");
				if (!manifestEntry) {
					alert("Invalid package: manifest.json not found.");
					return;
				}
				var manifestJson = zip.readAsText(manifestEntry);
				var manifest = JSON.parse(manifestJson);

				// ---- Verify package signature ----
				var sigResult = verifyPackageSignature(zip);
				if (sigResult.signed && !sigResult.valid) {
					var sigMsg = "WARNING: Package signature verification FAILED!\n\n";
					sigResult.errors.forEach(function(e) { sigMsg += "  \u274C " + e + "\n"; });
					sigMsg += "\nThis package may be corrupted or tampered with.\nDo you want to continue anyway?";
					if (!confirm(sigMsg)) return;
				}

				// ---- Restricted author check on import ----
				// If the package claims "Hamilton" as author but is NOT a known system library,
				// require password authorization before allowing the import.
				var importAuthor = (manifest.author || '').trim();
				if (isRestrictedAuthor(importAuthor)) {
					// Check if this library name matches a known system library
					var isKnownSysLib = systemLibraries.some(function(s) {
						return s.canonical_name === manifest.library_name || s.library_name === manifest.library_name;
					});
					if (!isKnownSysLib) {
						var pwOk = await promptAuthorPassword();
						if (!pwOk) {
							alert('Import cancelled. The package author "Hamilton" requires authorization for non-system libraries.');
							return;
						}
					}
				}

				var libName = manifest.library_name || "Unknown";
				if (!isValidLibraryName(libName)) {
					alert("Invalid library name: \"" + libName + "\".\nLibrary names cannot contain path separators, '..', or special characters.");
					_isImporting = false;
					return;
				}
				var libFiles = manifest.library_files || [];
				var demoFiles = manifest.demo_method_files || [];

				// Auto-detect .chm help files from library_files
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
				libFiles = filteredLibFiles;

				// Determine install paths
				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				var libDestDir = path.join(libBasePath, libName);
				var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);

				// ---- Populate the import preview modal ----
				var $modal = $("#importPreviewModal");

				// Icon / image in header
				var $icon = $modal.find(".imp-preview-icon");
				$icon.empty();
				var imgMime = manifest.library_image_mime || 'image/bmp';
				if (!manifest.library_image_mime && manifest.library_image) {
					var extLower = (manifest.library_image || '').split('.').pop().toLowerCase();
					if (IMAGE_MIME_MAP[extLower]) imgMime = IMAGE_MIME_MAP[extLower];
				}
				if (manifest.library_image_base64) {
					$icon.html('<img src="data:' + imgMime + ';base64,' + manifest.library_image_base64 + '" style="max-width:56px; max-height:56px; border-radius:6px;">');
				} else {
					$icon.html('<i class="fas fa-book fa-3x" style="color:var(--medium)"></i>');
				}

				// Metadata
				$modal.find(".imp-preview-name").text(libName);
				$modal.find(".imp-preview-version").text(manifest.version ? "v" + manifest.version : "");
				$modal.find(".imp-preview-author").text(manifest.author || "\u2014");
				$modal.find(".imp-preview-organization").text(manifest.organization || "\u2014");
				$modal.find(".imp-preview-venus").text(manifest.venus_compatibility || "\u2014");
				$modal.find(".imp-preview-created").text(manifest.created_date ? new Date(manifest.created_date).toLocaleString() : "\u2014");

				// Description
				if (manifest.description) {
					$modal.find(".imp-preview-description").text(manifest.description);
					$modal.find(".imp-preview-desc-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-desc-section").addClass("d-none");
				}

				// Tags
				var tags = manifest.tags || [];
				var $tagsContainer = $modal.find(".imp-preview-tags");
				$tagsContainer.empty();
				if (tags.length > 0) {
					tags.forEach(function(t) {
						$tagsContainer.append('<span class="badge badge-light mr-1" style="font-size:0.8rem;">' + escapeHtml(t) + '</span>');
					});
					$modal.find(".imp-preview-tags-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-tags-section").addClass("d-none");
				}

				// Library image in body
				if (manifest.library_image_base64) {
					$modal.find(".imp-preview-image").attr("src", "data:" + imgMime + ";base64," + manifest.library_image_base64);
					$modal.find(".imp-preview-image-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-image-section").addClass("d-none");
				}

				// Library files list
				var comDlls = manifest.com_register_dlls || [];
				var $libFilesList = $modal.find(".imp-preview-lib-files");
				$libFilesList.empty();
				if (libFiles.length === 0) {
					$libFilesList.html('<div class="text-muted text-center py-2 pkg-empty-msg"><i class="fas fa-inbox mr-1"></i>None</div>');
				} else {
					libFiles.forEach(function(f) {
						var isCom = comDlls.indexOf(f) !== -1;
						var comBadge = isCom ? '<span class="badge badge-info ml-2" title="This DLL will be registered as a COM object using RegAsm.exe /codebase. Administrator rights are required."><i class="fas fa-cog mr-1"></i>COM</span>' : '';
						$libFilesList.append(
							'<div class="pkg-file-item"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + f + '</span>' + comBadge + '</div>'
						);
					});
				}

				// COM registration notice
				if (comDlls.length > 0) {
					$modal.find(".imp-preview-com-section").removeClass("d-none");
					$modal.find(".imp-preview-com-list").text(comDlls.join(", "));
				} else {
					$modal.find(".imp-preview-com-section").addClass("d-none");
				}

				// Demo files list
				var $demoFilesList = $modal.find(".imp-preview-demo-files");
				$demoFilesList.empty();
				if (demoFiles.length === 0) {
					$demoFilesList.html('<div class="text-muted text-center py-2 pkg-empty-msg"><i class="fas fa-inbox mr-1"></i>None</div>');
				} else {
					demoFiles.forEach(function(f) {
						$demoFilesList.append(
							'<div class="pkg-file-item"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + f + '</span></div>'
						);
					});
				}

				// Help files list
				var $helpFilesList = $modal.find(".imp-preview-help-files");
				$helpFilesList.empty();
				if (helpFiles.length > 0) {
					helpFiles.forEach(function(f) {
						$helpFilesList.append(
							'<div class="pkg-file-item"><i class="fas fa-question-circle pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + f + '</span></div>'
						);
					});
					$modal.find(".imp-preview-help-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-help-section").addClass("d-none");
				}

				// Package signature status
				var $sigStatus = $modal.find(".imp-preview-signature-status");
				if ($sigStatus.length > 0) {
					$sigStatus.empty();
					if (sigResult.signed && sigResult.valid) {
						$sigStatus.html('<div class="d-flex align-items-center text-success"><i class="fas fa-shield-alt mr-2"></i><span>Package signature verified &mdash; integrity confirmed</span></div>');
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					} else if (sigResult.signed && !sigResult.valid) {
						var errHtml = '<div class="text-danger"><i class="fas fa-exclamation-triangle mr-2"></i><strong>Signature verification FAILED</strong></div>';
						sigResult.errors.forEach(function(e) {
							errHtml += '<div class="text-danger text-sm ml-4">&bull; ' + e + '</div>';
						});
						$sigStatus.html(errHtml);
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					} else {
						$sigStatus.html('<div class="d-flex align-items-center text-muted"><i class="fas fa-info-circle mr-2"></i><span>Unsigned package (legacy) &mdash; no signature to verify</span></div>');
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					}
				}

				// Install paths
				$modal.find(".imp-preview-lib-path").text("Library \u2192 " + libDestDir);
				$modal.find(".imp-preview-demo-path").text("Demo Methods \u2192 " + demoDestDir);

				// Check for existing library
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					$modal.find(".imp-preview-overwrite-warning").removeClass("d-none");
					$modal.find(".imp-preview-overwrite-text").text('A library named "' + libName + '" is already installed (v' + (existing.version || '?') + '). It will be updated.');
				} else {
					$modal.find(".imp-preview-overwrite-warning").addClass("d-none");
				}

				// Store data for confirm handler
				$modal.data("imp-zip", zip);
				$modal.data("imp-manifest", manifest);
				$modal.data("imp-libDestDir", libDestDir);
				$modal.data("imp-demoDestDir", demoDestDir);
				$modal.data("imp-filePath", filePath);
				$modal.data("imp-helpFiles", helpFiles);
				$modal.data("imp-filteredLibFiles", libFiles);

				$modal.modal("show");

			} catch(e) {
				alert("Error reading package:\n" + e.message);
			} finally {
				_isImporting = false;
			}
		}

		// ---- Confirm install from preview modal ----
		$(document).on("click", "#imp-preview-confirm", async function() {
			var $modal = $("#importPreviewModal");
			var zip = $modal.data("imp-zip");
			var manifest = $modal.data("imp-manifest");
			var libDestDir = $modal.data("imp-libDestDir");
			var demoDestDir = $modal.data("imp-demoDestDir");
			var filePath = $modal.data("imp-filePath");

			if (!zip || !manifest) return;

			var libName = manifest.library_name || "Unknown";
			var helpFiles = $modal.data("imp-helpFiles") || [];
			var libFiles = $modal.data("imp-filteredLibFiles") || [];
			var demoFiles = manifest.demo_method_files || [];
			var comDlls = manifest.com_register_dlls || [];
			var comWarning = false;  // tracks if COM registration failed but user chose to proceed

			// ---- COM REGISTRATION FIRST (before extracting files) ----
			if (comDlls.length > 0) {
				// We need to extract the DLLs to a temp location first for registration,
				// then move them to the final location.
				// Actually, we extract to the final location first, register, and if it fails
				// we can still clean up.

				// Create the library destination so we can extract COM DLLs
				if (!fs.existsSync(libDestDir)) {
					fs.mkdirSync(libDestDir, { recursive: true });
				}

				// Extract only the COM DLLs first
				var zipEntries = zip.getEntries();
				var comDllPaths = [];
				for (var ci = 0; ci < comDlls.length; ci++) {
					var comDllName = comDlls[ci];
					for (var ei = 0; ei < zipEntries.length; ei++) {
						var entry = zipEntries[ei];
						if (entry.entryName === "library/" + comDllName) {
							var outPath = path.join(libDestDir, comDllName);
							fs.writeFileSync(outPath, entry.getData());
							comDllPaths.push(outPath);
							break;
						}
					}
				}

				// Attempt COM registration with UAC elevation
				if (comDllPaths.length > 0) {
					var regResult = await comRegisterMultipleDlls(comDllPaths, true);

					if (!regResult.allSuccess) {
						// Build error message
						var failedDlls = [];
						var errDetails = "";
						for (var ri = 0; ri < regResult.results.length; ri++) {
							if (!regResult.results[ri].success) {
								failedDlls.push(path.basename(regResult.results[ri].dll));
								errDetails += "\n- " + path.basename(regResult.results[ri].dll) + ": " + regResult.results[ri].error;
							}
						}

						var proceedMsg = "COM registration failed for the following DLL(s):\n" + errDetails + "\n\n" +
							"This library may not work correctly without COM registration.\n\n" +
							"Do you still want to proceed with the import?\n" +
							"(The library card will be marked with a warning)";

						if (!confirm(proceedMsg)) {
							// User chose not to proceed - clean up extracted COM DLLs
							for (var di = 0; di < comDllPaths.length; di++) {
								try { if (fs.existsSync(comDllPaths[di])) fs.unlinkSync(comDllPaths[di]); } catch(ex) {}
							}
							// Remove libDestDir if empty
							try {
								if (fs.existsSync(libDestDir)) {
									var rem = fs.readdirSync(libDestDir);
									if (rem.length === 0) fs.rmdirSync(libDestDir);
								}
							} catch(ex) {}
							return;
						}
						comWarning = true;
					}
				}
			}

			try {
				var extractedCount = 0;

				// Create destination directories
				if (libFiles.length > 0 || helpFiles.length > 0) {
					if (!fs.existsSync(libDestDir)) {
						fs.mkdirSync(libDestDir, { recursive: true });
					}
				}
				if (demoFiles.length > 0) {
					if (!fs.existsSync(demoDestDir)) {
						fs.mkdirSync(demoDestDir, { recursive: true });
					}
				}

				// Extract files (skip COM DLLs already extracted above)
				var zipEntries = zip.getEntries();
				zipEntries.forEach(function(entry) {
					if (entry.entryName === "manifest.json" || entry.entryName === "signature.json") return;

					if (entry.entryName.indexOf("library/") === 0) {
						var fname = entry.entryName.substring("library/".length);
						if (fname) {
							// Skip COM DLLs already extracted
							if (comDlls.indexOf(fname) !== -1) {
								extractedCount++;
								return;
							}
							var outPath = safeZipExtractPath(libDestDir, fname);
							if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(outPath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(outPath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("demo_methods/") === 0) {
						var fname = entry.entryName.substring("demo_methods/".length);
						if (fname) {
							var outPath = safeZipExtractPath(demoDestDir, fname);
							if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(outPath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(outPath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("help_files/") === 0) {
						// Legacy/explicit help_files folder — extract to library directory
						var fname = entry.entryName.substring("help_files/".length);
						if (fname) {
							var outPath = safeZipExtractPath(libDestDir, fname);
							if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(outPath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(outPath, entry.getData());
							extractedCount++;
						}
					}
				});

				// Check if already exists in DB (update if so)
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				// Save to DB
				// Compute integrity hashes for installed files
				var fileHashes = computeLibraryHashes(
					libFiles,
					libDestDir,
					comDlls
				);

				var dbRecord = {
					library_name: manifest.library_name || "",
					author: manifest.author || "",
					organization: manifest.organization || "",
					version: manifest.version || "",
					venus_compatibility: manifest.venus_compatibility || "",
					description: manifest.description || "",
					tags: manifest.tags || [],
					created_date: manifest.created_date || "",
					library_image: manifest.library_image || null,
					library_image_base64: manifest.library_image_base64 || null,
					library_image_mime: manifest.library_image_mime || null,
					library_files: libFiles,
					demo_method_files: manifest.demo_method_files || [],
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: comWarning,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: path.basename(filePath),
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFiles, libDestDir),
					required_dependencies: extractRequiredDependencies(libFiles, libDestDir)
				};
				var saved = db_installed_libs.installed_libs.save(dbRecord);

				// Add the new library to the appropriate group in the tree
				var navtree = db_tree.tree.find();
				var targetGroupId = null;

				// If author is Hamilton, auto-assign to the Hamilton group
				var savedAuthor = (manifest.author || '').trim();
				if (isRestrictedAuthor(savedAuthor)) {
					// Find or create the Hamilton group entry in the tree
					var hamiltonTreeEntry = null;
					for (var ti = 0; ti < navtree.length; ti++) {
						if (navtree[ti]["group-id"] === "gHamilton") {
							hamiltonTreeEntry = navtree[ti];
							break;
						}
					}
					if (hamiltonTreeEntry) {
						targetGroupId = "gHamilton";
						var existingIds = hamiltonTreeEntry["method-ids"] || [];
						existingIds.push(saved._id);
						// Use raw file I/O to safely update tree (diskdb update may replace entire record)
						var treePath = path.join(USER_DATA_DIR, 'tree.json');
						var treeData = JSON.parse(fs.readFileSync(treePath, 'utf8'));
						for (var ui = 0; ui < treeData.length; ui++) {
							if (treeData[ui]["group-id"] === "gHamilton") {
								treeData[ui]["method-ids"] = existingIds;
								break;
							}
						}
						fs.writeFileSync(treePath, JSON.stringify(treeData), 'utf8');
						db_tree = db.connect(USER_DATA_DIR, ['tree']);
					} else {
						// Hamilton group is hardcoded; just create the tree entry
						var treePath2 = path.join(USER_DATA_DIR, 'tree.json');
						var treeData2 = JSON.parse(fs.readFileSync(treePath2, 'utf8'));
						treeData2.push({
							"group-id": "gHamilton",
							"method-ids": [saved._id],
							"locked": true
						});
						fs.writeFileSync(treePath2, JSON.stringify(treeData2), 'utf8');
						db_tree = db.connect(USER_DATA_DIR, ['tree']);
						targetGroupId = "gHamilton";
					}
				} else {
					// Non-Hamilton author: add to first custom group
					for (var ti = 0; ti < navtree.length; ti++) {
						var gEntry = getGroupById(navtree[ti]["group-id"]);
						if (gEntry && !gEntry["default"]) {
							targetGroupId = navtree[ti]["group-id"];
							var existingIds = navtree[ti]["method-ids"] || [];
							existingIds.push(saved._id);
							db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
							break;
						}
					}
				}
				// If no target group was found, create a default one
				if (!targetGroupId) {
					var newGroup = db_groups.groups.save({
						"name": "Libraries",
						"icon-class": "fa-book",
						"default": false,
						"navbar": "left",
						"favorite": true
					});
					db_tree.tree.save({
						"group-id": newGroup._id,
						"method-ids": [saved._id],
						"locked": false
					});
				}

				// Close modal and refresh
				$modal.modal("hide");
				impBuildLibraryCards();

				// Cache the package for repair & version rollback
				var cachedPath = '';
				try {
					var pkgBuffer = fs.readFileSync(filePath);
					cachedPath = cachePackageToStore(pkgBuffer, libName, manifest.version);
				} catch(cacheErr) {
					console.warn('Could not cache package: ' + cacheErr.message);
				}

				// Show styled success modal
				var $sm = $("#importSuccessModal");
				$sm.find(".import-success-libname").text(libName);
				$sm.find(".import-success-filecount").text(extractedCount + " file" + (extractedCount !== 1 ? "s" : "") + " installed");

				var pathsHtml = "";
				if (libFiles.length > 0) {
					pathsHtml += '<div class="path-label">Library Files</div>';
					pathsHtml += '<div class="path-value">' + libDestDir.replace(/</g, '&lt;') + '</div>';
				}
				if (demoFiles.length > 0) {
					pathsHtml += '<div class="path-label">Demo Methods</div>';
					pathsHtml += '<div class="path-value">' + demoDestDir.replace(/</g, '&lt;') + '</div>';
				}
				if (cachedPath) {
					pathsHtml += '<div class="path-label">Package Cached</div>';
					pathsHtml += '<div class="path-value">' + cachedPath.replace(/</g, '&lt;') + '</div>';
				}
				$sm.find(".import-success-paths").html(pathsHtml);
				if (!pathsHtml) $sm.find(".import-success-paths").addClass("d-none"); else $sm.find(".import-success-paths").removeClass("d-none");

				var $comStatus = $sm.find(".import-success-com-status");
				$comStatus.removeClass("com-warning com-ok").addClass("d-none");
				if (comWarning) {
					$comStatus.removeClass("d-none").addClass("com-warning")
						.html('<i class="fas fa-exclamation-triangle mr-1"></i>COM registration failed. The library card has been marked with a warning.');
				} else if (comDlls.length > 0) {
					$comStatus.removeClass("d-none").addClass("com-ok")
						.html('<i class="fas fa-check mr-1"></i>COM DLLs registered: ' + comDlls.join(", "));
				}

				$sm.modal("show");

			} catch(e) {
				alert("Error installing package:\n" + e.message);
			}
		});

		//**************************************************************************************
		//****** AUDIT LOG CONSTANTS ***********************************************************
		//**************************************************************************************
		var AUDIT_SIGNING_KEY = 'VenusLibMgr::AuditIntegrity::b9f4e7c2a1d8';
		var AUDIT_SIG_PREFIX  = '$$INTEGRITY_SIGNATURE$$ ';

		//****** RUN LIBRARY AUDIT *************************************************************
		//**************************************************************************************

		// Click "Run Library Audit" from overflow menu
		$(document).on("click", ".overflow-audit", function(e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");

			// Save to configured Hamilton Logfiles directory (fall back to default)
			var logFolderRec = db_links.links.findOne({"_id":"log-folder"});
			var logDir = (logFolderRec && logFolderRec.path) ? logFolderRec.path : "C:\\Program Files (x86)\\HAMILTON\\LogFiles";
			try {
				if (!fs.existsSync(logDir)) {
					fs.mkdirSync(logDir, { recursive: true });
				}
			} catch(mkdirErr) {
				alert("Error creating log directory:\n" + logDir + "\n\n" + mkdirErr.message);
				return;
			}
			var unixTime = Math.floor(Date.now() / 1000);
			var savePath = path.join(logDir, "libraryAuditLog_" + unixTime + ".txt");
			generateLibraryAuditLog(savePath);
		});

		/**
		 * Generates a full library audit log and writes it to the specified path.
		 * Includes all installed (user) libraries and all system libraries with
		 * their state, integrity, file hashes, and metadata.
		 * @param {string} savePath - Full path to write the audit log file
		 */
		function generateLibraryAuditLog(savePath) {
			try {
				var lines = [];
				var separator = "=".repeat(90);
				var subSeparator = "-".repeat(70);
				var now = new Date();

				// ---- Header ----
				lines.push(separator);
				lines.push("  LIBRARY AUDIT LOG");
				lines.push(separator);
				lines.push("Generated:        " + now.toISOString());
				lines.push("Unix Timestamp:   " + Math.floor(now.getTime() / 1000));
				lines.push("Computer:         " + os.hostname());
				lines.push("Username:         " + (os.userInfo().username || "Unknown"));
				lines.push("OS:               " + os.type() + " " + os.release() + " (" + os.arch() + ")");

				// VENUS paths
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var metFolderRec = db_links.links.findOne({"_id":"met-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metDir = (metFolderRec && metFolderRec.path) ? metFolderRec.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				lines.push("VENUS Library Dir: " + sysLibDir);
				lines.push("VENUS Methods Dir: " + metDir);
				lines.push("");

				// ---- Summary counts ----
				var installedLibs = db_installed_libs.installed_libs.find() || [];
				var activeLibs = installedLibs.filter(function(l) { return !l.deleted; });
				var deletedLibs = installedLibs.filter(function(l) { return l.deleted === true; });
				var sysLibs = getAllSystemLibraries();

				lines.push("SUMMARY");
				lines.push(subSeparator);
				lines.push("Installed libraries (active):   " + activeLibs.length);
				lines.push("Installed libraries (deleted):  " + deletedLibs.length);
				lines.push("System libraries:               " + sysLibs.length);
				lines.push("Total libraries audited:        " + (installedLibs.length + sysLibs.length));
				lines.push("");
				lines.push("");

				// ---- Installed (User) Libraries ----
				lines.push(separator);
				lines.push("  INSTALLED (USER) LIBRARIES");
				lines.push(separator);
				lines.push("");

				if (installedLibs.length === 0) {
					lines.push("  (No installed libraries found)");
					lines.push("");
				} else {
					for (var i = 0; i < installedLibs.length; i++) {
						var lib = installedLibs[i];
						var libName = lib.library_name || "Unknown";
						var integrity = verifyLibraryIntegrity(lib);

						lines.push(subSeparator);
						lines.push("Library:          " + libName);
						lines.push("ID:               " + (lib._id || ""));
						lines.push("Version:          " + (lib.version || "N/A"));
						lines.push("Author:           " + (lib.author || "N/A"));
						lines.push("Organization:     " + (lib.organization || "N/A"));
						lines.push("Description:      " + (lib.description || ""));
						lines.push("VENUS Compat.:    " + (lib.venus_compatibility || "N/A"));
						lines.push("Tags:             " + ((lib.tags && lib.tags.length > 0) ? lib.tags.join(", ") : "None"));
						lines.push("Status:           " + (lib.deleted ? "DELETED" : "Active"));
						lines.push("Created Date:     " + (lib.created_date || "N/A"));
						lines.push("Installed Date:   " + (lib.installed_date || "N/A"));
						if (lib.deleted && lib.deleted_date) {
							lines.push("Deleted Date:     " + lib.deleted_date);
						}
						lines.push("Source Package:   " + (lib.source_package || "N/A"));
						lines.push("Install Path:     " + (lib.lib_install_path || "N/A"));
						lines.push("Demo Path:        " + (lib.demo_install_path || "N/A"));

						// COM DLLs
						var comDlls = lib.com_register_dlls || [];
						lines.push("COM DLLs:         " + (comDlls.length > 0 ? comDlls.join(", ") : "None"));
						lines.push("COM Warning:      " + (lib.com_warning ? "YES" : "No"));

						// Integrity status
						var intStatus = integrity.valid ? "PASS" : "FAIL";
						if (integrity.valid && integrity.warnings.length > 0) intStatus = "WARNING";
						lines.push("Integrity:        " + intStatus);
						if (integrity.errors.length > 0) {
							integrity.errors.forEach(function(err) {
								lines.push("  [ERROR]  " + err);
							});
						}
						if (integrity.warnings.length > 0) {
							integrity.warnings.forEach(function(w) {
								lines.push("  [WARN]   " + w);
							});
						}

						// Library files
						var libFiles = lib.library_files || [];
						lines.push("Library Files (" + libFiles.length + "):");
						libFiles.forEach(function(f) {
							var fullPath = path.join(lib.lib_install_path || "", f);
							var exists = fs.existsSync(fullPath);
							var storedHash = (lib.file_hashes && lib.file_hashes[f]) ? lib.file_hashes[f] : null;
							var currentHash = exists ? computeFileHash(fullPath) : null;
							var hashMatch = (storedHash && currentHash) ? (storedHash === currentHash ? "MATCH" : "MISMATCH") : "N/A";
							lines.push("  - " + f);
							lines.push("      Exists: " + (exists ? "Yes" : "NO - MISSING"));
							if (storedHash)   lines.push("      Stored Hash:  " + storedHash);
							if (currentHash)  lines.push("      Current Hash: " + currentHash);
							if (storedHash || currentHash) lines.push("      Hash Status:  " + hashMatch);
						});

						// Demo files
						var demoFiles = lib.demo_method_files || [];
						if (demoFiles.length > 0) {
							lines.push("Demo Files (" + demoFiles.length + "):");
							demoFiles.forEach(function(f) {
								var fullPath = path.join(lib.demo_install_path || "", f);
								var exists = fs.existsSync(fullPath);
								lines.push("  - " + f + (exists ? "" : "  [MISSING]"));
							});
						}

						// Public functions
						var pubFns = lib.public_functions || [];
						if (pubFns.length > 0) {
							lines.push("Public Functions (" + pubFns.length + "):");
							pubFns.forEach(function(fn) {
								lines.push("  - " + (fn.qualifiedName || fn.name || ""));
							});
						}

						lines.push("");
					}
				}

				// ---- System Libraries ----
				lines.push("");
				lines.push(separator);
				lines.push("  SYSTEM LIBRARIES (Hamilton Base)");
				lines.push(separator);
				lines.push("");

				if (sysLibs.length === 0) {
					lines.push("  (No system libraries found)");
					lines.push("");
				} else {
					for (var s = 0; s < sysLibs.length; s++) {
						var sLib = sysLibs[s];
						var sLibName = sLib.canonical_name || sLib.library_name || "Unknown";
						var sIntegrity = verifySystemLibraryIntegrity(sLib);

						lines.push(subSeparator);
						lines.push("Library:          " + (sLib.display_name || sLibName));
						lines.push("Canonical Name:   " + sLibName);
						lines.push("ID:               " + (sLib._id || ""));
						lines.push("Author:           " + (sLib.author || "Hamilton"));
						lines.push("Organization:     " + (sLib.organization || "Hamilton"));
						lines.push("Type:             System (Read-Only)");
						lines.push("First Seen:       " + (sLib.first_seen_at || "N/A"));
						lines.push("Last Seen:        " + (sLib.last_seen_at || "N/A"));
						lines.push("Source Root:      " + (sLib.source_root || "Library"));
						lines.push("Has Primary Def:  " + (sLib.has_primary_definition ? "Yes" : "No"));

						// Resource types
						var resTypes = sLib.resource_types || [];
						lines.push("Resource Types:   " + (resTypes.length > 0 ? resTypes.join(", ") : "N/A"));

						// Integrity status
						var sIntStatus = sIntegrity.valid ? "PASS" : "FAIL";
						if (sIntegrity.valid && sIntegrity.warnings.length > 0) sIntStatus = "WARNING";
						lines.push("Integrity:        " + sIntStatus);
						if (sIntegrity.errors.length > 0) {
							sIntegrity.errors.forEach(function(err) {
								lines.push("  [ERROR]  " + err);
							});
						}
						if (sIntegrity.warnings.length > 0) {
							sIntegrity.warnings.forEach(function(w) {
								lines.push("  [WARN]   " + w);
							});
						}

						// Discovered files with integrity verification
						var discoveredFiles = sLib.discovered_files || [];
						var baselineEntry = systemLibraryBaseline[sLibName];
						var storedFiles = (baselineEntry && baselineEntry.files) ? baselineEntry.files : {};
						lines.push("Discovered Files (" + discoveredFiles.length + "):");
						discoveredFiles.forEach(function(f) {
							var relPath = f.replace(/^Library[\\\/]/i, '');
							var fullPath = path.join(sysLibDir, relPath);
							var exists = fs.existsSync(fullPath);
							var baseFileName = relPath.replace(/\\/g, '/').split('/').pop();
							var storedInfo = storedFiles[baseFileName] || null;
							var ext = path.extname(baseFileName).toLowerCase();

							lines.push("  - " + f);
							lines.push("      Exists: " + (exists ? "Yes" : "NO - MISSING"));

							if (storedInfo && exists) {
								var footer = parseHslMetadataFooter(fullPath);
								lines.push("      Method:       Hamilton Footer ($$valid$$, $$checksum$$)");
								lines.push("      Stored Valid: " + storedInfo.valid + "  Checksum: " + (storedInfo.checksum || "N/A"));
								if (footer) {
									lines.push("      Current Valid:" + footer.valid + "  Checksum: " + footer.checksum);
									var footerMatch = (storedInfo.valid === footer.valid && storedInfo.checksum === footer.checksum) ? "MATCH" : "MISMATCH";
									lines.push("      Status:       " + footerMatch);
								} else {
									lines.push("      Current:      No footer found");
									lines.push("      Status:       FOOTER REMOVED");
								}
							} else if (!storedInfo) {
								lines.push("      Status:       No baseline stored");
							}
						});

						lines.push("");
					}
				}

				// ---- Footer ----
				lines.push("");
				lines.push(separator);
				lines.push("  END OF AUDIT LOG");
				lines.push(separator);
				lines.push("Total entries: " + (installedLibs.length + sysLibs.length));
				lines.push("Audit completed at: " + new Date().toISOString());
				lines.push("");

				// Build content body and compute HMAC-SHA256 integrity signature
				var content = lines.join("\r\n");
				var hmac = crypto.createHmac('sha256', AUDIT_SIGNING_KEY);
				hmac.update(content, 'utf8');
				var signature = hmac.digest('hex');
				content += "\r\n" + AUDIT_SIG_PREFIX + signature;

				// Write file
				fs.writeFileSync(savePath, content, 'utf8');

				// Show styled success modal
				var $am = $("#auditSuccessModal");
				$am.find(".audit-success-path").text(savePath);
				$am.modal("show");

			} catch(e) {
				alert("Error generating audit log:\n" + e.message);
				console.error("Audit log error:", e);
			}
		}

		//****** CHECK AUDIT FILE **************************************************************
		//**************************************************************************************

		// Click "Check Audit File" from overflow menu
		$(document).on("click", ".overflow-check-audit", function(e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			$("#audit-open-dialog").val('');
			$("#audit-open-dialog").trigger("click");
		});

		// Audit file selected for verification
		$(document).on("change", "#audit-open-dialog", function() {
			var filePath = $(this).val();
			if (!filePath) return;
			$(this).val('');
			verifyAuditLogIntegrity(filePath);
		});

		/**
		 * Verifies the integrity of a saved audit log file by checking
		 * the embedded HMAC-SHA256 signature against the file body.
		 * @param {string} filePath - Full path to the audit log file
		 */
		function verifyAuditLogIntegrity(filePath) {
			var $vm = $("#auditVerifyModal");
			try {
				var raw = fs.readFileSync(filePath, 'utf8');

				// Find the signature line
				var sigIdx = raw.lastIndexOf(AUDIT_SIG_PREFIX);
				if (sigIdx === -1) {
					showAuditVerifyResult($vm, false, path.basename(filePath),
						'No integrity signature found in this file.\nThe file may not be a signed audit log, or the signature line was removed.');
					return;
				}

				// Split body (everything before the sig line) and stored signature
				var body = raw.substring(0, sigIdx);
				var storedSig = raw.substring(sigIdx + AUDIT_SIG_PREFIX.length).trim();

				// Remove trailing CRLF/LF from body that was added before signature
				body = body.replace(/\r?\n$/, '');

				// Recompute HMAC on body
				var hmac = crypto.createHmac('sha256', AUDIT_SIGNING_KEY);
				hmac.update(body, 'utf8');
				var computedSig = hmac.digest('hex');

				if (computedSig === storedSig) {
					showAuditVerifyResult($vm, true, path.basename(filePath),
						'The audit log integrity signature is valid.\nThis file has not been modified since it was generated.');
				} else {
					showAuditVerifyResult($vm, false, path.basename(filePath),
						'Signature mismatch — the file contents have been altered.\n\nStored:    ' + storedSig + '\nComputed: ' + computedSig);
				}
			} catch(e) {
				showAuditVerifyResult($vm, false, path.basename(filePath),
					'Error reading audit log:\n' + e.message);
			}
		}

		function showAuditVerifyResult($modal, passed, fileName, message) {
			var icon = passed
				? '<i class="fas fa-check-circle" style="color:#28a745;"></i>'
				: '<i class="fas fa-times-circle" style="color:#dc3545;"></i>';
			var title = passed ? 'Integrity Check Passed' : 'Integrity Check Failed';
			$modal.find(".audit-verify-icon").html(icon);
			$modal.find(".audit-verify-title").text(title);
			$modal.find(".audit-verify-filename").text(fileName);
			$modal.find(".audit-verify-message").text(message);
			$modal.modal("show");
		}

		//**************************************************************************************
		//****** VERIFY & REPAIR TOOL **********************************************************
		//**************************************************************************************

		// Click "Verify & Repair" from overflow menu
		$(document).on("click", ".overflow-repair", function(e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			repairPopulateModal();
			$("#repairModal").modal("show");
		});

		/**
		 * Populate the repair modal with all installed libraries
		 * (both user and system) and their integrity + cached package status.
		 */
		function repairPopulateModal() {
			var $list = $(".repair-lib-list");
			$list.empty();

			// ---- User-installed libraries ----
			var libs = db_installed_libs.installed_libs.find() || [];
			libs = libs.filter(function(l) { return !l.deleted && !isSystemLibrary(l._id); });

			// ---- System libraries ----
			var sysLibs = getAllSystemLibraries();

			if (libs.length === 0 && sysLibs.length === 0) {
				$list.html(
					'<div class="text-muted text-center py-4">' +
						'<i class="fas fa-inbox fa-2x color-lightgray"></i>' +
						'<p class="mt-2">No installed libraries to verify.</p>' +
					'</div>'
				);
				$(".repair-all-btn").prop("disabled", true);
				$(".repair-status-text").text('');
				return;
			}

			var failCount = 0;
			var warnCount = 0;
			var totalCount = 0;

			// ---- Render system libraries first ----
			if (sysLibs.length > 0) {
				$list.append('<div class="py-1 px-1 mt-1 mb-1" style="font-size:0.75rem; font-weight:600; color:var(--medium); text-transform:uppercase; letter-spacing:0.5px;"><i class="fas fa-lock mr-1"></i>System Libraries</div>');
			}

			sysLibs.forEach(function(sLib) {
				totalCount++;
				var libName = sLib.canonical_name || sLib.library_name;
				var integrity = verifySystemLibraryIntegrity(sLib);
				var cached = listCachedVersions(libName);
				var hasCached = cached.length > 0;

				var statusClass, statusIcon, statusText;
				if (!integrity.valid) {
					statusClass = 'text-danger';
					statusIcon = 'fa-times-circle';
					statusText = 'FAILED';
					failCount++;
				} else if (integrity.warnings.length > 0) {
					statusClass = 'text-warning';
					statusIcon = 'fa-exclamation-triangle';
					statusText = 'WARNING';
					warnCount++;
				} else {
					statusClass = 'text-success';
					statusIcon = 'fa-check-circle';
					statusText = 'OK';
				}

				var detailLines = [];
				integrity.errors.forEach(function(e) { detailLines.push('<span class="text-danger text-sm">&bull; ' + e + '</span>'); });
				integrity.warnings.forEach(function(w) { detailLines.push('<span class="text-warning text-sm">&bull; ' + w + '</span>'); });

				var repairBtnHtml = '';
				if (!integrity.valid && hasCached) {
					repairBtnHtml = '<button class="btn btn-sm btn-outline-success repair-single-btn ml-2" data-lib-name="' + libName.replace(/"/g, '&quot;') + '" data-is-system="true" title="Restore from backup package"><i class="fas fa-wrench mr-1"></i>Repair</button>';
				} else if (!integrity.valid && !hasCached) {
					repairBtnHtml = '<span class="text-muted text-sm ml-2" title="No backup package available. Run first-run backup to create one."><i class="fas fa-ban mr-1"></i>No backup</span>';
				}

				var cachedInfo = hasCached
					? '<span class="text-muted text-sm ml-2" title="' + cached.length + ' backup version(s) available"><i class="fas fa-archive mr-1"></i>' + cached.length + ' backup</span>'
					: '';

				var html =
					'<div class="repair-lib-item d-flex align-items-start py-2 px-1" style="border-bottom:1px solid var(--bg-divider);" data-lib-name="' + libName.replace(/"/g, '&quot;') + '" data-is-system="true">' +
						'<div class="mr-3 mt-1"><i class="fas ' + statusIcon + ' ' + statusClass + '"></i></div>' +
						'<div class="flex-grow-1" style="min-width:0;">' +
							'<div class="d-flex align-items-center flex-wrap">' +
								'<span class="font-weight-bold" style="color:var(--medium2);">' + libName + '</span>' +
								'<span class="badge badge-secondary ml-2" style="font-size:0.6rem;">System</span>' +
								'<span class="ml-2 ' + statusClass + ' text-sm font-weight-bold">' + statusText + '</span>' +
								cachedInfo +
							'</div>' +
							(detailLines.length > 0 ? '<div class="mt-1">' + detailLines.join('<br>') + '</div>' : '') +
						'</div>' +
						'<div class="ml-2 d-flex align-items-center" style="white-space:nowrap;">' + repairBtnHtml + '</div>' +
					'</div>';

				$list.append(html);
			});

			// ---- Render user-installed libraries ----
			if (libs.length > 0) {
				$list.append('<div class="py-1 px-1 mt-2 mb-1" style="font-size:0.75rem; font-weight:600; color:var(--medium); text-transform:uppercase; letter-spacing:0.5px;"><i class="fas fa-cube mr-1"></i>Installed Libraries</div>');
			}

			libs.forEach(function(lib) {
				totalCount++;
				var libName = lib.library_name || "Unknown";
				var integrity = verifyLibraryIntegrity(lib);
				var cached = listCachedVersions(libName);
				var hasCached = cached.length > 0;

				var statusClass, statusIcon, statusText;
				if (!integrity.valid) {
					statusClass = 'text-danger';
					statusIcon = 'fa-times-circle';
					statusText = 'FAILED';
					failCount++;
				} else if (integrity.warnings.length > 0) {
					statusClass = 'text-warning';
					statusIcon = 'fa-exclamation-triangle';
					statusText = 'WARNING';
					warnCount++;
				} else {
					statusClass = 'text-success';
					statusIcon = 'fa-check-circle';
					statusText = 'OK';
				}

				var detailLines = [];
				integrity.errors.forEach(function(e) { detailLines.push('<span class="text-danger text-sm">&bull; ' + e + '</span>'); });
				integrity.warnings.forEach(function(w) { detailLines.push('<span class="text-warning text-sm">&bull; ' + w + '</span>'); });

				var repairBtnHtml = '';
				if (!integrity.valid && hasCached) {
					repairBtnHtml = '<button class="btn btn-sm btn-outline-success repair-single-btn ml-2" data-lib-name="' + libName.replace(/"/g, '&quot;') + '" data-is-system="false" title="Re-install from cached package"><i class="fas fa-wrench mr-1"></i>Repair</button>';
				} else if (!integrity.valid && !hasCached) {
					repairBtnHtml = '<span class="text-muted text-sm ml-2" title="No cached package available for repair"><i class="fas fa-ban mr-1"></i>No cached pkg</span>';
				}

				var cachedInfo = hasCached
					? '<span class="text-muted text-sm ml-2" title="' + cached.length + ' cached version(s) available"><i class="fas fa-archive mr-1"></i>' + cached.length + ' cached</span>'
					: '';

				var html =
					'<div class="repair-lib-item d-flex align-items-start py-2 px-1" style="border-bottom:1px solid var(--bg-divider);" data-lib-name="' + libName.replace(/"/g, '&quot;') + '" data-is-system="false">' +
						'<div class="mr-3 mt-1"><i class="fas ' + statusIcon + ' ' + statusClass + '"></i></div>' +
						'<div class="flex-grow-1" style="min-width:0;">' +
							'<div class="d-flex align-items-center flex-wrap">' +
								'<span class="font-weight-bold" style="color:var(--medium2);">' + libName + '</span>' +
								'<span class="badge badge-light ml-2">' + (lib.version || '') + '</span>' +
								'<span class="ml-2 ' + statusClass + ' text-sm font-weight-bold">' + statusText + '</span>' +
								cachedInfo +
							'</div>' +
							(detailLines.length > 0 ? '<div class="mt-1">' + detailLines.join('<br>') + '</div>' : '') +
						'</div>' +
						'<div class="ml-2 d-flex align-items-center" style="white-space:nowrap;">' + repairBtnHtml + '</div>' +
					'</div>';

				$list.append(html);
			});

			var statusParts = [];
			statusParts.push(totalCount + ' librar' + (totalCount === 1 ? 'y' : 'ies'));
			if (failCount > 0) statusParts.push(failCount + ' failed');
			if (warnCount > 0) statusParts.push(warnCount + ' warning' + (warnCount !== 1 ? 's' : ''));
			if (failCount === 0 && warnCount === 0) statusParts.push('all OK');
			$(".repair-status-text").text(statusParts.join(' \u2022 '));
			$(".repair-all-btn").prop("disabled", failCount === 0);
		}

		// Repair a single library from its cached package
		$(document).on("click", ".repair-single-btn", function(e) {
			e.stopPropagation();
			var libName = $(this).attr("data-lib-name");
			if (!libName) return;
			var isSys = $(this).attr("data-is-system") === "true";
			if (isSys) {
				repairSystemLibraryFromCache(libName);
				repairPopulateModal();
			} else {
				repairLibraryFromCache(libName);
			}
		});

		// Repair all failed libraries
		$(document).on("click", ".repair-all-btn", function() {
			var failedItems = $(".repair-lib-item").filter(function() {
				return $(this).find(".fa-times-circle").length > 0;
			});
			var names = [];
			failedItems.each(function() {
				var name = $(this).attr("data-lib-name");
				var isSys = $(this).attr("data-is-system") === "true";
				if (name) names.push({ name: name, isSystem: isSys });
			});
			if (names.length === 0) return;
			var nameList = names.map(function(n) { return (n.isSystem ? '[System] ' : '') + n.name; }).join("\n");
			if (!confirm("Repair " + names.length + " librar" + (names.length === 1 ? "y" : "ies") + " from cached/backup packages?\n\n" + nameList)) return;
			var repaired = 0;
			var errors = [];
			names.forEach(function(item) {
				var result;
				if (item.isSystem) {
					result = repairSystemLibraryFromCache(item.name, true);
				} else {
					result = repairLibraryFromCache(item.name, true);
				}
				if (result.success) repaired++;
				else errors.push(item.name + ": " + result.error);
			});
			var msg = repaired + " of " + names.length + " librar" + (names.length === 1 ? "y" : "ies") + " repaired.";
			if (errors.length > 0) msg += "\n\nErrors:\n" + errors.join("\n");
			alert(msg);
			repairPopulateModal();
		});

		/**
		 * Repair a library by re-extracting files from the newest cached package.
		 * Verifies the cached package signature before extracting.
		 * @param {string} libName - Library name to repair
		 * @param {boolean} [silent] - If true, suppress alerts (for batch repair)
		 * @returns {{ success: boolean, error: string }}
		 */
		function repairLibraryFromCache(libName, silent) {
			try {
				var cached = listCachedVersions(libName);
				if (cached.length === 0) {
					var msg = 'No cached packages found for "' + libName + '".';
					if (!silent) alert(msg);
					return { success: false, error: msg };
				}

				// Use the newest cached version
				var newest = cached[0];
				var zip;
				try {
					zip = new AdmZip(newest.fullPath);
				} catch(e) {
					var msg2 = 'Failed to read cached package: ' + e.message;
					if (!silent) alert(msg2);
					return { success: false, error: msg2 };
				}

				// Verify the cached package signature
				var sigResult = verifyPackageSignature(zip);
				if (sigResult.signed && !sigResult.valid) {
					var msg3 = 'Cached package signature verification FAILED.\nThe cached package itself may be corrupted.\n\n' + sigResult.errors.join('\n');
					if (!silent) alert(msg3);
					return { success: false, error: 'Cached package signature failed' };
				}

				var manifestEntry = zip.getEntry('manifest.json');
				if (!manifestEntry) {
					var msg4 = 'Cached package is invalid (no manifest.json).';
					if (!silent) alert(msg4);
					return { success: false, error: msg4 };
				}
				var manifest = JSON.parse(zip.readAsText(manifestEntry));

				// Find the installed library record
				var lib = db_installed_libs.installed_libs.findOne({ library_name: libName });
				if (!lib) {
					var msg5 = 'Library "' + libName + '" not found in database.';
					if (!silent) alert(msg5);
					return { success: false, error: msg5 };
				}

				var libDestDir = lib.lib_install_path || '';
				var demoDestDir = lib.demo_install_path || '';
				if (!libDestDir) {
					var msg6 = 'Library install path unknown.';
					if (!silent) alert(msg6);
					return { success: false, error: msg6 };
				}

				// Re-extract library files
				if (!fs.existsSync(libDestDir)) {
					fs.mkdirSync(libDestDir, { recursive: true });
				}
				if (demoDestDir && !fs.existsSync(demoDestDir)) {
					fs.mkdirSync(demoDestDir, { recursive: true });
				}

				var extractedCount = 0;
				var zipEntries = zip.getEntries();
				zipEntries.forEach(function(entry) {
					if (entry.isDirectory || entry.entryName === 'manifest.json' || entry.entryName === 'signature.json') return;
					if (entry.entryName.indexOf('library/') === 0) {
						var fname = entry.entryName.substring('library/'.length);
						if (fname) {
							var safePath = safeZipExtractPath(libDestDir, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf('demo_methods/') === 0) {
						var fname2 = entry.entryName.substring('demo_methods/'.length);
						if (fname2 && demoDestDir) {
							var safePath2 = safeZipExtractPath(demoDestDir, fname2);
							if (!safePath2) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir2 = path.dirname(safePath2);
							if (!fs.existsSync(parentDir2)) fs.mkdirSync(parentDir2, { recursive: true });
							fs.writeFileSync(safePath2, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf('help_files/') === 0) {
						var fname3 = entry.entryName.substring('help_files/'.length);
						if (fname3) {
							var safePath3 = safeZipExtractPath(libDestDir, fname3);
							if (!safePath3) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir3 = path.dirname(safePath3);
							if (!fs.existsSync(parentDir3)) fs.mkdirSync(parentDir3, { recursive: true });
							fs.writeFileSync(safePath3, entry.getData());
							extractedCount++;
						}
					}
				});

				// Recompute hashes
				var libFiles = lib.library_files || [];
				var comDlls = lib.com_register_dlls || [];
				var fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls);

				// Update DB record with fresh hashes
				db_installed_libs.installed_libs.update({ _id: lib._id }, {
					file_hashes: fileHashes
				}, { multi: false, upsert: false });

				if (!silent) {
					alert('Library "' + libName + '" repaired successfully!\n\n' +
						extractedCount + ' files re-extracted from cached package.\n' +
						'Version: ' + (newest.version || '?') +
						(sigResult.signed ? '\nPackage signature: verified' : ''));
					repairPopulateModal();
					impBuildLibraryCards();
				}

				return { success: true, error: '' };

			} catch(e) {
				var errMsg = 'Repair failed: ' + e.message;
				if (!silent) alert(errMsg);
				return { success: false, error: errMsg };
			}
		}

        //**************************************************************************************
        //******  FUNCTION DECLARATIONS END ****************************************************
        //**************************************************************************************
		


		