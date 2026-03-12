
		// main.js v1.93.25
		// Author: Zachary Milot

		var gui = require('nw.gui');
		var win = gui.Window.get();
		var path = require('path');
		var spawn = require('child_process').spawn; 

		// ---------------------------------------------------------------------------
		// Global error boundary - catch unhandled errors to prevent silent failures
		// ---------------------------------------------------------------------------
		window.onerror = function(message, source, lineno, colno, error) {
			console.error('Unhandled error:', message, 'at', source, ':', lineno);
			try { _isImporting = false; } catch(_) {}
			return false; // allow default browser error handling to continue
		};
		window.addEventListener('unhandledrejection', function(event) {
			console.error('Unhandled promise rejection:', event.reason);
			try { _isImporting = false; } catch(_) {}
		});

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

		const fs = require('fs');
		// image-size removed - no longer used
		const os = require("os");
		const crypto = require('crypto');
		const shared = require('../lib/shared');
		const SearchIndex = require('../lib/search-index');

		/** Shared MIME type lookup for image file extensions (from shared.js) */
		var IMAGE_MIME_MAP = shared.IMAGE_MIME_MAP;

		/** Sanitize a ZIP entry filename - delegated to shared module */
		var safeZipExtractPath = shared.safeZipExtractPath;

		/** Escape HTML - delegated to shared module */
		var escapeHtml = shared.escapeHtml;

		/** Validate library name - delegated to shared module */
		var isValidLibraryName = shared.isValidLibraryName;

		/**
		 * Get the current Windows username via WScript.Network COM object.
		 * Falls back to os.userInfo().username if the COM call fails.
		 */
		function getWindowsUsername() {
			try {
				var network = new ActiveXObject('WScript.Network');
				return network.UserName || os.userInfo().username || 'Unknown';
			} catch(e) {
				return os.userInfo().username || 'Unknown';
			}
		}

		// ---- Windows Security Group Detection & Regulated Environment Access Control ----
		// Detects the current user's Windows group membership via `whoami /groups`.
		// Used to enforce access control on protected library management actions
		// (import, delete, rollback) when regulated environment mode is enabled.
		//
		// Precedence (allow overrides deny):
		//   1. User is in Lab Method Programmer OR Lab Service => ALLOWED
		//   2. User is in Lab Operator, Lab Operator 2, or Lab Remote Service => DENIED
		//   3. User is not in any Hamilton group:
		//      - Regulated mode ON  => DENIED  (strict default deny)
		//      - Regulated mode OFF => ALLOWED (compatibility default allow)

		var ALLOW_GROUPS = ['lab method programmer', 'lab service'];
		var DENY_GROUPS  = ['lab operator', 'lab operator 2', 'lab remote service'];

		/**
		 * Check if the current user is a Windows Administrator.
		 * Administrators are on the "super whitelist" and receive full access
		 * to all library management actions and settings.
		 * @returns {boolean}
		 */
		function isWindowsAdmin() {
			var groups = getWindowsGroups();
			for (var i = 0; i < groups.length; i++) {
				if (groups[i] === 'administrators' ||
				    groups[i].indexOf('builtin\\administrators') !== -1 ||
				    groups[i].indexOf('\\administrators') !== -1) {
					return true;
				}
			}
			return false;
		}

		/** Cached group membership result and timestamp */
		var _cachedGroups = null;
		var _cachedGroupsTime = 0;
		var GROUP_CACHE_TTL_MS = 15000; // 15 second cache

		/**
		 * Get the current user's Windows security groups.
		 * Uses `whoami /groups /fo csv /nh` and caches for 15 seconds.
		 * @returns {string[]} Array of lowercase group names
		 */
		function getWindowsGroups() {
			var now = Date.now();
			if (_cachedGroups && (now - _cachedGroupsTime) < GROUP_CACHE_TTL_MS) {
				return _cachedGroups;
			}
			try {
				var groupExecSync = require('child_process').execSync;
				var raw = groupExecSync('whoami /groups /fo csv /nh', { encoding: 'utf8', timeout: 10000 });
				var groups = [];
				var lines = raw.split('\n');
				for (var i = 0; i < lines.length; i++) {
					var line = lines[i].trim();
					if (!line) continue;
					// CSV format: "GROUP_NAME","Type","SID","Attributes"
					var match = line.match(/^"([^"]+)"/);
					if (match) {
						var fullGroupName = match[1].toLowerCase();
						// Extract just the group name after the domain backslash
						var parts = fullGroupName.split('\\');
						var shortName = parts[parts.length - 1];
						groups.push(shortName);
						// Also keep full qualified name for matching
						if (parts.length > 1) groups.push(fullGroupName);
					}
				}
				_cachedGroups = groups;
				_cachedGroupsTime = now;
				return groups;
			} catch(e) {
				console.warn('Could not query Windows groups: ' + e.message);
				_cachedGroups = [];
				_cachedGroupsTime = now;
				return [];
			}
		}

		/**
		 * Check if the current user is in any of the given group names.
		 * @param {string[]} targetGroups - lowercase group names to check
		 * @returns {boolean}
		 */
		function isInAnyGroup(targetGroups) {
			var userGroups = getWindowsGroups();
			for (var i = 0; i < targetGroups.length; i++) {
				for (var j = 0; j < userGroups.length; j++) {
					if (userGroups[j] === targetGroups[i] || userGroups[j].indexOf(targetGroups[i]) !== -1) {
						return true;
					}
				}
			}
			return false;
		}

		/**
		 * Check if the current user is allowed to perform a protected library
		 * management action (import, delete, rollback).
		 *
		 * When regulated environment mode is OFF (default):
		 *   Users not in any Hamilton group are ALLOWED (compatibility mode).
		 *
		 * When regulated environment mode is ON:
		 *   Users not in any Hamilton group are DENIED (strict default deny).
		 *
		 * In both modes, allow groups override deny groups.
		 *
		 * @returns {{ allowed: boolean, reason: string }}
		 */
		function canManageLibraries() {
			// Step 0: Administrators are on the super whitelist - always allowed
			if (isWindowsAdmin()) {
				return { allowed: true, reason: 'Windows Administrator (super whitelist)' };
			}

			// Step 1: Check allow groups (highest privilege wins)
			if (isInAnyGroup(ALLOW_GROUPS)) {
				return { allowed: true, reason: 'Member of authorized group' };
			}

			// Step 2: Check deny groups
			if (isInAnyGroup(DENY_GROUPS)) {
				return { allowed: false, reason: 'Your user group does not have permission to manage libraries.\n\nAuthorized groups: Lab Method Programmer, Lab Service.\nYour group assignment restricts this action.' };
			}

			// Step 3: Not in any Hamilton group - check regulated mode
			var regulatedMode = false;
			try {
				var s = db_settings.settings.findOne({"_id":"0"});
				regulatedMode = !!(s && s.chk_regulatedEnvironment);
			} catch(e) { console.warn('Could not read regulated mode setting: ' + e.message); }

			if (regulatedMode) {
				return { allowed: false, reason: 'Regulated environment mode is enabled.\n\nOnly users assigned to authorized groups (Lab Method Programmer, Lab Service) can manage libraries.\nContact your system administrator for access.' };
			}

			// Compatibility mode - allow by default
			return { allowed: true, reason: 'Compatibility mode (no group restriction)' };
		}

		/**
		 * Check if the current user is allowed to change the regulated environment setting.
		 * Administrators and members of authorized groups (Lab Method Programmer, Lab Service)
		 * can toggle this setting. In unregulated mode, any user can change all other settings,
		 * but only authorized group members or admins can toggle regulated mode ON, preventing
		 * false/accidental enabling of this mode.
		 * @returns {boolean}
		 */
		function canToggleRegulatedMode() {
			return isWindowsAdmin() || isInAnyGroup(ALLOW_GROUPS);
		}

		/**
		 * Check if the current user can change general settings (non-regulated-mode settings).
		 * In unregulated mode: any user can change all settings except toggling regulated mode on.
		 * In regulated mode: only authorized groups or admins can change settings.
		 * Administrators always have full settings access (super whitelist).
		 * @returns {boolean}
		 */
		function canChangeSettings() {
			if (isWindowsAdmin()) return true;
			var regulatedMode = false;
			try {
				var s = db_settings.settings.findOne({"_id":"0"});
				regulatedMode = !!(s && s.chk_regulatedEnvironment);
			} catch(e) { console.warn('Could not read regulated mode setting: ' + e.message); }
			if (!regulatedMode) return true; // Unregulated: any user can change settings
			return isInAnyGroup(ALLOW_GROUPS); // Regulated: only authorized groups
		}

		/**
		 * Show the Access Denied modal with the given reason.
		 * @param {string} actionName - e.g. "Import", "Delete", "Rollback"
		 * @param {string} reason - explanation text
		 */
		function showAccessDeniedModal(actionName, reason) {
			var $modal = $("#accessDeniedModal");
			$modal.find(".access-denied-action").text(actionName);
			$modal.find(".access-denied-reason").text(reason);
			$modal.find(".access-denied-user").text(getWindowsUsername());
			var groups = getWindowsGroups();
			var displayGroups = groups.length > 0 ? groups.filter(function(g) { return g.indexOf('\\') === -1; }).join(', ') : '(none detected)';
			$modal.find(".access-denied-groups").text(displayGroups);
			$modal.modal("show");
		}

		/**
		 * Query the Windows registry for Hamilton VENUS install date and version.
		 * Returns { version: string|null, installDate: string|null (ISO 8601 UTC) }
		 */
		function getVENUSInstallInfo() {
			var result = { version: null, installDate: null };
			try {
				var execSync = require('child_process').execSync;

				// Query all Uninstall keys and find Hamilton VENUS by name
				var regPaths = [
					'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
					'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
				];

				for (var rp = 0; rp < regPaths.length; rp++) {
					try {
						// List subkeys under Uninstall
						var subkeysRaw = require('child_process').execFileSync('reg', ['query', regPaths[rp]], { encoding: 'utf8', timeout: 10000 });
						var subkeys = subkeysRaw.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });

						for (var sk = 0; sk < subkeys.length; sk++) {
							try {
								var entryRaw = require('child_process').execFileSync('reg', ['query', subkeys[sk], '/v', 'DisplayName'], { encoding: 'utf8', timeout: 5000 });
								if (!/Hamilton\s+VENUS\s+\d/i.test(entryRaw)) continue;

								// Found the Hamilton VENUS entry - read all values
								var allVals = require('child_process').execFileSync('reg', ['query', subkeys[sk]], { encoding: 'utf8', timeout: 5000 });

								// Extract DisplayVersion
								var verMatch = allVals.match(/DisplayVersion\s+REG_SZ\s+(.+)/i);
								if (verMatch) result.version = verMatch[1].trim();

								// Extract InstallDate (YYYYMMDD format)
								var dateMatch = allVals.match(/InstallDate\s+REG_SZ\s+(\d{8})/i);
								if (dateMatch) {
									var ds = dateMatch[1];
									result.installDate = new Date(Date.UTC(
										parseInt(ds.substring(0,4), 10),
										parseInt(ds.substring(4,6), 10) - 1,
										parseInt(ds.substring(6,8), 10)
									)).toISOString();
								}

								// If we got a version, we found the right entry - stop searching
								if (result.version) break;
							} catch(e2) { /* skip subkey */ }
						}
					} catch(e3) { /* skip registry path */ }
					if (result.version) break;
				}

				// Fallback for install date: use the HAMILTON folder creation time
				if (!result.installDate) {
					try {
						var hamiltonDir = 'C:\\Program Files (x86)\\HAMILTON';
						if (fs.existsSync(hamiltonDir)) {
							var stats = fs.statSync(hamiltonDir);
							result.installDate = stats.birthtime.toISOString();
						}
					} catch(e4) { /* ignore */ }
				}
			} catch(e) {
				console.warn('Could not query VENUS install info from registry: ' + e.message);
			}
			return result;
		}

		/**
		 * Stamp system libraries with VENUS install metadata (install date, version,
		 * installed_by). Runs once on first launch, tracked by the
		 * 'sysLibMetadataComplete' setting. Writes metadata to
		 * system_library_metadata.json in the active Hamilton Library folder.
		 */
		function ensureSystemLibraryMetadata() {
			if (getSettingValue('sysLibMetadataComplete')) return;

			console.log('First run detected \u2014 stamping system libraries with VENUS install metadata...');
			var info = getVENUSInstallInfo();
			console.log('VENUS install info: version=' + (info.version || 'N/A') + ', installDate=' + (info.installDate || 'N/A'));

			var metadata = {};
			for (var i = 0; i < systemLibraries.length; i++) {
				var sLib = systemLibraries[i];
				var id = sLib._id || sLib.canonical_name;
				metadata[id] = {
					installed_date: info.installDate || new Date().toISOString(),
					installed_by: 'System',
					venus_version: info.version || ''
				};
				// Merge into in-memory array immediately
				sLib.installed_date = metadata[id].installed_date;
				sLib.installed_by = metadata[id].installed_by;
				if (info.version) sLib.venus_version = info.version;
			}

			try {
				var metaPath = getSystemLibraryMetadataPath();
				fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2), 'utf8');
				console.log('System library metadata saved to ' + metaPath);
			} catch(e) {
				console.warn('Could not save system library metadata: ' + e.message);
			}

			saveSetting('sysLibMetadataComplete', true);
			console.log('System library metadata stamping complete.');

			// Cache the detected version for the packager
			if (info.version) _cachedVENUSVersion = info.version;
		}

		/** Concurrency guard for import operations */
		var _isImporting = false;

		/**
		 * Cached VENUS software version string (e.g. "6.2.2.4006").
		 * Populated on startup from system_libraries.json or the Windows registry.
		 * Used to pre-fill the VENUS Compatibility field in the GUI packager.
		 */
		var _cachedVENUSVersion = '';

		/**
		 * Append an entry to the audit trail JSON log stored in the user data directory.
		 * The audit trail records packaging, import, and other lifecycle events with
		 * environmental context (Windows version, VENUS version, username) for
		 * traceability purposes. This file is NOT displayed in the GUI details view;
		 * it exists solely as a persistent audit record.
		 *
		 * @param {object} entry - Audit trail entry object
		 */
		function appendAuditTrailEntry(entry) {
			try {
				// USER_DATA_DIR may not be defined yet at call time; use lazy resolution
				var dir = (typeof LOCAL_DATA_DIR !== 'undefined') ? LOCAL_DATA_DIR : USER_DATA_DIR;
				var filePath = path.join(dir, 'audit_trail.json');
				var trail = [];
				if (fs.existsSync(filePath)) {
					try {
						trail = JSON.parse(fs.readFileSync(filePath, 'utf8'));
						if (!Array.isArray(trail)) trail = [];
					} catch(_) {
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
					} catch(_) { /* rotation archive is best-effort */ }
					trail = trail.slice(trail.length - MAX_AUDIT_ENTRIES);
				}

				fs.writeFileSync(filePath, JSON.stringify(trail, null, 2), 'utf8');
			} catch(e) {
				console.warn('Could not write audit trail entry: ' + e.message);
			}
		}

		/**
		 * Build a standard audit trail entry with common environmental fields.
		 *
		 * @param {string} eventType - e.g. "package_created", "library_imported", "archive_imported"
		 * @param {object} details   - Event-specific details (library_name, version, etc.)
		 * @returns {object} Complete audit trail entry
		 */
		function buildAuditTrailEntry(eventType, details) {
			return {
				event:            eventType,
				timestamp:        new Date().toISOString(),
				username:         getWindowsUsername(),
				windows_version:  shared.getWindowsVersion(),
				venus_version:    _cachedVENUSVersion || 'N/A',
				hostname:         os.hostname(),
				details:          details || {}
			};
		}

		/* ================================================================
		 *  EVENT HISTORY - modal UI for browsing the audit trail
		 * ================================================================ */

		/** Event-type → human-readable label */
		var EVENT_TYPE_LABELS = {
			'package_created':        'Package Created',
			'library_imported':       'Library Imported',
			'library_deleted':        'Library Deleted',
			'library_rollback':       'Library Rollback',
			'archive_imported':       'Archive Imported',
			'syslib_integrity_check': 'System Library Integrity Check'
		};

		/** Event-type → category (matches the <select> filter options) */
		var EVENT_TYPE_CATEGORIES = {
			'package_created':        'Create',
			'library_imported':       'Import',
			'library_deleted':        'Delete',
			'library_rollback':       'Rollback',
			'archive_imported':       'Import',
			'syslib_integrity_check': 'System'
		};

		/** Event-type → Font Awesome icon class */
		var EVENT_TYPE_ICONS = {
			'package_created':        'fa-box-open',
			'library_imported':       'fa-file-import',
			'library_deleted':        'fa-trash-alt',
			'library_rollback':       'fa-undo-alt',
			'archive_imported':       'fa-file-archive',
			'syslib_integrity_check': 'fa-shield-alt'
		};

		/** Event-type → badge colour */
		var EVENT_TYPE_COLORS = {
			'package_created':        '#28a745',
			'library_imported':       '#5f97c5',
			'library_deleted':        '#dc3545',
			'library_rollback':       '#fd7e14',
			'archive_imported':       '#17a2b8',
			'syslib_integrity_check': '#6f42c1'
		};

		/** In-memory cache of loaded trail entries (sorted newest-first) */
		var _evtHistoryEntries = [];

		/**
		 * Read the audit_trail.json file and return an array of entries
		 * sorted newest-first.
		 */
		function loadAuditTrail() {
			try {
				var dir = (typeof LOCAL_DATA_DIR !== 'undefined') ? LOCAL_DATA_DIR : USER_DATA_DIR;
				var fp  = path.join(dir, 'audit_trail.json');
				if (!fs.existsSync(fp)) return [];
				var raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
				if (!Array.isArray(raw)) return [];
				// Sort newest-first
				raw.sort(function(a, b) {
					return (b.timestamp || '').localeCompare(a.timestamp || '');
				});
				return raw;
			} catch(e) {
				console.warn('loadAuditTrail error: ' + e.message);
				return [];
			}
		}

		/**
		 * Format an ISO timestamp into a friendly local string.
		 */
		function formatEventTimestamp(iso) {
			try {
				var d = new Date(iso);
				if (isNaN(d.getTime())) return iso || '';
				var opts = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' };
				return d.toLocaleDateString('en-US', opts);
			} catch(_) {
				return iso || '';
			}
		}

		/**
		 * Build the detail key/value HTML block for an event entry.
		 */
		function buildEventDetailHtml(entry) {
			var details = entry.details || {};
			var keys = Object.keys(details);
			if (keys.length === 0) return '';
			var html = '<div class="evt-history-detail-block">';
			html += '<table class="table table-sm table-bordered mb-0" style="font-size:0.82rem;">';
			for (var i = 0; i < keys.length; i++) {
				var k = keys[i];
				var v = details[k];
				if (typeof v === 'object') v = JSON.stringify(v);
				var label = k.replace(/_/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
				html += '<tr><td class="font-weight-bold" style="width:160px;white-space:nowrap;">' + escapeHtml(label) + '</td>';
				html += '<td style="word-break:break-all;">' + escapeHtml(String(v)) + '</td></tr>';
			}
			html += '</table></div>';
			return html;
		}

		// escapeHtml is imported from shared module above

		/**
		 * Render a single event row.
		 */
		function renderEventRow(entry) {
			var evtType  = entry.event || 'unknown';
			var label    = EVENT_TYPE_LABELS[evtType] || evtType.replace(/_/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
			var icon     = EVENT_TYPE_ICONS[evtType]  || 'fa-circle';
			var color    = EVENT_TYPE_COLORS[evtType]  || '#6c757d';
			var category = EVENT_TYPE_CATEGORIES[evtType] || '';
			var ts       = formatEventTimestamp(entry.timestamp);
			var user     = entry.username || '';
			var hostname = entry.hostname || '';
			var detailHtml = buildEventDetailHtml(entry);
			var hasDetails = detailHtml.length > 0;

			// Build summary from details
			var summary = '';
			if (entry.details) {
				if (entry.details.library_name) summary = entry.details.library_name;
				if (entry.details.version) summary += ' v' + entry.details.version;
				if (entry.details.source_file) summary += (summary ? ' - ' : '') + entry.details.source_file;
				else if (entry.details.output_file) summary += (summary ? ' - ' : '') + entry.details.output_file;
			}

			var html = '<div class="evt-history-row" data-category="' + escapeHtml(category) + '" data-user="' + escapeHtml(user) + '">';
			html += '  <div class="evt-history-icon" style="background:' + color + ';">';
			html += '    <i class="fas ' + icon + '"></i>';
			html += '  </div>';
			html += '  <div class="evt-history-body">';
			html += '    <div class="evt-history-title">' + escapeHtml(label) + '</div>';
			if (summary) {
				html += '    <div class="evt-history-detail-text">' + escapeHtml(summary) + '</div>';
			}
			html += '    <div class="evt-history-meta">';
			html += '      <span class="evt-history-time"><i class="far fa-clock mr-1"></i>' + escapeHtml(ts) + '</span>';
			if (user) {
				html += '      <span class="evt-history-user"><i class="far fa-user mr-1"></i>' + escapeHtml(user) + (hostname ? ' (' + escapeHtml(hostname) + ')' : '') + '</span>';
			}
			html += '    </div>';
			if (hasDetails) {
				html += '    <a href="#" class="evt-history-details-toggle"><i class="fas fa-chevron-down mr-1"></i>Details</a>';
				html += '    ' + detailHtml;
			}
			html += '  </div>';
			html += '</div>';
			return html;
		}

		/**
		 * Apply current search + filter criteria and re-render the visible list.
		 */
		function filterEventHistory() {
			var searchVal   = $('.evt-history-search').val().toLowerCase().trim();
			var catFilter   = $('.evt-history-cat-filter').val();
			var userFilter  = $('.evt-history-user-filter').val();
			var $list       = $('.evt-history-list');
			var $rows       = $list.find('.evt-history-row');
			var visibleCount = 0;

			$rows.each(function() {
				var $row = $(this);
				var show = true;

				// Category filter
				if (catFilter && $row.data('category') !== catFilter) show = false;

				// User filter
				if (show && userFilter && $row.data('user') !== userFilter) show = false;

				// Text search
				if (show && searchVal) {
					var text = $row.text().toLowerCase();
					if (text.indexOf(searchVal) === -1) show = false;
				}

				$row.toggle(show);
				if (show) visibleCount++;
			});

			$('.evt-history-count').text(visibleCount + ' of ' + $rows.length + ' events');
		}

		/**
		 * Populate and open the Event History modal.
		 */
		function openEventHistoryModal() {
			// Load entries fresh
			_evtHistoryEntries = loadAuditTrail();

			var $list = $('.evt-history-list');
			$list.empty();

			if (_evtHistoryEntries.length === 0) {
				$list.html(
					'<div class="evt-history-empty">' +
					'  <i class="fas fa-inbox"></i>' +
					'  <div>No events recorded yet</div>' +
					'  <div style="font-size:0.8rem;">Activity such as imports, exports, and system checks will appear here.</div>' +
					'</div>'
				);
				$('.evt-history-count').text('0 events');
				$('.evt-history-footer-info').text('');
			} else {
				// Render all rows
				var htmlParts = [];
				var userSet = {};
				for (var i = 0; i < _evtHistoryEntries.length; i++) {
					htmlParts.push(renderEventRow(_evtHistoryEntries[i]));
					if (_evtHistoryEntries[i].username) userSet[_evtHistoryEntries[i].username] = true;
				}
				$list.html(htmlParts.join(''));

				// Populate user filter dropdown
				var $userFilter = $('.evt-history-user-filter');
				$userFilter.find('option:not(:first)').remove();
				var users = Object.keys(userSet).sort();
				for (var u = 0; u < users.length; u++) {
					$userFilter.append('<option value="' + escapeHtml(users[u]) + '">' + escapeHtml(users[u]) + '</option>');
				}

				// Update counts
				$('.evt-history-count').text(_evtHistoryEntries.length + ' events');

				// Footer info
				var oldest = _evtHistoryEntries[_evtHistoryEntries.length - 1];
				var newest = _evtHistoryEntries[0];
				$('.evt-history-footer-info').text(
					'Showing ' + _evtHistoryEntries.length + ' events  |  ' +
					formatEventTimestamp(oldest.timestamp) + '  -  ' +
					formatEventTimestamp(newest.timestamp)
				);
			}

			// Reset filters
			$('.evt-history-search').val('');
			$('.evt-history-cat-filter').val('');
			$('.evt-history-user-filter').val('');

			$('#eventHistoryModal').modal('show');
		}

		/**
		 * Export the currently visible event history rows to CSV.
		 */
		function exportEventHistoryCsv() {
			if (_evtHistoryEntries.length === 0) return;

			var searchVal  = $('.evt-history-search').val().toLowerCase().trim();
			var catFilter  = $('.evt-history-cat-filter').val();
			var userFilter = $('.evt-history-user-filter').val();

			var rows = [['Timestamp', 'Event', 'Category', 'User', 'Hostname', 'Details'].join(',')];
			for (var i = 0; i < _evtHistoryEntries.length; i++) {
				var e = _evtHistoryEntries[i];
				var cat  = EVENT_TYPE_CATEGORIES[e.event] || '';
				var lbl  = EVENT_TYPE_LABELS[e.event] || e.event || '';
				var user = e.username || '';

				// Apply same filters
				if (catFilter && cat !== catFilter) continue;
				if (userFilter && user !== userFilter) continue;
				if (searchVal) {
					var allText = (lbl + ' ' + cat + ' ' + user + ' ' + JSON.stringify(e.details || {})).toLowerCase();
					if (allText.indexOf(searchVal) === -1) continue;
				}

				var detailStr = '';
				if (e.details) {
					var parts = [];
					var dk = Object.keys(e.details);
					for (var j = 0; j < dk.length; j++) {
						var v = e.details[dk[j]];
						if (typeof v === 'object') v = JSON.stringify(v);
						parts.push(dk[j] + '=' + v);
					}
					detailStr = parts.join('; ');
				}

				rows.push([
					'"' + (e.timestamp || '').replace(/"/g, '""') + '"',
					'"' + lbl.replace(/"/g, '""') + '"',
					'"' + cat.replace(/"/g, '""') + '"',
					'"' + user.replace(/"/g, '""') + '"',
					'"' + (e.hostname || '').replace(/"/g, '""') + '"',
					'"' + detailStr.replace(/"/g, '""') + '"'
				].join(','));
			}

			return rows.join('\n');
		}

		/**
		 * Safely open a file/folder path via nw.Shell.openItem().
		 * Validates the path exists on disk before opening to prevent
		 * unvalidated DOM-sourced paths from being passed to the shell.
		 * @param {string} filePath
		 */
		function safeOpenItem(filePath) {
			if (!filePath || typeof filePath !== 'string' || filePath.trim() === '') return;
			var normalized = path.resolve(filePath);
			if (!fs.existsSync(normalized)) {
				console.warn('safeOpenItem: path does not exist: ' + normalized);
				return;
			}
			nw.Shell.openItem(normalized);
		}
    
        // Diskdb init
		var db = require('diskdb');

		// ---- Default Groups (hardcoded - never stored in external JSON) ----
		var DEFAULT_GROUPS = {
			"gStarred":  { "_id": "gStarred",  "name": "Starred",  "icon-class": "fa-star",         "default": true, "navbar": "left",  "favorite": true, "protected": true },
			"gAll":      { "_id": "gAll",      "name": "All",      "icon-class": "fa-home",         "default": true, "navbar": "left",  "favorite": true  },
			"gRecent":   { "_id": "gRecent",   "name": "Recent",   "icon-class": "fa-history",      "default": true, "navbar": "left",  "favorite": true  },
			"gFolders":  { "_id": "gFolders",  "name": "Import",   "icon-class": "fa-download",     "default": true, "navbar": "right", "favorite": false },
			"gEditors":  { "_id": "gEditors",  "name": "Export",   "icon-class": "fa-upload",       "default": true, "navbar": "right", "favorite": true  },
			"gHistory":  { "_id": "gHistory",  "name": "History",  "icon-class": "fa-list",         "default": true, "navbar": "right", "favorite": true  },
			"gOEM": { "_id": "gOEM", "name": "OEM", "icon-class": "fa-check-circle", "default": true, "navbar": "left",  "favorite": true, "protected": true }
		};

		/**
		 * Look up a group by _id.  Hardcoded defaults take priority;
		 * falls back to the external groups database (custom groups).
		 */
		function getGroupById(id) {
			if (DEFAULT_GROUPS[id]) return DEFAULT_GROUPS[id];
			try { return db_groups.groups.findOne({"_id": id}); } catch(e) { return null; }
		}

		// ================================================================
		// LOCAL DATA DIRECTORY
		// ================================================================
		// All persistent application data lives under a single writable "local/"
		// directory within the application install folder (Program Files).
		// This location is shared across all Windows users on the machine.
		// The installer grants the Users group Modify permissions on this
		// directory so that non-admin users can read and write data.
		//
		// Directory layout:
		//   <app_install_dir>/local/
		//     settings.json        - application settings (singleton record)
		//     installed_libs.json  - installed library registry
		//     groups.json          - custom user groups
		//     tree.json            - group→library membership tree
		//     links.json           - VENUS tool shortcuts & folder paths
		//     unsigned_libs.json   - scanned unsigned libraries
		//     publisher_registry.json - publisher/tag autocomplete data
		//     audit_trail.json     - append-only event audit log
		//     packages/            - cached .hxlibpkg backups for rollback & repair
		//     exports/             - default export output directory
		// ================================================================

		var APP_ROOT = (typeof nw !== 'undefined' && nw.__dirname) ? nw.__dirname : __dirname;

		/** Resolve the local data directory path.
		 *  Data is stored inside the application install directory (APP_ROOT/local)
		 *  so that it is shared across all Windows users on the machine.
		 *  The installer grants write permissions to the Users group on this folder.
		 *  An override is available via the LMV6_DATA_DIR environment variable.
		 */
		function resolveDefaultLocalDataDir() {
			try {
				if (typeof process !== 'undefined' && process.env && process.env.LMV6_DATA_DIR && process.env.LMV6_DATA_DIR.trim()) {
					return path.resolve(process.env.LMV6_DATA_DIR.trim());
				}
			} catch(_) {}

			return path.join(APP_ROOT, 'local');
		}

		var LOCAL_DATA_DIR = resolveDefaultLocalDataDir();

		/** Centralized installer store directory */
		var INSTALLER_STORE_DIR = path.join(LOCAL_DATA_DIR, shared.INSTALLER_STORE_DIRNAME);

		/** Ensure the local data directory and all subdirectories exist with seed files */
		function ensureLocalDataDir(dirPath) {
			if (!fs.existsSync(dirPath)) {
				fs.mkdirSync(dirPath, { recursive: true });
			}
			// Ensure subdirectories
			var subDirs = ['packages', 'exports', shared.INSTALLER_STORE_DIRNAME];
			subDirs.forEach(function(sub) {
				var subPath = path.join(dirPath, sub);
				if (!fs.existsSync(subPath)) {
					fs.mkdirSync(subPath, { recursive: true });
				}
			});
			// Seed empty collections if they don't exist
			var seedFiles = {
				'settings.json': '[{"_id":"0"}]',
				'installed_libs.json': '[]',
				'publisher_registry.json': '{"publishers":[],"tags":[],"maxPublisherSpaces":0}',
				'groups.json': '[]',
				'tree.json': '[{"group-id":"gAll","method-ids":[],"locked":false},{"group-id":"gRecent","method-ids":[],"locked":false},{"group-id":"gStarred","method-ids":[],"locked":false},{"group-id":"gFolders","method-ids":[],"locked":false},{"group-id":"gEditors","method-ids":[],"locked":false},{"group-id":"gHistory","method-ids":[],"locked":false},{"group-id":"gOEM","method-ids":[],"locked":true}]',
				'links.json': '[{"_id":"method-editor","name":"Method Editor","description":"","icon-customImage":"HxMet.png","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxMetEd.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lc-editor","name":"Liquid Class Editor","description":"","icon-customImage":"HxLiq.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxCoreLiquidEditor.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lbw-editor","name":"Labware Editor","description":"","icon-customImage":"HxLbw.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxLabwrEd.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"hsl-editor","name":"HSL Editor","description":"","icon-customImage":"HxHSL.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxHSLMetEd.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"sysCfg-editor","name":"System Configuration Editor","description":"","icon-customImage":"HxCfg.png","icon-class":"fa-dna","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\Hamilton.HxConfigEditor.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"run-control","group-id":"gEditors","name":"Run Control","description":"","icon-customImage":"HxRun.png","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxRun.exe","type":"file","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"ham-version","group-id":"gEditors","name":"Hamilton Version","description":"","icon-customImage":"HxVer.png","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin\\\\HxVersion.exe","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"bin-folder","name":"Bin","description":"VENUS software executables and dlls","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Bin","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"cfg-folder","name":"Config","description":"VENUS software configuration files","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Config","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lbw-folder","name":"Labware","description":"VENUS software labware definitions for carriers, racks, tubes and consumables","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Labware","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"lib-folder","name":"Library","description":"VENUS software library files","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Library","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"log-folder","name":"LogFiles","description":"Run traces and STAR communication logs","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Logfiles","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0},{"_id":"met-folder","name":"Methods","description":"Method files","icon-customImage":"","icon-class":"fa-folder","icon-color":"color-blue","path":"C:\\\\Program Files (x86)\\\\Hamilton\\\\Methods","type":"folder","default":true,"favorite":true,"last-started":"","last-startedUTC":0}]'
			};
			for (var fname in seedFiles) {
				var fpath = path.join(dirPath, fname);
				if (!fs.existsSync(fpath)) {
					fs.writeFileSync(fpath, seedFiles[fname], 'utf8');
				}
			}
		}

		// Initialize local data directory
		ensureLocalDataDir(LOCAL_DATA_DIR);

		// ---- Settings DB (now in local/ directory) ----
		var db_settings = db.connect(LOCAL_DATA_DIR, ['settings']);

		// ---- Legacy Migration ----
		// Migrate data from old locations to the app-local directory:
		//   1. Old app-root db/ folder (pre-restructure)
		//   2. Old per-user %LOCALAPPDATA% location (prior AppData-based storage)
		//   3. Old HAMILTON\Library\LibraryManagerForVenus6 folder
		//   4. Old HAMILTON\Library\.LibraryManagerForVenus6 hidden folder
		//   5. Old NW.js per-user dataPath location
		(function migrateToLocalDir() {
			var perUserLocations = [];
			try {
				var profileRoot = (typeof process !== 'undefined' && process.env)
					? (process.env.LOCALAPPDATA || process.env.APPDATA || '')
					: '';
				if (profileRoot) {
					perUserLocations.push(path.join(profileRoot, 'Library Manager for Venus 6', 'local'));
				}
			} catch(_) {}
			try {
				if (typeof nw !== 'undefined' && nw.App && typeof nw.App.dataPath === 'string' && nw.App.dataPath.trim()) {
					perUserLocations.push(path.join(nw.App.dataPath, 'local'));
				}
			} catch(_) {}
			var oldLocations = [
				path.join(APP_ROOT, 'db')
			].concat(perUserLocations).concat([
				path.join("C:\\Program Files (x86)\\HAMILTON\\Library", "LibraryManagerForVenus6"),
				path.join("C:\\Program Files (x86)\\HAMILTON\\Library", ".LibraryManagerForVenus6")
			]);
			var filesToMigrate = ['installed_libs.json', 'groups.json', 'tree.json', 'links.json', 'settings.json', 'audit_trail.json', 'publisher_registry.json'];
			oldLocations.forEach(function(oldDir) {
				if (!fs.existsSync(oldDir) || oldDir === LOCAL_DATA_DIR) return;
				filesToMigrate.forEach(function(fname) {
					try {
						var src = path.join(oldDir, fname);
						var dst = path.join(LOCAL_DATA_DIR, fname);
						if (!fs.existsSync(src)) return;
						var srcData = fs.readFileSync(src, 'utf8').trim();
						if (!srcData || srcData === '[]' || srcData === '{}') return;
						// For settings.json, merge keys into existing record rather than overwrite
						if (fname === 'settings.json') {
							try {
								var srcArr = JSON.parse(srcData);
								var srcSettings = Array.isArray(srcArr) && srcArr.length > 0 ? srcArr[0] : null;
								if (!srcSettings) return;
								var dstArr = JSON.parse(fs.readFileSync(dst, 'utf8'));
								var dstSettings = Array.isArray(dstArr) && dstArr.length > 0 ? dstArr[0] : {"_id":"0"};
								var merged = false;
								for (var key in srcSettings) {
									if (key !== '_id' && !(key in dstSettings)) {
										dstSettings[key] = srcSettings[key];
										merged = true;
									}
								}
								if (merged) {
									fs.writeFileSync(dst, JSON.stringify([dstSettings], null, 2), 'utf8');
									console.log('Merged settings from ' + oldDir);
								}
							} catch(e) { console.warn('Settings merge failed for ' + oldDir + ': ' + e.message); }
							return;
						}
						// For array-based files, only migrate if destination is empty/default
						var dstData = fs.readFileSync(dst, 'utf8').trim();
						if (dstData === '[]' || (dstData.startsWith('[') && JSON.parse(dstData).length === 0)) {
							var srcParsed = JSON.parse(srcData);
							if (Array.isArray(srcParsed) && srcParsed.length > 0) {
								fs.writeFileSync(dst, srcData, 'utf8');
								console.log('Migrated ' + fname + ' from ' + oldDir + ' (' + srcParsed.length + ' records)');
							}
						}
					} catch(e) {
						console.warn('Migration warning for ' + fname + ' from ' + oldDir + ': ' + e.message);
					}
				});
			});
			// Migrate cached packages from per-user AppData locations to app-local packages/
			var newPkgStore = path.join(LOCAL_DATA_DIR, 'packages');
			perUserLocations.forEach(function(legacyDir) {
				var legacyPkgStore = path.join(legacyDir, 'packages');
				if (fs.existsSync(legacyPkgStore) && legacyPkgStore !== newPkgStore) {
					try {
						var legacyLibDirs = fs.readdirSync(legacyPkgStore);
						legacyLibDirs.forEach(function(libDir) {
							var srcLib = path.join(legacyPkgStore, libDir);
							if (!fs.statSync(srcLib).isDirectory()) return;
							var dstLib = path.join(newPkgStore, libDir);
							if (!fs.existsSync(dstLib)) fs.mkdirSync(dstLib, { recursive: true });
							fs.readdirSync(srcLib).forEach(function(pkgFile) {
								var srcPkg = path.join(srcLib, pkgFile);
								var dstPkg = path.join(dstLib, pkgFile);
								if (!fs.existsSync(dstPkg) && pkgFile.toLowerCase().endsWith('.hxlibpkg')) {
									fs.copyFileSync(srcPkg, dstPkg);
									console.log('Migrated package from user profile: ' + libDir + '/' + pkgFile);
								}
							});
						});
					} catch(e) {
						console.warn('Per-user package migration warning: ' + e.message);
					}
				}
			});
			// Migrate old LibraryPackages from HAMILTON\Library to local/packages/
			var oldPkgStore = path.join("C:\\Program Files (x86)\\HAMILTON\\Library", "LibraryPackages");
			if (fs.existsSync(oldPkgStore) && oldPkgStore !== newPkgStore) {
				try {
					var libDirs = fs.readdirSync(oldPkgStore);
					libDirs.forEach(function(libDir) {
						var srcLib = path.join(oldPkgStore, libDir);
						if (!fs.statSync(srcLib).isDirectory()) return;
						var dstLib = path.join(newPkgStore, libDir);
						if (!fs.existsSync(dstLib)) fs.mkdirSync(dstLib, { recursive: true });
						fs.readdirSync(srcLib).forEach(function(pkgFile) {
							var srcPkg = path.join(srcLib, pkgFile);
							var dstPkg = path.join(dstLib, pkgFile);
							if (!fs.existsSync(dstPkg) && pkgFile.toLowerCase().endsWith('.hxlibpkg')) {
								fs.copyFileSync(srcPkg, dstPkg);
								console.log('Migrated package: ' + libDir + '/' + pkgFile);
							}
						});
					});
				} catch(e) {
					console.warn('Package store migration warning: ' + e.message);
				}
			}
		})();

		// Re-connect settings DB after migration (picks up any merged keys)
		db_settings = db.connect(LOCAL_DATA_DIR, ['settings']);

		// Set USER_DATA_DIR to LOCAL_DATA_DIR for backward compatibility with existing code
		var USER_DATA_DIR = LOCAL_DATA_DIR;

		// Connect data databases to the local/ directory
		var db_links = db.connect(LOCAL_DATA_DIR, ['links']);
		var db_groups = db.connect(LOCAL_DATA_DIR, ['groups']);
		var db_tree = db.connect(LOCAL_DATA_DIR, ['tree']); // contains the tree of group ids and method ids
		var db_installed_libs = db.connect(LOCAL_DATA_DIR, ['installed_libs']); // tracks installed .hxlibpkg libraries
		var db_unsigned_libs = db.connect(LOCAL_DATA_DIR, ['unsigned_libs']); // tracks scanned unsigned libraries

		console.log('Local data:   ' + LOCAL_DATA_DIR);

		// ---- Publisher & Tag Registry ----
		// Stored in USER_DATA_DIR/publisher_registry.json.
		// Tracks all known publisher/author names and tags for autocomplete
		// and for the @author search-chip space-limit heuristic.
		// Schema: { publishers: [{name, maxSpaces}], tags: [string], maxPublisherSpaces: number }
		var _publisherRegistryPath = path.join(USER_DATA_DIR, 'publisher_registry.json');
		var _publisherRegistry = { publishers: [], tags: [], maxPublisherSpaces: 0 };

		function loadPublisherRegistry() {
			try {
				if (fs.existsSync(_publisherRegistryPath)) {
					var raw = fs.readFileSync(_publisherRegistryPath, 'utf8');
					var data = JSON.parse(raw);
					_publisherRegistry = {
						publishers: Array.isArray(data.publishers) ? data.publishers : [],
						tags: Array.isArray(data.tags) ? data.tags : [],
						maxPublisherSpaces: (typeof data.maxPublisherSpaces === 'number') ? data.maxPublisherSpaces : 0
					};
				}
			} catch(e) {
				console.warn('Could not load publisher registry: ' + e.message);
			}
		}

		function savePublisherRegistry() {
			try {
				fs.writeFileSync(_publisherRegistryPath, JSON.stringify(_publisherRegistry, null, 2), 'utf8');
			} catch(e) {
				console.warn('Could not save publisher registry: ' + e.message);
			}
		}

		/**
		 * Register a publisher/author name in the registry.
		 * @param {string} name - author or organization name (can contain spaces)
		 */
		function registerPublisher(name) {
			if (!name || typeof name !== 'string') return;
			var trimmed = name.trim();
			if (!trimmed) return;
			var lower = trimmed.toLowerCase();
			var exists = _publisherRegistry.publishers.some(function(p) {
				return (p.name || '').toLowerCase() === lower;
			});
			if (!exists) {
				var spaces = (trimmed.match(/ /g) || []).length;
				_publisherRegistry.publishers.push({ name: trimmed, maxSpaces: spaces });
				_recalcMaxPublisherSpaces();
				savePublisherRegistry();
			}
		}

		/**
		 * Register tags in the registry (deduplicates, lowercased).
		 * @param {string[]} tags
		 */
		function registerTags(tags) {
			if (!Array.isArray(tags)) return;
			var changed = false;
			tags.forEach(function(t) {
				var sanitized = shared.sanitizeTag(t || '');
				if (!sanitized) return;
				if (_publisherRegistry.tags.indexOf(sanitized) === -1) {
					_publisherRegistry.tags.push(sanitized);
					changed = true;
				}
			});
			if (changed) savePublisherRegistry();
		}

		function _recalcMaxPublisherSpaces() {
			var max = 0;
			_publisherRegistry.publishers.forEach(function(p) {
				if (p.maxSpaces > max) max = p.maxSpaces;
			});
			_publisherRegistry.maxPublisherSpaces = max;
		}

		/**
		 * Get the maximum number of spaces any known publisher has.
		 * Used by the @author chip to know when to auto-close an unescaped author token.
		 */
		function getMaxPublisherSpaces() {
			return _publisherRegistry.maxPublisherSpaces || 0;
		}

		/**
		 * Get all known publisher names (for future autocomplete).
		 */
		function getKnownPublishers() {
			return _publisherRegistry.publishers.map(function(p) { return p.name; });
		}

		/**
		 * Get all known tags (for future autocomplete).
		 */
		function getKnownTags() {
			return _publisherRegistry.tags.slice();
		}

		/**
		 * Rebuild the publisher registry by scanning all installed + system libraries.
		 * Called once at startup and after any import/registration.
		 */
		function rebuildPublisherRegistry() {
			var seenPublishers = {};
			var seenTags = {};

			// Scan installed libraries
			var installedLibs = db_installed_libs.installed_libs.find() || [];
			installedLibs.forEach(function(lib) {
				if (lib.deleted) return;
				(lib.author || '').split(',').forEach(function(a) {
					var author = a.trim();
					if (author) seenPublishers[author.toLowerCase()] = author;
				});
				(lib.organization || '').split(',').forEach(function(o) {
					var org = o.trim();
					if (org) seenPublishers[org.toLowerCase()] = org;
				});
				(lib.tags || []).forEach(function(t) {
					var s = shared.sanitizeTag(t);
					if (s) seenTags[s] = true;
				});
			});

			// Scan system libraries
			var sysLibs = getAllSystemLibraries();
			sysLibs.forEach(function(sLib) {
				(sLib.author || '').split(',').forEach(function(a) {
					var author = a.trim();
					if (author) seenPublishers[author.toLowerCase()] = author;
				});
				(sLib.organization || '').split(',').forEach(function(o) {
					var org = o.trim();
					if (org) seenPublishers[org.toLowerCase()] = org;
				});
			});

			// Build new registry
			_publisherRegistry.publishers = [];
			Object.keys(seenPublishers).forEach(function(key) {
				var name = seenPublishers[key];
				var spaces = (name.match(/ /g) || []).length;
				_publisherRegistry.publishers.push({ name: name, maxSpaces: spaces });
			});
			_recalcMaxPublisherSpaces();

			_publisherRegistry.tags = Object.keys(seenTags);

			savePublisherRegistry();
		}

		loadPublisherRegistry();


		// Default groups are now defined in DEFAULT_GROUPS and should not live in the JSON.
		(function migrateDefaultGroups() {
			try {
				var groupsPath = path.join(USER_DATA_DIR, 'groups.json');
				var groupsRaw = fs.readFileSync(groupsPath, 'utf8');
				var groupsData = JSON.parse(groupsRaw);
				var defaultIds = Object.keys(DEFAULT_GROUPS);
				var before = groupsData.length;
				// Also remove orphan OEM/Hamilton entries with random _ids
				groupsData = groupsData.filter(function(g) {
					if (defaultIds.indexOf(g._id) !== -1) return false;
					if ((g.name === 'Hamilton' || g.name === 'OEM') && g['protected']) return false;
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
						treeData.push({ "group-id": gid, "method-ids": [], "locked": (gid === 'gOEM') });
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

		function getSystemLibraryMetadataPath() {
			var defaultLibPath = "C:\\Program Files (x86)\\HAMILTON\\Library";
			var libFolderPath = defaultLibPath;
			try {
				if (db_links && db_links.links) {
					var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
					if (libFolderRec && libFolderRec.path) {
						libFolderPath = libFolderRec.path;
					}
				}
			} catch(_) { /* fallback to default */ }

			if (!fs.existsSync(libFolderPath)) {
				try { fs.mkdirSync(libFolderPath, { recursive: true }); } catch(_) { /* best-effort */ }
			}

			return path.join(libFolderPath, 'system_library_metadata.json');
		}

		function migrateSystemMetadataToLibraryFolder() {
			try {
				var oldPath = path.join(USER_DATA_DIR, 'system_library_metadata.json');
				var newPath = getSystemLibraryMetadataPath();
				if (oldPath === newPath) return;
				if (!fs.existsSync(oldPath)) return;
				if (!fs.existsSync(newPath)) {
					fs.copyFileSync(oldPath, newPath);
					console.log('Migrated system library metadata to library folder: ' + newPath);
				}
			} catch(e) {
				console.warn('Could not migrate system library metadata: ' + e.message);
			}
		}

		// ---- System Libraries (hardcoded Hamilton base libraries) ----
		var systemLibraries = [];
		try {
			var _sysLibRaw = fs.readFileSync(path.join('db', 'system_libraries.json'), 'utf8');
			systemLibraries = JSON.parse(_sysLibRaw);

			// Move metadata from legacy USER_DATA_DIR location to the active
			// Library folder location for portability.
			migrateSystemMetadataToLibraryFolder();

			// Merge persisted install metadata from active Library folder
			try {
				var _metaPath = getSystemLibraryMetadataPath();
				if (fs.existsSync(_metaPath)) {
					var _metaRaw = fs.readFileSync(_metaPath, 'utf8');
					var _metaData = JSON.parse(_metaRaw);
					for (var _mi = 0; _mi < systemLibraries.length; _mi++) {
						var _sId = systemLibraries[_mi]._id || systemLibraries[_mi].canonical_name;
						if (_metaData[_sId]) {
							if (_metaData[_sId].installed_date) systemLibraries[_mi].installed_date = _metaData[_sId].installed_date;
							if (_metaData[_sId].installed_by)   systemLibraries[_mi].installed_by   = _metaData[_sId].installed_by;
							if (_metaData[_sId].venus_version)  systemLibraries[_mi].venus_version  = _metaData[_sId].venus_version;
						}
					}
				}
			} catch(_me) {
				console.warn('Could not load system library metadata: ' + _me.message);
			}

			// Read cached VENUS version from the first system library that has it
			for (var _vi = 0; _vi < systemLibraries.length; _vi++) {
				if (systemLibraries[_vi].venus_version) {
					_cachedVENUSVersion = systemLibraries[_vi].venus_version;
					break;
				}
			}
		} catch(e) {
			console.warn('Could not load system_libraries.json: ' + e.message);
		}

		// ---- System Library Baseline (integrity baseline from clean VENUS install) ----
		// Uses Hamilton's built-in $$valid$$ (read-only) metadata footer flag.
		var systemLibraryBaseline = {};
		try {
			var _sysHashRaw = fs.readFileSync(path.join('db', 'system_library_hashes.json'), 'utf8');
			var _sysHashData = JSON.parse(_sysHashRaw);
			systemLibraryBaseline = _sysHashData.libraries || {};
		} catch(e) {
			console.warn('Could not load system_library_hashes.json: ' + e.message);
		}

		// ---- Restricted Author / Organization Protection ----
		// Uses the centralized constants and validation from shared.js.

		// Re-export from shared for local use
		var isRestrictedAuthor = shared.isRestrictedAuthor;

		/**
		 * Build the OEM verified blue checkmark badge HTML for a given author name.
		 * Returns an empty string unless the library has a valid code-signing
		 * publisher certificate AND the author is a restricted OEM name.
		 * Only codesigned packages receive the blue checkmark badge.
		 * @param {string} author - Author or organization name
		 * @param {boolean} [large=false] - Use the larger variant for detail modals
		 * @param {Object} [cert=null] - Publisher certificate object (from DB or sigResult)
		 * @returns {string} HTML string
		 */
		function buildOemVerifiedBadge(author, large, cert) {
			if (!cert || !cert.publisher) return '';
			if (!isRestrictedAuthor(author)) return '';
			var sizeClass = large ? ' oem-verified-badge-lg' : '';
			var tooltipHtml = '';
			if (cert && cert.publisher) {
				tooltipHtml = '<span class="oem-cert-tooltip">' +
					'<span class="tooltip-header"><i class="fas fa-shield-alt"></i> Verified OEM Publisher</span>' +
					'<span class="tooltip-row"><span class="tooltip-label">Publisher</span><span class="tooltip-value">' + escapeHtml(cert.publisher) + '</span></span>' +
					(cert.organization ? '<span class="tooltip-row"><span class="tooltip-label">Organization</span><span class="tooltip-value">' + escapeHtml(cert.organization) + '</span></span>' : '') +
					'<span class="tooltip-divider"></span>' +
					'<span class="tooltip-row"><span class="tooltip-label">Key ID</span><span class="tooltip-value">' + escapeHtml(cert.key_id || '') + '</span></span>' +
					'<span class="tooltip-row"><span class="tooltip-label">Fingerprint</span><span class="tooltip-value">' + escapeHtml((cert.fingerprint || '').substring(0, 32)) + '\u2026</span></span>' +
					'<span class="tooltip-row"><span class="tooltip-label">Algorithm</span><span class="tooltip-value">Ed25519</span></span>' +
					'<span class="tooltip-row"><span class="tooltip-label">Cert Format</span><span class="tooltip-value">' + escapeHtml(cert.cert_format || '') + '</span></span>' +
					'<span class="tooltip-row"><span class="tooltip-label">Issued</span><span class="tooltip-value">' + escapeHtml(cert.created_date || '') + '</span></span>' +
				'</span>';
			}
			return '<span class="oem-verified-badge' + sizeClass + '">' +
				'<span class="oem-check-icon"><i class="fas fa-check"></i></span>' +
				tooltipHtml +
			'</span>';
		}

		/**
		 * Build the Code Signing Certificate detail section HTML for the detail modal.
		 * Only renders for verified OEM libraries that have a stored publisher_cert.
		 * @param {Object} cert - Publisher certificate object
		 * @returns {string} HTML string
		 */
		function buildCertDetailSection(cert) {
			if (!cert || !cert.publisher) return '';
			var matchedKeywords = shared.getMatchedRestrictedKeywords(cert.publisher + ' ' + (cert.organization || ''));
			var kwBadges = matchedKeywords.map(function(k) {
				return '<span style="background:#dbeafe; color:#1e40af; padding:1px 6px; border-radius:3px; margin-right:3px; font-size:0.72rem;">' + escapeHtml(k) + '</span>';
			}).join('');
			return '<div class="detail-section oem-cert-section">' +
				'<div class="oem-cert-section-header">' +
					'<span class="cert-shield"><i class="fas fa-certificate"></i></span>' +
					'<h6>Code Signing Certificate</h6>' +
					'<span class="cert-valid-badge"><i class="fas fa-check-circle"></i> Verified</span>' +
				'</div>' +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Publisher</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(cert.publisher) + '</span></div>' +
				(cert.organization ? '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Organization</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(cert.organization) + '</span></div>' : '') +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Certificate Format</span><span class="oem-cert-detail-value">' + escapeHtml(cert.cert_format || '') + '</span></div>' +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Signature Algorithm</span><span class="oem-cert-detail-value">Ed25519 (EdDSA)</span></div>' +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Key ID</span><span class="oem-cert-detail-value">' + escapeHtml(cert.key_id || '') + '</span></div>' +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Public Key</span><span class="oem-cert-detail-value">' + escapeHtml(cert.public_key || '') + '</span></div>' +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Fingerprint (SHA-256)</span><span class="oem-cert-detail-value">' + escapeHtml(cert.fingerprint || '') + '</span></div>' +
				'<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Issued Date</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(cert.created_date || '') + '</span></div>' +
				(kwBadges ? '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">OEM Keywords</span><span class="oem-cert-detail-value normal-font">' + kwBadges + '</span></div>' : '') +
			'</div>';
		}

		/**
		 * Build the grey checkmark badge for a converted distribution package.
		 * These packages were created from .exe installers by the companion tool.
		 * Shows a grey checkmark (not blue) with source exe certificate info on hover.
		 * @param {boolean} [large=false] - Use larger variant for detail modals
		 * @param {Object} [sourceCert=null] - source_certificate object from signature
		 * @param {string} [conversionSource=''] - Original .exe filename
		 * @returns {string} HTML string
		 */
		function buildConvertedBadge(large, sourceCert, conversionSource) {
			var sizeClass = large ? ' converted-verified-badge-lg' : '';
			var tooltipRows = '';
			if (sourceCert && sourceCert.present && sourceCert.signer_name) {
				tooltipRows =
					'<span class="tooltip-row"><span class="tooltip-label">EXE Signer</span><span class="tooltip-value">' + escapeHtml(sourceCert.signer_name) + '</span></span>' +
					(sourceCert.issuer_name ? '<span class="tooltip-row"><span class="tooltip-label">Issuer</span><span class="tooltip-value">' + escapeHtml(sourceCert.issuer_name) + '</span></span>' : '') +
					'<span class="tooltip-divider"></span>' +
					(sourceCert.thumbprint ? '<span class="tooltip-row"><span class="tooltip-label">Thumbprint</span><span class="tooltip-value">' + escapeHtml((sourceCert.thumbprint || '').substring(0, 32)) + '\u2026</span></span>' : '') +
					(sourceCert.serial_number ? '<span class="tooltip-row"><span class="tooltip-label">Serial</span><span class="tooltip-value">' + escapeHtml(sourceCert.serial_number) + '</span></span>' : '') +
					'<span class="tooltip-row"><span class="tooltip-label">Status</span><span class="tooltip-value">' + escapeHtml(sourceCert.status || 'Unknown') + '</span></span>';
			} else {
				tooltipRows =
					'<span class="tooltip-row"><span class="tooltip-label">Provenance</span><span class="tooltip-value" style="font-family:inherit;">Created from official library distribution</span></span>';
			}
			if (conversionSource) {
				tooltipRows += '<span class="tooltip-row"><span class="tooltip-label">Source</span><span class="tooltip-value">' + escapeHtml(conversionSource) + '</span></span>';
			}
			return '<span class="converted-verified-badge' + sizeClass + '">' +
				'<span class="converted-check-icon"><i class="fas fa-check"></i></span>' +
				'<span class="converted-cert-tooltip">' +
					'<span class="tooltip-header"><i class="fas fa-file-import"></i> Converted Distribution</span>' +
					tooltipRows +
				'</span>' +
			'</span>';
		}

		/**
		 * Build the Converted Distribution certificate detail section for the detail modal.
		 * Shows source .exe certificate metadata or "official distribution" fallback.
		 * @param {Object} sourceCert - source_certificate from signature
		 * @param {string} [conversionSource=''] - Original .exe filename
		 * @returns {string} HTML string
		 */
		function buildConvertedCertDetailSection(sourceCert, conversionSource) {
			var badgeText = (sourceCert && sourceCert.present) ? 'EXE Certificate' : 'Official Distribution';
			var rows = '';
			if (sourceCert && sourceCert.present && sourceCert.signer_name) {
				rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">EXE Signer</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.signer_name) + '</span></div>';
				if (sourceCert.issuer_name) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Issuer</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.issuer_name) + '</span></div>';
				if (sourceCert.subject) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Subject</span><span class="oem-cert-detail-value">' + escapeHtml(sourceCert.subject) + '</span></div>';
				if (sourceCert.issuer) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Issuer DN</span><span class="oem-cert-detail-value">' + escapeHtml(sourceCert.issuer) + '</span></div>';
				if (sourceCert.serial_number) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Serial Number</span><span class="oem-cert-detail-value">' + escapeHtml(sourceCert.serial_number) + '</span></div>';
				if (sourceCert.thumbprint) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Thumbprint</span><span class="oem-cert-detail-value">' + escapeHtml(sourceCert.thumbprint) + '</span></div>';
				if (sourceCert.not_before) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Valid From</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.not_before) + '</span></div>';
				if (sourceCert.not_after) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Valid Until</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.not_after) + '</span></div>';
				rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Status</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.status || 'Unknown') + '</span></div>';
				if (sourceCert.timestamp_signer) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Timestamp Signer</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.timestamp_signer) + '</span></div>';
			} else {
				rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Provenance</span><span class="oem-cert-detail-value normal-font">Created from official library distribution</span></div>';
				if (sourceCert && sourceCert.note) rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Note</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(sourceCert.note) + '</span></div>';
			}
			if (conversionSource) {
				rows += '<div class="oem-cert-detail-row"><span class="oem-cert-detail-label">Source Executable</span><span class="oem-cert-detail-value normal-font">' + escapeHtml(conversionSource) + '</span></div>';
			}
			return '<div class="detail-section converted-cert-section">' +
				'<div class="converted-cert-section-header">' +
					'<span class="cert-shield"><i class="fas fa-file-import"></i></span>' +
					'<h6>Converted Distribution</h6>' +
					'<span class="cert-converted-badge"><i class="fas fa-check-circle"></i> ' + escapeHtml(badgeText) + '</span>' +
				'</div>' +
				rows +
			'</div>';
		}

		/**
		 * Add a library ID to the gOEM tree group entry. Creates the entry if missing.
		 * Uses raw file I/O to safely update tree.json (diskdb update may replace entire record).
		 * @param {string} libId - The library _id to add to the OEM group
		 * @returns {string} "gOEM" for use as targetGroupId
		 */
		function addToOemTreeGroup(libId) {
			var treePath = path.join(USER_DATA_DIR, 'tree.json');
			var treeData = JSON.parse(fs.readFileSync(treePath, 'utf8'));
			var found = false;
			for (var i = 0; i < treeData.length; i++) {
				if (treeData[i]["group-id"] === "gOEM") {
					var ids = (treeData[i]["method-ids"] || []).slice();
					ids.push(libId);
					treeData[i]["method-ids"] = ids;
					found = true;
					break;
				}
			}
			if (!found) {
				treeData.push({
					"group-id": "gOEM",
					"method-ids": [libId],
					"locked": true
				});
			}
			fs.writeFileSync(treePath, JSON.stringify(treeData), 'utf8');
			db_tree = db.connect(USER_DATA_DIR, ['tree']);
			return "gOEM";
		}

		/**
		 * Validate the password for using a restricted author name.
		 * Delegates to shared.validateAuthorPassword for consistent behaviour.
		 * @param {string} password
		 * @returns {boolean}
		 */
		var validateAuthorPassword = shared.validateAuthorPassword;

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

		// Rebuild publisher registry at startup (after system libs are loaded)
		rebuildPublisherRegistry();

		// ---- Full-text Search Index ----
		var _searchIndex = new SearchIndex();
		var _searchIndexDirty = true; // flag to lazily rebuild before next search

		/**
		 * Rebuild the search index from all installed + system libraries.
		 * Called lazily before search when _searchIndexDirty is true.
		 */
		function rebuildSearchIndex() {
			_searchIndex.clear();

			// Index user-installed libraries
			var userLibs = db_installed_libs.installed_libs.find() || [];
			userLibs.forEach(function(lib) {
				if (lib.deleted || isSystemLibrary(lib._id)) return;
				_searchIndex.addLibrary(lib, 'user');
			});

			// Index system libraries (with cached function names)
			var fnCache = _buildSysLibFnCache();
			var sysLibs = getAllSystemLibraries();
			sysLibs.forEach(function(sLib) {
				// System libs get a virtual 'system' tag injected for #system search
				var augmented = Object.create(sLib);
				augmented.tags = ['system'].concat(sLib.tags || []);
				_searchIndex.addLibrary(augmented, 'system', fnCache[sLib._id] || '');
			});

			_searchIndexDirty = false;
		}

		function markSearchIndexDirty() {
			_searchIndexDirty = true;
		}

		// ---- Package Store - cache .hxlibpkg files for repair & version rollback ----
		// Stored under local/packages/<LibraryName>/ within the app directory
		function getPackageStoreDir() {
			return path.join(LOCAL_DATA_DIR, 'packages');
		}

		/**
		 * Build a deterministic filename for a cached package:
		 *   <LibraryName>_v<version>_<YYYYMMDD-HHmmss>.hxlibpkg
		 */
		function buildCachedPackageName(libName, version) {
			var safe   = (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_');
			var ver    = (version || '0.0.0').replace(/[<>:"\/\\|?*]/g, '_');
			var now    = new Date();
			var stamp  = now.getUTCFullYear().toString()
			           + String(now.getUTCMonth() + 1).padStart(2, '0')
			           + String(now.getUTCDate()).padStart(2, '0')
			           + '-'
			           + String(now.getUTCHours()).padStart(2, '0')
			           + String(now.getUTCMinutes()).padStart(2, '0')
			           + String(now.getUTCSeconds()).padStart(2, '0');
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
		 * System libraries have no demo methods - only library files and help files.
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
					format_version: shared.FORMAT_VERSION,
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
					is_system_backup: true,
					app_version: shared.getAppVersion(),
					windows_version: shared.getWindowsVersion(),
					venus_version: _cachedVENUSVersion || '',
					package_lineage: [shared.buildLineageEvent('created', {
						username: getWindowsUsername(),
						hostname: os.hostname(),
						venusVersion: _cachedVENUSVersion || ''
					})]
				};

				// Create ZIP package
				var zip = new AdmZip();
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files
				libFiles.forEach(function(f) {
					var fullPath = path.join(sysLibDir, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('library', f));
					}
				});

				// Add help files (CHMs) - packed into help_files/ folder
				helpFiles.forEach(function(f) {
					var fullPath = path.join(sysLibDir, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('help_files', f));
					}
				});
				// Wrap in binary container and cache to package store
				var pkgBuffer = packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG);
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
			console.log('First run detected - backing up system libraries to package store...');
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
					var rawBuf = fs.readFileSync(newest.fullPath);
					var zipBuf = unpackContainer(rawBuf, CONTAINER_MAGIC_PKG);
					zip = new AdmZip(zipBuf);
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
					showGenericSuccessModal({
						title: "System Library Repaired Successfully!",
						name: libName,
						detail: extractedCount + " file" + (extractedCount !== 1 ? "s" : "") + " re-extracted from backup package",
						statusHtml: sigResult.signed ? '<i class="fas fa-check mr-1"></i>Package signature: verified' : null,
						statusClass: 'com-ok'
					});
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
			// Persist maximized state for next launch (dual-write for reliability)
			try {
				saveSetting('windowMaximized', _windowIsMaximized);
				localStorage.setItem('windowMaximized', String(_windowIsMaximized));
			} catch(e) { console.log('Could not save window state: ' + e); }

			// Force-close the window (skip the close event re-fire)
			win.close(true);

			// Quit the NW.js application entirely — this terminates the
			// Node.js event loop and kills all nw.exe processes for this app.
			try { nw.App.quit(); } catch(_) {}

			// Safety net: if nw.App.quit() didn't terminate within 3 seconds
			// (e.g. a lingering async callback keeps the event loop alive),
			// force-kill the process so nothing remains in the background.
			setTimeout(function() { process.exitCode = 0; process.exit(); }, 3000);
		});

        //Window resize
		$(window).resize(function () {
			waitForFinalEvent(function () {
				fitNavBarItems();
				fitMainDivHeight();
				fitExporterHeight();
				fitImporterHeight();
				_updateCardTagOverflow();
			}, 150, "window-resize");
		});

        //Window load - race-safe: handles case where native load event fires
		//before jQuery can bind its handler (script parse time > resource load time)
		(function _windowLoadInit() {
			function _onWindowLoad() {
				// Track when splash animation and init are both done
				var _splashAnimDone = false;
				var _splashInitDone = false;
				// Use the real animation start time recorded in index.html,
				// not Date.now() (main.js loads late due to deferred script loading)
				var _splashStartTime = window._splashStartTime || Date.now();
				var SPLASH_ANIM_MS = 2300; // match SVG animation duration (~2273ms) + small buffer

				function dismissSplashIfReady() {
					if (!_splashAnimDone || !_splashInitDone) return;
					// Set window title bar to full name, taskbar to short name
					win.title = 'Library Manager';
					// Restore scrolling now that splash is leaving
					document.documentElement.style.overflow = '';
					document.body.style.overflow = '';
					// Reveal main app content (hidden via inline style to prevent unstyled flash)
					var appContent = document.querySelector('.container-fluid');
					if (appContent) appContent.style.visibility = 'visible';
					var splashEl = document.getElementById('splash-screen');
					if (splashEl) {
						splashEl.classList.add('splash-fade-out');
						splashEl.addEventListener('transitionend', function handler() {
							splashEl.removeEventListener('transitionend', handler);
							if (splashEl.parentNode) splashEl.parentNode.removeChild(splashEl);
						});
						// Safety: if transitionend doesn't fire within 2s, force remove
						setTimeout(function() {
							var el = document.getElementById('splash-screen');
							if (el && el.parentNode) el.parentNode.removeChild(el);
						}, 2000);
					}
				}

				// Fire when animation time has elapsed
				var elapsed = Date.now() - _splashStartTime;
				var remaining = Math.max(0, SPLASH_ANIM_MS - elapsed);
				setTimeout(function() {
					_splashAnimDone = true;
					dismissSplashIfReady();
				}, remaining);

				// Sync maximized state flag with persisted setting.
				// The actual maximize + pre-sizing is performed in index.html
				// BEFORE win.show() so the window appears full-screen instantly.
				// localStorage is the primary source; settings DB is fallback.
				try {
					var _storedMax = localStorage.getItem('windowMaximized');
					if (_storedMax !== null) {
						_windowIsMaximized = (_storedMax === 'true');
					} else if (getSettingValue('windowMaximized')) {
						_windowIsMaximized = true;
						localStorage.setItem('windowMaximized', 'true');
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

					// Mark init complete, dismiss splash if animation also done
					_splashInitDone = true;
					dismissSplashIfReady();
				}, 150);
			}

			// If load already fired, run immediately; otherwise wait for it
			if (document.readyState === 'complete') {
				_onWindowLoad();
			} else {
				window.addEventListener('load', _onWindowLoad);
			}
		})();

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
				// Pre-fill VENUS compatibility with detected version if field is empty
				if (!$("#pkg-venus-compat").val().trim() && _cachedVENUSVersion) {
					$("#pkg-venus-compat").val(_cachedVENUSVersion);
				}
				// Ensure trees show empty root on first visit
				if (!$("#pkg-lib-list").children().length) pkgUpdateLibFileList();
				if (!$("#pkg-demo-list").children().length) pkgUpdateDemoFileList();
				if (!$("#pkg-labware-tree").children().length) pkgUpdateLabwareFileList();
				if (!$("#pkg-bin-tree").children().length) pkgUpdateBinFileList();
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
			} else if(group_id == "gStarred"){
				// Starred Libraries tab - show only starred/favorite libraries
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-flex").addClass("d-none");
				impBuildLibraryCards(null, false, false, false, true);
				fitImporterHeight();
			} else if(group_id == "gSystem"){
				// System Libraries tab - show only system (Hamilton base) libraries
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-flex").addClass("d-none");
				impBuildLibraryCards(null, false, true);
				fitImporterHeight();
			} else if(group_id == "gUnsigned"){
				// Unsigned Libraries tab - show only scanned unsigned libraries
				$(".links-container").addClass("d-none");
				$(".exporter-container").addClass("d-none");
				$(".importer-container").removeClass("d-none");
				$("#imp-header").removeClass("d-flex").addClass("d-none");
				impBuildLibraryCards(null, false, false, true);
				fitImporterHeight();
			} else {
				// Custom group or other tab - show filtered library cards
				var groupData = getGroupById(group_id);
				if(groupData && (!groupData["default"] || group_id === "gOEM")){
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
				safeOpenItem(file_path);
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
			

			if(file_type==="method"){
				var args = [file_path];
				if($("#chk_run-autoclose").prop("checked")){ args.push("-t"); } //Run method immediately and terminate when method is complete.
				else if($("#chk_run-autoplay").prop("checked")){ args.push("-r"); } //Run method immediately.
    
				 var child =  spawn(HxRun, args, { detached: true, stdio: [ 'ignore', 'ignore', 'ignore' ] });
				 child.unref();
			}
			else if(file_type==="folder"){
				safeOpenItem(file_path);
				// nw.Shell.showItemInFolder(file_path);

			}
			else if(file_type==="file"){
				safeOpenItem(file_path);
			}
		});


		//Open attachment of a link card in the main div
		$(document).on("click", ".link-attachment", function () {
			var file_path = $(this).attr("data-filepath");	
			if(file_path!=""){
				safeOpenItem(file_path);
			}	
		});

		//Open In Method Editor link card in the main div
		$(document).on("click", ".link-OpenMethEditor", function () {
			
			var file_path = $(this).closest(".link-card-container").attr("data-filepath");
			if(file_path!=""){
				file_path = file_path.substr(0, file_path.lastIndexOf(".")) + ".med";
				safeOpenItem(file_path);
			}	
		});

		//Open Method Location link card in the main div
		$(document).on("click", ".link-OpenMethLocation", function () {
			
			var file_path = path.dirname($(this).closest(".link-card-container").attr("data-filepath"));
			if(file_path!=""){
				safeOpenItem(file_path);
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

		//Click "Report Issue" from overflow menu.
		$(document).on("click", ".overflow-report-issue", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			$("#reportIssueModal").modal("show");
		});

		//Click "About" from overflow menu.
		$(document).on("click", ".overflow-about", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			// Populate version from NW.js manifest (most reliable), with filesystem fallback
			var appVersion = '';
			try {
				if (typeof nw !== 'undefined' && nw.App && nw.App.manifest && nw.App.manifest.version) {
					appVersion = nw.App.manifest.version;
				} else {
					var pkgPath = path.join(path.dirname(process.execPath), 'package.json');
					var pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
					appVersion = pkgData.version || '';
				}
			} catch (ex) {
				appVersion = '';
			}
			$(".about-version").text(appVersion ? "Version " + appVersion : "");

			// Populate Windows version
			try {
				var winRelease = os.release(); // e.g. "10.0.19045"
				var winVersion = 'Windows ' + winRelease;
				// Try to get a friendly name from the registry (e.g. "Windows 11 Pro")
				try {
					var execSync = require('child_process').execSync;
					var prodName = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName', { encoding: 'utf8', timeout: 5000 });
					var pnMatch = prodName.match(/ProductName\s+REG_SZ\s+(.+)/i);
					if (pnMatch) {
						var buildMatch = prodName.match(/CurrentBuild\s+REG_SZ\s+(\d+)/i);
						winVersion = pnMatch[1].trim() + ' (Build ' + winRelease + ')';
					}
				} catch (_) { /* use fallback */ }
				$(".about-windows-version").text(winVersion);
			} catch (_) {
				$(".about-windows-version").text('N/A');
			}

			// Populate VENUS version
			try {
				var venusVer = _cachedVENUSVersion;
				if (!venusVer) {
					var vInfo = getVENUSInstallInfo();
					venusVer = vInfo.version || '';
					if (venusVer) _cachedVENUSVersion = venusVer;
				}
				$(".about-venus-version").text(venusVer || 'Not detected');
			} catch (_) {
				$(".about-venus-version").text('Not detected');
			}

			$("#aboutModal").modal("show");
		});

		// ---- Secret flask icon click handler: 8 clicks to toggle OEM/developer settings ----
		// OEM override state is session-only (in-memory); resets on app restart
		var _oemSessionUnlocked = false;
		var _oemSessionKeywordsEnabled = false;
		var _flaskClickCount = 0;
		var _flaskClickTimer = null;
		$(document).on("click", "#about-flask-icon", async function () {
			_flaskClickCount++;
			if (_flaskClickTimer) clearTimeout(_flaskClickTimer);
			_flaskClickTimer = setTimeout(function () { _flaskClickCount = 0; }, 3000);
			if (_flaskClickCount >= 8) {
				_flaskClickCount = 0;
				if (_flaskClickTimer) { clearTimeout(_flaskClickTimer); _flaskClickTimer = null; }
				if (_oemSessionUnlocked) {
					// Disabling developer mode does not require password
					_oemSessionUnlocked = false;
					applyOemSettingsVisibility(false);
					$("#chk_oemKeywordsEnabled").prop("checked", false);
					_oemSessionKeywordsEnabled = false;
					$(".oem-keywords-status").html('');
					alert('Developer settings disabled.');
				} else {
					// Enabling developer mode requires OEM password
					var pwOk = await promptAuthorPassword();
					if (pwOk) {
						_oemSessionUnlocked = true;
						applyOemSettingsVisibility(true);
						alert('Developer settings enabled.');
					}
				}
			}
		});

		/** Show or hide OEM/developer settings sections */
		function applyOemSettingsVisibility(unlocked) {
			if (unlocked) {
				$("#settings-oem-keywords-section").show();
				$("#pkg-installer-exe-section").show();
				$("#pkg-bin-files-section").show();
			} else {
				$("#settings-oem-keywords-section").hide();
				$("#pkg-installer-exe-section").hide();
				$("#pkg-bin-files-section").hide();
			}
		}

		//Click privacy policy link inside About modal.
		$(document).on("click", ".about-privacy-link", function (e) {
			e.preventDefault();
			$("#aboutModal").modal("hide");
			// Load privacy policy text from file
			try {
				var policyPath = path.join(path.dirname(process.execPath), 'PRIVACY_POLICY.txt');
				var policyText = fs.readFileSync(policyPath, 'utf8');
				$(".privacy-policy-text").text(policyText);
			} catch (ex) {
				$(".privacy-policy-text").text("Privacy policy file not found.");
			}
			$("#privacyPolicyModal").modal("show");
		});

		//Click terms of use link inside About modal.
		$(document).on("click", ".about-terms-link", function (e) {
			e.preventDefault();
			$("#aboutModal").modal("hide");
			// Load terms of use text from file
			try {
				var termsPath = path.join(path.dirname(process.execPath), 'TERMS_OF_USE.txt');
				var termsText = fs.readFileSync(termsPath, 'utf8');
				$(".terms-of-use-text").text(termsText);
			} catch (ex) {
				$(".terms-of-use-text").text("Terms of use file not found.");
			}
			$("#termsOfUseModal").modal("show");
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
			// Pre-fill VENUS compatibility with detected version if field is empty
			if (!$("#pkg-venus-compat").val().trim() && _cachedVENUSVersion) {
				$("#pkg-venus-compat").val(_cachedVENUSVersion);
			}
			// Ensure trees show empty root on first visit
			if (!$("#pkg-lib-list").children().length) pkgUpdateLibFileList();
			if (!$("#pkg-demo-list").children().length) pkgUpdateDemoFileList();
			if (!$("#pkg-labware-tree").children().length) pkgUpdateLabwareFileList();
			if (!$("#pkg-bin-tree").children().length) pkgUpdateBinFileList();
			// Refresh code signing UI for packager
			refreshSigningUI();
			var sigInfo = getSigningDisplayInfo();
			$("#chk-pkg-sign").prop("checked", !!sigInfo);
			$(".pkg-signing-detail").toggle(!!sigInfo);
			fitExporterHeight();
			return false;
		});

		//Click "History" from overflow menu
		$(document).on("click", ".overflow-history", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			openEventHistoryModal();
			return false;
		});

		// ---- Event History modal event listeners ----
		// Search box
		$(document).on("input", ".evt-history-search", function () {
			filterEventHistory();
		});
		// Category filter
		$(document).on("change", ".evt-history-cat-filter", function () {
			filterEventHistory();
		});
		// User filter
		$(document).on("change", ".evt-history-user-filter", function () {
			filterEventHistory();
		});
		// Toggle details expand/collapse
		$(document).on("click", ".evt-history-details-toggle", function (e) {
			e.preventDefault();
			var $block = $(this).siblings('.evt-history-detail-block');
			$block.toggleClass('show');
			var $icon = $(this).find('i');
			if ($block.hasClass('show')) {
				$icon.removeClass('fa-chevron-down').addClass('fa-chevron-up');
			} else {
				$icon.removeClass('fa-chevron-up').addClass('fa-chevron-down');
			}
		});
		// Export CSV button
		$(document).on("click", ".evt-history-export", function (e) {
			e.preventDefault();
			var csv = exportEventHistoryCsv();
			if (!csv) return;
			// Use the hidden NW file save dialog
			var $dlg = $('#evt-history-save-dialog');
			$dlg.off('change').on('change', function() {
				var savePath = $(this).val();
				if (savePath) {
					try {
						fs.writeFileSync(savePath, csv, 'utf8');
						alert('Event history exported to:\n' + savePath);
					} catch(ex) {
						alert('Could not save CSV: ' + ex.message);
					}
				}
				$(this).val('');
			});
			$dlg.trigger('click');
		});

		// ---- Library Search Bar ----
		var _searchTimeout = null;
		var _searchActive = false;
		var _preSearchGroupId = null; // remembers which tab was active before search
		var _currentSortOrder = 'az'; // current library sort order: az, za, newest, oldest
		var _searchInlineTokens = [];
		var _pendingDeleteChipIdx = -1;

		function clearPendingDeleteChip() {
			if (_pendingDeleteChipIdx >= 0) {
				$(".imp-search-chip.imp-search-chip-pending-delete").removeClass("imp-search-chip-pending-delete");
				_pendingDeleteChipIdx = -1;
			}
		}

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

		function renderSearchInlineTokens() {
			var $wrap = $("#imp-search-chip-wrap");
			if (!$wrap.length) return;
			if (!_searchInlineTokens || _searchInlineTokens.length === 0) {
				$wrap.addClass("d-none").empty();
				updateSearchInputWidth();
				return;
			}
			var html = '';
			_searchInlineTokens.forEach(function(token, idx) {
				if (!token || !token.type) return;
				if (token.type === 'text') {
					if (!token.value) return;
					html += '<span class="imp-search-inline-text" data-idx="' + idx + '">' +
						'<span class="imp-search-text-label">' + escapeHtml(token.value) + '</span>' +
						'<input type="text" class="imp-search-text-input" value="' + escapeHtml(token.value) + '" aria-label="Edit text">' +
					'</span>';
					return;
				}
				if (token.type === 'author') {
					html += '<span class="imp-search-chip imp-search-chip-author" data-idx="' + idx + '" data-tag="' + escapeHtml(token.value || '') + '" data-chip-type="author">' +
						'<span class="imp-search-chip-label">@' + escapeHtml(token.value || '') + '</span>' +
						'<input type="text" class="imp-search-chip-input" value="' + escapeHtml(token.value || '') + '" aria-label="Edit author">' +
						'<button type="button" class="imp-search-chip-remove" aria-label="Remove author" title="Remove author"><i class="fas fa-times"></i></button>' +
					'</span>';
					return;
				}
				html += '<span class="imp-search-chip" data-idx="' + idx + '" data-tag="' + escapeHtml(token.value || '') + '" data-chip-type="tag">' +
					'<span class="imp-search-chip-label">#' + escapeHtml(token.value || '') + '</span>' +
					'<input type="text" class="imp-search-chip-input" value="' + escapeHtml(token.value || '') + '" aria-label="Edit tag">' +
					'<button type="button" class="imp-search-chip-remove" aria-label="Remove tag" title="Remove tag"><i class="fas fa-times"></i></button>' +
				'</span>';
			});
			$wrap.html(html).removeClass("d-none");
			updateSearchInputWidth();
			scrollSearchFlowToEnd();
		}

		function updateSearchInputWidth() {
			var $input = $("#imp-search-input");
			if (!$input.length) return;
			var hasTokens = _searchInlineTokens && _searchInlineTokens.length > 0;
			var val = $input.val() || '';
			if (hasTokens) {
				// Auto-size to content so chips + text overflow & scroll as one stream
				$input.attr('placeholder', '');
				$input.css('width', Math.max(val.length + 1, 4) + 'ch');
			} else {
				$input.attr('placeholder', 'Search Libraries...');
				// Wide enough for placeholder, or content
				$input.css('width', Math.max(val.length + 1, 19) + 'ch');
			}
		}

		function scrollSearchFlowToEnd() {
			var $flow = $(".imp-search-flow");
			if (!$flow.length) return;
			// Defer to next animation frame so the browser has reflowed
			// the new DOM content and scrollWidth is up to date.
			requestAnimationFrame(function() {
				$flow.scrollLeft($flow.get(0).scrollWidth);
			});
		}

		function normalizeSearchInlineTokens() {
			var normalized = [];
			(_searchInlineTokens || []).forEach(function(token) {
				if (!token || !token.type) return;
				if (token.type === 'text') {
					var value = (token.value || '');
					if (!value) return;
					if (normalized.length && normalized[normalized.length - 1].type === 'text') {
						normalized[normalized.length - 1].value += value;
					} else {
						normalized.push({ type: 'text', value: value });
					}
					return;
				}
				if (token.type === 'author') {
					var authorVal = (token.value || '').trim();
					if (!authorVal) return;
					normalized.push({ type: 'author', value: authorVal });
					return;
				}
				var sanitized = shared.sanitizeTag(token.value || '');
				if (!sanitized) return;
				normalized.push({ type: 'tag', value: sanitized });
			});
			_searchInlineTokens = normalized;
		}

		function insertSearchTagToken(rawTag, options) {
			options = options || {};
			var sanitized = shared.sanitizeTag(rawTag || '');
			if (!sanitized) return false;
			_searchInlineTokens.push({ type: 'tag', value: sanitized });
			if (options.trailingSpace === true) {
				_searchInlineTokens.push({ type: 'text', value: ' ' });
			}
			normalizeSearchInlineTokens();
			renderSearchInlineTokens();
			return true;
		}

		function insertSearchAuthorToken(rawAuthor, options) {
			options = options || {};
			var trimmed = (rawAuthor || '').trim();
			if (!trimmed) return false;
			_searchInlineTokens.push({ type: 'author', value: trimmed });
			if (options.trailingSpace === true) {
				_searchInlineTokens.push({ type: 'text', value: ' ' });
			}
			normalizeSearchInlineTokens();
			renderSearchInlineTokens();
			return true;
		}

		function updateSearchTagChipByIndex(idx, rawNewTag) {
			if (idx < 0 || idx >= _searchInlineTokens.length) return false;
			var token = _searchInlineTokens[idx];
			if (!token) return false;

			if (token.type === 'author') {
				var trimmed = (rawNewTag || '').trim();
				if (!trimmed) return false;
				_searchInlineTokens[idx].value = trimmed;
				normalizeSearchInlineTokens();
				renderSearchInlineTokens();
				return true;
			}

			if (token.type !== 'tag') return false;
			var sanitized = shared.sanitizeTag(rawNewTag || '');
			if (!sanitized) return false;
			_searchInlineTokens[idx].value = sanitized;
			normalizeSearchInlineTokens();
			renderSearchInlineTokens();
			return true;
		}

		function consumeCompletedTagTokens() {
			var $input = $("#imp-search-input");
			var raw = $input.val() || '';
			if (raw.indexOf('#') === -1) return;
			var pending = raw;
			var consumedAny = false;

			while (true) {
				var match = pending.match(/(^|\s)#([^#@]+?)(?=\s*[#@])/);
				if (!match) break;

				var marker = '#' + match[2];
				var markerIndex = pending.indexOf(marker);
				if (markerIndex === -1) break;

				var prefixText = pending.slice(0, markerIndex);
				if (prefixText) {
					_searchInlineTokens.push({ type: 'text', value: prefixText });
				}

				if (!insertSearchTagToken(match[2], { trailingSpace: true })) {
					break;
				}

				pending = pending.slice(markerIndex + marker.length);
				if (pending.charAt(0) === ' ') {
					pending = pending.slice(1);
				}
				consumedAny = true;
			}

			if (consumedAny) {
				normalizeSearchInlineTokens();
				renderSearchInlineTokens();
				$input.val(pending);
				updateSearchInputWidth();
				scrollSearchFlowToEnd();
			}
		}

		function commitTrailingSearchTag(options) {
			options = options || {};
			var $input = $("#imp-search-input");
			var raw = $input.val() || '';
			var match = raw.match(/(^|\s)#([^#@]+?)\s*$/);
			if (!match) return false;

			var candidate = match[2] || '';
			var marker = '#' + candidate;
			var markerIndex = raw.lastIndexOf(marker);
			if (markerIndex === -1) return false;

			var prefixText = raw.slice(0, markerIndex);
			if (prefixText) {
				_searchInlineTokens.push({ type: 'text', value: prefixText });
			}

			if (!insertSearchTagToken(candidate, { trailingSpace: options.appendSpace === true })) return false;

			var nextRaw = '';
			$input.val(nextRaw);
			normalizeSearchInlineTokens();
			renderSearchInlineTokens();
			updateSearchInputWidth();
			scrollSearchFlowToEnd();
			return true;
		}

		/**
		 * Commit a trailing @author from the input.
		 * Author tokens can contain spaces, so only Tab/Enter commit them.
		 */
		function commitTrailingSearchAuthor(options) {
			options = options || {};
			var $input = $("#imp-search-input");
			var raw = $input.val() || '';
			// Match @authorname (may contain spaces) at end of input
			var match = raw.match(/(^|.*\s)@([^\s@].*)$/);
			if (!match) return false;

			var candidate = (match[2] || '').trim();
			if (!candidate) return false;

			var marker = '@' + match[2];
			var markerIndex = raw.lastIndexOf('@' + match[2].trimStart());
			if (markerIndex === -1) return false;

			var prefixText = raw.slice(0, markerIndex);
			if (prefixText) {
				_searchInlineTokens.push({ type: 'text', value: prefixText });
			}

			if (!insertSearchAuthorToken(candidate, { trailingSpace: options.appendSpace === true })) return false;

			$input.val('');
			normalizeSearchInlineTokens();
			renderSearchInlineTokens();
			updateSearchInputWidth();
			scrollSearchFlowToEnd();
			return true;
		}

		/**
		 * Auto-close an @author token if the user has typed more spaces than any
		 * known publisher has. This prevents the author chip from eating unlimited text.
		 * Called on every input event.
		 */
		function autoCloseAuthorTokenBySpaceLimit() {
			var $input = $("#imp-search-input");
			var raw = $input.val() || '';
			var match = raw.match(/(^|.*\s)@([^\s@].*)$/);
			if (!match) return;

			var afterAt = match[2] || '';
			var spaceCount = (afterAt.match(/ /g) || []).length;
			var maxSpaces = getMaxPublisherSpaces();

			// If typed more spaces than any known publisher, auto-commit
			if (spaceCount > maxSpaces) {
				// Find the last space - everything before it is the author, after is leftover
				var lastSpaceIdx = afterAt.lastIndexOf(' ');
				var authorPart = afterAt.slice(0, lastSpaceIdx).trim();
				var leftover = afterAt.slice(lastSpaceIdx + 1);

				if (authorPart) {
					var markerIndex = raw.lastIndexOf('@' + match[2].trimStart());
					if (markerIndex === -1) return;

					var prefixText = raw.slice(0, markerIndex);
					if (prefixText) {
						_searchInlineTokens.push({ type: 'text', value: prefixText });
					}

					if (insertSearchAuthorToken(authorPart, { trailingSpace: true })) {
						$input.val(leftover);
						normalizeSearchInlineTokens();
						renderSearchInlineTokens();
						updateSearchInputWidth();
						scrollSearchFlowToEnd();
					}
				}
			}
		}

		function getSearchInlineRawText() {
			var tokenText = (_searchInlineTokens || []).map(function(token) {
				if (!token) return '';
				if (token.type === 'tag') return '#' + (token.value || '');
				if (token.type === 'author') return '@' + (token.value || '');
				return token.value || '';
			}).join('');
			return tokenText + ($("#imp-search-input").val() || '');
		}

		function getSearchStateFromInput() {
			var rawInput = ($("#imp-search-input").val() || '').trim().toLowerCase();
			var tagFilters = [];
			var authorFilters = [];
			var textTokens = [];

			(_searchInlineTokens || []).forEach(function(token) {
				if (token && token.type === 'tag') {
					var tag = shared.sanitizeTag(token.value || '');
					if (tag) tagFilters.push(tag);
				}
				if (token && token.type === 'author') {
					var author = (token.value || '').trim().toLowerCase();
					if (author && authorFilters.indexOf(author) === -1) authorFilters.push(author);
				}
				if (token && token.type === 'text') {
					var txt = (token.value || '').trim();
					if (txt) textTokens.push(txt);
				}
			});

			if (rawInput) {
				rawInput.split(/(?=\s*[#@])/).forEach(function(part) {
					var token = part.trim();
					if (!token) return;
					if (token.charAt(0) === '#' && token.length > 1) {
						var tag = shared.sanitizeTag(token.substring(1));
						if (tag && tagFilters.indexOf(tag) === -1) {
							tagFilters.push(tag);
						} else if (!tag) {
							textTokens.push(token);
						}
					} else if (token.charAt(0) === '@' && token.length > 1) {
						var author = token.substring(1).trim().toLowerCase();
						if (author && authorFilters.indexOf(author) === -1) {
							authorFilters.push(author);
						}
					} else {
						textTokens.push(token);
					}
				});
			}

			var textQuery = textTokens.join(' ').trim();
			var displayBits = [];
			var displayHtmlBits = [];

			// Build display in token order to match search bar layout
			(_searchInlineTokens || []).forEach(function(token) {
				if (!token) return;
				if (token.type === 'author') {
					var a = (token.value || '').trim().toLowerCase();
					if (a) {
						displayBits.push('@' + a);
						displayHtmlBits.push('<b>@' + escapeHtml(a) + '</b>');
					}
				} else if (token.type === 'tag') {
					var t = shared.sanitizeTag(token.value || '');
					if (t) {
						displayBits.push('#' + t);
						displayHtmlBits.push('<b>#' + escapeHtml(t) + '</b>');
					}
				} else if (token.type === 'text') {
					var txt = (token.value || '').trim();
					if (txt) {
						displayBits.push(txt);
						displayHtmlBits.push(escapeHtml(txt));
					}
				}
			});

			// Append any trailing input (uncommitted text, tags, authors)
			if (rawInput) {
				rawInput.split(/(?=\s*[#@])/).forEach(function(part) {
					var ri = part.trim();
					if (!ri) return;
					if (ri.charAt(0) === '#' && ri.length > 1) {
						var rt = shared.sanitizeTag(ri.substring(1));
						if (rt) {
							displayBits.push('#' + rt);
							displayHtmlBits.push('<b>#' + escapeHtml(rt) + '</b>');
						} else {
							displayBits.push(ri);
							displayHtmlBits.push(escapeHtml(ri));
						}
					} else if (ri.charAt(0) === '@' && ri.length > 1) {
						var ra = ri.substring(1).trim().toLowerCase();
						if (ra) {
							displayBits.push('@' + ra);
							displayHtmlBits.push('<b>@' + escapeHtml(ra) + '</b>');
						}
					} else {
						displayBits.push(ri);
						displayHtmlBits.push(escapeHtml(ri));
					}
				});
			}

			var displayQuery = displayBits.join(' ').trim();
			var displayQueryHtml = displayHtmlBits.join(' ');

			return {
				tagFilters: tagFilters,
				authorFilters: authorFilters,
				textQuery: textQuery,
				displayQuery: displayQuery,
				displayQueryHtml: displayQueryHtml,
				hasSearch: tagFilters.length > 0 || authorFilters.length > 0 || textQuery.length > 0
			};
		}

		function refreshLibrarySearchFromInput() {
			consumeCompletedTagTokens();
			var state = getSearchStateFromInput();
			$(".imp-search-clear-wrap").toggleClass("d-none", !state.hasSearch);

			clearTimeout(_searchTimeout);
			_searchTimeout = setTimeout(function() {
					if (state.hasSearch) {
					impEnterSearchMode(state.displayQuery, {
						tagFilters: state.tagFilters,
						authorFilters: state.authorFilters,
						textQuery: state.textQuery,
						displayQueryHtml: state.displayQueryHtml
					});
				} else {
					impExitSearchMode();
				}
			}, 150);
		}

		// ---- Search Autocomplete ----
		var _acSelectedIdx = -1;

		function getSearchAutocompleteContext() {
			var raw = ($("#imp-search-input").val() || '');
			// Check for trailing @partial (author autocomplete)
			var authorMatch = raw.match(/(^|.*\s)@([^@]*)$/);
			if (authorMatch) {
				return { type: 'author', prefix: (authorMatch[2] || '').toLowerCase() };
			}
			// Check for trailing #partial (tag autocomplete)
			var tagMatch = raw.match(/(^|.*\s)#([^#@]*)$/);
			if (tagMatch) {
				return { type: 'tag', prefix: (tagMatch[2] || '').toLowerCase() };
			}
			return null;
		}

		function updateSearchAutocomplete() {
			var $ac = $("#imp-search-autocomplete");
			var ctx = getSearchAutocompleteContext();
			if (!ctx) {
				hideSearchAutocomplete();
				return;
			}

			var suggestions = [];
			if (ctx.type === 'tag') {
				var allTags = getKnownTags();
				// Also gather tags already used as chips so we can mark them
				var usedTags = {};
				(_searchInlineTokens || []).forEach(function(t) {
					if (t && t.type === 'tag') usedTags[t.value] = true;
				});
				allTags.forEach(function(tag) {
					if (usedTags[tag]) return; // skip already-active tags
					if (!ctx.prefix || tag.indexOf(ctx.prefix) !== -1) {
						suggestions.push({ type: 'tag', value: tag, label: '#' + tag });
					}
				});
				// Sort: prefix-match first, then alphabetical
				suggestions.sort(function(a, b) {
					var aStart = a.value.indexOf(ctx.prefix) === 0 ? 0 : 1;
					var bStart = b.value.indexOf(ctx.prefix) === 0 ? 0 : 1;
					if (aStart !== bStart) return aStart - bStart;
					return a.value.localeCompare(b.value);
				});
			} else if (ctx.type === 'author') {
				var allPubs = getKnownPublishers();
				var usedAuthors = {};
				(_searchInlineTokens || []).forEach(function(t) {
					if (t && t.type === 'author') usedAuthors[t.value.toLowerCase()] = true;
				});
				allPubs.forEach(function(pub) {
					if (usedAuthors[pub.toLowerCase()]) return;
					if (!ctx.prefix || pub.toLowerCase().indexOf(ctx.prefix) !== -1) {
						suggestions.push({ type: 'author', value: pub, label: '@' + pub });
					}
				});
				suggestions.sort(function(a, b) {
					var aStart = a.value.toLowerCase().indexOf(ctx.prefix) === 0 ? 0 : 1;
					var bStart = b.value.toLowerCase().indexOf(ctx.prefix) === 0 ? 0 : 1;
					if (aStart !== bStart) return aStart - bStart;
					return a.value.localeCompare(b.value);
				});
			}

			if (suggestions.length === 0) {
				hideSearchAutocomplete();
				return;
			}

			// Limit to 8 suggestions
			suggestions = suggestions.slice(0, 8);

			var icon = ctx.type === 'tag' ? 'fa-tag' : 'fa-user';
			var html = '';
			suggestions.forEach(function(s, i) {
				// Highlight matching portion
				var display = escapeHtml(s.label);
				if (ctx.prefix) {
					var matchIdx = s.value.toLowerCase().indexOf(ctx.prefix);
					if (matchIdx !== -1) {
						var prefix = s.label.charAt(0); // # or @
						var before = s.value.substring(0, matchIdx);
						var match = s.value.substring(matchIdx, matchIdx + ctx.prefix.length);
						var after = s.value.substring(matchIdx + ctx.prefix.length);
						display = escapeHtml(prefix) + escapeHtml(before) +
							'<span class="ac-match">' + escapeHtml(match) + '</span>' +
							escapeHtml(after);
					}
				}
				html += '<div class="imp-search-ac-item' + (i === 0 ? ' active' : '') + '" data-ac-idx="' + i + '" data-ac-type="' + s.type + '" data-ac-value="' + escapeHtml(s.value) + '">' +
					'<i class="fas ' + icon + ' ac-icon"></i>' +
					'<span class="ac-label">' + display + '</span>' +
				'</div>';
			});

			$ac.html(html).removeClass('d-none');
			_acSelectedIdx = 0;
		}

		function hideSearchAutocomplete() {
			$("#imp-search-autocomplete").addClass('d-none').empty();
			_acSelectedIdx = -1;
		}

		function selectAutocompleteItem(idx) {
			var $items = $("#imp-search-autocomplete .imp-search-ac-item");
			if (idx < 0 || idx >= $items.length) return;
			$items.removeClass('active');
			$items.eq(idx).addClass('active');
			_acSelectedIdx = idx;
			// Scroll into view
			var item = $items.eq(idx)[0];
			if (item) item.scrollIntoView({ block: 'nearest' });
		}

		function commitAutocompleteSelection() {
			var $items = $("#imp-search-autocomplete .imp-search-ac-item");
			if (_acSelectedIdx < 0 || _acSelectedIdx >= $items.length) return false;
			var $item = $items.eq(_acSelectedIdx);
			var type = $item.attr('data-ac-type');
			var value = $item.attr('data-ac-value');
			if (!type || !value) return false;

			var $input = $("#imp-search-input");
			var raw = $input.val() || '';

			if (type === 'tag') {
				// Remove the #partial from input
				var tagMatch = raw.match(/^(.*?)(?:^|\s)#[^#@]*$/);
				var prefix = tagMatch ? tagMatch[1] : '';
				if (prefix.trim()) {
					_searchInlineTokens.push({ type: 'text', value: prefix });
				}
				insertSearchTagToken(value, { trailingSpace: true });
				$input.val('');
			} else if (type === 'author') {
				// Remove the @partial from input
				var authorMatch = raw.match(/^(.*?)(?:^|\s)@[^@]*$/);
				var prefix2 = authorMatch ? authorMatch[1] : '';
				if (prefix2.trim()) {
					_searchInlineTokens.push({ type: 'text', value: prefix2 });
				}
				insertSearchAuthorToken(value, { trailingSpace: true });
				$input.val('');
			}

			hideSearchAutocomplete();
			normalizeSearchInlineTokens();
			renderSearchInlineTokens();
			updateSearchInputWidth();
			scrollSearchFlowToEnd();
			refreshLibrarySearchFromInput();
			$("#imp-search-input").focus();
			return true;
		}

		$(document).on("click", ".imp-search-ac-item", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var idx = parseInt($(this).attr('data-ac-idx'), 10);
			if (!isNaN(idx)) {
				_acSelectedIdx = idx;
				commitAutocompleteSelection();
			}
		});

		// Prevent mousedown on autocomplete from stealing focus
		$(document).on("mousedown", ".imp-search-autocomplete", function(e) {
			e.preventDefault();
		});

		$(document).on("input", "#imp-search-input", function() {
			clearPendingDeleteChip();
			// Prevent space immediately after a bare # or @ (no tag/author text yet).
			var $inp = $(this);
			var v = $inp.val() || '';
			var fixed = v.replace(/(^|[\s])# /g, '$1#').replace(/(^|[\s])@ /g, '$1@');
			if (fixed !== v) {
				var pos = this.selectionStart - (v.length - fixed.length);
				$inp.val(fixed);
				this.selectionStart = this.selectionEnd = Math.max(pos, 0);
			}
			// Auto-close @author if user typed more spaces than any known publisher
			autoCloseAuthorTokenBySpaceLimit();
			updateSearchInputWidth();
			scrollSearchFlowToEnd();
			refreshLibrarySearchFromInput();
			updateSearchAutocomplete();
		});

		$(document).on("blur", "#imp-search-input", function() {
			// Small delay so click on autocomplete item fires first
			setTimeout(function() {
				hideSearchAutocomplete();
			}, 150);
		});

		$(document).on("focus", "#imp-search-input", function() {
			updateSearchAutocomplete();
		});

		updateSearchInputWidth();

		$(document).on("click", ".imp-search-clear", function() {
			_searchInlineTokens = [];
			renderSearchInlineTokens();
			hideSearchAutocomplete();
			$("#imp-search-input").val("").trigger("input");
			updateSearchInputWidth();
		});

		$(document).on("click", ".imp-search-inline-text", function(e) {
			e.preventDefault();
			e.stopPropagation();
			clearPendingDeleteChip();
			var $span = $(this);
			if ($span.hasClass('editing')) return;
			// Measure the label's actual rendered width before hiding it
			var $label = $span.find('.imp-search-text-label');
			var labelWidth = $label[0].offsetWidth;
			$span.addClass('editing');
			var $editor = $span.find('.imp-search-text-input');
			var val = $editor.val() || '';
			$editor.css('width', labelWidth + 'px');
			$editor.focus();

			// Place caret near click position
			try {
				var spanRect = $span[0].getBoundingClientRect();
				var clickX = e.clientX - spanRect.left;
				var charWidth = spanRect.width / Math.max(val.length, 1);
				var caretPos = Math.round(clickX / charWidth);
				caretPos = Math.max(0, Math.min(caretPos, val.length));
				$editor[0].selectionStart = $editor[0].selectionEnd = caretPos;
			} catch(ex) {
				$editor[0].selectionStart = $editor[0].selectionEnd = val.length;
			}
		});

		$(document).on("input", ".imp-search-text-input", function() {
			// Measure by temporarily showing the label with new text
			var val = $(this).val() || '';
			var $span = $(this).closest('.imp-search-inline-text');
			var $label = $span.find('.imp-search-text-label');
			$label.text(val || ' ').css('display', 'inline');
			var w = $label[0].offsetWidth;
			$label.css('display', '');
			$(this).css('width', w + 'px');
		});

		$(document).on("keydown", ".imp-search-text-input", function(e) {
			if (e.key === 'Enter' || e.key === 'Tab') {
				e.preventDefault();
				$(this).data('focus-main-input', true);
				$(this).blur();
				return;
			}
			if (e.key === 'Escape') {
				e.preventDefault();
				$(this).data('cancel-edit', true);
				$(this).blur();
				return;
			}
			if (e.key === 'Delete') {
				var val = $(this).val() || '';
				var cursorAtEnd = this.selectionStart === val.length && this.selectionEnd === val.length;
				if (!cursorAtEnd) {
					clearPendingDeleteChip();
					return;
				}
				var idx = parseInt($(this).closest('.imp-search-inline-text').attr('data-idx'), 10);
				if (isNaN(idx)) return;
				// Find the next chip token after this text token
				var nextIdx = idx + 1;
				while (nextIdx < _searchInlineTokens.length && _searchInlineTokens[nextIdx].type === 'text' && !_searchInlineTokens[nextIdx].value.trim()) {
					nextIdx++;
				}
				if (nextIdx >= _searchInlineTokens.length) return;
				var nextToken = _searchInlineTokens[nextIdx];
				if (nextToken.type !== 'tag' && nextToken.type !== 'author') {
					clearPendingDeleteChip();
					return;
				}
				e.preventDefault();
				if (_pendingDeleteChipIdx === nextIdx) {
					// Second delete - remove the chip (and any whitespace between)
					_searchInlineTokens.splice(idx + 1, nextIdx - idx);
					_pendingDeleteChipIdx = -1;
					normalizeSearchInlineTokens();
					// Commit current text edit and re-render
					var $span = $(this).closest('.imp-search-inline-text');
					var currentIdx = parseInt($span.attr('data-idx'), 10);
					if (!isNaN(currentIdx) && currentIdx >= 0 && currentIdx < _searchInlineTokens.length) {
						_searchInlineTokens[currentIdx].value = $(this).val() || '';
					}
					normalizeSearchInlineTokens();
					renderSearchInlineTokens();
					refreshLibrarySearchFromInput();
					$("#imp-search-input").focus();
					scrollSearchFlowToEnd();
				} else {
					// First delete - highlight the chip
					clearPendingDeleteChip();
					_pendingDeleteChipIdx = nextIdx;
					$(".imp-search-chip[data-idx='" + nextIdx + "']").addClass("imp-search-chip-pending-delete");
				}
				return;
			}
			// Any other key clears pending delete highlight
			if (_pendingDeleteChipIdx >= 0) {
				clearPendingDeleteChip();
			}
		});

		$(document).on("blur", ".imp-search-text-input", function() {
			var $editor = $(this);
			var $span = $editor.closest('.imp-search-inline-text');
			if (!$span.length) return;
			var idx = parseInt($span.attr('data-idx'), 10);
			var cancelEdit = $editor.data('cancel-edit') === true;
			var focusMainInput = $editor.data('focus-main-input') === true;
			$editor.removeData('cancel-edit');
			$editor.removeData('focus-main-input');

			if (!cancelEdit && !isNaN(idx) && idx >= 0 && idx < _searchInlineTokens.length) {
				var newVal = $editor.val() || '';
				if (newVal.trim()) {
					_searchInlineTokens[idx].value = newVal;
				} else {
					_searchInlineTokens.splice(idx, 1);
				}
				normalizeSearchInlineTokens();
			}

			renderSearchInlineTokens();
			refreshLibrarySearchFromInput();
			if (focusMainInput || !cancelEdit) {
				$("#imp-search-input").focus();
				scrollSearchFlowToEnd();
			}
		});

		$(document).on("click", ".imp-search-chip-remove", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var idx = parseInt($(this).closest('.imp-search-chip').attr('data-idx'), 10);
			if (!isNaN(idx) && idx >= 0 && idx < _searchInlineTokens.length) {
				_searchInlineTokens.splice(idx, 1);
				normalizeSearchInlineTokens();
				renderSearchInlineTokens();
			}
			refreshLibrarySearchFromInput();
			$("#imp-search-input").focus();
			scrollSearchFlowToEnd();
		});

		$(document).on("click", ".imp-search-chip-label", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var $chip = $(this).closest('.imp-search-chip');
			if (!$chip.length) return;
			$chip.addClass('editing');
			var tag = ($chip.attr('data-tag') || '');
			var $editor = $chip.find('.imp-search-chip-input');
			$editor.val(tag).focus().select();
			scrollSearchFlowToEnd();
		});

		$(document).on("keydown", ".imp-search-chip-input", function(e) {
			if (e.key === 'Enter' || e.key === 'Tab') {
				e.preventDefault();
				$(this).data('focus-main-input', true);
				$(this).blur();
				return;
			}
			if (e.key === 'Escape') {
				e.preventDefault();
				$(this).data('cancel-edit', true);
				$(this).blur();
			}
		});

		$(document).on("blur", ".imp-search-chip-input", function() {
			var $editor = $(this);
			var $chip = $editor.closest('.imp-search-chip');
			if (!$chip.length) return;

			var idx = parseInt($chip.attr('data-idx'), 10);
			var cancelEdit = $editor.data('cancel-edit') === true;
			var focusMainInput = $editor.data('focus-main-input') === true;
			$editor.removeData('cancel-edit');
			$editor.removeData('focus-main-input');

			if (!cancelEdit) {
				updateSearchTagChipByIndex(idx, $editor.val());
			}

			renderSearchInlineTokens();
			refreshLibrarySearchFromInput();
			if (focusMainInput || !cancelEdit) {
				$("#imp-search-input").focus();
				scrollSearchFlowToEnd();
			}
		});

		$(document).on("keydown", "#imp-search-input", function(e) {
			var acVisible = !$("#imp-search-autocomplete").hasClass("d-none");
			var acItemCount = acVisible ? $("#imp-search-autocomplete .imp-search-ac-item").length : 0;

			// Autocomplete keyboard navigation
			if (acVisible && acItemCount > 0) {
				if (e.key === 'ArrowDown') {
					e.preventDefault();
					selectAutocompleteItem((_acSelectedIdx + 1) % acItemCount);
					return;
				}
				if (e.key === 'ArrowUp') {
					e.preventDefault();
					selectAutocompleteItem((_acSelectedIdx - 1 + acItemCount) % acItemCount);
					return;
				}
				if (e.key === 'Enter' || e.key === 'Tab') {
					if (_acSelectedIdx >= 0) {
						e.preventDefault();
						commitAutocompleteSelection();
						return;
					}
				}
				if (e.key === 'Escape') {
					e.preventDefault();
					hideSearchAutocomplete();
					return;
				}
			}

			if (e.key === 'Enter') {
				if (commitTrailingSearchAuthor({ appendSpace: true })) {
					e.preventDefault();
					refreshLibrarySearchFromInput();
					return;
				}
				if (commitTrailingSearchTag({ appendSpace: true })) {
					e.preventDefault();
					refreshLibrarySearchFromInput();
				}
				return;
			}

			if (e.key === 'Tab') {
				if (commitTrailingSearchAuthor({ appendSpace: true })) {
					refreshLibrarySearchFromInput();
					return;
				}
				if (commitTrailingSearchTag({ appendSpace: true })) {
					refreshLibrarySearchFromInput();
				}
				return;
			}

			if (e.key === 'ArrowLeft' && this.selectionStart === 0 && this.selectionEnd === 0 && _searchInlineTokens.length > 0) {
				e.preventDefault();
				clearPendingDeleteChip();
				var token = _searchInlineTokens.pop();
				var tokenRaw = '';
				if (token.type === 'tag') tokenRaw = '#' + (token.value || '');
				else if (token.type === 'author') tokenRaw = '@' + (token.value || '');
				else tokenRaw = (token.value || '');

				var currentVal = $(this).val() || '';
				$(this).val(tokenRaw + currentVal);
				normalizeSearchInlineTokens();
				renderSearchInlineTokens();
				updateSearchInputWidth();
				this.selectionStart = this.selectionEnd = 0;

				var flow = $(".imp-search-flow")[0];
				if (flow) flow.scrollLeft = this.offsetLeft - 10;
				return;
			}

			if (e.key === 'Backspace' && !$(this).val() && _searchInlineTokens.length > 0) {
				e.preventDefault();

				// Find the last meaningful token (skip trailing whitespace-only text)
				var lastIdx = _searchInlineTokens.length - 1;
				while (lastIdx >= 0 && _searchInlineTokens[lastIdx].type === 'text' && !_searchInlineTokens[lastIdx].value.trim()) {
					lastIdx--;
				}
				if (lastIdx < 0) return;

				var lastToken = _searchInlineTokens[lastIdx];

				if (lastToken.type === 'tag' || lastToken.type === 'author') {
					// Chip: highlight on first backspace, delete on second
					if (_pendingDeleteChipIdx === lastIdx) {
						// Already highlighted - delete the chip and trailing whitespace
						_searchInlineTokens.splice(lastIdx);
						_pendingDeleteChipIdx = -1;
						normalizeSearchInlineTokens();
						renderSearchInlineTokens();
						updateSearchInputWidth();
						scrollSearchFlowToEnd();
						refreshLibrarySearchFromInput();
					} else {
						// First backspace - highlight the chip for pending deletion
						clearPendingDeleteChip();
						_pendingDeleteChipIdx = lastIdx;
						$(".imp-search-chip[data-idx='" + lastIdx + "']").addClass("imp-search-chip-pending-delete");
					}
				} else {
					// Text token: pull it back into the input
					clearPendingDeleteChip();
					var textVal = lastToken.value || '';
					_searchInlineTokens.splice(lastIdx);
					$(this).val(textVal);
					normalizeSearchInlineTokens();
					renderSearchInlineTokens();
					updateSearchInputWidth();
					scrollSearchFlowToEnd();
					refreshLibrarySearchFromInput();
				}
			}
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

		function impEnterSearchMode(query, options) {
			options = options || {};
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

			var displayQuery = (typeof query === 'string') ? query : '';
			var displayQueryHtml = options.displayQueryHtml || '';
			var tagFilters = [];
			(options.tagFilters || []).forEach(function(rawTag) {
				var sanitized = shared.sanitizeTag(rawTag || '');
				if (sanitized && tagFilters.indexOf(sanitized) === -1) tagFilters.push(sanitized);
			});

			var authorFilters = [];
			(options.authorFilters || []).forEach(function(rawAuthor) {
				var a = (rawAuthor || '').trim().toLowerCase();
				if (a && authorFilters.indexOf(a) === -1) authorFilters.push(a);
			});

			var textQuery = ((options.textQuery || '') + '').toLowerCase().trim();

			// Backward compatibility for legacy single-string callers.
			if (!tagFilters.length && !authorFilters.length && !textQuery && typeof query === 'string') {
				var legacyQuery = query.trim().toLowerCase();
				if (legacyQuery.charAt(0) === '#' && legacyQuery.length > 1) {
					var legacyTag = shared.sanitizeTag(legacyQuery.substring(1));
					if (legacyTag) tagFilters.push(legacyTag);
					else textQuery = legacyQuery;
				} else if (legacyQuery.charAt(0) === '@' && legacyQuery.length > 1) {
					authorFilters.push(legacyQuery.substring(1));
				} else {
					textQuery = legacyQuery;
				}
			}

			var hasTagFilters = tagFilters.length > 0;
			var hasAuthorFilters = authorFilters.length > 0;
			var hasTextQuery = textQuery.length > 0;

			// Build combined search results using the full-text search index
			var $container = $("#imp-cards-container");
			$container.empty();

			// Lazily rebuild search index if dirty
			if (_searchIndexDirty) rebuildSearchIndex();

			// Run the indexed search (handles tag filters, author filters, text query)
			var indexResults = _searchIndex.search(textQuery, {
				tagFilters: tagFilters,
				authorFilters: authorFilters
			});

			// Build lookup maps for quick access to library records
			var userLibMap = {};
			var userLibs = db_installed_libs.installed_libs.find() || [];
			userLibs.forEach(function(l) {
				if (!l.deleted && !isSystemLibrary(l._id)) userLibMap[l._id] = l;
			});
			var sysLibMap = {};
			getAllSystemLibraries().forEach(function(s) { sysLibMap[s._id] = s; });

			// Render cards in relevance-ranked order
			var allCards = [];
			indexResults.forEach(function(result) {
				if (result.type === 'user') {
					var lib = userLibMap[result.id];
					if (lib) allCards.push({ type: 'user', html: impBuildSingleCardHtml(lib) });
				} else {
					var sLib = sysLibMap[result.id];
					if (sLib) allCards.push({ type: 'system', html: buildSystemLibraryCard(sLib) });
				}
			});

			if (allCards.length === 0) {
				var noResultsDisplay = displayQueryHtml || ('<b>' + escapeHtml(displayQuery) + '</b>');
				$container.html(
					'<div class="w-100 text-center py-5 imp-search-no-results">' +
						'<i class="fas fa-search fa-2x color-lightgray"></i>' +
						'<p class="text-muted mt-2">No libraries matching "' + noResultsDisplay + '"</p>' +
					'</div>'
				);
			} else {
				// Search results header
				var headerIcon = ((hasTagFilters || hasAuthorFilters) && !hasTextQuery) ? (hasAuthorFilters && !hasTagFilters ? '<i class="fas fa-user mr-1"></i>' : '<i class="fas fa-tag mr-1"></i>') : '<i class="fas fa-search mr-1"></i>';
				var headerDisplay = displayQueryHtml || ('<b>' + escapeHtml(displayQuery) + '</b>');
				$container.append(
					'<div class="col-md-12 mb-2">' +
						'<span class="text-muted text-sm">' + headerIcon + allCards.length + ' result' + (allCards.length !== 1 ? 's' : '') + ' for "' + headerDisplay + '"</span>' +
					'</div>'
				);
				allCards.forEach(function(c) {
					$container.append(c.html);
				});
				$container.append('<div class="col-md-12 my-3"></div>');
			}

			fitImporterHeight();
			setTimeout(_updateCardTagOverflow, 0);
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
		 * Build the Help link HTML for a library card.
		 * If there is one CHM file, renders a simple link that opens it directly.
		 * If there are multiple CHM files and a default_help_file is set, renders a simple link
		 * that opens the default file directly.
		 * If there are multiple CHM files and NO default_help_file is set, renders a Bootstrap
		 * dropdown so the user can pick which help file to open.
		 */
		function buildCardHelpLinkHtml(chmFiles, libId, defaultHelpFile, isSystem) {
			if (!chmFiles || chmFiles.length === 0) return '<span></span>';
			var helpColor = isSystem ? 'color:var(--medium);' : 'color:#007bff;';
			if (chmFiles.length === 1) {
				return '<a href="#" class="text-sm imp-lib-card-help-link" style="' + helpColor + '" data-lib-id="' + libId + '" title="Help"><i class="fas fa-question-circle"></i></a>';
			}
			// Multiple CHM files with a default - render a direct link targeting the default
			if (defaultHelpFile) {
				return '<a href="#" class="text-sm imp-lib-card-help-link" style="' + helpColor + '" data-lib-id="' + libId + '" data-default-chm="' + escapeHtml(defaultHelpFile) + '" title="Help"><i class="fas fa-question-circle"></i></a>';
			}
			// Multiple CHM files, no default - render a dropdown
			var html = '<div class="dropdown imp-help-dropdown" style="display:inline-block;">';
			html += '<a href="#" class="text-sm dropdown-toggle imp-lib-card-help-link" style="' + helpColor + '" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" data-lib-id="' + libId + '" title="Help"><i class="fas fa-question-circle"></i></a>';
			html += '<div class="dropdown-menu imp-help-dropdown-menu">';
			for (var i = 0; i < chmFiles.length; i++) {
				var fname = chmFiles[i];
				var displayName = path.basename(fname, path.extname(fname)).replace(/[_-]/g, ' ');
				html += '<a class="dropdown-item imp-help-dropdown-item" href="#" data-lib-id="' + libId + '" data-chm-file="' + escapeHtml(fname) + '"><i class="fas fa-book mr-2"></i>' + escapeHtml(displayName) + '</a>';
			}
			html += '</div></div>';
			return html;
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

			var integrity = _integrityCache[lib._id] || (_integrityCache[lib._id] = verifyLibraryIntegrity(lib));
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
					tagsHtml += '<button type="button" class="imp-tag-badge mr-1 mb-1" data-tag="' + t + '"><i class="fas fa-tag mr-1"></i>' + t + '</button>';
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

			// Check for CHM help files
			var helpFiles = lib.help_files || [];
			var chmHelpFiles = helpFiles.filter(function(f) { return path.extname(f).toLowerCase() === '.chm'; });
			var hasChmHelp = chmHelpFiles.length > 0;

			var deps = _depCache[lib._id] || (_depCache[lib._id] = extractRequiredDependencies(lib.library_files || [], lib.lib_install_path || ''));
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

			var oemBadge = buildOemVerifiedBadge(lib.author || '', false, lib.publisher_cert || null);
			var convertedBadge = '';
			if (!oemBadge && lib.converted_from_executable) {
				convertedBadge = buildConvertedBadge(false, lib.source_certificate || null, lib.conversion_source || '');
			}

			var helpLinkHtml = buildCardHelpLinkHtml(chmHelpFiles, lib._id, lib.default_help_file || null, false);

			return '<div class="col-md-4 col-xl-3 d-flex align-items-stretch imp-lib-card-container" data-lib-id="' + lib._id + '">' +
				'<div class="m-2 pl-3 pr-3 pt-3 pb-2 link-card imp-lib-card w-100' + cardExtraClass + '"' + cardTooltipAttr + '>' +
					'<div class="d-flex align-items-start">' +
						'<div class="mr-3 mt-1 imp-lib-card-icon">' + iconHtml + '</div>' +
						'<div class="flex-grow-1" style="min-width:0;">' +
							'<h6 class="mb-0 imp-lib-card-name cursor-pointer" style="color:var(--medium2);">' + libName + comWarningBadge + deletedBadge + '</h6>' +
							(version ? '<span class="text-muted text-sm">v' + version + '</span>' : '') +
							(author ? '<div class="text-muted text-sm">' + author + ' ' + oemBadge + convertedBadge + '</div>' : '') +
						'</div>' +
					'</div>' +
					(shortDesc ? '<p class="text-muted mt-2 mb-1" style="font-size:0.85em;">' + shortDesc + '</p>' : '') +
					'<div class="imp-lib-card-tags mt-1">' + tagsHtml + '<span class="imp-tag-ellipsis" data-lib-id="' + lib._id + '" title="View all tags">&hellip;</span></div>' +
					'<div class="imp-lib-card-footer">' +
						helpLinkHtml +
						'<span class="imp-lib-star" data-lib-id="' + lib._id + '" title="' + (isLibStarred(lib._id) ? 'Unstar' : 'Star') + '"><i class="' + (isLibStarred(lib._id) ? 'fas' : 'far') + ' fa-star"></i></span>' +
					'</div>' +
				'</div>' +
			'</div>';
		}

		//Settings screen menu navigation
		//Settings > Installation checkboxes
		$(document).on("click", "#chk_confirmBeforeInstall", function(){
			saveSetting($(this).attr("id"), $(this).prop("checked"));
		});

		//Settings > Installation: retain embedded installers
		$(document).on("click", "#chk_retainInstallers", function(){
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

		//Settings > Display - Show GitHub repository links
		$(document).on("click", "#chk_showGitHubLinks", function(e){
			// In regulated mode, GitHub links cannot be enabled
			var regulatedMode = false;
			try {
				var s = db_settings.settings.findOne({"_id":"0"});
				regulatedMode = !!(s && s.chk_regulatedEnvironment);
			} catch(ex) { console.warn('Could not read regulated mode setting: ' + ex.message); }
			if (regulatedMode) {
				e.preventDefault();
				$(this).prop("checked", false);
				alert('GitHub links cannot be enabled in regulated environment mode.\n\nExternal links are not permitted when regulated environment mode is active.');
				return;
			}
			saveSetting($(this).attr("id"), $(this).prop("checked"));
		});

		//Settings > Regulated Environment toggle
		$(document).on("click", "#chk_regulatedEnvironment", function(e){
			if (!canToggleRegulatedMode()) {
				e.preventDefault();
				$(this).prop("checked", !$(this).prop("checked")); // revert
				showAccessDeniedModal("Change Regulated Environment Setting",
					"Only users in authorized groups (Administrators, Lab Method Programmer, Lab Service) can enable or disable regulated environment mode.");
				return;
			}
			var checked = $(this).prop("checked");
			// Immediately revert - the modal will apply the change if confirmed
			$(this).prop("checked", !checked);
			e.preventDefault();

			showRegulatedModeConfirmModal(checked).then(function(confirmed) {
				if (!confirmed) return;
				$("#chk_regulatedEnvironment").prop("checked", checked);
				saveSetting("chk_regulatedEnvironment", checked);
				console.log('Regulated environment mode ' + (checked ? 'ENABLED' : 'DISABLED') + ' by ' + getWindowsUsername());

				// Update the regulated env status indicator
				var userIsAdmin = isWindowsAdmin();
				if (userIsAdmin && !isInAnyGroup(ALLOW_GROUPS)) {
					$(".regulated-env-status").html('<i class="fas fa-unlock mr-1"></i>You have access as a Windows Administrator (super whitelist).');
				} else {
					$(".regulated-env-status").html('<i class="fas fa-unlock mr-1"></i>You are authorized to change this setting.');
				}

				// Show/hide green unlock badges based on new regulated state
				if (checked && canToggleRegulatedMode()) {
					$(".settings-admin-badge").show();
				} else {
					$(".settings-admin-badge").hide();
				}

				// When enabling regulated mode, force-disable unsigned libraries
				if (checked) {
					$("#chk_includeUnsignedLibs").prop("checked", false).prop("disabled", true);
					saveSetting("chk_includeUnsignedLibs", false);
					$("#btn-scan-unsigned-libs").prop("disabled", true);
					$(".unsigned-scan-status").text("");
					$(".unsigned-scan-spinner").hide();
					$(".unsigned-scan-done").hide();
					$(".unsigned-regulated-status").html('<i class="fas fa-lock mr-1 text-warning"></i>Unsigned libraries cannot be enabled in regulated environment mode. All packages must be signed.');
					// Force-disable GitHub links
					$("#chk_showGitHubLinks").prop("checked", false).prop("disabled", true);
					saveSetting("chk_showGitHubLinks", false);
					$(".github-links-regulated-status").html('<i class="fas fa-lock mr-1 text-warning"></i>GitHub links cannot be enabled in regulated environment mode.');
					// Hide Report Issue menu item in regulated mode (no external links)
					$(".overflow-report-issue").hide();
					invalidateNavBar();
					console.log('Unsigned libraries and GitHub links disabled: regulated mode requires all packages to be signed.');
				} else {
					$("#chk_includeUnsignedLibs").prop("disabled", false);
					$(".unsigned-regulated-status").html('');
					// Re-enable GitHub links toggle
					$("#chk_showGitHubLinks").prop("disabled", false);
					$(".github-links-regulated-status").html('');
					// Show Report Issue menu item when not in regulated mode
					$(".overflow-report-issue").show();
				}
			}).catch(function(err) {
				console.error('Regulated mode confirmation error:', err);
			});
		});

		//Settings > Unsigned Libraries checkbox
		$(document).on("click", "#chk_includeUnsignedLibs", function(e){
			// In regulated mode, unsigned files cannot be enabled
			var regulatedMode = false;
			try {
				var s = db_settings.settings.findOne({"_id":"0"});
				regulatedMode = !!(s && s.chk_regulatedEnvironment);
			} catch(ex) { console.warn('Could not read regulated mode setting: ' + ex.message); }
			if (regulatedMode) {
				e.preventDefault();
				$(this).prop("checked", false);
				alert('Unsigned libraries cannot be enabled in regulated environment mode.\n\nAll packages must be signed when regulated environment mode is active. Disable regulated environment mode first to enable unsigned library scanning.');
				return;
			}
			var checked = $(this).prop("checked");
			saveSetting("chk_includeUnsignedLibs", checked);
			$("#btn-scan-unsigned-libs").prop("disabled", !checked);
			if (!checked) {
				$(".unsigned-scan-status").text("");
				$(".unsigned-scan-spinner").hide();
				$(".unsigned-scan-done").hide();
			} else {
				var ulibCount = (db_unsigned_libs.unsigned_libs.find() || []).length;
				if (ulibCount > 0) {
					$(".unsigned-scan-status").text(ulibCount + " unsigned librar" + (ulibCount === 1 ? "y" : "ies") + " tracked");
				}
			}
			// Refresh nav bar (show/hide Unsigned group) and cards
			invalidateNavBar();
			var activeGroup2 = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id");
			if (activeGroup2 === 'gAll') {
				impBuildLibraryCards();
			} else if (activeGroup2 === 'gUnsigned' && !checked) {
				// If we were on the Unsigned tab and it's now hidden, switch to All
				$('.navbar-custom .nav-item[data-group-id="gAll"]').addClass("active");
				impBuildLibraryCards();
			}
		});

		//Settings > Unsigned Libraries - Scan Now
		$(document).on("click", "#btn-scan-unsigned-libs", function(){
			scanUnsignedLibraries(true);
		});



		//Settings - Recent dropdown change text
		$(document).on("click", ".dd-maxRecent a", function () {
			var txt = $(this).text();
			$("#dd-maxRecent").text(txt);
			saveSetting("recent-max",txt);
		});

		// Settings > Data Location is now read-only (fixed in local/ directory)
		// Open the local data folder in Windows Explorer on click
		$(document).on("click", ".btn-openLocalDataDir", function() {
			try {
				require('child_process').spawn('explorer', [LOCAL_DATA_DIR], { detached: true, stdio: 'ignore' }).unref();
			} catch(e) {
				console.warn('Could not open local data directory: ' + e.message);
			}
		});

		// ---- Dark Mode / Night Mode ----
		/** Apply or remove dark mode from the document body */
		function applyDarkMode(enabled) {
			if (enabled) {
				$("body").addClass("dark-mode");
			} else {
				$("body").removeClass("dark-mode");
			}
		}

		/** Show or hide the manual dark-mode toolbar toggle based on system-theme setting */
		function applySystemThemeVisibility(useSystem) {
			if (useSystem) {
				$(".btn-dark-mode-toggle").hide();
			} else {
				$(".btn-dark-mode-toggle").show();
			}
		}

		/** Follow the OS dark/light preference */
		function applySystemTheme() {
			if (window.matchMedia) {
				var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
				applyDarkMode(prefersDark);
			}
		}

		// Listen for OS theme changes while the app is running
		if (window.matchMedia) {
			window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function(e) {
				if ($("#chk_useSystemTheme").is(":checked")) {
					applyDarkMode(e.matches);
				}
			});
		}

		// Settings checkbox toggle - use system theme
		$(document).on("change", "#chk_useSystemTheme", function() {
			var useSystem = $(this).is(":checked");
			saveSetting("chk_useSystemTheme", useSystem);
			applySystemThemeVisibility(useSystem);
			if (useSystem) {
				applySystemTheme();
			} else {
				// Restore the persisted manual dark-mode preference
				var settings = db_settings.settings.find()[0] || {};
				var darkEnabled = !!settings["chk_darkMode"];
				applyDarkMode(darkEnabled);
			}
		});

		// Toolbar toggle (moon/sun icon) - only visible when system theme is off
		$(document).on("click", ".btn-dark-mode-toggle", function(e) {
			e.preventDefault();
			var isNowDark = !$("body").hasClass("dark-mode");
			applyDarkMode(isNowDark);
			saveSetting("chk_darkMode", isNowDark);
		});

		$(document).on("click", ".btn-clearRecentList", function () {
			clearRecentList();
			$(".txt-recentCleared").text("Recent list has been cleared!");
			setTimeout(function(){ 
				$(".txt-recentCleared").text("");
			 }, 3000);
		});

		// Settings > Links > favorite icon click (eye toggle: visible / hidden)
		$(document).on("click", ".favorite-icon", function (e) {
			var bool_favorite = false;
			if($(this).hasClass("favorite")){
				//it´s already visible, hide it
				$(this).removeClass("favorite");
				$(this).find("i").removeClass("fa-eye").addClass("fa-eye-slash");
			}else{
				//make visible, select
				bool_favorite = true;
				$(this).addClass("favorite");
				$(this).find("i").removeClass("fa-eye-slash").addClass("fa-eye");
				
			}

			//Update favorite state in database
			var id;
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
				// Check group name validity
				if ($("#editModal .modal-content").attr("data-linkOrGroup") === "group") {
					var groupName = $.trim($('#editModal .txt-linkName').val());
					if (!shared.isValidGroupName(groupName)) {
						var reason = shared.isReservedGroupName(groupName)
							? 'The group name "' + groupName + '" is reserved and cannot be used.'
							: 'Group names can only contain letters, numbers, spaces, dashes, and underscores.';
						alert(reason + ' Please choose a different name.');
						$('#editModal .txt-linkName').css({ "border": "1px solid red", "background": "#FFCECE" });
						e.preventDefault();
						return;
					}
				}
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


		//fitSettingsDivHeight removed - groups and settings are now modals with their own scrolling


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
			return Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
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

					// Skip Export, History, OEM, Starred, and Import from normal nav rendering
					// These nav items are injected separately after the loop
					var skipNavItem = (group_id === "gEditors" || group_id === "gHistory" || group_id === "gOEM" || group_id === "gFolders" || group_id === "gStarred");

					var classCustomGroup = "";
					if(!group_default || group_protected){
						classCustomGroup = " custom-group ";
					}

					//add nav groups to nav bar (skip overflow menu items)
					if(!skipNavItem){
						var navItemStr = '<li class="nav-item' ;
						if(!group_favorite){navItemStr+=' d-none';}
						
						navItemStr +=  classCustomGroup + '" data-group-id="' + group_id + '">' +
										'<div class="navitem-content"><div><i class="far fa-1x ' + group_icon + '"></i></div>' +
										'<div><span class="nav-item-text">' + group_name + '</span></div></div></li>';

						(group_navbar==="left") ?  $(".navbarLeft").append(navItemStr) : $(".navbarRight").append(navItemStr);
					}

					//add nav groups to main div. This groups will be filled with the method cards
					var groupContainerStr = '<div class="row no-gutters d-none group-container w-100 '+ classCustomGroup + '" data-group-id="' + group_id + '"></div>';
					$(".links-container>.row").append(groupContainerStr);



					// add groups to settings > links
					// OEM/protected groups are always visible but without edit/delete
					var displayClass = "";
					if(group_default && !group_protected){displayClass = " d-none";}

					if (group_protected) {
						// Protected group: show in accordion with read-only badge, no edit/delete, no visibility toggle
						var accordionStr = '<div class="card mb-2 settings-links-group protected-group'+displayClass+'" data-group-id="'+ group_id +'">' +
								'<div class="card-header collapsed" role="tab" id="heading_'+group_id +'" data-toggle="collapse" href="#collapse_'+ group_id+'" aria-expanded="true" aria-controls="collapse_'+ group_id+'">' +
										'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
										'<span class="color-medium2"><i class="fas '+ group_icon +' fa-md ml-2 mr-2"></i><span class="group-name">'+ group_name +' </span></span>'+
										'<span class="badge badge-warning ml-2" style="font-size:0.7rem;">Protected</span>';
								accordionStr+='</div>'+  
								'<div id="collapse_'+ group_id+'" class="collapse" role="tabpanel" aria-labelledby="heading_'+group_id +'">'+
									'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">'+
									'</div>'+
								'</div>'+
							'</div>';
					} else {
						accordionStr = '<div class="card mb-2 settings-links-group cursor-pointer'+displayClass+'" data-group-id="'+ group_id +'">' +
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
											accordionStr+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon favorite tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="fas fa-eye fa-md"></i>'+
											'</span>';
										}else{
											accordionStr+='<span class="cursor-pointer color-medium float-right pl-2 pr-2 favorite-icon tooltip-delay1000" data-toggle="tooltip" title="Show/hide in home screen"">'+
												'<i class="far fa-eye-slash fa-md"></i>'+
											'</span>';
										}
								accordionStr+='</div>'+  
								'<div id="collapse_'+ group_id+'" class="collapse" role="tabpanel" aria-labelledby="heading_'+group_id +'">'+
									'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">'+

									'</div>'+
								'</div>'+
							'</div>';
					} // end if group_protected else
					$(".settings-links #accordion").append(accordionStr);


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

							var libSettingsOemBadge = buildOemVerifiedBadge(lib.author || '', false, lib.publisher_cert || null);
							var libSettingsConvertedBadge = '';
							if (!libSettingsOemBadge && lib.converted_from_executable) {
								libSettingsConvertedBadge = buildConvertedBadge(false, lib.source_certificate || null, lib.conversion_source || '');
							}

							var libItemStr = '<div class="settings-links-method w-100 pt-2" data-id="'+lib._id+'">' +
								libIcon +
								'<div class="d-inline-block pb-2 link-namepath">' +
									'<div class="name">' + libName + libVersion + '</div>' +
									'<div class="path">' + (libAuthor ? libAuthor + ' ' + libSettingsOemBadge + libSettingsConvertedBadge : '') + '</div>' +
								'</div>' +
							'</div>';
							$("#collapse_"+ group_id + " .card-body").append(libItemStr);
						}
					}

				} //end if navgroup
			} //end for groups

			// ---- Inject the static "Starred" group nav item (after All) ----
			{
				var starNavStr = '<li class="nav-item starred-group-nav" data-group-id="gStarred">' +
					'<div class="navitem-content"><div><i class="fas fa-1x fa-star"></i></div>' +
					'<div><span class="nav-item-text">Starred</span></div></div></li>';
				var $allNav = $(".navbarLeft .nav-item[data-group-id='gAll']");
				if ($allNav.length) {
					$allNav.after(starNavStr);
				} else {
					$(".navbarLeft").prepend(starNavStr);
				}
			}

			// ---- Inject the static "Unsigned" group nav item (only if setting enabled) ----
			var _unsignedEnabled = !!getSettingValue('chk_includeUnsignedLibs');
			var _unsignedLibs = _unsignedEnabled ? (db_unsigned_libs.unsigned_libs.find() || []) : [];
			if (_unsignedEnabled && _unsignedLibs.length > 0) {
				var unsNavStr = '<li class="nav-item unsigned-group-nav" data-group-id="gUnsigned">' +
					'<div class="navitem-content"><div><i class="far fa-1x fa-times-circle"></i></div>' +
					'<div><span class="nav-item-text">Unsigned</span></div></div></li>';
				$(".navbarLeft").append(unsNavStr);

				// Add Unsigned group to Settings accordion (read-only, no edit/delete/drag)
				var unsAccStr = '<div class="card mb-2 settings-links-group unsigned-group-settings protected-group" data-group-id="gUnsigned">' +
					'<div class="card-header collapsed" role="tab" id="heading_gUnsigned" data-toggle="collapse" href="#collapse_gUnsigned" aria-expanded="false" aria-controls="collapse_gUnsigned">' +
						'<span class="far fa-chevron-right mr-2 caret-right color-medium"></span>' +
						'<span class="color-medium2"><i class="far fa-times-circle fa-md ml-2 mr-2"></i><span class="group-name">Unsigned </span></span>' +
						'<span class="badge badge-secondary ml-2" style="font-size:0.7rem;">Auto-Detected</span>' +
					'</div>' +
					'<div id="collapse_gUnsigned" class="collapse" role="tabpanel" aria-labelledby="heading_gUnsigned">' +
						'<div class="card-body ml-5 mr-5 pl-4 pr-4 pt-2 pb-2">' +
						'</div>' +
					'</div>' +
				'</div>';
				$(".settings-links #accordion").append(unsAccStr);

				// Add unsigned library items into the Unsigned accordion
				_unsignedLibs.forEach(function(uLib) {
					var uLibName = escapeHtml(uLib.library_name || 'Unknown');
					var uLibVersion = uLib.version ? ' v' + escapeHtml(uLib.version) : '';
					var uLibIcon = '<i class="far fa-times-circle fa-lg ml-2 mr-2 mb-2 align-top pt-2" style="color:#adb5bd"></i>';
					var uItemStr = '<div class="settings-links-method w-100 pt-2 unsigned-lib-item" data-id="' + uLib._id + '">' +
						uLibIcon +
						'<div class="d-inline-block pb-2 link-namepath">' +
							'<div class="name" style="color:#6c757d;">' + uLibName + uLibVersion + ' <span class="badge badge-light" style="font-size:0.65rem;">Unsigned</span></div>' +
							'<div class="path" style="color:#adb5bd;">' + escapeHtml(uLib.author || 'Unknown author') + '</div>' +
						'</div>' +
					'</div>';
					$("#collapse_gUnsigned .card-body").append(uItemStr);
				});
			}

			// ---- Inject the static "System" group nav item ----
			if (systemLibraries.length > 0) {
				var sysNavStr = '<li class="nav-item system-group-nav" data-group-id="gSystem">' +
					'<div class="navitem-content"><div><i class="far fa-1x fa-lock"></i></div>' +
					'<div><span class="nav-item-text">System</span></div></div></li>';
				$(".navbarLeft").append(sysNavStr);

				// Add System group to Settings accordion (read-only, no edit/delete)
				var sysAccStr = '<div class="card mb-2 settings-links-group system-group-settings protected-group" data-group-id="gSystem">' +
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
							'<div class="name" style="color:#6c757d;">' + escapeHtml(sLibName) + ' <span class="badge badge-light" style="font-size:0.65rem;">System</span></div>' +
							'<div class="path" style="color:#adb5bd;">Hamilton</div>' +
						'</div>' +
					'</div>';
					$("#collapse_gSystem .card-body").append(sItemStr);
				}
			}

			// ---- Inject the OEM group nav item (after System) ----
			{
				var oemGrp = getGroupById("gOEM");
				if (oemGrp) {
					var oemFav = oemGrp["favorite"];
					var oemIcon = oemGrp["icon-class"] || "fa-check-circle";
					var oemNavStr = '<li class="nav-item custom-group' + (oemFav ? '' : ' d-none') + '" data-group-id="gOEM">' +
						'<div class="navitem-content"><div><i class="fas fa-1x ' + oemIcon + '"></i></div>' +
						'<div><span class="nav-item-text">' + oemGrp["name"] + '</span></div></div></li>';
					$(".navbarLeft").append(oemNavStr);
				}
			}

			// ---- HARDCODED NAV ORDER ENFORCEMENT ----
			// All is ALWAYS the leftmost nav item (it is the home screen).
			// System groups come next, then user-defined groups at the end.
			// Order: All | Starred | Recent | System | OEM | Unsigned | [user groups]
			// ** AI NOTE: gAll must NEVER be moved from the leftmost position **
			var _sysNavIds = { gAll:1, gRecent:1, gStarred:1, gSystem:1, gOEM:1, gUnsigned:1 };
			// Move all user-defined groups to the end of navbarLeft
			$(".navbarLeft .nav-item").each(function() {
				var gid = $(this).attr('data-group-id');
				if (gid && !_sysNavIds[gid]) {
					$(this).appendTo($(this).parent());
				}
			});
			// Enforce exact system group order in navbar:
			// All | Starred | Recent | System | OEM | Unsigned | [user groups]
			var _navOrder = ['gAll', 'gStarred', 'gRecent', 'gSystem', 'gOEM', 'gUnsigned'];
			var $navbarLeft = $(".navbarLeft");
			for (var _ni = _navOrder.length - 1; _ni >= 0; _ni--) {
				var $navEntry = $navbarLeft.find('.nav-item[data-group-id="' + _navOrder[_ni] + '"]');
				if ($navEntry.length) {
					$navEntry.prependTo($navbarLeft);
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

			// ---- ACCORDION ORDER ENFORCEMENT ----
			// Must be a 1:1 match with the nav bar order for system/auto-generated groups.
			// Nav order:  All | Starred | Recent | System | OEM | Unsigned | [user groups]
			// Accordion visible order: Starred | System | OEM | Unsigned | [user groups] | Unassigned
			// (All, Recent, Folders, Editors, History are hidden via d-none)
			{
				var $accordion = $(".settings-links #accordion");
				var _sysAccIds = { gAll:1, gRecent:1, gStarred:1, gFolders:1, gEditors:1, gHistory:1, gUnsigned:1, gSystem:1, gOEM:1 };

				// 1) Remove duplicate accordion entries (keep the first occurrence of each group-id)
				var _seenAccIds = {};
				$accordion.find('.settings-links-group').each(function() {
					var gid = $(this).attr('data-group-id');
					if (gid) {
						if (_seenAccIds[gid]) {
							$(this).remove(); // duplicate - remove it
						} else {
							_seenAccIds[gid] = true;
						}
					}
				});

				// 2) Enforce exact order: system groups in fixed order, then user groups, then Unassigned
				//    This matches the nav bar order exactly.
				var _accOrder = ['gStarred', 'gSystem', 'gOEM', 'gUnsigned'];
				// Detach system groups and re-prepend them in the correct order
				for (var _oi = _accOrder.length - 1; _oi >= 0; _oi--) {
					var $sysEntry = $accordion.find('.settings-links-group[data-group-id="' + _accOrder[_oi] + '"]');
					if ($sysEntry.length) {
						$sysEntry.prependTo($accordion);
					}
				}
				// Move all user-defined groups to just before Unassigned
				var $unassigned = $accordion.find('.settings-links-group[data-group-id="unassigned"]');
				$accordion.find('.settings-links-group').each(function() {
					var gid = $(this).attr('data-group-id');
					if (gid && !_sysAccIds[gid] && gid !== 'unassigned') {
						$(this).insertBefore($unassigned);
					}
				});
				// Ensure Unassigned is always last
				$unassigned.appendTo($accordion);
			}

			// add bottom divs for the groups container, after the group divs. This creates the needed margin to properly stretch the cards
			var spacerStr = '<div class="col-md-12 my-3"></div>';
			$(".links-container>.row").append(spacerStr);


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
				items: '> .settings-links-group:not([data-group-id="unassigned"]):not([data-group-id="gSystem"]):not([data-group-id="gUnsigned"]):not(.protected-group)',
				update: function(evet, ui){
					//recreate the tree.json
					saveTree();
				}
			});
			$( ".settings-links-group:not([data-group-id='gSystem']):not([data-group-id='gUnsigned']) .card-body" ).sortable({
				connectWith: ".settings-links-group:not([data-group-id='gSystem']):not([data-group-id='gUnsigned']) .card-body",
				items: '> .settings-links-method:not(.system-lib-item):not(.unsigned-lib-item)',
				update: function(event, ui ) {
					if (this === ui.item.parent()[0]) { // this avoids the update to be triggerd twice when moving between groups
						//recreate the tree.json
						saveTree();
					}
					
						
				}
			});
		}

		function saveTree(){
			try {
			// Build new tree array first, then write atomically to avoid
			// data loss if a crash occurs between remove() and save().
			var tree =[];
			var groups = $(".settings-links-group");
			for (var i = 0; i < groups.length; ++i) {
				var group_id = $(groups[i]).attr('data-group-id');
				if(group_id === "unassigned") continue; // skip the unassigned pseudo-group
				if(group_id === "gSystem") continue; // skip the system group (hardcoded, not persisted)
				if(group_id === "gUnsigned") continue; // skip the unsigned group (auto-detected, not persisted)
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

			// Preserve locked entries from the existing tree
			var existingTree = db_tree.tree.find();
			var lockedEntries = existingTree.filter(function(entry) { return entry.locked; });

			// Write the combined data atomically via temp file
			var treePath = path.join(USER_DATA_DIR, 'tree.json');
			var combined = lockedEntries.concat(tree);
			var tmpPath = treePath + '.tmp';
			fs.writeFileSync(tmpPath, JSON.stringify(combined), 'utf8');
			fs.renameSync(tmpPath, treePath);

			// Reconnect diskdb so it picks up the new data
			db_tree = db.connect(USER_DATA_DIR, ['tree']);
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
			var version = method["version"] || "-";
			var buildNumber = method["build-number"] || "-";
			var customFields = method["custom-fields"] || {};

			// Set icon or image
			var $icon = $("#detailModal .detail-modal-icon");
			$icon.empty();
			if(icon_customImage && icon_customImage !== "" && icon_customImage !== "placeholder"){
				var imgExists = false;
				try { imgExists = fs.existsSync(icon_customImage); } catch(e){ console.warn('Icon existence check failed: ' + e.message); }
				if(!imgExists && method["default"]){
					try { imgExists = fs.existsSync("html/img/" + icon_customImage); } catch(e){ console.warn('Fallback icon check failed: ' + e.message); }
					if(imgExists) icon_customImage = "img/" + icon_customImage;
				}
				if(imgExists){
					$icon.html('<img src="' + escapeHtml(icon_customImage) + '">');
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
			// Prevent deletion of the protected OEM group
			var grp = getGroupById(id);
			if (grp && grp["protected"]) {
				alert('The "' + grp.name + '" group is protected and cannot be deleted.');
				return;
			}
			confirmDeleteModal(id, "group");
		}

		function confirmDeleteModal(id, linkOrGroup){
			var $modal = $('#deleteModal');
			var str = "";
			if(linkOrGroup == "link"){
				str = $(".settings-links-method[data-id='" +id+"'] .name").text().trim();
			}
			if(linkOrGroup == "group"){
				str = $(".settings-links-group[data-group-id='" +id+"'] .group-name").text().trim();
			}

			// Populate the modal
			$modal.find(".delete-linkorgroup").text(linkOrGroup);
			$modal.find(".delete-item-name-header").text(str);
			$modal.find(".delete-item-expected-text").text(str);
			$modal.find(".delete-item-input").val("");
			$modal.find(".btn-delete").prop("disabled", true);
			$modal.find(".delete-item-consequences").text(
				'This will permanently remove the ' + linkOrGroup + ' "' + str + '"' +
				(linkOrGroup === 'group' ? '. Libraries in this group will become unassigned.' : '.')
			);

			// Enable/disable confirm button based on typed input
			$modal.find(".delete-item-input").off("input.deleteItem").on("input.deleteItem", function() {
				var typed = $(this).val().trim();
				$modal.find(".btn-delete").prop("disabled", typed !== str);
			});

			// Confirm button handler
			$modal.find(".btn-delete").off("click.deleteItem").on("click.deleteItem", function() {
				$modal.modal("hide");
				deleteData(id, linkOrGroup);
			});

			$modal.modal("show");
		}     


		function deleteData(id , linkOrGroup){
				var el;
				if(linkOrGroup == "link"){
					el = $(".settings-links-method[data-id='" +id+"']");
				}
				if(linkOrGroup == "group"){
					el = $(".settings-links-group[data-group-id='" +id+"']");
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
					for (var i = 1; i < 4; i++) {
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
				console.warn('Settings record not found - initializing defaults.');
				var defaults = {
					"_id": "0",
					"recent-max": 20,
					"chk_confirmBeforeInstall": true,
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

			//setting - Installation: retain embedded installers on import
			$("#chk_retainInstallers").prop("checked", !!settings["chk_retainInstallers"]);

			//setting - Display: hide system libraries
			$("#chk_hideSystemLibraries").prop("checked", !!settings["chk_hideSystemLibraries"]);

			//setting - Regulated environment mode (must be resolved before GitHub links & unsigned settings)
			var regulatedMode = !!settings["chk_regulatedEnvironment"];

			//setting - Display: show GitHub repository links (default on)
			// In regulated mode, GitHub links are always disabled
			if (regulatedMode) {
				$("#chk_showGitHubLinks").prop("checked", false).prop("disabled", true);
				saveSetting("chk_showGitHubLinks", false);
				$(".github-links-regulated-status").html('<i class="fas fa-lock mr-1 text-warning"></i>GitHub links cannot be enabled in regulated environment mode.');
				// Hide Report Issue menu item in regulated mode (no external links)
				$(".overflow-report-issue").hide();
			} else {
				$("#chk_showGitHubLinks").prop("checked", settings["chk_showGitHubLinks"] !== false).prop("disabled", false);
				$(".github-links-regulated-status").html('');
				// Show Report Issue menu item when not in regulated mode
				$(".overflow-report-issue").show();
			}

			//setting - Unsigned libraries
			var unsignedEnabled = !!settings["chk_includeUnsignedLibs"];
			// In regulated mode, unsigned files cannot be enabled - all packages must be signed
			if (regulatedMode && unsignedEnabled) {
				unsignedEnabled = false;
				saveSetting("chk_includeUnsignedLibs", false);
				console.log('Unsigned libraries disabled automatically: regulated environment mode requires all packages to be signed.');
			}
			$("#chk_includeUnsignedLibs").prop("checked", unsignedEnabled);
			$("#btn-scan-unsigned-libs").prop("disabled", !unsignedEnabled);
			// In regulated mode, disable the unsigned toggle entirely
			if (regulatedMode) {
				$("#chk_includeUnsignedLibs").prop("disabled", true);
				$(".unsigned-regulated-status").html('<i class="fas fa-lock mr-1 text-warning"></i>Unsigned libraries cannot be enabled in regulated environment mode. All packages must be signed.');
			} else {
				$("#chk_includeUnsignedLibs").prop("disabled", false);
				$(".unsigned-regulated-status").html('');
			}
			if (unsignedEnabled) {
				var ulibCount = (db_unsigned_libs.unsigned_libs.find() || []).length;
				if (ulibCount > 0) {
					$(".unsigned-scan-status").text(ulibCount + " unsigned librar" + (ulibCount === 1 ? "y" : "ies") + " tracked");
				}

			}

			//setting - Regulated Environment
			var regulatedEnabled = regulatedMode;
			$("#chk_regulatedEnvironment").prop("checked", regulatedEnabled);
			// Only authorized group members or administrators can toggle this setting
			var canToggle = canToggleRegulatedMode();
			var userIsAdmin = isWindowsAdmin();
			$("#chk_regulatedEnvironment").prop("disabled", !canToggle);
			if (!canToggle) {
				$(".regulated-env-status").html('<i class="fas fa-lock mr-1"></i>Only authorized users (Administrators, Lab Method Programmer, Lab Service) can change this setting.');
			} else if (userIsAdmin && !isInAnyGroup(ALLOW_GROUPS)) {
				$(".regulated-env-status").html('<i class="fas fa-unlock mr-1"></i>You have access as a Windows Administrator (super whitelist).');
			} else {
				$(".regulated-env-status").html('<i class="fas fa-unlock mr-1"></i>You are authorized to change this setting.');
			}

			// Show unlock icons on settings sections only in regulated mode for whitelisted users
			if (regulatedEnabled && canToggle) {
				$(".settings-admin-badge").show();
			} else {
				$(".settings-admin-badge").hide();
			}

			//setting - Data Location (read-only, always local/)
			$(".txt-localDataPath").val(LOCAL_DATA_DIR);

			//setting - Use System Theme (default: true for out-of-box behaviour)
			var useSystem = settings["chk_useSystemTheme"] !== false;
			$("#chk_useSystemTheme").prop("checked", useSystem);
			applySystemThemeVisibility(useSystem);

			//setting - Dark Mode / Night Mode (persisted between sessions)
			if (useSystem) {
				applySystemTheme();
			} else {
				var darkEnabled = !!settings["chk_darkMode"];
				applyDarkMode(darkEnabled);
			}

			//reset nav bar and hide overflowing nav bar items
			fitNavBarItems();
			fitMainDivHeight();
			updateSortableDivs();

			// Load code signing configuration
			refreshSettingsSigningStatus();
			refreshSigningUI();

			// OEM/developer settings visibility - always start hidden (session-only)
			applyOemSettingsVisibility(false);
			$("#chk_oemKeywordsEnabled").prop("checked", false);
			$(".oem-keywords-status").html('');


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

		/** Check if OEM keywords bypass is enabled in settings */
		function isOemKeywordsEnabled() {
			return _oemSessionKeywordsEnabled && _oemSessionUnlocked;
		}

		// ---- OEM Keywords toggle handler: require password to enable ----
		$(document).on("click", "#chk_oemKeywordsEnabled", async function () {
			var isChecked = $(this).is(":checked");
			if (isChecked) {
				// Require OEM password to enable
				var pwOk = await promptAuthorPassword();
				if (pwOk) {
					_oemSessionKeywordsEnabled = true;
					$(".oem-keywords-status").html('<i class="fas fa-check-circle text-success mr-1"></i>OEM keywords authorized. Password prompt is bypassed.');
				} else {
					$(this).prop("checked", false);
					$(".oem-keywords-status").html('<i class="fas fa-times-circle text-danger mr-1"></i>Authorization failed.');
					setTimeout(function() { $(".oem-keywords-status").html(''); }, 3000);
				}
			} else {
				_oemSessionKeywordsEnabled = false;
				$(".oem-keywords-status").html('');
			}
		});

		/** Read a single setting value from the settings DB */
		function getSettingValue(key) {
			var settings = db_settings.settings.find()[0];
			return settings ? settings[key] : undefined;
		}

		// ---- Starred libraries persistence ----
		function getStarredLibIds() {
			return getSettingValue('starred_libs') || [];
		}

		function isLibStarred(libId) {
			return getStarredLibIds().indexOf(libId) !== -1;
		}

		function toggleStarLib(libId) {
			var starred = getStarredLibIds();
			var idx = starred.indexOf(libId);
			if (idx === -1) {
				starred.push(libId);
			} else {
				starred.splice(idx, 1);
			}
			saveSetting('starred_libs', starred);
			return idx === -1; // returns true if now starred
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
			for(var i=0; i< arrlaststarted.length ; i++){
				var query ={"_id": arrlaststarted[i]["_id"]};
				var updated = db_links.links.update(query, dataToSave, options);
			}
							
			// empty the Recent group
			$(".group-container[data-group-id='gRecent']").empty();

		}

		function historyCleanup(){
			var settings = db_settings.settings.find()[0]; //get all settings data from settings.json
			var archiveDir = settings["history-archive-folder"];
			if(!archiveDir){archiveDir=os.tmpdir();} //if no dir is given use the default OS temp folder.
			$(".txt-history-archiveDir").val(archiveDir);
			//Set working dir for the method file browse
			$("#input-history-archiveDir").attr("nwworkingdir",archiveDir);
			if(settings["chk_settingHistoryCleanup"]==true){
				var days = parseInt(settings["history-days"], 10);
				if (isNaN(days) || days <= 0) { return; }
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
					console.warn('Could not read log directory: ' + HxFolder_LogFiles + ' - ' + err.message);
					return;
				}
				$(".cleanup-progress-bar").text("0%").css("width","0%").attr("aria-valuenow", 0);
				$(".cleanup-progress-text").text("Cleaning up run logs");
				$(".cleanup-progress").css("display","inline"); //force display after JQuery fadeout if a previous cleanup was run
					// console.log(files.length);

					files.forEach(function(file, index) {
							var currentPath = path.join(HxFolder_LogFiles,file);
							var bool_processFile = false;
							fs.stat(currentPath, function(err, stats) {
										if (err) {
												console.warn('Error getting stat from file: ' + currentPath + ' - ' + (err.code || err.message));
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
			// VENUS paths are hardcoded - no DLL/registry lookup needed
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

			// First-run: stamp system libraries with VENUS install metadata
			try {
				ensureSystemLibraryMetadata();
			} catch(e) {
				console.warn('Error during system library metadata stamping: ' + e.message);
			}

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
		var pkg_labwareFiles = [];         // labware definition files (absolute paths)
		var pkg_labwareSubdirs = {};       // absolutePath -> subdirectory within Labware root
		var pkg_binFiles = [];             // bin files (absolute paths) for Hamilton\Bin
		var pkg_binSubdirs = {};           // absolutePath -> subdirectory within Bin root
		var pkg_fileRelPaths = {};    // absolutePath -> relative path within package (preserves subfolder structure)
		var pkg_fileCustomDirs = {};  // absolutePath -> custom install subdir ("" = root, string = subdir, undefined = default)
		var pkg_installSubdir = null;  // global install subdir: null = default (library name), '' = root, string = custom subdir
		var pkg_libEmptyFolders = [];      // empty folders for library tree
		var pkg_demoEmptyFolders = [];     // empty folders for demo tree
		var pkg_iconFilePath = null;   // custom icon/image path chosen by user
		var pkg_iconAutoDetected = false;     // true if current preview is from auto-detected BMP
		var pkg_iconAutoDetectedPath = null;  // file path of the auto-detected BMP
		var pkg_iconDismissedAuto = false;    // true if user explicitly dismissed the auto-detected image
		var pkg_comRegisterDlls = [];  // DLL filenames selected for COM registration via RegAsm
		var pkg_installerFilePath = null;  // optional .exe installer to embed in the package
		var pkg_defaultHelpFile = null;  // basename of CHM file selected as default help for multi-CHM libraries
		var _pkgLastClickedRow = {};  // per-tree last clicked .ft-file-row element for shift-select

		/**
		 * Recursively collects all files under a directory.
		 * Returns an array of { absolutePath, relativePath } objects where
		 * relativePath is relative to baseDir (the folder the user selected).
		 */
		function getFilesRecursive(dir, baseDir) {
			var results = [];
			var items;
			try { items = fs.readdirSync(dir); } catch(e) { return results; }
			items.forEach(function(item) {
				var fullPath = path.join(dir, item);
				try {
					var stat = fs.statSync(fullPath);
					if (stat.isFile()) {
						results.push({
							absolutePath: fullPath,
							relativePath: path.relative(baseDir, fullPath)
						});
					} else if (stat.isDirectory()) {
						results = results.concat(getFilesRecursive(fullPath, baseDir));
					}
				} catch(e) {}
			});
			return results;
		}

		/**
		 * Computes the ZIP directory path for a file, preserving any subfolder
		 * structure in the relative path. E.g. zipSubdir('library', 'sub/file.hsl')
		 * returns 'library/sub'.  For flat files, returns baseZipDir unchanged.
		 */
		function zipSubdir(baseZipDir, relPath) {
			var relDir = path.dirname(relPath).replace(/\\/g, '/');
			return relDir && relDir !== '.' ? baseZipDir + '/' + relDir : baseZipDir;
		}

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

		// ---- Labware file input button triggers ----
		$(document).on("click", "#pkg-addLabwareFiles", function() {
			$("#pkg-input-labwarefiles").trigger("click");
		});
		$(document).on("click", "#pkg-addLabwareFolder", function() {
			$("#pkg-input-labwarefolder").trigger("click");
		});

		// ---- Bin file input button triggers ----
		$(document).on("click", "#pkg-addBinFiles", function() {
			$("#pkg-input-binfiles").trigger("click");
		});
		$(document).on("click", "#pkg-addBinFolder", function() {
			$("#pkg-input-binfolder").trigger("click");
		});

		// ---- Installer executable file picker ----
		$(document).on("click", "#pkg-pickInstallerExe", function() {
			$("#pkg-input-installer").trigger("click");
		});
		$(document).on("change", "#pkg-input-installer", function() {
			var fileInput = this;
			if (!fileInput.files || fileInput.files.length === 0) return;
			var filePath = fileInput.files[0].path;
			$(this).val('');
			if (!filePath) return;
			if (!fs.existsSync(filePath) || path.extname(filePath).toLowerCase() !== '.exe') {
				alert('Please select a valid .exe file.');
				return;
			}
			pkg_installerFilePath = filePath;
			$(".pkg-installer-filename").text(path.basename(filePath));
			$(".pkg-installer-detail").show();
			$(".pkg-installer-empty-msg").hide();
		});
		$(document).on("click", "#pkg-removeInstaller", function() {
			pkg_installerFilePath = null;
			$(".pkg-installer-filename").text('');
			$(".pkg-installer-detail").hide();
			$(".pkg-installer-empty-msg").show();
			$("#pkg-installer-description").val('');
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
				// User dismissed the auto-detected image - suppress re-detection until files change
				pkg_iconDismissedAuto = true;
			} else {
				// User removed a manually-chosen image - allow auto-detect to run again
				pkgAutoDetectBmpImage();
			}
		});

		// ---- File-type mismatch warning helper ----
		/**
		 * Show a warning modal when the user adds an unexpected file type.
		 * @param {string} message  - HTML-safe warning text to display.
		 * @param {Function} onYes  - Called when the user confirms they want to keep the files.
		 * @param {Function} onNo   - Called when the user declines (files should be removed).
		 */
		function pkgShowFileTypeWarning(message, onYes, onNo) {
			var $modal = $("#pkgFileTypeWarningModal");
			var $content = $modal.find('.pkg-filetype-warn-content');
			$content.removeClass('pkg-filetype-warn-error');
			$modal.find('.pkg-filetype-warn-title').text('Hold on a moment!');
			$modal.find('.pkg-filetype-warn-yes').show().text("Yes, I'm sure");
			$modal.find('.pkg-filetype-warn-no').removeClass('btn-danger').addClass('btn-primary').text('No, remove them');
			$modal.find(".pkg-filetype-warn-message").html(message);
			// Wire buttons (one-time handlers)
			$modal.find(".pkg-filetype-warn-yes").off("click").on("click", function() {
				$modal.modal("hide");
				if (onYes) onYes();
			});
			$modal.find(".pkg-filetype-warn-no").off("click").on("click", function() {
				$modal.modal("hide");
				if (onNo) onNo();
			});
			// Also treat backdrop dismiss / Esc as "No"
			$modal.off("hidden.bs.modal.ftw").on("hidden.bs.modal.ftw", function() {
				// Only fire onNo if neither button was clicked (modal was just dismissed)
				$modal.off("hidden.bs.modal.ftw");
			});
			$modal.modal("show");
		}

		function showTagValidationErrorModal(message) {
			var $modal = $("#pkgFileTypeWarningModal");
			var $content = $modal.find('.pkg-filetype-warn-content');
			$content.addClass('pkg-filetype-warn-error');
			$modal.find('.pkg-filetype-warn-title').text('Tag Validation Error');
			$modal.find('.pkg-filetype-warn-message').html($('<span>').text(message || 'Tag cannot be added.').html().replace(/\n/g, '<br>'));

			$modal.find('.pkg-filetype-warn-yes').off('click').hide();
			$modal.find('.pkg-filetype-warn-no')
				.off('click')
				.removeClass('btn-primary')
				.addClass('btn-danger')
				.text('OK')
				.on('click', function() {
					$modal.modal('hide');
				});

			$modal.off('hidden.bs.modal.ftw').on('hidden.bs.modal.ftw', function() {
				$modal.off('hidden.bs.modal.ftw');
			});

			$modal.modal('show');
		}

		// ---- Library file inputs ----
		$(document).on("change", "#pkg-input-libfiles", function() {
			var fileInput = this;
			var newDlls = [];
			var medFiles = [];
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && pkg_libraryFiles.indexOf(filePath) === -1) {
					pkg_libraryFiles.push(filePath);
					var baseName = path.basename(filePath);
					if (baseName.toLowerCase().endsWith('.dll')) {
						newDlls.push(baseName);
					}
					if (baseName.toLowerCase().endsWith('.med')) {
						medFiles.push(filePath);
					}
				}
			}
			// Auto-check for COM registration if exactly one DLL was added in this batch
			if (newDlls.length === 1 && pkg_comRegisterDlls.indexOf(newDlls[0]) === -1) {
				pkg_comRegisterDlls.push(newDlls[0]);
			}
			pkgUpdateLibFileList();
			$(this).val('');

			// Warn if .med (method) files were added to the Library Files section
			if (medFiles.length > 0) {
				var fileNames = medFiles.map(function(f) { return '<b>' + escapeHtml(path.basename(f)) + '</b>'; }).join(', ');
				pkgShowFileTypeWarning(
					'Whoa there! This section is for <b>library files</b> only. You\'ve added ' +
					(medFiles.length === 1 ? 'a method file' : medFiles.length + ' method files') +
					' (' + fileNames + ') that ' + (medFiles.length === 1 ? 'looks' : 'look') +
					' like ' + (medFiles.length === 1 ? 'it belongs' : 'they belong') +
					' in the <b>Demo Method Files</b> section instead.<br><br>Are you absolutely sure you want to add ' +
					(medFiles.length === 1 ? 'this method' : 'these methods') + ' here?',
					null, // onYes - keep the files
					function() {
						// onNo - remove the .med files from library files
						pkg_libraryFiles = pkg_libraryFiles.filter(function(f) {
							return medFiles.indexOf(f) === -1;
						});
						pkgUpdateLibFileList();
					}
				);
			}
		});

		$(document).on("change", "#pkg-input-libfolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var allFiles = getFilesRecursive(folderPath, path.dirname(folderPath));
					var newDlls = [];
					var medFiles = [];
					allFiles.forEach(function(fileInfo) {
						var filePath = fileInfo.absolutePath;
						var file = path.basename(filePath);
						if (pkg_libraryFiles.indexOf(filePath) === -1) {
							pkg_libraryFiles.push(filePath);
							pkg_fileRelPaths[filePath] = fileInfo.relativePath;
							if (file.toLowerCase().endsWith('.dll')) {
								newDlls.push(file);
							}
							if (file.toLowerCase().endsWith('.med')) {
								medFiles.push(filePath);
							}
						}
					});
					// Auto-check for COM registration if exactly one DLL was added in this batch
					if (newDlls.length === 1 && pkg_comRegisterDlls.indexOf(newDlls[0]) === -1) {
						pkg_comRegisterDlls.push(newDlls[0]);
					}
					pkgUpdateLibFileList();

					// Warn if .med (method) files were found in the folder
					if (medFiles.length > 0) {
						var fileNames = medFiles.map(function(f) { return '<b>' + escapeHtml(path.basename(f)) + '</b>'; }).join(', ');
						pkgShowFileTypeWarning(
							'Whoa there! This section is for <b>library files</b> only. You\'ve added ' +
							(medFiles.length === 1 ? 'a method file' : medFiles.length + ' method files') +
							' (' + fileNames + ') that ' + (medFiles.length === 1 ? 'looks' : 'look') +
							' like ' + (medFiles.length === 1 ? 'it belongs' : 'they belong') +
							' in the <b>Demo Method Files</b> section instead.<br><br>Are you absolutely sure you want to add ' +
							(medFiles.length === 1 ? 'this method' : 'these methods') + ' here?',
							null, // onYes - keep the files
							function() {
								// onNo - remove the .med files from library files
								pkg_libraryFiles = pkg_libraryFiles.filter(function(f) {
									return medFiles.indexOf(f) === -1;
								});
								pkgUpdateLibFileList();
							}
						);
					}
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Demo method file inputs ----
		$(document).on("change", "#pkg-input-demofiles", function() {
			var fileInput = this;
			var dllFiles = [];
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && pkg_demoMethodFiles.indexOf(filePath) === -1) {
					pkg_demoMethodFiles.push(filePath);
					if (path.basename(filePath).toLowerCase().endsWith('.dll')) {
						dllFiles.push(filePath);
					}
				}
			}
			pkgUpdateDemoFileList();
			$(this).val('');

			// Warn if .dll files were added to the Demo Method Files section
			if (dllFiles.length > 0) {
				var fileNames = dllFiles.map(function(f) { return '<b>' + escapeHtml(path.basename(f)) + '</b>'; }).join(', ');
				pkgShowFileTypeWarning(
					'Whoa there! This section is for <b>demo methods</b> only. You\'ve added ' +
					(dllFiles.length === 1 ? 'a DLL file' : dllFiles.length + ' DLL files') +
					' (' + fileNames + ') that ' + (dllFiles.length === 1 ? 'looks' : 'look') +
					' like ' + (dllFiles.length === 1 ? 'it belongs' : 'they belong') +
					' in the <b>Library Files</b> section instead.<br><br>Are you absolutely sure you want to add ' +
					(dllFiles.length === 1 ? 'this DLL' : 'these DLLs') + ' here?',
					null, // onYes - keep the files
					function() {
						// onNo - remove the .dll files from demo method files
						pkg_demoMethodFiles = pkg_demoMethodFiles.filter(function(f) {
							return dllFiles.indexOf(f) === -1;
						});
						pkgUpdateDemoFileList();
					}
				);
			}
		});

		$(document).on("change", "#pkg-input-demofolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var allFiles = getFilesRecursive(folderPath, path.dirname(folderPath));
					var dllFiles = [];
					allFiles.forEach(function(fileInfo) {
						var filePath = fileInfo.absolutePath;
						if (pkg_demoMethodFiles.indexOf(filePath) === -1) {
							pkg_demoMethodFiles.push(filePath);
							pkg_fileRelPaths[filePath] = fileInfo.relativePath;
							if (path.basename(filePath).toLowerCase().endsWith('.dll')) {
								dllFiles.push(filePath);
							}
						}
					});
					pkgUpdateDemoFileList();

					// Warn if .dll files were found in the folder
					if (dllFiles.length > 0) {
						var fileNames = dllFiles.map(function(f) { return '<b>' + escapeHtml(path.basename(f)) + '</b>'; }).join(', ');
						pkgShowFileTypeWarning(
							'Whoa there! This section is for <b>demo methods</b> only. You\'ve added ' +
							(dllFiles.length === 1 ? 'a DLL file' : dllFiles.length + ' DLL files') +
							' (' + fileNames + ') that ' + (dllFiles.length === 1 ? 'looks' : 'look') +
							' like ' + (dllFiles.length === 1 ? 'it belongs' : 'they belong') +
							' in the <b>Library Files</b> section instead.<br><br>Are you absolutely sure you want to add ' +
							(dllFiles.length === 1 ? 'this DLL' : 'these DLLs') + ' here?',
							null, // onYes - keep the files
							function() {
								// onNo - remove the .dll files from demo method files
								pkg_demoMethodFiles = pkg_demoMethodFiles.filter(function(f) {
									return dllFiles.indexOf(f) === -1;
								});
								pkgUpdateDemoFileList();
							}
						);
					}
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Labware file inputs ----
		$(document).on("change", "#pkg-input-labwarefiles", function() {
			var fileInput = this;
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && pkg_labwareFiles.indexOf(filePath) === -1) {
					pkg_labwareFiles.push(filePath);
					// Auto-detect subdirectory from the file's parent folder name
					var parentDir = path.basename(path.dirname(filePath));
					if (parentDir && parentDir !== '.' && parentDir !== path.parse(filePath).root) {
						pkg_labwareSubdirs[filePath] = parentDir;
					}
				}
			}
			pkgUpdateLabwareFileList();
			$(this).val('');
		});

		$(document).on("change", "#pkg-input-labwarefolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var allFiles = getFilesRecursive(folderPath, path.dirname(folderPath));
					allFiles.forEach(function(fileInfo) {
						var filePath = fileInfo.absolutePath;
						if (pkg_labwareFiles.indexOf(filePath) === -1) {
							pkg_labwareFiles.push(filePath);
							pkg_fileRelPaths[filePath] = fileInfo.relativePath;
							// Preserve subdirectory from relative path
							var relDir = path.dirname(fileInfo.relativePath);
							if (relDir && relDir !== '.') {
								pkg_labwareSubdirs[filePath] = relDir.replace(/\\/g, '/');
							}
						}
					});
					pkgUpdateLabwareFileList();
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Bin file inputs ----
		$(document).on("change", "#pkg-input-binfiles", function() {
			var fileInput = this;
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && pkg_binFiles.indexOf(filePath) === -1) {
					pkg_binFiles.push(filePath);
					var parentDir = path.basename(path.dirname(filePath));
					if (parentDir && parentDir !== '.' && parentDir !== path.parse(filePath).root) {
						pkg_binSubdirs[filePath] = parentDir;
					}
				}
			}
			pkgUpdateBinFileList();
			$(this).val('');
		});

		$(document).on("change", "#pkg-input-binfolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var allFiles = getFilesRecursive(folderPath, path.dirname(folderPath));
					allFiles.forEach(function(fileInfo) {
						var filePath = fileInfo.absolutePath;
						if (pkg_binFiles.indexOf(filePath) === -1) {
							pkg_binFiles.push(filePath);
							pkg_fileRelPaths[filePath] = fileInfo.relativePath;
							var relDir = path.dirname(fileInfo.relativePath);
							if (relDir && relDir !== '.') {
								pkg_binSubdirs[filePath] = relDir.replace(/\\/g, '/');
							}
						}
					});
					pkgUpdateBinFileList();
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Remove selected files ----
		$(document).on("click", "#pkg-removeLibFiles", function() {
			var selected = [];
			$("#pkg-lib-list .ft-file-row.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) { return; }
			pkg_libraryFiles = pkg_libraryFiles.filter(function(f) {
				if (selected.indexOf(f) !== -1) {
					delete pkg_fileCustomDirs[f];
					return false;
				}
				return true;
			});
			pkgUpdateLibFileList();
		});

		$(document).on("click", "#pkg-removeLabwareFiles", function() {
			var selected = [];
			$("#pkg-labware-tree .ft-file-row.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) { return; }
			pkg_labwareFiles = pkg_labwareFiles.filter(function(f) {
				if (selected.indexOf(f) !== -1) {
					delete pkg_labwareSubdirs[f];
					return false;
				}
				return true;
			});
			pkgUpdateLabwareFileList();
		});

		$(document).on("click", "#pkg-removeBinFiles", function() {
			var selected = [];
			$("#pkg-bin-tree .ft-file-row.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) { return; }
			pkg_binFiles = pkg_binFiles.filter(function(f) {
				if (selected.indexOf(f) !== -1) {
					delete pkg_binSubdirs[f];
					return false;
				}
				return true;
			});
			pkgUpdateBinFileList();
		});

		$(document).on("click", "#pkg-removeDemoFiles", function() {
			var selected = [];
			$("#pkg-demo-list .ft-file-row.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) { return; }
			pkg_demoMethodFiles = pkg_demoMethodFiles.filter(function(f) {
				return selected.indexOf(f) === -1;
			});
			pkgUpdateDemoFileList();
		});

		// ---- Toggle file selection in trees (click = single, ctrl+click = multi, shift+click = range) ----
		$(document).on("click", ".ft-file-row", function(e) {
			var $tree = $(this).closest(".pkg-file-tree");
			var treeId = $tree.attr("id");
			var $allRows = $tree.find(".ft-file-row");
			var clickedIdx = $allRows.index(this);

			if (e.shiftKey && _pkgLastClickedRow[treeId] !== undefined) {
				// Shift-click: select/deselect range between anchor and current
				var anchorIdx = _pkgLastClickedRow[treeId];
				if (anchorIdx !== clickedIdx && anchorIdx >= 0 && anchorIdx < $allRows.length) {
					var start = Math.min(anchorIdx, clickedIdx);
					var end = Math.max(anchorIdx, clickedIdx);
					var targetState = $allRows.eq(anchorIdx).hasClass("selected");
					for (var ri = start; ri <= end; ri++) {
						if (targetState) {
							$allRows.eq(ri).addClass("selected");
						} else {
							$allRows.eq(ri).removeClass("selected");
						}
					}
				}
			} else if (e.ctrlKey || e.metaKey) {
				$(this).toggleClass("selected");
			} else {
				var wasSelected = $(this).hasClass("selected");
				$tree.find(".ft-file-row").removeClass("selected");
				if (!wasSelected) $(this).addClass("selected");
			}
			_pkgLastClickedRow[treeId] = clickedIdx;
		});

		// Expand/collapse folder: click on the folder row (shared across all trees)
		$(document).on("click", ".ft-folder-row", function(e) {
			if ($(e.target).closest(".ft-com-label").length) return; // don't toggle on COM checkbox click
			var $row = $(this);
			var $branch = $row.next(".ft-branch");
			if (!$branch.length) return;
			var isOpen = !$branch.hasClass("collapsed");
			if (isOpen) {
				$branch.addClass("collapsed");
				$row.find(".ft-toggle").removeClass("fa-chevron-down").addClass("fa-chevron-right");
				$row.find(".ft-icon-folder").removeClass("fa-folder-open").addClass("fa-folder");
			} else {
				$branch.removeClass("collapsed");
				$row.find(".ft-toggle").removeClass("fa-chevron-right").addClass("fa-chevron-down");
				$row.find(".ft-icon-folder").removeClass("fa-folder").addClass("fa-folder-open");
			}
		});

		// ---- Detect library name from library files (.hsl > .hs_ > .smt hierarchy) ----
		var pkg_autoDetectedName = ""; // tracks the auto-detected name
		var pkg_nameOverridden = false; // tracks if user has overridden the name

		function pkgDetectLibraryName() {
			var libName = "";
			var extPriority = [".hsl", ".hsi", ".hs_", ".smt"];
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
				ftUpdateLibNameFolders();
				pkgToggleChangelogVisibility(libName);
			}
		}

		function pkgUpdatePathPlaceholders(name) {
			// Path is now shown in the tree root; no header hint to update
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
				// Already showing this exact auto-detected image - skip
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
				// BMP was removed from file list - clear auto-detected preview
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
				// Show autocomplete on focus
				pkgShowNameAutocomplete($input.val().trim());
			} else {
				// Revert to auto-detected
				$input.val(pkg_autoDetectedName).prop("readonly", true).css({"background-color": "#e9ecef", "cursor": "default"});
				$(this).html('<i class="fas fa-pencil-alt"></i>').attr("title", "Override auto-detected name");
				pkg_nameOverridden = false;
				$("#pkg-name-warning").addClass("d-none");
				$("#pkg-name-hint").removeClass("d-none");
				$("#pkg-name-autocomplete").addClass("d-none").empty();
				pkg_autocompleteActive = false;
				pkgUpdatePathPlaceholders(pkg_autoDetectedName);
				pkgCheckVersionDuplicate();
				pkgToggleChangelogVisibility(pkg_autoDetectedName);
			}
		});

		// ---- Update placeholders and warning on manual name change ----
		$(document).on("input", "#pkg-library-name", function() {
			var val = $(this).val().trim();
			pkgUpdatePathPlaceholders(val);
			ftUpdateLibNameFolders();
			if(pkg_autoDetectedName && val !== pkg_autoDetectedName){
				$("#pkg-name-warning").removeClass("d-none");
				$("#pkg-name-hint").addClass("d-none");
			} else {
				$("#pkg-name-warning").addClass("d-none");
				$("#pkg-name-hint").removeClass("d-none");
			}
			// Show autocomplete suggestions
			pkgShowNameAutocomplete(val);
			// Re-check version duplicate when name changes
			pkgCheckVersionDuplicate();
			// Show/hide changelog based on whether this is an existing library
			pkgToggleChangelogVisibility(val);
		});

		// ---- Show/hide changelog card when library name matches an existing library ----
		function pkgToggleChangelogVisibility(libName) {
			if (!libName) {
				$(".pkg-changelog-card").addClass("d-none");
				return;
			}
			var index = pkgBuildLibraryIndex();
			var lowerName = libName.toLowerCase();
			var found = false;
			for (var i = 0; i < index.length; i++) {
				if (index[i].name.toLowerCase() === lowerName) {
					found = true;
					break;
				}
			}
			if (found) {
				$(".pkg-changelog-card").removeClass("d-none");
			} else {
				$(".pkg-changelog-card").addClass("d-none");
			}
		}

		// ---- Library name autocomplete from installed + system libraries ----
		var pkg_autocompleteActive = false;

		function pkgBuildLibraryIndex() {
			// Build a deduplicated list of all known library names with latest version info
			var map = {}; // name -> { name, version, type, lib }
			var installedLibs = db_installed_libs.installed_libs.find() || [];
			for (var i = 0; i < installedLibs.length; i++) {
				var lib = installedLibs[i];
				if (lib.deleted) continue;
				var key = (lib.library_name || '').toLowerCase();
				if (!key) continue;
				if (!map[key] || (lib.installed_date && (!map[key].installed_date || lib.installed_date > map[key].installed_date))) {
					map[key] = { name: lib.library_name, version: lib.version || '', type: 'installed', lib: lib };
				}
			}
			var sysLibs = getAllSystemLibraries();
			for (var s = 0; s < sysLibs.length; s++) {
				var sLib = sysLibs[s];
				var sKey = (sLib.canonical_name || sLib.library_name || sLib.display_name || '').toLowerCase();
				if (!sKey) continue;
				if (!map[sKey]) {
					map[sKey] = { name: sLib.canonical_name || sLib.library_name || sLib.display_name, version: '', type: 'system', lib: sLib };
				}
			}
			var results = [];
			for (var k in map) { results.push(map[k]); }
			results.sort(function(a, b) { return a.name.localeCompare(b.name); });
			return results;
		}

		function pkgShowNameAutocomplete(query) {
			var $dropdown = $("#pkg-name-autocomplete");
			var $input = $("#pkg-library-name");
			// Only show when the field is editable
			if ($input.prop("readonly")) {
				$dropdown.addClass("d-none").empty();
				pkg_autocompleteActive = false;
				return;
			}
			var index = pkgBuildLibraryIndex();
			var matches;
			if (!query || query.length < 1) {
				// Show all libraries when field is empty
				matches = index.slice(0, 30);
			} else {
				var lowerQuery = query.toLowerCase();
				matches = index.filter(function(item) {
					return item.name.toLowerCase().indexOf(lowerQuery) !== -1;
				}).slice(0, 20);
			}

			if (matches.length === 0) {
				$dropdown.html('<div class="pkg-name-autocomplete-empty">No matching libraries found</div>');
				$dropdown.removeClass("d-none");
				pkg_autocompleteActive = true;
				return;
			}

			$dropdown.empty();
			matches.forEach(function(item) {
				var versionText = item.version ? 'v' + item.version : '';
				var badgeClass = item.type === 'system' ? 'badge-system' : 'badge-installed';
				var badgeLabel = item.type === 'system' ? 'System' : 'Installed';
				$dropdown.append(
					'<div class="pkg-name-autocomplete-item" data-name="' + escapeHtml(item.name) + '" data-type="' + item.type + '">' +
					'<span class="autocomplete-name">' + escapeHtml(item.name) + '</span>' +
					(versionText ? '<span class="autocomplete-version">' + escapeHtml(versionText) + '</span>' : '') +
					'<span class="autocomplete-badge ' + badgeClass + '">' + badgeLabel + '</span>' +
					'</div>'
				);
			});
			$dropdown.removeClass("d-none");
			pkg_autocompleteActive = true;
		}

		// Show autocomplete on focus (when editable)
		$(document).on("focus", "#pkg-library-name", function() {
			if (!$(this).prop("readonly")) {
				pkgShowNameAutocomplete($(this).val().trim());
			}
		});

		// Handle autocomplete item click - populate form from existing library
		$(document).on("click", ".pkg-name-autocomplete-item", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var selectedName = $(this).attr("data-name");
			var selectedType = $(this).attr("data-type");
			$("#pkg-library-name").val(selectedName);
			$("#pkg-name-autocomplete").addClass("d-none").empty();
			pkg_autocompleteActive = false;
			pkgUpdatePathPlaceholders(selectedName);
			ftUpdateLibNameFolders();

			// Load metadata and files from the latest version of this library
			pkgPopulateFromExistingLibrary(selectedName, selectedType);
			pkgCheckVersionDuplicate();
			pkgToggleChangelogVisibility(selectedName);
		});

		// Close autocomplete when clicking outside
		$(document).on("mousedown", function(e) {
			if (pkg_autocompleteActive && !$(e.target).closest("#pkg-library-name, #pkg-name-autocomplete").length) {
				$("#pkg-name-autocomplete").addClass("d-none").empty();
				pkg_autocompleteActive = false;
			}
		});

		// Keyboard navigation for autocomplete
		$(document).on("keydown", "#pkg-library-name", function(e) {
			if (!pkg_autocompleteActive) return;
			var $items = $(".pkg-name-autocomplete-item");
			var $active = $items.filter(".active");
			var idx = $items.index($active);

			if (e.key === "ArrowDown") {
				e.preventDefault();
				$items.removeClass("active");
				$items.eq(Math.min(idx + 1, $items.length - 1)).addClass("active");
			} else if (e.key === "ArrowUp") {
				e.preventDefault();
				$items.removeClass("active");
				if (idx > 0) $items.eq(idx - 1).addClass("active");
			} else if (e.key === "Enter" && $active.length) {
				e.preventDefault();
				$active.trigger("click");
			} else if (e.key === "Escape") {
				$("#pkg-name-autocomplete").addClass("d-none").empty();
				pkg_autocompleteActive = false;
			}
		});

		/**
		 * Populate the package form from an existing library's latest version.
		 * Loads metadata (author, org, description, tags, etc.) and adds the
		 * library files from the installed location to the file lists.
		 */
		function pkgPopulateFromExistingLibrary(libName, libType) {
			if (libType === 'installed') {
				// Find the latest version of this library
				var installedLibs = db_installed_libs.installed_libs.find() || [];
				var candidates = installedLibs.filter(function(l) {
					return l.library_name === libName && !l.deleted;
				});
				if (candidates.length === 0) return;
				// Sort by installed_date descending to get latest
				candidates.sort(function(a, b) {
					return (b.installed_date || '').localeCompare(a.installed_date || '');
				});
				var latest = candidates[0];

				// Populate metadata fields
				if (latest.author) $("#pkg-author").val(latest.author);
				if (latest.organization) $("#pkg-organization").val(latest.organization);
				if (latest.venus_compatibility) $("#pkg-venus-compat").val(latest.venus_compatibility);
				if (latest.description) $("#pkg-description").val(latest.description);
				if (latest.github_url) $("#pkg-github-url").val(latest.github_url);
				if (latest.tags && latest.tags.length > 0) $("#pkg-tags").val(latest.tags.join(", "));
				if (latest.install_to_library_root) pkg_installSubdir = '';
				else if (latest.custom_install_subdir) pkg_installSubdir = latest.custom_install_subdir;
				else pkg_installSubdir = null;

				// Populate version with current version (user should change it)
				if (latest.version) {
					$("#pkg-version").val(latest.version);
				}

				// Load library files from install path
				var libBasePath = latest.lib_install_path || "";
				var libFiles = latest.library_files || [];
				if (libBasePath && libFiles.length > 0) {
					pkg_libraryFiles = [];
					pkg_fileRelPaths = {};
					pkg_fileCustomDirs = {};
					for (var i = 0; i < libFiles.length; i++) {
						var fullPath = path.join(libBasePath, libFiles[i]);
						if (fs.existsSync(fullPath)) {
							pkg_libraryFiles.push(fullPath);
							pkg_fileRelPaths[fullPath] = libFiles[i];
						}
					}
					// Restore COM DLL selections
					pkg_comRegisterDlls = (latest.com_register_dlls || []).slice();
					pkgUpdateLibFileList();
				}

				// Load demo method files from install path
				var demoBasePath = latest.demo_install_path || "";
				var demoFiles = latest.demo_method_files || [];
				if (demoBasePath && demoFiles.length > 0) {
					pkg_demoMethodFiles = [];
					for (var d = 0; d < demoFiles.length; d++) {
						var demoFullPath = path.join(demoBasePath, demoFiles[d]);
						if (fs.existsSync(demoFullPath)) {
							pkg_demoMethodFiles.push(demoFullPath);
							pkg_fileRelPaths[demoFullPath] = demoFiles[d];
						}
					}
					pkgUpdateDemoFileList();
				}

				// Load icon from library image if available
				if (latest.library_image_base64 && latest.library_image_mime) {
					$("#pkg-icon-preview").html('<img src="data:' + latest.library_image_mime + ';base64,' + latest.library_image_base64 + '">').addClass('has-image');
					$("#pkg-icon-name").text((latest.library_image || "library icon") + " (from previous version)");
					$("#pkg-removeIcon").show();
					pkg_iconAutoDetected = true;
				}

				// Check version duplicate
				pkgCheckVersionDuplicate();

			} else if (libType === 'system') {
				// System libraries have limited metadata - populate what's available
				var sysLibs = getAllSystemLibraries();
				var sysLib = null;
				for (var si = 0; si < sysLibs.length; si++) {
					var sn = sysLibs[si].canonical_name || sysLibs[si].library_name || sysLibs[si].display_name;
					if (sn === libName) { sysLib = sysLibs[si]; break; }
				}
				if (!sysLib) return;

				if (sysLib.author) $("#pkg-author").val(sysLib.author);
				if (sysLib.organization) $("#pkg-organization").val(sysLib.organization);

				// Load system library files from discovered_files
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var discoveredFiles = sysLib.discovered_files || [];
				if (discoveredFiles.length > 0) {
					pkg_libraryFiles = [];
					pkg_fileRelPaths = {};
					pkg_fileCustomDirs = {};
					for (var df = 0; df < discoveredFiles.length; df++) {
						var relFile = discoveredFiles[df].replace(/^Library[\\\/]/i, '');
						var sysFullPath = path.join(sysLibDir, relFile);
						if (fs.existsSync(sysFullPath)) {
							pkg_libraryFiles.push(sysFullPath);
							pkg_fileRelPaths[sysFullPath] = relFile;
						}
					}
					pkgUpdateLibFileList();
				}
			}
		}

		// ---- Version duplicate checking ----
		function pkgCheckVersionDuplicate() {
			var libName = $("#pkg-library-name").val().trim();
			var version = $("#pkg-version").val().trim();
			if (!libName || !version) {
				$("#pkg-version").removeClass("version-duplicate");
				$("#pkg-version-warning").addClass("d-none");
				pkgSetCreateEnabled(true);
				return;
			}
			var installedLibs = db_installed_libs.installed_libs.find() || [];
			var duplicate = false;
			for (var i = 0; i < installedLibs.length; i++) {
				if (installedLibs[i].library_name === libName && installedLibs[i].version === version && !installedLibs[i].deleted) {
					duplicate = true;
					break;
				}
			}
			if (duplicate) {
				$("#pkg-version").addClass("version-duplicate");
				$("#pkg-version-warning-text").text('Version "' + version + '" already exists for "' + libName + '". Use a different version number.');
				$("#pkg-version-warning").removeClass("d-none");
				pkgSetCreateEnabled(false, 'Version "' + version + '" already exists for "' + libName + '". Change the version number to create a package.');
			} else {
				$("#pkg-version").removeClass("version-duplicate");
				$("#pkg-version-warning").addClass("d-none");
				pkgSetCreateEnabled(true);
			}
		}

		function pkgSetCreateEnabled(enabled, reason) {
			var $btn = $("#pkg-create");
			var $wrap = $("#pkg-create-wrapper");
			if (enabled) {
				$btn.prop("disabled", false).removeClass("pkg-create-disabled");
				$wrap.removeAttr("title").css("cursor", "");
			} else {
				$btn.prop("disabled", true).addClass("pkg-create-disabled");
				$wrap.attr("title", reason || 'Cannot create package').css("cursor", "not-allowed");
			}
		}

		$(document).on("input", "#pkg-version", function() {
			pkgCheckVersionDuplicate();
		});

		/**
		 * Compute the resultant install path for a single file in the packager.
		 * Considers per-file custom dir override, then global install-to-root / custom subdir.
		 */
		function pkgGetFileDestPath(absPath) {
			var libName = $("#pkg-library-name").val().trim() || "<libraryname>";
			var relPath = pkg_fileRelPaths[absPath] || path.basename(absPath);
			var fileName = path.basename(relPath);
			var relDir = path.dirname(relPath).replace(/\\/g, '/');
			var relDirPrefix = (relDir && relDir !== '.') ? relDir.replace(/\//g, '\\') + '\\' : '';
			if (pkg_installSubdir !== null) {
				if (pkg_installSubdir === '') return '...\\Hamilton\\Library\\' + relDirPrefix + fileName;
				var sanitized = pkg_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');
				return '...\\Hamilton\\Library\\' + sanitized + '\\' + relDirPrefix + fileName;
			}
			return '...\\Hamilton\\Library\\' + libName + '\\' + relDirPrefix + fileName;
		}

		/**
		 * Compute the resultant install path for a single file in the unsigned library modal.
		 */
		function ulibGetFileDestPath(absPath) {
			var libName = $("#ulib-name").val().trim() || "<libraryname>";
			var relDir = '';
			var fileName = path.basename(absPath);
			if (ulib_installSubdir !== null) {
				if (ulib_installSubdir === '') return '...\\Hamilton\\Library\\' + fileName;
				var sanitized = ulib_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');
				return '...\\Hamilton\\Library\\' + sanitized + '\\' + fileName;
			}
			return '...\\Hamilton\\Library\\' + libName + '\\' + fileName;
		}

		// ---- Shared tree rendering helpers ----

		/**
		 * Build a nested tree object from a list of absolute file paths.
		 * relPathFn(absPath) returns the relative path used for folder nesting.
		 * Returns { children: { folderName: treeNode, ... }, files: [ absPath, ... ] }
		 */
		function ftBuildTree(files, relPathFn) {
			var tree = { children: {}, files: [] };
			files.forEach(function(f) {
				var rel = relPathFn(f);
				var dir = path.dirname(rel).replace(/\\/g, '/');
				if (!dir || dir === '.') {
					tree.files.push(f);
				} else {
					var parts = dir.split('/');
					var node = tree;
					for (var i = 0; i < parts.length; i++) {
						if (!node.children[parts[i]]) node.children[parts[i]] = { children: {}, files: [] };
						node = node.children[parts[i]];
					}
					node.files.push(f);
				}
			});
			return tree;
		}

		/** Count total files in a tree node recursively */
		function ftCountFiles(node) {
			var count = node.files.length;
			Object.keys(node.children).forEach(function(k) { count += ftCountFiles(node.children[k]); });
			return count;
		}

		/**
		 * Recursively render a tree node to HTML.
		 * fileRowFn(absPath) returns the inner HTML of the file row (icon, label, badge/checkbox).
		 */
		function ftRenderNode(node, fileRowFn) {
			var html = '';
			var folderNames = Object.keys(node.children).sort(function(a, b) { return a.localeCompare(b); });

			folderNames.forEach(function(name) {
				var child = node.children[name];
				var total = ftCountFiles(child);
				html += '<li class="ft-node">';
				html += '<div class="ft-row ft-folder-row" data-folder="' + escapeHtml(name) + '">';
				html += '<i class="fas fa-chevron-down ft-toggle"></i>';
				html += '<i class="fas fa-folder-open ft-icon-folder"></i>';
				html += '<span class="ft-label">' + escapeHtml(name) + '</span>';
				html += '<span class="ft-count">' + total + '</span>';
				html += '<span class="ft-folder-actions"><i class="fas fa-trash-alt ft-folder-delete" title="Delete folder and its contents"></i></span>';
				html += '</div>';
				html += '<ul class="ft-branch">';
				html += ftRenderNode(child, fileRowFn);
				html += '</ul>';
				html += '</li>';
			});

			node.files.forEach(function(f) {
				html += '<li class="ft-node">';
				html += fileRowFn(f);
				html += '</li>';
			});

			return html;
		}

		/**
		 * Build the full tree HTML, wrapping in a root folder if subfolders exist.
		 * rootLabel: root folder label (e.g. "Library", "Demo Methods", "Labware")
		 * totalCount: total file count for root
		 */
		function ftBuildHtml(tree, rootLabel, totalCount, fileRowFn, rootPath) {
			var pathHint = rootPath ? '<span class="ft-root-path">' + escapeHtml(rootPath) + '</span>' : '';
			var html = '<ul class="ft-tree">';
			html += '<li class="ft-node ft-root-folder">';
			html += '<div class="ft-row ft-folder-row" data-folder="">';
			html += '<i class="fas fa-chevron-down ft-toggle"></i>';
			html += '<i class="fas fa-folder-open ft-icon-folder"></i>';
			html += '<span class="ft-label">' + escapeHtml(rootLabel) + '</span>';
			html += pathHint;
			html += '<span class="ft-count">' + totalCount + '</span>';
			html += '</div>';
			html += '<ul class="ft-branch">';
			html += ftRenderNode(tree, fileRowFn);
			html += '</ul>';
			html += '</li>';
			html += '</ul>';
			return html;
		}

		// ---- Update file list displays ----
		/** Get the install path string for a tree section. */
		function ftGetInstallPath(treeId) {
			var libName = $("#pkg-library-name").val() || '<libraryname>';
			if (treeId === 'pkg-lib-list') {
				if (pkg_installSubdir !== null) {
					var sub = pkg_installSubdir === '' ? '' : pkg_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');
					return '...\\Hamilton\\Library\\' + (sub ? sub + '\\' : '');
				}
				return '...\\Hamilton\\Library\\' + libName + '\\';
			} else if (treeId === 'pkg-demo-list') {
				return '...\\Hamilton\\Methods\\Library Demo Methods\\' + libName + '\\';
			} else if (treeId === 'pkg-labware-tree') {
				return '...\\Hamilton\\Labware\\';
			} else if (treeId === 'pkg-bin-tree') {
				return '...\\Hamilton\\Bin\\';
			}
			return '';
		}

		/** Update the library-name subfolder label in all empty trees. */
		function ftUpdateLibNameFolders() {
			var libName = $("#pkg-library-name").val().trim() || '<libraryname>';
			$('.ft-libname-node .ft-label').text(libName);
			$('.ft-libname-node').attr('data-folder', libName);
		}

		function pkgUpdateLibFileList() {
			var $list = $("#pkg-lib-list");
			$list.empty();
			delete _pkgLastClickedRow['pkg-lib-list'];
			if (pkg_libraryFiles.length === 0 && pkg_libEmptyFolders.length === 0) {
				var libName = $("#pkg-library-name").val().trim() || '<libraryname>';
				var emptyTree = { children: {}, files: [] };
				emptyTree.children[libName] = { children: {}, files: [] };
				var rootPath = pkg_installSubdir !== null ? ftGetInstallPath('pkg-lib-list') : '...\\Hamilton\\Library\\';
				$list.html(ftBuildHtml(emptyTree, 'Library', 0, function() { return ''; }, rootPath));
				$list.find('.ft-root-folder > .ft-branch > .ft-node > .ft-folder-row').addClass('ft-libname-node');
			} else {
				var tree = ftBuildTree(pkg_libraryFiles, function(f) {
					return pkg_fileRelPaths[f] || path.basename(f);
				});
				// Ensure user-created empty folders exist in the tree
				pkg_libEmptyFolders.forEach(function(folderPath) {
					var parts = folderPath.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '').split('/');
					var node = tree;
					for (var pi = 0; pi < parts.length; pi++) {
						if (!node.children[parts[pi]]) node.children[parts[pi]] = { children: {}, files: [] };
						node = node.children[parts[pi]];
					}
				});
				// Count CHM help files to determine if default help radio should be shown
				var chmCount = pkg_libraryFiles.filter(function(f) {
					return path.extname(f).toLowerCase() === '.chm';
				}).length;
				// Clear default help file if it refers to a file that was removed
				if (pkg_defaultHelpFile) {
					var stillExists = pkg_libraryFiles.some(function(f) {
						return path.basename(f) === pkg_defaultHelpFile;
					});
					if (!stillExists) pkg_defaultHelpFile = null;
				}
				var fileRowFn = function(f) {
					var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
					var baseName = path.basename(f);
					var ext = path.extname(baseName).toLowerCase();
					var isDll = ext === '.dll';
					var isChm = ext === '.chm';
					var isChecked = pkg_comRegisterDlls.indexOf(baseName) !== -1;
					var comHtml = '';
					if (isDll) {
						comHtml = '<label class="ft-com-label" title="Register this DLL as a COM object using RegAsm.exe /codebase during import. Requires administrator rights.">' +
							'<input type="checkbox" class="pkg-com-checkbox" data-dll="' + baseName.replace(/"/g, '&quot;') + '"' + (isChecked ? ' checked' : '') + '>' +
							'<span>COM</span></label>';
					}
					var defaultHelpHtml = '';
					if (isChm && chmCount > 1) {
						var isDefaultHelp = pkg_defaultHelpFile === baseName;
						defaultHelpHtml = '<label class="ft-default-help-label" title="Set as the default help file. When set, clicking Help on the library card will open this file directly instead of showing a menu.">' +
							'<input type="radio" name="pkg-default-help" class="pkg-default-help-radio" data-chm="' + baseName.replace(/"/g, '&quot;') + '"' + (isDefaultHelp ? ' checked' : '') + '>' +
							'<span>Default</span></label>';
					}
					var icon = isDll ? 'fa-cog' : (isChm ? 'fa-question-circle' : (ext === '.hsl' || ext === '.hs_' || ext === '.hsi' ? 'fa-code' : (ext === '.smt' ? 'fa-microchip' : 'fa-file')));
					var label = ext ? ext.replace('.', '').toUpperCase() : 'FILE';
					return '<div class="ft-row ft-file-row" data-path="' + escapedPath + '" draggable="true">' +
						'<i class="fas ' + icon + ' ft-icon-file"></i>' +
						'<span class="ft-label">' + escapeHtml(baseName) + '</span>' +
						comHtml +
						defaultHelpHtml +
						'<span class="ft-badge">' + escapeHtml(label) + '</span>' +
						'</div>';
				};
				$list.html(ftBuildHtml(tree, 'Library', pkg_libraryFiles.length, fileRowFn, ftGetInstallPath('pkg-lib-list')));
			}
			$("#pkg-lib-count").text(pkg_libraryFiles.length + " file" + (pkg_libraryFiles.length !== 1 ? "s" : ""));
			pkgDetectLibraryName();
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
		$(document).on("click", ".ft-com-label", function(e) {
			e.stopPropagation();
		});

		// ---- Default help file radio handler ----
		$(document).on("change", ".pkg-default-help-radio", function(e) {
			e.stopPropagation();
			var chmName = $(this).attr("data-chm");
			if ($(this).is(":checked")) {
				pkg_defaultHelpFile = chmName;
			}
		});

		// Prevent radio click from toggling file selection
		$(document).on("click", ".ft-default-help-label", function(e) {
			e.stopPropagation();
		});

		function pkgUpdateDemoFileList() {
			var $list = $("#pkg-demo-list");
			$list.empty();
			delete _pkgLastClickedRow['pkg-demo-list'];
			if (pkg_demoMethodFiles.length === 0 && pkg_demoEmptyFolders.length === 0) {
				var libName = $("#pkg-library-name").val().trim() || '<libraryname>';
				var emptyTree = { children: {}, files: [] };
				emptyTree.children[libName] = { children: {}, files: [] };
				$list.html(ftBuildHtml(emptyTree, 'Demo Methods', 0, function() { return ''; }, '...\\Hamilton\\Methods\\Library Demo Methods\\'));
				$list.find('.ft-root-folder > .ft-branch > .ft-node > .ft-folder-row').addClass('ft-libname-node');
			} else {
				var extIcons = {
					'.hsl': 'fa-code', '.hs_': 'fa-code', '.hsi': 'fa-code',
					'.stp': 'fa-play', '.med': 'fa-play', '.wfl': 'fa-project-diagram',
					'.csv': 'fa-table', '.txt': 'fa-file-alt'
				};
				var tree = ftBuildTree(pkg_demoMethodFiles, function(f) {
					return pkg_fileRelPaths[f] || path.basename(f);
				});
				// Ensure user-created empty folders exist in the tree
				pkg_demoEmptyFolders.forEach(function(folderPath) {
					var parts = folderPath.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '').split('/');
					var node = tree;
					for (var pi = 0; pi < parts.length; pi++) {
						if (!node.children[parts[pi]]) node.children[parts[pi]] = { children: {}, files: [] };
						node = node.children[parts[pi]];
					}
				});
				var fileRowFn = function(f) {
					var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
					var baseName = path.basename(f);
					var ext = path.extname(baseName).toLowerCase();
					var icon = extIcons[ext] || 'fa-file';
					var label = ext ? ext.replace('.', '').toUpperCase() : 'FILE';
					return '<div class="ft-row ft-file-row" data-path="' + escapedPath + '" draggable="true">' +
						'<i class="fas ' + icon + ' ft-icon-file"></i>' +
						'<span class="ft-label">' + escapeHtml(baseName) + '</span>' +
						'<span class="ft-badge">' + escapeHtml(label) + '</span>' +
						'</div>';
				};
				$list.html(ftBuildHtml(tree, 'Demo Methods', pkg_demoMethodFiles.length, fileRowFn, ftGetInstallPath('pkg-demo-list')));
			}
			$("#pkg-demo-count").text(pkg_demoMethodFiles.length + " file" + (pkg_demoMethodFiles.length !== 1 ? "s" : ""));
		}

		// ---- Labware file list tree renderer ----
		var pkg_labwareEmptyFolders = [];
		var pkg_binEmptyFolders = [];

		function pkgUpdateLabwareFileList() {
			var $tree = $("#pkg-labware-tree");
			$tree.empty();
			delete _pkgLastClickedRow['pkg-labware-tree'];
			if (pkg_labwareFiles.length === 0 && pkg_labwareEmptyFolders.length === 0) {
				var libName = $("#pkg-library-name").val().trim() || '<libraryname>';
				var emptyTree = { children: {}, files: [] };
				emptyTree.children[libName] = { children: {}, files: [] };
				$tree.html(ftBuildHtml(emptyTree, 'Labware', 0, function() { return ''; }, '...\\Hamilton\\Labware\\'));
				$tree.find('.ft-root-folder > .ft-branch > .ft-node > .ft-folder-row').addClass('ft-libname-node');
				$("#pkg-labware-count").text("0 files");
				return;
			}

			var extInfo = {
				'.rck': { icon: 'fa-th',               label: 'Rack' },
				'.ctr': { icon: 'fa-box',              label: 'Container' },
				'.tml': { icon: 'fa-file-alt',         label: 'Template' },
				'.dck': { icon: 'fa-layer-group',      label: 'Deck' },
				'.lay': { icon: 'fa-drafting-compass', label: 'Layout' }
			};

			// Build tree from subdirectory assignments
			var tree = { children: {}, files: [] };
			pkg_labwareFiles.forEach(function(f) {
				var subdir = (pkg_labwareSubdirs[f] || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
				if (!subdir) {
					tree.files.push(f);
				} else {
					var parts = subdir.split('/');
					var node = tree;
					for (var pi = 0; pi < parts.length; pi++) {
						if (!node.children[parts[pi]]) node.children[parts[pi]] = { children: {}, files: [] };
						node = node.children[parts[pi]];
					}
					node.files.push(f);
				}
			});

			// Ensure user-created empty folders exist in the tree
			pkg_labwareEmptyFolders.forEach(function(folderPath) {
				var parts = folderPath.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '').split('/');
				var node = tree;
				for (var pi = 0; pi < parts.length; pi++) {
					if (!node.children[parts[pi]]) node.children[parts[pi]] = { children: {}, files: [] };
					node = node.children[parts[pi]];
				}
			});

			var fileRowFn = function(f) {
				var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
				var baseName = path.basename(f);
				var ext = path.extname(f).toLowerCase();
				var info = extInfo[ext] || { icon: 'fa-file', label: ext ? ext.replace('.', '').toUpperCase() : 'FILE' };
				return '<div class="ft-row ft-file-row" data-path="' + escapedPath + '" draggable="true">' +
					'<i class="fas ' + info.icon + ' ft-icon-file"></i>' +
					'<span class="ft-label">' + escapeHtml(baseName) + '</span>' +
					'<span class="ft-badge">' + escapeHtml(info.label) + '</span>' +
					'</div>';
			};

			$tree.html(ftBuildHtml(tree, 'Labware', pkg_labwareFiles.length, fileRowFn, ftGetInstallPath('pkg-labware-tree')));
			$("#pkg-labware-count").text(pkg_labwareFiles.length + " file" + (pkg_labwareFiles.length !== 1 ? "s" : ""));
		}

		// ---- Bin file list tree renderer ----
		function pkgUpdateBinFileList() {
			var $tree = $("#pkg-bin-tree");
			$tree.empty();
			delete _pkgLastClickedRow['pkg-bin-tree'];
			if (pkg_binFiles.length === 0 && pkg_binEmptyFolders.length === 0) {
				var libName = $("#pkg-library-name").val().trim() || '<libraryname>';
				var emptyTree = { children: {}, files: [] };
				emptyTree.children[libName] = { children: {}, files: [] };
				$tree.html(ftBuildHtml(emptyTree, 'Bin', 0, function() { return ''; }, '...\\Hamilton\\Bin\\'));
				$tree.find('.ft-root-folder > .ft-branch > .ft-node > .ft-folder-row').addClass('ft-libname-node');
				$("#pkg-bin-count").text("0 files");
				return;
			}

			// Build tree from subdirectory assignments
			var tree = { children: {}, files: [] };
			pkg_binFiles.forEach(function(f) {
				var subdir = (pkg_binSubdirs[f] || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
				if (!subdir) {
					tree.files.push(f);
				} else {
					var parts = subdir.split('/');
					var node = tree;
					for (var pi = 0; pi < parts.length; pi++) {
						if (!node.children[parts[pi]]) node.children[parts[pi]] = { children: {}, files: [] };
						node = node.children[parts[pi]];
					}
					node.files.push(f);
				}
			});

			// Ensure user-created empty folders exist in the tree
			pkg_binEmptyFolders.forEach(function(folderPath) {
				var parts = folderPath.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '').split('/');
				var node = tree;
				for (var pi = 0; pi < parts.length; pi++) {
					if (!node.children[parts[pi]]) node.children[parts[pi]] = { children: {}, files: [] };
					node = node.children[parts[pi]];
				}
			});

			var fileRowFn = function(f) {
				var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
				var baseName = path.basename(f);
				var ext = path.extname(f).toLowerCase();
				var icon = ext === '.dll' ? 'fa-cog' : (ext === '.exe' ? 'fa-play' : 'fa-file');
				var label = ext ? ext.replace('.', '').toUpperCase() : 'FILE';
				return '<div class="ft-row ft-file-row" data-path="' + escapedPath + '" draggable="true">' +
					'<i class="fas ' + icon + ' ft-icon-file"></i>' +
					'<span class="ft-label">' + escapeHtml(baseName) + '</span>' +
					'<span class="ft-badge">' + escapeHtml(label) + '</span>' +
					'</div>';
			};

			$tree.html(ftBuildHtml(tree, 'Bin', pkg_binFiles.length, fileRowFn, ftGetInstallPath('pkg-bin-tree')));
			$("#pkg-bin-count").text(pkg_binFiles.length + " file" + (pkg_binFiles.length !== 1 ? "s" : ""));
		}

		// ---- Generic tree helpers for folder management across all three trees ----

		/**
		 * Map a tree container ID to its state: files array, relPath lookup, empty folders, update function, root label.
		 */
		function ftGetTreeState(treeId) {
			if (treeId === 'pkg-lib-list') {
				return {
					files: function() { return pkg_libraryFiles; },
					setFiles: function(v) { pkg_libraryFiles = v; },
					getRelPath: function(f) { return pkg_fileRelPaths[f] || path.basename(f); },
					setRelPath: function(f, rel) { pkg_fileRelPaths[f] = rel; },
					clearRelPath: function(f) { delete pkg_fileRelPaths[f]; },
					emptyFolders: function() { return pkg_libEmptyFolders; },
					setEmptyFolders: function(v) { pkg_libEmptyFolders = v; },
					update: function() { pkgUpdateLibFileList(); },
					rootLabel: 'Library'
				};
			} else if (treeId === 'pkg-demo-list') {
				return {
					files: function() { return pkg_demoMethodFiles; },
					setFiles: function(v) { pkg_demoMethodFiles = v; },
					getRelPath: function(f) { return pkg_fileRelPaths[f] || path.basename(f); },
					setRelPath: function(f, rel) { pkg_fileRelPaths[f] = rel; },
					clearRelPath: function(f) { delete pkg_fileRelPaths[f]; },
					emptyFolders: function() { return pkg_demoEmptyFolders; },
					setEmptyFolders: function(v) { pkg_demoEmptyFolders = v; },
					update: function() { pkgUpdateDemoFileList(); },
					rootLabel: 'Demo Methods'
				};
			} else if (treeId === 'pkg-labware-tree') {
				return {
					files: function() { return pkg_labwareFiles; },
					setFiles: function(v) { pkg_labwareFiles = v; },
					getRelPath: function(f) { return pkg_labwareSubdirs[f] ? pkg_labwareSubdirs[f] + '/' + path.basename(f) : path.basename(f); },
					setRelPath: function(f, rel) {
						var dir = path.dirname(rel).replace(/\\/g, '/');
						if (!dir || dir === '.') { delete pkg_labwareSubdirs[f]; }
						else { pkg_labwareSubdirs[f] = dir; }
					},
					clearRelPath: function(f) { delete pkg_labwareSubdirs[f]; },
					emptyFolders: function() { return pkg_labwareEmptyFolders; },
					setEmptyFolders: function(v) { pkg_labwareEmptyFolders = v; },
					update: function() { pkgUpdateLabwareFileList(); },
					rootLabel: 'Labware'
				};
			} else if (treeId === 'pkg-bin-tree') {
				return {
					files: function() { return pkg_binFiles; },
					setFiles: function(v) { pkg_binFiles = v; },
					getRelPath: function(f) { return pkg_binSubdirs[f] ? pkg_binSubdirs[f] + '/' + path.basename(f) : path.basename(f); },
					setRelPath: function(f, rel) {
						var dir = path.dirname(rel).replace(/\\/g, '/');
						if (!dir || dir === '.') { delete pkg_binSubdirs[f]; }
						else { pkg_binSubdirs[f] = dir; }
					},
					clearRelPath: function(f) { delete pkg_binSubdirs[f]; },
					emptyFolders: function() { return pkg_binEmptyFolders; },
					setEmptyFolders: function(v) { pkg_binEmptyFolders = v; },
					update: function() { pkgUpdateBinFileList(); },
					rootLabel: 'Bin'
				};
			}
			return null;
		}

		/**
		 * Collect distinct folder paths from a tree's files + empty folders.
		 */
		// "New Folder" button (generic for all trees)
		$(document).on("click", ".ft-newFolderBtn", function() {
			var treeId = $(this).attr("data-tree");
			var state = ftGetTreeState(treeId);
			if (!state) return;
			var name = prompt("Enter new folder name:", "");
			if (name && name.trim()) {
				name = name.trim().replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
				var ef = state.emptyFolders();
				if (name && ef.indexOf(name) === -1) {
					ef.push(name);
					state.update();
				}
			}
		});

		/** Collect truly empty folders across all package trees. Returns [{tree, folder}]. */
		function ftCollectEmptyFolders() {
			var result = [];
			var trees = [
				{ label: 'Library Files', emptyFolders: pkg_libEmptyFolders, files: pkg_libraryFiles, getSubdir: function(f) { var rel = pkg_fileRelPaths[f]; if (!rel) return ''; var d = path.dirname(rel).replace(/\\/g, '/'); return (!d || d === '.') ? '' : d; } },
				{ label: 'Demo Method Files', emptyFolders: pkg_demoEmptyFolders, files: pkg_demoMethodFiles, getSubdir: function(f) { var rel = pkg_fileRelPaths[f]; if (!rel) return ''; var d = path.dirname(rel).replace(/\\/g, '/'); return (!d || d === '.') ? '' : d; } },
				{ label: 'Labware Files', emptyFolders: pkg_labwareEmptyFolders, files: pkg_labwareFiles, getSubdir: function(f) { return (pkg_labwareSubdirs[f] || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, ''); } },
				{ label: 'Bin Files', emptyFolders: pkg_binEmptyFolders, files: pkg_binFiles, getSubdir: function(f) { return (pkg_binSubdirs[f] || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, ''); } }
			];
			trees.forEach(function(t) {
				t.emptyFolders.forEach(function(folderPath) {
					var fp = folderPath.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
					var hasFiles = t.files.some(function(f) {
						var sub = t.getSubdir(f);
						return sub === fp || sub.indexOf(fp + '/') === 0;
					});
					if (!hasFiles) result.push({ tree: t.label, folder: fp });
				});
			});
			return result;
		}

		// ---- Delete folder button handler ----
		$(document).on("click", ".ft-folder-delete", function(e) {
			e.stopPropagation();
			var $folderRow = $(this).closest(".ft-folder-row");
			var $tree = $folderRow.closest(".pkg-file-tree");
			var treeId = $tree.attr("id");
			var state = ftGetTreeState(treeId);
			if (!state) return;

			var folderPath = ftResolveFolderPath($folderRow);
			if (!folderPath) return;

			// Collect files inside this folder
			var filesToRemove = [];
			$folderRow.next(".ft-branch").find(".ft-file-row").each(function() {
				filesToRemove.push($(this).attr("data-path"));
			});

			var msg = 'Delete folder "' + folderPath + '"';
			if (filesToRemove.length > 0) {
				msg += ' and its ' + filesToRemove.length + ' file' + (filesToRemove.length !== 1 ? 's' : '') + '?';
			} else {
				msg += '?';
			}
			if (!confirm(msg)) return;

			// Remove files contained in this folder
			if (filesToRemove.length > 0) {
				var removeSet = {};
				filesToRemove.forEach(function(f) { removeSet[f] = true; });
				state.setFiles(state.files().filter(function(f) {
					if (removeSet[f]) {
						state.clearRelPath(f);
						return false;
					}
					return true;
				}));
			}

			// Remove matching empty folders (the folder itself and any children)
			var ef = state.emptyFolders();
			state.setEmptyFolders(ef.filter(function(fp) {
				return fp !== folderPath && fp.indexOf(folderPath + '/') !== 0;
			}));

			state.update();
		});

		// ================================================================
		// ---- DRAG AND DROP: OS file drop + internal rearrange ----
		// ================================================================

		var ftDragData = null; // { treeId, filePaths[] } — set during internal drag

		/**
		 * Resolve the full folder path for a folder row by walking up the tree.
		 * Returns '' for root, 'folderName' for single level, 'parent/child' for nested.
		 */
		function ftResolveFolderPath($folderRow) {
			var parts = [];
			var $row = $folderRow;
			while ($row.length) {
				var folderName = $row.attr("data-folder");
				if (folderName === '' || folderName === undefined) break; // root folder — stop
				parts.unshift(folderName);
				// Walk up: folder-row -> li.ft-node -> ul.ft-branch -> li.ft-node (parent) -> div.ft-folder-row
				var $parentNode = $row.closest("li.ft-node").parent("ul.ft-branch").closest("li.ft-node");
				if (!$parentNode.length) break;
				$row = $parentNode.children(".ft-folder-row").first();
				if (!$row.length) break;
			}
			return parts.join('/');
		}

		// --- Internal drag: dragstart on .ft-file-row ---
		$(document).on("dragstart", ".ft-file-row", function(e) {
			var $tree = $(this).closest(".pkg-file-tree");
			var treeId = $tree.attr("id");
			// Collect all selected file paths, or just this one if it's not selected
			var filePaths = [];
			if ($(this).hasClass("selected")) {
				$tree.find(".ft-file-row.selected").each(function() {
					filePaths.push($(this).attr("data-path"));
				});
			} else {
				filePaths.push($(this).attr("data-path"));
			}
			ftDragData = { treeId: treeId, filePaths: filePaths };
			e.originalEvent.dataTransfer.effectAllowed = 'move';
			e.originalEvent.dataTransfer.setData('text/plain', filePaths.join('\n'));
			// Mark dragging files
			var self = this;
			setTimeout(function() {
				if ($(self).hasClass("selected")) {
					$tree.find(".ft-file-row.selected").addClass("ft-dragging");
				} else {
					$(self).addClass("ft-dragging");
				}
			}, 0);
		});

		$(document).on("dragend", ".ft-file-row", function() {
			$(".ft-dragging").removeClass("ft-dragging");
			$(".ft-drop-target").removeClass("ft-drop-target");
			$(".ft-dragover").removeClass("ft-dragover");
			ftDragData = null;
		});

		// --- Folder row drop target highlighting ---
		$(document).on("dragover", ".ft-folder-row", function(e) {
			e.preventDefault();
			e.stopPropagation();
			// Highlight for internal drag (same or cross-tree)
			if (ftDragData) {
				e.originalEvent.dataTransfer.dropEffect = 'move';
				$(".ft-drop-target").removeClass("ft-drop-target");
				$(this).addClass("ft-drop-target");
			}
		});

		$(document).on("dragleave", ".ft-folder-row", function() {
			$(this).removeClass("ft-drop-target");
		});

		// --- Drop onto folder row: move files to that folder ---
		$(document).on("drop", ".ft-folder-row", function(e) {
			e.preventDefault();
			e.stopPropagation();
			$(this).removeClass("ft-drop-target");
			var $tree = $(this).closest(".pkg-file-tree");
			var treeId = $tree.attr("id");
			var targetFolder = ftResolveFolderPath($(this));

			if (ftDragData) {
				if (ftDragData.treeId === treeId) {
					// Same-tree rearrange
					var state = ftGetTreeState(treeId);
					if (state) {
						ftDragData.filePaths.forEach(function(fp) {
							var baseName = path.basename(fp);
							if (targetFolder === '') {
								state.clearRelPath(fp);
							} else {
								state.setRelPath(fp, targetFolder + '/' + baseName);
							}
						});
						ftDragData = null;
						state.update();
					}
				} else {
					// Cross-tree move
					ftCrossTreeMove(ftDragData.treeId, treeId, ftDragData.filePaths, targetFolder);
					ftDragData = null;
				}
				return;
			}

			// OS file drop onto a specific folder
			ftDragData = null;
			var dt = e.originalEvent.dataTransfer;
			if (dt && dt.files && dt.files.length > 0) {
				ftHandleOsFileDrop(treeId, dt.files, targetFolder);
			}
		});

		// --- OS file drop on tree container ---
		$(document).on("dragover", ".pkg-file-tree", function(e) {
			e.preventDefault();
			e.originalEvent.dataTransfer.dropEffect = ftDragData ? 'move' : 'copy';
			$(this).addClass("ft-dragover");
		});

		$(document).on("dragleave", ".pkg-file-tree", function(e) {
			// Only remove if we actually left the container (not entering a child)
			var rect = this.getBoundingClientRect();
			var x = e.originalEvent.clientX;
			var y = e.originalEvent.clientY;
			if (x <= rect.left || x >= rect.right || y <= rect.top || y >= rect.bottom) {
				$(this).removeClass("ft-dragover");
			}
		});

		$(document).on("drop", ".pkg-file-tree", function(e) {
			e.preventDefault();
			$(this).removeClass("ft-dragover");
			$(".ft-drop-target").removeClass("ft-drop-target");

			var treeId = $(this).attr("id");

			if (ftDragData) {
				if (ftDragData.treeId === treeId) {
					// Same-tree: drop on container background = move to root
					var state = ftGetTreeState(treeId);
					if (state) {
						ftDragData.filePaths.forEach(function(fp) {
							state.clearRelPath(fp);
						});
						ftDragData = null;
						state.update();
					}
				} else {
					// Cross-tree move to root of target tree
					ftCrossTreeMove(ftDragData.treeId, treeId, ftDragData.filePaths, '');
					ftDragData = null;
				}
				return;
			}

			ftDragData = null;
			var dt = e.originalEvent.dataTransfer;
			if (dt && dt.files && dt.files.length > 0) {
				ftHandleOsFileDrop(treeId, dt.files, '');
			}
		});

		/**
		 * Move files from one tree to another (cross-tree drag and drop).
		 * Removes files from the source tree and adds them to the target tree.
		 * @param {string} srcTreeId - Source tree container ID
		 * @param {string} dstTreeId - Destination tree container ID
		 * @param {string[]} filePaths - Absolute file paths being moved
		 * @param {string} targetFolder - Folder path within destination tree ('' = root)
		 */
		function ftCrossTreeMove(srcTreeId, dstTreeId, filePaths, targetFolder) {
			var srcState = ftGetTreeState(srcTreeId);
			var dstState = ftGetTreeState(dstTreeId);
			if (!srcState || !dstState) return;

			var srcFiles = srcState.files();
			var dstFiles = dstState.files();

			filePaths.forEach(function(fp) {
				// Remove from source
				var idx = srcFiles.indexOf(fp);
				if (idx !== -1) {
					srcFiles.splice(idx, 1);
					srcState.clearRelPath(fp);
				}
				// Add to destination (avoid duplicates)
				if (dstFiles.indexOf(fp) === -1) {
					dstFiles.push(fp);
					if (targetFolder) {
						dstState.setRelPath(fp, targetFolder + '/' + path.basename(fp));
					}
				}
			});

			srcState.update();
			dstState.update();
		}

		/**
		 * Handle files dropped from the OS file system into a tree container.
		 * @param {string} treeId - The tree container ID
		 * @param {FileList} fileList - The dropped files (NW.js provides .path)
		 * @param {string} targetFolder - Target folder within the tree ('' = root)
		 */
		function ftHandleOsFileDrop(treeId, fileList, targetFolder) {
			var state = ftGetTreeState(treeId);
			if (!state) return;
			var files = state.files();

			for (var i = 0; i < fileList.length; i++) {
				var filePath = fileList[i].path;
				if (!filePath) continue;

				try {
					var stat = fs.statSync(filePath);
				} catch(e) { continue; }

				if (stat.isDirectory()) {
					// Recursively add all files from the folder
					var allFiles = getFilesRecursive(filePath, filePath);
					allFiles.forEach(function(fileInfo) {
						if (files.indexOf(fileInfo.absolutePath) === -1) {
							files.push(fileInfo.absolutePath);
							var relDir = path.dirname(fileInfo.relativePath).replace(/\\/g, '/');
							var rel = (targetFolder ? targetFolder + '/' : '') +
								(relDir && relDir !== '.' ? relDir + '/' : '') +
								path.basename(fileInfo.absolutePath);
							state.setRelPath(fileInfo.absolutePath, rel);
						}
					});
				} else if (stat.isFile()) {
					if (files.indexOf(filePath) === -1) {
						files.push(filePath);
						if (targetFolder) {
							state.setRelPath(filePath, targetFolder + '/' + path.basename(filePath));
						}
					}
				}
			}

			state.update();
		}

		// Prevent default browser file drop behavior on the whole document
		$(document).on("dragover", function(e) { e.preventDefault(); });
		$(document).on("drop", function(e) { e.preventDefault(); });

		// ---- Reset form ----
		// Track whether restricted OEM author was already authorized for this session
		var pkg_oemAuthorized = false;

		// ---- Author/Organization field restriction: warn or allow based on developer mode ----
		$(document).on("blur", "#pkg-author, #pkg-organization", async function() {
			var fieldVal = $(this).val().trim();
			if (isRestrictedAuthor(fieldVal)) {
				if (_oemSessionUnlocked) {
					// Developer mode active – allow restricted names
					pkg_oemAuthorized = true;
				} else {
					// Not in developer mode – show warning and clear field
					$("#restrictedAuthorWarningModal").modal("show");
					$(this).val('');
					pkg_oemAuthorized = false;
				}
			} else if (!isRestrictedAuthor($('#pkg-author').val().trim()) && !isRestrictedAuthor($('#pkg-organization').val().trim())) {
				pkg_oemAuthorized = false;
			}
		});

		// Show popup when user clicks the disabled create button wrapper
		$(document).on("click", "#pkg-create-wrapper", function() {
			if ($("#pkg-create").prop("disabled")) {
				var reason = $(this).attr("title") || 'Cannot create package.';
				alert(reason);
				$("#pkg-version").focus();
			}
		});

		$(document).on("click", "#pkg-reset", function() {
			$("#pkg-author").val('');
			$("#pkg-organization").val('');
			$("#pkg-version").val('').removeClass("version-duplicate");
			$("#pkg-version-warning").addClass("d-none");
			pkgSetCreateEnabled(true);
			$("#pkg-venus-compat").val('');
			$("#pkg-description").val('');
			$("#pkg-github-url").val('');
			$("#pkg-changelog").val('');
			$(".pkg-changelog-card").addClass("d-none");
			$("#pkg-tags").val('');
			$("#pkg-library-name").val('').prop("readonly", true).css({"background-color": "#e9ecef", "cursor": "default"});
			$("#pkg-toggle-name-edit").html('<i class="fas fa-pencil-alt"></i>').attr("title", "Override auto-detected name");
			$("#pkg-name-warning").addClass("d-none");
			$("#pkg-name-hint").removeClass("d-none");
			$("#pkg-name-autocomplete").addClass("d-none").empty();
			pkg_autocompleteActive = false;
			pkg_autoDetectedName = "";
			pkg_nameOverridden = false;
			pkg_oemAuthorized = false;
			pkg_libraryFiles = [];
			pkg_demoMethodFiles = [];
			pkg_fileRelPaths = {};
			pkg_fileCustomDirs = {};
			pkg_installSubdir = null;
			pkg_iconFilePath = null;
			pkg_iconAutoDetected = false;
			pkg_iconAutoDetectedPath = null;
			pkg_iconDismissedAuto = false;
			pkg_comRegisterDlls = [];
			pkg_installerFilePath = null;
			pkg_defaultHelpFile = null;
			pkg_labwareFiles = [];
			pkg_labwareSubdirs = {};
			pkg_labwareEmptyFolders = [];
			pkg_binFiles = [];
			pkg_binSubdirs = {};
			pkg_binEmptyFolders = [];
			pkg_libEmptyFolders = [];
			pkg_demoEmptyFolders = [];
			_pkgLastClickedRow = {};
			$(".pkg-installer-detail").hide();
			$(".pkg-installer-empty-msg").show();
			$(".pkg-installer-filename").text('');
			$("#pkg-installer-description").val('');
			pkg_installSubdir = null;
			pkgUpdateLibFileList();
			pkgUpdateDemoFileList();
			pkgUpdateLabwareFileList();
			pkgUpdateBinFileList();
			$("#pkg-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
			$("#pkg-icon-name").text("No image selected");
			$("#pkg-removeIcon").hide();
		});

		// ---- Create Package button ----
		$(document).on("click", "#pkg-create", function() {
			// Validate required fields
			var author = $("#pkg-author").val().trim();
			var organization = $("#pkg-organization").val().trim();
			var version = $("#pkg-version").val().trim();
			var venusCompat = $("#pkg-venus-compat").val().trim();
			var description = $("#pkg-description").val().trim();

			var authorCheck = shared.isValidAuthorName(author);
			if (!authorCheck.valid) {
				alert(authorCheck.reason);
				$("#pkg-author").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			var orgCheck = shared.isValidOrganizationName(organization);
			if (!orgCheck.valid) {
				alert(orgCheck.reason);
				$("#pkg-organization").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (!version) {
				alert("Library Version Number is required.");
				$("#pkg-version").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (!venusCompat) {
				alert("VENUS Compatibility is required.");
				$("#pkg-venus-compat").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (!description) {
				alert("Description is required.");
				$("#pkg-description").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}

			// Validate GitHub Repository URL (optional, but must be valid if provided)
			var githubUrl = $("#pkg-github-url").val().trim();
			if (githubUrl) {
				var ghResult = shared.validateGitHubRepoUrl(githubUrl);
				if (!ghResult.valid) {
					alert("Invalid GitHub Repository URL:\n" + ghResult.reason);
					$("#pkg-github-url").focus().css({"border": "1px solid red", "background": "#FFCECE"});
					return;
				}
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
			for (var i = 0; i < pkg_labwareFiles.length; i++) {
				if (!fs.existsSync(pkg_labwareFiles[i])) {
					alert("Labware file not found:\n" + pkg_labwareFiles[i]);
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
			if (!isValidLibraryName(libName)) {
				alert('Invalid library name: "' + libName + '".\nLibrary names can only contain letters, numbers, spaces, dashes, and underscores.');
				$("#pkg-library-name").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}

			// Warn if any user-created folders are empty
			var emptyFolders = ftCollectEmptyFolders();
			if (emptyFolders.length > 0) {
				var folderList = emptyFolders.map(function(ef) { return '  \u2022 ' + ef.tree + ': ' + ef.folder; }).join('\n');
				if (!confirm('The following folders are empty and will create empty directories in the package:\n\n' + folderList + '\n\nDo you want to continue?')) {
					return;
				}
			}

			// Set default filename and trigger save dialog
			$("#pkg-save-dialog").attr("nwsaveas", libName + "_v" + version + ".hxlibpkg");
			$("#pkg-save-dialog").trigger("click");
		});

		// ---- Change Path button (unsigned library) ----
		var _fpEditContext = '';

		$(document).on("click", "#ulib-changeLibPath", function() {
			_fpEditContext = 'ulib';
			var libName = $("#ulib-name").val().trim() || "";
			var currentPath = (ulib_installSubdir !== null) ? ulib_installSubdir : libName;
			$("#fpedit-path-input").val(currentPath);
			fpEditUpdatePreview();
			$("#filePathEditModal").modal("show");
		});

		// Live preview update as user types in the path input
		$(document).on("input", "#fpedit-path-input", function() {
			fpEditUpdatePreview();
		});

		function fpEditUpdatePreview() {
			var subdir = $("#fpedit-path-input").val().trim().replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');
			if (subdir) {
				$(".filepath-edit-preview").text('...\\Hamilton\\Library\\' + subdir + '\\');
			} else {
				$(".filepath-edit-preview").text('...\\Hamilton\\Library\\');
			}
		}

		// Apply path change
		$(document).on("click", ".btn-filepath-edit-apply", function() {
			var subdir = $("#fpedit-path-input").val().trim().replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');
			if (subdir) {
				var subdirCheck = shared.isValidSubdirPath(subdir);
				if (!subdirCheck.valid) {
					alert(subdirCheck.reason);
					return;
				}
			}
			if (_fpEditContext === 'pkg') {
				var libName = $("#pkg-library-name").val().trim() || "";
				pkg_installSubdir = (subdir === libName) ? null : subdir;
				pkgUpdatePathPlaceholders(libName);
			} else {
				var libName = $("#ulib-name").val().trim() || "";
				ulib_installSubdir = (subdir === libName) ? null : subdir;
				ulibUpdateInstallPathHint();
			}
			$("#filePathEditModal").modal("hide");
		});

		/**
		 * Load the directory browser for a given prefix ("pkg" or "ulib").
		 * Reads subdirectories from the Library folder and renders them as
		 * clickable items. The user can navigate into subdirectories or type
		 * a new path.
		 */
		function pkgDirBrowserLoad(prefix) {
			var $browser = $("#" + prefix + "-dir-browser");
			var $breadcrumb = $("#" + prefix + "-dir-breadcrumb");
			var $input = $("#" + prefix + "-custom-subdir");
			var currentSubdir = $input.val().trim().replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');

			var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
			var libBaseDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : "C:\\Program Files (x86)\\HAMILTON\\Library";

			var browseDir = libBaseDir;
			if (currentSubdir) {
				browseDir = path.join(libBaseDir, currentSubdir);
			}

			// Build breadcrumb
			var crumbs = '<span class="pkg-dir-crumb pkg-dir-crumb-root" data-path="" data-prefix="' + prefix + '">Library</span>';
			if (currentSubdir) {
				var parts = currentSubdir.split('\\');
				var accumulated = '';
				for (var i = 0; i < parts.length; i++) {
					if (!parts[i]) continue;
					accumulated += (accumulated ? '\\' : '') + parts[i];
					crumbs += '<span class="pkg-dir-sep"><i class="fas fa-chevron-right"></i></span>';
					if (i === parts.length - 1) {
						crumbs += '<span class="pkg-dir-crumb pkg-dir-crumb-active">' + escapeHtml(parts[i]) + '</span>';
					} else {
						crumbs += '<span class="pkg-dir-crumb" data-path="' + escapeHtml(accumulated) + '" data-prefix="' + prefix + '">' + escapeHtml(parts[i]) + '</span>';
					}
				}
			}
			$breadcrumb.html(crumbs);

			// Read subdirectories
			var subdirs = [];
			try {
				if (fs.existsSync(browseDir)) {
					var entries = fs.readdirSync(browseDir, { withFileTypes: true });
					for (var j = 0; j < entries.length; j++) {
						if (entries[j].isDirectory() && !entries[j].name.startsWith('.')) {
							subdirs.push(entries[j].name);
						}
					}
					subdirs.sort(function(a, b) { return a.localeCompare(b, undefined, { sensitivity: 'base' }); });
				}
			} catch (e) {
				// Directory may not exist yet - that's fine
			}

			var html = '';
			if (subdirs.length === 0) {
				html = '<div class="pkg-dir-browser-empty text-muted text-center py-2"><i class="fas fa-folder-open mr-1"></i>No subdirectories found</div>';
			} else {
				for (var k = 0; k < subdirs.length; k++) {
					var subPath = currentSubdir ? (currentSubdir + '\\' + subdirs[k]) : subdirs[k];
					html += '<div class="pkg-dir-item" data-path="' + escapeHtml(subPath) + '" data-prefix="' + prefix + '">' +
						'<i class="fas fa-folder pkg-dir-item-icon"></i>' +
						'<span class="pkg-dir-item-name">' + escapeHtml(subdirs[k]) + '</span>' +
						'</div>';
				}
			}
			$browser.html(html);
		}

		// Click a directory entry to navigate into it or select it
		$(document).on("dblclick", ".pkg-dir-item:not(.pkg-dir-item-new)", function() {
			var subPath = $(this).attr("data-path");
			var prefix = $(this).attr("data-prefix");
			$("#" + prefix + "-custom-subdir").val(subPath);
			pkgDirBrowserLoad(prefix);
			if (prefix === "pkg") {
				var libName = $("#pkg-library-name").val().trim();
				pkgUpdatePathPlaceholders(libName);
			} else if (prefix === "fpedit") {
				fpEditUpdatePreview();
			} else {
				ulibUpdateInstallPathHint();
			}
		});

		// Single click selects the directory (sets the input value)
		$(document).on("click", ".pkg-dir-item:not(.pkg-dir-item-new)", function() {
			var subPath = $(this).attr("data-path");
			var prefix = $(this).attr("data-prefix");
			$("#" + prefix + "-dir-browser .pkg-dir-item").removeClass("selected");
			$(this).addClass("selected");
			$("#" + prefix + "-custom-subdir").val(subPath);
			if (prefix === "pkg") {
				var libName = $("#pkg-library-name").val().trim();
				pkgUpdatePathPlaceholders(libName);
			} else if (prefix === "fpedit") {
				fpEditUpdatePreview();
			} else {
				ulibUpdateInstallPathHint();
			}
		});

		// Click a breadcrumb to navigate up
		$(document).on("click", ".pkg-dir-crumb:not(.pkg-dir-crumb-active)", function() {
			var subPath = $(this).attr("data-path");
			var prefix = $(this).attr("data-prefix");
			$("#" + prefix + "-custom-subdir").val(subPath);
			pkgDirBrowserLoad(prefix);
			if (prefix === "pkg") {
				var libName = $("#pkg-library-name").val().trim();
				pkgUpdatePathPlaceholders(libName);
			} else if (prefix === "fpedit") {
				fpEditUpdatePreview();
			} else {
				ulibUpdateInstallPathHint();
			}
		});

		// Clear red styling when user types in required fields
		$(document).on("input", "#pkg-author, #pkg-organization, #pkg-version, #pkg-venus-compat, #pkg-description, #pkg-github-url", function() {
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
					// No logo asset - pass through source image as-is
					resolve({ base64: sourceB64 || null, mime: sourceMime || null });
					return;
				}

				var logoB64 = fs.readFileSync(LM_LOGO_GRAY_PATH).toString('base64');
				var logoImg = new Image();
				logoImg.onload = function() {
					if (sourceB64 && sourceMime) {
						// User provided an image - composite with logo overlay
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
						// No user image - use grayscale logo at full size
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
				var organization = $("#pkg-organization").val().trim();

				// Check restricted author/organization name
				if ((isRestrictedAuthor(author) || isRestrictedAuthor(organization)) && !_oemSessionUnlocked) {
					$("#restrictedAuthorWarningModal").modal("show");
					return;
				}
				var version = $("#pkg-version").val().trim();
				var venusCompat = $("#pkg-venus-compat").val().trim();
				var description = $("#pkg-description").val().trim();
				var githubUrl = $("#pkg-github-url").val().trim();
				var tagsRaw = $("#pkg-tags").val().trim();

				// Parse and sanitize tags (lowercase, spaces allowed)
				var tags = [];
				if (tagsRaw) {
					tagsRaw.split(",").forEach(function(t) {
						var s = shared.sanitizeTag(t);
						if (s) tags.push(s);
					});
				}

				// Filter reserved tags (system, OEM, and restricted company names are not allowed)
				var tagCheck = shared.filterReservedTags(tags);
				if (tagCheck.removed.length > 0) {
					showTagValidationErrorModal('The following tags are reserved and cannot be used: ' + tagCheck.removed.join(', ') + '\n\nThese tags have been automatically removed.');
					tags = tagCheck.filtered;
				}
				$("#pkg-tags").val(tags.join(", "));

				// Use library name from the detected field
				var libName = $("#pkg-library-name").val().trim() || "Unknown";

				// Find matching BMP image (same name as .hsl file) - auto-detect fallback
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
							} catch(e) {
								console.warn('Could not read BMP icon ' + path.basename(pkg_libraryFiles[i]) + ': ' + e.message);
								libImageFilename = null;
							}
							break;
						}
					}
				}

				// ---- Composite the library icon with grayscale LM logo overlay ----
				// The composited icon (with LM logo overlay) is used ONLY for the
				// icon/ directory inside the package ZIP - this is what Windows shows
				// for the .hxlibpkg file in Explorer.  The manifest stores the RAW
				// (uncomposited) image so imported libraries display the original
				// library artwork without the overlay.
				var compositedIconBase64 = null;
				var compositedIconFilename = null;
				try {
					var composited = await pkgCompositeLibraryIcon(libImageBase64, libImageMime);
					if (composited && composited.base64) {
						compositedIconBase64 = composited.base64;
						compositedIconFilename = libImageFilename || (libName + '_icon.png');
						// Ensure filename ends in .png since composite always outputs PNG
						if (compositedIconFilename && !compositedIconFilename.toLowerCase().endsWith('.png')) {
							compositedIconFilename = compositedIconFilename.replace(/\.[^.]+$/, '.png');
						}
					}
				} catch(e) {
					// Compositing failed - icon/ will use the raw image (non-critical)
					console.warn('Icon compositing failed:', e);
				}

				// Build manifest JSON (matches C# HxLibPkgManifest.ToJson() format)
				// Manifest stores the RAW library image - no overlay
				var manifest = {
					format_version: shared.FORMAT_VERSION,
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
					library_files: pkg_libraryFiles.map(function(f) { return pkg_fileRelPaths[f] || path.basename(f); }),
					demo_method_files: pkg_demoMethodFiles.map(function(f) { return pkg_fileRelPaths[f] || path.basename(f); }),
					com_register_dlls: pkg_comRegisterDlls.slice(),
					app_version: shared.getAppVersion(),
					windows_version: shared.getWindowsVersion(),
					venus_version: _cachedVENUSVersion || '',
					package_lineage: [shared.buildLineageEvent('created', {
						username: getWindowsUsername(),
						hostname: os.hostname(),
						venusVersion: _cachedVENUSVersion || ''
					})]
				};
				if (githubUrl) manifest.github_url = githubUrl;
				if (pkg_installSubdir === '') manifest.install_to_library_root = true;
				var customSubdir = (pkg_installSubdir && pkg_installSubdir !== '') ? pkg_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '') : '';
				if (customSubdir && !manifest.install_to_library_root) manifest.custom_install_subdir = customSubdir;
				var changelog = $("#pkg-changelog").val().trim();
				if (changelog) manifest.changelog = changelog;

				// Default help file (for multi-CHM libraries)
				if (pkg_defaultHelpFile) manifest.default_help_file = pkg_defaultHelpFile;

				// Labware files
				if (pkg_labwareFiles.length > 0) {
					manifest.labware_files = pkg_labwareFiles.map(function(f) {
						var subdir = pkg_labwareSubdirs[f] || '';
						var baseName = pkg_fileRelPaths[f] || path.basename(f);
						return subdir ? subdir.replace(/\\/g, '/') + '/' + baseName : baseName;
					});
				}

				// Bin files
				if (pkg_binFiles.length > 0) {
					manifest.bin_files = pkg_binFiles.map(function(f) {
						var subdir = pkg_binSubdirs[f] || '';
						var baseName = pkg_fileRelPaths[f] || path.basename(f);
						return subdir ? subdir.replace(/\\/g, '/') + '/' + baseName : baseName;
					});
				}

				// Installer executable
				if (pkg_installerFilePath && fs.existsSync(pkg_installerFilePath)) {
					manifest.installer_executable = path.basename(pkg_installerFilePath);
					var installerInfoDesc = $("#pkg-installer-description").val();
					if (installerInfoDesc && installerInfoDesc.trim()) {
						manifest.installer_info = { description: installerInfoDesc.trim() };
					}
				}

				// Sanitize all file paths in manifest to ensure only safe relative paths
				try {
					shared.sanitizeManifestFilePaths(manifest);
				} catch (e) {
					alert('Package creation aborted:\n' + e.message);
					pkgSetCreateEnabled(true);
					return;
				}

				// Create ZIP package using adm-zip
				var zip = new AdmZip();

				// Add metadata as ZIP archive comment for programmatic identification
				zip.addZipComment([libName, 'v' + version, author, organization, description].filter(Boolean).join(' | '));

				// Add manifest.json
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files under library/ directory (preserving subfolder structure)
				pkg_libraryFiles.forEach(function(fpath) {
					var relPath = pkg_fileRelPaths[fpath] || path.basename(fpath);
					zip.addLocalFile(fpath, zipSubdir('library', relPath));
				});

				// Add composited icon under icon/ directory (for Windows file system display)
				var iconDataForZip = compositedIconBase64 || libImageBase64;
				if (iconDataForZip) {
					var iconFilename = compositedIconFilename || libImageFilename || (libName + '_icon.png');
					zip.addFile("icon/" + iconFilename, Buffer.from(iconDataForZip, 'base64'));
				}

				// Add demo method files under demo_methods/ directory (preserving subfolder structure)
				pkg_demoMethodFiles.forEach(function(fpath) {
					var relPath = pkg_fileRelPaths[fpath] || path.basename(fpath);
					zip.addLocalFile(fpath, zipSubdir('demo_methods', relPath));
				});

				// Add labware files under labware/ directory (preserving subdirectory assignments)
				pkg_labwareFiles.forEach(function(fpath) {
					var subdir = pkg_labwareSubdirs[fpath] || '';
					var zipDir = subdir ? 'labware/' + subdir.replace(/\\/g, '/') : 'labware';
					zip.addLocalFile(fpath, zipDir);
				});

				// Add bin files under bin/ directory (preserving subdirectory assignments)
				pkg_binFiles.forEach(function(fpath) {
					var subdir = pkg_binSubdirs[fpath] || '';
					var zipDir = subdir ? 'bin/' + subdir.replace(/\\/g, '/') : 'bin';
					zip.addLocalFile(fpath, zipDir);
				});

				// Add installer executable under installer/ directory
				if (pkg_installerFilePath && fs.existsSync(pkg_installerFilePath)) {
					zip.addLocalFile(pkg_installerFilePath, 'installer');
				}

				// Sign the package for integrity verification
				var pkgUseCodeSigning = $("#chk-pkg-sign").is(":checked");
				var sigResult = applyPackageSigning(zip, pkgUseCodeSigning);

				// Wrap in binary container and write
				fs.writeFileSync(savePath, packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

				// Write package metadata to NTFS Alternate Data Stream for Windows identification
				try {
					var metaSummary = 'Library: ' + libName + '\r\n' +
						'Version: ' + version + '\r\n' +
						'Author: ' + author + '\r\n' +
						(organization ? 'Organization: ' + organization + '\r\n' : '') +
						'Description: ' + description + '\r\n' +
						'VENUS Compatibility: ' + venusCompat + '\r\n' +
						(githubUrl ? 'GitHub: ' + githubUrl + '\r\n' : '') +
						(tags.length > 0 ? 'Tags: ' + tags.join(', ') + '\r\n' : '') +
						'Created: ' + manifest.created_date + '\r\n' +
						'Library Files: ' + pkg_libraryFiles.length + '\r\n' +
						'Demo Files: ' + pkg_demoMethodFiles.length + '\r\n' +
						'Labware Files: ' + pkg_labwareFiles.length + '\r\n' +
						'Bin Files: ' + pkg_binFiles.length;
					fs.writeFileSync(savePath + ':package.metadata', metaSummary);
				} catch (_) { /* ADS write not critical - may fail on non-NTFS */ }

				// ---- Audit trail entry ----
				try {
					var auditData = {
						library_name:    libName,
						version:         version || '',
						author:          author || '',
						organization:    organization || '',
						description:     description || '',
						venus_compatibility: venusCompat || '',
						github_url:      githubUrl || '',
						tags:            tags.length > 0 ? tags.join(', ') : '',
						changelog:       changelog || '',
						output_file:     savePath,
						library_files:   pkg_libraryFiles.length,
						library_file_names: pkg_libraryFiles.map(function(f) { return path.basename(f); }).join(', '),
						demo_files:      pkg_demoMethodFiles.length,
						demo_file_names: pkg_demoMethodFiles.map(function(f) { return path.basename(f); }).join(', '),
						labware_files:   pkg_labwareFiles.length,
						labware_file_names: pkg_labwareFiles.map(function(f) { return path.basename(f); }).join(', '),
						bin_files:       pkg_binFiles.length,
						bin_file_names:  pkg_binFiles.map(function(f) { return path.basename(f); }).join(', '),
						com_dlls:        (manifest.com_register_dlls || []),
						install_to_root: !!manifest.install_to_library_root,
						custom_install_subdir: manifest.custom_install_subdir || '',
						icon_file:       libImageFilename || 'None'
					};
					if (sigResult.codeSigned) {
						auditData.code_signing_publisher = sigResult.publisher;
						auditData.code_signing_key_id = sigResult.keyId;
					}
					appendAuditTrailEntry(buildAuditTrailEntry('package_created', auditData));
				} catch(_) { /* non-critical */ }

				showGenericSuccessModal({
					title: "Package Created Successfully!",
					name: libName,
					detail: pkg_libraryFiles.length + " library file" + (pkg_libraryFiles.length !== 1 ? "s" : "") + ", " + pkg_demoMethodFiles.length + " demo method file" + (pkg_demoMethodFiles.length !== 1 ? "s" : "") + ", " + pkg_labwareFiles.length + " labware file" + (pkg_labwareFiles.length !== 1 ? "s" : "") + (pkg_binFiles.length > 0 ? ", " + pkg_binFiles.length + " bin file" + (pkg_binFiles.length !== 1 ? "s" : "") : ""),
					paths: [
						{ label: "Saved To", value: savePath }
					]
				});

				// Clear the form so the user knows the operation completed
				$('#pkg-reset').trigger('click');

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
			// ─── CRITICAL: Always use the 32-bit (x86) .NET Framework ───────────────
			// Hamilton VENUS 6 is a 32-bit (x86) application.  COM DLLs MUST be
			// registered with the 32-bit RegAsm.exe from
			//   C:\Windows\Microsoft.NET\Framework\   (32-bit)
			// and NEVER from
			//   C:\Windows\Microsoft.NET\Framework64\  (64-bit)
			// Using the 64-bit RegAsm registers COM objects in the 64-bit registry
			// hive, which is invisible to 32-bit VENUS and will cause runtime errors.
			// ─────────────────────────────────────────────────────────────────────────
			var frameworkDir = "C:\\Windows\\Microsoft.NET\\Framework\\";
			if (!fs.existsSync(frameworkDir)) return null;

			// Find the latest version directory containing RegAsm.exe
			var dirs = fs.readdirSync(frameworkDir).filter(function(d) {
				return d.match(/^v\d/);
			}).sort().reverse();

			for (var i = 0; i < dirs.length; i++) {
				var regasm = path.join(frameworkDir, dirs[i], "RegAsm.exe");
				if (fs.existsSync(regasm)) {
					// Defensive: reject if the resolved path somehow contains Framework64
					if (/Framework64/i.test(regasm)) {
						console.error('[COM] BLOCKED: Resolved RegAsm path is 64-bit (' + regasm + '). VENUS requires 32-bit.');
						continue;
					}
					return regasm;
				}
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
					resolve({success: false, error: "32-bit RegAsm.exe not found in C:\\Windows\\Microsoft.NET\\Framework\\.\nEnsure .NET Framework (x86) is installed. Do NOT use Framework64."});
					return;
				}

				if (!fs.existsSync(dllPath)) {
					resolve({success: false, error: "DLL file not found: " + dllPath});
					return;
				}

				// Validate the DLL path to prevent command injection via crafted manifest
				if (/[&|><`%\r\n]/.test(dllPath) || /'/.test(dllPath)) {
					resolve({success: false, error: "DLL path contains unsafe characters: " + path.basename(dllPath)});
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
		 * Registers or unregisters multiple DLLs in a SINGLE elevated session
		 * (one UAC prompt).  Creates a combined batch script that runs RegAsm
		 * on each DLL and captures per-DLL exit codes and output so individual
		 * success/failure can still be reported.
		 *
		 * This replaces the previous sequential approach that triggered a
		 * separate UAC prompt for every DLL via comRegisterDll().
		 *
		 * @param {Array<string>} dllPaths - Full paths to DLL files
		 * @param {boolean} register - true to register, false to unregister
		 * @returns {Promise<{allSuccess: boolean, results: Array}>}
		 */
		async function comRegisterMultipleDlls(dllPaths, register) {
			if (!dllPaths || dllPaths.length === 0) {
				return {allSuccess: true, results: []};
			}

			// If only one DLL, delegate to the single-DLL function (same UX)
			if (dllPaths.length === 1) {
				var single = await comRegisterDll(dllPaths[0], register);
				return {
					allSuccess: single.success,
					results: [{dll: dllPaths[0], success: single.success, error: single.error}]
				};
			}

			var regasm = findRegAsmPath();
			if (!regasm) {
				var errMsg = "32-bit RegAsm.exe not found in C:\\Windows\\Microsoft.NET\\Framework\\.\nEnsure .NET Framework (x86) is installed. Do NOT use Framework64.";
				return {allSuccess: false, results: dllPaths.map(function(d) {
					return {dll: d, success: false, error: errMsg};
				})};
			}

			// Validate all DLL paths up-front
			for (var vi = 0; vi < dllPaths.length; vi++) {
				if (!fs.existsSync(dllPaths[vi])) {
					return {allSuccess: false, results: [{dll: dllPaths[vi], success: false, error: "DLL file not found: " + dllPaths[vi]}]};
				}
				if (/[&|><`%\r\n]/.test(dllPaths[vi]) || /'/.test(dllPaths[vi])) {
					return {allSuccess: false, results: [{dll: dllPaths[vi], success: false, error: "DLL path contains unsafe characters: " + path.basename(dllPaths[vi])}]};
				}
			}

			return new Promise(function(resolve) {
				var tmpDir = os.tmpdir();
				var stamp = Date.now() + '_' + Math.random().toString(36).slice(2, 8);
				var scriptFile = path.join(tmpDir, 'lm_regasm_batch_' + stamp + '.cmd');

				// Build a single batch script that registers ALL DLLs and captures
				// per-DLL exit codes and RegAsm output to individual temp files.
				var batLines = ['@echo off'];
				var outFiles = [];
				for (var bi = 0; bi < dllPaths.length; bi++) {
					var outFile = path.join(tmpDir, 'lm_regasm_' + stamp + '_' + bi + '.log');
					var exitFile = path.join(tmpDir, 'lm_regasm_' + stamp + '_' + bi + '.exit');
					outFiles.push({log: outFile, exit: exitFile, dll: dllPaths[bi]});

					var regasmArgs = register
						? '"' + dllPaths[bi] + '" /codebase'
						: '/u "' + dllPaths[bi] + '" /codebase';

					batLines.push('"' + regasm + '" ' + regasmArgs + ' > "' + outFile + '" 2>&1');
					batLines.push('echo %errorlevel% > "' + exitFile + '"');
				}
				batLines.push('exit /b 0');

				fs.writeFileSync(scriptFile, batLines.join('\r\n'), 'utf8');

				// Elevate the combined batch script - SINGLE UAC prompt
				var psScript = "try { $p = Start-Process -FilePath '" + scriptFile + "' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode } catch { exit 1 }";
				var fullCmd = 'powershell.exe -NoProfile -Command "' + psScript + '"';

				var exec = require('child_process').exec;
				// Scale timeout: 30s base + 15s per DLL
				var timeoutMs = 30000 + (dllPaths.length * 15000);

				exec(fullCmd, {timeout: timeoutMs}, function(error) {
					var results = [];
					var allSuccess = true;

					// Read per-DLL results from temp files
					for (var ri = 0; ri < outFiles.length; ri++) {
						var regasmOutput = '';
						var exitCode = -1;
						try { regasmOutput = fs.readFileSync(outFiles[ri].log, 'utf8').trim(); } catch(e) {}
						try {
							var exitStr = fs.readFileSync(outFiles[ri].exit, 'utf8').trim();
							exitCode = parseInt(exitStr, 10);
						} catch(e) {}

						// Clean up per-DLL temp files
						try { fs.unlinkSync(outFiles[ri].log); } catch(e) {}
						try { fs.unlinkSync(outFiles[ri].exit); } catch(e) {}

						if (error && exitCode === -1) {
							// UAC was cancelled or elevation failed - no per-DLL files written
							results.push({dll: outFiles[ri].dll, success: false, error: "The operation was cancelled or requires administrator rights."});
							allSuccess = false;
						} else if (exitCode !== 0 && exitCode !== -1) {
							var errDetail = "COM " + (register ? "registration" : "deregistration") + " failed for " + path.basename(outFiles[ri].dll) + ".";
							if (regasmOutput) errDetail += "\n" + regasmOutput;
							results.push({dll: outFiles[ri].dll, success: false, error: errDetail});
							allSuccess = false;
						} else if (exitCode === 0) {
							results.push({dll: outFiles[ri].dll, success: true, error: null});
						} else {
							results.push({dll: outFiles[ri].dll, success: false, error: "The operation was cancelled or requires administrator rights."});
							allSuccess = false;
						}
					}

					// Clean up the batch script
					try { fs.unlinkSync(scriptFile); } catch(e) {}

					resolve({allSuccess: allSuccess, results: results});
				});
			});
		}

		/**
		 * Check whether a single .NET assembly DLL is registered as a COM object
		 * in the 32-bit (WOW6432Node) registry hive.
		 *
		 * Strategy: run the 32-bit RegAsm.exe /regfile:<temp> <dll> to generate a
		 * .reg file listing the CLSIDs the DLL *would* register, then check whether
		 * those CLSIDs already exist under HKCR\WOW6432Node\CLSID (or the 32-bit
		 * view).  Falls back to a simpler heuristic if RegAsm /regfile fails.
		 *
		 * @param {string} dllPath - Full path to the .NET DLL
		 * @returns {{ registered: boolean, details: string }}
		 */
		function checkCOMRegistrationStatus(dllPath) {
			if (!fs.existsSync(dllPath)) {
				return { registered: false, details: 'DLL file not found' };
			}

			if (/[&|><`%\r\n]/.test(dllPath) || /'/.test(dllPath)) {
				return { registered: false, details: 'DLL path contains unsafe characters' };
			}

			// Use RegAsm /regfile to discover CLSIDs without actually registering
			var regasm = findRegAsmPath();
			if (!regasm) {
				return { registered: false, details: '32-bit RegAsm.exe not found' };
			}

			var tmpReg = path.join(os.tmpdir(), 'lm_comcheck_' + Date.now() + '.reg');
			try {
				execSync('"' + regasm + '" "' + dllPath + '" /regfile:"' + tmpReg + '"', {
					timeout: 15000,
					windowsHide: true,
					stdio: 'pipe'
				});
			} catch (e) {
				// RegAsm /regfile can fail if the DLL is not a valid .NET assembly
				try { fs.unlinkSync(tmpReg); } catch(_) {}
				return { registered: false, details: 'RegAsm /regfile failed: ' + (e.message || '').substring(0, 120) };
			}

			// Parse the .reg file for CLSID entries
			var regContent = '';
			try { regContent = fs.readFileSync(tmpReg, 'utf16le'); } catch(_) {
				try { regContent = fs.readFileSync(tmpReg, 'utf8'); } catch(_2) {}
			}
			try { fs.unlinkSync(tmpReg); } catch(_) {}

			var clsidPattern = /\[HKEY_CLASSES_ROOT\\CLSID\\(\{[0-9A-Fa-f\-]+\})/g;
			var clsids = [];
			var match;
			while ((match = clsidPattern.exec(regContent)) !== null) {
				if (clsids.indexOf(match[1]) === -1) clsids.push(match[1]);
			}

			if (clsids.length === 0) {
				return { registered: false, details: 'No COM CLSIDs found in DLL' };
			}

			// Check each CLSID in the 32-bit registry hive
			var registeredCount = 0;
			var missingClsids = [];
			for (var i = 0; i < clsids.length; i++) {
				// Check WOW6432Node (32-bit view on 64-bit Windows)
				var regKey = 'HKCR\\WOW6432Node\\CLSID\\' + clsids[i];
				try {
					execSync('reg query "' + regKey + '" /ve', {
						timeout: 5000,
						windowsHide: true,
						stdio: 'pipe'
					});
					registeredCount++;
				} catch (_) {
					// Also try direct HKCR\CLSID (32-bit OS or SysWOW64 redirect)
					var regKey2 = 'HKCR\\CLSID\\' + clsids[i];
					try {
						execSync('reg query "' + regKey2 + '" /ve', {
							timeout: 5000,
							windowsHide: true,
							stdio: 'pipe'
						});
						registeredCount++;
					} catch (_2) {
						missingClsids.push(clsids[i]);
					}
				}
			}

			if (registeredCount === clsids.length) {
				return { registered: true, details: registeredCount + ' of ' + clsids.length + ' CLSID(s) registered' };
			} else {
				return { registered: false, details: registeredCount + ' of ' + clsids.length + ' CLSID(s) registered; missing: ' + missingClsids.join(', ') };
			}
		}

		/**
		 * Verify COM registration status for all DLLs in a library.
		 * @param {Object} lib - installed library DB record
		 * @returns {{ allRegistered: boolean, results: Array<{dll: string, registered: boolean, details: string}> }}
		 */
		function verifyCOMRegistration(lib) {
			var comDlls = lib.com_register_dlls || [];
			if (comDlls.length === 0) return { allRegistered: true, results: [] };

			var libPath = lib.lib_install_path || '';
			var results = [];
			var allRegistered = true;

			for (var i = 0; i < comDlls.length; i++) {
				var dllFullPath = path.join(libPath, comDlls[i]);
				var status = checkCOMRegistrationStatus(dllFullPath);
				results.push({ dll: comDlls[i], registered: status.registered, details: status.details });
				if (!status.registered) allRegistered = false;
			}

			return { allRegistered: allRegistered, results: results };
		}

		//**************************************************************************************
		//******  LIBRARY IMPORTER *************************************************************
		//**************************************************************************************

		var imp_manifest = null;
		var imp_zipData = null;
		var imp_filePath = null;

		// ---- HSL function parser - delegated to shared.js ----
		var sanitizeHslForParsing = shared.sanitizeHslForParsing;
		var splitHslArgs          = shared.splitHslArgs;
		var parseHslParameter     = shared.parseHslParameter;
		var extractHslDocComment  = shared.extractHslDocComment;
		var parseHslFunctions     = shared.parseHslFunctions;
		var extractPublicFunctions = shared.extractPublicFunctions;
		var extractHslIncludes    = shared.extractHslIncludes;

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
				if (ext !== '.hsl' && ext !== '.hs_' && ext !== '.hsi') return;
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

				// 3) Check unsigned libraries (if the feature is enabled)
				if (!libraryName) {
					var unsignedLibs = getUnsignedLibraries();
					for (var ui = 0; ui < unsignedLibs.length; ui++) {
						var uuLib = unsignedLibs[ui];
						var uuFiles = uuLib.library_files || [];
						for (var uf = 0; uf < uuFiles.length; uf++) {
							var uuFileName = path.basename(uuFiles[uf]).toLowerCase();
							if (uuFileName === targetFileName) {
								libraryName = uuLib.library_name;
								depType = 'unsigned';
								break;
							}
							if (resolvedPath) {
								var uuFullPath = path.join(uuLib.lib_base_path || '', uuFiles[uf]).replace(/\\/g, '/').toLowerCase();
								if (resolvedPath.replace(/\\/g, '/').toLowerCase() === uuFullPath) {
									libraryName = uuLib.library_name;
									depType = 'unsigned';
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
			var result = { valid: true, missing: [], found: [], warnings: [] };
			(deps || []).forEach(function(dep) {
				if (dep.type === 'unknown' || !dep.fileExists) {
					result.valid = false;
					result.missing.push(dep);
				} else if (dep.type === 'unsigned') {
					// Unsigned libs satisfy the dependency but with a warning
					result.found.push(dep);
					result.warnings.push(dep);
				} else {
					result.found.push(dep);
				}
			});
			return result;
		}

		// ---- Library integrity hashing (delegated to shared module) ----
		var computeFileHash        = shared.computeFileHash;
		var parseHslMetadataFooter = shared.parseHslMetadataFooter;

		/**
		 * Verifies the integrity of a system library by checking Hamilton's
		 * built-in $$valid$$ (read-only) flag in the metadata footer.
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
			});

			return result;
		}

		// ---- Package signing & hashing (delegated to shared module) ----
		var computeLibraryHashes  = shared.computeLibraryHashes;
		var signPackageZipWithCert = shared.signPackageZipWithCert;
		var verifyPackageSignature = shared.verifyPackageSignature;
		var validatePublisherCertificate = shared.validatePublisherCertificate;
		var generateSigningKeyPair      = shared.generateSigningKeyPair;
		var buildPublisherCertificate   = shared.buildPublisherCertificate;
		var computeKeyFingerprint       = shared.computeKeyFingerprint;

		// ---- Code signing configuration helpers ----

		/**
		 * Read the default signing key/cert paths from settings.
		 * Returns { keyPath: string|null, certPath: string|null }
		 */
		function getSigningConfig() {
			var s = db_settings.settings.findOne({"_id":"0"});
			return {
				keyPath:  (s && s.signing_key_path)  || null,
				certPath: (s && s.signing_cert_path) || null
			};
		}

		/**
		 * Load the default signing credentials from disk (private key PEM + publisher cert JSON).
		 * Returns { privateKeyPem: string, publisherCert: object } or null if not configured/invalid.
		 */
		function loadDefaultSigningCredentials() {
			var cfg = getSigningConfig();
			if (!cfg.keyPath || !cfg.certPath) return null;
			try {
				if (!fs.existsSync(cfg.keyPath) || !fs.existsSync(cfg.certPath)) return null;
				var keyPem = fs.readFileSync(cfg.keyPath, 'utf8');
				var certJson = JSON.parse(fs.readFileSync(cfg.certPath, 'utf8'));
				var validation = validatePublisherCertificate(certJson);
				if (!validation.valid) return null;
				return { privateKeyPem: keyPem, publisherCert: certJson };
			} catch(e) {
				console.warn('Failed to load default signing credentials: ' + e.message);
				return null;
			}
		}

		/**
		 * Get the display info for the current signing config.
		 * Returns { configured: boolean, publisher: string, organization: string, keyId: string } or null.
		 */
		function getSigningDisplayInfo() {
			var cfg = getSigningConfig();
			if (!cfg.keyPath || !cfg.certPath) return null;
			try {
				if (!fs.existsSync(cfg.certPath)) return null;
				var certJson = JSON.parse(fs.readFileSync(cfg.certPath, 'utf8'));
				var validation = validatePublisherCertificate(certJson);
				if (!validation.valid) return null;
				return {
					configured: true,
					publisher: certJson.publisher || 'Unknown',
					organization: certJson.organization || '',
					keyId: certJson.key_id || certJson.fingerprint.substring(0, 16)
				};
			} catch(e) {
				return null;
			}
		}

		/**
		 * Update all code-signing toggle UI elements across export modals.
		 * Shows publisher info if configured, or "not configured" notice.
		 */
		function refreshSigningUI() {
			var info = getSigningDisplayInfo();

			if (!info) {
				// Hide entire code signing sections when no key pair is configured
				$(".export-signing-section").hide();
				$(".archive-signing-section").hide();
				$("#chk-pkg-sign").closest(".exporter-card").hide();
				// Uncheck signing toggles and hide their detail panels
				$(".chk-export-sign").prop("checked", false);
				$(".export-signing-detail, .pkg-signing-detail").hide();
				return;
			}

			// Show code signing sections when key pair is configured
			$(".export-signing-section").show();
			$(".archive-signing-section").show();
			$("#chk-pkg-sign").closest(".exporter-card").show();

			// Export Choice modal
			$(".export-signing-configured").show();
			$(".export-signing-not-configured").hide();
			$(".export-signing-publisher-name").text(info.publisher + (info.organization ? ' (' + info.organization + ')' : ''));
			$(".export-signing-key-id").text(info.keyId);

			// Archive signing inline
			$(".archive-signing-publisher").text(info.publisher).show();
			$(".archive-signing-not-configured").hide();

			// Create Package form
			$(".pkg-signing-configured").show();
			$(".pkg-signing-not-configured").hide();
			$(".pkg-signing-publisher-name").text(info.publisher + (info.organization ? ' (' + info.organization + ')' : ''));
			$(".pkg-signing-key-id").text(info.keyId);
		}

		/**
		 * Apply code signing to a zip when the user has enabled it.
		 * Falls back to legacy HMAC-only signing if credentials are unavailable.
		 * @param {AdmZip} zip - The zip to sign
		 * @param {boolean} useCodeSigning - Whether user toggled code signing on
		 * @returns {{ codeSigned: boolean, publisher: string|null, keyId: string|null }}
		 */
		function applyPackageSigning(zip, useCodeSigning) {
			if (useCodeSigning) {
				var creds = loadDefaultSigningCredentials();
				if (creds) {
					signPackageZipWithCert(zip, creds.privateKeyPem, creds.publisherCert);
					return {
						codeSigned: true,
						publisher: creds.publisherCert.publisher || null,
						keyId: creds.publisherCert.key_id || null
					};
				}
			}
			// No signing credentials available - leave package unsigned
			return { codeSigned: false, publisher: null, keyId: null };
		}

		// ---- Toggle handlers for code signing checkboxes ----
		$(document).on("change", ".chk-export-sign", function() {
			var isChecked = $(this).is(":checked");
			var $modal = $(this).closest(".modal, .exporter-container, .modal-footer, .export-signing-section, .archive-signing-section, .card-body");
			// Show/hide the detail section
			$modal.find(".export-signing-detail, .pkg-signing-detail").toggle(isChecked);
			// For archive inline, nothing extra to toggle
		});

		// "Configure in Settings" link in export modals
		$(document).on("click", ".export-signing-open-settings", function(e) {
			e.preventDefault();
			// Close any open modal
			$(".modal").modal("hide");
			// Open settings modal
			setTimeout(function() { $("#settingsModal").modal("show"); }, 350);
		});

		// ---- Settings: Code Signing configuration ----

		// Browse for signing key file
		$(document).on("click", ".btn-browse-signing-key", function() {
			$("#settings-signing-key-picker").trigger("click");
		});
		$(document).on("change", "#settings-signing-key-picker", function() {
			var filePath = $(this).val();
			if (!filePath) return;
			$(this).val('');
			$(".settings-signing-key-path").val(filePath);
			saveSetting("signing_key_path", filePath);
			refreshSettingsSigningStatus();
			refreshSigningUI();
		});

		// Browse for signing certificate file
		$(document).on("click", ".btn-browse-signing-cert", function() {
			$("#settings-signing-cert-picker").trigger("click");
		});
		$(document).on("change", "#settings-signing-cert-picker", function() {
			var filePath = $(this).val();
			if (!filePath) return;
			$(this).val('');
			$(".settings-signing-cert-path").val(filePath);
			saveSetting("signing_cert_path", filePath);
			refreshSettingsSigningStatus();
			refreshSigningUI();
		});

		// Clear signing configuration
		$(document).on("click", ".btn-clear-signing-config", function() {
			$(".settings-signing-key-path").val('');
			$(".settings-signing-cert-path").val('');
			saveSetting("signing_key_path", '');
			saveSetting("signing_cert_path", '');
			refreshSettingsSigningStatus();
			refreshSigningUI();
		});

		// Generate key pair from Settings
		$(document).on("click", ".btn-generate-keypair", function() {
			// Prompt for publisher name
			var publisher = prompt("Enter a publisher name for the certificate:\n(e.g. your name or organization)");
			if (!publisher || !publisher.trim()) return;
			publisher = publisher.trim();
			var organization = prompt("Enter an organization name (optional):\nLeave blank to skip.");
			organization = (organization || '').trim();

			// Ask where to save
			$("#settings-keypair-output-dir").trigger("click");
			// Store publisher/org for use in change handler
			$("#settings-keypair-output-dir").data("publisher", publisher);
			$("#settings-keypair-output-dir").data("organization", organization);
		});

		$(document).on("change", "#settings-keypair-output-dir", function() {
			var outputDir = $(this).val();
			if (!outputDir) return;
			$(this).val('');
			var publisher = $(this).data("publisher") || '';
			var organization = $(this).data("organization") || '';
			if (!publisher) return;

			try {
				// Generate the key pair
				var keyPair = generateSigningKeyPair();
				var cert = buildPublisherCertificate(publisher, organization || undefined, keyPair.publicKeyRaw);

				// Build filenames
				var safeName = publisher.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
				if (!safeName) safeName = 'publisher';
				var keyFileName = safeName + '.key.pem';
				var certFileName = safeName + '.cert.json';
				var keyPath = path.join(outputDir, keyFileName);
				var certPath = path.join(outputDir, certFileName);

				// Check for overwrite
				if (fs.existsSync(keyPath) || fs.existsSync(certPath)) {
					if (!confirm('Files already exist in this folder:\n' + keyFileName + '\n' + certFileName + '\n\nOverwrite?')) return;
				}

				// Write files
				fs.writeFileSync(keyPath, keyPair.privateKeyPem, 'utf8');
				fs.writeFileSync(certPath, JSON.stringify(cert, null, 2), 'utf8');

				// Auto-configure as default signing key
				saveSetting("signing_key_path", keyPath);
				saveSetting("signing_cert_path", certPath);
				$(".settings-signing-key-path").val(keyPath);
				$(".settings-signing-cert-path").val(certPath);

				refreshSettingsSigningStatus();
				refreshSigningUI();

				alert('Key pair generated successfully!\n\nPrivate Key: ' + keyPath + '\nCertificate: ' + certPath + '\n\nConfigured as the default signing key.\n\nIMPORTANT: Keep the private key (.key.pem) file secure. Never share it. Only distribute the certificate (.cert.json) file.');
			} catch(e) {
				alert('Error generating key pair:\n' + e.message);
			}
		});

		/**
		 * Refresh the Settings modal code signing status display.
		 */
		function refreshSettingsSigningStatus() {
			var cfg = getSigningConfig();
			$(".settings-signing-key-path").val(cfg.keyPath || '');
			$(".settings-signing-cert-path").val(cfg.certPath || '');
			$(".settings-signing-status").hide();
			$(".settings-signing-error").hide();
			$(".btn-clear-signing-config").toggle(!!(cfg.keyPath || cfg.certPath));

			if (!cfg.keyPath && !cfg.certPath) return;

			// Validate the config
			var errors = [];
			if (cfg.keyPath && !fs.existsSync(cfg.keyPath)) errors.push('Private key file not found: ' + cfg.keyPath);
			if (cfg.certPath && !fs.existsSync(cfg.certPath)) errors.push('Certificate file not found: ' + cfg.certPath);
			if (!cfg.keyPath) errors.push('Private key file not configured');
			if (!cfg.certPath) errors.push('Certificate file not configured');

			if (errors.length > 0) {
				$(".settings-signing-error-text").text(errors.join('; '));
				$(".settings-signing-error").show();
				return;
			}

			try {
				var certJson = JSON.parse(fs.readFileSync(cfg.certPath, 'utf8'));
				var validation = validatePublisherCertificate(certJson);
				if (!validation.valid) {
					$(".settings-signing-error-text").text('Invalid certificate: ' + (validation.errors || []).join('; '));
					$(".settings-signing-error").show();
					return;
				}
				$(".settings-signing-publisher").text(certJson.publisher || 'Unknown Publisher');
				$(".settings-signing-key-id").text(certJson.key_id || certJson.fingerprint.substring(0, 16));
				if (certJson.organization) {
					$(".settings-signing-org").text(certJson.organization).show();
				} else {
					$(".settings-signing-org").hide();
				}
				$(".settings-signing-status").show();
			} catch(e) {
				$(".settings-signing-error-text").text('Error reading certificate: ' + e.message);
				$(".settings-signing-error").show();
			}
		}

		// ---- Binary container format (delegated to shared module) ----
		var CONTAINER_MAGIC_PKG   = shared.CONTAINER_MAGIC_PKG;
		var CONTAINER_MAGIC_ARC   = shared.CONTAINER_MAGIC_ARC;
		var packContainer         = shared.packContainer;
		var unpackContainer       = shared.unpackContainer;

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

		// ---- Integrity / dependency result caches ----
		// These are cleared whenever libraries are installed, deleted, or reimported.
		var _integrityCache = {};   // lib._id -> verifyLibraryIntegrity() result
		var _depCache = {};         // lib._id -> extractRequiredDependencies() result
		function invalidateLibCaches() { _integrityCache = {}; _depCache = {}; markSearchIndexDirty(); }

		// ---- Sort helpers for library cards ----
		function applyLibrarySort(libs, order) {
			if (!libs || libs.length === 0) return;
			switch (order) {
				case 'az':
					libs.sort(function(a, b) { return (a.library_name || '').localeCompare(b.library_name || '', undefined, {sensitivity: 'base'}); });
					break;
				case 'za':
					libs.sort(function(a, b) { return (b.library_name || '').localeCompare(a.library_name || '', undefined, {sensitivity: 'base'}); });
					break;
				case 'newest':
					libs.sort(function(a, b) {
						var da = a.installed_date ? new Date(a.installed_date).getTime() : 0;
						var db = b.installed_date ? new Date(b.installed_date).getTime() : 0;
						return db - da;
					});
					break;
				case 'oldest':
					libs.sort(function(a, b) {
						var da = a.installed_date ? new Date(a.installed_date).getTime() : 0;
						var db = b.installed_date ? new Date(b.installed_date).getTime() : 0;
						return da - db;
					});
					break;
			}
		}

		function applySystemLibrarySort(sysLibs, order) {
			if (!sysLibs || sysLibs.length === 0) return;
			switch (order) {
				case 'az':
					sysLibs.sort(function(a, b) { return (a.display_name || a.canonical_name || '').localeCompare(b.display_name || b.canonical_name || '', undefined, {sensitivity: 'base'}); });
					break;
				case 'za':
					sysLibs.sort(function(a, b) { return (b.display_name || b.canonical_name || '').localeCompare(a.display_name || a.canonical_name || '', undefined, {sensitivity: 'base'}); });
					break;
				case 'newest':
					sysLibs.sort(function(a, b) {
						var da = a.installed_date ? new Date(a.installed_date).getTime() : 0;
						var db = b.installed_date ? new Date(b.installed_date).getTime() : 0;
						return db - da;
					});
					break;
				case 'oldest':
					sysLibs.sort(function(a, b) {
						var da = a.installed_date ? new Date(a.installed_date).getTime() : 0;
						var db = b.installed_date ? new Date(b.installed_date).getTime() : 0;
						return da - db;
					});
					break;
			}
		}

		// ---- Build installed library cards from DB ----
		function impBuildLibraryCards(groupId, recentMode, systemMode, unsignedMode, starredMode) {
			var $container = $("#imp-cards-container");
			$container.empty();
			invalidateLibCaches(); // refresh integrity/dependency caches for this rebuild

			// ---- Starred-only mode: render only starred library cards ----
			if (starredMode) {
				var starredIds = getStarredLibIds();
				if (!starredIds || starredIds.length === 0) {
					$container.html(
						'<div class="w-100 text-center py-5 imp-empty-state">' +
							'<i class="far fa-star fa-3x color-lightgray"></i>' +
							'<p class="text-muted mt-3">You haven\'t starred any libraries yet.<br>Click the <i class="far fa-star" style="font-size:0.9em;"></i> on a library card to add it to your favorites.</p>' +
						'</div>'
					);
					return;
				}
				// Gather starred user libs
				var starredUserLibs = [];
				var starredSysLibs = [];
				starredIds.forEach(function(sid) {
					if (isSystemLibrary(sid)) {
						var sLib = getSystemLibrary(sid);
						if (sLib) starredSysLibs.push(sLib);
					} else {
						var lib = db_installed_libs.installed_libs.findOne({"_id": sid});
						if (lib && !lib.deleted) starredUserLibs.push(lib);
					}
				});
				if (starredUserLibs.length === 0 && starredSysLibs.length === 0) {
					$container.html(
						'<div class="w-100 text-center py-5 imp-empty-state">' +
							'<i class="far fa-star fa-3x color-lightgray"></i>' +
							'<p class="text-muted mt-3">You haven\'t starred any libraries yet.<br>Click the <i class="far fa-star" style="font-size:0.9em;"></i> on a library card to add it to your favorites.</p>' +
						'</div>'
					);
					return;
				}
				// Re-use the normal card builders for each
				applyLibrarySort(starredUserLibs, _currentSortOrder);
				applySystemLibrarySort(starredSysLibs, _currentSortOrder);
				starredUserLibs.forEach(function(lib) {
					$container.append(impBuildSingleCardHtml(lib));
				});
				starredSysLibs.forEach(function(sLib) {
					$container.append(buildSystemLibraryCard(sLib));
				});
				$container.append('<div class="col-md-12 my-3"></div>');
				setTimeout(_updateCardTagOverflow, 0);
				return;
			}

			// ---- Unsigned-only mode: render only unsigned library cards ----
			if (unsignedMode) {
				var uLibs = db_unsigned_libs.unsigned_libs.find() || [];
				if (!uLibs || uLibs.length === 0) {
					$container.html(
						'<div class="w-100 text-center py-5 imp-empty-state">' +
							'<i class="far fa-times-circle fa-3x color-lightgray"></i>' +
							'<p class="text-muted mt-3">No unsigned libraries found.<br>Go to <b>Settings</b> and click <b>Scan Now</b> to discover unsigned libraries.</p>' +
						'</div>'
					);
					return;
				}
				uLibs.forEach(function(uLib) {
					$container.append(buildUnsignedLibraryCard(uLib));
				});
				$container.append('<div class="col-md-12 my-3"></div>');
				setTimeout(_updateCardTagOverflow, 0);
				return;
			}

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
				applySystemLibrarySort(sysLibs, _currentSortOrder);
				sysLibs.forEach(function(sLib) {
					$container.append(buildSystemLibraryCard(sLib));
				});
				$container.append('<div class="col-md-12 my-3"></div>');
				setTimeout(_updateCardTagOverflow, 0);
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
						// Still show system libraries that have actual integrity errors
						var sysIntegrity = verifySystemLibraryIntegrity(sysLibsAll[si]);
						if (!sysIntegrity.valid) {
							visibleSysLibs.push(sysLibsAll[si]);
						}
					} else {
						visibleSysLibs.push(sysLibsAll[si]);
					}
				}
			}
			var hasSystemCards = visibleSysLibs.length > 0;

			// Apply sort order (skip for recent mode which has its own sort)
			if (!recentMode) {
				applyLibrarySort(libs, _currentSortOrder);
				applySystemLibrarySort(visibleSysLibs, _currentSortOrder);
			}

			if ((!libs || libs.length === 0) && !hasSystemCards) {
				var emptyMsg;
				if (recentMode) {
					emptyMsg = 'No recent imports.<br>Import a <b>.hxlibpkg</b> package to see it here.';
				} else if (groupId === 'gOEM') {
					emptyMsg = 'No OEM packages installed yet.<br>Import an OEM-authored <b>.hxlibpkg</b> to see it here.';
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
						tagsHtml += '<button type="button" class="imp-tag-badge mr-1" data-tag="' + t + '"><i class="fas fa-tag mr-1"></i>' + t + '</button>';
					});
				}

				// COM warning badge
				var comWarningBadge = "";
				if (hasComWarning && comDlls.length > 0) {
					comWarningBadge = '<span class="badge badge-warning ml-2" title="COM registration failed for: ' + escapeHtml(comDlls.join(', ')) + '. This library may not function correctly."><i class="fas fa-exclamation-triangle mr-1"></i>COM</span>';
				} else if (comDlls.length > 0) {
					comWarningBadge = '<span class="badge badge-info ml-2" title="COM registered DLLs: ' + escapeHtml(comDlls.join(', ')) + '"><i class="fas fa-cog mr-1"></i>COM</span>';
				}

				// Check for CHM help files
				var helpFiles = lib.help_files || [];
				var chmHelpFiles = helpFiles.filter(function(f) { return path.extname(f).toLowerCase() === '.chm'; });
				var hasChmHelp = chmHelpFiles.length > 0;

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
							'<div class="imp-lib-card-tags mt-1">' + tagsHtml + '<span class="imp-tag-ellipsis" data-lib-id="' + lib._id + '" title="View all tags">&hellip;</span></div>' +
							'<div class="imp-lib-card-footer">' +
								(hasChmHelp ? buildCardHelpLinkHtml(chmHelpFiles, lib._id, lib.default_help_file || null, false) : '<span></span>') +
								'<span class="imp-lib-star" data-lib-id="' + lib._id + '" title="' + (isLibStarred(lib._id) ? 'Unstar' : 'Star') + '"><i class="' + (isLibStarred(lib._id) ? 'fas' : 'far') + ' fa-star"></i></span>' +
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
			setTimeout(_updateCardTagOverflow, 0);
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

			// 2) No root icon found - collect submethod icons and tile them
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
				typeBadges = '<button type="button" class="imp-tag-badge mr-1 mb-1" data-tag="system"><i class="fas fa-tag mr-1"></i>System</button>';
			} else {
				typeBadges = '<button type="button" class="imp-tag-badge mr-1 mb-1" data-tag="system"><i class="fas fa-tag mr-1"></i>System Resource</button>';
			}

			var shortDesc = fileCount + ' file' + (fileCount !== 1 ? 's' : '') + ' (' + resTypes + ')';

			// Check for CHM help files in discovered_files
			var sysChmFiles = (sLib.discovered_files || []).filter(function(f) {
				return path.extname(f).toLowerCase() === '.chm';
			}).map(function(f) {
				return f.replace(/\\/g, '/').split('/').pop();
			});
			var hasSysChmHelp = sysChmFiles.length > 0;

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

			var sysOemBadge = buildOemVerifiedBadge(sLib.author || 'Hamilton', false, null);

			var str =
				'<div class="col-md-4 col-xl-3 d-flex align-items-stretch imp-lib-card-container imp-lib-card-system-container" data-lib-id="' + sLib._id + '" data-system="true">' +
					'<div class="m-2 pl-3 pr-3 pt-3 pb-2 link-card imp-lib-card imp-lib-card-system w-100' + cardExtraClass + '"' + cardTooltipAttr + '>' +
						'<div class="d-flex align-items-start">' +
							'<div class="mr-3 mt-1 imp-lib-card-icon">' + iconHtml + '</div>' +
							'<div class="flex-grow-1" style="min-width:0;">' +
								'<h6 class="mb-0 imp-lib-card-name imp-lib-card-name-system" style="color:#6c757d;" title="' + libName.replace(/"/g, '&quot;') + '">' + libName + '</h6>' +
								'<div class="text-muted text-sm">' + author + ' ' + sysOemBadge + '</div>' +
								'<span class="badge badge-secondary mt-1" style="font-size:0.6rem;"><i class="fas fa-lock mr-1"></i>Read-Only</span>' +
							'</div>' +
						'</div>' +
						'<p class="text-muted mt-2 mb-1" style="font-size:0.85em;">' + shortDesc + '</p>' +
						'<div class="imp-lib-card-tags mt-1">' + typeBadges + '</div>' +
						'<div class="imp-lib-card-footer">' +
							buildCardHelpLinkHtml(sysChmFiles, sLib._id, null, true) +
							'<span class="imp-lib-star" data-lib-id="' + sLib._id + '" title="' + (isLibStarred(sLib._id) ? 'Unstar' : 'Star') + '"><i class="' + (isLibStarred(sLib._id) ? 'fas' : 'far') + ' fa-star"></i></span>' +
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
			var detailCert = lib.publisher_cert || null;
			var detailAuthorText = lib.author || "\u2014";
			var detailAuthorBadge = buildOemVerifiedBadge(lib.author || '', true, detailCert);
			var detailConvertedAuthorBadge = '';
			if (!detailAuthorBadge && lib.converted_from_executable) {
				detailConvertedAuthorBadge = buildConvertedBadge(true, lib.source_certificate || null, lib.conversion_source || '');
			}
			if (detailAuthorBadge || detailConvertedAuthorBadge) {
				$("#libDetailModal .lib-detail-author").html(escapeHtml(detailAuthorText) + ' ' + detailAuthorBadge + detailConvertedAuthorBadge);
			} else {
				$("#libDetailModal .lib-detail-author").text(detailAuthorText);
			}
			var detailOrgBadge = buildOemVerifiedBadge(lib.organization || '', true, detailCert);
			var detailConvertedOrgBadge = '';
			if (!detailOrgBadge && lib.converted_from_executable) {
				detailConvertedOrgBadge = buildConvertedBadge(true, lib.source_certificate || null, lib.conversion_source || '');
			}
			if (detailOrgBadge || detailConvertedOrgBadge) {
				$("#libDetailModal .lib-detail-organization").html(escapeHtml(lib.organization || "\u2014") + ' ' + detailOrgBadge + detailConvertedOrgBadge);
			} else {
				$("#libDetailModal .lib-detail-organization").text(lib.organization || "\u2014");
			}
			$("#libDetailModal .lib-detail-venus").text(lib.venus_compatibility || "\u2014");
			$("#libDetailModal .lib-detail-installed-date").text(lib.installed_date ? new Date(lib.installed_date).toLocaleString() : "\u2014");
			$("#libDetailModal .lib-detail-created-date").text(lib.created_date ? new Date(lib.created_date).toLocaleString() : "\u2014");
			$("#libDetailModal .lib-detail-installed-by").text(lib.installed_by || "\u2014");

			// Description
			if (lib.description) {
				$("#libDetailModal .lib-detail-description").text(lib.description);
				$("#libDetailModal .lib-detail-desc-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-desc-section").addClass("d-none");
			}

			// GitHub URL (respect display setting - always hidden in regulated mode)
			var ghRegulated = !!getSettingValue("chk_regulatedEnvironment");
			if (lib.github_url && !ghRegulated && getSettingValue("chk_showGitHubLinks") !== false) {
				var ghValidation = shared.validateGitHubRepoUrl(lib.github_url);
				if (ghValidation.valid) {
					$("#libDetailModal .lib-detail-github-link").attr("href", lib.github_url).text(lib.github_url);
					$("#libDetailModal .lib-detail-github-section").removeClass("d-none");
				} else {
					$("#libDetailModal .lib-detail-github-section").addClass("d-none");
				}
			} else {
				$("#libDetailModal .lib-detail-github-section").addClass("d-none");
			}

			// Tags
			var tags = lib.tags || [];
			if (tags.length > 0) {
				$("#libDetailModal .lib-detail-tags").text(tags.join(", "));
				$("#libDetailModal .lib-detail-tags-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-tags-section").addClass("d-none");
			}

			// Package info (app_version, format_version, windows_version, venus_version)
			var _hasPackageInfo = lib.app_version || lib.format_version || lib.windows_version || lib.venus_version;
			if (_hasPackageInfo) {
				var _piHtml = '<div class="small">';
				if (lib.format_version) _piHtml += '<div><b>Format Version:</b> ' + escapeHtml(lib.format_version) + '</div>';
				if (lib.app_version) _piHtml += '<div><b>Created with App Version:</b> ' + escapeHtml(lib.app_version) + '</div>';
				if (lib.windows_version) _piHtml += '<div><b>Windows Version:</b> ' + escapeHtml(lib.windows_version) + '</div>';
				if (lib.venus_version) _piHtml += '<div><b>VENUS Version:</b> ' + escapeHtml(lib.venus_version) + '</div>';
				_piHtml += '</div>';
				$("#libDetailModal .lib-detail-package-info").html(_piHtml);
				$("#libDetailModal .lib-detail-package-info-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-package-info-section").addClass("d-none");
			}

			// Installer info
			if (lib.installer_executable) {
				var _instHtml = '<div class="small">';
				_instHtml += '<div><b>Executable:</b> ' + escapeHtml(lib.installer_executable) + '</div>';
				if (lib.installer_info && lib.installer_info.description) {
					_instHtml += '<div><b>Description:</b> ' + escapeHtml(lib.installer_info.description) + '</div>';
				}
				if (lib.installer_path && fs.existsSync(lib.installer_path)) {
					_instHtml += '<div class="mt-2"><button class="btn btn-sm btn-outline-primary lib-detail-open-installer-dir" data-dirpath="' + escapeHtml(path.dirname(lib.installer_path)) + '"><i class="fas fa-folder-open mr-1"></i>Open Installer Location</button></div>';
				} else if (lib.installer_path) {
					_instHtml += '<div class="text-muted mt-1"><i class="fas fa-exclamation-triangle text-warning mr-1"></i>Installer file not found on disk</div>';
				} else {
					_instHtml += '<div class="text-muted mt-1">Installer not extracted (enable <em>Retain embedded installers</em> in Settings)</div>';
				}
				_instHtml += '</div>';
				$("#libDetailModal .lib-detail-installer-info").html(_instHtml);
				$("#libDetailModal .lib-detail-installer-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-installer-section").addClass("d-none");
			}

			// Package lineage
			var _lineage = lib.package_lineage || [];
			if (_lineage.length > 0) {
				var _linHtml = '<div class="small">';
				_lineage.forEach(function(evt, idx) {
					var evtIcon = evt.event === 'created' ? 'fa-plus-circle text-success' :
								  evt.event === 'exported' ? 'fa-upload text-primary' :
								  'fa-exchange-alt text-info';
					_linHtml += '<div class="mb-2 pb-2' + (idx < _lineage.length - 1 ? ' border-bottom' : '') + '">';
					_linHtml += '<div><i class="fas ' + evtIcon + ' mr-1"></i><b>' + escapeHtml(evt.event || 'unknown') + '</b>';
					if (evt.timestamp) _linHtml += ' <span class="text-muted">- ' + escapeHtml(evt.timestamp) + '</span>';
					_linHtml += '</div>';
					if (evt.app_version) _linHtml += '<div class="ml-3">App: v' + escapeHtml(evt.app_version) + '</div>';
					if (evt.username) _linHtml += '<div class="ml-3">User: ' + escapeHtml(evt.username) + '</div>';
					if (evt.hostname) _linHtml += '<div class="ml-3">Host: ' + escapeHtml(evt.hostname) + '</div>';
					if (evt.windows_version) _linHtml += '<div class="ml-3">Windows: ' + escapeHtml(evt.windows_version) + '</div>';
					if (evt.venus_version) _linHtml += '<div class="ml-3">VENUS: ' + escapeHtml(evt.venus_version) + '</div>';
					if (evt.format_version) _linHtml += '<div class="ml-3">Format: ' + escapeHtml(evt.format_version) + '</div>';
					_linHtml += '</div>';
				});
				_linHtml += '</div>';
				$("#libDetailModal .lib-detail-lineage").html(_linHtml);
				$("#libDetailModal .lib-detail-lineage-section").removeClass("d-none");
			} else {
				$("#libDetailModal .lib-detail-lineage-section").addClass("d-none");
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
					var dirPath = libBasePath || path.dirname(fullPath);
					$libFiles.append(
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + escapeHtml(fullPath) + '" title="Open: ' + escapeHtml(fullPath) + '"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>' +
						'<span class="pkg-file-dir">' + escapeHtml(dirPath) + '</span>' +
						'<span class="pkg-file-open-folder" data-folderpath="' + escapeHtml(dirPath) + '" title="Open file location"><i class="fas fa-folder-open"></i></span></div>'
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
					var dirPath = demoBasePath || path.dirname(fullPath);
					$demoFiles.append(
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + escapeHtml(fullPath) + '" title="Open: ' + escapeHtml(fullPath) + '"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>' +
						'<span class="pkg-file-dir">' + escapeHtml(dirPath) + '</span>' +
						'<span class="pkg-file-open-folder" data-folderpath="' + escapeHtml(dirPath) + '" title="Open file location"><i class="fas fa-folder-open"></i></span></div>'
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
						'<div class="pkg-file-item pkg-file-link imp-help-file-open" data-filepath="' + escapeHtml(fullPath) + '" title="Open help: ' + escapeHtml(fullPath) + '" style="cursor:pointer;"><i class="fas fa-question-circle pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span><span class="badge badge-info ml-2" style="font-size:0.7rem;">Open</span></div>'
					);
				});
			} else {
				$("#libDetailModal .lib-detail-help-section").addClass("d-none");
			}

			// Install paths
			$("#libDetailModal .lib-detail-lib-path").text("Library: " + (lib.lib_install_path || "\u2014")).attr("data-folderpath", lib.lib_install_path || "");
			if (lib.demo_install_path) {
				$("#libDetailModal .lib-detail-demo-path").text("Demo Methods: " + lib.demo_install_path).attr("data-folderpath", lib.demo_install_path).show();
			} else {
				$("#libDetailModal .lib-detail-demo-path").text("").attr("data-folderpath", "").hide();
			}

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
				if ((depStatus.warnings || []).length > 0) {
					$depStatus.append('<div class="text-sm mb-1" style="color:#f0ad4e;"><i class="fas fa-exclamation-triangle mr-1"></i>' + depStatus.warnings.length + ' unsigned dependenc' + (depStatus.warnings.length !== 1 ? 'ies' : 'y') + ' (not packaged)</div>');
				}

				// List each dependency
				deps.forEach(function(dep) {
					var statusIcon, statusColor, statusText;
					if (!dep.fileExists || dep.type === 'unknown') {
						statusIcon = 'fa-times-circle';
						statusColor = '#d9534f';
						statusText = 'Missing';
					} else if (dep.type === 'unsigned') {
						statusIcon = 'fa-exclamation-triangle';
						statusColor = '#f0ad4e';
						statusText = 'Unsigned';
					} else if (dep.type === 'system') {
						statusIcon = 'fa-lock';
						statusColor = '#6c757d';
						statusText = 'System';
					} else {
						statusIcon = 'fa-check-circle';
						statusColor = '#5cb85c';
						statusText = 'Installed';
					}
					var badgeClass = dep.type === 'system' ? 'secondary' : dep.type === 'user' ? 'info' : dep.type === 'unsigned' ? 'warning' : 'danger';
					var typeBadge = '<span class="badge badge-' + badgeClass + ' ml-1" style="font-size:0.6rem;">' + statusText + '</span>';
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

			// Code Signing Certificate section (OEM verified libraries only)
			var $certSection = $("#libDetailModal .lib-detail-cert-section");
			var $certContent = $("#libDetailModal .lib-detail-cert-content");
			if (detailCert && (isRestrictedAuthor(lib.author) || isRestrictedAuthor(lib.organization))) {
				$certContent.html(buildCertDetailSection(detailCert));
				$certSection.removeClass("d-none");
			} else if (lib.converted_from_executable) {
				$certContent.html(buildConvertedCertDetailSection(lib.source_certificate || null, lib.conversion_source || ''));
				$certSection.removeClass("d-none");
			} else {
				$certSection.addClass("d-none");
				$certContent.empty();
			}

			// Store library id on the modal so delete button can use it
			$("#libDetailModal").attr("data-lib-id", libId);
			$("#libDetailModal").attr("data-system", "false");
			$("#libDetailModal").modal("show");
		}

		// ---- Open installer directory from detail modal ----
		$(document).on("click", ".lib-detail-open-installer-dir", function(e) {
			e.preventDefault();
			var dirPath = $(this).attr("data-dirpath");
			if (dirPath) safeOpenItem(dirPath);
		});

		// ---- Rollback to a cached package version from detail modal ----
		$(document).on("click", ".lib-detail-rollback-btn", async function(e) {
			e.preventDefault();

			// ---- Access control check ----
			var accessCheck = canManageLibraries();
			if (!accessCheck.allowed) {
				showAccessDeniedModal('Rollback Library', accessCheck.reason);
				return;
			}

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
				var rawBuf = fs.readFileSync(fullPath);
				var zipBuffer = unpackContainer(rawBuf, CONTAINER_MAGIC_PKG);
				var zip = new AdmZip(zipBuffer);
				var manifestEntry = zip.getEntry("manifest.json");
				if (!manifestEntry) {
					alert("Cached package is corrupt: manifest.json not found.");
					return;
				}
				var manifest = JSON.parse(zip.readAsText(manifestEntry));

				var rLibName = manifest.library_name || libName;
				if (!isValidLibraryName(rLibName)) {
					alert('Invalid library name in cached package: "' + rLibName + '".\nRollback cancelled.');
					return;
				}

				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				var rollbackCustomSubdir = manifest.custom_install_subdir || '';
				var libDestDir;
				if (manifest.install_to_library_root) {
					libDestDir = libBasePath;
				} else if (rollbackCustomSubdir) {
					libDestDir = path.join(libBasePath, rollbackCustomSubdir);
				} else {
					libDestDir = path.join(libBasePath, rLibName);
				}
				var demoDestDir = path.join(metBasePath, "Library Demo Methods", rLibName);

				// Labware destination
				var labFolder = db_links.links.findOne({"_id":"labware-folder"});
				var labwareBasePath = labFolder ? labFolder.path : (function() {
					var hamiltonDir = path.dirname(libBasePath);
					var sibling = path.join(hamiltonDir, 'Labware');
					return fs.existsSync(sibling) ? sibling : 'C:\\Program Files (x86)\\HAMILTON\\Labware';
				})();
				var labwareFiles = manifest.labware_files || [];

				// Bin destination
				var binFolder = db_links.links.findOne({"_id":"bin-folder"});
				var binBasePath = binFolder ? binFolder.path : 'C:\\Program Files (x86)\\HAMILTON\\Bin';
				var binFiles = manifest.bin_files || [];

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

				// Deregister existing COM DLLs before overwriting (best-effort)
				if (comDlls.length > 0 && fs.existsSync(libDestDir)) {
					var existingComPaths = [];
					for (var ci = 0; ci < comDlls.length; ci++) {
						var comFullPath = path.join(libDestDir, comDlls[ci]);
						if (fs.existsSync(comFullPath)) {
							existingComPaths.push(comFullPath);
						}
					}
					if (existingComPaths.length > 0) {
						try {
							await comRegisterMultipleDlls(existingComPaths, false);
						} catch(comErr) {
							console.warn('COM deregistration during rollback failed (continuing): ' + comErr.message);
						}
					}
				}

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
					} else if (entry.entryName.indexOf("labware/") === 0) {
						var fname = entry.entryName.substring("labware/".length);
						if (fname) {
							var safePath = safeZipExtractPath(labwareBasePath, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("bin/") === 0) {
						var fname = entry.entryName.substring("bin/".length);
						if (fname) {
							var safePath = safeZipExtractPath(binBasePath, fname);
							if (!safePath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(safePath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(safePath, entry.getData());
							extractedCount++;
						}
					}
				});

				// Extract installer files if present and setting enabled
				var rbInstallerPath = null;
				var rbInstallerOriginalName = null;
				var rbInstallerSize = null;
				var retainInstallers = !!getSettingValue('chk_retainInstallers');
				if (manifest.installer_executable && retainInstallers) {
					var installerLibDir = path.join(INSTALLER_STORE_DIR, (rLibName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_'));
					zipEntries.forEach(function(entry) {
						if (entry.isDirectory) return;
						if (entry.entryName.indexOf("installer/") === 0) {
							var fname = entry.entryName.substring("installer/".length);
							if (fname) {
								var safePath = safeZipExtractPath(installerLibDir, fname);
								if (!safePath) { console.warn('Skipping unsafe installer ZIP entry: ' + entry.entryName); return; }
								if (!fs.existsSync(installerLibDir)) fs.mkdirSync(installerLibDir, { recursive: true });
								var data = entry.getData();
								fs.writeFileSync(safePath, data);
								rbInstallerPath = safePath;
								rbInstallerOriginalName = fname;
								rbInstallerSize = data.length;
								extractedCount++;
							}
						}
					});
				}

				// Re-register COM DLLs after extraction (best-effort)
				var comWarning = false;
				if (comDlls.length > 0) {
					var newComPaths = comDlls.map(function(d) { return path.join(libDestDir, d); })
						.filter(function(p) { return fs.existsSync(p); });
					if (newComPaths.length > 0) {
						try {
							var regResult = await comRegisterMultipleDlls(newComPaths, true);
							if (!regResult.allSuccess) {
								comWarning = true;
								console.warn('COM registration after rollback incomplete for ' + rLibName);
							}
						} catch(comErr) {
							comWarning = true;
							console.warn('COM registration after rollback failed: ' + comErr.message);
						}
					}
				}

				// Update DB record
				var existing = db_installed_libs.installed_libs.findOne({"library_name": rLibName});
				if (existing) {
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				var fileHashes = {};
				try { fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls); } catch(e) { console.warn('Could not compute integrity hashes: ' + e.message); }

				// Verify signature on cached package for publisher_cert
				var rollbackSig = null;
				try { rollbackSig = verifyPackageSignature(zip); } catch(e) { console.warn('Could not verify rollback package signature: ' + e.message); }

				var dbRecord = {
					library_name: manifest.library_name || "",
					author: manifest.author || "",
					organization: manifest.organization || "",
					installed_by: getWindowsUsername(),
					version: manifest.version || "",
					venus_compatibility: manifest.venus_compatibility || "",
					description: manifest.description || "",
					github_url: manifest.github_url || "",
					tags: manifest.tags || [],
					created_date: manifest.created_date || "",
					app_version: manifest.app_version || "",
					format_version: manifest.format_version || "1.0",
					windows_version: manifest.windows_version || "",
					venus_version: manifest.venus_version || "",
					package_lineage: manifest.package_lineage || [],
					library_image: manifest.library_image || null,
					library_image_base64: manifest.library_image_base64 || null,
					library_image_mime: manifest.library_image_mime || null,
					library_files: libFiles,
					demo_method_files: demoFiles,
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: comWarning,
					com_registered: comDlls.length > 0 && !comWarning,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: path.basename(fullPath),
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFiles, libDestDir),
					required_dependencies: extractRequiredDependencies(libFiles, libDestDir),
					labware_files: labwareFiles,
					labware_install_path: labwareFiles.length > 0 ? labwareBasePath : null,
					bin_files: binFiles,
					bin_install_path: binFiles.length > 0 ? binBasePath : null,
					publisher_cert: (rollbackSig && rollbackSig.code_signed && rollbackSig.valid && rollbackSig.publisher_cert) ? rollbackSig.publisher_cert : null,
					installer_executable: manifest.installer_executable || null,
					installer_info: manifest.installer_info || null,
					installer_path: rbInstallerPath || null,
					installer_original_name: rbInstallerOriginalName || null,
					installer_size: rbInstallerSize || null
				};
				// Forward-compat: preserve unknown manifest fields in DB record
				Object.keys(manifest).forEach(function(mk) { if (shared.KNOWN_MANIFEST_KEYS.indexOf(mk) === -1 && !(mk in dbRecord)) dbRecord[mk] = manifest[mk]; });
				var saved = db_installed_libs.installed_libs.save(dbRecord);

				// Write .libmgr marker file
				try { shared.updateMarkerForLibrary(dbRecord); } catch(_) { /* non-critical */ }

				// Update publisher registry
				registerPublisher(manifest.author || '');
				registerPublisher(manifest.organization || '');
				registerTags(manifest.tags || []);

				// Re-add to group tree if needed
				var navtree = db_tree.tree.find();
				var inGroup = false;
				for (var ti = 0; ti < navtree.length; ti++) {
					var mids = navtree[ti]["method-ids"] || [];
					if (mids.indexOf(saved._id) !== -1) { inGroup = true; break; }
				}
				if (!inGroup) {
					var targetGroupId = null;
					var rollbackAuthor = (manifest.author || '').trim();
					var rollbackOrg = (manifest.organization || '').trim();

					if (isRestrictedAuthor(rollbackAuthor) || isRestrictedAuthor(rollbackOrg)) {
						// Restricted OEM author: route to gOEM group
						targetGroupId = addToOemTreeGroup(saved._id);
					} else {
						// Non-restricted author: add to first custom group
						for (var ti = 0; ti < navtree.length; ti++) {
							var gEntry = getGroupById(navtree[ti]["group-id"]);
							if (gEntry && !gEntry["default"]) {
								targetGroupId = navtree[ti]["group-id"];
								var existingIds = (navtree[ti]["method-ids"] || []).slice();
								existingIds.push(saved._id);
								db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
								break;
							}
						}
					}

					// Fallback: create a "Libraries" group if no target found
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

				// Close modal, refresh, and show success
				$("#libDetailModal").modal("hide");
				impBuildLibraryCards();

				showGenericSuccessModal({
					title: "Version Rollback Successful!",
					name: rLibName,
					detail: extractedCount + " file" + (extractedCount !== 1 ? "s" : "") + " installed - rolled back to version " + (manifest.version || '?')
				});

				// ---- Audit trail entry ----
				try {
					appendAuditTrailEntry(buildAuditTrailEntry('library_rollback', {
						library_name:     rLibName,
						version:          manifest.version || '',
						author:           manifest.author || '',
						source_file:      path.basename(fullPath),
						lib_install_path: libDestDir,
						files_extracted:  extractedCount
					}));
				} catch(_) { /* non-critical */ }

				if (comDlls.length > 0) {
					alert('NOTE: This library has COM DLLs that may need re-registration:\n\n' + comDlls.join(', ') + '\n\nRe-import via the GUI for automatic 32-bit COM registration, or run the 32-bit RegAsm manually:\n  C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /codebase <dll>\n\nIMPORTANT: Do NOT use Framework64 - VENUS is a 32-bit application.');
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
			var sysVerText = sLib.venus_version ? "System Library (VENUS " + sLib.venus_version + ")" : "System Library";
			$("#libDetailModal .lib-detail-version").text(sysVerText);
			var sysAuthor = sLib.author || "Hamilton";
			var sysAuthorOemBadge = buildOemVerifiedBadge(sysAuthor, true, null);
			if (sysAuthorOemBadge) {
				$("#libDetailModal .lib-detail-author").html(escapeHtml(sysAuthor) + ' ' + sysAuthorOemBadge);
			} else {
				$("#libDetailModal .lib-detail-author").text(sysAuthor);
			}
			var sysDetailOrg = sLib.organization || "Hamilton";
			var sysOrgOemBadge = buildOemVerifiedBadge(sysDetailOrg, true, null);
			if (sysOrgOemBadge) {
				$("#libDetailModal .lib-detail-organization").html(escapeHtml(sysDetailOrg) + ' ' + sysOrgOemBadge);
			} else {
				$("#libDetailModal .lib-detail-organization").text(sysDetailOrg);
			}
			$("#libDetailModal .lib-detail-venus").text(sLib.venus_version || "\u2014");
			$("#libDetailModal .lib-detail-installed-date").text(sLib.installed_date ? new Date(sLib.installed_date).toLocaleString() : "Included with VENUS");
			$("#libDetailModal .lib-detail-installed-by").text(sLib.installed_by || "System");
			$("#libDetailModal .lib-detail-created-date").text("N/A");

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

			// Library files list (from discovered_files) - separate CHMs into help section
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
					var relPath = f.replace(/^Library[\\\/]/i, '');
					var fullSysPath = path.join(sysLibDir, relPath);
					var dirSysPath = path.dirname(fullSysPath);
					$libFiles.append(
						'<div class="pkg-file-item"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name" style="color:#6c757d;">' + fileName + '</span>' +
						'<span class="pkg-file-dir">' + f + '</span>' +
						'<span class="pkg-file-open-folder" data-folderpath="' + escapeHtml(dirSysPath) + '" title="Open file location"><i class="fas fa-folder-open"></i></span></div>'
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
			$("#libDetailModal .lib-detail-demo-path").text("").hide();

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
				if ((sysDepStatus.warnings || []).length > 0) {
					$sysDepStatus.append('<div class="text-sm mb-1" style="color:#f0ad4e;"><i class="fas fa-exclamation-triangle mr-1"></i>' + sysDepStatus.warnings.length + ' unsigned dependenc' + (sysDepStatus.warnings.length !== 1 ? 'ies' : 'y') + ' (not packaged)</div>');
				}

				sysDeps.forEach(function(dep) {
					var statusIcon, statusColor, statusText;
					if (!dep.fileExists || dep.type === 'unknown') {
						statusIcon = 'fa-times-circle';
						statusColor = '#d9534f';
						statusText = 'Missing';
					} else if (dep.type === 'unsigned') {
						statusIcon = 'fa-exclamation-triangle';
						statusColor = '#f0ad4e';
						statusText = 'Unsigned';
					} else if (dep.type === 'system') {
						statusIcon = 'fa-lock';
						statusColor = '#6c757d';
						statusText = 'System';
					} else {
						statusIcon = 'fa-check-circle';
						statusColor = '#5cb85c';
						statusText = 'Installed';
					}
					var badgeClass = dep.type === 'system' ? 'secondary' : dep.type === 'user' ? 'info' : dep.type === 'unsigned' ? 'warning' : 'danger';
					var typeBadge = '<span class="badge badge-' + badgeClass + ' ml-1" style="font-size:0.6rem;">' + statusText + '</span>';
					$sysDepList.append(
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
				$sysDepSection.addClass("d-none");
			}

			// Public functions section - parse .hsl files from discovered_files
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

			// Hide cert section for system libraries (no stored publisher cert)
			$("#libDetailModal .lib-detail-cert-section").addClass("d-none");
			$("#libDetailModal .lib-detail-cert-content").empty();

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

			// Populate and show the export choice modal
			$("#exportChoiceModal").attr("data-lib-id", libId);
			$(".export-choice-libname").text(libName);

			// Resolve dependencies and show summary
			var allDepLibIds = resolveAllDependencyLibIds(libId);
			var depSummary = $(".export-choice-dep-summary");
			var depList = $(".export-choice-dep-list");
			var $depsOption = $(".export-choice-option[data-choice='deps']");
			if (allDepLibIds.length > 0) {
				var depNames = allDepLibIds.map(function(did) {
					var dl = db_installed_libs.installed_libs.findOne({"_id": did});
					return dl ? (dl.library_name || "Unknown") : "Unknown";
				});
				var listHtml = '<i class="fas fa-info-circle mr-1" style="color:var(--medium)"></i>' +
					allDepLibIds.length + ' dependenc' + (allDepLibIds.length !== 1 ? 'ies' : 'y') + ' found: ' +
					depNames.map(function(n) { return '<b>' + escapeHtml(n) + '</b>'; }).join(', ');
				depList.html(listHtml);
				depSummary.removeClass('d-none');
				$depsOption.removeClass('export-choice-disabled').css({ opacity: '', cursor: 'pointer', pointerEvents: '' });
			} else {
				depList.html('<i class="fas fa-ban mr-1" style="color:var(--lightgray)"></i>No exportable dependencies found');
				depSummary.removeClass('d-none');
				$depsOption.addClass('export-choice-disabled').css({ opacity: '0.45', cursor: 'not-allowed', pointerEvents: 'none' });
			}

			// Refresh signing UI and auto-enable if configured
			refreshSigningUI();
			var sigInfo = getSigningDisplayInfo();
			$("#chk-export-choice-sign").prop("checked", !!sigInfo);
			$(".export-signing-detail").toggle(!!sigInfo);

			$("#exportChoiceModal").modal("show");
		});

		// Export choice modal - hover effect (skip disabled)
		$(document).on("mouseenter", ".export-choice-option:not(.export-choice-disabled)", function() {
			$(this).css("background", "var(--body-background)");
		}).on("mouseleave", ".export-choice-option:not(.export-choice-disabled)", function() {
			$(this).css("background", "");
		});

		// Export choice modal - click an option (ignore disabled)
		$(document).on("click", ".export-choice-option:not(.export-choice-disabled)", function() {
			var choice = $(this).attr("data-choice");
			var libId = $("#exportChoiceModal").attr("data-lib-id");
			if (!libId) return;
			var useCodeSigning = $("#chk-export-choice-sign").is(":checked");
			$("#exportChoiceModal").modal("hide");

			var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
			if (!lib) { alert("Library not found."); return; }
			var libName = lib.library_name || "Unknown";

			if (choice === "single") {
				// Single library export (.hxlibpkg)
				$("#lib-export-save-dialog").attr("nwsaveas", libName + ".hxlibpkg");
				$("#lib-export-save-dialog").data("useCodeSigning", useCodeSigning);
				$("#lib-export-save-dialog").trigger("click");
			} else if (choice === "deps") {
				// Export with all dependencies (.hxlibarch)
				$("#lib-export-deps-save-dialog").attr("nwsaveas", libName + "_with_dependencies.hxlibarch");
				$("#lib-export-deps-save-dialog").data("libId", libId);
				$("#lib-export-deps-save-dialog").data("useCodeSigning", useCodeSigning);
				$("#lib-export-deps-save-dialog").trigger("click");
			}
		});

		$(document).on("change", "#lib-export-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			var useCodeSigning = !!($(this).data("useCodeSigning"));
			$(this).val('');
			var libId = $("#libDetailModal").attr("data-lib-id");
			if (!libId) return;
			exportSingleLibrary(libId, savePath, useCodeSigning);
		});

		// Save dialog for export with dependencies
		$(document).on("change", "#lib-export-deps-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			var useCodeSigning = !!($(this).data("useCodeSigning"));
			$(this).val('');
			var libId = $(this).data("libId");
			if (!libId) return;
			exportLibraryWithDependencies(libId, savePath, useCodeSigning);
		});

		function exportSingleLibrary(libId, savePath, useCodeSigning) {
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
				var labwareFiles = lib.labware_files || [];
				var labwareInstallPath = lib.labware_install_path || 'C:\\Program Files (x86)\\HAMILTON\\Labware';
				var binFiles = lib.bin_files || [];
				var binInstallPath = lib.bin_install_path || 'C:\\Program Files (x86)\\HAMILTON\\Bin';

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

				// Build manifest - include help_files for the importer
				// Also include CHMs in library_files for backward compatibility
				var manifestLibFiles = libraryFiles.slice();
				helpFiles.forEach(function(hf) {
					if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
				});

				var manifest = {
					format_version: shared.FORMAT_VERSION,
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
					com_register_dlls: comDlls.slice(),
					app_version: shared.getAppVersion(),
					windows_version: lib.windows_version || shared.getWindowsVersion(),
					venus_version: lib.venus_version || _cachedVENUSVersion || '',
					package_lineage: (lib.package_lineage || []).concat([shared.buildLineageEvent('exported', {
						username: getWindowsUsername(),
						hostname: os.hostname(),
						venusVersion: _cachedVENUSVersion || ''
					})])
				};

				// Include installer metadata in export manifest
				if (lib.installer_executable) manifest.installer_executable = lib.installer_executable;
				if (lib.installer_info) manifest.installer_info = lib.installer_info;
				if (labwareFiles.length > 0) manifest.labware_files = labwareFiles.slice();
				if (binFiles.length > 0) manifest.bin_files = binFiles.slice();

				// Sanitize all file paths in manifest to ensure only safe relative paths
				try {
					shared.sanitizeManifestFilePaths(manifest);
				} catch (e) {
					alert('Export aborted: unsafe file path detected.\n' + e.message);
					return;
				}

				// Preserve extra DB fields for forward compatibility
				Object.keys(lib).forEach(function(k) {
					if (shared.KNOWN_LIB_DB_KEYS.indexOf(k) === -1 && !(k in manifest)) {
						manifest[k] = lib[k];
					}
				});

				// Create ZIP package
				var zip = new AdmZip();

				// Add manifest
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files
				libraryFiles.forEach(function(f) {
					var fullPath = path.join(libBasePath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('library', f));
					}
				});

				// Add help files (CHMs - packed into library/ folder)
				helpFiles.forEach(function(f) {
					var fullPath = path.join(libBasePath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('library', f));
					}
				});

				// Add demo method files
				demoFiles.forEach(function(f) {
					var fullPath = path.join(demoBasePath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('demo_methods', f));
					}
				});

				// Add installer from installer store if available
				if (lib.installer_path && fs.existsSync(lib.installer_path)) {
					zip.addLocalFile(lib.installer_path, 'installer');
				}

				// Add labware files
				labwareFiles.forEach(function(f) {
					var fullPath = path.join(labwareInstallPath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('labware', f));
					}
				});

				// Add bin files
				binFiles.forEach(function(f) {
					var fullPath = path.join(binInstallPath, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, zipSubdir('bin', f));
					}
				});

				// Sign the package for integrity verification
				var sigResult = applyPackageSigning(zip, useCodeSigning);

				// Wrap in binary container and write
				fs.writeFileSync(savePath, packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

				var successDetail = libraryFiles.length + " library file" + (libraryFiles.length !== 1 ? "s" : "") + ", " + helpFiles.length + " help file" + (helpFiles.length !== 1 ? "s" : "") + ", " + demoFiles.length + " demo file" + (demoFiles.length !== 1 ? "s" : "");
				if (sigResult.codeSigned) {
					successDetail += '\nCode signed by: ' + sigResult.publisher;
				}

				showGenericSuccessModal({
					title: "Library Exported Successfully!",
					name: libName,
					detail: successDetail,
					paths: [
						{ label: "Saved To", value: savePath }
					]
				});

			} catch(e) {
				alert("Error exporting library:\n" + e.message);
			}
		}

		/**
		 * Recursively resolve all user-installed dependency library IDs for a
		 * given library.  Walks the dependency tree via extractRequiredDependencies
		 * and collects every user-installed library that is required (directly or
		 * transitively), excluding the root library itself.
		 *
		 * @param {string} rootLibId - The _id of the starting library
		 * @returns {Array<string>} deduplicated array of dependency library _ids
		 */
		function resolveAllDependencyLibIds(rootLibId) {
			var visited = {};   // _id -> true
			var result  = [];   // ordered list of dependency _ids

			// Pre-fetch all installed libs and build a name->record lookup map (O(n) instead of O(n²))
			var allLibs = db_installed_libs.installed_libs.find() || [];
			var libByName = {};  // lowercased library_name -> lib record
			var libById = {};    // _id -> lib record
			for (var li = 0; li < allLibs.length; li++) {
				var al = allLibs[li];
				if (al.deleted) continue;
				libById[al._id] = al;
				var lname = (al.library_name || '').toLowerCase();
				if (lname && !libByName[lname]) {
					libByName[lname] = al;
				}
			}

			function walk(libId) {
				if (visited[libId]) return;
				visited[libId] = true;

				var lib = libById[libId];
				if (!lib) return;

				var deps = extractRequiredDependencies(lib.library_files || [], lib.lib_install_path || '');
				(deps || []).forEach(function(dep) {
					if (dep.type !== 'user') return;          // only user-installed libraries can be exported
					// Resolve dep.libraryName back to a library record via lookup map
					var candidate = libByName[(dep.libraryName || '').toLowerCase()];
					if (candidate && !visited[candidate._id]) {
						result.push(candidate._id);
						walk(candidate._id);   // recurse into this dependency's own deps
					}
				});
			}

			walk(rootLibId);
			return result;
		}

		/**
		 * Export a library together with all of its recursively-resolved
		 * user-installed dependencies as a .hxlibarch archive.
		 *
		 * @param {string} libId    - The _id of the root library
		 * @param {string} savePath - Destination path for the .hxlibarch file
		 */
		function exportLibraryWithDependencies(libId, savePath, useCodeSigning) {
			try {
				// Build full list: root library + all recursive dependencies
				var depIds = resolveAllDependencyLibIds(libId);
				var allIds = [libId].concat(depIds);

				var archiveZip = new AdmZip();
				var exportedLibs = [];
				var errors = [];
				var usedFileNames = {};  // track sanitized filenames to avoid collisions

				allIds.forEach(function(id) {
					var lib = db_installed_libs.installed_libs.findOne({"_id": id});
					if (!lib) {
						errors.push("Library ID " + id + " not found in database.");
						return;
					}

					var libName     = lib.library_name || "Unknown";
					var libBasePath = lib.lib_install_path || "";
					var demoBasePath= lib.demo_install_path || "";
					var libraryFiles= lib.library_files || [];
					var demoFiles   = lib.demo_method_files || [];
					var helpFiles   = lib.help_files || [];
					var comDlls     = lib.com_register_dlls || [];

					// Include CHMs in manifest library_files for backward compatibility
					var manifestLibFiles = libraryFiles.slice();
					helpFiles.forEach(function(hf) {
						if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
					});

					var manifest = {
						format_version: shared.FORMAT_VERSION,
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
						com_register_dlls: comDlls.slice(),
						app_version: shared.getAppVersion(),
						windows_version: lib.windows_version || shared.getWindowsVersion(),
						venus_version: lib.venus_version || _cachedVENUSVersion || '',
						package_lineage: (lib.package_lineage || []).concat([shared.buildLineageEvent('exported', {
							username: getWindowsUsername(),
							hostname: os.hostname(),
							venusVersion: _cachedVENUSVersion || ''
						})])
					};

					// Include installer metadata in export manifest
					if (lib.installer_executable) manifest.installer_executable = lib.installer_executable;
					if (lib.installer_info) manifest.installer_info = lib.installer_info;

					// Preserve extra DB fields for forward compatibility
					Object.keys(lib).forEach(function(k) {
						if (shared.KNOWN_LIB_DB_KEYS.indexOf(k) === -1 && !(k in manifest)) {
							manifest[k] = lib[k];
						}
					});

					// Create an inner zip for this library (.hxlibpkg)
					var innerZip = new AdmZip();
					innerZip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

					var libFilesAdded = 0;
					libraryFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, zipSubdir('library', f));
							libFilesAdded++;
						}
					});

					helpFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, zipSubdir('library', f));
						}
					});

					var demoFilesAdded = 0;
					demoFiles.forEach(function(f) {
						var fullPath = path.join(demoBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, zipSubdir('demo_methods', f));
							demoFilesAdded++;
						}
					});

					// Add installer from installer store if available
					if (lib.installer_path && fs.existsSync(lib.installer_path)) {
						innerZip.addLocalFile(lib.installer_path, 'installer');
					}

					applyPackageSigning(innerZip, useCodeSigning);

					var innerBuffer = packContainer(innerZip.toBuffer(), CONTAINER_MAGIC_PKG);
					var baseName = libName.replace(/[<>:"\\\/|?*]/g, '_');
					var innerFileName = baseName + ".hxlibpkg";
					// Avoid collisions from sanitized names
					if (usedFileNames[innerFileName.toLowerCase()]) {
						var suffix = 2;
						while (usedFileNames[(baseName + '_' + suffix + '.hxlibpkg').toLowerCase()]) { suffix++; }
						innerFileName = baseName + '_' + suffix + '.hxlibpkg';
					}
					usedFileNames[innerFileName.toLowerCase()] = true;
					archiveZip.addFile(innerFileName, innerBuffer);

					exportedLibs.push({
						name: libName,
						libFiles: libFilesAdded,
						demoFiles: demoFilesAdded,
						isRoot: (id === libId)
					});
				});

				if (exportedLibs.length === 0) {
					alert("No libraries could be exported.\n\n" + errors.join("\n"));
					return;
				}

				// Load archive icon
				var archiveIconBase64 = null;
				var archiveIconMime   = null;
				var iconResult = getArchiveIconPng();
				if (iconResult && iconResult.base64) {
					archiveIconBase64 = iconResult.base64;
					archiveIconMime   = iconResult.mime || 'image/png';
				}

				// Add archive manifest
				var archManifest = {
					format_version: shared.FORMAT_VERSION,
					archive_type: "hxlibarch",
					created_date: new Date().toISOString(),
					library_count: exportedLibs.length,
					libraries: exportedLibs.map(function(l) { return l.name; }),
					archive_icon: archiveIconBase64 ? 'archive_icon.png' : null,
					archive_icon_base64: archiveIconBase64,
					archive_icon_mime: archiveIconMime,
					app_version: shared.getAppVersion(),
					windows_version: shared.getWindowsVersion(),
					venus_version: _cachedVENUSVersion || ''
				};
				archiveZip.addFile("archive_manifest.json", Buffer.from(JSON.stringify(archManifest, null, 2), "utf8"));

				if (archiveIconBase64) {
					archiveZip.addFile("icon/archive_icon.png", Buffer.from(archiveIconBase64, 'base64'));
				}

				// Wrap outer archive in binary container and write
				fs.writeFileSync(savePath, packContainer(archiveZip.toBuffer(), CONTAINER_MAGIC_ARC));

				// Build success list
				var rootLib = exportedLibs.filter(function(l) { return l.isRoot; })[0];
				var depLibs = exportedLibs.filter(function(l) { return !l.isRoot; });

				var archListHtml = '<div style="text-align:left;">';
				archListHtml += '<div style="margin-bottom:4px;"><i class="fas fa-book text-success mr-1"></i><b>' + (rootLib ? escapeHtml(rootLib.name) : '') + '</b> <span class="text-muted" style="font-size:0.8rem;">(root library)</span></div>';
				if (depLibs.length > 0) {
					archListHtml += '<div class="text-muted text-sm mb-1" style="margin-left:1.25rem;">Dependencies:</div>';
					depLibs.forEach(function(l) {
						archListHtml += '<div style="margin-bottom:4px; margin-left:1.25rem;"><i class="fas fa-check text-success mr-1"></i>' + escapeHtml(l.name) + ' <span class="text-muted" style="font-size:0.8rem;">(' + l.libFiles + ' lib, ' + l.demoFiles + ' demo)</span></div>';
					});
				}
				archListHtml += '</div>';

				var archStatusHtml = null;
				var archStatusClass = null;
				if (errors.length > 0) {
					archStatusHtml = '<i class="fas fa-exclamation-triangle mr-1"></i>' + errors.join('<br>');
					archStatusClass = 'com-warning';
				}

				showGenericSuccessModal({
					title: "Library Archive Exported Successfully!",
					detail: exportedLibs.length + " librar" + (exportedLibs.length !== 1 ? "ies" : "y") + " included (" + (exportedLibs.length - 1) + " dependenc" + ((exportedLibs.length - 1) !== 1 ? "ies" : "y") + ")",
					paths: [
						{ label: "Saved To", value: savePath }
					],
					listHtml: archListHtml,
					statusHtml: archStatusHtml,
					statusClass: archStatusClass
				});

			} catch(e) {
				alert("Error exporting library with dependencies:\n" + e.message);
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
			// Refresh archive signing toggle
			refreshSigningUI();
			var sigInfo = getSigningDisplayInfo();
			$("#chk-archive-sign").prop("checked", !!sigInfo);
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
							'<div class="font-weight-bold" style="color:var(--medium2);">' + escapeHtml(libName) + '</div>' +
							'<div class="text-muted text-sm">' +
								(version ? 'v' + escapeHtml(version) : '') +
								(author ? (version ? ' &middot; ' : '') + escapeHtml(author) : '') +
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
			// Store selected ids and signing state for use in save handler
			$("#exp-arch-save-dialog").data("selectedIds", selectedIds);
			$("#exp-arch-save-dialog").data("useCodeSigning", $("#chk-archive-sign").is(":checked"));
			$("#exp-arch-save-dialog").trigger("click");
		});

		// Save dialog change
		$(document).on("change", "#exp-arch-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			var selectedIds = $(this).data("selectedIds") || [];
			if (selectedIds.length === 0) return;
			var useCodeSigning = !!($(this).data("useCodeSigning"));
			expArchCreateArchive(selectedIds, savePath, useCodeSigning);
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
		async function expArchCreateArchive(libIds, savePath, useCodeSigning) {
			try {
				var archiveZip = new AdmZip();
				var exportedLibs = [];
				var errors = [];
				var usedFileNames = {};  // track sanitized filenames to avoid collisions

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
						format_version: shared.FORMAT_VERSION,
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
						com_register_dlls: comDlls.slice(),
						app_version: shared.getAppVersion(),
						windows_version: lib.windows_version || shared.getWindowsVersion(),
						venus_version: lib.venus_version || _cachedVENUSVersion || '',
						package_lineage: (lib.package_lineage || []).concat([shared.buildLineageEvent('exported', {
							username: getWindowsUsername(),
							hostname: os.hostname(),
							venusVersion: _cachedVENUSVersion || ''
						})])
					};

					// Preserve extra DB fields for forward compatibility
					Object.keys(lib).forEach(function(k) {
						if (shared.KNOWN_LIB_DB_KEYS.indexOf(k) === -1 && !(k in manifest)) {
							manifest[k] = lib[k];
						}
					});

					// Create an inner zip for this library (.hxlibpkg)
					var innerZip = new AdmZip();

					// Add manifest
					innerZip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

					// Add library files
					var libFilesAdded = 0;
					libraryFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, zipSubdir('library', f));
							libFilesAdded++;
						}
					});

					// Add help files (CHMs - packed into library/ folder)
					helpFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, zipSubdir('library', f));
						}
					});

					// Add demo method files
					var demoFilesAdded = 0;
					demoFiles.forEach(function(f) {
						var fullPath = path.join(demoBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, zipSubdir('demo_methods', f));
							demoFilesAdded++;
						}
					});

					// Sign the inner package
					applyPackageSigning(innerZip, useCodeSigning);

					// Convert inner zip to binary container and add to archive
					var innerBuffer = packContainer(innerZip.toBuffer(), CONTAINER_MAGIC_PKG);
					var baseName = libName.replace(/[<>:"\\\/|?*]/g, '_');
					var innerFileName = baseName + ".hxlibpkg";
					// Avoid collisions from sanitized names
					if (usedFileNames[innerFileName.toLowerCase()]) {
						var suffix = 2;
						while (usedFileNames[(baseName + '_' + suffix + '.hxlibpkg').toLowerCase()]) { suffix++; }
						innerFileName = baseName + '_' + suffix + '.hxlibpkg';
					}
					usedFileNames[innerFileName.toLowerCase()] = true;
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
					format_version: shared.FORMAT_VERSION,
					archive_type: "hxlibarch",
					created_date: new Date().toISOString(),
					app_version: shared.getAppVersion(),
					windows_version: shared.getWindowsVersion(),
					venus_version: _cachedVENUSVersion || '',
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

				// Write the archive as binary container
				fs.writeFileSync(savePath, packContainer(archiveZip.toBuffer(), CONTAINER_MAGIC_ARC));

				var archListHtml = '<div style="text-align:left;">';
				exportedLibs.forEach(function(l) {
					archListHtml += '<div style="margin-bottom:4px;"><i class="fas fa-check text-success mr-1"></i>' + escapeHtml(l.name) + ' <span class="text-muted" style="font-size:0.8rem;">(' + l.libFiles + ' lib, ' + l.demoFiles + ' demo)</span></div>';
				});
				archListHtml += '</div>';

				var archStatusHtml = null;
				var archStatusClass = null;
				if (errors.length > 0) {
					archStatusHtml = '<i class="fas fa-exclamation-triangle mr-1"></i>' + errors.join('<br>');
					archStatusClass = 'com-warning';
				}

				showGenericSuccessModal({
					title: "Archive Exported Successfully!",
					detail: exportedLibs.length + " librar" + (exportedLibs.length !== 1 ? "ies" : "y") + " included",
					paths: [
						{ label: "Saved To", value: savePath }
					],
					listHtml: archListHtml,
					statusHtml: archStatusHtml,
					statusClass: archStatusClass
				});

			} catch(e) {
				alert("Error creating archive:\n" + e.message);
			}
		}

		//**************************************************************************************
		//****** IMPORT ARCHIVE (.hxlibarch) - Import multiple libraries at once ****************
		//**************************************************************************************

		// Import archive: extract each .hxlibpkg and install sequentially
		async function impArchImportArchive(archivePath) {
			// ---- Access control check ----
			var accessCheck = canManageLibraries();
			if (!accessCheck.allowed) {
				showAccessDeniedModal('Import Archive', accessCheck.reason);
				return;
			}

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

				var rawArchBuf = fs.readFileSync(archivePath);
				var outerZipBuf = unpackContainer(rawArchBuf, CONTAINER_MAGIC_ARC);
				var archiveZip = new AdmZip(outerZipBuf);
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

				// ---- Duplicate detection pre-scan ----
				// Scan all packages for name/version and check against installed libraries.
				// If duplicates exist, notify the user and let them choose to skip or overwrite.
				var archDuplicates = [];
				for (var dupScanIdx = 0; dupScanIdx < pkgEntries.length; dupScanIdx++) {
					try {
						var dupScanBuf = pkgEntries[dupScanIdx].getData();
						var dupScanZipBuf = unpackContainer(dupScanBuf, CONTAINER_MAGIC_PKG);
						var dupScanZip = new AdmZip(dupScanZipBuf);
						var dupScanManifest = dupScanZip.getEntry("manifest.json");
						if (dupScanManifest) {
							var dupScanM = JSON.parse(dupScanZip.readAsText(dupScanManifest));
							var dupScanName = dupScanM.library_name || pkgEntries[dupScanIdx].entryName;
							var dupScanVer = dupScanM.version || '?';
							var dupExisting = db_installed_libs.installed_libs.findOne({"library_name": dupScanName});
							if (dupExisting && !dupExisting.deleted) {
								archDuplicates.push({
									index: dupScanIdx,
									libName: dupScanName,
									incomingVersion: dupScanVer,
									existingVersion: dupExisting.version || '?'
								});
							}
						}
					} catch (_) { /* scan failure is non-fatal */ }
				}

				// If duplicates found, ask user what to do
				var archSkipIndices = {};
				if (archDuplicates.length > 0) {
					var dupMsg = archDuplicates.length + " librar" + (archDuplicates.length !== 1 ? "ies are" : "y is") + " already installed:\n\n";
					archDuplicates.forEach(function(d) {
						if (d.existingVersion !== '?' && d.incomingVersion !== '?' && d.existingVersion === d.incomingVersion) {
							dupMsg += "  \u2022 " + d.libName + " (same version: v" + d.existingVersion + ")\n";
						} else {
							dupMsg += "  \u2022 " + d.libName + " (installed: v" + d.existingVersion + " \u2192 importing: v" + d.incomingVersion + ")\n";
						}
					});
					dupMsg += "\nClick OK to replace " + (archDuplicates.length !== 1 ? "these libraries" : "this library") + ", or Cancel to skip " + (archDuplicates.length !== 1 ? "them" : "it") + " and install only new libraries.";
					if (!confirm(dupMsg)) {
						// User chose to skip duplicates
						archDuplicates.forEach(function(d) {
							archSkipIndices[d.index] = true;
						});
						// If everything is a duplicate and user chose to skip, nothing to install
						if (Object.keys(archSkipIndices).length >= pkgEntries.length) {
							alert("All libraries in this archive are already installed. No changes were made.");
							return;
						}
					}
				}

				// ---- COM DLL pre-scan: detect all COM registrations needed upfront ----
				// Scan every package in the archive for com_register_dlls so we can
				// prompt the user for admin rights ONCE and register ALL DLLs in a
				// single elevated session rather than triggering multiple UAC prompts.
				var archiveComDllCount = 0;
				var archiveComPkgNames = [];
				for (var comScanIdx = 0; comScanIdx < pkgEntries.length; comScanIdx++) {
					if (archSkipIndices[comScanIdx]) continue; // skip libraries the user chose not to replace
					try {
						var comScanBuf = pkgEntries[comScanIdx].getData();
						var comScanZipBuf = unpackContainer(comScanBuf, CONTAINER_MAGIC_PKG);
						var comScanZip = new AdmZip(comScanZipBuf);
						var comScanManifest = comScanZip.getEntry("manifest.json");
						if (comScanManifest) {
							var comScanM = JSON.parse(comScanZip.readAsText(comScanManifest));
							var comScanDlls = comScanM.com_register_dlls || [];
							if (comScanDlls.length > 0) {
								archiveComDllCount += comScanDlls.length;
								archiveComPkgNames.push(comScanM.library_name || pkgEntries[comScanIdx].entryName);
							}
						}
					} catch (_) { /* scan failure is non-fatal */ }
				}

				if (archiveComDllCount > 0) {
					var comPromptMsg = "This archive contains " + archiveComDllCount + " COM DLL" + (archiveComDllCount !== 1 ? "s" : "") +
						" across " + archiveComPkgNames.length + " package" + (archiveComPkgNames.length !== 1 ? "s" : "") +
						" that require administrator rights to register:\n\n";
					archiveComPkgNames.forEach(function(n) { comPromptMsg += "  \u2022 " + n + "\n"; });
					comPromptMsg += "\nYou will be prompted for administrator rights once to register all COM objects.\n\nDo you want to continue?";
					if (!confirm(comPromptMsg)) {
						return;
					}
				}

				var results = { success: [], failed: [] };

				// Determine base install paths
				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				var labFolderArch = db_links.links.findOne({"_id":"labware-folder"});
				var labwareBasePathArch = labFolderArch ? labFolderArch.path : (function() {
					var hamiltonDir = path.dirname(libBasePath);
					var sibling = path.join(hamiltonDir, 'Labware');
					return fs.existsSync(sibling) ? sibling : 'C:\\Program Files (x86)\\HAMILTON\\Labware';
				})();
				var binFolderArch = db_links.links.findOne({"_id":"bin-folder"});
				var binBasePathArch = binFolderArch ? binFolderArch.path : 'C:\\Program Files (x86)\\HAMILTON\\Bin';

				// Track all COM DLL paths across all packages for batch registration
				var allComDllPaths = [];     // { dllPath, libName, savedId }

				// Process each package
				for (var archPkgIdx = 0; archPkgIdx < pkgEntries.length; archPkgIdx++) { (function() { var pkgEntry = pkgEntries[archPkgIdx];
					// Skip libraries the user chose not to replace
					if (archSkipIndices[archPkgIdx]) {
						results.failed.push(pkgEntry.entryName.replace('.hxlibpkg', '') + ": skipped (already installed)");
						return;
					}
					try {
						var pkgBuffer = pkgEntry.getData();
						var innerZipBuf = unpackContainer(pkgBuffer, CONTAINER_MAGIC_PKG);
						var innerZip = new AdmZip(innerZipBuf);
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

						// Author/organization validation for archive entry
						var archImportAuthor = (manifest.author || '').trim();
						var archImportOrg = (manifest.organization || '').trim();
						if (archImportAuthor) {
							var archAuthorChk = shared.isValidAuthorName(archImportAuthor);
							if (!archAuthorChk.valid) {
								results.failed.push(libName + ": " + archAuthorChk.reason);
								return;
							}
						}
						if (archImportOrg) {
							var archOrgChk = shared.isValidOrganizationName(archImportOrg);
							if (!archOrgChk.valid) {
								results.failed.push(libName + ": " + archOrgChk.reason);
								return;
							}
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

						var archCustomSubdir = manifest.custom_install_subdir || '';
						var libDestDir;
						if (manifest.install_to_library_root) {
							libDestDir = libBasePath;
						} else if (archCustomSubdir) {
							libDestDir = path.join(libBasePath, archCustomSubdir);
						} else {
							libDestDir = path.join(libBasePath, libName);
						}
						var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);
						var labwareFiles = manifest.labware_files || [];
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
							} else if (entry.entryName.indexOf("labware/") === 0) {
								var fname = entry.entryName.substring("labware/".length);
								if (fname) {
									var outPath = safeZipExtractPath(labwareBasePathArch, fname);
									if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("bin/") === 0) {
								var fname = entry.entryName.substring("bin/".length);
								if (fname) {
									var outPath = safeZipExtractPath(binBasePathArch, fname);
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
						try { fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls); } catch(e) { console.warn('Could not compute integrity hashes: ' + e.message); }

						var dbRecord = {
							library_name: manifest.library_name || "",
							author: manifest.author || "",
							organization: manifest.organization || "",
							installed_by: getWindowsUsername(),
							version: manifest.version || "",
							venus_compatibility: manifest.venus_compatibility || "",
							description: manifest.description || "",
							github_url: manifest.github_url || "",
							tags: manifest.tags || [],
							created_date: manifest.created_date || "",
							app_version: manifest.app_version || "",
							format_version: manifest.format_version || "1.0",
							windows_version: manifest.windows_version || "",
							venus_version: manifest.venus_version || "",
							package_lineage: manifest.package_lineage || [],
							library_image: manifest.library_image || null,
							library_image_base64: manifest.library_image_base64 || null,
							library_image_mime: manifest.library_image_mime || null,
							library_files: libFiles,
							demo_method_files: manifest.demo_method_files || [],
							help_files: helpFiles,
							com_register_dlls: comDlls,
							com_warning: comDlls.length > 0,  // mark as warning; cleared below if registration succeeds
							com_registered: false,
							lib_install_path: libDestDir,
							demo_install_path: demoDestDir,
							installed_date: new Date().toISOString(),
							source_package: pkgEntry.entryName,
							file_hashes: fileHashes,
							public_functions: extractPublicFunctions(libFiles, libDestDir),
							required_dependencies: extractRequiredDependencies(libFiles, libDestDir),
							labware_files: labwareFiles,
							labware_install_path: labwareFiles.length > 0 ? labwareBasePathArch : null,
							bin_files: manifest.bin_files || [],
							bin_install_path: (manifest.bin_files || []).length > 0 ? binBasePathArch : null,
							publisher_cert: (innerSig && innerSig.code_signed && innerSig.valid && innerSig.publisher_cert) ? innerSig.publisher_cert : null
						};
						// Forward-compat: preserve unknown manifest fields in DB record
						Object.keys(manifest).forEach(function(mk) { if (shared.KNOWN_MANIFEST_KEYS.indexOf(mk) === -1 && !(mk in dbRecord)) dbRecord[mk] = manifest[mk]; });
						var saved = db_installed_libs.installed_libs.save(dbRecord);

						// Write .libmgr marker file
						try { shared.updateMarkerForLibrary(dbRecord); } catch(_) { /* non-critical */ }

						// Update publisher registry
						registerPublisher(manifest.author || '');
						registerPublisher(manifest.organization || '');
						registerTags(manifest.tags || []);

						// Collect COM DLL paths for deferred batch registration
						// (all DLLs across all packages are registered in one UAC prompt after the loop)
						if (comDlls.length > 0) {
							var dllPaths = comDlls.map(function(d) { return path.join(libDestDir, d); })
								.filter(function(p) { return fs.existsSync(p); });
							for (var cdi = 0; cdi < dllPaths.length; cdi++) {
								allComDllPaths.push({dllPath: dllPaths[cdi], libName: libName, savedId: saved._id});
							}
						}

						// Auto-add to group
						var navtree = db_tree.tree.find();
						var targetGroupId = null;
						var archImportAuthor = (manifest.author || '').trim();
						var archImportOrg = (manifest.organization || '').trim();

						if (isRestrictedAuthor(archImportAuthor) || isRestrictedAuthor(archImportOrg)) {
							// Restricted OEM author: add to the OEM group
							targetGroupId = addToOemTreeGroup(saved._id);
						} else {
							// Non-restricted author: add to first custom group
							for (var ti = 0; ti < navtree.length; ti++) {
								var gEntry = getGroupById(navtree[ti]["group-id"]);
								if (gEntry && !gEntry["default"]) {
									targetGroupId = navtree[ti]["group-id"];
									var existingIds = (navtree[ti]["method-ids"] || []).slice();
									existingIds.push(saved._id);
									db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
									break;
								}
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
				})(); }

				// ---- Batch COM registration: register ALL COM DLLs in one UAC prompt ----
				if (allComDllPaths.length > 0) {
					var allDllPathsFlat = allComDllPaths.map(function(c) { return c.dllPath; });
					try {
						var batchComResult = await comRegisterMultipleDlls(allDllPathsFlat, true);

						// Build a lookup: dllPath -> success
						var comResultMap = {};
						for (var cri = 0; cri < batchComResult.results.length; cri++) {
							comResultMap[batchComResult.results[cri].dll] = batchComResult.results[cri];
						}

						// Update each library's DB record based on per-DLL results
						var processedLibs = {};
						for (var cli = 0; cli < allComDllPaths.length; cli++) {
							var comEntry = allComDllPaths[cli];
							if (!processedLibs[comEntry.libName]) {
								processedLibs[comEntry.libName] = { savedId: comEntry.savedId, allOk: true };
							}
							var dllResult = comResultMap[comEntry.dllPath];
							if (!dllResult || !dllResult.success) {
								processedLibs[comEntry.libName].allOk = false;
							}
						}

						Object.keys(processedLibs).forEach(function(pLibName) {
							var pInfo = processedLibs[pLibName];
							if (pInfo.allOk) {
								db_installed_libs.installed_libs.update(
									{"_id": pInfo.savedId},
									{"com_warning": false, "com_registered": true},
									{multi: false, upsert: false}
								);
							} else {
								console.warn('COM registration failed for ' + pLibName + ' (archive import)');
							}
						});

						if (!batchComResult.allSuccess) {
							var failedComDlls = batchComResult.results.filter(function(r) { return !r.success; });
							console.warn('[archive-import] COM registration: ' + failedComDlls.length + ' of ' + allDllPathsFlat.length + ' DLL(s) failed');
							var comWarningLibs = [];
							Object.keys(processedLibs).forEach(function(pLibName) {
								if (!processedLibs[pLibName].allOk) comWarningLibs.push(pLibName);
							});
							if (comWarningLibs.length > 0) {
								results.comWarnings = comWarningLibs;
							}
						}
					} catch(comErr) {
						console.warn('[archive-import] COM batch registration error: ' + comErr.message);
					}
				}

				// Show results
				var archImpListHtml = '<div style="text-align:left;">';
				if (results.success.length > 0) {
					results.success.forEach(function(n) {
						archImpListHtml += '<div style="margin-bottom:4px;"><i class="fas fa-check text-success mr-1"></i>' + escapeHtml(n) + '</div>';
					});
				}
				if (results.failed.length > 0) {
					results.failed.forEach(function(n) {
						archImpListHtml += '<div style="margin-bottom:4px;"><i class="fas fa-times text-danger mr-1"></i>' + escapeHtml(n) + '</div>';
					});
				}
				archImpListHtml += '</div>';

				var archImpTitle = results.failed.length > 0 ? "Archive Import Complete" : "Archive Imported Successfully!";

				var archImpStatusHtml = null;
				var archImpStatusClass = null;
				if (results.comWarnings && results.comWarnings.length > 0) {
					archImpStatusHtml = '<i class="fas fa-exclamation-triangle mr-1"></i>COM registration failed for: ' + results.comWarnings.map(function(n) { return escapeHtml(n); }).join(', ');
					archImpStatusClass = 'com-warning';
					archImpTitle = "Archive Import Complete";
				}

				showGenericSuccessModal({
					title: archImpTitle,
					detail: results.success.length + " succeeded" + (results.failed.length > 0 ? ", " + results.failed.length + " failed" : ""),
					listHtml: archImpListHtml,
					statusHtml: archImpStatusHtml,
					statusClass: archImpStatusClass
				});

				// ---- Audit trail entry ----
				try {
					appendAuditTrailEntry(buildAuditTrailEntry('archive_imported', {
						archive_file:    archivePath,
						packages_total:  pkgEntries.length,
						succeeded:       results.success,
						failed:          results.failed
					}));
				} catch(_) { /* non-critical */ }

				// Refresh the library cards
				impBuildLibraryCards();
				fitImporterHeight();

			} catch(e) {
				alert("Error importing archive:\n" + e.message);
			} finally {
				_isImporting = false;
			}
		}
		// ---- Clicking a tag badge triggers #tag search ----
		$(document).on("click", ".imp-tag-badge", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var tag = $(this).attr("data-tag");
			if (!tag) return;
			$("#imp-search-input").val("#" + tag).trigger("input");
		});

		$(document).on("mouseenter", ".imp-tag-badge", function() {
			$(this).closest(".imp-lib-card").addClass("imp-lib-card-tag-hover");
		});

		$(document).on("mouseleave", ".imp-tag-badge", function() {
			$(this).closest(".imp-lib-card").removeClass("imp-lib-card-tag-hover");
		});

		// ---- Clicking tag ellipsis opens the library detail modal ----
		$(document).on("click", ".imp-tag-ellipsis", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var libId = $(this).attr("data-lib-id");
			if (libId) impShowLibDetail(libId);
		});

		// ---- Detect tag overflow and show/hide ellipsis indicators ----
		function _updateCardTagOverflow() {
			$(".imp-lib-card-tags").each(function() {
				var el = this;
				var $ellipsis = $(el).children(".imp-tag-ellipsis");
				if ($ellipsis.length === 0) return;
				// Temporarily hide ellipsis to measure natural overflow
				$ellipsis.hide();
				var hasTags = $(el).children(".imp-tag-badge").length > 0;
				// Check if content overflows the two-row max-height
				var hasOverflow = el.scrollHeight > el.clientHeight;
				if (hasOverflow && hasTags) {
					$ellipsis.css("display", "inline-flex");
				} else {
					$ellipsis.hide();
				}
			});
		}

		$(document).on("click", ".imp-lib-card:not(.imp-unsigned-lib-card)", function(e) {
			// Don't open detail modal when clicking the Help link, Star, Tag badge, or Tag ellipsis
			if ($(e.target).closest(".imp-lib-card-help-link, .imp-help-dropdown").length) return;
			if ($(e.target).closest(".imp-lib-star").length) return;
			if ($(e.target).closest(".imp-tag-badge, .imp-tag-ellipsis").length) return;
			e.preventDefault();
			var libId = $(this).closest(".imp-lib-card-container").attr("data-lib-id");
			if (libId) impShowLibDetail(libId);
		});

		// ---- Toggle star on a library card ----
		$(document).on("click", ".imp-lib-star", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var libId = $(this).attr("data-lib-id");
			if (!libId) return;
			var nowStarred = toggleStarLib(libId);
			// Update just this star icon in-place
			$(this).attr("title", nowStarred ? "Unstar" : "Star");
			$(this).find("i").removeClass("fas far").addClass(nowStarred ? "fas" : "far");
			// If we're on the Starred tab, rebuild cards to reflect removal
			var activeGroup = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id");
			if (activeGroup === "gStarred" && !nowStarred) {
				impBuildLibraryCards(null, false, false, false, true);
				fitImporterHeight();
			}
		});

		// ---- Open CHM help file when clicking the Help link on a card ----
		// Single-CHM: direct click opens the file. Multi-CHM with default: opens the default file.
		// Multi-CHM without default: dropdown-toggle is handled by Bootstrap,
		// and individual items are handled by .imp-help-dropdown-item below.
		$(document).on("click", ".imp-lib-card-help-link:not(.dropdown-toggle)", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var libId = $(this).attr("data-lib-id");
			if (!libId) return;

			var defaultChm = $(this).attr("data-default-chm") || '';

			// Check if it's a system library
			if (isSystemLibrary(libId)) {
				var sLib = getSystemLibrary(libId);
				if (!sLib) return;
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';
				var chmFiles = (sLib.discovered_files || []).filter(function(f) {
					return path.extname(f).toLowerCase() === '.chm';
				});
				if (chmFiles.length > 0) {
					// Use default CHM if specified, otherwise first
					var targetChm = chmFiles[0];
					if (defaultChm) {
						var matched = chmFiles.find(function(f) {
							return f.replace(/\\/g, '/').split('/').pop() === defaultChm || f === defaultChm;
						});
						if (matched) targetChm = matched;
					}
					var relPath = targetChm.replace(/^Library[\\\/]/i, '');
					var fullPath = path.join(sysLibDir, relPath);
					if (fs.existsSync(fullPath)) {
						safeOpenItem(fullPath);
					}
				}
			} else {
				var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
				if (!lib) return;
				var helpFiles = lib.help_files || [];
				var chmFile;
				if (defaultChm) {
					chmFile = helpFiles.find(function(f) { return f === defaultChm || path.basename(f) === defaultChm; });
				}
				if (!chmFile) {
					chmFile = helpFiles.find(function(f) { return path.extname(f).toLowerCase() === '.chm'; });
				}
				if (chmFile) {
					var libBasePath = lib.lib_install_path || '';
					var fullPath = libBasePath ? path.join(libBasePath, chmFile) : chmFile;
					if (fs.existsSync(fullPath)) {
						safeOpenItem(fullPath);
					}
				}
			}
		});

		// ---- Open a specific CHM file from the multi-CHM help dropdown ----
		$(document).on("click", ".imp-help-dropdown-item", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var libId = $(this).attr("data-lib-id");
			var chmFileName = $(this).attr("data-chm-file");
			if (!libId || !chmFileName) return;

			// Close the dropdown
			$(this).closest(".imp-help-dropdown").find(".dropdown-menu").removeClass("show");
			$(this).closest(".imp-help-dropdown").find(".dropdown-toggle").attr("aria-expanded", "false");

			if (isSystemLibrary(libId)) {
				var sLib = getSystemLibrary(libId);
				if (!sLib) return;
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';
				// Find the matching discovered file for this CHM basename
				var matchedFile = (sLib.discovered_files || []).find(function(f) {
					var basename = f.replace(/\\/g, '/').split('/').pop();
					return basename === chmFileName;
				});
				if (matchedFile) {
					var relPath = matchedFile.replace(/^Library[\\\/]/i, '');
					var fullPath = path.join(sysLibDir, relPath);
					if (fs.existsSync(fullPath)) {
						safeOpenItem(fullPath);
					}
				}
			} else {
				var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
				if (!lib) return;
				var libBasePath = lib.lib_install_path || '';
				var fullPath = libBasePath ? path.join(libBasePath, chmFileName) : chmFileName;
				if (fs.existsSync(fullPath)) {
					safeOpenItem(fullPath);
				}
			}
		});

		// ---- Open library/demo file when clicking a file link in the detail modal ----
		$(document).on("click", ".pkg-file-link", function(e) {
			e.preventDefault();
			var filePath = $(this).attr("data-filepath");
			if (filePath) {
				safeOpenItem(filePath);
			}
		});

		// ---- Open file location folder when clicking the folder icon in the detail modal ----
		$(document).on("click", ".pkg-file-open-folder", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var folderPath = $(this).attr("data-folderpath");
			if (folderPath && fs.existsSync(folderPath)) {
				nw.Shell.openItem(folderPath);
			}
		});

		// ---- Open install path folder when clicking in the detail modal ----
		$(document).on("click", ".detail-path-link", function(e) {
			e.preventDefault();
			var folderPath = $(this).attr("data-folderpath");
			if (folderPath && fs.existsSync(folderPath)) {
				nw.Shell.openItem(folderPath);
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

		// ---- Show regulated mode confirmation modal (requires typing "I Accept") ----
		function showRegulatedModeConfirmModal(enabling) {
			return new Promise(function(resolve) {
				var $modal = $("#regulatedModeConfirmModal");
				var expectedText = "I Accept";
				var resolved = false;

				// Set modal content based on enable/disable
				if (enabling) {
					$modal.find(".reg-confirm-title").text("Enable Regulated Environment Mode");
					$modal.find(".reg-confirm-icon i").removeClass("fa-unlock").addClass("fa-lock");
					$modal.find(".reg-confirm-header").css("background", "#5f1616").css("border-bottom-color", "#d73a49");
					$modal.find(".reg-confirm-warning-box").html(
						'<p class="mb-2"><strong><i class="fas fa-exclamation-triangle mr-1"></i>This is a potentially destructive action that affects all users on this system.</strong></p>' +
						'<p class="mb-2">Enabling regulated environment mode will <b>restrict library management actions</b> (import, delete, rollback) to only users who belong to authorized Windows security groups (Lab Method Programmer, Lab Service) or Windows Administrators.</p>' +
						'<p class="mb-2"><b>All other users will be immediately locked out</b> of these actions. Unsigned library scanning will be automatically disabled, as all packages must be signed in regulated mode.</p>' +
						'<p class="mb-0">Ensure that all necessary users are assigned to the correct Windows security groups before proceeding.</p>'
					);
					$modal.find(".reg-confirm-btn").html('<i class="fas fa-lock mr-1"></i>I understand, enable regulated mode');
					$modal.find(".reg-confirm-btn").removeClass("btn-success").addClass("btn-danger");
					$modal.find(".reg-confirm-disclaimer-box").html(
						'<p class="mb-1"><strong><i class="fas fa-info-circle mr-1"></i>Important Disclaimer</strong></p>' +
						'<p class="mb-1">Regulated environment mode is provided as an optional feature intended to help reduce certain operational risks (for example, by disabling optional behaviors). ' +
						'It <b>does not</b> guarantee compliance with any law, regulation, guidance, or internal policy, and <b>does not</b> replace required validation/qualification, documentation, change control, audit readiness, or security controls in your environment.</p>' +
						'<p class="mb-0">The developer makes no warranties or representations regarding regulated use, and assumes no liability arising from reliance on or use of regulated environment mode.</p>'
					).show();
				} else {
					$modal.find(".reg-confirm-title").text("Disable Regulated Environment Mode");
					$modal.find(".reg-confirm-icon i").removeClass("fa-lock").addClass("fa-unlock");
					$modal.find(".reg-confirm-header").css("background", "#1a3a1a").css("border-bottom-color", "#28a745");
					$modal.find(".reg-confirm-warning-box").html(
						'<p class="mb-2"><strong><i class="fas fa-exclamation-triangle mr-1"></i>This is a potentially destructive action that affects all users on this system.</strong></p>' +
						'<p class="mb-2">Disabling regulated environment mode will <b>remove all access restrictions</b>. Every user on this system will be able to import, delete, and roll back libraries regardless of their Windows security group membership.</p>' +
						'<p class="mb-0">Users in explicitly denied groups (Lab Operator, Lab Operator 2, Lab Remote Service) will still be blocked, but all other users &mdash; including those without any group assignment &mdash; will gain full access.</p>'
					);
					$modal.find(".reg-confirm-btn").html('<i class="fas fa-unlock mr-1"></i>I understand, disable regulated mode');
					$modal.find(".reg-confirm-btn").removeClass("btn-danger").addClass("btn-success");
					$modal.find(".reg-confirm-disclaimer-box").hide();
				}

				// Reset input and button state
				$modal.find(".reg-confirm-input").val("");
				$modal.find(".reg-confirm-btn").prop("disabled", true);

				// Enable/disable the confirm button based on typed input
				$modal.find(".reg-confirm-input").off("input.regConfirm").on("input.regConfirm", function() {
					var typed = $(this).val().trim();
					$modal.find(".reg-confirm-btn").prop("disabled", typed !== expectedText);
				});

				// Confirm button handler
				$modal.find(".reg-confirm-btn").off("click.regConfirm").on("click.regConfirm", function() {
					if (!resolved) {
						resolved = true;
						$modal.modal("hide");
						resolve(true);
					}
				});

				// Cancel / dismiss handler
				$modal.off("hidden.bs.modal.regConfirm").on("hidden.bs.modal.regConfirm", function() {
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

			// ---- Access control check ----
			var accessCheck = canManageLibraries();
			if (!accessCheck.allowed) {
				showAccessDeniedModal('Delete Library', accessCheck.reason);
				return;
			}

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

			// Remove .libmgr marker entry for this library
			try { shared.removeMarkerEntry(libPath, libName); } catch(_) { /* non-critical */ }

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

			// ---- Audit trail entry ----
			try {
				appendAuditTrailEntry(buildAuditTrailEntry('library_deleted', {
					library_name: lib.library_name || '',
					version:      lib.version || '',
					author:       lib.author || '',
					delete_type:  'soft'
				}));
			} catch(_) { /* non-critical */ }

			// --- Remove from tree ---
			var navtree = db_tree.tree.find();
			for (var ti = 0; ti < navtree.length; ti++) {
				var mids = (navtree[ti]["method-ids"] || []).slice();  // clone to avoid mutating DiskDB internal array
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
			var filePaths = [];
			if (fileInput.files && fileInput.files.length > 0) {
				for (var fi = 0; fi < fileInput.files.length; fi++) {
					filePaths.push(fileInput.files[fi].path);
				}
			} else {
				var val = $(this).val();
				if (val) filePaths.push(val);
			}
			$(this).val('');
			if (filePaths.length === 0) return;

			// Separate archives from packages
			var archives = [];
			var packages = [];
			filePaths.forEach(function(fp) {
				var ext = path.extname(fp).toLowerCase();
				if (ext === ".hxlibarch") {
					archives.push(fp);
				} else {
					packages.push(fp);
				}
			});

			// If only one package and no archives, use the existing single-file preview flow
			if (packages.length === 1 && archives.length === 0) {
				impLoadAndInstall(packages[0]);
				return;
			}

			// If only archives and no packages, import archives sequentially
			if (packages.length === 0 && archives.length > 0) {
				(async function() {
					for (var ai = 0; ai < archives.length; ai++) {
						await impArchImportArchive(archives[ai]);
					}
				})();
				return;
			}

			// Defer heavy work to let file dialog close immediately
			setTimeout(function() {
				impBatchImportPackages(packages, archives);
			}, 50);
		});

		// ---- Batch import multiple .hxlibpkg files (with single UAC for COM) ----

		// Promise-based modal helpers for batch import
		function _batchShowConfirmModal() {
			return new Promise(function(resolve) {
				var $m = $("#batchImportModal");
				$m.find(".batch-import-footer").show();
				$m.find(".batch-import-cancel-x").show();
				$m.find(".batch-import-confirm-btn").off("click.batch").on("click.batch", function() { resolve(true); });
				$m.find(".batch-import-cancel-btn").off("click.batch").on("click.batch", function() { resolve(false); });
				$m.find(".batch-import-cancel-x").off("click.batch").on("click.batch", function() { resolve(false); });
			});
		}
		function _batchShowDupModal(duplicates) {
			return new Promise(function(resolve) {
				var $m = $("#batchDuplicateModal");
				$m.find(".batch-dup-subtitle").text(duplicates.length + " librar" + (duplicates.length !== 1 ? "ies" : "y"));
				var listHtml = '';
				duplicates.forEach(function(d) {
					var verText = '';
					if (d.existingVersion !== '?' && d.incomingVersion !== '?' && d.existingVersion === d.incomingVersion) {
						verText = 'same version: v' + escapeHtml(d.existingVersion);
					} else {
						verText = 'v' + escapeHtml(d.existingVersion) + ' &rarr; v' + escapeHtml(d.incomingVersion);
					}
					listHtml += '<div class="batch-dup-item"><div><span class="batch-dup-name">' + escapeHtml(d.libName) + '</span></div><div class="batch-dup-versions">' + verText + '</div></div>';
				});
				$m.find(".batch-dup-list").html(listHtml);
				$m.find(".batch-dup-replace-btn").off("click.batch").on("click.batch", function() { $m.modal("hide"); resolve(true); });
				$m.find(".batch-dup-skip-btn").off("click.batch").on("click.batch", function() { $m.modal("hide"); resolve(false); });
				$m.modal("show");
			});
		}
		function _batchShowComModal(dllCount, pkgNames) {
			return new Promise(function(resolve) {
				var $m = $("#batchComModal");
				$m.find(".batch-com-message").text("This batch contains " + dllCount + " COM DLL" + (dllCount !== 1 ? "s" : "") + " across " + pkgNames.length + " package" + (pkgNames.length !== 1 ? "s" : "") + " that require registration:");
				var listHtml = '';
				pkgNames.forEach(function(n) { listHtml += '<div class="batch-com-item"><i class="fas fa-cube"></i>' + escapeHtml(n) + '</div>'; });
				$m.find(".batch-com-list").html(listHtml);
				$m.find(".batch-com-continue-btn").off("click.batch").on("click.batch", function() { $m.modal("hide"); resolve(true); });
				$m.find(".batch-com-cancel-btn").off("click.batch").on("click.batch", function() { $m.modal("hide"); resolve(false); });
				$m.modal("show");
			});
		}
		function _batchYield() {
			return new Promise(function(resolve) { setTimeout(resolve, 0); });
		}

		async function impBatchImportPackages(packagePaths, archivePaths) {
			var accessCheck = canManageLibraries();
			if (!accessCheck.allowed) {
				showAccessDeniedModal('Import Library', accessCheck.reason);
				return;
			}

			if (_isImporting) {
				alert("An import is already in progress. Please wait for it to complete.");
				return;
			}
			_isImporting = true;

			// Show batch import modal immediately with scanning progress
			var $bm = $("#batchImportModal");
			$bm.find(".batch-import-header-title").text("Preparing Import\u2026");
			$bm.find(".batch-import-header-subtitle").text(packagePaths.length + " file" + (packagePaths.length !== 1 ? "s" : "") + " selected");
			$bm.find(".batch-import-phase-scan").removeClass("d-none");
			$bm.find(".batch-import-phase-confirm").addClass("d-none");
			$bm.find(".batch-import-phase-install").addClass("d-none");
			$bm.find(".batch-import-footer").hide();
			$bm.find(".batch-import-cancel-x").hide();
			$bm.find(".batch-import-progress-bar").css("width", "0%");
			$bm.find(".batch-import-scan-status").text("Scanning packages\u2026");
			$bm.modal("show");

			try {
				// ---- Pre-scan all packages: parse manifests, check duplicates, detect COM ----
				var pkgInfos = [];
				var parseErrors = [];
				var totalFiles = packagePaths.length;

				for (var pi = 0; pi < packagePaths.length; pi++) {
					// Update progress
					var pct = Math.round(((pi + 1) / totalFiles) * 100);
					$bm.find(".batch-import-progress-bar").css("width", pct + "%");
					$bm.find(".batch-import-scan-status").text("Scanning package " + (pi + 1) + " of " + totalFiles + "\u2026");

					// Yield to UI to keep responsive
					await _batchYield();

					try {
						var rawBuffer = fs.readFileSync(packagePaths[pi]);
						var zipBuffer = unpackContainer(rawBuffer, CONTAINER_MAGIC_PKG);
						var zip = new AdmZip(zipBuffer);
						var manifestEntry = zip.getEntry("manifest.json");
						if (!manifestEntry) {
							parseErrors.push(path.basename(packagePaths[pi]) + ": manifest.json not found");
							continue;
						}
						var manifest = JSON.parse(zip.readAsText(manifestEntry));
						var libName = manifest.library_name || "Unknown";

						if (!isValidLibraryName(libName)) {
							parseErrors.push(path.basename(packagePaths[pi]) + ": invalid library name");
							continue;
						}

						// Validate author/organization
						var batchAuthor = (manifest.author || '').trim();
						var batchOrg = (manifest.organization || '').trim();
						if (batchAuthor) {
							var batchAuthorChk = shared.isValidAuthorName(batchAuthor);
							if (!batchAuthorChk.valid) {
								parseErrors.push(libName + ": " + batchAuthorChk.reason);
								continue;
							}
						}
						if (batchOrg) {
							var batchOrgChk = shared.isValidOrganizationName(batchOrg);
							if (!batchOrgChk.valid) {
								parseErrors.push(libName + ": " + batchOrgChk.reason);
								continue;
							}
						}

						// Validate manifest paths
						var pathValidation = shared.validateManifestPaths(manifest);
						if (!pathValidation.valid) {
							parseErrors.push(libName + ": unsafe file paths detected");
							continue;
						}

						// Verify signature
						var sigResult = verifyPackageSignature(zip);
						if (sigResult.signed && !sigResult.valid) {
							parseErrors.push(libName + ": signature verification FAILED (" + sigResult.errors.join("; ") + ")");
							continue;
						}

						pkgInfos.push({
							filePath: packagePaths[pi],
							zip: zip,
							manifest: manifest,
							sigResult: sigResult,
							libName: libName,
							comDlls: manifest.com_register_dlls || []
						});
					} catch (e) {
						parseErrors.push(path.basename(packagePaths[pi]) + ": " + e.message);
					}
				}

				if (pkgInfos.length === 0 && archivePaths.length === 0) {
					$bm.modal("hide");
					var errMsg = "No valid packages found to import.";
					if (parseErrors.length > 0) errMsg += "\n\n" + parseErrors.join("\n");
					alert(errMsg);
					return;
				}

				// ---- Switch to confirmation phase ----
				$bm.find(".batch-import-phase-scan").addClass("d-none");
				$bm.find(".batch-import-phase-confirm").removeClass("d-none");
				$bm.find(".batch-import-header-title").text("Confirm Import");

				// Build package list HTML
				var listHtml = '';
				pkgInfos.forEach(function(info) {
					var ver = info.manifest.version ? 'v' + escapeHtml(info.manifest.version) : '';
					listHtml += '<div class="batch-import-pkg-item">';
					listHtml += '<i class="fas fa-cube batch-pkg-icon"></i>';
					listHtml += '<span class="batch-pkg-name">' + escapeHtml(info.libName) + '</span>';
					if (ver) listHtml += '<span class="batch-pkg-version">' + ver + '</span>';
					listHtml += '</div>';
				});
				archivePaths.forEach(function(ap) {
					listHtml += '<div class="batch-import-pkg-item">';
					listHtml += '<i class="fas fa-archive batch-pkg-icon"></i>';
					listHtml += '<span class="batch-pkg-name">' + escapeHtml(path.basename(ap)) + '</span>';
					listHtml += '<span class="batch-pkg-archive">archive</span>';
					listHtml += '</div>';
				});
				$bm.find(".batch-import-pkg-list").html(listHtml);

				// errors section
				var $errors = $bm.find(".batch-import-errors");
				if (parseErrors.length > 0) {
					var errHtml = '<div class="batch-import-error-title"><i class="fas fa-times-circle mr-1"></i>Skipped (' + parseErrors.length + ')</div>';
					parseErrors.forEach(function(e) { errHtml += '<div class="batch-import-error-item"><i class="fas fa-times mr-1"></i>' + escapeHtml(e) + '</div>'; });
					$errors.html(errHtml).removeClass("d-none");
				} else {
					$errors.addClass("d-none");
				}

				// Update button text
				var totalImportable = pkgInfos.length + archivePaths.length;
				$bm.find(".batch-import-confirm-btn").html('<i class="fas fa-file-import mr-1"></i>Import ' + (totalImportable > 1 ? 'All ' + totalImportable : ''));
				$bm.find(".batch-import-header-subtitle").text(pkgInfos.length + " package" + (pkgInfos.length !== 1 ? "s" : "") + (archivePaths.length > 0 ? " + " + archivePaths.length + " archive" + (archivePaths.length !== 1 ? "s" : "") : ""));

				// Wait for user confirmation
				var confirmed = await _batchShowConfirmModal();
				if (!confirmed) {
					$bm.modal("hide");
					return;
				}

				// ---- Duplicate detection ----
				var batchDuplicates = [];
				var batchSkipIndices = {};
				for (var di = 0; di < pkgInfos.length; di++) {
					var dupExisting = db_installed_libs.installed_libs.findOne({"library_name": pkgInfos[di].libName});
					if (dupExisting && !dupExisting.deleted) {
						batchDuplicates.push({
							index: di,
							libName: pkgInfos[di].libName,
							incomingVersion: pkgInfos[di].manifest.version || '?',
							existingVersion: dupExisting.version || '?'
						});
					}
				}

				if (batchDuplicates.length > 0) {
					var replaceDups = await _batchShowDupModal(batchDuplicates);
					if (!replaceDups) {
						batchDuplicates.forEach(function(d) { batchSkipIndices[d.index] = true; });
						var remaining = pkgInfos.filter(function(_, idx) { return !batchSkipIndices[idx]; });
						if (remaining.length === 0 && archivePaths.length === 0) {
							$bm.modal("hide");
							alert("All selected packages are already installed. No changes were made.");
							return;
						}
					}
				}

				// ---- COM DLL pre-scan: detect all COM registrations across all packages ----
				var batchComDllCount = 0;
				var batchComPkgNames = [];
				for (var ci = 0; ci < pkgInfos.length; ci++) {
					if (batchSkipIndices[ci]) continue;
					if (pkgInfos[ci].comDlls.length > 0) {
						batchComDllCount += pkgInfos[ci].comDlls.length;
						batchComPkgNames.push(pkgInfos[ci].libName);
					}
				}

				if (batchComDllCount > 0) {
					var comConfirmed = await _batchShowComModal(batchComDllCount, batchComPkgNames);
					if (!comConfirmed) {
						$bm.modal("hide");
						return;
					}
				}

				// ---- Switch to install phase with progress ----
				$bm.find(".batch-import-phase-confirm").addClass("d-none");
				$bm.find(".batch-import-phase-install").removeClass("d-none");
				$bm.find(".batch-import-footer").hide();
				$bm.find(".batch-import-cancel-x").hide();
				$bm.find(".batch-import-header-title").text("Installing\u2026");
				$bm.find(".batch-import-install-bar").css("width", "0%");

				// ---- Install each package ----
				var results = { success: [], failed: parseErrors.slice() };
				var allComDllPaths = [];

				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				var labFolderBatch = db_links.links.findOne({"_id":"labware-folder"});
				var labwareBasePathBatch = labFolderBatch ? labFolderBatch.path : (function() {
					var hamiltonDir = path.dirname(libBasePath);
					var sibling = path.join(hamiltonDir, 'Labware');
					return fs.existsSync(sibling) ? sibling : 'C:\\Program Files (x86)\\HAMILTON\\Labware';
				})();
				var binFolderBatch = db_links.links.findOne({"_id":"bin-folder"});
				var binBasePathBatch = binFolderBatch ? binFolderBatch.path : 'C:\\Program Files (x86)\\HAMILTON\\Bin';

				var installableCount = pkgInfos.filter(function(_, idx) { return !batchSkipIndices[idx]; }).length;
				var installedSoFar = 0;

				for (var ii = 0; ii < pkgInfos.length; ii++) { await (async function() {
					var info = pkgInfos[ii];
					if (batchSkipIndices[ii]) {
						results.failed.push(info.libName + ": skipped (already installed)");
						return;
					}

					// Update install progress
					installedSoFar++;
					var installPct = Math.round((installedSoFar / installableCount) * 100);
					$bm.find(".batch-import-install-bar").css("width", installPct + "%");
					$bm.find(".batch-import-install-status").text("Installing package " + installedSoFar + " of " + installableCount + "\u2026");
					$bm.find(".batch-import-install-current").text(info.libName);
					await _batchYield();

					try {
						var zip = info.zip;
						var manifest = info.manifest;
						var libName = info.libName;
						var comDlls = info.comDlls;
						var sigResult = info.sigResult;

						var origLibFiles = manifest.library_files || [];
						var demoFiles = manifest.demo_method_files || [];

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

						var installToRoot = !!manifest.install_to_library_root;
						var customSubdir = manifest.custom_install_subdir || '';
						var libDestDir;
						if (installToRoot) {
							libDestDir = libBasePath;
						} else if (customSubdir) {
							libDestDir = path.join(libBasePath, customSubdir);
						} else {
							libDestDir = path.join(libBasePath, libName);
						}
						var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);
						var labwareFiles = manifest.labware_files || [];
						var binFiles = manifest.bin_files || [];
						var extractedCount = 0;

						// Create destination directories
						if ((libFiles.length > 0 || helpFiles.length > 0) && !fs.existsSync(libDestDir)) {
							fs.mkdirSync(libDestDir, { recursive: true });
						}
						if (demoFiles.length > 0 && !fs.existsSync(demoDestDir)) {
							fs.mkdirSync(demoDestDir, { recursive: true });
						}

						// Extract files
						var zipEntries = zip.getEntries();
						zipEntries.forEach(function(entry) {
							if (entry.entryName === "manifest.json" || entry.entryName === "signature.json") return;
							if (entry.entryName.indexOf("library/") === 0) {
								var fname = entry.entryName.substring("library/".length);
								if (fname) {
									var outPath = safeZipExtractPath(libDestDir, fname);
									if (!outPath) return;
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("demo_methods/") === 0) {
								var fname = entry.entryName.substring("demo_methods/".length);
								if (fname) {
									var outPath = safeZipExtractPath(demoDestDir, fname);
									if (!outPath) return;
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("help_files/") === 0) {
								var fname = entry.entryName.substring("help_files/".length);
								if (fname) {
									var outPath = safeZipExtractPath(libDestDir, fname);
									if (!outPath) return;
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("labware/") === 0) {
								var fname = entry.entryName.substring("labware/".length);
								if (fname) {
									var outPath = safeZipExtractPath(labwareBasePathBatch, fname);
									if (!outPath) return;
									var parentDir = path.dirname(outPath);
									if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
									fs.writeFileSync(outPath, entry.getData());
									extractedCount++;
								}
							} else if (entry.entryName.indexOf("bin/") === 0) {
								var fname = entry.entryName.substring("bin/".length);
								if (fname) {
									var outPath = safeZipExtractPath(binBasePathBatch, fname);
									if (!outPath) return;
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

						var fileHashes = {};
						try { fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls); } catch(e) {}

						var dbRecord = {
							library_name: manifest.library_name || "",
							author: manifest.author || "",
							organization: manifest.organization || "",
							installed_by: getWindowsUsername(),
							version: manifest.version || "",
							venus_compatibility: manifest.venus_compatibility || "",
							description: manifest.description || "",
							github_url: manifest.github_url || "",
							tags: manifest.tags || [],
							created_date: manifest.created_date || "",
							app_version: manifest.app_version || "",
							format_version: manifest.format_version || "1.0",
							windows_version: manifest.windows_version || "",
							venus_version: manifest.venus_version || "",
							package_lineage: manifest.package_lineage || [],
							library_image: manifest.library_image || null,
							library_image_base64: manifest.library_image_base64 || null,
							library_image_mime: manifest.library_image_mime || null,
							library_files: libFiles,
							demo_method_files: manifest.demo_method_files || [],
							help_files: helpFiles,
							com_register_dlls: comDlls,
							com_warning: comDlls.length > 0,
							com_registered: false,
							lib_install_path: libDestDir,
							demo_install_path: demoDestDir,
							install_to_library_root: !!manifest.install_to_library_root,
							custom_install_subdir: manifest.custom_install_subdir || '',
							installed_date: new Date().toISOString(),
							source_package: path.basename(info.filePath),
							file_hashes: fileHashes,
							public_functions: extractPublicFunctions(libFiles, libDestDir),
							required_dependencies: extractRequiredDependencies(libFiles, libDestDir),
							publisher_cert: (sigResult && sigResult.code_signed && sigResult.valid && sigResult.publisher_cert) ? sigResult.publisher_cert : null,
							converted_from_executable: !!(sigResult && sigResult.converted),
							source_certificate: (sigResult && sigResult.converted && sigResult.source_certificate) ? sigResult.source_certificate : null,
							conversion_source: (sigResult && sigResult.converted && sigResult.conversion_source) ? sigResult.conversion_source : null,
							labware_files: labwareFiles,
							labware_install_path: labwareFiles.length > 0 ? labwareBasePathBatch : null,
							bin_files: binFiles,
							bin_install_path: binFiles.length > 0 ? binBasePathBatch : null
						};
						Object.keys(manifest).forEach(function(mk) { if (shared.KNOWN_MANIFEST_KEYS.indexOf(mk) === -1 && !(mk in dbRecord)) dbRecord[mk] = manifest[mk]; });
						var saved = db_installed_libs.installed_libs.save(dbRecord);

						try { shared.updateMarkerForLibrary(dbRecord); } catch(_) {}

						registerPublisher(manifest.author || '');
						registerPublisher(manifest.organization || '');
						registerTags(manifest.tags || []);

						// Collect COM DLL paths for deferred batch registration
						if (comDlls.length > 0) {
							var dllPaths = comDlls.map(function(d) { return path.join(libDestDir, d); })
								.filter(function(p) { return fs.existsSync(p); });
							for (var cdi = 0; cdi < dllPaths.length; cdi++) {
								allComDllPaths.push({dllPath: dllPaths[cdi], libName: libName, savedId: saved._id});
							}
						}

						// Add to appropriate group
						var navtree = db_tree.tree.find();
						var targetGroupId = null;
						var batchSavedAuthor = (manifest.author || '').trim();
						var batchSavedOrg = (manifest.organization || '').trim();

						if (isRestrictedAuthor(batchSavedAuthor) || isRestrictedAuthor(batchSavedOrg)) {
							targetGroupId = addToOemTreeGroup(saved._id);
						} else {
							for (var ti = 0; ti < navtree.length; ti++) {
								var gEntry = getGroupById(navtree[ti]["group-id"]);
								if (gEntry && !gEntry["default"]) {
									targetGroupId = navtree[ti]["group-id"];
									var existingIds = (navtree[ti]["method-ids"] || []).slice();
									existingIds.push(saved._id);
									db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
									break;
								}
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

						// Cache package
						try {
							var pkgBuffer = fs.readFileSync(info.filePath);
							cachePackageToStore(pkgBuffer, libName, manifest.version);
						} catch(cacheErr) {}

						results.success.push(libName + " (" + extractedCount + " files)");

						// Audit trail
						try {
							var sigStatus = 'unsigned';
							if (sigResult && sigResult.signed) sigStatus = sigResult.valid ? 'valid' : 'failed';
							if (sigResult && sigResult.code_signed) sigStatus = 'code_signed_' + sigStatus;
							appendAuditTrailEntry(buildAuditTrailEntry('library_imported', {
								library_name: libName,
								version: manifest.version || '',
								author: manifest.author || '',
								organization: manifest.organization || '',
								source_file: info.filePath,
								lib_install_path: libDestDir,
								demo_install_path: demoDestDir,
								files_extracted: extractedCount,
								signature_status: sigStatus,
								batch_import: true
							}));
						} catch(_) {}

					} catch(e) {
						results.failed.push(info.libName + ": " + e.message);
					}
				})(); }

				// ---- Batch COM registration: single UAC prompt for ALL COM DLLs ----
				if (allComDllPaths.length > 0) {
					$bm.find(".batch-import-install-status").text("Registering COM objects\u2026");
					$bm.find(".batch-import-install-current").text("");
					await _batchYield();

					var allDllPathsFlat = allComDllPaths.map(function(c) { return c.dllPath; });
					try {
						var batchComResult = await comRegisterMultipleDlls(allDllPathsFlat, true);

						var comResultMap = {};
						for (var cri = 0; cri < batchComResult.results.length; cri++) {
							comResultMap[batchComResult.results[cri].dll] = batchComResult.results[cri];
						}

						var processedLibs = {};
						for (var cli = 0; cli < allComDllPaths.length; cli++) {
							var comEntry = allComDllPaths[cli];
							if (!processedLibs[comEntry.libName]) {
								processedLibs[comEntry.libName] = { savedId: comEntry.savedId, allOk: true };
							}
							var dllResult = comResultMap[comEntry.dllPath];
							if (!dllResult || !dllResult.success) {
								processedLibs[comEntry.libName].allOk = false;
							}
						}

						Object.keys(processedLibs).forEach(function(pLibName) {
							var pInfo = processedLibs[pLibName];
							if (pInfo.allOk) {
								db_installed_libs.installed_libs.update(
									{"_id": pInfo.savedId},
									{"com_warning": false, "com_registered": true},
									{multi: false, upsert: false}
								);
							}
						});

						if (!batchComResult.allSuccess) {
							var comWarningLibs = [];
							Object.keys(processedLibs).forEach(function(pLibName) {
								if (!processedLibs[pLibName].allOk) comWarningLibs.push(pLibName);
							});
							if (comWarningLibs.length > 0) {
								results.comWarnings = comWarningLibs;
							}
						}
					} catch(comErr) {
						console.warn('[batch-import] COM batch registration error: ' + comErr.message);
					}
				}

				// ---- Process any archives after packages ----
				if (archivePaths.length > 0) {
					$bm.find(".batch-import-install-status").text("Importing archives\u2026");
					$bm.find(".batch-import-install-current").text("");
					await _batchYield();
					for (var ai = 0; ai < archivePaths.length; ai++) {
						await impArchImportArchive(archivePaths[ai]);
					}
				}

				// ---- Hide batch modal and show results ----
				$bm.modal("hide");

				var batchListHtml = '<div style="text-align:left;">';
				if (results.success.length > 0) {
					results.success.forEach(function(n) {
						batchListHtml += '<div style="margin-bottom:4px;"><i class="fas fa-check text-success mr-1"></i>' + escapeHtml(n) + '</div>';
					});
				}
				if (results.failed.length > 0) {
					results.failed.forEach(function(n) {
						batchListHtml += '<div style="margin-bottom:4px;"><i class="fas fa-times text-danger mr-1"></i>' + escapeHtml(n) + '</div>';
					});
				}
				batchListHtml += '</div>';

				var batchTitle = results.failed.length > 0 ? "Batch Import Complete" : "All Packages Imported Successfully!";

				var batchStatusHtml = null;
				var batchStatusClass = null;
				if (results.comWarnings && results.comWarnings.length > 0) {
					batchStatusHtml = '<i class="fas fa-exclamation-triangle mr-1"></i>COM registration failed for: ' + results.comWarnings.map(function(n) { return escapeHtml(n); }).join(', ');
					batchStatusClass = 'com-warning';
					batchTitle = "Batch Import Complete";
				}

				showGenericSuccessModal({
					title: batchTitle,
					detail: results.success.length + " succeeded" + (results.failed.length > 0 ? ", " + results.failed.length + " failed" : ""),
					listHtml: batchListHtml,
					statusHtml: batchStatusHtml,
					statusClass: batchStatusClass
				});

				impBuildLibraryCards();
				fitImporterHeight();

			} catch(e) {
				$bm.modal("hide");
				alert("Error during batch import:\n" + e.message);
			} finally {
				_isImporting = false;
			}
		}

		// ---- Load, preview, confirm and install package ----
		async function impLoadAndInstall(filePath) {
			// ---- Access control check ----
			var accessCheck = canManageLibraries();
			if (!accessCheck.allowed) {
				showAccessDeniedModal('Import Library', accessCheck.reason);
				return;
			}

			if (_isImporting) {
				alert("An import is already in progress. Please wait for it to complete.");
				return;
			}
			_isImporting = true;
			try {
				var rawBuffer = fs.readFileSync(filePath);
				var zipBuffer = unpackContainer(rawBuffer, CONTAINER_MAGIC_PKG);
				var zip = new AdmZip(zipBuffer);
				var manifestEntry = zip.getEntry("manifest.json");
				if (!manifestEntry) {
					alert("Invalid package: manifest.json not found.");
					_isImporting = false;
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
					if (!confirm(sigMsg)) { _isImporting = false; return; }
				}



				// ---- Author/organization length validation on import ----
				var importAuthor = (manifest.author || '').trim();
				var importOrg = (manifest.organization || '').trim();
				if (importAuthor) {
					var impAuthorCheck = shared.isValidAuthorName(importAuthor);
					if (!impAuthorCheck.valid) {
						alert("Invalid package: " + impAuthorCheck.reason);
						_isImporting = false;
						return;
					}
				}
				if (importOrg) {
					var impOrgCheck = shared.isValidOrganizationName(importOrg);
					if (!impOrgCheck.valid) {
						alert("Invalid package: " + impOrgCheck.reason);
						_isImporting = false;
						return;
					}
				}

				var libName = manifest.library_name || "Unknown";
				if (!isValidLibraryName(libName)) {
					alert("Invalid library name: \"" + libName + "\".\nLibrary names cannot contain path separators, '..', or special characters.");
					_isImporting = false;
					return;
				}

				// Validate all file paths in manifest are safe relative paths
				var pathValidation = shared.validateManifestPaths(manifest);
				if (!pathValidation.valid) {
					alert("Invalid package: unsafe file paths detected.\n\n" + pathValidation.errors.join("\n"));
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
				var installToRoot = !!manifest.install_to_library_root;
				var customSubdir = manifest.custom_install_subdir || '';
				var libDestDir;
				if (installToRoot) {
					libDestDir = libBasePath;
				} else if (customSubdir) {
					libDestDir = path.join(libBasePath, customSubdir);
				} else {
					libDestDir = path.join(libBasePath, libName);
				}
				var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);
				var labFolderImp = db_links.links.findOne({"_id":"labware-folder"});
				var labwareBasePathImp = labFolderImp ? labFolderImp.path : (function() {
					var hamiltonDir = path.dirname(libBasePath);
					var sibling = path.join(hamiltonDir, 'Labware');
					return fs.existsSync(sibling) ? sibling : 'C:\\Program Files (x86)\\HAMILTON\\Labware';
				})();
				var labwareFiles = manifest.labware_files || [];
				var binFolderImp = db_links.links.findOne({"_id":"bin-folder"});
				var binBasePathImp = binFolderImp ? binFolderImp.path : 'C:\\Program Files (x86)\\HAMILTON\\Bin';
				var binFiles = manifest.bin_files || [];

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
				var impPreviewCert = (sigResult.code_signed && sigResult.valid && sigResult.publisher_cert) ? sigResult.publisher_cert : null;
				var impAuthorBadge = buildOemVerifiedBadge(manifest.author || '', true, impPreviewCert);
				var impConvertedAuthorBadge = '';
				if (!impAuthorBadge && sigResult.converted) {
					impConvertedAuthorBadge = buildConvertedBadge(true, sigResult.source_certificate || null, sigResult.conversion_source || '');
				}
				if (impAuthorBadge || impConvertedAuthorBadge) {
					$modal.find(".imp-preview-author").html(escapeHtml(manifest.author || "\u2014") + ' ' + impAuthorBadge + impConvertedAuthorBadge);
				} else {
					$modal.find(".imp-preview-author").text(manifest.author || "\u2014");
				}
				var impOrgBadge = buildOemVerifiedBadge(manifest.organization || '', true, impPreviewCert);
				var impConvertedOrgBadge = '';
				if (!impOrgBadge && sigResult.converted) {
					impConvertedOrgBadge = buildConvertedBadge(true, sigResult.source_certificate || null, sigResult.conversion_source || '');
				}
				if (impOrgBadge || impConvertedOrgBadge) {
					$modal.find(".imp-preview-organization").html(escapeHtml(manifest.organization || "\u2014") + ' ' + impOrgBadge + impConvertedOrgBadge);
				} else {
					$modal.find(".imp-preview-organization").text(manifest.organization || "\u2014");
				}
				$modal.find(".imp-preview-venus").text(manifest.venus_compatibility || "\u2014");
				$modal.find(".imp-preview-created").text(manifest.created_date ? new Date(manifest.created_date).toLocaleString() : "\u2014");

				// Description
				if (manifest.description) {
					$modal.find(".imp-preview-description").text(manifest.description);
					$modal.find(".imp-preview-desc-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-desc-section").addClass("d-none");
				}

				// GitHub URL (respect display setting, validate to prevent javascript: XSS)
				var ghRegulated2 = !!getSettingValue("chk_regulatedEnvironment");
				if (manifest.github_url && !ghRegulated2 && getSettingValue("chk_showGitHubLinks") !== false) {
					var ghCheck = shared.validateGitHubRepoUrl(manifest.github_url);
					if (ghCheck.valid) {
						$modal.find(".imp-preview-github-link").attr("href", manifest.github_url).text(manifest.github_url);
						$modal.find(".imp-preview-github-section").removeClass("d-none");
					} else {
						$modal.find(".imp-preview-github-section").addClass("d-none");
					}
				} else {
					$modal.find(".imp-preview-github-section").addClass("d-none");
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
						var destFile = path.join(libDestDir, f);
						$libFilesList.append(
							'<div class="pkg-file-item" style="flex-wrap:wrap;"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>' + comBadge
							+ '<div class="hampkg-file-dirs"><span class="hampkg-file-to" title="' + escapeHtml(destFile) + '"><i class="fas fa-sign-in-alt mr-1"></i>' + escapeHtml(destFile) + '</span></div>'
							+ '</div>'
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
						var destFile = path.join(demoDestDir, f);
						$demoFilesList.append(
							'<div class="pkg-file-item" style="flex-wrap:wrap;"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>'
							+ '<div class="hampkg-file-dirs"><span class="hampkg-file-to" title="' + escapeHtml(destFile) + '"><i class="fas fa-sign-in-alt mr-1"></i>' + escapeHtml(destFile) + '</span></div>'
							+ '</div>'
						);
					});
				}

				// Help files list
				var $helpFilesList = $modal.find(".imp-preview-help-files");
				$helpFilesList.empty();
				if (helpFiles.length > 0) {
					helpFiles.forEach(function(f) {
						var destFile = path.join(libDestDir, f);
						$helpFilesList.append(
							'<div class="pkg-file-item" style="flex-wrap:wrap;"><i class="fas fa-question-circle pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>'
							+ '<div class="hampkg-file-dirs"><span class="hampkg-file-to" title="' + escapeHtml(destFile) + '"><i class="fas fa-sign-in-alt mr-1"></i>' + escapeHtml(destFile) + '</span></div>'
							+ '</div>'
						);
					});
					$modal.find(".imp-preview-help-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-help-section").addClass("d-none");
				}

				// Bin files list
				var $binFilesList = $modal.find(".imp-preview-bin-files");
				$binFilesList.empty();
				if (binFiles.length > 0) {
					binFiles.forEach(function(f) {
						var destFile = path.join(binBasePathImp, f);
						$binFilesList.append(
							'<div class="pkg-file-item" style="flex-wrap:wrap;"><i class="fas fa-cogs pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>'
							+ '<div class="hampkg-file-dirs"><span class="hampkg-file-to" title="' + escapeHtml(destFile) + '"><i class="fas fa-sign-in-alt mr-1"></i>' + escapeHtml(destFile) + '</span></div>'
							+ '</div>'
						);
					});
					$modal.find(".imp-preview-bin-section").removeClass("d-none");
				} else {
					$modal.find(".imp-preview-bin-section").addClass("d-none");
				}

				// Package signature status
				var $sigStatus = $modal.find(".imp-preview-signature-status");
				if ($sigStatus.length > 0) {
					$sigStatus.empty();
					if (sigResult.converted && sigResult.valid) {
						// Converted distribution from .exe installer
						var convSrc = sigResult.conversion_source ? escapeHtml(sigResult.conversion_source) : 'executable installer';
						var convCert = sigResult.source_certificate;
						var convCertHtml = '';
						if (convCert && convCert.present && convCert.signer_name) {
							convCertHtml = '<div class="d-flex align-items-center" style="color:#6b7280;">' +
								'<i class="fas fa-file-import mr-2"></i>' +
								'<span>Converted from <strong>' + convSrc + '</strong></span></div>' +
								'<div class="text-sm ml-4 mt-1 text-muted">EXE signed by: ' + escapeHtml(convCert.signer_name) +
								(convCert.issuer_name ? ' (Issuer: ' + escapeHtml(convCert.issuer_name) + ')' : '') + '</div>';
						} else {
							convCertHtml = '<div class="d-flex align-items-center" style="color:#6b7280;">' +
								'<i class="fas fa-file-import mr-2"></i>' +
								'<span>Converted from <strong>' + convSrc + '</strong></span></div>' +
								'<div class="text-sm ml-4 mt-1 text-muted">Created from official library distribution</div>';
						}
						$sigStatus.html(convCertHtml);
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					} else if (sigResult.code_signed && sigResult.valid && sigResult.publisher_cert) {
						// Code-signed with Ed25519 publisher certificate
						var pubName = escapeHtml(sigResult.publisher_cert.publisher);
						var pubOrg = sigResult.publisher_cert.organization ? ' (' + escapeHtml(sigResult.publisher_cert.organization) + ')' : '';
						var keyId = escapeHtml(sigResult.publisher_cert.key_id);
						var certHtml = '<div class="d-flex align-items-center text-success">' +
							'<i class="fas fa-certificate mr-2"></i>' +
							'<span>Code signed by <strong>' + pubName + '</strong>' + pubOrg + '</span></div>' +
							'<div class="text-sm ml-4 mt-1 text-muted">Key ID: ' + keyId + '</div>';
						$sigStatus.html(certHtml);
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					} else if (sigResult.signed && sigResult.valid) {
						$sigStatus.html('<div class="d-flex align-items-center text-success"><i class="fas fa-shield-alt mr-2"></i><span>Package integrity verified (HMAC-only &mdash; no publisher identity)</span></div>');
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					} else if (sigResult.signed && !sigResult.valid) {
						var errHtml = '<div class="text-danger"><i class="fas fa-exclamation-triangle mr-2"></i><strong>Signature verification FAILED</strong></div>';
						sigResult.errors.forEach(function(e) {
							errHtml += '<div class="text-danger text-sm ml-4">&bull; ' + escapeHtml(e) + '</div>';
						});
						$sigStatus.html(errHtml);
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					} else {
						$sigStatus.html('<div class="d-flex align-items-center text-muted"><i class="fas fa-info-circle mr-2"></i><span>Unsigned package (legacy) &mdash; no signature to verify</span></div>');
						$modal.find(".imp-preview-signature-section").removeClass("d-none");
					}
				}

				// Install paths (determined by manifest)
				$modal.find(".imp-preview-lib-path").text("Library \u2192 " + libDestDir);
				$modal.find(".imp-preview-demo-path").text("Demo Methods \u2192 " + demoDestDir);

				// Check for existing library
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					var existingVer = existing.version || '?';
					var incomingVer = manifest.version || '?';
					var isSameVersion = (existingVer !== '?' && incomingVer !== '?' && existingVer === incomingVer);
					$modal.find(".imp-preview-overwrite-warning").removeClass("d-none");
					if (isSameVersion) {
						$modal.find(".imp-preview-overwrite-warning .alert").removeClass("alert-warning").addClass("alert-info");
						$modal.find(".imp-preview-overwrite-text").text('A library named "' + libName + '" with the same version (v' + existingVer + ') is already installed. Importing will replace the existing copy.');
					} else {
						$modal.find(".imp-preview-overwrite-warning .alert").removeClass("alert-info").addClass("alert-warning");
						$modal.find(".imp-preview-overwrite-text").text('A library named "' + libName + '" is already installed (v' + existingVer + '). Importing will replace it with v' + incomingVer + '.');
					}
					$("#imp-preview-confirm").html('<i class="fas fa-sync-alt mr-2"></i>Replace Library');
				} else {
					$modal.find(".imp-preview-overwrite-warning").addClass("d-none");
					$modal.find(".imp-preview-overwrite-warning .alert").removeClass("alert-info").addClass("alert-warning");
					$("#imp-preview-confirm").html('<i class="fas fa-file-import mr-2"></i>Install Library');
				}

				// Store data for confirm handler
				$modal.data("imp-zip", zip);
				$modal.data("imp-manifest", manifest);
				$modal.data("imp-libDestDir", libDestDir);
				$modal.data("imp-demoDestDir", demoDestDir);
				$modal.data("imp-filePath", filePath);
				$modal.data("imp-helpFiles", helpFiles);
				$modal.data("imp-filteredLibFiles", libFiles);
				$modal.data("imp-sigResult", sigResult);
				$modal.data("imp-labwareBasePath", labwareBasePathImp);
				$modal.data("imp-labwareFiles", labwareFiles);
				$modal.data("imp-binBasePath", binBasePathImp);
				$modal.data("imp-binFiles", binFiles);

				$modal.modal("show");

			} catch(e) {
				alert("Error reading package:\n" + e.message);
				_isImporting = false;
			}
			// NOTE: _isImporting stays true while the preview modal is open.
			// It is reset by the confirm handler or the modal dismiss handler below.
		}

		// ---- Reset _isImporting when preview modal is dismissed without confirming ----
		$(document).on("hidden.bs.modal", "#importPreviewModal", function() {
			_isImporting = false;
		});

		// ---- Confirm install from preview modal ----
		$(document).on("click", "#imp-preview-confirm", async function() {
			// _isImporting is already true (set by impLoadAndInstall when the
			// preview modal was opened).  Disable the button to prevent
			// double-click; _isImporting is reset in the finally block.
			var $confirmBtn = $(this);
			if ($confirmBtn.prop('disabled')) return;
			$confirmBtn.prop('disabled', true);

			var $modal = $("#importPreviewModal");
			var zip = $modal.data("imp-zip");
			var manifest = $modal.data("imp-manifest");
			var libDestDir = $modal.data("imp-libDestDir");
			var demoDestDir = $modal.data("imp-demoDestDir");
			var filePath = $modal.data("imp-filePath");

			if (!zip || !manifest) { _isImporting = false; $confirmBtn.prop('disabled', false); return; }

			var libName = manifest.library_name || "Unknown";
			var helpFiles = $modal.data("imp-helpFiles") || [];
			var libFiles = $modal.data("imp-filteredLibFiles") || [];
			var impSigResult = $modal.data("imp-sigResult") || null;
			var demoFiles = manifest.demo_method_files || [];
			var labwareFiles = manifest.labware_files || [];
			var labwareBasePathImp = $modal.data("imp-labwareBasePath") || 'C:\\Program Files (x86)\\HAMILTON\\Labware';
			var binFiles = manifest.bin_files || [];
			var binBasePathImp = $modal.data("imp-binBasePath") || 'C:\\Program Files (x86)\\HAMILTON\\Bin';
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
							_isImporting = false;
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
						// Legacy/explicit help_files folder - extract to library directory
						var fname = entry.entryName.substring("help_files/".length);
						if (fname) {
							var outPath = safeZipExtractPath(libDestDir, fname);
							if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(outPath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(outPath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("labware/") === 0) {
						var fname = entry.entryName.substring("labware/".length);
						if (fname) {
							var outPath = safeZipExtractPath(labwareBasePathImp, fname);
							if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(outPath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(outPath, entry.getData());
							extractedCount++;
						}
					} else if (entry.entryName.indexOf("bin/") === 0) {
						var fname = entry.entryName.substring("bin/".length);
						if (fname) {
							var outPath = safeZipExtractPath(binBasePathImp, fname);
							if (!outPath) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir = path.dirname(outPath);
							if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
							fs.writeFileSync(outPath, entry.getData());
							extractedCount++;
						}
					}
				});

				// Extract installer executable to centralized store if present and setting enabled
				var impInstallerPath = null;
				var impInstallerOriginalName = null;
				var impInstallerSize = 0;
				var retainInstallers = !!getSettingValue('chk_retainInstallers');
				if (manifest.installer_executable && retainInstallers) {
					var installerLibDir = path.join(INSTALLER_STORE_DIR, (libName || 'Unknown').replace(/[<>:"\/\\|?*]/g, '_'));
					zipEntries.forEach(function(entry) {
						if (entry.isDirectory) return;
						if (entry.entryName.indexOf("installer/") === 0) {
							var fname = entry.entryName.substring("installer/".length);
							if (fname) {
								var safePath = safeZipExtractPath(installerLibDir, fname);
								if (!safePath) { console.warn('Skipping unsafe installer ZIP entry: ' + entry.entryName); return; }
								if (!fs.existsSync(installerLibDir)) fs.mkdirSync(installerLibDir, { recursive: true });
								var data = entry.getData();
								fs.writeFileSync(safePath, data);
								impInstallerPath = safePath;
								impInstallerOriginalName = fname;
								impInstallerSize = data.length;
								extractedCount++;
							}
						}
					});
				}

				// Check if already exists in DB (update if so)
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				// Save to DB
				// Compute integrity hashes for installed files
				var fileHashes = {};
				try { fileHashes = computeLibraryHashes(
					libFiles,
					libDestDir,
					comDlls
				); } catch(e) { console.warn('Could not compute integrity hashes: ' + e.message); }

				var dbRecord = {
					library_name: manifest.library_name || "",
					author: manifest.author || "",
					organization: manifest.organization || "",
					installed_by: getWindowsUsername(),
					version: manifest.version || "",
					venus_compatibility: manifest.venus_compatibility || "",
					description: manifest.description || "",
					github_url: manifest.github_url || "",
					tags: manifest.tags || [],
					created_date: manifest.created_date || "",
					app_version: manifest.app_version || "",
					format_version: manifest.format_version || "1.0",
					windows_version: manifest.windows_version || "",
					venus_version: manifest.venus_version || "",
					package_lineage: manifest.package_lineage || [],
					library_image: manifest.library_image || null,
					library_image_base64: manifest.library_image_base64 || null,
					library_image_mime: manifest.library_image_mime || null,
					library_files: libFiles,
					demo_method_files: manifest.demo_method_files || [],
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: comWarning,
					com_registered: comDlls.length > 0 && !comWarning,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					install_to_library_root: !!manifest.install_to_library_root,
					custom_install_subdir: manifest.custom_install_subdir || '',
					installed_date: new Date().toISOString(),
					source_package: path.basename(filePath),
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFiles, libDestDir),
					required_dependencies: extractRequiredDependencies(libFiles, libDestDir),
					publisher_cert: (impSigResult && impSigResult.code_signed && impSigResult.valid && impSigResult.publisher_cert) ? impSigResult.publisher_cert : null,
					converted_from_executable: !!(impSigResult && impSigResult.converted),
					source_certificate: (impSigResult && impSigResult.converted && impSigResult.source_certificate) ? impSigResult.source_certificate : null,
					conversion_source: (impSigResult && impSigResult.converted && impSigResult.conversion_source) ? impSigResult.conversion_source : null,
					installer_executable: manifest.installer_executable || null,
					installer_info: manifest.installer_info || null,
					installer_path: impInstallerPath || null,
					installer_original_name: impInstallerOriginalName || null,
					installer_size: impInstallerSize || 0,
					labware_files: labwareFiles,
					labware_install_path: labwareFiles.length > 0 ? labwareBasePathImp : null,
					bin_files: binFiles,
					bin_install_path: binFiles.length > 0 ? binBasePathImp : null
				};
				// Forward-compat: preserve unknown manifest fields in DB record
				Object.keys(manifest).forEach(function(mk) { if (shared.KNOWN_MANIFEST_KEYS.indexOf(mk) === -1 && !(mk in dbRecord)) dbRecord[mk] = manifest[mk]; });
				var saved = db_installed_libs.installed_libs.save(dbRecord);

				// Write .libmgr marker file
				try { shared.updateMarkerForLibrary(dbRecord); } catch(_) { /* non-critical */ }

				// Update publisher registry
				registerPublisher(manifest.author || '');
				registerPublisher(manifest.organization || '');
				registerTags(manifest.tags || []);

				// Add the new library to the appropriate group in the tree
				var navtree = db_tree.tree.find();
				var targetGroupId = null;

				// If author or organization is a restricted OEM name, auto-assign to the OEM group
				var savedAuthor = (manifest.author || '').trim();
				var savedOrg = (manifest.organization || '').trim();
				if (isRestrictedAuthor(savedAuthor) || isRestrictedAuthor(savedOrg)) {
					// Restricted OEM author: add to the OEM group
					targetGroupId = addToOemTreeGroup(saved._id);
				} else {
					// Non-restricted author: add to first custom group
					for (var ti = 0; ti < navtree.length; ti++) {
						var gEntry = getGroupById(navtree[ti]["group-id"]);
						if (gEntry && !gEntry["default"]) {
							targetGroupId = navtree[ti]["group-id"];
							var existingIds = (navtree[ti]["method-ids"] || []).slice();
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
				if (impInstallerPath) {
					pathsHtml += '<div class="path-label">Installer</div>';
					pathsHtml += '<div class="path-value">' + impInstallerPath.replace(/</g, '&lt;') + '</div>';
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
						.html('<i class="fas fa-check mr-1"></i>COM DLLs registered: ' + escapeHtml(comDlls.join(", ")));
				}

				$sm.modal("show");

				// ---- Audit trail entry ----
				try {
					var sigStatus = 'unsigned';
					var sigData = $modal.data("imp-sigResult");
					if (sigData && sigData.signed) sigStatus = sigData.valid ? 'valid' : 'failed';
					if (sigData && sigData.code_signed) sigStatus = 'code_signed_' + sigStatus;
					var auditEntry = {
						library_name:     libName,
						version:          manifest.version || '',
						author:           manifest.author || '',
						organization:     manifest.organization || '',
						source_file:      filePath,
						lib_install_path: libDestDir,
						demo_install_path: demoDestDir,
						files_extracted:  extractedCount,
						signature_status: sigStatus,
						com_warning:      comWarning
					};
					if (sigData && sigData.code_signed && sigData.publisher_cert) {
						auditEntry.code_signing_publisher = sigData.publisher_cert.publisher;
						auditEntry.code_signing_key_id = sigData.publisher_cert.key_id;
						auditEntry.code_signing_oem = sigData.oem_verified;
					}
					appendAuditTrailEntry(buildAuditTrailEntry('library_imported', auditEntry));
				} catch(_) { /* non-critical */ }

			} catch(e) {
				alert("Error installing package:\n" + e.message);
			} finally {
				_isImporting = false;
				$confirmBtn.prop('disabled', false);
			}
		});

		//**************************************************************************************
		//****** AUDIT LOG CONSTANTS ***********************************************************
		//**************************************************************************************
		// NOTE: This key is embedded in the client-side source and provides tamper-
		// *detection* only, NOT cryptographic authenticity.  See PKG_SIGNING_KEY note.
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
						lines.push("GitHub URL:       " + (lib.github_url || "N/A"));
						lines.push("Tags:             " + ((lib.tags && lib.tags.length > 0) ? lib.tags.join(", ") : "None"));
						lines.push("Status:           " + (lib.deleted ? "DELETED" : "Active"));
						lines.push("Format Version:   " + (lib.format_version || "N/A"));
						lines.push("App Version:      " + (lib.app_version || "N/A"));
						lines.push("Windows Version:  " + (lib.windows_version || "N/A"));
						lines.push("VENUS Version:    " + (lib.venus_version || "N/A"));
						lines.push("Created Date:     " + (lib.created_date || "N/A"));
						lines.push("Installed Date:   " + (lib.installed_date || "N/A"));
						lines.push("Installed By:     " + (lib.installed_by || "N/A"));
						if (lib.deleted && lib.deleted_date) {
							lines.push("Deleted Date:     " + lib.deleted_date);
							if (lib.deleted_by) lines.push("Deleted By:       " + lib.deleted_by);
						}
						lines.push("Source Package:   " + (lib.source_package || "N/A"));
						lines.push("Install Path:     " + (lib.lib_install_path || "N/A"));
						lines.push("Demo Path:        " + (lib.demo_install_path || "N/A"));
						lines.push("Install To Root:  " + (lib.install_to_library_root ? "Yes" : "No"));
						if (lib.custom_install_subdir) {
							lines.push("Custom Subdir:    " + lib.custom_install_subdir);
						}

						// Changelog
						if (lib.changelog) {
							lines.push("Changelog:");
							lib.changelog.split(/\r?\n/).forEach(function(cl) {
								lines.push("  " + cl);
							});
						} else {
							lines.push("Changelog:        N/A");
						}

						// COM DLLs
						var comDlls = lib.com_register_dlls || [];
						lines.push("COM DLLs:         " + (comDlls.length > 0 ? comDlls.join(", ") : "None"));
						lines.push("COM Registered:   " + (lib.com_registered ? "Yes" : "No"));
						lines.push("COM Warning:      " + (lib.com_warning ? "YES" : "No"));

						// Conversion source info
						if (lib.converted_from_executable) {
							lines.push("Converted From:   Executable");
							lines.push("Conversion Src:   " + (lib.conversion_source || "N/A"));
							if (lib.source_certificate && lib.source_certificate.present) {
								lines.push("Source Cert:      " + (lib.source_certificate.signer_name || "Unknown"));
								lines.push("Source Cert Status: " + (lib.source_certificate.status || "Unknown"));
							}
						}

						// Publisher certificate (code signing)
						if (lib.publisher_cert) {
							lines.push("Publisher Cert:   Present");
							lines.push("  Publisher:      " + (lib.publisher_cert.holder_name || "N/A"));
							lines.push("  Key ID:         " + (lib.publisher_cert.key_id || "N/A"));
							lines.push("  Signed Date:    " + (lib.publisher_cert.signed_date || "N/A"));
							lines.push("  Verified:       " + (lib.publisher_cert.verified ? "Yes" : "No"));
						} else {
							lines.push("Publisher Cert:   None (unsigned)");
						}

						// Package lineage
						var lineage = lib.package_lineage || [];
						if (lineage.length > 0) {
							lines.push("Package Lineage (" + lineage.length + "):");
							lineage.forEach(function(evt) {
								lines.push("  - " + (evt.event || "unknown") + " at " + (evt.timestamp || "N/A") + " by " + (evt.username || "N/A") + "@" + (evt.hostname || "N/A") + " (v" + (evt.app_version || "?") + ")");
							});
						}

						// Required dependencies
						var reqDeps = lib.required_dependencies || [];
						if (reqDeps.length > 0) {
							lines.push("Required Dependencies (" + reqDeps.length + "):");
							reqDeps.forEach(function(dep) {
								lines.push("  - " + dep);
							});
						}

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

						// Help files
						var helpFiles = lib.help_files || [];
						if (helpFiles.length > 0) {
							lines.push("Help Files (" + helpFiles.length + "):");
							helpFiles.forEach(function(f) {
								lines.push("  - " + f);
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
						lines.push("VENUS Version:    " + (sLib.venus_version || "N/A"));
						lines.push("Package Date:     N/A");
						lines.push("Installed Date:   " + (sLib.installed_date || "N/A"));
						lines.push("Installed By:     " + (sLib.installed_by || "N/A"));
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
								lines.push("      Method:       Hamilton Footer ($$valid$$ read-only flag)");
								lines.push("      Stored Valid: " + storedInfo.valid);
								if (footer) {
									lines.push("      Current Valid:" + footer.valid);
									var footerMatch = (storedInfo.valid === footer.valid) ? "MATCH" : "MISMATCH";
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
						'Signature mismatch - the file contents have been altered.\n\nStored:    ' + storedSig + '\nComputed: ' + computedSig);
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

			// Show loading state first, then populate asynchronously
			var $list = $(".repair-lib-list");
			$list.html(
				'<div class="text-center py-4">' +
					'<div class="spinner-border text-muted" role="status" style="width:2rem;height:2rem;"></div>' +
					'<p class="text-muted mt-2">Verifying libraries and COM registrations...</p>' +
					'<div class="progress mt-2 mx-auto" style="max-width:300px;height:6px;">' +
						'<div class="progress-bar" role="progressbar" style="width:0%;background:var(--accent);"></div>' +
					'</div>' +
				'</div>'
			);
			$(".repair-status-text").text('');
			$(".repair-all-btn").prop("disabled", true);
			$("#repairModal").modal("show");

			// Defer to allow modal to render before heavy work
			setTimeout(function() { repairPopulateModal(); }, 80);
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
				integrity.errors.forEach(function(e) { detailLines.push('<span class="text-danger text-sm">&bull; ' + escapeHtml(e) + '</span>'); });
				integrity.warnings.forEach(function(w) { detailLines.push('<span class="text-warning text-sm">&bull; ' + escapeHtml(w) + '</span>'); });

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
								'<span class="font-weight-bold" style="color:var(--medium2);">' + escapeHtml(libName) + '</span>' +
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
				var comDlls = lib.com_register_dlls || [];
				var hasCom = comDlls.length > 0;

				// COM registration verification
				var comStatus = null;
				if (hasCom) {
					comStatus = verifyCOMRegistration(lib);
				}

				var statusClass, statusIcon, statusText;
				if (!integrity.valid) {
					statusClass = 'text-danger';
					statusIcon = 'fa-times-circle';
					statusText = 'FAILED';
					failCount++;
				} else if ((hasCom && comStatus && !comStatus.allRegistered) || integrity.warnings.length > 0) {
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
				integrity.errors.forEach(function(e) { detailLines.push('<span class="text-danger text-sm">&bull; ' + escapeHtml(e) + '</span>'); });
				integrity.warnings.forEach(function(w) { detailLines.push('<span class="text-warning text-sm">&bull; ' + escapeHtml(w) + '</span>'); });

				// COM registration details
				if (hasCom && comStatus) {
					if (comStatus.allRegistered) {
						detailLines.push('<span class="text-success text-sm">&bull; COM: All ' + comDlls.length + ' DLL(s) registered <i class="fas fa-check ml-1"></i></span>');
					} else {
						comStatus.results.forEach(function(r) {
							if (!r.registered) {
								detailLines.push('<span class="text-warning text-sm">&bull; COM not registered: ' + escapeHtml(r.dll) + ' (' + escapeHtml(r.details) + ')</span>');
							}
						});
					}
				}

				var repairBtnHtml = '';
				if (!integrity.valid && hasCached) {
					repairBtnHtml = '<button class="btn btn-sm btn-outline-success repair-single-btn ml-2" data-lib-name="' + libName.replace(/"/g, '&quot;') + '" data-is-system="false" title="Re-install from cached package"><i class="fas fa-wrench mr-1"></i>Repair</button>';
				} else if (!integrity.valid && !hasCached) {
					repairBtnHtml = '<span class="text-muted text-sm ml-2" title="No cached package available for repair"><i class="fas fa-ban mr-1"></i>No cached pkg</span>';
				}

				// COM re-register button (shown when COM DLLs exist but are not all registered, and file integrity is OK)
				if (hasCom && comStatus && !comStatus.allRegistered && integrity.valid) {
					repairBtnHtml += '<button class="btn btn-sm btn-outline-info repair-com-btn ml-2" data-lib-id="' + (lib._id || '').replace(/"/g, '&quot;') + '" title="Re-register COM DLLs using 32-bit RegAsm.exe"><i class="fas fa-cog mr-1"></i>Re-register COM</button>';
				}

				var cachedInfo = hasCached
					? '<span class="text-muted text-sm ml-2" title="' + cached.length + ' cached version(s) available"><i class="fas fa-archive mr-1"></i>' + cached.length + ' cached</span>'
					: '';

				var comBadge = hasCom
					? '<span class="badge badge-' + (comStatus && comStatus.allRegistered ? 'info' : 'warning') + ' ml-2" style="font-size:0.6rem;" title="COM DLLs: ' + escapeHtml(comDlls.join(', ')) + '"><i class="fas fa-cog mr-1"></i>COM</span>'
					: '';

				var html =
					'<div class="repair-lib-item d-flex align-items-start py-2 px-1" style="border-bottom:1px solid var(--bg-divider);" data-lib-name="' + libName.replace(/"/g, '&quot;') + '" data-is-system="false">' +
						'<div class="mr-3 mt-1"><i class="fas ' + statusIcon + ' ' + statusClass + '"></i></div>' +
						'<div class="flex-grow-1" style="min-width:0;">' +
							'<div class="d-flex align-items-center flex-wrap">' +
								'<span class="font-weight-bold" style="color:var(--medium2);">' + escapeHtml(libName) + '</span>' +
								'<span class="badge badge-light ml-2">' + escapeHtml(lib.version || '') + '</span>' +
								comBadge +
								'<span class="ml-2 ' + statusClass + ' text-sm font-weight-bold">' + statusText + '</span>' +
								cachedInfo +
							'</div>' +
							(detailLines.length > 0 ? '<div class="mt-1">' + detailLines.join('<br>') + '</div>' : '') +
						'</div>' +
						'<div class="ml-2 d-flex align-items-center flex-wrap" style="white-space:nowrap;">' + repairBtnHtml + '</div>' +
					'</div>';

				$list.append(html);

				// Update progress bar
				var progress = Math.round(((totalCount) / (libs.length + sysLibs.length)) * 100);
				$(".repair-lib-list .progress-bar").css("width", progress + "%");
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

		// Re-register COM DLLs from Verify & Repair modal
		$(document).on("click", ".repair-com-btn", async function(e) {
			e.stopPropagation();
			var libId = $(this).attr("data-lib-id");
			if (!libId) return;
			var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
			if (!lib) {
				alert("Library record not found.");
				return;
			}
			var comDlls = lib.com_register_dlls || [];
			if (comDlls.length === 0) {
				alert("No COM DLLs configured for this library.");
				return;
			}
			var libPath = lib.lib_install_path || "";
			var dllPaths = comDlls.map(function(dll) {
				return path.join(libPath, dll);
			});
			// Verify the DLL files exist before attempting registration
			var missing = dllPaths.filter(function(p) { return !fs.existsSync(p); });
			if (missing.length > 0) {
				alert("The following COM DLL files are missing and cannot be registered:\n\n" + missing.join("\n") + "\n\nRepair the library first to restore the files.");
				return;
			}
			if (!confirm("Re-register " + comDlls.length + " COM DLL(s) for \"" + (lib.library_name || "Unknown") + "\"?\n\n" + comDlls.join("\n") + "\n\nThis requires administrator privileges (UAC prompt).")) return;
			var result = await comRegisterMultipleDlls(dllPaths, true);
			if (result.allSuccess) {
				// Update the DB record
				db_installed_libs.installed_libs.update({"_id": libId}, { com_registered: true, com_warning: false }, { multi: false, upsert: false });
				alert("COM registration successful for " + comDlls.length + " DLL(s).");
				repairPopulateModal();
			} else {
				var failedDlls = result.results.filter(function(r) { return !r.success; });
				var errMsgs = failedDlls.map(function(r) { return path.basename(r.dll) + ": " + (r.error || "Unknown error"); });
				db_installed_libs.installed_libs.update({"_id": libId}, { com_registered: false, com_warning: true }, { multi: false, upsert: false });
				alert("COM registration failed for " + failedDlls.length + " of " + comDlls.length + " DLL(s).\n\n" + errMsgs.join("\n"));
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
					var rawBuf = fs.readFileSync(newest.fullPath);
					var zipBuf = unpackContainer(rawBuf, CONTAINER_MAGIC_PKG);
					zip = new AdmZip(zipBuf);
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

				// Validate library name from cached package
				var cachedLibName = manifest.library_name || libName;
				if (!isValidLibraryName(cachedLibName)) {
					var msg4b = 'Invalid library name in cached package: "' + cachedLibName + '".';
					if (!silent) alert(msg4b);
					return { success: false, error: msg4b };
				}

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
					} else if (entry.entryName.indexOf('labware/') === 0) {
						var fname4 = entry.entryName.substring('labware/'.length);
						if (fname4) {
							var labRepairPath = lib.labware_install_path || 'C:\\Program Files (x86)\\HAMILTON\\Labware';
							var safePath4 = safeZipExtractPath(labRepairPath, fname4);
							if (!safePath4) { console.warn('Skipping unsafe ZIP entry: ' + entry.entryName); return; }
							var parentDir4 = path.dirname(safePath4);
							if (!fs.existsSync(parentDir4)) fs.mkdirSync(parentDir4, { recursive: true });
							fs.writeFileSync(safePath4, entry.getData());
							extractedCount++;
						}
					}
				});

				// Recompute hashes
				var libFiles = lib.library_files || [];
				var comDlls = lib.com_register_dlls || [];
				var fileHashes = {};
				try { fileHashes = computeLibraryHashes(libFiles, libDestDir, comDlls); } catch(e) { console.warn('Could not compute integrity hashes: ' + e.message); }

				// Update DB record with fresh hashes
				db_installed_libs.installed_libs.update({ _id: lib._id }, {
					file_hashes: fileHashes
				}, { multi: false, upsert: false });

				if (!silent) {
					showGenericSuccessModal({
						title: "Library Repaired Successfully!",
						name: libName,
						detail: extractedCount + " file" + (extractedCount !== 1 ? "s" : "") + " re-extracted - Version " + (newest.version || '?'),
						statusHtml: sigResult.signed ? '<i class="fas fa-check mr-1"></i>Package signature: verified' : null,
						statusClass: 'com-ok'
					});
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

		/**
		 * Show a styled success modal matching the visual identity of the import success modal.
		 * @param {Object} opts
		 * @param {string} opts.title - Modal heading (e.g. "Package Created Successfully!")
		 * @param {string} [opts.name] - Bold primary line (e.g. library name)
		 * @param {string} [opts.detail] - Secondary muted line (e.g. file count)
		 * @param {Array<{label:string, value:string}>} [opts.paths] - Label/value rows shown in the paths box
		 * @param {string} [opts.statusHtml] - Optional status bar HTML
		 * @param {string} [opts.statusClass] - 'com-ok' | 'com-warning'
		 * @param {string} [opts.listHtml] - Optional HTML list block (for archive results, etc.)
		 */
		function showGenericSuccessModal(opts) {
			var $m = $("#genericSuccessModal");
			$m.find(".generic-success-title").text(opts.title || "Success!");

			// Name line
			var $name = $m.find(".generic-success-name");
			if (opts.name) { $name.text(opts.name).removeClass("d-none"); } else { $name.text("").addClass("d-none"); }

			// Detail line
			var $detail = $m.find(".generic-success-detail");
			if (opts.detail) { $detail.text(opts.detail).removeClass("d-none"); } else { $detail.text("").addClass("d-none"); }

			// Paths section
			var $paths = $m.find(".generic-success-paths");
			var pathContent = "";
			if (opts.paths && opts.paths.length > 0) {
				opts.paths.forEach(function(p) {
					pathContent += '<div class="path-label">' + p.label + '</div>';
					pathContent += '<div class="path-value">' + (p.value || '').replace(/</g, '&lt;') + '</div>';
				});
			}
			if (opts.listHtml) {
				if (pathContent) pathContent += '<div style="margin-top:8px;"></div>';
				pathContent += opts.listHtml;
			}
			if (pathContent) {
				$paths.html(pathContent).removeClass("d-none");
			} else {
				$paths.html("").addClass("d-none");
			}

			// Status bar
			var $status = $m.find(".generic-success-status");
			$status.removeClass("com-warning com-ok").addClass("d-none");
			if (opts.statusHtml) {
				$status.removeClass("d-none").addClass(opts.statusClass || "com-ok").html(opts.statusHtml);
			}

			$m.modal("show");
		}

        //**************************************************************************************
        //******  UNSIGNED LIBRARY SCANNING, CARDS, DETAIL & EXPORT ************************
        //**************************************************************************************

		// Unsigned library modal state
		var ulib_allLibFiles = [];        // combined: discovered + user-added library files (absolute paths)
		var ulib_demoMethodFiles = [];    // user-added demo method files (absolute paths)
		var ulib_comRegisterDlls = [];    // DLL basenames selected for COM registration
		var ulib_fileCustomDirs = {};     // absolutePath -> custom install subdir ("" = root, string = subdir, undefined = default)
		var ulib_installSubdir = null;    // global install subdir: null = default (library name), '' = root, string = custom subdir
		var ulib_iconBase64 = null;       // base64-encoded icon data (user-picked or from DB)
		var ulib_iconMime = null;         // MIME type of the icon
		var ulib_iconFilename = null;     // original filename of the icon
		var ulib_iconFilePath = null;     // path of the user-picked icon file (null if from DB)

		/**
		 * Update the install path hint in the unsigned library detail modal header
		 * based on the install-to-root checkbox state.
		 */
		function ulibUpdateInstallPathHint() {
			var libName = $("#ulib-name").val().trim() || "libraryname";
			if (ulib_installSubdir !== null) {
				if (ulib_installSubdir === '') {
					$("#ulib-lib-path-hint").html('Installed to: ...\\Hamilton\\Library\\');
				} else {
					var sanitized = ulib_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '');
					$("#ulib-lib-path-hint").html('Installed to: ...\\Hamilton\\Library\\<span class="ulib-path-libname"></span>');
					$(".ulib-path-libname").text(sanitized);
				}
			} else {
				$("#ulib-lib-path-hint").html('Installed to: ...\\Hamilton\\Library\\<span class="ulib-path-libname"></span>');
				$(".ulib-path-libname").text(libName);
			}
		}

		/**
		 * Render the library file list in the unsigned library detail modal.
		 * Mirrors pkgUpdateLibFileList() from the Create Package form.
		 */
		function ulibUpdateLibFileList() {
			var $list = $("#ulib-file-list");
			$list.empty();
			if (ulib_allLibFiles.length === 0) {
				$list.html('<div class="text-muted text-center py-3 pkg-empty-msg"><i class="fas fa-inbox mr-2"></i>No library files added</div>');
			} else {
				ulib_allLibFiles.forEach(function(f) {
					var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
					var baseName = path.basename(f);
					var isDll = baseName.toLowerCase().endsWith('.dll');
					var isChecked = ulib_comRegisterDlls.indexOf(baseName) !== -1;
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
						'<span class="pkg-file-name">' + escapeHtml(baseName) + '</span>' +
						comCheckbox +
						'</div>'
					);
				});
			}
			$("#ulib-lib-count").text(ulib_allLibFiles.length + " file" + (ulib_allLibFiles.length !== 1 ? "s" : ""));
		}

		/**
		 * Render the demo method file list in the unsigned library detail modal.
		 * Mirrors pkgUpdateDemoFileList() from the Create Package form.
		 */
		function ulibUpdateDemoFileList() {
			var $list = $("#ulib-demo-list");
			$list.empty();
			if (ulib_demoMethodFiles.length === 0) {
				$list.html('<div class="text-muted text-center py-3 pkg-empty-msg"><i class="fas fa-inbox mr-2"></i>No demo method files added</div>');
			} else {
				ulib_demoMethodFiles.forEach(function(f) {
					var escapedPath = f.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
					$list.append(
						'<div class="pkg-file-item" data-path="' + escapedPath + '">' +
						'<i class="far fa-file pkg-file-icon"></i>' +
						'<span class="pkg-file-name">' + escapeHtml(path.basename(f)) + '</span>' +
						'</div>'
					);
				});
			}
			$("#ulib-demo-count").text(ulib_demoMethodFiles.length + " file" + (ulib_demoMethodFiles.length !== 1 ? "s" : ""));
		}

		/**
		 * Show or hide the COM registration warning in the unsigned library modal footer.
		 * Unlike the old behaviour, export is NOT blocked - the warning is informational only.
		 */
		function ulibUpdateComWarning() {
			var $warning = $("#ulib-com-warning");
			if (ulib_comRegisterDlls.length > 0) {
				$warning.removeClass("d-none");
			} else {
				$warning.addClass("d-none");
			}
		}

		/**
		 * Scan the Library folder for HSL-type files (.hsl, .hsi, .hs_, .smt) that are NOT part of a
		 * system library or a signed/installed library. Groups files by library name
		 * (derived from filename without extension) and stores them in unsigned_libs DB.
		 * No hashing or integrity checking is performed - this is purely for convenience.
		 */
		function scanUnsignedLibraries(showVisualFeedback) {
			var $status = $(".unsigned-scan-status");
			var $spinner = $(".unsigned-scan-spinner");
			var $done = $(".unsigned-scan-done");
			var $btn = $("#btn-scan-unsigned-libs");

			// Show spinner, hide previous checkmark, disable button
			if (showVisualFeedback) {
				$spinner.show();
				$done.hide();
				$btn.prop("disabled", true);
			}
			$status.text("Scanning...");

			// Defer heavy synchronous work so the browser can repaint and show the spinner
			setTimeout(function() {
			try {
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var libDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';

				if (!fs.existsSync(libDir)) {
					$status.text("Library folder not found.");
					return;
				}

				// Build sets of filenames already claimed by system or installed libraries
				var claimedFiles = {};

				// System libraries
				var sysLibs = getAllSystemLibraries();
				sysLibs.forEach(function(sLib) {
					(sLib.discovered_files || []).forEach(function(f) {
						var normalized = f.replace(/^Library[\\\/]/i, '').toLowerCase();
						claimedFiles[normalized] = true;
					});
				});

				// Installed (signed) libraries
				var installedLibs = db_installed_libs.installed_libs.find() || [];
				installedLibs.forEach(function(lib) {
					if (lib.deleted) return;
					(lib.library_files || []).forEach(function(f) {
						claimedFiles[f.toLowerCase()] = true;
					});
				});

				// Scan Library folder for unclaimed HSL-type files
				var targetExts = ['.hsl', '.hsi', '.hs_', '.smt'];
				var relatedExts = ['.sub', '.bmp', '.ico', '.chm', '.stp', '.res', '.fdb', '.sii', '.dec', '.dll'];
				var allExts = targetExts.concat(relatedExts);
				var discovered = {};  // libraryName -> { files: [], basePath }

				// Read all files in the Library folder (non-recursive first level + subfolders)
				function scanDir(dir, relBase) {
					var entries;
					try { entries = fs.readdirSync(dir); } catch(e) { return; }
					entries.forEach(function(entry) {
						var fullPath = path.join(dir, entry);
						var relPath = relBase ? path.join(relBase, entry) : entry;
						var stat;
						try { stat = fs.statSync(fullPath); } catch(e) { return; }

						if (stat.isDirectory()) {
							// Skip special directories
							var lowerEntry = entry.toLowerCase();
							if (lowerEntry === 'librarymanagerforvenus6' ||
								lowerEntry === 'librarymanager' ||
								lowerEntry === 'librarypackages' ||
								lowerEntry === '.librarymanagerforvenus6' ||
								lowerEntry === 'libraryintegrityaudit') return;
							scanDir(fullPath, relPath);
							return;
						}

						if (!stat.isFile()) return;
						// Skip temp files (filenames starting with ~ or .)
						if (entry.charAt(0) === '~' || entry.charAt(0) === '.') return;
						var ext = path.extname(entry).toLowerCase();
						if (allExts.indexOf(ext) === -1) return;

						// Skip if claimed by system or installed library
						if (claimedFiles[relPath.toLowerCase()]) return;
						if (claimedFiles[entry.toLowerCase()]) return;

						// Derive library name from primary definition files (.hsl, .hsi, .hs_, or .smt)
						if (targetExts.indexOf(ext) !== -1) {
							var libName = path.basename(entry, ext);
							// Skip Enu/Deu/Jpn/etc. resource variants - they'll be grouped with the base
							var enuMatch = libName.match(/^(.+?)(Enu|Deu|Jpn|Chs|Kor|Fra|Esp|Por)$/i);
							var baseName = enuMatch ? enuMatch[1] : libName;

							if (!discovered[baseName]) {
								discovered[baseName] = { files: [], basePath: dir };
							}
							if (discovered[baseName].files.indexOf(relPath) === -1) {
								discovered[baseName].files.push(relPath);
							}
						}
					});
				}

				scanDir(libDir, '');

				// For each discovered library, also gather related files (.hs_, .bmp, .chm, etc.)
				var allFiles;
				try { allFiles = []; scanDirFlat(libDir, '', allFiles); } catch(e) { allFiles = []; }

				function scanDirFlat(dir, relBase, result) {
					var entries;
					try { entries = fs.readdirSync(dir); } catch(e) { return; }
					entries.forEach(function(entry) {
						var fullPath = path.join(dir, entry);
						var relPath = relBase ? path.join(relBase, entry) : entry;
						var stat;
						try { stat = fs.statSync(fullPath); } catch(e) { return; }
						if (stat.isDirectory()) {
							var lowerEntry = entry.toLowerCase();
							if (lowerEntry === 'librarymanagerforvenus6' || lowerEntry === 'librarymanager' || lowerEntry === 'librarypackages' || lowerEntry === '.librarymanagerforvenus6' || lowerEntry === 'libraryintegrityaudit') return;
							// Skip dot-prefixed directories (temp/hidden)
							if (entry.charAt(0) === '.') return;
							scanDirFlat(fullPath, relPath, result);
						} else if (stat.isFile()) {
							// Skip temp files (filenames starting with ~ or .)
							if (entry.charAt(0) === '~' || entry.charAt(0) === '.') return;
							result.push(relPath);
						}
					});
				}

				Object.keys(discovered).forEach(function(baseName) {
					var baseNameLower = baseName.toLowerCase();
					// Find related files whose name starts with the library base name
					allFiles.forEach(function(relPath) {
						if (claimedFiles[relPath.toLowerCase()]) return;
						if (claimedFiles[path.basename(relPath).toLowerCase()]) return;
						var fname = path.basename(relPath);
						var fnameNoExt = path.basename(fname, path.extname(fname)).toLowerCase();
						var ext = path.extname(fname).toLowerCase();
						if (relatedExts.indexOf(ext) === -1) return;
						// Match base name exactly or base name + locale suffix
						if (fnameNoExt === baseNameLower || fnameNoExt.indexOf(baseNameLower) === 0) {
							if (discovered[baseName].files.indexOf(relPath) === -1) {
								discovered[baseName].files.push(relPath);
							}
						}
					});
				});

				// Merge with existing DB entries (preserve user-edited metadata)
				var existingEntries = db_unsigned_libs.unsigned_libs.find() || [];
				var existingByName = {};
				existingEntries.forEach(function(e) {
					existingByName[e.library_name.toLowerCase()] = e;
				});

				// Clear and rebuild
				db_unsigned_libs.unsigned_libs.remove({locked: false}); // remove all (diskdb quirk: need a filter)
				// Force clear: write to temp file then atomically rename
				var ulibPath = path.join(USER_DATA_DIR, 'unsigned_libs.json');
				var ulibTmpPath = ulibPath + '.tmp';
				fs.writeFileSync(ulibTmpPath, '[]', 'utf8');
				fs.renameSync(ulibTmpPath, ulibPath);
				db_unsigned_libs = db.connect(USER_DATA_DIR, ['unsigned_libs']);

				var count = 0;
				Object.keys(discovered).sort().forEach(function(baseName) {
					var entry = discovered[baseName];
					var existing = existingByName[baseName.toLowerCase()];

					// Try to resolve a .bmp image for this library
					var imageBase64 = null;
					var imageMime = null;
					var imageFilename = null;
					var bmpFile = entry.files.find(function(f) {
						return path.basename(f).toLowerCase() === baseName.toLowerCase() + '.bmp';
					});
					if (bmpFile) {
						try {
							var bmpPath = path.join(libDir, bmpFile);
							var bmpBuf = fs.readFileSync(bmpPath);
							imageBase64 = bmpBuf.toString('base64');
							imageMime = 'image/bmp';
							imageFilename = path.basename(bmpFile);
						} catch(e) { /* skip */ }
					}

					var record = {
						_id: 'ulib_' + baseName.toLowerCase().replace(/[^a-z0-9]/g, '_'),
						library_name: baseName,
						author: existing ? existing.author : '',
						organization: existing ? existing.organization : '',
						version: existing ? existing.version : '',
						venus_compatibility: existing ? existing.venus_compatibility : '',
						description: existing ? existing.description : '',
						tags: existing ? existing.tags : [],
						library_files: entry.files,
						lib_base_path: libDir,
						library_image: imageFilename,
						library_image_base64: imageBase64,
						library_image_mime: imageMime,
						scanned_date: new Date().toISOString(),
						is_unsigned: true
					};

					db_unsigned_libs.unsigned_libs.save(record);
					count++;
				});

				$status.text(count + " unsigned librar" + (count === 1 ? "y" : "ies") + " found");

				// Show green checkmark, hide spinner
				if (showVisualFeedback) {
					$spinner.hide();
					$done.show();
				}

				// Refresh cards if currently on Unsigned or All tab
				var activeGroup = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id");
				if (activeGroup === 'gUnsigned') {
					impBuildLibraryCards(null, false, false, true);
				} else if (activeGroup === 'gAll') {
					impBuildLibraryCards();
				}

				// Refresh nav bar to show/hide Unsigned tab
				invalidateNavBar();

			} catch(e) {
				console.error('Unsigned library scan error:', e);
				$status.text("Scan failed: " + e.message);
				if (showVisualFeedback) {
					$spinner.hide();
					$done.hide();
				}
			}
			// Re-enable button after scan completes
			if (showVisualFeedback) {
				$btn.prop("disabled", false);
			}
			}, 50); // end setTimeout - allows browser repaint so spinner is visible
		}

		/** Force nav bar rebuild to reflect unsigned group visibility changes */
		function invalidateNavBar() {
			try {
				// Save the active tab and re-select it after rebuild
				var activeGroupId = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id") || "gAll";
				createGroups();
				// Re-select the previously active tab
				var $navItem = $('.navbar-custom .nav-item[data-group-id="' + activeGroupId + '"], .navbar-custom .dropdown-navitem[data-group-id="' + activeGroupId + '"]');
				if ($navItem.length) {
					$navItem.addClass("active");
				} else {
					$('.navbar-custom .nav-item[data-group-id="gAll"]').addClass("active");
				}
			} catch(e) { console.error('Nav rebuild error:', e); }
		}

		/**
		 * Build a card HTML element for an unsigned library.
		 * Similar to system library cards but with an "Unsigned" badge and
		 * a View Details link that opens the editable detail modal.
		 */
		function buildUnsignedLibraryCard(uLib) {
			var libName = escapeHtml(uLib.library_name || "Unknown");
			var version = escapeHtml(uLib.version || "");
			var author = escapeHtml(uLib.author || "");
			var description = escapeHtml(uLib.description || "");
			var tags = (uLib.tags || []).map(function(t) { return escapeHtml(t); });
			var fileCount = (uLib.library_files || []).length;

			// Build icon
			var iconHtml;
			if (uLib.library_image_base64) {
				var mime = uLib.library_image_mime || 'image/bmp';
				iconHtml = '<img src="data:' + mime + ';base64,' + uLib.library_image_base64 + '" style="max-width:48px; max-height:48px; border-radius:4px;">';
			} else {
				iconHtml = '<i class="far fa-times-circle fa-3x" style="color:#adb5bd;"></i>';
			}

			var tagsHtml = "";
			if (tags.length > 0) {
				tags.forEach(function(t) {
					tagsHtml += '<button type="button" class="imp-tag-badge mr-1" data-tag="' + t + '"><i class="fas fa-tag mr-1"></i>' + t + '</button>';
				});
			}

			var shortDesc = description;
			if (shortDesc.length > 80) { shortDesc = shortDesc.substring(0, 80) + "..."; }

			var unsignedBadge = '<span class="badge badge-outline-secondary ml-2" style="font-size:0.65rem;"><i class="far fa-times-circle mr-1"></i>Unsigned</span>';

			var str =
				'<div class="col-md-4 col-xl-3 d-flex align-items-stretch imp-lib-card-container unsigned-lib-card-container" data-ulib-id="' + uLib._id + '">' +
					'<div class="m-2 pl-3 pr-3 pt-3 pb-2 link-card imp-lib-card imp-unsigned-lib-card w-100">' +
						'<div class="d-flex align-items-start">' +
							'<div class="mr-3 mt-1 imp-lib-card-icon">' + iconHtml + '</div>' +
							'<div class="flex-grow-1" style="min-width:0;">' +
								'<h6 class="mb-0 imp-lib-card-name cursor-pointer" style="color:var(--medium2);">' + libName + unsignedBadge + '</h6>' +
								(version ? '<span class="text-muted text-sm">v' + version + '</span>' : '') +
								(author ? '<div class="text-muted text-sm">' + author + '</div>' : '') +
							'</div>' +
						'</div>' +
						(shortDesc ? '<p class="text-muted mt-2 mb-1" style="font-size:0.85em;">' + shortDesc + '</p>' : '') +
						'<div class="imp-lib-card-tags mt-1">' + tagsHtml + '</div>' +
						'<div class="imp-lib-card-footer">' +
							'<a href="#" class="text-sm unsigned-lib-card-details cursor-pointer" style="color:var(--medium);"><i class="fas fa-edit mr-1"></i>Edit &amp; Export</a>' +
							'<span class="text-muted" style="font-size:0.75rem;">' + fileCount + ' file' + (fileCount !== 1 ? 's' : '') + '</span>' +
						'</div>' +
					'</div>' +
				'</div>';
			return str;
		}

		// ---- Click handler: open unsigned library detail/edit modal ----
		$(document).on("click", ".unsigned-lib-card-details, .unsigned-lib-card-container .imp-lib-card-name", function(e) {
			e.preventDefault();
			var ulibId = $(this).closest(".unsigned-lib-card-container").attr("data-ulib-id");
			if (ulibId) showUnsignedLibDetail(ulibId);
		});

		/**
		 * Populate and show the unsigned library detail/edit modal.
		 */
		function showUnsignedLibDetail(ulibId) {
			var uLib = db_unsigned_libs.unsigned_libs.findOne({"_id": ulibId});
			if (!uLib) { alert("Unsigned library not found."); return; }

			var $modal = $("#unsignedLibDetailModal");
			$modal.attr("data-ulib-id", ulibId);

			// Icon
			var $icon = $modal.find(".unsigned-lib-detail-icon");
			if (uLib.library_image_base64) {
				var mime = uLib.library_image_mime || 'image/bmp';
				$icon.html('<img src="data:' + mime + ';base64,' + uLib.library_image_base64 + '" style="max-width:64px; max-height:64px; border-radius:6px;">');
			} else {
				$icon.html('<i class="far fa-times-circle fa-3x" style="color:var(--medium)"></i>');
			}

			// Title
			$modal.find(".unsigned-lib-detail-name").text(uLib.library_name || "Unknown");

			// Update install path subtitles in card headers
			$modal.find(".ulib-path-libname").text(uLib.library_name || "libraryname");

			// Populate editable fields
			$("#ulib-name").val(uLib.library_name || "");
			$("#ulib-author").val(uLib.author || "");
			$("#ulib-organization").val(uLib.organization || "");
			$("#ulib-version").val(uLib.version || "");
			$("#ulib-venus-compat").val(uLib.venus_compatibility || "");
			$("#ulib-description").val(uLib.description || "");
			$("#ulib-github-url").val(uLib.github_url || "");
			$("#ulib-tags").val((uLib.tags || []).join(", "));

			// Initialize module-level state arrays from DB record
			var libDir = uLib.lib_base_path || '';
			ulib_allLibFiles = (uLib.library_files || []).map(function(f) { return path.join(libDir, f); });
			(uLib.additional_library_files || []).forEach(function(f) {
				if (ulib_allLibFiles.indexOf(f) === -1) ulib_allLibFiles.push(f);
			});
			ulib_demoMethodFiles = (uLib.demo_method_files || []).slice();
			ulib_comRegisterDlls = (uLib.com_register_dlls || []).slice();

			// Initialize icon state from DB record
			ulib_iconFilePath = null; // will be set if user picks a new image
			ulib_iconBase64 = uLib.library_image_base64 || null;
			ulib_iconMime = uLib.library_image_mime || null;
			ulib_iconFilename = uLib.library_image || null;

			// Render icon preview
			if (ulib_iconBase64) {
				var iconMime = ulib_iconMime || 'image/bmp';
				$("#ulib-icon-preview").html('<img src="data:' + iconMime + ';base64,' + ulib_iconBase64 + '">').addClass('has-image');
				$("#ulib-icon-name").text(ulib_iconFilename || "Library image");
				$("#ulib-removeIcon").show();
			} else {
				$("#ulib-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
				$("#ulib-icon-name").text("No image selected");
				$("#ulib-removeIcon").hide();
			}

			// Populate install path state
			if (uLib.install_to_library_root) ulib_installSubdir = '';
			else if (uLib.custom_install_subdir) ulib_installSubdir = uLib.custom_install_subdir;
			else ulib_installSubdir = null;
			ulib_fileCustomDirs = {};
			ulibUpdateInstallPathHint();

			// Render file lists using the shared update functions
			ulibUpdateLibFileList();
			ulibUpdateDemoFileList();
			ulibUpdateComWarning();

			// Set save dialog filename
			$("#ulib-export-save-dialog").attr("nwsaveas", (uLib.library_name || "library") + ".hxlibpkg");

			$modal.modal("show");
		}

		// ---- Unsigned lib: file input handlers ----
		$(document).on("click", "#ulib-addLibFiles", function() { $("#ulib-input-libfiles").trigger("click"); });
		$(document).on("click", "#ulib-addLibFolder", function() { $("#ulib-input-libfolder").trigger("click"); });
		$(document).on("click", "#ulib-addDemoFiles", function() { $("#ulib-input-demofiles").trigger("click"); });
		$(document).on("click", "#ulib-addDemoFolder", function() { $("#ulib-input-demofolder").trigger("click"); });

		// ---- Unsigned lib: icon / image picker (mirrors pkg icon picker) ----
		$(document).on("click", "#ulib-pickIcon", function() {
			$("#ulib-input-icon").trigger("click");
		});

		$(document).on("change", "#ulib-input-icon", function() {
			var fileInput = this;
			if (!fileInput.files || fileInput.files.length === 0) return;
			var filePath = fileInput.files[0].path;
			$(this).val('');
			if (!filePath) return;

			try {
				if (!fs.existsSync(filePath)) {
					alert("File not found: " + filePath);
					return;
				}
				var stats = fs.statSync(filePath);
				if (stats.size > 2 * 1024 * 1024) {
					alert("Image file is too large (max 2 MB).");
					return;
				}

				var ext = path.extname(filePath).toLowerCase();
				var mime = IMAGE_MIME_MAP[ext] || 'image/png';
				var b64 = fs.readFileSync(filePath).toString('base64');

				ulib_iconFilePath = filePath;
				ulib_iconBase64 = b64;
				ulib_iconMime = mime;
				ulib_iconFilename = path.basename(filePath);

				$("#ulib-icon-preview").html('<img src="data:' + mime + ';base64,' + b64 + '">').addClass('has-image');
				$("#ulib-icon-name").text(path.basename(filePath));
				$("#ulib-removeIcon").show();
			} catch(e) {
				alert("Error loading image: " + e.message);
			}
		});

		$(document).on("click", "#ulib-removeIcon", function() {
			ulib_iconFilePath = null;
			ulib_iconBase64 = null;
			ulib_iconMime = null;
			ulib_iconFilename = null;

			$("#ulib-icon-preview").html('<i class="fas fa-image fa-2x" style="color:#ccc;"></i>').removeClass('has-image');
			$("#ulib-icon-name").text("No image selected");
			$("#ulib-removeIcon").hide();

			// Also update modal header icon
			$("#unsignedLibDetailModal .unsigned-lib-detail-icon")
				.html('<i class="far fa-times-circle fa-3x" style="color:var(--medium)"></i>');
		});

		$(document).on("change", "#ulib-input-libfiles", function() {
			var fileInput = this;
			var newDlls = [];
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && ulib_allLibFiles.indexOf(filePath) === -1) {
					ulib_allLibFiles.push(filePath);
					var baseName = path.basename(filePath);
					if (baseName.toLowerCase().endsWith('.dll')) {
						newDlls.push(baseName);
					}
				}
			}
			if (newDlls.length === 1 && ulib_comRegisterDlls.indexOf(newDlls[0]) === -1) {
				ulib_comRegisterDlls.push(newDlls[0]);
			}
			ulibUpdateLibFileList();
			ulibUpdateComWarning();
			$(this).val('');
		});

		$(document).on("change", "#ulib-input-libfolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var files = fs.readdirSync(folderPath);
					var newDlls = [];
					files.forEach(function(file) {
						var filePath = path.join(folderPath, file);
						try {
							if (fs.statSync(filePath).isFile() && ulib_allLibFiles.indexOf(filePath) === -1) {
								ulib_allLibFiles.push(filePath);
								if (file.toLowerCase().endsWith('.dll')) {
									newDlls.push(file);
								}
							}
						} catch(e) {}
					});
					if (newDlls.length === 1 && ulib_comRegisterDlls.indexOf(newDlls[0]) === -1) {
						ulib_comRegisterDlls.push(newDlls[0]);
					}
					ulibUpdateLibFileList();
					ulibUpdateComWarning();
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		$(document).on("change", "#ulib-input-demofiles", function() {
			var fileInput = this;
			for (var i = 0; i < fileInput.files.length; i++) {
				var filePath = fileInput.files[i].path;
				if (filePath && ulib_demoMethodFiles.indexOf(filePath) === -1) {
					ulib_demoMethodFiles.push(filePath);
				}
			}
			ulibUpdateDemoFileList();
			$(this).val('');
		});

		$(document).on("change", "#ulib-input-demofolder", function() {
			var folderPath = $(this).val();
			if (folderPath) {
				try {
					var files = fs.readdirSync(folderPath);
					files.forEach(function(file) {
						var filePath = path.join(folderPath, file);
						try {
							if (fs.statSync(filePath).isFile() && ulib_demoMethodFiles.indexOf(filePath) === -1) {
								ulib_demoMethodFiles.push(filePath);
							}
						} catch(e) {}
					});
					ulibUpdateDemoFileList();
				} catch(e) {
					alert("Error reading folder: " + e.message);
				}
			}
			$(this).val('');
		});

		// ---- Unsigned lib: remove selected files ----
		$(document).on("click", "#ulib-removeLibFiles", function() {
			var selected = [];
			$("#ulib-file-list .pkg-file-item.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) return;
			ulib_allLibFiles = ulib_allLibFiles.filter(function(f) {
				if (selected.indexOf(f) !== -1) {
					delete ulib_fileCustomDirs[f];
					return false;
				}
				return true;
			});
			// Remove any COM registrations for removed DLLs
			var removedDlls = selected.map(function(f) { return path.basename(f); }).filter(function(n) { return n.toLowerCase().endsWith('.dll'); });
			ulib_comRegisterDlls = ulib_comRegisterDlls.filter(function(d) { return removedDlls.indexOf(d) === -1; });
			ulibUpdateLibFileList();
			ulibUpdateComWarning();
		});

		$(document).on("click", "#ulib-removeDemoFiles", function() {
			var selected = [];
			$("#ulib-demo-list .pkg-file-item.selected").each(function() {
				selected.push($(this).attr("data-path"));
			});
			if (selected.length === 0) return;
			ulib_demoMethodFiles = ulib_demoMethodFiles.filter(function(f) {
				return selected.indexOf(f) === -1;
			});
			ulibUpdateDemoFileList();
		});

		// ---- Unsigned lib: toggle file selection (click / ctrl+click) ----
		$(document).on("click", "#unsignedLibDetailModal .pkg-file-item", function(e) {
			if (e.ctrlKey || e.metaKey) {
				$(this).toggleClass("selected");
			} else {
				$(this).siblings().removeClass("selected");
				$(this).toggleClass("selected");
			}
		});

		// ---- Unsigned lib: COM register checkbox handler ----
		$(document).on("change", "#unsignedLibDetailModal .pkg-com-checkbox", function(e) {
			e.stopPropagation();
			var dllName = $(this).attr("data-dll");
			if ($(this).is(":checked")) {
				if (ulib_comRegisterDlls.indexOf(dllName) === -1) {
					ulib_comRegisterDlls.push(dllName);
				}
			} else {
				ulib_comRegisterDlls = ulib_comRegisterDlls.filter(function(d) { return d !== dllName; });
			}
			ulibUpdateComWarning();
		});

		$(document).on("click", "#unsignedLibDetailModal .pkg-com-checkbox-label", function(e) {
			e.stopPropagation();
		});

		// ---- Unsigned lib: clear red styling on GitHub URL input ----
		$(document).on("input", "#ulib-github-url", function() {
			$(this).css({"border": "", "background": ""});
		});

		// ---- Unsigned lib: restricted OEM author/organization check ----
		var ulib_oemAuthorized = false;

		$(document).on("blur", "#ulib-author, #ulib-organization", async function() {
			var fieldVal = $(this).val().trim();
			if (isRestrictedAuthor(fieldVal)) {
				if (_oemSessionUnlocked) {
					ulib_oemAuthorized = true;
				} else {
					$("#restrictedAuthorWarningModal").modal("show");
					$(this).val('');
					ulib_oemAuthorized = false;
				}
			} else if (!isRestrictedAuthor($('#ulib-author').val().trim()) && !isRestrictedAuthor($('#ulib-organization').val().trim())) {
				ulib_oemAuthorized = false;
			}
		});

		// Reset restricted author auth when modal closes
		$("#unsignedLibDetailModal").on("hidden.bs.modal", function() {
			ulib_oemAuthorized = false;
		});

		// ---- Save unsigned library metadata ----
		$(document).on("click", "#ulib-save-btn", async function() {
			var ulibId = $("#unsignedLibDetailModal").attr("data-ulib-id");
			if (!ulibId) return;

			var author = $("#ulib-author").val().trim();
			var organization = $("#ulib-organization").val().trim();

			// Validate author/organization length
			if (author && author.length < shared.AUTHOR_MIN_LENGTH) {
				alert("Author Name must be at least " + shared.AUTHOR_MIN_LENGTH + " characters.");
				$("#ulib-author").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (author && author.length > shared.AUTHOR_MAX_LENGTH) {
				alert("Author Name cannot exceed " + shared.AUTHOR_MAX_LENGTH + " characters.");
				$("#ulib-author").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (organization && organization.length < shared.AUTHOR_MIN_LENGTH) {
				alert("Organization must be at least " + shared.AUTHOR_MIN_LENGTH + " characters.");
				$("#ulib-organization").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}
			if (organization && organization.length > shared.AUTHOR_MAX_LENGTH) {
				alert("Organization cannot exceed " + shared.AUTHOR_MAX_LENGTH + " characters.");
				$("#ulib-organization").focus().css({"border": "1px solid red", "background": "#FFCECE"});
				return;
			}

			// Check restricted OEM author on save
			if (isRestrictedAuthor(author) || isRestrictedAuthor(organization)) {
				if (!ulib_oemAuthorized && !isOemKeywordsEnabled()) {
					var pwOk = await promptAuthorPassword();
					if (pwOk) {
						ulib_oemAuthorized = true;
					} else {
						alert("Cannot save: restricted OEM author/organization name requires authorization.");
						return;
					}
				}
			}

			var tagsRaw = $("#ulib-tags").val().trim();
			var tags = tagsRaw ? shared.sanitizeTags(tagsRaw.split(",")) : [];

			// Filter reserved tags (system, OEM, and restricted company names are not allowed)
			var tagCheck = shared.filterReservedTags(tags);
			if (tagCheck.removed.length > 0) {
				showTagValidationErrorModal('The following tags are reserved and cannot be used: ' + tagCheck.removed.join(', ') + '\n\nThese tags have been automatically removed.');
				tags = tagCheck.filtered;
			}
			$("#ulib-tags").val(tags.join(", "));

			// Validate GitHub Repository URL (optional, but must be valid if provided)
			var githubUrl = $("#ulib-github-url").val().trim();
			if (githubUrl) {
				var ghResult = shared.validateGitHubRepoUrl(githubUrl);
				if (!ghResult.valid) {
					alert("Invalid GitHub Repository URL:\n" + ghResult.reason);
					$("#ulib-github-url").focus().css({"border": "1px solid red", "background": "#FFCECE"});
					return;
				}
			}

			// Separate discovered files (relative to lib_base_path) from additional user-added files
			var uLib = db_unsigned_libs.unsigned_libs.findOne({"_id": ulibId});
			var libDir = uLib ? (uLib.lib_base_path || '') : '';
			var discoveredFiles = uLib ? (uLib.library_files || []) : [];
			var additionalLibFiles = ulib_allLibFiles.filter(function(f) {
				// A file is "additional" if it's not a resolved discovered file
				for (var i = 0; i < discoveredFiles.length; i++) {
					if (path.join(libDir, discoveredFiles[i]) === f) return false;
				}
				return true;
			});

			var updates = {
				author: author,
				organization: organization,
				version: $("#ulib-version").val().trim(),
				venus_compatibility: $("#ulib-venus-compat").val().trim(),
				description: $("#ulib-description").val().trim(),
				github_url: $("#ulib-github-url").val().trim(),
				tags: tags,
				additional_library_files: additionalLibFiles,
				demo_method_files: ulib_demoMethodFiles.slice(),
				com_register_dlls: ulib_comRegisterDlls.slice(),
				library_image: ulib_iconFilename,
				library_image_base64: ulib_iconBase64,
				library_image_mime: ulib_iconMime,
				install_to_library_root: ulib_installSubdir === '',
				custom_install_subdir: (ulib_installSubdir && ulib_installSubdir !== '') ? ulib_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '') : ''
			};

			// Update in DB
			db_unsigned_libs.unsigned_libs.update({"_id": ulibId}, updates, {multi: false, upsert: false});

			// Visual feedback
			var $btn = $("#ulib-save-btn");
			var origHtml = $btn.html();
			$btn.html('<i class="fas fa-check mr-1"></i>Saved!').prop("disabled", true);
			setTimeout(function() {
				$btn.html(origHtml).prop("disabled", false);
			}, 1200);

			// Refresh cards if visible
			var activeGroup = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id");
			if (activeGroup === 'gUnsigned') {
				impBuildLibraryCards(null, false, false, true);
			} else if (activeGroup === 'gAll') {
				impBuildLibraryCards();
			}
		});

		// ---- Register unsigned library into Library Manager ----
		$(document).on("click", "#ulib-register-btn", async function() {
			var ulibId = $("#unsignedLibDetailModal").attr("data-ulib-id");
			if (!ulibId) return;

			// Save any pending metadata first
			$("#ulib-save-btn").trigger("click");
			await new Promise(function(r) { setTimeout(r, 300); });

			// Validate required fields
			var missingFields = [];
			if (!$("#ulib-author").val().trim()) missingFields.push("Author");
			if (!$("#ulib-version").val().trim()) missingFields.push("Version");
			if (!$("#ulib-venus-compat").val().trim()) missingFields.push("VENUS Compatibility");
			if (!$("#ulib-description").val().trim()) missingFields.push("Description");
			if (missingFields.length > 0) {
				alert("The following required fields are missing:\n\n" + missingFields.join("\n"));
				return;
			}

			// If demo method files exist, prompt the user for placement preference
			if (ulib_demoMethodFiles.length > 0) {
				var uLib = db_unsigned_libs.unsigned_libs.findOne({"_id": ulibId});
				var libName = uLib ? (uLib.library_name || "Unknown") : "Unknown";
				var methodFolderRec = db_links.links.findOne({"_id":"met-folder"});
				var sysMethodDir = (methodFolderRec && methodFolderRec.path) ? methodFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Methods';
				var demoDestPreview = path.join(sysMethodDir, 'Library Demo Methods', libName);

				var $dlm = $("#ulibDemoLocationModal");
				$dlm.attr("data-ulib-id", ulibId);
				$("#ulib-demo-location-count").text(ulib_demoMethodFiles.length);
				$("#ulib-demo-location-move-path").text(demoDestPreview);
				$dlm.find(".ulib-demo-location-option").css("border-color", "transparent");
				$dlm.removeData("demo-choice");
				$("#ulib-demo-location-confirm").prop("disabled", true);
				$dlm.modal("show");
			} else {
				var result = await registerUnsignedLibrary(ulibId);
				if (result) {
					$("#unsignedLibDetailModal").modal("hide");
				}
			}
		});

		// ---- Demo location modal: option selection ----
		$(document).on("click", ".ulib-demo-location-option", function() {
			$(".ulib-demo-location-option").css("border-color", "transparent");
			$(this).css("border-color", "var(--medium)");
			$("#ulibDemoLocationModal").data("demo-choice", $(this).attr("data-choice"));
			$("#ulib-demo-location-confirm").prop("disabled", false);
		});

		// ---- Demo location modal: confirm ----
		$(document).on("click", "#ulib-demo-location-confirm", async function() {
			var $dlm = $("#ulibDemoLocationModal");
			var ulibId = $dlm.attr("data-ulib-id");
			var choice = $dlm.data("demo-choice");
			if (!ulibId || !choice) return;

			$dlm.modal("hide");

			var result = await registerUnsignedLibrary(ulibId, { demoLocation: choice });
			if (result) {
				$("#unsignedLibDetailModal").modal("hide");
			}
		});

		// ---- Remove unsigned library entry ----
		$(document).on("click", "#ulib-remove-btn", function() {
			var ulibId = $("#unsignedLibDetailModal").attr("data-ulib-id");
			if (!ulibId) return;
			if (!confirm("Remove this unsigned library from the list?\nThe files on disk will not be modified.")) return;

			db_unsigned_libs.unsigned_libs.remove({"_id": ulibId});
			$("#unsignedLibDetailModal").modal("hide");

			// Update status
			var remaining = (db_unsigned_libs.unsigned_libs.find() || []).length;
			$(".unsigned-scan-status").text(remaining + " unsigned librar" + (remaining === 1 ? "y" : "ies") + " tracked");

			// Refresh
			var activeGroup = $(".navbar-custom .nav-item.active, .navbar-custom .dropdown-navitem.active").attr("data-group-id");
			if (activeGroup === 'gUnsigned') {
				impBuildLibraryCards(null, false, false, true);
			} else if (activeGroup === 'gAll') {
				impBuildLibraryCards();
			}
			invalidateNavBar();
		});

		// ---- Export unsigned library as .hxlibpkg ----
		$(document).on("click", "#ulib-export-btn", function(e) {
			e.preventDefault();
			var ulibId = $("#unsignedLibDetailModal").attr("data-ulib-id");
			if (!ulibId) return;

			// Validate required fields
			var missingFields = [];
			if (!$("#ulib-author").val().trim()) missingFields.push("Author");
			if (!$("#ulib-version").val().trim()) missingFields.push("Version");
			if (!$("#ulib-venus-compat").val().trim()) missingFields.push("VENUS Compatibility");
			if (!$("#ulib-description").val().trim()) missingFields.push("Description");
			if (missingFields.length > 0) {
				alert("The following required fields are missing:\n\n" + missingFields.join("\n"));
				return;
			}

			// Save any pending metadata first
			$("#ulib-save-btn").trigger("click");

			// Trigger save dialog
			setTimeout(function() {
				$("#ulib-export-save-dialog").trigger("click");
			}, 200);
		});

		$(document).on("change", "#ulib-export-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			var ulibId = $("#unsignedLibDetailModal").attr("data-ulib-id");
			if (!ulibId) return;
			exportUnsignedLibrary(ulibId, savePath);
		});

		/**
		 * Register an unsigned library directly into Library Manager as a signed/installed library.
		 * This creates a database record in installed_libs.json, computes integrity hashes,
		 * extracts public functions and dependencies, assigns the library to a navigation group,
		 * removes it from the unsigned list, and refreshes the UI.
		 *
		 * @param {string} ulibId - The _id of the unsigned library record
		 * @param {Object} [opts] - Options
		 * @param {boolean} [opts.silent] - If true, suppress the success modal (used when called from export flow)
		 * @param {string} [opts.sourcePackage] - Source package filename (used when called from export flow)
		 * @returns {Promise<boolean>} true if registration succeeded, false otherwise
		 */
		async function registerUnsignedLibrary(ulibId, opts) {
			opts = opts || {};
			try {
				var uLib = db_unsigned_libs.unsigned_libs.findOne({"_id": ulibId});
				if (!uLib) { alert("Unsigned library not found."); return false; }

				var libName = uLib.library_name || "Unknown";
				var libDir = uLib.lib_base_path || '';
				if (!libDir) {
					alert('Cannot register "' + libName + '": library base path is missing.');
					return false;
				}
				var discoveredFiles = uLib.library_files || [];
				var additionalFiles = uLib.additional_library_files || [];
				var demoFiles = uLib.demo_method_files || [];
				var comDlls = uLib.com_register_dlls || [];

				// Build the list of library file basenames (same as what import uses)
				var allLibPaths = discoveredFiles.map(function(f) { return path.join(libDir, f); });
				additionalFiles.forEach(function(f) {
					if (allLibPaths.indexOf(f) === -1) allLibPaths.push(f);
				});

				// Build relative paths list for the DB record (preserves subdirectory structure)
				var libFileRelPaths = allLibPaths.map(function(f) {
					return libDir ? path.relative(libDir, f).replace(/\\/g, '/') : path.basename(f);
				});

				// Separate help files
				var helpFiles = [];
				allLibPaths.forEach(function(f) {
					if (path.extname(f).toLowerCase() === '.chm') {
						helpFiles.push(libDir ? path.relative(libDir, f).replace(/\\/g, '/') : path.basename(f));
					}
				});

				// Determine install paths (the library files are already in place on disk)
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';
				var libDestDir = libDir || sysLibDir;

				var methodFolderRec = db_links.links.findOne({"_id":"met-folder"});
				var sysMethodDir = (methodFolderRec && methodFolderRec.path) ? methodFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Methods';
				var demoDestDir = path.join(sysMethodDir, 'Library Demo Methods', libName);

				// Handle demo method file location based on user's choice
				var demoLocation = opts.demoLocation || 'move'; // 'move' = Library Demo Methods, 'keep' = library area
				if (demoLocation === 'keep') {
					// Keep demo files in their current location (library area)
					demoDestDir = libDestDir;
				} else if (demoLocation === 'move' && demoFiles.length > 0) {
					// Copy demo files to the Library Demo Methods folder
					try {
						if (!fs.existsSync(demoDestDir)) {
							fs.mkdirSync(demoDestDir, { recursive: true });
						}
						for (var di = 0; di < demoFiles.length; di++) {
							var srcDemo = demoFiles[di];
							var dstDemo = path.join(demoDestDir, path.basename(srcDemo));
							if (fs.existsSync(srcDemo)) {
								fs.copyFileSync(srcDemo, dstDemo);
							}
						}
					} catch(copyErr) {
						console.warn('Could not copy demo files to Library Demo Methods: ' + copyErr.message);
						// Fall back to keeping them in place
						demoDestDir = libDestDir;
					}
				}

				// Check for existing installed lib with same name
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				// Compute integrity hashes
				var fileHashes = {};
				try { fileHashes = computeLibraryHashes(libFileRelPaths, libDestDir, comDlls); } catch(e) { console.warn('Could not compute integrity hashes: ' + e.message); }

				// Build the installed library database record (same schema as import)
				var dbRecord = {
					library_name: libName,
					author: uLib.author || "",
					organization: uLib.organization || "",
					installed_by: getWindowsUsername(),
					version: uLib.version || "",
					venus_compatibility: uLib.venus_compatibility || "",
					description: uLib.description || "",
					github_url: uLib.github_url || "",
					tags: uLib.tags || [],
					created_date: uLib.scanned_date || new Date().toISOString(),
					library_image: uLib.library_image || null,
					library_image_base64: uLib.library_image_base64 || null,
					library_image_mime: uLib.library_image_mime || null,
					library_files: libFileRelPaths,
					demo_method_files: demoFiles.map(function(f) { return path.basename(f); }),
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: false,
					com_registered: false,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: opts.sourcePackage || '(registered from unsigned)',
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFileRelPaths, libDestDir),
					required_dependencies: extractRequiredDependencies(libFileRelPaths, libDestDir),
					publisher_cert: null
				};
				var saved = db_installed_libs.installed_libs.save(dbRecord);

				// Write .libmgr marker file
				try { shared.updateMarkerForLibrary(dbRecord); } catch(_) { /* non-critical */ }

				// Update publisher registry
				registerPublisher(uLib.author || '');
				registerPublisher(uLib.organization || '');
				registerTags(uLib.tags || []);

				// Add the new library to the appropriate group in the nav tree
				var navtree = db_tree.tree.find();
				var targetGroupId = null;

				var savedAuthor = (uLib.author || '').trim();
				var savedOrg = (uLib.organization || '').trim();
				if (isRestrictedAuthor(savedAuthor) || isRestrictedAuthor(savedOrg)) {
					targetGroupId = addToOemTreeGroup(saved._id);
				} else {
					for (var ti = 0; ti < navtree.length; ti++) {
						var gEntry = getGroupById(navtree[ti]["group-id"]);
						if (gEntry && !gEntry["default"]) {
							targetGroupId = navtree[ti]["group-id"];
							var existingIds = (navtree[ti]["method-ids"] || []).slice();
							existingIds.push(saved._id);
							db_tree.tree.update({"group-id": targetGroupId}, {"method-ids": existingIds}, {multi: false, upsert: false});
							break;
						}
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

				// Remove from unsigned libs
				db_unsigned_libs.unsigned_libs.remove({"_id": ulibId});

				// Update unsigned status display
				var remaining = (db_unsigned_libs.unsigned_libs.find() || []).length;
				$(".unsigned-scan-status").text(remaining + " unsigned librar" + (remaining === 1 ? "y" : "ies") + " tracked");

				// Audit trail
				try {
					appendAuditTrailEntry(buildAuditTrailEntry('library_registered', {
						library_name: libName,
						version: uLib.version || '',
						author: uLib.author || '',
						organization: uLib.organization || '',
						lib_install_path: libDestDir,
						source: 'unsigned_library',
						library_files: libFileRelPaths.length,
						demo_files: demoFiles.length
					}));
				} catch(_) { /* non-critical */ }

				// Refresh UI
				impBuildLibraryCards();
				invalidateNavBar();

				if (!opts.silent) {
					var successPaths = [
						{ label: "Library Path", value: libDestDir }
					];
					if (demoFiles.length > 0 && demoDestDir !== libDestDir) {
						successPaths.push({ label: "Demo Methods Path", value: demoDestDir });
					}
					showGenericSuccessModal({
						title: "Library Registered!",
						name: libName,
						detail: libFileRelPaths.length + " file" + (libFileRelPaths.length !== 1 ? "s" : "") + " registered" + (demoFiles.length > 0 ? " (incl. " + demoFiles.length + " demo)" : ""),
						paths: successPaths,
						statusHtml: '<i class="fas fa-check-circle mr-1"></i>Library is now signed and tracked by Library Manager',
						statusClass: 'com-ok'
					});
				}

				return true;
			} catch(e) {
				alert("Error registering unsigned library:\n" + e.message);
				return false;
			}
		}

		/**
		 * Export an unsigned library as a .hxlibpkg package.
		 * The package will be signed for integrity but the source was unsigned.
		 * After successful export, the library is automatically registered into
		 * Library Manager as a signed/installed library.
		 */
		async function exportUnsignedLibrary(ulibId, savePath) {
			try {
				var uLib = db_unsigned_libs.unsigned_libs.findOne({"_id": ulibId});
				if (!uLib) { alert("Unsigned library not found."); return; }

				var comDlls = uLib.com_register_dlls || [];

				var libName = uLib.library_name || "Unknown";
				var libDir = uLib.lib_base_path || '';
				var discoveredFiles = uLib.library_files || [];
				var additionalFiles = uLib.additional_library_files || [];
				var demoFiles = uLib.demo_method_files || [];

				// Build full library file list (discovered as relative, additional as absolute)
				var allLibPaths = discoveredFiles.map(function(f) { return path.join(libDir, f); });
				additionalFiles.forEach(function(f) {
					if (allLibPaths.indexOf(f) === -1) allLibPaths.push(f);
				});

				// Verify all library files exist
				for (var i = 0; i < allLibPaths.length; i++) {
					if (!fs.existsSync(allLibPaths[i])) {
						alert("Library file not found:\n" + allLibPaths[i] + "\n\nExport aborted.");
						return;
					}
				}

				// Verify demo method files exist
				for (var d = 0; d < demoFiles.length; d++) {
					if (!fs.existsSync(demoFiles[d])) {
						alert("Demo method file not found:\n" + demoFiles[d] + "\n\nExport aborted.");
						return;
					}
				}

				// Separate help files from library files (by basename)
				var helpPaths = [];
				var nonHelpPaths = [];
				allLibPaths.forEach(function(f) {
					if (path.extname(f).toLowerCase() === '.chm') {
						helpPaths.push(f);
					} else {
						nonHelpPaths.push(f);
					}
				});

				// Build manifest file lists (relative paths to preserve subfolder structure)
				var manifestLibFiles = nonHelpPaths.map(function(f) {
					return libDir ? path.relative(libDir, f).replace(/\\/g, '/') : path.basename(f);
				});
				var manifestHelpFiles = helpPaths.map(function(f) {
					return libDir ? path.relative(libDir, f).replace(/\\/g, '/') : path.basename(f);
				});
				manifestHelpFiles.forEach(function(hf) {
					if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
				});
				var manifestDemoFiles = demoFiles.map(function(f) { return path.basename(f); });

				var manifest = {
					format_version: shared.FORMAT_VERSION,
					library_name: libName,
					author: uLib.author || "",
					organization: uLib.organization || "",
					version: uLib.version || "",
					venus_compatibility: uLib.venus_compatibility || "",
					description: uLib.description || "",
					github_url: uLib.github_url || "",
					tags: uLib.tags || [],
					created_date: new Date().toISOString(),
					app_version: shared.getAppVersion(),
					windows_version: shared.getWindowsVersion(),
					venus_version: _cachedVENUSVersion || '',
					package_lineage: [shared.buildLineageEvent('created', {
						username: getWindowsUsername(),
						hostname: os.hostname(),
						venusVersion: _cachedVENUSVersion || ''
					})],
					library_image: uLib.library_image || null,
					library_image_base64: uLib.library_image_base64 || null,
					library_image_mime: uLib.library_image_mime || null,
					library_files: manifestLibFiles,
					demo_method_files: manifestDemoFiles,
					help_files: manifestHelpFiles,
					com_register_dlls: comDlls
				};
				if (ulib_installSubdir === '') manifest.install_to_library_root = true;
				var ulibCustomSubdir = (ulib_installSubdir && ulib_installSubdir !== '') ? ulib_installSubdir.replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/^\\|\\$/g, '') : '';
				if (ulibCustomSubdir && !manifest.install_to_library_root) manifest.custom_install_subdir = ulibCustomSubdir;

				// Create ZIP package
				var zip = new AdmZip();

				// Add manifest
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files (non-help)
				nonHelpPaths.forEach(function(f) {
					if (fs.existsSync(f)) {
						var relPath = libDir ? path.relative(libDir, f) : path.basename(f);
						zip.addLocalFile(f, zipSubdir('library', relPath));
					}
				});

				// Add help files
				helpPaths.forEach(function(f) {
					if (fs.existsSync(f)) {
						var relPath = libDir ? path.relative(libDir, f) : path.basename(f);
						zip.addLocalFile(f, zipSubdir('library', relPath));
					}
				});

				// Add demo method files
				demoFiles.forEach(function(f) {
					if (fs.existsSync(f)) {
						zip.addLocalFile(f, "demo_methods");
					}
				});

				// Add icon to icon/ directory if available
				if (uLib.library_image_base64) {
					var iconFilename = uLib.library_image || (libName + '_icon.png');
					zip.addFile("icon/" + iconFilename, Buffer.from(uLib.library_image_base64, 'base64'));
				}

				// Sign the package
				var ulibCfg = getSigningConfig();
				var ulibUseCodeSigning = !!(ulibCfg.keyPath && ulibCfg.certPath);
				applyPackageSigning(zip, ulibUseCodeSigning);

				// Write binary container
				fs.writeFileSync(savePath, packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

				var totalFiles = allLibPaths.length + demoFiles.length;

				// Audit trail
				try {
					appendAuditTrailEntry(buildAuditTrailEntry('package_created', {
						library_name: libName,
						version: uLib.version || '',
						author: uLib.author || '',
						organization: uLib.organization || '',
						output_file: savePath,
						library_files: allLibPaths.length,
						demo_files: demoFiles.length,
						source: 'unsigned_library'
					}));
				} catch(_) { /* non-critical */ }

				// Auto-register the library into Library Manager (signed/installed)
				var regSuccess = await registerUnsignedLibrary(ulibId, {
					silent: true,
					sourcePackage: path.basename(savePath)
				});

				var statusHtml = '';
				var statusClass = 'com-ok';
				if (regSuccess) {
					statusHtml = '<i class="fas fa-check-circle mr-1"></i>Library has been automatically registered in Library Manager';
				} else {
					statusHtml = '<i class="fas fa-exclamation-triangle mr-1"></i>Package exported but automatic registration failed. You can import the package manually.';
					statusClass = 'com-warning';
				}

				showGenericSuccessModal({
					title: regSuccess ? "Library Exported & Registered!" : "Package Exported",
					name: libName,
					detail: totalFiles + " file" + (totalFiles !== 1 ? "s" : "") + " packaged" + (demoFiles.length > 0 ? " (incl. " + demoFiles.length + " demo)" : ""),
					paths: [
						{ label: "Saved To", value: savePath }
					],
					statusHtml: statusHtml,
					statusClass: statusClass
				});

				$("#unsignedLibDetailModal").modal("hide");

			} catch(e) {
				alert("Error exporting unsigned library:\n" + e.message);
			}
		}

		/**
		 * Get all unsigned library records (for dependency resolution).
		 * Returns empty array if the feature is disabled.
		 */
		function getUnsignedLibraries() {
			if (!getSettingValue('chk_includeUnsignedLibs')) return [];
			return db_unsigned_libs.unsigned_libs.find() || [];
		}

		//**************************************************************************************
		//****** IMPORT HAMPKG (VENUS .pkg) ****************************************************
		//**************************************************************************************

		var pkgExtractor = require('../lib/pkg-extractor');

		/** State for the HamPkg import workflow */
		var _hampkgFiles = [];      // Array of extracted file entries from pkg-extractor
		var _hampkgPkgInfo = null;   // Parsed package info from parsePkg()
		var _hampkgBuffer = null;    // Raw .pkg file buffer
		var _hampkgFilePath = '';    // Path to the .pkg file
		var _hampkgLastClickedIdx = -1; // Last clicked file index for shift-select

		/**
		 * Format a byte count as a human-readable string.
		 */
		function formatFileSize(bytes) {
			if (bytes < 1024) return bytes + ' B';
			if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
			return (bytes / 1048576).toFixed(1) + ' MB';
		}

		/**
		 * Reset the HamPkg modal to its initial state (step 1: file selection).
		 */
		function hampkgReset() {
			_hampkgFiles = [];
			_hampkgPkgInfo = null;
			_hampkgBuffer = null;
			_hampkgFilePath = '';
			_hampkgLastClickedIdx = -1;

			var $modal = $("#importHamPkgModal");
			$modal.find(".hampkg-step-select").removeClass("d-none");
			$modal.find(".hampkg-step-explore").addClass("d-none");
			$modal.find(".hampkg-loading").addClass("d-none");
			$modal.find(".hampkg-btn-back").addClass("d-none");
			$modal.find(".hampkg-btn-import").prop("disabled", true);
			$modal.find("#hampkg-file-list").empty();
			$modal.find("#hampkg-lib-name").val("");
			$modal.find("#hampkg-lib-version").val("1.0.0");
			$modal.find("#hampkg-lib-author").val("");
			$modal.find("#hampkg-lib-org").val("");
			$modal.find("#hampkg-lib-venus").val("");
			$modal.find("#hampkg-lib-tags").val("");
			$modal.find("#hampkg-lib-desc").val("");

			$modal.find(".hampkg-cat-btn").removeClass("active");
			$modal.find('.hampkg-cat-btn[data-cat="all"]').addClass("active");
		}

		/**
		 * Load a .pkg or .hamPackage file buffer and populate the explore view.
		 */
		function hampkgLoadFile(filePath) {
			var $modal = $("#importHamPkgModal");

			// Show loading state
			$modal.find(".hampkg-step-select").addClass("d-none");
			$modal.find(".hampkg-loading").removeClass("d-none");

			try {
				_hampkgFilePath = filePath;
				var ext = path.extname(filePath).toLowerCase();

				if (ext === '.hampackage') {
					// .hamPackage = ZIP-based format
					var result = pkgExtractor.parseHamPackage(filePath);
					_hampkgPkgInfo = result.pkgInfo;
					_hampkgFiles = result.files;
					_hampkgBuffer = null; // not needed for ZIP format
				} else {
					// .pkg = binary HamPkg format
					_hampkgBuffer = fs.readFileSync(filePath);
					_hampkgPkgInfo = pkgExtractor.parsePkg(_hampkgBuffer);
					_hampkgFiles = pkgExtractor.extractAllFiles(_hampkgBuffer, _hampkgPkgInfo);
				}

				// Populate package info header
				$modal.find(".hampkg-pkg-name").text(path.basename(filePath));
				$modal.find(".hampkg-venus-ver").text(_hampkgPkgInfo.venusVersion || "\u2014");
				$modal.find(".hampkg-pkg-author").text(
					_hampkgPkgInfo.trailer ? _hampkgPkgInfo.trailer.author : "\u2014"
				);
				$modal.find(".hampkg-pkg-created").text(
					_hampkgPkgInfo.created ? _hampkgPkgInfo.created.toLocaleString() : "\u2014"
				);
				var fileDataCount = 0;
				for (var ec = 0; ec < _hampkgPkgInfo.entries.length; ec++) {
					if (_hampkgPkgInfo.entries[ec].flags === 1) fileDataCount++;
				}
				$modal.find(".hampkg-pkg-filecount").text(fileDataCount + " files");
				$modal.find(".hampkg-pkg-format").text(_hampkgPkgInfo.formatVersion);

				// Auto-fill VENUS compatibility from package
				if (_hampkgPkgInfo.venusVersion) {
					var venMajMin = _hampkgPkgInfo.venusVersion.split('.').slice(0, 2).join('.');
					$modal.find("#hampkg-lib-venus").val(venMajMin + "+");
				}

				// Auto-fill author from trailer
				if (_hampkgPkgInfo.trailer && _hampkgPkgInfo.trailer.author) {
					$modal.find("#hampkg-lib-author").val(_hampkgPkgInfo.trailer.author);
				}

				// Build file list
				hampkgBuildFileList();

				// Auto-detect library name from the files
				var detectedName = pkgExtractor.detectLibraryName(_hampkgFiles);
				if (detectedName) {
					$modal.find("#hampkg-lib-name").val(detectedName);
				}

				// Auto-select library and help files by default
				for (var af = 0; af < _hampkgFiles.length; af++) {
					var f = _hampkgFiles[af];
					if (f.pathCategory === 'library' || f.category.group === 'library' || f.category.group === 'help') {
						f.selected = true;
					}
				}
				hampkgBuildFileList();
				hampkgUpdateSummary();
				hampkgUpdateInstallPath();

				// Show explore view
				$modal.find(".hampkg-loading").addClass("d-none");
				$modal.find(".hampkg-step-explore").removeClass("d-none");
				$modal.find(".hampkg-btn-back").removeClass("d-none");

			} catch (e) {
				$modal.find(".hampkg-loading").addClass("d-none");
				$modal.find(".hampkg-step-select").removeClass("d-none");
				alert("Error reading package file:\n" + e.message);
			}
		}

		/**
		 * Compute the relative path within the destination directory from a file's relPath.
		 * Strips the Hamilton category prefix (Library\, Methods\, etc.) and the library name prefix
		 * to yield the subdir + filename relative to the install root.
		 * E.g. "Library\ASW Standard\ASW Global\ASWGlobal.hsl" with libName "ASW Standard"
		 *   → "ASW Global\ASWGlobal.hsl"
		 */
		function hampkgRelativeInstallPath(f, libName) {
			var rel = f.relPath || f.fileName;
			// Normalize separators
			rel = rel.replace(/\//g, '\\');
			var parts = rel.split('\\');
			// Strip known Hamilton top-level folders: Library, Methods, Labware, Config, System
			var topFolders = ['library', 'methods', 'labware', 'config', 'system', 'dependencies'];
			if (parts.length > 1 && topFolders.indexOf(parts[0].toLowerCase()) >= 0) {
				parts = parts.slice(1);
			}
			// Strip library name folder if it matches
			if (parts.length > 1 && libName && parts[0].toLowerCase() === libName.toLowerCase()) {
				parts = parts.slice(1);
			}
			// For methods/demo: also strip "Library Demo Methods" prefix if present
			if (parts.length > 1 && parts[0].toLowerCase() === 'library demo methods') {
				parts = parts.slice(1);
				if (parts.length > 1 && libName && parts[0].toLowerCase() === libName.toLowerCase()) {
					parts = parts.slice(1);
				}
			}
			return parts.join('\\');
		}

		/**
		 * Build the file list HTML from _hampkgFiles, respecting the active category filter.
		 */
		function hampkgBuildFileList() {
			var $list = $("#hampkg-file-list");
			$list.empty();

			var activeCat = $(".hampkg-cat-btn.active").data("cat") || "all";

			// Compute destination directories for from/to display
			var libFolder = db_links.links.findOne({"_id":"lib-folder"});
			var metFolder = db_links.links.findOne({"_id":"met-folder"});
			var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
			var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
			var libName = $("#hampkg-lib-name").val().trim() || "LibraryName";
			var libDestDir = path.join(libBasePath, libName);
			var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);

			var visibleCount = 0;
			for (var i = 0; i < _hampkgFiles.length; i++) {
				var f = _hampkgFiles[i];

				// Filter by category
				if (activeCat !== "all") {
					var matchesCat = false;
					if (activeCat === 'library' && (f.pathCategory === 'library' && f.category.group !== 'help')) matchesCat = true;
					else if (activeCat === 'help' && f.category.group === 'help') matchesCat = true;
					else if (activeCat === 'labware' && f.pathCategory === 'labware') matchesCat = true;
					else if (activeCat === 'config' && (f.pathCategory === 'config' || f.pathCategory === 'system')) matchesCat = true;
					else if (activeCat === 'demo' && (f.pathCategory === 'methods' || f.category.group === 'demo')) matchesCat = true;
					if (!matchesCat) continue;
				}

				visibleCount++;
				var selectedClass = f.selected ? ' selected' : '';
				var checkIcon = f.selected ? 'fa-check-square' : 'fa-square';

				// Determine from (source) and to (destination) directories
				var fromDir = f.absPath ? path.dirname(f.absPath) : path.dirname(f.relPath);
				var relInstall = hampkgRelativeInstallPath(f, libName);
				var toDir;
				if (f.pathCategory === 'methods' || f.category.group === 'demo') {
					toDir = path.join(demoDestDir, path.dirname(relInstall));
				} else {
					toDir = path.join(libDestDir, path.dirname(relInstall));
				}
				// Clean up trailing separator from path.dirname when relInstall is just a filename
				if (toDir.endsWith('\\') || toDir.endsWith('/')) toDir = toDir.slice(0, -1);
				if (toDir.endsWith('.')) toDir = toDir.slice(0, -1);
				if (toDir.endsWith('\\') || toDir.endsWith('/')) toDir = toDir.slice(0, -1);

				var html = '<div class="hampkg-file-item' + selectedClass + '" data-idx="' + i + '">'
					+ '<span class="hampkg-file-check"><i class="far ' + checkIcon + '"></i></span>'
					+ '<span class="hampkg-file-icon"><i class="fas ' + escapeHtml(f.category.icon) + '"></i></span>'
					+ '<span class="hampkg-file-name">' + escapeHtml(f.fileName) + '</span>'
					+ '<span class="hampkg-file-cat">' + escapeHtml(f.category.label) + '</span>'
					+ '<span class="hampkg-file-size">' + formatFileSize(f.size) + '</span>'
					+ '<div class="hampkg-file-dirs">'
					+ '<span class="hampkg-file-from" title="' + escapeHtml(fromDir) + '"><i class="fas fa-sign-out-alt mr-1"></i>' + escapeHtml(fromDir) + '</span>'
					+ '<span class="hampkg-file-to" title="' + escapeHtml(toDir) + '"><i class="fas fa-sign-in-alt mr-1"></i>' + escapeHtml(toDir) + '</span>'
					+ '</div>'
					+ '</div>';
				$list.append(html);
			}

			if (visibleCount === 0) {
				$list.append('<div class="text-center text-muted py-4"><i class="fas fa-inbox mr-2"></i>No files in this category</div>');
			}

			// Update category counts in button labels
			var counts = { all: _hampkgFiles.length, library: 0, help: 0, labware: 0, config: 0, demo: 0 };
			for (var j = 0; j < _hampkgFiles.length; j++) {
				var fc = _hampkgFiles[j];
				if (fc.pathCategory === 'library' && fc.category.group !== 'help') counts.library++;
				if (fc.category.group === 'help') counts.help++;
				if (fc.pathCategory === 'labware') counts.labware++;
				if (fc.pathCategory === 'config' || fc.pathCategory === 'system') counts.config++;
				if (fc.pathCategory === 'methods' || fc.category.group === 'demo') counts.demo++;
			}

			hampkgUpdateSelectionCount();
		}

		/**
		 * Update the selection count text and import button state.
		 */
		function hampkgUpdateSelectionCount() {
			var selectedCount = 0;
			for (var i = 0; i < _hampkgFiles.length; i++) {
				if (_hampkgFiles[i].selected) selectedCount++;
			}
			$(".hampkg-selected-count").text(selectedCount + " of " + _hampkgFiles.length + " files selected");

			// Enable import button only if at least one file is selected and required fields are filled
			hampkgValidateForm();
		}

		/**
		 * Validate the import form and enable/disable the import button.
		 */
		function hampkgValidateForm() {
			var selectedCount = 0;
			for (var i = 0; i < _hampkgFiles.length; i++) {
				if (_hampkgFiles[i].selected) selectedCount++;
			}

			var libName = $("#hampkg-lib-name").val().trim();
			var author = $("#hampkg-lib-author").val().trim();
			var version = $("#hampkg-lib-version").val().trim();
			var venus = $("#hampkg-lib-venus").val().trim();
			var desc = $("#hampkg-lib-desc").val().trim();

			var valid = selectedCount > 0 && libName.length > 0 && author.length >= 3 && version.length > 0 && venus.length > 0 && desc.length > 0;
			$(".hampkg-btn-import").prop("disabled", !valid);
		}

		/**
		 * Update the file summary panels showing which files will go where.
		 */
		function hampkgUpdateSummary() {
			var libFiles = [];
			var helpFiles = [];
			var demoFiles = [];
			var otherFiles = [];

			for (var i = 0; i < _hampkgFiles.length; i++) {
				var f = _hampkgFiles[i];
				if (!f.selected) continue;

				if (f.category.group === 'help') {
					helpFiles.push(f);
				} else if (f.pathCategory === 'methods' || f.category.group === 'demo') {
					demoFiles.push(f);
				} else if (f.pathCategory === 'labware' || f.pathCategory === 'config' || f.pathCategory === 'system') {
					otherFiles.push(f);
				} else {
					libFiles.push(f);
				}
			}

			// Library files
			var $libList = $(".hampkg-summary-lib-files");
			$libList.empty();
			if (libFiles.length === 0) {
				$libList.html('<div class="text-muted text-center py-2" style="font-size:0.78rem;">No library files selected</div>');
			} else {
				for (var li = 0; li < libFiles.length; li++) {
					$libList.append('<div class="pkg-file-item"><i class="fas ' + escapeHtml(libFiles[li].category.icon) + ' mr-2" style="color:var(--medium);"></i>' + escapeHtml(libFiles[li].fileName) + '</div>');
				}
			}

			// Help files
			var $helpList = $(".hampkg-summary-help-files");
			$helpList.empty();
			if (helpFiles.length === 0) {
				$helpList.html('<div class="text-muted text-center py-2" style="font-size:0.78rem;">No help files selected</div>');
			} else {
				for (var hi = 0; hi < helpFiles.length; hi++) {
					$helpList.append('<div class="pkg-file-item"><i class="fas fa-question-circle mr-2" style="color:var(--medium);"></i>' + escapeHtml(helpFiles[hi].fileName) + '</div>');
				}
			}

			// Demo files
			var $demoList = $(".hampkg-summary-demo-files");
			$demoList.empty();
			if (demoFiles.length > 0) {
				$(".hampkg-demo-section").removeClass("d-none");
				for (var di = 0; di < demoFiles.length; di++) {
					$demoList.append('<div class="pkg-file-item"><i class="fas fa-project-diagram mr-2" style="color:var(--medium);"></i>' + escapeHtml(demoFiles[di].fileName) + '</div>');
				}
			} else {
				$(".hampkg-demo-section").addClass("d-none");
			}

			// Labware/Config/Other files
			var $otherList = $(".hampkg-summary-other-files");
			$otherList.empty();
			if (otherFiles.length > 0) {
				$(".hampkg-labware-section").removeClass("d-none");
				for (var oi = 0; oi < otherFiles.length; oi++) {
					$otherList.append('<div class="pkg-file-item"><i class="fas ' + escapeHtml(otherFiles[oi].category.icon) + ' mr-2" style="color:var(--medium);"></i>' + escapeHtml(otherFiles[oi].fileName) + '</div>');
				}
			} else {
				$(".hampkg-labware-section").addClass("d-none");
			}
		}

		/**
		 * Update the install path preview based on library name and root-install checkbox.
		 */
		function hampkgUpdateInstallPath() {
			var libFolder = db_links.links.findOne({"_id":"lib-folder"});
			var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
			var libName = $("#hampkg-lib-name").val().trim() || "LibraryName";
			var destPath = path.join(libBasePath, libName);
			$(".hampkg-install-path").text(destPath);
		}

		// ---- Overflow menu: Import HamPkg ----
		$(document).on("click", ".overflow-import-hampkg", function(e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			hampkgReset();
			$("#importHamPkgModal").modal("show");
			return false;
		});

		// ---- Drop zone click -> trigger file input ----
		$(document).on("click", "#hampkg-drop-zone", function() {
			$("#hampkg-input-file").trigger("click");
		});

		// ---- Drop zone drag and drop ----
		$(document).on("dragover", "#hampkg-drop-zone", function(e) {
			e.preventDefault();
			e.stopPropagation();
			$(this).addClass("drag-over");
		});
		$(document).on("dragleave", "#hampkg-drop-zone", function(e) {
			e.preventDefault();
			e.stopPropagation();
			$(this).removeClass("drag-over");
		});
		$(document).on("drop", "#hampkg-drop-zone", function(e) {
			e.preventDefault();
			e.stopPropagation();
			$(this).removeClass("drag-over");
			var files = e.originalEvent.dataTransfer.files;
			if (files && files.length > 0) {
				var droppedPath = files[0].path;
				var droppedExt = path.extname(droppedPath).toLowerCase();
				if (droppedExt === '.pkg' || droppedExt === '.hampackage') {
					hampkgLoadFile(droppedPath);
				} else {
					alert("Please drop a Hamilton VENUS .pkg or .hamPackage file.");
				}
			}
		});

		// ---- File input change ----
		$(document).on("change", "#hampkg-input-file", function() {
			var fileInput = this;
			var filePath = "";
			if (fileInput.files && fileInput.files.length > 0) {
				filePath = fileInput.files[0].path;
			}
			$(this).val('');
			if (!filePath) return;
			hampkgLoadFile(filePath);
		});

		// ---- Back button ----
		$(document).on("click", ".hampkg-btn-back", function() {
			hampkgReset();
		});

		// ---- Category filter tabs ----
		$(document).on("click", ".hampkg-cat-btn", function() {
			$(".hampkg-cat-btn").removeClass("active");
			$(this).addClass("active");
			hampkgBuildFileList();
		});

		// ---- File item click (toggle selection, shift-click for range) ----
		$(document).on("click", ".hampkg-file-item", function(e) {
			var idx = parseInt($(this).data("idx"), 10);
			if (isNaN(idx) || idx < 0 || idx >= _hampkgFiles.length) return;

			if (e.shiftKey && _hampkgLastClickedIdx >= 0 && _hampkgLastClickedIdx !== idx) {
				// Shift-click: select/deselect all files between last clicked and current
				var start = Math.min(_hampkgLastClickedIdx, idx);
				var end = Math.max(_hampkgLastClickedIdx, idx);
				// Determine target state from the anchor item
				var targetState = _hampkgFiles[_hampkgLastClickedIdx].selected;
				// Build set of currently visible indices (respecting category filter)
				var activeCat = $(".hampkg-cat-btn.active").data("cat") || "all";
				var visibleIndices = [];
				for (var vi = 0; vi < _hampkgFiles.length; vi++) {
					var vf = _hampkgFiles[vi];
					if (activeCat === "all") {
						visibleIndices.push(vi);
					} else {
						var vm = false;
						if (activeCat === 'library' && vf.pathCategory === 'library' && vf.category.group !== 'help') vm = true;
						else if (activeCat === 'help' && vf.category.group === 'help') vm = true;
						else if (activeCat === 'labware' && vf.pathCategory === 'labware') vm = true;
						else if (activeCat === 'config' && (vf.pathCategory === 'config' || vf.pathCategory === 'system')) vm = true;
						else if (activeCat === 'demo' && (vf.pathCategory === 'methods' || vf.category.group === 'demo')) vm = true;
						if (vm) visibleIndices.push(vi);
					}
				}
				// Apply target state to all visible files in the range
				for (var ri = 0; ri < visibleIndices.length; ri++) {
					var rIdx = visibleIndices[ri];
					if (rIdx >= start && rIdx <= end) {
						_hampkgFiles[rIdx].selected = targetState;
					}
				}
			} else {
				// Normal click: toggle single file
				_hampkgFiles[idx].selected = !_hampkgFiles[idx].selected;
			}

			_hampkgLastClickedIdx = idx;
			hampkgBuildFileList();
			hampkgUpdateSummary();
			hampkgUpdateInstallPath();
		});

		// ---- Select All / None ----
		$(document).on("click", ".hampkg-select-all", function() {
			var activeCat = $(".hampkg-cat-btn.active").data("cat") || "all";
			for (var i = 0; i < _hampkgFiles.length; i++) {
				var f = _hampkgFiles[i];
				if (activeCat === "all") {
					f.selected = true;
				} else {
					var matches = false;
					if (activeCat === 'library' && f.pathCategory === 'library' && f.category.group !== 'help') matches = true;
					else if (activeCat === 'help' && f.category.group === 'help') matches = true;
					else if (activeCat === 'labware' && f.pathCategory === 'labware') matches = true;
					else if (activeCat === 'config' && (f.pathCategory === 'config' || f.pathCategory === 'system')) matches = true;
					else if (activeCat === 'demo' && (f.pathCategory === 'methods' || f.category.group === 'demo')) matches = true;
					if (matches) f.selected = true;
				}
			}
			hampkgBuildFileList();
			hampkgUpdateSummary();
			hampkgUpdateInstallPath();
		});

		$(document).on("click", ".hampkg-select-none", function() {
			for (var i = 0; i < _hampkgFiles.length; i++) {
				_hampkgFiles[i].selected = false;
			}
			hampkgBuildFileList();
			hampkgUpdateSummary();
			hampkgUpdateInstallPath();
		});

		// ---- Form field changes -> revalidate and update ----
		$(document).on("input", "#hampkg-lib-name, #hampkg-lib-author, #hampkg-lib-version, #hampkg-lib-venus, #hampkg-lib-desc", function() {
			hampkgValidateForm();
			hampkgUpdateInstallPath();
		});


		// ---- Modal reset on close ----
		$(document).on("hidden.bs.modal", "#importHamPkgModal", function() {
			hampkgReset();
		});

		// ---- IMPORT BUTTON: Install selected files as a library ----
		$(document).on("click", ".hampkg-btn-import", async function() {
			var $btn = $(this);
			if ($btn.prop("disabled")) return;
			$btn.prop("disabled", true);

			// ---- Access control check ----
			var accessCheck = canManageLibraries();
			if (!accessCheck.allowed) {
				showAccessDeniedModal('Import HamPkg', accessCheck.reason);
				$btn.prop("disabled", false);
				return;
			}

			try {
				var libName = $("#hampkg-lib-name").val().trim();
				var author = $("#hampkg-lib-author").val().trim();
				var organization = $("#hampkg-lib-org").val().trim();
				var version = $("#hampkg-lib-version").val().trim();
				var venusCompat = $("#hampkg-lib-venus").val().trim();
				var description = $("#hampkg-lib-desc").val().trim();
				var tagsRaw = $("#hampkg-lib-tags").val().trim();
				var installToRoot = false;

				// Validate required fields
				if (!libName) { alert("Library name is required."); $btn.prop("disabled", false); return; }
				if (!isValidLibraryName(libName)) { alert("Invalid library name. Use letters, numbers, spaces, hyphens, and underscores only."); $btn.prop("disabled", false); return; }
				if (author.length < shared.AUTHOR_MIN_LENGTH) { alert("Author must be at least " + shared.AUTHOR_MIN_LENGTH + " characters."); $btn.prop("disabled", false); return; }
				if (author.length > shared.AUTHOR_MAX_LENGTH) { alert("Author must be at most " + shared.AUTHOR_MAX_LENGTH + " characters."); $btn.prop("disabled", false); return; }

				// Parse tags
				var tags = [];
				if (tagsRaw) {
					tagsRaw.split(",").forEach(function(t) {
						var s = shared.sanitizeTag(t);
						if (s) tags.push(s);
					});
				}
				var tagCheck = shared.filterReservedTags(tags);
				tags = tagCheck.filtered;

				// Collect selected files, categorized
				var selectedLibFiles = [];
				var selectedHelpFiles = [];
				var selectedDemoFiles = [];
				var selectedOtherFiles = [];

				for (var i = 0; i < _hampkgFiles.length; i++) {
					var f = _hampkgFiles[i];
					if (!f.selected) continue;

					if (f.category.group === 'help') {
						selectedHelpFiles.push(f);
					} else if (f.pathCategory === 'methods' || f.category.group === 'demo') {
						selectedDemoFiles.push(f);
					} else if (f.pathCategory === 'labware' || f.pathCategory === 'config' || f.pathCategory === 'system') {
						selectedOtherFiles.push(f);
					} else {
						selectedLibFiles.push(f);
					}
				}

				if (selectedLibFiles.length === 0 && selectedHelpFiles.length === 0 && selectedDemoFiles.length === 0 && selectedOtherFiles.length === 0) {
					alert("No files selected for import.");
					$btn.prop("disabled", false);
					return;
				}

				// Determine install paths
				var libFolder = db_links.links.findOne({"_id":"lib-folder"});
				var metFolder = db_links.links.findOne({"_id":"met-folder"});
				var libBasePath = libFolder ? libFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Library";
				var metBasePath = metFolder ? metFolder.path : "C:\\Program Files (x86)\\HAMILTON\\Methods";
				var libDestDir = installToRoot ? libBasePath : path.join(libBasePath, libName);
				var demoDestDir = path.join(metBasePath, "Library Demo Methods", libName);

				// Check if library already exists
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					var existingVer = existing.version || '?';
					var isSameVersion = (existingVer !== '?' && version && existingVer === version);
					var overwriteMsg;
					if (isSameVersion) {
						overwriteMsg = 'A library named "' + libName + '" with the same version (v' + existingVer + ') is already installed.\n\nDo you want to replace it?';
					} else {
						overwriteMsg = 'A library named "' + libName + '" is already installed (v' + existingVer + ').\n\nDo you want to replace it with ' + (version ? 'v' + version : 'the imported version') + '?';
					}
					if (!confirm(overwriteMsg)) {
						$btn.prop("disabled", false);
						return;
					}
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				// Create directories
				if (selectedLibFiles.length > 0 || selectedHelpFiles.length > 0 || selectedOtherFiles.length > 0) {
					if (!fs.existsSync(libDestDir)) {
						fs.mkdirSync(libDestDir, { recursive: true });
					}
				}
				if (selectedDemoFiles.length > 0) {
					if (!fs.existsSync(demoDestDir)) {
						fs.mkdirSync(demoDestDir, { recursive: true });
					}
				}

				var extractedCount = 0;
				var libFileNames = [];
				var helpFileNames = [];
				var demoFileNames = [];

				// Extract library files (including other/labware/config - preserve subdirectory structure)
				var allLibEntries = selectedLibFiles.concat(selectedHelpFiles).concat(selectedOtherFiles);
				for (var li = 0; li < allLibEntries.length; li++) {
					var lf = allLibEntries[li];
					var relInstallPath = hampkgRelativeInstallPath(lf, libName);
					var outPath = path.join(libDestDir, relInstallPath);
					var parentDir = path.dirname(outPath);
					if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
					fs.writeFileSync(outPath, lf.data);
					extractedCount++;

					if (lf.category.group === 'help') {
						helpFileNames.push(relInstallPath);
					} else {
						libFileNames.push(relInstallPath);
					}
				}

				// Extract demo files (preserve subdirectory structure)
				for (var di = 0; di < selectedDemoFiles.length; di++) {
					var df = selectedDemoFiles[di];
					var demoRelPath = hampkgRelativeInstallPath(df, libName);
					var demoOutPath = path.join(demoDestDir, demoRelPath);
					var demoParentDir = path.dirname(demoOutPath);
					if (!fs.existsSync(demoParentDir)) fs.mkdirSync(demoParentDir, { recursive: true });
					fs.writeFileSync(demoOutPath, df.data);
					extractedCount++;
					demoFileNames.push(demoRelPath);
				}

				// Compute integrity hashes
				var fileHashes = {};
				try {
					fileHashes = computeLibraryHashes(libFileNames, libDestDir, []);
				} catch (e) {
					console.warn('Could not compute integrity hashes: ' + e.message);
				}

				// Build DB record
				var dbRecord = {
					library_name: libName,
					author: author,
					organization: organization,
					installed_by: getWindowsUsername(),
					version: version,
					venus_compatibility: venusCompat,
					description: description,
					github_url: "",
					tags: tags,
					created_date: new Date().toISOString(),
					app_version: shared.getAppVersion(),
					format_version: shared.FORMAT_VERSION,
					windows_version: shared.getWindowsVersion(),
					venus_version: _cachedVENUSVersion || '',
					package_lineage: [{
						event: 'imported_from_hampkg',
						timestamp: new Date().toISOString(),
						source_file: path.basename(_hampkgFilePath),
						venus_version: _hampkgPkgInfo ? _hampkgPkgInfo.venusVersion : '',
						pkg_author: _hampkgPkgInfo && _hampkgPkgInfo.trailer ? _hampkgPkgInfo.trailer.author : '',
						files_selected: extractedCount,
						files_total: _hampkgFiles.length
					}],
					library_image: null,
					library_image_base64: null,
					library_image_mime: null,
					library_files: libFileNames,
					demo_method_files: demoFileNames,
					help_files: helpFileNames,
					com_register_dlls: [],
					com_warning: false,
					com_registered: false,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: path.basename(_hampkgFilePath),
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFileNames, libDestDir),
					required_dependencies: extractRequiredDependencies(libFileNames, libDestDir),
					publisher_cert: null
				};

				// Auto-detect a BMP icon from extracted library files
				for (var bi = 0; bi < selectedLibFiles.length; bi++) {
					var bf = selectedLibFiles[bi];
					if (bf.extension === 'bmp' || bf.extension === 'png') {
						var iconBaseName = path.basename(bf.fileName, path.extname(bf.fileName)).toLowerCase();
						var libBaseName = libName.toLowerCase();
						if (iconBaseName === libBaseName || selectedLibFiles.length === 1) {
							try {
								dbRecord.library_image = bf.fileName;
								dbRecord.library_image_base64 = bf.data.toString('base64');
								dbRecord.library_image_mime = bf.extension === 'png' ? 'image/png' : 'image/bmp';
							} catch(_) {}
							break;
						}
					}
				}

				var saved = db_installed_libs.installed_libs.save(dbRecord);

				// Write .libmgr marker file
				try { shared.updateMarkerForLibrary(dbRecord); } catch(_) { /* non-critical */ }

				// Update publisher registry
				registerPublisher(author);
				registerPublisher(organization);
				registerTags(tags);

				// Auto-assign to group
				var savedAuthor = author;
				var savedOrg = organization;
				if (isRestrictedAuthor(savedAuthor) || isRestrictedAuthor(savedOrg)) {
					addToOemTreeGroup(saved._id);
				} else {
					var navtree = db_tree.tree.find();
					var targetGroupId = null;
					for (var ti = 0; ti < navtree.length; ti++) {
						var gEntry = getGroupById(navtree[ti]["group-id"]);
						if (gEntry && !gEntry["default"]) {
							targetGroupId = navtree[ti]["group-id"];
							var existingIds = (navtree[ti]["method-ids"] || []).slice();
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

				// Close modal and refresh
				$("#importHamPkgModal").modal("hide");
				impBuildLibraryCards();

				// Show success via the existing import success modal
				var $sm = $("#importSuccessModal");
				$sm.find(".import-success-libname").text(libName);
				$sm.find(".import-success-filecount").text(extractedCount + " file" + (extractedCount !== 1 ? "s" : "") + " installed from package");

				var pathsHtml = "";
				if (libFileNames.length > 0 || helpFileNames.length > 0) {
					pathsHtml += '<div class="path-label">Library Files</div>';
					pathsHtml += '<div class="path-value">' + escapeHtml(libDestDir) + '</div>';
				}
				if (demoFileNames.length > 0) {
					pathsHtml += '<div class="path-label">Demo Methods</div>';
					pathsHtml += '<div class="path-value">' + escapeHtml(demoDestDir) + '</div>';
				}
				$sm.find(".import-success-paths").html(pathsHtml);
				if (!pathsHtml) $sm.find(".import-success-paths").addClass("d-none"); else $sm.find(".import-success-paths").removeClass("d-none");
				$sm.find(".import-success-com-status").addClass("d-none");
				$sm.modal("show");

				// Audit trail entry
				try {
					appendAuditTrailEntry(buildAuditTrailEntry('hampkg_imported', {
						library_name:     libName,
						version:          version,
						author:           author,
						organization:     organization,
						source_file:      _hampkgFilePath,
						lib_install_path: libDestDir,
						demo_install_path: demoDestDir,
						files_extracted:  extractedCount,
						total_pkg_files:  _hampkgFiles.length,
						venus_pkg_version: _hampkgPkgInfo ? _hampkgPkgInfo.venusVersion : ''
					}));
				} catch(_) { /* non-critical */ }

			} catch (e) {
				alert("Error importing package:\n" + e.message);
			} finally {
				$btn.prop("disabled", false);
			}
		});

        //**************************************************************************************
        //******  FUNCTION DECLARATIONS END ****************************************************
        //**************************************************************************************
		


		