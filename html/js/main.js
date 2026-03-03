
		// main.js v1.4.8
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
		// image-size removed — no longer used
		const os = require("os");
		const crypto = require('crypto');
		const shared = require('../lib/shared');

		/** Shared MIME type lookup for image file extensions */
		var IMAGE_MIME_MAP = {
			'png':'image/png', 'jpg':'image/jpeg', 'jpeg':'image/jpeg',
			'bmp':'image/bmp', 'gif':'image/gif', 'ico':'image/x-icon', 'svg':'image/svg+xml',
			// keyed with leading dot for convenience (used by some callers)
			'.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
			'.bmp':'image/bmp', '.gif':'image/gif', '.ico':'image/x-icon', '.svg':'image/svg+xml'
		};

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
			} catch(e) {}

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
			} catch(e) {}
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
						var subkeysRaw = execSync('reg query "' + regPaths[rp] + '"', { encoding: 'utf8', timeout: 10000 });
						var subkeys = subkeysRaw.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });

						for (var sk = 0; sk < subkeys.length; sk++) {
							try {
								var entryRaw = execSync('reg query "' + subkeys[sk] + '" /v DisplayName', { encoding: 'utf8', timeout: 5000 });
								if (!/Hamilton\s+VENUS\s+\d/i.test(entryRaw)) continue;

								// Found the Hamilton VENUS entry - read all values
								var allVals = execSync('reg query "' + subkeys[sk] + '"', { encoding: 'utf8', timeout: 5000 });

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
		 * Get a concise Windows version string (e.g. "Windows_NT 10.0.19045 (x64)").
		 */
		function getWindowsVersion() {
			try {
				return os.type() + ' ' + os.release() + ' (' + os.arch() + ')';
			} catch(_) {
				return 'Unknown';
			}
		}

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
				windows_version:  getWindowsVersion(),
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
		//     settings.json        – application settings (singleton record)
		//     installed_libs.json  – installed library registry
		//     groups.json          – custom user groups
		//     tree.json            – group→library membership tree
		//     links.json           – VENUS tool shortcuts & folder paths
		//     unsigned_libs.json   – scanned unsigned libraries
		//     publisher_registry.json – publisher/tag autocomplete data
		//     audit_trail.json     – append-only event audit log
		//     packages/            – cached .hxlibpkg backups for rollback & repair
		//     exports/             – default export output directory
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
		var LEGACY_APP_LOCAL_DIR = path.join(APP_ROOT, 'local');

		/** Ensure the local data directory and all subdirectories exist with seed files */
		function ensureLocalDataDir(dirPath) {
			if (!fs.existsSync(dirPath)) {
				fs.mkdirSync(dirPath, { recursive: true });
			}
			// Ensure subdirectories
			var subDirs = ['packages', 'exports'];
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
							} catch(_) {}
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
				var author = (lib.author || '').trim();
				if (author) seenPublishers[author.toLowerCase()] = author;
				var org = (lib.organization || '').trim();
				if (org && org.toLowerCase() !== author.toLowerCase()) seenPublishers[org.toLowerCase()] = org;
				(lib.tags || []).forEach(function(t) {
					var s = shared.sanitizeTag(t);
					if (s) seenTags[s] = true;
				});
			});

			// Scan system libraries
			var sysLibs = getAllSystemLibraries();
			sysLibs.forEach(function(sLib) {
				var author = (sLib.author || '').trim();
				if (author) seenPublishers[author.toLowerCase()] = author;
				var org = (sLib.organization || '').trim();
				if (org && org.toLowerCase() !== author.toLowerCase()) seenPublishers[org.toLowerCase()] = org;
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
		//
		// The password is stored as a SHA-256 hash to avoid exposing the plaintext
		// in source control.  Comparison uses crypto.timingSafeEqual to resist
		// timing side-channel analysis.
		var HAMILTON_AUTHOR_PASSWORD_HASH = 'bbdc525497de1c19c57767e36b4f01dadcc05348664eea071ac984fd955bc207';

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
		 * Uses SHA-256 hashing and timing-safe comparison.
		 * @param {string} password
		 * @returns {boolean}
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

				// Add help files (CHMs) - packed into help_files/ folder
				helpFiles.forEach(function(f) {
					var fullPath = path.join(sysLibDir, f);
					if (fs.existsSync(fullPath)) {
						zip.addLocalFile(fullPath, "help_files");
					}
				});

				// Sign the package
				signPackageZip(zip);

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

        //Window load - race-safe: handles case where native load event fires
		//before jQuery can bind its handler (script parse time > resource load time)
		(function _windowLoadInit() {
			function _onWindowLoad() {
				// Track when splash animation and init are both done
				var _splashAnimDone = false;
				var _splashInitDone = false;
				var _splashStartTime = Date.now();
				var SPLASH_ANIM_MS = 2300; // match SVG animation duration (~2273ms) + small buffer

				function dismissSplashIfReady() {
					if (!_splashAnimDone || !_splashInitDone) return;
					// Restore scrolling now that splash is leaving
					document.documentElement.style.overflow = '';
					document.body.style.overflow = '';
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
			

			if(file_type=="method"){
				var args = [file_path];
				if($("#chk_run-autoclose").prop("checked")){ args.push("-t"); } //Run method immediately and terminate when method is complete.
				else if($("#chk_run-autoplay").prop("checked")){ args.push("-r"); } //Run method immediately.
    
				 var child =  spawn(HxRun, args, { detached: true, stdio: [ 'ignore', 'ignore', 'ignore' ] });
				 child.unref();
			}
			if(file_type=="folder"){
				safeOpenItem(file_path);
				// nw.Shell.showItemInFolder(file_path);

			}
			if(file_type=="file"){
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
			// console.log("Open in Method Editor " + file_path)
			if(file_path!=""){
				file_path = file_path.substr(0, file_path.lastIndexOf(".")) + ".med";
				safeOpenItem(file_path);
			}	
		});

		//Open Method Location link card in the main div
		$(document).on("click", ".link-OpenMethLocation", function () {
			
			var file_path = path.dirname($(this).closest(".link-card-container").attr("data-filepath"));
			// console.log("Open Location " + file_path);
			if(file_path!=""){
				safeOpenItem(file_path);
			}	
		});

		




		//Click "help" from overflow menu.
		$(document).on("click", ".overflow-help", function () {
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			var chmPath = path.join(path.dirname(process.execPath), 'Library Manager for Venus 6.chm');
			if (fs.existsSync(chmPath)) {
				nw.Shell.openItem(chmPath);
			} else {
				alert('Help file not found: ' + chmPath);
			}
		});

		//Click "About" from overflow menu.
		$(document).on("click", ".overflow-about", function (e) {
			e.preventDefault();
			$(".btn-overflow-menu .dropdown-menu").removeClass("show");
			$(".btn-overflow-toggle").attr("aria-expanded", "false");
			// Populate version from package.json
			try {
				var pkgPath = path.join(path.dirname(process.execPath), 'package.json');
				var pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
				$(".about-version").text("Version " + pkgData.version);
			} catch (ex) {
				$(".about-version").text("");
			}
			$("#aboutModal").modal("show");
		});

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
			if (raw.indexOf('#') === -1 || raw.search(/\s/) === -1) return;
			var pending = raw;
			var consumedAny = false;

			while (true) {
				var match = pending.match(/(^|\s)#([^\s#]+)(?=\s)/);
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
			var match = raw.match(/(^|\s)#([^\s#]+)\s*$/);
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
				rawInput.split(/\s+/).forEach(function(token) {
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
				rawInput.split(/\s+/).forEach(function(ri) {
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
			var tagMatch = raw.match(/(^|.*\s)#([^\s#]*)$/);
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
				var tagMatch = raw.match(/^(.*?)(?:^|\s)#[^\s#]*$/);
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
			var isAuthorChip = $(this).closest('.imp-search-chip').attr('data-chip-type') === 'author';
			if (e.key === 'Enter' || e.key === 'Tab' || (!isAuthorChip && e.key === ' ')) {
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

			function matchesTagFilters(tags) {
				if (!hasTagFilters) return true;
				var normalizedTags = (tags || []).map(function(t) { return (t || '').toLowerCase(); });
				return tagFilters.every(function(filterTag) {
					return normalizedTags.some(function(tag) { return tag.indexOf(filterTag) !== -1; });
				});
			}

			function matchesAuthorFilters(author, organization) {
				if (!hasAuthorFilters) return true;
				var a = (author || '').toLowerCase();
				var o = (organization || '').toLowerCase();
				return authorFilters.every(function(filter) {
					return a.indexOf(filter) !== -1 || o.indexOf(filter) !== -1;
				});
			}

			// User library cards
			userLibs.forEach(function(lib) {
				if (!matchesTagFilters(lib.tags || [])) return;
				if (!matchesAuthorFilters(lib.author, lib.organization)) return;
				if (hasTextQuery) {
					var fnNames = (lib.public_functions || []).map(function(fn) { return fn.qualifiedName || fn.name || ''; }).join(' ');
					var searchText = ((lib.library_name || '') + ' ' + (lib.author || '') + ' ' + (lib.description || '') + ' ' + (lib.tags || []).join(' ') + ' ' + fnNames).toLowerCase();
					if (searchText.indexOf(textQuery) === -1) return;
				}
				allCards.push({ type: 'user', html: impBuildSingleCardHtml(lib) });
			});

			// System library cards - include public function names in search
			// System libs carry a virtual "system" tag so #system matches them.
			var fnCache = hasTextQuery ? _buildSysLibFnCache() : null;
			sysLibs.forEach(function(sLib) {
				if (!matchesTagFilters(['system'])) return;
				if (!matchesAuthorFilters(sLib.author, sLib.organization)) return;
				if (hasTextQuery) {
					var fnNames = fnCache[sLib._id] || '';
					var searchText = ((sLib.display_name || sLib.canonical_name || '') + ' ' + (sLib.author || '') + ' ' + (sLib.resource_types || []).join(' ') + ' ' + fnNames).toLowerCase();
					if (searchText.indexOf(textQuery) === -1) return;
				}
				allCards.push({ type: 'system', html: buildSystemLibraryCard(sLib) });
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
			var hasChmHelp = helpFiles.some(function(f) { return path.extname(f).toLowerCase() === '.chm'; });

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
						(hasChmHelp ? '<a href="#" class="text-sm imp-lib-card-help-link" style="color:var(--medium);" data-lib-id="' + lib._id + '">Help</a>' : '<span></span>') +
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
			} catch(ex) {}
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
					$("#chk_scanUnsignedOnLaunch").prop("checked", false).prop("disabled", true);
					saveSetting("chk_scanUnsignedOnLaunch", false);
					$(".unsigned-scan-status").text("");
					$(".unsigned-scan-spinner").hide();
					$(".unsigned-scan-done").hide();
					$(".unsigned-regulated-status").html('<i class="fas fa-lock mr-1 text-warning"></i>Unsigned libraries cannot be enabled in regulated environment mode. All packages must be signed.');
					// Force-disable GitHub links
					$("#chk_showGitHubLinks").prop("checked", false).prop("disabled", true);
					saveSetting("chk_showGitHubLinks", false);
					$(".github-links-regulated-status").html('<i class="fas fa-lock mr-1 text-warning"></i>GitHub links cannot be enabled in regulated environment mode.');
					invalidateNavBar();
					console.log('Unsigned libraries and GitHub links disabled: regulated mode requires all packages to be signed.');
				} else {
					$("#chk_includeUnsignedLibs").prop("disabled", false);
					$(".unsigned-regulated-status").html('');
					// Re-enable GitHub links toggle
					$("#chk_showGitHubLinks").prop("disabled", false);
					$(".github-links-regulated-status").html('');
				}
			});
		});

		//Settings > Unsigned Libraries checkbox
		$(document).on("click", "#chk_includeUnsignedLibs", function(e){
			// In regulated mode, unsigned files cannot be enabled
			var regulatedMode = false;
			try {
				var s = db_settings.settings.findOne({"_id":"0"});
				regulatedMode = !!(s && s.chk_regulatedEnvironment);
			} catch(ex) {}
			if (regulatedMode) {
				e.preventDefault();
				$(this).prop("checked", false);
				alert('Unsigned libraries cannot be enabled in regulated environment mode.\n\nAll packages must be signed when regulated environment mode is active. Disable regulated environment mode first to enable unsigned library scanning.');
				return;
			}
			var checked = $(this).prop("checked");
			saveSetting("chk_includeUnsignedLibs", checked);
			$("#btn-scan-unsigned-libs").prop("disabled", !checked);
			$("#chk_scanUnsignedOnLaunch").prop("disabled", !checked);
			if (!checked) {
				$(".unsigned-scan-status").text("");
				$(".unsigned-scan-spinner").hide();
				$(".unsigned-scan-done").hide();
				$("#chk_scanUnsignedOnLaunch").prop("checked", false);
				saveSetting("chk_scanUnsignedOnLaunch", false);
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

		//Settings > Unsigned Libraries - Scan on launch checkbox
		$(document).on("click", "#chk_scanUnsignedOnLaunch", function(){
			var checked = $(this).prop("checked");
			saveSetting("chk_scanUnsignedOnLaunch", checked);
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
				require('child_process').exec('explorer "' + LOCAL_DATA_DIR + '"');
			} catch(e) {
				console.warn('Could not open local data directory: ' + e.message);
			}
		});

		// ---- Dark Mode / Night Mode ----
		/** Apply or remove dark mode from the document body */
		function applyDarkMode(enabled) {
			if (enabled) {
				$("body").addClass("dark-mode");
				$(".dark-mode-label").text("Day Mode");
			} else {
				$("body").removeClass("dark-mode");
				$(".dark-mode-label").text("Night Mode");
			}
		}

		/** Show or hide the manual dark-mode controls based on system-theme setting */
		function applySystemThemeVisibility(useSystem) {
			if (useSystem) {
				$(".btn-dark-mode-toggle").hide();
				$(".chk-darkMode-wrap").hide();
			} else {
				$(".btn-dark-mode-toggle").show();
				$(".chk-darkMode-wrap").show();
			}
		}

		/** Follow the OS dark/light preference */
		function applySystemTheme() {
			if (window.matchMedia) {
				var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
				applyDarkMode(prefersDark);
				$("#chk_darkMode").prop("checked", prefersDark);
			}
		}

		// Listen for OS theme changes while the app is running
		if (window.matchMedia) {
			window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function(e) {
				if ($("#chk_useSystemTheme").is(":checked")) {
					applyDarkMode(e.matches);
					$("#chk_darkMode").prop("checked", e.matches);
				}
			});
		}

		// Settings checkbox toggle – use system theme
		$(document).on("change", "#chk_useSystemTheme", function() {
			var useSystem = $(this).is(":checked");
			saveSetting("chk_useSystemTheme", useSystem);
			applySystemThemeVisibility(useSystem);
			if (useSystem) {
				applySystemTheme();
			}
		});

		// Overflow menu toggle (moon/sun icon)
		$(document).on("click", ".btn-dark-mode-toggle", function(e) {
			e.preventDefault();
			var isNowDark = !$("body").hasClass("dark-mode");
			applyDarkMode(isNowDark);
			$("#chk_darkMode").prop("checked", isNowDark);
			saveSetting("chk_darkMode", isNowDark);
		});

		// Settings checkbox toggle
		$(document).on("change", "#chk_darkMode", function() {
			var isNowDark = $(this).is(":checked");
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
				// Check reserved group names
				if ($("#editModal .modal-content").attr("data-linkOrGroup") === "group") {
					var groupName = $.trim($('#editModal .txt-linkName').val());
					if (shared.isReservedGroupName(groupName)) {
						alert('The group name "' + groupName + '" is reserved and cannot be used. Please choose a different name.');
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

					// Skip Export, History, Hamilton, Starred, and Import from normal nav rendering
					// These nav items are injected separately after the loop
					var skipNavItem = (group_id === "gEditors" || group_id === "gHistory" || group_id === "gHamilton" || group_id === "gFolders" || group_id === "gStarred");

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
					// Hamilton/protected groups are always visible but without edit/delete
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

							var libItemStr = '<div class="settings-links-method w-100 pt-2" data-id="'+lib._id+'">' +
								libIcon +
								'<div class="d-inline-block pb-2 link-namepath">' +
									'<div class="name">' + libName + libVersion + '</div>' +
									'<div class="path">' + (libAuthor ? libAuthor : '') + '</div>' +
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

			// ---- HARDCODED NAV ORDER ENFORCEMENT ----
			// All is ALWAYS the leftmost nav item (it is the home screen).
			// System groups come next, then user-defined groups at the end.
			// Order: All | Starred | Recent | System | Hamilton | Unsigned | [user groups]
			// ** AI NOTE: gAll must NEVER be moved from the leftmost position **
			var _sysNavIds = { gAll:1, gRecent:1, gStarred:1, gSystem:1, gHamilton:1, gUnsigned:1 };
			// Move all user-defined groups to the end of navbarLeft
			$(".navbarLeft .nav-item").each(function() {
				var gid = $(this).attr('data-group-id');
				if (gid && !_sysNavIds[gid]) {
					$(this).appendTo($(this).parent());
				}
			});
			// Enforce exact system group order in navbar:
			// All | Starred | Recent | System | Hamilton | Unsigned | [user groups]
			var _navOrder = ['gAll', 'gStarred', 'gRecent', 'gSystem', 'gHamilton', 'gUnsigned'];
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
			// Nav order:  All | Starred | Recent | System | Hamilton | Unsigned | [user groups]
			// Accordion visible order: Starred | System | Hamilton | Unsigned | [user groups] | Unassigned
			// (All, Recent, Folders, Editors, History are hidden via d-none)
			{
				var $accordion = $(".settings-links #accordion");
				var _sysAccIds = { gAll:1, gRecent:1, gStarred:1, gFolders:1, gEditors:1, gHistory:1, gUnsigned:1, gSystem:1, gHamilton:1 };

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
				var _accOrder = ['gStarred', 'gSystem', 'gHamilton', 'gUnsigned'];
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
			console.log("save tree..");
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
			} else {
				$("#chk_showGitHubLinks").prop("checked", settings["chk_showGitHubLinks"] !== false).prop("disabled", false);
				$(".github-links-regulated-status").html('');
			}

			//setting - Unsigned libraries
			var unsignedEnabled = !!settings["chk_includeUnsignedLibs"];
			// In regulated mode, unsigned files cannot be enabled - all packages must be signed
			if (regulatedMode && unsignedEnabled) {
				unsignedEnabled = false;
				saveSetting("chk_includeUnsignedLibs", false);
				saveSetting("chk_scanUnsignedOnLaunch", false);
				console.log('Unsigned libraries disabled automatically: regulated environment mode requires all packages to be signed.');
			}
			$("#chk_includeUnsignedLibs").prop("checked", unsignedEnabled);
			$("#btn-scan-unsigned-libs").prop("disabled", !unsignedEnabled);
			$("#chk_scanUnsignedOnLaunch").prop("disabled", !unsignedEnabled || regulatedMode);
			$("#chk_scanUnsignedOnLaunch").prop("checked", !!settings["chk_scanUnsignedOnLaunch"] && !regulatedMode);
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
				// Auto-scan on launch if enabled
				if (!!settings["chk_scanUnsignedOnLaunch"]) {
					scanUnsignedLibraries(true);
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

			//setting - Use System Theme
			var useSystem = !!settings["chk_useSystemTheme"];
			$("#chk_useSystemTheme").prop("checked", useSystem);
			applySystemThemeVisibility(useSystem);

			//setting - Dark Mode / Night Mode (persisted between sessions)
			if (useSystem) {
				applySystemTheme();
			} else {
				var darkEnabled = !!settings["chk_darkMode"];
				$("#chk_darkMode").prop("checked", darkEnabled);
				applyDarkMode(darkEnabled);
			}

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
					console.warn('Could not read log directory: ' + HxFolder_LogFiles + ' - ' + err.message);
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
				var fileNames = medFiles.map(function(f) { return '<b>' + path.basename(f) + '</b>'; }).join(', ');
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
					var files = fs.readdirSync(folderPath);
					var newDlls = [];
					var medFiles = [];
					files.forEach(function(file) {
						var filePath = path.join(folderPath, file);
						try {
							if (fs.statSync(filePath).isFile() && pkg_libraryFiles.indexOf(filePath) === -1) {
								pkg_libraryFiles.push(filePath);
								if (file.toLowerCase().endsWith('.dll')) {
									newDlls.push(file);
								}
								if (file.toLowerCase().endsWith('.med')) {
									medFiles.push(filePath);
								}
							}
						} catch(e) {}
					});
					// Auto-check for COM registration if exactly one DLL was added in this batch
					if (newDlls.length === 1 && pkg_comRegisterDlls.indexOf(newDlls[0]) === -1) {
						pkg_comRegisterDlls.push(newDlls[0]);
					}
					pkgUpdateLibFileList();

					// Warn if .med (method) files were found in the folder
					if (medFiles.length > 0) {
						var fileNames = medFiles.map(function(f) { return '<b>' + path.basename(f) + '</b>'; }).join(', ');
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
				var fileNames = dllFiles.map(function(f) { return '<b>' + path.basename(f) + '</b>'; }).join(', ');
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
					var files = fs.readdirSync(folderPath);
					var dllFiles = [];
					files.forEach(function(file) {
						var filePath = path.join(folderPath, file);
						try {
							if (fs.statSync(filePath).isFile() && pkg_demoMethodFiles.indexOf(filePath) === -1) {
								pkg_demoMethodFiles.push(filePath);
								if (file.toLowerCase().endsWith('.dll')) {
									dllFiles.push(filePath);
								}
							}
						} catch(e) {}
					});
					pkgUpdateDemoFileList();

					// Warn if .dll files were found in the folder
					if (dllFiles.length > 0) {
						var fileNames = dllFiles.map(function(f) { return '<b>' + path.basename(f) + '</b>'; }).join(', ');
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

		// ---- Author/Organization field restriction: prompt for password when "Hamilton" is entered ----
		$(document).on("blur", "#pkg-author, #pkg-organization", async function() {
			var fieldVal = $(this).val().trim();
			if (isRestrictedAuthor(fieldVal) && !pkg_hamiltonAuthorized) {
				var pwOk = await promptAuthorPassword();
				if (pwOk) {
					pkg_hamiltonAuthorized = true;
				} else {
					$(this).val('');
					$(this).focus();
					pkg_hamiltonAuthorized = false;
				}
			} else if (!isRestrictedAuthor(fieldVal) && !isRestrictedAuthor($('#pkg-author').val().trim()) && !isRestrictedAuthor($('#pkg-organization').val().trim())) {
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
			var organization = $("#pkg-organization").val().trim();
			var version = $("#pkg-version").val().trim();
			var venusCompat = $("#pkg-venus-compat").val().trim();
			var description = $("#pkg-description").val().trim();

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
				if (isRestrictedAuthor(author) || isRestrictedAuthor(organization)) {
					var pwOk = await promptAuthorPassword();
					if (!pwOk) {
						alert('Package creation cancelled. Using "Hamilton" as author or organization requires authorization.');
						return;
					}
				}
				var version = $("#pkg-version").val().trim();
				var venusCompat = $("#pkg-venus-compat").val().trim();
				var description = $("#pkg-description").val().trim();
				var githubUrl = $("#pkg-github-url").val().trim();
				var tagsRaw = $("#pkg-tags").val().trim();

				// Parse and sanitize tags (lowercase, no spaces)
				var tags = [];
				if (tagsRaw) {
					tagsRaw.split(",").forEach(function(t) {
						var s = shared.sanitizeTag(t);
						if (s) tags.push(s);
					});
				}

				// Filter reserved tags ("System" and "Hamilton" are not allowed)
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
							} catch(e) {}
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
				if (githubUrl) manifest.github_url = githubUrl;

				// Create ZIP package using adm-zip
				var zip = new AdmZip();

				// Add manifest.json
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files under library/ directory
				pkg_libraryFiles.forEach(function(fpath) {
					zip.addLocalFile(fpath, "library");
				});

				// Add composited icon under icon/ directory (for Windows file system display)
				var iconDataForZip = compositedIconBase64 || libImageBase64;
				if (iconDataForZip) {
					var iconFilename = compositedIconFilename || libImageFilename || (libName + '_icon.png');
					zip.addFile("icon/" + iconFilename, Buffer.from(iconDataForZip, 'base64'));
				}

				// Add demo method files under demo_methods/ directory
				pkg_demoMethodFiles.forEach(function(fpath) {
					zip.addLocalFile(fpath, "demo_methods");
				});

				// Sign the package for integrity verification
				signPackageZip(zip);

				// Wrap in binary container and write
				fs.writeFileSync(savePath, packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

				// ---- Audit trail entry ----
				try {
					appendAuditTrailEntry(buildAuditTrailEntry('package_created', {
						library_name:    libName,
						version:         version || '',
						author:          author || '',
						organization:    organization || '',
						output_file:     savePath,
						library_files:   pkg_libraryFiles.length,
						demo_files:      pkg_demoMethodFiles.length,
						com_dlls:        (manifest.com_register_dlls || [])
					}));
				} catch(_) { /* non-critical */ }

				showGenericSuccessModal({
					title: "Package Created Successfully!",
					name: libName,
					detail: pkg_libraryFiles.length + " library file" + (pkg_libraryFiles.length !== 1 ? "s" : "") + ", " + pkg_demoMethodFiles.length + " demo method file" + (pkg_demoMethodFiles.length !== 1 ? "s" : ""),
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

		// ---- HSL function parser - extracts public function signatures ----
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

		// ---- Package signing & hashing (delegated to shared module) ----
		var computeLibraryHashes  = shared.computeLibraryHashes;
		var signPackageZip        = shared.signPackageZip;
		var verifyPackageSignature = shared.verifyPackageSignature;

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
		function invalidateLibCaches() { _integrityCache = {}; _depCache = {}; }

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
				starredUserLibs.forEach(function(lib) {
					$container.append(impBuildSingleCardHtml(lib));
				});
				starredSysLibs.forEach(function(sLib) {
					$container.append(buildSystemLibraryCard(sLib));
				});
				$container.append('<div class="col-md-12 my-3"></div>');
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
						tagsHtml += '<button type="button" class="imp-tag-badge mr-1 mb-1" data-tag="' + t + '"><i class="fas fa-tag mr-1"></i>' + t + '</button>';
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
				var hasChmHelp = helpFiles.some(function(f) { return path.extname(f).toLowerCase() === '.chm'; });

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
								(hasChmHelp ? '<a href="#" class="text-sm imp-lib-card-help-link" style="color:var(--medium);" data-lib-id="' + lib._id + '">Help</a>' : '<span></span>') +
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
			var hasSysChmHelp = (sLib.discovered_files || []).some(function(f) {
				return path.extname(f).toLowerCase() === '.chm';
			});

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
							(hasSysChmHelp ? '<a href="#" class="text-sm imp-lib-card-help-link" style="color:var(--medium);" data-lib-id="' + sLib._id + '">Help</a>' : '<span></span>') +
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
			$("#libDetailModal .lib-detail-author").text(lib.author || "\u2014");
			$("#libDetailModal .lib-detail-organization").text(lib.organization || "\u2014");
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

			// GitHub URL (respect display setting — always hidden in regulated mode)
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
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + escapeHtml(fullPath) + '" title="Open: ' + escapeHtml(fullPath) + '"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span></div>'
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
						'<div class="pkg-file-item pkg-file-link" data-filepath="' + escapeHtml(fullPath) + '" title="Open: ' + escapeHtml(fullPath) + '"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span></div>'
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

			// Store library id on the modal so delete button can use it
			$("#libDetailModal").attr("data-lib-id", libId);
			$("#libDetailModal").attr("data-system", "false");
			$("#libDetailModal").modal("show");
		}

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
					}
				});

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
					library_image: manifest.library_image || null,
					library_image_base64: manifest.library_image_base64 || null,
					library_image_mime: manifest.library_image_mime || null,
					library_files: libFiles,
					demo_method_files: demoFiles,
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: comWarning,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: path.basename(fullPath),
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFiles, libDestDir),
					required_dependencies: extractRequiredDependencies(libFiles, libDestDir)
				};
				var saved = db_installed_libs.installed_libs.save(dbRecord);

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
						// Hamilton author: route to gHamilton group
						var hamiltonTreeEntry = null;
						for (var ti = 0; ti < navtree.length; ti++) {
							if (navtree[ti]["group-id"] === "gHamilton") {
								hamiltonTreeEntry = navtree[ti];
								break;
							}
						}
						if (hamiltonTreeEntry) {
							targetGroupId = "gHamilton";
							var existingIds = (hamiltonTreeEntry["method-ids"] || []).slice();
							existingIds.push(saved._id);
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
							// Hamilton group tree entry missing; create it
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
						// Non-Hamilton: add to first custom group
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
					alert('NOTE: This library has COM DLLs that may need re-registration:\n\n' + comDlls.join(', ') + '\n\nRe-import via the GUI for automatic 32-bit COM registration, or run the 32-bit RegAsm manually:\n  C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe /codebase <dll>\n\nIMPORTANT: Do NOT use Framework64 — VENUS is a 32-bit application.');
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
			$("#libDetailModal .lib-detail-author").text(sLib.author || "Hamilton");
			$("#libDetailModal .lib-detail-organization").text(sLib.organization || "Hamilton");
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
			$("#exportChoiceModal").modal("hide");

			var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
			if (!lib) { alert("Library not found."); return; }
			var libName = lib.library_name || "Unknown";

			if (choice === "single") {
				// Single library export (.hxlibpkg)
				$("#lib-export-save-dialog").attr("nwsaveas", libName + ".hxlibpkg");
				$("#lib-export-save-dialog").trigger("click");
			} else if (choice === "deps") {
				// Export with all dependencies (.hxlibarch)
				$("#lib-export-deps-save-dialog").attr("nwsaveas", libName + "_with_dependencies.hxlibarch");
				$("#lib-export-deps-save-dialog").data("libId", libId);
				$("#lib-export-deps-save-dialog").trigger("click");
			}
		});

		$(document).on("change", "#lib-export-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			var libId = $("#libDetailModal").attr("data-lib-id");
			if (!libId) return;
			exportSingleLibrary(libId, savePath);
		});

		// Save dialog for export with dependencies
		$(document).on("change", "#lib-export-deps-save-dialog", function() {
			var savePath = $(this).val();
			if (!savePath) return;
			$(this).val('');
			var libId = $(this).data("libId");
			if (!libId) return;
			exportLibraryWithDependencies(libId, savePath);
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

				// Build manifest - include help_files for the importer
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

				// Add help files (CHMs - packed into library/ folder)
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

				// Wrap in binary container and write
				fs.writeFileSync(savePath, packContainer(zip.toBuffer(), CONTAINER_MAGIC_PKG));

				showGenericSuccessModal({
					title: "Library Exported Successfully!",
					name: libName,
					detail: libraryFiles.length + " library file" + (libraryFiles.length !== 1 ? "s" : "") + ", " + helpFiles.length + " help file" + (helpFiles.length !== 1 ? "s" : "") + ", " + demoFiles.length + " demo file" + (demoFiles.length !== 1 ? "s" : ""),
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
		function exportLibraryWithDependencies(libId, savePath) {
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
					innerZip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

					var libFilesAdded = 0;
					libraryFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, "library");
							libFilesAdded++;
						}
					});

					helpFiles.forEach(function(f) {
						var fullPath = path.join(libBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, "library");
						}
					});

					var demoFilesAdded = 0;
					demoFiles.forEach(function(f) {
						var fullPath = path.join(demoBasePath, f);
						if (fs.existsSync(fullPath)) {
							innerZip.addLocalFile(fullPath, "demo_methods");
							demoFilesAdded++;
						}
					});

					signPackageZip(innerZip);

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

					// Add help files (CHMs - packed into library/ folder)
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

				// ---- Restricted author pre-check (scan all packages) ----
				// Because the forEach loop is synchronous, we cannot await inside it.
				// Pre-scan all manifests to see if any package claims a restricted
				// author or organization.  If so, prompt for the password once now.
				var hasRestrictedPackage = false;
				for (var pi = 0; pi < pkgEntries.length; pi++) {
					try {
						var scanBuf = pkgEntries[pi].getData();
						var scanZipBuf = unpackContainer(scanBuf, CONTAINER_MAGIC_PKG);
						var scanZip = new AdmZip(scanZipBuf);
						var scanManifest = scanZip.getEntry("manifest.json");
						if (scanManifest) {
							var scanM = JSON.parse(scanZip.readAsText(scanManifest));
							var scanAuthor = (scanM.author || '').trim();
							var scanOrg    = (scanM.organization || '').trim();
							var scanLibName = scanM.library_name || '';
							if (isRestrictedAuthor(scanAuthor) || isRestrictedAuthor(scanOrg)) {
								var scanIsSysLib = systemLibraries.some(function(s) {
									return s.canonical_name === scanLibName || s.library_name === scanLibName;
								});
								if (!scanIsSysLib) {
									hasRestrictedPackage = true;
									break;
								}
							}
						}
					} catch (_) { /* scan failure is non-fatal; will be caught during install */ }
				}
				if (hasRestrictedPackage) {
					var pwOk = await promptAuthorPassword();
					if (!pwOk) {
						alert('Import cancelled. One or more packages in this archive use the restricted author/organization name "Hamilton".');
						return;
					}
					archiveHamiltonAuthorized = true;
				}

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
							library_image: manifest.library_image || null,
							library_image_base64: manifest.library_image_base64 || null,
							library_image_mime: manifest.library_image_mime || null,
							library_files: libFiles,
							demo_method_files: manifest.demo_method_files || [],
							help_files: helpFiles,
							com_register_dlls: comDlls,
							com_warning: comDlls.length > 0,  // mark as warning; cleared below if registration succeeds
							lib_install_path: libDestDir,
							demo_install_path: demoDestDir,
							installed_date: new Date().toISOString(),
							source_package: pkgEntry.entryName,
							file_hashes: fileHashes,
							public_functions: extractPublicFunctions(libFiles, libDestDir),
							required_dependencies: extractRequiredDependencies(libFiles, libDestDir)
						};
						var saved = db_installed_libs.installed_libs.save(dbRecord);

						// Update publisher registry
						registerPublisher(manifest.author || '');
						registerPublisher(manifest.organization || '');
						registerTags(manifest.tags || []);

						// Attempt COM registration for DLLs (best-effort, non-blocking).
						// NOTE: This is intentionally not awaited because the enclosing
						// forEach is synchronous. The promise chain updates the DB record
						// on completion/failure, which is sufficient for archive import.
						if (comDlls.length > 0) {
							var dllPaths = comDlls.map(function(d) { return path.join(libDestDir, d); });
							comRegisterMultipleDlls(dllPaths, true).then(function(comResult) {
								if (comResult.allSuccess) {
									// Clear the warning flag
									db_installed_libs.installed_libs.update(
										{"_id": saved._id},
										{"com_warning": false},
										{multi: false, upsert: false}
									);
								} else {
									console.warn('COM registration failed for ' + libName + ' (archive import): ' +
										comResult.results.filter(function(r) { return !r.success; }).map(function(r) { return r.error; }).join('; '));
								}
							}).catch(function(err) {
								console.warn('COM registration error for ' + libName + ': ' + err.message);
							});
						}

						// Auto-add to group
						var navtree = db_tree.tree.find();
						var targetGroupId = null;
						var archImportAuthor = (manifest.author || '').trim();
						var archImportOrg = (manifest.organization || '').trim();

						if (isRestrictedAuthor(archImportAuthor) || isRestrictedAuthor(archImportOrg)) {
							// Hamilton author: add to the Hamilton group
							var hamiltonTreeEntry = null;
							for (var ti = 0; ti < navtree.length; ti++) {
								if (navtree[ti]["group-id"] === "gHamilton") {
									hamiltonTreeEntry = navtree[ti];
									break;
								}
							}
							if (hamiltonTreeEntry) {
								targetGroupId = "gHamilton";
								var existingIds = (hamiltonTreeEntry["method-ids"] || []).slice();
								existingIds.push(saved._id);
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
								// Hamilton group tree entry missing; create it
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
				});

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

				showGenericSuccessModal({
					title: archImpTitle,
					detail: results.success.length + " succeeded" + (results.failed.length > 0 ? ", " + results.failed.length + " failed" : ""),
					listHtml: archImpListHtml
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

		$(document).on("click", ".imp-lib-card:not(.imp-unsigned-lib-card)", function(e) {
			// Don't open detail modal when clicking the Help link, Star, or Tag badge
			if ($(e.target).closest(".imp-lib-card-help-link").length) return;
			if ($(e.target).closest(".imp-lib-star").length) return;
			if ($(e.target).closest(".imp-tag-badge").length) return;
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
		$(document).on("click", ".imp-lib-card-help-link", function(e) {
			e.preventDefault();
			e.stopPropagation();
			var libId = $(this).attr("data-lib-id");
			if (!libId) return;

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
					var relPath = chmFiles[0].replace(/^Library[\\\/]/i, '');
					var fullPath = path.join(sysLibDir, relPath);
					if (fs.existsSync(fullPath)) {
						safeOpenItem(fullPath);
					}
				}
			} else {
				var lib = db_installed_libs.installed_libs.findOne({"_id": libId});
				if (!lib) return;
				var helpFiles = lib.help_files || [];
				var chmFile = helpFiles.find(function(f) { return path.extname(f).toLowerCase() === '.chm'; });
				if (chmFile) {
					var libBasePath = lib.lib_install_path || '';
					var fullPath = libBasePath ? path.join(libBasePath, chmFile) : chmFile;
					if (fs.existsSync(fullPath)) {
						safeOpenItem(fullPath);
					}
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

		// ---- Show regulated mode confirmation modal (requires typing "i accept") ----
		function showRegulatedModeConfirmModal(enabling) {
			return new Promise(function(resolve) {
				var $modal = $("#regulatedModeConfirmModal");
				var expectedText = "i accept";
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
				}

				// Reset input and button state
				$modal.find(".reg-confirm-input").val("");
				$modal.find(".reg-confirm-btn").prop("disabled", true);

				// Enable/disable the confirm button based on typed input
				$modal.find(".reg-confirm-input").off("input.regConfirm").on("input.regConfirm", function() {
					var typed = $(this).val().trim().toLowerCase();
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

				// ---- Restricted author/organization check on import ----
				// If the package claims "Hamilton" as author or organization but is NOT a known system library,
				// require password authorization before allowing the import.
				var importAuthor = (manifest.author || '').trim();
				var importOrg = (manifest.organization || '').trim();
				if (isRestrictedAuthor(importAuthor) || isRestrictedAuthor(importOrg)) {
					// Check if this library name matches a known system library
					var isKnownSysLib = systemLibraries.some(function(s) {
						return s.canonical_name === manifest.library_name || s.library_name === manifest.library_name;
					});
					if (!isKnownSysLib) {
						var pwOk = await promptAuthorPassword();
						if (!pwOk) {
							alert('Import cancelled. The package author/organization "Hamilton" requires authorization for non-system libraries.');
							_isImporting = false;
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
						$libFilesList.append(
							'<div class="pkg-file-item"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span>' + comBadge + '</div>'
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
							'<div class="pkg-file-item"><i class="far fa-file pkg-file-icon"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span></div>'
						);
					});
				}

				// Help files list
				var $helpFilesList = $modal.find(".imp-preview-help-files");
				$helpFilesList.empty();
				if (helpFiles.length > 0) {
					helpFiles.forEach(function(f) {
						$helpFilesList.append(
							'<div class="pkg-file-item"><i class="fas fa-question-circle pkg-file-icon" style="color:var(--medium);"></i><span class="pkg-file-name">' + escapeHtml(f) + '</span></div>'
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
							errHtml += '<div class="text-danger text-sm ml-4">&bull; ' + escapeHtml(e) + '</div>';
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
				$modal.data("imp-sigResult", sigResult);

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
					}
				});

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

				// Update publisher registry
				registerPublisher(manifest.author || '');
				registerPublisher(manifest.organization || '');
				registerTags(manifest.tags || []);

				// Add the new library to the appropriate group in the tree
				var navtree = db_tree.tree.find();
				var targetGroupId = null;

				// If author or organization is Hamilton, auto-assign to the Hamilton group
				var savedAuthor = (manifest.author || '').trim();
				var savedOrg = (manifest.organization || '').trim();
				if (isRestrictedAuthor(savedAuthor) || isRestrictedAuthor(savedOrg)) {
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
						var existingIds = (hamiltonTreeEntry["method-ids"] || []).slice();
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
					appendAuditTrailEntry(buildAuditTrailEntry('library_imported', {
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
					}));
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
						lines.push("Tags:             " + ((lib.tags && lib.tags.length > 0) ? lib.tags.join(", ") : "None"));
						lines.push("Status:           " + (lib.deleted ? "DELETED" : "Active"));
						lines.push("Created Date:     " + (lib.created_date || "N/A"));
						lines.push("Installed Date:   " + (lib.installed_date || "N/A"));
						lines.push("Installed By:     " + (lib.installed_by || "N/A"));
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
								'<span class="font-weight-bold" style="color:var(--medium2);">' + escapeHtml(libName) + '</span>' +
								'<span class="badge badge-light ml-2">' + escapeHtml(lib.version || '') + '</span>' +
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
		var ulib_iconBase64 = null;       // base64-encoded icon data (user-picked or from DB)
		var ulib_iconMime = null;         // MIME type of the icon
		var ulib_iconFilename = null;     // original filename of the icon
		var ulib_iconFilePath = null;     // path of the user-picked icon file (null if from DB)

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
						'<span class="pkg-file-name">' + baseName + '</span>' +
						comCheckbox +
						'<span class="pkg-file-dir">' + path.dirname(f) + '</span>' +
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
						'<span class="pkg-file-name">' + path.basename(f) + '</span>' +
						'<span class="pkg-file-dir">' + path.dirname(f) + '</span>' +
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
		 * Scan the Library folder for .hsl and .smt files that are NOT part of a
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

				// Scan Library folder for unclaimed .hsl and .smt files
				var targetExts = ['.hsl', '.smt'];
				var relatedExts = ['.hs_', '.sub', '.bmp', '.ico', '.chm', '.stp', '.res', '.fdb', '.sii', '.dec', '.dll'];
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

						// Derive library name from primary definition files (.hsl or .smt)
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
							if (lowerEntry === 'librarymanagerforvenus6' || lowerEntry === 'librarypackages' || lowerEntry === '.librarymanagerforvenus6' || lowerEntry === 'libraryintegrityaudit') return;
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
					tagsHtml += '<button type="button" class="imp-tag-badge mr-1 mb-1" data-tag="' + t + '"><i class="fas fa-tag mr-1"></i>' + t + '</button>';
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
						(tagsHtml ? '<div class="mt-1 mb-2">' + tagsHtml + '</div>' : '') +
						'<div class="d-flex justify-content-between align-items-center mt-2 pt-2" style="border-top:1px solid #eee;">' +
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
				return selected.indexOf(f) === -1;
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

		// ---- Unsigned lib: Hamilton author/organization restriction ----
		var ulib_hamiltonAuthorized = false;

		$(document).on("blur", "#ulib-author, #ulib-organization", async function() {
			var fieldVal = $(this).val().trim();
			if (isRestrictedAuthor(fieldVal) && !ulib_hamiltonAuthorized) {
				var pwOk = await promptAuthorPassword();
				if (pwOk) {
					ulib_hamiltonAuthorized = true;
				} else {
					$(this).val('');
					$(this).focus();
					ulib_hamiltonAuthorized = false;
				}
			} else if (!isRestrictedAuthor(fieldVal) && !isRestrictedAuthor($('#ulib-author').val().trim()) && !isRestrictedAuthor($('#ulib-organization').val().trim())) {
				ulib_hamiltonAuthorized = false;
			}
		});

		// Reset Hamilton auth when modal closes
		$("#unsignedLibDetailModal").on("hidden.bs.modal", function() {
			ulib_hamiltonAuthorized = false;
		});

		// ---- Save unsigned library metadata ----
		$(document).on("click", "#ulib-save-btn", async function() {
			var ulibId = $("#unsignedLibDetailModal").attr("data-ulib-id");
			if (!ulibId) return;

			var author = $("#ulib-author").val().trim();
			var organization = $("#ulib-organization").val().trim();

			// Check Hamilton restriction on save
			if (isRestrictedAuthor(author) || isRestrictedAuthor(organization)) {
				if (!ulib_hamiltonAuthorized) {
					var pwOk = await promptAuthorPassword();
					if (pwOk) {
						ulib_hamiltonAuthorized = true;
					} else {
						alert("Cannot save: Hamilton author/organization requires authorization.");
						return;
					}
				}
			}

			var tagsRaw = $("#ulib-tags").val().trim();
			var tags = tagsRaw ? shared.sanitizeTags(tagsRaw.split(",")) : [];

			// Filter reserved tags ("System" and "Hamilton" are not allowed)
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
				library_image_mime: ulib_iconMime
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

			var result = await registerUnsignedLibrary(ulibId);
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

				// Build basenames list for the DB record (matches import format)
				var libFileBasenames = allLibPaths.map(function(f) { return path.basename(f); });

				// Separate help files
				var helpFiles = [];
				allLibPaths.forEach(function(f) {
					if (path.extname(f).toLowerCase() === '.chm') {
						helpFiles.push(path.basename(f));
					}
				});

				// Determine install paths (the library files are already in place on disk)
				var libFolderRec = db_links.links.findOne({"_id":"lib-folder"});
				var sysLibDir = (libFolderRec && libFolderRec.path) ? libFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Library';
				var libDestDir = libDir || sysLibDir;

				var methodFolderRec = db_links.links.findOne({"_id":"met-folder"});
				var sysMethodDir = (methodFolderRec && methodFolderRec.path) ? methodFolderRec.path : 'C:\\Program Files (x86)\\HAMILTON\\Methods';
				var demoDestDir = path.join(sysMethodDir, 'Library Demo Methods', libName);

				// Check for existing installed lib with same name
				var existing = db_installed_libs.installed_libs.findOne({"library_name": libName});
				if (existing) {
					db_installed_libs.installed_libs.remove({"_id": existing._id});
				}

				// Compute integrity hashes
				var fileHashes = {};
				try { fileHashes = computeLibraryHashes(libFileBasenames, libDestDir, comDlls); } catch(e) { console.warn('Could not compute integrity hashes: ' + e.message); }

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
					library_files: libFileBasenames,
					demo_method_files: demoFiles.map(function(f) { return path.basename(f); }),
					help_files: helpFiles,
					com_register_dlls: comDlls,
					com_warning: false,
					lib_install_path: libDestDir,
					demo_install_path: demoDestDir,
					installed_date: new Date().toISOString(),
					source_package: opts.sourcePackage || '(registered from unsigned)',
					file_hashes: fileHashes,
					public_functions: extractPublicFunctions(libFileBasenames, libDestDir),
					required_dependencies: extractRequiredDependencies(libFileBasenames, libDestDir)
				};
				var saved = db_installed_libs.installed_libs.save(dbRecord);

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
					var hamiltonTreeEntry = null;
					for (var ti = 0; ti < navtree.length; ti++) {
						if (navtree[ti]["group-id"] === "gHamilton") {
							hamiltonTreeEntry = navtree[ti];
							break;
						}
					}
					if (hamiltonTreeEntry) {
						targetGroupId = "gHamilton";
						var existingIds = (hamiltonTreeEntry["method-ids"] || []).slice();
						existingIds.push(saved._id);
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
						library_files: libFileBasenames.length,
						demo_files: demoFiles.length
					}));
				} catch(_) { /* non-critical */ }

				// Refresh UI
				impBuildLibraryCards();
				invalidateNavBar();

				if (!opts.silent) {
					showGenericSuccessModal({
						title: "Library Registered!",
						name: libName,
						detail: libFileBasenames.length + " file" + (libFileBasenames.length !== 1 ? "s" : "") + " registered" + (demoFiles.length > 0 ? " (incl. " + demoFiles.length + " demo)" : ""),
						paths: [
							{ label: "Library Path", value: libDestDir }
						],
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

				// Build manifest file lists (basenames)
				var manifestLibFiles = nonHelpPaths.map(function(f) { return path.basename(f); });
				var manifestHelpFiles = helpPaths.map(function(f) { return path.basename(f); });
				manifestHelpFiles.forEach(function(hf) {
					if (manifestLibFiles.indexOf(hf) === -1) manifestLibFiles.push(hf);
				});
				var manifestDemoFiles = demoFiles.map(function(f) { return path.basename(f); });

				var manifest = {
					format_version: "1.0",
					library_name: libName,
					author: uLib.author || "",
					organization: uLib.organization || "",
					version: uLib.version || "",
					venus_compatibility: uLib.venus_compatibility || "",
					description: uLib.description || "",
					github_url: uLib.github_url || "",
					tags: uLib.tags || [],
					created_date: new Date().toISOString(),
					library_image: uLib.library_image || null,
					library_image_base64: uLib.library_image_base64 || null,
					library_image_mime: uLib.library_image_mime || null,
					library_files: manifestLibFiles,
					demo_method_files: manifestDemoFiles,
					help_files: manifestHelpFiles,
					com_register_dlls: comDlls
				};

				// Create ZIP package
				var zip = new AdmZip();

				// Add manifest
				zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest, null, 2), "utf8"));

				// Add library files (non-help)
				nonHelpPaths.forEach(function(f) {
					if (fs.existsSync(f)) {
						zip.addLocalFile(f, "library");
					}
				});

				// Add help files
				helpPaths.forEach(function(f) {
					if (fs.existsSync(f)) {
						zip.addLocalFile(f, "library");
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
				signPackageZip(zip);

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
        //******  FUNCTION DECLARATIONS END ****************************************************
        //**************************************************************************************
		


		