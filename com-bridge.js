#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// COM Bridge  v1.9.25
//
// Copyright (c) 2026 Zachary Milot
// Author: Zachary Milot
//
// Minimal command dispatcher for the COM object (VenusLibraryManager.dll).
// Reads a command name and JSON arguments from process.argv, calls the
// corresponding service function, and writes the JSON result to stdout.
//
// Usage:
//   node com-bridge.js <command> [json-args]
//
// Examples:
//   node com-bridge.js list-libraries
//   node com-bridge.js import-library "{\"filePath\":\"C:\\pkg.hxlibpkg\"}"
//   node com-bridge.js export-library "{\"name\":\"MyLib\",\"output\":\"C:\\out.hxlibpkg\"}"
// ============================================================================

'use strict';

var service = require('./lib/service');

function success(data) {
    process.stdout.write(JSON.stringify({ success: true, data: data }));
}

function fail(message) {
    process.stdout.write(JSON.stringify({ success: false, error: String(message) }));
    process.exit(1);
}

function parseArgs() {
    var command = process.argv[2];
    var argsJson = process.argv[3] || '{}';
    var args;
    try {
        args = JSON.parse(argsJson);
    } catch (e) {
        fail('Invalid JSON arguments: ' + e.message);
    }
    return { command: command, args: args };
}

function main() {
    var parsed = parseArgs();
    if (!parsed) return;

    var command = parsed.command;
    var args = parsed.args;

    var ctx;
    try {
        ctx = service.createContext(args);
    } catch (e) {
        fail('Failed to create service context: ' + e.message);
    }

    try {
        switch (command) {
            case 'list-libraries': {
                var result = service.listLibraries(ctx, args);
                success(result);
                break;
            }
            case 'get-library': {
                var result = service.getLibrary(ctx, args.nameOrId || args.name || args.id);
                success(result);
                break;
            }
            case 'import-library': {
                var result = service.importLibrary(ctx, args);
                success(result);
                break;
            }
            case 'import-archive': {
                var result = service.importArchive(ctx, args);
                success(result);
                break;
            }
            case 'export-library': {
                var result = service.exportLibrary(ctx, args);
                success(result);
                break;
            }
            case 'export-archive': {
                var result = service.exportArchive(ctx, args);
                success(result);
                break;
            }
            case 'delete-library': {
                var result = service.deleteLibrary(ctx, args);
                success(result);
                break;
            }
            case 'create-package': {
                var result = service.createPackage(ctx, args);
                success(result);
                break;
            }
            case 'verify-package': {
                var result = service.verifyPackage(ctx, args);
                success(result);
                break;
            }
            case 'list-versions': {
                var result = service.listVersions(ctx, args);
                success(result);
                break;
            }
            case 'rollback-library': {
                var result = service.rollbackLibrary(ctx, args);
                success(result);
                break;
            }
            case 'list-publishers': {
                var result = service.listPublishers(ctx);
                success(result);
                break;
            }
            case 'generate-keypair': {
                var result = service.generateKeypair(ctx, args);
                success(result);
                break;
            }
            case 'get-system-libraries': {
                var result = service.getSystemLibraries();
                success(result);
                break;
            }
            case 'verify-syslib-hashes': {
                var result = service.verifySyslibHashes(ctx, args);
                success(result);
                break;
            }
            case 'generate-syslib-hashes': {
                var result = service.generateSyslibHashes(ctx, args);
                success(result);
                break;
            }
            case 'get-audit-trail': {
                var result = service.getAuditTrail(ctx, args);
                success(result);
                break;
            }
            case 'get-settings': {
                var result = service.getSettings(ctx);
                success(result);
                break;
            }
            default:
                fail('Unknown command: ' + command);
        }
    } catch (e) {
        fail(e.message || String(e));
    }
}

main();
