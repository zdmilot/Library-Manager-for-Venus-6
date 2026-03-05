// SPDX-License-Identifier: Apache-2.0
/**
 * Library Manager for Venus 6 - REST API Server  v1.6.5
 *
 * Copyright (c) 2026 Zachary Milot
 * Author: Zachary Milot
 *
 * Express-based REST API with Swagger/OpenAPI 3.0 documentation.
 * Provides 1:1 parity with CLI commands via the shared service layer.
 *
 * Usage:
 *   node rest-api.js                     # Start on default port 5555
 *   node rest-api.js --port 8080         # Start on custom port
 *   node rest-api.js --host 0.0.0.0      # Listen on all interfaces
 *   node rest-api.js --api-key <key>     # Require API key auth
 *
 * Swagger UI:   http://localhost:5555/docs
 * OpenAPI spec: http://localhost:5555/api-docs
 */

'use strict';

const express    = require('express');
const path       = require('path');
const fs         = require('fs');
const os         = require('os');
const crypto     = require('crypto');
const multer     = require('multer');
const swaggerUi  = require('swagger-ui-express');
const service    = require('./lib/service');

// ---------------------------------------------------------------------------
// Minimal argument parser
// ---------------------------------------------------------------------------
/**
 * Parse CLI-style `--key value` arguments into an object.
 * @param {string[]} argv - Array of argument strings.
 * @returns {Object<string, string|boolean>} Parsed key-value pairs.
 */
function parseArgs(argv) {
    var args = {};
    for (var i = 0; i < argv.length; i++) {
        var arg = argv[i];
        if (arg.startsWith('--')) {
            var key  = arg.slice(2);
            var next = argv[i + 1];
            if (next !== undefined && !next.startsWith('--')) { args[key] = next; i++; }
            else args[key] = true;
        }
    }
    return args;
}

var cliArgs   = parseArgs(process.argv.slice(2));
var API_PORT  = parseInt(cliArgs.port, 10) || 5555;
var API_HOST  = cliArgs.host || '127.0.0.1';
var API_KEY   = cliArgs['api-key'] || null;

// ---------------------------------------------------------------------------
// Temp upload directory for package imports
// ---------------------------------------------------------------------------
var UPLOAD_DIR = path.join(os.tmpdir(), 'venus-libmgr-uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

var upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 500 * 1024 * 1024 } /* 500 MB */ });

// ---------------------------------------------------------------------------
// Concurrency mutex (diskdb is not concurrent-safe)
// ---------------------------------------------------------------------------
var _mutexQueue = [];
var _mutexLocked = false;

/**
 * Acquire the concurrency mutex (diskdb is not concurrent-safe).
 * @returns {Promise<void>} Resolves when the lock is acquired.
 */
function acquireMutex() {
    return new Promise(function(resolve) {
        if (!_mutexLocked) { _mutexLocked = true; resolve(); }
        else _mutexQueue.push(resolve);
    });
}

/**
 * Release the concurrency mutex, allowing the next queued caller to proceed.
 */
function releaseMutex() {
    if (_mutexQueue.length > 0) {
        var next = _mutexQueue.shift();
        next();
    } else {
        _mutexLocked = false;
    }
}

// ---------------------------------------------------------------------------
// OpenAPI 3.0 Specification
// ---------------------------------------------------------------------------
var openApiSpec = {
    openapi: '3.0.3',
    info: {
        title:       'Library Manager for Venus 6 REST API',
        version:     '1.6.5',
        description: 'RESTful API for managing Hamilton VENUS 6 libraries. Provides complete 1:1 parity with the CLI commands for library import, export, packaging, verification, and audit trail operations. All operations use the same shared security model (Ed25519 code signing, HMAC integrity, OEM author protection) as the GUI and CLI.\n\n**Authentication:** If the server is started with `--api-key`, all requests must include the `X-API-Key` header.',
        contact: { name: 'Zachary Milot', url: 'https://github.com/zdmilot/Library-Manager-for-Venus-6' },
        license: { name: 'Apache-2.0', url: 'https://www.apache.org/licenses/LICENSE-2.0' }
    },
    servers: [
        { url: 'http://localhost:' + API_PORT, description: 'Local development server' }
    ],
    tags: [
        { name: 'Libraries',           description: 'Library CRUD operations' },
        { name: 'Packages',            description: 'Package creation and verification' },
        { name: 'Archives',            description: 'Multi-library archive operations' },
        { name: 'Versions',            description: 'Cached version management and rollback' },
        { name: 'Publishers',          description: 'Code signing and publisher certificates' },
        { name: 'System Libraries',    description: 'Hamilton system library integrity' },
        { name: 'Audit',               description: 'Audit trail access' },
        { name: 'Settings',            description: 'Application settings' },
        { name: 'Health',              description: 'Server health check' }
    ],
    components: {
        securitySchemes: {
            ApiKeyAuth: {
                type: 'apiKey',
                in: 'header',
                name: 'X-API-Key',
                description: 'API key authentication. Required when server is started with --api-key flag.'
            }
        },
        schemas: {
            Error: {
                type: 'object',
                properties: {
                    success: { type: 'boolean', example: false },
                    error:   { type: 'string',  example: 'Description of the error' }
                }
            },
            Library: {
                type: 'object',
                properties: {
                    _id:                 { type: 'string', description: 'Unique library ID' },
                    library_name:        { type: 'string', description: 'Library name' },
                    author:              { type: 'string', description: 'Author name' },
                    organization:        { type: 'string', description: 'Organization name' },
                    version:             { type: 'string', description: 'Version string' },
                    venus_compatibility: { type: 'string', description: 'VENUS version compatibility' },
                    description:         { type: 'string', description: 'Library description' },
                    github_url:          { type: 'string', description: 'GitHub repository URL' },
                    tags:                { type: 'array', items: { type: 'string' } },
                    created_date:        { type: 'string', format: 'date-time' },
                    library_files:       { type: 'array', items: { type: 'string' } },
                    demo_method_files:   { type: 'array', items: { type: 'string' } },
                    help_files:          { type: 'array', items: { type: 'string' } },
                    com_register_dlls:   { type: 'array', items: { type: 'string' } },
                    lib_install_path:    { type: 'string' },
                    demo_install_path:   { type: 'string' },
                    installed_date:      { type: 'string', format: 'date-time' },
                    installed_by:        { type: 'string' },
                    public_functions:    { type: 'array', items: { type: 'object' } },
                    required_dependencies: { type: 'array', items: { type: 'object' } },
                    deleted:             { type: 'boolean' },
                    deleted_date:        { type: 'string', format: 'date-time' }
                }
            },
            CachedVersion: {
                type: 'object',
                properties: {
                    file:     { type: 'string', description: 'Cached package filename' },
                    version:  { type: 'string', description: 'Package version' },
                    author:   { type: 'string', description: 'Package author' },
                    created:  { type: 'string', description: 'Original creation date' },
                    cached:   { type: 'string', format: 'date-time', description: 'Cache timestamp' },
                    size:     { type: 'integer', description: 'File size in bytes' },
                    fullPath: { type: 'string', description: 'Full filesystem path' }
                }
            },
            VerificationResult: {
                type: 'object',
                properties: {
                    package:        { type: 'string' },
                    signed:         { type: 'boolean' },
                    valid:          { type: 'boolean' },
                    code_signed:    { type: 'boolean' },
                    publisher_cert: { type: 'object', nullable: true },
                    oem_verified:   { type: 'boolean' },
                    errors:         { type: 'array', items: { type: 'string' } },
                    warnings:       { type: 'array', items: { type: 'string' } }
                }
            },
            ImportResult: {
                type: 'object',
                properties: {
                    libraryName:     { type: 'string' },
                    version:         { type: 'string' },
                    author:          { type: 'string' },
                    filesExtracted:  { type: 'integer' },
                    libInstallPath:  { type: 'string' },
                    demoInstallPath: { type: 'string' },
                    cachedPath:      { type: 'string', nullable: true },
                    signatureStatus: { type: 'string', enum: ['valid', 'failed', 'unsigned'] },
                    comDlls:         { type: 'array', items: { type: 'string' } }
                }
            },
            ExportResult: {
                type: 'object',
                properties: {
                    libraryName:  { type: 'string' },
                    outputPath:   { type: 'string' },
                    libraryFiles: { type: 'integer' },
                    demoFiles:    { type: 'integer' },
                    codeSigned:   { type: 'boolean' },
                    publisher:    { type: 'string', nullable: true }
                }
            },
            DeleteResult: {
                type: 'object',
                properties: {
                    libraryName: { type: 'string' },
                    deleteType:  { type: 'string', enum: ['soft', 'hard'] },
                    keepFiles:   { type: 'boolean' },
                    comDlls:     { type: 'array', items: { type: 'string' } }
                }
            },
            AuditEntry: {
                type: 'object',
                properties: {
                    event:           { type: 'string' },
                    timestamp:       { type: 'string', format: 'date-time' },
                    username:        { type: 'string' },
                    windows_version: { type: 'string' },
                    venus_version:   { type: 'string' },
                    hostname:        { type: 'string' },
                    details:         { type: 'object' }
                }
            },
            Publisher: {
                type: 'object',
                properties: {
                    name:         { type: 'string' },
                    certificates: { type: 'array', items: {
                        type: 'object',
                        properties: {
                            publisher:    { type: 'string' },
                            organization: { type: 'string' },
                            key_id:       { type: 'string' },
                            fingerprint:  { type: 'string' },
                            created_date: { type: 'string', format: 'date-time' }
                        }
                    }}
                }
            },
            SyslibVerifyResult: {
                type: 'object',
                properties: {
                    ok:       { type: 'array', items: { type: 'object' } },
                    tampered: { type: 'array', items: { type: 'object' } },
                    missing:  { type: 'array', items: { type: 'object' } },
                    errors:   { type: 'array', items: { type: 'object' } }
                }
            }
        }
    },
    security: API_KEY ? [{ ApiKeyAuth: [] }] : [],
    paths: {
        // ---- Health ----
        '/api/health': {
            get: {
                tags: ['Health'], summary: 'Health check', operationId: 'healthCheck',
                description: 'Returns server status, uptime, and version information.',
                responses: { '200': { description: 'Server is running', content: { 'application/json': { schema: {
                    type: 'object', properties: {
                        status: { type: 'string', example: 'ok' },
                        version: { type: 'string', example: '1.6.5' },
                        uptime: { type: 'number' },
                        hostname: { type: 'string' }
                    }
                }}}}}
            }
        },
        // ---- Libraries ----
        '/api/libraries': {
            get: {
                tags: ['Libraries'], summary: 'List installed libraries', operationId: 'listLibraries',
                description: 'Returns all installed libraries. Equivalent to CLI `list-libs`.',
                parameters: [
                    { name: 'includeDeleted', in: 'query', schema: { type: 'boolean', default: false }, description: 'Include soft-deleted libraries' }
                ],
                responses: {
                    '200': { description: 'Library list', content: { 'application/json': { schema: {
                        type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { '$ref': '#/components/schemas/Library' } } }
                    }}}},
                    '500': { description: 'Server error', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        '/api/libraries/{nameOrId}': {
            get: {
                tags: ['Libraries'], summary: 'Get a single library', operationId: 'getLibrary',
                description: 'Get details for a specific library by name or internal ID.',
                parameters: [
                    { name: 'nameOrId', in: 'path', required: true, schema: { type: 'string' }, description: 'Library name or _id' }
                ],
                responses: {
                    '200': { description: 'Library details', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { '$ref': '#/components/schemas/Library' } } } } } },
                    '404': { description: 'Library not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            },
            delete: {
                tags: ['Libraries'], summary: 'Delete a library', operationId: 'deleteLibrary',
                description: 'Delete an installed library. Equivalent to CLI `delete-lib --yes`.',
                parameters: [
                    { name: 'nameOrId', in: 'path', required: true, schema: { type: 'string' }, description: 'Library name or _id' }
                ],
                requestBody: { content: { 'application/json': { schema: {
                    type: 'object', properties: {
                        hard:      { type: 'boolean', default: false, description: 'Permanently remove DB record (vs soft-delete)' },
                        keepFiles: { type: 'boolean', default: false, description: 'Leave disk files in place' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Deletion result', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { '$ref': '#/components/schemas/DeleteResult' } } } } } },
                    '400': { description: 'Validation error', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
                    '404': { description: 'Library not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        '/api/libraries/import': {
            post: {
                tags: ['Libraries'], summary: 'Import a .hxlibpkg package', operationId: 'importLibrary',
                description: 'Import a single .hxlibpkg library package. Equivalent to CLI `import-lib`. Upload the package file as multipart form data.',
                requestBody: { required: true, content: { 'multipart/form-data': { schema: {
                    type: 'object', required: ['package'],
                    properties: {
                        package:        { type: 'string', format: 'binary', description: '.hxlibpkg file' },
                        force:          { type: 'string', enum: ['true', 'false'], description: 'Overwrite existing library' },
                        noGroup:        { type: 'string', enum: ['true', 'false'], description: 'Skip group assignment' },
                        noCache:        { type: 'string', enum: ['true', 'false'], description: 'Skip package caching' },
                        authorPassword: { type: 'string', description: 'OEM author password' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Import result', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { '$ref': '#/components/schemas/ImportResult' }, warnings: { type: 'array', items: { type: 'string' } } } } } } },
                    '400': { description: 'Import failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        '/api/libraries/import-archive': {
            post: {
                tags: ['Archives'], summary: 'Import a .hxlibarch archive', operationId: 'importArchive',
                description: 'Import a multi-library archive file. Equivalent to CLI `import-archive`.',
                requestBody: { required: true, content: { 'multipart/form-data': { schema: {
                    type: 'object', required: ['archive'],
                    properties: {
                        archive:        { type: 'string', format: 'binary', description: '.hxlibarch file' },
                        force:          { type: 'string', enum: ['true', 'false'] },
                        noGroup:        { type: 'string', enum: ['true', 'false'] },
                        noCache:        { type: 'string', enum: ['true', 'false'] },
                        authorPassword: { type: 'string' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Archive import result', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object' } } } } } },
                    '400': { description: 'Import failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        '/api/libraries/{nameOrId}/export': {
            get: {
                tags: ['Libraries'], summary: 'Export a library as .hxlibpkg', operationId: 'exportLibrary',
                description: 'Export an installed library as a downloadable .hxlibpkg binary. Equivalent to CLI `export-lib`.',
                parameters: [
                    { name: 'nameOrId', in: 'path', required: true, schema: { type: 'string' }, description: 'Library name or _id' }
                ],
                responses: {
                    '200': { description: 'Binary .hxlibpkg file download', content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } },
                    '400': { description: 'Export failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } },
                    '404': { description: 'Library not found', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        '/api/libraries/export-archive': {
            post: {
                tags: ['Archives'], summary: 'Export libraries as .hxlibarch', operationId: 'exportArchive',
                description: 'Export one or more installed libraries as a downloadable .hxlibarch archive. Equivalent to CLI `export-archive`.',
                requestBody: { required: true, content: { 'application/json': { schema: {
                    type: 'object',
                    properties: {
                        all:   { type: 'boolean', description: 'Export all non-system libraries' },
                        names: { type: 'array', items: { type: 'string' }, description: 'Library names to export' },
                        ids:   { type: 'array', items: { type: 'string' }, description: 'Library IDs to export' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Binary .hxlibarch file download', content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } },
                    '400': { description: 'Export failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        // ---- Versions & Rollback ----
        '/api/libraries/{name}/versions': {
            get: {
                tags: ['Versions'], summary: 'List cached versions', operationId: 'listVersions',
                description: 'List cached package versions for a library. Equivalent to CLI `list-versions`.',
                parameters: [
                    { name: 'name', in: 'path', required: true, schema: { type: 'string' }, description: 'Library name' }
                ],
                responses: {
                    '200': { description: 'Version list', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { '$ref': '#/components/schemas/CachedVersion' } } } } } } }
                }
            }
        },
        '/api/libraries/{name}/rollback': {
            post: {
                tags: ['Versions'], summary: 'Rollback to a cached version', operationId: 'rollbackLibrary',
                description: 'Reinstall a previously cached version of a library. Equivalent to CLI `rollback-lib`.',
                parameters: [
                    { name: 'name', in: 'path', required: true, schema: { type: 'string' }, description: 'Library name' }
                ],
                requestBody: { required: true, content: { 'application/json': { schema: {
                    type: 'object',
                    properties: {
                        version:        { type: 'string', description: 'Version string to roll back to' },
                        index:          { type: 'integer', description: 'Cache index (1-based) to roll back to' },
                        noGroup:        { type: 'boolean', default: false },
                        authorPassword: { type: 'string', description: 'OEM author password if needed' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Rollback result', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object' } } } } } },
                    '400': { description: 'Rollback failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        // ---- Packages ----
        '/api/packages/create': {
            post: {
                tags: ['Packages'], summary: 'Create a .hxlibpkg package', operationId: 'createPackage',
                description: 'Create a .hxlibpkg from a JSON spec file. Equivalent to CLI `create-package`. The spec file and all referenced files must exist on the server filesystem.',
                requestBody: { required: true, content: { 'application/json': { schema: {
                    type: 'object', required: ['specPath', 'output'],
                    properties: {
                        specPath:       { type: 'string', description: 'Path to JSON spec file on server' },
                        output:         { type: 'string', description: 'Output .hxlibpkg path on server' },
                        signKey:        { type: 'string', description: 'Path to Ed25519 private key PEM' },
                        signCert:       { type: 'string', description: 'Path to publisher .cert.json' },
                        authorPassword: { type: 'string', description: 'OEM author password' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Package creation result', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object' } } } } } },
                    '400': { description: 'Creation failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        '/api/packages/verify': {
            post: {
                tags: ['Packages'], summary: 'Verify package integrity', operationId: 'verifyPackage',
                description: 'Verify the integrity signature of a .hxlibpkg or .hxlibarch. Accepts file upload or server path. Equivalent to CLI `verify-package`.',
                requestBody: { required: true, content: { 'multipart/form-data': { schema: {
                    type: 'object',
                    properties: {
                        package:  { type: 'string', format: 'binary', description: '.hxlibpkg or .hxlibarch file' },
                        filePath: { type: 'string', description: 'Alternative: server-side file path' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Verification results', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { '$ref': '#/components/schemas/VerificationResult' } } } } } } },
                    '400': { description: 'Verification failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        // ---- Publishers ----
        '/api/publishers': {
            get: {
                tags: ['Publishers'], summary: 'List publisher certificates', operationId: 'listPublishers',
                description: 'List registered publisher signing certificates. Equivalent to CLI `list-publishers`.',
                responses: {
                    '200': { description: 'Publisher list', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { '$ref': '#/components/schemas/Publisher' } } } } } } }
                }
            }
        },
        '/api/publishers/generate-keypair': {
            post: {
                tags: ['Publishers'], summary: 'Generate Ed25519 signing keypair', operationId: 'generateKeypair',
                description: 'Generate a new Ed25519 key pair for package code signing.',
                requestBody: { required: true, content: { 'application/json': { schema: {
                    type: 'object', required: ['publisher'],
                    properties: {
                        publisher:      { type: 'string', description: 'Publisher name' },
                        organization:   { type: 'string', description: 'Organization name' },
                        outputDir:      { type: 'string', description: 'Output directory for key files' },
                        force:          { type: 'boolean', default: false },
                        authorPassword: { type: 'string', description: 'OEM author password' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Keypair generated', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object' } } } } } },
                    '400': { description: 'Generation failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        // ---- System Libraries ----
        '/api/system-libraries': {
            get: {
                tags: ['System Libraries'], summary: 'List system libraries', operationId: 'getSystemLibraries',
                description: 'List Hamilton built-in system libraries.',
                responses: { '200': { description: 'System library list', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { type: 'object' } } } } } } } }
            }
        },
        '/api/system-libraries/verify': {
            get: {
                tags: ['System Libraries'], summary: 'Verify system library integrity', operationId: 'verifySyslibHashes',
                description: 'Verify system libraries against the integrity baseline. Equivalent to CLI `verify-syslib-hashes`.',
                parameters: [
                    { name: 'hashFile', in: 'query', schema: { type: 'string' }, description: 'Override baseline file path' },
                    { name: 'libDir',   in: 'query', schema: { type: 'string' }, description: 'Override library directory' }
                ],
                responses: {
                    '200': { description: 'Verification results', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { '$ref': '#/components/schemas/SyslibVerifyResult' } } } } } }
                }
            }
        },
        '/api/system-libraries/generate-hashes': {
            post: {
                tags: ['System Libraries'], summary: 'Generate system library baseline', operationId: 'generateSyslibHashes',
                description: 'Generate integrity baseline for system libraries. Equivalent to CLI `generate-syslib-hashes`.',
                requestBody: { required: true, content: { 'application/json': { schema: {
                    type: 'object', required: ['sourceDir'],
                    properties: {
                        sourceDir: { type: 'string', description: 'Path to known-good Library folder' },
                        output:    { type: 'string', description: 'Output baseline file path' }
                    }
                }}}},
                responses: {
                    '200': { description: 'Baseline generated', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object' } } } } } },
                    '400': { description: 'Generation failed', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Error' } } } }
                }
            }
        },
        // ---- Audit ----
        '/api/audit': {
            get: {
                tags: ['Audit'], summary: 'Get audit trail', operationId: 'getAuditTrail',
                description: 'Retrieve the library management audit trail log.',
                parameters: [
                    { name: 'limit', in: 'query', schema: { type: 'integer' }, description: 'Return only the last N entries' }
                ],
                responses: {
                    '200': { description: 'Audit trail', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'array', items: { '$ref': '#/components/schemas/AuditEntry' } } } } } } }
                }
            }
        },
        // ---- Settings ----
        '/api/settings': {
            get: {
                tags: ['Settings'], summary: 'Get application settings', operationId: 'getSettings',
                description: 'Retrieve the current application settings.',
                responses: {
                    '200': { description: 'Settings', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, data: { type: 'object' } } } } } }
                }
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
var app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS - restricted to localhost origins only
app.use(function(req, res, next) {
    var origin = req.headers.origin || '';
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,X-API-Key');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// API key authentication middleware (timing-safe comparison)
function checkApiKey(req, res, next) {
    if (!API_KEY) return next();
    var key = req.headers['x-api-key'] || '';
    // Constant-time comparison to prevent timing side-channel attacks
    var keyBuf  = Buffer.from(key);
    var expBuf  = Buffer.from(API_KEY);
    if (keyBuf.length !== expBuf.length || !crypto.timingSafeEqual(keyBuf, expBuf)) {
        return res.status(401).json({ success: false, error: 'Invalid or missing API key' });
    }
    next();
}

app.use('/api', checkApiKey);

// Swagger UI (also protected by API key when enabled)
app.use('/docs', checkApiKey, swaggerUi.serve, swaggerUi.setup(openApiSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'Library Manager for Venus 6 - REST API Docs'
}));
app.get('/api-docs', checkApiKey, function(req, res) { res.json(openApiSpec); });

// ---------------------------------------------------------------------------
// Helper: wrap service calls with mutex for mutating operations
// ---------------------------------------------------------------------------
/**
 * Sanitize a string for use in Content-Disposition header filenames.
 * Strips characters that could enable HTTP header injection.
 */
function sanitizeFilename(name) {
    if (!name || typeof name !== 'string') return 'file';
    return name.replace(/[\r\n"\\]/g, '_').replace(/[^a-zA-Z0-9._\- ]/g, '_');
}

/**
 * Sanitize error messages to avoid leaking internal paths or stack traces.
 */
function sanitizeErrorMessage(msg) {
    if (!msg || typeof msg !== 'string') return 'Internal server error';
    // Strip absolute filesystem paths (Windows and Unix)
    return msg.replace(/[A-Za-z]:\\[^"'\s,;]+/g, '[path]')
              .replace(/\/[^\s"',;]+\/[^\s"',;]+/g, '[path]');
}

/**
 * Send a service result as a JSON response with appropriate HTTP status.
 * @param {object} res - Express response object.
 * @param {object} result - Service result with `success`, `error`, and optional `warnings`.
 * @param {number} [successStatus=200] - HTTP status for success.
 * @param {number} [errorStatus=400] - HTTP status for errors (auto-set to 404 for 'not found').
 */
function sendResult(res, result, successStatus, errorStatus) {
    if (result.success) {
        res.status(successStatus || 200).json(result);
    } else {
        var status = errorStatus || 400;
        if (result.error && result.error.indexOf('not found') !== -1) status = 404;
        // Sanitize error before sending to client
        var safeResult = { success: false, error: sanitizeErrorMessage(result.error) };
        if (result.warnings) safeResult.warnings = result.warnings;
        res.status(status).json(safeResult);
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Health
app.get('/api/health', function(req, res) {
    res.json({
        status: 'ok', version: '1.6.5',
        uptime: process.uptime()
    });
});

// List libraries
app.get('/api/libraries', function(req, res) {
    try {
        var ctx = service.createContext();
        var result = service.listLibraries(ctx, { includeDeleted: req.query.includeDeleted === 'true' });
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Get single library
app.get('/api/libraries/:nameOrId', function(req, res) {
    try {
        var ctx = service.createContext();
        var result = service.getLibrary(ctx, req.params.nameOrId);
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Import library (file upload)
app.post('/api/libraries/import', upload.single('package'), function(req, res) {
    acquireMutex().then(function() {
        try {
            if (!req.file) { releaseMutex(); return res.status(400).json({ success: false, error: 'No package file uploaded' }); }
            var ctx = service.createContext();
            var result = service.importLibrary(ctx, {
                filePath:       req.file.path,
                force:          req.body.force === 'true',
                noGroup:        req.body.noGroup === 'true',
                noCache:        req.body.noCache === 'true',
                authorPassword: req.body.authorPassword || null
            });
            // Clean up uploaded file
            try { fs.unlinkSync(req.file.path); } catch(_){}
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// Import archive (file upload)
app.post('/api/libraries/import-archive', upload.single('archive'), function(req, res) {
    acquireMutex().then(function() {
        try {
            if (!req.file) { releaseMutex(); return res.status(400).json({ success: false, error: 'No archive file uploaded' }); }
            var ctx = service.createContext();
            var result = service.importArchive(ctx, {
                filePath:       req.file.path,
                force:          req.body.force === 'true',
                noGroup:        req.body.noGroup === 'true',
                noCache:        req.body.noCache === 'true',
                authorPassword: req.body.authorPassword || null
            });
            try { fs.unlinkSync(req.file.path); } catch(_){}
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// Export library (binary download)
app.get('/api/libraries/:nameOrId/export', function(req, res) {
    try {
        var ctx = service.createContext();
        var tempPath = path.join(UPLOAD_DIR, 'export_' + Date.now() + '.hxlibpkg');
        var result = service.exportLibrary(ctx, { name: req.params.nameOrId, output: tempPath });
        if (!result.success) { return sendResult(res, result); }
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', 'attachment; filename="' + sanitizeFilename(result.data.libraryName || 'library') + '.hxlibpkg"');
        var stream = fs.createReadStream(tempPath);
        stream.pipe(res);
        stream.on('end', function() { try { fs.unlinkSync(tempPath); } catch(_){} });
        stream.on('close', function() { try { fs.unlinkSync(tempPath); } catch(_){} });
        stream.on('error', function(err) {
            try { fs.unlinkSync(tempPath); } catch(_){}
            if (!res.headersSent) res.status(500).json({ success: false, error: 'Export stream error' });
            else res.end();
        });
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Export archive (binary download)
app.post('/api/libraries/export-archive', function(req, res) {
    try {
        var ctx = service.createContext();
        var tempPath = path.join(UPLOAD_DIR, 'archive_' + Date.now() + '.hxlibarch');
        var result = service.exportArchive(ctx, {
            all:   req.body.all,
            names: req.body.names,
            ids:   req.body.ids,
            output: tempPath
        });
        if (!result.success) { return sendResult(res, result); }
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', 'attachment; filename="libraries.hxlibarch"');
        var stream = fs.createReadStream(tempPath);
        stream.pipe(res);
        stream.on('end', function() { try { fs.unlinkSync(tempPath); } catch(_){} });
        stream.on('close', function() { try { fs.unlinkSync(tempPath); } catch(_){} });
        stream.on('error', function(err) {
            try { fs.unlinkSync(tempPath); } catch(_){}
            if (!res.headersSent) res.status(500).json({ success: false, error: 'Export stream error' });
            else res.end();
        });
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Delete library
app.delete('/api/libraries/:nameOrId', function(req, res) {
    acquireMutex().then(function() {
        try {
            var ctx = service.createContext();
            var body = req.body || {};
            var result = service.deleteLibrary(ctx, {
                name:      req.params.nameOrId,
                hard:      body.hard === true,
                keepFiles: body.keepFiles === true
            });
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// List cached versions
app.get('/api/libraries/:name/versions', function(req, res) {
    try {
        var ctx = service.createContext();
        var result = service.listVersions(ctx, { name: req.params.name });
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Rollback
app.post('/api/libraries/:name/rollback', function(req, res) {
    acquireMutex().then(function() {
        try {
            var ctx = service.createContext();
            var body = req.body || {};
            var result = service.rollbackLibrary(ctx, {
                name:           req.params.name,
                version:        body.version,
                index:          body.index,
                noGroup:        body.noGroup === true,
                authorPassword: body.authorPassword || null
            });
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// Create package
app.post('/api/packages/create', function(req, res) {
    acquireMutex().then(function() {
        try {
            var ctx = service.createContext();
            var body = req.body || {};
            var result = service.createPackage(ctx, {
                specPath:       body.specPath,
                output:         body.output,
                signKey:        body.signKey,
                signCert:       body.signCert,
                authorPassword: body.authorPassword
            });
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// Verify package
app.post('/api/packages/verify', upload.single('package'), function(req, res) {
    try {
        var filePath = (req.body && req.body.filePath) ? req.body.filePath : (req.file ? req.file.path : null);
        if (!filePath) return res.status(400).json({ success: false, error: 'No package file provided' });
        var ctx = service.createContext();
        var result = service.verifyPackage(ctx, { filePath: filePath });
        if (req.file) { try { fs.unlinkSync(req.file.path); } catch(_){} }
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// List publishers
app.get('/api/publishers', function(req, res) {
    try {
        var ctx = service.createContext();
        var result = service.listPublishers(ctx);
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Generate keypair (mutex-protected; involves state mutation)
app.post('/api/publishers/generate-keypair', function(req, res) {
    acquireMutex().then(function() {
        try {
            var ctx = service.createContext();
            var body = req.body || {};
            var result = service.generateKeypair(ctx, {
                publisher:      body.publisher,
                organization:   body.organization,
                outputDir:      body.outputDir,
                force:          body.force === true,
                authorPassword: body.authorPassword
            });
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// System libraries
app.get('/api/system-libraries', function(req, res) {
    try {
        var result = service.getSystemLibraries();
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Verify system library hashes
app.get('/api/system-libraries/verify', function(req, res) {
    try {
        var ctx = service.createContext();
        var result = service.verifySyslibHashes(ctx, { hashFile: req.query.hashFile, libDir: req.query.libDir });
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Generate system library hashes (mutex-protected; writes baseline file)
app.post('/api/system-libraries/generate-hashes', function(req, res) {
    acquireMutex().then(function() {
        try {
            var ctx = service.createContext();
            var body = req.body || {};
            var result = service.generateSyslibHashes(ctx, { sourceDir: body.sourceDir, output: body.output });
            releaseMutex();
            sendResult(res, result);
        } catch(e) { releaseMutex(); res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
    });
});

// Audit trail
app.get('/api/audit', function(req, res) {
    try {
        var ctx = service.createContext();
        var limit = null;
        if (req.query.limit) {
            limit = parseInt(req.query.limit, 10);
            if (isNaN(limit) || limit < 1) {
                return res.status(400).json({ success: false, error: 'limit must be a positive integer' });
            }
        }
        var result = service.getAuditTrail(ctx, { limit: limit });
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// Settings
app.get('/api/settings', function(req, res) {
    try {
        var ctx = service.createContext();
        var result = service.getSettings(ctx);
        sendResult(res, result);
    } catch(e) { res.status(500).json({ success: false, error: sanitizeErrorMessage(e.message) }); }
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
app.listen(API_PORT, API_HOST, function() {
    console.log('');
    console.log('  Library Manager for Venus 6 - REST API Server v1.6.5');
    console.log('  ====================================================');
    console.log('  Listening:    http://' + API_HOST + ':' + API_PORT);
    console.log('  Swagger UI:   http://' + API_HOST + ':' + API_PORT + '/docs');
    console.log('  OpenAPI spec: http://' + API_HOST + ':' + API_PORT + '/api-docs');
    console.log('  API Key:      ' + (API_KEY ? 'ENABLED' : 'DISABLED (open access)'));
    console.log('');
});

module.exports = app;
