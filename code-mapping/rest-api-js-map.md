# Code Map: rest-api.js

**File**: `rest-api.js` | **Lines**: 928 | **Purpose**: REST API server with Swagger UI

## Imports

| Line | Module | Alias |
|------|--------|-------|
| L24  | `express` | `express` |
| L25  | `path` | `path` |
| L26  | `fs` | `fs` |
| L27  | `os` | `os` |
| L28  | `crypto` | `crypto` |
| L29  | `multer` | `multer` |
| L30  | `swagger-ui-express` | `swaggerUi` |
| L31  | `./lib/service` | `service` |

## Constants

| Line | Name | Value |
|------|------|-------|
| L50  | `API_PORT` | `parseInt(cliArgs.port) || 5555` |
| L51  | `API_HOST` | `cliArgs.host || '127.0.0.1'` |
| L52  | `API_KEY` | `cliArgs['api-key'] || null` |
| L58  | `UPLOAD_DIR` | `os.tmpdir()/venus-libmgr-uploads` |
| L61  | `upload` | multer instance (500 MB limit) |

## Functions

| Line | Function | Purpose |
|------|----------|---------|
| L38  | `parseArgs(argv)` | CLI argument parser |
| L69  | `acquireMutex()` | Promise-based mutex for diskdb concurrency |
| L76  | `releaseMutex()` | Release mutex, dequeue next waiter |
| L585 | `checkApiKey(req, res, next)` | Express middleware — timing-safe API key check |
| L605 | `sanitizeFilename(name)` | Strip unsafe chars for Content-Disposition |
| L613 | `sanitizeErrorMessage(msg)` | Strip filesystem paths from error messages |
| L620 | `sendResult(res, result, successStatus, errorStatus)` | Standardized JSON response |

## Middleware Stack

| Line | Middleware | Purpose |
|------|-----------|---------|
| L573 | `express.json({limit:'50mb'})` | JSON body parser |
| L574 | `express.urlencoded()` | URL-encoded parser |
| L577 | CORS handler | Restricts origin to localhost/127.0.0.1 |
| L593 | `checkApiKey` on `/api` | API key gate |
| L596 | Swagger UI on `/docs` | Interactive API docs |
| L600 | `/api-docs` GET | Raw OpenAPI JSON |

## Route Handlers → Service Mapping

| Method | Route | Line | Mutex | Service Call |
|--------|-------|------|-------|-------------|
| GET | `/api/health` | L633 | No | inline (returns uptime/version/hostname) |
| GET | `/api/libraries` | L642 | No | `service.listLibraries(ctx, opts)` |
| GET | `/api/libraries/:nameOrId` | L651 | No | `service.getLibrary(ctx, nameOrId)` |
| POST | `/api/libraries/import` | L659 | Yes | `service.importLibrary(ctx, opts)` |
| POST | `/api/libraries/import-archive` | L681 | Yes | `service.importArchive(ctx, opts)` |
| GET | `/api/libraries/:nameOrId/export` | L700 | No | `service.exportLibrary(ctx, opts)` |
| POST | `/api/libraries/export-archive` | L717 | No | `service.exportArchive(ctx, opts)` |
| DELETE | `/api/libraries/:nameOrId` | L752 | Yes | `service.deleteLibrary(ctx, opts)` |
| GET | `/api/libraries/:name/versions` | L770 | No | `service.listVersions(ctx, opts)` |
| POST | `/api/libraries/:name/rollback` | L779 | Yes | `service.rollbackLibrary(ctx, opts)` |
| POST | `/api/packages/create` | L798 | Yes | `service.createPackage(ctx, opts)` |
| POST | `/api/packages/verify` | L816 | No | `service.verifyPackage(ctx, opts)` |
| GET | `/api/publishers` | L827 | No | `service.listPublishers(ctx)` |
| POST | `/api/publishers/generate-keypair` | L835 | Yes | `service.generateKeypair(ctx, opts)` |
| GET | `/api/system-libraries` | L854 | No | `service.getSystemLibraries()` |
| GET | `/api/system-libraries/verify` | L862 | No | `service.verifySyslibHashes(ctx, opts)` |
| POST | `/api/system-libraries/generate-hashes` | L870 | Yes | `service.generateSyslibHashes(ctx, opts)` |
| GET | `/api/audit` | L883 | No | `service.getAuditTrail(ctx, opts)` |
| GET | `/api/settings` | L897 | No | `service.getSettings(ctx)` |

## OpenAPI Spec

Inline at L86. Defines schemas: `Error`, `Library`, `CachedVersion`, `VerificationResult`,
`ImportResult`, `ExportResult`, `DeleteResult`, `AuditEntry`, `Publisher`, `SyslibVerifyResult`.

## Notes

- `trustPublisher` is exported from service.js but NOT exposed via REST
- `crypto` is imported but only used indirectly via `checkApiKey` (timing-safe compare)
- Uploaded temp files are cleaned up in a `finally` block after import operations
- Export routes stream the binary file directly as `application/octet-stream`
