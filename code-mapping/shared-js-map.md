# Code Map: lib/shared.js

**File**: `lib/shared.js` | **Lines**: 1821 | **Purpose**: Shared crypto, validation, signing, HSL parsing

## Imports

| Line | Module |
|------|--------|
| L19  | `path` |
| L20  | `fs` |
| L21  | `crypto` |
| L22  | `os` |

## Constants

| Line | Name | Value/Purpose |
|------|------|---------------|
| L29  | `FORMAT_VERSION` | `'2.0'` — current manifest format version |
| L32  | `VALID_LINEAGE_EVENTS` | `['created', 'exported', 'repackaged']` |
| L38  | `KNOWN_MANIFEST_KEYS` | Array of known manifest fields |
| L51  | `KNOWN_LIB_DB_KEYS` | Array of known DB record fields |
| L63  | `HASH_EXTENSIONS` | `['.hsl', '.hs_', '.sub']` |
| L66  | `HSL_METADATA_EXTS` | `['.hsl', '.hs_', '.smt']` |
| L69  | `IMAGE_MIME_MAP` | File extension → MIME type mapping |
| L97  | `PKG_SIGNING_KEY` | HMAC key for tamper detection (embedded) |
| L123 | `CERT_FORMAT_VERSION` | `'hxlibpkg-publisher-cert/1.0'` |
| L272 | `CONTAINER_MAGIC_PKG` | 8-byte magic for .hxlibpkg |
| L275 | `CONTAINER_MAGIC_ARC` | 8-byte magic for .hxlibarch |
| L278 | `CONTAINER_SCRAMBLE_KEY` | 32-byte XOR key |
| L286 | `CONTAINER_HEADER_SIZE` | 48 bytes |
| L726 | `AUTHOR_MIN_LENGTH` | 3 |
| L727 | `AUTHOR_MAX_LENGTH` | 29 |
| L739 | `RESTRICTED_AUTHOR_KEYWORDS` | Array of restricted OEM author keywords |
| L887 | `OEM_AUTHOR_PASSWORD_HASH` | SHA-256 hash of OEM password |
| L915 | `RESERVED_TAGS` | `['system', 'hamilton', 'oem', 'stared', 'starred', ...]` |
| L940 | `TAG_MIN_LENGTH` | 2 |
| L941 | `TAG_MAX_LENGTH` | 24 |
| L942 | `TAG_MAX_COUNT` | 12 |
| L943 | `TAG_UNDERSCORE_EXCEPTIONS` | `['ml_star']` |
| L1138 | `RESERVED_GROUP_NAMES` | Array of reserved group name strings |

## Functions

### Crypto / Key Management
| Line | Function | Purpose |
|------|----------|---------|
| L130 | `generateSigningKeyPair()` | Generate Ed25519 keypair |
| L153 | `computeKeyFingerprint(publicKeyRaw)` | SHA-256 fingerprint of raw Ed25519 key |
| L166 | `buildPublisherCertificate(publisher, org, pubKeyRaw)` | Build certificate object |
| L186 | `ed25519Sign(data, privateKeyPem)` | Sign data with Ed25519 private key |
| L200 | `ed25519Verify(data, signatureB64, publicKeyB64)` | Verify Ed25519 signature |
| L221 | `validatePublisherCertificate(cert)` | Validate certificate structure |

### Binary Container Format
| Line | Function | Purpose |
|------|----------|---------|
| L299 | `packContainer(zipBuffer, magic)` | Wrap ZIP in binary container (XOR + HMAC) |
| L331 | `unpackContainer(containerBuffer, magic)` | Unwrap binary container, verify HMAC |

### HTML / Safety
| Line | Function | Purpose |
|------|----------|---------|
| L378 | `escapeHtml(str)` | XSS-safe HTML escaping |
| L400 | `safeZipExtractPath(baseDir, fname)` | Prevent path traversal in ZIP extraction |
| L420 | `isValidLibraryName(name)` | Validate library name for filesystem safety |

### Integrity Hashing
| Line | Function | Purpose |
|------|----------|---------|
| L448 | `computeFileHash(filePath)` | SHA-256 hash (skips last line for HSL files) |
| L481 | `computeLibraryHashes(libraryFiles, libBasePath, comDlls)` | Hash all tracked library files |
| L504 | `parseHslMetadataFooter(filePath)` | Parse Hamilton $$author$$valid$$time$$ footer |

### Package Signing (HMAC)
| Line | Function | Purpose |
|------|----------|---------|
| L542 | `computeZipEntryHashes(zip)` | SHA-256 hashes of all ZIP entries → sorted JSON |
| L568 | `signPackageZipWithCert(zip, privateKeyPem, certObj)` | Ed25519 + HMAC signature (v2.0) |
| L616 | `verifyPackageSignature(zip)` | Full verification (HMAC + Ed25519 + OEM badge) |

### OEM Author Protection
| Line | Function | Purpose |
|------|----------|---------|
| L739 | `RESTRICTED_AUTHOR_KEYWORDS` | Array of restricted OEM keywords |
| L783 | `isRestrictedAuthor(author)` | Check if author name is restricted |
| L799 | `getMatchedRestrictedKeywords(author)` | Get which keywords matched |
| L830 | `validateOemCertificateMatch(author, org, cert)` | Validate OEM package has matching cert |
| L895 | `validateAuthorPassword(password)` | Validate OEM password (SHA-256 compare) |

### Tag Validation
| Line | Function | Purpose |
|------|----------|---------|
| L950 | `isNumericOnlyTag(tag)` | Check if tag is numeric-only |
| L960 | `canonicalizeTagForDedup(tag)` | Normalize tag for deduplication |
| L969 | `buildTagBlockReason(code)` | Human-readable tag rejection reason |
| L992 | `sanitizeTagDetailed(tag)` | Detailed validation result with error codes |
| L1101 | `sanitizeTagsWithFeedback(tags)` | Batch validation with per-tag feedback |
| L1138 | `RESERVED_GROUP_NAMES` | Array of reserved group names |
| L1148 | `isReservedGroupName(name)` | Check if group name matches a reserved tag |
| L1160 | `isReservedTag(tag)` | Check if tag is reserved |
| L1173 | `filterReservedTags(tags)` | Remove reserved tags from array |
| L1196 | `sanitizeTag(tag)` | Sanitize and validate a single tag string |
| L1207 | `sanitizeTags(tags)` | Sanitize array of tags |

### GitHub URL Validation
| Line | Function | Purpose |
|------|----------|---------|
| L1267 | `validateGitHubRepoUrl(url)` | Validate and normalize GitHub repository URL |

### HSL Parsing
| Line | Function | Purpose |
|------|----------|---------|
| L1458 | `sanitizeHslForParsing(text)` | Strip strings/comments from HSL source |
| L1508 | `splitHslArgs(paramList)` | Split HSL function argument lists |
| L1528 | `parseHslParameter(param)` | Parse single HSL parameter declaration |
| L1552 | `extractHslDocComment(originalLines, funcStartLine)` | Extract doc comment above function |
| L1595 | `parseHslFunctions(text, fileName)` | Parse all function declarations from HSL |
| L1693 | `extractPublicFunctions(libFiles, libBasePath)` | Extract public functions from library files |
| L1724 | `extractHslIncludes(text)` | Extract #include targets from HSL source |

### Utility
| Line | Function | Purpose |
|------|----------|---------|
| L1393 | `getAppVersion()` | Get app version from package.json |
| L1414 | `getWindowsVersion()` | Get Windows OS version string |
| L1430 | `buildLineageEvent(eventType, opts)` | Build a package lineage event record |

## Exports (L1737)

All of the above functions and constants are exported via `module.exports`. Key exports:
`FORMAT_VERSION`, `VALID_LINEAGE_EVENTS`, `KNOWN_MANIFEST_KEYS`, `KNOWN_LIB_DB_KEYS`,
`HASH_EXTENSIONS`, `HSL_METADATA_EXTS`, `IMAGE_MIME_MAP`,
`AUTHOR_MIN_LENGTH`, `AUTHOR_MAX_LENGTH`, `RESTRICTED_AUTHOR_KEYWORDS`,
`CONTAINER_MAGIC_PKG`, `CONTAINER_MAGIC_ARC`, `CONTAINER_HEADER_SIZE`,
`CERT_FORMAT_VERSION`, `RESERVED_TAGS`, `RESERVED_GROUP_NAMES`,
`TAG_MIN_LENGTH`, `TAG_MAX_LENGTH`, `TAG_MAX_COUNT`,
`packContainer`, `unpackContainer`, `escapeHtml`, `safeZipExtractPath`,
`isValidLibraryName`, `computeFileHash`, `computeLibraryHashes`,
`parseHslMetadataFooter`, `computeZipEntryHashes`,
`signPackageZipWithCert`, `verifyPackageSignature`,
`validatePublisherCertificate`, `generateSigningKeyPair`,
`buildPublisherCertificate`, `computeKeyFingerprint`, `ed25519Sign`, `ed25519Verify`,
`isRestrictedAuthor`, `getMatchedRestrictedKeywords`, `validateAuthorPassword`,
`validateOemCertificateMatch`, `sanitizeTag`, `sanitizeTagDetailed`, `sanitizeTags`,
`sanitizeTagsWithFeedback`, `filterReservedTags`, `isReservedTag`, `isReservedGroupName`,
`validateGitHubRepoUrl`,
`getAppVersion`, `getWindowsVersion`, `buildLineageEvent`,
`sanitizeHslForParsing`, `splitHslArgs`, `parseHslParameter`, `extractHslDocComment`,
`parseHslFunctions`, `extractPublicFunctions`, `extractHslIncludes`
