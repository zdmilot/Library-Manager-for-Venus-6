# Code Map: lib/shared.js

**File**: `lib/shared.js` | **Lines**: 1915 | **Purpose**: Shared crypto, validation, signing, HSL parsing

## Imports

| Line | Module |
|------|--------|
| L3   | `path` |
| L4   | `fs` |
| L5   | `crypto` |
| L6   | `os` |

## Constants

| Line | Name | Value/Purpose |
|------|------|---------------|
| L29  | `FORMAT_VERSION` | `'2.0'` — current manifest format version |
| L32  | `VALID_LINEAGE_EVENTS` | `['created', 'exported', 'repackaged']` |
| L39  | `KNOWN_MANIFEST_KEYS` | Array of 23 known manifest fields |
| L55  | `KNOWN_LIB_DB_KEYS` | Array of 33 known DB record fields |
| L67  | `HASH_EXTENSIONS` | `['.hsl', '.hs_', '.sub']` |
| L70  | `HSL_METADATA_EXTS` | `['.hsl', '.hs_', '.smt']` |
| L73  | `IMAGE_MIME_MAP` | File extension → MIME type mapping (14 entries) |
| L97  | `PKG_SIGNING_KEY` | HMAC key for tamper detection (embedded) |
| L117 | `CERT_FORMAT_VERSION` | `'hxlibpkg-publisher-cert/1.0'` |
| L269 | `CONTAINER_MAGIC_PKG` | 8-byte magic for .hxlibpkg |
| L272 | `CONTAINER_MAGIC_ARC` | 8-byte magic for .hxlibarch |
| L275 | `CONTAINER_SCRAMBLE_KEY` | 32-byte XOR key |
| L284 | `CONTAINER_HEADER_SIZE` | 48 bytes |
| L970 | `RESTRICTED_AUTHOR_NAMES` | Set of restricted OEM author name patterns |
| L977 | `RESTRICTED_AUTHOR_KEYWORDS` | Array of restricted keywords |
| L985 | `OEM_AUTHOR_PASSWORD_HASH` | SHA-256 hash of OEM password |
| L1035 | `TAG_MIN_LENGTH` | 2 |
| L1036 | `TAG_MAX_LENGTH` | 50 |
| L1037 | `TAG_MAX_COUNT` | 20 |
| L1038 | `RESERVED_TAG_PREFIXES` | `['system-', 'oem-', 'hamilton-']` |
| L1039 | `RESERVED_TAGS` | `['official', 'verified', 'system', ...]` |
| L1041 | `TAG_UNDERSCORE_EXCEPTIONS` | `['ml_star']` |

## Functions

### Crypto / Key Management
| Line | Function | Purpose |
|------|----------|---------|
| L122 | `generateSigningKeyPair()` | Generate Ed25519 keypair |
| L143 | `computeKeyFingerprint(publicKeyRaw)` | SHA-256 fingerprint of raw Ed25519 key |
| L157 | `buildPublisherCertificate(publisher, org, pubKeyRaw)` | Build certificate object |
| L178 | `ed25519Sign(data, privateKeyPem)` | Sign data with Ed25519 private key |
| L193 | `ed25519Verify(data, signatureB64, publicKeyB64)` | Verify Ed25519 signature |
| L216 | `validatePublisherCertificate(cert)` | Validate certificate structure |

### Binary Container Format
| Line | Function | Purpose |
|------|----------|---------|
| L295 | `packContainer(zipBuffer, magic)` | Wrap ZIP in binary container (XOR + HMAC) |
| L323 | `unpackContainer(containerBuffer, magic)` | Unwrap binary container, verify HMAC |

### HTML / Safety
| Line | Function | Purpose |
|------|----------|---------|
| L370 | `escapeHtml(str)` | XSS-safe HTML escaping |
| L386 | `safeZipExtractPath(baseDir, fname)` | Prevent path traversal in ZIP extraction |
| L411 | `isValidLibraryName(name)` | Validate library name for filesystem safety |

### Integrity Hashing
| Line | Function | Purpose |
|------|----------|---------|
| L437 | `computeFileHash(filePath)` | SHA-256 hash (skips last line for HSL files) |
| L469 | `computeLibraryHashes(libraryFiles, libBasePath, comDlls)` | Hash all tracked library files |
| L494 | `parseHslMetadataFooter(filePath)` | Parse Hamilton $$author$$valid$$time$$ footer |

### Package Signing (HMAC)
| Line | Function | Purpose |
|------|----------|---------|
| L535 | `computeZipEntryHashes(zip)` | SHA-256 hashes of all ZIP entries → sorted JSON |
| L551 | `signPackageZip(zip)` | HMAC-SHA256 signature (v1.0 legacy) |
| L575 | `signPackageZipWithCert(zip, privateKeyPem, certObj)` | Ed25519 + HMAC signature (v2.0) |
| L625 | `verifyPackageSignature(zip, trustedCerts)` | Full verification (HMAC + Ed25519 + trust) |

### Certificate Trust Store
| Line | Function | Purpose |
|------|----------|---------|
| L764 | `loadTrustedCertificates(registryPath)` | Load trusted certs from publisher_registry.json |
| L797 | `saveTrustedCertificate(registryPath, cert, opts)` | Save/revoke certificate in registry |

### HSL Parsing
| Line | Function | Purpose |
|------|----------|---------|
| L854 | `sanitizeHslForParsing(text)` | Strip strings/comments from HSL source |
| L919 | `splitHslArgs(argsStr)` | Split HSL function argument lists |
| L938 | `parseHslParameter(paramStr)` | Parse single HSL parameter declaration |
| L962 | `extractHslDocComment(text, funcStartIdx)` | Extract doc comment above function |
| (cont.) | `parseHslFunctions(text)` | Parse all function declarations from HSL |
| (cont.) | `extractPublicFunctions(libPath, filenames)` | Extract public functions from library files |
| (cont.) | `extractHslIncludes(text)` | Extract #include targets from HSL source |

### OEM Author Protection
| Line | Function | Purpose |
|------|----------|---------|
| L970 | `RESTRICTED_AUTHOR_NAMES` | Set of exact restricted names |
| L988 | `isRestrictedAuthor(name)` | Check if author name is restricted |
| L993 | `getMatchedRestrictedKeywords(name)` | Get which keywords matched |
| L998 | `validateAuthorPassword(password)` | Validate OEM password (SHA-256 compare) |
| L1008 | `validateOemCertificateMatch(manifest, sigResult)` | Validate OEM package has matching cert |

### Tag Validation
| Line | Function | Purpose |
|------|----------|---------|
| L1055 | `canonicalizeTagForDedup(tag)` | Normalize tag for deduplication |
| L1059 | `buildTagBlockReason(code)` | Human-readable tag rejection reason |
| L1076 | `sanitizeTag(rawInput)` | Sanitize and validate a single tag string |
| L1116 | `sanitizeTagDetailed(rawInput)` | Detailed validation result with error codes |
| L1154 | `sanitizeTags(rawTags)` | Sanitize array of tags |
| L1165 | `filterReservedTags(tags)` | Remove reserved tags from array |
| L1173 | `isReservedGroupName(name)` | Check if group name matches a reserved tag |

### Utility
| Line | Function | Purpose |
|------|----------|---------|
| L1180 | `getAppVersion()` | Get app version from package.json |
| L1189 | `getWindowsVersion()` | Get Windows OS version string |
| L1198 | `buildLineageEvent(eventType, extras)` | Build a package lineage event record |

## Exports (module.exports)

All of the above functions and constants are exported. Key exports:
`FORMAT_VERSION`, `VALID_LINEAGE_EVENTS`, `KNOWN_MANIFEST_KEYS`, `KNOWN_LIB_DB_KEYS`,
`HASH_EXTENSIONS`, `HSL_METADATA_EXTS`, `IMAGE_MIME_MAP`, `PKG_SIGNING_KEY`,
`OEM_AUTHOR_PASSWORD_HASH`, `CONTAINER_MAGIC_PKG`, `CONTAINER_MAGIC_ARC`,
`packContainer`, `unpackContainer`, `escapeHtml`, `safeZipExtractPath`,
`isValidLibraryName`, `computeFileHash`, `computeLibraryHashes`,
`parseHslMetadataFooter`, `computeZipEntryHashes`, `signPackageZip`,
`signPackageZipWithCert`, `verifyPackageSignature`, `loadTrustedCertificates`,
`saveTrustedCertificate`, `validatePublisherCertificate`, `generateSigningKeyPair`,
`buildPublisherCertificate`, `computeKeyFingerprint`, `ed25519Sign`, `ed25519Verify`,
`sanitizeHslForParsing`, `splitHslArgs`, `parseHslParameter`, `extractHslDocComment`,
`parseHslFunctions`, `extractPublicFunctions`, `extractHslIncludes`,
`isRestrictedAuthor`, `getMatchedRestrictedKeywords`, `validateAuthorPassword`,
`validateOemCertificateMatch`, `sanitizeTag`, `sanitizeTagDetailed`, `sanitizeTags`,
`filterReservedTags`, `isReservedGroupName`, `getAppVersion`, `getWindowsVersion`,
`buildLineageEvent`
