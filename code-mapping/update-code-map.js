#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Code Map Generator for Library Manager
 *
 * Scans all source files and generates a structured JSON code map at
 * code-mapping/generated-map.json.  This script can be run without an
 * AI agent to keep the code map up to date after edits.
 *
 * Usage:
 *   node code-mapping/update-code-map.js
 *   node code-mapping/update-code-map.js --pretty     (indented output)
 *   node code-mapping/update-code-map.js --summary    (print summary to console)
 *
 * Output: code-mapping/generated-map.json
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration - files to scan
// ---------------------------------------------------------------------------
const PROJECT_ROOT = path.resolve(__dirname, '..');
const OUTPUT_FILE  = path.join(__dirname, 'generated-map.json');

const SOURCE_FILES = [
    'cli.js',
    'com-bridge.js',
    'lib/shared.js',
    'lib/service.js',
    'html/js/main.js',
    'html/js/syscheck-worker.js',
    'com/LibraryManager.cs',
];

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const PRETTY  = args.includes('--pretty');
const SUMMARY = args.includes('--summary');

// ---------------------------------------------------------------------------
// Regex patterns for JavaScript analysis
// ---------------------------------------------------------------------------

/**
 * Match function declarations:
 *   function name(...)
 *   async function name(...)
 *   var/let/const name = function(...)
 *   var/let/const name = async function(...)
 *   name: function(...)
 *   name: async function(...)
 */
const JS_FUNC_PATTERNS = [
    // Standard function declarations
    /^[ \t]*(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/,
    // Variable-assigned functions (arrow or function keyword)
    /^[ \t]*(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(/,
    // Arrow functions assigned to variables
    /^[ \t]*(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?\(?[^)]*\)?\s*=>/,
    // Object property functions
    /^[ \t]*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*(?:async\s+)?function\s*\(/,
    // Method-style object property
    /^[ \t]*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*\{/,
    // Event handlers via jQuery pattern
    /\.\s*on\s*\(\s*['"]([a-zA-Z]+)['"]\s*,\s*['"]([^'"]+)['"]/,
];

/**
 * Match require() statements
 */
const JS_REQUIRE_PATTERN = /(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/;

/**
 * Match constant declarations with simple values
 */
const JS_CONST_PATTERN = /^[ \t]*const\s+([A-Z][A-Z0-9_]*)\s*=\s*(.+?)(?:\s*;?\s*$)/;

/**
 * Match module.exports
 */
const JS_EXPORTS_PATTERN = /module\.exports\s*=/;

/**
 * Match JSDoc @param, @returns
 */
const JS_JSDOC_PARAM = /@param\s*\{([^}]+)\}\s*(\S+)/;
const JS_JSDOC_RETURNS = /@returns?\s*\{([^}]+)\}/;

/**
 * Match section header comments
 */
const JS_SECTION_HEADER = /^\/\/\s*-{5,}/;

// ---------------------------------------------------------------------------
// C# patterns (basic)
// ---------------------------------------------------------------------------
const CS_METHOD_PATTERN  = /^\s*(?:public|private|protected|internal|static|\s)*\s+(?:void|string|int|bool|object|Task|IEnumerable|List|Dictionary|\w+)\s+([A-Z][a-zA-Z0-9_]*)\s*[(<]/;
const CS_CLASS_PATTERN   = /^\s*(?:public|internal)\s+(?:static\s+)?class\s+([a-zA-Z_]\w*)/;

// ---------------------------------------------------------------------------
// Analysis functions
// ---------------------------------------------------------------------------

/**
 * Analyze a JavaScript file and return structured data.
 */
function analyzeJsFile(filePath) {
    const fullPath = path.join(PROJECT_ROOT, filePath);
    if (!fs.existsSync(fullPath)) {
        return { file: filePath, error: 'File not found' };
    }

    const content = fs.readFileSync(fullPath, 'utf8');
    const lines   = content.split('\n');

    const result = {
        file:      filePath,
        lines:     lines.length,
        size:      fs.statSync(fullPath).size,
        modified:  fs.statSync(fullPath).mtime.toISOString(),
        functions: [],
        requires:  [],
        constants: [],
        exports:   null,
        sections:  [],
        jsdocCoverage: { total: 0, documented: 0 },
    };

    let inJsdoc       = false;
    let jsdocLines    = [];
    let jsdocStart    = 0;
    let currentSection = null;

    for (let i = 0; i < lines.length; i++) {
        const line    = lines[i];
        const lineNum = i + 1;

        // Track JSDoc blocks
        if (line.trim().startsWith('/**')) {
            inJsdoc    = true;
            jsdocLines = [line];
            jsdocStart = lineNum;
            continue;
        }
        if (inJsdoc) {
            jsdocLines.push(line);
            if (line.trim().endsWith('*/') || line.trim() === '*/') {
                inJsdoc = false;
            }
            continue;
        }

        // Section headers
        if (JS_SECTION_HEADER.test(line)) {
            const nextLine = (lines[i + 1] || '').trim().replace(/^\/\/\s*/, '');
            if (nextLine && !JS_SECTION_HEADER.test(lines[i + 1] || '')) {
                currentSection = nextLine;
                result.sections.push({ line: lineNum, name: currentSection });
            }
            continue;
        }

        // Require statements
        const reqMatch = line.match(JS_REQUIRE_PATTERN);
        if (reqMatch) {
            result.requires.push({
                line:    lineNum,
                alias:   reqMatch[1],
                module:  reqMatch[2],
            });
            continue;
        }

        // Constants (UPPER_CASE)
        const constMatch = line.match(JS_CONST_PATTERN);
        if (constMatch) {
            const val = constMatch[2].trim();
            // Only capture simple values (not long objects/arrays)
            if (val.length < 120 && !val.startsWith('{') && !val.startsWith('[')) {
                result.constants.push({
                    line:  lineNum,
                    name:  constMatch[1],
                    value: val.replace(/;$/, '').trim(),
                });
            }
            continue;
        }

        // Function declarations
        for (const pattern of JS_FUNC_PATTERNS) {
            const funcMatch = line.match(pattern);
            if (funcMatch) {
                const funcName = funcMatch[1];
                // Skip minified / vendor patterns
                if (funcName && funcName.length > 1 && !/^[a-z]$/.test(funcName)) {
                    const hasJsdoc = jsdocLines.length > 0 &&
                                     lineNum - jsdocStart - jsdocLines.length <= 2;
                    const params = [];
                    if (hasJsdoc) {
                        jsdocLines.forEach(function(jl) {
                            const pm = jl.match(JS_JSDOC_PARAM);
                            if (pm) params.push({ type: pm[1], name: pm[2] });
                        });
                    }
                    result.functions.push({
                        line:       lineNum,
                        name:       funcName,
                        documented: hasJsdoc,
                        section:    currentSection,
                        params:     params.length > 0 ? params : undefined,
                    });
                    result.jsdocCoverage.total++;
                    if (hasJsdoc) result.jsdocCoverage.documented++;
                }
                jsdocLines = [];
                break;
            }
        }

        // Module.exports
        if (JS_EXPORTS_PATTERN.test(line) && !result.exports) {
            // Capture the exports block (up to closing brace or semicolon)
            let exportsBlock = line;
            let j = i + 1;
            while (j < lines.length && !(/};/.test(exportsBlock) || /;\s*$/.test(exportsBlock))) {
                exportsBlock += '\n' + lines[j];
                j++;
                if (j - i > 50) break; // Safety limit
            }
            // Extract exported names
            const exportNames = [];
            const nameRegex = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/g;
            let nm;
            // Skip the "module.exports = {" part
            const body = exportsBlock.replace(/module\.exports\s*=\s*\{?/, '');
            while ((nm = nameRegex.exec(body)) !== null) {
                const n = nm[1];
                if (!['module', 'exports', 'require', 'var', 'const', 'let', 'function',
                       'true', 'false', 'null', 'undefined', 'new', 'this', 'app'].includes(n)) {
                    exportNames.push(n);
                }
            }
            result.exports = {
                line:  lineNum,
                names: [...new Set(exportNames)],
            };
        }
    }

    return result;
}

/**
 * Analyze a C# file (basic method/class extraction).
 */
function analyzeCsFile(filePath) {
    const fullPath = path.join(PROJECT_ROOT, filePath);
    if (!fs.existsSync(fullPath)) {
        return { file: filePath, error: 'File not found' };
    }

    const content = fs.readFileSync(fullPath, 'utf8');
    const lines   = content.split('\n');

    const result = {
        file:     filePath,
        lines:    lines.length,
        size:     fs.statSync(fullPath).size,
        modified: fs.statSync(fullPath).mtime.toISOString(),
        classes:  [],
        methods:  [],
    };

    for (let i = 0; i < lines.length; i++) {
        const line    = lines[i];
        const lineNum = i + 1;

        const classMatch = line.match(CS_CLASS_PATTERN);
        if (classMatch) {
            result.classes.push({ line: lineNum, name: classMatch[1] });
            continue;
        }

        const methodMatch = line.match(CS_METHOD_PATTERN);
        if (methodMatch) {
            result.methods.push({ line: lineNum, name: methodMatch[1] });
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Cross-reference analysis
// ---------------------------------------------------------------------------

/**
 * Build cross-reference map: which functions are called from which files.
 */
function buildCrossReferences(fileResults) {
    const allFunctions = {};
    // Collect all function names and their home files
    fileResults.forEach(function(fr) {
        if (fr.functions) {
            fr.functions.forEach(function(fn) {
                if (!allFunctions[fn.name]) {
                    allFunctions[fn.name] = [];
                }
                allFunctions[fn.name].push(fr.file);
            });
        }
    });

    const crossRefs = {};
    fileResults.forEach(function(fr) {
        if (fr.error) return;
        const fullPath = path.join(PROJECT_ROOT, fr.file);
        const content  = fs.readFileSync(fullPath, 'utf8');
        Object.keys(allFunctions).forEach(function(fnName) {
            // Don't cross-ref a function against its own file
            const homes = allFunctions[fnName];
            if (homes.length === 1 && homes[0] === fr.file) return;
            // Check if this file references the function (simple heuristic)
            const regex = new RegExp('\\b' + fnName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
            if (regex.test(content)) {
                if (!crossRefs[fnName]) crossRefs[fnName] = { definedIn: homes, referencedIn: [] };
                if (!crossRefs[fnName].referencedIn.includes(fr.file)) {
                    crossRefs[fnName].referencedIn.push(fr.file);
                }
            }
        });
    });

    return crossRefs;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
    console.log('Code Map Generator - Library Manager');
    console.log('='.repeat(52));
    console.log('');

    const timestamp = new Date().toISOString();
    const fileResults = [];

    SOURCE_FILES.forEach(function(srcFile) {
        const ext = path.extname(srcFile).toLowerCase();
        process.stdout.write('  Scanning ' + srcFile + '...');

        let result;
        if (ext === '.cs') {
            result = analyzeCsFile(srcFile);
        } else {
            result = analyzeJsFile(srcFile);
        }
        fileResults.push(result);

        if (result.error) {
            console.log(' SKIP (' + result.error + ')');
        } else {
            const funcCount = (result.functions || result.methods || []).length;
            console.log(' ' + result.lines + ' lines, ' + funcCount + ' functions');
        }
    });

    // Build cross-references
    process.stdout.write('\n  Building cross-references...');
    const crossRefs = buildCrossReferences(fileResults);
    console.log(' ' + Object.keys(crossRefs).length + ' cross-file references');

    // Compute summary stats
    let totalLines = 0, totalFunctions = 0, totalDocumented = 0, totalUndocumented = 0;
    fileResults.forEach(function(fr) {
        if (fr.error) return;
        totalLines += fr.lines || 0;
        const fns = fr.functions || fr.methods || [];
        totalFunctions += fns.length;
        if (fr.jsdocCoverage) {
            totalDocumented   += fr.jsdocCoverage.documented;
            totalUndocumented += fr.jsdocCoverage.total - fr.jsdocCoverage.documented;
        }
    });

    const output = {
        _meta: {
            generated:   timestamp,
            generator:   'code-mapping/update-code-map.js',
            projectRoot: PROJECT_ROOT,
            version:     getPackageVersion(),
        },
        summary: {
            totalFiles:            fileResults.filter(function(f) { return !f.error; }).length,
            totalLines:            totalLines,
            totalFunctions:        totalFunctions,
            jsdocCoverage: {
                documented:   totalDocumented,
                undocumented: totalUndocumented,
                percentage:   totalFunctions > 0
                    ? Math.round((totalDocumented / totalFunctions) * 100)
                    : 0,
            },
            crossFileReferences: Object.keys(crossRefs).length,
        },
        files:          fileResults,
        crossReferences: crossRefs,
    };

    // Write output
    const json = JSON.stringify(output, null, PRETTY ? 2 : undefined);
    fs.writeFileSync(OUTPUT_FILE, json, 'utf8');
    console.log('\n  Written to: ' + path.relative(PROJECT_ROOT, OUTPUT_FILE));
    console.log('  Size: ' + (Buffer.byteLength(json) / 1024).toFixed(1) + ' KB');

    if (SUMMARY) {
        console.log('\n  === Summary ===');
        console.log('  Files scanned:      ' + output.summary.totalFiles);
        console.log('  Total lines:        ' + totalLines.toLocaleString());
        console.log('  Total functions:    ' + totalFunctions);
        console.log('  JSDoc coverage:     ' + output.summary.jsdocCoverage.percentage + '%');
        console.log('  Cross-file refs:    ' + output.summary.crossFileReferences);
    }

    console.log('\nDone.\n');
}

/**
 * Read version from package.json
 */
function getPackageVersion() {
    try {
        const pkg = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, 'package.json'), 'utf8'));
        return pkg.version || 'unknown';
    } catch (_) {
        return 'unknown';
    }
}

main();
