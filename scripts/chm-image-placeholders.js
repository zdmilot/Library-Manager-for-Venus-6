#!/usr/bin/env node
/**
 * CHM Image Placeholder Manager
 * 
 * Scans CHM help HTML files for <div class="image-placeholder"> elements,
 * builds a JSON map for managing screenshot images, and can replace
 * placeholders with actual <img> tags.
 *
 * Commands:
 *   scan     - Find all placeholders and write/update chm-image-map.json
 *   check    - Report which images are missing, ready, or unmapped
 *   apply    - Replace placeholders with <img> tags using the map
 *   dry-run  - Show what apply would do without changing files
 */

const fs = require('fs');
const path = require('path');

const CHM_DIR = path.join(__dirname, '..', 'CHM Help Source Files');
const IMAGES_DIR = path.join(CHM_DIR, 'images');
const MAP_FILE = path.join(IMAGES_DIR, 'chm-image-map.json');

const placeholderRegex = /<div\s+class="image-placeholder">([\s\S]*?)<\/div>/gi;

// ── helpers ──

function getHtmlFiles() {
    return fs.readdirSync(CHM_DIR)
        .filter(f => f.endsWith('.html'))
        .map(f => path.join(CHM_DIR, f));
}

function normalizeText(t) {
    return t.replace(/\s+/g, ' ').trim();
}

function loadMap() {
    if (!fs.existsSync(MAP_FILE)) return {};
    return JSON.parse(fs.readFileSync(MAP_FILE, 'utf8'));
}

function saveMap(map) {
    if (!fs.existsSync(IMAGES_DIR)) fs.mkdirSync(IMAGES_DIR, { recursive: true });
    fs.writeFileSync(MAP_FILE, JSON.stringify(map, null, 2) + '\n', 'utf8');
}

// ── scan ──

function scan() {
    const map = loadMap();
    const htmlFiles = getHtmlFiles();
    let found = 0;
    let newEntries = 0;

    htmlFiles.forEach(filePath => {
        const html = fs.readFileSync(filePath, 'utf8');
        const fileName = path.basename(filePath);
        let match;
        placeholderRegex.lastIndex = 0;
        while ((match = placeholderRegex.exec(html)) !== null) {
            const text = normalizeText(match[1]);
            found++;
            if (!map[text]) {
                map[text] = { image: '', file: fileName };
                newEntries++;
            } else if (!map[text].file) {
                map[text].file = fileName;
            }
        }
    });

    saveMap(map);
    console.log(`Scan complete: ${found} placeholders found across ${htmlFiles.length} files.`);
    console.log(`  ${newEntries} new entries added, ${Object.keys(map).length} total in map.`);
    console.log(`  Map saved to: ${MAP_FILE}`);
}

// ── check ──

function check() {
    const map = loadMap();
    const entries = Object.entries(map);
    if (entries.length === 0) {
        console.log('No entries in map. Run "scan" first.');
        return;
    }

    let missing = 0, ready = 0, unmapped = 0;

    entries.forEach(([text, val]) => {
        const img = val.image || '';
        const file = val.file || '?';
        if (!img) {
            unmapped++;
            console.log(`  [UNMAPPED]  ${file}: "${text.substring(0, 60)}..."`);
        } else {
            const imgPath = path.join(IMAGES_DIR, img);
            if (fs.existsSync(imgPath)) {
                ready++;
                console.log(`  [READY]     ${file}: ${img}`);
            } else {
                missing++;
                console.log(`  [MISSING]   ${file}: ${img}`);
            }
        }
    });

    console.log(`\nSummary: ${ready} ready, ${missing} missing, ${unmapped} unmapped (${entries.length} total)`);
}

// ── apply / dry-run ──

function apply(dryRun) {
    const map = loadMap();
    const htmlFiles = getHtmlFiles();
    let applied = 0, skipped = 0;

    htmlFiles.forEach(filePath => {
        let html = fs.readFileSync(filePath, 'utf8');
        let changed = false;

        html = html.replace(placeholderRegex, (fullMatch, innerText) => {
            const text = normalizeText(innerText);
            const entry = map[text];
            if (!entry || !entry.image) {
                skipped++;
                return fullMatch; // keep placeholder
            }
            const imgPath = path.join(IMAGES_DIR, entry.image);
            if (!fs.existsSync(imgPath)) {
                skipped++;
                console.log(`  [SKIP] Image file not found: ${entry.image}`);
                return fullMatch;
            }
            applied++;
            changed = true;
            const alt = text.replace(/PLACE IMAGE OF /i, '').replace(/ HERE$/i, '');
            const imgTag = `<img src="images/${entry.image}" alt="${alt}" class="doc-screenshot">`;
            if (dryRun) {
                console.log(`  [WOULD REPLACE] ${path.basename(filePath)}: "${text.substring(0, 50)}..." → ${entry.image}`);
                return fullMatch; // don't actually change in dry-run
            }
            return imgTag;
        });

        if (changed && !dryRun) {
            fs.writeFileSync(filePath, html, 'utf8');
            console.log(`  [UPDATED] ${path.basename(filePath)}`);
        }
    });

    const verb = dryRun ? 'Would apply' : 'Applied';
    console.log(`\n${verb}: ${applied} replacements, ${skipped} skipped.`);
}

// ── main ──

const cmd = process.argv[2] || 'scan';
switch (cmd) {
    case 'scan':
        scan();
        break;
    case 'check':
        check();
        break;
    case 'apply':
        apply(false);
        break;
    case 'dry-run':
        apply(true);
        break;
    default:
        console.log('Usage: node chm-image-placeholders.js [scan|check|apply|dry-run]');
        process.exit(1);
}
