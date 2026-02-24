/**
 * build_icons.js — High-quality icon generation pipeline
 * ========================================================
 * Uses sharp to render the SVG at maximum quality into multiple PNG sizes,
 * then builds a comprehensive multi-resolution ICO for the .exe,
 * and applies it with rcedit.
 *
 * Usage:  node build_icons.js
 *
 * Prerequisites (already in package.json):
 *   npm install sharp
 *   npm install --save-dev rcedit
 */

const sharp = require("sharp");
const fs = require("fs");
const path = require("path");

// ── Configuration ──────────────────────────────────────────────
const SVG_SOURCE = path.join(__dirname, "VenusLibraryManager.svg");
const ICONS_DIR = path.join(__dirname, "icons");
const OUTPUT_ICO = path.join(__dirname, "VenusLibraryManager.ico");
const OUTPUT_PNG = path.join(__dirname, "VenusLibraryManager.png");
const EXE_PATH = path.join(__dirname, "Library Manager.exe");

// Master render size — render SVG at this resolution first, then downscale.
// The SVG is 2000x2000; we render at 2x density to get a 4000px intermediate,
// then downscale to master size with lanczos3 for pristine results.
const MASTER_SIZE = 2048;

// All PNG sizes to generate (used for ICO layers + general use)
// Windows ICO standard sizes + extra HiDPI sizes
const ICO_SIZES = [
  1024, 768, 512, 384, 256, 192, 152, 144, 128, 96, 80, 72, 64, 60, 48, 40,
  36, 32, 24, 20, 16,
];

// The PNG size used for the NW.js window icon (package.json "icon")
const WINDOW_ICON_SIZE = 1024;

// ── Helpers ────────────────────────────────────────────────────

/** Render SVG to a high-res PNG buffer using sharp */
async function renderSvgToMaster() {
  console.log(`\n[1/5] Rendering SVG → ${MASTER_SIZE}x${MASTER_SIZE} master PNG...`);

  const svgBuffer = fs.readFileSync(SVG_SOURCE);

  // Render at 2x density (144 DPI) for a high-quality intermediate,
  // then resize down to master size with lanczos3 for best downsampling.
  const masterBuffer = await sharp(svgBuffer, { density: 144 })
    .resize(MASTER_SIZE, MASTER_SIZE, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 },
      kernel: sharp.kernel.lanczos3,
    })
    .png({ compressionLevel: 0 }) // lossless, no compression artifacts
    .toBuffer();

  console.log(`    Master buffer: ${(masterBuffer.length / 1024).toFixed(1)} KB`);
  return masterBuffer;
}

/** Generate individual PNG files at all required sizes */
async function generatePngs(masterBuffer) {
  console.log(`\n[2/5] Generating ${ICO_SIZES.length} PNG sizes...`);

  // Ensure icons directory exists
  if (!fs.existsSync(ICONS_DIR)) {
    fs.mkdirSync(ICONS_DIR, { recursive: true });
  }

  const pngBuffers = {};

  for (const size of ICO_SIZES) {
    let pipeline = sharp(masterBuffer).resize(size, size, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 },
      kernel: sharp.kernel.lanczos3,
    });

    // Apply subtle sharpening for smaller sizes to keep them crisp
    if (size <= 32) {
      pipeline = pipeline.sharpen({ sigma: 1.0, m1: 1.5, m2: 0.7 });
    } else if (size <= 64) {
      pipeline = pipeline.sharpen({ sigma: 0.8, m1: 1.0, m2: 0.5 });
    } else if (size <= 128) {
      pipeline = pipeline.sharpen({ sigma: 0.5, m1: 0.8, m2: 0.3 });
    }

    const pngBuffer = await pipeline
      .png({ compressionLevel: 9, adaptiveFiltering: true })
      .toBuffer();

    pngBuffers[size] = pngBuffer;

    const outPath = path.join(ICONS_DIR, `icon-${size}x${size}.png`);
    fs.writeFileSync(outPath, pngBuffer);
    console.log(`    ${String(size).padStart(4)}x${String(size).padEnd(4)}  ${(pngBuffer.length / 1024).toFixed(1).padStart(8)} KB`);
  }

  return pngBuffers;
}

/** Generate the NW.js window icon PNG at high resolution */
async function generateWindowPng(masterBuffer) {
  console.log(`\n[3/5] Generating window icon PNG (${WINDOW_ICON_SIZE}x${WINDOW_ICON_SIZE})...`);

  await sharp(masterBuffer)
    .resize(WINDOW_ICON_SIZE, WINDOW_ICON_SIZE, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 },
      kernel: sharp.kernel.lanczos3,
    })
    .png({ compressionLevel: 6 })
    .toFile(OUTPUT_PNG);

  const stats = fs.statSync(OUTPUT_PNG);
  console.log(`    Saved: ${OUTPUT_PNG}`);
  console.log(`    Size:  ${(stats.size / 1024).toFixed(1)} KB`);
}

/**
 * Build a multi-resolution ICO file.
 *
 * ICO format spec (simplified):
 * - Header: 6 bytes (reserved=0, type=1 for ICO, count)
 * - Directory entries: 16 bytes each
 * - Image data: PNG-compressed for each layer
 *
 * Using PNG-compressed layers (supported since Windows Vista) gives
 * maximum quality at every size. This is what modern tools produce.
 */
function buildIco(pngBuffers) {
  console.log(`\n[4/5] Building multi-resolution ICO...`);

  // ICO can include sizes up to 256x256 in the standard format.
  // Sizes > 256 are encoded as 0 in the directory entry (meaning 256).
  // In practice, Windows only reads up to 256x256 from ICO files.
  // We include all sizes up to 256 for maximum compatibility.
  const icoSizes = ICO_SIZES.filter((s) => s <= 256);

  const numImages = icoSizes.length;

  // ICO Header: 6 bytes
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // Reserved
  header.writeUInt16LE(1, 2); // Type: 1 = ICO
  header.writeUInt16LE(numImages, 4); // Number of images

  // Directory entries: 16 bytes each
  const dirSize = numImages * 16;
  const directory = Buffer.alloc(dirSize);

  // Calculate data offset (after header + directory)
  let dataOffset = 6 + dirSize;

  // Collect PNG data buffers in order
  const imageDataBuffers = [];

  for (let i = 0; i < numImages; i++) {
    const size = icoSizes[i];
    const pngData = pngBuffers[size];

    const entryOffset = i * 16;

    // Width (0 means 256)
    directory.writeUInt8(size >= 256 ? 0 : size, entryOffset + 0);
    // Height (0 means 256)
    directory.writeUInt8(size >= 256 ? 0 : size, entryOffset + 1);
    // Color palette (0 = no palette)
    directory.writeUInt8(0, entryOffset + 2);
    // Reserved
    directory.writeUInt8(0, entryOffset + 3);
    // Color planes (1 for ICO)
    directory.writeUInt16LE(1, entryOffset + 4);
    // Bits per pixel (32 for RGBA)
    directory.writeUInt16LE(32, entryOffset + 6);
    // Size of image data
    directory.writeUInt32LE(pngData.length, entryOffset + 8);
    // Offset of image data from beginning of file
    directory.writeUInt32LE(dataOffset, entryOffset + 12);

    imageDataBuffers.push(pngData);
    dataOffset += pngData.length;
  }

  // Concatenate everything
  const icoBuffer = Buffer.concat([header, directory, ...imageDataBuffers]);

  fs.writeFileSync(OUTPUT_ICO, icoBuffer);
  const stats = fs.statSync(OUTPUT_ICO);
  console.log(`    Saved: ${OUTPUT_ICO}`);
  console.log(`    Size:  ${(stats.size / 1024).toFixed(1)} KB`);
  console.log(`    Layers: ${numImages}`);
  console.log(`    Sizes:  ${icoSizes.join(", ")}`);
  console.log(`    Format: PNG-compressed (Vista+ standard, maximum quality)`);
}

/** Apply the ICO to the .exe using rcedit */
async function applyToExe() {
  console.log(`\n[5/5] Applying ICO to .exe...`);

  if (!fs.existsSync(EXE_PATH)) {
    console.log(`    [SKIP] .exe not found: ${EXE_PATH}`);
    return;
  }

  if (!fs.existsSync(OUTPUT_ICO)) {
    console.log(`    [SKIP] ICO not found: ${OUTPUT_ICO}`);
    return;
  }

  try {
    const rcedit = require("rcedit");
    await rcedit(EXE_PATH, { icon: OUTPUT_ICO });
    console.log(`    Applied icon to: ${EXE_PATH}`);
    console.log(`    The .exe will now show the crisp, high-res icon in Explorer.`);
  } catch (err) {
    console.error(`    [ERROR] rcedit failed: ${err.message}`);
    console.log(`    You can manually apply with: npx rcedit "${EXE_PATH}" --icon "${OUTPUT_ICO}"`);
  }
}

// ── Main ───────────────────────────────────────────────────────
async function main() {
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║   Venus Library Manager — Icon Build Pipeline       ║");
  console.log("╚══════════════════════════════════════════════════════╝");
  console.log(`\nSource SVG:  ${SVG_SOURCE}`);
  console.log(`Master size: ${MASTER_SIZE}x${MASTER_SIZE}`);
  console.log(`ICO sizes:   ${ICO_SIZES.length} layers`);

  // Step 1: Render SVG at ultra-high resolution
  const masterBuffer = await renderSvgToMaster();

  // Step 2: Generate all PNG sizes
  const pngBuffers = await generatePngs(masterBuffer);

  // Step 3: Generate the NW.js window icon
  await generateWindowPng(masterBuffer);

  // Step 4: Build ICO with all sizes ≤256
  buildIco(pngBuffers);

  // Step 5: Apply to .exe
  await applyToExe();

  console.log("\n══════════════════════════════════════════════════════");
  console.log("  DONE! All icons generated successfully.");
  console.log("══════════════════════════════════════════════════════");
  console.log(`\n  ICO file:     ${OUTPUT_ICO}`);
  console.log(`  Window PNG:   ${OUTPUT_PNG}`);
  console.log(`  All PNGs:     ${ICONS_DIR}/`);
  console.log(`  Sizes in ICO: ${ICO_SIZES.filter((s) => s <= 256).join(", ")}`);
  console.log("");
}

main().catch((err) => {
  console.error("\n[FATAL ERROR]", err);
  process.exit(1);
});
