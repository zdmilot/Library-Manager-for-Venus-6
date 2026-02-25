/**
 * build_icons.js — Apply pre-built ICO to the .exe
 * ==================================================
 * Uses resedit/pe-library to fully replace ALL icon resources in
 * the .exe with our single 256×256 ICO. This removes the leftover
 * NW.js/Chromium icons (IDR_MAINFRAME, IDR_X001_APP_LIST, etc.)
 * that would otherwise take priority at smaller display sizes.
 *
 * The ICO contains a single 256×256 PNG-compressed layer (the
 * maximum the ICO format supports). Windows auto-scales it for
 * all display contexts (taskbar, Explorer, desktop, etc.).
 *
 * Usage:  node build_icons.js
 *
 * After running, flush Windows icon cache to see the change:
 *   ie4uinit.exe -show
 *
 * Prerequisites (already in package.json devDependencies):
 *   npm install --save-dev resedit pe-library
 */

const fs = require("fs");
const path = require("path");
const { NtExecutable, NtExecutableResource, Resource } = require("resedit");

// ── Configuration ──────────────────────────────────────────────
const OUTPUT_ICO = path.join(__dirname, "VenusLibraryManager.ico");
const EXE_PATH = path.join(__dirname, "Venus Library Manager.exe");

// ── Helpers ────────────────────────────────────────────────────

/** Parse an ICO file buffer into its raw PNG layer(s) */
function parseIco(icoBuffer) {
  const numImages = icoBuffer.readUInt16LE(4);
  const images = [];
  for (let i = 0; i < numImages; i++) {
    const o = 6 + i * 16;
    const w = icoBuffer[o] === 0 ? 256 : icoBuffer[o];
    const h = icoBuffer[o + 1] === 0 ? 256 : icoBuffer[o + 1];
    const bpp = icoBuffer.readUInt16LE(o + 6);
    const dataSize = icoBuffer.readUInt32LE(o + 8);
    const dataOffset = icoBuffer.readUInt32LE(o + 12);
    const data = icoBuffer.slice(dataOffset, dataOffset + dataSize);
    images.push({ width: w, height: h, bpp, data });
  }
  return images;
}

// ── Main ───────────────────────────────────────────────────────
async function main() {
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║   Venus Library Manager — Apply Icon to .exe        ║");
  console.log("╚══════════════════════════════════════════════════════╝");

  // Validate files exist
  if (!fs.existsSync(EXE_PATH)) {
    console.error(`\n[ERROR] .exe not found: ${EXE_PATH}`);
    process.exit(1);
  }
  if (!fs.existsSync(OUTPUT_ICO)) {
    console.error(`\n[ERROR] ICO not found: ${OUTPUT_ICO}`);
    process.exit(1);
  }

  // Show ICO info
  const icoBuffer = fs.readFileSync(OUTPUT_ICO);
  const icoImages = parseIco(icoBuffer);
  console.log(`\nICO file:  ${OUTPUT_ICO}`);
  console.log(`ICO size:  ${(icoBuffer.length / 1024).toFixed(1)} KB`);
  console.log(`Layers:    ${icoImages.length}`);
  icoImages.forEach((img) => {
    console.log(`           ${img.width}×${img.height}, ${img.bpp}bpp, ${(img.data.length / 1024).toFixed(1)} KB`);
  });

  // Load the .exe
  console.log(`\nTarget:    ${EXE_PATH}`);
  const exeData = fs.readFileSync(EXE_PATH);
  const exe = NtExecutable.from(exeData);
  const res = NtExecutableResource.from(exe);

  // Show existing icon groups before changes
  const existingGroups = Resource.IconGroupEntry.fromEntries(res.entries);
  console.log(`\nExisting icon groups in .exe: ${existingGroups.length}`);
  existingGroups.forEach((group) => {
    const label = typeof group.id === "string" ? group.id : `#${group.id}`;
    group.icons.forEach((icon) => {
      const w = icon.width === 0 ? 256 : icon.width;
      const h = icon.height === 0 ? 256 : icon.height;
      console.log(`  ${label}: ${w}×${h}, ${icon.bitCount}bpp`);
    });
  });

  // Remove ALL existing icon resources (RT_ICON=3, RT_GROUP_ICON=14)
  console.log(`\nStripping all ${existingGroups.length} existing icon groups...`);
  res.entries = res.entries.filter((entry) => {
    return entry.type !== 3 && entry.type !== 14;
  });

  // Add our single 256×256 icon as IDR_MAINFRAME using replaceIconsForResource
  console.log(`Setting new icon: 256×256, 32bpp (single layer)...`);

  // Extract the PNG data from our ICO file
  const pngDataOffset = icoBuffer.readUInt32LE(6 + 12); // offset of first image data
  const pngDataSize = icoBuffer.readUInt32LE(6 + 8);    // size of first image data
  const pngData = icoBuffer.slice(pngDataOffset, pngDataOffset + pngDataSize);

  // Build the icon item in the format resedit expects
  const iconItem = {
    width: 256,
    height: 256,
    bitCount: 32,
    bin: pngData,
    isIcon: () => false,
  };

  Resource.IconGroupEntry.replaceIconsForResource(
    res.entries,
    "IDR_MAINFRAME",
    1033,
    [iconItem]
  );

  // Update version info strings (InternalName, ProductName, FileDescription)
  const viList = Resource.VersionInfo.fromEntries(res.entries);
  if (viList.length > 0) {
    const vi = viList[0];
    vi.setStringValues(
      { lang: 1033, codepage: 1200 },
      {
        FileDescription: "Venus Library Manager",
        ProductName: "Venus Library Manager",
        InternalName: "Venus Library Manager",
        OriginalFilename: "Venus Library Manager.exe",
      }
    );
    vi.outputToResourceEntries(res.entries);
    console.log(`\nVersion info updated: InternalName / ProductName / FileDescription → "Venus Library Manager"`);
  } else {
    console.log(`\n[WARN] No version info found in .exe — skipping version string update.`);
  }

  // Write back to the .exe
  res.outputResource(exe);
  const newExeData = exe.generate();
  fs.writeFileSync(EXE_PATH, Buffer.from(newExeData));

  // Verify
  const verifyExe = NtExecutable.from(fs.readFileSync(EXE_PATH));
  const verifyRes = NtExecutableResource.from(verifyExe);
  const verifyGroups = Resource.IconGroupEntry.fromEntries(verifyRes.entries);
  console.log(`\nVerification — icon groups in .exe: ${verifyGroups.length}`);
  verifyGroups.forEach((group) => {
    const label = typeof group.id === "string" ? group.id : `#${group.id}`;
    group.icons.forEach((icon) => {
      const w = icon.width === 0 ? 256 : icon.width;
      const h = icon.height === 0 ? 256 : icon.height;
      console.log(`  ${label}: ${w}×${h}, ${icon.bitCount}bpp`);
    });
  });

  console.log(`\nDone. Icon and version info embedded into .exe successfully.`);
  console.log(`\nIf Explorer still shows the old icon, flush the cache:`);
  console.log(`  ie4uinit.exe -show`);
}

main().catch((err) => {
  console.error("\n[FATAL ERROR]", err);
  process.exit(1);
});
