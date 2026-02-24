"""
Build a maximum-quality ICO file with correct PE-resource format.

The key to crisp .exe icons in Windows Explorer:
  - 256px layer: PNG-compressed (Windows Vista+ standard for large icons)
  - ALL layers below 256: raw 32-bit BMP (BITMAPINFOHEADER + RGBA pixel data)

This is the EXACT format that rcedit, Visual Studio, electron-builder, and
every professional tool produces. When embedding into a PE executable, Windows
reads BMP icon resources directly from the RT_ICON resource table. If layers
are PNG-encoded at small sizes, the PE resource loader may not render them
at the expected fidelity -- resulting in the "tiny icon" problem.

Pillow's ICO writer handles this correctly: PNG for >=128, BMP for <128.
We manually build the ICO to ensure 256=PNG and everything else=BMP.

Source: 2048px SVG render (via sharp) downscaled with LANCZOS.
"""

import os
import io
import struct
from PIL import Image, ImageFilter

# Comprehensive Windows icon sizes — every standard size Windows may request.
# The 256px layer is the "jumbo" icon shown in Explorer's Extra Large view.
# Single 256px layer only. Windows downscales from this for all views
# (taskbar, alt-tab, medium icons, etc.), producing the crispest result.
ICO_SIZES = [256]

SOURCE_PNG = "_temp_2048.png"
OUTPUT_ICO = "VenusLibraryManager.ico"
OUTPUT_PNG = "VenusLibraryManager.png"


def image_to_bmp_data(img: Image.Image) -> bytes:
    """
    Convert a PIL RGBA image to ICO-style BMP data.
    ICO BMP format = BITMAPINFOHEADER (40 bytes) + pixel rows (bottom-up) + AND mask.
    The height in the header is 2x the actual height (icon convention).
    """
    w, h = img.size
    pixels = img.load()

    # BITMAPINFOHEADER
    header = struct.pack(
        "<IiiHHIIiiII",
        40,          # biSize
        w,           # biWidth
        h * 2,       # biHeight (doubled for ICO: XOR mask + AND mask)
        1,           # biPlanes
        32,          # biBitCount (32-bit BGRA)
        0,           # biCompression (BI_RGB = uncompressed)
        0,           # biSizeImage (can be 0 for BI_RGB)
        0,           # biXPelsPerMeter
        0,           # biYPelsPerMeter
        0,           # biClrUsed
        0,           # biClrImportant
    )

    # Pixel data: bottom-up rows, BGRA byte order
    pixel_data = bytearray()
    for y in range(h - 1, -1, -1):  # bottom to top
        for x in range(w):
            r, g, b, a = pixels[x, y]
            pixel_data.extend([b, g, r, a])  # BGRA

    # AND mask: 1-bit mask, rows padded to 4-byte boundary
    # For 32-bit icons with alpha, the AND mask is all zeros (alpha handles transparency)
    and_row_bytes = ((w + 31) // 32) * 4  # bits per row, padded to DWORD
    and_mask = bytes(and_row_bytes * h)

    return header + bytes(pixel_data) + and_mask


def build_ico(layers: list, output_path: str):
    """
    Build an ICO file manually to ensure exact format control.
    256px = PNG-compressed, everything else = raw 32-bit BMP.
    """
    num = len(layers)

    # Prepare image data for each layer
    image_data_list = []
    format_labels = []
    for img in layers:
        if img.size[0] >= 256:
            # PNG-compressed for 256x256 (Windows standard for jumbo icons)
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            image_data_list.append(buf.getvalue())
            format_labels.append("PNG")
        else:
            # Raw 32-bit BMP for all other sizes (PE resource standard)
            image_data_list.append(image_to_bmp_data(img))
            format_labels.append("BMP")

    # ICO Header (6 bytes)
    header = struct.pack("<HHH", 0, 1, num)  # reserved=0, type=1 (ICO), count

    # Calculate offsets
    dir_size = num * 16
    data_offset = 6 + dir_size

    # Build directory entries and collect data
    directory = bytearray()
    current_offset = data_offset

    for i, (img, data) in enumerate(zip(layers, image_data_list)):
        w, h = img.size
        entry = struct.pack(
            "<BBBBHHII",
            0 if w >= 256 else w,   # width (0 = 256)
            0 if h >= 256 else h,   # height (0 = 256)
            0,                       # color palette count
            0,                       # reserved
            1,                       # color planes
            32,                      # bits per pixel
            len(data),               # data size (DWORD)
            current_offset,          # data offset (DWORD)
        )
        directory.extend(entry)
        current_offset += len(data)

    # Write the ICO file
    with open(output_path, "wb") as f:
        f.write(header)
        f.write(bytes(directory))
        for data in image_data_list:
            f.write(data)

    return format_labels


def main():
    if not os.path.isfile(SOURCE_PNG):
        print(f"[ERROR] Source not found: {SOURCE_PNG}")
        print("Generate it first:  node -e \"...sharp SVG render...\"")
        print("Or run:  node build_icons.js  (which creates it)")
        return

    src = Image.open(SOURCE_PNG).convert("RGBA")
    print(f"[INFO] Source: {src.width}x{src.height} RGBA")
    print(f"[INFO] Building {len(ICO_SIZES)} layers...\n")

    layers = []
    for size in ICO_SIZES:
        resized = src.resize((size, size), Image.LANCZOS)

        # Adaptive sharpening for smaller sizes to maintain crispness
        if size <= 24:
            resized = resized.filter(ImageFilter.SHARPEN)
        elif size <= 48:
            resized = resized.filter(ImageFilter.DETAIL)

        layers.append(resized)

    # Build ICO with correct format (PNG for 256, BMP for rest)
    format_labels = build_ico(layers, OUTPUT_ICO)

    for size, fmt in zip(ICO_SIZES, format_labels):
        print(f"  {size:>3}x{size:<3}  {fmt}")

    ico_size = os.path.getsize(OUTPUT_ICO)
    print(f"\n{'='*60}")
    print(f"  ICO saved:  {OUTPUT_ICO}")
    print(f"  File size:  {ico_size:>10,} bytes  ({ico_size/1024:.1f} KB)")
    print(f"  Layers:     {len(ICO_SIZES)}")
    print(f"  256px:      PNG (lossless, jumbo icon for Explorer)")
    print(f"  Others:     32-bit BMP (raw BGRA, PE resource standard)")
    print(f"{'='*60}")

    # Export 1024x1024 PNG for NW.js window icon (HiDPI-ready)
    png_out = src.resize((1024, 1024), Image.LANCZOS)
    png_out.save(OUTPUT_PNG, "PNG", optimize=False, compress_level=0)
    png_kb = os.path.getsize(OUTPUT_PNG) / 1024
    print(f"\n  PNG saved:  {OUTPUT_PNG} (1024x1024, {png_kb:.1f} KB)")


if __name__ == "__main__":
    main()
