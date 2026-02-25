"""
Build a maximum-quality ICO file with correct PE-resource format.

The 256px layer is PNG-compressed (Windows Vista+ standard for large icons).
Windows downscales from this single layer for all views (taskbar, alt-tab,
medium icons, etc.), producing the crispest result.

Source: 2048px SVG render (via sharp) downscaled with LANCZOS.
"""

import os
import io
import struct
from PIL import Image

# Single 256px layer. Windows downscales from this for all views
# (taskbar, alt-tab, medium icons, etc.).
ICO_SIZES = [256]

SOURCE_PNG = "_temp_2048.png"
OUTPUT_ICO = "VenusLibraryManager.ico"
OUTPUT_PNG = "VenusLibraryManager.png"


def build_ico(layers: list, output_path: str):
    """
    Build an ICO file manually to ensure exact format control.
    256px layers are PNG-compressed.
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
    print(f"{'='*60}")

    # Export 1024x1024 PNG for NW.js window icon (HiDPI-ready)
    png_out = src.resize((1024, 1024), Image.LANCZOS)
    png_out.save(OUTPUT_PNG, "PNG", optimize=False, compress_level=0)
    png_kb = os.path.getsize(OUTPUT_PNG) / 1024
    print(f"\n  PNG saved:  {OUTPUT_PNG} (1024x1024, {png_kb:.1f} KB)")


if __name__ == "__main__":
    main()
