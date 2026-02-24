"""
Image to ICO Converter
======================
Converts SVG or PNG images to high-quality, multi-resolution .ico and .png files.

Features:
  - SVG rendering at high resolution (1024px) via svglib/reportlab
  - PNG input also supported
  - Pads non-square images to square with transparent background
  - Generates multi-resolution ICO (256, 128, 64, 48, 32, 24, 16)
  - Uses LANCZOS resampling for maximum sharpness
  - Subtle sharpening on small sizes for crisp icons
  - Also exports a clean 256x256 PNG for app window icons

Usage:
  python png_to_ico.py <input.svg|input.png> [output_basename]

  If output_basename is omitted, uses the input filename stem.
  Generates: <basename>.ico and <basename>.png
"""

import sys
import os
import io
from PIL import Image, ImageFilter

# Standard Windows ICO sizes (largest first)
ICO_SIZES = [256, 128, 64, 48, 32, 24, 16]

# Render SVG at this size for maximum quality before downscaling
SVG_RENDER_SIZE = 1024


def render_svg_to_pil(svg_path: str, target_size: int = SVG_RENDER_SIZE) -> Image.Image:
    """Render an SVG file to a high-resolution PIL Image."""
    from svglib.svglib import svg2rlg
    from reportlab.graphics import renderPM

    print(f"[INFO] Rendering SVG at {target_size}x{target_size}...")
    drawing = svg2rlg(svg_path)
    if drawing is None:
        raise ValueError(f"Failed to parse SVG: {svg_path}")

    # Scale to target size
    scale_x = target_size / drawing.width
    scale_y = target_size / drawing.height
    scale = min(scale_x, scale_y)
    drawing.width = drawing.width * scale
    drawing.height = drawing.height * scale
    drawing.scale(scale, scale)

    # Render to PNG bytes in memory
    png_bytes = renderPM.drawToString(drawing, fmt="PNG", dpi=300)
    img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
    print(f"[INFO] SVG rendered to {img.width}x{img.height}")
    return img


def load_source(input_path: str) -> Image.Image:
    """Load source image from SVG or PNG."""
    ext = os.path.splitext(input_path)[1].lower()
    if ext == ".svg":
        return render_svg_to_pil(input_path)
    else:
        img = Image.open(input_path).convert("RGBA")
        print(f"[INFO] Loaded PNG: {img.width}x{img.height}")
        return img


def pad_to_square(img: Image.Image) -> Image.Image:
    """Pad a non-square image to square with transparent background, centered."""
    w, h = img.size
    if w == h:
        return img

    size = max(w, h)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset_x = (size - w) // 2
    offset_y = (size - h) // 2
    canvas.paste(img, (offset_x, offset_y), img if img.mode == "RGBA" else None)
    print(f"[INFO] Padded to square: {size}x{size}")
    return canvas


def sharpen_for_small_sizes(img: Image.Image) -> Image.Image:
    """Apply subtle sharpening to small icon sizes to keep them crisp."""
    if img.size[0] <= 48:
        return img.filter(ImageFilter.SHARPEN)
    return img


def generate_ico(src_square: Image.Image, output_path: str) -> None:
    """Generate a multi-resolution ICO file from a square source image."""
    icon_images = []
    for size in ICO_SIZES:
        resized = src_square.resize((size, size), Image.LANCZOS)
        resized = sharpen_for_small_sizes(resized)
        icon_images.append(resized)
        print(f"[INFO] ICO layer: {size}x{size}")

    icon_images[0].save(
        output_path,
        format="ICO",
        sizes=[(img.width, img.height) for img in icon_images],
        append_images=icon_images[1:],
    )

    file_size_kb = os.path.getsize(output_path) / 1024
    print(f"[OK] ICO saved: {output_path} ({file_size_kb:.1f} KB)")
    print(f"[OK] Contains {len(ICO_SIZES)} resolutions: {ICO_SIZES}")


def generate_png(src_square: Image.Image, output_path: str, size: int = 256) -> None:
    """Generate a clean square PNG at the specified size."""
    resized = src_square.resize((size, size), Image.LANCZOS)
    resized.save(output_path, "PNG", optimize=True)
    file_size_kb = os.path.getsize(output_path) / 1024
    print(f"[OK] PNG saved: {output_path} ({size}x{size}, {file_size_kb:.1f} KB)")


def main():
    if len(sys.argv) < 2:
        print("Usage: python png_to_ico.py <input.svg|input.png> [output_basename]")
        sys.exit(1)

    input_path = sys.argv[1]
    if not os.path.isfile(input_path):
        print(f"[ERROR] File not found: {input_path}")
        sys.exit(1)

    if len(sys.argv) >= 3:
        basename = sys.argv[2]
    else:
        basename = os.path.splitext(input_path)[0]

    # Load and prepare source
    src = load_source(input_path)
    src_square = pad_to_square(src)

    # Generate both outputs
    ico_path = basename + ".ico"
    png_path = basename + ".png"

    generate_ico(src_square, ico_path)
    generate_png(src_square, png_path)

    print(f"\n[DONE] Generated:")
    print(f"  ICO: {ico_path}")
    print(f"  PNG: {png_path}")


if __name__ == "__main__":
    main()
