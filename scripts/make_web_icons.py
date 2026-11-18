"""Draw the icons of the console.

    python scripts/make_web_icons.py

The icons are drawn here, with the standard library only, so the build needs
no image tool and no binary file is kept in the repository that cannot be
read. The mark is an "H" on the dark blue of the console.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

BACKGROUND = (18, 38, 58)
MARK = (255, 255, 255)
ACCENT = (90, 169, 224)

TARGET = Path(__file__).resolve().parents[1] / "web" / "public" / "icons"

Pixel = tuple[int, int, int]


def canvas(width: int, height: int, color: Pixel) -> list[list[Pixel]]:
    """A picture of one colour."""
    return [[color for _ in range(width)] for _ in range(height)]


def rect(
    picture: list[list[Pixel]], x0: int, y0: int, x1: int, y1: int, color: Pixel
) -> None:
    """Paint a rectangle of the picture."""
    height = len(picture)
    width = len(picture[0])
    for y in range(max(0, y0), min(height, y1)):
        for x in range(max(0, x0), min(width, x1)):
            picture[y][x] = color


def mark(size: int, *, maskable: bool) -> list[list[Pixel]]:
    """The mark of the console, on the background."""
    picture = canvas(size, size, BACKGROUND)
    scale = size / 64
    if maskable:
        scale = size / 64 * 0.62
        offset = (size - 64 * scale) / 2
    else:
        offset = 0.0

    def box(x0: float, y0: float, x1: float, y1: float) -> tuple[int, int, int, int]:
        return (
            round(offset + x0 * scale),
            round(offset + y0 * scale),
            round(offset + x1 * scale),
            round(offset + y1 * scale),
        )

    rect(picture, *box(15, 15, 24, 49), MARK)
    rect(picture, *box(40, 15, 49, 49), MARK)
    rect(picture, *box(15, 28, 49, 36), ACCENT)
    return picture


def png(size: int, picture: list[list[Pixel]]) -> bytes:
    """Encode a picture as a PNG."""
    raw = bytearray()
    for row in picture:
        raw.append(0)
        for pixel in row:
            raw.extend(pixel)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">2I5B", size, size, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    icons = {
        "icon-192.png": (192, False),
        "icon-512.png": (512, False),
        "maskable-512.png": (512, True),
        "apple-touch-icon.png": (180, False),
    }
    for name, (size, maskable) in icons.items():
        (TARGET / name).write_bytes(png(size, mark(size, maskable=maskable)))
        print(f"wrote {TARGET / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
