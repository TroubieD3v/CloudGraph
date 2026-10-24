"""Assemble docs/screenshots/frames/*.png (written by screenshots.mjs) into demo.gif.

    python scripts/make_gif.py

File names are NNN-HOLD.png; HOLD is the display time in 0.1 s ticks. Needs Pillow.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image

OUT = Path(__file__).resolve().parents[2] / "docs" / "screenshots"
SIZE = (1080, 675)


def main() -> None:
    frames, durations = [], []
    for f in sorted((OUT / "frames").glob("*.png")):
        hold = int(f.stem.split("-")[1])
        frames.append(Image.open(f).convert("RGB").resize(SIZE, Image.LANCZOS))
        durations.append(hold * 100)
    if not frames:
        raise SystemExit("no frames: run scripts/screenshots.mjs first")
    palette = frames[0].quantize(colors=128, method=Image.Quantize.MEDIANCUT)
    images = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in frames]
    target = OUT / "demo.gif"
    images[0].save(target, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True)
    shutil.rmtree(OUT / "frames")
    print(f"{target} {target.stat().st_size / 1024:.0f} KiB, {len(images)} frames")


if __name__ == "__main__":
    main()
