#!/usr/bin/env python3
"""Build two separate, autotype-aligned Seed demo GIFs (one per machine).

Each gif starts at the "seed build 12" splash. The splash->autotype segment is
normalized to a common gif-second (--autotype-at), so the prompt is typed at the
SAME moment in both files; the autotype->answer segment then plays at a common
--work-speedup, so the post-prompt speed difference between the machines is
directly visible. The faster machine holds its finished answer until the slower
one catches up, so both files share one length and loop in sync side-by-side.

Landmarks (seconds, capture-relative) are passed in (measured via OCR offline).
"""
from __future__ import annotations
import argparse, re, subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

CROP_X, CROP_Y, CROP_W, CROP_H = 0, 112, 1280, 788
BANNER_H = 52
FONTS = [
    "/System/Library/Fonts/Supplemental/Courier New Bold.ttf",
    "/System/Library/Fonts/Supplemental/Courier New.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]


def load_font(sz):
    for f in FONTS:
        try:
            return ImageFont.truetype(f, sz)
        except Exception:
            pass
    return ImageFont.load_default()


def frames(d: Path):
    return sorted((int(re.match(r"f_\d+_(\d+)\.png", p.name).group(1)), p)
                  for p in sorted(Path(d).glob("f_*.png"))
                  if re.match(r"f_\d+_(\d+)\.png", p.name))


def banner(width, label, tag, speedup):
    img = Image.new("RGB", (width, BANNER_H), (0, 0, 0))
    dr = ImageDraw.Draw(img)
    spec = load_font(24); small = load_font(19)
    white = (235, 235, 235); gray = (155, 155, 155)
    col = {"insecure": (235, 70, 70), "secure": (80, 220, 90)}
    dr.text((18, 12), label, font=spec, fill=white)
    if tag:
        dr.text((18, 44), tag, font=small, fill=col.get(tag, white))
    s = f"sped up {int(speedup)}x"
    dr.text((width - 18 - dr.textlength(s, font=small), 18), s, font=small, fill=gray)
    return img


def build(cap, splash, ttype, tend, A, S, total, fps, width, label, tag, out):
    fs = frames(cap)
    if not fs:
        raise SystemExit(f"no frames in {cap}")
    t0 = fs[0][0]
    scaled_h = round(CROP_H * width / CROP_W)
    work_gif = (tend - ttype) / S
    seq = Path("/tmp/_demo1"); seq.mkdir(exist_ok=True)
    for old in seq.glob("*.png"):
        old.unlink()
    n = int(total * fps)
    j = 0; cache = {}
    for i in range(n):
        t = i / fps
        if t < A:
            real = splash + (t / A) * (ttype - splash)     # setup, normalized
        elif t < A + work_gif:
            real = ttype + (t - A) * S                      # work, common speedup
        else:
            real = tend                                     # hold finished answer
        target = t0 + real * 1000.0
        while j + 1 < len(fs) and fs[j + 1][0] <= target:
            j += 1
        src = fs[min(j, len(fs) - 1)][1]
        if src not in cache:
            im = Image.open(src).convert("RGB").crop(
                (CROP_X, CROP_Y, CROP_X + CROP_W, CROP_Y + CROP_H)).resize(
                (width, scaled_h), Image.LANCZOS)
            canvas = Image.new("RGB", (width, scaled_h + BANNER_H), (0, 0, 0))
            canvas.paste(banner(width, label, tag, S), (0, 0))
            canvas.paste(im, (0, BANNER_H))
            cache[src] = canvas
        cache[src].save(seq / f"{i:05d}.png")

    fc = ("split[a][b];[a]palettegen=stats_mode=full[p];"
          "[b][p]paletteuse=dither=bayer:bayer_scale=3[o]")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["ffmpeg", "-y", "-v", "error", "-framerate", str(fps),
                        "-i", str(seq / "%05d.png"), "-filter_complex", fc,
                        "-map", "[o]", "-loop", "0", out], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-1500:]); raise SystemExit("ffmpeg failed")
    print(f"  {out}  ({Path(out).stat().st_size/1024:.0f} KB, {n} frames, {n/fps:.1f}s)")


def main():
    ap = argparse.ArgumentParser()
    for side in ("left", "right"):
        ap.add_argument(f"--{side}-frames", required=True)
        ap.add_argument(f"--{side}-label", required=True)
        ap.add_argument(f"--{side}-tag", default="")
        ap.add_argument(f"--{side}-splash", type=float, required=True)
        ap.add_argument(f"--{side}-type", type=float, required=True)
        ap.add_argument(f"--{side}-end", type=float, required=True)
        ap.add_argument(f"--{side}-out", required=True)
    ap.add_argument("--autotype-at", type=float, default=4.0)
    ap.add_argument("--work-speedup", type=float, default=12.0)
    ap.add_argument("--fps", type=int, default=12)
    ap.add_argument("--width", type=int, default=720)
    a = ap.parse_args()

    A, S = a.autotype_at, a.work_speedup
    total = A + max((a.left_end - a.left_type) / S, (a.right_end - a.right_type) / S)
    print(f"autotype @ {A}s, work {S}x, total {total:.1f}s ({int(total*a.fps)} frames @ {a.fps}fps)")
    build(a.left_frames, a.left_splash, a.left_type, a.left_end, A, S, total, a.fps, a.width,
          a.left_label, a.left_tag, a.left_out)
    build(a.right_frames, a.right_splash, a.right_type, a.right_end, A, S, total, a.fps, a.width,
          a.right_label, a.right_tag, a.right_out)


if __name__ == "__main__":
    main()
