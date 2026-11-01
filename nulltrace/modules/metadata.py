"""Image / document metadata extraction, including GPS geolocation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from PIL import ExifTags, Image

from ..job import Field, Module
from ..net import geo_summary

IMAGE_EXT = {".jpg", ".jpeg", ".tif", ".tiff", ".png", ".heic", ".webp", ".gif", ".bmp"}
HIGHLIGHT = {
    "Make", "Model", "LensModel", "Software", "DateTimeOriginal", "CreateDate",
    "Artist", "Copyright", "ImageDescription", "GPSLatitude", "GPSLongitude",
    "GPSAltitude", "SerialNumber", "OwnerName",
}


def _exiftool(path: Path) -> dict | None:
    exe = shutil.which("exiftool")
    if not exe:
        return None
    try:
        result = subprocess.run(
            [exe, "-j", "-G1", "-n", str(path)],
            capture_output=True, text=True, timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)[0]
    except (ValueError, IndexError):
        return None
    return {k.replace("EXIF:", "").replace("XMP-", ""): v for k, v in data.items()}


def _pil_exif(path: Path) -> dict:
    out: dict = {}
    with Image.open(path) as image:
        out["Format"] = image.format
        out["Dimensions"] = f"{image.width}x{image.height}"
        out["Mode"] = image.mode
        exif = image.getexif()
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if isinstance(value, bytes):
                continue
            out[name] = value
        ifd = exif.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(ExifTags, "IFD") else {}
        for tag_id, value in (ifd or {}).items():
            out[f"GPS:{ExifTags.GPSTAGS.get(tag_id, tag_id)}"] = value
    return out


def _ratio(value) -> float:
    """EXIF stores rationals as (numerator, denominator) pairs."""
    if isinstance(value, (tuple, list)) and len(value) == 2:
        numerator, denominator = value
        return float(numerator) / float(denominator) if denominator else 0.0
    return float(value)


def _dms_to_decimal(value) -> float | None:
    try:
        if isinstance(value, str):
            parts = value.replace(",", " ").split()
            return float(parts[0])
        if isinstance(value, (int, float)):
            return float(value)
        parts = list(value)
        degrees = _ratio(parts[0])
        minutes = _ratio(parts[1]) if len(parts) > 1 else 0.0
        seconds = _ratio(parts[2]) if len(parts) > 2 else 0.0
        return degrees + minutes / 60.0 + seconds / 3600.0
    except (TypeError, ValueError, IndexError, ZeroDivisionError):
        return None


def _gps(data: dict) -> tuple[float, float] | None:
    lat = lon = None
    for key, value in data.items():
        if key in ("GPSLatitude", "GPS:GPSLatitude", "GPS:Latitude"):
            lat = _dms_to_decimal(value)
        if key in ("GPSLongitude", "GPS:GPSLongitude", "GPS:Longitude"):
            lon = _dms_to_decimal(value)
        if key in ("GPSPosition",) and isinstance(value, str) and "," in value:
            a, b = value.split(",", 1)
            lat = _dms_to_decimal(a.strip())
            lon = _dms_to_decimal(b.strip())
    lat_ref = data.get("GPSLatitudeRef") or data.get("GPS:GPSLatitudeRef")
    lon_ref = data.get("GPSLongitudeRef") or data.get("GPS:GPSLongitudeRef")
    if lat is not None and str(lat_ref).upper().startswith("S"):
        lat = -abs(lat)
    if lon is not None and str(lon_ref).upper().startswith("W"):
        lon = -abs(lon)
    if lat is None or lon is None or (lat == 0 and lon == 0):
        return None
    return lat, lon


def run(ctx) -> None:
    raw = ctx.value("path").strip().strip('"')
    if not raw:
        ctx.error("Choose a file.")
        return
    path = Path(raw).expanduser()
    if not path.is_file():
        ctx.error(f"File not found: {path}")
        return

    ctx.title(f"Metadata — {path.name}")
    ctx.kv("Size", f"{path.stat().st_size / 1024:,.1f} KB")
    from datetime import datetime
    ctx.kv("Modified", datetime.fromtimestamp(path.stat().st_mtime).isoformat(sep=" ",
                                                                            timespec="seconds"))

    data: dict = {}
    engine = ""
    if path.suffix.lower() in IMAGE_EXT:
        try:
            data = _pil_exif(path)
            engine = "Pillow"
        except Exception as exc:
            ctx.warn(f"Pillow could not read the image: {exc}")
    tool = _exiftool(path)
    if tool:
        data.update(tool)
        engine = "ExifTool + Pillow" if engine else "ExifTool"

    if not data:
        ctx.warn("No metadata could be read.")
        if not shutil.which("exiftool"):
            ctx.note("ExifTool is not installed — it reads metadata from far more formats than Pillow.")
            ctx.link("Get ExifTool", "https://exiftool.org")
        return

    ctx.kv("Engine", engine)
    ctx.section("Fields")
    rows = []
    gps = _gps(data)
    for key in sorted(data):
        value = data[key]
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        value = str(value)
        if len(value) > 110:
            value = value[:107] + "..."
        sensitive = key in HIGHLIGHT or "GPS" in key or "Serial" in key
        rows.append((("! " if sensitive else "  ") + key, value))
    ctx.table(("Field", "Value"), rows)

    if gps:
        lat, lon = gps
        ctx.section("Geolocation")
        ctx.kv("Latitude", f"{lat:.6f}")
        ctx.kv("Longitude", f"{lon:.6f}")
        ctx.link("Open map", geo_summary(lat, lon))
        ctx.warn("Coordinates embedded by the camera — treat as sensitive.")
    elif path.suffix.lower() in IMAGE_EXT:
        ctx.section("Geolocation")
        ctx.muted("No GPS coordinates in this file.")

    if any("Serial" in k for k in data):
        ctx.warn("Serial numbers present — they can identify the exact device.")


MODULE = Module(
    id="metadata",
    title="Metadata",
    category="Media",
    summary="Read EXIF/XMP/document metadata, highlight device fingerprints and extract GPS coordinates.",
    fields=(
        Field("path", "File", kind="file", placeholder="C:\\path\\to\\photo.jpg", required=True),
    ),
    run=run,
    order=70,
)
