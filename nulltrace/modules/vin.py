"""VIN decoding via the free NHTSA vPIC API, plus WMI country lookup."""

from __future__ import annotations

from ..job import Field, Module
from ..net import HttpError, get_json

WMI_COUNTRY = {
    "1": "United States", "2": "Canada", "3": "Mexico", "4": "United States",
    "5": "United States", "6": "Australia", "7": "New Zealand", "8": "Argentina",
    "9": "Brazil", "J": "Japan", "K": "South Korea", "L": "China", "M": "India",
    "S": "United Kingdom", "T": "Switzerland", "V": "France", "W": "Germany",
    "X": "Russia / CIS", "Y": "Sweden / Finland", "Z": "Italy", "A": "South Africa",
}

TRANSLIT = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def _check_digit(vin: str) -> tuple[int, bool]:
    total = 0
    for index, char in enumerate(vin.upper()):
        value = int(char) if char.isdigit() else TRANSLIT.get(char)
        if value is None:
            return 0, False
        total += value * WEIGHTS[index]
    remainder = total % 11
    expected = "X" if remainder == 10 else str(remainder)
    return remainder, vin[8].upper() == expected


def run(ctx) -> None:
    vin = ctx.value("vin").strip().upper()
    if len(vin) != 17:
        ctx.error("A VIN must be exactly 17 characters.")
        return
    ctx.title(f"VIN decode — {vin}")
    ctx.kv("WMI", vin[:3])
    ctx.kv("Assembly country", WMI_COUNTRY.get(vin[0], "unknown"))
    ctx.kv("Model year code", vin[9])
    _, valid = _check_digit(vin)
    (ctx.ok if valid else ctx.warn)(
        "Check digit valid (North American VINs only)" if valid
        else "Check digit invalid or non-North-American VIN format")

    ctx.status("Decoding via NHTSA ...")
    try:
        data = get_json(
            f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValuesExtended/{vin}?format=json",
            timeout=30,
        )
    except HttpError as exc:
        ctx.error(f"NHTSA lookup failed: {exc}")
        return
    results = data.get("Results") or [{}]
    row = results[0]

    ctx.section("Vehicle")
    fields = [
        ("Make", "Make"), ("Model", "Model"), ("Trim", "Trim"), ("Series", "Series"),
        ("Model year", "ModelYear"), ("Vehicle type", "VehicleType"),
        ("Body class", "BodyClass"), ("Doors", "Doors"),
        ("Engine cylinders", "EngineCylinders"), ("Displacement (L)", "DisplacementL"),
        ("Engine model", "EngineModel"), ("Fuel type", "FuelTypePrimary"),
        ("Drive type", "DriveType"), ("Transmission", "TransmissionStyle"),
        ("GVWR", "GVWR"), ("Plant city", "PlantCity"), ("Plant country", "PlantCountry"),
        ("Manufacturer", "Manufacturer"), ("Series2", "Series2"),
        ("Seat belts", "SeatBeltsAll"), ("Airbag locations", "AirBagLocFront"),
    ]
    shown = 0
    for label, key in fields:
        value = str(row.get(key) or "").strip()
        if value and value.lower() not in ("not applicable", "0"):
            ctx.kv(label, value)
            shown += 1
    if not shown:
        ctx.warn("NHTSA returned no populated fields.")

    errors = str(row.get("ErrorText") or "").strip()
    if errors and not errors.startswith("0 -"):
        ctx.warn(f"API notes: {errors}")

    ctx.link("Full record", f"https://vpic.nhtsa.dot.gov/decoder/Decoder/ExportToExcel?VIN={vin}")
    ctx.note("Decoded data reflects manufacturer registrations, not the current condition of the car.")


MODULE = Module(
    id="vin",
    title="VIN Decoder",
    category="Media",
    summary="Decode a 17-character VIN into make, model, engine, plant and check-digit validity.",
    fields=(
        Field("vin", "VIN", placeholder="1HGCM82633A004352", required=True),
    ),
    run=run,
    order=190,
)
