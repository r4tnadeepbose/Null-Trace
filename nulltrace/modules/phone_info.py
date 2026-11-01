"""Phone number intelligence: validity, carrier, region, timezones."""

from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone

from ..job import Field, Module
from ..net import HttpError, get_json

TYPE_LABELS = {
    0: "Fixed line", 1: "Mobile", 2: "Fixed line or mobile", 3: "Toll free",
    4: "Premium rate", 5: "Shared cost", 6: "VoIP", 7: "Personal number",
    8: "Pager", 9: "Universal access", 10: "Voicemail", 27: "Unknown",
}


def _numverify(number: phonenumbers.PhoneNumber, key: str) -> dict | None:
    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164).lstrip("+")
    try:
        data = get_json(
            f"http://apilayer.net/api/validate?access_key={key}&number={e164}&format=1",
            timeout=15,
        )
    except HttpError:
        return None
    return data if data.get("valid") is not None else None


def _ipqs(number: phonenumbers.PhoneNumber, key: str) -> dict | None:
    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    try:
        return get_json(f"https://ipqualityscore.com/api/json/phone/{key}/{e164}", timeout=15)
    except HttpError:
        return None


def run(ctx) -> None:
    raw = ctx.value("number")
    default_region = (ctx.value("region") or "").upper() or None
    if not raw:
        ctx.error("Enter a phone number (include +country code when possible).")
        return

    try:
        number = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as exc:
        ctx.error(f"Could not parse number: {exc}")
        return

    if not phonenumbers.is_valid_number(number):
        ctx.warn("Number is not valid for its region — showing what can be parsed anyway.")
    ctx.title(f"Phone intelligence — {raw}")

    ctx.section("Number")
    ctx.kv("E.164", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164))
    ctx.kv("International",
           phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    ctx.kv("National",
           phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL))
    ctx.kv("RFC3966", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.RFC3966))
    ctx.kv("Country code", phonenumbers.region_code_for_number(number))
    ctx.kv("Valid", "yes" if phonenumbers.is_valid_number(number) else "no")
    ctx.kv("Possible", "yes" if phonenumbers.is_possible_number(number) else "no")
    ctx.kv("Type", TYPE_LABELS.get(phonenumbers.number_type(number), "Unknown"))

    ctx.section("Carrier & region")
    ctx.kv("Carrier (offline db)", carrier.name_for_number(number, "en") or "unknown")
    ctx.kv("Location (offline db)", geocoder.description_for_number(number, "en") or "unknown")
    zones = pn_timezone.time_zones_for_number(number)
    ctx.kv("Timezones", ", ".join(zones) if zones else "unknown")

    ctx.check_cancel()
    numverify_key = ctx.key("numverify")
    if numverify_key:
        ctx.section("Numverify")
        data = _numverify(number, numverify_key)
        if not data:
            ctx.warn("  Numverify request failed or key invalid.")
        else:
            for label, field in (("Carrier (live)", "carrier"), ("Line type", "line_type"),
                                 ("Location", "location"), ("Country", "country_name")):
                ctx.kv(label, data.get(field) or "unknown")
    else:
        ctx.muted("No Numverify key — live carrier lookup skipped.")

    ctx.check_cancel()
    ipqs_key = ctx.key("ipqualityscore")
    if ipqs_key:
        ctx.section("IPQualityScore")
        data = _ipqs(number, ipqs_key)
        if not data:
            ctx.warn("  request failed or key invalid")
        else:
            ctx.kv("Fraud score", data.get("fraud_score"))
            ctx.kv("Carrier", data.get("carrier"))
            ctx.kv("Line type", data.get("line_type"))
            ctx.kv("Active", data.get("active"))
            ctx.kv("Do not call", data.get("do_not_call"))
            ctx.kv("VOIP", data.get("VOIP"))
            ctx.kv("Risky", data.get("risky"))
            if data.get("fraud_score") and int(data["fraud_score"]) > 75:
                ctx.warn("High fraud score — treat with caution.")
    else:
        ctx.muted("No IPQualityScore key — fraud scoring skipped.")

    ctx.check_cancel()
    ctx.section("Public footprint")
    digits = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    for label, url in (
        ("Search number", f"https://duckduckgo.com/?q=%22{digits}%22"),
        ("Search national",
         f"https://duckduckgo.com/?q=%22"
         f"{phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)}%22"),
    ):
        ctx.link(label, url)


MODULE = Module(
    id="phone_info",
    title="Phone Intel",
    category="Identity",
    summary="Offline validity, carrier, region and timezone; optional Numverify and IPQS enrichment.",
    fields=(
        Field("number", "Phone number", placeholder="+14155552671", required=True,
              help="Include +country code for accurate parsing."),
        Field("region", "Default region", placeholder="US", help="Used when no + prefix."),
    ),
    keys=("numverify", "ipqualityscore"),
    run=run,
    order=60,
)
