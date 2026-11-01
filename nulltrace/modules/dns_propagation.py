"""Query several public resolvers to see whether a record has propagated."""

from __future__ import annotations

from ..job import Field, Module

RESOLVERS = (
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("Control D", "76.76.2.0"),
)


def _query(server: str, name: str, rtype: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        return ["(dnspython missing)"]
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = 4
    resolver.lifetime = 6
    try:
        answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
    except Exception as exc:  # timeout, NXDOMAIN, refused
        return [f"error: {type(exc).__name__}"]
    if answer.rrset is None:
        return []
    if rtype == "MX":
        return [f"{r.preference} {r.exchange}".rstrip(".") for r in answer]
    if rtype == "TXT":
        return [" ".join(part.decode("utf-8", "replace") for part in r.strings)
                for r in answer]
    return [r.to_text() for r in answer]


def run(ctx) -> None:
    name = ctx.value("domain").strip()
    rtype = (ctx.value("rtype") or "A").upper()
    if not name:
        ctx.error("Enter a domain.")
        return

    ctx.title(f"DNS propagation — {name} ({rtype})")
    ctx.muted("Each public resolver is asked directly; disagreement means the change "
              "has not reached everyone yet.")

    results = []
    for label, server in RESOLVERS:
        ctx.check_cancel()
        ctx.status(f"Asking {label} ({server}) ...")
        answers = _query(server, name, rtype)
        results.append((label, server, answers))

    ctx.section("Answers")
    rows = []
    for label, server, answers in results:
        joined = ", ".join(answers) if answers else "(no answer)"
        rows.append((label, server, joined[:90]))
    ctx.table(("Resolver", "Server", "Answer"), rows)

    distinct = {tuple(sorted(answers)) for _label, _server, answers in results}
    ctx.section("Verdict")
    ctx.kv("Distinct answer sets", len(distinct))
    if len(distinct) == 1:
        ctx.ok("Every resolver agrees — the record is consistent.")
    elif len(distinct) > 1:
        ctx.warn("Resolvers disagree; propagation is still in progress or split-horizon DNS is in use.")
        for label, server, answers in results:
            if answers:
                ctx.text(f"  {label}: {', '.join(answers[:4])}")

    ctx.note("Negative answers are often cached for the TTL of the previous record.")
    ctx.link("Check from many locations", f"https://dnschecker.org/#{rtype}/{name}")


MODULE = Module(
    id="dns_propagation",
    title="DNS Propagation",
    category="Network",
    summary="Ask five public resolvers for the same record and compare their answers.",
    fields=(
        Field("domain", "Domain", placeholder="example.com", required=True),
        Field("rtype", "Record", kind="choice",
              choices=("A", "AAAA", "MX", "TXT", "NS", "CNAME"), default="A"),
    ),
    run=run,
    order=22,
)
