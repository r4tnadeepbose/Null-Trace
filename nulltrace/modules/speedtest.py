"""Connection throughput test via speedtest-cli."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from ..job import Module


def _with_timeout(fn, seconds: float, label: str):
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(fn)
    try:
        return future.result(timeout=seconds)
    except FutureTimeout as exc:
        raise TimeoutError(f"{label} timed out after {seconds:.0f}s") from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def run(ctx) -> None:
    try:
        import speedtest
    except ImportError:
        ctx.error("speedtest-cli is not installed — run: pip install speedtest-cli")
        return

    ctx.title("Speed test")
    ctx.note("Selecting a server and measuring throughput can take up to two minutes.")
    ctx.status("Selecting the nearest server ...")
    try:
        client = speedtest.Speedtest(secure=True)
        best = _with_timeout(lambda: client.get_best_server(), 45, "Server selection")
    except Exception as exc:
        ctx.error(f"Could not reach a speedtest server: {exc}")
        ctx.note("Corporate networks and some ISPs block the Ookla endpoints.")
        return

    ctx.section("Server")
    ctx.kv("Sponsor", best.get("sponsor"))
    ctx.kv("Name", best.get("name"))
    ctx.kv("Country", best.get("country"))
    ctx.kv("Distance", f"{best.get('d')} km")
    latency = best.get("latency")
    ctx.kv("Latency", f"{latency:.2f} ms" if isinstance(latency, (int, float)) else latency)

    ctx.check_cancel()
    ctx.status("Testing download ...")
    try:
        download = _with_timeout(client.download, 90, "Download test")
    except Exception as exc:
        ctx.error(f"Download test failed: {exc}")
        download = 0

    ctx.check_cancel()
    ctx.status("Testing upload ...")
    try:
        upload = _with_timeout(client.upload, 90, "Upload test")
    except Exception as exc:
        ctx.error(f"Upload test failed: {exc}")
        upload = 0

    ctx.section("Throughput")
    ctx.kv("Download", f"{download / 1_000_000:.2f} Mbps" if download else "—")
    ctx.kv("Upload", f"{upload / 1_000_000:.2f} Mbps" if upload else "—")
    results = client.results
    client_info = getattr(results, "client", {}) or {}
    ctx.kv("Client IP", client_info.get("ip"))
    ctx.kv("ISP", client_info.get("isp"))
    try:
        ctx.link("Shareable result", results.share())
    except Exception:
        ctx.link("Speedtest", "https://www.speedtest.net")


MODULE = Module(
    id="speedtest",
    title="Speed Test",
    category="System",
    summary="Measure latency, download and upload throughput against the nearest Ookla server.",
    fields=(),
    run=run,
    order=170,
)
