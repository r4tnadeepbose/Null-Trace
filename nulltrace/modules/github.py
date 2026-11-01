"""GitHub reconnaissance: profiles, repositories and commit email exposure."""

from __future__ import annotations

from ..job import Field, Module
from ..net import HttpError, get_json

MODES = ("User profile", "Repository", "Email in commits")
API = "https://api.github.com"


def _headers(ctx) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.key("github")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        ctx.muted("No GitHub token — limited to 60 requests/hour.")
    return headers


def _user(ctx, name: str, headers: dict) -> None:
    profile = get_json(f"{API}/users/{name}", headers=headers)
    ctx.section("Profile")
    for label, key in (("Name", "name"), ("Login", "login"), ("Company", "company"),
                       ("Location", "location"), ("Blog", "blog"), ("Bio", "bio"),
                       ("Email", "email"), ("Twitter", "twitter_username"),
                       ("Public repos", "public_repos"), ("Followers", "followers"),
                       ("Following", "following"), ("Created", "created_at"),
                       ("Updated", "updated_at")):
        value = profile.get(key)
        if value:
            ctx.kv(label, value)
    ctx.link("Profile", profile.get("html_url", ""))

    repos = get_json(f"{API}/users/{name}/repos?per_page=100&sort=pushed", headers=headers)
    if isinstance(repos, list) and repos:
        ctx.section(f"Repositories ({len(repos)})")
        rows = [(
            r.get("name"),
            r.get("language") or "—",
            r.get("stargazers_count"),
            r.get("forks_count"),
            (r.get("pushed_at") or "")[:10],
        ) for r in repos[:30]]
        ctx.table(("Repo", "Language", "Stars", "Forks", "Last push"), rows)
        forked = [r["name"] for r in repos if r.get("fork")]
        if forked:
            ctx.muted(f"Forked: {', '.join(forked[:10])}")

    try:
        events = get_json(f"{API}/users/{name}/events/public?per_page=20", headers=headers)
    except HttpError:
        events = []
    if isinstance(events, list) and events:
        ctx.section("Recent public activity")
        for event in events[:10]:
            repo = event.get("repo", {}).get("name", "?")
            ctx.text(f"  {event.get('created_at', '')[:10]}  {event.get('type')}  {repo}")


def _repo(ctx, slug: str, headers: dict) -> None:
    data = get_json(f"{API}/repos/{slug}", headers=headers)
    ctx.section("Repository")
    for label, key in (("Full name", "full_name"), ("Description", "description"),
                       ("Language", "language"), ("Stars", "stargazers_count"),
                       ("Forks", "forks_count"), ("Watchers", "subscribers_count"),
                       ("Open issues", "open_issues_count"), ("Default branch", "default_branch"),
                       ("Created", "created_at"), ("Pushed", "pushed_at"),
                       ("Archived", "archived"), ("Fork", "fork")):
        ctx.kv(label, data.get(key))
    license_info = (data.get("license") or {}).get("name")
    if license_info:
        ctx.kv("License", license_info)
    ctx.link("Repository", data.get("html_url", ""))

    try:
        commits = get_json(f"{API}/repos/{slug}/commits?per_page=10", headers=headers)
    except HttpError:
        commits = []
    if isinstance(commits, list) and commits:
        ctx.section("Latest commits")
        rows = []
        for commit in commits:
            detail = commit.get("commit", {})
            author = detail.get("author", {})
            rows.append((
                commit.get("sha", "")[:7],
                (author.get("name") or "?")[:22],
                (author.get("email") or "?")[:34],
                (author.get("date") or "")[:10],
                (detail.get("message") or "").splitlines()[0][:60],
            ))
        ctx.table(("SHA", "Author", "Email", "Date", "Message"), rows)


def _email(ctx, email: str, headers: dict) -> None:
    search_headers = dict(headers)
    search_headers["Accept"] = "application/vnd.github.cloak-preview+json"
    try:
        data = get_json(
            f"{API}/search/commits?q=author-email:{email}&per_page=30",
            headers=search_headers,
        )
    except HttpError as exc:
        ctx.error(f"Commit search failed: {exc}")
        ctx.note("This endpoint requires authentication — add a GitHub token in Settings.")
        return
    total = data.get("total_count", 0)
    ctx.kv("Commit hits", total)
    for item in (data.get("items") or [])[:20]:
        repo = (item.get("repository") or {}).get("full_name", "?")
        commit = item.get("commit", {})
        author = commit.get("author", {})
        ctx.text(f"  {repo}  {item.get('sha', '')[:7]}  {(author.get('name') or '?')}  "
                 f"{(author.get('date') or '')[:10]}")
        ctx.muted(f"    {(commit.get('message') or '').splitlines()[0][:100]}")
    if total:
        ctx.warn("A commit email exposes the account's real address — check the user's consent.")


def run(ctx) -> None:
    mode = ctx.value("mode") or MODES[0]
    target = ctx.value("target").strip().lstrip("@")
    if not target:
        ctx.error("Enter a username, owner/repo or email.")
        return
    headers = _headers(ctx)
    ctx.title(f"GitHub — {target}")
    try:
        if mode == "User profile":
            _user(ctx, target, headers)
        elif mode == "Repository":
            if "/" not in target:
                ctx.error("Repository mode needs owner/repo, e.g. torvalds/linux.")
                return
            _repo(ctx, target, headers)
        else:
            _email(ctx, target, headers)
    except HttpError as exc:
        if "403" in str(exc) or "429" in str(exc):
            ctx.error("GitHub rate limit reached — add a token in Settings.")
        elif "404" in str(exc):
            ctx.error("Not found.")
        else:
            ctx.error(str(exc))


MODULE = Module(
    id="github",
    title="GitHub Recon",
    category="Identity",
    summary="Profile and repository intel, recent activity, and commit-history email discovery.",
    fields=(
        Field("mode", "Mode", kind="choice", choices=MODES, default=MODES[0]),
        Field("target", "Username / owner-repo / email", placeholder="torvalds  |  torvalds/linux",
              required=True),
    ),
    keys=("github",),
    run=run,
    order=200,
)
