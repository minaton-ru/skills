#!/usr/bin/env python3
"""Collect the PyPI, GitHub and CVE figures that the comparing-python-libraries skill needs.

Usage:
    python3 scripts/collect_metrics.py <pypi-name> [<pypi-name> ...]

Where `python3` is missing, as is common on Windows, run it with `python` or `py -3`.
Requires Python 3.12+ and the standard library only.

GitHub access, first available wins (recorded in the "auth" field):
    "gh"    - `gh api`, when the gh CLI is installed and `gh auth status` succeeds;
    "token" - urllib with the GITHUB_TOKEN environment variable;
    "none"  - urllib without authorization (low rate limits, fewer commit pages read).

Output: a JSON array on stdout, UTF-8, one object per library. Every figure is
{"value": ..., "source": "<URL a person can open in a browser>"}. A field that could not be
collected is null and its reason is under "errors": "not found", "not accessible",
"rate limited" or "host not supported" (only GitHub repositories are measured). Progress and
diagnostics go to stderr. The exit code is 0 even when some data is missing; it is non-zero
only for invalid arguments.

"cves" is a summary, not a list: the CVE count and the latest publication date, then the CVEs
that affect the latest release ("unfixed") and those the script could not decide on
("needs_manual_check"), each as {"id", "published", "source"}. Advisories without a CVE id are
only counted.

Example output (illustrative, abridged; the figures are not real; <advisories> stands for
https://github.com/advisories?query=ecosystem%3Apip+affects%3Ahttpx):
    [
      {
        "pypi_name": "httpx",
        "on_pypi": true,
        "latest_version": {"value": "0.28.1", "source": "https://pypi.org/project/httpx/0.28.1/"},
        "repo_url": "https://github.com/encode/httpx",
        "host": "github.com",
        "auth": "gh",
        "archived": {"value": false, "source": "https://github.com/encode/httpx"},
        "forks": {"value": 900, "source": "https://github.com/encode/httpx"},
        "cves": {
          "count": {"value": 1, "source": "<advisories>"},
          "latest_published": {"value": "2022-04-28",
                               "source": "https://osv.dev/vulnerability/GHSA-h8pj-cxx2-jfg2"},
          "unfixed": [],
          "needs_manual_check": [],
          "advisories_without_cve": {"value": 0, "source": "<advisories>"}
        },
        "errors": {"used_by": "not found"}
      }
    ]
"""

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

GITHUB_API_URL = "https://api.github.com"
GITHUB_URL = "https://github.com"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "collect-metrics-script"
HTTP_TIMEOUT_SECONDS = 30

# GitHub rate limits: the search API allows 10 requests a minute without a token and 30 with
# one; the core API allows 60 requests an hour without a token and 5000 with one. Search calls
# are paced below; without a token the commit history is read in fewer pages to stay inside
# the hourly core budget.
SEARCH_PAUSE_SECONDS = {"gh": 2.1, "token": 2.1, "none": 6.5}
COMMIT_PAGE_LIMIT = {"gh": 10, "token": 10, "none": 3}
MAX_RETRIES = 3
# A rate-limit reset further away than this (an exhausted hourly limit) is reported as
# "rate limited" instead of blocking the run.
MAX_RETRY_WAIT_SECONDS = 70
ADVISORY_PAGE_LIMIT = 5

REPO_URL_KEYS = ("source", "repository", "code", "github", "homepage")
SEARCH_FIELDS = {
    "issues_total": ("type:issue", "issues?q=is%3Aissue"),
    "prs_total": ("type:pr", "pulls?q=is%3Apr"),
    "prs_merged": ("type:pr is:merged", "pulls?q=is%3Apr+is%3Amerged"),
    "prs_open": ("type:pr state:open", "pulls?q=is%3Apr+is%3Aopen"),
}
RESULT_FIELDS = (
    "latest_version", "repo_url", "host", "archived", "forks", "stars", "created_at", "license",
    "last_commit_date", "days_since_last_commit", "issues_total", "prs_total", "prs_merged",
    "prs_open", "contributors_total", "contributors_active_last_year", "used_by", "cves",
)

PACKAGE_MENU_PATTERN = re.compile(
    r'href="([^"]*\?package_id=[^"]*)"[^>]*?aria-checked="(true|false)".*?'
    r'<span class="select-menu-item-text">\s*(.*?)\s*</span>',
    re.DOTALL,
)
REPOSITORY_COUNT_PATTERN = re.compile(
    r'dependent_type=REPOSITORY[^"]*">.*?([\d,]+)\s*Repositories', re.DOTALL
)
LINK_PATTERN = re.compile(r'<([^>]+)>;\s*rel="(\w+)"')


class FetchError(Exception):
    """A source could not deliver a figure; the message is the status written to "errors"."""


@dataclass
class HttpResponse:
    """An HTTP response with lower-case header names and a decoded body."""

    status: int
    headers: dict[str, str]
    body: str


def log_message(text: str) -> None:
    """Write a diagnostic line to stderr.

    Args:
        text: The message to write.
    """
    print(text, file=sys.stderr, flush=True)


def make_figure(value: Any, source: str) -> dict[str, Any]:
    """Pair a value with the URL a person can open to check it.

    Args:
        value: The collected value.
        source: A browser-friendly URL showing the value.

    Returns:
        A {"value", "source"} dictionary.
    """
    return {"value": value, "source": source}


def normalize_package_name(name: str) -> str:
    """Normalize a package name as PEP 503 does, for comparisons.

    Args:
        name: A package name in any spelling.

    Returns:
        The lower-case name with runs of "-", "_" and "." replaced by "-".
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def lowercase_headers(headers: Any) -> dict[str, str]:
    """Return a header mapping with lower-case names.

    Args:
        headers: Any object with an items() method yielding name/value pairs.

    Returns:
        A dictionary of lower-case header names to values.
    """
    return {name.lower(): value for name, value in headers.items()}


def send_http_request(
    url: str, headers: dict[str, str] | None = None, data: bytes | None = None
) -> HttpResponse:
    """Send one HTTP request with urllib; redirects are followed.

    Args:
        url: The URL to request.
        headers: Extra request headers.
        data: A request body; when given the request is a POST.

    Returns:
        The response, including 4xx and 5xx ones.
    """
    request = urllib.request.Request(
        url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", "replace")
            return HttpResponse(response.status, lowercase_headers(response.headers), body)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        return HttpResponse(error.code, lowercase_headers(error.headers), body)


def parse_gh_output(raw_output: str) -> HttpResponse:
    """Parse the output of `gh api --include` into a response.

    Args:
        raw_output: The status line, headers, a blank line and the body.

    Returns:
        The parsed response.
    """
    head, _, body = raw_output.replace("\r\n", "\n").partition("\n\n")
    status_line, *header_lines = head.split("\n")
    headers: dict[str, str] = {}
    for line in header_lines:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return HttpResponse(int(status_line.split()[1]), headers, body)


def is_rate_limited(response: HttpResponse) -> bool:
    """Tell whether a response is a GitHub rate-limit rejection.

    Args:
        response: The response to check.

    Returns:
        True for a 429, or a 403 that carries rate-limit signs.
    """
    if response.status == 429:
        return True
    return response.status == 403 and (
        "retry-after" in response.headers
        or response.headers.get("x-ratelimit-remaining") == "0"
        or "rate limit" in response.body.lower()
    )


def compute_retry_wait(response: HttpResponse | None, attempt: int) -> float | None:
    """Work out how long to wait before retrying a failed request.

    Args:
        response: The failed response, or None after a network error.
        attempt: The zero-based number of the attempt that failed.

    Returns:
        Seconds to wait, or None when the wait would exceed MAX_RETRY_WAIT_SECONDS.
    """
    wait = 2.0 * 2**attempt
    if response is not None and "retry-after" in response.headers:
        wait = float(response.headers["retry-after"])
    elif response is not None and response.headers.get("x-ratelimit-remaining") == "0":
        reset_at = float(response.headers.get("x-ratelimit-reset", time.time()))
        wait = max(reset_at - time.time(), 0) + 1
    return wait if wait <= MAX_RETRY_WAIT_SECONDS else None


def fetch_with_retries(send_request: Callable[[], HttpResponse], label: str) -> HttpResponse:
    """Send a request, retrying rate limits, server errors and network errors.

    Args:
        send_request: A callable that sends the request once.
        label: What is being fetched, for diagnostics.

    Returns:
        The first response that needs no retry.

    Raises:
        FetchError: "rate limited" or "not accessible" when the retries run out.
    """
    response = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = send_request()
        except OSError as error:
            log_message(f"  {label}: {error}")
            response = None
        if response is not None and response.status < 500 and not is_rate_limited(response):
            return response
        wait = compute_retry_wait(response, attempt)
        if attempt == MAX_RETRIES or wait is None:
            break
        log_message(f"  {label}: retrying in {wait:.0f} s")
        time.sleep(wait)
    if response is not None and is_rate_limited(response):
        raise FetchError("rate limited")
    raise FetchError("not accessible")


def raise_for_status(response: HttpResponse) -> None:
    """Turn an unsuccessful response into a FetchError.

    Args:
        response: The response to check.

    Raises:
        FetchError: "not found" for 404, "not accessible" for any other non-2xx status.
    """
    if response.status == 404:
        raise FetchError("not found")
    if not 200 <= response.status < 300:
        raise FetchError("not accessible")


def fetch_public_json(url: str, payload: dict[str, Any] | None = None) -> Any:
    """Fetch JSON from a public API, POSTing the payload when one is given.

    Args:
        url: The API URL.
        payload: A JSON request body for POST requests.

    Returns:
        The decoded JSON.

    Raises:
        FetchError: When the request fails.
    """
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    response = fetch_with_retries(lambda: send_http_request(url, headers, data), url)
    raise_for_status(response)
    return json.loads(response.body)


def fetch_page_text(url: str) -> str:
    """Fetch an HTML page.

    Args:
        url: The page URL.

    Returns:
        The page source.

    Raises:
        FetchError: When the request fails.
    """
    response = fetch_with_retries(lambda: send_http_request(url), url)
    raise_for_status(response)
    return response.body


def find_link_target(response: HttpResponse, relation: str) -> str | None:
    """Return the URL of a relation in a response's Link header.

    Args:
        response: A GitHub API response.
        relation: The link relation, such as "next" or "last".

    Returns:
        The URL, or None when the header has no such relation.
    """
    links = LINK_PATTERN.findall(response.headers.get("link", ""))
    return next((url for url, name in links if name == relation), None)


class GitHubClient:
    """Calls the GitHub REST API through gh, a token or anonymously, with pacing and retries."""

    def __init__(self) -> None:
        """Pick the access mode: gh when it is installed and logged in, then token, then none."""
        self.gh_path = shutil.which("gh")
        if self.gh_path and not self.check_gh_login():
            self.gh_path = None
        self.token = os.environ.get("GITHUB_TOKEN", "").strip()
        self.auth_mode = "gh" if self.gh_path else "token" if self.token else "none"
        self.last_search_at = 0.0

    def check_gh_login(self) -> bool:
        """Tell whether `gh auth status` succeeds.

        Returns:
            True when gh is logged in.
        """
        try:
            result = subprocess.run(
                [self.gh_path, "auth", "status"], capture_output=True, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def send_gh_request(self, path: str) -> HttpResponse:
        """Send one request through `gh api`.

        Args:
            path: The API path without the leading slash.

        Returns:
            The response.

        Raises:
            ConnectionError: When gh produced no response at all.
        """
        result = subprocess.run(
            [self.gh_path, "api", "--include", path],
            capture_output=True, timeout=HTTP_TIMEOUT_SECONDS * 2, check=False,
        )
        output = result.stdout.decode("utf-8", "replace")
        if not output.startswith("HTTP/"):
            raise ConnectionError(result.stderr.decode("utf-8", "replace").strip())
        return parse_gh_output(output)

    def send_api_request(self, path: str) -> HttpResponse:
        """Send one API request in the selected access mode.

        Args:
            path: The API path without the leading slash.

        Returns:
            The response.
        """
        if self.gh_path:
            return self.send_gh_request(path)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return send_http_request(f"{GITHUB_API_URL}/{path}", headers)

    def wait_for_search_slot(self) -> None:
        """Sleep until the pause between search requests has passed."""
        pause = SEARCH_PAUSE_SECONDS[self.auth_mode]
        delay = self.last_search_at + pause - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self.last_search_at = time.monotonic()

    def fetch_api_response(self, path: str) -> HttpResponse:
        """Fetch an API path, pacing search calls and retrying rejected ones.

        Args:
            path: The API path, or a full api.github.com URL from a Link header.

        Returns:
            A successful response.

        Raises:
            FetchError: When the request fails.
        """
        path = path.removeprefix(f"{GITHUB_API_URL}/")
        if path.startswith("search/"):
            self.wait_for_search_slot()
        response = fetch_with_retries(lambda: self.send_api_request(path), path)
        raise_for_status(response)
        return response


def find_repo_url(info: dict[str, Any]) -> str | None:
    """Pick the repository URL from PyPI metadata, preferring a GitHub one.

    Args:
        info: The "info" object of the PyPI JSON API.

    Returns:
        The cleaned repository URL, or None when PyPI lists none.
    """
    project_urls = {
        key.strip().lower(): url for key, url in (info.get("project_urls") or {}).items() if url
    }
    candidates = [project_urls[key] for key in REPO_URL_KEYS if key in project_urls]
    if info.get("home_page"):
        candidates.append(info["home_page"])
    cleaned = [clean_repo_url(url) for url in candidates]
    github_urls = [url for url in cleaned if url.startswith(f"{GITHUB_URL}/")]
    return (github_urls or cleaned or [None])[0]


def clean_repo_url(url: str) -> str:
    """Strip ".git", "/tree/..." and trailing slashes; reduce GitHub URLs to owner/repo.

    Args:
        url: A repository URL from PyPI.

    Returns:
        The cleaned URL.
    """
    url = re.sub(r"/(tree|blob)/.*$", "", url.strip()).rstrip("/").removesuffix(".git")
    parts = urllib.parse.urlsplit(url)
    path_parts = [part for part in parts.path.split("/") if part]
    if parts.hostname in ("github.com", "www.github.com") and len(path_parts) >= 2:
        return f"{GITHUB_URL}/{path_parts[0]}/{path_parts[1]}"
    return url


def collect_repo_basics(repo: dict[str, Any]) -> dict[str, Any]:
    """Extract the figures that come with the repository object.

    Args:
        repo: The response of GET /repos/{owner}/{repo}.

    Returns:
        Result fields keyed by name.
    """
    source = repo["html_url"]
    license_info = repo.get("license") or {}
    return {
        "repo_url": source,
        "archived": make_figure(repo["archived"], source),
        "forks": make_figure(repo["forks_count"], source),
        "stars": make_figure(repo["stargazers_count"], source),
        "created_at": make_figure(repo["created_at"][:10], source),
        "license": make_figure(license_info.get("spdx_id"), source),
    }


def collect_last_commit(
    client: GitHubClient, slug: str, branch: str, now: datetime
) -> dict[str, Any]:
    """Find the date of the last commit on the default branch.

    Args:
        client: The GitHub client.
        slug: The repository as "owner/repo".
        branch: The default branch.
        now: The current UTC time.

    Returns:
        The last_commit_date and days_since_last_commit fields.

    Raises:
        FetchError: When the commit cannot be fetched.
    """
    quoted_branch = urllib.parse.quote(branch, safe="")
    commits = json.loads(
        client.fetch_api_response(f"repos/{slug}/commits?sha={quoted_branch}&per_page=1").body
    )
    if not commits:
        raise FetchError("not found")
    committed_at = datetime.fromisoformat(commits[0]["commit"]["committer"]["date"])
    source = f"{GITHUB_URL}/{slug}/commits/{branch}"
    return {
        "last_commit_date": make_figure(committed_at.date().isoformat(), source),
        "days_since_last_commit": make_figure((now - committed_at).days, source),
    }


def collect_search_count(
    client: GitHubClient, slug: str, field: str, qualifiers: str, source_query: str
) -> dict[str, Any]:
    """Count issues or pull requests with the search API.

    Args:
        client: The GitHub client.
        slug: The repository as "owner/repo".
        field: The result field to fill.
        qualifiers: Search qualifiers added to "repo:owner/repo".
        source_query: The path and query of the matching github.com page.

    Returns:
        The single filled field.

    Raises:
        FetchError: When the search fails.
    """
    query = urllib.parse.quote(f"repo:{slug} {qualifiers}", safe="")
    response = client.fetch_api_response(f"search/issues?q={query}&per_page=1")
    total = json.loads(response.body)["total_count"]
    return {field: make_figure(total, f"{GITHUB_URL}/{slug}/{source_query}")}


def collect_contributor_total(client: GitHubClient, slug: str) -> dict[str, Any]:
    """Count contributors from the last page number of a one-per-page listing.

    Args:
        client: The GitHub client.
        slug: The repository as "owner/repo".

    Returns:
        The contributors_total field.

    Raises:
        FetchError: When the listing fails.
    """
    response = client.fetch_api_response(f"repos/{slug}/contributors?per_page=1")
    last_page = find_link_target(response, "last")
    if last_page:
        total = int(urllib.parse.parse_qs(urllib.parse.urlsplit(last_page).query)["page"][0])
    else:
        total = len(json.loads(response.body or "[]"))
    source = f"{GITHUB_URL}/{slug}/graphs/contributors"
    return {"contributors_total": make_figure(total, source)}


def collect_active_contributors(
    client: GitHubClient, slug: str, branch: str, now: datetime
) -> dict[str, Any]:
    """Count distinct commit authors on the default branch over the last 365 days.

    Args:
        client: The GitHub client.
        slug: The repository as "owner/repo".
        branch: The default branch.
        now: The current UTC time.

    Returns:
        The contributors_active_last_year field; "capped" is true when the page limit cut
        the count short.

    Raises:
        FetchError: When a page cannot be fetched.
    """
    since = (now - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    quoted_branch = urllib.parse.quote(branch, safe="")
    path: str | None = f"repos/{slug}/commits?sha={quoted_branch}&since={since}&per_page=100"
    authors: set[str] = set()
    page_limit = COMMIT_PAGE_LIMIT[client.auth_mode]
    for _ in range(page_limit):
        response = client.fetch_api_response(path)
        for commit in json.loads(response.body):
            author = commit.get("author") or {}
            authors.add(author.get("login") or commit["commit"]["author"]["email"].lower())
        path = find_link_target(response, "next")
        if not path:
            break
    figure = make_figure(len(authors), f"{GITHUB_URL}/{slug}/graphs/contributors")
    return {"contributors_active_last_year": {**figure, "capped": path is not None}}


def parse_repository_count(page: str) -> int | None:
    """Read the dependent repository count from a dependents page.

    Args:
        page: The HTML of a /network/dependents page.

    Returns:
        The count, or None when the page does not show one.
    """
    match = REPOSITORY_COUNT_PATTERN.search(page)
    return int(match.group(1).replace(",", "")) if match else None


def collect_used_by(slug: str, pypi_name: str) -> dict[str, Any]:
    """Read "Used by" from the dependents page, picking the package that matches PyPI.

    Args:
        slug: The repository as "owner/repo".
        pypi_name: The PyPI name of the library.

    Returns:
        The used_by field.

    Raises:
        FetchError: "not found" when the package or the count cannot be found.
    """
    url = f"{GITHUB_URL}/{slug}/network/dependents"
    page = fetch_page_text(url)
    packages = PACKAGE_MENU_PATTERN.findall(page)
    if packages:
        wanted = normalize_package_name(pypi_name)
        match = next(
            (item for item in packages
             if normalize_package_name(html.unescape(item[2])) == wanted),
            None,
        )
        if match is None:
            raise FetchError("not found")
        href, checked, _ = match
        if checked != "true":
            url = f"{GITHUB_URL}{html.unescape(href)}"
            page = fetch_page_text(url)
    count = parse_repository_count(page)
    if count is None:
        raise FetchError("not found")
    return {"used_by": make_figure(count, url)}


def apply_collector(
    result: dict[str, Any], error_key: str, collector: Callable[..., dict[str, Any]], *args: Any
) -> None:
    """Run a collector and merge its fields, or record its failure under "errors".

    Args:
        result: The library's result object.
        error_key: The "errors" key to use on failure.
        collector: A function returning result fields.
        *args: Arguments for the collector.
    """
    try:
        result.update(collector(*args))
    except FetchError as error:
        result["errors"][error_key] = str(error)


def collect_github_metrics(
    result: dict[str, Any], client: GitHubClient, repo_url: str, now: datetime
) -> None:
    """Fill every GitHub-based field of a library's result.

    Args:
        result: The library's result object, updated in place.
        client: The GitHub client.
        repo_url: The cleaned https://github.com/owner/repo URL.
        now: The current UTC time.
    """
    slug = repo_url.removeprefix(f"{GITHUB_URL}/")
    try:
        repo = json.loads(client.fetch_api_response(f"repos/{slug}").body)
    except FetchError as error:
        result["errors"]["repo"] = str(error)
        return
    result.update(collect_repo_basics(repo))
    slug, branch = repo["full_name"], repo["default_branch"]
    apply_collector(result, "last_commit_date", collect_last_commit, client, slug, branch, now)
    for field, (qualifiers, source_query) in SEARCH_FIELDS.items():
        apply_collector(
            result, field, collect_search_count, client, slug, field, qualifiers, source_query
        )
    apply_collector(result, "contributors_total", collect_contributor_total, client, slug)
    apply_collector(
        result, "contributors_active_last_year", collect_active_contributors,
        client, slug, branch, now,
    )
    apply_collector(result, "used_by", collect_used_by, slug, result["pypi_name"])


def query_osv_records(pypi_name: str, version: str | None) -> list[dict[str, Any]]:
    """Query OSV for a PyPI package, following every result page; withdrawn records are dropped.

    Args:
        pypi_name: The PyPI name.
        version: Limit the query to records affecting this version; None for all records.

    Returns:
        The OSV records.

    Raises:
        FetchError: When OSV cannot be queried.
    """
    payload: dict[str, Any] = {"package": {"name": pypi_name, "ecosystem": "PyPI"}}
    if version:
        payload["version"] = version
    records: list[dict[str, Any]] = []
    while True:
        response = fetch_public_json(OSV_QUERY_URL, payload)
        records.extend(record for record in response.get("vulns", []) if "withdrawn" not in record)
        if not response.get("next_page_token"):
            return records
        payload["page_token"] = response["next_page_token"]


def group_osv_records(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group OSV records that describe one vulnerability (shared id or alias, such as a CVE).

    Args:
        records: OSV records.

    Returns:
        Groups of records.
    """
    groups: list[tuple[set[str], list[dict[str, Any]]]] = []
    for record in records:
        ids = {record["id"], *record.get("aliases", [])}
        group = next((group for group in groups if group[0] & ids), None)
        if group:
            group[0].update(ids)
            group[1].append(record)
        else:
            groups.append((ids, [record]))
    return [group_records for _, group_records in groups]


def summarize_osv_group(
    records: list[dict[str, Any]], latest_ids: set[str]
) -> tuple[bool, dict[str, Any]]:
    """Turn a group of OSV records into one vulnerability entry.

    Args:
        records: OSV records of one vulnerability.
        latest_ids: Ids of the records that affect the latest release.

    Returns:
        Whether the vulnerability has a CVE id, and the entry: its CVE id (or the advisory id
        when there is none), publication date, affects_latest and source.
    """
    osv_ids = sorted(record["id"] for record in records)
    all_ids = [
        record_id for record in records
        for record_id in (record["id"], *record.get("aliases", []))
    ]
    cve_id = next((record_id for record_id in all_ids if record_id.startswith("CVE-")), None)
    preferred_id = next((osv_id for osv_id in osv_ids if osv_id.startswith("GHSA-")), osv_ids[0])
    return cve_id is not None, {
        "id": cve_id or preferred_id,
        "published": min(record.get("published", "") for record in records)[:10] or None,
        "affects_latest": any(record["id"] in latest_ids for record in records),
        "source": f"https://osv.dev/vulnerability/{preferred_id}",
    }


def fetch_github_advisories(client: GitHubClient, pypi_name: str) -> list[dict[str, Any]]:
    """List the GitHub Advisory Database entries for a pip package, skipping withdrawn ones.

    Args:
        client: The GitHub client.
        pypi_name: The PyPI name.

    Returns:
        The advisories.

    Raises:
        FetchError: When the listing fails.
    """
    package = urllib.parse.quote(pypi_name, safe="")
    path: str | None = f"advisories?ecosystem=pip&affects={package}&per_page=100"
    advisories: list[dict[str, Any]] = []
    for _ in range(ADVISORY_PAGE_LIMIT):
        response = client.fetch_api_response(path)
        advisories.extend(item for item in json.loads(response.body) if not item["withdrawn_at"])
        path = find_link_target(response, "next")
        if not path:
            break
    return advisories


def summarize_github_advisory(
    advisory: dict[str, Any], pypi_name: str
) -> dict[str, Any]:
    """Turn a GitHub advisory into a CVE entry.

    Args:
        advisory: An advisory from GET /advisories.
        pypi_name: The PyPI name.

    Returns:
        The CVE entry. affects_latest is True when no patched version exists, otherwise None:
        comparing versions needs the packaging library, which this script does without.
    """
    wanted = normalize_package_name(pypi_name)
    patched_versions = [
        vulnerability.get("first_patched_version")
        for vulnerability in advisory.get("vulnerabilities") or []
        if normalize_package_name(vulnerability["package"]["name"]) == wanted
    ]
    is_unpatched = bool(patched_versions) and not any(patched_versions)
    return {
        "id": advisory["cve_id"],
        "published": (advisory.get("published_at") or "")[:10] or None,
        "affects_latest": True if is_unpatched else None,
        "source": advisory["html_url"],
    }


def describe_cve(entry: dict[str, Any]) -> dict[str, Any]:
    """Keep the fields the report needs to name a CVE.

    Args:
        entry: A vulnerability entry.

    Returns:
        The id, publication date and source of the entry.
    """
    return {key: entry[key] for key in ("id", "published", "source")}


def build_cve_summary(
    cves: list[dict[str, Any]], advisory_count: int, pypi_name: str
) -> dict[str, Any]:
    """Summarize the CVEs of a package for screening and the CVEs criterion.

    Args:
        cves: One entry per CVE.
        advisory_count: The number of advisories without a CVE id.
        pypi_name: The PyPI name.

    Returns:
        The count, the most recent publication date, the CVEs affecting the latest release,
        the CVEs whose effect on it is unknown, and the count of advisories without a CVE id.
    """
    package = urllib.parse.quote(pypi_name, safe="")
    source = f"{GITHUB_URL}/advisories?query=ecosystem%3Apip+affects%3A{package}"
    latest = max(cves, key=lambda entry: entry["published"] or "", default=None)
    return {
        "count": make_figure(len(cves), source),
        "latest_published": make_figure(latest["published"], latest["source"]) if latest else None,
        "unfixed": [describe_cve(entry) for entry in cves if entry["affects_latest"] is True],
        "needs_manual_check": [
            describe_cve(entry) for entry in cves if entry["affects_latest"] is None
        ],
        "advisories_without_cve": make_figure(advisory_count, source),
    }


def collect_vulnerabilities(
    result: dict[str, Any], client: GitHubClient, pypi_name: str, version: str
) -> None:
    """Fill the cves summary from OSV and GitHub advisories.

    Args:
        result: The library's result object, updated in place.
        client: The GitHub client.
        pypi_name: The PyPI name.
        version: The latest PyPI version.
    """
    errors = result["errors"]
    try:
        all_records = query_osv_records(pypi_name, None)
        latest_ids = {record["id"] for record in query_osv_records(pypi_name, version)}
    except FetchError as error:
        errors["cves"] = str(error)
        return
    cves: list[dict[str, Any]] = []
    advisory_count = 0
    for group in group_osv_records(all_records):
        has_cve, entry = summarize_osv_group(group, latest_ids)
        if has_cve:
            cves.append(entry)
        else:
            advisory_count += 1
    try:
        github_advisories = fetch_github_advisories(client, pypi_name)
    except FetchError as error:
        errors["github_advisories"] = str(error)
        github_advisories = []
    known_cves = {entry["id"] for entry in cves}
    for advisory in github_advisories:
        if not advisory.get("cve_id") or advisory["cve_id"] in known_cves:
            continue
        cves.append(summarize_github_advisory(advisory, pypi_name))
        known_cves.add(advisory["cve_id"])
    result["cves"] = build_cve_summary(cves, advisory_count, pypi_name)


def collect_library_metrics(
    pypi_name: str, client: GitHubClient, now: datetime
) -> dict[str, Any]:
    """Collect every figure for one library.

    Args:
        pypi_name: The PyPI name.
        client: The GitHub client.
        now: The current UTC time.

    Returns:
        The library's result object.
    """
    log_message(f"{pypi_name}: collecting")
    result: dict[str, Any] = {"pypi_name": pypi_name, "on_pypi": None, "auth": client.auth_mode}
    result.update(dict.fromkeys(RESULT_FIELDS))
    result["errors"] = {}
    pypi_url = f"https://pypi.org/pypi/{urllib.parse.quote(pypi_name)}/json"
    try:
        info = fetch_public_json(pypi_url)["info"]
    except FetchError as error:
        if str(error) == "not found":
            result["on_pypi"] = False
        else:
            result["errors"]["pypi"] = str(error)
        return result
    result["on_pypi"] = True
    version = info["version"]
    result["latest_version"] = make_figure(
        version, f"https://pypi.org/project/{pypi_name}/{version}/"
    )
    repo_url = find_repo_url(info)
    result["repo_url"] = repo_url
    result["host"] = urllib.parse.urlsplit(repo_url).hostname if repo_url else None
    if repo_url is None:
        result["errors"]["repo_url"] = "not found"
    elif result["host"] == "github.com":
        collect_github_metrics(result, client, repo_url, now)
    else:
        result["errors"]["repo_url"] = "host not supported"
    collect_vulnerabilities(result, client, pypi_name, version)
    return result


def parse_arguments() -> list[str]:
    """Read the PyPI names from the command line; argparse exits non-zero on bad arguments.

    Returns:
        The PyPI names.
    """
    parser = argparse.ArgumentParser(
        description="Collect PyPI, GitHub and CVE figures for Python libraries as JSON."
    )
    parser.add_argument("names", nargs="+", metavar="pypi-name", help="a PyPI package name")
    return parser.parse_args().names


def main() -> None:
    """Collect figures for every library named on the command line and print them as JSON."""
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    names = parse_arguments()
    client = GitHubClient()
    log_message(f"GitHub access: {client.auth_mode}")
    now = datetime.now(timezone.utc)
    results = [collect_library_metrics(name, client, now) for name in names]
    json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
