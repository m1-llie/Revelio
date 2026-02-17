#!/usr/bin/env python3
"""
End-to-end CVE dataset builder.

Pipeline steps (each is skipped when its output already exists):
  1. Download all CVEs from NVD              → all_cves.jsonl
  2. Filter for memory-safety CWEs           → all_cves_memory_safety.jsonl
  3. Fetch patches from GitHub / GitLab      → patches/{CVE-ID}.patch
  4. Validate patches with GPT               → patch_validation_results.jsonl
  5. Classify patches & produce final output → cve_dataset.jsonl

Environment variables:
  NVD_API_KEY     – NVD API key (optional, speeds up step 1)
  GITHUB_TOKEN    – GitHub PAT (recommended for steps 3-4)
  GITLAB_TOKEN    – GitLab PAT (optional, for private GitLab repos)
  OPENAI_API_KEY  – OpenAI API key (required for step 4)

Usage:
    python build_dataset.py [--limit N] [--gh-workers N] [--llm-workers N]
                            [--model MODEL] [--output FILE]
"""

import argparse
import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote_plus

import aiohttp
import requests
from openai import AsyncOpenAI
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class TqdmLoggingHandler(logging.Handler):
    """Logging handler that uses tqdm.write to avoid colliding with progress bars."""

    def emit(self, record):
        try:
            tqdm.write(self.format(record))
        except Exception:
            self.handleError(record)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[TqdmLoggingHandler()],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths (all relative to script directory)
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path("/srv/share/vulagent/")
ALL_CVES_PATH = SCRIPT_DIR / "all_cves.jsonl"
MEMORY_SAFETY_CWES_PATH = SCRIPT_DIR / "memory_safety_cwes.json"
MEMORY_SAFETY_JSONL_PATH = SCRIPT_DIR / "all_cves_memory_safety.jsonl"
PATCHES_DIR = SCRIPT_DIR / "patches"
VALIDATION_RESULTS_PATH = SCRIPT_DIR / "patch_validation_results.jsonl"

# ---------------------------------------------------------------------------
# Step 1: Download CVEs from NVD
# ---------------------------------------------------------------------------

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 2000


def step1_download_cves():
    """Download all CVEs from NVD to all_cves.jsonl. Skips if file exists."""
    if ALL_CVES_PATH.exists():
        log.info("Step 1: %s already exists, skipping download.", ALL_CVES_PATH.name)
        return

    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    def fetch_page(start_index: int) -> dict:
        params = {"startIndex": start_index, "resultsPerPage": NVD_RESULTS_PER_PAGE}
        r = requests.get(NVD_BASE_URL, headers=headers, params=params)
        r.raise_for_status()
        return r.json()

    log.info("Step 1: Downloading CVEs from NVD ...")
    first = fetch_page(0)
    total = first["totalResults"]
    log.info("Total CVEs in NVD: %d", total)

    out = open(ALL_CVES_PATH, "w")
    written = 0
    for vuln in first["vulnerabilities"]:
        out.write(json.dumps(vuln) + "\n")
        written += 1

    pbar = tqdm(total=total, initial=written, unit="cve", desc="Downloading CVEs")

    start_index = NVD_RESULTS_PER_PAGE
    while start_index < total:
        data = fetch_page(start_index)
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            out.write(json.dumps(vuln) + "\n")
            written += 1
        pbar.update(len(vulns))
        start_index += NVD_RESULTS_PER_PAGE
        time.sleep(0.6 if api_key else 6)

    pbar.close()
    out.close()
    log.info("Step 1: Wrote %d CVEs to %s", written, ALL_CVES_PATH.name)


# ---------------------------------------------------------------------------
# Step 2: Filter for memory-safety CWEs
# ---------------------------------------------------------------------------


def _load_memory_safety_cwe_ids() -> set[str]:
    """Load the set of memory-safety CWE IDs from memory_safety_cwes.json."""
    data = json.loads(MEMORY_SAFETY_CWES_PATH.read_text())
    return set(data["all_cwe_ids"])


def _extract_cwe_ids(cve_obj: dict) -> set[str]:
    """Extract CWE IDs from a CVE object's weaknesses field."""
    cwe_ids = set()
    for weakness in cve_obj.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.add(val)
    return cwe_ids


def step2_filter_memory_safety():
    """Filter all_cves.jsonl for memory-safety CVEs → all_cves_memory_safety.jsonl."""
    if MEMORY_SAFETY_JSONL_PATH.exists():
        log.info("Step 2: %s already exists, skipping filter.", MEMORY_SAFETY_JSONL_PATH.name)
        return

    log.info("Step 2: Filtering for memory-safety CVEs ...")
    ms_cwes = _load_memory_safety_cwe_ids()

    total = 0
    count = 0
    with open(ALL_CVES_PATH) as inf, open(MEMORY_SAFETY_JSONL_PATH, "w") as out:
        for line in inf:
            total += 1
            entry = json.loads(line)
            cve = entry.get("cve", {})
            cwe_ids = _extract_cwe_ids(cve)
            if cwe_ids & ms_cwes:
                out.write(line)
                count += 1

    log.info("Step 2: Wrote %d memory-safety CVEs (out of %d total) to %s",
             count, total, MEMORY_SAFETY_JSONL_PATH.name)


# ---------------------------------------------------------------------------
# Step 3: Fetch patches from GitHub / GitLab
# ---------------------------------------------------------------------------

# URL patterns

RE_GH_COMMIT = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-fA-F]+)$"
)
RE_GH_PR_COMMIT = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/\d+/commits/(?P<sha>[0-9a-fA-F]+)$"
)
RE_GH_PR = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)$"
)
RE_GL_COMMIT = re.compile(
    r"https?://gitlab\.com/(?P<project>.+?)/-/commit/(?P<sha>[0-9a-fA-F]+)$"
)
RE_GL_MR = re.compile(
    r"https?://gitlab\.com/(?P<project>.+?)/-/merge_requests/(?P<iid>\d+)$"
)


@dataclass
class GHCommit:
    owner: str
    repo: str
    sha: str


@dataclass
class GHPR:
    owner: str
    repo: str
    number: int


@dataclass
class GLCommit:
    project: str
    sha: str


@dataclass
class GLMR:
    project: str
    iid: int


def classify_url(url: str):
    """Return a typed URL object or None."""
    for pattern, cls, keys in [
        (RE_GH_COMMIT, GHCommit, ("owner", "repo", "sha")),
        (RE_GH_PR_COMMIT, GHCommit, ("owner", "repo", "sha")),
        (RE_GL_COMMIT, GLCommit, ("project", "sha")),
    ]:
        m = pattern.match(url)
        if m:
            return cls(**{k: m.group(k) for k in keys})
    m = RE_GH_PR.match(url)
    if m:
        return GHPR(m.group("owner"), m.group("repo"), int(m.group("number")))
    m = RE_GL_MR.match(url)
    if m:
        return GLMR(m.group("project"), int(m.group("iid")))
    return None


@dataclass
class CVERecord:
    cve_id: str
    actions: list = field(default_factory=list)


def _load_cve_records(path: Path, limit: int | None = None) -> list[CVERecord]:
    records = []
    with open(path) as f:
        for i, line in enumerate(f):
            if limit is not None and i >= limit:
                break
            obj = json.loads(line)
            cve = obj["cve"]
            cve_id = cve["id"]
            actions = []
            for ref in cve.get("references", []):
                action = classify_url(ref["url"])
                if action is not None:
                    actions.append(action)
            if actions:
                records.append(CVERecord(cve_id=cve_id, actions=actions))
    return records


def _deduplicate_actions(actions: list) -> list:
    gh_commits: dict[tuple, list[str]] = {}
    gh_prs: dict[tuple, list[int]] = {}
    gl_items = []

    for a in actions:
        if isinstance(a, GHCommit):
            key = (a.owner, a.repo)
            gh_commits.setdefault(key, [])
            if a.sha not in gh_commits[key]:
                gh_commits[key].append(a.sha)
        elif isinstance(a, GHPR):
            key = (a.owner, a.repo)
            gh_prs.setdefault(key, [])
            if a.number not in gh_prs[key]:
                gh_prs[key].append(a.number)
        else:
            gl_items.append(a)

    result = []
    for key in set(gh_commits.keys()) | set(gh_prs.keys()):
        if key in gh_commits:
            for sha in gh_commits[key]:
                result.append(GHCommit(key[0], key[1], sha))
        else:
            for number in gh_prs[key]:
                result.append(GHPR(key[0], key[1], number))
    result.extend(gl_items)
    return result


# --- HTTP helpers ---

GITHUB_API = "https://api.github.com"
GITLAB_API = "https://gitlab.com/api/v4"


async def _gh_request(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    rate_state: dict,
    url: str,
    headers: dict,
    max_retries: int = 3,
) -> str | None:
    for attempt in range(max_retries):
        async with sem:
            remaining = rate_state.get("remaining")
            if remaining is not None and remaining < 50:
                reset_at = rate_state.get("reset", 0)
                wait = max(0, reset_at - time.time()) + 1
                if wait > 0:
                    log.info("GitHub rate limit low (%d remaining), sleeping %.0fs", remaining, wait)
                    await asyncio.sleep(wait)
            try:
                async with session.get(url, headers=headers) as resp:
                    rl_rem = resp.headers.get("X-RateLimit-Remaining")
                    rl_rst = resp.headers.get("X-RateLimit-Reset")
                    if rl_rem is not None:
                        rate_state["remaining"] = int(rl_rem)
                    if rl_rst is not None:
                        rate_state["reset"] = int(rl_rst)

                    if resp.status == 200:
                        return await resp.text()
                    elif resp.status == 403:
                        retry_after = resp.headers.get("Retry-After")
                        wait = int(retry_after) if retry_after else max(0, rate_state.get("reset", 0) - time.time()) + 1
                        log.warning("GitHub 403 on %s, sleeping %.0fs (attempt %d)", url, wait, attempt + 1)
                        await asyncio.sleep(wait)
                        continue
                    elif resp.status in (404, 422):
                        return None
                    elif resp.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                log.warning("GitHub request error on %s: %s, retrying in %ds", url, e, 2 ** attempt)
                await asyncio.sleep(2 ** attempt)
                continue
    return None


async def _fetch_gh_commit_diff(session, sem, rate_state, owner, repo, sha):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    return await _gh_request(session, sem, rate_state, url, {"Accept": "application/vnd.github.v3.diff"})


async def _fetch_gh_pr_diff(session, sem, rate_state, owner, repo, number):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{number}"
    return await _gh_request(session, sem, rate_state, url, {"Accept": "application/vnd.github.v3.diff"})


async def _gl_request(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    url: str,
    gl_token: str | None,
    is_diff_array: bool = False,
    is_mr_changes: bool = False,
    max_retries: int = 3,
) -> str | None:
    headers = {}
    if gl_token:
        headers["PRIVATE-TOKEN"] = gl_token
    for attempt in range(max_retries):
        async with sem:
            try:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return _gl_json_to_diff(data, is_diff_array, is_mr_changes)
                    elif resp.status == 429:
                        wait = int(resp.headers.get("Retry-After", "60"))
                        await asyncio.sleep(wait)
                        continue
                    elif resp.status == 404:
                        return None
                    elif resp.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(2 ** attempt)
                continue
    return None


def _gl_json_to_diff(data, is_diff_array=False, is_mr_changes=False) -> str:
    if is_diff_array:
        items = data if isinstance(data, list) else []
    elif is_mr_changes:
        items = data.get("changes", []) if isinstance(data, dict) else []
    else:
        items = []
    parts = []
    for item in items:
        old_p, new_p = item.get("old_path", ""), item.get("new_path", "")
        parts.append(f"diff --git a/{old_p} b/{new_p}\n{item.get('diff', '')}")
    return "\n".join(parts)


async def _fetch_gl_commit_diff(session, sem, project, sha, gl_token):
    encoded = quote_plus(project)
    url = f"{GITLAB_API}/projects/{encoded}/repository/commits/{sha}/diff"
    return await _gl_request(session, sem, url, gl_token, is_diff_array=True)


async def _fetch_gl_mr_diff(session, sem, project, iid, gl_token):
    encoded = quote_plus(project)
    url = f"{GITLAB_API}/projects/{encoded}/merge_requests/{iid}/changes"
    return await _gl_request(session, sem, url, gl_token, is_mr_changes=True)


async def _fetch_cve_patch(cve, gh_session, gl_session, gh_sem, gl_sem, gh_rate, gl_token):
    """Fetch and combine all diffs for a single CVE."""
    actions = _deduplicate_actions(cve.actions)
    parts = []
    for a in actions:
        diff = None
        if isinstance(a, GHCommit):
            diff = await _fetch_gh_commit_diff(gh_session, gh_sem, gh_rate, a.owner, a.repo, a.sha)
        elif isinstance(a, GHPR):
            diff = await _fetch_gh_pr_diff(gh_session, gh_sem, gh_rate, a.owner, a.repo, a.number)
        elif isinstance(a, GLCommit):
            diff = await _fetch_gl_commit_diff(gl_session, gl_sem, a.project, a.sha, gl_token)
        elif isinstance(a, GLMR):
            diff = await _fetch_gl_mr_diff(gl_session, gl_sem, a.project, a.iid, gl_token)
        if diff:
            parts.append(diff)
    return "\n".join(parts) if parts else None


async def step3_fetch_patches(limit: int | None, gh_workers: int, gl_workers: int):
    """Fetch patches for memory-safety CVEs into patches/. Skips existing patches."""
    PATCHES_DIR.mkdir(exist_ok=True)

    gh_token = os.environ.get("GITHUB_TOKEN")
    gl_token = os.environ.get("GITLAB_TOKEN")
    if not gh_token:
        log.warning("GITHUB_TOKEN not set – GitHub rate limit will be 60 req/hr.")

    cves = _load_cve_records(MEMORY_SAFETY_JSONL_PATH, limit=limit)
    log.info("Step 3: Loaded %d CVEs with actionable URLs.", len(cves))

    # Skip CVEs that already have patches
    before = len(cves)
    cves = [c for c in cves if not (PATCHES_DIR / f"{c.cve_id}.patch").exists()]
    if before != len(cves):
        log.info("Step 3: Skipping %d CVEs with existing patches, %d remaining.", before - len(cves), len(cves))

    if not cves:
        log.info("Step 3: All patches already downloaded.")
        return

    gh_headers = {}
    if gh_token:
        gh_headers["Authorization"] = f"token {gh_token}"

    timeout = aiohttp.ClientTimeout(total=60)
    gh_sem = asyncio.Semaphore(gh_workers)
    gl_sem = asyncio.Semaphore(gl_workers)
    gh_rate: dict = {}
    saved = 0
    failed = 0

    async with (
        aiohttp.ClientSession(headers=gh_headers, timeout=timeout) as gh_session,
        aiohttp.ClientSession(timeout=timeout) as gl_session,
    ):
        pbar = tqdm(total=len(cves), desc="Fetching patches", unit="CVE")

        async def fetch_and_save(cve: CVERecord):
            nonlocal saved, failed
            try:
                patch = await _fetch_cve_patch(cve, gh_session, gl_session, gh_sem, gl_sem, gh_rate, gl_token)
                if patch:
                    (PATCHES_DIR / f"{cve.cve_id}.patch").write_text(patch)
                    saved += 1
                else:
                    failed += 1
            except Exception as e:
                tqdm.write(f"ERROR {cve.cve_id}: {e}")
                failed += 1
            pbar.update(1)
            pbar.set_postfix(saved=saved, failed=failed)

        batch_size = 100
        for batch_start in range(0, len(cves), batch_size):
            batch = cves[batch_start : batch_start + batch_size]
            await asyncio.gather(*[asyncio.create_task(fetch_and_save(c)) for c in batch])

        pbar.close()

    log.info("Step 3: Saved %d new patches (%d failed).", saved, failed)


# ---------------------------------------------------------------------------
# Step 4: Validate patches with GPT
# ---------------------------------------------------------------------------

# Reuse GitHub commit URL patterns for fetching commit messages
RE_GH_COMMIT_LOOSE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-fA-F]+)"
)
RE_GH_PR_COMMIT_LOOSE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/\d+/commits/(?P<sha>[0-9a-fA-F]+)"
)

VALIDATION_SYSTEM_PROMPT = """\
You are a security researcher reviewing CVE patches. Your job is to determine \
whether a given patch is a genuine, valid fix for the described vulnerability, \
or whether it is unrelated, a dummy commit, a test-only change, a documentation \
change, or otherwise not a real fix.

Respond with a JSON object containing exactly two fields:
- "valid": true if the patch is a genuine fix for the vulnerability, false otherwise
- "reason": a brief (1-2 sentence) explanation of your judgment
"""


@dataclass
class CVEValidationEntry:
    cve_id: str
    description: str
    patch: str
    commit_urls: list  # list of (owner, repo, sha)


def _load_cves_for_validation(path: Path, patches_dir: Path, limit: int | None = None) -> list[CVEValidationEntry]:
    entries = []
    with open(path) as f:
        for i, line in enumerate(f):
            if limit is not None and i >= limit:
                break
            obj = json.loads(line)
            cve = obj["cve"]
            cve_id = cve["id"]

            patch_path = patches_dir / f"{cve_id}.patch"
            if not patch_path.exists():
                continue
            patch = patch_path.read_text()
            if not patch.strip():
                continue

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc["value"]
                    break

            commit_urls = []
            for ref in cve.get("references", []):
                url = ref["url"]
                m = RE_GH_PR_COMMIT_LOOSE.match(url)
                if m:
                    commit_urls.append((m.group("owner"), m.group("repo"), m.group("sha")))
                    continue
                m = RE_GH_COMMIT_LOOSE.match(url)
                if m:
                    commit_urls.append((m.group("owner"), m.group("repo"), m.group("sha")))

            entries.append(CVEValidationEntry(cve_id=cve_id, description=description, patch=patch, commit_urls=commit_urls))
    return entries


async def _fetch_commit_message(session, sem, rate_state, owner, repo, sha) -> str | None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    for attempt in range(3):
        async with sem:
            remaining = rate_state.get("remaining")
            if remaining is not None and remaining < 50:
                wait = max(0, rate_state.get("reset", 0) - time.time()) + 1
                if wait > 0:
                    await asyncio.sleep(wait)
            try:
                async with session.get(url, headers=headers) as resp:
                    rl_rem = resp.headers.get("X-RateLimit-Remaining")
                    rl_rst = resp.headers.get("X-RateLimit-Reset")
                    if rl_rem is not None:
                        rate_state["remaining"] = int(rl_rem)
                    if rl_rst is not None:
                        rate_state["reset"] = int(rl_rst)
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("commit", {}).get("message", "")
                    elif resp.status == 403:
                        wait = max(0, rate_state.get("reset", 0) - time.time()) + 1
                        await asyncio.sleep(wait)
                        continue
                    elif resp.status == 404:
                        return None
                    elif resp.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(2 ** attempt)
                continue
    return None


async def _fetch_commit_messages_for_cve(entry, session, sem, rate_state) -> str:
    if not entry.commit_urls:
        return ""
    seen = set()
    unique = []
    for owner, repo, sha in entry.commit_urls:
        if sha not in seen:
            seen.add(sha)
            unique.append((owner, repo, sha))
    messages = []
    for owner, repo, sha in unique[:3]:
        msg = await _fetch_commit_message(session, sem, rate_state, owner, repo, sha)
        if msg:
            messages.append(msg)
    return "\n---\n".join(messages)


def _build_validation_prompt(cve_id, description, patch, commit_message):
    max_patch_chars = 12000
    if len(patch) > max_patch_chars:
        patch = patch[:max_patch_chars] + "\n\n... [patch truncated] ..."
    parts = [f"## CVE ID\n{cve_id}", f"## Vulnerability Description\n{description}"]
    if commit_message:
        parts.append(f"## Commit Message\n{commit_message}")
    parts.append(f"## Patch (unified diff)\n```diff\n{patch}\n```")
    parts.append('Is this patch a genuine fix for the described vulnerability? Respond with JSON: {"valid": true/false, "reason": "..."}.')
    return "\n\n".join(parts)


def _parse_llm_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {"valid": None, "reason": f"Failed to parse LLM response: {text[:200]}"}


async def step4_validate_patches(limit: int | None, gh_workers: int, llm_workers: int, model: str):
    """Validate patches with GPT. Skips CVEs already in validation results."""

    # Load existing results
    existing_ids: set[str] = set()
    if VALIDATION_RESULTS_PATH.exists():
        with open(VALIDATION_RESULTS_PATH) as f:
            for line in f:
                try:
                    existing_ids.add(json.loads(line)["cve_id"])
                except (json.JSONDecodeError, KeyError):
                    pass
        log.info("Step 4: Loaded %d existing validation results.", len(existing_ids))

    entries = _load_cves_for_validation(MEMORY_SAFETY_JSONL_PATH, PATCHES_DIR, limit=limit)
    log.info("Step 4: Found %d CVEs with patches.", len(entries))

    entries = [e for e in entries if e.cve_id not in existing_ids]
    log.info("Step 4: %d CVEs remaining after skipping existing.", len(entries))

    if not entries:
        log.info("Step 4: Nothing to validate.")
        return

    gh_token = os.environ.get("GITHUB_TOKEN")
    gh_headers = {}
    if gh_token:
        gh_headers["Authorization"] = f"token {gh_token}"
    else:
        log.warning("GITHUB_TOKEN not set; commit messages may be unavailable.")

    timeout = aiohttp.ClientTimeout(total=30)
    gh_sem = asyncio.Semaphore(gh_workers)
    gh_rate: dict = {}
    client = AsyncOpenAI()
    llm_sem = asyncio.Semaphore(llm_workers)

    # Phase 1: fetch commit messages
    log.info("Step 4: Fetching commit messages ...")
    commit_messages: dict[str, str] = {}

    async with aiohttp.ClientSession(headers=gh_headers, timeout=timeout) as gh_session:
        pbar = tqdm(total=len(entries), desc="Fetching commit msgs", unit="CVE")

        async def fetch_msg(entry):
            msg = await _fetch_commit_messages_for_cve(entry, gh_session, gh_sem, gh_rate)
            commit_messages[entry.cve_id] = msg
            pbar.update(1)

        batch_size = 100
        for bs in range(0, len(entries), batch_size):
            await asyncio.gather(*[fetch_msg(e) for e in entries[bs : bs + batch_size]])
        pbar.close()

    # Phase 2: LLM validation
    log.info("Step 4: Validating patches with %s ...", model)
    results: list[dict] = []
    errors = 0
    out_file = open(VALIDATION_RESULTS_PATH, "a")

    pbar = tqdm(total=len(entries), desc="Validating patches", unit="CVE")

    async def validate_one(entry):
        nonlocal errors
        msg = commit_messages.get(entry.cve_id, "")
        user_prompt = _build_validation_prompt(entry.cve_id, entry.description, entry.patch, msg)
        async with llm_sem:
            for attempt in range(3):
                try:
                    response = await client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": VALIDATION_SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=0,
                        max_tokens=256,
                    )
                    text = response.choices[0].message.content
                    parsed = _parse_llm_response(text)
                    result = {
                        "cve_id": entry.cve_id,
                        "valid": parsed.get("valid"),
                        "reason": parsed.get("reason", ""),
                        "has_commit_message": bool(msg),
                        "model": model,
                    }
                    out_file.write(json.dumps(result) + "\n")
                    out_file.flush()
                    results.append(result)
                    break
                except Exception as e:
                    if attempt == 2:
                        tqdm.write(f"ERROR {entry.cve_id}: {e}")
                        result = {
                            "cve_id": entry.cve_id,
                            "valid": None,
                            "reason": f"LLM error: {e}",
                            "has_commit_message": bool(msg),
                            "model": model,
                        }
                        out_file.write(json.dumps(result) + "\n")
                        out_file.flush()
                        results.append(result)
                        errors += 1
                    else:
                        await asyncio.sleep(2 ** attempt)
        pbar.update(1)
        valid_count = sum(1 for r in results if r.get("valid") is True)
        invalid_count = sum(1 for r in results if r.get("valid") is False)
        pbar.set_postfix(valid=valid_count, invalid=invalid_count, errors=errors)

    batch_size = 50
    for bs in range(0, len(entries), batch_size):
        await asyncio.gather(*[validate_one(e) for e in entries[bs : bs + batch_size]])
    pbar.close()
    out_file.close()

    valid_count = sum(1 for r in results if r.get("valid") is True)
    invalid_count = sum(1 for r in results if r.get("valid") is False)
    unknown_count = sum(1 for r in results if r.get("valid") is None)
    log.info("Step 4: Processed %d – valid=%d, invalid=%d, unknown=%d",
             len(results), valid_count, invalid_count, unknown_count)


# ---------------------------------------------------------------------------
# Step 5: Classify patches and produce final dataset
# ---------------------------------------------------------------------------

RE_HUNK_HEADER = re.compile(r"^@@\s+[^@]+@@\s*(.*)$")
RE_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$", re.MULTILINE)


def _is_test_file(path: str) -> bool:
    parts = path.split("/")
    basename = parts[-1]
    dirs = parts[:-1]
    for d in dirs:
        if d.lower() in ("test", "tests", "testing", "__tests__", "spec", "t"):
            return True
    name = basename.rsplit(".", 1)[0] if "." in basename else basename
    low = name.lower()
    if low in ("test", "tests"):
        return True
    if low.startswith("test_"):
        return True
    if low.endswith(("_test", "-test", "_tests", "-tests", "_spec")):
        return True
    if name.endswith("Test") or name.endswith("Tests"):
        return True
    return False


def _extract_function_name(context: str) -> str | None:
    m = re.search(r"(\w+)\s*\(", context)
    if m:
        name = m.group(1)
        skip = {
            "if", "else", "for", "while", "switch", "case", "return",
            "sizeof", "typeof", "alignof", "static_assert",
            "struct", "class", "enum", "union", "namespace",
        }
        if name.lower() in skip:
            rest = context[m.end():]
            m2 = re.search(r"(\w+)\s*\(", rest)
            return m2.group(1) if m2 else None
        return name
    tokens = re.findall(r"\w+", context)
    return tokens[-1] if tokens else None


def _classify_patch(patch: str) -> dict | None:
    """
    Classify a unified diff patch, ignoring test files.

    Returns dict with:
      files_changed, functions_changed, files,
      is_single_file, is_multi_file, is_single_function, is_multi_function
    Or None if the patch has no non-test file changes.
    """
    if not patch or not patch.strip():
        return None

    file_matches = RE_DIFF_HEADER.findall(patch)
    files = []
    for _, new_path in file_matches:
        if not _is_test_file(new_path) and new_path not in files:
            files.append(new_path)

    if not files:
        return None

    non_test_paths = set(files)
    file_sections = re.split(r"^diff --git ", patch, flags=re.MULTILINE)
    all_functions = set()

    for section in file_sections:
        if not section.strip():
            continue
        header_match = re.match(r"a/(.+?) b/(.+?)$", section.splitlines()[0])
        if header_match and header_match.group(2) not in non_test_paths:
            continue
        for line in section.splitlines():
            m = RE_HUNK_HEADER.match(line)
            if m:
                ctx = m.group(1).strip()
                if ctx:
                    fn = _extract_function_name(ctx)
                    if fn:
                        all_functions.add(fn)

    files_changed = len(files)
    functions_changed = len(all_functions)

    return {
        "files_changed": files_changed,
        "functions_changed": functions_changed,
        "files": files,
        "is_single_file": files_changed == 1,
        "is_multi_file": files_changed > 1,
        "is_single_function": functions_changed <= 1,
        "is_multi_function": functions_changed > 1,
    }


def step5_build_final_dataset(output_path: Path):
    """Combine validation results + patch classification → final JSONL."""
    if output_path.exists():
        log.info("Step 5: %s already exists, skipping.", output_path.name)
        return

    # Load validation results
    validation: dict[str, dict] = {}
    if VALIDATION_RESULTS_PATH.exists():
        with open(VALIDATION_RESULTS_PATH) as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    validation[obj["cve_id"]] = obj
                except (json.JSONDecodeError, KeyError):
                    pass
    log.info("Step 5: Loaded %d validation results.", len(validation))

    # Load memory safety CVE metadata for descriptions / CWEs
    cve_meta: dict[str, dict] = {}
    with open(MEMORY_SAFETY_JSONL_PATH) as f:
        for line in f:
            obj = json.loads(line)
            cve = obj["cve"]
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc["value"]
                    break
            cwe_ids = sorted(_extract_cwe_ids(cve))
            cve_meta[cve["id"]] = {"description": description, "cwe_ids": cwe_ids}

    count = 0
    skipped_no_patch = 0
    skipped_invalid = 0

    with open(output_path, "w") as out:
        for patch_path in sorted(PATCHES_DIR.glob("*.patch")):
            cve_id = patch_path.stem
            patch_text = patch_path.read_text()

            # Must have passed validation (or at least not be explicitly invalid)
            val = validation.get(cve_id, {})
            if val.get("valid") is False:
                skipped_invalid += 1
                continue

            classification = _classify_patch(patch_text)
            if classification is None:
                skipped_no_patch += 1
                continue

            meta = cve_meta.get(cve_id, {})
            record = {
                "cve_id": cve_id,
                "description": meta.get("description", ""),
                "cwe_ids": meta.get("cwe_ids", []),
                "patch_path": str(patch_path),
                "validation_valid": val.get("valid"),
                "validation_reason": val.get("reason", ""),
                "files_changed": classification["files_changed"],
                "functions_changed": classification["functions_changed"],
                "files": classification["files"],
                "is_single_file": classification["is_single_file"],
                "is_multi_file": classification["is_multi_file"],
                "is_single_function": classification["is_single_function"],
                "is_multi_function": classification["is_multi_function"],
            }
            out.write(json.dumps(record) + "\n")
            count += 1

    log.info(
        "Step 5: Wrote %d CVEs to %s (skipped %d invalid, %d no non-test changes).",
        count, output_path.name, skipped_invalid, skipped_no_patch,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def async_main(args):
    step1_download_cves()
    step2_filter_memory_safety()
    await step3_fetch_patches(args.limit, args.gh_workers, args.gl_workers)
    await step4_validate_patches(args.limit, args.gh_workers, args.llm_workers, args.model)
    step5_build_final_dataset(Path(args.output))


def main():
    parser = argparse.ArgumentParser(description="End-to-end CVE dataset builder")
    parser.add_argument("--limit", type=int, default=None, help="Process only first N CVEs (for testing)")
    parser.add_argument("--gh-workers", type=int, default=20, help="Max concurrent GitHub requests")
    parser.add_argument("--gl-workers", type=int, default=5, help="Max concurrent GitLab requests")
    parser.add_argument("--llm-workers", type=int, default=30, help="Max concurrent LLM requests")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model for validation (default: gpt-4o)")
    parser.add_argument("--output", default="cve_dataset.jsonl", help="Final output JSONL (default: cve_dataset.jsonl)")
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
