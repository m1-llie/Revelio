#!/usr/bin/env python3
"""
Validate CVE patches using an LLM.

For each CVE in all_cves_memory_safety.jsonl that has a patch in patches/,
sends the vulnerability description, patch diff, and commit message to an LLM
to determine whether the patch is a genuine fix (vs. a dummy/unrelated commit).

Fetches commit messages from the GitHub API when possible.

Usage:
    python validate_patches.py [--limit N] [--workers N] [--model MODEL]

Environment variables:
    OPENAI_API_KEY  - OpenAI API key (required)
    GITHUB_TOKEN    - GitHub personal access token (recommended for rate limits)
"""

import argparse
import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

import aiohttp
from openai import AsyncOpenAI
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class TqdmLoggingHandler(logging.Handler):
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
# URL patterns (reused from fetch_patches.py)
# ---------------------------------------------------------------------------

RE_GH_COMMIT = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-fA-F]+)"
)
RE_GH_PR_COMMIT = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/\d+/commits/(?P<sha>[0-9a-fA-F]+)"
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    patch: str
    commit_urls: list  # list of (owner, repo, sha)


# ---------------------------------------------------------------------------
# Load CVEs and match with patches
# ---------------------------------------------------------------------------


def load_cves_with_patches(
    jsonl_path: str, patches_dir: Path, limit: int | None = None
) -> list[CVEEntry]:
    entries = []
    with open(jsonl_path) as f:
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

            # Extract English description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc["value"]
                    break

            # Extract GitHub commit URLs for fetching commit messages
            commit_urls = []
            for ref in cve.get("references", []):
                url = ref["url"]
                # Try PR commit first (more specific pattern)
                m = RE_GH_PR_COMMIT.match(url)
                if m:
                    commit_urls.append((m.group("owner"), m.group("repo"), m.group("sha")))
                    continue
                m = RE_GH_COMMIT.match(url)
                if m:
                    commit_urls.append((m.group("owner"), m.group("repo"), m.group("sha")))

            entries.append(
                CVEEntry(
                    cve_id=cve_id,
                    description=description,
                    patch=patch,
                    commit_urls=commit_urls,
                )
            )
    return entries


# ---------------------------------------------------------------------------
# Fetch commit messages from GitHub
# ---------------------------------------------------------------------------


async def fetch_commit_message(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    rate_state: dict,
    owner: str,
    repo: str,
    sha: str,
) -> str | None:
    """Fetch the commit message for a given GitHub commit."""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = {"Accept": "application/vnd.github.v3+json"}

    for attempt in range(3):
        async with sem:
            remaining = rate_state.get("remaining")
            if remaining is not None and remaining < 50:
                reset_at = rate_state.get("reset", 0)
                wait = max(0, reset_at - time.time()) + 1
                if wait > 0:
                    log.info("GitHub rate limit low (%d), sleeping %.0fs", remaining, wait)
                    await asyncio.sleep(wait)
            try:
                async with session.get(url, headers=headers) as resp:
                    rl_remaining = resp.headers.get("X-RateLimit-Remaining")
                    rl_reset = resp.headers.get("X-RateLimit-Reset")
                    if rl_remaining is not None:
                        rate_state["remaining"] = int(rl_remaining)
                    if rl_reset is not None:
                        rate_state["reset"] = int(rl_reset)

                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("commit", {}).get("message", "")
                    elif resp.status == 403:
                        reset_at = rate_state.get("reset", 0)
                        wait = max(0, reset_at - time.time()) + 1
                        log.warning("GitHub 403, sleeping %.0fs (attempt %d)", wait, attempt + 1)
                        await asyncio.sleep(wait)
                        continue
                    elif resp.status == 404:
                        return None
                    elif resp.status >= 500:
                        await asyncio.sleep(2**attempt)
                        continue
                    else:
                        return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(2**attempt)
                continue
    return None


async def fetch_commit_messages_for_cve(
    entry: CVEEntry,
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    rate_state: dict,
) -> str:
    """Fetch commit messages for a CVE. Returns combined messages or empty string."""
    if not entry.commit_urls:
        return ""

    # Deduplicate by sha
    seen = set()
    unique = []
    for owner, repo, sha in entry.commit_urls:
        if sha not in seen:
            seen.add(sha)
            unique.append((owner, repo, sha))

    messages = []
    for owner, repo, sha in unique[:3]:  # cap at 3 commits
        msg = await fetch_commit_message(session, sem, rate_state, owner, repo, sha)
        if msg:
            messages.append(msg)

    return "\n---\n".join(messages)


# ---------------------------------------------------------------------------
# LLM validation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security researcher reviewing CVE patches. Your job is to determine \
whether a given patch is a genuine, valid fix for the described vulnerability, \
or whether it is unrelated, a dummy commit, a test-only change, a documentation \
change, or otherwise not a real fix.

Respond with a JSON object containing exactly two fields:
- "valid": true if the patch is a genuine fix for the vulnerability, false otherwise
- "reason": a brief (1-2 sentence) explanation of your judgment
"""


def build_user_prompt(cve_id: str, description: str, patch: str, commit_message: str) -> str:
    # Truncate very large patches to avoid token limits
    max_patch_chars = 12000
    if len(patch) > max_patch_chars:
        patch = patch[:max_patch_chars] + "\n\n... [patch truncated] ..."

    parts = [
        f"## CVE ID\n{cve_id}",
        f"## Vulnerability Description\n{description}",
    ]
    if commit_message:
        parts.append(f"## Commit Message\n{commit_message}")
    parts.append(f"## Patch (unified diff)\n```diff\n{patch}\n```")
    parts.append(
        "Is this patch a genuine fix for the described vulnerability? "
        "Respond with JSON: {\"valid\": true/false, \"reason\": \"...\"}."
    )
    return "\n\n".join(parts)


def parse_llm_response(text: str) -> dict:
    """Extract JSON from LLM response, tolerating markdown fences."""
    text = text.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        m = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {"valid": None, "reason": f"Failed to parse LLM response: {text[:200]}"}


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


async def main():
    parser = argparse.ArgumentParser(description="Validate CVE patches with an LLM")
    parser.add_argument("--input", default="all_cves_memory_safety.jsonl", help="Input JSONL")
    parser.add_argument("--patches-dir", default="patches", help="Patches directory")
    parser.add_argument("--output", default="patch_validation_results.jsonl", help="Output JSONL")
    parser.add_argument("--limit", type=int, default=None, help="Process only first N CVEs")
    parser.add_argument(
        "--gh-workers", type=int, default=20, help="Max concurrent GitHub API requests"
    )
    parser.add_argument(
        "--llm-workers", type=int, default=30, help="Max concurrent LLM API requests"
    )
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model to use")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip CVEs already present in the output file",
    )
    args = parser.parse_args()

    patches_dir = Path(args.patches_dir)

    # Load existing results if --skip-existing
    existing_ids: set[str] = set()
    output_path = Path(args.output)
    if args.skip_existing and output_path.exists():
        with open(output_path) as f:
            for line in f:
                try:
                    existing_ids.add(json.loads(line)["cve_id"])
                except (json.JSONDecodeError, KeyError):
                    pass
        log.info("Loaded %d existing results from %s", len(existing_ids), args.output)

    # Load CVEs with patches
    log.info("Loading CVEs from %s ...", args.input)
    entries = load_cves_with_patches(args.input, patches_dir, limit=args.limit)
    log.info("Found %d CVEs with patches", len(entries))

    if args.skip_existing:
        entries = [e for e in entries if e.cve_id not in existing_ids]
        log.info("%d CVEs remaining after skipping existing", len(entries))

    if not entries:
        log.info("Nothing to do.")
        return

    # Set up GitHub session for fetching commit messages
    gh_token = os.environ.get("GITHUB_TOKEN")
    gh_headers = {}
    if gh_token:
        gh_headers["Authorization"] = f"token {gh_token}"
    else:
        log.warning("GITHUB_TOKEN not set; commit messages may be unavailable")

    timeout = aiohttp.ClientTimeout(total=30)
    gh_sem = asyncio.Semaphore(args.gh_workers)
    gh_rate: dict = {}

    # Set up OpenAI client
    client = AsyncOpenAI()
    llm_sem = asyncio.Semaphore(args.llm_workers)

    # Phase 1: Fetch commit messages
    log.info("Fetching commit messages from GitHub ...")
    commit_messages: dict[str, str] = {}

    async with aiohttp.ClientSession(headers=gh_headers, timeout=timeout) as gh_session:
        pbar = tqdm(total=len(entries), desc="Fetching commit msgs", unit="CVE")

        async def fetch_msg(entry: CVEEntry):
            msg = await fetch_commit_messages_for_cve(entry, gh_session, gh_sem, gh_rate)
            commit_messages[entry.cve_id] = msg
            pbar.update(1)

        # Process in batches
        batch_size = 100
        for batch_start in range(0, len(entries), batch_size):
            batch = entries[batch_start : batch_start + batch_size]
            await asyncio.gather(*[fetch_msg(e) for e in batch])

        pbar.close()

    has_msg = sum(1 for v in commit_messages.values() if v)
    log.info("Fetched commit messages for %d / %d CVEs", has_msg, len(entries))

    # Phase 2: LLM validation
    log.info("Validating patches with %s ...", args.model)
    results: list[dict] = []
    errors = 0

    # Open output file in append mode
    out_file = open(args.output, "a")

    pbar = tqdm(total=len(entries), desc="Validating patches", unit="CVE")

    async def validate_one(entry: CVEEntry):
        nonlocal errors
        msg = commit_messages.get(entry.cve_id, "")
        user_prompt = build_user_prompt(entry.cve_id, entry.description, entry.patch, msg)

        async with llm_sem:
            for attempt in range(3):
                try:
                    response = await client.chat.completions.create(
                        model=args.model,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        temperature=0,
                        max_tokens=256,
                    )
                    text = response.choices[0].message.content
                    parsed = parse_llm_response(text)
                    result = {
                        "cve_id": entry.cve_id,
                        "valid": parsed.get("valid"),
                        "reason": parsed.get("reason", ""),
                        "has_commit_message": bool(msg),
                        "model": args.model,
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
                            "model": args.model,
                        }
                        out_file.write(json.dumps(result) + "\n")
                        out_file.flush()
                        results.append(result)
                        errors += 1
                    else:
                        await asyncio.sleep(2**attempt)

        pbar.update(1)
        valid_count = sum(1 for r in results if r.get("valid") is True)
        invalid_count = sum(1 for r in results if r.get("valid") is False)
        pbar.set_postfix(valid=valid_count, invalid=invalid_count, errors=errors)

    # Process in batches
    batch_size = 50
    for batch_start in range(0, len(entries), batch_size):
        batch = entries[batch_start : batch_start + batch_size]
        await asyncio.gather(*[validate_one(e) for e in batch])

    pbar.close()
    out_file.close()

    # Summary
    valid_count = sum(1 for r in results if r.get("valid") is True)
    invalid_count = sum(1 for r in results if r.get("valid") is False)
    unknown_count = sum(1 for r in results if r.get("valid") is None)

    log.info("=" * 60)
    log.info("Results written to %s", args.output)
    log.info("Total processed: %d", len(results))
    log.info("  Valid patches:   %d", valid_count)
    log.info("  Invalid patches: %d", invalid_count)
    log.info("  Unknown/errors:  %d", unknown_count)
    log.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
