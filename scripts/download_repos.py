#!/usr/bin/env python3
"""
Download repos for CVEs into repos/<CVE_ID>/.

For each CVE in cve_dataset.jsonl:
1. Verify patch file exists in patches/
2. Find the commit SHA from the patch link in all_cves.jsonl
3. git clone the repo, checkout the parent commit (SHA~1), remove .git/

Caches bare clones in .repo_cache/ so that multiple CVEs referencing the
same repo don't require repeated downloads.

Usage:
    python download_repos.py [--output-dir DIR] [--workers N] [--limit N]

Environment variables:
    GITHUB_TOKEN  - GitHub personal access token (optional, helps with rate limits for private repos)
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# GitHub commit URL patterns
RE_GH_COMMIT = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-fA-F]+)"
)
RE_GH_PR_COMMIT = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/\d+/commits/(?P<sha>[0-9a-fA-F]+)"
)


@dataclass
class CVERepo:
    cve_id: str
    owner: str
    repo: str
    sha: str  # fix commit SHA

    @property
    def repo_key(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            return f"https://{token}@github.com/{self.owner}/{self.repo}.git"
        return f"https://github.com/{self.owner}/{self.repo}.git"


def load_all_cves_refs(path: str) -> dict[str, list[dict]]:
    """Load all_cves.jsonl and return a dict mapping CVE ID -> references list."""
    lookup: dict[str, list[dict]] = {}
    with open(path) as f:
        for line in f:
            obj = json.loads(line)
            cve_id = obj["cve"]["id"]
            lookup[cve_id] = obj["cve"].get("references", [])
    return lookup


def find_commit_from_refs(refs: list[dict]) -> CVERepo | None:
    """Find the first GitHub commit URL in references and return a CVERepo (without cve_id set)."""
    for ref in refs:
        url = ref["url"]
        m = RE_GH_PR_COMMIT.match(url) or RE_GH_COMMIT.match(url)
        if m:
            return CVERepo(
                cve_id="",
                owner=m.group("owner"),
                repo=m.group("repo"),
                sha=m.group("sha"),
            )
    return None


def load_cves(limit: int | None = None) -> list[CVERepo]:
    """
    Load CVEs from cve_dataset.jsonl, verify patches exist, and find
    commit SHAs from all_cves.jsonl.
    """
    # 1. Load cve_dataset.jsonl
    dataset = []
    with open("/srv/share/revelio/cve_dataset.jsonl") as f:
        for line in f:
            dataset.append(json.loads(line))

    # Sort by CVE ID descending (latest first)
    dataset.sort(key=lambda e: e["cve_id"], reverse=True)

    log.info("Loaded %d CVEs from cve_dataset.jsonl", len(dataset))

    # 2. Build lookup from all_cves.jsonl
    log.info("Loading all_cves.jsonl ...")
    cve_refs = load_all_cves_refs("all_cves.jsonl")
    log.info("Loaded %d CVEs from all_cves.jsonl", len(cve_refs))

    # 3. For each CVE: check patch exists, find commit info
    records = []
    skipped_no_patch = 0
    skipped_no_cve = 0
    skipped_no_commit = 0

    for entry in dataset:
        cve_id = entry["cve_id"]

        # Filter: only validated single-file CVEs
        if not entry.get("validation_valid") or not entry.get("is_single_file"):
            continue

        # Check patch file exists
        patch_path = Path(entry.get("patch_path", f"patches/{cve_id}.patch"))
        if not patch_path.exists():
            skipped_no_patch += 1
            continue

        # Look up references in all_cves.jsonl
        refs = cve_refs.get(cve_id)
        if refs is None:
            log.warning("CVE %s not found in all_cves.jsonl", cve_id)
            skipped_no_cve += 1
            continue

        # Find commit URL and extract owner/repo/sha
        cve_repo = find_commit_from_refs(refs)
        if cve_repo is None:
            log.warning("No GitHub commit URL found for %s", cve_id)
            skipped_no_commit += 1
            continue

        cve_repo.cve_id = cve_id
        records.append(cve_repo)

        if limit is not None and len(records) >= limit:
            break

    log.info(
        "Skipped: %d no patch, %d not in all_cves, %d no commit URL",
        skipped_no_patch, skipped_no_cve, skipped_no_commit,
    )
    return records


def run_git(args: list[str], cwd: str | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a git command and return the result."""
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def ensure_bare_clone(cve_repo: CVERepo, cache_dir: Path) -> Path | None:
    """Ensure a bare clone exists in the cache. Returns the cache path or None on failure."""
    repo_cache = cache_dir / cve_repo.owner / cve_repo.repo
    if repo_cache.exists():
        return repo_cache

    repo_cache.parent.mkdir(parents=True, exist_ok=True)
    result = run_git(
        ["clone", "--bare", cve_repo.clone_url, str(repo_cache)],
        timeout=1200,
    )
    if result.returncode != 0:
        log.error("Failed to clone %s: %s", cve_repo.repo_key, result.stderr.strip())
        # Clean up partial clone
        if repo_cache.exists():
            shutil.rmtree(repo_cache)
        return None
    return repo_cache


def checkout_cve_repo(cve_repo: CVERepo, cache_dir: Path, output_dir: Path) -> bool:
    """
    Create repos/<CVE_ID>/ by cloning from the bare cache and checking out sha~1.
    Returns True on success.
    """
    dest = output_dir / cve_repo.cve_id
    if dest.exists():
        return True  # already done

    # Ensure bare clone exists
    bare_path = ensure_bare_clone(cve_repo, cache_dir)
    if bare_path is None:
        return False

    # Clone from local bare cache (fast, no network)
    result = run_git(
        ["clone", str(bare_path), str(dest)],
        timeout=600,
    )
    if result.returncode != 0:
        log.error("[%s] Failed to clone from cache: %s", cve_repo.cve_id, result.stderr.strip())
        if dest.exists():
            shutil.rmtree(dest)
        return False

    # Checkout the parent of the fix commit (vulnerable version)
    result = run_git(["checkout", f"{cve_repo.sha}~1"], cwd=str(dest))
    if result.returncode != 0:
        # If parent doesn't exist (e.g. initial commit), try the fix commit itself
        log.warning(
            "[%s] Could not checkout %s~1, trying %s directly: %s",
            cve_repo.cve_id, cve_repo.sha[:12], cve_repo.sha[:12], result.stderr.strip(),
        )
        result = run_git(["checkout", cve_repo.sha], cwd=str(dest))
        if result.returncode != 0:
            log.error("[%s] Failed to checkout %s: %s", cve_repo.cve_id, cve_repo.sha[:12], result.stderr.strip())
            shutil.rmtree(dest)
            return False

    # Remove .git/ to save space
    git_dir = dest / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)

    return True


def process_one(cve_repo: CVERepo, cache_dir: Path, output_dir: Path, lock_dict: dict) -> tuple[str, bool]:
    """Process a single CVE. Thread-safe via per-repo locking for the cache step."""
    import threading

    repo_key = cve_repo.repo_key

    # Serialize bare-clone creation per repo to avoid races
    if repo_key not in lock_dict:
        lock_dict[repo_key] = threading.Lock()
    with lock_dict[repo_key]:
        bare_path = ensure_bare_clone(cve_repo, cache_dir)

    if bare_path is None:
        return cve_repo.cve_id, False

    # The checkout step is per-CVE so no lock needed
    success = checkout_cve_repo(cve_repo, cache_dir, output_dir)
    return cve_repo.cve_id, success


def main():
    parser = argparse.ArgumentParser(description="Download repos for CVEs")
    parser.add_argument(
        "--output-dir", default="repos",
        help="Output directory for checked-out repos",
    )
    parser.add_argument(
        "--cache-dir", default=".repo_cache",
        help="Directory for bare clone cache",
    )
    parser.add_argument(
        "--workers", type=int, default=4,
        help="Number of parallel workers",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Process only first N CVEs (for testing)",
    )
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="Skip CVEs that already have a directory in output-dir",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Load CVEs
    cve_repos = load_cves(limit=args.limit)
    log.info("Found %d CVEs with GitHub commit references", len(cve_repos))

    # Skip existing
    if args.skip_existing:
        before = len(cve_repos)
        cve_repos = [c for c in cve_repos if not (output_dir / c.cve_id).exists()]
        log.info("Skipping %d existing, %d remaining", before - len(cve_repos), len(cve_repos))

    if not cve_repos:
        log.info("Nothing to do.")
        return

    # Show unique repos
    unique_repos = {c.repo_key for c in cve_repos}
    log.info("Unique repos to clone: %d", len(unique_repos))

    # Process with thread pool
    lock_dict: dict = {}
    succeeded = 0
    failed = 0
    failed_ids = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(process_one, cve, cache_dir, output_dir, lock_dict): cve
            for cve in cve_repos
        }
        pbar = tqdm(total=len(futures), desc="Downloading repos", unit="CVE")
        for future in as_completed(futures):
            cve_id, success = future.result()
            if success:
                succeeded += 1
            else:
                failed += 1
                failed_ids.append(cve_id)
            pbar.update(1)
            pbar.set_postfix(ok=succeeded, fail=failed)
        pbar.close()

    log.info("=" * 60)
    log.info("Done. %d succeeded, %d failed", succeeded, failed)
    if failed_ids:
        log.info("Failed CVE IDs: %s", ", ".join(failed_ids[:20]))
        if len(failed_ids) > 20:
            log.info("  ... and %d more", len(failed_ids) - 20)
    log.info("Repos saved to %s/", output_dir)
    log.info("Bare clone cache in %s/", cache_dir)


if __name__ == "__main__":
    main()
