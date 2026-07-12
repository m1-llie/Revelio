"""Post-confirmation findings deduplication.

Groups a run's already-confirmed hypotheses (``artifacts/handoffs/validation_*.json``)
by crash signature — the sanitizer's ``DEDUP_TOKEN`` when available, else a
lightweight fallback signature (see ``revelio.run.crash_signals``). This is
strictly a post-hoc read of already-captured data: it does not re-run or
re-validate anything, and it does not affect the confirmation loop itself.
"""

from __future__ import annotations

import json
from pathlib import Path

from revelio.artifacts.schema import DedupGroup, DedupReport


def compute_dedup_report(handoffs_dir: Path) -> DedupReport:
    """Group confirmed findings under ``handoffs_dir`` by exact-match crash signature.

    Lightweight, O(N), string equality only — no fuzzy/similarity matching.
    Prefers ``dedup_token`` when present; falls back to ``fallback_signature``
    otherwise. The two signature types are never mixed within one group, since
    they carry different confidence levels.
    """
    confirmed: list[dict] = []
    for f in sorted(handoffs_dir.glob("validation_*.json")):
        try:
            wrapper = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        data = wrapper.get("data") or {}
        if data.get("crash_detected"):
            confirmed.append(data)

    # Sorted glob order == hypothesis_id order == confirmation order, so the
    # first hid appended to each group is the first one confirmed.
    groups: dict[tuple[str, str], list[str]] = {}
    for data in confirmed:
        token = data.get("dedup_token")
        fallback = data.get("fallback_signature")
        if token:
            key = ("dedup_token", token)
        elif fallback and fallback != "unknown":
            key = ("fallback", fallback)
        else:
            # No real signature could be extracted — each such finding is its
            # own singleton group rather than being lumped together under a
            # shared "unknown" bucket, which would falsely merge unrelated
            # crashes that merely share a lack of signature data.
            key = ("unresolved", data["hypothesis_id"])
        groups.setdefault(key, []).append(data["hypothesis_id"])

    report = DedupReport()
    for (signature_type, signature), hids in groups.items():
        canonical, *duplicates = hids
        report.groups.append(DedupGroup(signature_type, signature, canonical, duplicates))
        report.duplicate_of.update({hid: canonical for hid in duplicates})
    return report
