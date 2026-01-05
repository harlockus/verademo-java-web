
#!/usr/bin/env python3
"""
Veracode Findings Delta reporter (refactored for readability & lower cyclomatic complexity).

Usage:
    python diff_reporting_findings.py \
        --app-name MyApp \
        --current current.json \
        --previous previous.json \
        --out-dir out/
"""

import argparse
import csv
import json
import os
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ----------------------------
# Constants & simple mappings
# ----------------------------

NOISY_KEYS = {
    "last_update_time",
    "last_seen_date",
    "last_seen",
    "last_updated",
    "last_updated_date",
    "data_refresh_date",
    "generation_date",
}

SEVERITY_ORDER = ["VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW", "INFO", "UNKNOWN"]

SEVERITY_MAP = {
    "5": "VERY_HIGH",
    "4": "HIGH",
    "3": "MEDIUM",
    "2": "LOW",
    "1": "VERY_LOW",
    "0": "INFO",
}

CANDIDATE_ID_KEYS = ("issue_id", "flaw_id", "id", "finding_id", "guid")

# ----------------------------
# General utilities
# ----------------------------

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-name", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def write_md(path: str, lines: Iterable[str]) -> None:
    """Write Markdown from a list/iterable of lines."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def write_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    """Write rows to CSV with provided fieldnames."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def extract_list(data: Any, preferred_keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
    """
    Given parsed JSON, return a list of dict findings.
    - If `data` is a list, keep only dict items.
    - If `data` is a dict, return the first list found by keys in `preferred_keys`.
    """
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in preferred_keys:
            items = data.get(key)
            if isinstance(items, list):
                return [x for x in items if isinstance(x, dict)]
    return []


def load_json(path: str) -> List[Dict[str, Any]]:
    """Load findings JSON from path (supports top-level list or dict with common keys)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return extract_list(data, ("findings", "items", "results"))


def normalize_severity(value: Any) -> str:
    """Normalize severity to canonical label."""
    if value is None:
        return "UNKNOWN"
    s = str(value).strip()
    return SEVERITY_MAP.get(s, s.upper())


def strip_noisy(d: Dict[str, Any]) -> Dict[str, Any]:
    """Remove keys considered noisy/transient for diffing."""
    return {k: v for k, v in d.items() if k not in NOISY_KEYS}


def coerce_bool(value: Any) -> Optional[bool]:
    """
    Convert value to a boolean if possible:
    - True/False booleans return as-is.
    - Strings accepted: 'true/yes/y' -> True, 'false/no/n' -> False.
    - Otherwise returns None.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in {"true", "yes", "y"}:
            return True
        if s in {"false", "no", "n"}:
            return False
    return None

# ----------------------------
# Finding-specific utilities
# ----------------------------

def best_id(f: Dict[str, Any]) -> str:
    """Select the best identifier for a finding; fall back to a signature."""
    for k in CANDIDATE_ID_KEYS:
        v = f.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()

    parts = [
        str(f.get("cwe") or ""),
        str(f.get("category") or f.get("categoryname") or f.get("category_name") or ""),
        str(f.get("file_path") or f.get("file") or ""),
        str(f.get("line") or ""),
        str(f.get("scan_type") or ""),
    ]
    return "SIG:" + "\n".join(parts)


def file_key(f: Dict[str, Any]) -> str:
    """Group key by file-related fields."""
    val = str(f.get("file_path") or f.get("file") or f.get("filename") or "").strip()
    return val or "UNKNOWN_FILE"


def cwe_category_key(f: Dict[str, Any]) -> str:
    """Group key combining CWE and category (when available)."""
    cwe = f.get("cwe") or f.get("cwe_id")
    cat = f.get("category") or f.get("categoryname") or f.get("category_name")
    if cwe and cat:
        return f"{cwe} - {cat}"
    if cwe:
        return str(cwe)
    if cat:
        return str(cat)
    return "UNKNOWN_CWE_OR_CATEGORY"


def affects_policy(f: Dict[str, Any]) -> Optional[bool]:
    """Try multiple fields to determine whether a finding affects policy compliance."""
    for key in (
        "affects_policy_compliance",
        "vulnerability_affects_policy_compliance",
        "component_affects_policy_compliance",
    ):
        val = coerce_bool(f.get(key))
        if val is not None:
            return val
    return None

# ----------------------------
# Delta computations
# ----------------------------

def map_by_id(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index findings by their best ID."""
    return {best_id(f): f for f in findings}


def diff_fields(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return changed fields (excluding noisy keys) between two finding dicts."""
    o = strip_noisy(old)
    n = strip_noisy(new)
    keys = set(o) | set(n)
    return {k: {"from": o.get(k), "to": n.get(k)} for k in keys if o.get(k) != n.get(k)}


def compute_changes(
    prev_by_id: Dict[str, Dict[str, Any]],
    cur_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[str], List[str], List[Dict[str, Any]]]:
    """Compute added, removed, common IDs, and per-ID changed-field records."""
    cur_ids = set(cur_by_id)
    prev_ids = set(prev_by_id)

    added = sorted(cur_ids - prev_ids)
    removed = sorted(prev_ids - cur_ids)
    common = sorted(cur_ids & prev_ids)

    changed = []
    for fid in common:
        changes = diff_fields(prev_by_id[fid], cur_by_id[fid])
        if changes:
            changed.append({"id": fid, "changed_fields": changes})

    return added, removed, common, changed


def severity_counter(items: List[Dict[str, Any]]) -> Counter:
    """Count findings by normalized severity."""
    c = Counter()
    for f in items:
        sev = normalize_severity(f.get("severity") or f.get("severity_level"))
        c[sev] += 1
    return c


def group_delta(
    current: List[Dict[str, Any]],
    previous: List[Dict[str, Any]],
    key_fn,
) -> List[Dict[str, Any]]:
    """Compute per-group deltas using the provided key function."""
    cur_g = Counter(key_fn(f) for f in current)
    prev_g = Counter(key_fn(f) for f in previous)

    keys = set(cur_g) | set(prev_g)
    rows = [
        {
            "group": k,
            "previous": prev_g.get(k, 0),
            "current": cur_g.get(k, 0),
            "delta": cur_g.get(k, 0) - prev_g.get(k, 0),
        }
        for k in keys
    ]
    rows.sort(key=lambda r: (abs(r["delta"]), r["current"]), reverse=True)
    return rows


def count_affects(items: List[Dict[str, Any]]) -> Tuple[int, int, int]:
    """Return counts of (True, False, Unknown) for affects_policy across items."""
    true_count = false_count = unknown_count = 0
    for f in items:
        val = affects_policy(f)
        if val is True:
            true_count += 1
        elif val is False:
            false_count += 1
        else:
            unknown_count += 1
    return true_count, false_count, unknown_count

# ----------------------------
# Output writers
# ----------------------------

def write_executive_summary(
    out_dir: str,
    app_name: str,
    cur_ids_count: int,
    prev_ids_count: int,
    added_count: int,
    removed_count: int,
    changed_count: int,
    prev_sev: Counter,
    cur_sev: Counter,
) -> None:
    lines = []
    lines.append(f"# Veracode Findings Delta — {app_name}\n")
    lines.append(f"- Current findings: **{cur_ids_count}**")
    lines.append(f"- Previous findings: **{prev_ids_count}**")
    lines.append(f"- New (IDs not seen before): **{added_count}**")
    lines.append(f"- Removed (IDs no longer present): **{removed_count}**")
    lines.append(f"- Changed (same ID, fields changed): **{changed_count}**\n")

    lines.append("## Severity delta\n")
    # Markdown table header
    lines.append(
        "Severity | Previous | Current | Δ\n"
        "---|---:|---:|---:\n"
    )
    for s in SEVERITY_ORDER:
        p = prev_sev.get(s, 0)
        c = cur_sev.get(s, 0)
        lines.append(f"{s} | {p} | {c} | {c-p:+d}")

    write_md(os.path.join(out_dir, "executive_summary.md"), lines)


def write_compliance_summary(
    out_dir: str,
    app_name: str,
    prev_items: List[Dict[str, Any]],
    cur_items: List[Dict[str, Any]],
    prev_sev: Counter,
    cur_sev: Counter,
) -> None:
    lines = []
    lines.append(f"# Compliance delta — {app_name}\n")

    # If any policy flag is present, show detailed counts
    prev_flags = [affects_policy(f) for f in prev_items]
    cur_flags = [affects_policy(f) for f in cur_items]
    has_policy_flag = any(v is not None for v in (prev_flags + cur_flags))

    if has_policy_flag:
        pt, pf, pu = count_affects(prev_items)
        ct, cf, cu = count_affects(cur_items)
        lines.append(f"- Affects policy compliance (True): prev **{pt}** → curr **{ct}** (Δ {ct-pt:+d})")
        lines.append(f"- Does not affect policy (False): prev **{pf}** → curr **{cf}** (Δ {cf-pf:+d})")
        lines.append(f"- Unknown/Not provided: prev **{pu}** → curr **{cu}** (Δ {cu-pu:+d})\n")
    else:
        lines.append("- No explicit `*_affects_policy_*` flag present in findings JSON.\n")

    lines.append("## Policy-relevant proxy (severity)\n")
    for s in ("VERY_HIGH", "HIGH"):
        p = prev_sev.get(s, 0)
        c = cur_sev.get(s, 0)
        lines.append(f"- {s}: prev **{p}** → curr **{c}** (Δ {c-p:+d})")
    lines.append("")  # trailing newline

    write_md(os.path.join(out_dir, "compliance_summary.md"), lines)


def write_readme(out_dir: str, app_name: str) -> None:
    lines = [
        f"# Diff outputs — {app_name}",
        "",
        "- `executive_summary.md` — A) executive delta",
        "- `developer_by_file.csv` and `developer_by_cwe_category.csv` — B) developer delta",
        "- `compliance_summary.md` — C) compliance delta",
        "- `raw_changes.json` — D) raw change listing",
        "",
    ]
    write_md(os.path.join(out_dir, "README.md"), lines)

# ----------------------------
# Main
# ----------------------------

def main() -> None:
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    current = load_json(args.current)
    previous = load_json(args.previous)

    cur_by_id = map_by_id(current)
    prev_by_id = map_by_id(previous)

    added, removed, common, changed = compute_changes(prev_by_id, cur_by_id)

    # Raw changes output (cap changed list at 2000 entries for sanity)
    raw_out = {
        "app_name": args.app_name,
        "counts": {
            "current": len(cur_by_id),
            "previous": len(prev_by_id),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
        "added_ids": added,
        "removed_ids": removed,
        "changed": changed[:2000],
        "notes": "Changed list truncated to 2000 items if very large.",
    }
    with open(os.path.join(args.out_dir, "raw_changes.json"), "w", encoding="utf-8") as f:
        json.dump(raw_out, f, indent=2, ensure_ascii=False)

    # Severity counters
    cur_sev = severity_counter(current)
    prev_sev = severity_counter(previous)

    # Executive summary
    write_executive_summary(
        out_dir=args.out_dir,
        app_name=args.app_name,
        cur_ids_count=len(cur_by_id),
        prev_ids_count=len(prev_by_id),
        added_count=len(added),
        removed_count=len(removed),
        changed_count=len(changed),
        prev_sev=prev_sev,
        cur_sev=cur_sev,
    )

    # Developer deltas
    write_csv(
        os.path.join(args.out_dir, "developer_by_file.csv"),
        group_delta(current, previous, file_key),
        ["group", "previous", "current", "delta"],
    )
    write_csv(
        os.path.join(args.out_dir, "developer_by_cwe_category.csv"),
        group_delta(current, previous, cwe_category_key),
        ["group", "previous", "current", "delta"],
    )

    # Compliance summary
    write_compliance_summary(
        out_dir=args.out_dir,
        app_name=args.app_name,
        prev_items=previous,
        cur_items=current,
        prev_sev=prev_sev,
        cur_sev=cur_sev,
    )

    # README
    write_readme(args.out_dir, args.app_name)

    print("Diff outputs written to:", args.out_dir)


if __name__ == "__main__":
    main()
