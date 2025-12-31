#!/usr/bin/env python3
"""
Veracode Reporting API Findings JSON -> SARIF 2.1.0 (GitHub Code Scanning).

Fixes "lines not clickable" by mapping Veracode paths to REAL repo paths:
- strips build output prefixes (e.g. target/<module>/...)
- tries common Java source roots (src/main/webapp, etc.)
- verifies file exists in GITHUB_WORKSPACE before emitting SARIF URI
"""

import argparse
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

SEV_MAP = {
    "5": ("error",   "VERY_HIGH", "9.5"),
    "4": ("error",   "HIGH",      "8.0"),
    "3": ("warning", "MEDIUM",    "5.5"),
    "2": ("note",    "LOW",       "3.0"),
    "1": ("note",    "VERY_LOW",  "1.0"),
    "0": ("note",    "INFO",      "0.1"),
}

DEFAULT_SOURCE_ROOTS = [
    "",                 # repo root
    "src/main/webapp/",
    "src/main/resources/",
    "src/",
]

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def as_str(x: Any) -> str:
    return "" if x is None else str(x)

def normalize_path(p: str) -> str:
    p = p.replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")

def safe_int(x: Any, default: int = 1) -> int:
    try:
        v = int(str(x))
        return v if v >= 1 else default
    except Exception:
        return default

def stable_placeholder_line(rule_id: str, msg: str) -> int:
    h = sha256_text(f"{rule_id}|{msg}")
    return (int(h[:8], 16) % 20000) + 1

def pick_first(item: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        v = item.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def strip_build_prefix(p: str) -> str:
    """
    Examples:
      target/verademo/WEB-INF/views/profile.jsp -> WEB-INF/views/profile.jsp
      target/classes/com/x/Foo.class -> com/x/Foo.class
    """
    p = normalize_path(p)
    if p.startswith("target/"):
        rest = p[len("target/"):]
        # drop first segment after target/ (module name like verademo/, classes/, etc.)
        if "/" in rest:
            rest = rest.split("/", 1)[1]
        return rest
    return p

def resolve_repo_uri(repo_root: str, raw_path: str, source_roots: List[str]) -> Optional[str]:
    """
    Returns a repo-relative path that actually exists in the checkout.
    """
    raw_path = strip_build_prefix(raw_path)

    for root in source_roots:
        candidate = normalize_path(root + raw_path)
        full = os.path.join(repo_root, candidate)
        if os.path.isfile(full):
            return candidate

    # also try the raw path directly (already normalized)
    raw_norm = normalize_path(raw_path)
    if os.path.isfile(os.path.join(repo_root, raw_norm)):
        return raw_norm

    return None

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--placeholder-uri", required=True)
    ap.add_argument("--output-stats", required=True)
    ap.add_argument("--tool-name", default="Veracode Reporting API")
    ap.add_argument("--tool-version", default="")
    args = ap.parse_args()

    repo_root = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    placeholder_uri = normalize_path(args.placeholder_uri)

    with open(args.input, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        raise SystemExit("Expected a JSON list (use out/findings_single_app_*.json).")

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    total = 0
    resolved_paths = 0
    placeholder_used = 0
    target_stripped = 0

    for it in findings:
        if not isinstance(it, dict):
            continue
        total += 1

        scan_type = as_str(it.get("scan_type")).strip()
        sev_raw = as_str(it.get("severity")).strip()
        sarif_level, sev_label, gh_sec_score = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN", "0.0"))

        cwe_id = as_str(it.get("cwe_id")).strip()
        category_name = as_str(it.get("category_name")).strip()
        flaw_name = as_str(it.get("flaw_name")).strip()
        finding_id = as_str(it.get("finding_id")).strip()

        if cwe_id:
            rule_id = f"CWE-{cwe_id}" if not cwe_id.upper().startswith("CWE-") else cwe_id.upper()
        elif category_name:
            rule_id = f"VERACODE-{sha256_text(category_name)[:10].upper()}"
        else:
            rule_id = "VERACODE-ISSUE"

        rule_name = category_name or flaw_name or rule_id
        msg_core = flaw_name or as_str(it.get("description")).strip() or rule_name
        msg = f"[{sev_label}] {msg_core}" + (f" (finding_id={finding_id})" if finding_id else "")

        # Prefer local_path/static_local_path for static analysis
        raw_path = pick_first(it, ["local_path", "static_local_path"])
        raw_line = it.get("source_file_line")
        start_line = safe_int(raw_line, default=1)

        uri: str
        if scan_type == "Static Analysis" and raw_path:
            stripped = strip_build_prefix(raw_path)
            if stripped != normalize_path(raw_path):
                target_stripped += 1
            resolved = resolve_repo_uri(repo_root, raw_path, DEFAULT_SOURCE_ROOTS)
            if resolved:
                uri = resolved
                resolved_paths += 1
            else:
                uri = placeholder_uri
                start_line = stable_placeholder_line(rule_id, msg)
                placeholder_used += 1
        else:
            # SCA or no path: placeholder
            uri = placeholder_uri
            start_line = stable_placeholder_line(rule_id, msg)
            placeholder_used += 1

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": msg_core},
                "help": {"text": f"{rule_name}\nSeverity: {sev_label}\nRule: {rule_id}"},
                "properties": {
                    "tags": ["security", "veracode", "reporting-api"],
                    "security-severity": gh_sec_score,
                    "veracode-severity": sev_label,
                    "cwe": cwe_id,
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start_line},
                }
            }],
            "properties": {
                "finding_id": finding_id,
                "scan_type": scan_type,
                "veracode_severity": sev_label,
                "isPlaceholderLocation": (uri == placeholder_uri),
                "raw_path": raw_path or "",
            },
        })

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": args.tool_name,
                **({"version": args.tool_version} if args.tool_version else {}),
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    stats = {
        "input_findings": total,
        "sarif_results": len(results),
        "sarif_rules": len(rules),
        "resolved_repo_paths": resolved_paths,
        "placeholder_used": placeholder_used,
        "target_prefix_stripped": target_stripped,
        "source_roots_tried": DEFAULT_SOURCE_ROOTS,
        "repo_root": repo_root,
    }
    with open(args.output_stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"Wrote SARIF: {args.output}")
    print(f"Stats: {stats}")

if __name__ == "__main__":
    main()
