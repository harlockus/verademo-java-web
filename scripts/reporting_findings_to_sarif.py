#!/usr/bin/env python3
"""
Veracode Reporting API (Findings) JSON -> SARIF 2.1.0 for GitHub Code Scanning.

This converter is tailored to the Reporting API JSON shape you have:
- scan_type: "Static Analysis" (only these reliably map to repo files)
- local_path / static_local_path: repo-relative file paths
- source_file_line: line number (string)
- severity: "0".."5"

Key requirements:
- GitHub Code Scanning requires at least one location per SARIF result. 
- We only attach real source locations for Static Analysis findings. Others go to a placeholder.
"""

import argparse
import hashlib
import json
from typing import Any, Dict, List, Optional

# severity -> (sarif level, label, github security severity score)
SEV_MAP = {
    "5": ("error",   "VERY_HIGH", "9.5"),
    "4": ("error",   "HIGH",      "8.0"),
    "3": ("warning", "MEDIUM",    "5.5"),
    "2": ("note",    "LOW",       "3.0"),
    "1": ("note",    "VERY_LOW",  "1.0"),
    "0": ("note",    "INFO",      "0.1"),
}


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def as_str(x: Any) -> str:
    return "" if x is None else str(x)


def normalize_repo_path(p: str) -> str:
    p = p.replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    # no leading slash; GitHub expects repo-relative URIs
    return p.lstrip("/")


def safe_int(x: Any, default: int = 1) -> int:
    try:
        v = int(str(x))
        return v if v >= 1 else default
    except Exception:
        return default


def stable_placeholder_line(rule_id: str, msg: str) -> int:
    # stable line so placeholder findings don't all collide at line 1
    h = sha256_text(f"{rule_id}|{msg}")
    return (int(h[:8], 16) % 20000) + 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="out/findings_single_app_*.json (list)")
    ap.add_argument("--output", required=True, help="Output SARIF file")
    ap.add_argument("--placeholder-uri", required=True, help="Repo-relative placeholder file")
    ap.add_argument("--output-stats", required=True, help="Stats JSON output")
    ap.add_argument("--tool-name", default="Veracode Reporting API")
    ap.add_argument("--tool-version", default="")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        raise SystemExit("Expected input JSON to be a list (use out/findings_single_app_*.json).")

    placeholder_uri = normalize_repo_path(args.placeholder_uri)

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    total = 0
    static_with_location = 0
    static_missing_location = 0
    non_static = 0
    placeholder_used = 0

    for it in findings:
        if not isinstance(it, dict):
            continue
        total += 1

        scan_type = as_str(it.get("scan_type")).strip()

        # severity (string "0".."5")
        sev_raw = as_str(it.get("severity")).strip()
        sarif_level, sev_label, gh_sec_score = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN", "0.0"))

        # CWE/category/rule identity
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

        # message
        msg_core = flaw_name or as_str(it.get("description")).strip() or rule_name
        msg = f"[{sev_label}] {msg_core}"
        if finding_id:
            msg += f" (finding_id={finding_id})"

        # Only Static Analysis findings should be mapped to source files
        uri: str
        start_line: int

        if scan_type == "Static Analysis":
            # Prefer repo-relative local_path first, then static_local_path.
            file_path = as_str(it.get("local_path")).strip() or as_str(it.get("static_local_path")).strip()
            line_raw = it.get("source_file_line")
            line = safe_int(line_raw, default=1)

            if file_path:
                uri = normalize_repo_path(file_path)
                start_line = line
                static_with_location += 1
            else:
                # Static analysis but no file path: placeholder
                uri = placeholder_uri
                start_line = stable_placeholder_line(rule_id, msg)
                static_missing_location += 1
                placeholder_used += 1
        else:
            # Non-static findings (e.g., SCA): do NOT pretend we have a code location
            non_static += 1
            uri = placeholder_uri
            start_line = stable_placeholder_line(rule_id, msg)
            placeholder_used += 1

        # Define rule once with security metadata so GitHub ranks properly
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
                    "scan_type": scan_type,
                },
            }

        # GitHub requires locations[] for each result. 
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
            },
        })

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": args.tool_name,
                    **({"version": args.tool_version} if args.tool_version else {}),
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    stats = {
        "input_findings": total,
        "sarif_results": len(results),
        "sarif_rules": len(rules),
        "static_with_location": static_with_location,
        "static_missing_location": static_missing_location,
        "non_static_placeholder": non_static,
        "placeholder_used_total": placeholder_used,
        "placeholder_uri": placeholder_uri,
        "path_fields_used_for_static": ["local_path", "static_local_path"],
        "line_field_used_for_static": "source_file_line",
    }
    with open(args.output_stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"Wrote SARIF: {args.output} (results={len(results)}, rules={len(rules)})")
    print(f"Wrote stats: {args.output_stats} -> {stats}")


if __name__ == "__main__":
    main()
