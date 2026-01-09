#!/usr/bin/env python3
"""
Veracode Pipeline Scan JSON -> SARIF 2.1.0 for GitHub Code Scanning.

Guarantees:
- Every result has at least one location (required by GitHub Code Scanning).
- Findings without file/line are anchored to a placeholder file with stable unique lines.
- GitHub-friendly security metadata is included (security-severity + security tag).
"""

import argparse
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

# =============================================================================
# Constants & key groups
# =============================================================================

# Preferred keys for different fields in incoming Veracode JSON
KEYS_SEVERITY   = ["severity", "severity_level", "severityCode"]
KEYS_CWE        = ["cwe", "cwe_id", "cweId"]
KEYS_CATEGORY   = ["category", "categoryname", "category_name"]
KEYS_MESSAGE    = ["display_text", "message", "description", "issue_type"]
KEYS_FILE       = ["file_path", "file", "filename", "source_file"]
KEYS_LINE       = ["line", "line_number", "lineNumber"]

# Maps Veracode severity code strings to SARIF data
SEVERITY_MAP: Dict[str, Tuple[str, str, str]] = {
    "5": ("error",   "VERY_HIGH", "9.5"),
    "4": ("error",   "HIGH",      "8.0"),
    "3": ("warning", "MEDIUM",    "5.5"),
    "2": ("note",    "LOW",       "3.0"),
    "1": ("note",    "VERY_LOW",  "1.0"),
    "0": ("note",    "INFO",      "0.1"),
}

# =============================================================================
# Simple utilities
# =============================================================================

@dataclass(frozen=True)
class Severity:
    """Typed, readable container for severity mapping results."""
    level: str   # SARIF level: "error" | "warning" | "note"
    label: str   # Human-readable label: e.g., "HIGH"
    gh_score: str  # GitHub security score string

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def normalize_repo_path(path: str) -> str:
    """
    Make paths repo-friendly and consistent (forward slashes, trim, drop leading './').
    """
    p = (path or "").replace("\\", "/").strip()
    return p[2:] if p.startswith("./") else p

def first_of(obj: Dict[str, Any], keys: Iterable[str]) -> Any:
    """
    Return first present & non-None value for any of the provided keys.
    """
    for k in keys:
        v = obj.get(k)
        if v is not None:
            return v
    return None

def get_text(obj: Dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    """
    Get a trimmed string for the first matching key; otherwise default.
    """
    v = first_of(obj, keys)
    s = "" if v is None else str(v).strip()
    return s if s else default

def get_int(obj: Dict[str, Any], keys: Iterable[str], default: int = 1) -> int:
    """
    Get a positive integer (>=1). Fallback to default on errors or invalid values.
    """
    v = first_of(obj, keys)
    try:
        num = int(str(v))
        return num if num >= 1 else default
    except Exception:
        return default

def stable_placeholder_line(rule_id: str, message_text: str) -> int:
    """
    Produce a stable line number 1..20000 based on rule_id and message.
    Ensures placeholder lines are deterministic for GitHub annotations.
    """
    h = sha256_text(f"{rule_id}\n{message_text}")
    return (int(h[:8], 16) % 20000) + 1

# =============================================================================
# Domain helpers
# =============================================================================

def map_severity(item: Dict[str, Any]) -> Severity:
    """
    Map Veracode severity fields to SARIF level, label, and GitHub security score.
    Defaults to ('warning', 'UNKNOWN', '0.0') if not found.
    """
    raw = get_text(item, KEYS_SEVERITY)
    level, label, score = SEVERITY_MAP.get(raw, ("warning", "UNKNOWN", "0.0"))
    return Severity(level=level, label=label, gh_score=score)

def determine_rule_id_and_name(cwe_str: str, category: str) -> Tuple[str, str]:
    """
    Choose a rule ID and readable rule name.

    Priority:
    1) If CWE is present -> ensure it is 'CWE-<ID>' format (uppercased).
    2) Else if category is present -> VERACODE-<10-char hash prefix>.
    3) Else -> 'VERACODE-ISSUE'.
    Rule name is category if present, otherwise rule ID.
    """
    if cwe_str:
        cwe_up = cwe_str.upper()
        rule_id = cwe_up if cwe_up.startswith("CWE-") else f"CWE-{cwe_str}"
        return rule_id, (category or rule_id)

    if category:
        rule_id = f"VERACODE-{sha256_text(category)[:10].upper()}"
        return rule_id, category

    return "VERACODE-ISSUE", "VERACODE-ISSUE"

def compute_location(
    file_path: str,
    line: int,
    rule_id: str,
    message_text: str,
    placeholder_uri: str,
) -> Tuple[str, int, bool]:
    """
    Decide URI and line for a finding. If no file path, anchor to placeholder with a
    deterministic line number.
    Returns: (uri, start_line, is_placeholder)
    """
    if file_path:
        return normalize_repo_path(file_path), line, False
    return placeholder_uri, stable_placeholder_line(rule_id, message_text), True

def build_rule(
    rule_id: str,
    rule_name: str,
    message_text: str,
    sev_label: str,
    gh_sec_score: str,
    cwe_str: str,
) -> Dict[str, Any]:
    """
    Construct a SARIF rule entry with helpful security metadata.
    """
    return {
        "id": rule_id,
        "name": rule_name,
        "shortDescription": {"text": rule_name},
        "fullDescription": {"text": message_text or rule_name},
        "help": {
            "text": f"{rule_name}\nSeverity: {sev_label}\nRule: {rule_id}"
        },
        "properties": {
            "tags": ["security", "veracode", "pipeline-scan"],
            "security-severity": gh_sec_score,
            "precision": "high",
            "veracode-severity": sev_label,
            "cwe": cwe_str or "",
        },
    }

def build_result(
    rule_id: str,
    severity: Severity,
    message_text: str,
    uri: str,
    line: int,
    is_placeholder: bool,
) -> Dict[str, Any]:
    """
    Construct a SARIF result entry with at least one physical location.
    """
    titled_msg = f"[{severity.label}] {message_text}" if message_text else severity.label
    return {
        "ruleId": rule_id,
        "level": severity.level,
        "message": {"text": titled_msg},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
        "properties": {
            "veracode-severity": severity.label,
            "isPlaceholderLocation": is_placeholder,
        },
    }

def ensure_rule(
    rules_by_id: Dict[str, Dict[str, Any]],
    rule_id: str,
    rule_name: str,
    message_text: str,
    severity: Severity,
    cwe_str: str,
) -> None:
    """
    Insert rule into the rules dictionary if it's not already present.
    Keeps conversion logic flat and side-effect free.
    """
    if rule_id not in rules_by_id:
        rules_by_id[rule_id] = build_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            message_text=message_text,
            sev_label=severity.label,
            gh_sec_score=severity.gh_score,
            cwe_str=cwe_str,
        )

def build_driver(tool_name: str, tool_version: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build SARIF 'driver' section with optional version.
    """
    driver = {"name": tool_name, "rules": rules}
    if tool_version:
        driver["version"] = tool_version
    return driver

# =============================================================================
# Conversion pipeline
# =============================================================================

def convert_to_sarif(
    data: Dict[str, Any],
    tool_name: str,
    tool_version: str,
    placeholder_uri: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Core conversion from Veracode Pipeline Scan JSON to SARIF.

    Returns:
      (sarif_document, stats_dict)
    """
    findings = data.get("findings") or data.get("issues") or data.get("results") or []
    if not isinstance(findings, list):
        findings = []

    placeholder_uri = normalize_repo_path(placeholder_uri)

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    count_total = 0
    count_file_loc = 0
    count_placeholder_loc = 0

    for item in findings:
        if not isinstance(item, dict):
            continue
        count_total += 1

        severity = map_severity(item)
        cwe_str   = get_text(item, KEYS_CWE)
        category  = get_text(item, KEYS_CATEGORY)
        rule_id, rule_name = determine_rule_id_and_name(cwe_str, category)

        message_text = get_text(item, KEYS_MESSAGE, default=rule_name)
        file_path    = get_text(item, KEYS_FILE)
        line         = get_int(item, KEYS_LINE, default=1)

        uri, start_line, is_placeholder = compute_location(
            file_path=file_path,
            line=line,
            rule_id=rule_id,
            message_text=message_text,
            placeholder_uri=placeholder_uri,
        )
        count_file_loc        += (0 if is_placeholder else 1)
        count_placeholder_loc += (1 if is_placeholder else 0)

        ensure_rule(
            rules_by_id=rules_by_id,
            rule_id=rule_id,
            rule_name=rule_name,
            message_text=message_text,
            severity=severity,
            cwe_str=cwe_str,
        )

        results.append(
            build_result(
                rule_id=rule_id,
                severity=severity,
                message_text=message_text,
                uri=uri,
                line=start_line,
                is_placeholder=is_placeholder,
            )
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": build_driver(tool_name, tool_version, list(rules_by_id.values()))},
                "results": results,
            }
        ],
    }

    stats = {
        "findings_total_in_json": count_total,
        "sarif_results_written": len(results),
        "sarif_rules_written": len(rules_by_id),
        "results_with_file_location": count_file_loc,
        "results_with_placeholder_location": count_placeholder_loc,
        "placeholder_uri": placeholder_uri,
    }
    return sarif, stats

# =============================================================================
# CLI & I/O
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert Veracode Pipeline Scan JSON to SARIF 2.1.0"
    )
    parser.add_argument("--input", required=True, help="Path to Veracode JSON input")
    parser.add_argument("--output", required=True, help="Path to SARIF output (.sarif)")
    parser.add_argument(
        "--placeholder-uri",
        required=True,
        help="Repo-relative path used when findings lack file/line (e.g., 'veracode_placeholder.txt')",
    )
    parser.add_argument(
        "--output-stats",
        required=True,
        help="Path to write conversion stats JSON",
    )
    parser.add_argument("--tool-name", default="Veracode Pipeline Scan")
    parser.add_argument("--tool-version", default="")
    return parser.parse_args()

def read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# =============================================================================
# Entry point (kept as requested)
# =============================================================================

def main() -> None:
    args = parse_args()
    data = read_json(args.input)

    sarif, stats = convert_to_sarif(
        data=data,
        tool_name=args.tool_name,
        tool_version=args.tool_version,
        placeholder_uri=args.placeholder_uri,
    )

    write_json(args.output, sarif)
    write_json(args.output_stats, stats)

    print(
        f"Wrote SARIF: {args.output} "
        f"(results={len(sarif['runs'][0]['results'])}, "
        f"rules={len(sarif['runs'][0]['tool']['driver']['rules'])})"
    )
    print(f"Wrote stats: {args.output_stats} -> {stats}")

if __name__ == "__main__":
    main()
