#!/usr/bin/env python3
"""
Pull Veracode AppSec Reporting Findings for a single application (optionally scoped to a sandbox),
then export lossless JSON and Excel outputs.

Refactored for readability and lower cyclomatic complexity.
"""

import json
import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from datetime import date
import calendar

import requests
import pandas as pd
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# -----------------------
# Constants & configuration
# -----------------------
API_TIMEOUT_S = 60
POLL_INTERVAL_S = 15
MAX_POLL_S = 20 * 60  # 20 minutes
OUT_DIR = "out"

# -----------------------
# Generic utilities
# -----------------------
def must_env(name: str) -> str:
    """Return a required env var or exit with a helpful message."""
    v = os.getenv(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required env var: {name}")
    return v


def opt_env(name: str) -> str:
    """Return an optional env var (empty string if unset)."""
    return os.getenv(name, "").strip()


def validate_date_yyyy_mm_dd(s: str, start_or_end: str) -> None:
    """Validate YYYY-MM-DD date-only format."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise SystemExit(f"LAST_UPDATED_{start_or_end}_DATE must be YYYY-MM-DD (date only), e.g. 2025-12-01")


def ensure_out_dir() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)


def dump_json(path: str, obj: Any) -> None:
    """Write JSON with UTF-8 and pretty indentation."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def hmac_auth_from_env() -> RequestsAuthPluginVeracodeHMAC:
    """Build Veracode HMAC auth from env vars."""
    api_id = must_env("VERACODE_API_ID")
    api_key = must_env("VERACODE_API_KEY")
    return RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)


def get_json(url: str, auth: RequestsAuthPluginVeracodeHMAC, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """GET JSON with common error handling."""
    r = requests.get(url, params=params, auth=auth, timeout=API_TIMEOUT_S)
    if r.status_code >= 400:
        raise SystemExit(f"GET {url} failed ({r.status_code}):\n{r.text}")
    return r.json()


def post_json(url: str, auth: RequestsAuthPluginVeracodeHMAC, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """POST JSON; always return (status, body-as-json-or-fallback)."""
    r = requests.post(url, json=payload, auth=auth, timeout=API_TIMEOUT_S)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text}
    return r.status_code, body

# -----------------------
# Applications API
# -----------------------
def applications_lookup_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, name: str) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/applications"
    return get_json(url, auth, params={"name": name, "page": 0, "size": 50})


def extract_first_application(apps_resp: Dict[str, Any]) -> Dict[str, Any]:
    """Return the first application dict or exit if none."""
    embedded = apps_resp.get("_embedded") or {}
    apps = embedded.get("applications") or []
    if not isinstance(apps, list) or not apps or not isinstance(apps[0], dict):
        raise SystemExit("No applications returned. Check APPLICATION_NAME or permissions.")
    return apps[0]


def resolve_app_ids(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_name: str) -> Tuple[Optional[int], Optional[str], Dict[str, Any]]:
    resp = applications_lookup_by_name(api_base, auth, app_name)
    app0 = extract_first_application(resp)
    # tolerant extraction
    app_id = _to_int_or_none(app0.get("id"))
    app_guid = app0.get("guid") if isinstance(app0.get("guid"), str) and app0.get("guid") else None
    return app_id, app_guid, app0

# -----------------------
# Sandboxes API
# (resolve SANDBOX_NAME -> sandbox id/guid)
# -----------------------
def list_sandboxes(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, page: int = 0) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/applications/{app_guid}/sandboxes"
    return get_json(url, auth, params={"page": page, "size": 50})


def extract_sandboxes(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Try common shapes; return list of sandbox dicts."""
    embedded = resp.get("_embedded") or {}
    for key in ("sandboxes", "sandbox"):
        v = embedded.get(key)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    # fallback: any list of dicts under _embedded
    for v in embedded.values():
        if isinstance(v, list) and (not v or isinstance(v[0], dict)):
            return [x for x in v if isinstance(x, dict)]
    return []


def sandbox_fields(sb: Dict[str, Any]) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Return (sandbox_id, sandbox_guid, sandbox_name)."""
    name = sb.get("name") or sb.get("sandbox_name")
    guid = sb.get("guid") or sb.get("sandbox_guid")
    sid = sb.get("id") or sb.get("sandbox_id")
    return _to_int_or_none(sid), guid if isinstance(guid, str) and guid else None, name if isinstance(name, str) and name else None


def resolve_sandbox_by_name(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, app_guid: str, sandbox_name: str) -> Dict[str, Any]:
    """Find a sandbox by exact name via bounded paging."""
    for page in range(0, 10):
        sbs = extract_sandboxes(list_sandboxes(api_base, auth, app_guid, page=page))
        if not sbs:
            break
        for sb in sbs:
            _, _, nm = sandbox_fields(sb)
            if nm == sandbox_name:
                return sb
    raise SystemExit(f"Sandbox '{sandbox_name}' not found for this application. Check exact name/case.")

# -----------------------
# Reporting API
# -----------------------
def generate_findings_report(
    api_base: str,
    auth: RequestsAuthPluginVeracodeHMAC,
    last_updated_start: str,
    app_id: Optional[int],
    policy_sandbox: Optional[str],
    sandbox_id: Optional[int],
) -> Dict[str, Any]:
    """
    Create a FINDINGS report with graceful fallbacks:

    Try (app_id + policy_sandbox + sandbox_id) → (app_id + policy_sandbox) → (last_updated only)
    Stop at the first successful (status < 400) submission.
    """
    url = f"{api_base}/appsec/v1/analytics/report"

    base = {"report_type": "FINDINGS", "last_updated_start_date": last_updated_start}
    variants: List[Dict[str, Any]] = [
        {**base, **_maybe({"app_id": app_id, "policy_sandbox": policy_sandbox, "sandbox_id": sandbox_id})},
        {**base, **_maybe({"app_id": app_id, "policy_sandbox": policy_sandbox})},
        base,
    ]

    last_body: Dict[str, Any] = {}
    for payload in variants:
        status, body = post_json(url, auth, payload)
        if status < 400:
            return body
        last_body = body  # keep most recent failure body

    dump_json(f"{OUT_DIR}/report_create.json", last_body)
    raise SystemExit(f"POST {url} failed—see {OUT_DIR}/report_create.json for details.")


def extract_report_id(created: Dict[str, Any]) -> Optional[str]:
    embedded = created.get("_embedded")
    if isinstance(embedded, dict):
        rid = embedded.get("id")
        if isinstance(rid, str) and rid:
            return rid
    rid2 = created.get("id")
    if isinstance(rid2, str) and rid2:
        return rid2
    return None


def get_report_page(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, report_id: str, page: int) -> Dict[str, Any]:
    url = f"{api_base}/appsec/v1/analytics/report/{report_id}"
    return get_json(url, auth, params={"page": page})


def is_ready(obj: Dict[str, Any]) -> bool:
    status = str(
        obj.get("status")
        or obj.get("state")
        or (obj.get("_embedded") or {}).get("status")
        or ""
    ).upper()
    return status in {"COMPLETED", "COMPLETE", "READY", "FINISHED"}


def total_pages(obj: Dict[str, Any]) -> int:
    meta = (obj.get("_embedded") or {}).get("page_metadata") or {}
    tp = meta.get("total_pages")
    return _to_int_or_default(tp, default=1)


def extract_findings(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = (obj.get("_embedded") or {}).get("findings")
    return [f for f in findings] if isinstance(findings, list) else []


def wait_for_report_ready(api_base: str, auth: RequestsAuthPluginVeracodeHMAC, report_id: str) -> Dict[str, Any]:
    """Poll page 0 until the report is ready or we time out."""
    start = time.time()
    while True:
        page0 = get_report_page(api_base, auth, report_id, page=0)
        dump_json(f"{OUT_DIR}/report_page0_latest.json", page0)
        if is_ready(page0):
            return page0
        if time.time() - start > MAX_POLL_S:
            raise SystemExit("Timed out waiting for report readiness.")
        time.sleep(POLL_INTERVAL_S)

# -----------------------
# Client-side filtering
# -----------------------
def matches_scope(
    finding: Dict[str, Any],
    app_name: str,
    sandbox_name: str,
    sandbox_id: Optional[int],
) -> bool:
    """Return True if a finding belongs to the requested app and (optional) sandbox."""
    if _first_str(finding, ["app_name", "application_name", "applicationName"]) != app_name:
        return False

    if not sandbox_name:
        return True  # app-level scope only

    # Prefer sandbox name; fall back to sandbox id if name absent
    fn = _first_str(finding, ["sandbox_name", "sandboxName"])
    if fn:
        return fn == sandbox_name

    fid = _first_int(finding, ["sandbox_id", "sandboxId"])
    return sandbox_id is not None and fid == sandbox_id


def filter_findings(
    findings: Iterable[Dict[str, Any]],
    app_name: str,
    sandbox_name: str,
    sandbox_id: Optional[int],
) -> List[Dict[str, Any]]:
    return [f for f in findings if matches_scope(f, app_name, sandbox_name, sandbox_id)]

# -----------------------
# Lossless Excel export
# -----------------------
def to_cell(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return v


def findings_to_dataframe_lossless(findings: List[Dict[str, Any]]) -> pd.DataFrame:
    all_keys = set()
    for f in findings:
        if isinstance(f, dict):
            all_keys.update(f.keys())

    rows: List[Dict[str, Any]] = []
    for f in findings:
        rows.append({k: to_cell(f.get(k)) for k in all_keys})

    df = pd.DataFrame(rows)
    return df.reindex(sorted(df.columns), axis=1)


def export_findings_lossless_excel(findings: List[Dict[str, Any]], out_xlsx: str) -> None:
    df_flat = findings_to_dataframe_lossless(findings)
    df_raw = pd.DataFrame({
        "finding_json": [
            json.dumps(f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            for f in findings
        ]
    })
    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df_flat.to_excel(writer, index=False, sheet_name="findings_flat")
        df_raw.to_excel(writer, index=False, sheet_name="findings_raw_json")

# -----------------------
# Small internal helpers
# -----------------------
def _to_int_or_none(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v))
    except Exception:
        return None


def _to_int_or_default(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _maybe(items: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow dict of keys whose values are not None/empty."""
    return {k: v for k, v in items.items() if v is not None and v != ""}


def _first_str(obj: Dict[str, Any], keys: List[str]) -> Optional[str]:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _first_int(obj: Dict[str, Any], keys: List[str]) -> Optional[int]:
    for k in keys:
        v = obj.get(k)
        iv = _to_int_or_none(v)
        if iv is not None:
            return iv
    return None

def within_six_months(date_str1: str, date_str2: str) -> bool:
    """
    Return True if two dates (YYYY-MM-DD strings) are within 6 calendar months
    of each other (inclusive), otherwise False.

    Definition used:
    - Take the earlier of the two dates and add exactly 6 calendar months.
    - If the later date is <= (earlier date + 6 months), return True.

    Examples:
        within_six_months("2024-01-31", "2024-07-31") -> True   # exactly 6 months
        within_six_months("2024-01-31", "2024-08-01") -> False  # beyond 6 months
        within_six_months("2024-08-31", "2025-02-28") -> True   # end-of-month handling
    """
    def parse_yyyy_mm_dd(s: str) -> date:
        y, m, d = map(int, s.split("-"))
        return date(y, m, d)

    def add_months(dt: date, months: int) -> date:
        """
        Add 'months' calendar months to a date, clamping the day to the last valid
        day of the target month (e.g., Jan 31 + 1 month -> Feb 28 or Feb 29 in leap years).
        """
        y = dt.year
        m = dt.month + months
        # Normalize year/month
        y += (m - 1) // 12
        m = ((m - 1) % 12) + 1

        # Clamp day to month's last day
        last_day = calendar.monthrange(y, m)[1]
        d = min(dt.day, last_day)
        return date(y, m, d)

    d1 = parse_yyyy_mm_dd(date_str1)
    d2 = parse_yyyy_mm_dd(date_str2)

    # Order: earlier, later
    earlier, later = (d1, d2) if d1 <= d2 else (d2, d1)
    six_months_after_earlier = add_months(earlier, 6)

    return later <= six_months_after_earlier

# -----------------------
# Main
# -----------------------
def main() -> None:
    ensure_out_dir()

    api_base = must_env("VERACODE_API_BASE").rstrip("/")
    app_name = must_env("APPLICATION_NAME")
    last_updated_start = must_env("LAST_UPDATED_START_DATE")
    validate_date_yyyy_mm_dd(last_updated_start, "START")

    last_updated_end = opt_env("LAST_UPDATED_END_DATE")
    validate_date_yyyy_mm_dd(last_updated_end, "END")

    if not within_six_months(last_updated_start, last_updated_end):
        raise SystemExit("Start and end dates must be within 6 months of each other")

    sandbox_name = opt_env("SANDBOX_NAME")
    auth = hmac_auth_from_env()

    # Resolve application
    app_id, app_guid, app_obj = resolve_app_ids(api_base, auth, app_name)
    dump_json(f"{OUT_DIR}/application_lookup.json", app_obj)
    print(f"Resolved application: name={app_name}, id={app_id}, guid={app_guid}")

    # Resolve sandbox (if provided)
    sandbox_id: Optional[int] = None
    sandbox_guid: Optional[str] = None
    if sandbox_name:
        if not app_guid:
            raise SystemExit("Application GUID is required to resolve sandboxes but was not found.")
        sb_obj = resolve_sandbox_by_name(api_base, auth, app_guid, sandbox_name)
        sandbox_id, sandbox_guid, _ = sandbox_fields(sb_obj)
        dump_json(f"{OUT_DIR}/sandbox_lookup.json", sb_obj)
        print(f"Resolved sandbox: name={sandbox_name}, sandbox_id={sandbox_id}, sandbox_guid={sandbox_guid}")

    # Policy vs Sandbox selector (server-side hint)
    policy_sandbox = "Sandbox" if sandbox_name else "Policy"

    # Create report (with fallbacks)
    created = generate_findings_report(
        api_base=api_base,
        auth=auth,
        last_updated_start=last_updated_start,
        app_id=app_id,
        policy_sandbox=policy_sandbox,
        sandbox_id=sandbox_id,
    )
    dump_json(f"{OUT_DIR}/report_create.json", created)

    report_id = extract_report_id(created)
    if not report_id:
        raise SystemExit("No report id returned (see out/report_create.json).")

    # Wait until ready
    page0 = wait_for_report_ready(api_base, auth, report_id)

    # Paginate
    total = total_pages(page0)
    pages: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []
    for p in range(total):
        obj = get_report_page(api_base, auth, report_id, page=p)
        pages.append(obj)
        all_findings.extend(extract_findings(obj))

    dump_json(f"{OUT_DIR}/report_pages.json", pages)
    dump_json(f"{OUT_DIR}/findings_portfolio_flat.json", all_findings)

    # Scope to requested app (+ sandbox if provided)
    scoped = filter_findings(all_findings, app_name=app_name, sandbox_name=sandbox_name, sandbox_id=sandbox_id)
    suffix = f"{app_name}" + (f"__sandbox__{sandbox_name}" if sandbox_name else "")
    dump_json(f"{OUT_DIR}/findings_single_app_{suffix}.json", scoped)

    # Lossless Excel
    out_xlsx = f"{OUT_DIR}/findings_single_app_{suffix}.xlsx"
    export_findings_lossless_excel(scoped, out_xlsx)

    # Summary
    print(f"report_id={report_id}")
    print(f"total_pages={total}")
    print(f"findings_total={len(all_findings)}")
    print(f"findings_scoped={len(scoped)}")
    print(f"Wrote JSON: out/findings_single_app_{suffix}.json")
    print(f"Wrote Excel (lossless): {out_xlsx}")


if __name__ == "__main__":
    main()
