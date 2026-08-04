#!/usr/bin/env python3
"""Run Poutine against ./src and emit Scrutineer findings JSON."""

import json
import os
import re
import shutil
import subprocess
from urllib.parse import urlparse


SEVERITY_MAP = {
    "note": "Low",
    "warning": "Medium",
    "error": "High",
}


def main():
    if shutil.which("poutine") is None:
        emit_error("poutine not on PATH")
        return

    env = os.environ.copy()
    env["POUTINE_DISABLE_VERSION_CHECK"] = "1"
    proc = subprocess.run(
        [
            "poutine",
            "analyze_local",
            ".",
            "--format",
            "json",
            "--quiet",
            "--disable-version-check",
        ],
        cwd="./src",
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"exit status {proc.returncode}"
        emit_error(f"poutine: {detail[:2000]}")
        return

    try:
        report = json.loads(proc.stdout) if proc.stdout else {}
    except json.JSONDecodeError as exc:
        emit_error(f"poutine json: {exc}")
        return

    if not isinstance(report, dict):
        emit_error("poutine json: expected an object")
        return
    findings = report.get("findings", [])
    rules = report.get("rules", {})
    if not isinstance(findings, list) or not isinstance(rules, dict):
        emit_error("poutine json: findings and rules have unexpected shapes")
        return

    findings.sort(key=finding_sort_key)
    mapped = [map_finding(i, finding, rules) for i, finding in enumerate(findings, 1)]
    print(json.dumps({"findings": mapped}, sort_keys=True))


def emit_error(message):
    print(json.dumps({"findings": [], "error": message}, sort_keys=True))


def finding_sort_key(finding):
    if not isinstance(finding, dict):
        return ("", "", 0, json.dumps(finding, sort_keys=True, default=str))
    meta = finding.get("meta") if isinstance(finding.get("meta"), dict) else {}
    return (
        text(finding.get("rule_id")),
        text(meta.get("path")),
        positive_int(meta.get("line")),
        json.dumps(finding, sort_keys=True, default=str),
    )


def map_finding(index, finding, rules):
    if not isinstance(finding, dict):
        finding = {}
    rule_id = text(finding.get("rule_id")) or "poutine-finding"
    rule = rules.get(rule_id)
    if not isinstance(rule, dict):
        rule = {}
    meta = finding.get("meta")
    if not isinstance(meta, dict):
        meta = {}

    severity = SEVERITY_MAP.get(text(rule.get("level")).lower(), "Medium")
    location = finding_location(meta)
    title = text(rule.get("title")) or rule_id
    return {
        "id": f"F{index}",
        "title": title,
        "severity": severity,
        "location": location,
        "locations": [location],
        "trace": finding_trace(rule, meta),
        "rating": f"{severity} from Poutine rule {rule_id}",
        "references": rule_references(rule_id, rule.get("refs")),
    }


def finding_location(meta):
    path = safe_repo_path(text(meta.get("path")))
    line = positive_int(meta.get("line"))
    return f"{path}:{line}" if line else path


def safe_repo_path(value):
    if not value or "\\" in value or value.startswith("/"):
        return "workflow"
    if re.match(r"^[A-Za-z]:", value):
        return "workflow"
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "workflow"
    return "/".join(parts)


def positive_int(value):
    if isinstance(value, bool):
        return 0
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def finding_trace(rule, meta):
    parts = []
    add_trace(parts, "Details", meta.get("details"))
    add_trace(parts, "Rule", rule.get("description"))
    add_trace(parts, "Job", meta.get("job"))
    add_trace(parts, "Step", meta.get("step"))
    add_trace(parts, "Event triggers", meta.get("event_triggers"))
    add_trace(parts, "Injection sources", meta.get("injection_sources"))
    add_trace(parts, "LOTP tool", meta.get("lotp_tool"))
    add_trace(parts, "LOTP action", meta.get("lotp_action"))
    add_trace(parts, "LOTP targets", meta.get("lotp_targets"))
    add_trace(parts, "Referenced secrets", meta.get("referenced_secrets"))
    return "\n".join(parts)


def add_trace(parts, label, value):
    rendered = trace_value(value)
    if rendered:
        parts.append(f"{label}: {rendered}")


def trace_value(value):
    if isinstance(value, list):
        return ", ".join(item for item in (text(v) for v in value) if item)
    return text(value)


def rule_references(rule_id, refs):
    if not isinstance(refs, list):
        return []
    result = []
    for value in refs:
        url = text(value)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue
        result.append(
            {
                "url": url,
                "summary": f"Poutine rule {rule_id}",
                "tags": "poutine,docs",
            }
        )
    return result


def text(value):
    return value.strip() if isinstance(value, str) else ""


if __name__ == "__main__":
    main()
