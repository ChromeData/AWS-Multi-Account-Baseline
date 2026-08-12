#!/usr/bin/env python3
"""Summarise Prowler OCSF-JSON findings by severity into findings/triage.md.

Prowler writes one JSON object per finding (OCSF). This rolls them up so you can
see the shape of the run and drive it down deliberately. Usage:

    python3 scripts/triage.py findings/*.ocsf.json
"""
import glob
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

FINDINGS = Path(__file__).resolve().parent.parent / "findings"


def load(paths):
    items = []
    for p in paths:
        text = Path(p).read_text().strip()
        if not text:
            continue
        # Prowler OCSF output is usually a JSON array; tolerate JSONL too.
        try:
            data = json.loads(text)
            items.extend(data if isinstance(data, list) else [data])
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    items.append(json.loads(line))
    return items


def sev(item):
    # OCSF uses severity_id / status_code; fall back across shapes.
    return (item.get("severity") or item.get("severity_id")
            or item.get("finding_info", {}).get("severity") or "Unknown")


def status(item):
    return (item.get("status_code") or item.get("status") or "").upper()


def service_of(item):
    return (item.get("resources", [{}])[0].get("group", {}).get("name")
            or item.get("cloud", {}).get("service") or "unknown")


def rollup(items):
    """The scoring core: split failing findings out and count them by severity
    and service. Pure, so tests exercise the exact aggregation the report uses."""
    fails = [i for i in items if status(i) in ("FAIL", "FAILED", "NEW")]
    by_sev = Counter(str(sev(i)) for i in fails)
    by_service = defaultdict(int)
    for i in fails:
        by_service[str(service_of(i))] += 1
    return fails, by_sev, by_service


def main():
    paths = sys.argv[1:] or glob.glob(str(FINDINGS / "*.json"))
    if not paths:
        sys.exit("no Prowler JSON found — run 'make scan' first")

    items = load(paths)
    fails, by_sev, by_service = rollup(items)

    lines = ["# Prowler Triage\n",
             f"Total findings parsed: **{len(items)}** · failing: **{len(fails)}**\n",
             "## By severity\n"]
    for s in ("Critical", "High", "Medium", "Low", "Informational", "Unknown"):
        if by_sev.get(s):
            lines.append(f"- **{s}:** {by_sev[s]}")
    lines.append("\n## Top failing services\n")
    for svc, n in sorted(by_service.items(), key=lambda x: -x[1])[:15]:
        lines.append(f"- {svc}: {n}")
    lines.append("\n## Remediation log\n")
    lines.append("| Finding | Severity | Real risk? | Action |")
    lines.append("|---------|----------|-----------|--------|")
    lines.append("| | | | |")

    out = FINDINGS / "triage.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")
    print(f"failing findings: {len(fails)} — {dict(by_sev)}")


if __name__ == "__main__":
    main()
