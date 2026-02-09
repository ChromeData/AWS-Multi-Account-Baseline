"""Offline tests for the Prowler triage roller.

No AWS, no Prowler run. Synthetic OCSF findings exercise the parsing and rollup,
because the whole value of the triage step is an accurate count by severity — if
that's wrong, you drive the wrong findings to zero.

Run:  python -m pytest tests/ -v
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("triage", ROOT / "scripts" / "triage.py")
triage = importlib.util.module_from_spec(spec)
sys.modules["triage"] = triage
spec.loader.exec_module(triage)


def finding(severity, status="FAIL", service="s3"):
    return {
        "severity": severity,
        "status_code": status,
        "resources": [{"group": {"name": service}}],
    }


class TestStatusAndSeverity:
    def test_fail_variants_all_count_as_failing(self):
        items = [finding("High", "FAIL"), finding("High", "FAILED"), finding("High", "NEW")]
        fails, _, _ = triage.rollup(items)
        assert len(fails) == 3

    def test_pass_is_not_a_failure(self):
        items = [finding("High", "PASS"), finding("Low", "FAIL")]
        fails, _, _ = triage.rollup(items)
        assert len(fails) == 1

    def test_severity_falls_back_across_shapes(self):
        # OCSF exports vary; severity may live under severity_id.
        item = {"severity_id": "Critical", "status_code": "FAIL", "resources": [{}]}
        assert triage.sev(item) == "Critical"


class TestRollup:
    def test_counts_by_severity(self):
        items = [finding("High"), finding("High"), finding("Low")]
        _, by_sev, _ = triage.rollup(items)
        assert by_sev["High"] == 2
        assert by_sev["Low"] == 1

    def test_counts_by_service(self):
        items = [finding("High", service="s3"), finding("High", service="iam"),
                 finding("Medium", service="s3")]
        _, _, by_service = triage.rollup(items)
        assert by_service["s3"] == 2
        assert by_service["iam"] == 1

    def test_empty_input_is_safe(self):
        fails, by_sev, by_service = triage.rollup([])
        assert fails == [] and not by_sev and not by_service


class TestLoad:
    def test_reads_json_array(self, tmp_path):
        p = tmp_path / "a.json"
        p.write_text('[{"severity":"High","status_code":"FAIL"}]')
        assert len(triage.load([p])) == 1

    def test_tolerates_jsonl(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text('{"severity":"High","status_code":"FAIL"}\n'
                     '{"severity":"Low","status_code":"PASS"}')
        assert len(triage.load([p])) == 2

    def test_skips_empty_files(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("")
        assert triage.load([p]) == []
