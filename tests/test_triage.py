"""Offline tests for the Prowler triage roller.

No AWS, no Prowler run. Synthetic OCSF findings exercise the parsing and rollup,
because the whole value of the triage step is an accurate count by severity, if
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


# --- regressions found 2026-08-12 -------------------------------------------


def test_ocsf_severity_id_maps_to_a_displayed_label():
    """A finding with severity_id and no severity string must still show up.

    OCSF severity_id is an integer enum. The original fallback returned it raw,
    so it stringified to "4" and matched none of the named rows the report
    iterates. The finding was counted in the total and silently dropped from
    the severity table: "failing: 2" printed above an empty list.
    """
    items = [
        {"status_code": "FAIL", "severity_id": 4, "resources": [{"group": {"name": "s3"}}]},
        {"status_code": "FAIL", "severity_id": 5, "resources": [{"group": {"name": "iam"}}]},
    ]
    fails, by_sev, _ = triage.rollup(items)
    assert len(fails) == 2
    assert by_sev["High"] == 1
    assert by_sev["Critical"] == 1

    # The real assertion: everything counted is also renderable.
    named = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
    assert sum(by_sev.get(s, 0) for s in named) == len(fails), \
        "every counted finding must land in a severity the report actually prints"


def test_severity_string_wins_over_id():
    """When Prowler sends both, the human-readable string is authoritative."""
    items = [{"status_code": "FAIL", "severity": "Medium", "severity_id": 4,
              "resources": [{"group": {"name": "ec2"}}]}]
    _, by_sev, _ = triage.rollup(items)
    assert by_sev["Medium"] == 1
    assert "High" not in by_sev


def test_unknown_severity_id_does_not_vanish():
    """An id outside the enum still has to be countable and printable."""
    items = [{"status_code": "FAIL", "severity_id": 99,
              "resources": [{"group": {"name": "s3"}}]}]
    fails, by_sev, _ = triage.rollup(items)
    assert len(fails) == 1
    assert by_sev["Unknown"] == 1


def test_fatal_folds_into_critical():
    """OCSF 6 is Fatal. The report has no Fatal row, so it must not disappear."""
    items = [{"status_code": "FAIL", "severity_id": 6,
              "resources": [{"group": {"name": "iam"}}]}]
    _, by_sev, _ = triage.rollup(items)
    assert by_sev["Critical"] == 1


def test_string_severity_id_passes_through_as_a_label():
    """Some exporters put the label directly in severity_id rather than the enum.

    Caught by an existing test when the integer mapping was added: int("Critical")
    raises, and the first version of the fix swallowed it into "Unknown",
    turning a correctly-labelled critical finding into an unknown one.
    """
    assert triage.sev({"severity_id": "Critical"}) == "Critical"
    assert triage.sev({"severity_id": 5}) == "Critical"
