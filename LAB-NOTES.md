# Lab Notes — 09 AWS Multi-Account Baseline

Running log. Errors, dead ends, fixes, surprises. Dated, newest at the bottom.

---

## Format

```
### YYYY-MM-DD — what I was trying to do

**Expected:**
**Got:**
**Cause:**
**Fix:**
```

---

## Finds and decisions

### The baseline failed its own scanner (fixed)

First cut: the CloudTrail bucket had no encryption, no public-access block, no
bucket policy. Prowler would flag the security baseline's OWN infrastructure —
CKV-style S3 findings on the audit log. Added public-access block, KMS
encryption, versioning, and a least-privilege bucket policy. A baseline has to
pass the audit it exists to enable.

### CloudTrail needs the bucket policy first

`depends_on = [aws_s3_bucket_policy.trail]` — CloudTrail validates that it can
write to the bucket at create time. Without the ordering, apply fails with an
"insufficient bucket permissions" error that doesn't name the race.

### Config recorder left off on purpose

Enabling AWS Config recording across all resource types is the biggest cost lever
here. It's commented in `main.tf` with the reasoning. Turn it on once a clean
Prowler run without it is confirmed.

### Triage severity fallback

OCSF exports differ — severity can be under `severity` or `severity_id`. The
roller falls back across shapes; a test pins it, because a miscounted Critical is
the worst possible bug in a triage tool.

---

## Known traps (confirm on apply)

- **Security Hub standards take time to evaluate.** Right after apply, findings
  are sparse because the standards haven't run. Wait before the first Prowler
  scan or the baseline looks cleaner than it is.
- **GuardDuty + Security Hub cost.** Small but non-zero. `make destroy` when done.
- **Prowler needs its own read role.** Confirm it has SecurityAudit +
  ViewOnlyAccess, or it under-reports and the triage looks falsely clean.

---

## Open questions

- [ ] Starting Prowler finding count, and how far to zero after the baseline?
- [ ] Which findings are the baseline's own resources vs. account defaults?
- [ ] Does enabling Config materially change the finding count?
- [ ] Capture the before/after triage.md for findings/.

---

## Log

### 2026-08-12 — the baseline would have failed its own scan

Reviewing `main.tf` before the first apply, the CloudTrail bucket had no encryption,
no public-access block, no versioning, and no bucket policy.

Prowler would have flagged the security baseline's own audit-log bucket. A baseline
that fails the audit it exists to enable is worse than no baseline, because it lands
in the report as noise and trains people to ignore the findings.

**Fixed before applying:** public-access block, KMS encryption, versioning, and a
bucket policy scoped to CloudTrail's two required actions.

Also added `depends_on = [aws_s3_bucket_policy.trail]`. CloudTrail validates it can
write at create time, and without the ordering the apply fails with an "insufficient
bucket permissions" error that doesn't name the race as the cause.

---

### 2026-08-12 — severity fallback in the triage roller

OCSF exports don't agree on where severity lives: sometimes `severity`, sometimes
`severity_id`, sometimes nested under `finding_info`. Same for status, which shows up
as `FAIL`, `FAILED`, or `NEW` depending on the exporter.

A miscounted Critical is the worst possible bug in a triage tool, because you drive
the wrong findings to zero and believe you're done. Both fallbacks are pinned by
tests.

Final run: **9 passed** (`findings/test-run.txt`).

**Deliberately left off:** the AWS Config recorder, commented in `main.tf`. It's the
single biggest cost lever here and I want a clean Prowler run without it first, so I
can attribute the cost and the finding-count change separately.
