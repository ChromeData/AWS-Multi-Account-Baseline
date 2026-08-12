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

_(first entry goes here on the first real apply)_
