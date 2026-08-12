# Lab Notes — AWS Multi-Account Security Baseline

> Running log, newest first.

## Known traps (pre-seeded)

### Security Hub standards ARNs are region-specific

The CIS and FSBP subscription ARNs differ by partition/region. A wrong ARN fails
with a not-found that doesn't say "wrong region." Confirm against
`aws securityhub describe-standards`.

### Config recording is the cost bomb

Enabling AWS Config across all resource types is where a lab bill actually grows.
It's commented out by default. Turn it on deliberately, watch cost for a day, and
note the delta — that awareness is part of the exercise.

### Prowler needs its own permissions

Prowler runs as your credentials. If checks come back "access denied" rather than
pass/fail, that's a Prowler IAM gap, not a finding. Use the SecurityAudit +
`ViewOnlyAccess` managed policies.

### The goal isn't zero findings

Some Prowler findings are controls you've consciously not enabled in a lab (e.g.
org-wide Config). Document those as accepted, don't chase a false 100%.

## YYYY-MM-DD — <first real entry>

**Goal:** · **What happened:** · **Why:** · **Fix:** · **Time lost:**

## Open questions
- [ ] How much did enabling Config actually cost over 24h?
- [ ] Which findings only appear in a multi-account layout vs. single-account?
