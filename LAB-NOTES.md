# Lab Notes, 09 AWS Multi-Account Baseline

Running log. Errors, dead ends, fixes, surprises. Dated, newest at the bottom.

---

## Format

```
### YYYY-MM-DD, what I was trying to do

**Expected:**
**Got:**
**Cause:**
**Fix:**
```

---

## Finds and decisions

### The baseline failed its own scanner (fixed)

First cut: the CloudTrail bucket had no encryption, no public-access block, no
bucket policy. Prowler would flag the security baseline's OWN infrastructure: CKV-style S3 findings on the audit log. Added public-access block, KMS
encryption, versioning, and a least-privilege bucket policy. A baseline has to
pass the audit it exists to enable.

### CloudTrail needs the bucket policy first

`depends_on = [aws_s3_bucket_policy.trail]`. CloudTrail validates that it can
write to the bucket at create time. Without the ordering, apply fails with an
"insufficient bucket permissions" error that doesn't name the race.

### Config recorder left off on purpose

Enabling AWS Config recording across all resource types is the biggest cost lever
here. It's commented in `main.tf` with the reasoning. Turn it on once a clean
Prowler run without it is confirmed.

### Triage severity fallback

OCSF exports differ. Severity can be under `severity` or `severity_id`. The
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

### 2026-08-12, the baseline would have failed its own scan

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

### 2026-08-12, severity fallback in the triage roller

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

### 2026-08-12, the audit bucket was a confused deputy

GuardDuty, Security Hub, Access Analyzer and CloudTrail are all LocalStack Pro,
so the detection half of this baseline cannot run locally. S3 can, and that is
where the audit evidence actually lives, so I applied the five trail-bucket
resources with `-target` and read them back from the API.

Two provider settings were needed and neither is obvious. `s3_use_path_style`
must be true, because LocalStack serves S3 from one host and virtual-host
addressing does not resolve. And `skip_requesting_account_id` must stay **false**
here, unlike the other labs: the bucket name interpolates the account id, so
skipping the lookup leaves it unresolved and the provider dies with a bare
"plugin failed to respond" that names the bucket and explains nothing.

Encryption `aws:kms`, versioning on, all four public-access flags true. Then the
bucket policy:

```
AWSCloudTrailAclCheck    Condition: {}
AWSCloudTrailWrite       Condition: {"s3:x-amz-acl": "bucket-owner-full-control"}
```

**Neither statement had `aws:SourceArn`.** The principal is the CloudTrail
*service*, which is not scoped to an account, so the policy trusted CloudTrail
globally rather than this account's trail. That is the cross-account
confused-deputy pattern AWS has documented since 2022 and now bakes into its own
console-generated policies.

The file's own comment says "a security baseline whose own audit-log bucket is
unencrypted and world-readable is the joke that writes itself." The encryption
and public access were fine. The trust boundary was not, and it was the one
thing not being checked.

Fixed on both statements, re-applied, confirmed on the deployed object. The trail
ARN is composed from parts rather than read from `aws_cloudtrail.baseline.arn`,
because the trail `depends_on` the bucket policy and referencing the resource
directly is a dependency cycle.

**Separate bug, same shape as everything else here.** `scripts/triage.py` counted
findings whose severity arrived as OCSF `severity_id` and then never showed them:
the fallback returned the raw integer, `"4"`, which matches none of the named
rows the report prints. A report reading "failing: 12" above an empty severity
table. Reproduced at 2 counted / 0 displayed, fixed with the OCSF enum mapping.

My first fix then broke an existing test, correctly: some exporters put the
*label* in `severity_id`, and `int("Critical")` raised, quietly turning a
critical finding into an unknown one. Both shapes handled and pinned. 14 tests,
up from 9.

Detail in `findings/localstack-run.txt`.

---

### 2026-08-12, ran the free half against real AWS, proved the block enforces

The baseline bundles free and paid services. Applied only the free ones with
`-target`: the S3 trail bucket and its hardening, plus Access Analyzer.
GuardDuty, Security Hub and CloudTrail were left off deliberately, and confirmed
disabled at teardown.

Two things proven that LocalStack could not:

**The confused-deputy fix holds on real AWS.** Both bucket-policy statements
carry `aws:SourceArn` scoped to this account's trail, with the real account ARN
interpolated.

**The public-access block was observed enforcing.** Reading config back is not
proof, so I tried to make the audit bucket public:

```
aws s3api put-bucket-policy ... Principal:"*"
-> AccessDenied ... because public policies are prevented by the
   BlockPublicPolicy setting in S3 Block Public Access.
```

AWS names `BlockPublicPolicy` in the denial. The control refused a real request.

6 resources destroyed. Account swept clean afterwards: no GuardDuty, no Security
Hub, no buckets, no KMS keys, no secrets, no trails, no Lambda. **Cost: $0.**

GuardDuty and Security Hub detection cannot be proven without charges, so they
stay config-verified. Detail in `findings/real-aws-run.txt`.

---
