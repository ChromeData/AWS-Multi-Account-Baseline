# Lab 09 — AWS Multi-Account Security Baseline

**Stand up a mock multi-account AWS org, apply a security baseline drawn from the
AWS Security Reference Architecture, then scan the whole thing with Prowler and
drive the findings to zero — the org-wide control plane a senior AWS security
engineer owns.**

| | |
|---|---|
| **Domains** | AWS · security |
| **Built on** | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) (Apache-2.0) · [aws-samples/aws-security-reference-architecture-examples](https://github.com/aws-samples/aws-security-reference-architecture-examples) (MIT-0) |
| **Runtime** | ~5 hours · ~$2–5 (mostly free control-plane services) |
| **Status** | 🟡 In progress |

---

## Why this lab exists

A single hardened account is a lab exercise; a hardened *organization* is the job.
The AWS SRA describes how the security services should be laid out across accounts —
GuardDuty, Security Hub, Config, IAM Access Analyzer, delegated admin. This lab
builds a scaled-down version and then proves it with Prowler, which is the same tool
that would audit it in production. Driving a Prowler run from dozens of findings to a
justified near-zero is the artifact.

## What I built

- A **mock org** (AWS Organizations with a management account + a couple of member
  accounts, or a single account with the same services if you're avoiding multi-
  account cost) tagged and structured per SRA.
- A **baseline**: GuardDuty, Security Hub, Config, Access Analyzer, and CloudTrail
  org-trail turned on, with delegated administration where the SRA calls for it.
- A **Prowler pipeline** producing a compliance report against CIS + the AWS
  Foundational Security Best Practices, with each remaining finding either fixed or
  documented as an accepted risk with reasoning.

## What I did not build

Prowler and the SRA examples are upstream. My work is the org layout, the baseline
enablement, and the finding-by-finding remediation write-up.

---

## Running it

```bash
make baseline       # enable the security services (SRA-aligned)
make scan           # prowler aws -> findings/prowler-report.html + .json
make triage         # summarise findings by severity into findings/triage.md
make destroy        # tear the baseline back down
```

## The deliverable

`findings/triage.md` — the before/after that shows judgment, not just tool output:

| Severity | Initial findings | After remediation | Notes |
|----------|------------------|-------------------|-------|
| Critical | | | |
| High | | | |
| Medium | | | |

Then the analysis: which findings are real, which are Prowler being strict about a
control you've consciously accepted, and how the SRA layout changed the picture vs.
a flat single-account setup.

## Cost note

Multi-account with GuardDuty/Config across accounts can accrue cost. The Makefile
defaults to a **single-account SRA-lite** baseline; opt into true multi-account only
if you have an org sandbox. Either way, `make destroy` disables the paid services.

## What broke

See [LAB-NOTES.md](./LAB-NOTES.md).
