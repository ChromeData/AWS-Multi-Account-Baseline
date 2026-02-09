# SRA-lite security baseline. Single-account by default; the commented org blocks
# show where delegated-admin wiring goes if you run a true multi-account sandbox.
#
# Structure follows aws-samples/aws-security-reference-architecture-examples.

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

provider "aws" {
  default_tags {
    tags = { Purpose = "pam-cloud-lab", Lab = "09-aws-multiaccount-baseline" }
  }
}

# --- CloudTrail org/account trail ------------------------------------------
resource "aws_cloudtrail" "baseline" {
  name                          = "lab09-baseline-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

resource "aws_s3_bucket" "trail" {
  bucket        = "lab09-cloudtrail-${data.aws_caller_identity.me.account_id}"
  force_destroy = true
}

data "aws_caller_identity" "me" {}

# --- GuardDuty --------------------------------------------------------------
resource "aws_guardduty_detector" "baseline" {
  enable = true
}

# --- Security Hub + standards ----------------------------------------------
resource "aws_securityhub_account" "baseline" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.baseline]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.baseline]
}

data "aws_region" "current" {}

# --- IAM Access Analyzer ----------------------------------------------------
resource "aws_accessanalyzer_analyzer" "baseline" {
  analyzer_name = "lab09-account-analyzer"
  type          = "ACCOUNT"
}

# --- AWS Config (recorder + delivery) --------------------------------------
# Left as a documented TODO to keep first-run cost predictable — enabling Config
# recording across all resource types is the biggest cost lever in this lab.
# Turn on per SRA once you've seen a clean Prowler run without it.
#
# resource "aws_config_configuration_recorder" "baseline" { ... }

# --- Multi-account (optional) ----------------------------------------------
# In a real org sandbox you'd delegate Security Hub / GuardDuty admin to an audit
# account here:
# resource "aws_guardduty_organization_admin_account" "audit" { admin_account_id = var.audit_account_id }
# resource "aws_securityhub_organization_admin_account" "audit" { admin_account_id = var.audit_account_id }
