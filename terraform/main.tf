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

variable "use_localstack" {
  description = <<-EOT
    Point the provider at LocalStack instead of a real account.

    Only part of this lab can run there, and the boundary is worth stating.
    GuardDuty, Security Hub, Access Analyzer and CloudTrail itself are
    LocalStack Pro features; the community image does not implement them, so
    the detection half of the baseline cannot be exercised locally at all.

    What CAN run is S3, which is where the audit evidence lives. The trail
    bucket's public-access block, encryption, versioning and bucket policy are
    the controls that decide whether the audit trail can be read or tampered
    with by anyone who should not, and those are checkable for free.

    Use with -target on the S3 resources; a full apply hangs on CloudTrail.
  EOT
  type        = bool
  default     = false
}

provider "aws" {
  default_tags {
    tags = { Purpose = "pam-cloud-lab", Lab = "09-aws-multiaccount-baseline" }
  }

  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack

  # NOT skipped, unlike the other labs. The trail bucket name interpolates
  # data.aws_caller_identity.me.account_id, so skipping the account lookup
  # leaves the name unresolved and the provider crashes on apply with a bare
  # "plugin failed to respond". LocalStack implements STS GetCallerIdentity,
  # so the lookup works and returns 000000000000.
  skip_requesting_account_id = false

  # LocalStack serves S3 on one host, so virtual-host addressing
  # (bucket.s3.amazonaws.com) does not resolve. Path style is required.
  s3_use_path_style = var.use_localstack

  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      s3  = "http://localhost:4566"
      iam = "http://localhost:4566"
      sts = "http://localhost:4566"
      kms = "http://localhost:4566"
    }
  }
}

# --- CloudTrail org/account trail ------------------------------------------
resource "aws_cloudtrail" "baseline" {
  name                          = "lab09-baseline-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # The bucket policy must exist before CloudTrail will accept the bucket.
  depends_on = [aws_s3_bucket_policy.trail]
}

resource "aws_s3_bucket" "trail" {
  bucket        = "lab09-cloudtrail-${data.aws_caller_identity.me.account_id}"
  force_destroy = true
}

# A security baseline whose own audit-log bucket is unencrypted and world-
# readable is the joke that writes itself. These four resources keep Prowler
# from flagging the baseline's own infrastructure.
resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

# CloudTrail needs write access to the bucket; nothing else does.
resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.me.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "me" {}

locals {
  # Built by hand rather than read from aws_cloudtrail.baseline.arn.
  #
  # The trail depends_on the bucket policy (CloudTrail refuses a bucket whose
  # policy does not yet allow it), so referencing the trail resource from the
  # policy is a dependency cycle. Composing the ARN from parts breaks it, and
  # the name is a literal three lines up so it cannot drift far.
  trail_arn = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.me.account_id}:trail/lab09-baseline-trail"
}

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
# Deliberately not enabled. Config recording across all resource types is the
# single biggest cost driver in this baseline, and enabling it at the same time
# as everything else makes it impossible to attribute either the spend or the
# change in Prowler's finding count to it.
#
# The sequence is: apply this baseline, take a clean Prowler run, record the
# number, then enable Config and re-run. Two measurements, one variable.
# See LAB-NOTES.md.
#
# resource "aws_config_configuration_recorder" "baseline" { ... }

# --- Multi-account (optional) ----------------------------------------------
# In a real org sandbox you'd delegate Security Hub / GuardDuty admin to an audit
# account here:
# resource "aws_guardduty_organization_admin_account" "audit" { admin_account_id = var.audit_account_id }
# resource "aws_securityhub_organization_admin_account" "audit" { admin_account_id = var.audit_account_id }
