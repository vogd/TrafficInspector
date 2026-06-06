# S3 data lake: raw NFW + VPC Flow Logs for AI/analytics (Athena/SageMaker/Bedrock) + long retention.
data "aws_caller_identity" "me" {}

resource "aws_s3_bucket" "lake" {
  bucket_prefix = "trafinspector-lake-"
  force_destroy = true
  tags          = var.tags
}
resource "aws_s3_bucket_public_access_block" "lake" {
  bucket                  = aws_s3_bucket.lake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "lake" {
  bucket = aws_s3_bucket.lake.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.lake.arn}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control", "aws:SourceAccount" = data.aws_caller_identity.me.account_id } }
      },
      {
        Sid       = "AWSLogDeliveryAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.lake.arn
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.me.account_id } }
      }
    ]
  })
}

# VPC Flow Logs -> S3 as Parquet, hive-partitioned by hour (good for Athena/AI scans)
resource "aws_flow_log" "lake" {
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.lake.arn}/vpcflow/"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.inspection.id
  destination_options {
    file_format                = "parquet"
    per_hour_partition         = true
    hive_compatible_partitions = true
  }
  tags       = var.tags
  depends_on = [aws_s3_bucket_policy.lake]
}

output "lake_bucket" {
  value = aws_s3_bucket.lake.id
}
