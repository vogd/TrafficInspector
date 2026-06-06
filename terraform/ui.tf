# Private S3 bucket holds the rendered comparison page (access via presigned URL or console).
resource "aws_s3_bucket" "ui" {
  bucket_prefix = "trafinspector-ui-"
  force_destroy = true
  tags          = var.tags
}
resource "aws_s3_bucket_public_access_block" "ui" {
  bucket                  = aws_s3_bucket.ui.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "archive_file" "comparison" {
  type        = "zip"
  source_file = "${path.module}/lambda/ingest.py"
  output_path = "${path.module}/lambda/ingest.zip"
}

resource "aws_iam_role" "comparison" {
  name = "trafinspector-comparison"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}
resource "aws_iam_role_policy" "comparison" {
  role = aws_iam_role.comparison.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"], Resource = "*" },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:*" },
      { Effect = "Allow", Action = ["dynamodb:BatchWriteItem", "dynamodb:PutItem"], Resource = aws_dynamodb_table.conns.arn },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.lake.arn}/*" }
    ]
  })
}

resource "aws_lambda_function" "comparison" {
  function_name    = "trafinspector-comparison"
  role             = aws_iam_role.comparison.arn
  runtime          = "python3.12"
  handler          = "ingest.handler"
  filename         = data.archive_file.comparison.output_path
  source_code_hash = data.archive_file.comparison.output_base64sha256
  timeout          = 300
  environment {
    variables = {
      ALERT_LG    = aws_cloudwatch_log_group.nfw["alert"].name
      TLS_LG      = aws_cloudwatch_log_group.nfw["tls"].name
      NFW_FLOW_LG = aws_cloudwatch_log_group.nfw["flow"].name
      VPC_FLOW_LG = aws_cloudwatch_log_group.flow.name
      TABLE       = aws_dynamodb_table.conns.name
      LAKE_BUCKET = aws_s3_bucket.lake.id
      WINDOW_MIN  = "1440"
    }
  }
  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "comparison" {
  name                = "trafinspector-comparison"
  schedule_expression = "rate(1 minute)"
  tags                = var.tags
}
resource "aws_cloudwatch_event_target" "comparison" {
  rule = aws_cloudwatch_event_rule.comparison.name
  arn  = aws_lambda_function.comparison.arn
}
resource "aws_lambda_permission" "comparison" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.comparison.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.comparison.arn
}

output "comparison_bucket" {
  value = aws_s3_bucket.ui.id
}
