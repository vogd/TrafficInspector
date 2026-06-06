# AI Classifier: runs every 5 min, deduplicates by destination, caches results
# Uses DynamoDB cache to avoid re-classifying known destinations

resource "aws_dynamodb_table" "classifications" {
  name         = "trafinspector-classifications"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "dest_key"

  attribute {
    name = "dest_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = var.tags
}

data "archive_file" "classifier" {
  type        = "zip"
  source_file = "${path.module}/lambda/classifier.py"
  output_path = "${path.module}/lambda/classifier.zip"
}

resource "aws_iam_role" "classifier" {
  name = "trafinspector-classifier"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "classifier" {
  role = aws_iam_role.classifier.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.conns.arn, "${aws_dynamodb_table.conns.arn}/index/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:BatchGetItem"]
        Resource = aws_dynamodb_table.classifications.arn
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = ["arn:aws:bedrock:*::foundation-model/*", "arn:aws:bedrock:*:*:inference-profile/*"]
      }
    ]
  })
}

resource "aws_lambda_function" "classifier" {
  function_name    = "trafinspector-classifier"
  role             = aws_iam_role.classifier.arn
  handler          = "classifier.handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  filename         = data.archive_file.classifier.output_path
  source_code_hash = data.archive_file.classifier.output_base64sha256

  environment {
    variables = {
      TABLE          = aws_dynamodb_table.conns.name
      CACHE_TABLE    = aws_dynamodb_table.classifications.name
      BEDROCK_REGION = "us-east-1"
      MODEL_ID       = "us.anthropic.claude-sonnet-4-6"
    }
  }
  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "classifier" {
  name                = "trafinspector-classifier"
  schedule_expression = "rate(5 minutes)"
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "classifier" {
  rule = aws_cloudwatch_event_rule.classifier.name
  arn  = aws_lambda_function.classifier.arn
}

resource "aws_lambda_permission" "classifier" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.classifier.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.classifier.arn
}

# Admin API Lambda — taxonomy approve/reject/list
data "archive_file" "admin" {
  type        = "zip"
  source_file = "${path.module}/lambda/admin.py"
  output_path = "${path.module}/lambda/admin.zip"
}

resource "aws_iam_role" "admin" {
  name = "trafinspector-admin"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:*" },
      { Effect = "Allow", Action = ["dynamodb:Scan", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], Resource = aws_dynamodb_table.classifications.arn },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.lake.arn}/taxonomy.json" }
    ]
  })
}

resource "aws_lambda_function" "admin" {
  function_name    = "trafinspector-admin"
  role             = aws_iam_role.admin.arn
  handler          = "admin.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.admin.output_path
  source_code_hash = data.archive_file.admin.output_base64sha256
  environment {
    variables = {
      CACHE_TABLE     = aws_dynamodb_table.classifications.name
      TAXONOMY_BUCKET = aws_s3_bucket.lake.id
    }
  }
  tags = var.tags
}

resource "aws_apigatewayv2_integration" "admin" {
  api_id                 = aws_apigatewayv2_api.query.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.admin.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "admin" {
  api_id    = aws_apigatewayv2_api.query.id
  route_key = "ANY /admin"
  target    = "integrations/${aws_apigatewayv2_integration.admin.id}"
}

resource "aws_apigatewayv2_route" "admin_post" {
  api_id    = aws_apigatewayv2_api.query.id
  route_key = "POST /admin"
  target    = "integrations/${aws_apigatewayv2_integration.admin.id}"
}

resource "aws_lambda_permission" "admin_apigw" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.admin.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.query.execution_arn}/*/*"
}
