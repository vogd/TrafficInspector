data "archive_file" "query" {
  type        = "zip"
  source_file = "${path.module}/lambda/query.py"
  output_path = "${path.module}/lambda/query.zip"
}

resource "aws_iam_role" "query" {
  name = "trafinspector-query"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}
resource "aws_iam_role_policy" "query" {
  role = aws_iam_role.query.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:*" },
      { Effect = "Allow", Action = ["dynamodb:Query"], Resource = [aws_dynamodb_table.conns.arn, "${aws_dynamodb_table.conns.arn}/index/*"] }
    ]
  })
}

resource "aws_lambda_function" "query" {
  function_name    = "trafinspector-query"
  role             = aws_iam_role.query.arn
  runtime          = "python3.12"
  handler          = "query.handler"
  filename         = data.archive_file.query.output_path
  source_code_hash = data.archive_file.query.output_base64sha256
  timeout          = 30
  environment { variables = { TABLE = aws_dynamodb_table.conns.name } }
  tags = var.tags
}

# Public (unauthenticated) Function URL — POC only; returns internal connection metadata.
resource "aws_lambda_function_url" "query" {
  function_name      = aws_lambda_function.query.function_name
  authorization_type = "AWS_IAM"
  cors {
    allow_origins = ["*"]
    allow_methods = ["GET"]
  }
}

# Grant CloudFront OAC permission to invoke the Function URL
resource "aws_lambda_permission" "query_url" {
  statement_id  = "AllowCloudFrontOAC"
  action        = "lambda:InvokeFunctionUrl"
  function_name = aws_lambda_function.query.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.ui.arn
  function_url_auth_type = "AWS_IAM"
}

output "query_url" {
  value = aws_lambda_function_url.query.function_url
}

# Public API Gateway HTTP API (bypasses org SCP that blocks Lambda Function URLs)
resource "aws_apigatewayv2_api" "query" {
  name          = "trafinspector-query"
  protocol_type = "HTTP"
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
  }
}

resource "aws_apigatewayv2_integration" "query" {
  api_id                 = aws_apigatewayv2_api.query.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.query.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "query" {
  api_id    = aws_apigatewayv2_api.query.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.query.id}"
}

resource "aws_apigatewayv2_stage" "query" {
  api_id      = aws_apigatewayv2_api.query.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.query.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.query.execution_arn}/*/*"
}

output "query_api_url" {
  value = aws_apigatewayv2_stage.query.invoke_url
}

resource "aws_s3_object" "ui" {
  bucket       = aws_s3_bucket.ui.id
  key          = "index.html"
  source       = "${path.module}/ui/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/ui/index.html")
}

resource "aws_s3_object" "ui_cfg" {
  bucket       = aws_s3_bucket.ui.id
  key          = "config.js"
  content      = templatefile("${path.module}/ui/config.js.tftpl", { query_api_url = aws_apigatewayv2_stage.query.invoke_url })
  content_type = "application/javascript"
  etag         = md5(templatefile("${path.module}/ui/config.js.tftpl", { query_api_url = aws_apigatewayv2_stage.query.invoke_url }))
}

resource "aws_s3_object" "admin" {
  bucket       = aws_s3_bucket.ui.id
  key          = "admin.html"
  source       = "${path.module}/ui/admin.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/ui/admin.html")
}
