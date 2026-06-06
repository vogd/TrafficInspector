resource "aws_dynamodb_table" "conns" {
  name         = "trafinspector-connections"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "conn_id"

  attribute {
    name = "conn_id"
    type = "S"
  }
  attribute {
    name = "gsipk"
    type = "S"
  }
  attribute {
    name = "ts"
    type = "N"
  }

  global_secondary_index {
    name            = "by_time"
    hash_key        = "gsipk"
    range_key       = "ts"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = var.tags
}
