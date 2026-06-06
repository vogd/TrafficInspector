# SNS topic for threat alerts
resource "aws_sns_topic" "alerts" {
  name = "trafinspector-alerts"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "golovaty.alexander@googlemail.com"
}

# CloudWatch metric filter: count NFW alerts that are NOT our app-detection rules (sid >= 300 = threats/evasion)
# We filter on action=blocked OR known threat categories from managed rules
resource "aws_cloudwatch_log_metric_filter" "threat_alerts" {
  name           = "trafinspector-threat-detections"
  log_group_name = "/trafinspector/nfw/alert"
  pattern        = "{ $.event.alert.action = \"blocked\" }"

  metric_transformation {
    name          = "ThreatDetections"
    namespace     = "TrafInspector"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "evasion_alerts" {
  name           = "trafinspector-evasion-detections"
  log_group_name = "/trafinspector/nfw/alert"
  pattern        = "{ $.event.alert.signature = \"Evasion:*\" || $.event.alert.signature = \"VPN:*\" || $.event.alert.signature = \"P2P:*\" }"

  metric_transformation {
    name          = "EvasionDetections"
    namespace     = "TrafInspector"
    value         = "1"
    default_value = "0"
  }
}

# Alarm: any blocked traffic or evasion attempt → SNS
resource "aws_cloudwatch_metric_alarm" "threats" {
  alarm_name          = "trafinspector-threat-detected"
  alarm_description   = "NFW blocked traffic or detected evasion/P2P/VPN"
  namespace           = "TrafInspector"
  metric_name         = "ThreatDetections"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "evasion" {
  alarm_name          = "trafinspector-evasion-detected"
  alarm_description   = "VPN/Tor/P2P evasion traffic detected"
  namespace           = "TrafInspector"
  metric_name         = "EvasionDetections"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
