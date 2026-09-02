output "sns_topic_arn" {
  description = "Topic every alarm publishes to."
  value       = aws_sns_topic.alerts.arn
}

output "dashboard_name" {
  description = "CloudWatch dashboard name."
  value       = aws_cloudwatch_dashboard.waf.dashboard_name
}

output "alarm_names" {
  description = "Every alarm created, for the evidence bundle."
  value = concat(
    [aws_cloudwatch_metric_alarm.blocked_spike.alarm_name,
    aws_cloudwatch_metric_alarm.allowed_collapse.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.detection : a.alarm_name]
  )
}
