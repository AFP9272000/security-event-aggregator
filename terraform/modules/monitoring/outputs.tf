output "dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "dashboard_arn" {
  description = "ARN of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.main.dashboard_arn
}

output "alarm_arns" {
  description = "ARNs of all CloudWatch alarms"
  value = {
    api_gateway_cpu    = aws_cloudwatch_metric_alarm.api_gateway_cpu.arn
    event_processor_cpu = aws_cloudwatch_metric_alarm.event_processor_cpu.arn
    alb_5xx_errors     = aws_cloudwatch_metric_alarm.alb_5xx_errors.arn
    alb_high_latency   = aws_cloudwatch_metric_alarm.alb_high_latency.arn
    sqs_queue_depth    = aws_cloudwatch_metric_alarm.sqs_queue_depth.arn
    sqs_message_age    = aws_cloudwatch_metric_alarm.sqs_message_age.arn
    dynamodb_throttle  = aws_cloudwatch_metric_alarm.dynamodb_throttle.arn
    critical_events    = aws_cloudwatch_metric_alarm.critical_events.arn
  }
}
