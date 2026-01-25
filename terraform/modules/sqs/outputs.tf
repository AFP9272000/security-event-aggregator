output "queue_url" {
  description = "URL of the SQS queue"
  value       = aws_sqs_queue.events.url
}

output "queue_arn" {
  description = "ARN of the SQS queue"
  value       = aws_sqs_queue.events.arn
}

output "queue_name" {
  description = "Name of the SQS queue"
  value       = aws_sqs_queue.events.name
}

output "dlq_url" {
  description = "URL of the dead letter queue"
  value       = var.enable_dlq ? aws_sqs_queue.events_dlq[0].url : null
}

output "dlq_arn" {
  description = "ARN of the dead letter queue"
  value       = var.enable_dlq ? aws_sqs_queue.events_dlq[0].arn : null
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic"
  value       = aws_sns_topic.alerts.name
}
