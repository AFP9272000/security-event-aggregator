output "ecs_execution_role_arn" {
  description = "ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_execution.arn
}

output "api_gateway_task_role_arn" {
  description = "ARN of the API Gateway task role"
  value       = aws_iam_role.api_gateway_task.arn
}

output "event_ingest_task_role_arn" {
  description = "ARN of the Event Ingest task role"
  value       = aws_iam_role.event_ingest_task.arn
}

output "event_processor_task_role_arn" {
  description = "ARN of the Event Processor task role"
  value       = aws_iam_role.event_processor_task.arn
}

output "github_actions_role_arn" {
  description = "ARN of the GitHub Actions role"
  value       = var.enable_github_oidc && var.github_repo != "" ? aws_iam_role.github_actions[0].arn : null
}
