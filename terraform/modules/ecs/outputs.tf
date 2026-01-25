output "cluster_id" {
  description = "ID of the ECS cluster"
  value       = aws_ecs_cluster.main.id
}

output "cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "api_gateway_service_name" {
  description = "Name of the API Gateway ECS service"
  value       = aws_ecs_service.api_gateway.name
}

output "event_ingest_service_name" {
  description = "Name of the Event Ingest ECS service"
  value       = aws_ecs_service.event_ingest.name
}

output "event_processor_service_name" {
  description = "Name of the Event Processor ECS service"
  value       = aws_ecs_service.event_processor.name
}

output "api_gateway_task_definition_arn" {
  description = "ARN of the API Gateway task definition"
  value       = aws_ecs_task_definition.api_gateway.arn
}

output "event_ingest_task_definition_arn" {
  description = "ARN of the Event Ingest task definition"
  value       = aws_ecs_task_definition.event_ingest.arn
}

output "event_processor_task_definition_arn" {
  description = "ARN of the Event Processor task definition"
  value       = aws_ecs_task_definition.event_processor.arn
}
