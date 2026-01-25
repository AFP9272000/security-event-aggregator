output "namespace_id" {
  description = "ID of the service discovery namespace"
  value       = aws_service_discovery_private_dns_namespace.main.id
}

output "namespace_arn" {
  description = "ARN of the service discovery namespace"
  value       = aws_service_discovery_private_dns_namespace.main.arn
}

output "namespace_name" {
  description = "Name of the service discovery namespace"
  value       = aws_service_discovery_private_dns_namespace.main.name
}

output "api_gateway_service_arn" {
  description = "ARN of the API Gateway service discovery service"
  value       = aws_service_discovery_service.api_gateway.arn
}

output "event_ingest_service_arn" {
  description = "ARN of the Event Ingest service discovery service"
  value       = aws_service_discovery_service.event_ingest.arn
}

output "event_processor_service_arn" {
  description = "ARN of the Event Processor service discovery service"
  value       = aws_service_discovery_service.event_processor.arn
}

output "api_gateway_dns" {
  description = "DNS name for API Gateway service"
  value       = "api-gateway.${aws_service_discovery_private_dns_namespace.main.name}"
}

output "event_ingest_dns" {
  description = "DNS name for Event Ingest service"
  value       = "event-ingest.${aws_service_discovery_private_dns_namespace.main.name}"
}

output "event_processor_dns" {
  description = "DNS name for Event Processor service"
  value       = "event-processor.${aws_service_discovery_private_dns_namespace.main.name}"
}
