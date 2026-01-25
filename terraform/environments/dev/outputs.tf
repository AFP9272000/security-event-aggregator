#------------------------------------------------------------------------------
# Security Event Aggregator - Dev Environment Outputs
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# VPC
#------------------------------------------------------------------------------
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnet_ids
}

#------------------------------------------------------------------------------
# ECR
#------------------------------------------------------------------------------
output "ecr_repository_urls" {
  description = "ECR repository URLs"
  value       = module.ecr.repository_urls
}

#------------------------------------------------------------------------------
# Load Balancer
#------------------------------------------------------------------------------
output "alb_dns_name" {
  description = "ALB DNS name - use this to access the API"
  value       = module.alb.alb_dns_name
}

output "api_url" {
  description = "API Gateway URL"
  value       = "http://${module.alb.alb_dns_name}"
}

#------------------------------------------------------------------------------
# ECS
#------------------------------------------------------------------------------
output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = module.ecs.cluster_name
}

output "ecs_services" {
  description = "ECS service names"
  value = {
    api_gateway     = module.ecs.api_gateway_service_name
    event_ingest    = module.ecs.event_ingest_service_name
    event_processor = module.ecs.event_processor_service_name
  }
}

#------------------------------------------------------------------------------
# Data Layer
#------------------------------------------------------------------------------
output "dynamodb_table_name" {
  description = "DynamoDB table name"
  value       = module.dynamodb.table_name
}

output "sqs_queue_url" {
  description = "SQS queue URL"
  value       = module.sqs.queue_url
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = module.sqs.sns_topic_arn
}

#------------------------------------------------------------------------------
# Service Discovery
#------------------------------------------------------------------------------
output "service_discovery_namespace" {
  description = "Service discovery namespace"
  value       = module.cloudmap.namespace_name
}

#------------------------------------------------------------------------------
# Monitoring
#------------------------------------------------------------------------------
output "cloudwatch_dashboard_url" {
  description = "URL to CloudWatch dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${module.monitoring.dashboard_name}"
}

#------------------------------------------------------------------------------
# CI/CD
#------------------------------------------------------------------------------
output "github_actions_role_arn" {
  description = "GitHub Actions IAM role ARN"
  value       = module.iam.github_actions_role_arn
}

#------------------------------------------------------------------------------
# Deployment Commands
#------------------------------------------------------------------------------
output "deployment_commands" {
  description = "Commands to deploy container images"
  value       = <<-EOT
    
    # Login to ECR
    aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${split("/", module.ecr.repository_urls["api-gateway"])[0]}
    
    # Build and push API Gateway
    docker build -t ${module.ecr.repository_urls["api-gateway"]}:latest ./services/api-gateway
    docker push ${module.ecr.repository_urls["api-gateway"]}:latest
    
    # Build and push Event Ingest
    docker build -t ${module.ecr.repository_urls["event-ingest"]}:latest ./services/event-ingest
    docker push ${module.ecr.repository_urls["event-ingest"]}:latest
    
    # Build and push Event Processor
    docker build -t ${module.ecr.repository_urls["event-processor"]}:latest ./services/event-processor
    docker push ${module.ecr.repository_urls["event-processor"]}:latest
    
    # Force new deployment
    aws ecs update-service --cluster ${module.ecs.cluster_name} --service ${module.ecs.api_gateway_service_name} --force-new-deployment
    aws ecs update-service --cluster ${module.ecs.cluster_name} --service ${module.ecs.event_ingest_service_name} --force-new-deployment
    aws ecs update-service --cluster ${module.ecs.cluster_name} --service ${module.ecs.event_processor_service_name} --force-new-deployment
    
  EOT
}
