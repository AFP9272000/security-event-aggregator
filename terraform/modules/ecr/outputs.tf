output "repository_urls" {
  description = "Map of service names to repository URLs"
  value       = { for k, v in aws_ecr_repository.services : k => v.repository_url }
}

output "repository_arns" {
  description = "Map of service names to repository ARNs"
  value       = { for k, v in aws_ecr_repository.services : k => v.arn }
}

output "repository_names" {
  description = "Map of service names to repository names"
  value       = { for k, v in aws_ecr_repository.services : k => v.name }
}
