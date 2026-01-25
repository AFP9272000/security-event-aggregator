variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table"
  type        = string
}

variable "sqs_queue_arn" {
  description = "ARN of the SQS queue"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic"
  type        = string
}

variable "ecr_repository_arns" {
  description = "List of ECR repository ARNs"
  type        = list(string)
  default     = []
}

variable "secrets_manager_arns" {
  description = "List of Secrets Manager secret ARNs to allow access to"
  type        = list(string)
  default     = null
}

variable "enable_github_oidc" {
  description = "Enable GitHub Actions OIDC provider and role"
  type        = bool
  default     = true
}

variable "github_repo" {
  description = "GitHub repository in format owner/repo"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
