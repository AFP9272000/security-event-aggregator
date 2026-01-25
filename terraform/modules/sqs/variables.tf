variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "message_retention_seconds" {
  description = "Message retention period in seconds"
  type        = number
  default     = 345600 # 4 days
}

variable "receive_wait_time_seconds" {
  description = "Long polling wait time"
  type        = number
  default     = 10
}

variable "visibility_timeout_seconds" {
  description = "Visibility timeout for messages"
  type        = number
  default     = 60
}

variable "enable_dlq" {
  description = "Enable dead letter queue"
  type        = bool
  default     = true
}

variable "max_receive_count" {
  description = "Max receives before message goes to DLQ"
  type        = number
  default     = 3
}

variable "sns_kms_key_id" {
  description = "KMS key ID for SNS encryption (use 'alias/aws/sns' for AWS managed key)"
  type        = string
  default     = "alias/aws/sns"
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
