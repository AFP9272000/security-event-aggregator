variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "service_names" {
  description = "List of service names to create repositories for"
  type        = list(string)
  default     = ["api-gateway", "event-ingest", "event-processor"]
}

variable "image_tag_mutability" {
  description = "Image tag mutability setting"
  type        = string
  default     = "MUTABLE"
}

variable "scan_on_push" {
  description = "Enable image scanning on push"
  type        = bool
  default     = true
}

variable "image_retention_count" {
  description = "Number of tagged images to retain"
  type        = number
  default     = 10
}

variable "untagged_image_retention_days" {
  description = "Days to retain untagged images"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
