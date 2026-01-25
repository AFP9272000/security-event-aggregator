#------------------------------------------------------------------------------
# Cloud Map Module - Security Event Aggregator
# Creates service discovery namespace for inter-service communication
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Private DNS Namespace
#------------------------------------------------------------------------------
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = var.namespace_name
  description = "Service discovery namespace for ${var.project_name}"
  vpc         = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-namespace"
  })
}

#------------------------------------------------------------------------------
# Service Discovery Services
#------------------------------------------------------------------------------
resource "aws_service_discovery_service" "api_gateway" {
  name = "api-gateway"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_service_discovery_service" "event_ingest" {
  name = "event-ingest"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

resource "aws_service_discovery_service" "event_processor" {
  name = "event-processor"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}
