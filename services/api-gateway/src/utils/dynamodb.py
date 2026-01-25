"""
DynamoDB Utility Functions

Handles all interactions with the DynamoDB events table.
"""

import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from decimal import Decimal
import json

from models import SecurityEvent, EventSearchRequest, EventStats, EventSeverity, EventSource


# Get configuration from environment
TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "security-events")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT")


def get_dynamodb_resource():
    """Get DynamoDB resource, using LocalStack endpoint if configured"""
    if LOCALSTACK_ENDPOINT:
        return boto3.resource(
            "dynamodb",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test"
        )
    return boto3.resource("dynamodb", region_name=AWS_REGION)


def get_table():
    """Get the DynamoDB table"""
    dynamodb = get_dynamodb_resource()
    return dynamodb.Table(TABLE_NAME)


def decimal_default(obj):
    """JSON serializer for Decimal types"""
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def convert_floats_to_decimal(obj: Any) -> Any:
    """Recursively convert floats to Decimal for DynamoDB"""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(i) for i in obj]
    return obj


def convert_decimal_to_float(obj: Any) -> Any:
    """Recursively convert Decimal to float for JSON serialization"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_decimal_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimal_to_float(i) for i in obj]
    return obj


async def get_event_by_id(event_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single event by ID"""
    table = get_table()
    
    try:
        response = table.get_item(Key={"event_id": event_id})
        item = response.get("Item")
        if item:
            return convert_decimal_to_float(item)
        return None
    except Exception as e:
        print(f"Error getting event {event_id}: {e}")
        raise


async def query_events(search: EventSearchRequest) -> List[Dict[str, Any]]:
    """
    Query events based on search criteria.
    
    Note: In production, you'd use a GSI for time-based queries.
    For this demo, we scan with filters (not ideal for large datasets).
    """
    table = get_table()
    
    # Build filter expression
    filter_expressions = []
    expression_values = {}
    expression_names = {}
    
    if search.start_time:
        filter_expressions.append("#et >= :start_time")
        expression_values[":start_time"] = search.start_time.isoformat()
        expression_names["#et"] = "event_time"
    
    if search.end_time:
        if "#et" not in expression_names:
            expression_names["#et"] = "event_time"
        filter_expressions.append("#et <= :end_time")
        expression_values[":end_time"] = search.end_time.isoformat()
    
    if search.sources:
        filter_expressions.append("#src IN ({})".format(
            ", ".join([f":src{i}" for i in range(len(search.sources))])
        ))
        for i, src in enumerate(search.sources):
            expression_values[f":src{i}"] = src.value
        expression_names["#src"] = "source"
    
    if search.severities:
        filter_expressions.append("#sev IN ({})".format(
            ", ".join([f":sev{i}" for i in range(len(search.severities))])
        ))
        for i, sev in enumerate(search.severities):
            expression_values[f":sev{i}"] = sev.value
        expression_names["#sev"] = "severity"
    
    if search.event_types:
        filter_expressions.append("#evtype IN ({})".format(
            ", ".join([f":evtype{i}" for i in range(len(search.event_types))])
        ))
        for i, et in enumerate(search.event_types):
            expression_values[f":evtype{i}"] = et
        expression_names["#evtype"] = "event_type"
    
    # Build scan parameters
    scan_params = {"Limit": search.limit}
    
    if filter_expressions:
        scan_params["FilterExpression"] = " AND ".join(filter_expressions)
        scan_params["ExpressionAttributeValues"] = expression_values
        scan_params["ExpressionAttributeNames"] = expression_names
    
    try:
        response = table.scan(**scan_params)
        items = response.get("Items", [])
        return [convert_decimal_to_float(item) for item in items]
    except Exception as e:
        print(f"Error querying events: {e}")
        raise


async def get_event_stats() -> EventStats:
    """Get aggregated statistics about events"""
    table = get_table()
    
    stats = EventStats()
    now = datetime.utcnow()
    last_24h = (now - timedelta(hours=24)).isoformat()
    
    try:
        # Scan all events (in production, use pre-aggregated data or streams)
        response = table.scan()
        items = response.get("Items", [])
        
        stats.total_events = len(items)
        
        severity_counts = {}
        source_counts = {}
        category_counts = {}
        event_type_counts = {}
        source_ip_counts = {}
        events_24h = 0
        critical_24h = 0
        
        for item in items:
            # Count by severity
            sev = item.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Count by source
            src = item.get("source", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1
            
            # Count by category
            cat = item.get("event_category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            
            # Count event types
            et = item.get("event_type", "unknown")
            event_type_counts[et] = event_type_counts.get(et, 0) + 1
            
            # Count source IPs
            network = item.get("network", {})
            if network and network.get("source_ip"):
                ip = network["source_ip"]
                source_ip_counts[ip] = source_ip_counts.get(ip, 0) + 1
            
            # Count last 24h
            event_time = item.get("event_time", "")
            if event_time >= last_24h:
                events_24h += 1
                if sev == "critical":
                    critical_24h += 1
        
        stats.events_by_severity = severity_counts
        stats.events_by_source = source_counts
        stats.events_by_category = category_counts
        stats.events_last_24h = events_24h
        stats.critical_events_last_24h = critical_24h
        
        # Top event types
        stats.top_event_types = [
            {"event_type": k, "count": v}
            for k, v in sorted(event_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Top source IPs
        stats.top_source_ips = [
            {"source_ip": k, "count": v}
            for k, v in sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        return stats
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        raise


async def check_dynamodb_health() -> bool:
    """Check if DynamoDB is accessible"""
    try:
        table = get_table()
        table.table_status
        return True
    except Exception as e:
        print(f"DynamoDB health check failed: {e}")
        return False
