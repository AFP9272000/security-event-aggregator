"""
Alerting Module

Sends alerts for high-severity security events via SNS.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

import boto3

from models import EventSeverity


# Configuration
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ALERT_THRESHOLD_SEVERITY = os.environ.get("ALERT_THRESHOLD_SEVERITY", "high")
ALERT_THRESHOLD_RISK_SCORE = int(os.environ.get("ALERT_THRESHOLD_RISK_SCORE", "70"))
LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT")


def get_sns_client():
    """Get SNS client"""
    if LOCALSTACK_ENDPOINT:
        return boto3.client(
            "sns",
            endpoint_url=LOCALSTACK_ENDPOINT,
            region_name=AWS_REGION,
            aws_access_key_id="test",
            aws_secret_access_key="test"
        )
    return boto3.client("sns", region_name=AWS_REGION)


def should_alert(event: Dict[str, Any], risk_score: int) -> bool:
    """
    Determine if an event should trigger an alert.
    
    Alerts are sent for:
    - Critical severity events
    - High severity events
    - Events with risk score above threshold
    - Events that are part of correlations
    """
    severity = event.get("severity", "info")
    
    # Always alert on critical
    if severity == "critical":
        return True
    
    # Alert on high if configured
    if severity == "high" and ALERT_THRESHOLD_SEVERITY in ["high", "medium", "low", "info"]:
        return True
    
    # Alert based on risk score
    if risk_score >= ALERT_THRESHOLD_RISK_SCORE:
        return True
    
    return False


def format_event_alert(event: Dict[str, Any], risk_score: int, correlations: List[Dict[str, Any]] = None) -> str:
    """Format an event into an alert message"""
    
    lines = [
        "=" * 60,
        "SECURITY ALERT",
        "=" * 60,
        "",
        f"Title: {event.get('title', 'Unknown Event')}",
        f"Severity: {event.get('severity', 'unknown').upper()}",
        f"Risk Score: {risk_score}/100",
        "",
        f"Event ID: {event.get('event_id', 'N/A')}",
        f"Source: {event.get('source', 'unknown')}",
        f"Event Type: {event.get('event_type', 'unknown')}",
        f"Category: {event.get('event_category', 'unknown')}",
        f"Time: {event.get('event_time', 'unknown')}",
        "",
    ]
    
    # Add AWS context if available
    aws_context = event.get("aws_context", {})
    if aws_context:
        lines.append("AWS Context:")
        if aws_context.get("account_id"):
            lines.append(f"  Account: {aws_context['account_id']}")
        if aws_context.get("region"):
            lines.append(f"  Region: {aws_context['region']}")
        if aws_context.get("service"):
            lines.append(f"  Service: {aws_context['service']}")
        if aws_context.get("resource_arn"):
            lines.append(f"  Resource: {aws_context['resource_arn']}")
        lines.append("")
    
    # Add actor info if available
    actor = event.get("actor", {})
    if actor:
        lines.append("Actor:")
        if actor.get("user_name"):
            lines.append(f"  User: {actor['user_name']}")
        if actor.get("arn"):
            lines.append(f"  ARN: {actor['arn']}")
        if actor.get("principal_type"):
            lines.append(f"  Type: {actor['principal_type']}")
        lines.append("")
    
    # Add network info if available
    network = event.get("network", {})
    if network:
        lines.append("Network:")
        if network.get("source_ip"):
            lines.append(f"  Source IP: {network['source_ip']}")
        if network.get("user_agent"):
            lines.append(f"  User Agent: {network['user_agent'][:100]}")
        lines.append("")
    
    # Add MITRE ATT&CK info if available
    mitre = event.get("mitre_attack", {})
    if mitre:
        lines.append("MITRE ATT&CK:")
        if mitre.get("tactic"):
            lines.append(f"  Tactic: {mitre['tactic']}")
        if mitre.get("technique_id"):
            lines.append(f"  Technique: {mitre['technique_id']} - {mitre.get('technique_name', '')}")
        lines.append("")
    
    # Add correlation info if available
    if correlations:
        lines.append("Correlated Patterns:")
        for corr in correlations:
            if event.get("event_id") in corr.get("event_ids", []):
                lines.append(f"  - {corr.get('rule', 'unknown')}: {corr.get('description', '')}")
        lines.append("")
    
    # Description
    if event.get("description"):
        lines.append("Description:")
        lines.append(f"  {event['description']}")
        lines.append("")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)


def format_correlation_alert(correlation: Dict[str, Any]) -> str:
    """Format a correlation pattern into an alert message"""
    
    lines = [
        "=" * 60,
        "SECURITY CORRELATION ALERT",
        "=" * 60,
        "",
        f"Pattern: {correlation.get('rule', 'unknown')}",
        f"Description: {correlation.get('description', 'N/A')}",
        f"Severity: {correlation.get('severity', 'unknown').upper()}",
        "",
        f"Correlation ID: {correlation.get('correlation_id', 'N/A')}",
        f"Event Count: {correlation.get('event_count', 0)}",
        "",
    ]
    
    # Add pattern-specific details
    if correlation.get("source_ip"):
        lines.append(f"Source IP: {correlation['source_ip']}")
    
    if correlation.get("actor"):
        lines.append(f"Actor: {correlation['actor']}")
    
    if correlation.get("sequence"):
        lines.append(f"Event Sequence: {' -> '.join(correlation['sequence'])}")
    
    if correlation.get("event_types"):
        lines.append(f"Event Types: {', '.join(correlation['event_types'][:5])}")
    
    lines.append("")
    lines.append(f"Related Event IDs: {', '.join(correlation.get('event_ids', [])[:5])}")
    if len(correlation.get("event_ids", [])) > 5:
        lines.append(f"  ... and {len(correlation['event_ids']) - 5} more")
    
    lines.append("")
    lines.append("=" * 60)
    
    return "\n".join(lines)


async def send_event_alert(
    event: Dict[str, Any],
    risk_score: int,
    correlations: List[Dict[str, Any]] = None
) -> bool:
    """
    Send an alert for a security event via SNS.
    
    Args:
        event: The security event
        risk_score: Calculated risk score
        correlations: Related correlation patterns
        
    Returns:
        True if alert was sent successfully
    """
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not configured, skipping alert")
        return False
    
    try:
        sns = get_sns_client()
        
        message = format_event_alert(event, risk_score, correlations)
        subject = f"[{event.get('severity', 'INFO').upper()}] {event.get('title', 'Security Event')[:80]}"
        
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes={
                "severity": {
                    "DataType": "String",
                    "StringValue": event.get("severity", "info")
                },
                "event_type": {
                    "DataType": "String",
                    "StringValue": event.get("event_type", "unknown")
                },
                "risk_score": {
                    "DataType": "Number",
                    "StringValue": str(risk_score)
                }
            }
        )
        
        print(f"Sent alert for event {event.get('event_id')}, MessageId: {response['MessageId']}")
        return True
        
    except Exception as e:
        print(f"Error sending alert: {e}")
        return False


async def send_correlation_alert(correlation: Dict[str, Any]) -> bool:
    """
    Send an alert for a correlation pattern via SNS.
    
    Args:
        correlation: The correlation result
        
    Returns:
        True if alert was sent successfully
    """
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not configured, skipping alert")
        return False
    
    try:
        sns = get_sns_client()
        
        message = format_correlation_alert(correlation)
        subject = f"[CORRELATION] {correlation.get('rule', 'Pattern')}: {correlation.get('description', '')[:60]}"
        
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
            MessageAttributes={
                "alert_type": {
                    "DataType": "String",
                    "StringValue": "correlation"
                },
                "rule": {
                    "DataType": "String",
                    "StringValue": correlation.get("rule", "unknown")
                },
                "severity": {
                    "DataType": "String",
                    "StringValue": correlation.get("severity", "high")
                }
            }
        )
        
        print(f"Sent correlation alert {correlation.get('correlation_id')}, MessageId: {response['MessageId']}")
        return True
        
    except Exception as e:
        print(f"Error sending correlation alert: {e}")
        return False
