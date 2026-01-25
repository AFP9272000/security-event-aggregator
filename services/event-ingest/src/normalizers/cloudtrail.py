"""
CloudTrail Event Normalizer

Converts AWS CloudTrail events to the normalized security event schema.
Includes MITRE ATT&CK mapping for common CloudTrail event types.
"""

from datetime import datetime
from typing import Dict, Any, Optional
import re

from models import (
    SecurityEvent,
    EventSeverity,
    EventSource,
    EventStatus,
    MitreAttackInfo,
    AWSContext,
    ActorInfo,
    NetworkInfo,
)


# MITRE ATT&CK mappings for common CloudTrail events
MITRE_MAPPINGS = {
    # Initial Access
    "ConsoleLogin": MitreAttackInfo(
        tactic="Initial Access",
        technique_id="T1078",
        technique_name="Valid Accounts"
    ),
    # Persistence
    "CreateUser": MitreAttackInfo(
        tactic="Persistence",
        technique_id="T1136.003",
        technique_name="Create Account: Cloud Account"
    ),
    "CreateAccessKey": MitreAttackInfo(
        tactic="Persistence",
        technique_id="T1098.001",
        technique_name="Account Manipulation: Additional Cloud Credentials"
    ),
    "CreateRole": MitreAttackInfo(
        tactic="Persistence",
        technique_id="T1098",
        technique_name="Account Manipulation"
    ),
    "AttachUserPolicy": MitreAttackInfo(
        tactic="Persistence",
        technique_id="T1098",
        technique_name="Account Manipulation"
    ),
    "AttachRolePolicy": MitreAttackInfo(
        tactic="Persistence",
        technique_id="T1098",
        technique_name="Account Manipulation"
    ),
    # Privilege Escalation
    "AssumeRole": MitreAttackInfo(
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism"
    ),
    "UpdateAssumeRolePolicy": MitreAttackInfo(
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism"
    ),
    # Defense Evasion
    "StopLogging": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs"
    ),
    "DeleteTrail": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs"
    ),
    "UpdateTrail": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs"
    ),
    "PutEventSelectors": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs"
    ),
    "DeleteFlowLogs": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs"
    ),
    # Credential Access
    "GetSecretValue": MitreAttackInfo(
        tactic="Credential Access",
        technique_id="T1555",
        technique_name="Credentials from Password Stores"
    ),
    "GetPasswordData": MitreAttackInfo(
        tactic="Credential Access",
        technique_id="T1555",
        technique_name="Credentials from Password Stores"
    ),
    # Discovery
    "DescribeInstances": MitreAttackInfo(
        tactic="Discovery",
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery"
    ),
    "ListBuckets": MitreAttackInfo(
        tactic="Discovery",
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery"
    ),
    "ListUsers": MitreAttackInfo(
        tactic="Discovery",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account"
    ),
    "ListRoles": MitreAttackInfo(
        tactic="Discovery",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account"
    ),
    # Exfiltration
    "GetObject": MitreAttackInfo(
        tactic="Exfiltration",
        technique_id="T1530",
        technique_name="Data from Cloud Storage"
    ),
    # Impact
    "DeleteBucket": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1485",
        technique_name="Data Destruction"
    ),
    "TerminateInstances": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1489",
        technique_name="Service Stop"
    ),
}


# Severity classification for CloudTrail events
HIGH_SEVERITY_EVENTS = {
    "ConsoleLogin",  # With failed attempts
    "CreateUser",
    "CreateAccessKey",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "PutBucketAcl",
    "AuthorizeSecurityGroupIngress",
    "CreateSecurityGroup",
    "ModifyInstanceAttribute",
    "RunInstances",  # Depending on context
}

CRITICAL_SEVERITY_PATTERNS = [
    r".*Delete.*Trail.*",
    r".*Stop.*Logging.*",
    r".*Disable.*",
    r".*Root.*",
]


def determine_severity(event_name: str, error_code: Optional[str], user_type: Optional[str]) -> EventSeverity:
    """Determine event severity based on event type and context"""
    
    # Critical: Root account usage or logging tampering
    if user_type == "Root":
        return EventSeverity.CRITICAL
    
    for pattern in CRITICAL_SEVERITY_PATTERNS:
        if re.match(pattern, event_name, re.IGNORECASE):
            return EventSeverity.CRITICAL
    
    # High: Failed authentication or high-risk events
    if error_code in ["AccessDenied", "UnauthorizedAccess", "InvalidClientTokenId"]:
        return EventSeverity.HIGH
    
    if event_name in HIGH_SEVERITY_EVENTS:
        return EventSeverity.HIGH
    
    # Medium: Potential reconnaissance or privilege escalation
    if event_name.startswith("List") or event_name.startswith("Describe"):
        return EventSeverity.LOW
    
    if event_name.startswith("Get"):
        return EventSeverity.LOW
    
    # Default
    return EventSeverity.INFO


def categorize_event(event_name: str, event_source: str) -> str:
    """Categorize the event type"""
    
    # Authentication events
    if event_name in ["ConsoleLogin", "GetFederationToken", "GetSessionToken", "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"]:
        return "authentication"
    
    # IAM events
    if event_source == "iam.amazonaws.com" or event_name.startswith(("Create", "Delete", "Update", "Attach", "Detach", "Put")) and "User" in event_name or "Role" in event_name or "Policy" in event_name:
        return "identity_management"
    
    # Network events
    if event_source in ["ec2.amazonaws.com"] and any(x in event_name for x in ["SecurityGroup", "Vpc", "Subnet", "Route", "NetworkAcl"]):
        return "network_security"
    
    # Data access events
    if event_source == "s3.amazonaws.com" or event_name in ["GetObject", "PutObject", "DeleteObject"]:
        return "data_access"
    
    # Logging events
    if event_source in ["cloudtrail.amazonaws.com", "logs.amazonaws.com"]:
        return "logging"
    
    # Resource modification
    if event_name.startswith(("Create", "Delete", "Modify", "Update", "Terminate")):
        return "resource_modification"
    
    # Discovery/Reconnaissance
    if event_name.startswith(("List", "Describe", "Get")):
        return "discovery"
    
    return "other"


def normalize_cloudtrail_event(raw_event: Dict[str, Any]) -> SecurityEvent:
    """
    Convert a CloudTrail event to normalized SecurityEvent format.
    
    Args:
        raw_event: Raw CloudTrail event from S3/CloudWatch
        
    Returns:
        Normalized SecurityEvent
    """
    # Extract basic fields
    event_name = raw_event.get("eventName", "Unknown")
    event_source = raw_event.get("eventSource", "unknown")
    event_time_str = raw_event.get("eventTime", datetime.utcnow().isoformat())
    
    # Parse event time
    try:
        event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
    except:
        event_time = datetime.utcnow()
    
    # Extract user identity
    user_identity = raw_event.get("userIdentity", {})
    user_type = user_identity.get("type")
    
    # Build actor info
    actor = ActorInfo(
        principal_id=user_identity.get("principalId"),
        principal_type=user_type,
        arn=user_identity.get("arn"),
        access_key_id=user_identity.get("accessKeyId"),
        user_name=user_identity.get("userName"),
        session_name=user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName"),
    )
    
    # Build network info
    network = NetworkInfo(
        source_ip=raw_event.get("sourceIPAddress"),
        user_agent=raw_event.get("userAgent"),
    )
    
    # Build AWS context
    aws_context = AWSContext(
        account_id=user_identity.get("accountId"),
        region=raw_event.get("awsRegion"),
        service=event_source.split(".")[0] if event_source else None,
    )
    
    # Extract resource ARN if available
    resources = raw_event.get("resources", [])
    if resources:
        aws_context.resource_arn = resources[0].get("ARN")
        aws_context.resource_type = resources[0].get("type")
    
    # Determine severity
    error_code = raw_event.get("errorCode")
    severity = determine_severity(event_name, error_code, user_type)
    
    # Get MITRE mapping
    mitre_attack = MITRE_MAPPINGS.get(event_name)
    
    # Build title and description
    title = f"CloudTrail: {event_name}"
    if error_code:
        title += f" ({error_code})"
    
    description = f"AWS {event_name} event from {event_source}"
    if actor.user_name:
        description += f" by user {actor.user_name}"
    elif actor.arn:
        description += f" by {actor.arn}"
    if error_code:
        error_message = raw_event.get("errorMessage", "")
        description += f". Error: {error_code} - {error_message}"
    
    # Categorize event
    category = categorize_event(event_name, event_source)
    
    # Build tags
    tags = ["cloudtrail", event_source.split(".")[0] if event_source else "aws"]
    if error_code:
        tags.append("error")
        tags.append(error_code.lower())
    if user_type == "Root":
        tags.append("root-account")
    if mitre_attack:
        tags.append(f"mitre-{mitre_attack.technique_id}")
    
    return SecurityEvent(
        source=EventSource.CLOUDTRAIL,
        source_event_id=raw_event.get("eventID"),
        event_time=event_time,
        event_type=event_name,
        event_category=category,
        severity=severity,
        status=EventStatus.NEW,
        title=title,
        description=description,
        aws_context=aws_context,
        actor=actor,
        network=network,
        mitre_attack=mitre_attack,
        raw_event=raw_event,
        tags=tags,
    )
