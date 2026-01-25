"""
GuardDuty Finding Normalizer

Converts AWS GuardDuty findings to the normalized security event schema.
Includes MITRE ATT&CK mapping for GuardDuty finding types.
"""

from datetime import datetime
from typing import Dict, Any, Optional

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


# GuardDuty severity mapping (GuardDuty uses 0-10 scale)
def map_guardduty_severity(severity: float) -> EventSeverity:
    """Map GuardDuty numeric severity to our severity levels"""
    if severity >= 8.0:
        return EventSeverity.CRITICAL
    elif severity >= 6.0:
        return EventSeverity.HIGH
    elif severity >= 4.0:
        return EventSeverity.MEDIUM
    elif severity >= 2.0:
        return EventSeverity.LOW
    else:
        return EventSeverity.INFO


# MITRE ATT&CK mappings for GuardDuty finding types
MITRE_MAPPINGS = {
    # Reconnaissance
    "Recon:EC2/PortProbeUnprotectedPort": MitreAttackInfo(
        tactic="Reconnaissance",
        technique_id="T1595.001",
        technique_name="Active Scanning: Scanning IP Blocks"
    ),
    "Recon:EC2/Portscan": MitreAttackInfo(
        tactic="Reconnaissance",
        technique_id="T1595.001",
        technique_name="Active Scanning: Scanning IP Blocks"
    ),
    # Initial Access
    "UnauthorizedAccess:EC2/SSHBruteForce": MitreAttackInfo(
        tactic="Initial Access",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing"
    ),
    "UnauthorizedAccess:EC2/RDPBruteForce": MitreAttackInfo(
        tactic="Initial Access",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing"
    ),
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": MitreAttackInfo(
        tactic="Initial Access",
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts"
    ),
    # Execution
    "Execution:EC2/SuspiciousFile": MitreAttackInfo(
        tactic="Execution",
        technique_id="T1204",
        technique_name="User Execution"
    ),
    # Persistence
    "Persistence:IAMUser/UserPermissions": MitreAttackInfo(
        tactic="Persistence",
        technique_id="T1098",
        technique_name="Account Manipulation"
    ),
    # Privilege Escalation
    "PrivilegeEscalation:IAMUser/AdministrativePermissions": MitreAttackInfo(
        tactic="Privilege Escalation",
        technique_id="T1098",
        technique_name="Account Manipulation"
    ),
    # Defense Evasion
    "Stealth:IAMUser/CloudTrailLoggingDisabled": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs"
    ),
    "DefenseEvasion:EC2/UnusualDNSResolver": MitreAttackInfo(
        tactic="Defense Evasion",
        technique_id="T1568",
        technique_name="Dynamic Resolution"
    ),
    # Credential Access
    "CredentialAccess:IAMUser/AnomalousBehavior": MitreAttackInfo(
        tactic="Credential Access",
        technique_id="T1528",
        technique_name="Steal Application Access Token"
    ),
    # Discovery
    "Discovery:IAMUser/AnomalousBehavior": MitreAttackInfo(
        tactic="Discovery",
        technique_id="T1087.004",
        technique_name="Account Discovery: Cloud Account"
    ),
    # Exfiltration
    "Exfiltration:S3/ObjectRead.Unusual": MitreAttackInfo(
        tactic="Exfiltration",
        technique_id="T1530",
        technique_name="Data from Cloud Storage"
    ),
    "Exfiltration:S3/MaliciousIPCaller": MitreAttackInfo(
        tactic="Exfiltration",
        technique_id="T1530",
        technique_name="Data from Cloud Storage"
    ),
    # Impact
    "Impact:EC2/WinRMBruteForce": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1110",
        technique_name="Brute Force"
    ),
    "Impact:S3/MaliciousIPCaller": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1485",
        technique_name="Data Destruction"
    ),
    # Crypto Mining
    "CryptoCurrency:EC2/BitcoinTool.B": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1496",
        technique_name="Resource Hijacking"
    ),
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1496",
        technique_name="Resource Hijacking"
    ),
    # Trojan
    "Trojan:EC2/BlackholeTraffic": MitreAttackInfo(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol"
    ),
    "Trojan:EC2/DropPoint": MitreAttackInfo(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol"
    ),
    # Backdoor
    "Backdoor:EC2/DenialOfService.Tcp": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1498",
        technique_name="Network Denial of Service"
    ),
    "Backdoor:EC2/DenialOfService.Udp": MitreAttackInfo(
        tactic="Impact",
        technique_id="T1498",
        technique_name="Network Denial of Service"
    ),
}


def categorize_guardduty_finding(finding_type: str) -> str:
    """Categorize GuardDuty finding by type prefix"""
    prefix = finding_type.split(":")[0] if ":" in finding_type else finding_type
    
    category_mapping = {
        "Recon": "reconnaissance",
        "UnauthorizedAccess": "unauthorized_access",
        "Execution": "execution",
        "Persistence": "persistence",
        "PrivilegeEscalation": "privilege_escalation",
        "DefenseEvasion": "defense_evasion",
        "Stealth": "defense_evasion",
        "CredentialAccess": "credential_access",
        "Discovery": "discovery",
        "Exfiltration": "exfiltration",
        "Impact": "impact",
        "CryptoCurrency": "cryptomining",
        "Trojan": "malware",
        "Backdoor": "malware",
        "Behavior": "anomaly",
        "PenTest": "pentest",
        "Policy": "policy_violation",
    }
    
    return category_mapping.get(prefix, "other")


def normalize_guardduty_finding(raw_finding: Dict[str, Any]) -> SecurityEvent:
    """
    Convert a GuardDuty finding to normalized SecurityEvent format.
    
    Args:
        raw_finding: Raw GuardDuty finding
        
    Returns:
        Normalized SecurityEvent
    """
    # Extract basic fields
    finding_type = raw_finding.get("Type", "Unknown")
    finding_id = raw_finding.get("Id", "")
    account_id = raw_finding.get("AccountId", "")
    region = raw_finding.get("Region", "")
    
    # Parse timestamps
    created_at = raw_finding.get("CreatedAt", "")
    updated_at = raw_finding.get("UpdatedAt", "")
    
    try:
        event_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except:
        event_time = datetime.utcnow()
    
    # Map severity
    gd_severity = raw_finding.get("Severity", 0)
    severity = map_guardduty_severity(gd_severity)
    
    # Extract resource information
    resource = raw_finding.get("Resource", {})
    resource_type = resource.get("ResourceType", "")
    
    # Build AWS context
    aws_context = AWSContext(
        account_id=account_id,
        region=region,
        resource_type=resource_type,
    )
    
    # Extract instance details if available
    instance_details = resource.get("InstanceDetails", {})
    if instance_details:
        aws_context.resource_arn = instance_details.get("InstanceId")
    
    # Extract S3 bucket details if available
    s3_bucket = resource.get("S3BucketDetails", [])
    if s3_bucket:
        aws_context.resource_arn = s3_bucket[0].get("Arn")
    
    # Extract access key details if available
    access_key_details = resource.get("AccessKeyDetails", {})
    
    # Build actor info
    actor = None
    if access_key_details:
        actor = ActorInfo(
            principal_id=access_key_details.get("PrincipalId"),
            principal_type=access_key_details.get("UserType"),
            access_key_id=access_key_details.get("AccessKeyId"),
            user_name=access_key_details.get("UserName"),
        )
    
    # Extract network info from service details
    service = raw_finding.get("Service", {})
    action = service.get("Action", {})
    
    network = None
    
    # Network connection action
    network_info = action.get("NetworkConnectionAction", {})
    if network_info:
        remote_ip = network_info.get("RemoteIpDetails", {})
        local_port = network_info.get("LocalPortDetails", {})
        remote_port = network_info.get("RemotePortDetails", {})
        
        network = NetworkInfo(
            source_ip=remote_ip.get("IpAddressV4"),
            source_port=remote_port.get("Port"),
            destination_port=local_port.get("Port"),
            protocol=network_info.get("Protocol"),
        )
    
    # AWS API call action
    api_call = action.get("AwsApiCallAction", {})
    if api_call:
        remote_ip = api_call.get("RemoteIpDetails", {})
        if not network:
            network = NetworkInfo()
        network.source_ip = remote_ip.get("IpAddressV4")
        network.user_agent = api_call.get("UserAgent")
    
    # Get MITRE mapping
    mitre_attack = MITRE_MAPPINGS.get(finding_type)
    
    # If no exact match, try prefix match
    if not mitre_attack:
        for key, value in MITRE_MAPPINGS.items():
            if finding_type.startswith(key.split(":")[0] + ":"):
                mitre_attack = value
                break
    
    # Build title and description
    title = raw_finding.get("Title", f"GuardDuty: {finding_type}")
    description = raw_finding.get("Description", "")
    
    # Categorize finding
    category = categorize_guardduty_finding(finding_type)
    
    # Build tags
    tags = ["guardduty", category]
    if severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]:
        tags.append("high-priority")
    if mitre_attack:
        tags.append(f"mitre-{mitre_attack.technique_id}")
    if resource_type:
        tags.append(resource_type.lower())
    
    return SecurityEvent(
        source=EventSource.GUARDDUTY,
        source_event_id=finding_id,
        event_time=event_time,
        event_type=finding_type,
        event_category=category,
        severity=severity,
        status=EventStatus.NEW,
        title=title,
        description=description,
        aws_context=aws_context,
        actor=actor,
        network=network,
        mitre_attack=mitre_attack,
        raw_event=raw_finding,
        tags=tags,
        metadata={
            "guardduty_severity": gd_severity,
            "updated_at": updated_at,
            "count": service.get("Count", 1),
        }
    )
