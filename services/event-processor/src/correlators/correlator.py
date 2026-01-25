"""
Event Correlator

Correlates related security events to identify attack patterns
and potential security incidents.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import hashlib

from models import SecurityEvent, EventSeverity


# Correlation rules based on MITRE ATT&CK patterns
CORRELATION_RULES = {
    # Credential stuffing / brute force pattern
    "brute_force": {
        "description": "Multiple failed authentication attempts",
        "event_types": ["ConsoleLogin"],
        "conditions": {
            "min_events": 5,
            "time_window_minutes": 15,
            "error_codes": ["AccessDenied", "UnauthorizedAccess"],
        },
        "severity_boost": EventSeverity.HIGH,
    },
    
    # Privilege escalation pattern
    "privilege_escalation": {
        "description": "IAM modifications following authentication",
        "event_sequence": ["ConsoleLogin", "CreateAccessKey"],
        "time_window_minutes": 60,
        "severity_boost": EventSeverity.CRITICAL,
    },
    
    # Data exfiltration pattern
    "data_exfiltration": {
        "description": "Unusual data access pattern",
        "event_types": ["GetObject"],
        "conditions": {
            "min_events": 50,
            "time_window_minutes": 30,
        },
        "severity_boost": EventSeverity.HIGH,
    },
    
    # Logging tampering pattern
    "logging_tampering": {
        "description": "CloudTrail logging modifications",
        "event_types": ["StopLogging", "DeleteTrail", "UpdateTrail"],
        "severity_boost": EventSeverity.CRITICAL,
    },
    
    # Reconnaissance pattern
    "reconnaissance": {
        "description": "Multiple discovery API calls",
        "event_type_prefixes": ["List", "Describe", "Get"],
        "conditions": {
            "min_events": 20,
            "time_window_minutes": 10,
        },
        "severity_boost": EventSeverity.MEDIUM,
    },
}


def generate_correlation_id(events: List[Dict[str, Any]], rule_name: str) -> str:
    """Generate a unique correlation ID for a group of related events"""
    # Create a hash based on rule name and first event details
    first_event = events[0] if events else {}
    
    hash_input = f"{rule_name}:{first_event.get('event_type', '')}:{first_event.get('source_ip', '')}"
    
    return hashlib.sha256(hash_input.encode()).hexdigest()[:16]


def check_brute_force(events: List[Dict[str, Any]], time_window: int = 15) -> Optional[Dict[str, Any]]:
    """
    Check for brute force pattern.
    
    Looks for multiple failed login attempts from the same IP
    within a time window.
    """
    rule = CORRELATION_RULES["brute_force"]
    
    # Filter to relevant events
    login_events = [
        e for e in events 
        if e.get("event_type") in rule["event_types"]
    ]
    
    if len(login_events) < rule["conditions"]["min_events"]:
        return None
    
    # Group by source IP
    events_by_ip: Dict[str, List[Dict]] = {}
    for event in login_events:
        ip = event.get("network", {}).get("source_ip", "unknown")
        if ip not in events_by_ip:
            events_by_ip[ip] = []
        events_by_ip[ip].append(event)
    
    # Check each IP for brute force pattern
    for ip, ip_events in events_by_ip.items():
        failed_events = [
            e for e in ip_events
            if any(tag in e.get("tags", []) for tag in ["accessdenied", "unauthorizedaccess", "error"])
        ]
        
        if len(failed_events) >= rule["conditions"]["min_events"]:
            return {
                "rule": "brute_force",
                "description": rule["description"],
                "source_ip": ip,
                "event_count": len(failed_events),
                "event_ids": [e.get("event_id") for e in failed_events],
                "severity": rule["severity_boost"].value,
                "correlation_id": generate_correlation_id(failed_events, "brute_force"),
            }
    
    return None


def check_privilege_escalation(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Check for privilege escalation pattern.
    
    Looks for IAM modifications following authentication events.
    """
    rule = CORRELATION_RULES["privilege_escalation"]
    
    # Group events by actor
    events_by_actor: Dict[str, List[Dict]] = {}
    for event in events:
        actor = event.get("actor", {})
        actor_id = actor.get("user_name") or actor.get("arn") or "unknown"
        if actor_id not in events_by_actor:
            events_by_actor[actor_id] = []
        events_by_actor[actor_id].append(event)
    
    # Check each actor for the sequence
    for actor_id, actor_events in events_by_actor.items():
        # Sort by time
        sorted_events = sorted(
            actor_events,
            key=lambda e: e.get("event_time", "")
        )
        
        # Look for login followed by IAM changes
        login_event = None
        iam_events = []
        
        for event in sorted_events:
            event_type = event.get("event_type", "")
            
            if event_type == "ConsoleLogin" and "error" not in event.get("tags", []):
                login_event = event
            elif login_event and event_type in ["CreateAccessKey", "CreateUser", "AttachUserPolicy", "AttachRolePolicy"]:
                iam_events.append(event)
        
        if login_event and iam_events:
            all_events = [login_event] + iam_events
            return {
                "rule": "privilege_escalation",
                "description": rule["description"],
                "actor": actor_id,
                "sequence": [e.get("event_type") for e in all_events],
                "event_count": len(all_events),
                "event_ids": [e.get("event_id") for e in all_events],
                "severity": rule["severity_boost"].value,
                "correlation_id": generate_correlation_id(all_events, "privilege_escalation"),
            }
    
    return None


def check_logging_tampering(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Check for logging tampering pattern.
    
    Any modification to CloudTrail logging is immediately flagged.
    """
    rule = CORRELATION_RULES["logging_tampering"]
    
    tampering_events = [
        e for e in events
        if e.get("event_type") in rule["event_types"]
    ]
    
    if tampering_events:
        return {
            "rule": "logging_tampering",
            "description": rule["description"],
            "event_count": len(tampering_events),
            "event_ids": [e.get("event_id") for e in tampering_events],
            "event_types": list(set(e.get("event_type") for e in tampering_events)),
            "severity": rule["severity_boost"].value,
            "correlation_id": generate_correlation_id(tampering_events, "logging_tampering"),
        }
    
    return None


def check_reconnaissance(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Check for reconnaissance pattern.
    
    Multiple discovery-type API calls in a short window.
    """
    rule = CORRELATION_RULES["reconnaissance"]
    
    # Filter to discovery events
    recon_events = [
        e for e in events
        if any(
            e.get("event_type", "").startswith(prefix)
            for prefix in rule["event_type_prefixes"]
        )
    ]
    
    if len(recon_events) < rule["conditions"]["min_events"]:
        return None
    
    # Group by source IP
    events_by_ip: Dict[str, List[Dict]] = {}
    for event in recon_events:
        ip = event.get("network", {}).get("source_ip", "unknown")
        if ip not in events_by_ip:
            events_by_ip[ip] = []
        events_by_ip[ip].append(event)
    
    # Check each IP
    for ip, ip_events in events_by_ip.items():
        if len(ip_events) >= rule["conditions"]["min_events"]:
            return {
                "rule": "reconnaissance",
                "description": rule["description"],
                "source_ip": ip,
                "event_count": len(ip_events),
                "event_ids": [e.get("event_id") for e in ip_events[:20]],  # Limit IDs
                "event_types": list(set(e.get("event_type") for e in ip_events))[:10],
                "severity": rule["severity_boost"].value,
                "correlation_id": generate_correlation_id(ip_events, "reconnaissance"),
            }
    
    return None


def correlate_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run all correlation rules against a batch of events.
    
    Args:
        events: List of security events to correlate
        
    Returns:
        List of correlation results
    """
    correlations = []
    
    # Run each correlation check
    checks = [
        check_brute_force,
        check_privilege_escalation,
        check_logging_tampering,
        check_reconnaissance,
    ]
    
    for check in checks:
        result = check(events)
        if result:
            correlations.append(result)
    
    return correlations


def calculate_risk_score(event: Dict[str, Any], correlations: List[Dict[str, Any]]) -> int:
    """
    Calculate a risk score (0-100) for an event.
    
    Factors:
    - Base severity (critical=80, high=60, medium=40, low=20, info=10)
    - Correlation membership (+20 for each correlation)
    - MITRE ATT&CK mapping (+10)
    - Root account usage (+30)
    """
    # Base score from severity
    severity_scores = {
        "critical": 80,
        "high": 60,
        "medium": 40,
        "low": 20,
        "info": 10,
    }
    
    score = severity_scores.get(event.get("severity", "info"), 10)
    
    # Check if event is in any correlations
    event_id = event.get("event_id", "")
    for correlation in correlations:
        if event_id in correlation.get("event_ids", []):
            score += 20
    
    # MITRE ATT&CK mapping
    if event.get("mitre_attack"):
        score += 10
    
    # Root account
    if "root-account" in event.get("tags", []):
        score += 30
    
    # Cap at 100
    return min(score, 100)
