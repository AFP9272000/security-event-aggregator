#!/usr/bin/env python3
"""
Test Script for Security Event Aggregator

This script tests the local deployment by:
1. Checking service health
2. Ingesting sample CloudTrail events
3. Ingesting sample GuardDuty findings
4. Querying events via the API
5. Checking statistics
"""

import requests
import json
import time
from datetime import datetime, timedelta


# Service URLs
API_GATEWAY_URL = "http://localhost:8000"
EVENT_INGEST_URL = "http://localhost:8001"
EVENT_PROCESSOR_URL = "http://localhost:8002"


# Sample CloudTrail events
SAMPLE_CLOUDTRAIL_EVENTS = [
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE123",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
            "userName": "alice"
        },
        "eventTime": (datetime.utcnow() - timedelta(minutes=30)).isoformat() + "Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "userAgent": "Mozilla/5.0",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success"},
        "eventID": "event-001-console-login"
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE123",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
            "userName": "alice"
        },
        "eventTime": (datetime.utcnow() - timedelta(minutes=25)).isoformat() + "Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "userAgent": "aws-cli/2.0",
        "requestParameters": {"userName": "alice"},
        "responseElements": {"accessKey": {"accessKeyId": "AKIAEXAMPLE"}},
        "eventID": "event-002-create-access-key"
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAMALICIOUS",
            "arn": "arn:aws:iam::123456789012:user/suspicious",
            "accountId": "123456789012",
            "userName": "suspicious"
        },
        "eventTime": (datetime.utcnow() - timedelta(minutes=20)).isoformat() + "Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.100",
        "userAgent": "aws-cli/2.0",
        "requestParameters": {"name": "main-trail"},
        "responseElements": None,
        "eventID": "event-003-stop-logging"
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "Root",
            "principalId": "123456789012",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012"
        },
        "eventTime": (datetime.utcnow() - timedelta(minutes=15)).isoformat() + "Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.1",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {"userName": "backdoor-admin"},
        "responseElements": {"user": {"userName": "backdoor-admin"}},
        "eventID": "event-004-root-create-user"
    },
    # Failed login attempts (brute force pattern)
    *[{
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAATTACKER",
            "arn": "arn:aws:iam::123456789012:user/target",
            "accountId": "123456789012",
            "userName": "target"
        },
        "eventTime": (datetime.utcnow() - timedelta(minutes=i)).isoformat() + "Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.200",
        "userAgent": "Mozilla/5.0",
        "errorCode": "AccessDenied",
        "errorMessage": "Invalid credentials",
        "eventID": f"event-brute-{i}"
    } for i in range(5, 11)]
]


# Sample GuardDuty findings
SAMPLE_GUARDDUTY_FINDINGS = [
    {
        "AccountId": "123456789012",
        "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/gd-001",
        "CreatedAt": (datetime.utcnow() - timedelta(minutes=10)).isoformat() + "Z",
        "Description": "EC2 instance i-0123456789 is communicating with a known Bitcoin mining pool.",
        "Id": "gd-finding-001",
        "Region": "us-east-1",
        "Resource": {
            "InstanceDetails": {
                "InstanceId": "i-0123456789",
                "InstanceType": "t2.micro"
            },
            "ResourceType": "Instance"
        },
        "Severity": 8.0,
        "Title": "Cryptocurrency Mining Activity Detected",
        "Type": "CryptoCurrency:EC2/BitcoinTool.B",
        "UpdatedAt": datetime.utcnow().isoformat() + "Z",
        "Service": {
            "Action": {
                "NetworkConnectionAction": {
                    "RemoteIpDetails": {
                        "IpAddressV4": "203.0.113.100"
                    },
                    "RemotePortDetails": {
                        "Port": 8333
                    },
                    "Protocol": "TCP"
                }
            },
            "Count": 15
        }
    },
    {
        "AccountId": "123456789012",
        "Arn": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/gd-002",
        "CreatedAt": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z",
        "Description": "API GetSecretValue was invoked from an unusual IP address.",
        "Id": "gd-finding-002",
        "Region": "us-east-1",
        "Resource": {
            "AccessKeyDetails": {
                "AccessKeyId": "AKIAEXAMPLE",
                "PrincipalId": "AIDAEXAMPLE",
                "UserName": "service-account",
                "UserType": "IAMUser"
            },
            "ResourceType": "AccessKey"
        },
        "Severity": 6.5,
        "Title": "Unusual API Call from Unknown IP",
        "Type": "CredentialAccess:IAMUser/AnomalousBehavior",
        "UpdatedAt": datetime.utcnow().isoformat() + "Z",
        "Service": {
            "Action": {
                "AwsApiCallAction": {
                    "Api": "GetSecretValue",
                    "ServiceName": "secretsmanager.amazonaws.com",
                    "RemoteIpDetails": {
                        "IpAddressV4": "198.51.100.50"
                    },
                    "UserAgent": "aws-sdk-python/1.0"
                }
            },
            "Count": 3
        }
    }
]


def check_health(service_name: str, url: str) -> bool:
    """Check if a service is healthy"""
    try:
        response = requests.get(f"{url}/health", timeout=30)
        if response.status_code == 200:
            print(f"✓ {service_name} is healthy")
            return True
        else:
            print(f"✗ {service_name} returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"✗ {service_name} is not reachable: {e}")
        return False


def ingest_cloudtrail_events():
    """Ingest sample CloudTrail events"""
    print("\nIngesting CloudTrail events...")
    
    response = requests.post(
        f"{EVENT_INGEST_URL}/ingest/cloudtrail",
        json={"events": SAMPLE_CLOUDTRAIL_EVENTS},
        timeout=30
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Ingested {result['events_processed']} CloudTrail events")
        print(f"  Event IDs: {result['event_ids'][:3]}...")
        return result['event_ids']
    else:
        print(f"✗ Failed to ingest CloudTrail events: {response.text}")
        return []


def ingest_guardduty_findings():
    """Ingest sample GuardDuty findings"""
    print("\nIngesting GuardDuty findings...")
    
    response = requests.post(
        f"{EVENT_INGEST_URL}/ingest/guardduty",
        json={"findings": SAMPLE_GUARDDUTY_FINDINGS},
        timeout=30
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Ingested {result['events_processed']} GuardDuty findings")
        print(f"  Event IDs: {result['event_ids']}")
        return result['event_ids']
    else:
        print(f"✗ Failed to ingest GuardDuty findings: {response.text}")
        return []


def query_events():
    """Query events via API Gateway"""
    print("\nQuerying events...")
    
    # Get all events
    response = requests.get(f"{API_GATEWAY_URL}/events", timeout=30)
    
    if response.status_code == 200:
        events = response.json()
        print(f"✓ Retrieved {len(events)} events")
        
        # Show summary
        severities = {}
        sources = {}
        for event in events:
            sev = event.get('severity', 'unknown')
            src = event.get('source', 'unknown')
            severities[sev] = severities.get(sev, 0) + 1
            sources[src] = sources.get(src, 0) + 1
        
        print(f"  By severity: {severities}")
        print(f"  By source: {sources}")
    else:
        print(f"✗ Failed to query events: {response.text}")


def get_critical_events():
    """Query critical severity events"""
    print("\nQuerying critical events...")
    
    response = requests.get(
        f"{API_GATEWAY_URL}/events/severity/critical",
        timeout=30
    )
    
    if response.status_code == 200:
        events = response.json()
        print(f"✓ Found {len(events)} critical events")
        for event in events[:3]:
            print(f"  - {event.get('title', 'Unknown')}")
    else:
        print(f"✗ Failed to query critical events: {response.text}")


def get_statistics():
    """Get event statistics"""
    print("\nGetting statistics...")
    
    response = requests.get(f"{API_GATEWAY_URL}/events/stats", timeout=30)
    
    if response.status_code == 200:
        stats = response.json()
        print(f"✓ Statistics:")
        print(f"  Total events: {stats.get('total_events', 0)}")
        print(f"  Events last 24h: {stats.get('events_last_24h', 0)}")
        print(f"  Critical last 24h: {stats.get('critical_events_last_24h', 0)}")
        print(f"  By severity: {stats.get('events_by_severity', {})}")
    else:
        print(f"✗ Failed to get statistics: {response.text}")


def trigger_correlation():
    """Trigger correlation processing"""
    print("\nTriggering correlation analysis...")
    
    response = requests.post(
        f"{EVENT_PROCESSOR_URL}/process/trigger",
        timeout=30
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✓ Correlation triggered")
        print(f"  Recent events: {result.get('recent_events_count', 0)}")
        print(f"  Correlations found: {result.get('correlations_found', 0)}")
        
        for corr in result.get('correlations', []):
            print(f"  - {corr.get('rule')}: {corr.get('description')}")
    else:
        print(f"✗ Failed to trigger correlation: {response.text}")


def main():
    print("=" * 60)
    print("Security Event Aggregator - Integration Test")
    print("=" * 60)
    
    # Check service health
    print("\n--- Checking Service Health ---")
    services_healthy = all([
        check_health("API Gateway", API_GATEWAY_URL),
        check_health("Event Ingest", EVENT_INGEST_URL),
        check_health("Event Processor", EVENT_PROCESSOR_URL),
    ])
    
    if not services_healthy:
        print("\n⚠ Some services are not healthy. Make sure docker-compose is running.")
        print("Run: docker-compose up -d")
        return
    
    # Ingest events
    print("\n--- Ingesting Events ---")
    cloudtrail_ids = ingest_cloudtrail_events()
    guardduty_ids = ingest_guardduty_findings()
    
    # Wait for events to be processed
    print("\nWaiting for events to be stored...")
    time.sleep(3)
    
    # Query events
    print("\n--- Querying Events ---")
    query_events()
    get_critical_events()
    get_statistics()
    
    # Trigger correlation
    print("\n--- Running Correlation ---")
    trigger_correlation()
    
    print("\n" + "=" * 60)
    print("Integration Test Complete!")
    print("=" * 60)
    print("\nYou can explore the APIs at:")
    print(f"  - API Gateway Docs: {API_GATEWAY_URL}/docs")
    print(f"  - Event Ingest Docs: {EVENT_INGEST_URL}/docs")
    print(f"  - Event Processor Docs: {EVENT_PROCESSOR_URL}/docs")


if __name__ == "__main__":
    main()
