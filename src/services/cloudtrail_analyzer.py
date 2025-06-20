import logging
import json
import gzip
import boto3
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress
import re
from src.services.aws_client import AWSClient
from src.models.security import SecurityFinding, AWSResource, db

logger = logging.getLogger(__name__)

class CloudTrailAnalyzer:
    """Advanced CloudTrail log analysis for security monitoring"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
        
        # Define suspicious patterns
        self.suspicious_patterns = {
            'privilege_escalation': [
                'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy',
                'CreateRole', 'CreateUser', 'AddUserToGroup'
            ],
            'data_access': [
                'GetObject', 'ListBucket', 'GetBucketAcl', 'GetBucketPolicy',
                'DescribeDBInstances', 'DescribeSnapshots'
            ],
            'infrastructure_changes': [
                'CreateSecurityGroup', 'AuthorizeSecurityGroupIngress',
                'ModifyDBInstance', 'CreateDBInstance', 'DeleteDBInstance',
                'TerminateInstances', 'RunInstances'
            ],
            'credential_access': [
                'CreateAccessKey', 'UpdateAccessKey', 'GetSessionToken',
                'AssumeRole', 'GetCredentialsForIdentity'
            ],
            'persistence': [
                'CreateUser', 'CreateRole', 'CreateLoginProfile',
                'UpdateLoginProfile', 'CreateAccessKey'
            ]
        }
        
        # Define high-risk API calls
        self.high_risk_apis = {
            'DeleteTrail', 'StopLogging', 'PutBucketAcl', 'PutBucketPolicy',
            'DeleteBucket', 'DeleteDBInstance', 'TerminateInstances',
            'DetachUserPolicy', 'DeleteUser', 'DeleteRole'
        }
        
        # Define normal business hours (can be configured)
        self.business_hours = {
            'start': 8,  # 8 AM
            'end': 18,   # 6 PM
            'timezone': 'UTC'
        }
    
    def analyze_cloudtrail_logs(self, start_time: datetime, end_time: datetime, 
                               regions: List[str] = None) -> List[Dict[str, Any]]:
        """Analyze CloudTrail logs for suspicious activities"""
        findings = []
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            for region in regions:
                self.logger.info(f"Analyzing CloudTrail logs for region: {region}")
                
                # Get CloudTrail events
                events = self._get_cloudtrail_events(region, start_time, end_time)
                
                # Analyze events for various threats
                findings.extend(self._detect_privilege_escalation(events, region))
                findings.extend(self._detect_unusual_api_activity(events, region))
                findings.extend(self._detect_suspicious_logins(events, region))
                findings.extend(self._detect_data_exfiltration(events, region))
                findings.extend(self._detect_infrastructure_tampering(events, region))
                findings.extend(self._detect_credential_abuse(events, region))
                findings.extend(self._detect_off_hours_activity(events, region))
                findings.extend(self._detect_geographic_anomalies(events, region))
                findings.extend(self._detect_failed_operations(events, region))
                findings.extend(self._detect_root_account_usage(events, region))
                
        except Exception as e:
            self.logger.error(f"Failed to analyze CloudTrail logs: {str(e)}")
        
        return findings
    
    def _get_enabled_regions(self) -> List[str]:
        """Get list of enabled AWS regions"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            self.logger.error(f"Failed to get enabled regions: {str(e)}")
            return ['us-east-1']  # Default fallback
    
    def _get_cloudtrail_events(self, region: str, start_time: datetime, 
                              end_time: datetime) -> List[Dict[str, Any]]:
        """Retrieve CloudTrail events for analysis"""
        events = []
        
        try:
            cloudtrail_client = self.aws_client.get_client('cloudtrail', region)
            
            paginator = cloudtrail_client.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                MaxItems=10000  # Limit to prevent excessive API calls
            ):
                events.extend(page.get('Events', []))
                
        except Exception as e:
            self.logger.error(f"Failed to get CloudTrail events for region {region}: {str(e)}")
        
        return events
    
    def _detect_privilege_escalation(self, events: List[Dict[str, Any]], 
                                   region: str) -> List[Dict[str, Any]]:
        """Detect privilege escalation attempts"""
        findings = []
        
        # Track privilege escalation activities by user
        user_activities = defaultdict(list)
        
        for event in events:
            event_name = event.get('EventName', '')
            user_identity = event.get('UserIdentity', {})
            user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
            
            if event_name in self.suspicious_patterns['privilege_escalation']:
                user_activities[user_name].append({
                    'event_name': event_name,
                    'event_time': event.get('EventTime'),
                    'source_ip': event.get('SourceIPAddress'),
                    'user_agent': event.get('UserAgent'),
                    'resources': event.get('Resources', [])
                })
        
        # Analyze patterns
        for user_name, activities in user_activities.items():
            if len(activities) >= 3:  # Multiple privilege escalation attempts
                findings.append({
                    'type': 'security_threat',
                    'severity': 'high',
                    'title': f'Potential Privilege Escalation by {user_name}',
                    'description': f'User {user_name} performed {len(activities)} privilege escalation activities in region {region}',
                    'recommendation': 'Investigate user activities and review permissions granted',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'activity_count': len(activities),
                        'activities': activities[:5],  # Limit to first 5 for brevity
                        'time_range': f"{activities[0]['event_time']} to {activities[-1]['event_time']}"
                    }
                })
        
        return findings
    
    def _detect_unusual_api_activity(self, events: List[Dict[str, Any]], 
                                   region: str) -> List[Dict[str, Any]]:
        """Detect unusual API activity patterns"""
        findings = []
        
        # Track API call patterns
        api_patterns = defaultdict(lambda: defaultdict(int))
        user_api_counts = defaultdict(Counter)
        
        for event in events:
            event_name = event.get('EventName', '')
            user_identity = event.get('UserIdentity', {})
            user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
            event_time = event.get('EventTime')
            
            if event_time:
                hour = event_time.hour
                api_patterns[event_name][hour] += 1
                user_api_counts[user_name][event_name] += 1
        
        # Detect unusual API call volumes
        for user_name, api_counts in user_api_counts.items():
            total_calls = sum(api_counts.values())
            
            if total_calls > 1000:  # High volume of API calls
                top_apis = api_counts.most_common(5)
                
                findings.append({
                    'type': 'anomaly',
                    'severity': 'medium',
                    'title': f'High Volume API Activity by {user_name}',
                    'description': f'User {user_name} made {total_calls} API calls in region {region}',
                    'recommendation': 'Review user activity for potential automation or abuse',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'total_calls': total_calls,
                        'top_apis': dict(top_apis)
                    }
                })
        
        # Detect high-risk API usage
        for event in events:
            event_name = event.get('EventName', '')
            
            if event_name in self.high_risk_apis:
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                
                findings.append({
                    'type': 'high_risk_activity',
                    'severity': 'high',
                    'title': f'High-Risk API Call: {event_name}',
                    'description': f'User {user_name} executed high-risk API {event_name} in region {region}',
                    'recommendation': 'Verify this action was authorized and necessary',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'api_name': event_name,
                        'event_time': event.get('EventTime').isoformat() if event.get('EventTime') else None,
                        'source_ip': event.get('SourceIPAddress'),
                        'resources': event.get('Resources', [])
                    }
                })
        
        return findings
    
    def _detect_suspicious_logins(self, events: List[Dict[str, Any]], 
                                region: str) -> List[Dict[str, Any]]:
        """Detect suspicious login patterns"""
        findings = []
        
        # Track login events
        login_events = []
        
        for event in events:
            event_name = event.get('EventName', '')
            
            if event_name in ['ConsoleLogin', 'AssumeRole', 'GetSessionToken']:
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                source_ip = event.get('SourceIPAddress', '')
                user_agent = event.get('UserAgent', '')
                event_time = event.get('EventTime')
                
                login_events.append({
                    'user_name': user_name,
                    'source_ip': source_ip,
                    'user_agent': user_agent,
                    'event_time': event_time,
                    'event_name': event_name
                })
        
        # Analyze login patterns
        user_ips = defaultdict(set)
        user_agents = defaultdict(set)
        
        for login in login_events:
            user_ips[login['user_name']].add(login['source_ip'])
            user_agents[login['user_name']].add(login['user_agent'])
        
        # Detect multiple IP addresses for single user
        for user_name, ips in user_ips.items():
            if len(ips) > 5:  # User logging in from many different IPs
                findings.append({
                    'type': 'anomaly',
                    'severity': 'medium',
                    'title': f'Multiple Login IPs for {user_name}',
                    'description': f'User {user_name} logged in from {len(ips)} different IP addresses',
                    'recommendation': 'Verify all login locations are legitimate',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'ip_count': len(ips),
                        'ip_addresses': list(ips)[:10]  # Limit to first 10
                    }
                })
        
        # Detect suspicious IP addresses
        for login in login_events:
            source_ip = login['source_ip']
            
            if self._is_suspicious_ip(source_ip):
                findings.append({
                    'type': 'security_threat',
                    'severity': 'high',
                    'title': f'Login from Suspicious IP: {source_ip}',
                    'description': f'User {login["user_name"]} logged in from potentially malicious IP {source_ip}',
                    'recommendation': 'Investigate login and consider blocking IP address',
                    'context': {
                        'user_name': login['user_name'],
                        'region': region,
                        'source_ip': source_ip,
                        'event_time': login['event_time'].isoformat() if login['event_time'] else None,
                        'user_agent': login['user_agent']
                    }
                })
        
        return findings
    
    def _detect_data_exfiltration(self, events: List[Dict[str, Any]], 
                                region: str) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration activities"""
        findings = []
        
        # Track data access patterns
        data_access_events = []
        
        for event in events:
            event_name = event.get('EventName', '')
            
            if event_name in self.suspicious_patterns['data_access']:
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                source_ip = event.get('SourceIPAddress', '')
                event_time = event.get('EventTime')
                resources = event.get('Resources', [])
                
                data_access_events.append({
                    'user_name': user_name,
                    'event_name': event_name,
                    'source_ip': source_ip,
                    'event_time': event_time,
                    'resources': resources
                })
        
        # Analyze patterns
        user_data_access = defaultdict(list)
        
        for event in data_access_events:
            user_data_access[event['user_name']].append(event)
        
        # Detect excessive data access
        for user_name, accesses in user_data_access.items():
            if len(accesses) > 100:  # High volume of data access
                findings.append({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'title': f'Potential Data Exfiltration by {user_name}',
                    'description': f'User {user_name} performed {len(accesses)} data access operations',
                    'recommendation': 'Investigate data access patterns and verify legitimacy',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'access_count': len(accesses),
                        'time_range': f"{accesses[0]['event_time']} to {accesses[-1]['event_time']}",
                        'unique_resources': len(set(
                            resource.get('resourceName', '') 
                            for access in accesses 
                            for resource in access['resources']
                        ))
                    }
                })
        
        return findings
    
    def _detect_infrastructure_tampering(self, events: List[Dict[str, Any]], 
                                       region: str) -> List[Dict[str, Any]]:
        """Detect infrastructure tampering activities"""
        findings = []
        
        # Track infrastructure changes
        infra_changes = []
        
        for event in events:
            event_name = event.get('EventName', '')
            
            if event_name in self.suspicious_patterns['infrastructure_changes']:
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                source_ip = event.get('SourceIPAddress', '')
                event_time = event.get('EventTime')
                resources = event.get('Resources', [])
                
                infra_changes.append({
                    'user_name': user_name,
                    'event_name': event_name,
                    'source_ip': source_ip,
                    'event_time': event_time,
                    'resources': resources
                })
        
        # Analyze patterns
        user_changes = defaultdict(list)
        
        for change in infra_changes:
            user_changes[change['user_name']].append(change)
        
        # Detect excessive infrastructure changes
        for user_name, changes in user_changes.items():
            if len(changes) > 20:  # High volume of infrastructure changes
                findings.append({
                    'type': 'infrastructure_tampering',
                    'severity': 'medium',
                    'title': f'Extensive Infrastructure Changes by {user_name}',
                    'description': f'User {user_name} made {len(changes)} infrastructure changes',
                    'recommendation': 'Review infrastructure changes for unauthorized modifications',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'change_count': len(changes),
                        'change_types': list(set(change['event_name'] for change in changes)),
                        'time_range': f"{changes[0]['event_time']} to {changes[-1]['event_time']}"
                    }
                })
        
        return findings
    
    def _detect_credential_abuse(self, events: List[Dict[str, Any]], 
                               region: str) -> List[Dict[str, Any]]:
        """Detect credential abuse patterns"""
        findings = []
        
        # Track credential-related activities
        credential_events = []
        
        for event in events:
            event_name = event.get('EventName', '')
            
            if event_name in self.suspicious_patterns['credential_access']:
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                source_ip = event.get('SourceIPAddress', '')
                event_time = event.get('EventTime')
                
                credential_events.append({
                    'user_name': user_name,
                    'event_name': event_name,
                    'source_ip': source_ip,
                    'event_time': event_time
                })
        
        # Analyze patterns
        user_credential_activities = defaultdict(list)
        
        for event in credential_events:
            user_credential_activities[event['user_name']].append(event)
        
        # Detect excessive credential activities
        for user_name, activities in user_credential_activities.items():
            if len(activities) > 10:  # High volume of credential activities
                findings.append({
                    'type': 'credential_abuse',
                    'severity': 'high',
                    'title': f'Excessive Credential Activities by {user_name}',
                    'description': f'User {user_name} performed {len(activities)} credential-related activities',
                    'recommendation': 'Investigate credential usage and verify legitimacy',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'activity_count': len(activities),
                        'activity_types': list(set(activity['event_name'] for activity in activities))
                    }
                })
        
        return findings
    
    def _detect_off_hours_activity(self, events: List[Dict[str, Any]], 
                                 region: str) -> List[Dict[str, Any]]:
        """Detect activities outside business hours"""
        findings = []
        
        off_hours_events = []
        
        for event in events:
            event_time = event.get('EventTime')
            
            if event_time and self._is_off_hours(event_time):
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                event_name = event.get('EventName', '')
                source_ip = event.get('SourceIPAddress', '')
                
                # Only flag significant activities during off hours
                if event_name in self.high_risk_apis or event_name in self.suspicious_patterns['infrastructure_changes']:
                    off_hours_events.append({
                        'user_name': user_name,
                        'event_name': event_name,
                        'source_ip': source_ip,
                        'event_time': event_time
                    })
        
        # Group by user
        user_off_hours = defaultdict(list)
        
        for event in off_hours_events:
            user_off_hours[event['user_name']].append(event)
        
        # Generate findings
        for user_name, events_list in user_off_hours.items():
            if len(events_list) > 5:  # Multiple off-hours activities
                findings.append({
                    'type': 'anomaly',
                    'severity': 'medium',
                    'title': f'Off-Hours Activity by {user_name}',
                    'description': f'User {user_name} performed {len(events_list)} significant activities outside business hours',
                    'recommendation': 'Verify off-hours activities are authorized',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'activity_count': len(events_list),
                        'activities': [
                            {
                                'event_name': event['event_name'],
                                'event_time': event['event_time'].isoformat(),
                                'source_ip': event['source_ip']
                            }
                            for event in events_list[:5]
                        ]
                    }
                })
        
        return findings
    
    def _detect_geographic_anomalies(self, events: List[Dict[str, Any]], 
                                   region: str) -> List[Dict[str, Any]]:
        """Detect geographic anomalies in access patterns"""
        findings = []
        
        # Track user locations
        user_locations = defaultdict(set)
        
        for event in events:
            user_identity = event.get('UserIdentity', {})
            user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
            source_ip = event.get('SourceIPAddress', '')
            
            if source_ip and not self._is_aws_internal_ip(source_ip):
                # In a real implementation, you would use IP geolocation service
                # For now, we'll use a simplified approach
                location = self._get_ip_location(source_ip)
                if location:
                    user_locations[user_name].add(location)
        
        # Detect users accessing from multiple countries
        for user_name, locations in user_locations.items():
            if len(locations) > 3:  # User accessing from multiple locations
                findings.append({
                    'type': 'geographic_anomaly',
                    'severity': 'medium',
                    'title': f'Multiple Geographic Locations for {user_name}',
                    'description': f'User {user_name} accessed AWS from {len(locations)} different geographic locations',
                    'recommendation': 'Verify all access locations are legitimate for this user',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'location_count': len(locations),
                        'locations': list(locations)
                    }
                })
        
        return findings
    
    def _detect_failed_operations(self, events: List[Dict[str, Any]], 
                                region: str) -> List[Dict[str, Any]]:
        """Detect patterns in failed operations"""
        findings = []
        
        # Track failed events
        failed_events = []
        
        for event in events:
            error_code = event.get('ErrorCode')
            error_message = event.get('ErrorMessage')
            
            if error_code or error_message:
                user_identity = event.get('UserIdentity', {})
                user_name = user_identity.get('userName', user_identity.get('arn', 'Unknown'))
                event_name = event.get('EventName', '')
                source_ip = event.get('SourceIPAddress', '')
                event_time = event.get('EventTime')
                
                failed_events.append({
                    'user_name': user_name,
                    'event_name': event_name,
                    'source_ip': source_ip,
                    'event_time': event_time,
                    'error_code': error_code,
                    'error_message': error_message
                })
        
        # Analyze patterns
        user_failures = defaultdict(list)
        
        for event in failed_events:
            user_failures[event['user_name']].append(event)
        
        # Detect excessive failures (potential brute force or reconnaissance)
        for user_name, failures in user_failures.items():
            if len(failures) > 50:  # High number of failed operations
                findings.append({
                    'type': 'reconnaissance',
                    'severity': 'medium',
                    'title': f'High Number of Failed Operations by {user_name}',
                    'description': f'User {user_name} had {len(failures)} failed operations',
                    'recommendation': 'Investigate failed operations for potential reconnaissance or brute force attempts',
                    'context': {
                        'user_name': user_name,
                        'region': region,
                        'failure_count': len(failures),
                        'common_errors': dict(Counter(
                            failure['error_code'] for failure in failures if failure['error_code']
                        ).most_common(5)),
                        'time_range': f"{failures[0]['event_time']} to {failures[-1]['event_time']}"
                    }
                })
        
        return findings
    
    def _detect_root_account_usage(self, events: List[Dict[str, Any]], 
                                 region: str) -> List[Dict[str, Any]]:
        """Detect root account usage"""
        findings = []
        
        for event in events:
            user_identity = event.get('UserIdentity', {})
            user_type = user_identity.get('type', '')
            
            if user_type == 'Root':
                event_name = event.get('EventName', '')
                source_ip = event.get('SourceIPAddress', '')
                event_time = event.get('EventTime')
                user_agent = event.get('UserAgent', '')
                
                findings.append({
                    'type': 'critical_security_event',
                    'severity': 'critical',
                    'title': 'Root Account Usage Detected',
                    'description': f'Root account was used to perform {event_name} operation',
                    'recommendation': 'Investigate root account usage immediately and ensure it was authorized',
                    'compliance_standard': 'CIS',
                    'context': {
                        'region': region,
                        'event_name': event_name,
                        'source_ip': source_ip,
                        'event_time': event_time.isoformat() if event_time else None,
                        'user_agent': user_agent
                    }
                })
        
        return findings
    
    # Helper methods
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            # Check if IP is in private ranges (shouldn't be accessing AWS directly)
            ip = ipaddress.IPv4Address(ip_address)
            
            private_ranges = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16')
            ]
            
            for private_range in private_ranges:
                if ip in private_range:
                    return True
            
            # In a real implementation, you would check against threat intelligence feeds
            # For now, we'll use a simple heuristic
            
            return False
            
        except ValueError:
            # Invalid IP address
            return True
    
    def _is_aws_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is AWS internal"""
        # AWS service IP ranges - this is a simplified check
        aws_patterns = [
            r'^52\.',  # Common AWS IP range
            r'^54\.',  # Common AWS IP range
            r'^3\.',   # Common AWS IP range
        ]
        
        for pattern in aws_patterns:
            if re.match(pattern, ip_address):
                return True
        
        return False
    
    def _get_ip_location(self, ip_address: str) -> Optional[str]:
        """Get geographic location of IP address"""
        # In a real implementation, you would use a geolocation service
        # For now, we'll return a placeholder
        try:
            ip = ipaddress.IPv4Address(ip_address)
            
            # Simple heuristic based on IP ranges (not accurate, just for demo)
            if str(ip).startswith('192.168.') or str(ip).startswith('10.') or str(ip).startswith('172.'):
                return 'Private Network'
            
            # You would integrate with services like MaxMind, IPinfo, etc.
            return 'Unknown Location'
            
        except ValueError:
            return None
    
    def _is_off_hours(self, event_time: datetime) -> bool:
        """Check if event occurred outside business hours"""
        try:
            hour = event_time.hour
            
            # Check if outside business hours
            if hour < self.business_hours['start'] or hour >= self.business_hours['end']:
                return True
            
            # Check if weekend (Saturday = 5, Sunday = 6)
            if event_time.weekday() >= 5:
                return True
            
            return False
            
        except Exception:
            return False
    
    def analyze_cloudtrail_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyze CloudTrail trends over time"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            # Get events for trend analysis
            all_events = []
            regions = self._get_enabled_regions()[:3]  # Limit to 3 regions for performance
            
            for region in regions:
                events = self._get_cloudtrail_events(region, start_time, end_time)
                all_events.extend(events)
            
            # Analyze trends
            trends = {
                'total_events': len(all_events),
                'unique_users': len(set(
                    event.get('UserIdentity', {}).get('userName', 
                    event.get('UserIdentity', {}).get('arn', 'Unknown'))
                    for event in all_events
                )),
                'top_apis': dict(Counter(
                    event.get('EventName', 'Unknown') for event in all_events
                ).most_common(10)),
                'top_users': dict(Counter(
                    event.get('UserIdentity', {}).get('userName', 
                    event.get('UserIdentity', {}).get('arn', 'Unknown'))
                    for event in all_events
                ).most_common(10)),
                'error_rate': len([
                    event for event in all_events 
                    if event.get('ErrorCode') or event.get('ErrorMessage')
                ]) / len(all_events) * 100 if all_events else 0,
                'regions_active': len(set(event.get('AwsRegion', 'Unknown') for event in all_events)),
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'days': days
                }
            }
            
            return trends
            
        except Exception as e:
            self.logger.error(f"Failed to analyze CloudTrail trends: {str(e)}")
            return {}

class CloudTrailLogProcessor:
    """Process CloudTrail logs from S3 for detailed analysis"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
    
    def process_s3_logs(self, bucket_name: str, prefix: str = '', 
                       start_date: datetime = None, end_date: datetime = None) -> List[Dict[str, Any]]:
        """Process CloudTrail logs stored in S3"""
        events = []
        
        try:
            s3_client = self.aws_client.get_client('s3')
            
            # List objects in bucket
            paginator = s3_client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    
                    # Filter by date if specified
                    if start_date or end_date:
                        obj_date = obj['LastModified'].replace(tzinfo=None)
                        if start_date and obj_date < start_date:
                            continue
                        if end_date and obj_date > end_date:
                            continue
                    
                    # Process log file
                    if key.endswith('.json.gz'):
                        log_events = self._process_log_file(s3_client, bucket_name, key)
                        events.extend(log_events)
            
        except Exception as e:
            self.logger.error(f"Failed to process S3 logs: {str(e)}")
        
        return events
    
    def _process_log_file(self, s3_client, bucket_name: str, key: str) -> List[Dict[str, Any]]:
        """Process individual CloudTrail log file"""
        events = []
        
        try:
            # Download and decompress log file
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            
            with gzip.GzipFile(fileobj=response['Body']) as gz_file:
                log_data = json.loads(gz_file.read().decode('utf-8'))
                
                # Extract events
                records = log_data.get('Records', [])
                events.extend(records)
                
        except Exception as e:
            self.logger.error(f"Failed to process log file {key}: {str(e)}")
        
        return events

