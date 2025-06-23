import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from src.services.aws_client import AWSClient
from src.models.security import SecurityFinding, AWSResource, db

logger = logging.getLogger(__name__)

class GuardDutyIntegration:
    """Integration with AWS GuardDuty for threat detection"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
        
        # Define severity mapping
        self.severity_mapping = {
            'LOW': 'low',
            'MEDIUM': 'medium',
            'HIGH': 'high',
            'CRITICAL': 'critical'
        }
        
        # Define finding type categories
        self.finding_categories = {
            'Backdoor': 'malware',
            'Behavior': 'anomaly',
            'Cryptocurrency': 'cryptocurrency_mining',
            'Malware': 'malware',
            'Persistence': 'persistence',
            'Policy': 'policy_violation',
            'PrivilegeEscalation': 'privilege_escalation',
            'Recon': 'reconnaissance',
            'ResourceConsumption': 'resource_abuse',
            'Stealth': 'stealth',
            'Trojan': 'malware',
            'UnauthorizedAccess': 'unauthorized_access'
        }
    
    def sync_guardduty_findings(self, regions: List[str] = None) -> List[Dict[str, Any]]:
        """Sync findings from GuardDuty across regions"""
        all_findings = []
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            for region in regions:
                self.logger.info(f"Syncing GuardDuty findings from region: {region}")
                
                # Check if GuardDuty is enabled in this region
                if not self._is_guardduty_enabled(region):
                    self.logger.warning(f"GuardDuty not enabled in region {region}")
                    continue
                
                # Get findings from GuardDuty
                findings = self._get_guardduty_findings(region)
                
                # Process and normalize findings
                for finding in findings:
                    processed_finding = self._process_guardduty_finding(finding, region)
                    if processed_finding:
                        all_findings.append(processed_finding)
                
        except Exception as e:
            self.logger.error(f"Failed to sync GuardDuty findings: {str(e)}")
        
        return all_findings
    
    def _get_enabled_regions(self) -> List[str]:
        """Get list of enabled AWS regions"""
        try:
            ec2_client = self.aws_client.get_client('ec2')
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            self.logger.error(f"Failed to get enabled regions: {str(e)}")
            return ['us-east-1']
    
    def _is_guardduty_enabled(self, region: str) -> bool:
        """Check if GuardDuty is enabled in the region"""
        try:
            guardduty_client = self.aws_client.get_client('guardduty', region)
            
            # List detectors
            response = guardduty_client.list_detectors()
            detectors = response.get('DetectorIds', [])
            
            if not detectors:
                return False
            
            # Check if any detector is enabled
            for detector_id in detectors:
                detector_response = guardduty_client.get_detector(DetectorId=detector_id)
                if detector_response.get('Status') == 'ENABLED':
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to check GuardDuty status in region {region}: {str(e)}")
            return False
    
    def _get_guardduty_findings(self, region: str) -> List[Dict[str, Any]]:
        """Get GuardDuty findings from a specific region"""
        findings = []
        
        try:
            guardduty_client = self.aws_client.get_client('guardduty', region)
            
            # Get detector IDs
            detectors_response = guardduty_client.list_detectors()
            detector_ids = detectors_response.get('DetectorIds', [])
            
            for detector_id in detector_ids:
                # List findings for this detector
                findings_response = guardduty_client.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'updatedAt': {
                                'GreaterThan': int((datetime.utcnow() - timedelta(days=7)).timestamp() * 1000)
                            }
                        }
                    },
                    MaxResults=100
                )
                
                finding_ids = findings_response.get('FindingIds', [])
                
                if finding_ids:
                    # Get detailed finding information
                    detailed_response = guardduty_client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )
                    
                    findings.extend(detailed_response.get('Findings', []))
                
        except Exception as e:
            self.logger.error(f"Failed to get GuardDuty findings from region {region}: {str(e)}")
        
        return findings
    
    def _process_guardduty_finding(self, finding: Dict[str, Any], region: str) -> Optional[Dict[str, Any]]:
        """Process and normalize GuardDuty finding"""
        try:
            finding_id = finding.get('Id', '')
            finding_type = finding.get('Type', '')
            severity = finding.get('Severity', 0)
            title = finding.get('Title', '')
            description = finding.get('Description', '')
            created_at = finding.get('CreatedAt', '')
            updated_at = finding.get('UpdatedAt', '')
            
            # Map severity
            mapped_severity = self._map_severity(severity)
            
            # Extract resource information
            resource_info = self._extract_resource_info(finding)
            
            # Categorize finding
            category = self._categorize_finding(finding_type)
            
            # Extract additional context
            context = self._extract_finding_context(finding)
            
            # Generate recommendations
            recommendation = self._generate_recommendation(finding_type, context)
            
            processed_finding = {
                'type': 'guardduty_finding',
                'severity': mapped_severity,
                'title': title,
                'description': description,
                'recommendation': recommendation,
                'finding_type': category,
                'source': 'AWS GuardDuty',
                'external_id': finding_id,
                'context': {
                    'region': region,
                    'guardduty_type': finding_type,
                    'guardduty_severity': severity,
                    'created_at': created_at,
                    'updated_at': updated_at,
                    'resource_info': resource_info,
                    **context
                }
            }
            
            return processed_finding
            
        except Exception as e:
            self.logger.error(f"Failed to process GuardDuty finding: {str(e)}")
            return None
    
    def _map_severity(self, severity_score: float) -> str:
        """Map GuardDuty severity score to our severity levels"""
        if severity_score >= 7.0:
            return 'critical'
        elif severity_score >= 4.0:
            return 'high'
        elif severity_score >= 1.0:
            return 'medium'
        else:
            return 'low'
    
    def _categorize_finding(self, finding_type: str) -> str:
        """Categorize GuardDuty finding type"""
        for category, mapped_type in self.finding_categories.items():
            if category in finding_type:
                return mapped_type
        
        return 'security_threat'
    
    def _extract_resource_info(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract resource information from GuardDuty finding"""
        resource_info = {}
        
        try:
            resource = finding.get('Resource', {})
            
            # Instance details
            instance_details = resource.get('InstanceDetails', {})
            if instance_details:
                resource_info.update({
                    'instance_id': instance_details.get('InstanceId'),
                    'instance_type': instance_details.get('InstanceType'),
                    'launch_time': instance_details.get('LaunchTime'),
                    'platform': instance_details.get('Platform'),
                    'availability_zone': instance_details.get('AvailabilityZone'),
                    'image_id': instance_details.get('ImageId'),
                    'tags': instance_details.get('Tags', [])
                })
                
                # Network interfaces
                network_interfaces = instance_details.get('NetworkInterfaces', [])
                if network_interfaces:
                    resource_info['network_interfaces'] = [
                        {
                            'network_interface_id': ni.get('NetworkInterfaceId'),
                            'private_ip': ni.get('PrivateIpAddress'),
                            'public_ip': ni.get('PublicIp'),
                            'subnet_id': ni.get('SubnetId'),
                            'vpc_id': ni.get('VpcId'),
                            'security_groups': ni.get('SecurityGroups', [])
                        }
                        for ni in network_interfaces
                    ]
            
            # Access key details
            access_key_details = resource.get('AccessKeyDetails', {})
            if access_key_details:
                resource_info.update({
                    'access_key_id': access_key_details.get('AccessKeyId'),
                    'principal_id': access_key_details.get('PrincipalId'),
                    'user_name': access_key_details.get('UserName'),
                    'user_type': access_key_details.get('UserType')
                })
            
            # S3 bucket details
            s3_bucket_details = resource.get('S3BucketDetails', [])
            if s3_bucket_details:
                resource_info['s3_buckets'] = [
                    {
                        'name': bucket.get('Name'),
                        'type': bucket.get('Type'),
                        'created_at': bucket.get('CreatedAt'),
                        'owner': bucket.get('Owner', {}),
                        'tags': bucket.get('Tags', []),
                        'default_server_side_encryption': bucket.get('DefaultServerSideEncryption', {}),
                        'public_access': bucket.get('PublicAccess', {})
                    }
                    for bucket in s3_bucket_details
                ]
            
        except Exception as e:
            self.logger.error(f"Failed to extract resource info: {str(e)}")
        
        return resource_info
    
    def _extract_finding_context(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract additional context from GuardDuty finding"""
        context = {}
        
        try:
            service = finding.get('Service', {})
            
            # Action details
            action = service.get('Action', {})
            if action:
                action_type = action.get('ActionType')
                context['action_type'] = action_type
                
                if action_type == 'NETWORK_CONNECTION':
                    network_connection = action.get('NetworkConnectionAction', {})
                    context.update({
                        'connection_direction': network_connection.get('ConnectionDirection'),
                        'local_port': network_connection.get('LocalPortDetails', {}).get('Port'),
                        'remote_ip': network_connection.get('RemoteIpDetails', {}).get('IpAddressV4'),
                        'remote_port': network_connection.get('RemotePortDetails', {}).get('Port'),
                        'protocol': network_connection.get('Protocol'),
                        'blocked': network_connection.get('Blocked')
                    })
                    
                    # IP geo location
                    remote_ip_details = network_connection.get('RemoteIpDetails', {})
                    if remote_ip_details:
                        context.update({
                            'remote_country': remote_ip_details.get('Country', {}).get('CountryName'),
                            'remote_city': remote_ip_details.get('City', {}).get('CityName'),
                            'remote_organization': remote_ip_details.get('Organization', {}).get('Org')
                        })
                
                elif action_type == 'AWS_API_CALL':
                    api_call = action.get('AwsApiCallAction', {})
                    context.update({
                        'api_name': api_call.get('Api'),
                        'service_name': api_call.get('ServiceName'),
                        'caller_type': api_call.get('CallerType'),
                        'user_agent': api_call.get('UserAgent'),
                        'error_code': api_call.get('ErrorCode')
                    })
                    
                    # Remote IP details for API calls
                    remote_ip_details = api_call.get('RemoteIpDetails', {})
                    if remote_ip_details:
                        context.update({
                            'api_caller_ip': remote_ip_details.get('IpAddressV4'),
                            'api_caller_country': remote_ip_details.get('Country', {}).get('CountryName'),
                            'api_caller_city': remote_ip_details.get('City', {}).get('CityName')
                        })
                
                elif action_type == 'DNS_REQUEST':
                    dns_request = action.get('DnsRequestAction', {})
                    context.update({
                        'domain': dns_request.get('Domain'),
                        'protocol': dns_request.get('Protocol'),
                        'blocked': dns_request.get('Blocked')
                    })
                
                elif action_type == 'PORT_PROBE':
                    port_probe = action.get('PortProbeAction', {})
                    context.update({
                        'blocked': port_probe.get('Blocked'),
                        'port_probe_details': port_probe.get('PortProbeDetails', [])
                    })
            
            # Evidence details
            evidence = service.get('Evidence', {})
            if evidence:
                threat_intelligence_details = evidence.get('ThreatIntelligenceDetails', [])
                if threat_intelligence_details:
                    context['threat_intelligence'] = [
                        {
                            'threat_list_name': ti.get('ThreatListName'),
                            'threat_names': ti.get('ThreatNames', [])
                        }
                        for ti in threat_intelligence_details
                    ]
            
            # Additional service information
            context.update({
                'archived': service.get('Archived', False),
                'count': service.get('Count', 1),
                'detector_id': service.get('DetectorId'),
                'event_first_seen': service.get('EventFirstSeen'),
                'event_last_seen': service.get('EventLastSeen'),
                'resource_role': service.get('ResourceRole'),
                'service_name': service.get('ServiceName')
            })
            
        except Exception as e:
            self.logger.error(f"Failed to extract finding context: {str(e)}")
        
        return context
    
    def _generate_recommendation(self, finding_type: str, context: Dict[str, Any]) -> str:
        """Generate recommendation based on finding type and context"""
        recommendations = {
            'Backdoor': 'Isolate the affected resource immediately and investigate for compromise. Review network connections and running processes.',
            'Behavior': 'Investigate the unusual behavior pattern. Review user activities and system logs for anomalies.',
            'Cryptocurrency': 'Terminate cryptocurrency mining activities immediately. Check for unauthorized software and review resource usage.',
            'Malware': 'Quarantine the affected resource and run comprehensive malware scans. Review security controls and update antivirus definitions.',
            'Persistence': 'Remove persistence mechanisms and review system configurations. Check for unauthorized scheduled tasks or startup items.',
            'Policy': 'Review and update security policies. Ensure compliance with organizational security standards.',
            'PrivilegeEscalation': 'Investigate privilege escalation attempt. Review user permissions and access controls.',
            'Recon': 'Monitor for follow-up attacks. Implement additional network monitoring and access controls.',
            'ResourceConsumption': 'Investigate resource abuse. Review billing and usage patterns for anomalies.',
            'Stealth': 'Investigate stealth techniques used. Review logs for evidence of data exfiltration or lateral movement.',
            'Trojan': 'Remove trojan malware and investigate compromise scope. Update security controls and monitor for reinfection.',
            'UnauthorizedAccess': 'Revoke unauthorized access immediately. Review access logs and update authentication mechanisms.'
        }
        
        # Find matching recommendation
        for category in recommendations:
            if category in finding_type:
                base_recommendation = recommendations[category]
                
                # Add context-specific recommendations
                if context.get('remote_country') and context['remote_country'] not in ['United States', 'Your Expected Country']:
                    base_recommendation += f" Note: Activity originated from {context['remote_country']}."
                
                if context.get('blocked') is False:
                    base_recommendation += " The connection was not blocked - consider implementing additional network controls."
                
                return base_recommendation
        
        return "Investigate this security finding and take appropriate remediation actions based on your security policies."
    
    def enable_guardduty(self, regions: List[str] = None) -> Dict[str, bool]:
        """Enable GuardDuty in specified regions"""
        results = {}
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            for region in regions:
                try:
                    guardduty_client = self.aws_client.get_client('guardduty', region)
                    
                    # Check if already enabled
                    if self._is_guardduty_enabled(region):
                        results[region] = True
                        continue
                    
                    # Create detector
                    response = guardduty_client.create_detector(
                        Enable=True,
                        FindingPublishingFrequency='FIFTEEN_MINUTES'
                    )
                    
                    detector_id = response.get('DetectorId')
                    if detector_id:
                        self.logger.info(f"GuardDuty enabled in region {region} with detector {detector_id}")
                        results[region] = True
                    else:
                        results[region] = False
                        
                except Exception as e:
                    self.logger.error(f"Failed to enable GuardDuty in region {region}: {str(e)}")
                    results[region] = False
                    
        except Exception as e:
            self.logger.error(f"Failed to enable GuardDuty: {str(e)}")
        
        return results
    
    def get_guardduty_statistics(self, regions: List[str] = None) -> Dict[str, Any]:
        """Get GuardDuty statistics across regions"""
        statistics = {
            'total_findings': 0,
            'findings_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'findings_by_type': {},
            'regions_enabled': 0,
            'regions_total': 0,
            'top_threat_types': {},
            'recent_findings_count': 0
        }
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            statistics['regions_total'] = len(regions)
            
            for region in regions:
                if self._is_guardduty_enabled(region):
                    statistics['regions_enabled'] += 1
                    
                    # Get findings statistics
                    findings = self._get_guardduty_findings(region)
                    statistics['total_findings'] += len(findings)
                    
                    for finding in findings:
                        # Count by severity
                        severity = self._map_severity(finding.get('Severity', 0))
                        statistics['findings_by_severity'][severity] += 1
                        
                        # Count by type
                        finding_type = finding.get('Type', 'Unknown')
                        category = self._categorize_finding(finding_type)
                        statistics['findings_by_type'][category] = statistics['findings_by_type'].get(category, 0) + 1
                        
                        # Count recent findings (last 24 hours)
                        updated_at = finding.get('UpdatedAt', '')
                        if updated_at:
                            try:
                                update_time = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                                if (datetime.now(update_time.tzinfo) - update_time).days < 1:
                                    statistics['recent_findings_count'] += 1
                            except:
                                pass
            
            # Get top threat types
            if statistics['findings_by_type']:
                statistics['top_threat_types'] = dict(
                    sorted(statistics['findings_by_type'].items(), 
                          key=lambda x: x[1], reverse=True)[:5]
                )
                
        except Exception as e:
            self.logger.error(f"Failed to get GuardDuty statistics: {str(e)}")
        
        return statistics
    
    def configure_guardduty_notifications(self, sns_topic_arn: str, regions: List[str] = None) -> Dict[str, bool]:
        """Configure GuardDuty to send notifications to SNS topic"""
        results = {}
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            for region in regions:
                try:
                    if not self._is_guardduty_enabled(region):
                        results[region] = False
                        continue
                    
                    guardduty_client = self.aws_client.get_client('guardduty', region)
                    
                    # Get detector IDs
                    detectors_response = guardduty_client.list_detectors()
                    detector_ids = detectors_response.get('DetectorIds', [])
                    
                    for detector_id in detector_ids:
                        # Create publishing destination
                        try:
                            response = guardduty_client.create_publishing_destination(
                                DetectorId=detector_id,
                                DestinationType='S3',  # or 'SNS' if supported
                                DestinationProperties={
                                    'DestinationArn': sns_topic_arn,
                                    'KmsKeyArn': ''  # Optional KMS key
                                }
                            )
                            
                            self.logger.info(f"Configured GuardDuty notifications for detector {detector_id} in region {region}")
                            results[region] = True
                            
                        except Exception as e:
                            self.logger.error(f"Failed to configure notifications for detector {detector_id}: {str(e)}")
                            results[region] = False
                            
                except Exception as e:
                    self.logger.error(f"Failed to configure GuardDuty notifications in region {region}: {str(e)}")
                    results[region] = False
                    
        except Exception as e:
            self.logger.error(f"Failed to configure GuardDuty notifications: {str(e)}")
        
        return results
    
    def suppress_guardduty_finding(self, detector_id: str, finding_id: str, region: str) -> bool:
        """Suppress a GuardDuty finding"""
        try:
            guardduty_client = self.aws_client.get_client('guardduty', region)
            
            # Archive the finding
            guardduty_client.archive_findings(
                DetectorId=detector_id,
                FindingIds=[finding_id]
            )
            
            self.logger.info(f"Suppressed GuardDuty finding {finding_id} in region {region}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to suppress GuardDuty finding: {str(e)}")
            return False
    
    def create_guardduty_threat_intel_set(self, detector_id: str, region: str, 
                                        threat_intel_set_name: str, location: str, 
                                        format_type: str = 'TXT') -> Optional[str]:
        """Create a threat intelligence set in GuardDuty"""
        try:
            guardduty_client = self.aws_client.get_client('guardduty', region)
            
            response = guardduty_client.create_threat_intel_set(
                DetectorId=detector_id,
                Name=threat_intel_set_name,
                Format=format_type,
                Location=location,
                Activate=True
            )
            
            threat_intel_set_id = response.get('ThreatIntelSetId')
            self.logger.info(f"Created threat intelligence set {threat_intel_set_id} in region {region}")
            
            return threat_intel_set_id
            
        except Exception as e:
            self.logger.error(f"Failed to create threat intelligence set: {str(e)}")
            return None

