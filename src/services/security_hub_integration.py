import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from src.services.aws_client import AWSClient
from src.models.security import SecurityFinding, AWSResource, db

logger = logging.getLogger(__name__)

class SecurityHubIntegration:
    """Integration with AWS Security Hub for centralized security findings"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
        
        # Define severity mapping
        self.severity_mapping = {
            'INFORMATIONAL': 'informational',
            'LOW': 'low',
            'MEDIUM': 'medium',
            'HIGH': 'high',
            'CRITICAL': 'critical'
        }
        
        # Define compliance status mapping
        self.compliance_mapping = {
            'PASSED': 'compliant',
            'WARNING': 'warning',
            'FAILED': 'non_compliant',
            'NOT_AVAILABLE': 'unknown'
        }
        
        # Define workflow status mapping
        self.workflow_mapping = {
            'NEW': 'new',
            'NOTIFIED': 'notified',
            'RESOLVED': 'resolved',
            'SUPPRESSED': 'suppressed'
        }
    
    def sync_security_hub_findings(self, regions: List[str] = None) -> List[Dict[str, Any]]:
        """Sync findings from Security Hub across regions"""
        all_findings = []
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            for region in regions:
                self.logger.info(f"Syncing Security Hub findings from region: {region}")
                
                # Check if Security Hub is enabled in this region
                if not self._is_security_hub_enabled(region):
                    self.logger.warning(f"Security Hub not enabled in region {region}")
                    continue
                
                # Get findings from Security Hub
                findings = self._get_security_hub_findings(region)
                
                # Process and normalize findings
                for finding in findings:
                    processed_finding = self._process_security_hub_finding(finding, region)
                    if processed_finding:
                        all_findings.append(processed_finding)
                
        except Exception as e:
            self.logger.error(f"Failed to sync Security Hub findings: {str(e)}")
        
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
    
    def _is_security_hub_enabled(self, region: str) -> bool:
        """Check if Security Hub is enabled in the region"""
        try:
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Try to get hub details
            response = securityhub_client.describe_hub()
            return response.get('HubArn') is not None
            
        except securityhub_client.exceptions.InvalidAccessException:
            return False
        except Exception as e:
            self.logger.error(f"Failed to check Security Hub status in region {region}: {str(e)}")
            return False
    
    def _get_security_hub_findings(self, region: str) -> List[Dict[str, Any]]:
        """Get Security Hub findings from a specific region"""
        findings = []
        
        try:
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Get findings with pagination
            paginator = securityhub_client.get_paginator('get_findings')
            
            # Filter for recent findings (last 7 days)
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            
            page_iterator = paginator.paginate(
                Filters={
                    'UpdatedAt': [
                        {
                            'Start': seven_days_ago,
                            'End': datetime.utcnow()
                        }
                    ],
                    'RecordState': [
                        {
                            'Value': 'ACTIVE',
                            'Comparison': 'EQUALS'
                        }
                    ]
                },
                MaxItems=1000  # Limit to prevent excessive API calls
            )
            
            for page in page_iterator:
                findings.extend(page.get('Findings', []))
                
        except Exception as e:
            self.logger.error(f"Failed to get Security Hub findings from region {region}: {str(e)}")
        
        return findings
    
    def _process_security_hub_finding(self, finding: Dict[str, Any], region: str) -> Optional[Dict[str, Any]]:
        """Process and normalize Security Hub finding"""
        try:
            finding_id = finding.get('Id', '')
            product_arn = finding.get('ProductArn', '')
            generator_id = finding.get('GeneratorId', '')
            aws_account_id = finding.get('AwsAccountId', '')
            
            # Basic finding information
            title = finding.get('Title', '')
            description = finding.get('Description', '')
            severity = finding.get('Severity', {})
            
            # Map severity
            severity_label = severity.get('Label', 'MEDIUM')
            mapped_severity = self.severity_mapping.get(severity_label, 'medium')
            
            # Extract compliance information
            compliance = finding.get('Compliance', {})
            compliance_status = compliance.get('Status', 'NOT_AVAILABLE')
            mapped_compliance = self.compliance_mapping.get(compliance_status, 'unknown')
            
            # Extract workflow information
            workflow = finding.get('Workflow', {})
            workflow_status = workflow.get('Status', 'NEW')
            mapped_workflow = self.workflow_mapping.get(workflow_status, 'new')
            
            # Extract resource information
            resources = finding.get('Resources', [])
            resource_info = self._extract_security_hub_resources(resources)
            
            # Extract remediation information
            remediation = finding.get('Remediation', {})
            recommendation = remediation.get('Recommendation', {}).get('Text', '')
            
            if not recommendation:
                recommendation = self._generate_security_hub_recommendation(finding)
            
            # Extract additional context
            context = self._extract_security_hub_context(finding)
            
            # Determine finding type
            finding_type = self._determine_security_hub_finding_type(finding)
            
            processed_finding = {
                'type': 'security_hub_finding',
                'severity': mapped_severity,
                'title': title,
                'description': description,
                'recommendation': recommendation,
                'finding_type': finding_type,
                'source': 'AWS Security Hub',
                'external_id': finding_id,
                'compliance_status': mapped_compliance,
                'workflow_status': mapped_workflow,
                'context': {
                    'region': region,
                    'product_arn': product_arn,
                    'generator_id': generator_id,
                    'aws_account_id': aws_account_id,
                    'severity_score': severity.get('Normalized', 0),
                    'compliance_details': compliance,
                    'workflow_details': workflow,
                    'resource_info': resource_info,
                    **context
                }
            }
            
            return processed_finding
            
        except Exception as e:
            self.logger.error(f"Failed to process Security Hub finding: {str(e)}")
            return None
    
    def _extract_security_hub_resources(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract resource information from Security Hub finding"""
        resource_info = []
        
        for resource in resources:
            try:
                resource_data = {
                    'id': resource.get('Id', ''),
                    'type': resource.get('Type', ''),
                    'partition': resource.get('Partition', ''),
                    'region': resource.get('Region', ''),
                    'tags': resource.get('Tags', {}),
                    'details': {}
                }
                
                # Extract resource-specific details
                details = resource.get('Details', {})
                
                # AWS EC2 Instance details
                if 'AwsEc2Instance' in details:
                    ec2_details = details['AwsEc2Instance']
                    resource_data['details'].update({
                        'instance_type': ec2_details.get('Type'),
                        'image_id': ec2_details.get('ImageId'),
                        'vpc_id': ec2_details.get('VpcId'),
                        'subnet_id': ec2_details.get('SubnetId'),
                        'launched_at': ec2_details.get('LaunchedAt'),
                        'security_groups': ec2_details.get('SecurityGroups', []),
                        'network_interfaces': ec2_details.get('NetworkInterfaces', [])
                    })
                
                # AWS S3 Bucket details
                elif 'AwsS3Bucket' in details:
                    s3_details = details['AwsS3Bucket']
                    resource_data['details'].update({
                        'owner_id': s3_details.get('OwnerId'),
                        'owner_name': s3_details.get('OwnerName'),
                        'created_at': s3_details.get('CreatedAt'),
                        'server_side_encryption': s3_details.get('ServerSideEncryptionConfiguration', {}),
                        'bucket_lifecycle_configuration': s3_details.get('BucketLifecycleConfiguration', {}),
                        'public_access_block': s3_details.get('PublicAccessBlockConfiguration', {}),
                        'bucket_notification_configuration': s3_details.get('BucketNotificationConfiguration', {})
                    })
                
                # AWS IAM User details
                elif 'AwsIamUser' in details:
                    iam_details = details['AwsIamUser']
                    resource_data['details'].update({
                        'user_id': iam_details.get('UserId'),
                        'user_name': iam_details.get('UserName'),
                        'path': iam_details.get('Path'),
                        'created_date': iam_details.get('CreateDate'),
                        'user_policy_list': iam_details.get('UserPolicyList', []),
                        'group_list': iam_details.get('GroupList', []),
                        'attached_managed_policies': iam_details.get('AttachedManagedPolicies', []),
                        'permissions_boundary': iam_details.get('PermissionsBoundary', {})
                    })
                
                # AWS RDS DB Instance details
                elif 'AwsRdsDbInstance' in details:
                    rds_details = details['AwsRdsDbInstance']
                    resource_data['details'].update({
                        'db_instance_identifier': rds_details.get('DBInstanceIdentifier'),
                        'db_instance_class': rds_details.get('DBInstanceClass'),
                        'engine': rds_details.get('Engine'),
                        'engine_version': rds_details.get('EngineVersion'),
                        'publicly_accessible': rds_details.get('PubliclyAccessible'),
                        'storage_encrypted': rds_details.get('StorageEncrypted'),
                        'vpc_security_groups': rds_details.get('VpcSecurityGroups', []),
                        'db_security_groups': rds_details.get('DbSecurityGroups', []),
                        'backup_retention_period': rds_details.get('BackupRetentionPeriod'),
                        'multi_az': rds_details.get('MultiAz')
                    })
                
                # AWS Security Group details
                elif 'AwsEc2SecurityGroup' in details:
                    sg_details = details['AwsEc2SecurityGroup']
                    resource_data['details'].update({
                        'group_name': sg_details.get('GroupName'),
                        'group_id': sg_details.get('GroupId'),
                        'owner_id': sg_details.get('OwnerId'),
                        'vpc_id': sg_details.get('VpcId'),
                        'ip_permissions': sg_details.get('IpPermissions', []),
                        'ip_permissions_egress': sg_details.get('IpPermissionsEgress', [])
                    })
                
                resource_info.append(resource_data)
                
            except Exception as e:
                self.logger.error(f"Failed to extract resource details: {str(e)}")
                continue
        
        return resource_info
    
    def _extract_security_hub_context(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract additional context from Security Hub finding"""
        context = {}
        
        try:
            # Extract timestamps
            context.update({
                'created_at': finding.get('CreatedAt', ''),
                'updated_at': finding.get('UpdatedAt', ''),
                'first_observed_at': finding.get('FirstObservedAt', ''),
                'last_observed_at': finding.get('LastObservedAt', '')
            })
            
            # Extract source information
            source_url = finding.get('SourceUrl', '')
            if source_url:
                context['source_url'] = source_url
            
            # Extract malware information
            malware = finding.get('Malware', [])
            if malware:
                context['malware'] = [
                    {
                        'name': m.get('Name'),
                        'type': m.get('Type'),
                        'path': m.get('Path'),
                        'state': m.get('State')
                    }
                    for m in malware
                ]
            
            # Extract network information
            network = finding.get('Network', {})
            if network:
                context['network'] = {
                    'direction': network.get('Direction'),
                    'protocol': network.get('Protocol'),
                    'source_ip': network.get('SourceIpV4'),
                    'source_port': network.get('SourcePort'),
                    'destination_ip': network.get('DestinationIpV4'),
                    'destination_port': network.get('DestinationPort'),
                    'source_domain': network.get('SourceDomain'),
                    'destination_domain': network.get('DestinationDomain')
                }
            
            # Extract process information
            process = finding.get('Process', {})
            if process:
                context['process'] = {
                    'name': process.get('Name'),
                    'path': process.get('Path'),
                    'pid': process.get('Pid'),
                    'parent_pid': process.get('ParentPid'),
                    'launched_at': process.get('LaunchedAt'),
                    'terminated_at': process.get('TerminatedAt')
                }
            
            # Extract threat intelligence
            threat_intel_indicators = finding.get('ThreatIntelIndicators', [])
            if threat_intel_indicators:
                context['threat_intelligence'] = [
                    {
                        'type': ti.get('Type'),
                        'value': ti.get('Value'),
                        'category': ti.get('Category'),
                        'last_observed_at': ti.get('LastObservedAt'),
                        'source': ti.get('Source'),
                        'source_url': ti.get('SourceUrl')
                    }
                    for ti in threat_intel_indicators
                ]
            
            # Extract user-defined fields
            user_defined_fields = finding.get('UserDefinedFields', {})
            if user_defined_fields:
                context['user_defined_fields'] = user_defined_fields
            
            # Extract verification state
            verification_state = finding.get('VerificationState', '')
            if verification_state:
                context['verification_state'] = verification_state
            
            # Extract criticality
            criticality = finding.get('Criticality', 0)
            if criticality:
                context['criticality'] = criticality
            
            # Extract confidence
            confidence = finding.get('Confidence', 0)
            if confidence:
                context['confidence'] = confidence
            
        except Exception as e:
            self.logger.error(f"Failed to extract Security Hub context: {str(e)}")
        
        return context
    
    def _determine_security_hub_finding_type(self, finding: Dict[str, Any]) -> str:
        """Determine finding type based on Security Hub finding"""
        try:
            # Check product ARN to determine source
            product_arn = finding.get('ProductArn', '')
            generator_id = finding.get('GeneratorId', '')
            title = finding.get('Title', '').lower()
            
            # GuardDuty findings
            if 'guardduty' in product_arn.lower():
                if 'backdoor' in title or 'trojan' in title:
                    return 'malware'
                elif 'cryptocurrency' in title:
                    return 'cryptocurrency_mining'
                elif 'recon' in title:
                    return 'reconnaissance'
                elif 'behavior' in title:
                    return 'anomaly'
                else:
                    return 'security_threat'
            
            # Config findings
            elif 'config' in product_arn.lower():
                return 'compliance_violation'
            
            # Inspector findings
            elif 'inspector' in product_arn.lower():
                if 'cve' in title or 'vulnerability' in title:
                    return 'vulnerability'
                else:
                    return 'security_assessment'
            
            # Security Hub security standards findings
            elif 'security-control' in generator_id.lower():
                if 'encryption' in title:
                    return 'encryption_issue'
                elif 'access' in title or 'permission' in title:
                    return 'access_control_issue'
                elif 'logging' in title:
                    return 'logging_issue'
                elif 'network' in title or 'security group' in title:
                    return 'network_security_issue'
                else:
                    return 'compliance_violation'
            
            # Macie findings
            elif 'macie' in product_arn.lower():
                return 'data_security_issue'
            
            # Default categorization based on title keywords
            if 'malware' in title or 'virus' in title:
                return 'malware'
            elif 'vulnerability' in title or 'cve' in title:
                return 'vulnerability'
            elif 'compliance' in title:
                return 'compliance_violation'
            elif 'encryption' in title:
                return 'encryption_issue'
            elif 'access' in title or 'permission' in title:
                return 'access_control_issue'
            elif 'network' in title:
                return 'network_security_issue'
            elif 'data' in title:
                return 'data_security_issue'
            else:
                return 'security_finding'
                
        except Exception as e:
            self.logger.error(f"Failed to determine finding type: {str(e)}")
            return 'security_finding'
    
    def _generate_security_hub_recommendation(self, finding: Dict[str, Any]) -> str:
        """Generate recommendation for Security Hub finding"""
        try:
            finding_type = self._determine_security_hub_finding_type(finding)
            title = finding.get('Title', '').lower()
            
            recommendations = {
                'malware': 'Quarantine the affected resource and run comprehensive malware scans. Review security controls and update antivirus definitions.',
                'vulnerability': 'Apply security patches and updates. Review vulnerability management processes.',
                'compliance_violation': 'Review and update configurations to meet compliance requirements. Implement necessary security controls.',
                'encryption_issue': 'Enable encryption for data at rest and in transit. Review encryption key management practices.',
                'access_control_issue': 'Review and update access controls. Implement principle of least privilege.',
                'network_security_issue': 'Review network security configurations. Update security group rules and network ACLs.',
                'data_security_issue': 'Review data classification and protection measures. Implement appropriate data security controls.',
                'logging_issue': 'Enable comprehensive logging and monitoring. Review log retention and analysis processes.',
                'cryptocurrency_mining': 'Terminate cryptocurrency mining activities immediately. Check for unauthorized software and review resource usage.',
                'reconnaissance': 'Monitor for follow-up attacks. Implement additional network monitoring and access controls.',
                'anomaly': 'Investigate the unusual behavior pattern. Review user activities and system logs for anomalies.'
            }
            
            base_recommendation = recommendations.get(finding_type, 
                'Review this security finding and implement appropriate remediation measures based on your security policies.')
            
            # Add specific recommendations based on title keywords
            if 'public' in title and 's3' in title:
                base_recommendation += ' Ensure S3 buckets are not publicly accessible unless required.'
            elif 'mfa' in title:
                base_recommendation += ' Enable multi-factor authentication for all users.'
            elif 'root' in title:
                base_recommendation += ' Avoid using root account for daily operations. Use IAM users instead.'
            elif 'cloudtrail' in title:
                base_recommendation += ' Ensure CloudTrail is enabled and properly configured for audit logging.'
            
            return base_recommendation
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendation: {str(e)}")
            return 'Review this security finding and take appropriate remediation actions.'
    
    def enable_security_hub(self, regions: List[str] = None, enable_standards: bool = True) -> Dict[str, bool]:
        """Enable Security Hub in specified regions"""
        results = {}
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            for region in regions:
                try:
                    securityhub_client = self.aws_client.get_client('securityhub', region)
                    
                    # Check if already enabled
                    if self._is_security_hub_enabled(region):
                        results[region] = True
                        continue
                    
                    # Enable Security Hub
                    response = securityhub_client.enable_security_hub(
                        Tags={
                            'Environment': 'Production',
                            'ManagedBy': 'CloudSecurityAutomation'
                        },
                        EnableDefaultStandards=enable_standards
                    )
                    
                    hub_arn = response.get('HubArn')
                    if hub_arn:
                        self.logger.info(f"Security Hub enabled in region {region} with ARN {hub_arn}")
                        results[region] = True
                    else:
                        results[region] = False
                        
                except Exception as e:
                    self.logger.error(f"Failed to enable Security Hub in region {region}: {str(e)}")
                    results[region] = False
                    
        except Exception as e:
            self.logger.error(f"Failed to enable Security Hub: {str(e)}")
        
        return results
    
    def get_security_standards_subscriptions(self, region: str) -> List[Dict[str, Any]]:
        """Get Security Hub standards subscriptions for a region"""
        subscriptions = []
        
        try:
            if not self._is_security_hub_enabled(region):
                return subscriptions
            
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Get standards subscriptions
            response = securityhub_client.get_enabled_standards()
            
            for subscription in response.get('StandardsSubscriptions', []):
                subscriptions.append({
                    'standards_subscription_arn': subscription.get('StandardsSubscriptionArn'),
                    'standards_arn': subscription.get('StandardsArn'),
                    'standards_input': subscription.get('StandardsInput', {}),
                    'standards_status': subscription.get('StandardsStatus')
                })
                
        except Exception as e:
            self.logger.error(f"Failed to get standards subscriptions for region {region}: {str(e)}")
        
        return subscriptions
    
    def enable_security_standard(self, region: str, standards_arn: str) -> bool:
        """Enable a specific security standard in Security Hub"""
        try:
            if not self._is_security_hub_enabled(region):
                return False
            
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Enable the standard
            response = securityhub_client.batch_enable_standards(
                StandardsSubscriptionRequests=[
                    {
                        'StandardsArn': standards_arn,
                        'StandardsInput': {}
                    }
                ]
            )
            
            subscriptions = response.get('StandardsSubscriptions', [])
            if subscriptions:
                self.logger.info(f"Enabled security standard {standards_arn} in region {region}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to enable security standard: {str(e)}")
            return False
    
    def update_finding_workflow(self, region: str, finding_id: str, workflow_status: str, note: str = '') -> bool:
        """Update workflow status of a Security Hub finding"""
        try:
            if not self._is_security_hub_enabled(region):
                return False
            
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Update finding workflow
            response = securityhub_client.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': finding_id,
                        'ProductArn': ''  # Will be filled automatically
                    }
                ],
                Workflow={
                    'Status': workflow_status.upper()
                },
                Note={
                    'Text': note,
                    'UpdatedBy': 'CloudSecurityAutomation'
                } if note else {}
            )
            
            processed_findings = response.get('ProcessedFindings', [])
            if processed_findings:
                self.logger.info(f"Updated workflow status for finding {finding_id} to {workflow_status}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to update finding workflow: {str(e)}")
            return False
    
    def create_custom_insight(self, region: str, name: str, filters: Dict[str, Any], 
                            group_by_attribute: str) -> Optional[str]:
        """Create a custom insight in Security Hub"""
        try:
            if not self._is_security_hub_enabled(region):
                return None
            
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Create insight
            response = securityhub_client.create_insight(
                Name=name,
                Filters=filters,
                GroupByAttribute=group_by_attribute
            )
            
            insight_arn = response.get('InsightArn')
            if insight_arn:
                self.logger.info(f"Created custom insight {name} in region {region}")
                return insight_arn
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to create custom insight: {str(e)}")
            return None
    
    def get_security_hub_statistics(self, regions: List[str] = None) -> Dict[str, Any]:
        """Get Security Hub statistics across regions"""
        statistics = {
            'total_findings': 0,
            'findings_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0},
            'findings_by_compliance': {'compliant': 0, 'non_compliant': 0, 'warning': 0, 'unknown': 0},
            'findings_by_workflow': {'new': 0, 'notified': 0, 'resolved': 0, 'suppressed': 0},
            'regions_enabled': 0,
            'regions_total': 0,
            'standards_enabled': [],
            'top_finding_types': {},
            'recent_findings_count': 0
        }
        
        try:
            if not regions:
                regions = self._get_enabled_regions()
            
            statistics['regions_total'] = len(regions)
            
            for region in regions:
                if self._is_security_hub_enabled(region):
                    statistics['regions_enabled'] += 1
                    
                    # Get findings statistics
                    findings = self._get_security_hub_findings(region)
                    statistics['total_findings'] += len(findings)
                    
                    for finding in findings:
                        # Count by severity
                        severity = finding.get('Severity', {}).get('Label', 'MEDIUM')
                        mapped_severity = self.severity_mapping.get(severity, 'medium')
                        statistics['findings_by_severity'][mapped_severity] += 1
                        
                        # Count by compliance
                        compliance = finding.get('Compliance', {}).get('Status', 'NOT_AVAILABLE')
                        mapped_compliance = self.compliance_mapping.get(compliance, 'unknown')
                        statistics['findings_by_compliance'][mapped_compliance] += 1
                        
                        # Count by workflow
                        workflow = finding.get('Workflow', {}).get('Status', 'NEW')
                        mapped_workflow = self.workflow_mapping.get(workflow, 'new')
                        statistics['findings_by_workflow'][mapped_workflow] += 1
                        
                        # Count by type
                        finding_type = self._determine_security_hub_finding_type(finding)
                        statistics['top_finding_types'][finding_type] = statistics['top_finding_types'].get(finding_type, 0) + 1
                        
                        # Count recent findings (last 24 hours)
                        updated_at = finding.get('UpdatedAt', '')
                        if updated_at:
                            try:
                                update_time = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                                if (datetime.now(update_time.tzinfo) - update_time).days < 1:
                                    statistics['recent_findings_count'] += 1
                            except:
                                pass
                    
                    # Get standards information
                    standards = self.get_security_standards_subscriptions(region)
                    for standard in standards:
                        standard_name = standard['standards_arn'].split('/')[-1]
                        if standard_name not in statistics['standards_enabled']:
                            statistics['standards_enabled'].append(standard_name)
            
            # Get top finding types
            if statistics['top_finding_types']:
                statistics['top_finding_types'] = dict(
                    sorted(statistics['top_finding_types'].items(), 
                          key=lambda x: x[1], reverse=True)[:10]
                )
                
        except Exception as e:
            self.logger.error(f"Failed to get Security Hub statistics: {str(e)}")
        
        return statistics
    
    def send_findings_to_security_hub(self, findings: List[Dict[str, Any]], region: str) -> bool:
        """Send custom findings to Security Hub"""
        try:
            if not self._is_security_hub_enabled(region):
                return False
            
            securityhub_client = self.aws_client.get_client('securityhub', region)
            
            # Format findings for Security Hub
            formatted_findings = []
            
            for finding in findings:
                formatted_finding = {
                    'SchemaVersion': '2018-10-08',
                    'Id': finding.get('external_id', f"custom-{finding.get('id', '')}"),
                    'ProductArn': f"arn:aws:securityhub:{region}:{self.aws_client.account_id}:product/{self.aws_client.account_id}/default",
                    'GeneratorId': 'cloud-security-automation',
                    'AwsAccountId': self.aws_client.account_id,
                    'CreatedAt': datetime.utcnow().isoformat() + 'Z',
                    'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
                    'Severity': {
                        'Label': finding.get('severity', 'MEDIUM').upper(),
                        'Normalized': self._get_normalized_severity(finding.get('severity', 'medium'))
                    },
                    'Title': finding.get('title', 'Security Finding'),
                    'Description': finding.get('description', 'Custom security finding'),
                    'Remediation': {
                        'Recommendation': {
                            'Text': finding.get('recommendation', 'Review and remediate this finding')
                        }
                    },
                    'Resources': self._format_resources_for_security_hub(finding.get('context', {}).get('resource_info', []))
                }
                
                formatted_findings.append(formatted_finding)
            
            # Send findings in batches (max 100 per batch)
            batch_size = 100
            for i in range(0, len(formatted_findings), batch_size):
                batch = formatted_findings[i:i + batch_size]
                
                response = securityhub_client.batch_import_findings(
                    Findings=batch
                )
                
                failed_count = response.get('FailedCount', 0)
                success_count = response.get('SuccessCount', 0)
                
                self.logger.info(f"Sent {success_count} findings to Security Hub, {failed_count} failed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send findings to Security Hub: {str(e)}")
            return False
    
    def _get_normalized_severity(self, severity: str) -> int:
        """Get normalized severity score for Security Hub"""
        severity_scores = {
            'informational': 0,
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
        
        return severity_scores.get(severity.lower(), 50)
    
    def _format_resources_for_security_hub(self, resource_info: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format resource information for Security Hub"""
        formatted_resources = []
        
        for resource in resource_info:
            formatted_resource = {
                'Id': resource.get('resource_id', ''),
                'Type': resource.get('resource_type', ''),
                'Partition': 'aws',
                'Region': resource.get('region', ''),
                'Tags': resource.get('tags', {})
            }
            
            formatted_resources.append(formatted_resource)
        
        return formatted_resources

