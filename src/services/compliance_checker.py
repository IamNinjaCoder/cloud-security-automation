import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from src.services.aws_client import AWSClient
from src.models.security import AWSResource, SecurityFinding, db

logger = logging.getLogger(__name__)

class ComplianceChecker:
    """Comprehensive compliance checking for various standards"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
        
        # Define compliance frameworks
        self.frameworks = {
            'CIS': self._get_cis_checks(),
            'SOC2': self._get_soc2_checks(),
            'HIPAA': self._get_hipaa_checks(),
            'GDPR': self._get_gdpr_checks(),
            'NIST': self._get_nist_checks()
        }
    
    def run_compliance_check(self, framework: str, resources: List[AWSResource]) -> List[Dict[str, Any]]:
        """Run compliance checks for a specific framework"""
        findings = []
        
        if framework not in self.frameworks:
            self.logger.error(f"Unknown compliance framework: {framework}")
            return findings
        
        checks = self.frameworks[framework]
        
        for check in checks:
            try:
                result = self._execute_compliance_check(check, resources)
                if result:
                    findings.extend(result)
            except Exception as e:
                self.logger.error(f"Failed to execute compliance check {check['id']}: {str(e)}")
        
        return findings
    
    def _execute_compliance_check(self, check: Dict[str, Any], resources: List[AWSResource]) -> List[Dict[str, Any]]:
        """Execute a specific compliance check"""
        findings = []
        
        # Filter resources by type if specified
        applicable_resources = resources
        if check.get('resource_types'):
            applicable_resources = [
                r for r in resources 
                if r.resource_type in check['resource_types']
            ]
        
        # Execute the check function
        check_function = getattr(self, check['function'], None)
        if check_function:
            findings = check_function(applicable_resources, check)
        
        return findings
    
    def _get_cis_checks(self) -> List[Dict[str, Any]]:
        """Get CIS AWS Foundations Benchmark checks"""
        return [
            {
                'id': 'CIS-1.1',
                'title': 'Avoid the use of the "root" account',
                'description': 'The "root" account has unrestricted access to all resources in the AWS account',
                'severity': 'critical',
                'function': '_check_root_account_usage',
                'resource_types': ['IAM_User']
            },
            {
                'id': 'CIS-1.2',
                'title': 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
                'description': 'Multi-factor authentication (MFA) adds an extra layer of protection on top of a user name and password',
                'severity': 'high',
                'function': '_check_iam_mfa',
                'resource_types': ['IAM_User']
            },
            {
                'id': 'CIS-1.3',
                'title': 'Ensure credentials unused for 90 days or greater are disabled',
                'description': 'AWS IAM users can access AWS resources using different types of credentials',
                'severity': 'medium',
                'function': '_check_unused_credentials',
                'resource_types': ['IAM_User']
            },
            {
                'id': 'CIS-2.1',
                'title': 'Ensure CloudTrail is enabled in all regions',
                'description': 'AWS CloudTrail is a web service that records AWS API calls',
                'severity': 'high',
                'function': '_check_cloudtrail_enabled',
                'resource_types': ['CloudTrail_Trail']
            },
            {
                'id': 'CIS-2.2',
                'title': 'Ensure CloudTrail log file validation is enabled',
                'description': 'CloudTrail log file validation creates a digitally signed digest file',
                'severity': 'medium',
                'function': '_check_cloudtrail_validation',
                'resource_types': ['CloudTrail_Trail']
            },
            {
                'id': 'CIS-2.3',
                'title': 'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
                'description': 'CloudTrail logs contain sensitive information',
                'severity': 'critical',
                'function': '_check_cloudtrail_bucket_access',
                'resource_types': ['S3_Bucket']
            },
            {
                'id': 'CIS-2.4',
                'title': 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
                'description': 'Sending CloudTrail logs to CloudWatch Logs enables real-time monitoring',
                'severity': 'medium',
                'function': '_check_cloudtrail_cloudwatch',
                'resource_types': ['CloudTrail_Trail']
            },
            {
                'id': 'CIS-4.1',
                'title': 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
                'description': 'Security groups provide stateful filtering of ingress/egress network traffic',
                'severity': 'critical',
                'function': '_check_ssh_access',
                'resource_types': ['EC2_SecurityGroup']
            },
            {
                'id': 'CIS-4.2',
                'title': 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389',
                'description': 'Security groups provide stateful filtering of ingress/egress network traffic',
                'severity': 'critical',
                'function': '_check_rdp_access',
                'resource_types': ['EC2_SecurityGroup']
            },
            {
                'id': 'CIS-4.3',
                'title': 'Ensure VPC flow logging is enabled in all VPCs',
                'description': 'VPC Flow Logs capture information about IP traffic',
                'severity': 'medium',
                'function': '_check_vpc_flow_logs',
                'resource_types': ['VPC']
            }
        ]
    
    def _get_soc2_checks(self) -> List[Dict[str, Any]]:
        """Get SOC 2 compliance checks"""
        return [
            {
                'id': 'SOC2-CC6.1',
                'title': 'Logical and physical access controls',
                'description': 'The entity implements logical and physical access controls',
                'severity': 'high',
                'function': '_check_access_controls',
                'resource_types': ['IAM_User', 'IAM_Role', 'EC2_SecurityGroup']
            },
            {
                'id': 'SOC2-CC6.7',
                'title': 'Data transmission and disposal',
                'description': 'The entity restricts the transmission, movement, and disposal of information',
                'severity': 'high',
                'function': '_check_data_encryption',
                'resource_types': ['S3_Bucket', 'RDS_Instance', 'EBS_Volume']
            },
            {
                'id': 'SOC2-CC7.1',
                'title': 'System monitoring',
                'description': 'The entity uses detection and monitoring procedures',
                'severity': 'medium',
                'function': '_check_monitoring',
                'resource_types': ['CloudTrail_Trail', 'CloudWatch_Alarm']
            }
        ]
    
    def _get_hipaa_checks(self) -> List[Dict[str, Any]]:
        """Get HIPAA compliance checks"""
        return [
            {
                'id': 'HIPAA-164.312(a)(1)',
                'title': 'Access Control',
                'description': 'Implement technical safeguards to allow access only to those persons or software programs that have been granted access rights',
                'severity': 'critical',
                'function': '_check_access_controls',
                'resource_types': ['IAM_User', 'IAM_Role']
            },
            {
                'id': 'HIPAA-164.312(e)(1)',
                'title': 'Transmission Security',
                'description': 'Implement technical safeguards to guard against unauthorized access to electronic protected health information',
                'severity': 'critical',
                'function': '_check_transmission_security',
                'resource_types': ['S3_Bucket', 'RDS_Instance']
            }
        ]
    
    def _get_gdpr_checks(self) -> List[Dict[str, Any]]:
        """Get GDPR compliance checks"""
        return [
            {
                'id': 'GDPR-Art32',
                'title': 'Security of processing',
                'description': 'Implement appropriate technical and organisational measures to ensure a level of security',
                'severity': 'high',
                'function': '_check_data_security',
                'resource_types': ['S3_Bucket', 'RDS_Instance', 'EBS_Volume']
            }
        ]
    
    def _get_nist_checks(self) -> List[Dict[str, Any]]:
        """Get NIST Cybersecurity Framework checks"""
        return [
            {
                'id': 'NIST-ID.AM-1',
                'title': 'Physical devices and systems within the organization are inventoried',
                'description': 'Asset management processes and procedures are established',
                'severity': 'medium',
                'function': '_check_asset_inventory',
                'resource_types': ['EC2_Instance', 'RDS_Instance']
            },
            {
                'id': 'NIST-PR.AC-1',
                'title': 'Identities and credentials are issued, managed, verified, revoked, and audited',
                'description': 'Identity management and access control processes',
                'severity': 'high',
                'function': '_check_identity_management',
                'resource_types': ['IAM_User', 'IAM_Role']
            }
        ]
    
    # Compliance check implementations
    
    def _check_root_account_usage(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for root account usage"""
        findings = []
        
        try:
            # This would require CloudTrail log analysis to detect root account usage
            # For now, we'll check if root account has access keys
            iam_client = self.aws_client.get_client('iam')
            
            try:
                account_summary = iam_client.get_account_summary()
                root_access_keys = account_summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
                
                if root_access_keys > 0:
                    findings.append({
                        'type': 'compliance',
                        'severity': check['severity'],
                        'title': check['title'],
                        'description': 'Root account has access keys configured',
                        'recommendation': 'Remove root account access keys and use IAM users instead',
                        'compliance_standard': 'CIS',
                        'rule_id': check['id']
                    })
            except Exception:
                pass
                
        except Exception as e:
            self.logger.error(f"Failed to check root account usage: {str(e)}")
        
        return findings
    
    def _check_iam_mfa(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check IAM users for MFA"""
        findings = []
        
        try:
            iam_client = self.aws_client.get_client('iam')
            
            # Get all users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    # Check if user has console access
                    try:
                        login_profile = iam_client.get_login_profile(UserName=user_name)
                        
                        # User has console access, check for MFA
                        mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
                        
                        if not mfa_devices['MFADevices']:
                            findings.append({
                                'type': 'compliance',
                                'severity': check['severity'],
                                'title': f'IAM user {user_name} missing MFA',
                                'description': f'IAM user {user_name} has console access but no MFA device configured',
                                'recommendation': 'Enable MFA for all IAM users with console access',
                                'compliance_standard': 'CIS',
                                'rule_id': check['id'],
                                'context': {
                                    'user_name': user_name
                                }
                            })
                            
                    except iam_client.exceptions.NoSuchEntityException:
                        # User doesn't have console access, skip MFA check
                        pass
                    except Exception:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Failed to check IAM MFA: {str(e)}")
        
        return findings
    
    def _check_unused_credentials(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for unused credentials"""
        findings = []
        
        try:
            iam_client = self.aws_client.get_client('iam')
            
            # Get all users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    # Check access keys
                    access_keys = iam_client.list_access_keys(UserName=user_name)
                    
                    for key_metadata in access_keys['AccessKeyMetadata']:
                        access_key_id = key_metadata['AccessKeyId']
                        
                        try:
                            last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                            last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                            
                            if last_used_date:
                                days_since_use = (datetime.now(last_used_date.tzinfo) - last_used_date).days
                                
                                if days_since_use >= 90:
                                    findings.append({
                                        'type': 'compliance',
                                        'severity': check['severity'],
                                        'title': f'Unused access key for user {user_name}',
                                        'description': f'Access key {access_key_id} for user {user_name} has not been used for {days_since_use} days',
                                        'recommendation': 'Disable or delete unused access keys',
                                        'compliance_standard': 'CIS',
                                        'rule_id': check['id'],
                                        'context': {
                                            'user_name': user_name,
                                            'access_key_id': access_key_id,
                                            'days_since_use': days_since_use
                                        }
                                    })
                            else:
                                # Never used
                                findings.append({
                                    'type': 'compliance',
                                    'severity': check['severity'],
                                    'title': f'Never used access key for user {user_name}',
                                    'description': f'Access key {access_key_id} for user {user_name} has never been used',
                                    'recommendation': 'Delete access keys that have never been used',
                                    'compliance_standard': 'CIS',
                                    'rule_id': check['id'],
                                    'context': {
                                        'user_name': user_name,
                                        'access_key_id': access_key_id
                                    }
                                })
                                
                        except Exception:
                            pass
                            
        except Exception as e:
            self.logger.error(f"Failed to check unused credentials: {str(e)}")
        
        return findings
    
    def _check_cloudtrail_enabled(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if CloudTrail is enabled in all regions"""
        findings = []
        
        try:
            # Get all regions
            ec2_client = self.aws_client.get_client('ec2')
            regions_response = ec2_client.describe_regions()
            all_regions = [region['RegionName'] for region in regions_response['Regions']]
            
            # Check each region for CloudTrail
            regions_with_trails = set()
            
            for resource in resources:
                if resource.resource_type == 'CloudTrail_Trail':
                    configuration = json.loads(resource.configuration)
                    if configuration.get('is_multi_region_trail'):
                        # Multi-region trail covers all regions
                        regions_with_trails.update(all_regions)
                    else:
                        regions_with_trails.add(resource.region)
            
            # Check for regions without trails
            regions_without_trails = set(all_regions) - regions_with_trails
            
            if regions_without_trails:
                findings.append({
                    'type': 'compliance',
                    'severity': check['severity'],
                    'title': 'CloudTrail not enabled in all regions',
                    'description': f'CloudTrail is not enabled in regions: {", ".join(regions_without_trails)}',
                    'recommendation': 'Enable CloudTrail in all regions or use a multi-region trail',
                    'compliance_standard': 'CIS',
                    'rule_id': check['id'],
                    'context': {
                        'missing_regions': list(regions_without_trails)
                    }
                })
                
        except Exception as e:
            self.logger.error(f"Failed to check CloudTrail enabled: {str(e)}")
        
        return findings
    
    def _check_cloudtrail_validation(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if CloudTrail log file validation is enabled"""
        findings = []
        
        for resource in resources:
            if resource.resource_type == 'CloudTrail_Trail':
                try:
                    configuration = json.loads(resource.configuration)
                    
                    if not configuration.get('log_file_validation_enabled', False):
                        findings.append({
                            'type': 'compliance',
                            'severity': check['severity'],
                            'title': f'CloudTrail {resource.resource_id} log validation disabled',
                            'description': f'CloudTrail trail {resource.resource_id} does not have log file validation enabled',
                            'recommendation': 'Enable log file validation for CloudTrail trails',
                            'compliance_standard': 'CIS',
                            'rule_id': check['id'],
                            'context': {
                                'trail_name': resource.resource_id
                            }
                        })
                        
                except Exception as e:
                    self.logger.error(f"Failed to check CloudTrail validation for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_cloudtrail_bucket_access(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if CloudTrail S3 bucket is not publicly accessible"""
        findings = []
        
        # This would require cross-referencing CloudTrail trails with their S3 buckets
        # For now, we'll check all S3 buckets for public access
        for resource in resources:
            if resource.resource_type == 'S3_Bucket':
                try:
                    configuration = json.loads(resource.configuration)
                    
                    # Check for public access
                    if configuration.get('public_read_access') or configuration.get('public_write_access'):
                        # Check if this bucket is used by CloudTrail
                        bucket_name = resource.resource_id
                        
                        # This is a simplified check - in practice, you'd query CloudTrail configurations
                        if 'cloudtrail' in bucket_name.lower() or 'trail' in bucket_name.lower():
                            findings.append({
                                'type': 'compliance',
                                'severity': check['severity'],
                                'title': f'CloudTrail S3 bucket {bucket_name} is publicly accessible',
                                'description': f'S3 bucket {bucket_name} used for CloudTrail logs is publicly accessible',
                                'recommendation': 'Remove public access from CloudTrail S3 buckets',
                                'compliance_standard': 'CIS',
                                'rule_id': check['id'],
                                'context': {
                                    'bucket_name': bucket_name
                                }
                            })
                            
                except Exception as e:
                    self.logger.error(f"Failed to check CloudTrail bucket access for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_cloudtrail_cloudwatch(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if CloudTrail trails are integrated with CloudWatch Logs"""
        findings = []
        
        for resource in resources:
            if resource.resource_type == 'CloudTrail_Trail':
                try:
                    configuration = json.loads(resource.configuration)
                    
                    if not configuration.get('cloud_watch_logs_log_group_arn'):
                        findings.append({
                            'type': 'compliance',
                            'severity': check['severity'],
                            'title': f'CloudTrail {resource.resource_id} not integrated with CloudWatch',
                            'description': f'CloudTrail trail {resource.resource_id} is not sending logs to CloudWatch',
                            'recommendation': 'Configure CloudTrail to send logs to CloudWatch Logs',
                            'compliance_standard': 'CIS',
                            'rule_id': check['id'],
                            'context': {
                                'trail_name': resource.resource_id
                            }
                        })
                        
                except Exception as e:
                    self.logger.error(f"Failed to check CloudTrail CloudWatch integration for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_ssh_access(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for SSH access from 0.0.0.0/0"""
        findings = []
        
        for resource in resources:
            if resource.resource_type == 'EC2_SecurityGroup':
                try:
                    configuration = json.loads(resource.configuration)
                    inbound_rules = configuration.get('inbound_rules', [])
                    
                    for rule in inbound_rules:
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 65535)
                        
                        # Check if port 22 is in the range
                        if from_port <= 22 <= to_port:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    findings.append({
                                        'type': 'compliance',
                                        'severity': check['severity'],
                                        'title': f'Security group {resource.resource_id} allows SSH from anywhere',
                                        'description': f'Security group {resource.resource_id} allows SSH access (port 22) from 0.0.0.0/0',
                                        'recommendation': 'Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager',
                                        'compliance_standard': 'CIS',
                                        'rule_id': check['id'],
                                        'context': {
                                            'security_group_id': resource.resource_id,
                                            'port': 22
                                        }
                                    })
                                    
                except Exception as e:
                    self.logger.error(f"Failed to check SSH access for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_rdp_access(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for RDP access from 0.0.0.0/0"""
        findings = []
        
        for resource in resources:
            if resource.resource_type == 'EC2_SecurityGroup':
                try:
                    configuration = json.loads(resource.configuration)
                    inbound_rules = configuration.get('inbound_rules', [])
                    
                    for rule in inbound_rules:
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 65535)
                        
                        # Check if port 3389 is in the range
                        if from_port <= 3389 <= to_port:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    findings.append({
                                        'type': 'compliance',
                                        'severity': check['severity'],
                                        'title': f'Security group {resource.resource_id} allows RDP from anywhere',
                                        'description': f'Security group {resource.resource_id} allows RDP access (port 3389) from 0.0.0.0/0',
                                        'recommendation': 'Restrict RDP access to specific IP ranges or use AWS Systems Manager Session Manager',
                                        'compliance_standard': 'CIS',
                                        'rule_id': check['id'],
                                        'context': {
                                            'security_group_id': resource.resource_id,
                                            'port': 3389
                                        }
                                    })
                                    
                except Exception as e:
                    self.logger.error(f"Failed to check RDP access for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_vpc_flow_logs(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if VPC flow logging is enabled"""
        findings = []
        
        for resource in resources:
            if resource.resource_type == 'VPC':
                try:
                    # Check if VPC has flow logs enabled
                    ec2_client = self.aws_client.get_client('ec2', resource.region)
                    
                    flow_logs = ec2_client.describe_flow_logs(
                        Filters=[
                            {
                                'Name': 'resource-id',
                                'Values': [resource.resource_id]
                            }
                        ]
                    )
                    
                    if not flow_logs['FlowLogs']:
                        findings.append({
                            'type': 'compliance',
                            'severity': check['severity'],
                            'title': f'VPC {resource.resource_id} flow logs disabled',
                            'description': f'VPC {resource.resource_id} does not have flow logs enabled',
                            'recommendation': 'Enable VPC flow logs to capture IP traffic information',
                            'compliance_standard': 'CIS',
                            'rule_id': check['id'],
                            'context': {
                                'vpc_id': resource.resource_id
                            }
                        })
                        
                except Exception as e:
                    self.logger.error(f"Failed to check VPC flow logs for {resource.resource_id}: {str(e)}")
        
        return findings
    
    # Additional compliance check implementations for SOC2, HIPAA, GDPR, NIST
    
    def _check_access_controls(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check access controls implementation"""
        findings = []
        
        # This would implement comprehensive access control checks
        # For now, we'll do basic checks
        
        for resource in resources:
            if resource.resource_type == 'IAM_User':
                # Check for users with administrative access
                try:
                    configuration = json.loads(resource.configuration)
                    attached_policies = configuration.get('attached_policies', [])
                    
                    for policy in attached_policies:
                        if 'Administrator' in policy.get('PolicyName', ''):
                            findings.append({
                                'type': 'compliance',
                                'severity': check['severity'],
                                'title': f'IAM user {resource.resource_id} has administrative access',
                                'description': f'IAM user {resource.resource_id} has administrative policy attached',
                                'recommendation': 'Apply principle of least privilege',
                                'compliance_standard': check.get('compliance_standard', 'SOC2'),
                                'rule_id': check['id']
                            })
                            
                except Exception as e:
                    self.logger.error(f"Failed to check access controls for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_data_encryption(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check data encryption implementation"""
        findings = []
        
        for resource in resources:
            try:
                configuration = json.loads(resource.configuration)
                
                if resource.resource_type == 'S3_Bucket':
                    if not configuration.get('encryption_enabled', False):
                        findings.append({
                            'type': 'compliance',
                            'severity': check['severity'],
                            'title': f'S3 bucket {resource.resource_id} encryption disabled',
                            'description': f'S3 bucket {resource.resource_id} does not have encryption enabled',
                            'recommendation': 'Enable server-side encryption for S3 bucket',
                            'compliance_standard': check.get('compliance_standard', 'SOC2'),
                            'rule_id': check['id']
                        })
                
                elif resource.resource_type == 'RDS_Instance':
                    if not configuration.get('encrypted', False):
                        findings.append({
                            'type': 'compliance',
                            'severity': check['severity'],
                            'title': f'RDS instance {resource.resource_id} encryption disabled',
                            'description': f'RDS instance {resource.resource_id} does not have encryption at rest enabled',
                            'recommendation': 'Enable encryption at rest for RDS instance',
                            'compliance_standard': check.get('compliance_standard', 'SOC2'),
                            'rule_id': check['id']
                        })
                
                elif resource.resource_type == 'EBS_Volume':
                    if not configuration.get('encrypted', False):
                        findings.append({
                            'type': 'compliance',
                            'severity': check['severity'],
                            'title': f'EBS volume {resource.resource_id} encryption disabled',
                            'description': f'EBS volume {resource.resource_id} is not encrypted',
                            'recommendation': 'Enable encryption for EBS volumes',
                            'compliance_standard': check.get('compliance_standard', 'SOC2'),
                            'rule_id': check['id']
                        })
                        
            except Exception as e:
                self.logger.error(f"Failed to check data encryption for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_monitoring(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check monitoring implementation"""
        findings = []
        
        # Check if CloudTrail is enabled
        has_cloudtrail = any(r.resource_type == 'CloudTrail_Trail' for r in resources)
        
        if not has_cloudtrail:
            findings.append({
                'type': 'compliance',
                'severity': check['severity'],
                'title': 'CloudTrail not enabled',
                'description': 'No CloudTrail trails found for monitoring API activities',
                'recommendation': 'Enable CloudTrail for comprehensive monitoring',
                'compliance_standard': check.get('compliance_standard', 'SOC2'),
                'rule_id': check['id']
            })
        
        return findings
    
    def _check_transmission_security(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check transmission security for HIPAA compliance"""
        findings = []
        
        # This would implement HIPAA-specific transmission security checks
        # For now, we'll check basic encryption
        return self._check_data_encryption(resources, check)
    
    def _check_data_security(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check data security for GDPR compliance"""
        findings = []
        
        # This would implement GDPR-specific data security checks
        # For now, we'll check basic encryption and access controls
        findings.extend(self._check_data_encryption(resources, check))
        
        return findings
    
    def _check_asset_inventory(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check asset inventory for NIST compliance"""
        findings = []
        
        # Check for resources without proper tagging
        for resource in resources:
            try:
                resource_tags = json.loads(resource.tags) if resource.tags else {}
                
                required_tags = ['Environment', 'Owner', 'Project', 'CostCenter']
                missing_tags = [tag for tag in required_tags if tag not in resource_tags]
                
                if missing_tags:
                    findings.append({
                        'type': 'compliance',
                        'severity': check['severity'],
                        'title': f'{resource.resource_type} {resource.resource_id} missing inventory tags',
                        'description': f'Resource is missing required tags: {", ".join(missing_tags)}',
                        'recommendation': 'Add required tags for proper asset inventory management',
                        'compliance_standard': 'NIST',
                        'rule_id': check['id'],
                        'context': {
                            'missing_tags': missing_tags
                        }
                    })
                    
            except Exception as e:
                self.logger.error(f"Failed to check asset inventory for {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _check_identity_management(self, resources: List[AWSResource], check: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check identity management for NIST compliance"""
        findings = []
        
        # This would implement comprehensive identity management checks
        # For now, we'll check basic IAM practices
        return self._check_access_controls(resources, check)

