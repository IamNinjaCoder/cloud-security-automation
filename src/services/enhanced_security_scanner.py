import logging
import json
import ipaddress
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from src.services.aws_client import AWSClient
from src.models.security import AWSResource, SecurityFinding, db

logger = logging.getLogger(__name__)

class EnhancedSecurityScanner:
    """Enhanced security scanner with contextual analysis and advanced checks"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
    
    def perform_contextual_security_analysis(self, resource: AWSResource) -> List[Dict[str, Any]]:
        """Perform contextual security analysis on a resource"""
        findings = []
        
        try:
            if resource.resource_type == 'EC2_SecurityGroup':
                findings.extend(self._analyze_security_group_context(resource))
            elif resource.resource_type == 'S3_Bucket':
                findings.extend(self._analyze_s3_bucket_context(resource))
            elif resource.resource_type == 'EC2_Instance':
                findings.extend(self._analyze_ec2_instance_context(resource))
            elif resource.resource_type == 'RDS_Instance':
                findings.extend(self._analyze_rds_instance_context(resource))
                
        except Exception as e:
            self.logger.error(f"Failed contextual analysis for resource {resource.resource_id}: {str(e)}")
        
        return findings
    
    def _analyze_security_group_context(self, resource: AWSResource) -> List[Dict[str, Any]]:
        """Enhanced security group analysis with context"""
        findings = []
        
        try:
            configuration = json.loads(resource.configuration)
            inbound_rules = configuration.get('inbound_rules', [])
            resource_tags = json.loads(resource.tags) if resource.tags else {}
            
            # Determine environment criticality from tags
            environment = resource_tags.get('Environment', '').lower()
            is_production = environment in ['prod', 'production', 'live']
            
            for rule in inbound_rules:
                protocol = rule.get('IpProtocol', '')
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                
                # Analyze IP ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    description = ip_range.get('Description', '')
                    
                    # Check for overly permissive access
                    if cidr == '0.0.0.0/0':
                        severity = self._determine_severity_by_context(from_port, to_port, is_production)
                        
                        findings.append({
                            'type': 'misconfiguration',
                            'severity': severity,
                            'title': f'Security Group Open to Internet on Port {from_port}-{to_port}',
                            'description': f'Security group {resource.resource_id} allows access from anywhere (0.0.0.0/0) on port(s) {from_port}-{to_port}. Environment: {environment or "Unknown"}',
                            'recommendation': self._get_port_specific_recommendation(from_port, to_port),
                            'context': {
                                'environment': environment,
                                'is_production': is_production,
                                'protocol': protocol,
                                'description': description
                            }
                        })
                    
                    # Check for large CIDR blocks that might be too permissive
                    elif '/' in cidr:
                        try:
                            network = ipaddress.IPv4Network(cidr, strict=False)
                            if network.num_addresses > 256:  # /24 or larger
                                findings.append({
                                    'type': 'misconfiguration',
                                    'severity': 'medium',
                                    'title': f'Security Group with Large CIDR Block Access',
                                    'description': f'Security group allows access from large network {cidr} ({network.num_addresses} addresses) on port(s) {from_port}-{to_port}',
                                    'recommendation': 'Consider restricting access to smaller, more specific IP ranges',
                                    'context': {
                                        'cidr': cidr,
                                        'num_addresses': network.num_addresses,
                                        'protocol': protocol
                                    }
                                })
                        except ValueError:
                            pass
                
                # Check for security group references
                for sg_ref in rule.get('UserIdGroupPairs', []):
                    referenced_sg = sg_ref.get('GroupId', '')
                    if referenced_sg:
                        # This is actually a good practice, but we can check for circular references
                        findings.extend(self._check_security_group_circular_references(resource, referenced_sg))
            
            # Check for unused security groups
            findings.extend(self._check_unused_security_group(resource))
            
        except Exception as e:
            self.logger.error(f"Failed to analyze security group context: {str(e)}")
        
        return findings
    
    def _analyze_s3_bucket_context(self, resource: AWSResource) -> List[Dict[str, Any]]:
        """Enhanced S3 bucket analysis"""
        findings = []
        bucket_name = resource.resource_id
        
        try:
            s3_client = self.aws_client.get_client('s3')
            resource_tags = json.loads(resource.tags) if resource.tags else {}
            
            # Check versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'type': 'compliance',
                        'severity': 'medium',
                        'title': 'S3 Bucket Versioning Disabled',
                        'description': f'S3 bucket {bucket_name} does not have versioning enabled',
                        'recommendation': 'Enable versioning to protect against accidental deletion or modification',
                        'compliance_standard': 'CIS'
                    })
            except Exception:
                pass
            
            # Check MFA Delete
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('MfaDelete') != 'Enabled':
                    findings.append({
                        'type': 'compliance',
                        'severity': 'medium',
                        'title': 'S3 Bucket MFA Delete Disabled',
                        'description': f'S3 bucket {bucket_name} does not have MFA Delete enabled',
                        'recommendation': 'Enable MFA Delete for additional protection against accidental deletion',
                        'compliance_standard': 'CIS'
                    })
            except Exception:
                pass
            
            # Check logging
            try:
                logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in logging_config:
                    findings.append({
                        'type': 'compliance',
                        'severity': 'medium',
                        'title': 'S3 Bucket Access Logging Disabled',
                        'description': f'S3 bucket {bucket_name} does not have access logging enabled',
                        'recommendation': 'Enable access logging to track requests made to the bucket',
                        'compliance_standard': 'CIS'
                    })
            except Exception:
                pass
            
            # Check lifecycle configuration
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            except Exception:
                findings.append({
                    'type': 'cost_optimization',
                    'severity': 'low',
                    'title': 'S3 Bucket Missing Lifecycle Policy',
                    'description': f'S3 bucket {bucket_name} does not have a lifecycle policy configured',
                    'recommendation': 'Configure lifecycle policies to automatically transition or delete old objects to reduce costs'
                })
            
            # Check notification configuration
            try:
                notification = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
                if not any(key in notification for key in ['TopicConfigurations', 'QueueConfigurations', 'LambdaConfigurations']):
                    findings.append({
                        'type': 'monitoring',
                        'severity': 'low',
                        'title': 'S3 Bucket Missing Event Notifications',
                        'description': f'S3 bucket {bucket_name} does not have event notifications configured',
                        'recommendation': 'Configure event notifications for important bucket activities'
                    })
            except Exception:
                pass
            
        except Exception as e:
            self.logger.error(f"Failed to analyze S3 bucket context: {str(e)}")
        
        return findings
    
    def _analyze_ec2_instance_context(self, resource: AWSResource) -> List[Dict[str, Any]]:
        """Enhanced EC2 instance analysis"""
        findings = []
        
        try:
            configuration = json.loads(resource.configuration)
            resource_tags = json.loads(resource.tags) if resource.tags else {}
            
            # Check if instance is in public subnet with public IP
            if configuration.get('public_ip') and configuration.get('subnet_id'):
                findings.append({
                    'type': 'misconfiguration',
                    'severity': 'medium',
                    'title': 'EC2 Instance in Public Subnet with Public IP',
                    'description': f'EC2 instance {resource.resource_id} has a public IP and may be in a public subnet',
                    'recommendation': 'Consider using NAT Gateway or VPN for outbound access instead of public IP',
                    'context': {
                        'public_ip': configuration.get('public_ip'),
                        'subnet_id': configuration.get('subnet_id')
                    }
                })
            
            # Check for instances without proper tagging
            required_tags = ['Environment', 'Owner', 'Project']
            missing_tags = [tag for tag in required_tags if tag not in resource_tags]
            if missing_tags:
                findings.append({
                    'type': 'compliance',
                    'severity': 'low',
                    'title': 'EC2 Instance Missing Required Tags',
                    'description': f'EC2 instance {resource.resource_id} is missing required tags: {", ".join(missing_tags)}',
                    'recommendation': 'Add required tags for proper resource management and cost allocation',
                    'context': {
                        'missing_tags': missing_tags,
                        'current_tags': list(resource_tags.keys())
                    }
                })
            
            # Check for old instances (running for more than 90 days)
            if configuration.get('launch_time'):
                launch_time = datetime.fromisoformat(configuration['launch_time'].replace('Z', '+00:00'))
                age_days = (datetime.now(launch_time.tzinfo) - launch_time).days
                
                if age_days > 90:
                    findings.append({
                        'type': 'cost_optimization',
                        'severity': 'low',
                        'title': 'Long-Running EC2 Instance',
                        'description': f'EC2 instance {resource.resource_id} has been running for {age_days} days',
                        'recommendation': 'Review if this long-running instance is still needed or can be optimized',
                        'context': {
                            'age_days': age_days,
                            'launch_time': configuration['launch_time']
                        }
                    })
            
            # Check for instances without monitoring
            try:
                ec2_client = self.aws_client.get_client('ec2', resource.region)
                response = ec2_client.describe_instances(InstanceIds=[resource.resource_id])
                
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        monitoring = instance.get('Monitoring', {})
                        if monitoring.get('State') != 'enabled':
                            findings.append({
                                'type': 'monitoring',
                                'severity': 'medium',
                                'title': 'EC2 Instance Detailed Monitoring Disabled',
                                'description': f'EC2 instance {resource.resource_id} does not have detailed monitoring enabled',
                                'recommendation': 'Enable detailed monitoring for better visibility into instance performance'
                            })
            except Exception:
                pass
            
        except Exception as e:
            self.logger.error(f"Failed to analyze EC2 instance context: {str(e)}")
        
        return findings
    
    def _analyze_rds_instance_context(self, resource: AWSResource) -> List[Dict[str, Any]]:
        """Enhanced RDS instance analysis"""
        findings = []
        
        try:
            configuration = json.loads(resource.configuration)
            
            # Check for automated backups
            backup_retention = configuration.get('backup_retention_period', 0)
            if backup_retention == 0:
                findings.append({
                    'type': 'compliance',
                    'severity': 'high',
                    'title': 'RDS Instance Automated Backups Disabled',
                    'description': f'RDS instance {resource.resource_id} has automated backups disabled',
                    'recommendation': 'Enable automated backups with appropriate retention period',
                    'compliance_standard': 'CIS'
                })
            elif backup_retention < 7:
                findings.append({
                    'type': 'compliance',
                    'severity': 'medium',
                    'title': 'RDS Instance Insufficient Backup Retention',
                    'description': f'RDS instance {resource.resource_id} has backup retention of only {backup_retention} days',
                    'recommendation': 'Set backup retention to at least 7 days for production databases'
                })
            
            # Check for Multi-AZ deployment
            if not configuration.get('multi_az', False):
                findings.append({
                    'type': 'availability',
                    'severity': 'medium',
                    'title': 'RDS Instance Not Multi-AZ',
                    'description': f'RDS instance {resource.resource_id} is not configured for Multi-AZ deployment',
                    'recommendation': 'Enable Multi-AZ deployment for high availability and automatic failover'
                })
            
            # Check for minor version auto upgrade
            try:
                rds_client = self.aws_client.get_client('rds', resource.region)
                response = rds_client.describe_db_instances(DBInstanceIdentifier=resource.resource_id)
                
                for db_instance in response['DBInstances']:
                    if not db_instance.get('AutoMinorVersionUpgrade', False):
                        findings.append({
                            'type': 'maintenance',
                            'severity': 'low',
                            'title': 'RDS Instance Auto Minor Version Upgrade Disabled',
                            'description': f'RDS instance {resource.resource_id} does not have auto minor version upgrade enabled',
                            'recommendation': 'Enable auto minor version upgrade to receive security patches automatically'
                        })
            except Exception:
                pass
            
        except Exception as e:
            self.logger.error(f"Failed to analyze RDS instance context: {str(e)}")
        
        return findings
    
    def _determine_severity_by_context(self, from_port: int, to_port: int, is_production: bool) -> str:
        """Determine severity based on port and environment context"""
        critical_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
        high_risk_ports = [21, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        # Check if any critical port is in the range
        for port in critical_ports:
            if from_port <= port <= to_port:
                return 'critical' if is_production else 'high'
        
        # Check if any high-risk port is in the range
        for port in high_risk_ports:
            if from_port <= port <= to_port:
                return 'high' if is_production else 'medium'
        
        return 'medium' if is_production else 'low'
    
    def _get_port_specific_recommendation(self, from_port: int, to_port: int) -> str:
        """Get specific recommendations based on port"""
        port_recommendations = {
            22: "Consider using AWS Systems Manager Session Manager instead of SSH, or restrict to specific IP ranges",
            3389: "Use AWS Systems Manager Session Manager or restrict RDP access to specific IP ranges",
            80: "Consider using CloudFront or Application Load Balancer with proper security groups",
            443: "Ensure proper SSL/TLS configuration and consider using CloudFront",
            3306: "Database should not be directly accessible from internet. Use VPC and security groups",
            5432: "PostgreSQL should not be directly accessible from internet. Use VPC and security groups",
            1433: "SQL Server should not be directly accessible from internet. Use VPC and security groups",
            6379: "Redis should not be directly accessible from internet. Use VPC and security groups",
            27017: "MongoDB should not be directly accessible from internet. Use VPC and security groups"
        }
        
        for port in range(from_port, to_port + 1):
            if port in port_recommendations:
                return port_recommendations[port]
        
        return "Restrict access to specific IP ranges or use VPN/bastion host for secure access"
    
    def _check_security_group_circular_references(self, resource: AWSResource, referenced_sg: str) -> List[Dict[str, Any]]:
        """Check for circular references in security groups"""
        findings = []
        
        try:
            # This would require a more complex implementation to track all references
            # For now, we'll just note that this is a referenced security group
            pass
        except Exception as e:
            self.logger.error(f"Failed to check circular references: {str(e)}")
        
        return findings
    
    def _check_unused_security_group(self, resource: AWSResource) -> List[Dict[str, Any]]:
        """Check if security group is unused"""
        findings = []
        
        try:
            ec2_client = self.aws_client.get_client('ec2', resource.region)
            
            # Check if security group is attached to any instances
            instances_response = ec2_client.describe_instances(
                Filters=[
                    {
                        'Name': 'instance.group-id',
                        'Values': [resource.resource_id]
                    }
                ]
            )
            
            has_instances = any(
                reservation['Instances'] 
                for reservation in instances_response['Reservations']
            )
            
            if not has_instances:
                # Check if it's attached to other resources (ELB, RDS, etc.)
                # This is a simplified check - in practice, you'd check multiple services
                findings.append({
                    'type': 'cost_optimization',
                    'severity': 'low',
                    'title': 'Unused Security Group',
                    'description': f'Security group {resource.resource_id} appears to be unused',
                    'recommendation': 'Review and delete unused security groups to reduce clutter and potential security risks'
                })
            
        except Exception as e:
            self.logger.error(f"Failed to check unused security group: {str(e)}")
        
        return findings

class IAMSecurityAnalyzer:
    """Advanced IAM security analysis"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
    
    def analyze_iam_users(self) -> List[Dict[str, Any]]:
        """Analyze IAM users for security issues"""
        findings = []
        
        try:
            iam_client = self.aws_client.get_client('iam')
            
            # Get all users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    # Check for unused access keys
                    findings.extend(self._check_unused_access_keys(iam_client, user_name))
                    
                    # Check for overprivileged users
                    findings.extend(self._check_overprivileged_user(iam_client, user_name))
                    
                    # Check for users without MFA
                    findings.extend(self._check_user_mfa(iam_client, user_name))
                    
                    # Check for old users
                    findings.extend(self._check_old_user(user, user_name))
        
        except Exception as e:
            self.logger.error(f"Failed to analyze IAM users: {str(e)}")
        
        return findings
    
    def _check_unused_access_keys(self, iam_client, user_name: str) -> List[Dict[str, Any]]:
        """Check for unused access keys"""
        findings = []
        
        try:
            response = iam_client.list_access_keys(UserName=user_name)
            
            for key_metadata in response['AccessKeyMetadata']:
                access_key_id = key_metadata['AccessKeyId']
                
                # Get last used information
                try:
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    
                    if last_used_date:
                        days_since_use = (datetime.now(last_used_date.tzinfo) - last_used_date).days
                        
                        if days_since_use > 90:
                            findings.append({
                                'type': 'security',
                                'severity': 'medium',
                                'title': 'Unused IAM Access Key',
                                'description': f'IAM user {user_name} has an access key that hasn\'t been used for {days_since_use} days',
                                'recommendation': 'Deactivate or delete unused access keys to reduce security risk',
                                'context': {
                                    'user_name': user_name,
                                    'access_key_id': access_key_id,
                                    'days_since_use': days_since_use
                                }
                            })
                    else:
                        findings.append({
                            'type': 'security',
                            'severity': 'medium',
                            'title': 'Never Used IAM Access Key',
                            'description': f'IAM user {user_name} has an access key that has never been used',
                            'recommendation': 'Delete access keys that have never been used',
                            'context': {
                                'user_name': user_name,
                                'access_key_id': access_key_id
                            }
                        })
                        
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Failed to check unused access keys for user {user_name}: {str(e)}")
        
        return findings
    
    def _check_overprivileged_user(self, iam_client, user_name: str) -> List[Dict[str, Any]]:
        """Check for overprivileged users"""
        findings = []
        
        try:
            # Get user policies
            inline_policies = iam_client.list_user_policies(UserName=user_name)
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
            
            # Check for wildcard permissions in inline policies
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policy_document = policy_doc['PolicyDocument']
                
                if self._has_wildcard_permissions(policy_document):
                    findings.append({
                        'type': 'security',
                        'severity': 'high',
                        'title': 'IAM User with Wildcard Permissions',
                        'description': f'IAM user {user_name} has wildcard permissions in inline policy {policy_name}',
                        'recommendation': 'Apply principle of least privilege and remove wildcard permissions',
                        'context': {
                            'user_name': user_name,
                            'policy_name': policy_name,
                            'policy_type': 'inline'
                        }
                    })
            
            # Check for administrative policies
            for policy in attached_policies['AttachedPolicies']:
                if 'Administrator' in policy['PolicyName'] or policy['PolicyArn'].endswith('AdministratorAccess'):
                    findings.append({
                        'type': 'security',
                        'severity': 'critical',
                        'title': 'IAM User with Administrative Access',
                        'description': f'IAM user {user_name} has administrative access policy attached',
                        'recommendation': 'Remove administrative access and grant only necessary permissions',
                        'context': {
                            'user_name': user_name,
                            'policy_name': policy['PolicyName'],
                            'policy_arn': policy['PolicyArn']
                        }
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to check overprivileged user {user_name}: {str(e)}")
        
        return findings
    
    def _check_user_mfa(self, iam_client, user_name: str) -> List[Dict[str, Any]]:
        """Check if user has MFA enabled"""
        findings = []
        
        try:
            mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
            
            if not mfa_devices['MFADevices']:
                findings.append({
                    'type': 'security',
                    'severity': 'medium',
                    'title': 'IAM User without MFA',
                    'description': f'IAM user {user_name} does not have MFA enabled',
                    'recommendation': 'Enable MFA for all IAM users to improve security',
                    'compliance_standard': 'CIS',
                    'context': {
                        'user_name': user_name
                    }
                })
        
        except Exception as e:
            self.logger.error(f"Failed to check MFA for user {user_name}: {str(e)}")
        
        return findings
    
    def _check_old_user(self, user: Dict, user_name: str) -> List[Dict[str, Any]]:
        """Check for old users"""
        findings = []
        
        try:
            create_date = user.get('CreateDate')
            if create_date:
                age_days = (datetime.now(create_date.tzinfo) - create_date).days
                
                if age_days > 365:  # User older than 1 year
                    findings.append({
                        'type': 'governance',
                        'severity': 'low',
                        'title': 'Old IAM User Account',
                        'description': f'IAM user {user_name} was created {age_days} days ago',
                        'recommendation': 'Review old user accounts to ensure they are still needed',
                        'context': {
                            'user_name': user_name,
                            'age_days': age_days,
                            'create_date': create_date.isoformat()
                        }
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to check old user {user_name}: {str(e)}")
        
        return findings
    
    def _has_wildcard_permissions(self, policy_document: Dict) -> bool:
        """Check if policy document has wildcard permissions"""
        try:
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    
                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]
                    
                    # Check for wildcard actions or resources
                    if '*' in actions or '*' in resources:
                        return True
                    
                    # Check for broad permissions
                    for action in actions:
                        if isinstance(action, str) and action.endswith(':*'):
                            return True
            
            return False
            
        except Exception:
            return False

class ThreatIntelligenceIntegration:
    """Threat intelligence integration for enhanced security analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address reputation (placeholder for external service integration)"""
        # This would integrate with services like VirusTotal, AbuseIPDB, etc.
        # For now, we'll return a placeholder response
        
        try:
            # Check if IP is in known bad ranges (simplified example)
            bad_ip_ranges = [
                '10.0.0.0/8',    # Private ranges that shouldn't be public
                '172.16.0.0/12',
                '192.168.0.0/16'
            ]
            
            for bad_range in bad_ip_ranges:
                try:
                    if ipaddress.IPv4Address(ip_address) in ipaddress.IPv4Network(bad_range):
                        return {
                            'is_malicious': True,
                            'reputation_score': 0,
                            'source': 'internal_check',
                            'details': f'IP {ip_address} is in private range {bad_range} but configured for public access'
                        }
                except ValueError:
                    continue
            
            return {
                'is_malicious': False,
                'reputation_score': 100,
                'source': 'internal_check',
                'details': 'No issues found in basic checks'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to check IP reputation for {ip_address}: {str(e)}")
            return {
                'is_malicious': False,
                'reputation_score': 50,
                'source': 'error',
                'details': f'Error checking reputation: {str(e)}'
            }
    
    def analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation"""
        # Placeholder for domain reputation analysis
        return {
            'is_malicious': False,
            'reputation_score': 100,
            'source': 'internal_check',
            'details': 'Domain reputation check not implemented'
        }

