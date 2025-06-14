import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from src.services.aws_client import AWSClient, AWSResourceDiscovery
from src.models.security import AWSResource, SecurityFinding, SecurityPolicy, db
from src.config import DEFAULT_SECURITY_POLICIES

logger = logging.getLogger(__name__)

class SecurityScanner:
    """Main security scanner for AWS resources"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.resource_discovery = AWSResourceDiscovery(aws_client)
        self.logger = logging.getLogger(__name__)
    
    def scan_all_resources(self, regions: List[str] = None) -> Dict[str, Any]:
        """Perform comprehensive security scan of all AWS resources"""
        scan_results = {
            'scan_id': datetime.utcnow().isoformat(),
            'started_at': datetime.utcnow().isoformat(),
            'resources_scanned': 0,
            'findings_created': 0,
            'regions': regions or [self.aws_client.config.AWS_DEFAULT_REGION],
            'status': 'running'
        }
        
        try:
            # Discover all resources
            self.logger.info("Starting resource discovery...")
            resources = self.resource_discovery.discover_all_resources(regions)
            
            # Store resources in database
            for resource_data in resources:
                self._store_resource(resource_data)
            
            scan_results['resources_scanned'] = len(resources)
            
            # Perform security checks
            self.logger.info("Starting security assessment...")
            findings_count = self._perform_security_checks()
            scan_results['findings_created'] = findings_count
            
            scan_results['status'] = 'completed'
            scan_results['completed_at'] = datetime.utcnow().isoformat()
            
            self.logger.info(f"Security scan completed. Resources: {len(resources)}, Findings: {findings_count}")
            
        except Exception as e:
            scan_results['status'] = 'failed'
            scan_results['error'] = str(e)
            self.logger.error(f"Security scan failed: {str(e)}")
        
        return scan_results
    
    def _store_resource(self, resource_data: Dict[str, Any]) -> AWSResource:
        """Store or update AWS resource in database"""
        try:
            # Check if resource already exists
            existing_resource = AWSResource.query.filter_by(
                resource_id=resource_data['resource_id'],
                resource_type=resource_data['resource_type']
            ).first()
            
            if existing_resource:
                # Update existing resource
                existing_resource.tags = json.dumps(resource_data.get('tags', {}))
                existing_resource.configuration = json.dumps(resource_data.get('configuration', {}))
                existing_resource.last_scanned = datetime.utcnow()
                existing_resource.status = resource_data.get('status', 'active')
                db.session.commit()
                return existing_resource
            else:
                # Create new resource
                new_resource = AWSResource(
                    resource_id=resource_data['resource_id'],
                    resource_type=resource_data['resource_type'],
                    region=resource_data['region'],
                    account_id=self.aws_client.get_account_id() or 'unknown',
                    resource_name=resource_data.get('resource_name'),
                    tags=json.dumps(resource_data.get('tags', {})),
                    configuration=json.dumps(resource_data.get('configuration', {})),
                    status=resource_data.get('status', 'active')
                )
                db.session.add(new_resource)
                db.session.commit()
                return new_resource
                
        except Exception as e:
            self.logger.error(f"Failed to store resource {resource_data.get('resource_id')}: {str(e)}")
            db.session.rollback()
            return None
    
    def _perform_security_checks(self) -> int:
        """Perform security checks on all resources"""
        findings_count = 0
        
        # Get all resources from database
        resources = AWSResource.query.all()
        
        for resource in resources:
            try:
                # Perform checks based on resource type
                if resource.resource_type == 'S3_Bucket':
                    findings_count += self._check_s3_security(resource)
                elif resource.resource_type == 'EC2_Instance':
                    findings_count += self._check_ec2_security(resource)
                elif resource.resource_type == 'EC2_SecurityGroup':
                    findings_count += self._check_security_group(resource)
                elif resource.resource_type == 'RDS_Instance':
                    findings_count += self._check_rds_security(resource)
                    
            except Exception as e:
                self.logger.error(f"Failed to check security for resource {resource.resource_id}: {str(e)}")
        
        return findings_count
    
    def _check_s3_security(self, resource: AWSResource) -> int:
        """Check S3 bucket security"""
        findings_count = 0
        bucket_name = resource.resource_id
        
        try:
            s3_client = self.aws_client.get_client('s3')
            
            # Check bucket ACL
            try:
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl_response.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                        self._create_finding(
                            resource=resource,
                            finding_type='misconfiguration',
                            severity='high',
                            title='S3 Bucket Public Read Access',
                            description=f'S3 bucket {bucket_name} has public read access enabled',
                            recommendation='Remove public read access from bucket ACL',
                            auto_remediable=True
                        )
                        findings_count += 1
            except Exception as e:
                self.logger.debug(f"Could not check ACL for bucket {bucket_name}: {str(e)}")
            
            # Check bucket policy
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response['Policy'])
                
                for statement in policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                        self._create_finding(
                            resource=resource,
                            finding_type='misconfiguration',
                            severity='critical',
                            title='S3 Bucket Public Policy',
                            description=f'S3 bucket {bucket_name} has a policy allowing public access',
                            recommendation='Review and restrict bucket policy to specific principals',
                            auto_remediable=False
                        )
                        findings_count += 1
            except Exception as e:
                self.logger.debug(f"Could not check policy for bucket {bucket_name}: {str(e)}")
            
            # Check encryption
            try:
                encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
            except Exception:
                self._create_finding(
                    resource=resource,
                    finding_type='compliance',
                    severity='medium',
                    title='S3 Bucket Encryption Disabled',
                    description=f'S3 bucket {bucket_name} does not have server-side encryption enabled',
                    recommendation='Enable server-side encryption for the bucket',
                    compliance_standard='CIS',
                    auto_remediable=True
                )
                findings_count += 1
                
        except Exception as e:
            self.logger.error(f"Failed to check S3 security for {bucket_name}: {str(e)}")
        
        return findings_count
    
    def _check_security_group(self, resource: AWSResource) -> int:
        """Check EC2 security group rules"""
        findings_count = 0
        
        try:
            configuration = json.loads(resource.configuration)
            inbound_rules = configuration.get('inbound_rules', [])
            
            for rule in inbound_rules:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Check for sensitive ports
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 65535)
                        
                        sensitive_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                        for port in sensitive_ports:
                            if from_port <= port <= to_port:
                                severity = 'critical' if port in [22, 3389] else 'high'
                                self._create_finding(
                                    resource=resource,
                                    finding_type='misconfiguration',
                                    severity=severity,
                                    title=f'Security Group Open to World on Port {port}',
                                    description=f'Security group {resource.resource_id} allows access from 0.0.0.0/0 on port {port}',
                                    recommendation=f'Restrict access to port {port} to specific IP ranges',
                                    auto_remediable=False
                                )
                                findings_count += 1
                                break
                        
        except Exception as e:
            self.logger.error(f"Failed to check security group {resource.resource_id}: {str(e)}")
        
        return findings_count
    
    def _check_ec2_security(self, resource: AWSResource) -> int:
        """Check EC2 instance security"""
        findings_count = 0
        
        try:
            configuration = json.loads(resource.configuration)
            
            # Check if instance has public IP
            if configuration.get('public_ip'):
                self._create_finding(
                    resource=resource,
                    finding_type='misconfiguration',
                    severity='medium',
                    title='EC2 Instance with Public IP',
                    description=f'EC2 instance {resource.resource_id} has a public IP address',
                    recommendation='Consider using NAT Gateway or VPN for outbound access instead of public IP',
                    auto_remediable=False
                )
                findings_count += 1
            
            # Check instance metadata service
            try:
                ec2_client = self.aws_client.get_client('ec2', resource.region)
                response = ec2_client.describe_instances(InstanceIds=[resource.resource_id])
                
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        metadata_options = instance.get('MetadataOptions', {})
                        if metadata_options.get('HttpTokens') != 'required':
                            self._create_finding(
                                resource=resource,
                                finding_type='security',
                                severity='medium',
                                title='EC2 Instance Metadata Service v1 Enabled',
                                description=f'EC2 instance {resource.resource_id} allows IMDSv1 which is less secure',
                                recommendation='Configure instance to require IMDSv2 tokens',
                                auto_remediable=True
                            )
                            findings_count += 1
                            
            except Exception as e:
                self.logger.debug(f"Could not check metadata options for {resource.resource_id}: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Failed to check EC2 security for {resource.resource_id}: {str(e)}")
        
        return findings_count
    
    def _check_rds_security(self, resource: AWSResource) -> int:
        """Check RDS instance security"""
        findings_count = 0
        
        try:
            configuration = json.loads(resource.configuration)
            
            # Check encryption
            if not configuration.get('encrypted', False):
                self._create_finding(
                    resource=resource,
                    finding_type='compliance',
                    severity='high',
                    title='RDS Instance Not Encrypted',
                    description=f'RDS instance {resource.resource_id} does not have encryption enabled',
                    recommendation='Enable encryption for the RDS instance',
                    compliance_standard='CIS',
                    auto_remediable=False
                )
                findings_count += 1
            
            # Check public accessibility
            if configuration.get('publicly_accessible', False):
                self._create_finding(
                    resource=resource,
                    finding_type='misconfiguration',
                    severity='high',
                    title='RDS Instance Publicly Accessible',
                    description=f'RDS instance {resource.resource_id} is publicly accessible',
                    recommendation='Disable public accessibility and use VPC security groups',
                    auto_remediable=True
                )
                findings_count += 1
            
            # Check backup retention
            backup_retention = configuration.get('backup_retention_period', 0)
            if backup_retention < 7:
                self._create_finding(
                    resource=resource,
                    finding_type='compliance',
                    severity='medium',
                    title='RDS Instance Insufficient Backup Retention',
                    description=f'RDS instance {resource.resource_id} has backup retention period of {backup_retention} days',
                    recommendation='Set backup retention period to at least 7 days',
                    compliance_standard='SOC2',
                    auto_remediable=True
                )
                findings_count += 1
                
        except Exception as e:
            self.logger.error(f"Failed to check RDS security for {resource.resource_id}: {str(e)}")
        
        return findings_count
    
    def _create_finding(self, resource: AWSResource, finding_type: str, severity: str, 
                       title: str, description: str, recommendation: str, 
                       compliance_standard: str = None, auto_remediable: bool = False) -> SecurityFinding:
        """Create a security finding"""
        try:
            # Check if finding already exists
            existing_finding = SecurityFinding.query.filter_by(
                resource_id=resource.id,
                title=title,
                status='open'
            ).first()
            
            if existing_finding:
                # Update existing finding
                existing_finding.updated_at = datetime.utcnow()
                db.session.commit()
                return existing_finding
            
            # Create new finding
            finding = SecurityFinding(
                resource_id=resource.id,
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description,
                recommendation=recommendation,
                compliance_standard=compliance_standard,
                auto_remediable=auto_remediable
            )
            
            db.session.add(finding)
            db.session.commit()
            
            self.logger.info(f"Created {severity} finding: {title}")
            return finding
            
        except Exception as e:
            self.logger.error(f"Failed to create finding: {str(e)}")
            db.session.rollback()
            return None

class ComplianceChecker:
    """Compliance checking service"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def check_cis_compliance(self) -> Dict[str, Any]:
        """Check CIS AWS Foundations Benchmark compliance"""
        compliance_results = {
            'standard': 'CIS AWS Foundations Benchmark',
            'version': '1.4.0',
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'score': 0.0,
            'findings': []
        }
        
        try:
            # Get all CIS-related findings
            cis_findings = SecurityFinding.query.filter_by(
                compliance_standard='CIS',
                status='open'
            ).all()
            
            compliance_results['total_checks'] = len(cis_findings)
            compliance_results['failed'] = len(cis_findings)
            compliance_results['passed'] = 0  # Simplified - in reality would check passed controls
            
            if compliance_results['total_checks'] > 0:
                compliance_results['score'] = (compliance_results['passed'] / compliance_results['total_checks']) * 100
            
            compliance_results['findings'] = [finding.to_dict() for finding in cis_findings]
            
        except Exception as e:
            self.logger.error(f"Failed to check CIS compliance: {str(e)}")
        
        return compliance_results
    
    def generate_compliance_report(self, standard: str = 'CIS') -> Dict[str, Any]:
        """Generate compliance report"""
        if standard == 'CIS':
            return self.check_cis_compliance()
        else:
            return {'error': f'Compliance standard {standard} not supported'}

