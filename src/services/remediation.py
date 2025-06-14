import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from src.services.aws_client import AWSClient
from src.models.security import SecurityFinding, RemediationAction, AWSResource, db

logger = logging.getLogger(__name__)

class AutoRemediationService:
    """Automated remediation service for security findings"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
    
    def remediate_finding(self, finding_id: int) -> Dict[str, Any]:
        """Attempt to automatically remediate a security finding"""
        try:
            finding = SecurityFinding.query.get(finding_id)
            if not finding:
                return {'success': False, 'error': 'Finding not found'}
            
            if not finding.auto_remediable:
                return {'success': False, 'error': 'Finding is not auto-remediable'}
            
            if finding.status != 'open':
                return {'success': False, 'error': 'Finding is not in open status'}
            
            # Create remediation action record
            remediation_action = RemediationAction(
                finding_id=finding.id,
                action_type=self._get_action_type(finding),
                status='in_progress',
                started_at=datetime.utcnow()
            )
            db.session.add(remediation_action)
            db.session.commit()
            
            # Perform remediation based on finding type
            result = self._execute_remediation(finding, remediation_action)
            
            # Update remediation action status
            remediation_action.status = 'completed' if result['success'] else 'failed'
            remediation_action.completed_at = datetime.utcnow()
            if not result['success']:
                remediation_action.error_message = result.get('error', 'Unknown error')
            
            # Update finding status if remediation was successful
            if result['success']:
                finding.status = 'resolved'
                finding.resolved_at = datetime.utcnow()
                finding.remediation_status = 'completed'
            else:
                finding.remediation_status = 'failed'
            
            db.session.commit()
            
            self.logger.info(f"Remediation {'successful' if result['success'] else 'failed'} for finding {finding_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to remediate finding {finding_id}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_action_type(self, finding: SecurityFinding) -> str:
        """Determine the appropriate remediation action type"""
        if 'S3 Bucket Public' in finding.title:
            return 'fix_s3_public_access'
        elif 'S3 Bucket Encryption' in finding.title:
            return 'enable_s3_encryption'
        elif 'RDS Instance Publicly Accessible' in finding.title:
            return 'disable_rds_public_access'
        elif 'RDS Instance Insufficient Backup' in finding.title:
            return 'update_rds_backup_retention'
        elif 'EC2 Instance Metadata Service' in finding.title:
            return 'enforce_imdsv2'
        else:
            return 'generic_remediation'
    
    def _execute_remediation(self, finding: SecurityFinding, action: RemediationAction) -> Dict[str, Any]:
        """Execute the specific remediation action"""
        try:
            resource = finding.resource
            action_type = action.action_type
            
            if action_type == 'fix_s3_public_access':
                return self._fix_s3_public_access(resource)
            elif action_type == 'enable_s3_encryption':
                return self._enable_s3_encryption(resource)
            elif action_type == 'disable_rds_public_access':
                return self._disable_rds_public_access(resource)
            elif action_type == 'update_rds_backup_retention':
                return self._update_rds_backup_retention(resource)
            elif action_type == 'enforce_imdsv2':
                return self._enforce_imdsv2(resource)
            else:
                return {'success': False, 'error': f'Unknown action type: {action_type}'}
                
        except Exception as e:
            self.logger.error(f"Failed to execute remediation action {action.action_type}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _fix_s3_public_access(self, resource: AWSResource) -> Dict[str, Any]:
        """Remove public access from S3 bucket"""
        try:
            bucket_name = resource.resource_id
            s3_client = self.aws_client.get_client('s3')
            
            # Block public access
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            self.logger.info(f"Successfully blocked public access for S3 bucket {bucket_name}")
            return {
                'success': True,
                'message': f'Public access blocked for S3 bucket {bucket_name}',
                'actions_taken': ['Enabled public access block configuration']
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to fix S3 public access: {str(e)}'}
    
    def _enable_s3_encryption(self, resource: AWSResource) -> Dict[str, Any]:
        """Enable server-side encryption for S3 bucket"""
        try:
            bucket_name = resource.resource_id
            s3_client = self.aws_client.get_client('s3')
            
            # Enable AES256 encryption
            s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
            
            self.logger.info(f"Successfully enabled encryption for S3 bucket {bucket_name}")
            return {
                'success': True,
                'message': f'Encryption enabled for S3 bucket {bucket_name}',
                'actions_taken': ['Enabled AES256 server-side encryption']
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to enable S3 encryption: {str(e)}'}
    
    def _disable_rds_public_access(self, resource: AWSResource) -> Dict[str, Any]:
        """Disable public accessibility for RDS instance"""
        try:
            instance_id = resource.resource_id
            rds_client = self.aws_client.get_client('rds', resource.region)
            
            # Modify RDS instance to disable public accessibility
            rds_client.modify_db_instance(
                DBInstanceIdentifier=instance_id,
                PubliclyAccessible=False,
                ApplyImmediately=True
            )
            
            self.logger.info(f"Successfully disabled public access for RDS instance {instance_id}")
            return {
                'success': True,
                'message': f'Public access disabled for RDS instance {instance_id}',
                'actions_taken': ['Set PubliclyAccessible to False']
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to disable RDS public access: {str(e)}'}
    
    def _update_rds_backup_retention(self, resource: AWSResource) -> Dict[str, Any]:
        """Update RDS backup retention period"""
        try:
            instance_id = resource.resource_id
            rds_client = self.aws_client.get_client('rds', resource.region)
            
            # Set backup retention to 7 days
            rds_client.modify_db_instance(
                DBInstanceIdentifier=instance_id,
                BackupRetentionPeriod=7,
                ApplyImmediately=True
            )
            
            self.logger.info(f"Successfully updated backup retention for RDS instance {instance_id}")
            return {
                'success': True,
                'message': f'Backup retention updated for RDS instance {instance_id}',
                'actions_taken': ['Set backup retention period to 7 days']
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to update RDS backup retention: {str(e)}'}
    
    def _enforce_imdsv2(self, resource: AWSResource) -> Dict[str, Any]:
        """Enforce IMDSv2 for EC2 instance"""
        try:
            instance_id = resource.resource_id
            ec2_client = self.aws_client.get_client('ec2', resource.region)
            
            # Modify instance metadata options to require IMDSv2
            ec2_client.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens='required',
                HttpPutResponseHopLimit=1,
                HttpEndpoint='enabled'
            )
            
            self.logger.info(f"Successfully enforced IMDSv2 for EC2 instance {instance_id}")
            return {
                'success': True,
                'message': f'IMDSv2 enforced for EC2 instance {instance_id}',
                'actions_taken': ['Set HttpTokens to required', 'Limited hop count to 1']
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to enforce IMDSv2: {str(e)}'}
    
    def remediate_all_auto_remediable(self) -> Dict[str, Any]:
        """Remediate all auto-remediable findings"""
        try:
            # Get all open auto-remediable findings
            findings = SecurityFinding.query.filter_by(
                status='open',
                auto_remediable=True
            ).all()
            
            results = {
                'total_findings': len(findings),
                'successful': 0,
                'failed': 0,
                'results': []
            }
            
            for finding in findings:
                result = self.remediate_finding(finding.id)
                results['results'].append({
                    'finding_id': finding.id,
                    'title': finding.title,
                    'result': result
                })
                
                if result['success']:
                    results['successful'] += 1
                else:
                    results['failed'] += 1
            
            self.logger.info(f"Bulk remediation completed: {results['successful']} successful, {results['failed']} failed")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to perform bulk remediation: {str(e)}")
            return {'success': False, 'error': str(e)}

class NotificationService:
    """Service for sending security notifications"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def send_finding_notification(self, finding: SecurityFinding) -> bool:
        """Send notification for a new security finding"""
        try:
            if finding.severity in ['critical', 'high']:
                message = self._format_finding_message(finding)
                
                # Send to Slack if configured
                if self.config.SLACK_WEBHOOK_URL:
                    self._send_slack_notification(message)
                
                # Send email if configured
                if self.config.NOTIFICATION_EMAIL:
                    self._send_email_notification(finding.title, message)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to send notification for finding {finding.id}: {str(e)}")
            return False
    
    def _format_finding_message(self, finding: SecurityFinding) -> str:
        """Format finding for notification"""
        return f"""
🚨 Security Finding Alert

**Severity:** {finding.severity.upper()}
**Title:** {finding.title}
**Resource:** {finding.resource.resource_id if finding.resource else 'N/A'}
**Description:** {finding.description}
**Recommendation:** {finding.recommendation}

Auto-remediable: {'Yes' if finding.auto_remediable else 'No'}
        """.strip()
    
    def _send_slack_notification(self, message: str) -> bool:
        """Send notification to Slack"""
        try:
            import requests
            
            payload = {
                'text': message,
                'username': 'Security Bot',
                'icon_emoji': ':shield:'
            }
            
            response = requests.post(
                self.config.SLACK_WEBHOOK_URL,
                json=payload,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {str(e)}")
            return False
    
    def _send_email_notification(self, subject: str, message: str) -> bool:
        """Send email notification"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg['From'] = self.config.EMAIL_USERNAME
            msg['To'] = self.config.NOTIFICATION_EMAIL
            msg['Subject'] = f"Security Alert: {subject}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(self.config.EMAIL_SMTP_SERVER, self.config.EMAIL_SMTP_PORT)
            server.starttls()
            server.login(self.config.EMAIL_USERNAME, self.config.EMAIL_PASSWORD)
            
            text = msg.as_string()
            server.sendmail(self.config.EMAIL_USERNAME, self.config.NOTIFICATION_EMAIL, text)
            server.quit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {str(e)}")
            return False

