import logging
import json
import uuid
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from src.services.aws_client import AWSClient
from src.models.security import SecurityFinding, RemediationAction, db
from src.services.remediation import RemediationService

logger = logging.getLogger(__name__)

class PlaybookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"

class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class PlaybookStep:
    """Represents a single step in an incident response playbook"""
    id: str
    name: str
    description: str
    action_type: str
    parameters: Dict[str, Any]
    depends_on: List[str] = None
    timeout_minutes: int = 30
    retry_count: int = 3
    requires_approval: bool = False
    rollback_action: Optional[Dict[str, Any]] = None
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    output: Optional[Dict[str, Any]] = None

@dataclass
class IncidentPlaybook:
    """Represents an incident response playbook"""
    id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    steps: List[PlaybookStep]
    status: PlaybookStatus = PlaybookStatus.PENDING
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.context is None:
            self.context = {}

class IncidentResponseOrchestrator:
    """Advanced incident response orchestration system"""
    
    def __init__(self, aws_client: AWSClient, remediation_service: RemediationService):
        self.aws_client = aws_client
        self.remediation_service = remediation_service
        self.logger = logging.getLogger(__name__)
        self.active_playbooks: Dict[str, IncidentPlaybook] = {}
        self.playbook_templates = self._initialize_playbook_templates()
        self.approval_callbacks: Dict[str, Callable] = {}
    
    def _initialize_playbook_templates(self) -> Dict[str, IncidentPlaybook]:
        """Initialize predefined incident response playbooks"""
        return {
            'compromised_ec2_instance': self._create_compromised_ec2_playbook(),
            'data_exfiltration_s3': self._create_s3_data_exfiltration_playbook(),
            'suspicious_iam_activity': self._create_suspicious_iam_playbook(),
            'security_group_breach': self._create_security_group_breach_playbook(),
            'rds_public_exposure': self._create_rds_exposure_playbook(),
            'root_account_usage': self._create_root_account_usage_playbook(),
            'mass_resource_deletion': self._create_mass_deletion_playbook()
        }
    
    def trigger_incident_response(self, finding: SecurityFinding, playbook_type: str = None) -> Optional[str]:
        """Trigger incident response based on security finding"""
        try:
            # Determine appropriate playbook
            if not playbook_type:
                playbook_type = self._determine_playbook_type(finding)
            
            if not playbook_type or playbook_type not in self.playbook_templates:
                self.logger.warning(f"No suitable playbook found for finding {finding.id}")
                return None
            
            # Create playbook instance
            template = self.playbook_templates[playbook_type]
            playbook = self._create_playbook_instance(template, finding)
            
            # Start execution
            self.active_playbooks[playbook.id] = playbook
            self._execute_playbook(playbook)
            
            return playbook.id
            
        except Exception as e:
            self.logger.error(f"Failed to trigger incident response: {str(e)}")
            return None
    
    def _determine_playbook_type(self, finding: SecurityFinding) -> Optional[str]:
        """Determine appropriate playbook based on finding characteristics"""
        finding_title = finding.title.lower()
        finding_type = finding.finding_type.lower()
        severity = finding.severity.lower()
        
        # High-priority mappings
        if 'compromised' in finding_title or 'malware' in finding_title:
            return 'compromised_ec2_instance'
        
        if 'data exfiltration' in finding_title or 'unusual data transfer' in finding_title:
            return 'data_exfiltration_s3'
        
        if 'root account' in finding_title:
            return 'root_account_usage'
        
        if 'mass deletion' in finding_title or 'bulk delete' in finding_title:
            return 'mass_resource_deletion'
        
        # Resource-specific mappings
        if finding.resource and finding.resource.resource_type == 'EC2_SecurityGroup':
            if severity in ['critical', 'high'] and 'open' in finding_title:
                return 'security_group_breach'
        
        if finding.resource and finding.resource.resource_type == 'RDS_Instance':
            if 'public' in finding_title:
                return 'rds_public_exposure'
        
        if finding_type == 'iam_anomaly' or 'iam' in finding_title:
            return 'suspicious_iam_activity'
        
        return None
    
    def _create_playbook_instance(self, template: IncidentPlaybook, finding: SecurityFinding) -> IncidentPlaybook:
        """Create a playbook instance from template with context"""
        playbook_id = str(uuid.uuid4())
        
        # Deep copy template and customize
        steps = []
        for step in template.steps:
            new_step = PlaybookStep(
                id=f"{playbook_id}_{step.id}",
                name=step.name,
                description=step.description,
                action_type=step.action_type,
                parameters=step.parameters.copy(),
                depends_on=step.depends_on.copy() if step.depends_on else None,
                timeout_minutes=step.timeout_minutes,
                retry_count=step.retry_count,
                requires_approval=step.requires_approval,
                rollback_action=step.rollback_action.copy() if step.rollback_action else None
            )
            
            # Inject finding context into parameters
            new_step.parameters['finding_id'] = finding.id
            if finding.resource:
                new_step.parameters['resource_id'] = finding.resource.resource_id
                new_step.parameters['resource_type'] = finding.resource.resource_type
                new_step.parameters['region'] = finding.resource.region
            
            steps.append(new_step)
        
        return IncidentPlaybook(
            id=playbook_id,
            name=f"{template.name} - Finding {finding.id}",
            description=template.description,
            trigger_conditions=template.trigger_conditions.copy(),
            steps=steps,
            context={
                'finding_id': finding.id,
                'severity': finding.severity,
                'resource_type': finding.resource.resource_type if finding.resource else None,
                'triggered_at': datetime.utcnow().isoformat()
            }
        )
    
    def _execute_playbook(self, playbook: IncidentPlaybook):
        """Execute incident response playbook"""
        try:
            playbook.status = PlaybookStatus.RUNNING
            playbook.started_at = datetime.utcnow()
            
            self.logger.info(f"Starting playbook execution: {playbook.name}")
            
            # Execute steps in dependency order
            self._execute_playbook_steps(playbook)
            
        except Exception as e:
            self.logger.error(f"Playbook execution failed: {str(e)}")
            playbook.status = PlaybookStatus.FAILED
            playbook.completed_at = datetime.utcnow()
    
    def _execute_playbook_steps(self, playbook: IncidentPlaybook):
        """Execute playbook steps respecting dependencies"""
        completed_steps = set()
        
        while len(completed_steps) < len(playbook.steps):
            progress_made = False
            
            for step in playbook.steps:
                if step.status != StepStatus.PENDING:
                    continue
                
                # Check dependencies
                if step.depends_on:
                    dependencies_met = all(
                        dep_id in completed_steps for dep_id in step.depends_on
                    )
                    if not dependencies_met:
                        continue
                
                # Execute step
                if self._execute_step(playbook, step):
                    completed_steps.add(step.id)
                    progress_made = True
                else:
                    # Step failed or requires approval
                    if step.status == StepStatus.FAILED:
                        playbook.status = PlaybookStatus.FAILED
                        playbook.completed_at = datetime.utcnow()
                        return
                    elif step.requires_approval:
                        playbook.status = PlaybookStatus.AWAITING_APPROVAL
                        return
            
            if not progress_made:
                # No progress made, check for deadlock
                pending_steps = [s for s in playbook.steps if s.status == StepStatus.PENDING]
                if pending_steps:
                    self.logger.error(f"Playbook deadlock detected: {[s.id for s in pending_steps]}")
                    playbook.status = PlaybookStatus.FAILED
                    playbook.completed_at = datetime.utcnow()
                    return
                break
        
        # All steps completed
        playbook.status = PlaybookStatus.COMPLETED
        playbook.completed_at = datetime.utcnow()
        self.logger.info(f"Playbook completed successfully: {playbook.name}")
    
    def _execute_step(self, playbook: IncidentPlaybook, step: PlaybookStep) -> bool:
        """Execute a single playbook step"""
        try:
            step.status = StepStatus.RUNNING
            step.started_at = datetime.utcnow()
            
            self.logger.info(f"Executing step: {step.name}")
            
            # Check if step requires approval
            if step.requires_approval and not self._is_step_approved(step):
                self._request_approval(playbook, step)
                return False
            
            # Execute the step action
            success = self._execute_step_action(step)
            
            if success:
                step.status = StepStatus.COMPLETED
                step.completed_at = datetime.utcnow()
                return True
            else:
                step.status = StepStatus.FAILED
                step.completed_at = datetime.utcnow()
                return False
                
        except Exception as e:
            self.logger.error(f"Step execution failed: {str(e)}")
            step.status = StepStatus.FAILED
            step.completed_at = datetime.utcnow()
            step.error_message = str(e)
            return False
    
    def _execute_step_action(self, step: PlaybookStep) -> bool:
        """Execute the actual step action"""
        action_type = step.action_type
        parameters = step.parameters
        
        try:
            if action_type == 'isolate_ec2_instance':
                return self._isolate_ec2_instance(parameters)
            elif action_type == 'create_snapshot':
                return self._create_ec2_snapshot(parameters)
            elif action_type == 'block_s3_public_access':
                return self._block_s3_public_access(parameters)
            elif action_type == 'disable_iam_user':
                return self._disable_iam_user(parameters)
            elif action_type == 'rotate_access_keys':
                return self._rotate_access_keys(parameters)
            elif action_type == 'update_security_group':
                return self._update_security_group(parameters)
            elif action_type == 'enable_cloudtrail_logging':
                return self._enable_cloudtrail_logging(parameters)
            elif action_type == 'send_notification':
                return self._send_notification(parameters)
            elif action_type == 'create_support_case':
                return self._create_support_case(parameters)
            elif action_type == 'backup_resource':
                return self._backup_resource(parameters)
            else:
                self.logger.error(f"Unknown action type: {action_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Action execution failed: {str(e)}")
            return False
    
    # Playbook template definitions
    
    def _create_compromised_ec2_playbook(self) -> IncidentPlaybook:
        """Create playbook for compromised EC2 instance"""
        steps = [
            PlaybookStep(
                id="isolate_instance",
                name="Isolate EC2 Instance",
                description="Move instance to isolation security group",
                action_type="isolate_ec2_instance",
                parameters={},
                requires_approval=True
            ),
            PlaybookStep(
                id="create_snapshot",
                name="Create Instance Snapshot",
                description="Create snapshot for forensic analysis",
                action_type="create_snapshot",
                parameters={},
                depends_on=["isolate_instance"]
            ),
            PlaybookStep(
                id="notify_security_team",
                name="Notify Security Team",
                description="Send immediate notification to security team",
                action_type="send_notification",
                parameters={
                    "channel": "security_alerts",
                    "priority": "critical",
                    "message": "EC2 instance compromise detected - isolation initiated"
                }
            ),
            PlaybookStep(
                id="create_support_case",
                name="Create AWS Support Case",
                description="Create support case for incident investigation",
                action_type="create_support_case",
                parameters={
                    "severity": "high",
                    "category": "security"
                },
                depends_on=["create_snapshot"]
            )
        ]
        
        return IncidentPlaybook(
            id="compromised_ec2_template",
            name="Compromised EC2 Instance Response",
            description="Automated response for compromised EC2 instances",
            trigger_conditions={
                "finding_types": ["malware_detection", "compromise_indicator"],
                "resource_types": ["EC2_Instance"],
                "min_severity": "high"
            },
            steps=steps
        )
    
    def _create_s3_data_exfiltration_playbook(self) -> IncidentPlaybook:
        """Create playbook for S3 data exfiltration"""
        steps = [
            PlaybookStep(
                id="block_public_access",
                name="Block S3 Public Access",
                description="Immediately block public access to S3 bucket",
                action_type="block_s3_public_access",
                parameters={}
            ),
            PlaybookStep(
                id="enable_access_logging",
                name="Enable S3 Access Logging",
                description="Enable detailed access logging for investigation",
                action_type="enable_s3_logging",
                parameters={},
                depends_on=["block_public_access"]
            ),
            PlaybookStep(
                id="notify_data_team",
                name="Notify Data Protection Team",
                description="Alert data protection team of potential breach",
                action_type="send_notification",
                parameters={
                    "channel": "data_protection",
                    "priority": "critical",
                    "message": "Potential S3 data exfiltration detected"
                }
            ),
            PlaybookStep(
                id="backup_bucket",
                name="Create Bucket Backup",
                description="Create backup of current bucket state",
                action_type="backup_resource",
                parameters={
                    "resource_type": "s3_bucket"
                },
                depends_on=["block_public_access"]
            )
        ]
        
        return IncidentPlaybook(
            id="s3_exfiltration_template",
            name="S3 Data Exfiltration Response",
            description="Automated response for S3 data exfiltration incidents",
            trigger_conditions={
                "finding_types": ["data_exfiltration", "unusual_access"],
                "resource_types": ["S3_Bucket"],
                "min_severity": "high"
            },
            steps=steps
        )
    
    def _create_suspicious_iam_playbook(self) -> IncidentPlaybook:
        """Create playbook for suspicious IAM activity"""
        steps = [
            PlaybookStep(
                id="disable_user",
                name="Disable IAM User",
                description="Temporarily disable suspicious IAM user",
                action_type="disable_iam_user",
                parameters={},
                requires_approval=True
            ),
            PlaybookStep(
                id="rotate_keys",
                name="Rotate Access Keys",
                description="Rotate all access keys for the user",
                action_type="rotate_access_keys",
                parameters={},
                depends_on=["disable_user"]
            ),
            PlaybookStep(
                id="audit_permissions",
                name="Audit User Permissions",
                description="Review and audit user permissions",
                action_type="audit_iam_permissions",
                parameters={},
                depends_on=["disable_user"]
            ),
            PlaybookStep(
                id="notify_iam_team",
                name="Notify IAM Team",
                description="Alert IAM team of suspicious activity",
                action_type="send_notification",
                parameters={
                    "channel": "iam_security",
                    "priority": "high",
                    "message": "Suspicious IAM activity detected - user disabled"
                }
            )
        ]
        
        return IncidentPlaybook(
            id="suspicious_iam_template",
            name="Suspicious IAM Activity Response",
            description="Automated response for suspicious IAM activities",
            trigger_conditions={
                "finding_types": ["iam_anomaly", "privilege_escalation"],
                "resource_types": ["IAM_User", "IAM_Role"],
                "min_severity": "medium"
            },
            steps=steps
        )
    
    def _create_security_group_breach_playbook(self) -> IncidentPlaybook:
        """Create playbook for security group breach"""
        steps = [
            PlaybookStep(
                id="update_security_group",
                name="Update Security Group Rules",
                description="Remove overly permissive rules",
                action_type="update_security_group",
                parameters={
                    "action": "remove_permissive_rules"
                }
            ),
            PlaybookStep(
                id="audit_affected_instances",
                name="Audit Affected Instances",
                description="Check all instances using this security group",
                action_type="audit_security_group_usage",
                parameters={},
                depends_on=["update_security_group"]
            ),
            PlaybookStep(
                id="notify_network_team",
                name="Notify Network Team",
                description="Alert network security team",
                action_type="send_notification",
                parameters={
                    "channel": "network_security",
                    "priority": "high",
                    "message": "Security group breach detected and remediated"
                }
            )
        ]
        
        return IncidentPlaybook(
            id="security_group_breach_template",
            name="Security Group Breach Response",
            description="Automated response for security group breaches",
            trigger_conditions={
                "finding_types": ["misconfiguration", "security_breach"],
                "resource_types": ["EC2_SecurityGroup"],
                "min_severity": "high"
            },
            steps=steps
        )
    
    def _create_rds_exposure_playbook(self) -> IncidentPlaybook:
        """Create playbook for RDS public exposure"""
        steps = [
            PlaybookStep(
                id="disable_public_access",
                name="Disable RDS Public Access",
                description="Disable public accessibility for RDS instance",
                action_type="disable_rds_public_access",
                parameters={}
            ),
            PlaybookStep(
                id="backup_database",
                name="Create Database Backup",
                description="Create immediate backup of database",
                action_type="backup_resource",
                parameters={
                    "resource_type": "rds_instance"
                },
                depends_on=["disable_public_access"]
            ),
            PlaybookStep(
                id="audit_connections",
                name="Audit Database Connections",
                description="Review recent database connections",
                action_type="audit_rds_connections",
                parameters={},
                depends_on=["disable_public_access"]
            ),
            PlaybookStep(
                id="notify_dba_team",
                name="Notify DBA Team",
                description="Alert database administration team",
                action_type="send_notification",
                parameters={
                    "channel": "dba_alerts",
                    "priority": "critical",
                    "message": "RDS public exposure remediated - review required"
                }
            )
        ]
        
        return IncidentPlaybook(
            id="rds_exposure_template",
            name="RDS Public Exposure Response",
            description="Automated response for RDS public exposure",
            trigger_conditions={
                "finding_types": ["misconfiguration", "public_exposure"],
                "resource_types": ["RDS_Instance"],
                "min_severity": "high"
            },
            steps=steps
        )
    
    def _create_root_account_usage_playbook(self) -> IncidentPlaybook:
        """Create playbook for root account usage"""
        steps = [
            PlaybookStep(
                id="alert_security_team",
                name="Immediate Security Alert",
                description="Send immediate alert for root account usage",
                action_type="send_notification",
                parameters={
                    "channel": "security_critical",
                    "priority": "critical",
                    "message": "ROOT ACCOUNT USAGE DETECTED - Immediate investigation required"
                }
            ),
            PlaybookStep(
                id="audit_root_activity",
                name="Audit Root Account Activity",
                description="Review all recent root account activities",
                action_type="audit_root_activity",
                parameters={},
                depends_on=["alert_security_team"]
            ),
            PlaybookStep(
                id="disable_root_keys",
                name="Disable Root Access Keys",
                description="Disable any root account access keys",
                action_type="disable_root_access_keys",
                parameters={},
                requires_approval=True,
                depends_on=["audit_root_activity"]
            ),
            PlaybookStep(
                id="create_incident_report",
                name="Create Incident Report",
                description="Generate detailed incident report",
                action_type="create_incident_report",
                parameters={
                    "incident_type": "root_account_usage"
                },
                depends_on=["audit_root_activity"]
            )
        ]
        
        return IncidentPlaybook(
            id="root_usage_template",
            name="Root Account Usage Response",
            description="Critical response for root account usage",
            trigger_conditions={
                "finding_types": ["root_account_usage", "privilege_escalation"],
                "min_severity": "critical"
            },
            steps=steps
        )
    
    def _create_mass_deletion_playbook(self) -> IncidentPlaybook:
        """Create playbook for mass resource deletion"""
        steps = [
            PlaybookStep(
                id="emergency_alert",
                name="Emergency Alert",
                description="Send emergency alert for mass deletion",
                action_type="send_notification",
                parameters={
                    "channel": "emergency_response",
                    "priority": "critical",
                    "message": "MASS RESOURCE DELETION DETECTED - Emergency response initiated"
                }
            ),
            PlaybookStep(
                id="suspend_user_access",
                name="Suspend User Access",
                description="Suspend access for users involved in deletion",
                action_type="suspend_user_access",
                parameters={},
                requires_approval=True,
                depends_on=["emergency_alert"]
            ),
            PlaybookStep(
                id="inventory_deleted_resources",
                name="Inventory Deleted Resources",
                description="Create inventory of deleted resources",
                action_type="inventory_deleted_resources",
                parameters={},
                depends_on=["emergency_alert"]
            ),
            PlaybookStep(
                id="initiate_recovery",
                name="Initiate Recovery Process",
                description="Begin resource recovery from backups",
                action_type="initiate_recovery",
                parameters={},
                requires_approval=True,
                depends_on=["inventory_deleted_resources"]
            )
        ]
        
        return IncidentPlaybook(
            id="mass_deletion_template",
            name="Mass Resource Deletion Response",
            description="Emergency response for mass resource deletion",
            trigger_conditions={
                "finding_types": ["mass_deletion", "data_loss"],
                "min_severity": "critical"
            },
            steps=steps
        )
    
    # Action implementations
    
    def _isolate_ec2_instance(self, parameters: Dict[str, Any]) -> bool:
        """Isolate EC2 instance by moving to quarantine security group"""
        try:
            resource_id = parameters.get('resource_id')
            region = parameters.get('region')
            
            if not resource_id or not region:
                return False
            
            ec2_client = self.aws_client.get_client('ec2', region)
            
            # Create or get quarantine security group
            quarantine_sg = self._get_or_create_quarantine_security_group(ec2_client)
            
            # Update instance security groups
            ec2_client.modify_instance_attribute(
                InstanceId=resource_id,
                Groups=[quarantine_sg]
            )
            
            self.logger.info(f"EC2 instance {resource_id} isolated to quarantine security group")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to isolate EC2 instance: {str(e)}")
            return False
    
    def _create_ec2_snapshot(self, parameters: Dict[str, Any]) -> bool:
        """Create snapshot of EC2 instance volumes"""
        try:
            resource_id = parameters.get('resource_id')
            region = parameters.get('region')
            
            if not resource_id or not region:
                return False
            
            ec2_client = self.aws_client.get_client('ec2', region)
            
            # Get instance volumes
            response = ec2_client.describe_instances(InstanceIds=[resource_id])
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for block_device in instance.get('BlockDeviceMappings', []):
                        volume_id = block_device['Ebs']['VolumeId']
                        
                        # Create snapshot
                        snapshot_response = ec2_client.create_snapshot(
                            VolumeId=volume_id,
                            Description=f"Forensic snapshot for incident response - Instance {resource_id}"
                        )
                        
                        self.logger.info(f"Created snapshot {snapshot_response['SnapshotId']} for volume {volume_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create EC2 snapshot: {str(e)}")
            return False
    
    def _block_s3_public_access(self, parameters: Dict[str, Any]) -> bool:
        """Block public access to S3 bucket"""
        try:
            resource_id = parameters.get('resource_id')
            
            if not resource_id:
                return False
            
            s3_client = self.aws_client.get_client('s3')
            
            # Block public access
            s3_client.put_public_access_block(
                Bucket=resource_id,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            self.logger.info(f"Blocked public access for S3 bucket {resource_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block S3 public access: {str(e)}")
            return False
    
    def _disable_iam_user(self, parameters: Dict[str, Any]) -> bool:
        """Disable IAM user by attaching deny-all policy"""
        try:
            user_name = parameters.get('resource_id')
            
            if not user_name:
                return False
            
            iam_client = self.aws_client.get_client('iam')
            
            # Create or get deny-all policy
            deny_policy_arn = self._get_or_create_deny_all_policy(iam_client)
            
            # Attach deny policy to user
            iam_client.attach_user_policy(
                UserName=user_name,
                PolicyArn=deny_policy_arn
            )
            
            self.logger.info(f"Disabled IAM user {user_name} with deny-all policy")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to disable IAM user: {str(e)}")
            return False
    
    def _rotate_access_keys(self, parameters: Dict[str, Any]) -> bool:
        """Rotate access keys for IAM user"""
        try:
            user_name = parameters.get('resource_id')
            
            if not user_name:
                return False
            
            iam_client = self.aws_client.get_client('iam')
            
            # Get existing access keys
            response = iam_client.list_access_keys(UserName=user_name)
            
            for key_metadata in response['AccessKeyMetadata']:
                access_key_id = key_metadata['AccessKeyId']
                
                # Deactivate old key
                iam_client.update_access_key(
                    UserName=user_name,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )
                
                self.logger.info(f"Deactivated access key {access_key_id} for user {user_name}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rotate access keys: {str(e)}")
            return False
    
    def _update_security_group(self, parameters: Dict[str, Any]) -> bool:
        """Update security group rules"""
        try:
            resource_id = parameters.get('resource_id')
            region = parameters.get('region')
            action = parameters.get('action', 'remove_permissive_rules')
            
            if not resource_id or not region:
                return False
            
            ec2_client = self.aws_client.get_client('ec2', region)
            
            if action == 'remove_permissive_rules':
                # Get security group details
                response = ec2_client.describe_security_groups(GroupIds=[resource_id])
                
                for sg in response['SecurityGroups']:
                    for rule in sg.get('IpPermissions', []):
                        # Check for overly permissive rules
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                # Remove this rule
                                ec2_client.revoke_security_group_ingress(
                                    GroupId=resource_id,
                                    IpPermissions=[rule]
                                )
                                self.logger.info(f"Removed permissive rule from security group {resource_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update security group: {str(e)}")
            return False
    
    def _send_notification(self, parameters: Dict[str, Any]) -> bool:
        """Send notification to specified channel"""
        try:
            channel = parameters.get('channel', 'default')
            priority = parameters.get('priority', 'medium')
            message = parameters.get('message', 'Incident response notification')
            
            # This would integrate with actual notification systems
            # For now, we'll just log the notification
            self.logger.info(f"NOTIFICATION [{priority.upper()}] to {channel}: {message}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {str(e)}")
            return False
    
    def _create_support_case(self, parameters: Dict[str, Any]) -> bool:
        """Create AWS support case"""
        try:
            severity = parameters.get('severity', 'medium')
            category = parameters.get('category', 'security')
            
            # This would integrate with AWS Support API
            # For now, we'll just log the action
            self.logger.info(f"Created AWS support case - Severity: {severity}, Category: {category}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create support case: {str(e)}")
            return False
    
    def _backup_resource(self, parameters: Dict[str, Any]) -> bool:
        """Create backup of resource"""
        try:
            resource_type = parameters.get('resource_type')
            resource_id = parameters.get('resource_id')
            
            # This would implement resource-specific backup logic
            self.logger.info(f"Created backup for {resource_type} {resource_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to backup resource: {str(e)}")
            return False
    
    # Helper methods
    
    def _get_or_create_quarantine_security_group(self, ec2_client) -> str:
        """Get or create quarantine security group"""
        try:
            # Try to find existing quarantine security group
            response = ec2_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': ['incident-response-quarantine']
                    }
                ]
            )
            
            if response['SecurityGroups']:
                return response['SecurityGroups'][0]['GroupId']
            
            # Create new quarantine security group
            vpc_response = ec2_client.describe_vpcs(
                Filters=[{'Name': 'isDefault', 'Values': ['true']}]
            )
            
            vpc_id = vpc_response['VPCs'][0]['VpcId'] if vpc_response['VPCs'] else None
            
            create_response = ec2_client.create_security_group(
                GroupName='incident-response-quarantine',
                Description='Quarantine security group for incident response',
                VpcId=vpc_id
            )
            
            return create_response['GroupId']
            
        except Exception as e:
            self.logger.error(f"Failed to get/create quarantine security group: {str(e)}")
            raise
    
    def _get_or_create_deny_all_policy(self, iam_client) -> str:
        """Get or create deny-all policy"""
        policy_name = 'IncidentResponseDenyAll'
        
        try:
            # Try to get existing policy
            response = iam_client.get_policy(
                PolicyArn=f'arn:aws:iam::{self.aws_client.account_id}:policy/{policy_name}'
            )
            return response['Policy']['Arn']
            
        except iam_client.exceptions.NoSuchEntityException:
            # Create new policy
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
            
            response = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
                Description='Deny all policy for incident response'
            )
            
            return response['Policy']['Arn']
    
    def _is_step_approved(self, step: PlaybookStep) -> bool:
        """Check if step has been approved"""
        # This would implement approval checking logic
        # For now, return False to trigger approval request
        return False
    
    def _request_approval(self, playbook: IncidentPlaybook, step: PlaybookStep):
        """Request approval for step execution"""
        self.logger.info(f"Approval required for step: {step.name} in playbook: {playbook.name}")
        
        # This would integrate with approval workflow system
        # For now, we'll just log the request
        approval_request = {
            'playbook_id': playbook.id,
            'step_id': step.id,
            'step_name': step.name,
            'description': step.description,
            'requested_at': datetime.utcnow().isoformat(),
            'context': playbook.context
        }
        
        self.logger.info(f"Approval request: {json.dumps(approval_request, indent=2)}")
    
    def approve_step(self, playbook_id: str, step_id: str, approved_by: str) -> bool:
        """Approve a step for execution"""
        try:
            if playbook_id not in self.active_playbooks:
                return False
            
            playbook = self.active_playbooks[playbook_id]
            step = next((s for s in playbook.steps if s.id == step_id), None)
            
            if not step:
                return False
            
            # Mark step as approved and continue execution
            step.requires_approval = False
            
            self.logger.info(f"Step {step.name} approved by {approved_by}")
            
            # Resume playbook execution
            if playbook.status == PlaybookStatus.AWAITING_APPROVAL:
                playbook.status = PlaybookStatus.RUNNING
                self._execute_playbook_steps(playbook)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to approve step: {str(e)}")
            return False
    
    def get_playbook_status(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of playbook"""
        if playbook_id not in self.active_playbooks:
            return None
        
        playbook = self.active_playbooks[playbook_id]
        
        return {
            'id': playbook.id,
            'name': playbook.name,
            'status': playbook.status.value,
            'created_at': playbook.created_at.isoformat() if playbook.created_at else None,
            'started_at': playbook.started_at.isoformat() if playbook.started_at else None,
            'completed_at': playbook.completed_at.isoformat() if playbook.completed_at else None,
            'steps': [
                {
                    'id': step.id,
                    'name': step.name,
                    'status': step.status.value,
                    'started_at': step.started_at.isoformat() if step.started_at else None,
                    'completed_at': step.completed_at.isoformat() if step.completed_at else None,
                    'error_message': step.error_message
                }
                for step in playbook.steps
            ],
            'context': playbook.context
        }
    
    def rollback_playbook(self, playbook_id: str) -> bool:
        """Rollback executed playbook steps"""
        try:
            if playbook_id not in self.active_playbooks:
                return False
            
            playbook = self.active_playbooks[playbook_id]
            
            # Execute rollback actions in reverse order
            completed_steps = [s for s in reversed(playbook.steps) if s.status == StepStatus.COMPLETED]
            
            for step in completed_steps:
                if step.rollback_action:
                    self.logger.info(f"Rolling back step: {step.name}")
                    # Execute rollback action
                    # This would implement rollback logic
            
            playbook.status = PlaybookStatus.CANCELLED
            self.logger.info(f"Playbook {playbook.name} rolled back successfully")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rollback playbook: {str(e)}")
            return False

