from src.models import db
from datetime import datetime
import json

class AWSResource(db.Model):
    """Model for AWS resources discovered during scans"""
    __tablename__ = 'aws_resources'
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.String(255), nullable=False)
    resource_type = db.Column(db.String(100), nullable=False)  # EC2, S3, RDS, etc.
    region = db.Column(db.String(50), nullable=False)
    account_id = db.Column(db.String(20), nullable=False)
    resource_name = db.Column(db.String(255))
    tags = db.Column(db.Text)  # JSON string of tags
    configuration = db.Column(db.Text)  # JSON string of resource configuration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')  # active, terminated, etc.
    
    # Relationships
    findings = db.relationship('SecurityFinding', backref='resource', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<AWSResource {self.resource_type}:{self.resource_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'resource_type': self.resource_type,
            'region': self.region,
            'account_id': self.account_id,
            'resource_name': self.resource_name,
            'tags': json.loads(self.tags) if self.tags else {},
            'configuration': json.loads(self.configuration) if self.configuration else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'status': self.status,
            'findings_count': len(self.findings)
        }

class SecurityFinding(db.Model):
    """Model for security findings and vulnerabilities"""
    __tablename__ = 'security_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('aws_resources.id'), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)  # vulnerability, misconfiguration, compliance
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text)
    compliance_standard = db.Column(db.String(100))  # CIS, SOC2, PCI-DSS, etc.
    rule_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='open')  # open, resolved, suppressed
    auto_remediable = db.Column(db.Boolean, default=False)
    remediation_status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<SecurityFinding {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'finding_type': self.finding_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'recommendation': self.recommendation,
            'compliance_standard': self.compliance_standard,
            'rule_id': self.rule_id,
            'status': self.status,
            'auto_remediable': self.auto_remediable,
            'remediation_status': self.remediation_status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }

class SecurityPolicy(db.Model):
    """Model for security policies and rules"""
    __tablename__ = 'security_policies'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    policy_type = db.Column(db.String(50), nullable=False)  # compliance, security, custom
    resource_types = db.Column(db.Text)  # JSON array of applicable resource types
    rules = db.Column(db.Text, nullable=False)  # JSON string of policy rules
    severity = db.Column(db.String(20), default='medium')
    enabled = db.Column(db.Boolean, default=True)
    auto_remediate = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SecurityPolicy {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'policy_type': self.policy_type,
            'resource_types': json.loads(self.resource_types) if self.resource_types else [],
            'rules': json.loads(self.rules) if self.rules else {},
            'severity': self.severity,
            'enabled': self.enabled,
            'auto_remediate': self.auto_remediate,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ScanJob(db.Model):
    """Model for tracking security scan jobs"""
    __tablename__ = 'scan_jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    job_type = db.Column(db.String(50), nullable=False)  # discovery, security_scan, compliance_check
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    region = db.Column(db.String(50))
    resource_types = db.Column(db.Text)  # JSON array of resource types to scan
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    resources_scanned = db.Column(db.Integer, default=0)
    findings_created = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanJob {self.job_type}:{self.status}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'job_type': self.job_type,
            'status': self.status,
            'region': self.region,
            'resource_types': json.loads(self.resource_types) if self.resource_types else [],
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'resources_scanned': self.resources_scanned,
            'findings_created': self.findings_created,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class RemediationAction(db.Model):
    """Model for tracking automated remediation actions"""
    __tablename__ = 'remediation_actions'
    
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('security_findings.id'), nullable=False)
    action_type = db.Column(db.String(100), nullable=False)  # fix_security_group, enable_encryption, etc.
    action_details = db.Column(db.Text)  # JSON string of action parameters
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, failed
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    rollback_info = db.Column(db.Text)  # JSON string for rollback if needed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    finding = db.relationship('SecurityFinding', backref='remediation_actions')
    
    def __repr__(self):
        return f'<RemediationAction {self.action_type}:{self.status}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'action_type': self.action_type,
            'action_details': json.loads(self.action_details) if self.action_details else {},
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'rollback_info': json.loads(self.rollback_info) if self.rollback_info else {},
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

