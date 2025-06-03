import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///security_automation.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # AWS Configuration
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_DEFAULT_REGION = os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'
    AWS_SESSION_TOKEN = os.environ.get('AWS_SESSION_TOKEN')  # For temporary credentials
    
    # Security Scanning Configuration
    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 60))
    AUTO_REMEDIATION_ENABLED = os.environ.get('AUTO_REMEDIATION_ENABLED', 'false').lower() == 'true'
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', 5))
    
    # Notification Configuration
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    EMAIL_SMTP_SERVER = os.environ.get('EMAIL_SMTP_SERVER')
    EMAIL_SMTP_PORT = int(os.environ.get('EMAIL_SMTP_PORT', 587))
    EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
    NOTIFICATION_EMAIL = os.environ.get('NOTIFICATION_EMAIL')
    
    # Compliance Standards
    ENABLED_COMPLIANCE_STANDARDS = os.environ.get('ENABLED_COMPLIANCE_STANDARDS', 'CIS,SOC2').split(',')
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'security_automation.log')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///dev_security_automation.db'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///prod_security_automation.db'

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    AUTO_REMEDIATION_ENABLED = False

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'default')
    return config.get(env, config['default'])

# AWS Resource Types to Monitor
AWS_RESOURCE_TYPES = {
    'EC2': ['instances', 'security_groups', 'key_pairs', 'volumes', 'snapshots'],
    'S3': ['buckets'],
    'RDS': ['instances', 'clusters', 'snapshots'],
    'IAM': ['users', 'roles', 'policies', 'groups'],
    'VPC': ['vpcs', 'subnets', 'route_tables', 'network_acls', 'internet_gateways'],
    'Lambda': ['functions'],
    'CloudTrail': ['trails'],
    'CloudWatch': ['alarms', 'log_groups'],
    'KMS': ['keys'],
    'ELB': ['load_balancers'],
    'ECS': ['clusters', 'services', 'tasks'],
    'EKS': ['clusters']
}

# Security Check Categories
SECURITY_CHECK_CATEGORIES = {
    'access_control': 'Access Control and IAM',
    'data_protection': 'Data Protection and Encryption',
    'network_security': 'Network Security',
    'logging_monitoring': 'Logging and Monitoring',
    'backup_recovery': 'Backup and Recovery',
    'compliance': 'Compliance and Governance',
    'vulnerability': 'Vulnerability Management',
    'configuration': 'Configuration Management'
}

# Severity Levels
SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']

# Default Security Policies
DEFAULT_SECURITY_POLICIES = [
    {
        'name': 'S3 Bucket Public Read Access',
        'description': 'Detect S3 buckets with public read access',
        'policy_type': 'security',
        'resource_types': ['S3'],
        'severity': 'high',
        'auto_remediate': True,
        'rules': {
            'check_type': 'bucket_acl',
            'condition': 'public_read_access',
            'action': 'remove_public_access'
        }
    },
    {
        'name': 'EC2 Security Group Open to World',
        'description': 'Detect security groups with 0.0.0.0/0 access on sensitive ports',
        'policy_type': 'security',
        'resource_types': ['EC2'],
        'severity': 'critical',
        'auto_remediate': False,
        'rules': {
            'check_type': 'security_group_rules',
            'condition': 'open_to_world',
            'sensitive_ports': [22, 3389, 1433, 3306, 5432]
        }
    },
    {
        'name': 'RDS Instance Encryption',
        'description': 'Ensure RDS instances have encryption enabled',
        'policy_type': 'compliance',
        'resource_types': ['RDS'],
        'severity': 'medium',
        'auto_remediate': False,
        'rules': {
            'check_type': 'encryption_status',
            'condition': 'encryption_disabled'
        }
    }
]

