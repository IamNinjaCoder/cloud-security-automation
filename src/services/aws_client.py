import boto3
import json
import logging
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Optional, Any
from src.config import get_config

logger = logging.getLogger(__name__)

class AWSClient:
    """AWS client wrapper for security automation"""
    
    def __init__(self):
        self.config = get_config()
        self._clients = {}
        self._session = None
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize AWS session with credentials"""
        try:
            session_kwargs = {
                'region_name': self.config.AWS_DEFAULT_REGION
            }
            
            # Add credentials if provided
            if self.config.AWS_ACCESS_KEY_ID and self.config.AWS_SECRET_ACCESS_KEY:
                session_kwargs.update({
                    'aws_access_key_id': self.config.AWS_ACCESS_KEY_ID,
                    'aws_secret_access_key': self.config.AWS_SECRET_ACCESS_KEY
                })
                
                if self.config.AWS_SESSION_TOKEN:
                    session_kwargs['aws_session_token'] = self.config.AWS_SESSION_TOKEN
            
            self._session = boto3.Session(**session_kwargs)
            logger.info("AWS session initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {str(e)}")
            raise
    
    def get_client(self, service_name: str, region: str = None) -> boto3.client:
        """Get AWS service client"""
        region = region or self.config.AWS_DEFAULT_REGION
        client_key = f"{service_name}_{region}"
        
        if client_key not in self._clients:
            try:
                self._clients[client_key] = self._session.client(service_name, region_name=region)
                logger.debug(f"Created {service_name} client for region {region}")
            except Exception as e:
                logger.error(f"Failed to create {service_name} client: {str(e)}")
                raise
        
        return self._clients[client_key]
    
    def get_available_regions(self, service_name: str = 'ec2') -> List[str]:
        """Get list of available AWS regions for a service"""
        try:
            client = self.get_client(service_name)
            regions = client.describe_regions()['Regions']
            return [region['RegionName'] for region in regions]
        except Exception as e:
            logger.error(f"Failed to get available regions: {str(e)}")
            return [self.config.AWS_DEFAULT_REGION]
    
    def get_account_id(self) -> Optional[str]:
        """Get AWS account ID"""
        try:
            sts_client = self.get_client('sts')
            response = sts_client.get_caller_identity()
            return response.get('Account')
        except Exception as e:
            logger.error(f"Failed to get account ID: {str(e)}")
            return None
    
    def test_connection(self) -> Dict[str, Any]:
        """Test AWS connection and permissions"""
        result = {
            'connected': False,
            'account_id': None,
            'region': self.config.AWS_DEFAULT_REGION,
            'permissions': {},
            'error': None
        }
        
        try:
            # Test basic connection
            account_id = self.get_account_id()
            if account_id:
                result['connected'] = True
                result['account_id'] = account_id
                
                # Test service permissions
                result['permissions'] = self._test_service_permissions()
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"AWS connection test failed: {str(e)}")
        
        return result
    
    def _test_service_permissions(self) -> Dict[str, bool]:
        """Test permissions for various AWS services"""
        permissions = {}
        
        # Test EC2 permissions
        try:
            ec2_client = self.get_client('ec2')
            ec2_client.describe_instances(MaxResults=1)
            permissions['ec2'] = True
        except Exception:
            permissions['ec2'] = False
        
        # Test S3 permissions
        try:
            s3_client = self.get_client('s3')
            s3_client.list_buckets()
            permissions['s3'] = True
        except Exception:
            permissions['s3'] = False
        
        # Test IAM permissions
        try:
            iam_client = self.get_client('iam')
            iam_client.list_users(MaxItems=1)
            permissions['iam'] = True
        except Exception:
            permissions['iam'] = False
        
        # Test RDS permissions
        try:
            rds_client = self.get_client('rds')
            rds_client.describe_db_instances(MaxRecords=1)
            permissions['rds'] = True
        except Exception:
            permissions['rds'] = False
        
        return permissions

class AWSResourceDiscovery:
    """AWS resource discovery service"""
    
    def __init__(self, aws_client: AWSClient):
        self.aws_client = aws_client
        self.logger = logging.getLogger(__name__)
    
    def discover_ec2_instances(self, region: str = None) -> List[Dict[str, Any]]:
        """Discover EC2 instances"""
        try:
            ec2_client = self.aws_client.get_client('ec2', region)
            response = ec2_client.describe_instances()
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        'resource_id': instance['InstanceId'],
                        'resource_type': 'EC2_Instance',
                        'region': region or self.aws_client.config.AWS_DEFAULT_REGION,
                        'resource_name': self._get_instance_name(instance),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                        'configuration': {
                            'instance_type': instance.get('InstanceType'),
                            'state': instance.get('State', {}).get('Name'),
                            'vpc_id': instance.get('VpcId'),
                            'subnet_id': instance.get('SubnetId'),
                            'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            'public_ip': instance.get('PublicIpAddress'),
                            'private_ip': instance.get('PrivateIpAddress'),
                            'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None
                        }
                    })
            
            self.logger.info(f"Discovered {len(instances)} EC2 instances in region {region}")
            return instances
            
        except Exception as e:
            self.logger.error(f"Failed to discover EC2 instances: {str(e)}")
            return []
    
    def discover_s3_buckets(self) -> List[Dict[str, Any]]:
        """Discover S3 buckets"""
        try:
            s3_client = self.aws_client.get_client('s3')
            response = s3_client.list_buckets()
            
            buckets = []
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Get bucket location
                try:
                    location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    region = location_response['LocationConstraint'] or 'us-east-1'
                except Exception:
                    region = 'us-east-1'
                
                # Get bucket tags
                tags = {}
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    tags = {tag['Key']: tag['Value'] for tag in tags_response['TagSet']}
                except Exception:
                    pass
                
                buckets.append({
                    'resource_id': bucket_name,
                    'resource_type': 'S3_Bucket',
                    'region': region,
                    'resource_name': bucket_name,
                    'tags': tags,
                    'configuration': {
                        'creation_date': bucket['CreationDate'].isoformat() if bucket.get('CreationDate') else None
                    }
                })
            
            self.logger.info(f"Discovered {len(buckets)} S3 buckets")
            return buckets
            
        except Exception as e:
            self.logger.error(f"Failed to discover S3 buckets: {str(e)}")
            return []
    
    def discover_security_groups(self, region: str = None) -> List[Dict[str, Any]]:
        """Discover EC2 security groups"""
        try:
            ec2_client = self.aws_client.get_client('ec2', region)
            response = ec2_client.describe_security_groups()
            
            security_groups = []
            for sg in response['SecurityGroups']:
                security_groups.append({
                    'resource_id': sg['GroupId'],
                    'resource_type': 'EC2_SecurityGroup',
                    'region': region or self.aws_client.config.AWS_DEFAULT_REGION,
                    'resource_name': sg.get('GroupName'),
                    'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])},
                    'configuration': {
                        'description': sg.get('Description'),
                        'vpc_id': sg.get('VpcId'),
                        'inbound_rules': sg.get('IpPermissions', []),
                        'outbound_rules': sg.get('IpPermissionsEgress', [])
                    }
                })
            
            self.logger.info(f"Discovered {len(security_groups)} security groups in region {region}")
            return security_groups
            
        except Exception as e:
            self.logger.error(f"Failed to discover security groups: {str(e)}")
            return []
    
    def discover_rds_instances(self, region: str = None) -> List[Dict[str, Any]]:
        """Discover RDS instances"""
        try:
            rds_client = self.aws_client.get_client('rds', region)
            response = rds_client.describe_db_instances()
            
            instances = []
            for db in response['DBInstances']:
                # Get tags
                tags = {}
                try:
                    tags_response = rds_client.list_tags_for_resource(ResourceName=db['DBInstanceArn'])
                    tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
                except Exception:
                    pass
                
                instances.append({
                    'resource_id': db['DBInstanceIdentifier'],
                    'resource_type': 'RDS_Instance',
                    'region': region or self.aws_client.config.AWS_DEFAULT_REGION,
                    'resource_name': db['DBInstanceIdentifier'],
                    'tags': tags,
                    'configuration': {
                        'engine': db.get('Engine'),
                        'engine_version': db.get('EngineVersion'),
                        'instance_class': db.get('DBInstanceClass'),
                        'status': db.get('DBInstanceStatus'),
                        'encrypted': db.get('StorageEncrypted', False),
                        'multi_az': db.get('MultiAZ', False),
                        'publicly_accessible': db.get('PubliclyAccessible', False),
                        'vpc_security_groups': [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])],
                        'backup_retention_period': db.get('BackupRetentionPeriod')
                    }
                })
            
            self.logger.info(f"Discovered {len(instances)} RDS instances in region {region}")
            return instances
            
        except Exception as e:
            self.logger.error(f"Failed to discover RDS instances: {str(e)}")
            return []
    
    def _get_instance_name(self, instance: Dict[str, Any]) -> str:
        """Extract instance name from tags"""
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                return tag['Value']
        return instance['InstanceId']
    
    def discover_all_resources(self, regions: List[str] = None) -> List[Dict[str, Any]]:
        """Discover all supported resources across regions"""
        if not regions:
            regions = [self.aws_client.config.AWS_DEFAULT_REGION]
        
        all_resources = []
        
        # Discover S3 buckets (global service)
        all_resources.extend(self.discover_s3_buckets())
        
        # Discover regional resources
        for region in regions:
            all_resources.extend(self.discover_ec2_instances(region))
            all_resources.extend(self.discover_security_groups(region))
            all_resources.extend(self.discover_rds_instances(region))
        
        self.logger.info(f"Total resources discovered: {len(all_resources)}")
        return all_resources

