"""
IAM role credential service for cloud providers.

Provides unified interface for managing IAM credentials across AWS, GCP, and Azure.
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

logger = logging.getLogger(__name__)


class IAMCredentialService:
    """Service for managing IAM credentials across cloud providers."""

    # Permission mapping to AWS IAM actions
    AWS_PERMISSION_MAPPING = {
        'read': [
            'rds:DescribeDBInstances',
            'rds:DescribeDBClusters',
            'rds-db:connect'
        ],
        'write': [
            'rds:DescribeDBInstances',
            'rds:DescribeDBClusters',
            'rds-db:connect'
        ],
        'admin': [
            'rds:*',
            'rds-db:*'
        ]
    }

    # GCP permission mapping (placeholder)
    GCP_PERMISSION_MAPPING = {
        'read': ['roles/cloudsql.client'],
        'write': ['roles/cloudsql.client'],
        'admin': ['roles/cloudsql.admin']
    }

    # Azure permission mapping (placeholder)
    AZURE_PERMISSION_MAPPING = {
        'read': ['Reader'],
        'write': ['Contributor'],
        'admin': ['Owner']
    }

    def __init__(self, aws_region: str = 'us-east-1'):
        """Initialize IAM credential service."""
        self.aws_region = aws_region
        if BOTO3_AVAILABLE:
            self.iam_client = boto3.client('iam', region_name=aws_region)
            self.sts_client = boto3.client('sts', region_name=aws_region)
        else:
            self.iam_client = None
            self.sts_client = None
            logger.warning("boto3 not available, AWS operations will fail")

    def create_aws_role(
        self,
        resource: str,
        application: str,
        permissions: List[str]
    ) -> Dict:
        """
        Create IAM role with trust policy for RDS/ElastiCache.

        Args:
            resource: Resource identifier (e.g., RDS instance ARN)
            application: Application name for role naming
            permissions: List of permissions (read, write, admin)

        Returns:
            Dict with role_arn and policy_document
        """
        if not BOTO3_AVAILABLE or not self.iam_client:
            raise RuntimeError("boto3 not available for AWS operations")

        try:
            # Generate role name
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            role_name = f"articdbm-{application}-{timestamp}"

            # Create trust policy for RDS/EC2
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": [
                                "rds.amazonaws.com",
                                "ec2.amazonaws.com"
                            ]
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }

            # Create the role
            create_role_response = self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"ArticDBM role for {application}",
                Tags=[
                    {'Key': 'Application', 'Value': application},
                    {'Key': 'ManagedBy', 'Value': 'ArticDBM'},
                    {'Key': 'Resource', 'Value': resource}
                ]
            )

            role_arn = create_role_response['Role']['Arn']

            # Build permission policy
            actions = []
            for perm in permissions:
                actions.extend(
                    self.AWS_PERMISSION_MAPPING.get(perm, [])
                )

            permission_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": list(set(actions)),
                        "Resource": resource
                    }
                ]
            }

            # Attach inline policy
            policy_name = f"{role_name}-policy"
            self.iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(permission_policy)
            )

            logger.info(f"Created AWS IAM role: {role_arn}")

            return {
                'role_arn': role_arn,
                'role_name': role_name,
                'policy_document': permission_policy,
                'trust_policy': trust_policy,
                'provider': 'aws',
                'created_at': datetime.utcnow().isoformat()
            }

        except ClientError as e:
            logger.error(f"Failed to create AWS IAM role: {e}")
            raise RuntimeError(f"AWS IAM role creation failed: {str(e)}")

    def create_gcp_service_account(
        self,
        resource: str,
        application: str,
        permissions: List[str]
    ) -> Dict:
        """
        Create GCP service account with Cloud SQL/Memorystore roles.

        Args:
            resource: Resource identifier (e.g., Cloud SQL instance)
            application: Application name for service account naming
            permissions: List of permissions (read, write, admin)

        Returns:
            Dict with service_account_email and key_json (placeholder)
        """
        # Placeholder implementation
        # In production, would use google-cloud-iam
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        service_account_name = f"articdbm-{application}-{timestamp}"
        service_account_email = (
            f"{service_account_name}@project-id.iam.gserviceaccount.com"
        )

        # Map permissions to GCP roles
        roles = []
        for perm in permissions:
            roles.extend(self.GCP_PERMISSION_MAPPING.get(perm, []))

        logger.warning(
            "GCP service account creation is a placeholder. "
            "Install google-cloud-iam for production use."
        )

        return {
            'service_account_email': service_account_email,
            'service_account_name': service_account_name,
            'key_json': {
                'type': 'service_account',
                'project_id': 'placeholder-project-id',
                'private_key_id': 'placeholder-key-id',
                'private_key': 'placeholder-private-key',
                'client_email': service_account_email,
                'client_id': 'placeholder-client-id'
            },
            'roles': list(set(roles)),
            'provider': 'gcp',
            'created_at': datetime.utcnow().isoformat(),
            'warning': 'Placeholder implementation - requires google-cloud-iam'
        }

    def create_azure_managed_identity(
        self,
        resource: str,
        application: str,
        permissions: List[str]
    ) -> Dict:
        """
        Create Azure managed identity.

        Args:
            resource: Resource identifier (e.g., Azure SQL database)
            application: Application name for identity naming
            permissions: List of permissions (read, write, admin)

        Returns:
            Dict with client_id and tenant_id (placeholder)
        """
        # Placeholder implementation
        # In production, would use azure-identity and azure-mgmt-msi
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        identity_name = f"articdbm-{application}-{timestamp}"

        # Map permissions to Azure roles
        roles = []
        for perm in permissions:
            roles.extend(self.AZURE_PERMISSION_MAPPING.get(perm, []))

        logger.warning(
            "Azure managed identity creation is a placeholder. "
            "Install azure-identity for production use."
        )

        return {
            'client_id': f"placeholder-client-id-{timestamp}",
            'tenant_id': 'placeholder-tenant-id',
            'identity_name': identity_name,
            'principal_id': f"placeholder-principal-id-{timestamp}",
            'roles': list(set(roles)),
            'provider': 'azure',
            'created_at': datetime.utcnow().isoformat(),
            'warning': 'Placeholder - requires azure-identity and azure-mgmt-msi'
        }

    def rotate_credentials(
        self,
        credential_id: str,
        provider_type: str
    ) -> Dict:
        """
        Rotate IAM credentials.

        Args:
            credential_id: Identifier for the credential (role ARN, SA email, etc)
            provider_type: Cloud provider (aws, gcp, azure)

        Returns:
            Dict with new credential information
        """
        if provider_type == 'aws':
            return self._rotate_aws_credentials(credential_id)
        elif provider_type == 'gcp':
            return self._rotate_gcp_credentials(credential_id)
        elif provider_type == 'azure':
            return self._rotate_azure_credentials(credential_id)
        else:
            raise ValueError(f"Unsupported provider type: {provider_type}")

    def _rotate_aws_credentials(self, role_arn: str) -> Dict:
        """Rotate AWS IAM role credentials."""
        if not BOTO3_AVAILABLE or not self.iam_client:
            raise RuntimeError("boto3 not available for AWS operations")

        try:
            # Extract role name from ARN
            role_name = role_arn.split('/')[-1]

            # Get current inline policies
            policies_response = self.iam_client.list_role_policies(
                RoleName=role_name
            )

            rotated_policies = []
            for policy_name in policies_response['PolicyNames']:
                # Get policy document
                policy_response = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )

                # Re-attach with new version (forcing rotation)
                self.iam_client.put_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(
                        policy_response['PolicyDocument']
                    )
                )
                rotated_policies.append(policy_name)

            logger.info(f"Rotated AWS IAM role credentials: {role_arn}")

            return {
                'role_arn': role_arn,
                'role_name': role_name,
                'rotated_policies': rotated_policies,
                'provider': 'aws',
                'rotated_at': datetime.utcnow().isoformat()
            }

        except ClientError as e:
            logger.error(f"Failed to rotate AWS credentials: {e}")
            raise RuntimeError(f"AWS credential rotation failed: {str(e)}")

    def _rotate_gcp_credentials(self, service_account_email: str) -> Dict:
        """Rotate GCP service account credentials (placeholder)."""
        logger.warning("GCP credential rotation is a placeholder")
        return {
            'service_account_email': service_account_email,
            'provider': 'gcp',
            'rotated_at': datetime.utcnow().isoformat(),
            'warning': 'Placeholder implementation'
        }

    def _rotate_azure_credentials(self, client_id: str) -> Dict:
        """Rotate Azure managed identity credentials (placeholder)."""
        logger.warning("Azure credential rotation is a placeholder")
        return {
            'client_id': client_id,
            'provider': 'azure',
            'rotated_at': datetime.utcnow().isoformat(),
            'warning': 'Placeholder implementation'
        }

    def revoke_credentials(
        self,
        credential_id: str,
        provider_type: str
    ) -> bool:
        """
        Revoke IAM credentials.

        Args:
            credential_id: Identifier for the credential
            provider_type: Cloud provider (aws, gcp, azure)

        Returns:
            True if successfully revoked
        """
        if provider_type == 'aws':
            return self._revoke_aws_credentials(credential_id)
        elif provider_type == 'gcp':
            return self._revoke_gcp_credentials(credential_id)
        elif provider_type == 'azure':
            return self._revoke_azure_credentials(credential_id)
        else:
            raise ValueError(f"Unsupported provider type: {provider_type}")

    def _revoke_aws_credentials(self, role_arn: str) -> bool:
        """Revoke AWS IAM role."""
        if not BOTO3_AVAILABLE or not self.iam_client:
            raise RuntimeError("boto3 not available for AWS operations")

        try:
            # Extract role name from ARN
            role_name = role_arn.split('/')[-1]

            # Delete all inline policies
            policies_response = self.iam_client.list_role_policies(
                RoleName=role_name
            )
            for policy_name in policies_response['PolicyNames']:
                self.iam_client.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )

            # Detach all managed policies
            attached_policies = self.iam_client.list_attached_role_policies(
                RoleName=role_name
            )
            for policy in attached_policies['AttachedPolicies']:
                self.iam_client.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy['PolicyArn']
                )

            # Delete the role
            self.iam_client.delete_role(RoleName=role_name)

            logger.info(f"Revoked AWS IAM role: {role_arn}")
            return True

        except ClientError as e:
            logger.error(f"Failed to revoke AWS credentials: {e}")
            raise RuntimeError(f"AWS credential revocation failed: {str(e)}")

    def _revoke_gcp_credentials(self, service_account_email: str) -> bool:
        """Revoke GCP service account (placeholder)."""
        logger.warning("GCP credential revocation is a placeholder")
        return True

    def _revoke_azure_credentials(self, client_id: str) -> bool:
        """Revoke Azure managed identity (placeholder)."""
        logger.warning("Azure credential revocation is a placeholder")
        return True
