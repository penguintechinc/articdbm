"""
mTLS Certificate Credential Service for MarchProxy Authentication.

Provides X.509 certificate generation, rotation, and revocation
with RSA key pairs for mutual TLS authentication.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from app.utils.security import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)


class MTLSCredentialService:
    """
    Service for managing mTLS certificate credentials.

    Handles generation, rotation, and revocation of X.509 certificates
    with RSA key pairs for client authentication.
    """

    def __init__(self):
        """Initialize the mTLS credential service."""
        self.key_size = 2048
        self.hash_algorithm = hashes.SHA256()
        self.ca_cert = None
        self.ca_key = None

    def _load_or_generate_ca(self) -> tuple:
        """
        Load CA certificate and key from environment or generate self-signed CA.

        Returns:
            Tuple of (ca_cert, ca_key)

        Raises:
            ValueError: If CA cert exists but key is missing or vice versa
        """
        if self.ca_cert and self.ca_key:
            return self.ca_cert, self.ca_key

        # Try to load from environment variables
        ca_cert_pem = os.getenv("MTLS_CA_CERT")
        ca_key_pem = os.getenv("MTLS_CA_KEY")

        if ca_cert_pem and ca_key_pem:
            try:
                self.ca_cert = x509.load_pem_x509_certificate(
                    ca_cert_pem.encode(), default_backend()
                )
                self.ca_key = serialization.load_pem_private_key(
                    ca_key_pem.encode(), password=None, backend=default_backend()
                )
                logger.info("Loaded CA certificate from environment")
                return self.ca_cert, self.ca_key
            except Exception as e:
                logger.error(f"Failed to load CA from environment: {e}")
                raise ValueError(f"Invalid CA certificate or key: {e}")

        if ca_cert_pem or ca_key_pem:
            raise ValueError(
                "Both MTLS_CA_CERT and MTLS_CA_KEY must be set, or neither"
            )

        # Generate self-signed CA
        logger.warning("Generating self-signed CA certificate (development only)")
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )

        ca_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ArticDBM"),
                x509.NameAttribute(NameOID.COMMON_NAME, "ArticDBM Root CA"),
            ]
        )

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, self.hash_algorithm, default_backend())
        )

        logger.info("Generated self-signed CA certificate")
        return self.ca_cert, self.ca_key

    def generate_certificate(
        self,
        resource: Dict[str, Any],
        application: Optional[Dict[str, Any]] = None,
        permissions: Optional[list[str]] = None,
        valid_days: int = 365,
    ) -> Dict[str, Any]:
        """
        Generate a new mTLS client certificate.

        Args:
            resource: Resource dict with 'name', 'endpoint', etc.
            application: Optional application dict with 'name'
            permissions: List of permissions (not encoded in cert, stored in DB)
            valid_days: Certificate validity period in days (default: 365)

        Returns:
            Dictionary containing:
            - cert_pem: Client certificate in PEM format (str)
            - key_pem_encrypted: Encrypted private key (bytes)
            - ca_cert_pem: CA certificate in PEM format (str)

        Raises:
            ValueError: If resource data is invalid
            KeyError: If required resource fields are missing
        """
        if permissions is None:
            permissions = ["read"]

        # Validate resource has required fields
        if not resource.get("name"):
            raise KeyError("Resource must have 'name' field")

        resource_name = resource.get("name")
        app_name = application.get("name") if application else "default"
        endpoint = resource.get("endpoint", "localhost")

        # Load or generate CA
        ca_cert, ca_key = self._load_or_generate_ca()

        # Generate RSA private key for client
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend(),
        )

        # Build certificate subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ArticDBM"),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"{app_name}.{resource_name}"
                ),
            ]
        )

        # Build certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
        )

        # Add Subject Alternative Name (SAN)
        san_list = [x509.DNSName(endpoint)]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

        # Add Key Usage extension (client auth)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add Extended Key Usage (client authentication)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )

        # Sign certificate with CA key
        client_cert = builder.sign(ca_key, self.hash_algorithm, default_backend())

        # Serialize certificate to PEM
        cert_pem = client_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("utf-8")

        # Serialize private key to PEM (unencrypted)
        key_pem = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Encrypt private key using app encryption utilities
        key_pem_encrypted = encrypt_data(key_pem)

        # Serialize CA certificate to PEM
        ca_cert_pem = ca_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("utf-8")

        logger.info(
            f"Generated mTLS certificate for resource={resource_name}, "
            f"application={app_name}, valid_days={valid_days}"
        )

        return {
            "cert_pem": cert_pem,
            "key_pem_encrypted": key_pem_encrypted,
            "ca_cert_pem": ca_cert_pem,
        }

    def rotate_certificate(
        self, credential_id: int, resource: Dict[str, Any], valid_days: int = 365
    ) -> Dict[str, Any]:
        """
        Rotate a certificate by generating a new cert/key pair.

        Args:
            credential_id: ID of credential to rotate
            resource: Resource dict for certificate generation
            valid_days: Certificate validity period in days (default: 365)

        Returns:
            Dictionary containing:
            - cert_pem: New client certificate in PEM format
            - key_pem_encrypted: New encrypted private key
            - ca_cert_pem: CA certificate in PEM format

        Raises:
            ValueError: If resource data is invalid
        """
        logger.info(f"Rotating mTLS certificate for credential {credential_id}")

        # For rotation, we generate a completely new certificate
        # In practice, you'd fetch the application info from DB using credential_id
        application = {"name": "rotated_app"}  # Placeholder

        return self.generate_certificate(
            resource=resource,
            application=application,
            permissions=None,
            valid_days=valid_days,
        )

    def revoke_certificate(self, credential_id: int) -> bool:
        """
        Revoke a certificate by marking it as inactive.

        In production, this would:
        1. Add certificate to CRL (Certificate Revocation List)
        2. Update database to mark credential as inactive
        3. Optionally publish updated CRL

        Args:
            credential_id: ID of credential to revoke

        Returns:
            True if revocation was successful, False otherwise

        Raises:
            ValueError: If credential_id is invalid
        """
        if not isinstance(credential_id, int) or credential_id <= 0:
            raise ValueError("credential_id must be a positive integer")

        try:
            # Import here to avoid circular imports
            from app.extensions import pydal_manager

            # Get PyDAL database instance
            db = pydal_manager.db

            # Mark credential as inactive in database
            credential = db(db.credentials.id == credential_id).select(
                db.credentials.id
            ).first()

            if not credential:
                logger.warning(f"Credential {credential_id} not found for revocation")
                return False

            # Update credential to inactive
            db(db.credentials.id == credential_id).update(is_active=False)
            db.commit()

            # TODO: In production, add to CRL and publish
            # self._add_to_crl(credential_id)

            logger.info(f"Revoked mTLS certificate credential {credential_id}")
            return True

        except Exception as e:
            logger.error(
                f"mTLS certificate revocation failed for credential {credential_id}: {e}"
            )
            raise Exception(f"Failed to revoke certificate: {e}")

    def get_ca_certificate(self) -> str:
        """
        Get the CA certificate in PEM format.

        Returns:
            CA certificate PEM string

        Raises:
            ValueError: If CA certificate cannot be loaded
        """
        try:
            ca_cert, _ = self._load_or_generate_ca()
            ca_cert_pem = ca_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode("utf-8")
            return ca_cert_pem

        except Exception as e:
            logger.error(f"Failed to get CA certificate: {e}")
            raise ValueError(f"Cannot retrieve CA certificate: {e}")
