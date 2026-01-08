"""
Security utilities for ArticDBM Manager.

Provides cryptographic operations including password hashing, API key generation,
data encryption/decryption, and secure username generation.
"""

import os
import secrets
import string
import base64
import logging
from typing import Tuple

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

logger = logging.getLogger(__name__)


def generate_secure_password(length: int = 32) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length in characters (default: 32)

    Returns:
        Secure random password containing uppercase, lowercase, digits, and symbols
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")

    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(characters) for _ in range(length))
    return password


def generate_api_key() -> str:
    """
    Generate a cryptographically secure 32-byte API key (base64 URL-safe).

    Returns:
        Base64 URL-safe encoded 32-byte random key
    """
    random_bytes = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password to hash

    Returns:
        Bcrypt hashed password (bytes)

    Raises:
        ValueError: If password is empty or None
    """
    if not password:
        raise ValueError("Password cannot be empty")

    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed


def verify_password(password: str, hashed: bytes) -> bool:
    """
    Verify a plain text password against a bcrypt hash.

    Args:
        password: Plain text password to verify
        hashed: Bcrypt hashed password (bytes)

    Returns:
        True if password matches hash, False otherwise
    """
    if not password or not hashed:
        return False

    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def get_encryption_key() -> bytes:
    """
    Get or generate the Fernet encryption key from environment.

    Attempts to load ENCRYPTION_KEY from environment. If not set,
    generates a new key and logs a warning (for development only).

    Returns:
        Fernet-compatible encryption key (bytes)

    Raises:
        ValueError: If key cannot be generated or loaded
    """
    encryption_key_env = os.getenv("ENCRYPTION_KEY")

    if encryption_key_env:
        try:
            # Assume base64-encoded key
            key_bytes = base64.urlsafe_b64decode(encryption_key_env + "==")
            if len(key_bytes) != 32:
                raise ValueError("Encryption key must be 32 bytes")
            return key_bytes
        except Exception as e:
            raise ValueError(f"Invalid ENCRYPTION_KEY format: {e}")

    # Generate new key for development
    logger.warning(
        "ENCRYPTION_KEY not set in environment. Generating ephemeral key. "
        "Set ENCRYPTION_KEY environment variable for production."
    )
    return Fernet.generate_key()


def _derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a Fernet-compatible key from a password using PBKDF2.

    Args:
        password: Password to derive key from
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)

    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key, salt


def encrypt_sensitive_data(data: str, key: bytes = None) -> bytes:
    """
    Encrypt sensitive data using Fernet (AES-128 in CBC mode).

    Args:
        data: Plain text data to encrypt
        key: Optional encryption key (uses get_encryption_key() if not provided)

    Returns:
        Encrypted data (bytes)

    Raises:
        ValueError: If data is empty or encryption fails
    """
    if not data:
        raise ValueError("Data cannot be empty")

    if key is None:
        key = get_encryption_key()

    try:
        cipher = Fernet(key)
        encrypted = cipher.encrypt(data.encode("utf-8"))
        return encrypted
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")


def decrypt_sensitive_data(encrypted: bytes, key: bytes = None) -> str:
    """
    Decrypt sensitive data using Fernet.

    Args:
        encrypted: Encrypted data (bytes)
        key: Optional encryption key (uses get_encryption_key() if not provided)

    Returns:
        Decrypted plain text (str)

    Raises:
        ValueError: If decryption fails or data is corrupted
    """
    if not encrypted:
        raise ValueError("Encrypted data cannot be empty")

    if key is None:
        key = get_encryption_key()

    try:
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def generate_username(prefix: str, length: int = 8) -> str:
    """
    Generate a secure username with prefix and random suffix.

    Args:
        prefix: Username prefix (e.g., "myapp_reader")
        length: Length of random suffix in characters (default: 8)

    Returns:
        Generated username (e.g., "myapp_reader_abc123XY")

    Raises:
        ValueError: If prefix is empty or invalid
    """
    if not prefix:
        raise ValueError("Prefix cannot be empty")

    if not isinstance(prefix, str):
        raise ValueError("Prefix must be a string")

    # Validate prefix contains only alphanumeric and underscore
    if not all(c.isalnum() or c == "_" for c in prefix):
        raise ValueError("Prefix must contain only alphanumeric characters and underscores")

    # Generate random suffix with alphanumeric characters
    suffix_chars = string.ascii_letters + string.digits
    suffix = "".join(secrets.choice(suffix_chars) for _ in range(length))

    return f"{prefix}_{suffix}"
