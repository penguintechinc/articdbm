"""PII detection service for GDPR compliance."""

import re
from typing import Any, Dict, List, Optional


class PIIDetector:
    """Detect GDPR-defined PII in PyDAL table columns."""

    # GDPR PII field name patterns
    FIELD_NAME_PATTERNS = {
        'email': [r'\bemail\b', r'\bmail\b', r'contact_email', r'e_?mail'],
        'phone': [r'\bphone\b', r'mobile', r'telephone', r'contact_phone'],
        'name': [r'full_name', r'\bname\b', r'fname', r'lname', r'first_name', r'last_name'],
        'ssn': [r'\bssn\b', r'social_security', r'tax_id', r'passport'],
        'dob': [r'\bdob\b', r'date_of_birth', r'birth_date', r'birthday'],
        'address': [r'\baddress\b', r'\bstreet\b', r'\bcity\b', r'postal_code', r'\bzip\b'],
        'credit_card': [r'card_number', r'cc_number', r'credit_card'],
        'national_id': [r'national_id', r'id_number', r'drivers_license'],
    }

    @staticmethod
    def detect_pii_columns(pydal_table) -> Dict[str, str]:
        """
        Scan PyDAL table for PII columns.

        Args:
            pydal_table: PyDAL table object

        Returns:
            Dict mapping column_name -> pii_type
            Example: {'email': 'email', 'phone': 'phone', 'address': 'address'}
        """
        pii_cols = {}

        for field in pydal_table:
            col_name = field.name
            col_type = str(field.type)

            # Skip system fields
            if col_name in ['id', 'created_on', 'modified_on', 'created_by', 'updated_by']:
                continue

            # Check field name patterns
            for pii_type, patterns in PIIDetector.FIELD_NAME_PATTERNS.items():
                if any(re.search(pattern, col_name, re.IGNORECASE) for pattern in patterns):
                    pii_cols[col_name] = pii_type
                    break

        return pii_cols

    @staticmethod
    def mask_pii_value(value: Any, pii_type: str) -> str:
        """
        Mask PII value based on type.

        Args:
            value: The actual PII value
            pii_type: Type of PII (email, phone, name, ssn, dob, address, etc.)

        Returns:
            Masked string representation
        """
        if value is None:
            return '***'

        if not isinstance(value, str):
            value = str(value)

        if not value:
            return '***'

        if pii_type == 'email':
            try:
                local, domain = value.split('@', 1)
                # john.doe@example.com → j***@example.com
                masked_local = f"{local[0]}***" if len(local) > 0 else '***'
                return f"{masked_local}@{domain}"
            except ValueError:
                return '***@***'

        elif pii_type == 'phone':
            # +1-555-123-4567 → +1-***-****67
            # 555-1234 → ***-1234
            masked = re.sub(r'\d(?=\d{2})', '*', value)
            return masked

        elif pii_type == 'name':
            # John Doe → J***
            if len(value) > 1:
                return f"{value[0]}***"
            return value

        elif pii_type in ['ssn', 'passport', 'national_id']:
            # Show only last 4 if possible
            if len(value) >= 4:
                return f"***-{value[-4:]}"
            return '***'

        elif pii_type in ['dob', 'address', 'credit_card']:
            # Complete masking
            return '***'

        # Default masking
        return '***'

    @staticmethod
    def has_pii_fields(pydal_table) -> bool:
        """Check if table has any PII fields."""
        return bool(PIIDetector.detect_pii_columns(pydal_table))

    @staticmethod
    def get_pii_columns_info(pydal_table) -> Dict[str, Dict[str, str]]:
        """
        Get detailed information about PII columns.

        Args:
            pydal_table: PyDAL table object

        Returns:
            Dict with column info including type and pii_type
        """
        pii_columns = PIIDetector.detect_pii_columns(pydal_table)
        result = {}

        for field in pydal_table:
            col_name = field.name
            if col_name in pii_columns:
                result[col_name] = {
                    'pii_type': pii_columns[col_name],
                    'field_type': str(field.type),
                    'required': field.requires is not None,
                }

        return result
