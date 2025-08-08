"""
Hardcoded Secrets Analyzer for AODS
Handles detection and analysis of hardcoded authentication secrets.
"""

import base64
import logging
import re
from typing import Dict, List, Optional

from core.apk_ctx import APKContext
from .data_structures import (
    AuthenticationVulnerability,
    SECRET_PATTERNS
)

logger = logging.getLogger(__name__)

class SecretsAnalyzer:
    """Analyzer for hardcoded authentication secrets."""
    
    def __init__(self):
        """Initialize secrets analyzer with patterns."""
        self.vulnerabilities = []
        self.secret_patterns = SECRET_PATTERNS
    
    def analyze_hardcoded_secrets(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze hardcoded authentication secrets."""
        logger.info("Analyzing hardcoded authentication secrets")
        
        self.vulnerabilities = []
        
        if hasattr(apk_ctx, 'source_files'):
            for file_path, content in apk_ctx.source_files.items():
                self._check_hardcoded_secrets_in_file(file_path, content)
        
        # Also check resource files
        if hasattr(apk_ctx, 'resource_files'):
            for file_path, content in apk_ctx.resource_files.items():
                self._check_hardcoded_secrets_in_file(file_path, content)
        
        # Check configuration files
        if hasattr(apk_ctx, 'config_files'):
            for file_path, content in apk_ctx.config_files.items():
                self._check_hardcoded_secrets_in_file(file_path, content)
        
        return self.vulnerabilities
    
    def _check_hardcoded_secrets_in_file(self, file_path: str, content: str):
        """Check for hardcoded secrets in a file."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)
                    decoded_value = self._try_decode_value(secret_value)
                    
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type=f"hardcoded_{secret_type}",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        decoded_value=decoded_value,
                        secret_value=secret_value,
                        line_number=line_num,
                        severity="CRITICAL"
                    ))
            
            # Additional secret patterns for comprehensive detection
            self._check_additional_secret_patterns(file_path, line_num, line)
    
    def _check_additional_secret_patterns(self, file_path: str, line_num: int, line: str):
        """Check for additional secret patterns not covered by main patterns."""
        
        # Check for hardcoded private keys
        if re.search(r"-----BEGIN.*PRIVATE KEY-----", line, re.IGNORECASE):
            self.vulnerabilities.append(AuthenticationVulnerability(
                vuln_type="hardcoded_private_key",
                location=f"{file_path}:{line_num}",
                value=line.strip(),
                line_number=line_num,
                severity="CRITICAL"
            ))
        
        # Check for hardcoded certificates
        if re.search(r"-----BEGIN CERTIFICATE-----", line, re.IGNORECASE):
            self.vulnerabilities.append(AuthenticationVulnerability(
                vuln_type="hardcoded_certificate",
                location=f"{file_path}:{line_num}",
                value=line.strip(),
                line_number=line_num,
                severity="HIGH"
            ))
        
        # Check for database connection strings with credentials
        if re.search(r"(?:jdbc|mongodb|mysql|postgresql)://.*:.*@", line, re.IGNORECASE):
            self.vulnerabilities.append(AuthenticationVulnerability(
                vuln_type="hardcoded_db_credentials",
                location=f"{file_path}:{line_num}",
                value=line.strip(),
                line_number=line_num,
                severity="CRITICAL"
            ))
        
        # Check for hardcoded encryption keys
        key_patterns = [
            r"(?:encryption|crypto).*key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})",
            r"(?:aes|des|rsa).*key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})"
        ]
        for pattern in key_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                key_value = match.group(1)
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="hardcoded_encryption_key",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    secret_value=key_value,
                    line_number=line_num,
                    severity="CRITICAL"
                ))
        
        # Check for hardcoded HMAC secrets
        if re.search(r"hmac.*secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})", line, re.IGNORECASE):
            match = re.search(r"hmac.*secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9+/=]{16,})", line, re.IGNORECASE)
            if match:
                secret_value = match.group(1)
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="hardcoded_hmac_secret",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    secret_value=secret_value,
                    line_number=line_num,
                    severity="HIGH"
                ))
    
    def _try_decode_value(self, value: str) -> Optional[str]:
        """Try to decode potentially encoded values."""
        try:
            # Try base64 decoding
            if len(value) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
                decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 0:
                    return f"Base64 decoded: {decoded}"
        except Exception as e:
            self.logger.debug(f"Base64 decoding failed: {e}")
        
        try:
            # Try JWT decoding
            if value.count('.') == 2:
                parts = value.split('.')
                for i, part in enumerate(parts[:2]):  # Header and payload
                    # Add padding if needed
                    padded = part + '=' * (4 - len(part) % 4)
                    decoded = base64.urlsafe_b64decode(padded).decode('utf-8', errors='ignore')
                    if decoded:
                        return f"JWT part {i+1}: {decoded}"
        except Exception as e:
            self.logger.debug(f"JWT decoding failed: {e}")
        
        try:
            # Try hex decoding
            if len(value) >= 8 and all(c in '0123456789abcdefABCDEF' for c in value):
                decoded = bytes.fromhex(value).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 0:
                    return f"Hex decoded: {decoded}"
        except Exception as e:
            self.logger.debug(f"Hex decoding failed: {e}")
        
        return None
    
    def get_secret_types_found(self, apk_ctx: APKContext) -> Dict[str, int]:
        """Get count of each type of secret found."""
        vulnerabilities = self.analyze_hardcoded_secrets(apk_ctx)
        secret_counts = {}
        
        for vuln in vulnerabilities:
            secret_type = vuln.vuln_type
            secret_counts[secret_type] = secret_counts.get(secret_type, 0) + 1
        
        return secret_counts
    
    def has_hardcoded_secrets(self, apk_ctx: APKContext) -> bool:
        """Check if the app contains hardcoded secrets."""
        vulnerabilities = self.analyze_hardcoded_secrets(apk_ctx)
        return len(vulnerabilities) > 0
    
    def get_high_entropy_strings(self, apk_ctx: APKContext) -> List[dict]:
        """Find high-entropy strings that might be secrets."""
        high_entropy_strings = []
        
        if not hasattr(apk_ctx, 'source_files'):
            return high_entropy_strings
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    # Look for high-entropy strings
                    matches = re.findall(r'["\']([a-zA-Z0-9+/=]{20,})["\']', line)
                    for match in matches:
                        entropy = self._calculate_entropy(match)
                        if entropy > 4.0:  # High entropy threshold
                            high_entropy_strings.append({
                                'location': f"{file_path}:{line_num}",
                                'string': match,
                                'entropy': entropy,
                                'context': line.strip()
                            })
        
        return high_entropy_strings
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(string)
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Simplified entropy calculation
        
        return entropy 