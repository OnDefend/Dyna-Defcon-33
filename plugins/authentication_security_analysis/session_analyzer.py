"""
Session Management Analyzer for AODS
Handles session management security analysis including token storage and validation.
"""

import base64
import logging
import re
from typing import List, Optional

from core.apk_ctx import APKContext
from .data_structures import (
    AuthenticationVulnerability,
    AuthenticationPatternCategory,
    AUTHENTICATION_PATTERNS
)

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class SessionAnalyzer:
    """Analyzer for session management security."""
    
    def __init__(self):
        """Initialize session analyzer with patterns."""
        self.vulnerabilities = []
        self.session_patterns = AUTHENTICATION_PATTERNS[AuthenticationPatternCategory.SESSION_MANAGEMENT.value]
    
    def analyze_session_management(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze session management security."""
        logger.info("Analyzing session management implementation")
        
        self.vulnerabilities = []
        
        if hasattr(apk_ctx, 'source_files'):
            for file_path, content in apk_ctx.source_files.items():
                if file_path.endswith(('.java', '.kt')):
                    self._check_session_management_patterns(file_path, content)
        
        return self.vulnerabilities
    
    def _check_session_management_patterns(self, file_path: str, content: str):
        """Check for insecure session management patterns."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for insecure session storage
            for pattern in self.session_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Check if it's storing sensitive data insecurely
                    if re.search(r"MODE_WORLD_READABLE|MODE_WORLD_WRITABLE", line, re.IGNORECASE):
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="insecure_session_storage",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="CRITICAL"
                        ))
                    
                    # Extract potential session tokens
                    token_match = re.search(r'["\']([a-zA-Z0-9+/=]{20,})["\']', line)
                    if token_match:
                        token_value = token_match.group(1)
                        decoded_value = self._try_decode_value(token_value)
                        
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="hardcoded_session_token",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            decoded_value=decoded_value,
                            secret_value=token_value,
                            line_number=line_num,
                            severity="CRITICAL"
                        ))
            
            # Check for session tokens stored in plain text
            if re.search(r"putString.*(?:session|token)", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-2):min(len(lines), line_num+2)]
                context = '\n'.join(context_lines)
                
                # Check if encryption is used
                if not re.search(r"encrypt|cipher|crypto", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="plaintext_session_storage",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH"
                    ))
            
            # Check for session timeout issues
            if re.search(r"session.*timeout|timeout.*session", line, re.IGNORECASE):
                # Extract timeout value
                timeout_match = re.search(r"(\d+)", line)
                if timeout_match:
                    timeout_value = int(timeout_match.group(1))
                    # Check if timeout is too long (more than 30 minutes)
                    if timeout_value > 1800000:  # 30 minutes in milliseconds
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="excessive_session_timeout",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="MEDIUM"
                        ))
            
            # Check for session fixation vulnerabilities
            if re.search(r"setSessionId|session.*id.*=", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-3):min(len(lines), line_num+3)]
                context = '\n'.join(context_lines)
                
                # Check if session is regenerated after authentication
                if not re.search(r"regenerate|new.*session|invalidate", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="session_fixation_vulnerability",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH"
                    ))
            
            # Check for missing session invalidation
            if re.search(r"logout|signout|sign.*out", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-1):min(len(lines), line_num+5)]
                context = '\n'.join(context_lines)
                
                # Check if session is properly invalidated
                if not re.search(r"invalidate|clear|remove.*session|session.*clear", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="missing_session_invalidation",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM"
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
        
        return None
    
    def has_session_management(self, apk_ctx: APKContext) -> bool:
        """Check if the app implements session management."""
        if not hasattr(apk_ctx, 'source_files'):
            return False
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in self.session_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
        
        return False
    
    def get_session_storage_methods(self, apk_ctx: APKContext) -> List[str]:
        """Get list of session storage methods used."""
        methods = []
        
        if not hasattr(apk_ctx, 'source_files'):
            return methods
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                if re.search(r"SharedPreferences", content, re.IGNORECASE):
                    methods.append("SharedPreferences")
                if re.search(r"Keychain.*kSecAttrAccessible", content, re.IGNORECASE):
                    methods.append("iOS Keychain")
                if re.search(r"NSUserDefaults", content, re.IGNORECASE):
                    methods.append("NSUserDefaults")
                if re.search(r"SQLite|database", content, re.IGNORECASE):
                    methods.append("Database")
        
        return list(set(methods))  # Remove duplicates
    
    def get_potential_session_tokens(self, apk_ctx: APKContext) -> List[dict]:
        """Extract potential session tokens found in the code."""
        tokens = []
        
        if not hasattr(apk_ctx, 'source_files'):
            return tokens
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    # Look for token patterns
                    token_match = re.search(r'["\']([a-zA-Z0-9+/=]{20,})["\']', line)
                    if token_match and re.search(r"session|token|auth", line, re.IGNORECASE):
                        token_value = token_match.group(1)
                        decoded = self._try_decode_value(token_value)
                        
                        tokens.append({
                            'location': f"{file_path}:{line_num}",
                            'token': token_value,
                            'decoded': decoded,
                            'context': line.strip()
                        })
        
        return tokens 