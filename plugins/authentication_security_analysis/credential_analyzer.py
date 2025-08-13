"""
Credential Confirmation Analyzer for AODS
Handles credential confirmation mechanism analysis following MASTG-TEST-0017.
"""

import logging
import re
from typing import List

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

class CredentialAnalyzer:
    """Analyzer for credential confirmation mechanisms."""
    
    def __init__(self):
        """Initialize credential analyzer with patterns."""
        self.vulnerabilities = []
        self.credential_patterns = AUTHENTICATION_PATTERNS[AuthenticationPatternCategory.CREDENTIAL_CONFIRMATION.value]
    
    def analyze_credential_confirmation(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze credential confirmation implementation (MASTG-TEST-0017)."""
        logger.info("Analyzing credential confirmation mechanisms")
        
        self.vulnerabilities = []
        
        if hasattr(apk_ctx, 'source_files'):
            for file_path, content in apk_ctx.source_files.items():
                if file_path.endswith(('.java', '.kt')):
                    self._check_credential_confirmation_patterns(file_path, content)
        
        return self.vulnerabilities
    
    def _check_credential_confirmation_patterns(self, file_path: str, content: str):
        """Check for credential confirmation patterns."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for missing credential confirmation
            if re.search(r"createConfirmDeviceCredentialIntent", line, re.IGNORECASE):
                # Check if result is properly handled
                context_lines = lines[max(0, line_num-1):min(len(lines), line_num+5)]
                context = '\n'.join(context_lines)
                
                if not re.search(r"onActivityResult|startActivityForResult", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="improper_credential_confirmation_handling",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH"
                    ))
            
            # Check for bypassed credential confirmation
            if re.search(r"isKeyguardSecure.*false|KeyguardManager.*false", line, re.IGNORECASE):
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="bypassed_credential_confirmation",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    line_number=line_num,
                    severity="CRITICAL"
                ))
            
            # Check for improper keyguard manager usage
            if re.search(r"KeyguardManager", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-2):min(len(lines), line_num+3)]
                context = '\n'.join(context_lines)
                
                # Check if keyguard security is properly validated
                if not re.search(r"isKeyguardSecure|isDeviceSecure", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="missing_keyguard_validation",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM"
                    ))
            
            # Check for direct credential bypass attempts
            if re.search(r"(?:skip|bypass|ignore).*(?:credential|auth|pin|password)", line, re.IGNORECASE):
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="credential_bypass_attempt",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    line_number=line_num,
                    severity="HIGH"
                ))
            
            # Check for weak credential validation
            if re.search(r"(?:password|pin).*(?:equals|==).*(?:\".*\"|'.*')", line, re.IGNORECASE):
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="hardcoded_credential_validation",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    line_number=line_num,
                    severity="CRITICAL"
                ))
            
            # Check for credential storage in plain text
            if re.search(r"putString.*(?:password|pin|credential)", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-2):min(len(lines), line_num+2)]
                context = '\n'.join(context_lines)
                
                # Check if encryption is used
                if not re.search(r"encrypt|cipher|crypto", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="plaintext_credential_storage",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH"
                    ))
    
    def has_credential_confirmation(self, apk_ctx: APKContext) -> bool:
        """Check if the app implements credential confirmation."""
        if not hasattr(apk_ctx, 'source_files'):
            return False
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in self.credential_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
        
        return False
    
    def get_credential_mechanisms_used(self, apk_ctx: APKContext) -> List[str]:
        """Get list of credential confirmation mechanisms used."""
        mechanisms = []
        
        if not hasattr(apk_ctx, 'source_files'):
            return mechanisms
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                if re.search(r"createConfirmDeviceCredentialIntent", content, re.IGNORECASE):
                    mechanisms.append("DeviceCredentialIntent")
                if re.search(r"KeyguardManager", content, re.IGNORECASE):
                    mechanisms.append("KeyguardManager")
                if re.search(r"isActivePasswordSufficient", content, re.IGNORECASE):
                    mechanisms.append("DevicePolicyManager")
                if re.search(r"LAContext\.canEvaluatePolicy", content, re.IGNORECASE):
                    mechanisms.append("LAContext (iOS)")
        
        return list(set(mechanisms))  # Remove duplicates 