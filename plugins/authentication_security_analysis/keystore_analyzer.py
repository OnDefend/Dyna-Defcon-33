"""
Android Keystore Analyzer for AODS
Handles Android Keystore usage analysis for authentication security.
"""

import logging
import re
from typing import List, Dict

from core.apk_ctx import APKContext
from .data_structures import AuthenticationVulnerability

logger = logging.getLogger(__name__)

class KeystoreAnalyzer:
    """Analyzer for Android Keystore usage in authentication."""
    
    def __init__(self):
        """Initialize keystore analyzer."""
        self.vulnerabilities = []
    
    def analyze_keystore_usage(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze Android Keystore usage for authentication."""
        logger.info("Analyzing Android Keystore usage")
        
        self.vulnerabilities = []
        
        if hasattr(apk_ctx, 'source_files'):
            for file_path, content in apk_ctx.source_files.items():
                if file_path.endswith(('.java', '.kt')):
                    self._check_keystore_patterns(file_path, content)
        
        return self.vulnerabilities
    
    def _check_keystore_patterns(self, file_path: str, content: str):
        """Check for insecure keystore usage patterns."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for weak keystore configurations
            if re.search(r"KeyGenParameterSpec\.Builder", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-1):min(len(lines), line_num+15)]
                context = '\n'.join(context_lines)
                
                # Check for missing user authentication requirement
                if not re.search(r"setUserAuthenticationRequired\(true\)", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="keystore_missing_user_auth",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH"
                    ))
                
                # Check for weak authentication timeout
                timeout_match = re.search(r"setUserAuthenticationValidityDurationSeconds\((\d+)\)", context)
                if timeout_match:
                    timeout_value = int(timeout_match.group(1))
                    if timeout_value > 300:  # More than 5 minutes
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_excessive_auth_timeout",
                            location=f"{file_path}:{line_num}",
                            value=f"Timeout: {timeout_value} seconds",
                            line_number=line_num,
                            severity="MEDIUM"
                        ))
                    elif timeout_value == -1:  # No timeout
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_no_auth_timeout",
                            location=f"{file_path}:{line_num}",
                            value="No authentication timeout set",
                            line_number=line_num,
                            severity="HIGH"
                        ))
                
                # Check for missing biometric authentication
                if not re.search(r"setUserAuthenticationType.*BIOMETRIC", context, re.IGNORECASE):
                    if not re.search(r"setUserAuthenticationRequired.*false", context, re.IGNORECASE):
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_missing_biometric_auth",
                            location=f"{file_path}:{line_num}",
                            value="Biometric authentication not enforced",
                            line_number=line_num,
                            severity="MEDIUM"
                        ))
                
                # Check for weak key sizes
                key_size_match = re.search(r"setKeySize\((\d+)\)", context)
                if key_size_match:
                    key_size = int(key_size_match.group(1))
                    if key_size < 2048:  # Weak key size for RSA
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_weak_key_size",
                            location=f"{file_path}:{line_num}",
                            value=f"Key size: {key_size} bits",
                            line_number=line_num,
                            severity="HIGH"
                        ))
                
                # Check for insecure key purposes
                if re.search(r"setKeyPurposes.*ENCRYPT.*DECRYPT", context, re.IGNORECASE):
                    if not re.search(r"setEncryptionPaddings.*OAEP", context, re.IGNORECASE):
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_insecure_encryption_padding",
                            location=f"{file_path}:{line_num}",
                            value="Insecure encryption padding",
                            line_number=line_num,
                            severity="MEDIUM"
                        ))
            
            # Check for legacy keystore usage
            if re.search(r"KeyStore\.getInstance\(.*AndroidKeyStore", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-2):min(len(lines), line_num+5)]
                context = '\n'.join(context_lines)
                
                # Check for proper key loading
                if not re.search(r"load\(null\)", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="keystore_improper_initialization",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM"
                    ))
            
            # Check for key alias security
            if re.search(r"getKey\(|containsAlias\(", line, re.IGNORECASE):
                # Extract key alias
                alias_match = re.search(r'["\']([^"\']+)["\']', line)
                if alias_match:
                    alias = alias_match.group(1)
                    # Check for predictable key aliases
                    if alias.lower() in ['key', 'secret', 'auth', 'password', 'token']:
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_predictable_alias",
                            location=f"{file_path}:{line_num}",
                            value=f"Predictable alias: {alias}",
                            line_number=line_num,
                            severity="LOW"
                        ))
            
            # Check for keystore key generation without authentication
            if re.search(r"KeyGenerator\.getInstance", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-1):min(len(lines), line_num+10)]
                context = '\n'.join(context_lines)
                
                if re.search(r"AndroidKeyStore", context, re.IGNORECASE):
                    if not re.search(r"setUserAuthenticationRequired", context, re.IGNORECASE):
                        self.vulnerabilities.append(AuthenticationVulnerability(
                            vuln_type="keystore_unauthenticated_key_generation",
                            location=f"{file_path}:{line_num}",
                            value=line.strip(),
                            line_number=line_num,
                            severity="HIGH"
                        ))
            
            # Check for insecure key import
            if re.search(r"setKeyEntry|importKey", line, re.IGNORECASE):
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="keystore_external_key_import",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    line_number=line_num,
                    severity="MEDIUM"
                ))
    
    def has_keystore_usage(self, apk_ctx: APKContext) -> bool:
        """Check if the app uses Android Keystore."""
        if not hasattr(apk_ctx, 'source_files'):
            return False
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                if re.search(r"AndroidKeyStore|KeyGenParameterSpec", content, re.IGNORECASE):
                    return True
        
        return False
    
    def get_keystore_configurations(self, apk_ctx: APKContext) -> List[Dict]:
        """Get keystore configurations found in the app."""
        configurations = []
        
        if not hasattr(apk_ctx, 'source_files'):
            return configurations
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    if re.search(r"KeyGenParameterSpec\.Builder", line, re.IGNORECASE):
                        context_lines = lines[max(0, line_num-1):min(len(lines), line_num+15)]
                        context = '\n'.join(context_lines)
                        
                        config = {
                            'location': f"{file_path}:{line_num}",
                            'user_auth_required': bool(re.search(r"setUserAuthenticationRequired\(true\)", context, re.IGNORECASE)),
                            'biometric_auth': bool(re.search(r"setUserAuthenticationType.*BIOMETRIC", context, re.IGNORECASE)),
                            'timeout': self._extract_timeout(context),
                            'key_size': self._extract_key_size(context),
                            'encryption_padding': self._extract_encryption_padding(context)
                        }
                        configurations.append(config)
        
        return configurations
    
    def _extract_timeout(self, context: str) -> int:
        """Extract authentication timeout from context."""
        timeout_match = re.search(r"setUserAuthenticationValidityDurationSeconds\((\d+)\)", context)
        if timeout_match:
            return int(timeout_match.group(1))
        return -1  # No timeout found
    
    def _extract_key_size(self, context: str) -> int:
        """Extract key size from context."""
        key_size_match = re.search(r"setKeySize\((\d+)\)", context)
        if key_size_match:
            return int(key_size_match.group(1))
        return 0  # No key size found
    
    def _extract_encryption_padding(self, context: str) -> str:
        """Extract encryption padding from context."""
        if re.search(r"setEncryptionPaddings.*OAEP", context, re.IGNORECASE):
            return "OAEP"
        elif re.search(r"setEncryptionPaddings.*PKCS1", context, re.IGNORECASE):
            return "PKCS1"
        return "Unknown"
    
    def get_security_score(self, apk_ctx: APKContext) -> Dict:
        """Calculate security score for keystore usage."""
        vulnerabilities = self.analyze_keystore_usage(apk_ctx)
        configurations = self.get_keystore_configurations(apk_ctx)
        
        score = 100
        issues = []
        
        for vuln in vulnerabilities:
            if vuln.severity == "CRITICAL":
                score -= 30
            elif vuln.severity == "HIGH":
                score -= 20
            elif vuln.severity == "MEDIUM":
                score -= 10
            elif vuln.severity == "LOW":
                score -= 5
            
            issues.append(vuln.vuln_type)
        
        return {
            'score': max(0, score),
            'total_vulnerabilities': len(vulnerabilities),
            'configurations_found': len(configurations),
            'issues': issues,
            'uses_keystore': self.has_keystore_usage(apk_ctx)
        } 