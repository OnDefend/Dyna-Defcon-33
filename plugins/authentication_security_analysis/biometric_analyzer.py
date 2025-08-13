"""
Biometric Authentication Analyzer for AODS
Handles comprehensive biometric authentication security analysis following MASTG-TEST-0018.
"""

import logging
import re
import xml.etree.ElementTree as ET
from typing import List

from core.apk_ctx import APKContext
from .data_structures import (
    AuthenticationVulnerability,
    AuthenticationPatternCategory,
    AUTHENTICATION_PATTERNS
)

logger = logging.getLogger(__name__)

class BiometricAnalyzer:
    """Analyzer for biometric authentication implementation security."""
    
    def __init__(self):
        """Initialize biometric analyzer with patterns."""
        self.vulnerabilities = []
        self.biometric_patterns = AUTHENTICATION_PATTERNS[AuthenticationPatternCategory.BIOMETRIC_APIS.value]
        self.weak_patterns = AUTHENTICATION_PATTERNS[AuthenticationPatternCategory.WEAK_BIOMETRIC_IMPLEMENTATION.value]
    
    def analyze_biometric_implementation(self, apk_ctx: APKContext) -> List[AuthenticationVulnerability]:
        """Analyze biometric authentication implementation (MASTG-TEST-0018)."""
        logger.info("Analyzing biometric authentication implementation")
        
        self.vulnerabilities = []
        
        # Check Java/Kotlin source files
        if hasattr(apk_ctx, 'source_files'):
            for file_path, content in apk_ctx.source_files.items():
                if file_path.endswith(('.java', '.kt')):
                    self._check_biometric_patterns(file_path, content)
        
        # Check AndroidManifest.xml for biometric permissions
        self._check_biometric_manifest(apk_ctx)
        
        # Check for weak biometric configurations
        self._check_weak_biometric_config(apk_ctx)
        
        return self.vulnerabilities
    
    def _check_biometric_patterns(self, file_path: str, content: str):
        """Check for biometric authentication patterns in source code."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for weak biometric implementations
            for pattern in self.weak_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="weak_biometric_implementation",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH"
                    ))
            
            # Check for missing error handling in biometric callbacks
            if re.search(r"BiometricPrompt\.AuthenticationCallback", line, re.IGNORECASE):
                # Look for empty or missing error handling
                context_lines = lines[max(0, line_num-1):min(len(lines), line_num+10)]
                context = '\n'.join(context_lines)
                
                if not re.search(r"onAuthenticationError|onAuthenticationFailed", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="missing_biometric_error_handling",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM"
                    ))
    
    def _check_biometric_manifest(self, apk_ctx: APKContext):
        """Check AndroidManifest.xml for biometric-related configurations."""
        if hasattr(apk_ctx, 'manifest_path') and apk_ctx.manifest_path:
            try:
                tree = ET.parse(apk_ctx.manifest_path)
                root = tree.getroot()
                
                # Check for biometric permissions
                biometric_permissions = [
                    "android.permission.USE_BIOMETRIC",
                    "android.permission.USE_FINGERPRINT"
                ]
                
                permissions = root.findall('.//uses-permission')
                found_biometric = False
                
                for perm in permissions:
                    perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                    if perm_name in biometric_permissions:
                        found_biometric = True
                        
                        # Check if there are hardware requirements
                        features = root.findall('.//uses-feature')
                        has_hardware_req = any(
                            f.get('{http://schemas.android.com/apk/res/android}name', '') == 'android.hardware.fingerprint'
                            for f in features
                        )
                        
                        if not has_hardware_req:
                            self.vulnerabilities.append(AuthenticationVulnerability(
                                vuln_type="missing_biometric_hardware_requirement",
                                location=f"{apk_ctx.manifest_path}",
                                value=f"Permission: {perm_name}",
                                severity="LOW"
                            ))
                
            except Exception as e:
                logger.error(f"Error analyzing manifest for biometric config: {e}")
    
    def _check_weak_biometric_config(self, apk_ctx: APKContext):
        """Check for weak biometric configurations."""
        logger.info("Analyzing biometric configuration weaknesses")
        
        # Check for weak fallback mechanisms, improper error handling, etc.
        if hasattr(apk_ctx, 'source_files'):
            for file_path, content in apk_ctx.source_files.items():
                if file_path.endswith(('.java', '.kt')):
                    self._check_biometric_config_patterns(file_path, content)
    
    def _check_biometric_config_patterns(self, file_path: str, content: str):
        """Check for weak biometric configuration patterns."""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for weak fallback mechanisms
            if re.search(r"setNegativeButtonText\(.*null.*\)", line, re.IGNORECASE):
                self.vulnerabilities.append(AuthenticationVulnerability(
                    vuln_type="biometric_weak_fallback",
                    location=f"{file_path}:{line_num}",
                    value=line.strip(),
                    line_number=line_num,
                    severity="HIGH"
                ))
            
            # Check for missing device credential fallback
            if re.search(r"setDeviceCredentialAllowed\(false\)", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-5):min(len(lines), line_num+5)]
                context = '\n'.join(context_lines)
                
                # Check if there's no alternative authentication method
                if not re.search(r"setNegativeButtonText", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="biometric_no_fallback",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="CRITICAL"
                    ))
            
            # Check for improper biometric error handling
            if re.search(r"onAuthenticationError.*\{.*\}", line, re.IGNORECASE):
                if "finish()" in line or "return" in line:
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="biometric_improper_error_handling",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM"
                    ))
            
            # Check for weak biometric prompt configuration
            if re.search(r"BiometricPrompt\.Builder", line, re.IGNORECASE):
                context_lines = lines[max(0, line_num-1):min(len(lines), line_num+10)]
                context = '\n'.join(context_lines)
                
                # Check for missing subtitle or description
                if not re.search(r"setSubtitle\(", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="biometric_weak_prompt_config",
                        location=f"{file_path}:{line_num}",
                        value="Missing biometric prompt subtitle",
                        line_number=line_num,
                        severity="LOW"
                    ))
                
                # Check for weak confirmation requirement
                if re.search(r"setConfirmationRequired\(false\)", context, re.IGNORECASE):
                    self.vulnerabilities.append(AuthenticationVulnerability(
                        vuln_type="biometric_no_confirmation_required",
                        location=f"{file_path}:{line_num}",
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM"
                    ))
    
    def has_biometric_implementation(self, apk_ctx: APKContext) -> bool:
        """Check if the app implements biometric authentication."""
        if not hasattr(apk_ctx, 'source_files'):
            return False
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in self.biometric_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
        
        return False
    
    def get_biometric_apis_used(self, apk_ctx: APKContext) -> List[str]:
        """Get list of biometric APIs used in the application."""
        apis_found = []
        
        if not hasattr(apk_ctx, 'source_files'):
            return apis_found
        
        for file_path, content in apk_ctx.source_files.items():
            if file_path.endswith(('.java', '.kt')):
                for pattern in self.biometric_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if match not in apis_found:
                            apis_found.append(match)
        
        return apis_found 