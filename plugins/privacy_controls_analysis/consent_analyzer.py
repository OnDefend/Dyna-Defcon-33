"""
Consent Analyzer

Specialized analysis for data collection consent mechanisms and GDPR compliance.
Implements MASTG-TEST-0026 and GDPR Article 7 requirements.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .data_structures import PrivacyVulnerability, ConsentType, PrivacyDataType, PrivacySeverity
from .privacy_pattern_analyzer import PrivacyPatternAnalyzer

class ConsentAnalyzer:
    """
    Analyzes consent mechanisms for data collection compliance.
    Focuses on GDPR Article 7 and MASTG-TEST-0026 requirements.
    """
    
    def __init__(self):
        self.pattern_analyzer = PrivacyPatternAnalyzer()
        self.consent_mechanisms = self._initialize_consent_mechanisms()
        self.consent_quality_patterns = self._initialize_consent_quality_patterns()
        
    def _initialize_consent_mechanisms(self) -> Dict[str, List[str]]:
        """Initialize patterns for identifying consent mechanisms"""
        return {
            "explicit_consent": [
                r"accept.*terms",
                r"agree.*privacy",
                r"consent.*data",
                r"permission.*request",
                r"allow.*access",
                r"grant.*permission",
                r"authorize.*collection",
                r"approve.*usage"
            ],
            "consent_dialog": [
                r"AlertDialog.*consent",
                r"Dialog.*privacy",
                r"showPermissionDialog",
                r"requestPermissions",
                r"checkSelfPermission",
                r"shouldShowRequestPermissionRationale"
            ],
            "privacy_settings": [
                r"privacy.*settings",
                r"data.*preferences",
                r"consent.*management",
                r"permission.*settings",
                r"privacy.*controls"
            ],
            "opt_out_mechanisms": [
                r"opt.*out",
                r"disable.*tracking",
                r"turn.*off.*analytics",
                r"stop.*data.*collection",
                r"withdraw.*consent",
                r"revoke.*permission"
            ]
        }
    
    def _initialize_consent_quality_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for assessing consent quality"""
        return {
            "insufficient_consent": [
                r"pre.*checked",
                r"default.*true",
                r"automatically.*accept",
                r"implied.*consent",
                r"bundled.*consent",
                r"all.*or.*nothing"
            ],
            "valid_consent": [
                r"freely.*given",
                r"specific.*purpose",
                r"informed.*consent",
                r"unambiguous.*indication",
                r"clear.*affirmative.*action",
                r"separate.*consent"
            ],
            "consent_withdrawal": [
                r"easy.*to.*withdraw",
                r"simple.*opt.*out",
                r"one.*click.*unsubscribe",
                r"immediate.*effect",
                r"confirm.*withdrawal"
            ]
        }
    
    def analyze_consent_mechanisms(self, apk_ctx, file_content_pairs: List[Tuple[str, str]]) -> List[PrivacyVulnerability]:
        """
        Analyze consent mechanisms in application files
        
        Args:
            apk_ctx: APK context
            file_content_pairs: List of (file_path, content) tuples
            
        Returns:
            List of privacy vulnerabilities related to consent
        """
        vulnerabilities = []
        
        # Check manifest permissions
        manifest_vulns = self._analyze_manifest_consent(apk_ctx)
        vulnerabilities.extend(manifest_vulns)
        
        # Analyze source files for consent patterns
        for file_path, content in file_content_pairs:
            if self._should_analyze_file(file_path):
                consent_vulns = self._analyze_file_consent(file_path, content)
                vulnerabilities.extend(consent_vulns)
        
        # Check for missing consent mechanisms
        missing_consent_vulns = self._check_missing_consent_mechanisms(file_content_pairs)
        vulnerabilities.extend(missing_consent_vulns)
        
        return vulnerabilities
    
    def _analyze_manifest_consent(self, apk_ctx) -> List[PrivacyVulnerability]:
        """Analyze manifest for consent-requiring permissions"""
        vulnerabilities = []
        
        try:
            manifest_path = apk_ctx.get_manifest_path()
            if not manifest_path or not Path(manifest_path).exists():
                return vulnerabilities
            
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            sensitive_permissions = self.pattern_analyzer.get_sensitive_permissions()
            
            for permission in root.findall(".//uses-permission"):
                perm_name = permission.get("{http://schemas.android.com/apk/res/android}name", "")
                
                if any(sens_perm in perm_name for sens_perm in sensitive_permissions):
                    data_type = self.pattern_analyzer.classify_permission_data_type(perm_name)
                    
                    vuln = PrivacyVulnerability(
                        vuln_type="consent_missing",
                        location=manifest_path,
                        value=perm_name,
                        privacy_data=data_type.value,
                        severity="HIGH",
                        data_type=data_type,
                        consent_type=ConsentType.NONE,
                        processing_purpose="Unknown - requires analysis"
                    )
                    vulnerabilities.append(vuln)
        
        except ET.ParseError as e:
            # Handle malformed manifest
            self.logger.warning(f"Malformed manifest XML, skipping consent analysis: {e}")
        except Exception as e:
            # Handle other errors gracefully
            self.logger.warning(f"Error analyzing manifest for consent patterns: {e}")
        
        return vulnerabilities
    
    def _analyze_file_consent(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Analyze individual file for consent mechanisms"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Find data collection without consent
        privacy_patterns = self.pattern_analyzer.find_patterns_in_content(content, "privacy")
        consent_patterns = self.pattern_analyzer.find_patterns_in_content(content, "consent")
        
        # Check if data collection has corresponding consent
        for pattern_match in privacy_patterns:
            pattern_text, start_pos, end_pos, pattern_obj = pattern_match
            
            if pattern_obj.requires_consent:
                line_num = content[:start_pos].count('\n') + 1
                
                # Look for nearby consent mechanisms
                has_nearby_consent = self._has_nearby_consent(content, start_pos, end_pos)
                
                if not has_nearby_consent:
                    vuln = PrivacyVulnerability(
                        vuln_type="consent_missing",
                        location=file_path,
                        value=pattern_text,
                        line_number=line_num,
                        privacy_data=pattern_obj.data_type.value,
                        severity=pattern_obj.severity.value,
                        data_type=pattern_obj.data_type,
                        consent_type=ConsentType.NONE,
                        processing_purpose=self._extract_processing_purpose(lines, line_num - 1)
                    )
                    vulnerabilities.append(vuln)
        
        # Check consent quality
        consent_quality_vulns = self._analyze_consent_quality(file_path, content)
        vulnerabilities.extend(consent_quality_vulns)
        
        return vulnerabilities
    
    def _analyze_consent_quality(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Analyze quality of consent mechanisms"""
        vulnerabilities = []
        
        # Check for insufficient consent patterns
        for category, patterns in self.consent_quality_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    if category == "insufficient_consent":
                        vuln = PrivacyVulnerability(
                            vuln_type="consent_insufficient",
                            location=file_path,
                            value=match.group(),
                            line_number=line_num,
                            severity="HIGH",
                            consent_type=ConsentType.IMPLIED,
                            processing_purpose="Insufficient consent mechanism detected"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _has_nearby_consent(self, content: str, start_pos: int, end_pos: int, proximity: int = 500) -> bool:
        """Check if there's a consent mechanism near the data collection code"""
        
        # Define search window
        search_start = max(0, start_pos - proximity)
        search_end = min(len(content), end_pos + proximity)
        search_content = content[search_start:search_end]
        
        # Look for consent patterns in the vicinity
        for category, patterns in self.consent_mechanisms.items():
            if category != "opt_out_mechanisms":  # Opt-out is not sufficient for initial consent
                for pattern in patterns:
                    if re.search(pattern, search_content, re.IGNORECASE):
                        return True
        
        return False
    
    def _check_missing_consent_mechanisms(self, file_content_pairs: List[Tuple[str, str]]) -> List[PrivacyVulnerability]:
        """Check for applications that collect data but have no consent mechanisms"""
        vulnerabilities = []
        
        has_data_collection = False
        has_consent_mechanism = False
        
        for file_path, content in file_content_pairs:
            if not self._should_analyze_file(file_path):
                continue
                
            # Check for data collection
            privacy_patterns = self.pattern_analyzer.find_patterns_in_content(content, "privacy")
            if privacy_patterns:
                has_data_collection = True
            
            # Check for consent mechanisms
            consent_patterns = self.pattern_analyzer.find_patterns_in_content(content, "consent")
            if consent_patterns:
                has_consent_mechanism = True
        
        # If we have data collection but no consent mechanisms
        if has_data_collection and not has_consent_mechanism:
            vuln = PrivacyVulnerability(
                vuln_type="privacy_controls_missing",
                location="Application-wide",
                value="No consent mechanisms found",
                severity="CRITICAL",
                consent_type=ConsentType.NONE,
                processing_purpose="Data collection without user consent"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_processing_purpose(self, lines: List[str], line_index: int) -> str:
        """Extract the purpose of data processing from surrounding context"""
        if line_index < 0 or line_index >= len(lines):
            return "Unknown purpose"
        
        # Look at surrounding lines for context
        context_start = max(0, line_index - 3)
        context_end = min(len(lines), line_index + 4)
        context = " ".join(lines[context_start:context_end])
        
        # Common purpose patterns
        purpose_patterns = {
            r"analytic|track|measure": "Analytics and tracking",
            r"advertis|marketing|ad": "Advertising and marketing",
            r"security|auth|login": "Security and authentication",
            r"location|maps|navigation": "Location services",
            r"social|share|connect": "Social features",
            r"personaliz|recommend|custom": "Personalization",
            r"crash|error|debug": "Error reporting and debugging"
        }
        
        for pattern, purpose in purpose_patterns.items():
            if re.search(pattern, context, re.IGNORECASE):
                return purpose
        
        return "General application functionality"
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed for consent patterns"""
        
        # Skip test files and certain directories
        skip_patterns = [
            "/test/", "/tests/", "/androidTest/",
            "/mock/", "/sample/", "/example/",
            ".class", ".dex", ".so"
        ]
        
        for pattern in skip_patterns:
            if pattern in file_path:
                return False
        
        # Focus on relevant file types
        analyze_extensions = ['.java', '.kt', '.xml', '.json']
        return any(file_path.endswith(ext) for ext in analyze_extensions)
    
    def get_consent_recommendations(self, vulnerabilities: List[PrivacyVulnerability]) -> List[str]:
        """Generate consent-specific recommendations"""
        recommendations = []
        
        consent_issues = [v for v in vulnerabilities if "consent" in v.vuln_type]
        
        if consent_issues:
            recommendations.append(
                "Implement explicit consent mechanisms before collecting personal data"
            )
            recommendations.append(
                "Ensure consent requests are specific, informed, and freely given"
            )
            recommendations.append(
                "Provide easy withdrawal mechanisms for all consent given"
            )
            recommendations.append(
                "Document lawful basis for data processing under GDPR Article 6"
            )
        
        return recommendations 