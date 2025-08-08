"""
Data Processing Analyzer

Specialized analysis for personal data processing compliance.
Implements MASTG-TEST-0027 and GDPR Article 5 requirements.
"""

import re
from typing import Dict, List, Optional, Tuple, Set
from .data_structures import PrivacyVulnerability, PrivacyDataType, PrivacySeverity
from .privacy_pattern_analyzer import PrivacyPatternAnalyzer

class DataProcessingAnalyzer:
    """
    Analyzes personal data processing for GDPR compliance.
    Focuses on GDPR Article 5 principles and MASTG-TEST-0027.
    """
    
    def __init__(self):
        self.pattern_analyzer = PrivacyPatternAnalyzer()
        self.processing_patterns = self._initialize_processing_patterns()
        self.excessive_data_indicators = self._initialize_excessive_data_patterns()
        self.encryption_patterns = self._initialize_encryption_patterns()
        
    def _initialize_processing_patterns(self) -> Dict[str, List[str]]:
        """Initialize personal data processing patterns"""
        return {
            "collection": [
                r"collect.*data",
                r"gather.*information", 
                r"acquire.*personal",
                r"obtain.*user.*data",
                r"retrieve.*profile",
                r"capture.*details",
                r"extract.*personal"
            ],
            "storage": [
                r"store.*personal",
                r"save.*user.*data",
                r"persist.*information",
                r"cache.*personal",
                r"database.*personal",
                r"file.*personal.*data"
            ],
            "transmission": [
                r"send.*personal",
                r"transmit.*user.*data",
                r"upload.*personal",
                r"sync.*user.*data",
                r"share.*personal.*data",
                r"transfer.*information"
            ],
            "processing": [
                r"process.*personal",
                r"analyze.*user.*data", 
                r"compute.*personal",
                r"transform.*user.*data",
                r"manipulate.*personal"
            ],
            "profiling": [
                r"profile.*user",
                r"behavioral.*analysis",
                r"user.*pattern",
                r"preference.*analysis",
                r"demographic.*data",
                r"psychographic.*analysis"
            ]
        }
    
    def _initialize_excessive_data_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns indicating excessive data collection"""
        return {
            "unnecessary_permissions": [
                r"permission.*not.*used",
                r"unused.*permission",
                r"excessive.*permission",
                r"over.*privileged"
            ],
            "broad_collection": [
                r"all.*user.*data",
                r"complete.*profile",
                r"entire.*contact.*list",
                r"full.*device.*access",
                r"comprehensive.*data",
                r"maximum.*information"
            ],
            "sensitive_combinations": [
                r"location.*contacts",
                r"camera.*microphone",
                r"biometric.*location",
                r"financial.*location",
                r"health.*tracking"
            ]
        }
    
    def _initialize_encryption_patterns(self) -> Dict[str, List[str]]:
        """Initialize encryption and security patterns"""
        return {
            "encryption_present": [
                r"encrypt",
                r"AES",
                r"RSA",
                r"SHA",
                r"TLS",
                r"SSL",
                r"crypto",
                r"cipher",
                r"hash",
                r"secure.*storage"
            ],
            "unencrypted_storage": [
                r"SharedPreferences.*putString",
                r"FileOutputStream.*write",
                r"SQLiteDatabase.*insert",
                r"plaintext",
                r"unencrypted",
                r"clear.*text"
            ],
            "weak_encryption": [
                r"DES(?!.*AES)",  # DES but not 3DES or AES
                r"MD5",
                r"SHA1(?!.*SHA256)",  # SHA1 but not SHA256
                r"RC4",
                r"ECB.*mode"
            ]
        }
    
    def analyze_data_processing(self, file_content_pairs: List[Tuple[str, str]]) -> List[PrivacyVulnerability]:
        """
        Analyze personal data processing patterns
        
        Args:
            file_content_pairs: List of (file_path, content) tuples
            
        Returns:
            List of privacy vulnerabilities related to data processing
        """
        vulnerabilities = []
        
        for file_path, content in file_content_pairs:
            if self._should_analyze_file(file_path):
                # Analyze data collection and processing
                processing_vulns = self._analyze_file_processing(file_path, content)
                vulnerabilities.extend(processing_vulns)
                
                # Check for excessive data collection
                excessive_vulns = self._check_excessive_data_collection(file_path, content)
                vulnerabilities.extend(excessive_vulns)
                
                # Check encryption of personal data
                encryption_vulns = self._check_data_encryption(file_path, content)
                vulnerabilities.extend(encryption_vulns)
        
        # Check for data minimization compliance
        minimization_vulns = self._check_data_minimization(file_content_pairs)
        vulnerabilities.extend(minimization_vulns)
        
        return vulnerabilities
    
    def _analyze_file_processing(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Analyze data processing patterns in a file"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Find personal data processing without proper safeguards
        privacy_patterns = self.pattern_analyzer.find_patterns_in_content(content, "privacy")
        
        for pattern_match in privacy_patterns:
            pattern_text, start_pos, end_pos, pattern_obj = pattern_match
            line_num = content[:start_pos].count('\n') + 1
            
            # Check if processing has proper security measures
            has_encryption = self._has_nearby_encryption(content, start_pos, end_pos)
            processing_purpose = self._extract_processing_purpose(lines, line_num - 1)
            
            if not has_encryption and pattern_obj.data_type in [
                PrivacyDataType.LOCATION, PrivacyDataType.CONTACTS, 
                PrivacyDataType.BIOMETRIC, PrivacyDataType.DEVICE_ID
            ]:
                vuln = PrivacyVulnerability(
                    vuln_type="personal_data_unencrypted",
                    location=file_path,
                    value=pattern_text,
                    line_number=line_num,
                    privacy_data=pattern_obj.data_type.value,
                    severity="HIGH",
                    data_type=pattern_obj.data_type,
                    processing_purpose=processing_purpose
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_excessive_data_collection(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Check for excessive data collection patterns"""
        vulnerabilities = []
        
        for category, patterns in self.excessive_data_indicators.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    vuln = PrivacyVulnerability(
                        vuln_type="personal_data_excessive",
                        location=file_path,
                        value=match.group(),
                        line_number=line_num,
                        severity="MEDIUM" if category == "unnecessary_permissions" else "HIGH",
                        processing_purpose="Potentially excessive data collection"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_data_encryption(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Check for proper encryption of personal data"""
        vulnerabilities = []
        
        # Check for unencrypted storage patterns
        for pattern in self.encryption_patterns["unencrypted_storage"]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if this storage involves personal data
                surrounding_context = self._get_surrounding_context(content, match.start(), match.end())
                if self._contains_personal_data_context(surrounding_context):
                    vuln = PrivacyVulnerability(
                        vuln_type="personal_data_unencrypted",
                        location=file_path,
                        value=match.group(),
                        line_number=line_num,
                        severity="HIGH",
                        processing_purpose="Unencrypted storage of personal data"
                    )
                    vulnerabilities.append(vuln)
        
        # Check for weak encryption patterns
        for pattern in self.encryption_patterns["weak_encryption"]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                vuln = PrivacyVulnerability(
                    vuln_type="personal_data_unencrypted",
                    location=file_path,
                    value=match.group(),
                    line_number=line_num,
                    severity="MEDIUM",
                    processing_purpose="Weak encryption algorithm used"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_data_minimization(self, file_content_pairs: List[Tuple[str, str]]) -> List[PrivacyVulnerability]:
        """Check GDPR data minimization principle compliance"""
        vulnerabilities = []
        
        collected_data_types = set()
        processing_purposes = set()
        
        # Analyze all files to understand data collection scope
        for file_path, content in file_content_pairs:
            if not self._should_analyze_file(file_path):
                continue
                
            privacy_patterns = self.pattern_analyzer.find_patterns_in_content(content, "privacy")
            
            for pattern_match in privacy_patterns:
                pattern_text, start_pos, end_pos, pattern_obj = pattern_match
                collected_data_types.add(pattern_obj.data_type)
                
                lines = content.split('\n')
                line_num = content[:start_pos].count('\n') + 1
                purpose = self._extract_processing_purpose(lines, line_num - 1)
                processing_purposes.add(purpose)
        
        # Check if data collection seems excessive for stated purposes
        if len(collected_data_types) > 5 and len(processing_purposes) < 3:
            vuln = PrivacyVulnerability(
                vuln_type="personal_data_excessive",
                location="Application-wide",
                value=f"Collecting {len(collected_data_types)} data types for {len(processing_purposes)} purposes",
                severity="MEDIUM",
                processing_purpose="Potential violation of data minimization principle"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _has_nearby_encryption(self, content: str, start_pos: int, end_pos: int, proximity: int = 300) -> bool:
        """Check if there's encryption near the data processing code"""
        
        search_start = max(0, start_pos - proximity)
        search_end = min(len(content), end_pos + proximity)
        search_content = content[search_start:search_end]
        
        for pattern in self.encryption_patterns["encryption_present"]:
            if re.search(pattern, search_content, re.IGNORECASE):
                return True
        
        return False
    
    def _get_surrounding_context(self, content: str, start_pos: int, end_pos: int, context_size: int = 200) -> str:
        """Get surrounding context for better analysis"""
        context_start = max(0, start_pos - context_size)
        context_end = min(len(content), end_pos + context_size)
        return content[context_start:context_end]
    
    def _contains_personal_data_context(self, context: str) -> bool:
        """Check if context contains personal data indicators"""
        personal_data_indicators = [
            "user", "personal", "profile", "contact", "location", 
            "phone", "email", "address", "name", "id", "biometric"
        ]
        
        context_lower = context.lower()
        return any(indicator in context_lower for indicator in personal_data_indicators)
    
    def _extract_processing_purpose(self, lines: List[str], line_index: int) -> str:
        """Extract the purpose of data processing from surrounding context"""
        if line_index < 0 or line_index >= len(lines):
            return "Unknown purpose"
        
        # Look at surrounding lines for context
        context_start = max(0, line_index - 5)
        context_end = min(len(lines), line_index + 6)
        context = " ".join(lines[context_start:context_end])
        
        # Enhanced purpose patterns
        purpose_patterns = {
            r"analytic|track|measure|metric": "Analytics and performance tracking",
            r"advertis|marketing|ad|promotion": "Advertising and marketing",
            r"security|auth|login|verify": "Security and authentication",
            r"location|maps|navigation|gps": "Location-based services",
            r"social|share|connect|friend": "Social networking features",
            r"personaliz|recommend|custom|preference": "Content personalization",
            r"crash|error|debug|log": "Error reporting and debugging",
            r"payment|billing|purchase|transaction": "Payment processing",
            r"backup|sync|cloud|save": "Data backup and synchronization",
            r"notification|alert|message|push": "Communication and notifications"
        }
        
        for pattern, purpose in purpose_patterns.items():
            if re.search(pattern, context, re.IGNORECASE):
                return purpose
        
        return "General application functionality"
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed for data processing"""
        
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
    
    def assess_gdpr_article5_compliance(self, vulnerabilities: List[PrivacyVulnerability]) -> Dict[str, float]:
        """Assess compliance with GDPR Article 5 principles"""
        
        total_issues = len(vulnerabilities)
        if total_issues == 0:
            return {
                "lawfulness": 100.0,
                "purpose_limitation": 100.0,
                "data_minimization": 100.0,
                "accuracy": 100.0,
                "storage_limitation": 100.0,
                "security": 100.0
            }
        
        # Count issues by GDPR principle
        excessive_data_issues = sum(1 for v in vulnerabilities if "excessive" in v.vuln_type)
        unencrypted_issues = sum(1 for v in vulnerabilities if "unencrypted" in v.vuln_type)
        
        return {
            "lawfulness": max(0, 100 - (total_issues * 15)),
            "purpose_limitation": max(0, 100 - (excessive_data_issues * 25)),
            "data_minimization": max(0, 100 - (excessive_data_issues * 30)),
            "accuracy": 95.0,  # Requires different analysis
            "storage_limitation": 90.0,  # Requires retention analysis
            "security": max(0, 100 - (unencrypted_issues * 20))
        }
    
    def get_processing_recommendations(self, vulnerabilities: List[PrivacyVulnerability]) -> List[str]:
        """Generate data processing specific recommendations"""
        recommendations = []
        
        processing_issues = [v for v in vulnerabilities if "personal_data" in v.vuln_type]
        
        if processing_issues:
            recommendations.append(
                "Implement strong encryption for all personal data storage and transmission"
            )
            recommendations.append(
                "Apply data minimization principle - collect only necessary data"
            )
            recommendations.append(
                "Document lawful basis for each type of personal data processing"
            )
            recommendations.append(
                "Implement purpose limitation - use data only for stated purposes"
            )
            recommendations.append(
                "Regular audit of data collection practices for GDPR Article 5 compliance"
            )
        
        return recommendations 