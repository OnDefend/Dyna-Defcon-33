"""
Third Party Analyzer

Specialized analysis for third-party data sharing and SDK privacy compliance.
Implements MASTG-TEST-0028 and GDPR Article 28 requirements.
"""

import re
import json
from typing import Dict, List, Optional, Tuple, Set
from .data_structures import PrivacyVulnerability, PrivacyDataType, ThirdPartySDK
from .privacy_pattern_analyzer import PrivacyPatternAnalyzer

class ThirdPartyAnalyzer:
    """
    Analyzes third-party data sharing and SDK privacy compliance.
    Focuses on GDPR Article 28 processor requirements and MASTG-TEST-0028.
    """
    
    def __init__(self):
        self.pattern_analyzer = PrivacyPatternAnalyzer()
        self.known_sdks = self._initialize_known_sdks()
        self.data_sharing_patterns = self._initialize_data_sharing_patterns()
        self.processor_agreement_patterns = self._initialize_processor_patterns()
        
    def _initialize_known_sdks(self) -> Dict[str, ThirdPartySDK]:
        """Initialize database of known third-party SDKs and their privacy implications"""
        return {
            "google_analytics": ThirdPartySDK(
                name="Google Analytics",
                package_patterns=["com.google.analytics", "com.google.firebase.analytics"],
                data_collected=[PrivacyDataType.DEVICE_ID, PrivacyDataType.LOCATION, PrivacyDataType.BROWSER_HISTORY],
                privacy_policy_url="https://policies.google.com/privacy",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            ),
            "facebook_sdk": ThirdPartySDK(
                name="Facebook SDK",
                package_patterns=["com.facebook.sdk", "com.facebook.appevents"],
                data_collected=[PrivacyDataType.DEVICE_ID, PrivacyDataType.CONTACTS, PrivacyDataType.LOCATION],
                privacy_policy_url="https://www.facebook.com/privacy/explanation",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            ),
            "admob": ThirdPartySDK(
                name="Google AdMob",
                package_patterns=["com.google.android.gms.ads", "com.google.ads"],
                data_collected=[PrivacyDataType.DEVICE_ID, PrivacyDataType.LOCATION],
                privacy_policy_url="https://policies.google.com/privacy",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            ),
            "crashlytics": ThirdPartySDK(
                name="Firebase Crashlytics",
                package_patterns=["com.google.firebase.crashlytics", "io.fabric.sdk.android.crashlytics"],
                data_collected=[PrivacyDataType.DEVICE_ID],
                privacy_policy_url="https://firebase.google.com/support/privacy",
                consent_required=False,
                data_sharing=True,
                tracking_enabled=False
            ),
            "mixpanel": ThirdPartySDK(
                name="Mixpanel",
                package_patterns=["com.mixpanel.android"],
                data_collected=[PrivacyDataType.DEVICE_ID, PrivacyDataType.LOCATION, PrivacyDataType.BROWSER_HISTORY],
                privacy_policy_url="https://mixpanel.com/legal/privacy-policy/",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            ),
            "flurry": ThirdPartySDK(
                name="Flurry Analytics",
                package_patterns=["com.flurry.android"],
                data_collected=[PrivacyDataType.DEVICE_ID, PrivacyDataType.LOCATION],
                privacy_policy_url="https://www.verizonmedia.com/policies/us/en/verizonmedia/privacy/",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            ),
            "branch": ThirdPartySDK(
                name="Branch.io",
                package_patterns=["io.branch.sdk"],
                data_collected=[PrivacyDataType.DEVICE_ID],
                privacy_policy_url="https://branch.io/policies/#privacy",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            ),
            "appsflyer": ThirdPartySDK(
                name="AppsFlyer",
                package_patterns=["com.appsflyer"],
                data_collected=[PrivacyDataType.DEVICE_ID, PrivacyDataType.LOCATION],
                privacy_policy_url="https://www.appsflyer.com/privacy-policy/",
                consent_required=True,
                data_sharing=True,
                tracking_enabled=True
            )
        }
    
    def _initialize_data_sharing_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for detecting data sharing activities"""
        return {
            "url_sharing": [
                r"https?://[^/]*google[^/]*",
                r"https?://[^/]*facebook[^/]*",
                r"https?://[^/]*twitter[^/]*",
                r"https?://[^/]*linkedin[^/]*",
                r"https?://[^/]*amazon[^/]*",
                r"https?://[^/]*microsoft[^/]*",
                r"https?://[^/]*analytics[^/]*",
                r"https?://[^/]*tracking[^/]*"
            ],
            "api_calls": [
                r"\.track\(",
                r"\.send\(",
                r"\.upload\(",
                r"\.sync\(",
                r"\.share\(",
                r"\.log\(",
                r"\.report\(",
                r"\.submit\("
            ],
            "data_transmission": [
                r"HttpURLConnection",
                r"OkHttp",
                r"Retrofit",
                r"Volley",
                r"AsyncHttpClient",
                r"retrofit2",
                r"okhttp3"
            ]
        }
    
    def _initialize_processor_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for data processor agreement requirements"""
        return {
            "missing_agreement": [
                r"processor.*agreement",
                r"data.*processing.*agreement", 
                r"DPA",
                r"controller.*processor",
                r"sub.*processor"
            ],
            "gdpr_requirements": [
                r"adequate.*protection",
                r"appropriate.*safeguards",
                r"standard.*contractual.*clauses",
                r"binding.*corporate.*rules",
                r"adequacy.*decision"
            ]
        }
    
    def analyze_third_party_sharing(self, file_content_pairs: List[Tuple[str, str]]) -> List[PrivacyVulnerability]:
        """
        Analyze third-party data sharing patterns
        
        Args:
            file_content_pairs: List of (file_path, content) tuples
            
        Returns:
            List of privacy vulnerabilities related to third-party sharing
        """
        vulnerabilities = []
        detected_sdks = set()
        
        for file_path, content in file_content_pairs:
            if self._should_analyze_file(file_path):
                # Detect third-party SDKs
                sdk_vulns, file_sdks = self._detect_third_party_sdks(file_path, content)
                vulnerabilities.extend(sdk_vulns)
                detected_sdks.update(file_sdks)
                
                # Analyze data sharing patterns
                sharing_vulns = self._analyze_data_sharing(file_path, content)
                vulnerabilities.extend(sharing_vulns)
                
                # Check for processor agreements
                processor_vulns = self._check_processor_agreements(file_path, content)
                vulnerabilities.extend(processor_vulns)
        
        # Analyze SDK combinations for enhanced privacy risks
        combination_vulns = self._analyze_sdk_combinations(detected_sdks)
        vulnerabilities.extend(combination_vulns)
        
        return vulnerabilities
    
    def _detect_third_party_sdks(self, file_path: str, content: str) -> Tuple[List[PrivacyVulnerability], Set[str]]:
        """Detect third-party SDKs and assess their privacy implications"""
        vulnerabilities = []
        detected_sdks = set()
        
        for sdk_key, sdk_info in self.known_sdks.items():
            for pattern in sdk_info.package_patterns:
                if pattern in content:
                    detected_sdks.add(sdk_key)
                    
                    # Check if SDK requires consent but none is implemented
                    if sdk_info.consent_required:
                        has_consent = self._check_sdk_consent(content, sdk_info)
                        
                        if not has_consent:
                            vuln = PrivacyVulnerability(
                                vuln_type="third_party_sharing",
                                location=file_path,
                                value=pattern,
                                third_party=sdk_info.name,
                                severity="HIGH" if sdk_info.tracking_enabled else "MEDIUM",
                                processing_purpose=f"Third-party data sharing via {sdk_info.name}"
                            )
                            vulnerabilities.append(vuln)
                    
                    # Check for excessive data collection by SDK
                    if len(sdk_info.data_collected) > 3:
                        vuln = PrivacyVulnerability(
                            vuln_type="personal_data_excessive",
                            location=file_path,
                            value=pattern,
                            third_party=sdk_info.name,
                            privacy_data=", ".join([dt.value for dt in sdk_info.data_collected]),
                            severity="MEDIUM",
                            processing_purpose=f"Extensive data collection by {sdk_info.name}"
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities, detected_sdks
    
    def _analyze_data_sharing(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Analyze data sharing patterns in code"""
        vulnerabilities = []
        
        # Check for URLs that indicate data sharing
        for pattern in self.data_sharing_patterns["url_sharing"]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if personal data is being shared to this URL
                surrounding_context = self._get_surrounding_context(content, match.start(), match.end())
                if self._contains_personal_data_context(surrounding_context):
                    
                    domain = self._extract_domain(match.group())
                    vuln = PrivacyVulnerability(
                        vuln_type="third_party_sharing",
                        location=file_path,
                        value=match.group(),
                        line_number=line_num,
                        third_party=domain,
                        severity="HIGH",
                        processing_purpose="Personal data shared with third party"
                    )
                    vulnerabilities.append(vuln)
        
        # Check for data transmission methods
        for pattern in self.data_sharing_patterns["data_transmission"]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                # Look for nearby personal data patterns
                surrounding_context = self._get_surrounding_context(content, match.start(), match.end(), 400)
                if self._contains_personal_data_context(surrounding_context) and self._contains_external_url(surrounding_context):
                    
                    vuln = PrivacyVulnerability(
                        vuln_type="third_party_sharing",
                        location=file_path,
                        value=match.group(),
                        line_number=line_num,
                        severity="MEDIUM",
                        processing_purpose="Network transmission of personal data"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_processor_agreements(self, file_path: str, content: str) -> List[PrivacyVulnerability]:
        """Check for data processor agreement requirements"""
        vulnerabilities = []
        
        # This is primarily for documentation files or configuration
        if any(ext in file_path.lower() for ext in ['.md', '.txt', '.json', '.xml']):
            
            # Check if file mentions data processors but lacks agreement references
            has_processor_mention = any(re.search(pattern, content, re.IGNORECASE) 
                                      for pattern in ["processor", "third.*party", "vendor", "supplier"])
            
            has_agreement_mention = any(re.search(pattern, content, re.IGNORECASE) 
                                       for pattern in self.processor_agreement_patterns["missing_agreement"])
            
            if has_processor_mention and not has_agreement_mention:
                vuln = PrivacyVulnerability(
                    vuln_type="third_party_sharing",
                    location=file_path,
                    value="Missing processor agreement documentation",
                    severity="LOW",
                    processing_purpose="GDPR Article 28 compliance documentation missing"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_sdk_combinations(self, detected_sdks: Set[str]) -> List[PrivacyVulnerability]:
        """Analyze combinations of SDKs for enhanced privacy risks"""
        vulnerabilities = []
        
        # High-risk combinations
        high_risk_combinations = [
            {"google_analytics", "facebook_sdk"},  # Cross-platform tracking
            {"admob", "facebook_sdk"},  # Advertising + social tracking
            {"mixpanel", "flurry", "google_analytics"}  # Multiple analytics
        ]
        
        for combination in high_risk_combinations:
            if combination.issubset(detected_sdks):
                sdk_names = [self.known_sdks[sdk].name for sdk in combination]
                
                vuln = PrivacyVulnerability(
                    vuln_type="tracking_without_consent",
                    location="Application-wide",
                    value=", ".join(sdk_names),
                    severity="HIGH",
                    processing_purpose="High-risk SDK combination enables extensive user tracking"
                )
                vulnerabilities.append(vuln)
        
        # Too many tracking SDKs
        tracking_sdks = [sdk for sdk in detected_sdks 
                        if self.known_sdks[sdk].tracking_enabled]
        
        if len(tracking_sdks) > 3:
            vuln = PrivacyVulnerability(
                vuln_type="tracking_without_consent",
                location="Application-wide",
                value=f"{len(tracking_sdks)} tracking SDKs detected",
                severity="MEDIUM",
                processing_purpose="Excessive tracking SDK usage"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_sdk_consent(self, content: str, sdk_info: ThirdPartySDK) -> bool:
        """Check if SDK has proper consent implementation"""
        
        # Look for consent patterns near SDK usage
        consent_patterns = [
            r"consent.*" + sdk_info.name.lower().replace(" ", ".*"),
            r"permission.*" + sdk_info.name.lower().replace(" ", ".*"),
            r"opt.*in.*" + sdk_info.name.lower().replace(" ", ".*"),
            r"gdpr.*" + sdk_info.name.lower().replace(" ", ".*")
        ]
        
        for pattern in consent_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _get_surrounding_context(self, content: str, start_pos: int, end_pos: int, context_size: int = 300) -> str:
        """Get surrounding context for analysis"""
        context_start = max(0, start_pos - context_size)
        context_end = min(len(content), end_pos + context_size)
        return content[context_start:context_end]
    
    def _contains_personal_data_context(self, context: str) -> bool:
        """Check if context contains personal data indicators"""
        personal_data_indicators = [
            "user", "personal", "profile", "contact", "location", 
            "phone", "email", "address", "name", "id", "device",
            "biometric", "preference", "behavior", "analytics"
        ]
        
        context_lower = context.lower()
        return any(indicator in context_lower for indicator in personal_data_indicators)
    
    def _contains_external_url(self, context: str) -> bool:
        """Check if context contains external URLs"""
        url_pattern = r"https?://[^\s]+"
        return bool(re.search(url_pattern, context))
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        match = re.search(r"https?://([^/]+)", url)
        return match.group(1) if match else "unknown"
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed"""
        
        # Skip test files
        skip_patterns = ["/test/", "/tests/", "/androidTest/", "/mock/"]
        for pattern in skip_patterns:
            if pattern in file_path:
                return False
        
        # Analyze relevant file types
        analyze_extensions = ['.java', '.kt', '.xml', '.json', '.md', '.txt']
        return any(file_path.endswith(ext) for ext in analyze_extensions)
    
    def get_detected_sdks(self, file_content_pairs: List[Tuple[str, str]]) -> Dict[str, ThirdPartySDK]:
        """Get list of detected third-party SDKs"""
        detected = {}
        
        for file_path, content in file_content_pairs:
            if not self._should_analyze_file(file_path):
                continue
                
            for sdk_key, sdk_info in self.known_sdks.items():
                for pattern in sdk_info.package_patterns:
                    if pattern in content:
                        detected[sdk_key] = sdk_info
                        break
        
        return detected
    
    def assess_gdpr_article28_compliance(self, vulnerabilities: List[PrivacyVulnerability]) -> float:
        """Assess compliance with GDPR Article 28 (Processor requirements)"""
        
        third_party_issues = [v for v in vulnerabilities if "third_party" in v.vuln_type]
        
        if not third_party_issues:
            return 100.0
        
        # Calculate compliance score based on severity and number of issues
        critical_issues = sum(1 for v in third_party_issues if v.severity == "CRITICAL")
        high_issues = sum(1 for v in third_party_issues if v.severity == "HIGH")
        medium_issues = sum(1 for v in third_party_issues if v.severity == "MEDIUM")
        
        score = max(0, 100 - (critical_issues * 30 + high_issues * 20 + medium_issues * 10))
        return score
    
    def get_third_party_recommendations(self, vulnerabilities: List[PrivacyVulnerability]) -> List[str]:
        """Generate third-party specific recommendations"""
        recommendations = []
        
        third_party_issues = [v for v in vulnerabilities if "third_party" in v.vuln_type]
        
        if third_party_issues:
            recommendations.append(
                "Implement consent mechanisms for all third-party data sharing"
            )
            recommendations.append(
                "Document data processing agreements with all third-party processors"
            )
            recommendations.append(
                "Review and minimize third-party SDK usage to reduce privacy risks"
            )
            recommendations.append(
                "Ensure adequate safeguards for international data transfers"
            )
            recommendations.append(
                "Regular audit of third-party data processing activities"
            )
        
        return recommendations 