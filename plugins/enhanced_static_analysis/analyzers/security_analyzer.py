"""
Security Findings Analysis Engine

This module handles processing and analysis of security findings.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SecurityFindingsEngine:
    """
    Engine for processing security findings results.
    
    Provides enhanced processing, categorization, and analysis of security findings.
    """
    
    def __init__(self):
        """Initialize the security findings engine."""
        self.severity_weights = {
            "CRITICAL": 4.0,
            "HIGH": 3.0,
            "MEDIUM": 2.0,
            "LOW": 1.0
        }
        
        self.finding_categories = {
            "injection": ["sql", "xss", "command", "ldap", "xpath", "injection"],
            "authentication": ["auth", "login", "password", "credential", "session"],
            "authorization": ["access", "permission", "role", "privilege"],
            "crypto": ["crypto", "cipher", "hash", "encrypt", "decrypt", "ssl", "tls"],
            "data_storage": ["storage", "database", "file", "cache", "preference"],
            "network": ["network", "http", "https", "url", "connection"],
            "platform": ["platform", "android", "api", "permission", "intent"],
            "code_quality": ["code", "quality", "complexity", "maintainability"]
        }
    
    def process_security_findings(self, findings_data: List[Any]) -> List[Any]:
        """
        Process security findings with enhanced categorization and risk assessment.
        
        Args:
            findings_data: Raw security findings results
            
        Returns:
            List[Any]: Processed security findings
        """
        if not findings_data:
            return []
        
        logger.info(f"Processing {len(findings_data)} security findings")
        
        processed_findings = []
        
        for finding in findings_data:
            # Enhance finding with additional metadata
            enhanced_finding = self._enhance_finding(finding)
            
            # Apply risk categorization
            enhanced_finding = self._categorize_finding_risk(enhanced_finding)
            
            # Add contextual information
            enhanced_finding = self._add_contextual_info(enhanced_finding)
            
            # Generate remediation guidance
            enhanced_finding = self._add_remediation_guidance(enhanced_finding)
            
            processed_findings.append(enhanced_finding)
        
        # Sort by severity and confidence
        processed_findings.sort(key=lambda x: (
            self.severity_weights.get(x.severity, 0),
            x.confidence
        ), reverse=True)
        
        logger.info(f"Processed {len(processed_findings)} findings successfully")
        return processed_findings
    
    def _enhance_finding(self, finding: Any) -> Any:
        """
        Enhance finding with additional metadata and analysis.
        
        Args:
            finding: Raw finding object
            
        Returns:
            Any: Enhanced finding object
        """
        # Add risk score based on severity and confidence
        finding.risk_score = self._calculate_finding_risk_score(finding)
        
        # Categorize finding type
        finding.category_detailed = self._determine_finding_category(finding)
        
        # Add OWASP mapping
        finding.owasp_category = self._map_to_owasp_category(finding)
        
        # Add CWE mapping if available
        finding.cwe_id = self._map_to_cwe(finding)
        
        # Add exploitability assessment
        finding.exploitability = self._assess_exploitability(finding)
        
        return finding
    
    def _categorize_finding_risk(self, finding: Any) -> Any:
        """
        Categorize finding based on risk level.
        
        Args:
            finding: Finding object to categorize
            
        Returns:
            Any: Finding with risk categorization
        """
        severity = getattr(finding, 'severity', 'LOW')
        confidence = getattr(finding, 'confidence', 0.0)
        
        # Adjust severity based on confidence
        if confidence < 0.3:
            # Low confidence findings get downgraded
            if severity == 'CRITICAL':
                finding.adjusted_severity = 'HIGH'
            elif severity == 'HIGH':
                finding.adjusted_severity = 'MEDIUM'
            else:
                finding.adjusted_severity = severity
        else:
            finding.adjusted_severity = severity
        
        # Set priority based on adjusted severity
        priority_map = {
            'CRITICAL': 'URGENT',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW'
        }
        finding.priority = priority_map.get(finding.adjusted_severity, 'LOW')
        
        return finding
    
    def _add_contextual_info(self, finding: Any) -> Any:
        """
        Add contextual information to finding.
        
        Args:
            finding: Finding object to enhance
            
        Returns:
            Any: Finding with contextual information
        """
        # Add file context
        if hasattr(finding, 'file_path') and finding.file_path:
            finding.file_type = self._determine_file_type(finding.file_path)
            finding.component_type = self._determine_component_type(finding.file_path)
        
        # Add code context
        if hasattr(finding, 'code_snippet') and finding.code_snippet:
            finding.code_context = self._analyze_code_context(finding.code_snippet)
        
        # Add impact assessment
        finding.impact_assessment = self._assess_impact(finding)
        
        return finding
    
    def _add_remediation_guidance(self, finding: Any) -> Any:
        """
        Add remediation guidance to finding.
        
        Args:
            finding: Finding object to enhance
            
        Returns:
            Any: Finding with remediation guidance
        """
        category = getattr(finding, 'category_detailed', 'UNKNOWN')
        
        # Generate specific remediation steps
        finding.remediation_steps = self._generate_remediation_steps(finding, category)
        
        # Add prevention guidance
        finding.prevention_guidance = self._generate_prevention_guidance(category)
        
        # Add testing recommendations
        finding.testing_recommendations = self._generate_testing_recommendations(category)
        
        return finding
    
    def _calculate_finding_risk_score(self, finding: Any) -> float:
        """
        Calculate comprehensive risk score for a finding.
        
        Args:
            finding: Finding object
            
        Returns:
            float: Risk score between 0.0 and 1.0
        """
        severity = getattr(finding, 'severity', 'LOW')
        confidence = getattr(finding, 'confidence', 0.0)
        
        # Base score from severity
        severity_score = self.severity_weights.get(severity, 1.0) / 4.0
        
        # Adjust by confidence
        confidence_factor = confidence
        
        # File location factor
        file_path = getattr(finding, 'file_path', '')
        location_factor = 1.0
        if 'test' in file_path.lower():
            location_factor = 0.5
        elif any(keyword in file_path.lower() for keyword in ['main', 'src', 'app']):
            location_factor = 1.2
        
        # Category factor
        category = getattr(finding, 'category', '')
        category_factor = 1.0
        if 'injection' in category.lower():
            category_factor = 1.5
        elif 'crypto' in category.lower():
            category_factor = 1.3
        
        # Calculate final score
        final_score = severity_score * confidence_factor * location_factor * category_factor
        return min(1.0, final_score)
    
    def _determine_finding_category(self, finding: Any) -> str:
        """
        Determine the detailed category of a finding.
        
        Args:
            finding: Finding object
            
        Returns:
            str: Detailed category
        """
        title = getattr(finding, 'title', '').lower()
        description = getattr(finding, 'description', '').lower()
        category = getattr(finding, 'category', '').lower()
        
        search_text = f"{title} {description} {category}"
        
        for category_name, keywords in self.finding_categories.items():
            if any(keyword in search_text for keyword in keywords):
                return category_name.upper()
        
        return "UNKNOWN"
    
    def _map_to_owasp_category(self, finding: Any) -> str:
        """
        Map finding to OWASP Mobile Top 10 category.
        
        Args:
            finding: Finding object
            
        Returns:
            str: OWASP category
        """
        category = getattr(finding, 'category_detailed', 'UNKNOWN')
        
        owasp_mapping = {
            'INJECTION': 'M7: Client Code Quality',
            'AUTHENTICATION': 'M4: Insecure Authentication',
            'AUTHORIZATION': 'M6: Insecure Authorization',
            'CRYPTO': 'M5: Insufficient Cryptography',
            'DATA_STORAGE': 'M2: Insecure Data Storage',
            'NETWORK': 'M3: Insecure Communication',
            'PLATFORM': 'M1: Improper Platform Usage',
            'CODE_QUALITY': 'M7: Client Code Quality'
        }
        
        return owasp_mapping.get(category, 'M10: Extraneous Functionality')
    
    def _map_to_cwe(self, finding: Any) -> str:
        """
        Map finding to CWE (Common Weakness Enumeration) ID.
        
        Args:
            finding: Finding object
            
        Returns:
            str: CWE ID
        """
        category = getattr(finding, 'category_detailed', 'UNKNOWN')
        title = getattr(finding, 'title', '').lower()
        
        # Common CWE mappings
        if 'sql' in title:
            return 'CWE-89'
        elif 'xss' in title:
            return 'CWE-79'
        elif 'command' in title:
            return 'CWE-78'
        elif 'crypto' in title or 'encryption' in title:
            return 'CWE-327'
        elif 'authentication' in title:
            return 'CWE-287'
        elif 'authorization' in title:
            return 'CWE-862'
        elif 'password' in title:
            return 'CWE-256'
        elif 'session' in title:
            return 'CWE-384'
        else:
            return 'CWE-119'  # Generic buffer overflow
    
    def _assess_exploitability(self, finding: Any) -> str:
        """
        Assess exploitability level of a finding.
        
        Args:
            finding: Finding object
            
        Returns:
            str: Exploitability level
        """
        severity = getattr(finding, 'severity', 'LOW')
        confidence = getattr(finding, 'confidence', 0.0)
        category = getattr(finding, 'category_detailed', 'UNKNOWN')
        
        if category == 'INJECTION' and severity in ['CRITICAL', 'HIGH'] and confidence >= 0.8:
            return 'HIGH'
        elif category == 'AUTHENTICATION' and severity in ['CRITICAL', 'HIGH']:
            return 'HIGH'
        elif category == 'CRYPTO' and severity in ['CRITICAL', 'HIGH']:
            return 'MEDIUM'
        elif severity == 'CRITICAL' and confidence >= 0.7:
            return 'HIGH'
        elif severity == 'HIGH' and confidence >= 0.6:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_remediation_steps(self, finding: Any, category: str) -> List[str]:
        """
        Generate specific remediation steps for a finding.
        
        Args:
            finding: Finding object
            category: Finding category
            
        Returns:
            List[str]: Remediation steps
        """
        steps = []
        
        if category == 'INJECTION':
            steps.extend([
                "Implement proper input validation and sanitization",
                "Use parameterized queries or prepared statements",
                "Apply principle of least privilege for database access",
                "Implement output encoding for dynamic content"
            ])
        elif category == 'AUTHENTICATION':
            steps.extend([
                "Implement strong authentication mechanisms",
                "Use secure password policies and storage",
                "Implement multi-factor authentication",
                "Use secure session management"
            ])
        elif category == 'CRYPTO':
            steps.extend([
                "Use strong cryptographic algorithms",
                "Implement proper key management",
                "Use secure random number generation",
                "Validate cryptographic implementations"
            ])
        elif category == 'DATA_STORAGE':
            steps.extend([
                "Implement secure data storage practices",
                "Use encryption for sensitive data",
                "Apply proper access controls",
                "Implement data classification policies"
            ])
        else:
            steps.extend([
                "Review and fix the identified security issue",
                "Implement proper security controls",
                "Follow secure coding practices",
                "Conduct security testing"
            ])
        
        return steps
    
    def _generate_prevention_guidance(self, category: str) -> List[str]:
        """Generate prevention guidance for a category."""
        guidance = []
        
        if category == 'INJECTION':
            guidance.extend([
                "Use secure coding practices",
                "Implement defense in depth",
                "Regular security training for developers",
                "Use static analysis tools"
            ])
        elif category == 'AUTHENTICATION':
            guidance.extend([
                "Follow authentication best practices",
                "Implement proper session management",
                "Use industry-standard authentication frameworks",
                "Regular security assessments"
            ])
        # Add more categories as needed
        
        return guidance
    
    def _generate_testing_recommendations(self, category: str) -> List[str]:
        """Generate testing recommendations for a category."""
        recommendations = []
        
        if category == 'INJECTION':
            recommendations.extend([
                "Perform penetration testing",
                "Use automated security scanning tools",
                "Implement fuzzing tests",
                "Conduct code reviews"
            ])
        elif category == 'AUTHENTICATION':
            recommendations.extend([
                "Test authentication mechanisms",
                "Verify session management",
                "Test password policies",
                "Verify multi-factor authentication"
            ])
        # Add more categories as needed
        
        return recommendations
    
    def _determine_file_type(self, file_path: str) -> str:
        """Determine file type based on file path."""
        if file_path.endswith('.java'):
            return 'JAVA'
        elif file_path.endswith('.kt'):
            return 'KOTLIN'
        elif file_path.endswith('.xml'):
            return 'XML'
        elif file_path.endswith('.properties'):
            return 'PROPERTIES'
        elif file_path.endswith('.json'):
            return 'JSON'
        else:
            return 'UNKNOWN'
    
    def _determine_component_type(self, file_path: str) -> str:
        """Determine component type based on file path."""
        if 'activity' in file_path.lower():
            return 'ACTIVITY'
        elif 'service' in file_path.lower():
            return 'SERVICE'
        elif 'receiver' in file_path.lower():
            return 'RECEIVER'
        elif 'provider' in file_path.lower():
            return 'PROVIDER'
        elif 'fragment' in file_path.lower():
            return 'FRAGMENT'
        else:
            return 'UNKNOWN'
    
    def _analyze_code_context(self, code_snippet: str) -> Dict[str, Any]:
        """Analyze code context for additional insights."""
        return {
            'length': len(code_snippet),
            'complexity': 'HIGH' if len(code_snippet) > 200 else 'MEDIUM' if len(code_snippet) > 100 else 'LOW',
            'has_comments': '//' in code_snippet or '/*' in code_snippet,
            'has_strings': '"' in code_snippet or "'" in code_snippet
        }
    
    def _assess_impact(self, finding: Any) -> Dict[str, str]:
        """Assess the impact of a finding."""
        severity = getattr(finding, 'severity', 'LOW')
        category = getattr(finding, 'category_detailed', 'UNKNOWN')
        
        impact_levels = {
            'confidentiality': 'LOW',
            'integrity': 'LOW',
            'availability': 'LOW'
        }
        
        if category == 'INJECTION':
            impact_levels['confidentiality'] = 'HIGH'
            impact_levels['integrity'] = 'HIGH'
        elif category == 'AUTHENTICATION':
            impact_levels['confidentiality'] = 'HIGH'
            impact_levels['integrity'] = 'MEDIUM'
        elif category == 'CRYPTO':
            impact_levels['confidentiality'] = 'HIGH'
        
        return impact_levels 