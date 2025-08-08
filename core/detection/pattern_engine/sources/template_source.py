#!/usr/bin/env python3
"""
Template Pattern Source

Generates vulnerability patterns from predefined templates with systematic variations.
"""

import logging
from typing import Dict, List, Any, Optional
from ..models import VulnerabilityPattern, PatternTemplate, PatternType, SeverityLevel, LanguageSupport
from .base import PatternSource

class TemplatePatternSource(PatternSource):
    """Generate patterns from predefined templates."""
    
    def __init__(self, **kwargs):
        """Initialize template pattern source."""
        super().__init__(**kwargs)
        
    def load_patterns(self) -> List[VulnerabilityPattern]:
        """Generate patterns from templates."""
        patterns = []
        templates = self._get_pattern_templates()
        
        for template in templates:
            template_patterns = self._expand_template(template)
            patterns.extend(template_patterns)
            
        self.logger.info(f"Generated {len(patterns)} template-based patterns")
        return patterns
    
    def _get_pattern_templates(self) -> List[PatternTemplate]:
        """Get predefined pattern templates."""
        templates = []
        
        # SQL Injection Templates
        sql_template = PatternTemplate(
            template_id="sql_injection_android",
            template_name="Android SQL Injection Template",
            base_regex=r'(?i){method}\s*\(\s*[^)]*\+[^)]*\)',
            vulnerability_type=PatternType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            cwe_id="CWE-89",
            variations=[
                {"method": "rawQuery", "context": "Android SQLite raw queries"},
                {"method": "execSQL", "context": "Android SQLite SQL execution"},
                {"method": "query", "context": "Android SQLite query builder"},
                {"method": "compileStatement", "context": "Android SQLite compiled statements"},
                {"method": "queryWithFactory", "context": "Android SQLite factory queries"}
            ]
        )
        templates.append(sql_template)
        
        # Path Traversal Templates
        path_template = PatternTemplate(
            template_id="path_traversal_android", 
            template_name="Android Path Traversal Template",
            base_regex=r'new\s+File\s*\(\s*[^)]*{traversal_pattern}[^)]*\)',
            vulnerability_type=PatternType.PATH_TRAVERSAL,
            severity=SeverityLevel.HIGH,
            cwe_id="CWE-22",
            variations=[
                {"traversal_pattern": r'\.\./', "context": "Relative path traversal"},
                {"traversal_pattern": r'\.\.\\/\.\.\/', "context": "Multiple level traversal"},
                {"traversal_pattern": r'\.\.\\', "context": "Windows-style traversal"},
                {"traversal_pattern": r'%2e%2e%2f', "context": "URL-encoded traversal"},
                {"traversal_pattern": r'\.\.%252f', "context": "Double URL-encoded traversal"}
            ]
        )
        templates.append(path_template)
        
        # Code Injection Templates
        code_template = PatternTemplate(
            template_id="code_injection_android",
            template_name="Android Code Injection Template", 
            base_regex=r'{runtime_method}\s*\(\s*[^)]*\+[^)]*\)',
            vulnerability_type=PatternType.CODE_INJECTION,
            severity=SeverityLevel.CRITICAL,
            cwe_id="CWE-78",
            variations=[
                {"runtime_method": r'Runtime\.getRuntime\(\)\.exec', "context": "Runtime command execution"},
                {"runtime_method": r'ProcessBuilder', "context": "Process builder execution"},
                {"runtime_method": r'Desktop\.getDesktop\(\)\.open', "context": "Desktop file opening"},
                {"runtime_method": r'Class\.forName\([^)]*\)\.newInstance', "context": "Dynamic class loading"}
            ]
        )
        templates.append(code_template)
        
        # Hardcoded Secrets Templates
        secrets_template = PatternTemplate(
            template_id="hardcoded_secrets_android",
            template_name="Android Hardcoded Secrets Template",
            base_regex=r'(?i){secret_type}\s*=\s*["\'][a-zA-Z0-9+/={{8,}}["\']',
            vulnerability_type=PatternType.HARDCODED_SECRETS,
            severity=SeverityLevel.HIGH,
            cwe_id="CWE-798",
            variations=[
                {"secret_type": "API_KEY", "context": "Hardcoded API keys"},
                {"secret_type": "SECRET_KEY", "context": "Hardcoded secret keys"},
                {"secret_type": "PASSWORD", "context": "Hardcoded passwords"},
                {"secret_type": "PRIVATE_KEY", "context": "Hardcoded private keys"},
                {"secret_type": "TOKEN", "context": "Hardcoded tokens"},
                {"secret_type": "ENCRYPTION_KEY", "context": "Hardcoded encryption keys"}
            ]
        )
        templates.append(secrets_template)
        
        # Weak Cryptography Templates
        crypto_template = PatternTemplate(
            template_id="weak_crypto_android",
            template_name="Android Weak Cryptography Template",
            base_regex=r'Cipher\.getInstance\s*\(\s*["\'](?:{weak_algorithm})["\']',
            vulnerability_type=PatternType.WEAK_CRYPTOGRAPHY,
            severity=SeverityLevel.MEDIUM,
            cwe_id="CWE-327",
            variations=[
                {"weak_algorithm": "DES", "context": "DES encryption algorithm"},
                {"weak_algorithm": "RC4", "context": "RC4 stream cipher"},
                {"weak_algorithm": "MD5", "context": "MD5 hash algorithm"},
                {"weak_algorithm": "SHA1", "context": "SHA1 hash algorithm"},
                {"weak_algorithm": "DESede", "context": "Triple DES algorithm"}
            ]
        )
        templates.append(crypto_template)
        
        # WebView Security Templates
        webview_template = PatternTemplate(
            template_id="webview_security_android",
            template_name="Android WebView Security Template",
            base_regex=r'{webview_method}\s*\(\s*{value}\s*\)',
            vulnerability_type=PatternType.WEBVIEW_SECURITY,
            severity=SeverityLevel.MEDIUM,
            cwe_id="CWE-200",
            variations=[
                {"webview_method": "setJavaScriptEnabled", "value": "true", "context": "JavaScript enabled in WebView"},
                {"webview_method": "setAllowFileAccess", "value": "true", "context": "File access enabled in WebView"},
                {"webview_method": "setAllowContentAccess", "value": "true", "context": "Content access enabled in WebView"},
                {"webview_method": "setAllowFileAccessFromFileURLs", "value": "true", "context": "File URL access enabled"},
                {"webview_method": "setAllowUniversalAccessFromFileURLs", "value": "true", "context": "Universal access enabled"}
            ]
        )
        templates.append(webview_template)
        
        # Information Disclosure Templates
        info_template = PatternTemplate(
            template_id="info_disclosure_android",
            template_name="Android Information Disclosure Template",
            base_regex=r'(?i){logging_method}\s*\([^)]*{sensitive_data}[^)]*\)',
            vulnerability_type=PatternType.INFORMATION_DISCLOSURE,
            severity=SeverityLevel.MEDIUM,
            cwe_id="CWE-200",
            variations=[
                {"logging_method": "Log\\.d", "sensitive_data": "password", "context": "Password logging"},
                {"logging_method": "Log\\.i", "sensitive_data": "token", "context": "Token logging"},
                {"logging_method": "Log\\.v", "sensitive_data": "key", "context": "Key logging"},
                {"logging_method": "System\\.out\\.println", "sensitive_data": "secret", "context": "Secret printing"},
                {"logging_method": "printStackTrace", "sensitive_data": "credential", "context": "Credential stack traces"}
            ]
        )
        templates.append(info_template)
        
        return templates
    
    def _expand_template(self, template: PatternTemplate) -> List[VulnerabilityPattern]:
        """Expand a template into multiple patterns."""
        patterns = []
        
        for i, variation in enumerate(template.variations):
            try:
                # Replace placeholders in base regex
                expanded_regex = template.base_regex
                for placeholder, value in variation.items():
                    if placeholder != "context":
                        expanded_regex = expanded_regex.replace(f"{{{placeholder}}}", str(value))
                
                # Create pattern
                pattern = VulnerabilityPattern(
                    pattern_id=f"{template.template_id}_{i:03d}",
                    pattern_name=f"{template.template_name} - {variation.get('context', f'Variation {i+1}')}",
                    pattern_regex=expanded_regex,
                    pattern_type=template.vulnerability_type,
                    severity=template.severity,
                    cwe_id=template.cwe_id,
                    masvs_category=self._map_type_to_masvs(template.vulnerability_type),
                    description=f"Template-based pattern for {template.vulnerability_type.value}: {variation.get('context', 'Generic variation')}",
                    confidence_base=0.85,
                    language_support=[LanguageSupport.JAVA, LanguageSupport.KOTLIN],
                    context_requirements=self._extract_context_requirements(template.vulnerability_type, variation),
                    false_positive_indicators=["test", "example", "demo", "mock"],
                    validation_score=0.8,
                    source="Pattern Templates",
                    source_data={
                        "template_id": template.template_id,
                        "variation_index": i,
                        "variation_data": variation
                    }
                )
                
                if self.validate_pattern(pattern):
                    patterns.append(pattern)
                    
            except Exception as e:
                self.logger.warning(f"Failed to expand template {template.template_id} variation {i}: {e}")
                
        return patterns
    
    def _map_type_to_masvs(self, pattern_type: PatternType) -> str:
        """Map pattern type to MASVS category."""
        mapping = {
            PatternType.SQL_INJECTION: "MSTG-CODE-8",
            PatternType.PATH_TRAVERSAL: "MSTG-STORAGE-2",
            PatternType.CODE_INJECTION: "MSTG-CODE-8",
            PatternType.HARDCODED_SECRETS: "MSTG-CRYPTO-1",
            PatternType.WEAK_CRYPTOGRAPHY: "MSTG-CRYPTO-4",
            PatternType.WEBVIEW_SECURITY: "MSTG-PLATFORM-2",
            PatternType.INFORMATION_DISCLOSURE: "MSTG-STORAGE-1"
        }
        return mapping.get(pattern_type, "MSTG-CODE-8")
    
    def _extract_context_requirements(self, pattern_type: PatternType, variation: Dict[str, Any]) -> List[str]:
        """Extract context requirements based on pattern type and variation."""
        context_map = {
            PatternType.SQL_INJECTION: ["database", "user_input"],
            PatternType.PATH_TRAVERSAL: ["file_operations", "user_input"],
            PatternType.CODE_INJECTION: ["system_commands", "user_input"],
            PatternType.HARDCODED_SECRETS: ["cryptography", "authentication"],
            PatternType.WEAK_CRYPTOGRAPHY: ["cryptography"],
            PatternType.WEBVIEW_SECURITY: ["web_content", "browser"],
            PatternType.INFORMATION_DISCLOSURE: ["logging", "debugging"]
        }
        
        return context_map.get(pattern_type, ["general"])
    
    def get_source_info(self) -> Dict[str, Any]:
        """Get template source information."""
        return {
            "source_name": "Pattern Templates",
            "source_type": "template_expansion",
            "description": "Patterns generated from predefined templates with systematic variations",
            "pattern_count_range": "35-50", 
            "template_count": 7,
            "expansion_ratio": "5-10 patterns per template",
            "data_quality": "high"
        } 