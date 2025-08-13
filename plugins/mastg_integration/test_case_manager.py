#!/usr/bin/env python3
"""
MASTG Test Case Manager Module

Manages MASTG test case definitions, loading, filtering, and validation.
Provides comprehensive test case management with MASVS control mapping.

Features:
- Complete MASTG test case definitions
- MASVS control mapping and validation
- Test case filtering and selection
- Dynamic test case loading
- Plugin mapping configuration
- Test prerequisite validation
"""

import logging
from typing import Dict, List, Optional, Set
from pathlib import Path
import yaml

from .data_structures import (
    MASTGTestCase, MASTGConfiguration, MASTGCategory, 
    MASTGRiskLevel, MASTGExecutionMode
)

class MASTGTestCaseManager:
    """
    Manages MASTG test cases with comprehensive MASVS compliance mapping.
    
    Provides test case definition, filtering, validation, and dynamic loading
    capabilities for the MASTG integration plugin.
    """
    
    def __init__(self, config: MASTGConfiguration):
        """Initialize the test case manager with configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Test case storage
        self._test_cases: Dict[str, MASTGTestCase] = {}
        self._masvs_mapping: Dict[str, List[str]] = {}
        self._category_mapping: Dict[MASTGCategory, List[str]] = {}
        
        # Load test cases
        self._initialize_test_cases()
        self._build_mappings()
        
        self.logger.info(f"Loaded {len(self._test_cases)} MASTG test cases")
    
    def _initialize_test_cases(self):
        """Initialize comprehensive MASTG test case definitions."""
        
        # MASTG-CRYPTO tests
        self._add_crypto_test_cases()
        
        # MASTG-AUTH tests  
        self._add_auth_test_cases()
        
        # MASTG-NETWORK tests
        self._add_network_test_cases()
        
        # MASTG-PLATFORM tests
        self._add_platform_test_cases()
        
        # MASTG-CODE tests
        self._add_code_test_cases()
        
        # MASTG-RESILIENCE tests
        self._add_resilience_test_cases()
        
        # MASTG-STORAGE tests
        self._add_storage_test_cases()
        
        # Load external test cases if available
        self._load_external_test_cases()
    
    def _add_crypto_test_cases(self):
        """Add cryptography-related MASTG test cases."""
        
        self._test_cases["MASTG-CRYPTO-001"] = MASTGTestCase(
            test_id="MASTG-CRYPTO-001",
            title="Testing Symmetric Cryptography",
            description="Verify proper implementation of symmetric encryption algorithms",
            category=MASTGCategory.CRYPTO,
            masvs_controls=["MSTG-CRYPTO-1", "MSTG-CRYPTO-2"],
            mastg_sections=["0x05i"],
            plugin_mapping="cryptography_tests",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Weak cryptography can lead to data compromise",
            expected_findings=["weak_algorithm", "insufficient_key_length", "improper_mode"],
            false_positive_indicators=["test_code", "debug_configuration"]
        )
        
        self._test_cases["MASTG-CRYPTO-002"] = MASTGTestCase(
            test_id="MASTG-CRYPTO-002", 
            title="Testing Cryptographic Key Management",
            description="Verify secure storage and handling of cryptographic keys",
            category=MASTGCategory.CRYPTO,
            masvs_controls=["MSTG-CRYPTO-1", "MSTG-CRYPTO-5"],
            mastg_sections=["0x05i"],
            plugin_mapping="cryptography_tests",
            difficulty="HARD",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.CRITICAL,
            impact_description="Poor key management can compromise entire cryptographic system",
            expected_findings=["hardcoded_keys", "insecure_key_storage", "weak_key_derivation"],
            false_positive_indicators=["sample_keys", "test_certificates"]
        )
        
        self._test_cases["MASTG-CRYPTO-003"] = MASTGTestCase(
            test_id="MASTG-CRYPTO-003",
            title="Testing Random Number Generation", 
            description="Verify proper random number generation for cryptographic operations",
            category=MASTGCategory.CRYPTO,
            masvs_controls=["MSTG-CRYPTO-6"],
            mastg_sections=["0x05i"],
            plugin_mapping="cryptography_tests",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Weak randomness can make cryptographic operations predictable",
            expected_findings=["weak_random_generator", "predictable_seeds", "insufficient_entropy"],
            false_positive_indicators=["test_random_values", "demo_implementations"]
        )
    
    def _add_auth_test_cases(self):
        """Add authentication-related MASTG test cases."""
        
        self._test_cases["MASTG-AUTH-001"] = MASTGTestCase(
            test_id="MASTG-AUTH-001",
            title="Testing Authentication and Session Management",
            description="Verify proper authentication mechanisms and session handling",
            category=MASTGCategory.AUTH,
            masvs_controls=["MSTG-AUTH-1", "MSTG-AUTH-2"],
            mastg_sections=["0x04f"],
            plugin_mapping="authentication_security_analysis",
            difficulty="MEDIUM",
            automation_level="PARTIAL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Weak authentication can lead to unauthorized access",
            expected_findings=["weak_password_policy", "insecure_session_management", "missing_mfa"],
            false_positive_indicators=["test_accounts", "demo_authentication"]
        )
        
        self._test_cases["MASTG-AUTH-002"] = MASTGTestCase(
            test_id="MASTG-AUTH-002",
            title="Testing Biometric Authentication",
            description="Verify secure implementation of biometric authentication",
            category=MASTGCategory.AUTH,
            masvs_controls=["MSTG-AUTH-8", "MSTG-AUTH-9"],
            mastg_sections=["0x04f"],
            plugin_mapping="authentication_security_analysis",
            difficulty="HARD",
            automation_level="PARTIAL",
            base_risk_level=MASTGRiskLevel.MEDIUM,
            impact_description="Insecure biometric authentication can be bypassed",
            expected_findings=["insecure_biometric_storage", "bypassable_biometric_checks"],
            false_positive_indicators=["simulator_biometrics", "test_biometric_data"]
        )
    
    def _add_network_test_cases(self):
        """Add network security MASTG test cases."""
        
        self._test_cases["MASTG-NETWORK-001"] = MASTGTestCase(
            test_id="MASTG-NETWORK-001",
            title="Testing Network Communication",
            description="Verify secure network communication and certificate validation",
            category=MASTGCategory.NETWORK,
            masvs_controls=["MSTG-NETWORK-1", "MSTG-NETWORK-2"],
            mastg_sections=["0x05g"],
            plugin_mapping="enhanced_network_security_analysis",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Insecure network communication can expose sensitive data",
            expected_findings=["weak_tls_configuration", "certificate_validation_bypass", "cleartext_traffic"],
            false_positive_indicators=["test_servers", "development_certificates"]
        )
        
        self._test_cases["MASTG-NETWORK-002"] = MASTGTestCase(
            test_id="MASTG-NETWORK-002",
            title="Testing Certificate Pinning",
            description="Verify proper implementation of certificate pinning",
            category=MASTGCategory.NETWORK,
            masvs_controls=["MSTG-NETWORK-3", "MSTG-NETWORK-4"],
            mastg_sections=["0x05g"],
            plugin_mapping="advanced_ssl_tls_analyzer",
            difficulty="HARD",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Missing certificate pinning enables man-in-the-middle attacks",
            expected_findings=["missing_certificate_pinning", "bypassable_pinning", "weak_pinning_implementation"],
            false_positive_indicators=["debug_pinning_bypass", "test_certificates"]
        )
    
    def _add_platform_test_cases(self):
        """Add platform interaction MASTG test cases."""
        
        self._test_cases["MASTG-PLATFORM-001"] = MASTGTestCase(
            test_id="MASTG-PLATFORM-001",
            title="Testing App Permissions",
            description="Verify proper app permission usage and validation",
            category=MASTGCategory.PLATFORM,
            masvs_controls=["MSTG-PLATFORM-1", "MSTG-PLATFORM-11"],
            mastg_sections=["0x05h"],
            plugin_mapping="improper_platform_usage",
            difficulty="EASY",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.MEDIUM,
            impact_description="Excessive permissions increase attack surface",
            expected_findings=["excessive_permissions", "dangerous_permissions", "runtime_permission_bypass"],
            false_positive_indicators=["test_permissions", "development_permissions"]
        )
        
        self._test_cases["MASTG-PLATFORM-002"] = MASTGTestCase(
            test_id="MASTG-PLATFORM-002",
            title="Testing Deep Links and URL Schemes", 
            description="Verify secure handling of deep links and custom URL schemes",
            category=MASTGCategory.PLATFORM,
            masvs_controls=["MSTG-PLATFORM-3", "MSTG-PLATFORM-11"],
            mastg_sections=["0x05h"],
            plugin_mapping="improper_platform_usage",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Insecure deep links can enable unauthorized access",
            expected_findings=["insecure_deep_links", "unvalidated_url_schemes", "intent_injection"],
            false_positive_indicators=["test_schemes", "debug_links"]
        )
    
    def _add_code_test_cases(self):
        """Add code quality MASTG test cases."""
        
        self._test_cases["MASTG-CODE-001"] = MASTGTestCase(
            test_id="MASTG-CODE-001",
            title="Testing Code Quality and Build Settings",
            description="Verify secure code practices and build configuration",
            category=MASTGCategory.CODE,
            masvs_controls=["MSTG-CODE-2", "MSTG-CODE-4"],
            mastg_sections=["0x05a"],
            plugin_mapping="native_binary_analysis",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.MEDIUM,
            impact_description="Poor code quality increases vulnerability risk",
            expected_findings=["debug_symbols", "insecure_build_settings", "code_signing_issues"],
            false_positive_indicators=["debug_builds", "development_configurations"]
        )
        
        self._test_cases["MASTG-CODE-002"] = MASTGTestCase(
            test_id="MASTG-CODE-002",
            title="Testing Memory Corruption Bugs",
            description="Verify protection against memory corruption vulnerabilities",
            category=MASTGCategory.CODE,
            masvs_controls=["MSTG-CODE-8"],
            mastg_sections=["0x05a"],
            plugin_mapping="native_binary_analysis",
            difficulty="HARD",
            automation_level="PARTIAL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Memory corruption can lead to code execution",
            expected_findings=["buffer_overflow", "use_after_free", "missing_memory_protections"],
            false_positive_indicators=["test_crash_handlers", "debugging_memory_tools"]
        )
    
    def _add_resilience_test_cases(self):
        """Add resilience MASTG test cases."""
        
        self._test_cases["MASTG-RESILIENCE-001"] = MASTGTestCase(
            test_id="MASTG-RESILIENCE-001",
            title="Testing Anti-Debugging Detection",
            description="Verify anti-debugging mechanisms and tamper detection",
            category=MASTGCategory.RESILIENCE,
            masvs_controls=["MSTG-RESILIENCE-2"],
            mastg_sections=["0x05j"],
            plugin_mapping="anti_tampering_analysis",
            difficulty="HARD",
            automation_level="PARTIAL",
            base_risk_level=MASTGRiskLevel.MEDIUM,
            impact_description="Missing anti-debugging makes reverse engineering easier",
            expected_findings=["missing_debug_detection", "bypassable_anti_debug", "weak_tamper_detection"],
            false_positive_indicators=["debug_builds", "testing_frameworks"]
        )
        
        self._test_cases["MASTG-RESILIENCE-002"] = MASTGTestCase(
            test_id="MASTG-RESILIENCE-002",
            title="Testing Root Detection",
            description="Verify root detection mechanisms and bypass resistance",
            category=MASTGCategory.RESILIENCE,
            masvs_controls=["MSTG-RESILIENCE-1"],
            mastg_sections=["0x05j"],
            plugin_mapping="enhanced_root_detection_bypass_analyzer",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.MEDIUM,
            impact_description="Missing root detection reduces app security on compromised devices",
            expected_findings=["missing_root_detection", "bypassable_root_checks", "weak_root_detection"],
            false_positive_indicators=["emulator_detection", "test_devices"]
        )
    
    def _add_storage_test_cases(self):
        """Add data storage MASTG test cases."""
        
        self._test_cases["MASTG-STORAGE-001"] = MASTGTestCase(
            test_id="MASTG-STORAGE-001",
            title="Testing Local Data Storage",
            description="Verify secure local data storage mechanisms",
            category=MASTGCategory.STORAGE,
            masvs_controls=["MSTG-STORAGE-1", "MSTG-STORAGE-2"],
            mastg_sections=["0x05d"],
            plugin_mapping="insecure_data_storage",
            difficulty="MEDIUM",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.HIGH,
            impact_description="Insecure data storage can expose sensitive information",
            expected_findings=["unencrypted_sensitive_data", "insecure_storage_location", "weak_encryption"],
            false_positive_indicators=["test_data", "sample_configurations"]
        )
        
        self._test_cases["MASTG-STORAGE-002"] = MASTGTestCase(
            test_id="MASTG-STORAGE-002",
            title="Testing Sensitive Data in Logs",
            description="Verify that sensitive data is not exposed in application logs",
            category=MASTGCategory.STORAGE,
            masvs_controls=["MSTG-STORAGE-3"],
            mastg_sections=["0x05d"],
            plugin_mapping="insecure_data_storage",
            difficulty="EASY",
            automation_level="FULL",
            base_risk_level=MASTGRiskLevel.MEDIUM,
            impact_description="Sensitive data in logs can be accessed by other apps or attackers",
            expected_findings=["sensitive_data_in_logs", "verbose_logging", "debug_information_exposure"],
            false_positive_indicators=["sanitized_logs", "test_log_messages"]
        )
    
    def _load_external_test_cases(self):
        """Load additional test cases from external configuration files."""
        try:
            config_path = Path(__file__).parent / "mastg_test_cases.yaml"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    external_cases = yaml.safe_load(f)
                    for case_data in external_cases.get('test_cases', []):
                        test_case = self._create_test_case_from_dict(case_data)
                        self._test_cases[test_case.test_id] = test_case
                        
                self.logger.info(f"Loaded external test cases from {config_path}")
        except Exception as e:
            self.logger.warning(f"Could not load external test cases: {e}")
    
    def _create_test_case_from_dict(self, case_data: Dict) -> MASTGTestCase:
        """Create a test case from dictionary data."""
        return MASTGTestCase(
            test_id=case_data['test_id'],
            title=case_data['title'],
            description=case_data['description'],
            category=MASTGCategory(case_data.get('category', 'GENERAL')),
            masvs_controls=case_data.get('masvs_controls', []),
            mastg_sections=case_data.get('mastg_sections', []),
            plugin_mapping=case_data.get('plugin_mapping'),
            difficulty=case_data.get('difficulty', 'MEDIUM'),
            automation_level=case_data.get('automation_level', 'FULL'),
            base_risk_level=MASTGRiskLevel(case_data.get('base_risk_level', 'MEDIUM')),
            impact_description=case_data.get('impact_description', ''),
            expected_findings=case_data.get('expected_findings', []),
            false_positive_indicators=case_data.get('false_positive_indicators', [])
        )
    
    def _build_mappings(self):
        """Build reverse mappings for efficient lookup."""
        
        # Build MASVS control mapping
        for test_case in self._test_cases.values():
            for control in test_case.masvs_controls:
                if control not in self._masvs_mapping:
                    self._masvs_mapping[control] = []
                self._masvs_mapping[control].append(test_case.test_id)
        
        # Build category mapping
        for test_case in self._test_cases.values():
            if test_case.category not in self._category_mapping:
                self._category_mapping[test_case.category] = []
            self._category_mapping[test_case.category].append(test_case.test_id)
    
    def get_available_test_cases(self) -> List[MASTGTestCase]:
        """Get all available test cases based on configuration filters."""
        filtered_cases = []
        
        for test_case in self._test_cases.values():
            # Apply category filter
            if (self.config.enabled_categories and 
                test_case.category not in self.config.enabled_categories):
                continue
            
            # Apply exclusion filter
            if test_case.test_id in self.config.excluded_test_ids:
                continue
            
            # Apply risk level filter
            if test_case.base_risk_level.value < self.config.minimum_risk_level.value:
                continue
            
            filtered_cases.append(test_case)
        
        self.logger.info(f"Filtered to {len(filtered_cases)} test cases based on configuration")
        return filtered_cases
    
    def get_test_case_by_id(self, test_id: str) -> Optional[MASTGTestCase]:
        """Get a specific test case by ID."""
        return self._test_cases.get(test_id)
    
    def get_test_cases_by_category(self, category: MASTGCategory) -> List[MASTGTestCase]:
        """Get test cases filtered by category."""
        test_ids = self._category_mapping.get(category, [])
        return [self._test_cases[test_id] for test_id in test_ids]
    
    def get_test_cases_by_masvs_control(self, control: str) -> List[MASTGTestCase]:
        """Get test cases that cover a specific MASVS control."""
        test_ids = self._masvs_mapping.get(control, [])
        return [self._test_cases[test_id] for test_id in test_ids]
    
    def get_plugin_mappings(self) -> Dict[str, List[str]]:
        """Get mapping of plugins to their test cases."""
        plugin_mapping = {}
        for test_case in self._test_cases.values():
            if test_case.plugin_mapping:
                if test_case.plugin_mapping not in plugin_mapping:
                    plugin_mapping[test_case.plugin_mapping] = []
                plugin_mapping[test_case.plugin_mapping].append(test_case.test_id)
        return plugin_mapping
    
    def get_masvs_coverage(self) -> Dict[str, List[str]]:
        """Get MASVS coverage mapping."""
        return self._masvs_mapping.copy()
    
    def validate_test_case(self, test_case: MASTGTestCase) -> List[str]:
        """Validate a test case and return list of validation errors."""
        errors = []
        
        # Check required fields
        if not test_case.test_id:
            errors.append("test_id is required")
        if not test_case.title:
            errors.append("title is required")
        if not test_case.description:
            errors.append("description is required")
        if not test_case.masvs_controls:
            errors.append("masvs_controls cannot be empty")
        
        # Check ID format
        if test_case.test_id and not test_case.test_id.startswith("MASTG-"):
            errors.append("test_id should start with 'MASTG-'")
        
        # Check plugin mapping validity
        if test_case.plugin_mapping:
            # This could be enhanced to check against available plugins
            pass
        
        return errors
    
    def get_test_case_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded test cases."""
        stats = {
            "total_test_cases": len(self._test_cases),
            "by_category": {},
            "by_difficulty": {},
            "by_automation_level": {},
            "by_risk_level": {}
        }
        
        for test_case in self._test_cases.values():
            # Category stats
            category = test_case.category.value
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            # Difficulty stats
            difficulty = test_case.difficulty
            stats["by_difficulty"][difficulty] = stats["by_difficulty"].get(difficulty, 0) + 1
            
            # Automation level stats
            automation = test_case.automation_level
            stats["by_automation_level"][automation] = stats["by_automation_level"].get(automation, 0) + 1
            
            # Risk level stats
            risk = test_case.base_risk_level.value
            stats["by_risk_level"][risk] = stats["by_risk_level"].get(risk, 0) + 1
        
        return stats 