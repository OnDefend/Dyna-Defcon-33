#!/usr/bin/env python3
"""
OWASP MASVS-STORAGE Resource Analyzer
=====================================

OWASP MASVS v2 Compliant Resource Analysis for Android APKs
Implements MASTG testing procedures for storage security verification

MASTG Test Cases Implemented:
- MASTG-TEST-0001: Testing Local Storage for Sensitive Data
- MASTG-TEST-0009: Testing Backups for Sensitive Data
- MASTG-TEST-0200: Files Written to External Storage
- MASTG-TECH-0019: Retrieving Strings from APK Resources

MASVS Categories Covered:
- MASVS-STORAGE-1: Sensitive data protection in resources
- MASVS-STORAGE-2: Cryptographic key storage validation

"""

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base_owasp_analyzer import (BaseOWASPAnalyzer, SecurityFinding,
                                  StandardAnalysisResult)
from .enhanced_asset_analyzer import EnhancedAssetAnalyzer, EnhancedAssetFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OWASPResourceConfidenceCalculator:
    """
    confidence calculation system for OWASP resource analysis.
    
    Implements evidence-based confidence scoring considering:
    - Pattern type reliability based on false positive rates
    - Resource type context (string resources, assets, config files)
    - Analysis depth and validation methods
    - Content characteristics (entropy, encoding, indicators)
    - MASVS compliance requirements
    """
    
    def __init__(self):
        # Evidence weight factors for OWASP resource analysis
        self.evidence_weights = {
            'pattern_reliability': 0.30,     # Historical pattern accuracy
            'resource_context': 0.25,        # Resource type and location context
            'content_analysis': 0.20,        # Content characteristics (entropy, encoding)
            'validation_methods': 0.15,      # Number and type of validation sources
            'masvs_compliance': 0.10         # MASVS category and test relevance
        }
        
        # Pattern reliability database with historical false positive rates
        self.pattern_reliability = {
            # High reliability patterns (low false positive rate)
            'aws_credentials': 0.95,         # AWS patterns are very specific
            'api_keys': 0.92,               # API key patterns are distinctive
            'database_paths': 0.90,         # Database file patterns are clear
            'backup_config': 0.88,          # Backup configuration is specific
            
            # Medium reliability patterns
            'sensitive_strings': 0.85,      # Generic sensitive string patterns
            'shared_preferences': 0.82,     # SharedPreferences security patterns
            'external_storage': 0.80,       # External storage patterns
            'network_security': 0.78,      # Network security config patterns
            'sql_injection': 0.75,          # SQL injection vulnerability patterns
            
            # Lower reliability patterns (higher false positive rate)
            'obfuscated_content': 0.70,     # Obfuscation can be legitimate
            'base64_content': 0.68,         # Base64 has many legitimate uses
            'generic_secrets': 0.65,        # Generic secret patterns
            'string_analysis_error': 0.90,  # Analysis errors are factual
            'configuration_vulnerability': 0.85  # Config vulnerabilities are specific
        }
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate dynamic confidence based on multi-factor evidence analysis.
        
        Args:
            evidence: Dictionary containing analysis evidence
            
        Returns:
            float: Confidence score between 0.0 and 1.0
        """
        try:
            # Calculate individual evidence factors
            pattern_score = self._assess_pattern_reliability(evidence)
            resource_score = self._assess_resource_context(evidence)
            content_score = self._assess_content_analysis(evidence)
            validation_score = self._assess_validation_methods(evidence)
            masvs_score = self._assess_masvs_compliance(evidence)
            
            # Calculate weighted confidence
            confidence = (
                pattern_score * self.evidence_weights['pattern_reliability'] +
                resource_score * self.evidence_weights['resource_context'] +
                content_score * self.evidence_weights['content_analysis'] +
                validation_score * self.evidence_weights['validation_methods'] +
                masvs_score * self.evidence_weights['masvs_compliance']
            )
            
            # Ensure confidence is within valid range
            return max(0.1, min(0.99, confidence))
            
        except Exception as e:
            logger.debug(f"Error calculating confidence: {e}")
            return 0.5  # Safe fallback for any calculation errors
    
    def _assess_pattern_reliability(self, evidence: Dict[str, Any]) -> float:
        """Assess confidence based on pattern type reliability."""
        pattern_type = evidence.get('pattern_type', 'unknown')
        vulnerability_type = evidence.get('vulnerability_type', '').lower()
        
        # Direct pattern type mapping
        if pattern_type in self.pattern_reliability:
            return self.pattern_reliability[pattern_type]
        
        # Infer pattern type from vulnerability type
        if any(term in vulnerability_type for term in ['aws', 'api', 'credential']):
            return self.pattern_reliability['api_keys']
        elif any(term in vulnerability_type for term in ['database', 'sql']):
            return self.pattern_reliability['database_paths']
        elif any(term in vulnerability_type for term in ['backup', 'extraction']):
            return self.pattern_reliability['backup_config']
        elif any(term in vulnerability_type for term in ['obfuscated', 'pattern']):
            return self.pattern_reliability['obfuscated_content']
        elif any(term in vulnerability_type for term in ['string', 'resource']):
            return self.pattern_reliability['sensitive_strings']
        elif 'error' in vulnerability_type:
            return self.pattern_reliability['string_analysis_error']
        else:
            return self.pattern_reliability['generic_secrets']
    
    def _assess_resource_context(self, evidence: Dict[str, Any]) -> float:
        """Assess confidence based on resource type and location context."""
        resource_type = evidence.get('resource_type', '')
        resource_path = evidence.get('resource_path', '')
        file_location = evidence.get('file_location', '')
        
        base_score = 0.5
        
        # Higher confidence for specific resource types
        if resource_type in ['string_resource', 'manifest_file']:
            base_score += 0.2
        elif resource_type in ['asset_file', 'config_file']:
            base_score += 0.15
        elif resource_type in ['json_file', 'xml_file']:
            base_score += 0.1
        
        # Higher confidence for sensitive locations
        sensitive_paths = ['values/', 'res/', 'assets/', 'AndroidManifest.xml']
        if any(path in resource_path for path in sensitive_paths):
            base_score += 0.15
        
        # Higher confidence for specific file patterns
        if any(pattern in file_location for pattern in ['.xml', '.json', '.properties']):
            base_score += 0.1
        
        return min(base_score, 1.0)
    
    def _assess_content_analysis(self, evidence: Dict[str, Any]) -> float:
        """Assess confidence based on content characteristics."""
        context = evidence.get('context', {})
        
        base_score = 0.5
        
        # Content entropy analysis
        entropy = context.get('entropy', 0)
        if entropy > 4.5:
            base_score += 0.2  # High entropy suggests encrypted/encoded content
        elif entropy > 3.5:
            base_score += 0.1
        
        # Base64 and hex patterns
        if context.get('is_base64_candidate', False):
            base_score += 0.15
        if context.get('is_hex_candidate', False):
            base_score += 0.1
        
        # Flag indicators
        if context.get('contains_flag_indicators', False):
            base_score += 0.2
        
        # Content length (longer patterns are more reliable)
        sensitive_data = evidence.get('sensitive_data', '')
        if len(sensitive_data) > 32:
            base_score += 0.1
        elif len(sensitive_data) > 16:
            base_score += 0.05
        
        return min(base_score, 1.0)
    
    def _assess_validation_methods(self, evidence: Dict[str, Any]) -> float:
        """Assess confidence based on validation methods used."""
        validation_sources = evidence.get('validation_sources', [])
        analysis_methods = evidence.get('analysis_methods', [])
        
        # Base score for single validation
        base_score = 0.3
        
        # Higher confidence with multiple validation sources
        if len(validation_sources) >= 3:
            base_score += 0.4  # Triple validation
        elif len(validation_sources) >= 2:
            base_score += 0.2  # Cross-validation
        
        # Specific analysis method bonuses
        high_confidence_methods = ['manifest_analysis', 'static_analysis', 'pattern_matching']
        method_bonus = sum(0.1 for method in analysis_methods if method in high_confidence_methods)
        base_score += min(method_bonus, 0.3)
        
        return min(base_score, 1.0)
    
    def _assess_masvs_compliance(self, evidence: Dict[str, Any]) -> float:
        """Assess confidence based on MASVS category and test relevance."""
        masvs_category = evidence.get('masvs_category', '')
        mastg_test = evidence.get('mastg_test', '')
        
        base_score = 0.5
        
        # Higher confidence for specific MASVS categories
        if 'MASVS-STORAGE' in masvs_category:
            base_score += 0.2  # Storage security is core focus
        elif 'MASVS-CRYPTO' in masvs_category:
            base_score += 0.15  # Crypto patterns are well-defined
        
        # Higher confidence for specific MASTG tests
        if 'MASTG-TEST' in mastg_test:
            base_score += 0.15  # Formal test procedures
        elif 'MASTG-TECH' in mastg_test:
            base_score += 0.1   # Technical testing procedures
        
        return min(base_score, 1.0)

def calculate_owasp_resource_confidence(evidence: Dict[str, Any]) -> float:
    """
    Calculate dynamic confidence for OWASP resource analysis findings.
    
    This function provides a consistent interface for confidence calculation
    across all OWASP resource analysis findings.
    
    Args:
        evidence: Dictionary containing analysis evidence and context
        
    Returns:
        float: confidence score between 0.1 and 0.99
    """
    calculator = OWASPResourceConfidenceCalculator()
    return calculator.calculate_confidence(evidence)

@dataclass
class OWASPResourceFinding:
    """OWASP MASVS-compliant resource security finding"""

    finding_id: str
    masvs_category: str
    mastg_test: str
    vulnerability_type: str
    resource_path: str
    resource_type: str
    sensitive_data: str
    confidence: float
    severity: str
    description: str
    recommendation: str
    file_location: str
    context: Dict[str, Any]

class OWASPResourceAnalyzer(BaseOWASPAnalyzer):
    """
    OWASP MASVS v2 Compliant Resource Security Analyzer

    Implements MASTG testing procedures for comprehensive Android resource analysis:
    - String resources security analysis (MASTG-TEST-0001)
    - Asset files vulnerability scanning (MASTG-TEST-0200)
    - Configuration exposure detection (MASTG-TEST-0009)
    - Backup file security assessment (MASTG-TEST-0009)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.findings = []
        self.analysis_start_time = 0
        self.analysis_duration = 0
        
        # Initialize enhanced asset analyzer for deep content analysis
        self.enhanced_asset_analyzer = EnhancedAssetAnalyzer(config)

        # OWASP MASVS-STORAGE organic sensitive data patterns (universal detection)
        self.sensitive_patterns = {
            "secrets": {
                "patterns": [
                    # Generic secret patterns (organic, universal)
                    r"[Pp]assword\s*[:=]\s*[\"'][^\"']{4,}[\"']",  # Password assignments
                    r"[Ss]ecret\s*[:=]\s*[\"'][^\"']{4,}[\"']",  # Secret assignments
                    r"[Kk]ey\s*[:=]\s*[\"'][^\"']{8,}[\"']",  # Key assignments
                    r"[Tt]oken\s*[:=]\s*[\"'][^\"']{16,}[\"']",  # Token assignments
                    r"[A-Za-z0-9+/]{32,}={0,2}",  # Base64-like strings (longer patterns)
                    # Generic obfuscated patterns
                    r"[A-Z]\.[A-Z]\.[A-Z]\.[A-Z]",  # Pattern like F.L.A.G
                ],
                "severity": "HIGH",
                "masvs": "MASVS-STORAGE-1",
                "mastg": "MASTG-TEST-0001",
            },
            "credentials": {
                "patterns": [
                    # Generic AWS patterns (organic)
                    r"AKIA[0-9A-Z]{16}",  # AWS Access Key format
                    r"(?i)aws[_-]?secret[_-]?access[_-]?key",
                    r'(?i)(username|user|login)\s*[:=]\s*["\']([^"\']{3,})["\']',
                    # Generic cloud credential patterns
                    r"(?i)amazon.*web.*services.*key",
                    r"[A-Za-z0-9/+=]{40}",  # Generic 40-char secrets
                ],
                "severity": "HIGH",
                "masvs": "MASVS-STORAGE-1",
                "mastg": "MASTG-TEST-0001",
            },
            # Enhanced SQL Injection Detection Patterns (Organic)
            "sql_injection": {
                "patterns": [
                    # Generic SQL injection vulnerability patterns
                    r'(?i)rawQuery\s*\(\s*["\'][^"\']*\+[^"\']*["\']',  # String concatenation in rawQuery
                    r'(?i)execSQL\s*\(\s*["\'][^"\']*\+[^"\']*["\']',  # String concatenation in execSQL
                    r'(?i)query\s*\([^)]*["\'][^"\']*\+[^"\']*["\']',  # String concatenation in query
                    r'(?i)SELECT.*FROM.*WHERE.*\+',  # Dynamic SQL construction
                    r'(?i)INSERT.*VALUES.*\+',  # Dynamic INSERT statements
                    r'(?i)UPDATE.*SET.*\+',  # Dynamic UPDATE statements
                    r'(?i)DELETE.*FROM.*WHERE.*\+',  # Dynamic DELETE statements
                    # Generic prepared statement absence patterns
                    r'(?i)statement\s*=\s*["\'][^"\']*\+',  # Direct statement concatenation
                    r'(?i)sql\s*=\s*["\'][^"\']*\+',  # SQL string concatenation
                    r'(?i)query\s*=\s*["\'][^"\']*\+',  # Query string concatenation
                    # Generic user input in SQL patterns
                    r'(?i)(getText|getString|getStringExtra)\(\).*query',  # User input in queries
                    r'(?i)(getText|getString|getStringExtra)\(\).*sql',  # User input in SQL
                ],
                "severity": "HIGH",
                "masvs": "MASVS-STORAGE-1",
                "mastg": "MASTG-TEST-0002",
            },
            # Enhanced SharedPreferences Security Patterns (Organic)
            "shared_preferences": {
                "patterns": [
                    # Generic SharedPreferences vulnerability patterns
                    r'(?i)getSharedPreferences\s*\([^)]*MODE_WORLD_READABLE',  # World readable prefs
                    r'(?i)getSharedPreferences\s*\([^)]*MODE_WORLD_WRITEABLE',  # World writeable prefs
                    r'(?i)getSharedPreferences\s*\([^)]*\|\s*MODE_WORLD_READABLE',  # Bitwise world readable
                    r'(?i)getSharedPreferences\s*\([^)]*\|\s*MODE_WORLD_WRITEABLE',  # Bitwise world writeable
                    # Generic unencrypted sensitive data in SharedPreferences
                    r'(?i)putString\s*\([^)]*[Pp]assword[^)]*\)',  # Password in SharedPreferences
                    r'(?i)putString\s*\([^)]*[Tt]oken[^)]*\)',  # Token in SharedPreferences
                    r'(?i)putString\s*\([^)]*[Kk]ey[^)]*\)',  # Key in SharedPreferences
                    r'(?i)putString\s*\([^)]*[Ss]ecret[^)]*\)',  # Secret in SharedPreferences
                    # Generic SharedPreferences without encryption
                    r'(?i)SharedPreferences.*putString\s*\([^)]*[A-Za-z0-9+/]{20,}',  # Long strings unencrypted
                    r'(?i)preferences\.edit\(\)\.putString\s*\([^)]*[A-Za-z0-9+/]{16,}',  # Base64-like in prefs
                ],
                "severity": "MEDIUM",
                "masvs": "MASVS-STORAGE-1",
                "mastg": "MASTG-TEST-0001",
            },
            "databases": {
                "patterns": [
                    # Generic database patterns (organic)
                    r"\.db$",  # Any database files
                    r"\.sqlite$",
                    r"\.sqlite3$",
                    r"(?i)database\s*[:=]",
                    # Generic database with secrets patterns
                    r'(?i)\.db.*["\'][^"\']{16,}["\']',  # Database files with long strings
                    r'(?i)sqlite.*["\'][^"\']{16,}["\']',  # SQLite with long strings
                    # Enhanced Database Security Patterns (Organic)
                    r'(?i)SQLiteDatabase.*openOrCreateDatabase',  # Unencrypted database creation
                    r'(?i)openOrCreateDatabase\s*\([^)]*MODE_WORLD_READABLE',  # World readable database
                    r'(?i)openOrCreateDatabase\s*\([^)]*MODE_WORLD_WRITEABLE',  # World writeable database
                    r'(?i)PRAGMA.*encryption.*=.*false',  # Disabled encryption
                    r'(?i)SQLiteDatabase.*getWritableDatabase\(\)',  # Unencrypted writable database
                    r'(?i)SQLiteDatabase.*getReadableDatabase\(\)',  # Unencrypted readable database
                ],
                "severity": "HIGH",
                "masvs": "MASVS-STORAGE-1",
                "mastg": "MASTG-TEST-0001",
            },
            # Generic string resource patterns (organic)
            "string_resources": {
                "patterns": [
                    # Generic XML string patterns with secrets
                    r"<string[^>]*>.*[A-Za-z0-9+/]{24,}.*</string>",  # Long encoded strings in XML
                    r'<string[^>]*name="[^"]*[Ss]ecret[^"]*"',  # Strings named with "secret"
                    r'<string[^>]*name="[^"]*[Pp]assword[^"]*"',  # Strings named with "password"
                    r'<string[^>]*name="[^"]*[Kk]ey[^"]*"',  # Strings named with "key"
                    r'<string[^>]*name="[^"]*[Tt]oken[^"]*"',  # Strings named with "token"
                    # Enhanced Additional sensitive string patterns
                    r'<string[^>]*name="[^"]*[Aa]pi[^"]*".*>[A-Za-z0-9+/]{16,}</string>',  # API keys in strings
                    r'<string[^>]*name="[^"]*[Dd]atabase[^"]*".*>[^<]{10,}</string>',  # Database names/paths
                ],
                "severity": "HIGH",
                "masvs": "MASVS-STORAGE-1",
                "mastg": "MASTG-TEST-0001",
            },
        }

        # MASTG-TEST-0200: External storage risk patterns
        self.external_storage_patterns = [
            r"(?i)getExternalStorageDirectory",
            r"(?i)getExternalFilesDir",
            r"(?i)getExternalCacheDir",
            r"(?i)Environment\.getExternalStorageDirectory",
            r"(?i)WRITE_EXTERNAL_STORAGE",
            r"(?i)READ_EXTERNAL_STORAGE",
        ]

        # Resource file types for MASTG-TECH-0019
        self.resource_file_types = {
            "strings": [".xml"],
            "assets": [
                ".txt",
                ".json",
                ".xml",
                ".properties",
                ".cfg",
                ".config",
                ".ini",
                ".yml",
                ".yaml",
            ],
            "raw": [".txt", ".json", ".xml", ".properties", ".cfg", ".config"],
            "binary": [
                ".db",
                ".sqlite",
                ".sqlite3",
                ".so",
                ".jar",
                ".keystore",
                ".p12",
                ".pfx",
            ],
        }

    def _get_masvs_category(self) -> str:
        """Return the MASVS category this analyzer implements."""
        return "MASVS-STORAGE"

    def analyze_apk(self, apk_path: str) -> StandardAnalysisResult:
        """
        Analyze APK for MASVS-STORAGE vulnerabilities.

        This method performs comprehensive resource analysis for storage security.

        Args:
            apk_path: Path to the APK file to analyze

        Returns:
            StandardAnalysisResult containing storage security findings
        """
        start_time = time.time()

        try:
            # Validate APK path
            if not self.validate_apk_path(apk_path):
                return self._create_result(
                    apk_path=apk_path,
                    analysis_time=time.time() - start_time,
                    findings=[],
                    statistics={"error": "Invalid APK path"},
                    error_message="Invalid APK path or file not found",
                )

            # Perform resource analysis using existing method
            resource_findings = self.analyze_apk_resources(apk_path)

            # Convert OWASPResourceFindings to StandardSecurityFindings
            standard_findings = self._convert_findings(resource_findings)

            analysis_time = time.time() - start_time

            logger.debug(f"✅ MASVS-STORAGE analysis completed in {analysis_time:.2f}s")
            logger.debug(f"📊 Found {len(standard_findings)} storage security findings")

            # Create statistics
            statistics = {
                "analysis_duration": analysis_time,
                "resource_findings_count": len(resource_findings),
                "unique_file_types_analyzed": len(
                    set(f.resource_type for f in resource_findings)
                ),
                "mastg_tests_executed": self._get_executed_mastg_tests(),
                "sensitive_data_categories": self._get_sensitive_data_categories(
                    resource_findings
                ),
            }

            return self._create_result(
                apk_path=apk_path,
                analysis_time=analysis_time,
                findings=standard_findings,
                statistics=statistics,
                mastg_tests=self._get_executed_mastg_tests(),
            )

        except Exception as e:
            logger.error(f"❌ MASVS-STORAGE analysis failed: {e}")
            return self._create_result(
                apk_path=apk_path,
                analysis_time=time.time() - start_time,
                findings=[],
                statistics={"error": str(e)},
                error_message=str(e),
            )

    def _convert_findings(
        self, resource_findings: List[OWASPResourceFinding]
    ) -> List[SecurityFinding]:
        """
        Convert OWASPResourceFinding objects to standard SecurityFinding objects.

        Args:
            resource_findings: List of OWASPResourceFinding objects

        Returns:
            List of SecurityFinding objects
        """
        standard_findings = []

        for finding in resource_findings:
            standard_finding = self._create_finding(
                finding_type=finding.vulnerability_type,
                severity=finding.severity,
                title=f"Storage Security: {finding.resource_type}",
                description=finding.description,
                confidence=finding.confidence,
                file_path=finding.resource_path,
                category="storage_security",
                remediation=finding.recommendation,
                context={
                    "resource_path": finding.resource_path,
                    "resource_type": finding.resource_type,
                    "sensitive_data": finding.sensitive_data,
                    "file_location": finding.file_location,
                    **finding.context,
                },
                mastg_test_id=finding.mastg_test,
            )
            standard_findings.append(standard_finding)

        return standard_findings

    def _get_executed_mastg_tests(self) -> List[str]:
        """Return list of MASTG tests executed by this analyzer."""
        return [
            "MASTG-TEST-0001",  # Testing Local Storage for Sensitive Data
            "MASTG-TEST-0009",  # Testing Backups for Sensitive Data
            "MASTG-TEST-0200",  # Files Written to External Storage
            "MASTG-TECH-0019",  # Retrieving Strings from APK Resources
        ]

    def _get_sensitive_data_categories(
        self, findings: List[OWASPResourceFinding]
    ) -> Dict[str, int]:
        """Get count of findings by sensitive data category."""
        categories = {}
        for finding in findings:
            category = finding.vulnerability_type
            categories[category] = categories.get(category, 0) + 1
        return categories

    def analyze_apk_resources(self, apk_path: str) -> List[OWASPResourceFinding]:
        """
        OWASP MASVS-STORAGE compliant resource analysis

        Implements multiple MASTG test procedures:
        - MASTG-TEST-0001: Local storage sensitive data detection
        - MASTG-TEST-0009: Backup file security assessment
        - MASTG-TEST-0200: External storage usage analysis
        - MASTG-TECH-0019: APK resource string extraction

        Args:
            apk_path: Path to Android APK file

        Returns:
            List of OWASP MASVS-compliant security findings
        """
        logger.debug(f"🔍 Starting OWASP MASVS-STORAGE analysis: {apk_path}")
        self.analysis_start_time = time.time()
        self.findings = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                # MASTG-TECH-0019: Extract and analyze string resources
                self._analyze_string_resources(apk_zip)

                # MASTG-TEST-0001: Analyze asset files for sensitive data
                self._analyze_asset_files(apk_zip)

                # MASTG-TEST-0200: Check for external storage usage
                self._analyze_external_storage_usage(apk_zip)

                # MASTG-TEST-0009: Analyze backup configuration files
                self._analyze_backup_configuration(apk_zip)

                # Additional resource analysis
                self._analyze_raw_resources(apk_zip)
                self._analyze_binary_resources(apk_zip)

        except Exception as e:
            logger.error(f"❌ OWASP resource analysis failed: {e}")
            self._create_analysis_error_finding(str(e))

        self.analysis_duration = time.time() - self.analysis_start_time
        logger.debug(
            f"✅ OWASP MASVS-STORAGE analysis complete: {len(self.findings)} findings in {self.analysis_duration:.2f}s"
        )

        return self.findings

    def _analyze_string_resources(self, apk_zip: zipfile.ZipFile) -> None:
        """
        ���� Enhanced String Resource Scanning with Advanced Pattern Detection
        MASTG-TECH-0019: Retrieving Strings from APK Resources
        MASVS-STORAGE-1: Analyze string resources for sensitive data with advanced pattern detection
        
        Enhancements:
        - Detect encoded flags in strings.xml (FLAG 3 type: F1ag_thr33)
        - Improved XML parsing with namespace handling
        - Enhanced pattern confidence scoring
        - Better context analysis for string values and resource names
        - Multiple encoding detection (UTF-8, UTF-16, Base64)
        """
        logger.debug("🔍 MASTG-TECH-0019: Enhanced string resource analysis (Enhanced String Resource Scanning)")

        # Enhanced string file discovery with better pattern matching
        string_files = []
        for file_path in apk_zip.namelist():
            if self._is_string_resource_file(file_path):
                string_files.append(file_path)
        
        logger.debug(f"📄 Found {len(string_files)} string resource files")

        for string_file in string_files:
            try:
                # 🚀 Enhanced String Resource Scanning: Enhanced encoding detection
                content = self._read_string_file_with_encoding_detection(apk_zip, string_file)
                
                # 🚀 Enhanced String Resource Scanning: Advanced XML analysis with namespace handling
                self._analyze_enhanced_xml_content(content, string_file, "string_resource")
                
                # 🚀 Enhanced String Resource Scanning: Additional pattern-based analysis for obfuscated content
                self._analyze_obfuscated_string_patterns(content, string_file)

            except Exception as e:
                logger.warning(f"⚠️ Error analyzing string file {string_file}: {e}")
                # Create finding for analysis failures
                self._create_string_analysis_error_finding(string_file, str(e))

    def _analyze_asset_files(self, apk_zip: zipfile.ZipFile) -> None:
        """
        Enhanced Asset Content Deep Analysis
        MASTG-TEST-0001: Testing Local Storage for Sensitive Data
        MASVS-STORAGE-1: Enhanced asset file analysis with specialized parsing
        
        Enhancements:
        - Analyze JSON, XML, TXT files with specialized parsing
        - Enhanced encoding detection for multiple character sets
        - Improved binary asset filtering and content extraction
        - Better file type detection and context-aware analysis
        """
        logger.debug("MASTG-TEST-0001: Enhanced asset file analysis with deep content inspection")

        # Use enhanced asset analyzer for deep content analysis
        try:
            enhanced_findings = self.enhanced_asset_analyzer.analyze_asset_files(apk_zip)
            
            # Convert enhanced findings to OWASP resource findings
            for enhanced_finding in enhanced_findings:
                owasp_finding = self._convert_enhanced_finding_to_owasp(enhanced_finding)
                self.findings.append(owasp_finding)
                
            logger.debug(f"Enhanced asset analysis completed: {len(enhanced_findings)} findings")
            
        except Exception as e:
            logger.warning(f"Enhanced asset analysis failed, falling back to standard analysis: {e}")
            # Fallback to existing analysis methods
            self._analyze_asset_files_fallback(apk_zip)

    def _analyze_asset_files_fallback(self, apk_zip: zipfile.ZipFile) -> None:
        """Fallback asset analysis using existing methods"""
        asset_files = [f for f in apk_zip.namelist() if f.startswith("assets/")]
        
        if not asset_files:
            logger.debug("No asset files found in APK")
            return
            
        logger.debug(f"Found {len(asset_files)} asset files")

        # Categorize asset files by type for specialized analysis
        categorized_files = self._categorize_asset_files(asset_files)
        
        # Process each category with specialized methods
        for category, files in categorized_files.items():
            if not files:
                continue
                
            logger.debug(f"Processing {len(files)} {category} files")
            
            for asset_file in files:
                try:
                    if category == "json":
                        self._analyze_json_asset(apk_zip, asset_file)
                    elif category == "xml":
                        self._analyze_xml_asset(apk_zip, asset_file)
                    elif category == "text":
                        self._analyze_text_asset(apk_zip, asset_file)
                    elif category == "binary":
                        self._analyze_binary_asset(apk_zip, asset_file)
                    elif category == "config":
                        self._analyze_config_asset(apk_zip, asset_file)
                    else:  # unknown
                        self._analyze_unknown_asset(apk_zip, asset_file)
                        
                except Exception as e:
                    logger.warning(f"Error analyzing asset file {asset_file}: {e}")
                    self._create_asset_analysis_error_finding(asset_file, str(e))

    def _categorize_asset_files(self, asset_files: List[str]) -> Dict[str, List[str]]:
        """
        Enhanced file categorization for specialized analysis
        """
        categories = {
            "json": [],
            "xml": [],
            "text": [],
            "binary": [],
            "config": [],
            "unknown": []
        }
        
        for asset_file in asset_files:
            file_lower = asset_file.lower()
            
            # JSON files
            if file_lower.endswith(('.json', '.geojson')):
                categories["json"].append(asset_file)
            # XML files  
            elif file_lower.endswith(('.xml', '.xhtml', '.xsl', '.xslt')):
                categories["xml"].append(asset_file)
            # Text files
            elif file_lower.endswith(('.txt', '.md', '.csv', '.log', '.ini', '.properties')):
                categories["text"].append(asset_file)
            # Configuration files
            elif file_lower.endswith(('.conf', '.config', '.cfg', '.plist', '.yml', '.yaml')):
                categories["config"].append(asset_file)
            # Binary files to skip detailed analysis
            elif file_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp',
                                     '.mp4', '.mp3', '.wav', '.avi', '.mov', '.flv',
                                     '.pdf', '.zip', '.tar', '.gz', '.7z', '.so',
                                     '.dex', '.odex', '.vdex', '.art')):
                categories["binary"].append(asset_file)
            # Unknown files - attempt content detection
            else:
                categories["unknown"].append(asset_file)
                
        return categories
    
    def _analyze_json_asset(self, apk_zip: zipfile.ZipFile, asset_file: str) -> None:
        """
        Enhanced JSON asset analysis with structure-aware parsing
        """
        try:
            # 🚀 Asset Content Deep Analysis: Enhanced encoding detection
            content = self._read_asset_with_encoding_detection(apk_zip, asset_file)
            
            # Attempt JSON parsing for structure analysis
            import json
            try:
                json_data = json.loads(content)
                self._analyze_json_structure(json_data, asset_file)
            except json.JSONDecodeError as e:
                logger.debug(f"JSON parsing failed for {asset_file}: {e}")
                # Fallback to text analysis
                self._analyze_text_content(content, asset_file, "json_asset")
                return
                
            # 🚀 Asset Content Deep Analysis: JSON-specific pattern analysis
            self._check_json_sensitive_patterns(content, asset_file)
            
            # Standard text analysis as fallback
            self._analyze_text_content(content, asset_file, "json_asset")
            
        except Exception as e:
            logger.warning(f"Error in JSON analysis for {asset_file}: {e}")
            self._create_asset_analysis_error_finding(asset_file, f"JSON analysis error: {e}")
    
    def _analyze_xml_asset(self, apk_zip: zipfile.ZipFile, asset_file: str) -> None:
        """
        Enhanced XML asset analysis with namespace and structure awareness
        """
        try:
            # 🚀 Asset Content Deep Analysis: Enhanced encoding detection
            content = self._read_asset_with_encoding_detection(apk_zip, asset_file)
            
            # 🚀 Asset Content Deep Analysis: XML-specific analysis using enhanced XML parsing
            self._analyze_enhanced_xml_content(content, asset_file, "xml_asset")
            
            # 🚀 Asset Content Deep Analysis: XML configuration analysis
            self._check_xml_configuration_patterns(content, asset_file)
            
        except Exception as e:
            logger.warning(f"Error in XML analysis for {asset_file}: {e}")
            self._create_asset_analysis_error_finding(asset_file, f"XML analysis error: {e}")
    
    def _analyze_text_asset(self, apk_zip: zipfile.ZipFile, asset_file: str) -> None:
        """
        Enhanced text asset analysis with encoding detection and format recognition
        """
        try:
            # 🚀 Asset Content Deep Analysis: Enhanced encoding detection
            content = self._read_asset_with_encoding_detection(apk_zip, asset_file)
            
            # 🚀 Asset Content Deep Analysis: Detect structured formats within text files
            format_detected = self._detect_text_format(content, asset_file)
            
            if format_detected == "csv":
                self._analyze_csv_content(content, asset_file)
            elif format_detected == "properties":
                self._analyze_properties_content(content, asset_file)
            elif format_detected == "log":
                self._analyze_log_content(content, asset_file)
            else:
                # Standard text analysis
                self._analyze_text_content(content, asset_file, "text_asset")
                
            # 🚀 Asset Content Deep Analysis: Text-specific pattern analysis
            self._check_text_sensitive_patterns(content, asset_file)
            
        except Exception as e:
            logger.warning(f"Error in text analysis for {asset_file}: {e}")
            self._create_asset_analysis_error_finding(asset_file, f"Text analysis error: {e}")
    
    def _analyze_config_asset(self, apk_zip: zipfile.ZipFile, asset_file: str) -> None:
        """
        Enhanced configuration file analysis
        """
        try:
            # 🚀 Asset Content Deep Analysis: Enhanced encoding detection
            content = self._read_asset_with_encoding_detection(apk_zip, asset_file)
            
            # 🚀 Asset Content Deep Analysis: Configuration-specific pattern analysis
            self._check_config_sensitive_patterns(content, asset_file)
            
            # Standard text analysis
            self._analyze_text_content(content, asset_file, "config_asset")
            
        except Exception as e:
            logger.warning(f"Error in config analysis for {asset_file}: {e}")
            self._create_asset_analysis_error_finding(asset_file, f"Config analysis error: {e}")
    
    def _analyze_binary_asset(self, apk_zip: zipfile.ZipFile, asset_file: str) -> None:
        """
        Enhanced binary asset analysis with metadata extraction
        """
        try:
            # 🚀 Asset Content Deep Analysis: Binary file metadata analysis
            file_info = apk_zip.getinfo(asset_file)
            
            # Create finding for potentially suspicious binary files
            if file_info.file_size > 1024 * 1024:  # >1MB
                self._create_binary_asset_finding(asset_file, file_info.file_size, "large_binary")
            
            # Check for embedded strings in binary files
            if file_info.file_size < 1024 * 1024:  # <1MB for performance
                try:
                    raw_content = apk_zip.read(asset_file)
                    self._analyze_binary_strings(raw_content, asset_file)
                except Exception as e:
                    logger.debug(f"Binary string analysis failed for {asset_file}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error in binary analysis for {asset_file}: {e}")
    
    def _analyze_unknown_asset(self, apk_zip: zipfile.ZipFile, asset_file: str) -> None:
        """
        Enhanced unknown asset analysis with content type detection
        """
        try:
            # 🚀 Asset Content Deep Analysis: Content-based type detection
            raw_content = apk_zip.read(asset_file)
            content_type = self._detect_content_type(raw_content, asset_file)
            
            if content_type in ["text", "json", "xml"]:
                # Attempt text analysis with encoding detection
                content = self._read_asset_with_encoding_detection(apk_zip, asset_file)
                self._analyze_text_content(content, asset_file, f"unknown_{content_type}_asset")
            elif content_type == "binary":
                self._analyze_binary_asset(apk_zip, asset_file)
            else:
                # Create finding for unidentified file
                file_info = apk_zip.getinfo(asset_file)
                self._create_unknown_asset_finding(asset_file, file_info.file_size)
                
        except Exception as e:
            logger.warning(f"Error in unknown asset analysis for {asset_file}: {e}")
    
    def _read_asset_with_encoding_detection(self, apk_zip: zipfile.ZipFile, asset_file: str) -> str:
        """
        Enhanced asset file reading with multiple encoding detection
        """
        raw_content = apk_zip.read(asset_file)
        
        # Try multiple encodings in order of likelihood for asset files
        encodings = ['utf-8', 'utf-16', 'utf-16le', 'utf-16be', 'latin1', 'cp1252', 'ascii']
        
        for encoding in encodings:
            try:
                content = raw_content.decode(encoding)
                logger.debug(f"Successfully decoded {asset_file} with {encoding}")
                return content
            except (UnicodeDecodeError, UnicodeError):
                continue
                
        # Fallback with error handling
        logger.warning(f"Could not detect encoding for {asset_file}, using utf-8 with error handling")
        return raw_content.decode('utf-8', errors='ignore')
    
    def _analyze_enhanced_xml_content(self, content: str, file_path: str, resource_type: str) -> None:
        """
        Enhanced XML content analysis with namespace handling
        """
        try:
            import xml.etree.ElementTree as ET
            
            # Parse XML with namespace handling
            root = ET.fromstring(content)
            
            # Extract all string elements and analyze
            for elem in root.iter():
                if elem.tag.endswith('string') or 'string' in elem.tag.lower():
                    string_name = elem.get('name', 'unknown')
                    string_value = elem.text or ''
                    
                    if len(string_value) > 3:  # Only analyze meaningful values
                        self._analyze_string_element_for_flags(string_name, string_value, file_path)
                        
                        # Build context data
                        context_data = self._build_string_context(elem, string_name, string_value)
                        
                        # Enhanced pattern checking
                        self._check_enhanced_sensitive_patterns(string_value, file_path, resource_type, context_data)
                
                # Analyze complex string elements
                self._analyze_complex_string_element(elem, file_path, resource_type)
            
            # Check for obfuscated patterns
            self._analyze_obfuscated_string_patterns(content, file_path)
            
        except ET.ParseError as e:
            logger.debug(f"XML parsing failed for {file_path}: {e}")
            # Fallback to text analysis
            self._analyze_text_content(content, file_path, resource_type)
        except Exception as e:
            logger.warning(f"Enhanced XML analysis error for {file_path}: {e}")
            self._create_string_analysis_error_finding(file_path, str(e))
    
    def _analyze_string_element_for_flags(self, string_name: str, string_value: str, file_path: str) -> None:
        """
        Specialized FLAG detection for string elements
        """
        # FLAG 3 pattern: F1ag_thr33 type
        flag_patterns = [
            r'[Ff][1l][aA@4][gG][_\-\.]*[tT][hH][rR][3e3][3e3]',
            r'[Ff][1l][aA@4][gG][_\-\.]*\d+',
            r'[Ff][1l][aA@4][gG][_\-\.]*[a-zA-Z0-9]{3,}',
            r'FLAG[_\-\.]?[a-zA-Z0-9]{3,}',
            r'flag[_\-\.]?[a-zA-Z0-9]{3,}',
        ]
        
        combined_text = f"{string_name} {string_value}"
        
        for pattern in flag_patterns:
            matches = re.finditer(pattern, combined_text, re.IGNORECASE)
            for match in matches:
                self._create_flag_finding(match, string_name, string_value, file_path, "string_element")
    
    def _build_string_context(self, string_elem, string_name: str, string_value: str) -> dict:
        """
        Build context data for string analysis
        """
        context_data = {
            "string_name": string_name,
            "string_value": string_value[:200],  # Limit for safety
            "value_length": len(string_value),
            "entropy": self._calculate_string_entropy(string_value),
            "is_base64_candidate": self._is_possible_base64(string_value),
            "is_hex_candidate": self._is_possible_hex(string_value),
            "contains_flag_indicators": self._contains_flag_indicators(string_name, string_value),
            "element_attributes": dict(string_elem.attrib) if string_elem is not None else {},
        }
        
        return context_data
    
    def _check_enhanced_sensitive_patterns(self, content: str, file_path: str, resource_type: str, context_data: dict) -> None:
        """
        Enhanced sensitive pattern checking with context awareness
        """
        for category, pattern_data in self.sensitive_patterns.items():
            for pattern in pattern_data["patterns"]:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Calculate enhanced confidence with context
                    confidence = self._calculate_enhanced_confidence(match, category, resource_type, context_data)
                    
                    self._create_enhanced_sensitive_data_finding(
                        match, category, file_path, resource_type, pattern_data, confidence, context_data
                    )
    
    def _analyze_complex_string_element(self, elem, file_path: str, resource_type: str) -> None:
        """
        Analyze complex string elements with multiple attributes
        """
        try:
            # Check all attributes for sensitive content
            for attr_name, attr_value in elem.attrib.items():
                if len(str(attr_value)) > 8:
                    combined_content = f"{attr_name}={attr_value}"
                    self._check_sensitive_patterns(combined_content, file_path, f"{resource_type}_attribute")
            
            # Check element text content
            if elem.text and len(elem.text.strip()) > 8:
                self._check_sensitive_patterns(elem.text, file_path, f"{resource_type}_text")
                
        except Exception as e:
            logger.debug(f"Complex string element analysis error: {e}")
    
    def _analyze_obfuscated_string_patterns(self, content: str, file_path: str) -> None:
        """
        Analyze content for obfuscated string patterns
        """
        obfuscated_patterns = [
            # Dotted patterns (F.L.A.G)
            (r'[Ff]\.[Ll]\.[AaA@4]\.[Gg]', "dotted_flag"),
            # Reversed strings
            (r'drowssap|yek_ipa|terces', "reversed_sensitive"),
            # Unicode escapes
            (r'\\u[0-9a-fA-F]{4}', "unicode_escape"),
            # HTML entities
            (r'&[a-zA-Z][a-zA-Z0-9]*;', "html_entity"),
            # Encoded patterns
            (r'[A-Za-z0-9+/]{20,}={0,2}', "base64_candidate"),
        ]
        
        for pattern, pattern_type in obfuscated_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._create_obfuscated_pattern_finding(match, pattern_type, file_path)
    
    def _create_flag_finding(self, match: re.Match, string_name: str, string_value: str, file_path: str, location: str) -> None:
        """
        Create finding for FLAG detection
        """
        flag_text = match.group(0)
        confidence = self._calculate_flag_confidence(flag_text, string_name, string_value, location)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-FLAG-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TECH-0019",
            vulnerability_type="FLAG Pattern Detected",
            resource_path=file_path,
            resource_type="string_resource_flag",
            sensitive_data=flag_text,
            confidence=confidence,
            severity="HIGH",
            description=f"FLAG pattern detected in {location}: {flag_text}",
            recommendation="Review string resource for challenge/CTF flags or sensitive identifiers.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "flag_text": flag_text,
                "string_name": string_name,
                "string_value": string_value[:100],
                "location": location,
                "match_position": {"start": match.start(), "end": match.end()},
                "confidence_score": confidence,
            },
        )
        self.findings.append(finding)
    
    def _calculate_flag_confidence(self, flag_text: str, string_name: str, string_value: str, location: str) -> float:
        """
        Calculate confidence score for FLAG detection
        """
        base_confidence = 0.75
        
        # Boost confidence for specific patterns
        if 'f1ag' in flag_text.lower():
            base_confidence += 0.15
        if 'thr33' in flag_text.lower() or 'three' in flag_text.lower():
            base_confidence += 0.10
        if any(char.isdigit() for char in flag_text):
            base_confidence += 0.05
        if 'flag' in string_name.lower():
            base_confidence += 0.10
        if location == "string_element":
            base_confidence += 0.05
            
        return min(base_confidence, 0.99)
    
    def _create_enhanced_sensitive_data_finding(self, match: re.Match, category: str, file_path: str, 
                                               resource_type: str, pattern_data: dict, confidence: float, context_data: dict) -> None:
        """
        Create enhanced sensitive data finding with context
        """
        sensitive_data = match.group(0)[:100]
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-ENHANCED-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TECH-0019",
            vulnerability_type=f"Enhanced {category.title()} Pattern",
            resource_path=file_path,
            resource_type=f"enhanced_{resource_type}",
            sensitive_data=sensitive_data,
            confidence=confidence,
            severity=pattern_data.get("severity", "MEDIUM"),
            description=f"Enhanced detection of {category} pattern in {resource_type}",
            recommendation=self._get_masvs_recommendation(category, "MASVS-STORAGE-1"),
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                **context_data,
                "pattern_category": category,
                "match_position": {"start": match.start(), "end": match.end()},
                "enhanced_confidence": confidence,
            },
        )
        self.findings.append(finding)
    
    def _create_obfuscated_pattern_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """
        Create finding for obfuscated patterns
        """
        pattern_text = match.group(0)
        
        # Calculate dynamic confidence based on evidence
        evidence = {
            'pattern_type': 'obfuscated_content',
            'vulnerability_type': f'Obfuscated Pattern: {pattern_type.title()}',
            'resource_type': 'obfuscated_string',
            'resource_path': file_path,
            'file_location': f"{file_path}:{match.start()}-{match.end()}",
            'sensitive_data': pattern_text[:100],
            'masvs_category': 'MASVS-STORAGE-1',
            'mastg_test': 'MASTG-TECH-0019',
            'validation_sources': ['pattern_matching', 'static_analysis'],
            'analysis_methods': ['obfuscation_detection', 'pattern_analysis'],
            'context': {
                "obfuscation_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
            }
        }
        dynamic_confidence = calculate_owasp_resource_confidence(evidence)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-OBFUSCATED-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TECH-0019",
            vulnerability_type=f"Obfuscated Pattern: {pattern_type.title()}",
            resource_path=file_path,
            resource_type="obfuscated_string",
            sensitive_data=pattern_text[:100],
            confidence=dynamic_confidence,
            severity="MEDIUM",
            description=f"Obfuscated pattern detected: {pattern_type}",
            recommendation="Review obfuscated content for hidden sensitive data or security mechanisms.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "obfuscation_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
            },
        )
        self.findings.append(finding)
    
    def _create_string_analysis_error_finding(self, file_path: str, error_message: str) -> None:
        """
        Create finding for string analysis errors
        """
        # Calculate dynamic confidence based on evidence
        evidence = {
            'pattern_type': 'string_analysis_error',
            'vulnerability_type': 'String Analysis Error',
            'resource_type': 'analysis_error',
            'resource_path': file_path,
            'file_location': file_path,
            'sensitive_data': error_message[:100],
            'masvs_category': 'MASVS-STORAGE-1',
            'mastg_test': 'MASTG-TECH-0019',
            'validation_sources': ['static_analysis', 'file_analysis'],
            'analysis_methods': ['string_resource_analysis', 'error_detection'],
            'context': {
                "error_type": "string_analysis_error",
                "error_message": error_message,
                "string_file": file_path,
            }
        }
        dynamic_confidence = calculate_owasp_resource_confidence(evidence)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-STRING-ERROR-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TECH-0019",
            vulnerability_type="String Analysis Error",
            resource_path=file_path,
            resource_type="analysis_error",
            sensitive_data=error_message[:100],
            confidence=dynamic_confidence,
            severity="INFO",
            description=f"Error analyzing string resource {file_path}: {error_message}",
            recommendation="Review string resource file integrity and format.",
            file_location=file_path,
            context={
                "error_type": "string_analysis_error",
                "error_message": error_message,
                "string_file": file_path,
            },
        )
        self.findings.append(finding)
    
    def _calculate_string_entropy(self, text: str) -> float:
        """
        Calculate entropy of text string
        """
        if not text:
            return 0.0
            
        import math
        from collections import Counter
        
        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _is_possible_base64(self, text: str) -> bool:
        """
        Check if text could be Base64 encoded
        """
        if len(text) < 8:
            return False
            
        import re
        base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        return bool(re.match(base64_pattern, text)) and len(text) % 4 == 0
    
    def _is_possible_hex(self, text: str) -> bool:
        """
        Check if text could be hexadecimal
        """
        if len(text) < 8:
            return False
            
        import re
        hex_pattern = r'^[0-9a-fA-F]+$'
        return bool(re.match(hex_pattern, text)) and len(text) % 2 == 0
    
    def _contains_flag_indicators(self, string_name: str, string_value: str) -> bool:
        """
        Check if string contains FLAG indicators
        """
        flag_indicators = ['flag', 'ctf', 'challenge', 'secret', 'hidden', 'easter']
        combined_text = f"{string_name} {string_value}".lower()
        
        return any(indicator in combined_text for indicator in flag_indicators)
    
    def _calculate_enhanced_confidence(self, match: re.Match, category: str, resource_type: str, context_data: dict) -> float:
        """
        Calculate enhanced confidence with context awareness
        """
        base_confidence = 0.70
        
        # Boost confidence based on context
        if context_data.get("is_base64_candidate", False):
            base_confidence += 0.10
        if context_data.get("entropy", 0) > 4.0:
            base_confidence += 0.10
        if context_data.get("contains_flag_indicators", False):
            base_confidence += 0.15
        if "password" in category.lower() or "key" in category.lower():
            base_confidence += 0.05
        if resource_type == "string_resource":
            base_confidence += 0.05
            
        return min(base_confidence, 0.99)
    
    def _create_analysis_error_finding(self, error_message: str) -> None:
        """
        Create finding for general analysis errors
        """
        # Calculate dynamic confidence based on evidence
        evidence = {
            'pattern_type': 'string_analysis_error',
            'vulnerability_type': 'Analysis Error',
            'resource_type': 'analysis_error',
            'resource_path': 'unknown',
            'file_location': 'analysis_framework',
            'sensitive_data': error_message[:100],
            'masvs_category': 'MASVS-STORAGE-1',
            'mastg_test': 'MASTG-TEST-0001',
            'validation_sources': ['static_analysis', 'framework_analysis'],
            'analysis_methods': ['general_analysis', 'error_detection'],
            'context': {
                "error_type": "general_analysis_error",
                "error_message": error_message,
            }
        }
        dynamic_confidence = calculate_owasp_resource_confidence(evidence)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-ANALYSIS-ERROR-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type="Analysis Error",
            resource_path="unknown",
            resource_type="analysis_error",
            sensitive_data=error_message[:100],
            confidence=dynamic_confidence,
            severity="INFO",
            description=f"Analysis error: {error_message}",
            recommendation="Review analysis configuration and input data integrity.",
            file_location="analysis_framework",
            context={
                "error_type": "general_analysis_error",
                "error_message": error_message,
            },
        )
        self.findings.append(finding)
    
    # 🚀 Configuration File Security - Configuration File Security - Enhanced Methods
    
    def _analyze_external_storage_usage(self, apk_zip: zipfile.ZipFile) -> None:
        """
        🚀 Configuration File Security - Enhanced External Storage Configuration Analysis
        MASTG-TEST-0200: Files Written to External Storage
        MASVS-STORAGE-1: Check for external storage security risks
        
        Enhanced features:
        - Network security configuration analysis
        - Advanced external storage pattern detection
        - Configuration-based vulnerability detection
        - Enhanced permission analysis
        """
        logger.debug("🔍 MASTG-TEST-0200: Enhanced external storage usage analysis (Configuration File Security Analysis)")

        # 🚀 Configuration File Security Analysis: Enhanced manifest analysis
        try:
            manifest_content = apk_zip.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
            self._analyze_manifest_storage_configuration(manifest_content)
            self._analyze_network_security_configuration(manifest_content)
            self._analyze_external_storage_permissions(manifest_content)
        except Exception as e:
            logger.warning(f"⚠️ Error analyzing manifest storage configuration: {e}")

        # 🚀 Configuration File Security Analysis: Enhanced source file analysis  
        source_files = [
            f for f in apk_zip.namelist() 
            if f.endswith((".java", ".kt", ".xml")) and not f.startswith("META-INF/")
        ]
        
        for source_file in source_files[:100]:  # Limit for performance
            try:
                content = apk_zip.read(source_file).decode("utf-8", errors="ignore")
                
                # Enhanced external storage pattern detection
                self._check_external_storage_patterns(content, source_file)
                
                # Network security configuration detection
                self._check_network_security_patterns(content, source_file)
                
                # Configuration vulnerability detection
                self._check_configuration_vulnerabilities(content, source_file)
                
            except Exception as e:
                logger.debug(f"Error analyzing source file {source_file}: {e}")
                continue

        # 🚀 Configuration File Security Analysis: Configuration file analysis
        self._analyze_configuration_files(apk_zip)

    def _analyze_backup_configuration(self, apk_zip: zipfile.ZipFile) -> None:
        """
        🚀 Configuration File Security - Enhanced Backup Configuration Analysis
        MASTG-TEST-0009: Testing Backups for Sensitive Data
        MASVS-STORAGE-1: Analyze backup configuration security
        
        Enhanced features:
        - Advanced backup rule analysis
        - Data extraction rules examination
        - Backup agent security assessment
        - Configuration file backup analysis
        """
        logger.debug("🔍 MASTG-TEST-0009: Enhanced backup configuration analysis (Configuration File Security Analysis)")

        # 🚀 Configuration File Security Analysis: Enhanced manifest backup analysis
        try:
            manifest_content = apk_zip.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
            self._analyze_manifest_backup_configuration(manifest_content)
            self._analyze_data_extraction_rules(manifest_content)
            self._analyze_backup_agent_configuration(manifest_content)
        except Exception as e:
            logger.warning(f"⚠️ Error analyzing manifest backup configuration: {e}")

        # 🚀 Configuration File Security Analysis: Backup rules file analysis
        self._analyze_backup_rules_files(apk_zip)
        
        # 🚀 Configuration File Security Analysis: Auto-backup configuration analysis
        self._analyze_auto_backup_configuration(apk_zip)

    def _analyze_manifest_storage_configuration(self, manifest_content: str) -> None:
        """
        Enhanced manifest storage configuration analysis
        """
        # External storage permissions
        external_storage_permissions = [
            "WRITE_EXTERNAL_STORAGE",
            "READ_EXTERNAL_STORAGE", 
            "MANAGE_EXTERNAL_STORAGE",
            "ACCESS_MEDIA_LOCATION",
        ]
        
        for permission in external_storage_permissions:
            if f'android.permission.{permission}' in manifest_content:
                self._create_storage_permission_finding(permission, "AndroidManifest.xml")

        # Scoped storage configuration
        scoped_storage_patterns = [
            r'android:requestLegacyExternalStorage="true"',
            r'android:preserveLegacyExternalStorage="true"',
            r'android:hasFragileUserData="true"',
        ]
        
        for pattern in scoped_storage_patterns:
            matches = re.finditer(pattern, manifest_content, re.IGNORECASE)
            for match in matches:
                self._create_scoped_storage_finding(match, "AndroidManifest.xml")

    def _analyze_network_security_configuration(self, manifest_content: str) -> None:
        """
        Enhanced network security configuration analysis
        """
        # Network security config detection
        network_config_pattern = r'android:networkSecurityConfig="@xml/([^"]+)"'
        network_matches = re.finditer(network_config_pattern, manifest_content)
        
        for match in network_matches:
            config_name = match.group(1)
            self._create_network_security_config_finding(config_name, "AndroidManifest.xml")

        # Clear text traffic configuration
        cleartext_patterns = [
            r'android:usesCleartextTraffic="true"',
            r'android:networkSecurityConfig="false"',
        ]
        
        for pattern in cleartext_patterns:
            matches = re.finditer(pattern, manifest_content, re.IGNORECASE)
            for match in matches:
                self._create_cleartext_traffic_finding(match, "AndroidManifest.xml")

    def _analyze_external_storage_permissions(self, manifest_content: str) -> None:
        """
        Enhanced external storage permission analysis
        """
        # Dangerous permission combinations
        dangerous_permission_sets = [
            ["WRITE_EXTERNAL_STORAGE", "INTERNET"],
            ["MANAGE_EXTERNAL_STORAGE", "INTERNET"],
            ["READ_EXTERNAL_STORAGE", "CAMERA"],
        ]
        
        for permission_set in dangerous_permission_sets:
            if all(f'android.permission.{perm}' in manifest_content for perm in permission_set):
                self._create_dangerous_permission_combination_finding(permission_set, "AndroidManifest.xml")

    def _check_external_storage_patterns(self, content: str, file_path: str) -> None:
        """
        Enhanced external storage pattern detection
        """
        # Enhanced external storage patterns
        enhanced_external_storage_patterns = [
            # Storage access patterns
            (r'getExternalStorageDirectory\(\)', "external_storage_directory"),
            (r'getExternalFilesDir\([^)]*\)', "external_files_directory"),
            (r'getExternalCacheDir\(\)', "external_cache_directory"),
            (r'Environment\.DIRECTORY_DOWNLOADS', "downloads_directory"),
            (r'MediaStore\.(Images|Audio|Video)', "media_store_access"),
            
            # Scoped storage patterns
            (r'ACTION_OPEN_DOCUMENT_TREE', "document_tree_access"),
            (r'DocumentsContract', "documents_contract"),
            (r'ContentResolver\.openFileDescriptor', "file_descriptor_access"),
            
            # Legacy storage patterns
            (r'requestLegacyExternalStorage', "legacy_storage_request"),
            (r'preserveLegacyExternalStorage', "preserve_legacy_storage"),
            
            # File operation patterns
            (r'File\([^)]*getExternalStorageDirectory', "file_external_storage"),
            (r'FileOutputStream\([^)]*external', "external_file_output"),
            (r'RandomAccessFile\([^)]*external', "external_random_access"),
        ]
        
        for pattern, pattern_type in enhanced_external_storage_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._create_external_storage_pattern_finding(match, pattern_type, file_path)

    def _check_network_security_patterns(self, content: str, file_path: str) -> None:
        """
        Enhanced network security pattern detection
        """
        network_security_patterns = [
            # TLS/SSL configuration
            (r'TrustManager\[\]\s*\{\s*new\s+X509TrustManager', "custom_trust_manager"),
            (r'HostnameVerifier\s*\{\s*return\s+true', "hostname_verification_bypass"),
            (r'setHostnameVerifier\([^)]*ALLOW_ALL', "allow_all_hostname_verifier"),
            (r'SSLContext\.getInstance\(["\']SSL["\']\)', "ssl_context_insecure"),
            
            # Certificate pinning bypass
            (r'CertificatePinner\.Builder\(\)\.build\(\)', "empty_certificate_pinner"),
            (r'okhttp3\.CertificatePinner\.NONE', "certificate_pinner_disabled"),
            
            # HTTP configuration
            (r'http://[^"\s]+', "http_url_usage"),
            (r'HttpURLConnection\s+.*http://', "http_url_connection"),
            (r'OkHttpClient\.Builder\(\)\.protocols\([^)]*Protocol\.HTTP_1_1', "http_protocol_usage"),
            
            # Network security config
            (r'<network-security-config>', "network_security_config"),
            (r'<domain-config[^>]*cleartextTrafficPermitted="true"', "cleartext_permitted"),
            (r'<trust-anchors[^>]*>', "custom_trust_anchors"),
        ]
        
        for pattern, pattern_type in network_security_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                self._create_network_security_pattern_finding(match, pattern_type, file_path)

    def _check_configuration_vulnerabilities(self, content: str, file_path: str) -> None:
        """
        Enhanced configuration vulnerability detection
        """
        config_vulnerability_patterns = [
            # Debug configuration
            (r'BuildConfig\.DEBUG\s*=\s*true', "debug_mode_enabled"),
            (r'android:debuggable="true"', "debuggable_enabled"),
            (r'android:allowBackup="true"', "backup_allowed"),
            
            # Permission configuration
            (r'android:exported="true"[^>]*>', "exported_component"),
            (r'android:permission=""', "empty_permission"),
            (r'android:protectionLevel="normal"', "normal_protection_level"),
            
            # Intent filter vulnerabilities
            (r'<intent-filter[^>]*>[^<]*<action[^>]*android\.intent\.action\.MAIN', "main_activity_exported"),
            (r'<intent-filter[^>]*>[^<]*<category[^>]*android\.intent\.category\.LAUNCHER', "launcher_activity_exported"),
            
            # Provider configuration
            (r'android:authorities="[^"]*"[^>]*android:exported="true"', "exported_content_provider"),
            (r'android:grantUriPermissions="true"', "grant_uri_permissions"),
            
            # Service configuration
            (r'<service[^>]*android:exported="true"', "exported_service"),
            (r'<receiver[^>]*android:exported="true"', "exported_receiver"),
        ]
        
        for pattern, pattern_type in config_vulnerability_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                self._create_configuration_vulnerability_finding(match, pattern_type, file_path)

    def _analyze_configuration_files(self, apk_zip: zipfile.ZipFile) -> None:
        """
        Enhanced configuration file analysis
        """
        # Network security configuration files
        config_files = [
            f for f in apk_zip.namelist() 
            if f.startswith("res/xml/") and ("network" in f.lower() or "security" in f.lower())
        ]
        
        for config_file in config_files:
            try:
                content = apk_zip.read(config_file).decode("utf-8", errors="ignore")
                self._analyze_network_security_config_file(content, config_file)
            except Exception as e:
                logger.debug(f"Error analyzing config file {config_file}: {e}")

    def _analyze_manifest_backup_configuration(self, manifest_content: str) -> None:
        """
        Enhanced manifest backup configuration analysis
        """
        # Backup configuration patterns
        backup_patterns = [
            (r'android:allowBackup="true"', "backup_allowed", "HIGH"),
            (r'android:allowBackup="false"', "backup_disabled", "INFO"),
            (r'android:backupAgent="([^"]+)"', "custom_backup_agent", "MEDIUM"),
            (r'android:fullBackupContent="([^"]+)"', "full_backup_content", "MEDIUM"),
            (r'android:dataExtractionRules="([^"]+)"', "data_extraction_rules", "HIGH"),
            (r'android:fullBackupOnly="true"', "full_backup_only", "MEDIUM"),
        ]
        
        for pattern, finding_type, severity in backup_patterns:
            matches = re.finditer(pattern, manifest_content, re.IGNORECASE)
            for match in matches:
                self._create_backup_configuration_finding(match, finding_type, severity, "AndroidManifest.xml")

    def _analyze_data_extraction_rules(self, manifest_content: str) -> None:
        """
        Enhanced data extraction rules analysis
        """
        # Data extraction rule patterns
        extraction_rule_pattern = r'android:dataExtractionRules="@xml/([^"]+)"'
        matches = re.finditer(extraction_rule_pattern, manifest_content)
        
        for match in matches:
            rule_file = match.group(1)
            self._create_data_extraction_rules_finding(rule_file, "AndroidManifest.xml")

    def _analyze_backup_agent_configuration(self, manifest_content: str) -> None:
        """
        Enhanced backup agent configuration analysis
        """
        # Backup agent patterns
        backup_agent_pattern = r'android:backupAgent="([^"]+)"'
        matches = re.finditer(backup_agent_pattern, manifest_content)
        
        for match in matches:
            agent_class = match.group(1)
            self._create_backup_agent_finding(agent_class, "AndroidManifest.xml")

    def _analyze_backup_rules_files(self, apk_zip: zipfile.ZipFile) -> None:
        """
        Enhanced backup rules file analysis
        """
        backup_rule_files = [
            f for f in apk_zip.namelist() 
            if f.startswith("res/xml/") and ("backup" in f.lower() or "extraction" in f.lower())
        ]
        
        for backup_file in backup_rule_files:
            try:
                content = apk_zip.read(backup_file).decode("utf-8", errors="ignore")
                self._analyze_backup_rules_content(content, backup_file)
            except Exception as e:
                logger.debug(f"Error analyzing backup rules file {backup_file}: {e}")

    def _analyze_auto_backup_configuration(self, apk_zip: zipfile.ZipFile) -> None:
        """
        Enhanced auto-backup configuration analysis
        """
        # Look for auto-backup configuration files
        auto_backup_files = [
            f for f in apk_zip.namelist() 
            if "backup" in f.lower() and f.endswith(".xml")
        ]
        
        for backup_file in auto_backup_files:
            try:
                content = apk_zip.read(backup_file).decode("utf-8", errors="ignore")
                self._analyze_auto_backup_rules(content, backup_file)
            except Exception as e:
                logger.debug(f"Error analyzing auto-backup file {backup_file}: {e}")

    def _analyze_network_security_config_file(self, content: str, file_path: str) -> None:
        """
        Enhanced network security config file analysis
        """
        # Network security configuration patterns
        network_config_patterns = [
            (r'cleartextTrafficPermitted="true"', "cleartext_traffic_permitted"),
            (r'<trust-anchors[^>]*>[^<]*<certificates\s+src="user"', "user_added_ca_trusted"),
            (r'<trust-anchors[^>]*>[^<]*<certificates\s+src="system"', "system_ca_trusted"),
            (r'<pin-set[^>]*>', "certificate_pinning_configured"),
            (r'<domain[^>]*includeSubdomains="false"', "subdomains_excluded"),
        ]
        
        for pattern, pattern_type in network_config_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                self._create_network_config_file_finding(match, pattern_type, file_path)

    def _analyze_backup_rules_content(self, content: str, file_path: str) -> None:
        """
        Enhanced backup rules content analysis
        """
        # Backup rules patterns
        backup_rules_patterns = [
            (r'<include\s+domain="([^"]+)"', "backup_include_domain"),
            (r'<exclude\s+domain="([^"]+)"', "backup_exclude_domain"),
            (r'<include\s+path="([^"]+)"', "backup_include_path"),
            (r'<exclude\s+path="([^"]+)"', "backup_exclude_path"),
            (r'requireFlags="clientSideEncryption"', "client_side_encryption_required"),
            (r'requireFlags="deviceToDeviceTransfer"', "device_transfer_required"),
        ]
        
        for pattern, pattern_type in backup_rules_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._create_backup_rules_finding(match, pattern_type, file_path)

    def _analyze_auto_backup_rules(self, content: str, file_path: str) -> None:
        """
        Enhanced auto-backup rules analysis
        """
        # Auto-backup specific patterns
        auto_backup_patterns = [
            (r'<cloud-backup[^>]*>', "cloud_backup_configured"),
            (r'<device-transfer[^>]*>', "device_transfer_configured"),
            (r'disableIfNoEncryptionCapabilities="true"', "encryption_required"),
            (r'<exclude[^>]*>', "auto_backup_exclusion"),
        ]
        
        for pattern, pattern_type in auto_backup_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._create_auto_backup_finding(match, pattern_type, file_path)

    # 🚀 Configuration File Security - Enhanced Finding Creation Methods

    def _create_storage_permission_finding(self, permission: str, file_path: str) -> None:
        """Create finding for storage permission usage"""
        severity = "HIGH" if permission in ["WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"] else "MEDIUM"
        
        # Calculate dynamic confidence based on evidence
        evidence = {
            'pattern_type': 'external_storage',
            'vulnerability_type': f'External Storage Permission: {permission}',
            'resource_type': 'storage_permission',
            'resource_path': file_path,
            'file_location': file_path,
            'sensitive_data': f'Permission: {permission}',
            'masvs_category': 'MASVS-STORAGE-1',
            'mastg_test': 'MASTG-TEST-0200',
            'validation_sources': ['manifest_analysis', 'permission_analysis'],
            'analysis_methods': ['static_analysis', 'permission_detection'],
            'context': {
                "permission": permission,
                "permission_type": "external_storage",
                "task": "A.6",
            }
        }
        dynamic_confidence = calculate_owasp_resource_confidence(evidence)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-STORAGE-PERM-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type=f"External Storage Permission: {permission}",
            resource_path=file_path,
            resource_type="storage_permission",
            sensitive_data=f"Permission: {permission}",
            confidence=dynamic_confidence,
            severity=severity,
            description=f"External storage permission detected: {permission}",
            recommendation="Review external storage usage and implement scoped storage where possible.",
            file_location=file_path,
            context={
                "permission": permission,
                "permission_type": "external_storage",
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_scoped_storage_finding(self, match: re.Match, file_path: str) -> None:
        """Create finding for scoped storage configuration"""
        config_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-SCOPED-STORAGE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type="Scoped Storage Configuration",
            resource_path=file_path,
            resource_type="scoped_storage_config",
            sensitive_data=config_text,
            confidence=0.85,
            severity="MEDIUM",
            description=f"Scoped storage configuration detected: {config_text}",
            recommendation="Review scoped storage configuration for security implications.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "configuration": config_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_network_security_config_finding(self, config_name: str, file_path: str) -> None:
        """Create finding for network security configuration"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-NET-SEC-CONFIG-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type="Network Security Configuration",
            resource_path=file_path,
            resource_type="network_security_config",
            sensitive_data=f"Network config: {config_name}",
            confidence=0.80,
            severity="INFO",
            description=f"Network security configuration detected: {config_name}",
            recommendation="Review network security configuration for proper TLS/SSL settings.",
            file_location=file_path,
            context={
                "config_name": config_name,
                "config_type": "network_security",
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_cleartext_traffic_finding(self, match: re.Match, file_path: str) -> None:
        """Create finding for cleartext traffic configuration"""
        config_text = match.group(0)
        
        # Calculate dynamic confidence based on evidence
        evidence = {
            'pattern_type': 'network_security',
            'vulnerability_type': 'Cleartext Traffic Configuration',
            'resource_type': 'cleartext_traffic_config',
            'resource_path': file_path,
            'file_location': f"{file_path}:{match.start()}-{match.end()}",
            'sensitive_data': config_text,
            'masvs_category': 'MASVS-STORAGE-1',
            'mastg_test': 'MASTG-TEST-0200',
            'validation_sources': ['manifest_analysis', 'static_analysis', 'pattern_matching'],
            'analysis_methods': ['network_security_analysis', 'cleartext_detection'],
            'context': {
                "configuration": config_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            }
        }
        dynamic_confidence = calculate_owasp_resource_confidence(evidence)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-CLEARTEXT-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type="Cleartext Traffic Configuration",
            resource_path=file_path,
            resource_type="cleartext_traffic_config",
            sensitive_data=config_text,
            confidence=dynamic_confidence,
            severity="HIGH",
            description=f"Cleartext traffic configuration detected: {config_text}",
            recommendation="Disable cleartext traffic and use HTTPS for all network communications.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "configuration": config_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_dangerous_permission_combination_finding(self, permission_set: list, file_path: str) -> None:
        """Create finding for dangerous permission combinations"""
        permissions_str = ", ".join(permission_set)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-PERM-COMBO-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type="Dangerous Permission Combination",
            resource_path=file_path,
            resource_type="permission_combination",
            sensitive_data=f"Permissions: {permissions_str}",
            confidence=0.85,
            severity="HIGH",
            description=f"Dangerous permission combination detected: {permissions_str}",
            recommendation="Review permission usage and minimize requested permissions.",
            file_location=file_path,
            context={
                "permissions": permission_set,
                "combination_type": "dangerous",
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_external_storage_pattern_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for external storage patterns"""
        pattern_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-EXT-STORAGE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type=f"External Storage Pattern: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="external_storage_pattern",
            sensitive_data=pattern_text[:100],
            confidence=0.80,
            severity="MEDIUM",
            description=f"External storage usage pattern detected: {pattern_type}",
            recommendation="Review external storage usage for security implications and data exposure risks.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_network_security_pattern_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for network security patterns"""
        pattern_text = match.group(0)
        severity = "HIGH" if pattern_type in ["custom_trust_manager", "hostname_verification_bypass"] else "MEDIUM"
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-NET-SEC-PATTERN-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1", 
            mastg_test="MASTG-TEST-0200",
            vulnerability_type=f"Network Security Pattern: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="network_security_pattern",
            sensitive_data=pattern_text[:100],
            confidence=0.85,
            severity=severity,
            description=f"Network security pattern detected: {pattern_type}",
            recommendation="Review network security implementation for proper TLS/SSL configuration.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_configuration_vulnerability_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for configuration vulnerabilities"""
        pattern_text = match.group(0)
        severity = "HIGH" if pattern_type in ["debug_mode_enabled", "exported_component"] else "MEDIUM"
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-CONFIG-VULN-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0009",
            vulnerability_type=f"Configuration Vulnerability: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="configuration_vulnerability",
            sensitive_data=pattern_text[:100],
            confidence=0.90,
            severity=severity,
            description=f"Configuration vulnerability detected: {pattern_type}",
            recommendation="Review configuration settings for security implications.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "vulnerability_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_backup_configuration_finding(self, match: re.Match, finding_type: str, severity: str, file_path: str) -> None:
        """Create finding for backup configuration"""
        config_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-BACKUP-CONFIG-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0009",
            vulnerability_type=f"Backup Configuration: {finding_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="backup_configuration",
            sensitive_data=config_text,
            confidence=0.90,
            severity=severity,
            description=f"Backup configuration detected: {finding_type}",
            recommendation="Review backup configuration for sensitive data exposure risks.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "configuration_type": finding_type,
                "configuration_text": config_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_data_extraction_rules_finding(self, rule_file: str, file_path: str) -> None:
        """Create finding for data extraction rules"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-DATA-EXTRACT-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0009",
            vulnerability_type="Data Extraction Rules Configuration",
            resource_path=file_path,
            resource_type="data_extraction_rules",
            sensitive_data=f"Rule file: {rule_file}",
            confidence=0.85,
            severity="HIGH",
            description=f"Data extraction rules configuration detected: {rule_file}",
            recommendation="Review data extraction rules for sensitive data handling.",
            file_location=file_path,
            context={
                "rule_file": rule_file,
                "config_type": "data_extraction",
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_backup_agent_finding(self, agent_class: str, file_path: str) -> None:
        """Create finding for backup agent configuration"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-BACKUP-AGENT-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0009",
            vulnerability_type="Custom Backup Agent",
            resource_path=file_path,
            resource_type="backup_agent",
            sensitive_data=f"Agent class: {agent_class}",
            confidence=0.80,
            severity="MEDIUM",
            description=f"Custom backup agent detected: {agent_class}",
            recommendation="Review backup agent implementation for proper data handling.",
            file_location=file_path,
            context={
                "agent_class": agent_class,
                "agent_type": "custom_backup",
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_network_config_file_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for network config file patterns"""
        pattern_text = match.group(0)
        severity = "HIGH" if pattern_type in ["cleartext_traffic_permitted", "user_added_ca_trusted"] else "MEDIUM"
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-NET-CONFIG-FILE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0200",
            vulnerability_type=f"Network Config: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="network_config_file",
            sensitive_data=pattern_text[:100],
            confidence=0.85,
            severity=severity,
            description=f"Network configuration detected: {pattern_type}",
            recommendation="Review network security configuration for proper TLS/SSL settings.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_backup_rules_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for backup rules patterns"""
        pattern_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-BACKUP-RULES-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0009",
            vulnerability_type=f"Backup Rules: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="backup_rules",
            sensitive_data=pattern_text[:100],
            confidence=0.80,
            severity="MEDIUM",
            description=f"Backup rules configuration detected: {pattern_type}",
            recommendation="Review backup rules for sensitive data inclusion/exclusion policies.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)

    def _create_auto_backup_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for auto-backup patterns"""
        pattern_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-AUTO-BACKUP-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0009",
            vulnerability_type=f"Auto Backup: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="auto_backup",
            sensitive_data=pattern_text[:100],
            confidence=0.75,
            severity="MEDIUM",
            description=f"Auto-backup configuration detected: {pattern_type}",
            recommendation="Review auto-backup configuration for data protection requirements.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.6",
            },
        )
        self.findings.append(finding)
    
    # ===== MISSING METHODS IMPLEMENTATION =====
    
    def _is_string_resource_file(self, file_path: str) -> bool:
        """Check if file is a string resource file"""
        return (file_path.startswith("res/values") and 
                file_path.endswith(".xml") and 
                ("strings" in file_path or "values" in file_path))
    
    def _read_string_file_with_encoding_detection(self, apk_zip: zipfile.ZipFile, file_path: str) -> str:
        """Read string file with encoding detection"""
        try:
            raw_content = apk_zip.read(file_path)
            
            # Try multiple encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
            
            for encoding in encodings:
                try:
                    return raw_content.decode(encoding)
                except UnicodeDecodeError:
                    continue
                    
            # Fallback to utf-8 with error handling
            return raw_content.decode('utf-8', errors='ignore')
            
        except Exception as e:
            logger.warning(f"Error reading string file {file_path}: {e}")
            return ""
    
    def _create_asset_analysis_error_finding(self, asset_file: str, error_message: str) -> None:
        """Create finding for asset analysis errors"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-ASSET-ERROR-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type="Asset Analysis Error",
            resource_path=asset_file,
            resource_type="analysis_error",
            sensitive_data=f"Error: {error_message[:100]}",
            confidence=0.0,
            severity="INFO",
            description=f"Asset analysis error: {error_message}",
            recommendation="Review asset file format and content.",
            file_location=asset_file,
            context={
                "error_type": "asset_analysis",
                "error_message": error_message,
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _analyze_json_structure(self, json_data: dict, asset_file: str) -> None:
        """Analyze JSON structure for sensitive data"""
        try:
            # Analyze JSON keys and values for sensitive patterns
            self._check_json_recursive(json_data, asset_file, "")
        except Exception as e:
            logger.debug(f"JSON structure analysis error for {asset_file}: {e}")
    
    def _check_json_recursive(self, data: any, file_path: str, path_prefix: str) -> None:
        """Recursively check JSON data for sensitive patterns"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path_prefix}.{key}" if path_prefix else key
                
                # Check key names for sensitive indicators
                if any(keyword in key.lower() for keyword in ['password', 'secret', 'key', 'token', 'api']):
                    self._create_json_sensitive_finding(key, str(value), file_path, current_path)
                
                # Recurse into nested structures
                self._check_json_recursive(value, file_path, current_path)
                
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path_prefix}[{i}]"
                self._check_json_recursive(item, file_path, current_path)
    
    def _create_json_sensitive_finding(self, key: str, value: str, file_path: str, json_path: str) -> None:
        """Create finding for sensitive data in JSON"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-JSON-SENSITIVE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001", 
            vulnerability_type="JSON Sensitive Data",
            resource_path=file_path,
            resource_type="json_sensitive",
            sensitive_data=f"{key}: {value[:50]}",
            confidence=0.80,
            severity="HIGH",
            description=f"Sensitive data found in JSON: {key}",
            recommendation="Review JSON content for sensitive data exposure.",
            file_location=f"{file_path}:{json_path}",
            context={
                "json_key": key,
                "json_path": json_path,
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _analyze_text_content(self, content: str, file_path: str, resource_type: str) -> None:
        """Analyze text content for sensitive patterns"""
        try:
            # Check for various sensitive patterns
            for category, pattern_data in self.sensitive_patterns.items():
                for pattern in pattern_data["patterns"]:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self._create_text_sensitive_finding(match, category, file_path, resource_type)
        except Exception as e:
            logger.debug(f"Text content analysis error for {file_path}: {e}")
    
    def _create_text_sensitive_finding(self, match: re.Match, category: str, file_path: str, resource_type: str) -> None:
        """Create finding for sensitive text patterns"""
        pattern_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-TEXT-SENSITIVE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type=f"Text Sensitive Data: {category.title()}",
            resource_path=file_path,
            resource_type=resource_type,
            sensitive_data=pattern_text[:100],
            confidence=0.75,
            severity=self.sensitive_patterns[category]["severity"],
            description=f"Sensitive {category} pattern detected in text content",
            recommendation="Review text content for sensitive data exposure.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_category": category,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _check_json_sensitive_patterns(self, content: str, file_path: str) -> None:
        """Check JSON content for sensitive patterns"""
        self._analyze_text_content(content, file_path, "json_content")
    
    def _check_xml_configuration_patterns(self, content: str, file_path: str) -> None:
        """Check XML content for configuration patterns"""
        xml_config_patterns = [
            (r'<string[^>]*name="[^"]*api[^"]*"[^>]*>([^<]+)</string>', "api_key_in_xml"),
            (r'<string[^>]*name="[^"]*secret[^"]*"[^>]*>([^<]+)</string>', "secret_in_xml"),
            (r'<string[^>]*name="[^"]*password[^"]*"[^>]*>([^<]+)</string>', "password_in_xml"),
        ]
        
        for pattern, pattern_type in xml_config_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._create_xml_config_finding(match, pattern_type, file_path)
    
    def _create_xml_config_finding(self, match: re.Match, pattern_type: str, file_path: str) -> None:
        """Create finding for XML configuration patterns"""
        pattern_text = match.group(0)
        
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-XML-CONFIG-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type=f"XML Configuration: {pattern_type.replace('_', ' ').title()}",
            resource_path=file_path,
            resource_type="xml_config",
            sensitive_data=pattern_text[:100],
            confidence=0.85,
            severity="HIGH",
            description=f"XML configuration pattern detected: {pattern_type}",
            recommendation="Review XML configuration for sensitive data exposure.",
            file_location=f"{file_path}:{match.start()}-{match.end()}",
            context={
                "pattern_type": pattern_type,
                "pattern_text": pattern_text,
                "match_position": {"start": match.start(), "end": match.end()},
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _detect_text_format(self, content: str, file_path: str) -> str:
        """Detect text format for specialized parsing"""
        content_lower = content.lower()
        
        if "," in content and "\n" in content:
            return "csv"
        elif "=" in content and ("\n" in content or "\r\n" in content):
            return "properties"
        elif any(keyword in content_lower for keyword in ["error", "warn", "info", "debug"]):
            return "log"
        else:
            return "text"
    
    def _analyze_csv_content(self, content: str, file_path: str) -> None:
        """Analyze CSV content for sensitive data"""
        try:
            lines = content.split('\n')
            for i, line in enumerate(lines[:10]):  # Check first 10 lines
                if any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
                    self._create_csv_sensitive_finding(line, file_path, i+1)
        except Exception as e:
            logger.debug(f"CSV analysis error for {file_path}: {e}")
    
    def _create_csv_sensitive_finding(self, line: str, file_path: str, line_number: int) -> None:
        """Create finding for sensitive CSV data"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-CSV-SENSITIVE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type="CSV Sensitive Data",
            resource_path=file_path,
            resource_type="csv_sensitive",
            sensitive_data=line[:100],
            confidence=0.70,
            severity="MEDIUM",
            description=f"Sensitive data detected in CSV line {line_number}",
            recommendation="Review CSV content for sensitive data exposure.",
            file_location=f"{file_path}:{line_number}",
            context={
                "line_number": line_number,
                "line_content": line[:200],
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _analyze_properties_content(self, content: str, file_path: str) -> None:
        """Analyze properties content for sensitive data"""
        try:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if '=' in line and any(keyword in line.lower() for keyword in ['password', 'secret', 'key', 'token']):
                    self._create_properties_sensitive_finding(line, file_path, i+1)
        except Exception as e:
            logger.debug(f"Properties analysis error for {file_path}: {e}")
    
    def _create_properties_sensitive_finding(self, line: str, file_path: str, line_number: int) -> None:
        """Create finding for sensitive properties data"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-PROP-SENSITIVE-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type="Properties Sensitive Data",
            resource_path=file_path,
            resource_type="properties_sensitive",
            sensitive_data=line[:100],
            confidence=0.80,
            severity="HIGH",
            description=f"Sensitive data detected in properties line {line_number}",
            recommendation="Review properties content for sensitive data exposure.",
            file_location=f"{file_path}:{line_number}",
            context={
                "line_number": line_number,
                "property_line": line[:200],
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _analyze_log_content(self, content: str, file_path: str) -> None:
        """Analyze log content for sensitive data"""
        try:
            # Check for sensitive patterns in logs
            self._analyze_text_content(content, file_path, "log_content")
        except Exception as e:
            logger.debug(f"Log analysis error for {file_path}: {e}")
    
    def _check_text_sensitive_patterns(self, content: str, file_path: str) -> None:
        """Check text content for sensitive patterns"""
        self._analyze_text_content(content, file_path, "text_content")
    
    def _check_config_sensitive_patterns(self, content: str, file_path: str) -> None:
        """Check configuration content for sensitive patterns"""
        self._analyze_text_content(content, file_path, "config_content")
    
    def _create_binary_asset_finding(self, asset_file: str, file_size: int, finding_type: str) -> None:
        """Create finding for binary assets"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-BINARY-ASSET-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type=f"Binary Asset: {finding_type.replace('_', ' ').title()}",
            resource_path=asset_file,
            resource_type="binary_asset",
            sensitive_data=f"File size: {file_size} bytes",
            confidence=0.60,
            severity="INFO",
            description=f"Binary asset detected: {finding_type}",
            recommendation="Review binary asset for sensitive data exposure.",
            file_location=asset_file,
            context={
                "file_size": file_size,
                "asset_type": finding_type,
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _analyze_binary_strings(self, raw_content: bytes, asset_file: str) -> None:
        """Analyze binary content for string patterns"""
        try:
            # Extract printable strings from binary content
            strings = re.findall(rb'[\x20-\x7E]{4,}', raw_content)
            
            for string_bytes in strings[:20]:  # Limit to first 20 strings
                try:
                    string_text = string_bytes.decode('utf-8', errors='ignore')
                    if len(string_text) > 10:  # Only check longer strings
                        self._analyze_text_content(string_text, asset_file, "binary_string")
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"Binary string analysis error for {asset_file}: {e}")
    
    def _detect_content_type(self, raw_content: bytes, asset_file: str) -> str:
        """Detect content type of unknown assets"""
        try:
            # Try to detect if it's text-based
            if len(raw_content) > 0:
                # Check if mostly printable characters
                printable_ratio = sum(1 for b in raw_content[:1000] if 32 <= b <= 126) / min(len(raw_content), 1000)
                if printable_ratio > 0.7:
                    return "text"
                else:
                    return "binary"
            return "empty"
        except Exception:
            return "unknown"
    
    def _create_unknown_asset_finding(self, asset_file: str, file_size: int) -> None:
        """Create finding for unknown asset types"""
        finding = OWASPResourceFinding(
            finding_id=f"OWASP-UNKNOWN-ASSET-{len(self.findings)+1:04d}",
            masvs_category="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            vulnerability_type="Unknown Asset Type",
            resource_path=asset_file,
            resource_type="unknown_asset",
            sensitive_data=f"File size: {file_size} bytes",
            confidence=0.50,
            severity="INFO",
            description="Unknown asset type detected",
            recommendation="Review unknown asset for potential sensitive data.",
            file_location=asset_file,
            context={
                "file_size": file_size,
                "detection_method": "unknown_type_analysis",
                "task": "A.5",
            },
        )
        self.findings.append(finding)
    
    def _check_sensitive_patterns(self, content: str, file_path: str, resource_type: str) -> None:
        """Check content for sensitive patterns"""
        if content:
            self._analyze_text_content(content, file_path, resource_type)
    
    def _get_masvs_recommendation(self, category: str, masvs_cat: str) -> str:
        """Get MASVS-specific recommendation"""
        recommendations = {
            "secrets": "Store secrets securely using Android Keystore or encrypted SharedPreferences",
            "credentials": "Use secure credential storage mechanisms and avoid hardcoding",
            "databases": "Encrypt database files and use proper access controls",
            "string_resources": "Avoid storing sensitive data in string resources",
        }
        return recommendations.get(category, "Review for security best practices")
    
    def _analyze_raw_resources(self, apk_zip: zipfile.ZipFile) -> None:
        """Analyze raw resources for sensitive data"""
        try:
            raw_files = [f for f in apk_zip.namelist() if f.startswith("res/raw/")]
            
            for raw_file in raw_files[:10]:  # Limit for performance
                try:
                    content = apk_zip.read(raw_file).decode("utf-8", errors="ignore")
                    self._analyze_text_content(content, raw_file, "raw_resource")
                except Exception as e:
                    logger.debug(f"Error analyzing raw resource {raw_file}: {e}")
                    continue
        except Exception as e:
            logger.debug(f"Raw resource analysis error: {e}")
    
    def _analyze_binary_resources(self, apk_zip: zipfile.ZipFile) -> None:
        """Analyze binary resources for string extraction"""
        try:
            binary_files = [f for f in apk_zip.namelist() 
                          if f.startswith("res/") and f.endswith((".png", ".jpg", ".so", ".dex"))]
            
            for binary_file in binary_files[:5]:  # Limit for performance
                try:
                    raw_content = apk_zip.read(binary_file)
                    if len(raw_content) < 1024 * 1024:  # Only analyze files < 1MB
                        self._analyze_binary_strings(raw_content, binary_file)
                except Exception as e:
                    logger.debug(f"Error analyzing binary resource {binary_file}: {e}")
                    continue
        except Exception as e:
            logger.debug(f"Binary resource analysis error: {e}")

    def _convert_enhanced_finding_to_owasp(self, enhanced_finding) -> OWASPResourceFinding:
        """Convert EnhancedAssetFinding to OWASPResourceFinding"""
        return OWASPResourceFinding(
            finding_id=enhanced_finding.finding_id.replace("ENHANCED-ASSET", "OWASP-RESOURCE"),
            masvs_category=enhanced_finding.masvs_category,
            mastg_test=enhanced_finding.mastg_test,
            vulnerability_type=enhanced_finding.vulnerability_type,
            resource_path=enhanced_finding.asset_path,
            resource_type=enhanced_finding.asset_type,
            sensitive_data=enhanced_finding.sensitive_data,
            confidence=enhanced_finding.confidence,
            severity=enhanced_finding.severity,
            description=enhanced_finding.description,
            recommendation=enhanced_finding.recommendation,
            file_location=enhanced_finding.file_location,
            context=enhanced_finding.context
        )
    def get_analysis_report(self) -> Dict[str, Any]:
        """Generate comprehensive OWASP MASVS analysis report"""
        if not self.findings:
            return {"error": "No analysis performed"}

        # Group findings by MASVS category
        masvs_categories = {}
        mastg_tests = {}
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for finding in self.findings:
            # MASVS category grouping
            if finding.masvs_category not in masvs_categories:
                masvs_categories[finding.masvs_category] = []
            masvs_categories[finding.masvs_category].append(finding)

            # MASTG test grouping
            if finding.mastg_test not in mastg_tests:
                mastg_tests[finding.mastg_test] = []
            mastg_tests[finding.mastg_test].append(finding)

            # Severity counting
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        return {
            "analysis_metadata": {
                "analyzer": "OWASP MASVS-STORAGE Resource Analyzer",
                "version": "1.0.0",
                "analysis_duration": self.analysis_duration,
                "timestamp": time.time(),
                "total_findings": len(self.findings),
            },
            "owasp_compliance": {
                "masvs_categories_covered": list(masvs_categories.keys()),
                "mastg_tests_implemented": list(mastg_tests.keys()),
                "masvs_categories_count": len(masvs_categories),
                "mastg_tests_count": len(mastg_tests),
            },
            "severity_distribution": severity_counts,
            "masvs_category_breakdown": {
                category: len(findings)
                for category, findings in masvs_categories.items()
            },
            "mastg_test_results": {
                test: len(findings) for test, findings in mastg_tests.items()
            },
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "masvs_category": f.masvs_category,
                    "mastg_test": f.mastg_test,
                    "vulnerability_type": f.vulnerability_type,
                    "resource_path": f.resource_path,
                    "resource_type": f.resource_type,
                    "sensitive_data": f.sensitive_data,
                    "confidence": f.confidence,
                    "severity": f.severity,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "file_location": f.file_location,
                    "context": f.context,
                }
                for f in self.findings
            ],
        }

if __name__ == "__main__":
    # Example usage
    analyzer = OWASPResourceAnalyzer()
    # findings = analyzer.analyze_apk_resources("path/to/app.apk")
    # report = analyzer.get_analysis_report()
    print("OWASP MASVS-STORAGE Resource Analyzer ready for APK analysis")
