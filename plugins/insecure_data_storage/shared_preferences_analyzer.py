"""
Shared Preferences Security Analyzer Module

Specialized analyzer for shared preferences security analysis.
Comprehensive implementation for the modular architecture.
"""

import logging
import re
import os
import hashlib
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    SharedPreferencesAnalysis, StorageVulnerability, StorageVulnerabilitySeverity,
    StorageType, StorageSecurityLevel
)
from .confidence_calculator import StorageConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

class SharedPreferencesAnalyzer:
    """Shared preferences security analyzer with comprehensive analysis capabilities."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: StorageConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Initialize analysis patterns
        self.preferences_patterns = self._initialize_preferences_patterns()
        self.encryption_patterns = self._initialize_encryption_patterns()
        self.sensitive_data_patterns = self._initialize_sensitive_data_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            'preferences_analyzed': 0,
            'vulnerabilities_found': 0,
            'encrypted_preferences': 0,
            'files_analyzed': 0,
            'source_files_analyzed': 0,
            'prefs_files_analyzed': 0
        }
        
        # **FIX**: Pre-compile regex patterns for performance
        self._compile_patterns()
    
    def _stable_id(self, *parts: str) -> str:
        """**FIX**: Generate stable IDs using hashlib instead of unstable hash()."""
        raw = "||".join(str(p) for p in parts)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    
    def _compile_patterns(self):
        """**FIX**: Pre-compile regex patterns for better performance."""
        # Modern encryption patterns (AndroidX Security Crypto)
        self._enc_code_patterns = [
            re.compile(r'\bEncryptedSharedPreferences\.create\s*\(', re.IGNORECASE),
            re.compile(r'\bnew\s+MasterKey\b', re.IGNORECASE),
            re.compile(r'\bMasterKey\.Builder\b', re.IGNORECASE),
            re.compile(r'androidx\.security\.crypto\.MasterKey', re.IGNORECASE),
            re.compile(r'\bMasterKeys\.getOrCreate\b', re.IGNORECASE)  # deprecated - flag for warning
        ]
        
        # Sensitive data patterns for XML key/value analysis
        self._sensitive_key_pattern = re.compile(
            r'(password|passwd|pwd|secret|api[-_]?key|access[-_]?token|refresh[-_]?token|private[-_]?key|credential|auth)', 
            re.IGNORECASE
        )
        self._pii_pattern = re.compile(
            r'(email|username|user|login|account|ssn|credit|card|bank)', 
            re.IGNORECASE
        )
        
        # Base64-ish pattern for encrypted value detection
        self._base64ish_pattern = re.compile(r'^[A-Za-z0-9+/=]{24,}$')
    
    def analyze(self, apk_ctx) -> List[SharedPreferencesAnalysis]:
        """Analyze shared preferences security comprehensively."""
        analyses = []
        
        try:
            self.logger.info("Starting comprehensive shared preferences security analysis")
            
            # Find preferences files
            preferences_files = self._find_preferences_files(apk_ctx)
            
            # Find source files with preferences usage
            source_files = self._find_source_files_with_preferences(apk_ctx)
            
            # Analyze preferences files
            for prefs_file in preferences_files:
                try:
                    analysis = self._analyze_preferences_file(prefs_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                        self.analysis_stats['preferences_analyzed'] += 1
                except Exception as e:
                    self.logger.warning(f"Failed to analyze preferences file {prefs_file}: {e}")
            
            # Analyze source code for preferences usage
            for source_file in source_files:
                try:
                    analysis = self._analyze_source_for_preferences(source_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                        self.analysis_stats['preferences_analyzed'] += 1
                except Exception as e:
                    self.logger.warning(f"Failed to analyze source file {source_file}: {e}")
            
            # Update statistics
            self.analysis_stats['files_analyzed'] = len(preferences_files) + len(source_files)
            
            self.logger.info(f"Shared preferences analysis completed: {len(analyses)} preferences analyzed")
            
            return analyses
            
        except Exception as e:
            self.logger.error(f"Shared preferences analysis failed: {e}")
            return []
    
    def _find_preferences_files(self, apk_ctx) -> List[str]:
        """**FIX**: Find ONLY actual shared preferences files in /shared_prefs/*.xml."""
        prefs = set()
        
        try:
            # **FIX**: Restrict to actual shared_prefs directory only
            if hasattr(apk_ctx, 'get_files'):
                files = apk_ctx.get_files()
                for p in files:
                    lower = p.lower()
                    # Must be in shared_prefs directory AND be .xml
                    if "/shared_prefs/" in lower and lower.endswith(".xml"):
                        prefs.add(p)
            
            # **FIX**: Try direct directory API if available
            if hasattr(apk_ctx, 'get_files_in_dir'):
                try:
                    shared_prefs_files = apk_ctx.get_files_in_dir("shared_prefs/")
                    for p in shared_prefs_files:
                        if p.lower().endswith(".xml"):
                            prefs.add(p)
                except Exception:
                    pass  # Directory might not exist
                        
        except Exception as e:
            self.logger.debug(f"Error finding preferences files: {e}")
        
        return sorted(prefs)
    
    def _find_source_files_with_preferences(self, apk_ctx) -> List[str]:
        """Find source files that use shared preferences."""
        source_files = []
        
        try:
            if hasattr(apk_ctx, 'get_java_files'):
                java_files = apk_ctx.get_java_files()
                
                # Check files for preferences usage
                for file_path in java_files[:200]:  # Limit for performance
                    try:
                        if hasattr(apk_ctx, 'get_file_content'):
                            content = apk_ctx.get_file_content(file_path)
                            if content and self._contains_preferences_code(content):
                                source_files.append(file_path)
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error finding source files with preferences: {e}")
        
        return source_files
    
    def _contains_preferences_code(self, content: str) -> bool:
        """Check if source code contains shared preferences usage."""
        preferences_indicators = [
            'SharedPreferences',
            'getSharedPreferences',
            'PreferenceManager',
            'getDefaultSharedPreferences',
            'SharedPreferences.Editor',
            'commit()',
            'apply()',
            'putString',
            'putInt',
            'putBoolean',
            'getString',
            'getInt',
            'getBoolean',
            'EncryptedSharedPreferences'
        ]
        
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in preferences_indicators)
    
    def _analyze_preferences_file(self, prefs_file: str, apk_ctx) -> Optional[SharedPreferencesAnalysis]:
        """Analyze a specific preferences file."""
        try:
            analysis = SharedPreferencesAnalysis(
                preferences_file=os.path.basename(prefs_file),
                encryption_status="unencrypted",  # Will be updated below
                vulnerabilities=[]
            )
            
            # Check file permissions
            permission_vulns = self._check_file_permissions(prefs_file)
            analysis.vulnerabilities.extend(permission_vulns)
            
            # Analyze file content for sensitive data
            if hasattr(apk_ctx, 'get_file_content'):
                content = apk_ctx.get_file_content(prefs_file)
                if content:
                    sensitive_data_vulns = self._check_sensitive_data_in_preferences(content, prefs_file)
                    analysis.vulnerabilities.extend(sensitive_data_vulns)
            
            # Check encryption status
            encryption_result = self._check_preferences_encryption(prefs_file, apk_ctx)
            analysis.encryption_status = "encrypted" if encryption_result.get('encrypted', False) else "unencrypted"
            
            if analysis.encryption_status == "unencrypted":
                vulnerability = StorageVulnerability(
                    id=self._stable_id("prefs_unencrypted", prefs_file),  # **FIX**: Stable ID
                    title="Unencrypted Shared Preferences",
                    description=f"Shared preferences file '{os.path.basename(prefs_file)}' is not encrypted",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.SHARED_PREFERENCES,
                    masvs_control="MASVS-STORAGE-1",  # **FIX**: Updated MASVS reference
                    file_path=prefs_file,
                    location=f"SharedPreferences file: {os.path.basename(prefs_file)}",
                    line_number=1,  # File-level finding
                    affected_files=[prefs_file],
                    evidence=f"Preferences file: {prefs_file}",
                    remediation="Use EncryptedSharedPreferences with MasterKey for sensitive data",
                    confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                        "preferences", "unencrypted", {"file_path": prefs_file}
                    )
                )
                analysis.vulnerabilities.append(vulnerability)
            else:
                self.analysis_stats['encrypted_preferences'] += 1
            
            self.analysis_stats['vulnerabilities_found'] += len(analysis.vulnerabilities)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing preferences file {prefs_file}: {e}")
            return None
    
    def _analyze_source_for_preferences(self, source_file: str, apk_ctx) -> Optional[SharedPreferencesAnalysis]:
        """Analyze source code for shared preferences security patterns."""
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return None
            
            content = apk_ctx.get_file_content(source_file)
            if not content:
                return None
            
            analysis = SharedPreferencesAnalysis(
                preferences_file=source_file,  # **FIX**: Use the actual source file path
                encryption_status="unencrypted",  # **FIX**: Add required parameter
                vulnerabilities=[]
            )
            
            # Check for various shared preferences security issues
            vulns = []
            
            # Check for world-readable mode
            vulns.extend(self._check_world_readable_mode(content, source_file))
            
            # Check for sensitive data storage
            vulns.extend(self._check_sensitive_data_storage(content, source_file))
            
            # Check for encryption usage
            vulns.extend(self._check_encryption_usage(content, source_file))
            
            # Check for preferences backup issues
            vulns.extend(self._check_preferences_backup_issues(content, source_file))
            
            analysis.vulnerabilities = vulns
            self.analysis_stats['vulnerabilities_found'] += len(vulns)
            
            return analysis if vulns else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing source file {source_file}: {e}")
            return None
    
    def _check_file_permissions(self, prefs_file: str) -> List[StorageVulnerability]:
        """Check shared preferences file permissions."""
        vulnerabilities = []
        
        try:
            # Check if file is in world-readable location
            if any(path in prefs_file.lower() for path in ['/sdcard/', '/external/', '/storage/emulated/0/']):
                vulnerability = StorageVulnerability(
                    id=f"prefs_world_readable_{hash(prefs_file)}",
                    title="Shared Preferences in World-Readable Location",
                    description=f"Preferences file '{os.path.basename(prefs_file)}' is in world-readable location",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.SHARED_PREFERENCES,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[prefs_file],
                    evidence=f"World-readable preferences: {prefs_file}",
                    remediation="Store preferences in app's private directory",
                    confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                        prefs_file, "world_readable", {"file_path": prefs_file}
                    )
                )
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            self.logger.debug(f"Error checking file permissions: {e}")
        
        return vulnerabilities
    
    def _iter_prefs_entries(self, xml_text: str) -> List[tuple[str, str, str]]:
        """**FIX**: Parse XML properly to extract key-value pairs."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            self.logger.debug(f"XML parse error: {e}")
            return []
        
        entries = []
        for node in root:
            key = node.attrib.get("name", "")
            val = (node.text or "").strip()
            entries.append((key, val, node.tag))
        return entries
    
    def _check_sensitive_data_in_preferences(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """**FIX**: Use proper XML parsing for sensitive data detection with full evidence visibility."""
        vulnerabilities = []
        
        try:
            # **FIX**: Parse XML structure instead of regex on raw content
            entries = self._iter_prefs_entries(content)
            if not entries:
                return vulnerabilities

            for i, (key, value, tag) in enumerate(entries, start=1):
                # Check for sensitive patterns in key names and values
                is_sensitive_key = self._sensitive_key_pattern.search(key) or self._pii_pattern.search(key)
                is_sensitive_value = self._sensitive_key_pattern.search(value) or self._pii_pattern.search(value)
                
                if is_sensitive_key or is_sensitive_value:
                    # Determine severity based on content type
                    severity = StorageVulnerabilitySeverity.CRITICAL if any(
                        pattern in key.lower() for pattern in ['password', 'secret', 'token', 'key', 'credential']
                    ) else StorageVulnerabilitySeverity.HIGH
                    
                    # **FULL EVIDENCE VISIBILITY** - Show complete key and value
                    evidence = f"XML Entry {i}: key='{key}', value='{value}', tag=<{tag}>"
                    
                    vulnerability = StorageVulnerability(
                        id=self._stable_id("prefs_sensitive", file_path, str(i), key),
                        title="Sensitive Data in Shared Preferences",
                        description=f"Sensitive data found in preferences entry: '{key}'",
                        severity=severity,
                        storage_type=StorageType.SHARED_PREFERENCES,
                        masvs_control="MASVS-STORAGE-1",  # **FIX**: Updated MASVS reference
                        file_path=file_path,
                        location=f"XML entry {i}: <{tag} name=\"{key}\">",
                        line_number=i,  # XML entry number
                        affected_files=[file_path],
                        evidence=evidence,  # **FULL VISIBILITY** - No masking
                        remediation="Remove sensitive data from SharedPreferences or use EncryptedSharedPreferences with proper MasterKey",
                        confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                            "preferences", "sensitive_xml_entry", {"entry_index": i, "key": key, "value_length": len(value)}
                        )
                    )
                    vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            self.logger.debug(f"Error checking sensitive data in XML: {e}")
        
        return vulnerabilities
    
    def _check_world_readable_mode(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for world-readable mode in preferences creation."""
        vulnerabilities = []
        
        world_readable_patterns = [
            r'MODE_WORLD_READABLE',
            r'MODE_WORLD_WRITEABLE',
            r'Context\.MODE_WORLD_READABLE',
            r'Context\.MODE_WORLD_WRITEABLE'
        ]
        
        for pattern in world_readable_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"prefs_world_mode_{hash(file_path + str(line_num))}",
                    title="World-Readable Shared Preferences",
                    description=f"Shared preferences created with {match.group()} mode",
                    severity=StorageVulnerabilitySeverity.CRITICAL,
                    storage_type=StorageType.SHARED_PREFERENCES,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use MODE_PRIVATE for shared preferences",
                    confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                        file_path, "world_readable_mode", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_sensitive_data_storage(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for sensitive data being stored in preferences."""
        vulnerabilities = []
        
        # Check for sensitive data patterns in put operations
        sensitive_put_patterns = [
            r'putString\s*\([^)]*(?:password|pwd|pass|secret|key|token|auth|credential)',
            r'putString\s*\([^)]*(?:email|username|user|login|account)',
            r'putString\s*\([^)]*(?:ssn|social|security|credit|card|bank)',
            r'putString\s*\([^)]*(?:api[_-]?key|private[_-]?key|session[_-]?token)'
        ]
        
        for pattern in sensitive_put_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"prefs_sensitive_put_{hash(file_path + str(line_num))}",
                    title="Sensitive Data Stored in Preferences",
                    description="Potentially sensitive data stored in shared preferences",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.SHARED_PREFERENCES,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use EncryptedSharedPreferences or avoid storing sensitive data",
                    confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                        file_path, "sensitive_data_storage", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_encryption_usage(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for proper encryption usage in preferences."""
        vulnerabilities = []
        
        # Check if preferences are used but encryption is not
        has_preferences = any(pattern in content for pattern in [
            'getSharedPreferences',
            'PreferenceManager.getDefaultSharedPreferences'
        ])
        
        has_encryption = any(pattern in content for pattern in [
            'EncryptedSharedPreferences',
            'MasterKeys.getOrCreate',
            'AES256_GCM',
            'AES256_SIV'
        ])
        
        if has_preferences and not has_encryption:
            vulnerability = StorageVulnerability(
                id=f"prefs_no_encryption_{hash(file_path)}",
                title="Unencrypted Shared Preferences Usage",
                description="Shared preferences used without encryption",
                severity=StorageVulnerabilitySeverity.MEDIUM,
                storage_type=StorageType.SHARED_PREFERENCES,
                masvs_control="MSTG-STORAGE-1",
                affected_files=[file_path],
                evidence="Preferences usage without encryption",
                remediation="Use EncryptedSharedPreferences for sensitive data",
                confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                    file_path, "no_encryption", {"has_preferences": has_preferences, "has_encryption": has_encryption}
                )
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_preferences_backup_issues(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for preferences backup security issues."""
        vulnerabilities = []
        
        # Check for backup allowance without encryption
        backup_patterns = [
            r'allowBackup\s*=\s*["\']true["\']',
            r'backup.*preferences',
            r'preferences.*backup.*external'
        ]
        
        for pattern in backup_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"prefs_backup_{hash(file_path + str(line_num))}",
                    title="Preferences Backup Security Risk",
                    description="Shared preferences may be included in app backups",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.SHARED_PREFERENCES,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Disable backup for sensitive preferences or use encryption",
                    confidence=self.confidence_calculator.calculate_shared_preferences_confidence(
                        file_path, "backup_risk", {"line_number": line_num, "pattern": match.group()}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _file_uses_encrypted_prefs(self, code_text: str) -> tuple[bool, str]:
        """**FIX**: Detect encryption from code patterns, not XML content."""
        if not code_text:
            return False, "no_code"
        
        # Check for modern encryption patterns
        for pattern in self._enc_code_patterns:
            if pattern.search(code_text):
                pattern_text = pattern.pattern
                if "MasterKeys.getOrCreate" in pattern_text:
                    return True, "deprecated_masterkeys"
                elif "EncryptedSharedPreferences" in pattern_text:
                    return True, "encrypted_shared_prefs"
                elif "MasterKey" in pattern_text:
                    return True, "modern_masterkey"
                else:
                    return True, "androidx_crypto"
        
        return False, "unencrypted"
    
    def _check_preferences_encryption(self, prefs_file: str, apk_ctx) -> Dict[str, Any]:
        """**FIX**: XML files cannot indicate encryption - analyze source code instead."""
        # XML preferences files themselves don't contain encryption information
        # Encryption detection must come from source code analysis
        return {'encrypted': False, 'method': 'xml_requires_source_analysis'}
    
    def _initialize_preferences_patterns(self) -> Dict[str, List[str]]:
        """Initialize shared preferences patterns."""
        return {
            'basic_preferences': [
                'getSharedPreferences',
                'PreferenceManager.getDefaultSharedPreferences',
                'SharedPreferences.Editor',
                'putString',
                'putInt',
                'putBoolean',
                'putFloat',
                'putLong',
                'commit()',
                'apply()'
            ],
            'encrypted_preferences': [
                'EncryptedSharedPreferences',
                'MasterKeys.getOrCreate',
                'AES256_GCM',
                'AES256_SIV'
            ]
        }
    
    def _initialize_encryption_patterns(self) -> Dict[str, List[str]]:
        """Initialize encryption patterns."""
        return {
            'encryption_indicators': [
                'EncryptedSharedPreferences',
                'MasterKeys',
                'AES256_GCM',
                'AES256_SIV',
                'androidx.security.crypto'
            ],
            'weak_encryption': [
                'DES',
                'MD5',
                'SHA1'
            ]
        }
    
    def _initialize_sensitive_data_patterns(self) -> Dict[str, List[str]]:
        """Initialize sensitive data patterns."""
        return {
            'credentials': [
                r'(?i)password.*["\'][^"\']{8,}["\']',
                r'(?i)pwd.*["\'][^"\']{4,}["\']',
                r'(?i)pass.*["\'][^"\']{4,}["\']',
                r'(?i)secret.*["\'][^"\']{8,}["\']',
                r'(?i)key.*["\'][^"\']{16,}["\']',
                r'(?i)token.*["\'][^"\']{20,}["\']',
                r'(?i)auth.*["\'][^"\']{16,}["\']'
            ],
            'personal_info': [
                r'(?i)email.*["\'][^"\']*@[^"\']*["\']',
                r'(?i)username.*["\'][^"\']{3,}["\']',
                r'(?i)user.*["\'][^"\']{3,}["\']',
                r'(?i)login.*["\'][^"\']{3,}["\']',
                r'(?i)account.*["\'][^"\']{3,}["\']'
            ],
            'financial_info': [
                r'(?i)ssn.*["\'][0-9-]{9,}["\']',
                r'(?i)social.*["\'][0-9-]{9,}["\']',
                r'(?i)credit.*["\'][0-9-]{13,}["\']',
                r'(?i)card.*["\'][0-9-]{13,}["\']',
                r'(?i)bank.*["\'][0-9-]{8,}["\']'
            ],
            'api_keys': [
                r'(?i)api[_-]?key.*["\'][^"\']{20,}["\']',
                r'(?i)private[_-]?key.*["\'][^"\']{32,}["\']',
                r'(?i)session[_-]?token.*["\'][^"\']{20,}["\']',
                r'(?i)access[_-]?token.*["\'][^"\']{20,}["\']'
            ]
        } 