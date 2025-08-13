"""
Storage Security Analyzer

This module provides comprehensive storage security analysis capabilities for Android applications,
specializing in identifying encryption vulnerabilities, key management issues, and storage
security assessment.

Features:
- Encryption implementation analysis
- Key management security assessment
- Storage security level evaluation
- Backup security analysis
- Shared storage security evaluation
- Data leakage risk assessment
"""

import logging
import re
import json
import base64
import hashlib
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
from dataclasses import dataclass

from .data_structures import (
    StorageSecurityFinding, StorageSecurityLevel, VulnerabilitySeverity,
    ConfidenceEvidence, EnhancedDataStorageAnalysisConfig
)

logger = logging.getLogger(__name__)

class StorageSecurityAnalyzer:
    """
    Comprehensive storage security analyzer specializing in Android storage encryption
    and security analysis with advanced pattern matching.
    """
    
    def __init__(self, config: EnhancedDataStorageAnalysisConfig):
        """Initialize the storage security analyzer with configuration."""
        self.config = config
        
        # Initialize storage security patterns
        self.storage_security_patterns = self._initialize_storage_security_patterns()
        self.encryption_patterns = self._initialize_encryption_patterns()
        self.key_management_patterns = self._initialize_key_management_patterns()
        
        # Storage security weights
        self.security_weights = self._initialize_security_weights()
        
        # Analysis statistics
        self.analysis_stats = {
            "files_analyzed": 0,
            "security_issues_found": 0,
            "encryption_issues": 0,
            "unencrypted_storage": 0
        }
    
    def _initialize_storage_security_patterns(self) -> Dict[str, List[str]]:
        """Initialize comprehensive storage security patterns."""
        return {
            "unencrypted_storage": [
                r'SharedPreferences.*putString\([^,]+,\s*[^)]+\)',
                r'getSharedPreferences\([^)]+\)\.edit\(\)',
                r'FileOutputStream.*write\(',
                r'openFileOutput\([^,]+,\s*MODE_PRIVATE\)',
                r'SQLiteDatabase.*execSQL\(',
                r'ContentValues.*put\(',
                r'getWritableDatabase\(\)',
                r'getReadableDatabase\(\)',
                r'editor\.putString\(',
                r'editor\.putInt\(',
                r'editor\.putBoolean\(',
                r'editor\.putFloat\(',
                r'editor\.putLong\('
            ],
            "weak_encryption": [
                r'DES\.',
                r'new\s+DES',
                r'Algorithm\s*=\s*["\']DES["\']',
                r'cipher\.getInstance\(["\']DES',
                r'MD5\.',
                r'MessageDigest\.getInstance\(["\']MD5["\']',
                r'Base64\.encode\(',
                r'Base64\.decode\(',
                r'ROT13',
                r'Caesar',
                r'XOR.*encrypt'
            ],
            "key_hardcoding": [
                r'key\s*=\s*["\'][^"\']{8,}["\']',
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'secret\s*=\s*["\'][^"\']{8,}["\']',
                r'private.*key\s*=\s*["\'][^"\']{20,}["\']',
                r'AES.*key\s*=\s*["\'][^"\']{16,}["\']',
                r'encryption.*key\s*=\s*["\'][^"\']{16,}["\']',
                r'String.*KEY\s*=\s*["\'][^"\']{8,}["\']',
                r'final.*KEY\s*=\s*["\'][^"\']{8,}["\']'
            ],
            "insecure_key_storage": [
                r'KeyStore\.getInstance\(["\']AndroidKeyStore["\']',
                r'keyStore\.load\(null\)',
                r'keyStore\.setKeyEntry\(',
                r'getSystemService\(Context\.KEYGUARD_SERVICE\)',
                r'SharedPreferences.*put.*[kK]ey',
                r'preferences.*put.*[kK]ey',
                r'sqlite.*insert.*key',
                r'ContentValues.*put.*key'
            ],
            "backup_vulnerabilities": [
                r'android:allowBackup\s*=\s*["\']true["\']',
                r'allowBackup\s*=\s*true',
                r'backup.*Agent',
                r'onBackup\(',
                r'onRestore\(',
                r'BackupManager',
                r'BackupAgent',
                r'dataExtractionRules'
            ],
            "external_storage_usage": [
                r'getExternalStorageDirectory\(\)',
                r'getExternalFilesDir\(',
                r'getExternalCacheDir\(',
                r'Environment\.getExternalStorageDirectory\(',
                r'WRITE_EXTERNAL_STORAGE',
                r'READ_EXTERNAL_STORAGE',
                r'isExternalStorageWritable\(',
                r'isExternalStorageReadable\('
            ],
            "logging_sensitive_data": [
                r'Log\.[dviwe]\([^,]+,.*password',
                r'Log\.[dviwe]\([^,]+,.*key',
                r'Log\.[dviwe]\([^,]+,.*secret',
                r'Log\.[dviwe]\([^,]+,.*token',
                r'Log\.[dviwe]\([^,]+,.*credential',
                r'System\.out\.println.*password',
                r'System\.out\.println.*key',
                r'System\.out\.println.*secret',
                r'printStackTrace\(\)'
            ]
        }
    
    def _initialize_encryption_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize encryption implementation analysis patterns."""
        return {
            "strong_encryption": {
                "patterns": [
                    r'AES',
                    r'cipher\.getInstance\(["\']AES',
                    r'Algorithm\s*=\s*["\']AES["\']',
                    r'RSA',
                    r'cipher\.getInstance\(["\']RSA',
                    r'Algorithm\s*=\s*["\']RSA["\']',
                    r'SHA-256',
                    r'SHA-512',
                    r'MessageDigest\.getInstance\(["\']SHA-256["\']',
                    r'MessageDigest\.getInstance\(["\']SHA-512["\']'
                ],
                "level": StorageSecurityLevel.ENCRYPTED,
                "description": "Strong encryption implementation detected"
            },
            "weak_encryption": {
                "patterns": [
                    r'DES',
                    r'cipher\.getInstance\(["\']DES',
                    r'Algorithm\s*=\s*["\']DES["\']',
                    r'MD5',
                    r'MessageDigest\.getInstance\(["\']MD5["\']',
                    r'SHA-1',
                    r'MessageDigest\.getInstance\(["\']SHA-1["\']',
                    r'Base64'
                ],
                "level": StorageSecurityLevel.VULNERABLE,
                "description": "Weak encryption implementation detected"
            },
            "no_encryption": {
                "patterns": [
                    r'plaintext',
                    r'unencrypted',
                    r'no.*encryption',
                    r'SharedPreferences.*putString.*password',
                    r'SharedPreferences.*putString.*key',
                    r'SharedPreferences.*putString.*secret'
                ],
                "level": StorageSecurityLevel.EXPOSED,
                "description": "No encryption detected for sensitive data"
            }
        }
    
    def _initialize_key_management_patterns(self) -> Dict[str, List[str]]:
        """Initialize key management analysis patterns."""
        return {
            "secure_key_generation": [
                r'KeyGenerator\.getInstance\(["\']AES["\']',
                r'KeyPairGenerator\.getInstance\(["\']RSA["\']',
                r'SecureRandom\(\)',
                r'KeyGenParameterSpec\.Builder\(',
                r'keyGenerator\.generateKey\(\)',
                r'keyPairGenerator\.generateKeyPair\(\)'
            ],
            "key_derivation": [
                r'PBKDF2WithHmacSHA256',
                r'PBEKeySpec\(',
                r'SecretKeyFactory\.getInstance\(',
                r'generateSecret\(',
                r'deriveKey\(',
                r'KeyDerivationFunction'
            ],
            "android_keystore": [
                r'AndroidKeyStore',
                r'KeyStore\.getInstance\(["\']AndroidKeyStore["\']',
                r'keyStore\.load\(null\)',
                r'KeyGenParameterSpec\.Builder\(',
                r'setEncryptionRequired\(true\)',
                r'setUserAuthenticationRequired\(true\)'
            ],
            "insecure_key_handling": [
                r'String.*key\s*=\s*["\']',
                r'char\[\].*key\s*=',
                r'byte\[\].*key\s*=',
                r'key\.getBytes\(\)',
                r'key\.toCharArray\(\)',
                r'hardcoded.*key'
            ]
        }
    
    def _initialize_security_weights(self) -> Dict[str, float]:
        """Initialize storage security weight factors."""
        return {
            "unencrypted_storage": 0.8,
            "weak_encryption": 0.7,
            "key_hardcoding": 0.9,
            "insecure_key_storage": 0.8,
            "backup_vulnerabilities": 0.6,
            "external_storage_usage": 0.7,
            "logging_sensitive_data": 0.8
        }
    
    def analyze_storage_security(self, apk_ctx) -> List[StorageSecurityFinding]:
        """
        Analyze storage security in the Android application.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            List of storage security findings
        """
        findings = []
        
        try:
            # Get analysis targets
            targets = self._get_analysis_targets(apk_ctx)
            
            # Analyze each target for storage security issues
            for target in targets:
                target_findings = self._analyze_target_for_storage_security(target)
                findings.extend(target_findings)
                
                self.analysis_stats["files_analyzed"] += 1
                
                # Respect analysis limits
                if len(findings) >= self.config.max_files_to_analyze:
                    logger.warning(f"Reached maximum files limit: {self.config.max_files_to_analyze}")
                    break
            
            # Filter and deduplicate findings
            findings = self._filter_and_deduplicate_findings(findings)
            
            # Update statistics
            self.analysis_stats["security_issues_found"] = len(findings)
            self.analysis_stats["encryption_issues"] = len([f for f in findings if f.security_level == StorageSecurityLevel.VULNERABLE])
            self.analysis_stats["unencrypted_storage"] = len([f for f in findings if f.security_level == StorageSecurityLevel.EXPOSED])
            
            return findings
            
        except Exception as e:
            logger.error(f"Error during storage security analysis: {str(e)}")
            return []
    
    def _get_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Get files and directories to analyze for storage security."""
        targets = []
        
        try:
            # Analyze source code files
            if hasattr(apk_ctx, 'java_files'):
                for java_file in apk_ctx.java_files:
                    targets.append({
                        "type": "java_source",
                        "path": java_file.get('path', ''),
                        "content": java_file.get('content', ''),
                        "size": len(java_file.get('content', '')),
                        "filename": os.path.basename(java_file.get('path', ''))
                    })
            
            # Analyze XML files (for manifest analysis)
            if hasattr(apk_ctx, 'xml_files'):
                for xml_file in apk_ctx.xml_files:
                    targets.append({
                        "type": "xml_file",
                        "path": xml_file.get('path', ''),
                        "content": xml_file.get('content', ''),
                        "size": len(xml_file.get('content', '')),
                        "filename": os.path.basename(xml_file.get('path', ''))
                    })
            
            # Analyze configuration files
            if hasattr(apk_ctx, 'config_files'):
                for config_file in apk_ctx.config_files:
                    targets.append({
                        "type": "config_file",
                        "path": config_file.get('path', ''),
                        "content": config_file.get('content', ''),
                        "size": len(config_file.get('content', '')),
                        "filename": os.path.basename(config_file.get('path', ''))
                    })
            
            # Analyze database files
            if hasattr(apk_ctx, 'database_files'):
                for db_file in apk_ctx.database_files:
                    targets.append({
                        "type": "database_file",
                        "path": db_file.get('path', ''),
                        "content": db_file.get('content', ''),
                        "size": len(db_file.get('content', '')),
                        "filename": os.path.basename(db_file.get('path', ''))
                    })
            
            return targets
            
        except Exception as e:
            logger.error(f"Error getting storage security analysis targets: {str(e)}")
            return []
    
    def _analyze_target_for_storage_security(self, target: Dict[str, Any]) -> List[StorageSecurityFinding]:
        """Analyze a target for storage security issues."""
        findings = []
        
        try:
            content = target.get('content', '')
            file_path = target.get('path', '')
            
            # Analyze each storage security pattern type
            for security_type, patterns in self.storage_security_patterns.items():
                type_findings = self._detect_storage_security_type(
                    security_type, patterns, content, file_path, target
                )
                findings.extend(type_findings)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error analyzing target for storage security: {str(e)}")
            return []
    
    def _detect_storage_security_type(self, security_type: str, patterns: List[str], 
                                     content: str, file_path: str, target: Dict[str, Any]) -> List[StorageSecurityFinding]:
        """Detect specific storage security issue type."""
        findings = []
        
        try:
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Extract context and validate
                    context = self._extract_context(content, match.start(), match.end())
                    
                    # Create finding
                    finding = StorageSecurityFinding(
                        storage_type=self._determine_storage_type(file_path, context),
                        storage_path=file_path,
                        encryption_status=self._assess_encryption_status(security_type, match.group(0)),
                        access_control=self._assess_access_control(security_type, context),
                        security_level=self._assess_storage_security_level(security_type, match.group(0)),
                        encryption_algorithm=self._detect_encryption_algorithm(context),
                        key_management=self._assess_key_management(context),
                        security_issues=[self._get_security_issue_description(security_type)],
                        data_leakage_risks=[self._get_data_leakage_risk(security_type)],
                        location=f"Line {content[:match.start()].count(chr(10)) + 1}",
                        contains_sensitive_data=self._contains_sensitive_data(context),
                        is_backup_location=self._is_backup_location(file_path, context),
                        is_shared_storage=self._is_shared_storage(file_path, context),
                        security_recommendations=self._get_security_recommendations(security_type),
                        compliance_requirements=self._get_compliance_requirements(security_type)
                    )
                    
                    # Calculate confidence and severity
                    finding.confidence = self._calculate_storage_confidence(security_type, match.group(0), context)
                    finding.severity = self._assess_storage_severity(security_type)
                    
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error detecting storage security type {security_type}: {str(e)}")
            return []
    
    def _determine_storage_type(self, file_path: str, context: str) -> str:
        """Determine the type of storage based on file path and context."""
        if "SharedPreferences" in context:
            return "SharedPreferences"
        elif "SQLite" in context or ".db" in file_path:
            return "SQLite Database"
        elif "FileOutputStream" in context or "FileInputStream" in context:
            return "File Storage"
        elif "external" in file_path.lower() or "external" in context.lower():
            return "External Storage"
        elif "cache" in file_path.lower() or "cache" in context.lower():
            return "Cache Storage"
        else:
            return "Unknown Storage"
    
    def _assess_encryption_status(self, security_type: str, evidence: str) -> str:
        """Assess encryption status based on security type and evidence."""
        if security_type == "unencrypted_storage":
            return "Unencrypted"
        elif security_type == "weak_encryption":
            return "Weak Encryption"
        elif "AES" in evidence:
            return "AES Encrypted"
        elif "RSA" in evidence:
            return "RSA Encrypted"
        else:
            return "Unknown"
    
    def _assess_access_control(self, security_type: str, context: str) -> str:
        """Assess access control based on security type and context."""
        if "MODE_PRIVATE" in context:
            return "Private"
        elif "MODE_WORLD_READABLE" in context:
            return "World Readable"
        elif "MODE_WORLD_WRITEABLE" in context:
            return "World Writable"
        elif "external" in context.lower():
            return "External Access"
        else:
            return "Unknown"
    
    def _assess_storage_security_level(self, security_type: str, evidence: str) -> StorageSecurityLevel:
        """Assess storage security level based on security type and evidence."""
        if security_type in ["unencrypted_storage", "logging_sensitive_data"]:
            return StorageSecurityLevel.EXPOSED
        elif security_type in ["weak_encryption", "backup_vulnerabilities", "external_storage_usage"]:
            return StorageSecurityLevel.VULNERABLE
        elif security_type in ["key_hardcoding", "insecure_key_storage"]:
            return StorageSecurityLevel.VULNERABLE
        else:
            return StorageSecurityLevel.PROTECTED
    
    def _detect_encryption_algorithm(self, context: str) -> Optional[str]:
        """Detect encryption algorithm from context."""
        if "AES" in context:
            return "AES"
        elif "RSA" in context:
            return "RSA"
        elif "DES" in context:
            return "DES"
        else:
            return None
    
    def _assess_key_management(self, context: str) -> Optional[str]:
        """Assess key management approach from context."""
        if "AndroidKeyStore" in context:
            return "Android KeyStore"
        elif "KeyGenerator" in context:
            return "Key Generator"
        elif "hardcoded" in context.lower() or "String" in context and "key" in context:
            return "Hardcoded Key"
        else:
            return "Unknown"
    
    def _contains_sensitive_data(self, context: str) -> bool:
        """Check if context contains sensitive data indicators."""
        sensitive_keywords = ["password", "key", "secret", "token", "credential", "private", "confidential"]
        return any(keyword in context.lower() for keyword in sensitive_keywords)
    
    def _is_backup_location(self, file_path: str, context: str) -> bool:
        """Check if location is related to backup functionality."""
        backup_indicators = ["backup", "BackupAgent", "onBackup", "onRestore"]
        return any(indicator in file_path or indicator in context for indicator in backup_indicators)
    
    def _is_shared_storage(self, file_path: str, context: str) -> bool:
        """Check if location is shared storage."""
        shared_indicators = ["external", "shared", "public", "world"]
        return any(indicator in file_path.lower() or indicator in context.lower() for indicator in shared_indicators)
    
    def _assess_storage_severity(self, security_type: str) -> VulnerabilitySeverity:
        """Assess severity based on storage security issue type."""
        severity_map = {
            "unencrypted_storage": VulnerabilitySeverity.HIGH,
            "weak_encryption": VulnerabilitySeverity.MEDIUM,
            "key_hardcoding": VulnerabilitySeverity.CRITICAL,
            "insecure_key_storage": VulnerabilitySeverity.HIGH,
            "backup_vulnerabilities": VulnerabilitySeverity.MEDIUM,
            "external_storage_usage": VulnerabilitySeverity.MEDIUM,
            "logging_sensitive_data": VulnerabilitySeverity.HIGH
        }
        return severity_map.get(security_type, VulnerabilitySeverity.MEDIUM)
    
    def _calculate_storage_confidence(self, security_type: str, evidence: str, context: str) -> float:
        """Calculate confidence score for storage security finding."""
        try:
            base_confidence = self.security_weights.get(security_type, 0.5)
            
            # Adjust based on evidence quality
            evidence_boost = 0.0
            if security_type == "key_hardcoding" and len(evidence) > 20:
                evidence_boost = 0.2
            elif security_type == "weak_encryption" and ("DES" in evidence or "MD5" in evidence):
                evidence_boost = 0.3
            elif security_type == "unencrypted_storage" and "SharedPreferences" in context:
                evidence_boost = 0.2
            
            # Adjust based on context
            context_boost = 0.0
            if "sensitive" in context.lower() or "private" in context.lower():
                context_boost = 0.1
            elif "password" in context.lower() or "key" in context.lower():
                context_boost = 0.15
            
            final_confidence = min(1.0, base_confidence + evidence_boost + context_boost)
            return final_confidence
            
        except Exception as e:
            logger.error(f"Error calculating storage confidence: {str(e)}")
            return 0.5
    
    def _get_security_issue_description(self, security_type: str) -> str:
        """Get description of security issue."""
        descriptions = {
            "unencrypted_storage": "Sensitive data stored without encryption",
            "weak_encryption": "Weak encryption algorithms used for data protection",
            "key_hardcoding": "Cryptographic keys hardcoded in source code",
            "insecure_key_storage": "Cryptographic keys stored insecurely",
            "backup_vulnerabilities": "Data backup mechanisms may expose sensitive information",
            "external_storage_usage": "Sensitive data stored on external storage",
            "logging_sensitive_data": "Sensitive data logged to system logs"
        }
        return descriptions.get(security_type, "Unknown storage security issue")
    
    def _get_data_leakage_risk(self, security_type: str) -> str:
        """Get data leakage risk description."""
        risks = {
            "unencrypted_storage": "Plaintext data accessible to malicious apps",
            "weak_encryption": "Encrypted data easily decryptable by attackers",
            "key_hardcoding": "Hardcoded keys can be extracted from APK",
            "insecure_key_storage": "Keys accessible to unauthorized applications",
            "backup_vulnerabilities": "Backup data exposed during backup/restore",
            "external_storage_usage": "Data accessible to all applications",
            "logging_sensitive_data": "Sensitive data visible in system logs"
        }
        return risks.get(security_type, "Unknown data leakage risk")
    
    def _get_security_recommendations(self, security_type: str) -> List[str]:
        """Get security recommendations for storage security type."""
        recommendations = {
            "unencrypted_storage": [
                "Implement encryption for sensitive data storage",
                "Use Android KeyStore for key management",
                "Consider using EncryptedSharedPreferences"
            ],
            "weak_encryption": [
                "Replace weak algorithms with AES-256",
                "Use cryptographically secure random number generation",
                "Implement proper key derivation functions"
            ],
            "key_hardcoding": [
                "Remove hardcoded keys from source code",
                "Use Android KeyStore for key generation",
                "Implement proper key derivation from user input"
            ],
            "insecure_key_storage": [
                "Use Android KeyStore for secure key storage",
                "Implement proper key lifecycle management",
                "Use hardware-backed key storage when available"
            ],
            "backup_vulnerabilities": [
                "Disable backup for sensitive data",
                "Implement custom backup exclusion rules",
                "Encrypt backup data if backup is necessary"
            ],
            "external_storage_usage": [
                "Move sensitive data to internal storage",
                "Implement proper access controls",
                "Encrypt data before storing on external storage"
            ],
            "logging_sensitive_data": [
                "Remove sensitive data from log statements",
                "Implement secure logging practices",
                "Use production-safe logging configurations"
            ]
        }
        return recommendations.get(security_type, [])
    
    def _get_compliance_requirements(self, security_type: str) -> List[str]:
        """Get compliance requirements for storage security type."""
        requirements = {
            "unencrypted_storage": ["MASVS-STORAGE-1", "MSTG-STORAGE-1"],
            "weak_encryption": ["MASVS-CRYPTO-1", "MSTG-CRYPTO-1"],
            "key_hardcoding": ["MASVS-CRYPTO-1", "MSTG-CRYPTO-1"],
            "insecure_key_storage": ["MASVS-CRYPTO-1", "MSTG-CRYPTO-1"],
            "backup_vulnerabilities": ["MASVS-STORAGE-1", "MSTG-STORAGE-1"],
            "external_storage_usage": ["MASVS-STORAGE-2", "MSTG-STORAGE-2"],
            "logging_sensitive_data": ["MASVS-STORAGE-2", "MSTG-STORAGE-2"]
        }
        return requirements.get(security_type, [])
    
    def _extract_context(self, content: str, start: int, end: int, context_size: int = 100) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end].strip()
        except Exception:
            return ""
    
    def _filter_and_deduplicate_findings(self, findings: List[StorageSecurityFinding]) -> List[StorageSecurityFinding]:
        """Filter and deduplicate storage security findings using unified deduplication framework."""
        if not findings:
            return []
        
        try:
            # Import unified deduplication framework
            from core.unified_deduplication_framework import (
                deduplicate_findings,
                DeduplicationStrategy
            )
            
            # Convert findings to dictionaries for unified deduplication
            dict_findings = []
            for finding in findings:
                dict_finding = {
                    'title': f"Storage Security Issue: {finding.security_issues[0] if finding.security_issues else 'Unknown'}",
                    'file_path': finding.storage_path,
                    'severity': finding.severity.value if hasattr(finding, 'severity') else 'MEDIUM',
                    'category': 'storage_security',
                    'description': f"Security issue in storage path: {finding.storage_path}",
                    'finding_id': id(finding)
                }
                dict_findings.append(dict_finding)
            
            # Use unified deduplication framework with PRESERVATION strategy to maintain storage-specific logic
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.PRESERVATION)
            
            # Map deduplicated results back to original findings
            unique_finding_ids = {f['finding_id'] for f in result.unique_findings}
            filtered_findings = [f for f in findings if id(f) in unique_finding_ids]
            
            # Log deduplication results for transparency
            if len(findings) != len(filtered_findings):
                removed_count = len(findings) - len(filtered_findings)
                logging.getLogger(__name__).info(f"Unified deduplication: {len(findings)} -> {len(filtered_findings)} "
                                                f"({removed_count} duplicates removed)")
            
            return filtered_findings
            
        except Exception as e:
            # Fallback to original simple deduplication
            logging.getLogger(__name__).warning(f"Unified deduplication failed, using fallback: {e}")
            return self._filter_and_deduplicate_findings_fallback(findings)
    
    def _filter_and_deduplicate_findings_fallback(self, findings: List[StorageSecurityFinding]) -> List[StorageSecurityFinding]:
        """Fallback deduplication method (original logic)."""
        # Remove duplicates based on storage path and security issue
        seen = set()
        filtered_findings = []
        
        for finding in findings:
            key = (finding.storage_path, finding.security_issues[0] if finding.security_issues else "")
            if key not in seen:
                seen.add(key)
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get storage security analysis statistics."""
        return {
            "analyzer_type": "storage_security",
            "statistics": self.analysis_stats.copy(),
            "pattern_counts": {
                pattern_type: len(patterns)
                for pattern_type, patterns in self.storage_security_patterns.items()
            },
            "analysis_coverage": {
                "total_patterns": sum(len(patterns) for patterns in self.storage_security_patterns.values()),
                "pattern_types": len(self.storage_security_patterns),
                "security_levels": len(StorageSecurityLevel),
                "severity_levels": len(VulnerabilitySeverity)
            }
        } 