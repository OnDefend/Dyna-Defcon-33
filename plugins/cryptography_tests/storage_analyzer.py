#!/usr/bin/env python3
"""
Cryptographic Storage Security Analyzer

This module provides comprehensive analysis of cryptographic storage security
in Android applications, including encrypted data storage, database encryption,
secure deletion mechanisms, and storage integrity protection.

Key Features:
- Encrypted storage implementation analysis
- Database encryption assessment
- Secure deletion mechanism evaluation
- Storage integrity protection analysis
- Cold storage security assessment
- Data-at-rest encryption evaluation
- File system encryption analysis
- Key derivation for storage analysis
"""

import logging
import re
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import base64
import hashlib

from .data_structures import (
    CryptographicVulnerability,
    CryptographicStorageAnalysis,
    CryptographicAlgorithmType,
    ComplianceStandard
)
from core.shared_data_structures.base_vulnerability import VulnerabilitySeverity
from .confidence_calculator import CryptoConfidenceCalculator

logger = logging.getLogger(__name__)

@dataclass
class StorageEncryptionMethod:
    """Details about storage encryption methods."""
    storage_type: str
    encryption_algorithm: str
    key_derivation: str
    location: str
    is_secure: bool
    integrity_protection: bool = False
    authentication_required: bool = False
    security_level: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

@dataclass
class DatabaseEncryptionConfig:
    """Database encryption configuration details."""
    database_type: str
    encryption_method: str
    key_management: str
    location: str
    is_encrypted: bool
    supports_transparent_encryption: bool = False
    column_level_encryption: bool = False
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

class StorageAnalyzer:
    """
    Comprehensive cryptographic storage security analyzer.
    
    Analyzes storage encryption implementations, database security,
    and data-at-rest protection mechanisms to identify vulnerabilities
    and compliance issues.
    """
    
    def __init__(self, apk_ctx):
        """Initialize the storage analyzer."""
        self.apk_ctx = apk_ctx
        self.confidence_calculator = CryptoConfidenceCalculator()
        
        # Storage security patterns
        self.storage_patterns = self._initialize_storage_patterns()
        
        # Secure storage methods
        self.secure_storage_methods = {
            "EncryptedSharedPreferences": "Encrypted shared preferences",
            "EncryptedFile": "Encrypted file storage",
            "AndroidKeyStore": "Android Keystore storage",
            "SQLCipher": "SQLCipher encrypted database",
            "Room_encrypt": "Room database with encryption",
            "Realm_encrypt": "Realm database with encryption",
            "ConcealSharedPreferences": "Facebook Conceal encryption",
            "AES_GCM": "AES-GCM encryption",
            "ChaCha20_Poly1305": "ChaCha20-Poly1305 encryption"
        }
        
        # Insecure storage methods
        self.insecure_storage_methods = {
            "SharedPreferences": "Unencrypted shared preferences",
            "FileOutputStream": "Unencrypted file output",
            "ExternalStorage": "External storage (insecure)",
            "PublicDirectory": "Public directory storage",
            "SystemProperties": "System properties (visible)",
            "Logs": "Application logs (visible)",
            "Cache": "Cache storage (temporary)",
            "TempFile": "Temporary files"
        }
        
        # Database encryption support
        self.database_encryption_support = {
            "SQLite": {
                "native_encryption": False,
                "extensions": ["SQLCipher", "SEE"],
                "recommended": "SQLCipher"
            },
            "Room": {
                "native_encryption": False,
                "extensions": ["SQLCipher integration"],
                "recommended": "Room with SQLCipher"
            },
            "Realm": {
                "native_encryption": True,
                "extensions": [],
                "recommended": "Realm encryption"
            },
            "ObjectBox": {
                "native_encryption": True,
                "extensions": [],
                "recommended": "ObjectBox encryption"
            }
        }
        
        logger.info("Initialized StorageAnalyzer")
    
    def _initialize_storage_patterns(self) -> Dict[str, List[str]]:
        """Initialize storage security detection patterns."""
        return {
            "encrypted_storage": [
                r"EncryptedSharedPreferences\.create",
                r"EncryptedFile\.Builder",
                r"MasterKey\.Builder",
                r"AES256_GCM_HKDF_4KB",
                r"EncryptionScheme\.AES256_GCM_HKDF_4KB",
                r"KeysetHandle\.generateNew",
                r"ConcealSharedPreferences",
                r"Conceal\.createDefaultCrypto",
                r"SqlCipher\.encrypt",
                r"openOrCreateDatabase.*password"
            ],
            "database_encryption": [
                r"SQLCipherUtils\.encrypt",
                r"net\.sqlcipher\.database",
                r"Room\.databaseBuilder.*encryption",
                r"RealmConfiguration\.Builder.*encryptionKey",
                r"Realm\.setDefaultConfiguration.*encryptionKey",
                r"ObjectBoxBuilder.*encryption",
                r"openOrCreateDatabase\([^)]*password",
                r"SQLiteDatabase\.openDatabase.*password",
                r"Room\.encryptedDatabaseBuilder"
            ],
            "insecure_storage": [
                r"SharedPreferences\.Editor\.putString",
                r"FileOutputStream\([^)]*\)",
                r"getExternalFilesDir",
                r"getExternalStorageDirectory",
                r"openFileOutput\(.*MODE_WORLD_READABLE",
                r"openFileOutput\(.*MODE_WORLD_WRITEABLE",
                r"System\.setProperty",
                r"Log\.[dviwe]\(",
                r"getCacheDir",
                r"File\.createTempFile"
            ],
            "storage_integrity": [
                r"MessageDigest\.getInstance.*SHA",
                r"Mac\.getInstance.*HMAC",
                r"Signature\.getInstance",
                r"checksum",
                r"hash.*verify",
                r"integrity.*check",
                r"CRC32",
                r"Adler32"
            ],
            "secure_deletion": [
                r"SecureRandom.*nextBytes",
                r"Arrays\.fill.*\\(byte\\)\\s*0",
                r"zero.*buffer",
                r"clear.*memory",
                r"wipe.*data",
                r"secure.*delete",
                r"overwrite.*file"
            ],
            "key_derivation_storage": [
                r"PBKDF2WithHmacSHA",
                r"scrypt",
                r"bcrypt",
                r"Argon2",
                r"deriveKey.*storage",
                r"generateKey.*storage",
                r"password.*derive",
                r"salt.*generation"
            ]
        }
    
    def analyze_storage_security(self, file_contents: Dict[str, str]) -> CryptographicStorageAnalysis:
        """
        Perform comprehensive cryptographic storage analysis.
        
        Args:
            file_contents: Dictionary of file paths to their contents
            
        Returns:
            Cryptographic storage analysis results
        """
        analysis = CryptographicStorageAnalysis()
        
        try:
            # Analyze each file for storage patterns
            for file_path, content in file_contents.items():
                if self._is_relevant_file(file_path):
                    self._analyze_file_storage(file_path, content, analysis)
            
            # Analyze encrypted storage implementations
            self._analyze_encrypted_storage_implementations(file_contents, analysis)
            
            # Analyze database encryption
            self._analyze_database_encryption(file_contents, analysis)
            
            # Analyze storage integrity protection
            self._analyze_storage_integrity_protection(file_contents, analysis)
            
            # Analyze secure deletion mechanisms
            self._analyze_secure_deletion_mechanisms(file_contents, analysis)
            
            # Calculate overall storage security score
            analysis.overall_score = self._calculate_storage_score(analysis)
            
            # Generate recommendations
            analysis.recommendations = self._generate_storage_recommendations(analysis)
            
            # Set compliance status
            analysis.compliance_status = self._assess_compliance(analysis)
            
            logger.info(f"Storage analysis completed: {len(analysis.vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Error during storage analysis: {e}")
            analysis.vulnerabilities.append(
                self._create_analysis_error_vulnerability(str(e))
            )
        
        return analysis
    
    def _is_relevant_file(self, file_path: str) -> bool:
        """Check if file is relevant for storage analysis."""
        relevant_extensions = ['.java', '.kt', '.xml', '.json', '.properties', '.db']
        relevant_keywords = [
            'storage', 'database', 'file', 'encrypt', 'shared', 'preferences',
            'cache', 'temp', 'sqlite', 'room', 'realm', 'data', 'save'
        ]
        
        file_path_lower = file_path.lower()
        
        # Check extension
        if any(file_path_lower.endswith(ext) for ext in relevant_extensions):
            return True
        
        # Check for relevant keywords in path
        if any(keyword in file_path_lower for keyword in relevant_keywords):
            return True
        
        return False
    
    def _analyze_file_storage(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Analyze a single file for storage security patterns."""
        
        # Check for insecure storage practices
        self._check_insecure_storage_practices(file_path, content, analysis)
        
        # Check for encrypted storage implementations
        self._check_encrypted_storage_implementations(file_path, content, analysis)
        
        # Check for database encryption
        self._check_database_encryption_usage(file_path, content, analysis)
        
        # Check for storage integrity protection
        self._check_storage_integrity_protection(file_path, content, analysis)
        
        # Check for secure deletion mechanisms
        self._check_secure_deletion_mechanisms(file_path, content, analysis)
    
    def _check_insecure_storage_practices(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check for insecure storage practices."""
        patterns = self.storage_patterns["insecure_storage"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine storage type
                matched_text = match.group(0)
                storage_type = "Unknown"
                security_issue = "Insecure storage"
                
                if "SharedPreferences" in matched_text:
                    storage_type = "SharedPreferences"
                    security_issue = "Unencrypted shared preferences"
                elif "FileOutputStream" in matched_text:
                    storage_type = "FileOutput"
                    security_issue = "Unencrypted file output"
                elif "External" in matched_text:
                    storage_type = "ExternalStorage"
                    security_issue = "External storage access"
                elif "MODE_WORLD" in matched_text:
                    storage_type = "WorldAccessible"
                    security_issue = "World-accessible file"
                elif "System.setProperty" in matched_text:
                    storage_type = "SystemProperties"
                    security_issue = "System properties storage"
                elif "Log." in matched_text:
                    storage_type = "Logging"
                    security_issue = "Data in application logs"
                elif "Cache" in matched_text:
                    storage_type = "Cache"
                    security_issue = "Cache storage"
                elif "Temp" in matched_text:
                    storage_type = "TempFile"
                    security_issue = "Temporary file storage"
                
                # Check if sensitive data might be involved
                context = self._get_context_around_match(content, match, 5)
                if self._contains_sensitive_data_keywords(context):
                    severity = VulnerabilitySeverity.HIGH
                    if storage_type in ["ExternalStorage", "WorldAccessible"]:
                        severity = VulnerabilitySeverity.CRITICAL
                    
                    vulnerability = CryptographicVulnerability(
                        vulnerability_id=f"insecure_storage_{hashlib.md5((file_path + str(line_num)).encode()).hexdigest()[:8]}",
                        title=f"Insecure Data Storage: {storage_type}",
                        description=f"{security_issue} detected: {matched_text[:50]}...",
                        severity=severity,
                        location=f"{file_path}:{line_num}",
                        algorithm_name="Storage Security",
                        cryptographic_weakness=security_issue,
                        attack_vectors=[
                            "Local file access",
                            "Device compromise",
                            "Backup extraction",
                            "Forensic analysis"
                        ],
                        algorithm_recommendations=[
                            "Use EncryptedSharedPreferences",
                            "Use EncryptedFile for file storage",
                            "Implement database encryption",
                            "Use Android Keystore for key storage"
                        ]
                    )
                    
                    analysis.vulnerabilities.append(vulnerability)
    
    def _check_encrypted_storage_implementations(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check for encrypted storage implementations."""
        patterns = self.storage_patterns["encrypted_storage"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine encryption method
                matched_text = match.group(0)
                encryption_method = "Unknown"
                security_level = "MEDIUM"
                
                if "EncryptedSharedPreferences" in matched_text:
                    encryption_method = "EncryptedSharedPreferences"
                    security_level = "HIGH"
                elif "EncryptedFile" in matched_text:
                    encryption_method = "EncryptedFile"
                    security_level = "HIGH"
                elif "MasterKey" in matched_text:
                    encryption_method = "MasterKey"
                    security_level = "HIGH"
                elif "AES256_GCM" in matched_text:
                    encryption_method = "AES256_GCM"
                    security_level = "HIGH"
                elif "Conceal" in matched_text:
                    encryption_method = "FacebookConceal"
                    security_level = "MEDIUM"
                elif "SqlCipher" in matched_text:
                    encryption_method = "SQLCipher"
                    security_level = "HIGH"
                
                # Record encrypted storage implementation
                analysis.encrypted_storage_implementations.append({
                    "method": encryption_method,
                    "location": f"{file_path}:{line_num}",
                    "security_level": security_level,
                    "implementation_details": matched_text,
                    "is_secure": security_level in ["HIGH", "VERY_HIGH"]
                })
    
    def _check_database_encryption_usage(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check for database encryption usage."""
        patterns = self.storage_patterns["database_encryption"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine database type and encryption
                matched_text = match.group(0)
                database_type = "Unknown"
                encryption_type = "Unknown"
                
                if "SQLCipher" in matched_text:
                    database_type = "SQLite"
                    encryption_type = "SQLCipher"
                elif "Room" in matched_text and "encrypt" in matched_text:
                    database_type = "Room"
                    encryption_type = "Room_Encryption"
                elif "Realm" in matched_text and "encryptionKey" in matched_text:
                    database_type = "Realm"
                    encryption_type = "Realm_Encryption"
                elif "ObjectBox" in matched_text and "encryption" in matched_text:
                    database_type = "ObjectBox"
                    encryption_type = "ObjectBox_Encryption"
                elif "openDatabase" in matched_text and "password" in matched_text:
                    database_type = "SQLite"
                    encryption_type = "Password_Protected"
                
                # Record database encryption
                analysis.database_encryption.append({
                    "database_type": database_type,
                    "encryption_type": encryption_type,
                    "location": f"{file_path}:{line_num}",
                    "implementation": matched_text,
                    "is_secure": encryption_type in ["SQLCipher", "Realm_Encryption", "ObjectBox_Encryption"]
                })
    
    def _check_storage_integrity_protection(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check for storage integrity protection mechanisms."""
        patterns = self.storage_patterns["storage_integrity"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if it's used for storage integrity
                context = self._get_context_around_match(content, match, 10)
                if any(keyword in context.lower() for keyword in ['storage', 'file', 'database', 'integrity', 'verify']):
                    # Determine integrity method
                    matched_text = match.group(0)
                    integrity_method = "Unknown"
                    
                    if "SHA" in matched_text:
                        integrity_method = "SHA_Hash"
                    elif "HMAC" in matched_text:
                        integrity_method = "HMAC"
                    elif "Signature" in matched_text:
                        integrity_method = "Digital_Signature"
                    elif "CRC32" in matched_text:
                        integrity_method = "CRC32"
                    elif "checksum" in matched_text:
                        integrity_method = "Checksum"
                    
                    # Record integrity protection
                    analysis.storage_integrity_protection.append({
                        "method": integrity_method,
                        "location": f"{file_path}:{line_num}",
                        "implementation": matched_text,
                        "security_level": "HIGH" if integrity_method in ["HMAC", "Digital_Signature"] else "MEDIUM"
                    })
    
    def _check_secure_deletion_mechanisms(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check for secure deletion mechanisms."""
        patterns = self.storage_patterns["secure_deletion"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine deletion method
                matched_text = match.group(0)
                deletion_method = "Unknown"
                
                if "SecureRandom" in matched_text:
                    deletion_method = "Random_Overwrite"
                elif "Arrays.fill" in matched_text or "zero" in matched_text:
                    deletion_method = "Zero_Fill"
                elif "clear" in matched_text:
                    deletion_method = "Memory_Clear"
                elif "wipe" in matched_text:
                    deletion_method = "Data_Wipe"
                elif "overwrite" in matched_text:
                    deletion_method = "File_Overwrite"
                
                # Record secure deletion mechanism
                analysis.secure_deletion_mechanisms.append({
                    "method": deletion_method,
                    "location": f"{file_path}:{line_num}",
                    "implementation": matched_text,
                    "security_level": "HIGH" if deletion_method in ["Random_Overwrite", "File_Overwrite"] else "MEDIUM"
                })
    
    def _analyze_encrypted_storage_implementations(self, file_contents: Dict[str, str], analysis: CryptographicStorageAnalysis) -> None:
        """Comprehensive analysis of encrypted storage implementations."""
        for file_path, content in file_contents.items():
            # Check for specific encrypted storage configurations
            self._analyze_encrypted_shared_preferences(file_path, content, analysis)
            self._analyze_encrypted_file_usage(file_path, content, analysis)
            self._analyze_key_derivation_for_storage(file_path, content, analysis)
    
    def _analyze_encrypted_shared_preferences(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Analyze EncryptedSharedPreferences usage."""
        esp_pattern = r"EncryptedSharedPreferences\.create\([^)]+\)"
        matches = re.finditer(esp_pattern, content, re.IGNORECASE | re.DOTALL)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            
            # Extract configuration details
            config_text = match.group(0)
            
            # Check for proper configuration
            has_master_key = "MasterKey" in config_text
            has_proper_scheme = any(scheme in config_text for scheme in ["AES256_GCM_HKDF_4KB", "AES256_SIV_HMAC_SHA256"])
            
            if not has_master_key or not has_proper_scheme:
                vulnerability = CryptographicVulnerability(
                    vulnerability_id=f"esp_config_{hashlib.md5((file_path + str(line_num)).encode()).hexdigest()[:8]}",
                    title="Improper EncryptedSharedPreferences Configuration",
                    description="EncryptedSharedPreferences not properly configured",
                    severity=VulnerabilitySeverity.MEDIUM,
                    location=f"{file_path}:{line_num}",
                    algorithm_name="EncryptedSharedPreferences",
                    cryptographic_weakness="Improper configuration",
                    algorithm_recommendations=[
                        "Use MasterKey.Builder for key management",
                        "Use AES256_GCM_HKDF_4KB encryption scheme",
                        "Follow Android security best practices"
                    ]
                )
                analysis.vulnerabilities.append(vulnerability)
    
    def _analyze_encrypted_file_usage(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Analyze EncryptedFile usage."""
        ef_pattern = r"EncryptedFile\.Builder\([^)]+\)"
        matches = re.finditer(ef_pattern, content, re.IGNORECASE | re.DOTALL)
        
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            
            # Extract configuration details
            config_text = match.group(0)
            
            # Check for proper configuration
            has_master_key = "MasterKey" in config_text
            has_proper_scheme = "AES256_GCM_HKDF_4KB" in config_text
            
            if not has_master_key or not has_proper_scheme:
                vulnerability = CryptographicVulnerability(
                    vulnerability_id=f"ef_config_{hashlib.md5((file_path + str(line_num)).encode()).hexdigest()[:8]}",
                    title="Improper EncryptedFile Configuration",
                    description="EncryptedFile not properly configured",
                    severity=VulnerabilitySeverity.MEDIUM,
                    location=f"{file_path}:{line_num}",
                    algorithm_name="EncryptedFile",
                    cryptographic_weakness="Improper configuration",
                    algorithm_recommendations=[
                        "Use MasterKey.Builder for key management",
                        "Use AES256_GCM_HKDF_4KB encryption scheme"
                    ]
                )
                analysis.vulnerabilities.append(vulnerability)
    
    def _analyze_key_derivation_for_storage(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Analyze key derivation functions used for storage."""
        patterns = self.storage_patterns["key_derivation_storage"]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Determine KDF type
                matched_text = match.group(0)
                kdf_type = "Unknown"
                
                if "PBKDF2" in matched_text:
                    kdf_type = "PBKDF2"
                elif "scrypt" in matched_text:
                    kdf_type = "scrypt"
                elif "bcrypt" in matched_text:
                    kdf_type = "bcrypt"
                elif "Argon2" in matched_text:
                    kdf_type = "Argon2"
                
                # Record KDF usage for storage
                analysis.key_derivation_for_storage.append({
                    "kdf_type": kdf_type,
                    "location": f"{file_path}:{line_num}",
                    "implementation": matched_text,
                    "is_secure": kdf_type in ["scrypt", "bcrypt", "Argon2"],
                    "security_level": "HIGH" if kdf_type in ["scrypt", "Argon2"] else "MEDIUM"
                })
    
    def _analyze_database_encryption(self, file_contents: Dict[str, str], analysis: CryptographicStorageAnalysis) -> None:
        """Comprehensive database encryption analysis."""
        # Check for unencrypted database usage
        for file_path, content in file_contents.items():
            self._check_unencrypted_database_usage(file_path, content, analysis)
            self._check_database_encryption_implementation(file_path, content, analysis)
    
    def _check_unencrypted_database_usage(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check for unencrypted database usage."""
        unencrypted_patterns = [
            r"SQLiteOpenHelper",
            r"SQLiteDatabase\.openDatabase\([^)]*\)(?!.*password)",
            r"Room\.databaseBuilder\([^)]*\)(?!.*encrypt)",
            r"openOrCreateDatabase\([^)]*\)(?!.*password)"
        ]
        
        for pattern in unencrypted_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if sensitive data might be stored
                context = self._get_context_around_match(content, match, 10)
                if self._contains_sensitive_data_keywords(context):
                    vulnerability = CryptographicVulnerability(
                        vulnerability_id=f"unencrypted_db_{hashlib.md5((file_path + str(line_num)).encode()).hexdigest()[:8]}",
                        title="Unencrypted Database Storage",
                        description=f"Unencrypted database usage: {match.group(0)[:50]}...",
                        severity=VulnerabilitySeverity.MEDIUM,
                        location=f"{file_path}:{line_num}",
                        algorithm_name="Database Security",
                        cryptographic_weakness="Unencrypted database storage",
                        attack_vectors=[
                            "Database file access",
                            "SQLite file extraction",
                            "Device forensics"
                        ],
                        algorithm_recommendations=[
                            "Use SQLCipher for SQLite encryption",
                            "Implement Room database encryption",
                            "Use Realm with encryption enabled"
                        ]
                    )
                    analysis.vulnerabilities.append(vulnerability)
    
    def _check_database_encryption_implementation(self, file_path: str, content: str, analysis: CryptographicStorageAnalysis) -> None:
        """Check database encryption implementation details."""
        # SQLCipher implementation check
        sqlcipher_patterns = [
            r"net\.sqlcipher\.database\.SQLiteDatabase",
            r"SQLCipherUtils\.encrypt",
            r"openOrCreateDatabase\([^)]*password[^)]*\)"
        ]
        
        for pattern in sqlcipher_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                # Check for proper SQLCipher usage
                context = self._get_context_around_match(content, match, 10)
                
                # Check for hardcoded passwords
                if re.search(r'password\s*=\s*["\'][^"\']+["\']', context, re.IGNORECASE):
                    vulnerability = CryptographicVulnerability(
                        vulnerability_id=f"hardcoded_db_pass_{hashlib.md5((file_path + str(line_num)).encode()).hexdigest()[:8]}",
                        title="Hardcoded Database Password",
                        description="Database password is hardcoded",
                        severity=VulnerabilitySeverity.HIGH,
                        location=f"{file_path}:{line_num}",
                        algorithm_name="Database Security",
                        cryptographic_weakness="Hardcoded database password",
                        algorithm_recommendations=[
                            "Use key derivation functions for database passwords",
                            "Store database keys in Android Keystore",
                            "Use user-derived passwords"
                        ]
                    )
                    analysis.vulnerabilities.append(vulnerability)
    
    def _analyze_storage_integrity_protection(self, file_contents: Dict[str, str], analysis: CryptographicStorageAnalysis) -> None:
        """Analyze storage integrity protection mechanisms."""
        # Check for lack of integrity protection
        for file_path, content in file_contents.items():
            if any(storage in content for storage in ["EncryptedSharedPreferences", "EncryptedFile", "SQLCipher"]):
                # Check if integrity protection is implemented
                has_integrity = any(integrity in content for integrity in ["HMAC", "Signature", "MessageDigest"])
                if not has_integrity:
                    # This is informational, not necessarily a vulnerability
                    analysis.recommendations.append(
                        f"Consider implementing integrity protection for encrypted storage in {file_path}"
                    )
    
    def _analyze_secure_deletion_mechanisms(self, file_contents: Dict[str, str], analysis: CryptographicStorageAnalysis) -> None:
        """Analyze secure deletion mechanisms."""
        # Check for proper secure deletion implementation
        for file_path, content in file_contents.items():
            if "delete" in content.lower() or "remove" in content.lower():
                # Check for secure deletion patterns
                has_secure_deletion = any(
                    pattern in content for pattern in [
                        "SecureRandom", "Arrays.fill", "zero", "wipe", "overwrite"
                    ]
                )
                
                if not has_secure_deletion and self._contains_sensitive_data_keywords(content):
                    analysis.recommendations.append(
                        f"Consider implementing secure deletion mechanisms in {file_path}"
                    )
    
    def _contains_sensitive_data_keywords(self, text: str) -> bool:
        """Check if text contains keywords indicating sensitive data."""
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'credential', 'auth',
            'private', 'confidential', 'sensitive', 'personal', 'financial',
            'credit', 'ssn', 'social', 'medical', 'health', 'biometric'
        ]
        
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in sensitive_keywords)
    
    def _get_context_around_match(self, content: str, match, lines: int = 5) -> str:
        """Get context around a regex match."""
        match_start = match.start()
        match_end = match.end()
        
        # Find line boundaries
        lines_before = content[:match_start].split('\n')[-lines:]
        lines_after = content[match_end:].split('\n')[:lines]
        current_line = content[match_start:match_end]
        
        return '\n'.join(lines_before + [current_line] + lines_after)
    
    def _calculate_storage_score(self, analysis: CryptographicStorageAnalysis) -> float:
        """Calculate overall storage security score."""
        score = 1.0
        
        # Penalize for vulnerabilities
        critical_vulns = sum(1 for v in analysis.vulnerabilities if v.severity.value == "CRITICAL")
        high_vulns = sum(1 for v in analysis.vulnerabilities if v.severity.value == "HIGH")
        medium_vulns = sum(1 for v in analysis.vulnerabilities if v.severity.value == "MEDIUM")
        
        score -= critical_vulns * 0.4
        score -= high_vulns * 0.2
        score -= medium_vulns * 0.1
        
        # Bonus for secure storage implementations
        if analysis.encrypted_storage_implementations:
            score += 0.2
        
        if analysis.database_encryption:
            score += 0.15
        
        if analysis.storage_integrity_protection:
            score += 0.1
        
        if analysis.secure_deletion_mechanisms:
            score += 0.05
        
        return max(0.0, min(1.0, score))
    
    def _generate_storage_recommendations(self, analysis: CryptographicStorageAnalysis) -> List[str]:
        """Generate storage security recommendations."""
        recommendations = []
        
        # Encrypted storage recommendations
        if not analysis.encrypted_storage_implementations:
            recommendations.append("Implement encrypted storage for sensitive data")
        
        # Database encryption recommendations
        if not analysis.database_encryption:
            recommendations.append("Use database encryption for sensitive data storage")
        
        # Integrity protection recommendations
        if not analysis.storage_integrity_protection:
            recommendations.append("Implement storage integrity protection mechanisms")
        
        # Secure deletion recommendations
        if not analysis.secure_deletion_mechanisms:
            recommendations.append("Implement secure deletion for sensitive data")
        
        return recommendations
    
    def _assess_compliance(self, analysis: CryptographicStorageAnalysis) -> Dict[ComplianceStandard, bool]:
        """Assess storage compliance with standards."""
        compliance = {}
        
        # Check for encrypted storage
        has_encryption = bool(analysis.encrypted_storage_implementations or analysis.database_encryption)
        
        # Check for no critical vulnerabilities
        no_critical_vulns = not any(v.severity.value == "CRITICAL" for v in analysis.vulnerabilities)
        
        # GDPR compliance (data protection)
        compliance[ComplianceStandard.GDPR] = has_encryption and no_critical_vulns
        
        # HIPAA compliance (healthcare data)
        compliance[ComplianceStandard.HIPAA] = has_encryption and no_critical_vulns
        
        # PCI DSS compliance (payment data)
        compliance[ComplianceStandard.PCI_DSS] = has_encryption and no_critical_vulns
        
        return compliance
    
    def _create_analysis_error_vulnerability(self, error_message: str) -> CryptographicVulnerability:
        """Create a vulnerability for analysis errors."""
        return CryptographicVulnerability(
            vulnerability_id=f"storage_analysis_error_{hashlib.md5(error_message.encode()).hexdigest()[:8]}",
            title="Storage Analysis Error",
            description=f"Error during storage analysis: {error_message}",
            severity=VulnerabilitySeverity.LOW,
            location="analysis_engine",
            algorithm_name="Storage Security",
            cryptographic_weakness="Analysis limitation",
            algorithm_recommendations=["Manual review recommended"]
        ) 