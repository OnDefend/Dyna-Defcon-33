"""
File Storage Security Analyzer Module

Specialized analyzer for file storage security analysis.
Comprehensive implementation for the modular architecture.
"""

import logging
import re
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.shared_infrastructure.dependency_injection import AnalysisContext
from .data_structures import (
    FileStorageAnalysis, StorageVulnerability, StorageVulnerabilitySeverity,
    StorageType, StorageSecurityLevel
)
from .confidence_calculator import StorageConfidenceCalculator

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

class FileStorageAnalyzer:
    """File storage security analyzer with comprehensive analysis capabilities."""
    
    def __init__(self, context: AnalysisContext, confidence_calculator: StorageConfidenceCalculator, logger: logging.Logger):
        self.context = context
        self.confidence_calculator = confidence_calculator
        self.logger = logger
        
        # Initialize analysis patterns
        self.file_patterns = self._initialize_file_patterns()
        self.permission_patterns = self._initialize_permission_patterns()
        self.encryption_patterns = self._initialize_encryption_patterns()
        
        # Analysis statistics
        self.analysis_stats = {
            'files_analyzed': 0,
            'vulnerabilities_found': 0,
            'encrypted_files': 0,
            'external_storage_files': 0
        }
    
    def analyze(self, apk_ctx) -> List[FileStorageAnalysis]:
        """Analyze file storage security comprehensively."""
        analyses = []
        
        try:
            self.logger.info("Starting comprehensive file storage security analysis")
            
            # Find storage-related files
            storage_files = self._find_storage_files(apk_ctx)
            
            # Find source files with file storage operations
            source_files = self._find_source_files_with_storage(apk_ctx)
            
            # Analyze storage files
            for storage_file in storage_files:
                try:
                    analysis = self._analyze_storage_file(storage_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                        self.analysis_stats['files_analyzed'] += 1
                except Exception as e:
                    self.logger.warning(f"Failed to analyze storage file {storage_file}: {e}")
            
            # Analyze source code for storage patterns
            for source_file in source_files:
                try:
                    analysis = self._analyze_source_for_storage(source_file, apk_ctx)
                    if analysis:
                        analyses.append(analysis)
                        self.analysis_stats['files_analyzed'] += 1
                except Exception as e:
                    self.logger.warning(f"Failed to analyze source file {source_file}: {e}")
            
            self.logger.info(f"File storage analysis completed: {len(analyses)} files analyzed")
            
            return analyses
            
        except Exception as e:
            self.logger.error(f"File storage analysis failed: {e}")
            return []
    
    def _find_storage_files(self, apk_ctx) -> List[str]:
        """Find storage-related files in the APK."""
        storage_files = []
        
        try:
            # Look for various file types that might contain sensitive data
            sensitive_extensions = ['.txt', '.json', '.xml', '.properties', '.config', '.dat', '.bin']
            
            if hasattr(apk_ctx, 'get_files'):
                all_files = apk_ctx.get_files()
                for file_path in all_files:
                    # Check for sensitive file extensions
                    if any(file_path.lower().endswith(ext) for ext in sensitive_extensions):
                        storage_files.append(file_path)
                    
                    # Check for files in sensitive directories
                    if any(dir_name in file_path.lower() for dir_name in 
                           ['assets', 'raw', 'files', 'cache', 'data', 'external']):
                        storage_files.append(file_path)
            
            # Look for files in specific directories
            sensitive_dirs = ['assets/', 'res/raw/', 'files/', 'cache/']
            for dir_path in sensitive_dirs:
                if hasattr(apk_ctx, 'get_files_in_dir'):
                    try:
                        files_in_dir = apk_ctx.get_files_in_dir(dir_path)
                        storage_files.extend(files_in_dir)
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error finding storage files: {e}")
        
        return list(set(storage_files))  # Remove duplicates
    
    def _find_source_files_with_storage(self, apk_ctx) -> List[str]:
        """Find source files that contain file storage operations."""
        source_files = []
        
        try:
            if hasattr(apk_ctx, 'get_java_files'):
                java_files = apk_ctx.get_java_files()
                
                # Check files for storage-related code
                for file_path in java_files[:150]:  # Limit for performance
                    try:
                        if hasattr(apk_ctx, 'get_file_content'):
                            content = apk_ctx.get_file_content(file_path)
                            if content and self._contains_storage_code(content):
                                source_files.append(file_path)
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Error finding source files with storage: {e}")
        
        return source_files
    
    def _contains_storage_code(self, content: str) -> bool:
        """Check if source code contains file storage operations."""
        storage_indicators = [
            'FileOutputStream',
            'FileInputStream',
            'FileWriter',
            'FileReader',
            'File(',
            'Files.write',
            'Files.read',
            'openFileOutput',
            'openFileInput',
            'getFilesDir',
            'getCacheDir',
            'getExternalStorageDirectory',
            'getExternalFilesDir',
            'getExternalCacheDir',
            'Environment.getExternalStorageDirectory',
            'createTempFile',
            'RandomAccessFile'
        ]
        
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in storage_indicators)
    
    def _analyze_storage_file(self, storage_file: str, apk_ctx) -> Optional[FileStorageAnalysis]:
        """Analyze a specific storage file."""
        try:
            analysis = FileStorageAnalysis(
                file_path=storage_file,
                storage_location=self._determine_storage_location(storage_file),
                encryption_status="unencrypted",  # Will be updated below
                vulnerabilities=[]
            )
            
            # Check file permissions and location
            location_vulns = self._check_file_location_security(storage_file)
            analysis.vulnerabilities.extend(location_vulns)
            
            # Check file encryption
            encryption_result = self._check_file_encryption(storage_file, apk_ctx)
            analysis.encryption_status = "encrypted" if encryption_result.get('encrypted', False) else "unencrypted"
            
            if analysis.encryption_status == "unencrypted":
                vulnerability = StorageVulnerability(
                    id=f"file_unencrypted_{hash(storage_file)}",
                    title="Unencrypted File Storage",
                    description=f"File '{os.path.basename(storage_file)}' is stored without encryption",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[storage_file],
                    evidence=f"Unencrypted file: {storage_file}",
                    remediation="Encrypt sensitive files using Android cryptographic APIs",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        storage_file, "unencrypted", {"file_path": storage_file}
                    )
                )
                analysis.vulnerabilities.append(vulnerability)
            else:
                self.analysis_stats['encrypted_files'] += 1
            
            # Check file content for sensitive data
            if hasattr(apk_ctx, 'get_file_content'):
                content = apk_ctx.get_file_content(storage_file)
                if content:
                    sensitive_data_vulns = self._check_sensitive_data_in_file(content, storage_file)
                    analysis.vulnerabilities.extend(sensitive_data_vulns)
            
            self.analysis_stats['vulnerabilities_found'] += len(analysis.vulnerabilities)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing storage file {storage_file}: {e}")
            return None
    
    def _analyze_source_for_storage(self, source_file: str, apk_ctx) -> Optional[FileStorageAnalysis]:
        """Analyze source code for file storage security patterns."""
        try:
            if not hasattr(apk_ctx, 'get_file_content'):
                return None
            
            content = apk_ctx.get_file_content(source_file)
            if not content:
                return None
            
            analysis = FileStorageAnalysis(
                file_path=source_file,
                storage_location=StorageType.INTERNAL_STORAGE,  # **FIX**: Use proper enum value
                encryption_status="unencrypted",  # **FIX**: Add required parameter  
                vulnerabilities=[]
            )
            
            # Check for various file storage security issues
            vulns = []
            
            # Check for external storage usage
            vulns.extend(self._check_external_storage_usage(content, source_file))
            
            # Check for world-readable file creation
            vulns.extend(self._check_world_readable_file_creation(content, source_file))
            
            # Check for insecure file permissions
            vulns.extend(self._check_insecure_file_permissions(content, source_file))
            
            # Check for temporary file issues
            vulns.extend(self._check_temporary_file_issues(content, source_file))
            
            # Check for cache security issues
            vulns.extend(self._check_cache_security_issues(content, source_file))
            
            analysis.vulnerabilities = vulns
            self.analysis_stats['vulnerabilities_found'] += len(vulns)
            
            return analysis if vulns else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing source file {source_file}: {e}")
            return None
    
    def _determine_storage_location(self, file_path: str) -> StorageType:
        """Determine the storage location (enum) of a file path."""
        file_path_lower = file_path.lower()

        if any(keyword in file_path_lower for keyword in ['external', 'sdcard', '/storage/emulated/0']):
            return StorageType.EXTERNAL_STORAGE
        if any(keyword in file_path_lower for keyword in ['cache', 'tmp', 'temp']):
            return StorageType.CACHE
        if any(keyword in file_path_lower for keyword in ['files', '/data/data', 'internal']):
            return StorageType.INTERNAL_STORAGE
        if any(keyword in file_path_lower for keyword in ['config', 'assets', 'raw']):
            return StorageType.CONFIGURATION_FILES
        return StorageType.UNKNOWN
    
    def _check_file_location_security(self, file_path: str) -> List[StorageVulnerability]:
        """Check file location security."""
        vulnerabilities = []
        
        try:
            # Check for external storage
            if any(keyword in file_path.lower() for keyword in ['external', 'sdcard', '/storage/emulated/0']):
                vulnerability = StorageVulnerability(
                    id=f"file_external_{hash(file_path)}",
                    title="File in External Storage",
                    description=f"File '{os.path.basename(file_path)}' is stored in external storage",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-2",
                    affected_files=[file_path],
                    evidence=f"External storage file: {file_path}",
                    remediation="Store sensitive files in internal storage with proper permissions",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "external_storage", {"file_path": file_path}
                    )
                )
                vulnerabilities.append(vulnerability)
                self.analysis_stats['external_storage_files'] += 1
            
            # Check for world-readable locations
            if any(keyword in file_path.lower() for keyword in ['/tmp/', '/var/tmp/', '/sdcard/']):
                vulnerability = StorageVulnerability(
                    id=f"file_world_readable_{hash(file_path)}",
                    title="File in World-Readable Location",
                    description=f"File '{os.path.basename(file_path)}' is in world-readable location",
                    severity=StorageVulnerabilitySeverity.CRITICAL,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"World-readable file: {file_path}",
                    remediation="Move file to app's private internal storage",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "world_readable", {"file_path": file_path}
                    )
                )
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            self.logger.debug(f"Error checking file location security: {e}")
        
        return vulnerabilities
    
    def _check_file_encryption(self, file_path: str, apk_ctx) -> Dict[str, Any]:
        """Check if file is encrypted."""
        try:
            if hasattr(apk_ctx, 'get_file_binary_content'):
                binary_content = apk_ctx.get_file_binary_content(file_path)
                if binary_content:
                    # Check for encryption signatures
                    if binary_content.startswith(b'-----BEGIN ENCRYPTED'):
                        return {'encrypted': True, 'method': 'PEM'}
                    elif binary_content.startswith(b'AES') or binary_content.startswith(b'ENC'):
                        return {'encrypted': True, 'method': 'AES'}
                    elif len(binary_content) > 100 and self._looks_encrypted(binary_content):
                        return {'encrypted': True, 'method': 'unknown'}
            
            # Check file extension for encryption indicators
            if any(ext in file_path.lower() for ext in ['.enc', '.encrypted', '.aes', '.gpg']):
                return {'encrypted': True, 'method': 'extension_based'}
            
            return {'encrypted': False, 'method': 'none'}
            
        except Exception as e:
            self.logger.debug(f"Error checking file encryption: {e}")
            return {'encrypted': False, 'method': 'none'}
    
    def _looks_encrypted(self, data: bytes) -> bool:
        """Check if binary data looks encrypted."""
        try:
            # Simple heuristic: encrypted data should have high entropy
            if len(data) < 100:
                return False
            
            # Check for patterns that suggest encryption
            unique_bytes = len(set(data))
            entropy_ratio = unique_bytes / min(len(data), 256)
            
            # High entropy suggests encryption
            return entropy_ratio > 0.7
            
        except Exception:
            return False
    
    def _check_sensitive_data_in_file(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for sensitive data in file content."""
        vulnerabilities = []
        
        try:
            # Check for various types of sensitive data
            sensitive_patterns = {
                'credentials': [
                    r'(?i)password\s*[:=]\s*["\'][^"\']{4,}["\']',
                    r'(?i)secret\s*[:=]\s*["\'][^"\']{8,}["\']',
                    r'(?i)api[_-]?key\s*[:=]\s*["\'][^"\']{20,}["\']',
                    r'(?i)token\s*[:=]\s*["\'][^"\']{20,}["\']'
                ],
                'personal_info': [
                    r'(?i)email\s*[:=]\s*["\'][^"\']*@[^"\']*["\']',
                    r'(?i)phone\s*[:=]\s*["\'][^"\']*\d{3}[^"\']*["\']',
                    r'(?i)address\s*[:=]\s*["\'][^"\']{10,}["\']'
                ],
                'financial': [
                    r'(?i)credit.*card\s*[:=]\s*["\'][^"\']*\d{4}[^"\']*["\']',
                    r'(?i)bank.*account\s*[:=]\s*["\'][^"\']*\d{6}[^"\']*["\']',
                    r'(?i)ssn\s*[:=]\s*["\'][^"\']*\d{3}[^"\']*["\']'
                ]
            }
            
            for data_type, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        vulnerability = StorageVulnerability(
                            id=f"file_sensitive_{data_type}_{hash(file_path + str(line_num))}",
                            title=f"Sensitive Data in File: {data_type}",
                            description=f"Potentially sensitive {data_type} found in file",
                            severity=StorageVulnerabilitySeverity.HIGH,
                            storage_type=StorageType.FILE_STORAGE,
                            masvs_control="MSTG-STORAGE-1",
                            affected_files=[file_path],
                            evidence=f"Line {line_num}: {match.group()[:50]}...",
                            remediation="Remove sensitive data from files or encrypt the files",
                            confidence=self.confidence_calculator.calculate_file_storage_confidence(
                                file_path, f"sensitive_{data_type}", {"line_number": line_num}
                            )
                        )
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            self.logger.debug(f"Error checking sensitive data in file: {e}")
        
        return vulnerabilities
    
    def _check_external_storage_usage(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for external storage usage."""
        vulnerabilities = []
        
        external_storage_patterns = [
            r'getExternalStorageDirectory\(\)',
            r'Environment\.getExternalStorageDirectory\(\)',
            r'getExternalFilesDir\(',
            r'getExternalCacheDir\(',
            r'\/sdcard\/',
            r'\/storage\/emulated\/0\/'
        ]
        
        for pattern in external_storage_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"file_external_usage_{hash(file_path + str(line_num))}",
                    title="External Storage Usage",
                    description="Code uses external storage which may not be secure",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-2",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use internal storage for sensitive data",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "external_storage_usage", {"line_number": line_num}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_world_readable_file_creation(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for world-readable file creation."""
        vulnerabilities = []
        
        world_readable_patterns = [
            r'openFileOutput\s*\([^)]*MODE_WORLD_READABLE',
            r'openFileOutput\s*\([^)]*MODE_WORLD_WRITEABLE',
            r'FileOutputStream\s*\([^)]*MODE_WORLD_READABLE',
            r'FileOutputStream\s*\([^)]*MODE_WORLD_WRITEABLE'
        ]
        
        for pattern in world_readable_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"file_world_readable_creation_{hash(file_path + str(line_num))}",
                    title="World-Readable File Creation",
                    description="File created with world-readable permissions",
                    severity=StorageVulnerabilitySeverity.CRITICAL,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use MODE_PRIVATE for file creation",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "world_readable_creation", {"line_number": line_num}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_insecure_file_permissions(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for insecure file permissions."""
        vulnerabilities = []
        
        # Check for chmod with permissive permissions
        chmod_patterns = [
            r'chmod\s*\(\s*["\'][^"\']*["\'],\s*0?[67][0-7][0-7]',  # World-readable/writable
            r'setReadable\s*\(\s*true\s*,\s*false\s*\)',  # World-readable
            r'setWritable\s*\(\s*true\s*,\s*false\s*\)',  # World-writable
            r'setExecutable\s*\(\s*true\s*,\s*false\s*\)'  # World-executable
        ]
        
        for pattern in chmod_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"file_insecure_permissions_{hash(file_path + str(line_num))}",
                    title="Insecure File Permissions",
                    description="File permissions set to allow world access",
                    severity=StorageVulnerabilitySeverity.HIGH,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use restrictive file permissions for sensitive files",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "insecure_permissions", {"line_number": line_num}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_temporary_file_issues(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for temporary file security issues."""
        vulnerabilities = []
        
        temp_file_patterns = [
            r'createTempFile\s*\(',
            r'File\.createTempFile\s*\(',
            r'Files\.createTempFile\s*\(',
            r'\/tmp\/',
            r'getTempDir\(\)',
            r'System\.getProperty\s*\(\s*["\']java\.io\.tmpdir["\']'
        ]
        
        for pattern in temp_file_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"file_temp_insecure_{hash(file_path + str(line_num))}",
                    title="Insecure Temporary File Usage",
                    description="Temporary files may be accessible to other apps",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-1",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use app's private cache directory for temporary files",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "temp_file_insecure", {"line_number": line_num}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_cache_security_issues(self, content: str, file_path: str) -> List[StorageVulnerability]:
        """Check for cache security issues."""
        vulnerabilities = []
        
        # Check for external cache usage
        external_cache_patterns = [
            r'getExternalCacheDir\(\)',
            r'Environment\.getExternalStorageDirectory\(\).*cache',
            r'\/sdcard\/.*cache'
        ]
        
        for pattern in external_cache_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                vulnerability = StorageVulnerability(
                    id=f"file_external_cache_{hash(file_path + str(line_num))}",
                    title="External Cache Usage",
                    description="External cache directory used for potentially sensitive data",
                    severity=StorageVulnerabilitySeverity.MEDIUM,
                    storage_type=StorageType.FILE_STORAGE,
                    masvs_control="MSTG-STORAGE-2",
                    affected_files=[file_path],
                    evidence=f"Line {line_num}: {match.group()}",
                    remediation="Use internal cache directory for sensitive data",
                    confidence=self.confidence_calculator.calculate_file_storage_confidence(
                        file_path, "external_cache", {"line_number": line_num}
                    )
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _initialize_file_patterns(self) -> Dict[str, List[str]]:
        """Initialize file operation patterns."""
        return {
            'file_operations': [
                'FileOutputStream',
                'FileInputStream',
                'FileWriter',
                'FileReader',
                'RandomAccessFile',
                'openFileOutput',
                'openFileInput',
                'Files.write',
                'Files.read'
            ],
            'storage_directories': [
                'getFilesDir',
                'getCacheDir',
                'getExternalStorageDirectory',
                'getExternalFilesDir',
                'getExternalCacheDir'
            ]
        }
    
    def _initialize_permission_patterns(self) -> Dict[str, List[str]]:
        """Initialize permission patterns."""
        return {
            'insecure_modes': [
                'MODE_WORLD_READABLE',
                'MODE_WORLD_WRITEABLE',
                'Context.MODE_WORLD_READABLE',
                'Context.MODE_WORLD_WRITEABLE'
            ],
            'permission_methods': [
                'chmod',
                'setReadable',
                'setWritable',
                'setExecutable'
            ]
        }
    
    def _initialize_encryption_patterns(self) -> Dict[str, List[str]]:
        """Initialize encryption patterns."""
        return {
            'encryption_indicators': [
                'Cipher.getInstance',
                'SecretKeySpec',
                'IvParameterSpec',
                'KeyGenerator',
                'SecureRandom',
                'MessageDigest',
                'Mac.getInstance'
            ],
            'encryption_files': [
                '.enc',
                '.encrypted',
                '.aes',
                '.gpg'
            ]
        } 