#!/usr/bin/env python3
"""
APK Parsing Utilities for AODS Shared Infrastructure

Comprehensive APK parsing and analysis utilities that provide enhanced
APK inspection, manifest parsing, and metadata extraction capabilities.

Features:
- APK structure analysis and validation
- Android manifest parsing (binary and text)
- Certificate and signature analysis
- Resource extraction and analysis
- DEX file analysis and metadata
- Native library inspection
- Asset file enumeration
- Security-focused APK analysis
- Performance-optimized parsing
- Error handling and recovery

This component provides standardized APK parsing capabilities for all
AODS plugins, ensuring consistent and reliable APK analysis.
"""

import os
import re
import zipfile
import logging
import hashlib
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET
import tempfile
import shutil

# Optional imports for enhanced APK parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    default_backend = None

from ..analysis_exceptions import AnalysisError
from ..file_handlers import SafeFileReader, FileTypeDetector

logger = logging.getLogger(__name__)

class APKValidationResult(Enum):
    """APK validation results."""
    VALID = "valid"
    INVALID_STRUCTURE = "invalid_structure"
    MISSING_MANIFEST = "missing_manifest"
    CORRUPTED = "corrupted"
    UNSIGNED = "unsigned"
    INVALID_SIGNATURE = "invalid_signature"

class ArchitectureType(Enum):
    """Android architecture types."""
    ARM = "arm"
    ARM64 = "arm64"
    X86 = "x86"
    X86_64 = "x86_64"
    MIPS = "mips"
    MIPS64 = "mips64"
    UNKNOWN = "unknown"

@dataclass
class APKMetadata:
    """Container for APK metadata."""
    package_name: str
    version_name: str
    version_code: int
    min_sdk_version: int
    target_sdk_version: int
    compile_sdk_version: Optional[int] = None
    app_name: Optional[str] = None
    main_activity: Optional[str] = None
    file_size: int = 0
    file_hash_md5: str = ""
    file_hash_sha256: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'package_name': self.package_name,
            'version_name': self.version_name,
            'version_code': self.version_code,
            'min_sdk_version': self.min_sdk_version,
            'target_sdk_version': self.target_sdk_version,
            'compile_sdk_version': self.compile_sdk_version,
            'app_name': self.app_name,
            'main_activity': self.main_activity,
            'file_size': self.file_size,
            'file_hash_md5': self.file_hash_md5,
            'file_hash_sha256': self.file_hash_sha256
        }

@dataclass
class ManifestPermission:
    """Android manifest permission."""
    name: str
    protection_level: str = "unknown"
    is_dangerous: bool = False
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'protection_level': self.protection_level,
            'is_dangerous': self.is_dangerous,
            'description': self.description
        }

@dataclass
class ManifestComponent:
    """Android manifest component (activity, service, receiver, provider)."""
    component_type: str  # activity, service, receiver, provider
    name: str
    exported: bool = False
    enabled: bool = True
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'component_type': self.component_type,
            'name': self.name,
            'exported': self.exported,
            'enabled': self.enabled,
            'intent_filters': self.intent_filters,
            'permissions': self.permissions,
            'metadata': self.metadata
        }

@dataclass
class CertificateInfo:
    """Certificate information."""
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int
    fingerprint_md5: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    is_self_signed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'not_before': self.not_before,
            'not_after': self.not_after,
            'signature_algorithm': self.signature_algorithm,
            'public_key_algorithm': self.public_key_algorithm,
            'key_size': self.key_size,
            'fingerprint_md5': self.fingerprint_md5,
            'fingerprint_sha1': self.fingerprint_sha1,
            'fingerprint_sha256': self.fingerprint_sha256,
            'is_self_signed': self.is_self_signed
        }

@dataclass
class NativeLibraryInfo:
    """Native library information."""
    filename: str
    architecture: ArchitectureType
    file_size: int
    symbols: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    stripped: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'filename': self.filename,
            'architecture': self.architecture.value,
            'file_size': self.file_size,
            'symbols': self.symbols,
            'dependencies': self.dependencies,
            'stripped': self.stripped
        }

@dataclass
class APKAnalysisResult:
    """Complete APK analysis result."""
    apk_path: Path
    validation_result: APKValidationResult
    metadata: Optional[APKMetadata] = None
    permissions: List[ManifestPermission] = field(default_factory=list)
    components: List[ManifestComponent] = field(default_factory=list)
    certificates: List[CertificateInfo] = field(default_factory=list)
    native_libraries: List[NativeLibraryInfo] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    analysis_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'apk_path': str(self.apk_path),
            'validation_result': self.validation_result.value,
            'metadata': self.metadata.to_dict() if self.metadata else None,
            'permissions': [p.to_dict() for p in self.permissions],
            'components': [c.to_dict() for c in self.components],
            'certificates': [cert.to_dict() for cert in self.certificates],
            'native_libraries': [lib.to_dict() for lib in self.native_libraries],
            'dex_files': self.dex_files,
            'assets': self.assets,
            'resources': self.resources,
            'security_issues': self.security_issues,
            'analysis_time': self.analysis_time
        }

class APKValidator:
    """
    Comprehensive APK validation system for security and integrity checks.
    
    Provides detailed validation of APK structure, signatures, manifest,
    and security characteristics. Used across AODS plugins for consistent
    APK validation logic.
    """
    
    def __init__(self):
        """Initialize APK validator."""
        self.logger = logging.getLogger(__name__)
        
        # Tool availability
        self.aapt_available = shutil.which('aapt') is not None
        self.keytool_available = shutil.which('keytool') is not None
        self.jarsigner_available = shutil.which('jarsigner') is not None
        
        # Validation patterns
        self.required_files = {'AndroidManifest.xml', 'classes.dex'}
        self.suspicious_patterns = {
            'debug_keys': ['debug.keystore', 'testkey'],
            'malicious_files': ['payload.dex', 'exploit.so', 'backdoor'],
            'development_artifacts': ['.git', '.svn', 'debug.apk']
        }
        
        self.logger.info("APK validator initialized")
    
    def validate_apk(self, apk_path: Union[str, Path]) -> APKValidationResult:
        """
        Perform comprehensive APK validation.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            APKValidationResult indicating validation status
        """
        apk_path = Path(apk_path)
        
        try:
            # Check file existence and basic properties
            if not apk_path.exists():
                self.logger.error(f"APK file not found: {apk_path}")
                return APKValidationResult.INVALID_STRUCTURE
            
            if not apk_path.is_file():
                self.logger.error(f"Path is not a file: {apk_path}")
                return APKValidationResult.INVALID_STRUCTURE
            
            # Check file size (must be > 1KB)
            if apk_path.stat().st_size < 1024:
                self.logger.error(f"APK file too small: {apk_path.stat().st_size} bytes")
                return APKValidationResult.CORRUPTED
            
            # Validate ZIP structure
            if not self._validate_zip_structure(apk_path):
                return APKValidationResult.INVALID_STRUCTURE
            
            # Validate required APK files
            if not self._validate_required_files(apk_path):
                return APKValidationResult.MISSING_MANIFEST
            
            # Validate manifest structure
            if not self._validate_manifest_structure(apk_path):
                return APKValidationResult.MISSING_MANIFEST
            
            # Check for signature
            signature_status = self._validate_signatures(apk_path)
            if signature_status != APKValidationResult.VALID:
                return signature_status
            
            # Check for suspicious content
            if not self._check_security_indicators(apk_path):
                self.logger.warning(f"Suspicious content detected in APK: {apk_path}")
                # Continue validation but log warning
            
            return APKValidationResult.VALID
            
        except Exception as e:
            self.logger.error(f"APK validation failed: {e}")
            return APKValidationResult.CORRUPTED
    
    def _validate_zip_structure(self, apk_path: Path) -> bool:
        """Validate APK ZIP file structure."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # Test ZIP integrity
                bad_file = apk.testzip()
                if bad_file is not None:
                    self.logger.error(f"Corrupted file in APK: {bad_file}")
                    return False
                
                # Check for empty APK
                if len(apk.namelist()) == 0:
                    self.logger.error("APK contains no files")
                    return False
                
                return True
                
        except zipfile.BadZipFile:
            self.logger.error(f"Invalid ZIP file: {apk_path}")
            return False
        except Exception as e:
            self.logger.error(f"ZIP validation error: {e}")
            return False
    
    def _validate_required_files(self, apk_path: Path) -> bool:
        """Validate presence of required APK files."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                file_list = set(apk.namelist())
                
                # Check for required files
                missing_files = self.required_files - file_list
                if missing_files:
                    self.logger.error(f"Missing required files: {missing_files}")
                    return False
                
                return True
                
        except Exception as e:
            self.logger.error(f"Required files validation error: {e}")
            return False
    
    def _validate_manifest_structure(self, apk_path: Path) -> bool:
        """Validate AndroidManifest.xml structure."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # Read manifest
                manifest_data = apk.read('AndroidManifest.xml')
                
                # Check manifest size (must be > 100 bytes)
                if len(manifest_data) < 100:
                    self.logger.error("AndroidManifest.xml too small")
                    return False
                
                # Basic manifest validation using AAPT if available
                if self.aapt_available:
                    return self._validate_manifest_with_aapt(apk_path)
                
                # Basic binary XML check
                if manifest_data.startswith(b'\x03\x00'):
                    return True  # Binary XML format
                
                # Try parsing as text XML
                try:
                    ET.fromstring(manifest_data.decode('utf-8'))
                    return True
                except:
                    # Binary XML that we can't parse without AAPT
                    self.logger.warning("Binary manifest found but AAPT not available")
                    return True  # Assume valid
                
        except Exception as e:
            self.logger.error(f"Manifest validation error: {e}")
            return False
    
    def _validate_manifest_with_aapt(self, apk_path: Path) -> bool:
        """Validate manifest using AAPT tool."""
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', str(apk_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.logger.error(f"AAPT validation failed: {result.stderr}")
                return False
            
            # Check for required manifest elements
            output = result.stdout
            if 'package:' not in output:
                self.logger.error("No package information in manifest")
                return False
            
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("AAPT validation timeout")
            return False
        except Exception as e:
            self.logger.error(f"AAPT validation error: {e}")
            return False
    
    def _validate_signatures(self, apk_path: Path) -> APKValidationResult:
        """Validate APK signatures."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                file_list = apk.namelist()
                
                # Check for META-INF directory
                meta_inf_files = [f for f in file_list if f.startswith('META-INF/')]
                if not meta_inf_files:
                    return APKValidationResult.UNSIGNED
                
                # Check for signature files
                signature_files = [f for f in meta_inf_files if f.endswith(('.RSA', '.DSA', '.EC'))]
                if not signature_files:
                    return APKValidationResult.UNSIGNED
                
                # Check for certificate files
                cert_files = [f for f in meta_inf_files if f.endswith('.SF')]
                if not cert_files:
                    return APKValidationResult.INVALID_SIGNATURE
                
                # Validate signature using jarsigner if available
                if self.jarsigner_available:
                    return self._validate_signature_with_jarsigner(apk_path)
                
                return APKValidationResult.VALID
                
        except Exception as e:
            self.logger.error(f"Signature validation error: {e}")
            return APKValidationResult.INVALID_SIGNATURE
    
    def _validate_signature_with_jarsigner(self, apk_path: Path) -> APKValidationResult:
        """Validate signature using jarsigner tool."""
        try:
            result = subprocess.run(
                ['jarsigner', '-verify', str(apk_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return APKValidationResult.VALID
            else:
                self.logger.error(f"Signature verification failed: {result.stderr}")
                return APKValidationResult.INVALID_SIGNATURE
                
        except subprocess.TimeoutExpired:
            self.logger.error("Signature validation timeout")
            return APKValidationResult.INVALID_SIGNATURE
        except Exception as e:
            self.logger.error(f"Signature validation error: {e}")
            return APKValidationResult.INVALID_SIGNATURE
    
    def _check_security_indicators(self, apk_path: Path) -> bool:
        """Check for security indicators and suspicious content."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                file_list = apk.namelist()
                
                # Check for suspicious files
                for category, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        suspicious_files = [f for f in file_list if pattern.lower() in f.lower()]
                        if suspicious_files:
                            self.logger.warning(f"Suspicious {category} detected: {suspicious_files}")
                            return False
                
                return True
                
        except Exception as e:
            self.logger.error(f"Security check error: {e}")
            return False
    
    def get_validation_details(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Get detailed validation information.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dictionary with detailed validation results
        """
        apk_path = Path(apk_path)
        details = {
            'file_exists': apk_path.exists(),
            'file_size': apk_path.stat().st_size if apk_path.exists() else 0,
            'zip_valid': False,
            'required_files_present': False,
            'manifest_valid': False,
            'signature_status': 'unknown',
            'suspicious_content': [],
            'validation_result': APKValidationResult.INVALID_STRUCTURE
        }
        
        try:
            # Basic file validation
            if not details['file_exists']:
                return details
            
            # ZIP structure
            details['zip_valid'] = self._validate_zip_structure(apk_path)
            if not details['zip_valid']:
                return details
            
            # Required files
            details['required_files_present'] = self._validate_required_files(apk_path)
            
            # Manifest validation
            details['manifest_valid'] = self._validate_manifest_structure(apk_path)
            
            # Signature validation
            signature_result = self._validate_signatures(apk_path)
            details['signature_status'] = signature_result.value
            
            # Security checks
            security_ok = self._check_security_indicators(apk_path)
            if not security_ok:
                with zipfile.ZipFile(apk_path, 'r') as apk:
                    file_list = apk.namelist()
                    for category, patterns in self.suspicious_patterns.items():
                        for pattern in patterns:
                            suspicious_files = [f for f in file_list if pattern.lower() in f.lower()]
                            if suspicious_files:
                                details['suspicious_content'].extend(suspicious_files)
            
            # Overall validation
            details['validation_result'] = self.validate_apk(apk_path)
            
        except Exception as e:
            self.logger.error(f"Validation details error: {e}")
            details['error'] = str(e)
        
        return details


class APKParser:
    """
    Comprehensive APK parser for Android application analysis.
    
    Provides detailed analysis of APK structure, manifest, certificates,
    native libraries, and security characteristics.
    """
    
    def __init__(self):
        """Initialize APK parser."""
        self.logger = logging.getLogger(__name__)
        
        # Tool availability
        self.aapt_available = shutil.which('aapt') is not None
        self.aapt2_available = shutil.which('aapt2') is not None
        self.keytool_available = shutil.which('keytool') is not None
        
        # Dangerous permissions list
        self.dangerous_permissions = self._load_dangerous_permissions()
        
        # Known security issues patterns
        self.security_patterns = self._load_security_patterns()
        
        if not (self.aapt_available or self.aapt2_available):
            self.logger.warning("AAPT/AAPT2 not available - manifest parsing will be limited")
        
        self.logger.info("APK parser initialized")
    
    def parse_apk(self, apk_path: Union[str, Path], 
                  extract_details: bool = True,
                  validate_signatures: bool = True,
                  analyze_native_libs: bool = True) -> APKAnalysisResult:
        """
        Parse APK file and extract comprehensive information.
        
        Args:
            apk_path: Path to APK file
            extract_details: Whether to extract detailed information
            validate_signatures: Whether to validate signatures
            analyze_native_libs: Whether to analyze native libraries
            
        Returns:
            APKAnalysisResult with complete analysis
        """
        import time
        start_time = time.time()
        
        apk_path = Path(apk_path)
        result = APKAnalysisResult(apk_path=apk_path, validation_result=APKValidationResult.VALID)
        
        try:
            # Validate APK structure
            validation_result = self.validate_apk_structure(apk_path)
            result.validation_result = validation_result
            
            if validation_result != APKValidationResult.VALID:
                self.logger.warning(f"APK validation failed: {validation_result.value}")
                return result
            
            # Extract basic metadata
            result.metadata = self.extract_apk_metadata(apk_path)
            
            if extract_details:
                # Parse manifest
                manifest_data = self.parse_manifest(apk_path)
                if manifest_data:
                    result.permissions = manifest_data.get('permissions', [])
                    result.components = manifest_data.get('components', [])
                
                # Analyze certificates
                if validate_signatures:
                    result.certificates = self.extract_certificate_info(apk_path)
                
                # Analyze native libraries
                if analyze_native_libs:
                    result.native_libraries = self.analyze_native_libraries(apk_path)
                
                # Extract file lists
                result.dex_files = self.extract_dex_files(apk_path)
                result.assets = self.extract_assets(apk_path)
                result.resources = self.extract_resources(apk_path)
                
                # Security analysis
                result.security_issues = self.analyze_security_issues(result)
            
            result.analysis_time = time.time() - start_time
            self.logger.info(f"APK analysis completed in {result.analysis_time:.2f}s")
            
            return result
            
        except Exception as e:
            self.logger.error(f"APK parsing failed: {e}")
            result.validation_result = APKValidationResult.CORRUPTED
            result.security_issues.append(f"Parsing failed: {e}")
            result.analysis_time = time.time() - start_time
            return result
    
    def validate_apk_structure(self, apk_path: Path) -> APKValidationResult:
        """Validate APK file structure."""
        try:
            if not apk_path.exists():
                return APKValidationResult.INVALID_STRUCTURE
            
            # Check if it's a valid ZIP file
            if not zipfile.is_zipfile(apk_path):
                return APKValidationResult.INVALID_STRUCTURE
            
            # Check for required files
            with zipfile.ZipFile(apk_path, 'r') as zf:
                files = zf.namelist()
                
                # Must have AndroidManifest.xml
                if 'AndroidManifest.xml' not in files:
                    return APKValidationResult.MISSING_MANIFEST
                
                # Must have at least one DEX file
                if not any(f.endswith('.dex') for f in files):
                    return APKValidationResult.INVALID_STRUCTURE
                
                # Check for signature files
                meta_inf_files = [f for f in files if f.startswith('META-INF/')]
                has_signature = any(f.endswith(('.RSA', '.DSA', '.EC')) for f in meta_inf_files)
                
                if not has_signature:
                    return APKValidationResult.UNSIGNED
            
            return APKValidationResult.VALID
            
        except zipfile.BadZipFile:
            return APKValidationResult.CORRUPTED
        except Exception:
            return APKValidationResult.INVALID_STRUCTURE
    
    def extract_apk_metadata(self, apk_path: Path) -> Optional[APKMetadata]:
        """Extract basic APK metadata."""
        try:
            # Calculate file hashes
            file_size = apk_path.stat().st_size
            md5_hash, sha256_hash = self._calculate_file_hashes(apk_path)
            
            # Use AAPT to extract basic metadata
            if self.aapt_available:
                metadata = self._extract_metadata_with_aapt(apk_path)
                if metadata:
                    metadata.file_size = file_size
                    metadata.file_hash_md5 = md5_hash
                    metadata.file_hash_sha256 = sha256_hash
                    return metadata
            
            # Fallback to manifest parsing
            manifest_data = self._parse_binary_manifest(apk_path)
            if manifest_data:
                return APKMetadata(
                    package_name=manifest_data.get('package', 'unknown'),
                    version_name=manifest_data.get('versionName', 'unknown'),
                    version_code=int(manifest_data.get('versionCode', 0)),
                    min_sdk_version=int(manifest_data.get('minSdkVersion', 1)),
                    target_sdk_version=int(manifest_data.get('targetSdkVersion', 1)),
                    file_size=file_size,
                    file_hash_md5=md5_hash,
                    file_hash_sha256=sha256_hash
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to extract APK metadata: {e}")
            return None
    
    def parse_manifest(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse Android manifest and extract components and permissions."""
        try:
            if self.aapt_available:
                return self._parse_manifest_with_aapt(apk_path)
            else:
                return self._parse_binary_manifest_detailed(apk_path)
        except Exception as e:
            self.logger.error(f"Failed to parse manifest: {e}")
            return None
    
    def extract_certificate_info(self, apk_path: Path) -> List[CertificateInfo]:
        """Extract certificate information from APK."""
        certificates = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Find certificate files in META-INF
                cert_files = [f for f in zf.namelist() 
                             if f.startswith('META-INF/') and f.endswith(('.RSA', '.DSA', '.EC'))]
                
                for cert_file in cert_files:
                    cert_data = zf.read(cert_file)
                    cert_info = self._parse_certificate(cert_data)
                    if cert_info:
                        certificates.append(cert_info)
            
            return certificates
            
        except Exception as e:
            self.logger.error(f"Failed to extract certificate info: {e}")
            return []
    
    def analyze_native_libraries(self, apk_path: Path) -> List[NativeLibraryInfo]:
        """Analyze native libraries in APK."""
        libraries = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Find native libraries
                lib_files = [f for f in zf.namelist() 
                           if f.startswith('lib/') and f.endswith('.so')]
                
                for lib_file in lib_files:
                    # Extract architecture from path (e.g., lib/arm64-v8a/libexample.so)
                    path_parts = lib_file.split('/')
                    if len(path_parts) >= 3:
                        arch_str = path_parts[1]
                        arch = self._parse_architecture(arch_str)
                        
                        filename = path_parts[-1]
                        file_size = zf.getinfo(lib_file).file_size
                        
                        # Create library info
                        lib_info = NativeLibraryInfo(
                            filename=filename,
                            architecture=arch,
                            file_size=file_size
                        )
                        
                        # Extract library for detailed analysis if needed
                        # This would require additional tools like objdump or readelf
                        
                        libraries.append(lib_info)
            
            return libraries
            
        except Exception as e:
            self.logger.error(f"Failed to analyze native libraries: {e}")
            return []
    
    def extract_dex_files(self, apk_path: Path) -> List[str]:
        """Extract list of DEX files."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                return [f for f in zf.namelist() if f.endswith('.dex')]
        except Exception:
            return []
    
    def extract_assets(self, apk_path: Path) -> List[str]:
        """Extract list of asset files."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                return [f for f in zf.namelist() if f.startswith('assets/')]
        except Exception:
            return []
    
    def extract_resources(self, apk_path: Path) -> List[str]:
        """Extract list of resource files."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                return [f for f in zf.namelist() if f.startswith('res/')]
        except Exception:
            return []
    
    def analyze_security_issues(self, result: APKAnalysisResult) -> List[str]:
        """Analyze APK for security issues."""
        issues = []
        
        try:
            # Check for dangerous permissions
            dangerous_perms = [p for p in result.permissions if p.is_dangerous]
            if dangerous_perms:
                issues.append(f"Uses {len(dangerous_perms)} dangerous permissions")
            
            # Check for exported components without proper protection
            exported_components = [c for c in result.components if c.exported]
            unprotected_components = [c for c in exported_components if not c.permissions]
            if unprotected_components:
                issues.append(f"{len(unprotected_components)} exported components without permissions")
            
            # Check for debug build
            if result.metadata:
                if 'debug' in result.metadata.app_name.lower() if result.metadata.app_name else False:
                    issues.append("Appears to be a debug build")
            
            # Check for weak signature algorithm
            for cert in result.certificates:
                if 'md5' in cert.signature_algorithm.lower() or 'sha1' in cert.signature_algorithm.lower():
                    issues.append(f"Weak signature algorithm: {cert.signature_algorithm}")
            
            # Check for native libraries without security features
            for lib in result.native_libraries:
                if not lib.stripped:
                    issues.append(f"Native library not stripped: {lib.filename}")
            
            # Check for suspicious assets
            suspicious_assets = []
            for asset in result.assets:
                if any(pattern in asset.lower() for pattern in ['key', 'secret', 'password', 'token']):
                    suspicious_assets.append(asset)
            
            if suspicious_assets:
                issues.append(f"Suspicious asset files found: {len(suspicious_assets)}")
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            return [f"Security analysis failed: {e}"]
    
    def _extract_metadata_with_aapt(self, apk_path: Path) -> Optional[APKMetadata]:
        """Extract metadata using AAPT tool."""
        try:
            cmd = ['aapt', 'dump', 'badging', str(apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return None
            
            output = result.stdout
            
            # Parse AAPT output
            package_match = re.search(r"package: name='([^']+)'", output)
            version_name_match = re.search(r"versionName='([^']+)'", output)
            version_code_match = re.search(r"versionCode='([^']+)'", output)
            min_sdk_match = re.search(r"sdkVersion:'([^']+)'", output)
            target_sdk_match = re.search(r"targetSdkVersion:'([^']+)'", output)
            app_name_match = re.search(r"application-label:'([^']+)'", output)
            main_activity_match = re.search(r"launchable-activity: name='([^']+)'", output)
            
            return APKMetadata(
                package_name=package_match.group(1) if package_match else 'unknown',
                version_name=version_name_match.group(1) if version_name_match else 'unknown',
                version_code=int(version_code_match.group(1)) if version_code_match else 0,
                min_sdk_version=int(min_sdk_match.group(1)) if min_sdk_match else 1,
                target_sdk_version=int(target_sdk_match.group(1)) if target_sdk_match else 1,
                app_name=app_name_match.group(1) if app_name_match else None,
                main_activity=main_activity_match.group(1) if main_activity_match else None
            )
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
            return None
    
    def _parse_manifest_with_aapt(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse manifest using AAPT tool."""
        try:
            # Get permissions
            cmd = ['aapt', 'dump', 'permissions', str(apk_path)]
            perm_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            permissions = []
            if perm_result.returncode == 0:
                for line in perm_result.stdout.split('\n'):
                    if 'uses-permission:' in line:
                        perm_match = re.search(r"name='([^']+)'", line)
                        if perm_match:
                            perm_name = perm_match.group(1)
                            permissions.append(ManifestPermission(
                                name=perm_name,
                                is_dangerous=perm_name in self.dangerous_permissions
                            ))
            
            # Get XML dump for components
            cmd = ['aapt', 'dump', 'xmltree', str(apk_path), 'AndroidManifest.xml']
            xml_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            components = []
            if xml_result.returncode == 0:
                components = self._parse_components_from_aapt_xml(xml_result.stdout)
            
            return {
                'permissions': permissions,
                'components': components
            }
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return None
    
    def _parse_binary_manifest(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse binary manifest with comprehensive binary XML parsing."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                
                # Comprehensive binary XML parsing implementation
                parser = AndroidBinaryXMLParser(manifest_data)
                parsed_manifest = parser.parse()
                
                if parsed_manifest:
                    return self._extract_manifest_metadata(parsed_manifest)
                else:
                    # Fallback to AAPT parsing if binary parsing fails
                    return self._parse_manifest_with_aapt(apk_path)
                
        except Exception as e:
            self.logger.warning(f"Binary manifest parsing failed: {e}")
            # Fallback to AAPT parsing
            return self._parse_manifest_with_aapt(apk_path)
    
    def _parse_binary_manifest_detailed(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse binary manifest for detailed information including permissions and components."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                
                # Comprehensive binary XML parsing for detailed analysis
                parser = AndroidBinaryXMLParser(manifest_data)
                parsed_manifest = parser.parse()
                
                if parsed_manifest:
                    detailed_info = {
                        'permissions': self._extract_permissions(parsed_manifest),
                        'components': self._extract_components(parsed_manifest),
                        'metadata': self._extract_application_metadata(parsed_manifest),
                        'services': self._extract_services(parsed_manifest),
                        'receivers': self._extract_receivers(parsed_manifest),
                        'providers': self._extract_providers(parsed_manifest),
                        'intent_filters': self._extract_intent_filters(parsed_manifest),
                        'features': self._extract_features(parsed_manifest),
                        'instrumentation': self._extract_instrumentation(parsed_manifest)
                    }
                    return detailed_info
                else:
                    # Fallback to AAPT for detailed parsing
                    return self._parse_detailed_with_aapt(apk_path)
                
        except Exception as e:
            self.logger.error(f"Detailed binary manifest parsing failed: {e}")
            return self._parse_detailed_with_aapt(apk_path)
    
    def _parse_detailed_with_aapt(self, apk_path: Path) -> Dict[str, Any]:
        """Fallback detailed parsing using AAPT tool."""
        try:
            import subprocess
            
            # Use aapt to extract detailed manifest information
            detailed_info = {
                'permissions': [],
                'components': [],
                'metadata': {},
                'services': [],
                'receivers': [],
                'providers': [],
                'intent_filters': [],
                'features': [],
                'instrumentation': []
            }
            
            # Extract permissions
            perm_cmd = ['aapt', 'dump', 'permissions', str(apk_path)]
            perm_result = subprocess.run(perm_cmd, capture_output=True, text=True, timeout=30)
            if perm_result.returncode == 0:
                detailed_info['permissions'] = self._parse_aapt_permissions(perm_result.stdout)
            
            # Extract other manifest details
            xmltree_cmd = ['aapt', 'dump', 'xmltree', str(apk_path), 'AndroidManifest.xml']
            tree_result = subprocess.run(xmltree_cmd, capture_output=True, text=True, timeout=30)
            if tree_result.returncode == 0:
                manifest_details = self._parse_aapt_xmltree(tree_result.stdout)
                detailed_info.update(manifest_details)
            
            return detailed_info
            
        except Exception as e:
            self.logger.error(f"AAPT detailed parsing failed: {e}")
            return {
                'permissions': [],
                'components': [],
                'metadata': {},
                'services': [],
                'receivers': [],
                'providers': [],
                'intent_filters': [],
                'features': [],
                'instrumentation': []
            }
    
    def _extract_manifest_metadata(self, parsed_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic metadata from parsed manifest."""
        manifest_tag = parsed_manifest.get('manifest', {})
        
        return {
            'package': manifest_tag.get('package', 'unknown'),
            'versionName': manifest_tag.get('versionName', 'unknown'),
            'versionCode': manifest_tag.get('versionCode', '0'),
            'minSdkVersion': self._get_min_sdk_version(parsed_manifest),
            'targetSdkVersion': self._get_target_sdk_version(parsed_manifest),
            'compileSdkVersion': manifest_tag.get('compileSdkVersion', 'unknown'),
            'installLocation': manifest_tag.get('installLocation', 'auto')
        }
    
    def _extract_permissions(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract permissions from parsed manifest."""
        permissions = []
        
        # Extract uses-permission tags
        uses_permissions = parsed_manifest.get('uses-permission', [])
        if not isinstance(uses_permissions, list):
            uses_permissions = [uses_permissions]
        
        for perm in uses_permissions:
            if isinstance(perm, dict):
                permissions.append({
                    'name': perm.get('name', ''),
                    'type': 'uses-permission',
                    'maxSdkVersion': perm.get('maxSdkVersion'),
                    'required': perm.get('required', True)
                })
        
        # Extract permission tags (custom permissions)
        custom_permissions = parsed_manifest.get('permission', [])
        if not isinstance(custom_permissions, list):
            custom_permissions = [custom_permissions]
        
        for perm in custom_permissions:
            if isinstance(perm, dict):
                permissions.append({
                    'name': perm.get('name', ''),
                    'type': 'permission',
                    'protectionLevel': perm.get('protectionLevel', 'normal'),
                    'permissionGroup': perm.get('permissionGroup'),
                    'label': perm.get('label'),
                    'description': perm.get('description')
                })
        
        return permissions
    
    def _extract_components(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract components (activities, services, etc.) from parsed manifest."""
        components = []
        
        application = parsed_manifest.get('application', {})
        if not application:
            return components
        
        # Extract activities
        activities = application.get('activity', [])
        if not isinstance(activities, list):
            activities = [activities]
        
        for activity in activities:
            if isinstance(activity, dict):
                components.append({
                    'type': 'activity',
                    'name': activity.get('name', ''),
                    'exported': activity.get('exported', False),
                    'enabled': activity.get('enabled', True),
                    'label': activity.get('label'),
                    'theme': activity.get('theme'),
                    'launchMode': activity.get('launchMode'),
                    'intent_filters': self._extract_component_intent_filters(activity)
                })
        
        # Extract services
        services = application.get('service', [])
        if not isinstance(services, list):
            services = [services]
        
        for service in services:
            if isinstance(service, dict):
                components.append({
                    'type': 'service',
                    'name': service.get('name', ''),
                    'exported': service.get('exported', False),
                    'enabled': service.get('enabled', True),
                    'permission': service.get('permission'),
                    'process': service.get('process'),
                    'intent_filters': self._extract_component_intent_filters(service)
                })
        
        return components
    
    def _extract_services(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract services from parsed manifest."""
        services = []
        application = parsed_manifest.get('application', {})
        
        service_list = application.get('service', [])
        if not isinstance(service_list, list):
            service_list = [service_list]
        
        for service in service_list:
            if isinstance(service, dict):
                services.append({
                    'name': service.get('name', ''),
                    'exported': service.get('exported', False),
                    'enabled': service.get('enabled', True),
                    'permission': service.get('permission'),
                    'process': service.get('process'),
                    'isolatedProcess': service.get('isolatedProcess', False),
                    'stopWithTask': service.get('stopWithTask', True)
                })
        
        return services
    
    def _extract_receivers(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract broadcast receivers from parsed manifest."""
        receivers = []
        application = parsed_manifest.get('application', {})
        
        receiver_list = application.get('receiver', [])
        if not isinstance(receiver_list, list):
            receiver_list = [receiver_list]
        
        for receiver in receiver_list:
            if isinstance(receiver, dict):
                receivers.append({
                    'name': receiver.get('name', ''),
                    'exported': receiver.get('exported', False),
                    'enabled': receiver.get('enabled', True),
                    'permission': receiver.get('permission'),
                    'priority': receiver.get('priority', 0),
                    'intent_filters': self._extract_component_intent_filters(receiver)
                })
        
        return receivers
    
    def _extract_providers(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract content providers from parsed manifest."""
        providers = []
        application = parsed_manifest.get('application', {})
        
        provider_list = application.get('provider', [])
        if not isinstance(provider_list, list):
            provider_list = [provider_list]
        
        for provider in provider_list:
            if isinstance(provider, dict):
                providers.append({
                    'name': provider.get('name', ''),
                    'authorities': provider.get('authorities', ''),
                    'exported': provider.get('exported', False),
                    'enabled': provider.get('enabled', True),
                    'permission': provider.get('permission'),
                    'readPermission': provider.get('readPermission'),
                    'writePermission': provider.get('writePermission'),
                    'grantUriPermissions': provider.get('grantUriPermissions', False)
                })
        
        return providers
    
    def _extract_application_metadata(self, parsed_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract application metadata from parsed manifest."""
        application = parsed_manifest.get('application', {})
        
        metadata = {
            'name': application.get('name'),
            'label': application.get('label'),
            'icon': application.get('icon'),
            'theme': application.get('theme'),
            'debuggable': application.get('debuggable', False),
            'allowBackup': application.get('allowBackup', True),
            'allowClearUserData': application.get('allowClearUserData', True),
            'hardwareAccelerated': application.get('hardwareAccelerated', False),
            'largeHeap': application.get('largeHeap', False),
            'usesCleartextTraffic': application.get('usesCleartextTraffic', True),
            'networkSecurityConfig': application.get('networkSecurityConfig'),
            'requestLegacyExternalStorage': application.get('requestLegacyExternalStorage', False)
        }
        
        # Extract meta-data tags
        meta_data_list = application.get('meta-data', [])
        if not isinstance(meta_data_list, list):
            meta_data_list = [meta_data_list]
        
        metadata['meta_data'] = []
        for meta_data in meta_data_list:
            if isinstance(meta_data, dict):
                metadata['meta_data'].append({
                    'name': meta_data.get('name', ''),
                    'value': meta_data.get('value'),
                    'resource': meta_data.get('resource')
                })
        
        return metadata
    
    def _extract_intent_filters(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract intent filters from parsed manifest."""
        intent_filters = []
        application = parsed_manifest.get('application', {})
        
        # Search all components for intent filters
        for component_type in ['activity', 'service', 'receiver']:
            components = application.get(component_type, [])
            if not isinstance(components, list):
                components = [components]
            
            for component in components:
                if isinstance(component, dict):
                    component_filters = self._extract_component_intent_filters(component)
                    for filter_info in component_filters:
                        filter_info['component'] = component.get('name', '')
                        filter_info['component_type'] = component_type
                        intent_filters.append(filter_info)
        
        return intent_filters
    
    def _extract_features(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract uses-feature tags from parsed manifest."""
        features = []
        
        feature_list = parsed_manifest.get('uses-feature', [])
        if not isinstance(feature_list, list):
            feature_list = [feature_list]
        
        for feature in feature_list:
            if isinstance(feature, dict):
                features.append({
                    'name': feature.get('name', ''),
                    'required': feature.get('required', True),
                    'glEsVersion': feature.get('glEsVersion')
                })
        
        return features
    
    def _extract_instrumentation(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract instrumentation tags from parsed manifest."""
        instrumentation = []
        
        instrumentation_list = parsed_manifest.get('instrumentation', [])
        if not isinstance(instrumentation_list, list):
            instrumentation_list = [instrumentation_list]
        
        for instr in instrumentation_list:
            if isinstance(instr, dict):
                instrumentation.append({
                    'name': instr.get('name', ''),
                    'targetPackage': instr.get('targetPackage', ''),
                    'label': instr.get('label'),
                    'handleProfiling': instr.get('handleProfiling', False),
                    'functionalTest': instr.get('functionalTest', False)
                })
        
        return instrumentation
    
    def _extract_component_intent_filters(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract intent filters from a component."""
        intent_filters = []
        
        filter_list = component.get('intent-filter', [])
        if not isinstance(filter_list, list):
            filter_list = [filter_list]
        
        for intent_filter in filter_list:
            if isinstance(intent_filter, dict):
                filter_info = {
                    'actions': [],
                    'categories': [],
                    'data': [],
                    'priority': intent_filter.get('priority', 0)
                }
                
                # Extract actions
                actions = intent_filter.get('action', [])
                if not isinstance(actions, list):
                    actions = [actions]
                for action in actions:
                    if isinstance(action, dict):
                        filter_info['actions'].append(action.get('name', ''))
                
                # Extract categories
                categories = intent_filter.get('category', [])
                if not isinstance(categories, list):
                    categories = [categories]
                for category in categories:
                    if isinstance(category, dict):
                        filter_info['categories'].append(category.get('name', ''))
                
                # Extract data
                data_list = intent_filter.get('data', [])
                if not isinstance(data_list, list):
                    data_list = [data_list]
                for data in data_list:
                    if isinstance(data, dict):
                        filter_info['data'].append({
                            'scheme': data.get('scheme'),
                            'host': data.get('host'),
                            'port': data.get('port'),
                            'path': data.get('path'),
                            'pathPattern': data.get('pathPattern'),
                            'pathPrefix': data.get('pathPrefix'),
                            'mimeType': data.get('mimeType')
                        })
                
                intent_filters.append(filter_info)
        
        return intent_filters
    
    def _parse_certificate(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Parse certificate data from APK signature."""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning("Cryptography library not available for certificate parsing")
            return None
        
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography import x509
            import hashlib
            
            # Try to parse as PKCS#7 structure first
            try:
                # Parse PKCS#7 signature to extract certificate
                pkcs7_data = pkcs7.load_der_pkcs7_certificates(cert_data)
                if pkcs7_data:
                    cert = pkcs7_data[0]  # Get the first certificate
                else:
                    # Fallback: try to parse as X.509 certificate directly
                    cert = x509.load_der_x509_certificate(cert_data)
            except:
                # Last fallback: try PEM format
                try:
                    cert = x509.load_pem_x509_certificate(cert_data)
                except:
                    self.logger.debug("Failed to parse certificate in any format")
                    return None
            
            # Extract certificate information
            subject_name = cert.subject.rfc4514_string()
            issuer_name = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()
            
            # Extract signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name
            
            # Extract public key information
            public_key = cert.public_key()
            public_key_algorithm = public_key.__class__.__name__.replace('PublicKey', '')
            
            # Determine key size
            key_size = 0
            try:
                if hasattr(public_key, 'key_size'):
                    key_size = public_key.key_size
                elif hasattr(public_key, 'curve'):
                    key_size = public_key.curve.key_size
            except:
                pass
            
            # Calculate fingerprints
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            fingerprint_md5 = hashlib.md5(cert_der).hexdigest()
            fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
            fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
            
            return CertificateInfo(
                subject=subject_name,
                issuer=issuer_name,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=signature_algorithm,
                public_key_algorithm=public_key_algorithm,
                key_size=key_size,
                fingerprint_md5=fingerprint_md5,
                fingerprint_sha1=fingerprint_sha1,
                fingerprint_sha256=fingerprint_sha256
            )
            
        except Exception as e:
            self.logger.debug(f"Certificate parsing failed: {e}")
            return None
    
    def _parse_components_from_aapt_xml(self, xml_output: str) -> List[ManifestComponent]:
        """Parse components from AAPT XML output."""
        components = []
        
        # This would parse the AAPT XML tree output
        # Implementation would be specific to AAPT output format
        
        return components
    
    def _parse_architecture(self, arch_str: str) -> ArchitectureType:
        """Parse architecture type from string."""
        arch_mapping = {
            'armeabi': ArchitectureType.ARM,
            'armeabi-v7a': ArchitectureType.ARM,
            'arm64-v8a': ArchitectureType.ARM64,
            'x86': ArchitectureType.X86,
            'x86_64': ArchitectureType.X86_64,
            'mips': ArchitectureType.MIPS,
            'mips64': ArchitectureType.MIPS64
        }
        
        return arch_mapping.get(arch_str, ArchitectureType.UNKNOWN)
    
    def _calculate_file_hashes(self, file_path: Path) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes of file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    def _load_dangerous_permissions(self) -> Set[str]:
        """Load list of dangerous Android permissions."""
        return {
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ADD_VOICEMAIL',
            'android.permission.USE_SIP',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.RECEIVE_WAP_PUSH',
            'android.permission.RECEIVE_MMS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACCESS_MEDIA_LOCATION',
            'android.permission.ACCEPT_HANDOVER',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.ACTIVITY_RECOGNITION',
            'android.permission.ANSWER_PHONE_CALLS',
            'android.permission.READ_PHONE_NUMBERS'
        }
    
    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load security issue patterns."""
        return {
            'suspicious_files': [
                'key', 'secret', 'password', 'token', 'private', 'cert', 'p12', 'jks'
            ],
            'debug_indicators': [
                'debug', 'test', 'dev', 'staging'
            ]
        }

class APKAnalyzer:
    """
    High-level APK analysis orchestrator for comprehensive APK security assessment.
    
    Provides simplified access to comprehensive APK analysis including validation,
    manifest parsing, certificate analysis, and security assessment. Acts as the
    main entry point for APK analysis in the shared infrastructure.
    """
    
    def __init__(self):
        """Initialize the APK analyzer."""
        self.logger = logging.getLogger(__name__)
        self.validator = APKValidator()
        self.parser = APKParser()
        self.manifest_parser = None  # Will be initialized when needed
        
        self.logger.info("APKAnalyzer initialized with comprehensive analysis capabilities")
    
    def analyze(self, apk_path: Union[str, Path], 
                include_manifest: bool = True,
                include_certificates: bool = True,
                include_security_analysis: bool = True,
                include_native_libraries: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive APK analysis with configurable components.
        
        Args:
            apk_path: Path to APK file
            include_manifest: Include detailed manifest analysis
            include_certificates: Include certificate analysis
            include_security_analysis: Include security assessment
            include_native_libraries: Include native library analysis
            
        Returns:
            Dict[str, Any]: Comprehensive analysis results
        """
        apk_path = Path(apk_path)
        
        try:
            self.logger.info(f"Starting comprehensive analysis of {apk_path.name}")
            start_time = time.time()
            
            result = {
                'apk_path': str(apk_path),
                'analysis_timestamp': time.time(),
                'analysis_components': {
                    'validation': True,
                    'basic_analysis': True,
                    'manifest_analysis': include_manifest,
                    'certificate_analysis': include_certificates,
                    'security_analysis': include_security_analysis,
                    'native_library_analysis': include_native_libraries
                }
            }
            
            # Step 1: APK Validation
            validation_result = self.validator.validate_apk_structure(apk_path)
            result['validation'] = {
                'result': validation_result.value,
                'is_valid': validation_result == APKValidationResult.VALID
            }
            
            if validation_result != APKValidationResult.VALID:
                self.logger.warning(f"APK validation failed: {validation_result.value}")
                result['analysis_time'] = time.time() - start_time
                return result
            
            # Step 2: Basic APK Analysis
            apk_analysis = self.parser.parse_apk(
                apk_path,
                extract_details=True,
                validate_signatures=include_certificates,
                analyze_native_libs=include_native_libraries
            )
            
            result['basic_analysis'] = {
                'metadata': apk_analysis.metadata.to_dict() if apk_analysis.metadata else None,
                'permissions': [p.to_dict() for p in apk_analysis.permissions],
                'components': [c.to_dict() for c in apk_analysis.components],
                'dex_files': apk_analysis.dex_files,
                'assets': apk_analysis.assets[:20],  # Limit to first 20
                'resources': apk_analysis.resources[:20]  # Limit to first 20
            }
            
            if include_certificates:
                result['certificates'] = [cert.to_dict() for cert in apk_analysis.certificates]
            
            if include_native_libraries:
                result['native_libraries'] = [lib.to_dict() for lib in apk_analysis.native_libraries]
            
            # Step 3: Enhanced Manifest Analysis
            if include_manifest:
                if not self.manifest_parser:
                    self.manifest_parser = ManifestParser()
                
                manifest_analysis = self.manifest_parser.parse_manifest(apk_path)
                result['manifest_analysis'] = manifest_analysis
            
            # Step 4: Security Analysis
            if include_security_analysis:
                security_analysis = self._perform_security_analysis(result)
                result['security_analysis'] = security_analysis
            
            result['analysis_time'] = time.time() - start_time
            self.logger.info(f"APK analysis completed in {result['analysis_time']:.2f}s")
            
            return result
            
        except Exception as e:
            self.logger.error(f"APK analysis failed: {e}")
            return {
                'apk_path': str(apk_path),
                'analysis_timestamp': time.time(),
                'error': str(e),
                'analysis_time': time.time() - start_time if 'start_time' in locals() else 0
            }
    
    def quick_analyze(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Perform quick APK analysis with essential information only.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dict[str, Any]: Essential analysis results
        """
        return self.analyze(
            apk_path,
            include_manifest=False,
            include_certificates=False,
            include_security_analysis=False,
            include_native_libraries=False
        )
    
    def security_analyze(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Perform security-focused APK analysis.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dict[str, Any]: Security-focused analysis results
        """
        return self.analyze(
            apk_path,
            include_manifest=True,
            include_certificates=True,
            include_security_analysis=True,
            include_native_libraries=False
        )
    
    def validate_only(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate APK structure only.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dict[str, Any]: Validation results
        """
        try:
            validation_result = self.validator.validate_apk_structure(Path(apk_path))
            return {
                'apk_path': str(apk_path),
                'validation_result': validation_result.value,
                'is_valid': validation_result == APKValidationResult.VALID,
                'validation_details': self.validator.get_validation_details(apk_path)
            }
        except Exception as e:
            return {
                'apk_path': str(apk_path),
                'validation_result': 'error',
                'is_valid': False,
                'error': str(e)
            }
    
    def _perform_security_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive security analysis on APK data."""
        security_analysis = {
            'overall_risk_score': 0,
            'risk_level': 'LOW',
            'security_issues': [],
            'recommendations': [],
            'analysis_summary': {}
        }
        
        try:
            # Analyze basic analysis data
            basic_analysis = analysis_data.get('basic_analysis', {})
            
            # Permission analysis
            permissions = basic_analysis.get('permissions', [])
            perm_score = self._analyze_permissions_risk(permissions)
            security_analysis['overall_risk_score'] += perm_score
            
            # Component analysis
            components = basic_analysis.get('components', [])
            comp_score = self._analyze_components_risk(components)
            security_analysis['overall_risk_score'] += comp_score
            
            # Certificate analysis
            if 'certificates' in analysis_data:
                cert_score = self._analyze_certificates_risk(analysis_data['certificates'])
                security_analysis['overall_risk_score'] += cert_score
            
            # Manifest analysis
            if 'manifest_analysis' in analysis_data:
                manifest_data = analysis_data['manifest_analysis']
                if manifest_data and 'security_analysis' in manifest_data:
                    manifest_score = manifest_data['security_analysis'].get('risk_score', 0)
                    security_analysis['overall_risk_score'] += manifest_score * 0.3  # Weight factor
                    
                    # Add manifest issues
                    manifest_issues = manifest_data['security_analysis'].get('security_issues', [])
                    security_analysis['security_issues'].extend(manifest_issues)
                    
                    # Add manifest recommendations
                    manifest_recs = manifest_data['security_analysis'].get('recommendations', [])
                    security_analysis['recommendations'].extend(manifest_recs)
            
            # Determine risk level
            total_score = security_analysis['overall_risk_score']
            if total_score >= 70:
                security_analysis['risk_level'] = 'CRITICAL'
            elif total_score >= 50:
                security_analysis['risk_level'] = 'HIGH'
            elif total_score >= 25:
                security_analysis['risk_level'] = 'MEDIUM'
            else:
                security_analysis['risk_level'] = 'LOW'
            
            # Generate summary
            security_analysis['analysis_summary'] = {
                'total_permissions': len(permissions),
                'dangerous_permissions': len([p for p in permissions if p.get('is_dangerous', False)]),
                'total_components': len(components),
                'exported_components': len([c for c in components if c.get('exported', False)]),
                'certificate_count': len(analysis_data.get('certificates', [])),
                'has_manifest_analysis': 'manifest_analysis' in analysis_data
            }
            
            return security_analysis
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            security_analysis['error'] = str(e)
            return security_analysis
    
    def _analyze_permissions_risk(self, permissions: List[Dict[str, Any]]) -> int:
        """Analyze permissions for security risk."""
        risk_score = 0
        dangerous_count = 0
        
        for perm in permissions:
            if perm.get('is_dangerous', False):
                dangerous_count += 1
                risk_score += 8
        
        # Additional risk for excessive permissions
        if dangerous_count > 10:
            risk_score += 15
        elif dangerous_count > 5:
            risk_score += 8
        
        return min(risk_score, 50)  # Cap at 50
    
    def _analyze_components_risk(self, components: List[Dict[str, Any]]) -> int:
        """Analyze components for security risk."""
        risk_score = 0
        exported_count = 0
        
        for comp in components:
            if comp.get('exported', False):
                exported_count += 1
                risk_score += 3
                
                # Higher risk if no permissions
                if not comp.get('permissions'):
                    risk_score += 5
        
        return min(risk_score, 30)  # Cap at 30
    
    def _analyze_certificates_risk(self, certificates: List[Dict[str, Any]]) -> int:
        """Analyze certificates for security risk."""
        risk_score = 0
        
        for cert in certificates:
            # Check for weak signature algorithms
            sig_alg = cert.get('signature_algorithm', '').lower()
            if 'md5' in sig_alg or 'sha1' in sig_alg:
                risk_score += 15
            
            # Check for debug certificates
            subject = cert.get('subject', '').lower()
            if 'debug' in subject or 'test' in subject:
                risk_score += 20
        
        return min(risk_score, 25)  # Cap at 25

class ManifestParser:
    """
    Comprehensive Android manifest parser for shared infrastructure.
    
    Provides advanced manifest parsing capabilities including binary XML parsing,
    comprehensive permission analysis, component detection, and security assessment.
    Designed for integration with the AODS APK analysis framework.
    """
    
    def __init__(self):
        """Initialize the manifest parser."""
        self.logger = logging.getLogger(__name__)
        
        # Tool availability
        self.aapt_available = shutil.which('aapt') is not None
        self.aapt2_available = shutil.which('aapt2') is not None
        
        # Load dangerous permissions
        self.dangerous_permissions = self._load_dangerous_permissions()
        
        # Security-critical permission patterns
        self.critical_permissions = {
            'SYSTEM_LEVEL': [
                'android.permission.WRITE_SECURE_SETTINGS',
                'android.permission.INSTALL_PACKAGES',
                'android.permission.DELETE_PACKAGES',
                'android.permission.CLEAR_APP_CACHE',
                'android.permission.CLEAR_APP_USER_DATA',
                'android.permission.FORCE_STOP_PACKAGES'
            ],
            'PRIVACY_SENSITIVE': [
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.READ_CALL_LOG',
                'android.permission.WRITE_CALL_LOG',
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.RECEIVE_SMS',
                'android.permission.READ_PHONE_STATE',
                'android.permission.CALL_PHONE',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO'
            ],
            'NETWORK_ACCESS': [
                'android.permission.INTERNET',
                'android.permission.ACCESS_NETWORK_STATE',
                'android.permission.ACCESS_WIFI_STATE',
                'android.permission.CHANGE_WIFI_STATE',
                'android.permission.CHANGE_NETWORK_STATE'
            ],
            'STORAGE_ACCESS': [
                'android.permission.WRITE_EXTERNAL_STORAGE',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.MANAGE_EXTERNAL_STORAGE'
            ]
        }
        
        # Component security patterns
        self.risky_component_patterns = [
            'backup', 'debug', 'test', 'dev', 'admin', 'root', 'su', 'shell'
        ]
        
        # Intent filter security concerns
        self.sensitive_intent_actions = [
            'android.intent.action.BOOT_COMPLETED',
            'android.intent.action.DEVICE_ADMIN_ENABLED',
            'android.intent.action.NEW_OUTGOING_CALL',
            'android.intent.action.PHONE_STATE',
            'android.intent.action.SMS_RECEIVED',
            'android.intent.action.PACKAGE_INSTALL',
            'android.intent.action.PACKAGE_REPLACED'
        ]
        
        self.logger.info("ManifestParser initialized with enhanced security analysis capabilities")
    
    def parse_manifest(self, apk_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """
        Parse Android manifest and extract comprehensive information.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Optional[Dict[str, Any]]: Comprehensive manifest analysis results
        """
        apk_path = Path(apk_path)
        
        try:
            # Try AAPT-based parsing first (most reliable)
            if self.aapt_available or self.aapt2_available:
                result = self._parse_with_aapt(apk_path)
                if result:
                    self.logger.info("Manifest parsed successfully with AAPT")
                    return result
            
            # Fallback to binary XML parsing
            result = self._parse_binary_manifest(apk_path)
            if result:
                self.logger.info("Manifest parsed with binary XML parser")
                return result
            
            # Last resort: basic ZIP content analysis
            result = self._parse_fallback(apk_path)
            if result:
                self.logger.warning("Manifest parsed with fallback method - limited data available")
                return result
            
            self.logger.error("All manifest parsing methods failed")
            return None
            
        except Exception as e:
            self.logger.error(f"Manifest parsing failed: {e}")
            return None
    
    def _parse_with_aapt(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse manifest using AAPT tool for comprehensive analysis."""
        try:
            result = {
                'metadata': {},
                'permissions': [],
                'components': [],
                'features': [],
                'security_analysis': {},
                'intent_filters': [],
                'parsing_method': 'AAPT'
            }
            
            # Extract basic metadata
            metadata = self._extract_metadata_with_aapt(apk_path)
            if metadata:
                result['metadata'] = {
                    'package_name': metadata.package_name,
                    'version_name': metadata.version_name,
                    'version_code': metadata.version_code,
                    'min_sdk_version': metadata.min_sdk_version,
                    'target_sdk_version': metadata.target_sdk_version,
                    'app_name': metadata.app_name,
                    'main_activity': metadata.main_activity
                }
            
            # Extract permissions with detailed analysis
            permissions = self._extract_permissions_with_aapt(apk_path)
            result['permissions'] = permissions
            
            # Extract components with security analysis
            components = self._extract_components_with_aapt(apk_path)
            result['components'] = components
            
            # Extract features and uses-sdk information
            features = self._extract_features_with_aapt(apk_path)
            result['features'] = features
            
            # Perform security analysis
            result['security_analysis'] = self._analyze_manifest_security(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"AAPT-based parsing failed: {e}")
            return None
    
    def _parse_binary_manifest(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse binary manifest with comprehensive binary XML parsing."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                
                # Comprehensive binary XML parsing implementation
                parser = AndroidBinaryXMLParser(manifest_data)
                parsed_manifest = parser.parse()
                
                if parsed_manifest:
                    return self._extract_manifest_metadata(parsed_manifest)
                else:
                    # Fallback to AAPT parsing if binary parsing fails
                    return self._parse_manifest_with_aapt(apk_path)
                
        except Exception as e:
            self.logger.warning(f"Binary manifest parsing failed: {e}")
            # Fallback to AAPT parsing
            return self._parse_manifest_with_aapt(apk_path)
    
    def _parse_binary_manifest_detailed(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """Parse binary manifest for detailed information including permissions and components."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                manifest_data = zf.read('AndroidManifest.xml')
                
                # Comprehensive binary XML parsing for detailed analysis
                parser = AndroidBinaryXMLParser(manifest_data)
                parsed_manifest = parser.parse()
                
                if parsed_manifest:
                    detailed_info = {
                        'permissions': self._extract_permissions(parsed_manifest),
                        'components': self._extract_components(parsed_manifest),
                        'metadata': self._extract_application_metadata(parsed_manifest),
                        'services': self._extract_services(parsed_manifest),
                        'receivers': self._extract_receivers(parsed_manifest),
                        'providers': self._extract_providers(parsed_manifest),
                        'intent_filters': self._extract_intent_filters(parsed_manifest),
                        'features': self._extract_features(parsed_manifest),
                        'instrumentation': self._extract_instrumentation(parsed_manifest)
                    }
                    return detailed_info
                else:
                    # Fallback to AAPT for detailed parsing
                    return self._parse_detailed_with_aapt(apk_path)
                
        except Exception as e:
            self.logger.error(f"Detailed binary manifest parsing failed: {e}")
            return self._parse_detailed_with_aapt(apk_path)
    
    def _parse_detailed_with_aapt(self, apk_path: Path) -> Dict[str, Any]:
        """Fallback detailed parsing using AAPT tool."""
        try:
            import subprocess
            
            # Use aapt to extract detailed manifest information
            detailed_info = {
                'permissions': [],
                'components': [],
                'metadata': {},
                'services': [],
                'receivers': [],
                'providers': [],
                'intent_filters': [],
                'features': [],
                'instrumentation': []
            }
            
            # Extract permissions
            perm_cmd = ['aapt', 'dump', 'permissions', str(apk_path)]
            perm_result = subprocess.run(perm_cmd, capture_output=True, text=True, timeout=30)
            if perm_result.returncode == 0:
                detailed_info['permissions'] = self._parse_aapt_permissions(perm_result.stdout)
            
            # Extract other manifest details
            xmltree_cmd = ['aapt', 'dump', 'xmltree', str(apk_path), 'AndroidManifest.xml']
            tree_result = subprocess.run(xmltree_cmd, capture_output=True, text=True, timeout=30)
            if tree_result.returncode == 0:
                manifest_details = self._parse_aapt_xmltree(tree_result.stdout)
                detailed_info.update(manifest_details)
            
            return detailed_info
            
        except Exception as e:
            self.logger.error(f"AAPT detailed parsing failed: {e}")
            return {
                'permissions': [],
                'components': [],
                'metadata': {},
                'services': [],
                'receivers': [],
                'providers': [],
                'intent_filters': [],
                'features': [],
                'instrumentation': []
            }
    
    def _extract_manifest_metadata(self, parsed_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic metadata from parsed manifest."""
        manifest_tag = parsed_manifest.get('manifest', {})
        
        return {
            'package': manifest_tag.get('package', 'unknown'),
            'versionName': manifest_tag.get('versionName', 'unknown'),
            'versionCode': manifest_tag.get('versionCode', '0'),
            'minSdkVersion': self._get_min_sdk_version(parsed_manifest),
            'targetSdkVersion': self._get_target_sdk_version(parsed_manifest),
            'compileSdkVersion': manifest_tag.get('compileSdkVersion', 'unknown'),
            'installLocation': manifest_tag.get('installLocation', 'auto')
        }
    
    def _extract_permissions(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract permissions from parsed manifest."""
        permissions = []
        
        # Extract uses-permission tags
        uses_permissions = parsed_manifest.get('uses-permission', [])
        if not isinstance(uses_permissions, list):
            uses_permissions = [uses_permissions]
        
        for perm in uses_permissions:
            if isinstance(perm, dict):
                permissions.append({
                    'name': perm.get('name', ''),
                    'type': 'uses-permission',
                    'maxSdkVersion': perm.get('maxSdkVersion'),
                    'required': perm.get('required', True)
                })
        
        # Extract permission tags (custom permissions)
        custom_permissions = parsed_manifest.get('permission', [])
        if not isinstance(custom_permissions, list):
            custom_permissions = [custom_permissions]
        
        for perm in custom_permissions:
            if isinstance(perm, dict):
                permissions.append({
                    'name': perm.get('name', ''),
                    'type': 'permission',
                    'protectionLevel': perm.get('protectionLevel', 'normal'),
                    'permissionGroup': perm.get('permissionGroup'),
                    'label': perm.get('label'),
                    'description': perm.get('description')
                })
        
        return permissions
    
    def _extract_components(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract components (activities, services, etc.) from parsed manifest."""
        components = []
        
        application = parsed_manifest.get('application', {})
        if not application:
            return components
        
        # Extract activities
        activities = application.get('activity', [])
        if not isinstance(activities, list):
            activities = [activities]
        
        for activity in activities:
            if isinstance(activity, dict):
                components.append({
                    'type': 'activity',
                    'name': activity.get('name', ''),
                    'exported': activity.get('exported', False),
                    'enabled': activity.get('enabled', True),
                    'label': activity.get('label'),
                    'theme': activity.get('theme'),
                    'launchMode': activity.get('launchMode'),
                    'intent_filters': self._extract_component_intent_filters(activity)
                })
        
        # Extract services
        services = application.get('service', [])
        if not isinstance(services, list):
            services = [services]
        
        for service in services:
            if isinstance(service, dict):
                components.append({
                    'type': 'service',
                    'name': service.get('name', ''),
                    'exported': service.get('exported', False),
                    'enabled': service.get('enabled', True),
                    'permission': service.get('permission'),
                    'process': service.get('process'),
                    'intent_filters': self._extract_component_intent_filters(service)
                })
        
        return components
    
    def _extract_services(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract services from parsed manifest."""
        services = []
        application = parsed_manifest.get('application', {})
        
        service_list = application.get('service', [])
        if not isinstance(service_list, list):
            service_list = [service_list]
        
        for service in service_list:
            if isinstance(service, dict):
                services.append({
                    'name': service.get('name', ''),
                    'exported': service.get('exported', False),
                    'enabled': service.get('enabled', True),
                    'permission': service.get('permission'),
                    'process': service.get('process'),
                    'isolatedProcess': service.get('isolatedProcess', False),
                    'stopWithTask': service.get('stopWithTask', True)
                })
        
        return services
    
    def _extract_receivers(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract broadcast receivers from parsed manifest."""
        receivers = []
        application = parsed_manifest.get('application', {})
        
        receiver_list = application.get('receiver', [])
        if not isinstance(receiver_list, list):
            receiver_list = [receiver_list]
        
        for receiver in receiver_list:
            if isinstance(receiver, dict):
                receivers.append({
                    'name': receiver.get('name', ''),
                    'exported': receiver.get('exported', False),
                    'enabled': receiver.get('enabled', True),
                    'permission': receiver.get('permission'),
                    'priority': receiver.get('priority', 0),
                    'intent_filters': self._extract_component_intent_filters(receiver)
                })
        
        return receivers
    
    def _extract_providers(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract content providers from parsed manifest."""
        providers = []
        application = parsed_manifest.get('application', {})
        
        provider_list = application.get('provider', [])
        if not isinstance(provider_list, list):
            provider_list = [provider_list]
        
        for provider in provider_list:
            if isinstance(provider, dict):
                providers.append({
                    'name': provider.get('name', ''),
                    'authorities': provider.get('authorities', ''),
                    'exported': provider.get('exported', False),
                    'enabled': provider.get('enabled', True),
                    'permission': provider.get('permission'),
                    'readPermission': provider.get('readPermission'),
                    'writePermission': provider.get('writePermission'),
                    'grantUriPermissions': provider.get('grantUriPermissions', False)
                })
        
        return providers
    
    def _extract_application_metadata(self, parsed_manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Extract application metadata from parsed manifest."""
        application = parsed_manifest.get('application', {})
        
        metadata = {
            'name': application.get('name'),
            'label': application.get('label'),
            'icon': application.get('icon'),
            'theme': application.get('theme'),
            'debuggable': application.get('debuggable', False),
            'allowBackup': application.get('allowBackup', True),
            'allowClearUserData': application.get('allowClearUserData', True),
            'hardwareAccelerated': application.get('hardwareAccelerated', False),
            'largeHeap': application.get('largeHeap', False),
            'usesCleartextTraffic': application.get('usesCleartextTraffic', True),
            'networkSecurityConfig': application.get('networkSecurityConfig'),
            'requestLegacyExternalStorage': application.get('requestLegacyExternalStorage', False)
        }
        
        # Extract meta-data tags
        meta_data_list = application.get('meta-data', [])
        if not isinstance(meta_data_list, list):
            meta_data_list = [meta_data_list]
        
        metadata['meta_data'] = []
        for meta_data in meta_data_list:
            if isinstance(meta_data, dict):
                metadata['meta_data'].append({
                    'name': meta_data.get('name', ''),
                    'value': meta_data.get('value'),
                    'resource': meta_data.get('resource')
                })
        
        return metadata
    
    def _extract_intent_filters(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract intent filters from parsed manifest."""
        intent_filters = []
        application = parsed_manifest.get('application', {})
        
        # Search all components for intent filters
        for component_type in ['activity', 'service', 'receiver']:
            components = application.get(component_type, [])
            if not isinstance(components, list):
                components = [components]
            
            for component in components:
                if isinstance(component, dict):
                    component_filters = self._extract_component_intent_filters(component)
                    for filter_info in component_filters:
                        filter_info['component'] = component.get('name', '')
                        filter_info['component_type'] = component_type
                        intent_filters.append(filter_info)
        
        return intent_filters
    
    def _extract_features(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract uses-feature tags from parsed manifest."""
        features = []
        
        feature_list = parsed_manifest.get('uses-feature', [])
        if not isinstance(feature_list, list):
            feature_list = [feature_list]
        
        for feature in feature_list:
            if isinstance(feature, dict):
                features.append({
                    'name': feature.get('name', ''),
                    'required': feature.get('required', True),
                    'glEsVersion': feature.get('glEsVersion')
                })
        
        return features
    
    def _extract_instrumentation(self, parsed_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract instrumentation tags from parsed manifest."""
        instrumentation = []
        
        instrumentation_list = parsed_manifest.get('instrumentation', [])
        if not isinstance(instrumentation_list, list):
            instrumentation_list = [instrumentation_list]
        
        for instr in instrumentation_list:
            if isinstance(instr, dict):
                instrumentation.append({
                    'name': instr.get('name', ''),
                    'targetPackage': instr.get('targetPackage', ''),
                    'label': instr.get('label'),
                    'handleProfiling': instr.get('handleProfiling', False),
                    'functionalTest': instr.get('functionalTest', False)
                })
        
        return instrumentation
    
    def _extract_component_intent_filters(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract intent filters from a component."""
        intent_filters = []
        
        filter_list = component.get('intent-filter', [])
        if not isinstance(filter_list, list):
            filter_list = [filter_list]
        
        for intent_filter in filter_list:
            if isinstance(intent_filter, dict):
                filter_info = {
                    'actions': [],
                    'categories': [],
                    'data': [],
                    'priority': intent_filter.get('priority', 0)
                }
                
                # Extract actions
                actions = intent_filter.get('action', [])
                if not isinstance(actions, list):
                    actions = [actions]
                for action in actions:
                    if isinstance(action, dict):
                        filter_info['actions'].append(action.get('name', ''))
                
                # Extract categories
                categories = intent_filter.get('category', [])
                if not isinstance(categories, list):
                    categories = [categories]
                for category in categories:
                    if isinstance(category, dict):
                        filter_info['categories'].append(category.get('name', ''))
                
                # Extract data
                data_list = intent_filter.get('data', [])
                if not isinstance(data_list, list):
                    data_list = [data_list]
                for data in data_list:
                    if isinstance(data, dict):
                        filter_info['data'].append({
                            'scheme': data.get('scheme'),
                            'host': data.get('host'),
                            'port': data.get('port'),
                            'path': data.get('path'),
                            'pathPattern': data.get('pathPattern'),
                            'pathPrefix': data.get('pathPrefix'),
                            'mimeType': data.get('mimeType')
                        })
                
                intent_filters.append(filter_info)
        
        return intent_filters
    
    def _parse_certificate(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Parse certificate data from APK signature."""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning("Cryptography library not available for certificate parsing")
            return None
        
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.serialization import pkcs7
            from cryptography import x509
            import hashlib
            
            # Try to parse as PKCS#7 structure first
            try:
                # Parse PKCS#7 signature to extract certificate
                pkcs7_data = pkcs7.load_der_pkcs7_certificates(cert_data)
                if pkcs7_data:
                    cert = pkcs7_data[0]  # Get the first certificate
                else:
                    # Fallback: try to parse as X.509 certificate directly
                    cert = x509.load_der_x509_certificate(cert_data)
            except:
                # Last fallback: try PEM format
                try:
                    cert = x509.load_pem_x509_certificate(cert_data)
                except:
                    self.logger.debug("Failed to parse certificate in any format")
                    return None
            
            # Extract certificate information
            subject_name = cert.subject.rfc4514_string()
            issuer_name = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()
            
            # Extract signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name
            
            # Extract public key information
            public_key = cert.public_key()
            public_key_algorithm = public_key.__class__.__name__.replace('PublicKey', '')
            
            # Determine key size
            key_size = 0
            try:
                if hasattr(public_key, 'key_size'):
                    key_size = public_key.key_size
                elif hasattr(public_key, 'curve'):
                    key_size = public_key.curve.key_size
            except:
                pass
            
            # Calculate fingerprints
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            fingerprint_md5 = hashlib.md5(cert_der).hexdigest()
            fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
            fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
            
            return CertificateInfo(
                subject=subject_name,
                issuer=issuer_name,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=signature_algorithm,
                public_key_algorithm=public_key_algorithm,
                key_size=key_size,
                fingerprint_md5=fingerprint_md5,
                fingerprint_sha1=fingerprint_sha1,
                fingerprint_sha256=fingerprint_sha256
            )
            
        except Exception as e:
            self.logger.debug(f"Certificate parsing failed: {e}")
            return None
    
    def _parse_components_from_aapt_xml(self, xml_output: str) -> List[ManifestComponent]:
        """Parse components from AAPT XML output."""
        components = []
        
        # This would parse the AAPT XML tree output
        # Implementation would be specific to AAPT output format
        
        return components
    
    def _parse_architecture(self, arch_str: str) -> ArchitectureType:
        """Parse architecture type from string."""
        arch_mapping = {
            'armeabi': ArchitectureType.ARM,
            'armeabi-v7a': ArchitectureType.ARM,
            'arm64-v8a': ArchitectureType.ARM64,
            'x86': ArchitectureType.X86,
            'x86_64': ArchitectureType.X86_64,
            'mips': ArchitectureType.MIPS,
            'mips64': ArchitectureType.MIPS64
        }
        
        return arch_mapping.get(arch_str, ArchitectureType.UNKNOWN)
    
    def _calculate_file_hashes(self, file_path: Path) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes of file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    def _load_dangerous_permissions(self) -> Set[str]:
        """Load list of dangerous Android permissions."""
        return {
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.ADD_VOICEMAIL',
            'android.permission.USE_SIP',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.BODY_SENSORS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_WAP_PUSH',
            'android.permission.RECEIVE_MMS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        }
    
    def _extract_metadata_with_aapt(self, apk_path: Path) -> Optional[APKMetadata]:
        """Extract metadata using AAPT tool (reused from APKParser)."""
        try:
            cmd = ['aapt', 'dump', 'badging', str(apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return None
            
            output = result.stdout
            
            # Parse AAPT output
            package_match = re.search(r"package: name='([^']+)'", output)
            version_name_match = re.search(r"versionName='([^']+)'", output)
            version_code_match = re.search(r"versionCode='([^']+)'", output)
            min_sdk_match = re.search(r"sdkVersion:'([^']+)'", output)
            target_sdk_match = re.search(r"targetSdkVersion:'([^']+)'", output)
            app_name_match = re.search(r"application-label:'([^']+)'", output)
            main_activity_match = re.search(r"launchable-activity: name='([^']+)'", output)
            
            return APKMetadata(
                package_name=package_match.group(1) if package_match else 'unknown',
                version_name=version_name_match.group(1) if version_name_match else 'unknown',
                version_code=int(version_code_match.group(1)) if version_code_match else 0,
                min_sdk_version=int(min_sdk_match.group(1)) if min_sdk_match else 1,
                target_sdk_version=int(target_sdk_match.group(1)) if target_sdk_match else 1,
                app_name=app_name_match.group(1) if app_name_match else None,
                main_activity=main_activity_match.group(1) if main_activity_match else None
            )
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
            return None

@dataclass
class CertificateInfo:
    """Container for certificate information."""
    subject: str
    issuer: str
    serial_number: str
    version: int
    signature_algorithm: str
    not_before: str
    not_after: str
    is_self_signed: bool
    key_size: int
    fingerprint_md5: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    extensions: Dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)

class CertificateAnalyzer:
    """
    Comprehensive certificate analysis and validation.
    
    Provides detailed certificate inspection, validation, and security analysis
    for APK signing certificates with enhanced security assessment capabilities.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crypto_available = CRYPTOGRAPHY_AVAILABLE
        
        # Security thresholds
        self.min_key_size = 2048
        self.weak_algorithms = {
            'md5', 'sha1', 'md2', 'md4'
        }
        self.deprecated_algorithms = {
            'sha1withRSA', 'md5withRSA', 'md2withRSA'
        }
    
    def analyze_apk_certificates(self, apk_path: Path) -> List[CertificateInfo]:
        """
        Analyze all certificates in an APK file.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            List of CertificateInfo objects for all certificates found
        """
        certificates = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for certificate files in META-INF
                cert_files = [f for f in apk_zip.namelist() 
                             if f.startswith('META-INF/') and 
                             (f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC'))]
                
                for cert_file in cert_files:
                    try:
                        cert_data = apk_zip.read(cert_file)
                        cert_info = self._parse_certificate_data(cert_data)
                        if cert_info:
                            certificates.append(cert_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to parse certificate {cert_file}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to analyze certificates in {apk_path}: {e}")
            
        return certificates
    
    def validate_certificate_security(self, cert_info: CertificateInfo) -> Dict[str, Any]:
        """
        Validate certificate security properties.
        
        Args:
            cert_info: Certificate information to validate
            
        Returns:
            Security validation results
        """
        validation = {
            'is_secure': True,
            'security_score': 100,
            'issues': [],
            'recommendations': []
        }
        
        # Check key size
        if cert_info.key_size < self.min_key_size:
            validation['is_secure'] = False
            validation['security_score'] -= 30
            validation['issues'].append(f"Weak key size: {cert_info.key_size} bits")
            validation['recommendations'].append(f"Use at least {self.min_key_size}-bit keys")
        
        # Check signature algorithm
        algorithm = cert_info.signature_algorithm.lower()
        if any(weak in algorithm for weak in self.weak_algorithms):
            validation['is_secure'] = False
            validation['security_score'] -= 40
            validation['issues'].append(f"Weak signature algorithm: {cert_info.signature_algorithm}")
            validation['recommendations'].append("Use SHA-256 or stronger signature algorithms")
        
        elif algorithm in self.deprecated_algorithms:
            validation['security_score'] -= 20
            validation['issues'].append(f"Deprecated signature algorithm: {cert_info.signature_algorithm}")
            validation['recommendations'].append("Migrate to SHA-256 or stronger algorithms")
        
        # Check certificate validity period
        try:
            import datetime
            not_after = datetime.datetime.strptime(cert_info.not_after, '%Y-%m-%d %H:%M:%S')
            days_until_expiry = (not_after - datetime.datetime.now()).days
            
            if days_until_expiry < 0:
                validation['is_secure'] = False
                validation['security_score'] -= 50
                validation['issues'].append("Certificate has expired")
                validation['recommendations'].append("Renew the certificate immediately")
            elif days_until_expiry < 30:
                validation['security_score'] -= 15
                validation['issues'].append(f"Certificate expires soon: {days_until_expiry} days")
                validation['recommendations'].append("Plan certificate renewal")
        except Exception:
            validation['issues'].append("Could not validate certificate expiry")
        
        # Check for self-signed certificates
        if cert_info.is_self_signed:
            validation['security_score'] -= 10
            validation['issues'].append("Certificate is self-signed")
            validation['recommendations'].append("Consider using CA-signed certificates for production")
        
        return validation
    
    def _parse_certificate_data(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Parse certificate data and extract information."""
        if not self.crypto_available:
            return self._parse_certificate_fallback(cert_data)
        
        try:
            # Try to parse as PKCS#7/PKCS#12 first
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs7
            
            try:
                # Try PKCS#7 format first
                cert_collection = pkcs7.load_der_pkcs7_certificates(cert_data)
                if cert_collection:
                    certificate = cert_collection[0]
                else:
                    return None
            except Exception:
                # Try direct certificate parsing
                try:
                    certificate = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    # Try PEM format
                    try:
                        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                    except Exception:
                        return None
            
            return self._extract_certificate_info(certificate)
            
        except Exception as e:
            self.logger.warning(f"Failed to parse certificate: {e}")
            return self._parse_certificate_fallback(cert_data)
    
    def _extract_certificate_info(self, certificate) -> CertificateInfo:
        """Extract information from a parsed certificate."""
        try:
            # Basic certificate information
            subject = certificate.subject.rfc4514_string()
            issuer = certificate.issuer.rfc4514_string()
            serial_number = str(certificate.serial_number)
            version = certificate.version.value
            signature_algorithm = certificate.signature_algorithm_oid._name
            
            # Validity period
            not_before = certificate.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
            not_after = certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
            
            # Check if self-signed
            is_self_signed = subject == issuer
            
            # Extract public key information
            public_key = certificate.public_key()
            key_size = public_key.key_size if hasattr(public_key, 'key_size') else 0
            
            # Generate fingerprints
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            fingerprint_md5 = hashlib.md5(cert_der).hexdigest()
            fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
            fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
            
            # Extract extensions
            extensions = {}
            for ext in certificate.extensions:
                try:
                    extensions[ext.oid._name] = str(ext.value)
                except Exception:
                    extensions[ext.oid._name] = "Could not parse extension"
            
            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                version=version,
                signature_algorithm=signature_algorithm,
                not_before=not_before,
                not_after=not_after,
                is_self_signed=is_self_signed,
                key_size=key_size,
                fingerprint_md5=fingerprint_md5,
                fingerprint_sha1=fingerprint_sha1,
                fingerprint_sha256=fingerprint_sha256,
                extensions=extensions
            )
            
        except Exception as e:
            self.logger.error(f"Failed to extract certificate info: {e}")
            return None
    
    def _parse_certificate_fallback(self, cert_data: bytes) -> Optional[CertificateInfo]:
        """Fallback certificate parsing when cryptography library is unavailable."""
        try:
            # Basic parsing using openssl command if available
            if shutil.which('openssl'):
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(cert_data)
                    temp_path = temp_file.name
                
                try:
                    # Extract certificate info using openssl
                    cmd = ['openssl', 'pkcs7', '-inform', 'DER', '-in', temp_path, '-print_certs', '-text']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        return self._parse_openssl_output(result.stdout)
                    
                finally:
                    os.unlink(temp_path)
            
            # Minimal fallback - just compute hashes
            return CertificateInfo(
                subject="Unknown (parsing failed)",
                issuer="Unknown (parsing failed)",
                serial_number="Unknown",
                version=0,
                signature_algorithm="Unknown",
                not_before="Unknown",
                not_after="Unknown",
                is_self_signed=False,
                key_size=0,
                fingerprint_md5=hashlib.md5(cert_data).hexdigest(),
                fingerprint_sha1=hashlib.sha1(cert_data).hexdigest(),
                fingerprint_sha256=hashlib.sha256(cert_data).hexdigest(),
                is_valid=False,
                validation_errors=["Certificate parsing failed - cryptography library unavailable"]
            )
            
        except Exception as e:
            self.logger.error(f"Fallback certificate parsing failed: {e}")
            return None
    
    def _parse_openssl_output(self, output: str) -> Optional[CertificateInfo]:
        """Parse openssl command output to extract certificate information."""
        try:
            # Extract basic information using regex
            subject_match = re.search(r'Subject:\s*(.+)', output)
            issuer_match = re.search(r'Issuer:\s*(.+)', output)
            serial_match = re.search(r'Serial Number:\s*([a-fA-F0-9:]+)', output)
            algorithm_match = re.search(r'Signature Algorithm:\s*(.+)', output)
            not_before_match = re.search(r'Not Before:\s*(.+)', output)
            not_after_match = re.search(r'Not After:\s*(.+)', output)
            
            subject = subject_match.group(1).strip() if subject_match else "Unknown"
            issuer = issuer_match.group(1).strip() if issuer_match else "Unknown"
            
            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_match.group(1) if serial_match else "Unknown",
                version=3,  # Assume X.509 v3
                signature_algorithm=algorithm_match.group(1) if algorithm_match else "Unknown",
                not_before=not_before_match.group(1) if not_before_match else "Unknown",
                not_after=not_after_match.group(1) if not_after_match else "Unknown",
                is_self_signed=subject == issuer,
                key_size=0,  # Cannot determine from openssl text output
                fingerprint_md5="",
                fingerprint_sha1="",
                fingerprint_sha256="",
                is_valid=True,
                validation_errors=["Limited parsing - using openssl fallback"]
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse openssl output: {e}")
            return None

@dataclass 
class NativeLibraryInfo:
    """Container for native library information."""
    name: str
    path: str
    architecture: ArchitectureType
    file_size: int
    file_hash: str
    is_stripped: bool
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    
@dataclass
class DEXInfo:
    """Container for DEX file information."""
    file_path: str
    file_size: int
    file_hash: str
    classes_count: int
    methods_count: int 
    strings_count: int
    api_level: int
    security_issues: List[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    encryption_detected: bool = False

class DEXAnalyzer:
    """
    Comprehensive DEX file analysis and inspection.
    
    Provides detailed DEX file analysis including class enumeration, method analysis,
    obfuscation detection, and security issue identification.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.obfuscation_patterns = [
            r'[a-z]{1,2}',  # Single/double character class names
            r'[A-Z][a-z]?',  # Proguard-style names
            r'[0-9]+',       # Numeric class names
            r'[a-zA-Z0-9]{32,}',  # Very long random names
        ]
        
        # Security-related class patterns
        self.security_patterns = {
            'crypto': [
                r'javax\.crypto\.',
                r'java\.security\.',
                r'android\.security\.'
            ],
            'network': [
                r'java\.net\.',
                r'android\.net\.',
                r'org\.apache\.http\.'
            ],
            'reflection': [
                r'java\.lang\.reflect\.',
                r'java\.lang\.Class'
            ],
            'native': [
                r'java\.lang\.System\.loadLibrary',
                r'java\.lang\.Runtime\.exec'
            ]
        }
    
    def analyze_apk_dex_files(self, apk_path: Path) -> List[DEXInfo]:
        """
        Analyze all DEX files in an APK.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            List of DEXInfo objects for all DEX files found
        """
        dex_files = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Find all DEX files
                dex_file_names = [f for f in apk_zip.namelist() 
                                 if f.endswith('.dex')]
                
                for dex_file in dex_file_names:
                    try:
                        dex_data = apk_zip.read(dex_file)
                        dex_info = self._analyze_dex_data(dex_file, dex_data)
                        if dex_info:
                            dex_files.append(dex_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to analyze DEX file {dex_file}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to analyze DEX files in {apk_path}: {e}")
            
        return dex_files
    
    def detect_obfuscation(self, dex_info: DEXInfo, class_names: List[str]) -> Dict[str, Any]:
        """
        Detect obfuscation in DEX file based on class names and structure.
        
        Args:
            dex_info: DEX file information
            class_names: List of class names extracted from DEX
            
        Returns:
            Obfuscation analysis results
        """
        if not class_names:
            return {'obfuscated': False, 'confidence': 0.0, 'indicators': []}
        
        indicators = []
        obfuscated_count = 0
        
        for class_name in class_names:
            # Remove package prefix for analysis
            simple_name = class_name.split('.')[-1] if '.' in class_name else class_name
            
            for pattern in self.obfuscation_patterns:
                if re.fullmatch(pattern, simple_name):
                    obfuscated_count += 1
                    break
        
        obfuscation_ratio = obfuscated_count / len(class_names)
        
        # Determine obfuscation level
        if obfuscation_ratio > 0.7:
            indicators.append("High ratio of obfuscated class names")
            confidence = 0.9
            obfuscated = True
        elif obfuscation_ratio > 0.4:
            indicators.append("Medium ratio of obfuscated class names")
            confidence = 0.6
            obfuscated = True
        elif obfuscation_ratio > 0.1:
            indicators.append("Low ratio of obfuscated class names")
            confidence = 0.3
            obfuscated = False
        else:
            confidence = 0.0
            obfuscated = False
        
        # Additional heuristics
        avg_name_length = sum(len(name.split('.')[-1]) for name in class_names) / len(class_names)
        if avg_name_length < 3:
            indicators.append("Very short class names detected")
            confidence += 0.2
            obfuscated = True
        
        return {
            'obfuscated': obfuscated,
            'confidence': min(confidence, 1.0),
            'obfuscation_ratio': obfuscation_ratio,
            'indicators': indicators,
            'total_classes': len(class_names),
            'obfuscated_classes': obfuscated_count
        }
    
    def analyze_security_patterns(self, class_names: List[str]) -> Dict[str, List[str]]:
        """
        Analyze security-related patterns in class names.
        
        Args:
            class_names: List of class names to analyze
            
        Returns:
            Dictionary mapping security categories to found patterns
        """
        security_findings = {category: [] for category in self.security_patterns}
        
        for class_name in class_names:
            for category, patterns in self.security_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, class_name):
                        if class_name not in security_findings[category]:
                            security_findings[category].append(class_name)
        
        return security_findings
    
    def _analyze_dex_data(self, file_path: str, dex_data: bytes) -> Optional[DEXInfo]:
        """Analyze DEX file data and extract information."""
        try:
            # Calculate basic metrics
            file_size = len(dex_data)
            file_hash = hashlib.sha256(dex_data).hexdigest()
            
            # Try to parse DEX header
            dex_info = self._parse_dex_header(dex_data)
            if not dex_info:
                return None
            
            # Enhanced analysis using external tools if available
            enhanced_info = self._enhanced_dex_analysis(file_path, dex_data)
            if enhanced_info:
                dex_info.update(enhanced_info)
            
            return DEXInfo(
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                classes_count=dex_info.get('classes_count', 0),
                methods_count=dex_info.get('methods_count', 0),
                strings_count=dex_info.get('strings_count', 0),
                api_level=dex_info.get('api_level', 1),
                security_issues=dex_info.get('security_issues', []),
                obfuscation_detected=dex_info.get('obfuscation_detected', False),
                encryption_detected=dex_info.get('encryption_detected', False)
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze DEX data: {e}")
            return None
    
    def _parse_dex_header(self, dex_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DEX file header to extract basic information."""
        try:
            if len(dex_data) < 112:  # Minimum DEX header size
                return None
            
            # Check DEX magic number
            magic = dex_data[:8]
            if not magic.startswith(b'dex\n'):
                return None
            
            # Extract version
            version = magic[4:7].decode('ascii')
            
            # Parse header fields (little-endian)
            import struct
            
            # File size (offset 32)
            file_size = struct.unpack('<I', dex_data[32:36])[0]
            
            # String IDs size (offset 56) 
            string_ids_size = struct.unpack('<I', dex_data[56:60])[0]
            
            # Type IDs size (offset 64)
            type_ids_size = struct.unpack('<I', dex_data[64:68])[0]
            
            # Proto IDs size (offset 72)
            proto_ids_size = struct.unpack('<I', dex_data[72:76])[0]
            
            # Field IDs size (offset 80)
            field_ids_size = struct.unpack('<I', dex_data[80:84])[0]
            
            # Method IDs size (offset 88)
            method_ids_size = struct.unpack('<I', dex_data[88:92])[0]
            
            # Class defs size (offset 96)
            class_defs_size = struct.unpack('<I', dex_data[96:100])[0]
            
            return {
                'version': version,
                'file_size': file_size,
                'strings_count': string_ids_size,
                'classes_count': class_defs_size,
                'methods_count': method_ids_size,
                'api_level': 1,  # Default, would need more parsing to determine
                'security_issues': [],
                'obfuscation_detected': False,
                'encryption_detected': False
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to parse DEX header: {e}")
            return None
    
    def _enhanced_dex_analysis(self, file_path: str, dex_data: bytes) -> Optional[Dict[str, Any]]:
        """Enhanced DEX analysis using external tools if available."""
        enhanced_info = {}
        
        # Try using dexdump if available
        if shutil.which('dexdump'):
            try:
                with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as temp_file:
                    temp_file.write(dex_data)
                    temp_path = temp_file.name
                
                try:
                    cmd = ['dexdump', '-d', temp_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        enhanced_info.update(self._parse_dexdump_output(result.stdout))
                        
                finally:
                    os.unlink(temp_path)
                    
            except Exception as e:
                self.logger.debug(f"Enhanced DEX analysis failed: {e}")
        
        # Basic heuristic analysis
        enhanced_info.update(self._heuristic_dex_analysis(dex_data))
        
        return enhanced_info if enhanced_info else None
    
    def _parse_dexdump_output(self, output: str) -> Dict[str, Any]:
        """Parse dexdump output to extract additional information."""
        info = {}
        
        try:
            # Extract class information
            class_matches = re.findall(r'Class descriptor\s*:\s*\'([^\']+)\'', output)
            if class_matches:
                info['class_names'] = class_matches
                
                # Analyze obfuscation
                obfuscation_analysis = self.detect_obfuscation(None, class_matches)
                info['obfuscation_detected'] = obfuscation_analysis['obfuscated']
                
                # Analyze security patterns
                security_patterns = self.analyze_security_patterns(class_matches)
                security_issues = []
                for category, findings in security_patterns.items():
                    if findings:
                        security_issues.append(f"{category.title()} API usage detected: {len(findings)} classes")
                info['security_issues'] = security_issues
            
            # Extract method information
            method_matches = re.findall(r'name\s*:\s*\'([^\']+)\'', output)
            if method_matches:
                info['method_names'] = method_matches
        
        except Exception as e:
            self.logger.warning(f"Failed to parse dexdump output: {e}")
        
        return info
    
    def _heuristic_dex_analysis(self, dex_data: bytes) -> Dict[str, Any]:
        """Heuristic analysis of DEX file without external tools."""
        info = {}
        
        try:
            # Check for encryption/packing indicators
            entropy = self._calculate_entropy(dex_data[:1024])  # Check first 1KB
            if entropy > 7.5:  # High entropy suggests encryption/packing
                info['encryption_detected'] = True
                info['security_issues'] = info.get('security_issues', []) + ['High entropy suggests encryption/packing']
            
            # Look for common obfuscation/packing strings
            obfuscation_indicators = [
                b'ProGuard',
                b'DexGuard', 
                b'allatori',
                b'zelix',
                b'dasho'
            ]
            
            for indicator in obfuscation_indicators:
                if indicator in dex_data:
                    info['obfuscation_detected'] = True
                    info['security_issues'] = info.get('security_issues', []) + [f'Obfuscation tool detected: {indicator.decode("ascii", errors="ignore")}']
                    break
            
        except Exception as e:
            self.logger.debug(f"Heuristic DEX analysis failed: {e}")
        
        return info
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        import math
        from collections import Counter
        
        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

class NativeLibraryAnalyzer:
    """
    Comprehensive native library security analysis.
    
    Provides detailed analysis of native libraries (.so files) in APKs including
    architecture detection, symbol analysis, and security issue identification.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_functions = {
            'crypto': ['AES_encrypt', 'RSA_encrypt', 'MD5_Init', 'SHA1_Init'],
            'network': ['socket', 'connect', 'send', 'recv'],
            'filesystem': ['fopen', 'fwrite', 'fread', 'unlink'],
            'process': ['fork', 'exec', 'system', 'popen'],
            'dangerous': ['gets', 'strcpy', 'sprintf', 'strcat']
        }
    
    def analyze_apk_native_libraries(self, apk_path: Path) -> List[NativeLibraryInfo]:
        """
        Analyze all native libraries in an APK.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            List of NativeLibraryInfo objects for all native libraries found
        """
        libraries = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Find all native libraries
                lib_files = [f for f in apk_zip.namelist() 
                            if f.startswith('lib/') and f.endswith('.so')]
                
                for lib_file in lib_files:
                    try:
                        lib_data = apk_zip.read(lib_file)
                        lib_info = self._analyze_native_library(lib_file, lib_data)
                        if lib_info:
                            libraries.append(lib_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to analyze native library {lib_file}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to analyze native libraries in {apk_path}: {e}")
            
        return libraries
    
    def _analyze_native_library(self, lib_path: str, lib_data: bytes) -> Optional[NativeLibraryInfo]:
        """Analyze individual native library file."""
        try:
            # Extract basic information
            lib_name = os.path.basename(lib_path)
            file_size = len(lib_data)
            file_hash = hashlib.sha256(lib_data).hexdigest()
            
            # Determine architecture from path
            architecture = self._determine_architecture(lib_path)
            
            # Check if stripped
            is_stripped = self._is_library_stripped(lib_data)
            
            # Extract symbols if possible
            exports, imports = self._extract_symbols(lib_data)
            
            # Identify security issues
            security_issues = self._identify_security_issues(exports + imports)
            
            return NativeLibraryInfo(
                name=lib_name,
                path=lib_path,
                architecture=architecture,
                file_size=file_size,
                file_hash=file_hash,
                is_stripped=is_stripped,
                exports=exports,
                imports=imports,
                security_issues=security_issues
            )
            
        except Exception as e:
            self.logger.error(f"Failed to analyze native library: {e}")
            return None
    
    def _determine_architecture(self, lib_path: str) -> ArchitectureType:
        """Determine architecture from library path."""
        path_lower = lib_path.lower()
        
        if '/arm64-v8a/' in path_lower:
            return ArchitectureType.ARM64
        elif '/armeabi-v7a/' in path_lower or '/armeabi/' in path_lower:
            return ArchitectureType.ARM
        elif '/x86_64/' in path_lower:
            return ArchitectureType.X86_64
        elif '/x86/' in path_lower:
            return ArchitectureType.X86
        elif '/mips64/' in path_lower:
            return ArchitectureType.MIPS64
        elif '/mips/' in path_lower:
            return ArchitectureType.MIPS
        else:
            return ArchitectureType.UNKNOWN
    
    def _is_library_stripped(self, lib_data: bytes) -> bool:
        """Check if native library is stripped."""
        try:
            # Look for ELF header
            if len(lib_data) < 64:
                return True
            
            # Check ELF magic
            if lib_data[:4] != b'\x7fELF':
                return True
            
            # Simple heuristic: look for common debug symbols
            debug_indicators = [b'.debug_', b'.symtab', b'.strtab']
            for indicator in debug_indicators:
                if indicator in lib_data:
                    return False
            
            return True
            
        except Exception:
            return True
    
    def _extract_symbols(self, lib_data: bytes) -> Tuple[List[str], List[str]]:
        """Extract exported and imported symbols from library."""
        exports = []
        imports = []
        
        try:
            # Use readelf if available
            if shutil.which('readelf'):
                with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as temp_file:
                    temp_file.write(lib_data)
                    temp_path = temp_file.name
                
                try:
                    # Extract exports
                    cmd = ['readelf', '--dyn-syms', temp_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        exports = self._parse_readelf_symbols(result.stdout, 'export')
                    
                    # Extract imports  
                    cmd = ['readelf', '--dyn-syms', '--use-dynamic', temp_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        imports = self._parse_readelf_symbols(result.stdout, 'import')
                        
                finally:
                    os.unlink(temp_path)
            
            # Fallback: basic string extraction
            if not exports and not imports:
                exports, imports = self._extract_symbols_fallback(lib_data)
                
        except Exception as e:
            self.logger.debug(f"Symbol extraction failed: {e}")
        
        return exports[:100], imports[:100]  # Limit to prevent excessive memory usage
    
    def _parse_readelf_symbols(self, output: str, symbol_type: str) -> List[str]:
        """Parse readelf output to extract symbols."""
        symbols = []
        
        try:
            lines = output.split('\n')
            for line in lines:
                # Look for symbol definitions
                if re.search(r'\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\w+)', line):
                    match = re.search(r'\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\w+)', line)
                    if match:
                        symbol = match.group(1)
                        if symbol and symbol != 'UND':
                            symbols.append(symbol)
        
        except Exception as e:
            self.logger.debug(f"Failed to parse readelf output: {e}")
        
        return symbols
    
    def _extract_symbols_fallback(self, lib_data: bytes) -> Tuple[List[str], List[str]]:
        """Fallback symbol extraction using string analysis."""
        exports = []
        imports = []
        
        try:
            # Extract printable strings
            strings = re.findall(b'[\x20-\x7e]{4,}', lib_data)
            
            for string_bytes in strings[:500]:  # Limit analysis
                try:
                    string = string_bytes.decode('ascii')
                    # Look for function-like names
                    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', string):
                        if any(func in string for func_list in self.security_functions.values() for func in func_list):
                            imports.append(string)
                        elif len(string) > 3 and not string.isupper():
                            exports.append(string)
                except UnicodeDecodeError:
                    continue
        
        except Exception as e:
            self.logger.debug(f"Fallback symbol extraction failed: {e}")
        
        return exports[:50], imports[:50]
    
    def _identify_security_issues(self, symbols: List[str]) -> List[str]:
        """Identify security issues based on symbol analysis."""
        issues = []
        
        for category, functions in self.security_functions.items():
            found_functions = [func for func in functions if any(func in symbol for symbol in symbols)]
            if found_functions:
                if category == 'dangerous':
                    issues.append(f"Dangerous functions detected: {', '.join(found_functions)}")
                else:
                    issues.append(f"{category.title()} functions detected: {len(found_functions)} functions")
        
        return issues

# Global manifest parser instance
_manifest_parser = None

def get_manifest_parser() -> ManifestParser:
    """Get global manifest parser instance."""
    global _manifest_parser
    if _manifest_parser is None:
        _manifest_parser = ManifestParser()
    return _manifest_parser

def parse_manifest(apk_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Parse Android manifest using global parser."""
    return get_manifest_parser().parse_manifest(apk_path)

# Global APK parser instance
_apk_parser = None

def get_apk_parser() -> APKParser:
    """Get global APK parser instance."""
    global _apk_parser
    if _apk_parser is None:
        _apk_parser = APKParser()
    return _apk_parser

def parse_apk(apk_path: Union[str, Path], **kwargs) -> APKAnalysisResult:
    """Parse APK using global parser."""
    return get_apk_parser().parse_apk(apk_path, **kwargs)

def validate_apk(apk_path: Union[str, Path]) -> APKValidationResult:
    """Validate APK structure using global parser."""
    return get_apk_parser().validate_apk_structure(Path(apk_path))

def extract_apk_metadata(apk_path: Union[str, Path]) -> Optional[APKMetadata]:
    """Extract APK metadata using global parser."""
    return get_apk_parser().extract_apk_metadata(Path(apk_path)) 

@dataclass
class APKStructureInfo:
    """Container for APK structure analysis information."""
    total_files: int
    total_size: int
    compression_ratio: float
    file_types: Dict[str, int]
    directory_structure: Dict[str, Any]
    integrity_issues: List[str] = field(default_factory=list)
    suspicious_files: List[str] = field(default_factory=list)
    manifest_present: bool = True
    certificates_present: bool = True
    resources_present: bool = True

@dataclass
class APKSecurityAnalysisResult:
    """Container for comprehensive APK security analysis results."""
    apk_path: str
    overall_security_score: float
    risk_level: str
    certificates: List[CertificateInfo]
    dex_files: List[DEXInfo]
    native_libraries: List[NativeLibraryInfo]
    structure_info: APKStructureInfo
    manifest_analysis: Optional[Dict[str, Any]]
    security_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analysis_timestamp: str = field(default_factory=lambda: time.strftime('%Y-%m-%d %H:%M:%S'))

class APKStructureAnalyzer:
    """
    Comprehensive APK structure and integrity analysis.
    
    Provides detailed analysis of APK file structure, integrity validation,
    and detection of structural anomalies that may indicate tampering or malicious activity.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_file_patterns = [
            r'\.(?:exe|dll|bat|cmd|scr|pif)$',  # Windows executables
            r'\.(?:sh|bash|zsh)$',             # Shell scripts
            r'\.(?:jar|war|ear)$',             # Java archives
            r'META-INF/.*\.(?:jar|zip)$',      # Nested archives in META-INF
            r'classes\d*\.dex\..*',            # Modified DEX files
            r'lib/.*\.(?:a|lib)$',             # Static libraries
        ]
        
        self.expected_directories = {
            'META-INF', 'res', 'assets', 'lib', 'classes.dex', 'AndroidManifest.xml'
        }
        
        self.file_type_extensions = {
            'dex': ['.dex'],
            'native': ['.so'],
            'resource': ['.xml', '.png', '.jpg', '.jpeg', '.gif', '.webp'],
            'asset': [],  # Files in assets/ directory
            'certificate': ['.rsa', '.dsa', '.ec'],
            'manifest': ['AndroidManifest.xml'],
            'other': []
        }
    
    def analyze_apk_structure(self, apk_path: Path) -> APKStructureInfo:
        """
        Analyze APK file structure and integrity.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            APKStructureInfo object with comprehensive structure analysis
        """
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get file listing
                file_list = apk_zip.namelist()
                
                # Calculate basic metrics
                total_files = len(file_list)
                total_size = sum(apk_zip.getinfo(f).file_size for f in file_list)
                compressed_size = sum(apk_zip.getinfo(f).compress_size for f in file_list)
                compression_ratio = compressed_size / total_size if total_size > 0 else 0
                
                # Analyze file types
                file_types = self._categorize_files(file_list)
                
                # Build directory structure
                directory_structure = self._build_directory_structure(file_list)
                
                # Check for integrity issues
                integrity_issues = self._check_integrity_issues(apk_zip, file_list)
                
                # Identify suspicious files
                suspicious_files = self._identify_suspicious_files(file_list)
                
                # Check for required components
                manifest_present = 'AndroidManifest.xml' in file_list
                certificates_present = any(f.startswith('META-INF/') and 
                                         any(f.endswith(ext) for ext in ['.RSA', '.DSA', '.EC']) 
                                         for f in file_list)
                resources_present = any(f.startswith('res/') for f in file_list)
                
                return APKStructureInfo(
                    total_files=total_files,
                    total_size=total_size,
                    compression_ratio=compression_ratio,
                    file_types=file_types,
                    directory_structure=directory_structure,
                    integrity_issues=integrity_issues,
                    suspicious_files=suspicious_files,
                    manifest_present=manifest_present,
                    certificates_present=certificates_present,
                    resources_present=resources_present
                )
                
        except Exception as e:
            self.logger.error(f"Failed to analyze APK structure: {e}")
            return APKStructureInfo(
                total_files=0,
                total_size=0,
                compression_ratio=0.0,
                file_types={},
                directory_structure={},
                integrity_issues=[f"Analysis failed: {str(e)}"],
                suspicious_files=[],
                manifest_present=False,
                certificates_present=False,
                resources_present=False
            )
    
    def validate_apk_integrity(self, apk_path: Path) -> Dict[str, Any]:
        """
        Validate APK file integrity and detect tampering.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Integrity validation results
        """
        validation = {
            'is_valid': True,
            'integrity_score': 100,
            'issues': [],
            'warnings': []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Test ZIP integrity
                bad_files = apk_zip.testzip()
                if bad_files:
                    validation['is_valid'] = False
                    validation['integrity_score'] -= 50
                    validation['issues'].append(f"Corrupted files detected: {bad_files}")
                
                # Check for required files
                file_list = apk_zip.namelist()
                
                if 'AndroidManifest.xml' not in file_list:
                    validation['is_valid'] = False
                    validation['integrity_score'] -= 40
                    validation['issues'].append("Missing AndroidManifest.xml")
                
                if not any(f.endswith('.dex') for f in file_list):
                    validation['is_valid'] = False
                    validation['integrity_score'] -= 30
                    validation['issues'].append("No DEX files found")
                
                # Check certificate presence
                cert_files = [f for f in file_list if f.startswith('META-INF/') and 
                             any(f.endswith(ext) for ext in ['.RSA', '.DSA', '.EC'])]
                if not cert_files:
                    validation['integrity_score'] -= 20
                    validation['warnings'].append("No certificates found - unsigned APK")
                
                # Check for duplicate files (potential tampering)
                duplicate_check = self._check_duplicate_files(apk_zip, file_list)
                if duplicate_check['duplicates']:
                    validation['integrity_score'] -= 15
                    validation['warnings'].append(f"Duplicate files detected: {len(duplicate_check['duplicates'])}")
                
        except zipfile.BadZipFile:
            validation['is_valid'] = False
            validation['integrity_score'] = 0
            validation['issues'].append("Invalid ZIP file format")
        except Exception as e:
            validation['is_valid'] = False
            validation['integrity_score'] = 0
            validation['issues'].append(f"Integrity check failed: {str(e)}")
        
        return validation
    
    def _categorize_files(self, file_list: List[str]) -> Dict[str, int]:
        """Categorize files by type."""
        file_types = {category: 0 for category in self.file_type_extensions}
        
        for file_path in file_list:
            categorized = False
            
            # Check special cases first
            if file_path == 'AndroidManifest.xml':
                file_types['manifest'] += 1
                categorized = True
            elif file_path.startswith('assets/'):
                file_types['asset'] += 1
                categorized = True
            elif file_path.startswith('META-INF/'):
                for ext in self.file_type_extensions['certificate']:
                    if file_path.upper().endswith(ext.upper()):
                        file_types['certificate'] += 1
                        categorized = True
                        break
            
            # Check by extension if not categorized
            if not categorized:
                for category, extensions in self.file_type_extensions.items():
                    if category in ['manifest', 'asset', 'certificate']:
                        continue
                    
                    for ext in extensions:
                        if file_path.lower().endswith(ext):
                            file_types[category] += 1
                            categorized = True
                            break
                    
                    if categorized:
                        break
            
            # Default to 'other' if not categorized
            if not categorized:
                file_types['other'] += 1
        
        return file_types
    
    def _build_directory_structure(self, file_list: List[str]) -> Dict[str, Any]:
        """Build hierarchical directory structure."""
        structure = {}
        
        for file_path in file_list:
            parts = file_path.split('/')
            current = structure
            
            for part in parts[:-1]:  # Directories
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            # File
            if parts:
                filename = parts[-1]
                if filename:  # Avoid empty strings
                    current[filename] = 'file'
        
        return structure
    
    def _check_integrity_issues(self, apk_zip: zipfile.ZipFile, file_list: List[str]) -> List[str]:
        """Check for various integrity issues."""
        issues = []
        
        # Check for files with suspicious compression ratios
        for file_path in file_list:
            try:
                file_info = apk_zip.getinfo(file_path)
                if file_info.file_size > 0:
                    compression_ratio = file_info.compress_size / file_info.file_size
                    if compression_ratio > 1.1:  # Compressed size larger than original
                        issues.append(f"Suspicious compression ratio in {file_path}")
                    elif compression_ratio < 0.1 and file_info.file_size > 1000:  # Very high compression
                        issues.append(f"Unusually high compression in {file_path}")
            except Exception:
                issues.append(f"Cannot read file info for {file_path}")
        
        # Check for files with unusual timestamps
        current_time = time.time()
        for file_path in file_list:
            try:
                file_info = apk_zip.getinfo(file_path)
                file_time = time.mktime(file_info.date_time + (0, 0, -1))
                
                # Check for future timestamps
                if file_time > current_time + 86400:  # More than 1 day in future
                    issues.append(f"Future timestamp detected in {file_path}")
                
                # Check for very old timestamps (before Android existed)
                if file_time < time.mktime((2007, 1, 1, 0, 0, 0, 0, 0, -1)):
                    issues.append(f"Suspiciously old timestamp in {file_path}")
                    
            except Exception:
                continue
        
        return issues
    
    def _identify_suspicious_files(self, file_list: List[str]) -> List[str]:
        """Identify potentially suspicious files."""
        suspicious = []
        
        for file_path in file_list:
            for pattern in self.suspicious_file_patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    suspicious.append(file_path)
                    break
            
            # Check for hidden files (starting with dot)
            filename = os.path.basename(file_path)
            if filename.startswith('.') and len(filename) > 1:
                suspicious.append(file_path)
            
            # Check for very long filenames (potential evasion)
            if len(filename) > 100:
                suspicious.append(file_path)
        
        return suspicious
    
    def _check_duplicate_files(self, apk_zip: zipfile.ZipFile, file_list: List[str]) -> Dict[str, Any]:
        """Check for duplicate files based on content hash."""
        file_hashes = {}
        duplicates = []
        
        try:
            for file_path in file_list[:100]:  # Limit to prevent excessive processing
                try:
                    content = apk_zip.read(file_path)
                    content_hash = hashlib.md5(content).hexdigest()
                    
                    if content_hash in file_hashes:
                        duplicates.append({
                            'original': file_hashes[content_hash],
                            'duplicate': file_path,
                            'hash': content_hash
                        })
                    else:
                        file_hashes[content_hash] = file_path
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Duplicate file check failed: {e}")
        
        return {
            'duplicates': duplicates,
            'total_unique_hashes': len(file_hashes)
        }

class APKSecurityAnalysis:
    """
    Comprehensive security analysis framework for APK files.
    
    Orchestrates all security analysis components to provide a unified
    security assessment with scoring, risk evaluation, and recommendations.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.certificate_analyzer = CertificateAnalyzer()
        self.dex_analyzer = DEXAnalyzer()
        self.native_analyzer = NativeLibraryAnalyzer()
        self.structure_analyzer = APKStructureAnalyzer()
        self.manifest_parser = ManifestParser()
        
        # Security scoring weights
        self.scoring_weights = {
            'certificates': 0.25,
            'dex_analysis': 0.20,
            'native_libraries': 0.15,
            'structure_integrity': 0.20,
            'manifest_security': 0.20
        }
    
    def analyze_apk_security(self, apk_path: Union[str, Path]) -> APKSecurityAnalysisResult:
        """
        Perform comprehensive security analysis of an APK file.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            APKSecurityAnalysisResult with comprehensive analysis results
        """
        apk_path = Path(apk_path)
        
        self.logger.info(f"Starting comprehensive security analysis of {apk_path}")
        
        # Initialize results container
        security_issues = []
        recommendations = []
        
        # Certificate analysis
        certificates = self.certificate_analyzer.analyze_apk_certificates(apk_path)
        cert_score = self._evaluate_certificate_security(certificates, security_issues, recommendations)
        
        # DEX file analysis
        dex_files = self.dex_analyzer.analyze_apk_dex_files(apk_path)
        dex_score = self._evaluate_dex_security(dex_files, security_issues, recommendations)
        
        # Native library analysis
        native_libraries = self.native_analyzer.analyze_apk_native_libraries(apk_path)
        native_score = self._evaluate_native_security(native_libraries, security_issues, recommendations)
        
        # Structure analysis
        structure_info = self.structure_analyzer.analyze_apk_structure(apk_path)
        structure_score = self._evaluate_structure_security(structure_info, security_issues, recommendations)
        
        # Manifest analysis
        manifest_analysis = self.manifest_parser.parse_manifest(apk_path)
        manifest_score = self._evaluate_manifest_security(manifest_analysis, security_issues, recommendations)
        
        # Calculate overall security score
        overall_score = self._calculate_overall_score({
            'certificates': cert_score,
            'dex_analysis': dex_score,
            'native_libraries': native_score,
            'structure_integrity': structure_score,
            'manifest_security': manifest_score
        })
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        return APKSecurityAnalysisResult(
            apk_path=str(apk_path),
            overall_security_score=overall_score,
            risk_level=risk_level,
            certificates=certificates,
            dex_files=dex_files,
            native_libraries=native_libraries,
            structure_info=structure_info,
            manifest_analysis=manifest_analysis,
            security_issues=security_issues,
            recommendations=recommendations
        )
    
    def _evaluate_certificate_security(self, certificates: List[CertificateInfo], 
                                     issues: List[str], recommendations: List[str]) -> float:
        """Evaluate certificate security and update issues/recommendations."""
        if not certificates:
            issues.append("No certificates found - unsigned APK")
            recommendations.append("Sign APK with a valid certificate")
            return 0.0
        
        total_score = 0.0
        for cert in certificates:
            validation = self.certificate_analyzer.validate_certificate_security(cert)
            total_score += validation['security_score']
            issues.extend(validation['issues'])
            recommendations.extend(validation['recommendations'])
        
        return total_score / len(certificates)
    
    def _evaluate_dex_security(self, dex_files: List[DEXInfo],
                              issues: List[str], recommendations: List[str]) -> float:
        """Evaluate DEX file security."""
        if not dex_files:
            issues.append("No DEX files found")
            return 0.0
        
        score = 100.0
        
        for dex in dex_files:
            issues.extend(dex.security_issues)
            
            if dex.obfuscation_detected:
                score -= 10
                issues.append(f"Code obfuscation detected in {dex.file_path}")
                recommendations.append("Review obfuscated code for malicious functionality")
            
            if dex.encryption_detected:
                score -= 20
                issues.append(f"Code encryption/packing detected in {dex.file_path}")
                recommendations.append("Analyze encrypted code thoroughly")
        
        return max(score, 0.0)
    
    def _evaluate_native_security(self, native_libs: List[NativeLibraryInfo],
                                 issues: List[str], recommendations: List[str]) -> float:
        """Evaluate native library security."""
        if not native_libs:
            return 100.0  # No native code is secure
        
        score = 100.0
        
        for lib in native_libs:
            issues.extend(lib.security_issues)
            
            if lib.is_stripped:
                score -= 5
                recommendations.append(f"Stripped library {lib.name} - review for security")
            
            if lib.architecture == ArchitectureType.UNKNOWN:
                score -= 10
                issues.append(f"Unknown architecture for {lib.name}")
        
        return max(score, 0.0)
    
    def _evaluate_structure_security(self, structure: APKStructureInfo,
                                   issues: List[str], recommendations: List[str]) -> float:
        """Evaluate APK structure security."""
        score = 100.0
        
        issues.extend(structure.integrity_issues)
        
        if structure.suspicious_files:
            score -= len(structure.suspicious_files) * 5
            issues.append(f"Suspicious files detected: {len(structure.suspicious_files)}")
            recommendations.append("Review suspicious files for malicious content")
        
        if not structure.manifest_present:
            score -= 40
            issues.append("AndroidManifest.xml missing")
        
        if not structure.certificates_present:
            score -= 20
            issues.append("No certificates present")
        
        return max(score, 0.0)
    
    def _evaluate_manifest_security(self, manifest: Optional[Dict[str, Any]],
                                   issues: List[str], recommendations: List[str]) -> float:
        """Evaluate manifest security."""
        if not manifest:
            issues.append("Could not parse AndroidManifest.xml")
            return 0.0
        
        score = 100.0
        
        # Check permissions
        permissions = manifest.get('permissions', [])
        dangerous_permissions = [p for p in permissions if 'dangerous' in str(p).lower()]
        
        if dangerous_permissions:
            score -= len(dangerous_permissions) * 2
            issues.append(f"Dangerous permissions detected: {len(dangerous_permissions)}")
            recommendations.append("Review dangerous permissions for necessity")
        
        # Check for exported components
        exported_components = manifest.get('exported_components', [])
        if exported_components:
            score -= len(exported_components) * 1
            recommendations.append("Review exported components for security")
        
        return max(score, 0.0)
    
    def _calculate_overall_score(self, component_scores: Dict[str, float]) -> float:
        """Calculate weighted overall security score."""
        total_score = 0.0
        for component, score in component_scores.items():
            weight = self.scoring_weights.get(component, 0.0)
            total_score += score * weight
        
        return max(0.0, min(100.0, total_score))
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on security score."""
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"
    
    def analyze_malware_patterns(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Enhanced malware pattern detection and analysis.
        
        Analyzes APK for common malware patterns, suspicious behaviors,
        and potential security threats.
        """
        apk_path = Path(apk_path)
        malware_indicators = {
            'suspicious_permissions': [],
            'obfuscation_patterns': [],
            'network_anomalies': [],
            'file_anomalies': [],
            'behavior_patterns': [],
            'risk_score': 0.0
        }
        
        try:
            # Analyze suspicious permission combinations
            manifest_data = self.manifest_parser.parse_manifest(apk_path)
            permissions = manifest_data.get('permissions', [])
            
            # Check for dangerous permission combinations
            dangerous_combos = [
                (['android.permission.READ_SMS', 'android.permission.SEND_SMS'], 'SMS manipulation'),
                (['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'], 'Location tracking'),
                (['android.permission.RECORD_AUDIO', 'android.permission.INTERNET'], 'Audio surveillance'),
                (['android.permission.CAMERA', 'android.permission.INTERNET'], 'Camera surveillance'),
                (['android.permission.READ_CONTACTS', 'android.permission.INTERNET'], 'Contact data theft'),
                (['android.permission.CALL_PHONE', 'android.permission.INTERNET'], 'Premium rate fraud'),
                (['android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.READ_EXTERNAL_STORAGE'], 'File system access')
            ]
            
            perm_names = [p.get('name', '') for p in permissions if isinstance(p, dict)]
            for combo, description in dangerous_combos:
                if all(perm in perm_names for perm in combo):
                    malware_indicators['suspicious_permissions'].append({
                        'pattern': combo,
                        'description': description,
                        'risk_level': 'High'
                    })
                    malware_indicators['risk_score'] += 15
            
            # Analyze file structure for anomalies
            structure_info = self.structure_analyzer.analyze_apk_structure(apk_path)
            
            # Check for suspicious file patterns
            suspicious_patterns = [
                (r'.*\.dex$', 'Multiple DEX files', 10),
                (r'assets/.*\.apk$', 'Embedded APK files', 20),
                (r'.*/(su|busybox|sqlite3)$', 'Root utility binaries', 25),
                (r'.*\.(so|dll|exe)$', 'Native executables', 5),
                (r'lib/.*/lib.*\.so$', 'Unusual native libraries', 10)
            ]
            
            file_list = structure_info.get('file_list', [])
            for pattern, description, risk_points in suspicious_patterns:
                import re
                matching_files = [f for f in file_list if re.match(pattern, f)]
                if matching_files:
                    malware_indicators['file_anomalies'].append({
                        'pattern': pattern,
                        'description': description,
                        'files': matching_files[:5],  # Limit to first 5 matches
                        'count': len(matching_files),
                        'risk_points': risk_points
                    })
                    malware_indicators['risk_score'] += risk_points
            
            # Analyze network behavior patterns
            network_patterns = self._analyze_network_behavior_patterns(apk_path)
            malware_indicators['network_anomalies'] = network_patterns
            malware_indicators['risk_score'] += sum(p.get('risk_points', 0) for p in network_patterns)
            
            # Advanced obfuscation detection
            obfuscation_analysis = self._analyze_code_obfuscation(apk_path)
            malware_indicators['obfuscation_patterns'] = obfuscation_analysis
            malware_indicators['risk_score'] += sum(p.get('risk_points', 0) for p in obfuscation_analysis)
            
            # Behavioral pattern analysis
            behavior_analysis = self._analyze_suspicious_behaviors(apk_path)
            malware_indicators['behavior_patterns'] = behavior_analysis
            malware_indicators['risk_score'] += sum(p.get('risk_points', 0) for p in behavior_analysis)
            
        except Exception as e:
            self.logger.error(f"Malware pattern analysis failed: {e}")
        
        return malware_indicators
    
    def _analyze_network_behavior_patterns(self, apk_path: Path) -> List[Dict[str, Any]]:
        """Analyze network behavior patterns for suspicious activity."""
        network_patterns = []
        
        try:
            # Extract strings and analyze for network indicators
            all_strings = []
            dex_files = self.dex_analyzer.analyze_apk_dex_files(apk_path)
            for dex in dex_files:
                all_strings.extend(dex.strings)
            
            # Suspicious network patterns
            suspicious_network_indicators = [
                (r'https?://[a-zA-Z0-9.-]+\.(?:tk|ml|ga|cf|onion)', 'Suspicious TLD usage', 15),
                (r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', 'Hardcoded IP addresses', 10),
                (r'(?:cmd|shell|exec|su|root)', 'Shell command patterns', 20),
                (r'(?:bot|command|control|c2|cnc)', 'C&C patterns', 25),
                (r'(?:encrypt|decrypt|aes|rsa|base64)', 'Encryption patterns', 5),
                (r'(?:download|upload|exfiltrate)', 'Data transfer patterns', 15)
            ]
            
            import re
            for pattern, description, risk_points in suspicious_network_indicators:
                matches = []
                for string in all_strings:
                    if re.search(pattern, string, re.IGNORECASE):
                        matches.append(string)
                
                if matches:
                    network_patterns.append({
                        'pattern': pattern,
                        'description': description,
                        'matches': matches[:3],  # Limit to first 3 matches
                        'count': len(matches),
                        'risk_points': risk_points
                    })
        
        except Exception as e:
            self.logger.debug(f"Network behavior analysis failed: {e}")
        
        return network_patterns
    
    def _analyze_code_obfuscation(self, apk_path: Path) -> List[Dict[str, Any]]:
        """Analyze code for obfuscation patterns."""
        obfuscation_patterns = []
        
        try:
            dex_files = self.dex_analyzer.analyze_apk_dex_files(apk_path)
            
            for dex in dex_files:
                # Check for obfuscated class names
                obfuscated_classes = [cls for cls in dex.classes if self._is_obfuscated_name(cls)]
                if len(obfuscated_classes) > 10:  # Threshold for obfuscation
                    obfuscation_patterns.append({
                        'type': 'Class name obfuscation',
                        'description': f'Found {len(obfuscated_classes)} obfuscated class names',
                        'sample_names': obfuscated_classes[:5],
                        'risk_points': 10
                    })
                
                # Check for string obfuscation
                suspicious_strings = [s for s in dex.strings if self._is_suspicious_string(s)]
                if suspicious_strings:
                    obfuscation_patterns.append({
                        'type': 'String obfuscation',
                        'description': f'Found {len(suspicious_strings)} suspicious strings',
                        'sample_strings': suspicious_strings[:3],
                        'risk_points': 15
                    })
                
                # Check for reflection usage (potential obfuscation)
                reflection_indicators = [s for s in dex.strings if 'reflection' in s.lower() or 'invoke' in s.lower()]
                if len(reflection_indicators) > 5:
                    obfuscation_patterns.append({
                        'type': 'Heavy reflection usage',
                        'description': f'Found {len(reflection_indicators)} reflection indicators',
                        'risk_points': 8
                    })
        
        except Exception as e:
            self.logger.debug(f"Code obfuscation analysis failed: {e}")
        
        return obfuscation_patterns
    
    def _analyze_suspicious_behaviors(self, apk_path: Path) -> List[Dict[str, Any]]:
        """Analyze for suspicious behavioral patterns."""
        behavior_patterns = []
        
        try:
            # Analyze manifest for suspicious behaviors
            manifest_data = self.manifest_parser.parse_manifest(apk_path)
            
            # Check for hidden activities (no launcher intent)
            activities = manifest_data.get('activities', [])
            launcher_activities = [a for a in activities if self._has_launcher_intent(a)]
            if len(activities) > 0 and len(launcher_activities) == 0:
                behavior_patterns.append({
                    'type': 'Hidden application',
                    'description': 'No launcher activities found - potential stealth app',
                    'risk_points': 20
                })
            
            # Check for device admin requests
            receivers = manifest_data.get('receivers', [])
            admin_receivers = [r for r in receivers if 'DeviceAdminReceiver' in str(r)]
            if admin_receivers:
                behavior_patterns.append({
                    'type': 'Device administration',
                    'description': 'Requests device administrator privileges',
                    'risk_points': 15
                })
            
            # Check for accessibility service abuse
            services = manifest_data.get('services', [])
            accessibility_services = [s for s in services if 'AccessibilityService' in str(s)]
            if accessibility_services:
                behavior_patterns.append({
                    'type': 'Accessibility service',
                    'description': 'Uses accessibility services (potential overlay attacks)',
                    'risk_points': 12
                })
            
            # Check for boot receivers
            boot_receivers = [r for r in receivers if 'BOOT_COMPLETED' in str(r)]
            if boot_receivers:
                behavior_patterns.append({
                    'type': 'Boot persistence',
                    'description': 'Starts automatically on device boot',
                    'risk_points': 8
                })
        
        except Exception as e:
            self.logger.debug(f"Suspicious behavior analysis failed: {e}")
        
        return behavior_patterns
    
    def _is_obfuscated_name(self, name: str) -> bool:
        """Check if a class/method name appears obfuscated."""
        if len(name) <= 2:
            return True
        if len(name) == 1 and name.isalpha():
            return True
        if all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' for c in name) and len(name) <= 3:
            return True
        return False
    
    def _is_suspicious_string(self, string: str) -> bool:
        """Check if a string appears suspicious or obfuscated."""
        if len(string) < 4:
            return False
        
        # Check for base64-like strings
        if len(string) > 20 and string.isalnum() and string.endswith('='):
            return True
        
        # Check for hex-encoded strings
        if len(string) > 10 and all(c in '0123456789abcdefABCDEF' for c in string):
            return True
        
        # Check for encrypted-looking strings
        if len(string) > 15 and sum(1 for c in string if c.isupper()) / len(string) > 0.7:
            return True
        
        return False
    
    def _has_launcher_intent(self, activity: Dict[str, Any]) -> bool:
        """Check if activity has launcher intent."""
        intent_filters = activity.get('intent_filters', [])
        for intent_filter in intent_filters:
            actions = intent_filter.get('actions', [])
            categories = intent_filter.get('categories', [])
            if 'android.intent.action.MAIN' in actions and 'android.intent.category.LAUNCHER' in categories:
                return True
        return False
    
    def validate_security_best_practices(self, apk_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate APK against Android security best practices.
        
        Checks for compliance with Android security guidelines,
        OWASP Mobile Top 10, and industry best practices.
        """
        apk_path = Path(apk_path)
        validation_results = {
            'overall_compliance': 0.0,
            'passed_checks': [],
            'failed_checks': [],
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Certificate validation
            certificates = self.certificate_analyzer.analyze_apk_certificates(apk_path)
            
            # Check certificate validity period
            for cert in certificates:
                try:
                    from datetime import datetime
                    not_after = datetime.fromisoformat(cert.not_after.replace('Z', '+00:00'))
                    not_before = datetime.fromisoformat(cert.not_before.replace('Z', '+00:00'))
                    now = datetime.now(not_after.tzinfo)
                    
                    if not_after < now:
                        validation_results['failed_checks'].append({
                            'check': 'Certificate validity',
                            'description': 'Certificate has expired',
                            'severity': 'High'
                        })
                    elif (not_after - now).days < 30:
                        validation_results['warnings'].append({
                            'check': 'Certificate expiry warning',
                            'description': 'Certificate expires within 30 days',
                            'severity': 'Medium'
                        })
                    else:
                        validation_results['passed_checks'].append({
                            'check': 'Certificate validity',
                            'description': 'Certificate is valid and not expiring soon'
                        })
                    
                    # Check certificate strength
                    if cert.key_size < 2048 and 'RSA' in cert.public_key_algorithm:
                        validation_results['failed_checks'].append({
                            'check': 'Certificate key strength',
                            'description': f'RSA key size {cert.key_size} is below recommended 2048 bits',
                            'severity': 'Medium'
                        })
                    
                except Exception:
                    validation_results['warnings'].append({
                        'check': 'Certificate parsing',
                        'description': 'Could not fully validate certificate',
                        'severity': 'Low'
                    })
            
            # Network security validation
            manifest_data = self.manifest_parser.parse_manifest(apk_path)
            
            # Check for network security config
            application = manifest_data.get('application', {})
            if 'android:networkSecurityConfig' not in str(application):
                validation_results['warnings'].append({
                    'check': 'Network security configuration',
                    'description': 'No network security configuration specified',
                    'severity': 'Medium'
                })
                validation_results['recommendations'].append(
                    'Implement network security configuration to control cleartext traffic'
                )
            
            # Check for cleartext traffic allowance
            if 'android:usesCleartextTraffic' in str(application) and 'true' in str(application):
                validation_results['failed_checks'].append({
                    'check': 'Cleartext traffic',
                    'description': 'Application allows cleartext HTTP traffic',
                    'severity': 'High'
                })
                validation_results['recommendations'].append(
                    'Disable cleartext traffic or use network security configuration'
                )
            
            # Check backup allowance
            if 'android:allowBackup' in str(application) and 'true' in str(application):
                validation_results['warnings'].append({
                    'check': 'Backup allowance',
                    'description': 'Application data backup is enabled',
                    'severity': 'Medium'
                })
                validation_results['recommendations'].append(
                    'Consider disabling backup for sensitive applications'
                )
            
            # Check debug mode
            if 'android:debuggable' in str(application) and 'true' in str(application):
                validation_results['failed_checks'].append({
                    'check': 'Debug mode',
                    'description': 'Application is debuggable in production',
                    'severity': 'High'
                })
                validation_results['recommendations'].append(
                    'Disable debug mode for production releases'
                )
            
            # Calculate overall compliance score
            total_checks = (len(validation_results['passed_checks']) + 
                          len(validation_results['failed_checks']) + 
                          len(validation_results['warnings']))
            
            if total_checks > 0:
                passed_weight = len(validation_results['passed_checks']) * 1.0
                warning_weight = len(validation_results['warnings']) * 0.5
                compliance_score = (passed_weight + warning_weight) / total_checks * 100
                validation_results['overall_compliance'] = compliance_score
            
        except Exception as e:
            self.logger.error(f"Security best practices validation failed: {e}")
        
        return validation_results

# Global manifest parser instance