#!/usr/bin/env python3
"""
Dynamic Storage Security Coordinator for AODS

This module implements comprehensive storage security analysis:
- Dynamic SD Card and External Storage Analysis
- File permission and security analysis 
- Sensitive data exposure detection
- Storage encryption analysis capabilities
- Real-time file system monitoring

Integrates with existing AODS storage analysis infrastructure.
"""

import asyncio
import os
import json
import logging
import hashlib
import time
import stat
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import shutil
import subprocess

# Storage analysis data structures
class StorageType(Enum):
    INTERNAL_STORAGE = "internal_storage"
    EXTERNAL_STORAGE = "external_storage"
    SD_CARD = "sd_card"
    SHARED_STORAGE = "shared_storage"
    SCOPED_STORAGE = "scoped_storage"
    CACHE_STORAGE = "cache_storage"

class StorageSecurityLevel(Enum):
    SECURE = "secure"
    MODERATE = "moderate"
    VULNERABLE = "vulnerable"
    CRITICAL = "critical"

class FilePermissionLevel(Enum):
    PRIVATE = "private"
    WORLD_READABLE = "world_readable"
    WORLD_WRITABLE = "world_writable"
    EXECUTABLE = "executable"
    UNRESTRICTED = "unrestricted"

class EncryptionType(Enum):
    NONE = "none"
    DEVICE_ENCRYPTION = "device_encryption"
    FILE_LEVEL = "file_level"
    AES = "aes"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

@dataclass
class StorageLocation:
    """Storage location analysis result"""
    path: str
    storage_type: StorageType
    permissions: int
    permission_level: FilePermissionLevel
    size_bytes: int
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    accessed_time: Optional[datetime] = None
    owner_uid: Optional[int] = None
    group_gid: Optional[int] = None
    is_encrypted: bool = False
    encryption_type: EncryptionType = EncryptionType.NONE

@dataclass
class SensitiveDataFinding:
    """Sensitive data exposure finding"""
    finding_id: str
    file_path: str
    data_type: str
    sensitivity_level: str
    pattern_matched: str
    confidence_score: float
    risk_level: StorageSecurityLevel
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class StorageAnalysisResult:
    """Complete storage analysis result"""
    analysis_id: str
    app_package: str
    storage_locations: List[StorageLocation] = field(default_factory=list)
    sensitive_findings: List[SensitiveDataFinding] = field(default_factory=list)
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    encryption_summary: Dict[str, Any] = field(default_factory=dict)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class ExternalStorageMonitor:
    """Monitor external storage access patterns and security"""
    
    def __init__(self, app_package: str):
        self.logger = logging.getLogger(__name__)
        self.app_package = app_package
        self.monitoring_active = False
        self.monitored_paths = set()
        self.access_patterns = []
        
        # Common Android storage paths
        self.storage_paths = {
            StorageType.EXTERNAL_STORAGE: [
                "/sdcard/",
                "/storage/emulated/0/",
                "/mnt/sdcard/"
            ],
            StorageType.SD_CARD: [
                "/storage/",
                "/mnt/external_sd/",
                "/storage/sdcard1/"
            ],
            StorageType.SHARED_STORAGE: [
                "/storage/emulated/0/Android/data/",
                "/storage/emulated/0/Download/",
                "/storage/emulated/0/DCIM/"
            ],
            StorageType.CACHE_STORAGE: [
                "/data/data/{}/cache/".format(app_package),
                "/storage/emulated/0/Android/data/{}/cache/".format(app_package)
            ]
        }
    
    async def start_monitoring(self) -> bool:
        """Start monitoring external storage access"""
        try:
            self.monitoring_active = True
            self.logger.info(f"Started external storage monitoring for {self.app_package}")
            
            # Initialize monitoring for each storage type
            for storage_type, paths in self.storage_paths.items():
                for path in paths:
                    if os.path.exists(path):
                        self.monitored_paths.add((path, storage_type))
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to start storage monitoring: {e}")
            return False
    
    async def analyze_storage_locations(self) -> List[StorageLocation]:
        """Analyze all accessible storage locations"""
        locations = []
        
        for path, storage_type in self.monitored_paths:
            try:
                if os.path.exists(path):
                    location = await self._analyze_location(path, storage_type)
                    if location:
                        locations.append(location)
            except Exception as e:
                self.logger.warning(f"Failed to analyze storage location {path}: {e}")
        
        return locations
    
    async def _analyze_location(self, path: str, storage_type: StorageType) -> Optional[StorageLocation]:
        """Analyze individual storage location"""
        try:
            stat_info = os.stat(path)
            
            # Determine permission level
            permissions = stat_info.st_mode
            permission_level = self._classify_permissions(permissions)
            
            # Get timestamps
            created_time = datetime.fromtimestamp(stat_info.st_ctime, timezone.utc)
            modified_time = datetime.fromtimestamp(stat_info.st_mtime, timezone.utc)
            accessed_time = datetime.fromtimestamp(stat_info.st_atime, timezone.utc)
            
            # Check encryption
            is_encrypted, encryption_type = await self._check_encryption(path)
            
            return StorageLocation(
                path=path,
                storage_type=storage_type,
                permissions=permissions,
                permission_level=permission_level,
                size_bytes=stat_info.st_size if os.path.isfile(path) else 0,
                created_time=created_time,
                modified_time=modified_time,
                accessed_time=accessed_time,
                owner_uid=stat_info.st_uid,
                group_gid=stat_info.st_gid,
                is_encrypted=is_encrypted,
                encryption_type=encryption_type
            )
        except Exception as e:
            self.logger.error(f"Error analyzing location {path}: {e}")
            return None
    
    def _classify_permissions(self, permissions: int) -> FilePermissionLevel:
        """Classify file permissions into security levels"""
        # Check for world-readable/writable permissions
        if permissions & stat.S_IROTH and permissions & stat.S_IWOTH:
            return FilePermissionLevel.UNRESTRICTED
        elif permissions & stat.S_IWOTH:
            return FilePermissionLevel.WORLD_WRITABLE
        elif permissions & stat.S_IROTH:
            return FilePermissionLevel.WORLD_READABLE
        elif permissions & stat.S_IXUSR:
            return FilePermissionLevel.EXECUTABLE
        else:
            return FilePermissionLevel.PRIVATE
    
    async def _check_encryption(self, path: str) -> Tuple[bool, EncryptionType]:
        """Check if storage location is encrypted"""
        try:
            # Check for device-level encryption indicators
            if self._is_device_encrypted():
                return True, EncryptionType.DEVICE_ENCRYPTION
            
            # Check for file-level encryption
            if os.path.isfile(path):
                encryption_type = await self._analyze_file_encryption(path)
                return encryption_type != EncryptionType.NONE, encryption_type
            
            return False, EncryptionType.NONE
        except Exception as e:
            self.logger.warning(f"Encryption check failed for {path}: {e}")
            return False, EncryptionType.UNKNOWN
    
    def _is_device_encrypted(self) -> bool:
        """Check if device storage is encrypted"""
        try:
            # Check Android encryption status
            result = subprocess.run(['getprop', 'ro.crypto.state'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip() == 'encrypted'
        except Exception:
            pass
        return False
    
    async def _analyze_file_encryption(self, file_path: str) -> EncryptionType:
        """Analyze file for encryption indicators"""
        try:
            # Read file header to detect encryption
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            # Check for common encryption signatures
            if b'AES' in header or header.startswith(b'Salted__'):
                return EncryptionType.AES
            elif len(set(header)) < 16:  # Low entropy might indicate encryption
                return EncryptionType.CUSTOM
            else:
                return EncryptionType.NONE
        except Exception:
            return EncryptionType.UNKNOWN
    
    async def stop_monitoring(self):
        """Stop storage monitoring"""
        self.monitoring_active = False
        self.logger.info("Stopped external storage monitoring")

class SensitiveDataDetector:
    """Detect sensitive data exposure in storage"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Sensitive data patterns
        self.patterns = {
            'credentials': [
                r'password\s*[=:]\s*["\']?([^"\'\s]{6,})["\']?',
                r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9]{16,})["\']?',
                r'secret\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
                r'token\s*[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?'
            ],
            'financial': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'IBAN\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}'
            ],
            'personal': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',  # Phone
                r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'  # Date
            ],
            'technical': [
                r'-----BEGIN [A-Z\s]+ KEY-----',  # Private keys
                r'jdbc:[a-zA-Z0-9]+://[^"\'\\s]+',  # Database URLs
                r'https?://[^"\'\\s]+[a-zA-Z0-9/]'  # URLs
            ]
        }
    
    async def scan_for_sensitive_data(self, storage_locations: List[StorageLocation]) -> List[SensitiveDataFinding]:
        """Scan storage locations for sensitive data"""
        findings = []
        
        for location in storage_locations:
            if os.path.isfile(location.path):
                file_findings = await self._scan_file(location)
                findings.extend(file_findings)
            elif os.path.isdir(location.path):
                dir_findings = await self._scan_directory(location)
                findings.extend(dir_findings)
        
        return findings
    
    async def _scan_file(self, location: StorageLocation) -> List[SensitiveDataFinding]:
        """Scan individual file for sensitive data"""
        findings = []
        
        try:
            # Only scan text files to avoid binary false positives
            if not self._is_text_file(location.path):
                return findings
            
            with open(location.path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100000)  # Limit to first 100KB
            
            for data_type, patterns in self.patterns.items():
                for pattern in patterns:
                    findings.extend(self._find_pattern_matches(
                        location.path, content, pattern, data_type
                    ))
        
        except Exception as e:
            self.logger.warning(f"Failed to scan file {location.path}: {e}")
        
        return findings
    
    async def _scan_directory(self, location: StorageLocation) -> List[SensitiveDataFinding]:
        """Scan directory for sensitive files"""
        findings = []
        
        try:
            for root, dirs, files in os.walk(location.path):
                for file in files[:10]:  # Limit to first 10 files per directory
                    file_path = os.path.join(root, file)
                    file_location = StorageLocation(
                        path=file_path,
                        storage_type=location.storage_type,
                        permissions=location.permissions,
                        permission_level=location.permission_level,
                        size_bytes=0
                    )
                    file_findings = await self._scan_file(file_location)
                    findings.extend(file_findings)
        
        except Exception as e:
            self.logger.warning(f"Failed to scan directory {location.path}: {e}")
        
        return findings
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is likely a text file"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
            
            # Check for binary indicators
            if b'\x00' in chunk:
                return False
            
            # Check file extension
            text_extensions = {'.txt', '.log', '.json', '.xml', '.properties', '.conf', '.ini'}
            return Path(file_path).suffix.lower() in text_extensions
        except Exception:
            return False
    
    def _find_pattern_matches(self, file_path: str, content: str, pattern: str, data_type: str) -> List[SensitiveDataFinding]:
        """Find pattern matches in content"""
        import re
        findings = []
        
        try:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for i, match in enumerate(matches):
                if i >= 5:  # Limit to 5 matches per pattern per file
                    break
                
                finding_id = hashlib.md5(f"{file_path}_{pattern}_{match.start()}".encode()).hexdigest()[:12]
                confidence = self._calculate_confidence(match.group(), data_type)
                risk_level = self._assess_risk_level(data_type, confidence)
                
                finding = SensitiveDataFinding(
                    finding_id=finding_id,
                    file_path=file_path,
                    data_type=data_type,
                    sensitivity_level=self._get_sensitivity_level(data_type),
                    pattern_matched=match.group()[:50],  # Truncate for security
                    confidence_score=confidence,
                    risk_level=risk_level,
                    recommendations=self._get_recommendations(data_type, risk_level),
                    metadata={
                        'pattern_used': pattern,
                        'match_position': match.start(),
                        'context_length': len(content)
                    }
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.warning(f"Pattern matching failed: {e}")
        
        return findings
    
    def _calculate_confidence(self, match: str, data_type: str) -> float:
        """Calculate confidence score for match"""
        confidence = 0.5
        
        # Adjust based on data type
        if data_type == 'credentials':
            if len(match) > 12:
                confidence += 0.3
            if any(c.isupper() and c.islower() for c in match):
                confidence += 0.1
        elif data_type == 'financial':
            confidence += 0.4  # Financial patterns are usually high confidence
        elif data_type == 'personal':
            confidence += 0.2
        elif data_type == 'technical':
            confidence += 0.3
        
        return min(0.95, confidence)
    
    def _assess_risk_level(self, data_type: str, confidence: float) -> StorageSecurityLevel:
        """Assess risk level based on data type and confidence"""
        if data_type in ['credentials', 'financial'] and confidence > 0.7:
            return StorageSecurityLevel.CRITICAL
        elif data_type in ['credentials', 'financial'] and confidence > 0.5:
            return StorageSecurityLevel.VULNERABLE
        elif confidence > 0.8:
            return StorageSecurityLevel.VULNERABLE
        elif confidence > 0.6:
            return StorageSecurityLevel.MODERATE
        else:
            return StorageSecurityLevel.SECURE
    
    def _get_sensitivity_level(self, data_type: str) -> str:
        """Get sensitivity level description"""
        levels = {
            'credentials': 'Highly Sensitive',
            'financial': 'Highly Sensitive',
            'personal': 'Sensitive',
            'technical': 'Moderately Sensitive'
        }
        return levels.get(data_type, 'Sensitive')
    
    def _get_recommendations(self, data_type: str, risk_level: StorageSecurityLevel) -> List[str]:
        """Get security recommendations"""
        recommendations = []
        
        if risk_level in [StorageSecurityLevel.CRITICAL, StorageSecurityLevel.VULNERABLE]:
            recommendations.extend([
                "Remove sensitive data from external storage",
                "Implement proper encryption for sensitive data",
                "Use Android Keystore for credential storage"
            ])
        
        if data_type == 'credentials':
            recommendations.extend([
                "Use secure credential storage APIs",
                "Implement token-based authentication",
                "Avoid hardcoded credentials"
            ])
        elif data_type == 'financial':
            recommendations.extend([
                "Comply with PCI DSS requirements",
                "Implement data tokenization",
                "Use secure payment processing APIs"
            ])
        
        return recommendations

class StorageEncryptionAnalyzer:
    """Analyze storage encryption implementations"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def analyze_encryption(self, storage_locations: List[StorageLocation]) -> Dict[str, Any]:
        """Analyze encryption across storage locations"""
        encryption_summary = {
            'total_locations': len(storage_locations),
            'encrypted_locations': 0,
            'encryption_types': {},
            'security_score': 0.0,
            'recommendations': []
        }
        
        for location in storage_locations:
            if location.is_encrypted:
                encryption_summary['encrypted_locations'] += 1
                enc_type = location.encryption_type.value
                encryption_summary['encryption_types'][enc_type] = \
                    encryption_summary['encryption_types'].get(enc_type, 0) + 1
        
        # Calculate security score
        if encryption_summary['total_locations'] > 0:
            encryption_ratio = encryption_summary['encrypted_locations'] / encryption_summary['total_locations']
            encryption_summary['security_score'] = encryption_ratio * 100
        
        # Generate recommendations
        if encryption_summary['security_score'] < 50:
            encryption_summary['recommendations'].extend([
                "Enable device-level encryption",
                "Implement file-level encryption for sensitive data",
                "Use Android's built-in encryption APIs"
            ])
        elif encryption_summary['security_score'] < 80:
            encryption_summary['recommendations'].extend([
                "Improve encryption coverage",
                "Consider stronger encryption algorithms"
            ])
        
        return encryption_summary

class DynamicStorageSecurityCoordinator:
    """Main coordinator for dynamic storage security analysis"""
    
    def __init__(self, app_package: str, config: Optional[Dict] = None):
        self.logger = logging.getLogger(__name__)
        self.app_package = app_package
        self.config = config or {}
        
        # Initialize components
        self.storage_monitor = ExternalStorageMonitor(app_package)
        self.sensitive_detector = SensitiveDataDetector()
        self.encryption_analyzer = StorageEncryptionAnalyzer()
        
        # Analysis state
        self.analysis_active = False
        self.current_analysis = None
    
    async def coordinate_storage_analysis(self, analysis_profile: str = "comprehensive") -> StorageAnalysisResult:
        """
        Coordinate comprehensive storage security analysis.
        
        Analysis Profiles:
        - 'comprehensive': Full storage security analysis
        - 'external_focus': Focus on external storage locations
        - 'sensitive_data': Focus on sensitive data detection
        - 'encryption': Focus on encryption analysis
        - 'permissions': Focus on file permission analysis
        """
        analysis_id = f"STORAGE_{int(time.time())}"
        self.logger.info(f"Starting storage analysis {analysis_id} with profile: {analysis_profile}")
        
        try:
            self.analysis_active = True
            
            # Step 1: Start storage monitoring
            monitoring_success = await self.storage_monitor.start_monitoring()
            if not monitoring_success:
                raise Exception("Failed to start storage monitoring")
            
            # Step 2: Analyze storage locations based on profile
            storage_locations = await self._coordinate_location_analysis(analysis_profile)
            
            # Step 3: Detect sensitive data based on profile
            sensitive_findings = await self._coordinate_sensitive_detection(
                storage_locations, analysis_profile
            )
            
            # Step 4: Analyze encryption based on profile
            encryption_summary = await self._coordinate_encryption_analysis(
                storage_locations, analysis_profile
            )
            
            # Step 5: Generate security assessment
            security_assessment = await self._generate_security_assessment(
                storage_locations, sensitive_findings, encryption_summary
            )
            
            # Create comprehensive result
            result = StorageAnalysisResult(
                analysis_id=analysis_id,
                app_package=self.app_package,
                storage_locations=storage_locations,
                sensitive_findings=sensitive_findings,
                security_issues=security_assessment['issues'],
                encryption_summary=encryption_summary,
                risk_assessment=security_assessment['risk_assessment'],
                recommendations=security_assessment['recommendations']
            )
            
            self.current_analysis = result
            self.logger.info(f"Storage analysis {analysis_id} completed successfully")
            return result
            
        except Exception as e:
            self.logger.error(f"Storage analysis failed: {e}")
            raise
        finally:
            self.analysis_active = False
            await self.storage_monitor.stop_monitoring()
    
    async def _coordinate_location_analysis(self, profile: str) -> List[StorageLocation]:
        """Coordinate storage location analysis based on profile"""
        if profile in ['comprehensive', 'external_focus', 'permissions']:
            return await self.storage_monitor.analyze_storage_locations()
        else:
            # For other profiles, get minimal location info
            basic_locations = await self.storage_monitor.analyze_storage_locations()
            return basic_locations[:5]  # Limit for focused analysis
    
    async def _coordinate_sensitive_detection(self, locations: List[StorageLocation], 
                                            profile: str) -> List[SensitiveDataFinding]:
        """Coordinate sensitive data detection based on profile"""
        if profile in ['comprehensive', 'sensitive_data']:
            return await self.sensitive_detector.scan_for_sensitive_data(locations)
        else:
            # Limited detection for other profiles
            return await self.sensitive_detector.scan_for_sensitive_data(locations[:3])
    
    async def _coordinate_encryption_analysis(self, locations: List[StorageLocation], 
                                            profile: str) -> Dict[str, Any]:
        """Coordinate encryption analysis based on profile"""
        if profile in ['comprehensive', 'encryption']:
            return await self.encryption_analyzer.analyze_encryption(locations)
        else:
            # Basic encryption check for other profiles
            basic_summary = {
                'total_locations': len(locations),
                'encrypted_locations': sum(1 for loc in locations if loc.is_encrypted),
                'security_score': 0.0,
                'recommendations': []
            }
            if basic_summary['total_locations'] > 0:
                basic_summary['security_score'] = (
                    basic_summary['encrypted_locations'] / basic_summary['total_locations'] * 100
                )
            return basic_summary
    
    async def _generate_security_assessment(self, locations: List[StorageLocation],
                                          findings: List[SensitiveDataFinding],
                                          encryption: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive security assessment"""
        issues = []
        
        # Check for permission issues
        for location in locations:
            if location.permission_level in [FilePermissionLevel.WORLD_READABLE, 
                                           FilePermissionLevel.WORLD_WRITABLE,
                                           FilePermissionLevel.UNRESTRICTED]:
                issues.append({
                    'type': 'insecure_permissions',
                    'severity': 'high',
                    'location': location.path,
                    'permission_level': location.permission_level.value,
                    'description': f"Insecure file permissions detected: {location.permission_level.value}"
                })
        
        # Check for unencrypted sensitive data
        for finding in findings:
            if finding.risk_level in [StorageSecurityLevel.CRITICAL, StorageSecurityLevel.VULNERABLE]:
                issues.append({
                    'type': 'sensitive_data_exposure',
                    'severity': 'critical' if finding.risk_level == StorageSecurityLevel.CRITICAL else 'high',
                    'location': finding.file_path,
                    'data_type': finding.data_type,
                    'description': f"Sensitive {finding.data_type} data exposed in storage"
                })
        
        # Risk assessment
        risk_score = 0
        if encryption['security_score'] < 50:
            risk_score += 30
        elif encryption['security_score'] < 80:
            risk_score += 15
        
        critical_findings = len([f for f in findings if f.risk_level == StorageSecurityLevel.CRITICAL])
        risk_score += critical_findings * 20
        
        vulnerable_findings = len([f for f in findings if f.risk_level == StorageSecurityLevel.VULNERABLE])
        risk_score += vulnerable_findings * 10
        
        risk_level = "LOW"
        if risk_score > 70:
            risk_level = "CRITICAL"
        elif risk_score > 50:
            risk_level = "HIGH"
        elif risk_score > 30:
            risk_level = "MEDIUM"
        
        # Generate recommendations
        recommendations = []
        if encryption['security_score'] < 80:
            recommendations.append("Implement comprehensive storage encryption")
        if critical_findings > 0:
            recommendations.append("Remove or encrypt sensitive data in storage")
        if any(issue['type'] == 'insecure_permissions' for issue in issues):
            recommendations.append("Review and restrict file permissions")
        
        recommendations.extend([
            "Use Android Keystore for sensitive data",
            "Implement proper data classification",
            "Regular security audits of storage locations"
        ])
        
        return {
            'issues': issues,
            'risk_assessment': {
                'risk_score': min(100, risk_score),
                'risk_level': risk_level,
                'total_issues': len(issues),
                'critical_issues': len([i for i in issues if i['severity'] == 'critical']),
                'encryption_coverage': encryption['security_score']
            },
            'recommendations': recommendations
        }
    
    async def get_analysis_summary(self) -> Optional[Dict[str, Any]]:
        """Get summary of current analysis"""
        if not self.current_analysis:
            return None
        
        return {
            'analysis_id': self.current_analysis.analysis_id,
            'app_package': self.current_analysis.app_package,
            'storage_locations_count': len(self.current_analysis.storage_locations),
            'sensitive_findings_count': len(self.current_analysis.sensitive_findings),
            'security_issues_count': len(self.current_analysis.security_issues),
            'risk_level': self.current_analysis.risk_assessment.get('risk_level', 'UNKNOWN'),
            'encryption_score': self.current_analysis.encryption_summary.get('security_score', 0),
            'analysis_timestamp': self.current_analysis.analysis_timestamp.isoformat()
        }

# Integration with AODS framework
async def integrate_storage_analysis_with_aods(coordinator: DynamicStorageSecurityCoordinator,
                                             aods_context: Dict[str, Any]) -> Dict[str, Any]:
    """Integrate storage analysis with AODS framework"""
    try:
        # Determine analysis profile based on AODS scan mode
        scan_mode = aods_context.get('scan_mode', 'comprehensive')
        profile_mapping = {
            'lightning': 'permissions',
            'fast': 'external_focus',
            'standard': 'sensitive_data',
            'deep': 'comprehensive',
            'comprehensive': 'comprehensive'
        }
        
        analysis_profile = profile_mapping.get(scan_mode, 'comprehensive')
        
        # Run coordinated storage analysis
        storage_result = await coordinator.coordinate_storage_analysis(analysis_profile)
        
        # Convert to AODS-compatible format
        aods_findings = []
        for finding in storage_result.sensitive_findings:
            aods_findings.append({
                'type': 'storage_security',
                'subtype': finding.data_type,
                'severity': finding.risk_level.value,
                'confidence': finding.confidence_score,
                'location': finding.file_path,
                'description': f"Sensitive {finding.data_type} data found in storage",
                'recommendations': finding.recommendations,
                'metadata': finding.metadata
            })
        
        for issue in storage_result.security_issues:
            aods_findings.append({
                'type': 'storage_security',
                'subtype': issue['type'],
                'severity': issue['severity'],
                'confidence': 0.9,
                'location': issue.get('location', 'unknown'),
                'description': issue['description'],
                'recommendations': [],
                'metadata': issue
            })
        
        return {
            'storage_analysis_complete': True,
            'analysis_profile': analysis_profile,
            'storage_findings': aods_findings,
            'risk_assessment': storage_result.risk_assessment,
            'encryption_summary': storage_result.encryption_summary,
            'recommendations': storage_result.recommendations,
            'analysis_summary': await coordinator.get_analysis_summary()
        }
        
    except Exception as e:
        logging.getLogger(__name__).error(f"AODS storage analysis integration failed: {e}")
        return {
            'storage_analysis_complete': False,
            'error': str(e),
            'analysis_profile': 'failed'
        }

if __name__ == "__main__":
    async def demo_storage_analysis():
        """Demo of Dynamic Storage Security Coordinator"""
        coordinator = DynamicStorageSecurityCoordinator("com.example.test")
        
        try:
            # Run comprehensive analysis
            result = await coordinator.coordinate_storage_analysis("comprehensive")
            
            print(f"Storage Analysis Complete: {result.analysis_id}")
            print(f"Storage Locations: {len(result.storage_locations)}")
            print(f"Sensitive Findings: {len(result.sensitive_findings)}")
            print(f"Security Issues: {len(result.security_issues)}")
            print(f"Risk Level: {result.risk_assessment.get('risk_level', 'UNKNOWN')}")
            print(f"Encryption Score: {result.encryption_summary.get('security_score', 0):.1f}%")
            
        except Exception as e:
            print(f"Demo failed: {e}")
    
    asyncio.run(demo_storage_analysis()) 