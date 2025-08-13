"""
File System Security Analyzer

This module provides comprehensive file system security analysis capabilities for Android applications,
specializing in identifying file permission issues, access control vulnerabilities, and storage
security assessment.

Features:
- File permission analysis and validation
- Access control security assessment
- World-readable/writable file detection
- System file security evaluation
- External storage security analysis
- File ownership and group analysis
"""

import logging
import re
import os
import stat
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
from dataclasses import dataclass

from .data_structures import (
    FilePermissionFinding, FilePermissionLevel, VulnerabilitySeverity,
    ConfidenceEvidence, EnhancedDataStorageAnalysisConfig
)

logger = logging.getLogger(__name__)

class FileSystemSecurityAnalyzer:
    """
    Comprehensive file system security analyzer specializing in Android file permissions
    and access control analysis with advanced pattern matching.
    """
    
    def __init__(self, config: EnhancedDataStorageAnalysisConfig):
        """Initialize the file system security analyzer with configuration."""
        self.config = config
        
        # Initialize file system security patterns
        self.file_system_patterns = self._initialize_file_system_patterns()
        self.permission_patterns = self._initialize_permission_patterns()
        self.security_context_patterns = self._initialize_security_context_patterns()
        
        # Permission security weights
        self.permission_weights = self._initialize_permission_weights()
        
        # Analysis statistics
        self.analysis_stats = {
            "files_analyzed": 0,
            "permission_issues_found": 0,
            "critical_issues": 0,
            "world_accessible_files": 0
        }
    
    def _initialize_file_system_patterns(self) -> Dict[str, List[str]]:
        """Initialize comprehensive file system security patterns."""
        return {
            "world_readable": [
                r'MODE_WORLD_READABLE',
                r'Context\.MODE_WORLD_READABLE',
                r'openFileOutput\([^,]+,\s*MODE_WORLD_READABLE',
                r'getSharedPreferences\([^,]+,\s*MODE_WORLD_READABLE',
                r'FileOutputStream.*MODE_WORLD_READABLE',
                r'chmod\s+[0-9]*[0-9][4-7][0-9]',
                r'permissions\s*=\s*["\'].*r.*["\']',
                r'file\.setReadable\(true,\s*false\)'
            ],
            "world_writable": [
                r'MODE_WORLD_WRITEABLE',
                r'Context\.MODE_WORLD_WRITEABLE',
                r'openFileOutput\([^,]+,\s*MODE_WORLD_WRITEABLE',
                r'getSharedPreferences\([^,]+,\s*MODE_WORLD_WRITEABLE',
                r'FileOutputStream.*MODE_WORLD_WRITEABLE',
                r'chmod\s+[0-9]*[0-9][2367][0-9]',
                r'permissions\s*=\s*["\'].*w.*["\']',
                r'file\.setWritable\(true,\s*false\)'
            ],
            "unsafe_file_operations": [
                r'File\s*\([^)]*getExternalStorageDirectory\(\)',
                r'Environment\.getExternalStorageDirectory\(\)',
                r'getExternalFilesDir\(null\)',
                r'getCacheDir\(\)',
                r'getExternalCacheDir\(\)',
                r'openFileOutput\([^,]+,\s*MODE_APPEND',
                r'FileOutputStream.*MODE_APPEND',
                r'RandomAccessFile.*["\']rw["\']'
            ],
            "insecure_permissions": [
                r'setPermissions\(.*777.*\)',
                r'setPermissions\(.*666.*\)',
                r'chmod.*777',
                r'chmod.*666',
                r'umask\s*\(\s*0\s*\)',
                r'permissions\s*=\s*["\']777["\']',
                r'file\.setExecutable\(true,\s*false\)'
            ],
            "temp_file_issues": [
                r'File\.createTempFile\(',
                r'createTempFile\(',
                r'getTempDirectory\(\)',
                r'File.*\.tmp["\']',
                r'tmp["\'].*File',
                r'temp.*File.*create',
                r'deleteOnExit\(\)'
            ],
            "backup_file_exposure": [
                r'\.backup["\']',
                r'\.bak["\']',
                r'\.old["\']',
                r'backup.*File',
                r'File.*backup',
                r'getBackupDir\(\)',
                r'backup.*directory'
            ]
        }
    
    def _initialize_permission_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize file permission analysis patterns."""
        return {
            "dangerous_permissions": {
                "patterns": [
                    r'0777',  # World read/write/execute
                    r'0666',  # World read/write
                    r'0755',  # World read/execute
                    r'0644',  # World read
                    r'777',   # Octal without leading zero
                    r'666',
                    r'755',
                    r'644'
                ],
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Overly permissive file permissions"
            },
            "moderate_permissions": {
                "patterns": [
                    r'0750',  # Group read/execute
                    r'0740',  # Group read
                    r'0640',  # Group read
                    r'750',
                    r'740',
                    r'640'
                ],
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "Potentially risky group permissions"
            },
            "secure_permissions": {
                "patterns": [
                    r'0700',  # Owner only
                    r'0600',  # Owner read/write
                    r'0400',  # Owner read only
                    r'700',
                    r'600',
                    r'400'
                ],
                "severity": VulnerabilitySeverity.LOW,
                "description": "Secure file permissions"
            }
        }
    
    def _initialize_security_context_patterns(self) -> Dict[str, List[str]]:
        """Initialize security context analysis patterns."""
        return {
            "selinux_context": [
                r'getFileContext\(',
                r'setFileContext\(',
                r'SELinux\.getFileContext',
                r'security\.selinux',
                r'selinux_context',
                r'file_contexts'
            ],
            "app_data_access": [
                r'getFilesDir\(\)',
                r'getDataDir\(\)',
                r'getDir\(',
                r'getDatabasePath\(',
                r'getPreferencesDir\(',
                r'getNoBackupFilesDir\(\)'
            ],
            "external_storage": [
                r'getExternalStorageDirectory\(\)',
                r'getExternalFilesDir\(',
                r'getExternalCacheDir\(',
                r'isExternalStorageWritable\(',
                r'isExternalStorageReadable\(',
                r'EXTERNAL_STORAGE'
            ]
        }
    
    def _initialize_permission_weights(self) -> Dict[str, float]:
        """Initialize permission security weight factors."""
        return {
            "world_readable": 0.8,
            "world_writable": 0.9,
            "unsafe_file_operations": 0.7,
            "insecure_permissions": 0.8,
            "temp_file_issues": 0.6,
            "backup_file_exposure": 0.7
        }
    
    def analyze_file_system_security(self, apk_ctx) -> List[FilePermissionFinding]:
        """
        Analyze file system security in the Android application.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            List of file permission findings
        """
        findings = []
        
        try:
            # Get analysis targets
            targets = self._get_analysis_targets(apk_ctx)
            
            # Analyze each target for file system security issues
            for target in targets:
                target_findings = self._analyze_target_for_file_system_security(target)
                findings.extend(target_findings)
                
                self.analysis_stats["files_analyzed"] += 1
                
                # Respect analysis limits
                if len(findings) >= self.config.max_files_to_analyze:
                    logger.warning(f"Reached maximum files limit: {self.config.max_files_to_analyze}")
                    break
            
            # Filter and deduplicate findings
            findings = self._filter_and_deduplicate_findings(findings)
            
            # Update statistics
            self.analysis_stats["permission_issues_found"] = len(findings)
            self.analysis_stats["critical_issues"] = len([f for f in findings if f.severity == VulnerabilitySeverity.CRITICAL])
            self.analysis_stats["world_accessible_files"] = len([f for f in findings if f.permission_level == FilePermissionLevel.INSECURE])
            
            return findings
            
        except Exception as e:
            logger.error(f"Error during file system security analysis: {str(e)}")
            return []
    
    def _get_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Get files and directories to analyze for file system security."""
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
            
            # Analyze XML files
            if hasattr(apk_ctx, 'xml_files'):
                for xml_file in apk_ctx.xml_files:
                    targets.append({
                        "type": "xml_file",
                        "path": xml_file.get('path', ''),
                        "content": xml_file.get('content', ''),
                        "size": len(xml_file.get('content', '')),
                        "filename": os.path.basename(xml_file.get('path', ''))
                    })
            
            # Analyze native code files
            if hasattr(apk_ctx, 'native_files'):
                for native_file in apk_ctx.native_files:
                    targets.append({
                        "type": "native_code",
                        "path": native_file.get('path', ''),
                        "content": native_file.get('content', ''),
                        "size": len(native_file.get('content', '')),
                        "filename": os.path.basename(native_file.get('path', ''))
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
            
            return targets
            
        except Exception as e:
            logger.error(f"Error getting file system analysis targets: {str(e)}")
            return []
    
    def _analyze_target_for_file_system_security(self, target: Dict[str, Any]) -> List[FilePermissionFinding]:
        """Analyze a target for file system security issues."""
        findings = []
        
        try:
            content = target.get('content', '')
            file_path = target.get('path', '')
            
            # Analyze each file system security pattern type
            for security_type, patterns in self.file_system_patterns.items():
                type_findings = self._detect_file_system_security_type(
                    security_type, patterns, content, file_path, target
                )
                findings.extend(type_findings)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error analyzing target for file system security: {str(e)}")
            return []
    
    def _detect_file_system_security_type(self, security_type: str, patterns: List[str], 
                                         content: str, file_path: str, target: Dict[str, Any]) -> List[FilePermissionFinding]:
        """Detect specific file system security issue type."""
        findings = []
        
        try:
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Extract context and validate
                    context = self._extract_context(content, match.start(), match.end())
                    
                    # Create finding
                    finding = FilePermissionFinding(
                        file_path=file_path,
                        permission_mode=match.group(0),
                        owner="unknown",
                        group="unknown",
                        size=target.get('size', 0),
                        permission_level=self._assess_permission_level(security_type, match.group(0)),
                        security_issues=[self._get_security_issue_description(security_type)],
                        access_risks=[self._get_access_risk_description(security_type)],
                        location=f"Line {content[:match.start()].count(chr(10)) + 1}",
                        compliance_violations=self._get_compliance_violations(security_type),
                        remediation_steps=self._get_remediation_steps(security_type),
                        is_system_file=self._is_system_file(file_path),
                        is_app_data=self._is_app_data_file(file_path),
                        is_external_storage=self._is_external_storage_file(file_path)
                    )
                    
                    # Calculate confidence and severity
                    finding.confidence = self._calculate_file_system_confidence(security_type, match.group(0), context)
                    finding.severity = self._assess_file_system_severity(security_type)
                    
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error detecting file system security type {security_type}: {str(e)}")
            return []
    
    def _assess_permission_level(self, security_type: str, evidence: str) -> FilePermissionLevel:
        """Assess the permission level based on security type and evidence."""
        if security_type in ["world_readable", "world_writable", "insecure_permissions"]:
            return FilePermissionLevel.INSECURE
        elif security_type in ["unsafe_file_operations", "temp_file_issues", "backup_file_exposure"]:
            return FilePermissionLevel.MODERATE
        else:
            return FilePermissionLevel.SECURE
    
    def _assess_file_system_severity(self, security_type: str) -> VulnerabilitySeverity:
        """Assess severity based on file system security issue type."""
        severity_map = {
            "world_readable": VulnerabilitySeverity.HIGH,
            "world_writable": VulnerabilitySeverity.CRITICAL,
            "unsafe_file_operations": VulnerabilitySeverity.MEDIUM,
            "insecure_permissions": VulnerabilitySeverity.HIGH,
            "temp_file_issues": VulnerabilitySeverity.MEDIUM,
            "backup_file_exposure": VulnerabilitySeverity.MEDIUM
        }
        return severity_map.get(security_type, VulnerabilitySeverity.MEDIUM)
    
    def _calculate_file_system_confidence(self, security_type: str, evidence: str, context: str) -> float:
        """Calculate confidence score for file system security finding."""
        try:
            base_confidence = self.permission_weights.get(security_type, 0.5)
            
            # Adjust based on context
            context_boost = 0.0
            if security_type == "world_readable" and "MODE_WORLD_READABLE" in evidence:
                context_boost = 0.3
            elif security_type == "world_writable" and "MODE_WORLD_WRITEABLE" in evidence:
                context_boost = 0.3
            elif security_type == "insecure_permissions" and re.search(r'777|666', evidence):
                context_boost = 0.2
            
            # Adjust based on file context
            file_context_boost = 0.0
            if "sensitive" in context.lower() or "private" in context.lower():
                file_context_boost = 0.1
            
            final_confidence = min(1.0, base_confidence + context_boost + file_context_boost)
            return final_confidence
            
        except Exception as e:
            logger.error(f"Error calculating file system confidence: {str(e)}")
            return 0.5
    
    def _get_security_issue_description(self, security_type: str) -> str:
        """Get description of security issue."""
        descriptions = {
            "world_readable": "File is world-readable, potentially exposing sensitive data",
            "world_writable": "File is world-writable, allowing unauthorized modifications",
            "unsafe_file_operations": "Unsafe file operations that may expose data",
            "insecure_permissions": "Overly permissive file permissions",
            "temp_file_issues": "Temporary files may expose sensitive data",
            "backup_file_exposure": "Backup files may contain sensitive information"
        }
        return descriptions.get(security_type, "Unknown file system security issue")
    
    def _get_access_risk_description(self, security_type: str) -> str:
        """Get description of access risk."""
        risks = {
            "world_readable": "Any application can read file contents",
            "world_writable": "Any application can modify file contents",
            "unsafe_file_operations": "External storage access may be intercepted",
            "insecure_permissions": "Unauthorized access to sensitive files",
            "temp_file_issues": "Temporary files persisting after use",
            "backup_file_exposure": "Backup files accessible to other applications"
        }
        return risks.get(security_type, "Unknown access risk")
    
    def _get_compliance_violations(self, security_type: str) -> List[str]:
        """Get compliance violations for security type."""
        violations = {
            "world_readable": ["MASVS-STORAGE-1", "MSTG-STORAGE-1"],
            "world_writable": ["MASVS-STORAGE-1", "MSTG-STORAGE-1"],
            "unsafe_file_operations": ["MASVS-STORAGE-2", "MSTG-STORAGE-2"],
            "insecure_permissions": ["MASVS-STORAGE-1", "MSTG-STORAGE-1"],
            "temp_file_issues": ["MASVS-STORAGE-2", "MSTG-STORAGE-2"],
            "backup_file_exposure": ["MASVS-STORAGE-1", "MSTG-STORAGE-1"]
        }
        return violations.get(security_type, [])
    
    def _get_remediation_steps(self, security_type: str) -> List[str]:
        """Get remediation steps for security type."""
        steps = {
            "world_readable": [
                "Use MODE_PRIVATE for file creation",
                "Implement proper access controls",
                "Validate file permissions before operations"
            ],
            "world_writable": [
                "Remove world-writable permissions",
                "Use application-specific directories",
                "Implement file integrity checks"
            ],
            "unsafe_file_operations": [
                "Use internal storage for sensitive data",
                "Implement proper encryption",
                "Validate file paths before operations"
            ],
            "insecure_permissions": [
                "Set restrictive file permissions",
                "Use proper file creation modes",
                "Implement access control validation"
            ],
            "temp_file_issues": [
                "Clean up temporary files properly",
                "Use secure temporary directories",
                "Implement file deletion verification"
            ],
            "backup_file_exposure": [
                "Encrypt backup files",
                "Use secure backup locations",
                "Implement backup access controls"
            ]
        }
        return steps.get(security_type, [])
    
    def _is_system_file(self, file_path: str) -> bool:
        """Check if file is a system file."""
        system_paths = ["/system/", "/proc/", "/dev/", "/sys/"]
        return any(system_path in file_path for system_path in system_paths)
    
    def _is_app_data_file(self, file_path: str) -> bool:
        """Check if file is in app data directory."""
        app_data_paths = ["/data/data/", "/data/user/", "files/", "cache/"]
        return any(app_path in file_path for app_path in app_data_paths)
    
    def _is_external_storage_file(self, file_path: str) -> bool:
        """Check if file is in external storage."""
        external_paths = ["/storage/", "/sdcard/", "/mnt/", "external"]
        return any(external_path in file_path for external_path in external_paths)
    
    def _extract_context(self, content: str, start: int, end: int, context_size: int = 100) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end].strip()
        except Exception:
            return ""
    
    def _filter_and_deduplicate_findings(self, findings: List[FilePermissionFinding]) -> List[FilePermissionFinding]:
        """Filter and deduplicate file system findings using unified deduplication framework."""
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
                    'title': f"File Permission Issue: {finding.permission_mode}",
                    'file_path': finding.file_path,
                    'severity': finding.severity.value if hasattr(finding, 'severity') else 'MEDIUM',
                    'category': 'file_system_security',
                    'description': f"Permission mode {finding.permission_mode} on file: {finding.file_path}",
                    'finding_id': id(finding)
                }
                dict_findings.append(dict_finding)
            
            # Use unified deduplication framework with PRESERVATION strategy to maintain file-specific logic
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
    
    def _filter_and_deduplicate_findings_fallback(self, findings: List[FilePermissionFinding]) -> List[FilePermissionFinding]:
        """Fallback deduplication method (original logic)."""
        # Remove duplicates based on file path and permission mode
        seen = set()
        filtered_findings = []
        
        for finding in findings:
            key = (finding.file_path, finding.permission_mode)
            if key not in seen:
                seen.add(key)
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get file system analysis statistics."""
        return {
            "analyzer_type": "file_system_security",
            "statistics": self.analysis_stats.copy(),
            "pattern_counts": {
                pattern_type: len(patterns)
                for pattern_type, patterns in self.file_system_patterns.items()
            },
            "analysis_coverage": {
                "total_patterns": sum(len(patterns) for patterns in self.file_system_patterns.values()),
                "pattern_types": len(self.file_system_patterns),
                "permission_levels": len(FilePermissionLevel),
                "severity_levels": len(VulnerabilitySeverity)
            }
        } 