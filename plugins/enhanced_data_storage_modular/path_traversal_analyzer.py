"""
Path Traversal Analyzer

This module provides comprehensive path traversal vulnerability detection capabilities for Android applications,
specializing in identifying directory traversal attacks, path injection vulnerabilities, and
file access control bypass attempts.

Features:
- Path traversal pattern detection
- Directory traversal vulnerability analysis
- User input validation assessment
- File path sanitization evaluation
- Attack vector identification
- Mitigation strategy recommendations
"""

import logging
import re
import os
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
from dataclasses import dataclass

from .data_structures import (
    PathTraversalFinding, PathTraversalRisk, VulnerabilitySeverity,
    ConfidenceEvidence, EnhancedDataStorageAnalysisConfig
)

# Import unified deduplication framework
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)

logger = logging.getLogger(__name__)

class PathTraversalAnalyzer:
    """
    Comprehensive path traversal analyzer specializing in Android directory traversal
    vulnerability detection with advanced pattern matching.
    """
    
    def __init__(self, config: EnhancedDataStorageAnalysisConfig):
        """Initialize the path traversal analyzer with configuration."""
        self.config = config
        
        # Initialize path traversal patterns
        self.path_traversal_patterns = self._initialize_path_traversal_patterns()
        self.user_input_patterns = self._initialize_user_input_patterns()
        self.file_operation_patterns = self._initialize_file_operation_patterns()
        
        # Path traversal risk weights
        self.risk_weights = self._initialize_risk_weights()
        
        # Analysis statistics
        self.analysis_stats = {
            "files_analyzed": 0,
            "traversal_vulnerabilities": 0,
            "high_risk_vulnerabilities": 0,
            "user_input_sources": 0
        }
    
    def _initialize_path_traversal_patterns(self) -> Dict[str, List[str]]:
        """Initialize comprehensive path traversal patterns."""
        return {
            "directory_traversal": [
                r'\.\./\.\./\.\.',
                r'\.\.[\\/]\.\.[\\/]',
                r'\.\.[\\/]\.\.[\\/]\.\.[\\/]',
                r'\.\.[\\/]\.\.[\\/]\.\.[\\/]\.\.[\\/]',
                r'\.\.[\\/]\.\.[\\/]\.\.[\\/]\.\.[\\/]\.\.[\\/]',
                r'\.\.\\',
                r'\.\./',
                r'%2e%2e%2f',
                r'%2e%2e%5c',
                r'%2e%2e/',
                r'%2e%2e\\',
                r'\.\.%2f',
                r'\.\.%5c'
            ],
            "path_injection": [
                r'new\s+File\([^)]*\+[^)]*\)',
                r'new\s+File\([^)]*user[^)]*\)',
                r'new\s+File\([^)]*input[^)]*\)',
                r'new\s+File\([^)]*request[^)]*\)',
                r'new\s+File\([^)]*parameter[^)]*\)',
                r'FileInputStream\([^)]*\+[^)]*\)',
                r'FileOutputStream\([^)]*\+[^)]*\)',
                r'File\([^)]*getString\([^)]*\)',
                r'File\([^)]*getParameter\([^)]*\)'
            ],
            "unsafe_file_operations": [
                r'File\([^)]*\.\.[\\/]',
                r'new\s+File\([^)]*\.\.[\\/]',
                r'getCanonicalPath\(\)',
                r'getAbsolutePath\(\)',
                r'File\.separator',
                r'System\.getProperty\(["\']file\.separator["\']',
                r'\.getPath\(\)',
                r'\.getParent\(\)',
                r'\.getParentFile\(\)'
            ],
            "file_access_bypass": [
                r'File\([^)]*["\'][^"\']*\.\.[^"\']*["\']',
                r'openFileInput\([^)]*\.\.',
                r'openFileOutput\([^)]*\.\.',
                r'getFileStreamPath\([^)]*\.\.',
                r'getFilesDir\(\).*\.\.',
                r'getCacheDir\(\).*\.\.',
                r'getExternalFilesDir\([^)]*\.\.',
                r'getExternalCacheDir\([^)]*\.\.'
            ],
            "web_path_traversal": [
                r'WebView.*loadUrl\([^)]*\.\.',
                r'loadUrl\([^)]*\.\.',
                r'WebSettings.*setAllowFileAccess\(true\)',
                r'WebSettings.*setAllowFileAccessFromFileURLs\(true\)',
                r'WebSettings.*setAllowUniversalAccessFromFileURLs\(true\)',
                r'file://[^"\']*\.\.',
                r'content://[^"\']*\.\.'
            ],
            "zip_slip": [
                r'ZipEntry\.getName\(\)',
                r'zipEntry\.getName\(\)',
                r'new\s+File\([^)]*zipEntry\.getName\(\)',
                r'new\s+File\([^)]*entry\.getName\(\)',
                r'File\([^)]*\.getName\(\)',
                r'extractTo\([^)]*zipEntry',
                r'unzip\([^)]*entry'
            ]
        }
    
    def _initialize_user_input_patterns(self) -> Dict[str, List[str]]:
        """Initialize user input source patterns."""
        return {
            "http_parameters": [
                r'request\.getParameter\(',
                r'getParameter\(',
                r'getParameterValues\(',
                r'getParameterNames\(',
                r'HttpServletRequest.*getParameter',
                r'intent\.getStringExtra\(',
                r'getStringExtra\(',
                r'getIntExtra\(',
                r'getBooleanExtra\(',
                r'getSerializableExtra\('
            ],
            "file_input": [
                r'BufferedReader.*readLine\(\)',
                r'Scanner.*nextLine\(\)',
                r'Scanner.*next\(\)',
                r'FileReader.*read\(\)',
                r'FileInputStream.*read\(\)',
                r'readLine\(\)',
                r'nextLine\(\)',
                r'readUTF\(\)',
                r'readString\(\)'
            ],
            "bundle_data": [
                r'Bundle.*getString\(',
                r'bundle\.getString\(',
                r'getArguments\(\)\.getString\(',
                r'savedInstanceState\.getString\(',
                r'intent\.getExtras\(\)',
                r'getIntent\(\)\.getExtras\(\)',
                r'intent\.getData\(\)',
                r'getIntent\(\)\.getData\(\)'
            ],
            "shared_preferences": [
                r'SharedPreferences.*getString\(',
                r'preferences\.getString\(',
                r'getSharedPreferences\([^)]*\)\.getString\(',
                r'PreferenceManager\.getDefaultSharedPreferences\([^)]*\)\.getString\(',
                r'sharedPrefs\.getString\(',
                r'prefs\.getString\('
            ]
        }
    
    def _initialize_file_operation_patterns(self) -> Dict[str, List[str]]:
        """Initialize file operation patterns."""
        return {
            "file_creation": [
                r'new\s+File\(',
                r'File\.createNewFile\(\)',
                r'File\.createTempFile\(',
                r'Files\.createFile\(',
                r'Files\.createDirectory\(',
                r'Files\.createDirectories\(',
                r'mkdirs\(\)',
                r'mkdir\(\)'
            ],
            "file_reading": [
                r'FileInputStream\(',
                r'FileReader\(',
                r'BufferedReader\(',
                r'Scanner\(',
                r'Files\.readAllBytes\(',
                r'Files\.readAllLines\(',
                r'Files\.readString\(',
                r'openFileInput\('
            ],
            "file_writing": [
                r'FileOutputStream\(',
                r'FileWriter\(',
                r'BufferedWriter\(',
                r'PrintWriter\(',
                r'Files\.write\(',
                r'Files\.writeString\(',
                r'openFileOutput\(',
                r'RandomAccessFile\('
            ],
            "file_access": [
                r'File\.exists\(\)',
                r'File\.canRead\(\)',
                r'File\.canWrite\(\)',
                r'File\.canExecute\(\)',
                r'File\.isFile\(\)',
                r'File\.isDirectory\(\)',
                r'File\.length\(\)',
                r'File\.lastModified\(\)'
            ]
        }
    
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """Initialize path traversal risk weight factors."""
        return {
            "directory_traversal": 0.9,
            "path_injection": 0.8,
            "unsafe_file_operations": 0.7,
            "file_access_bypass": 0.8,
            "web_path_traversal": 0.9,
            "zip_slip": 0.8
        }
    
    def analyze_path_traversal(self, apk_ctx) -> List[PathTraversalFinding]:
        """
        Analyze path traversal vulnerabilities in the Android application.
        
        Args:
            apk_ctx: APK analysis context
            
        Returns:
            List of path traversal findings
        """
        findings = []
        
        try:
            # Get analysis targets
            targets = self._get_analysis_targets(apk_ctx)
            
            # Analyze each target for path traversal vulnerabilities
            for target in targets:
                target_findings = self._analyze_target_for_path_traversal(target)
                findings.extend(target_findings)
                
                self.analysis_stats["files_analyzed"] += 1
                
                # Respect analysis limits
                if len(findings) >= self.config.max_files_to_analyze:
                    logger.warning(f"Reached maximum files limit: {self.config.max_files_to_analyze}")
                    break
            
            # Filter and deduplicate findings
            findings = self._filter_and_deduplicate_findings(findings)
            
            # Update statistics
            self.analysis_stats["traversal_vulnerabilities"] = len(findings)
            self.analysis_stats["high_risk_vulnerabilities"] = len([f for f in findings if f.traversal_risk == PathTraversalRisk.HIGH_RISK])
            self.analysis_stats["user_input_sources"] = len([f for f in findings if f.allows_external_input])
            
            return findings
            
        except Exception as e:
            logger.error(f"Error during path traversal analysis: {str(e)}")
            return []
    
    def _get_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Get files and directories to analyze for path traversal."""
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
            
            # Analyze web content files
            if hasattr(apk_ctx, 'web_files'):
                for web_file in apk_ctx.web_files:
                    targets.append({
                        "type": "web_content",
                        "path": web_file.get('path', ''),
                        "content": web_file.get('content', ''),
                        "size": len(web_file.get('content', '')),
                        "filename": os.path.basename(web_file.get('path', ''))
                    })
            
            return targets
            
        except Exception as e:
            logger.error(f"Error getting path traversal analysis targets: {str(e)}")
            return []
    
    def _analyze_target_for_path_traversal(self, target: Dict[str, Any]) -> List[PathTraversalFinding]:
        """Analyze a target for path traversal vulnerabilities."""
        findings = []
        
        try:
            content = target.get('content', '')
            file_path = target.get('path', '')
            
            # Analyze each path traversal pattern type
            for traversal_type, patterns in self.path_traversal_patterns.items():
                type_findings = self._detect_path_traversal_type(
                    traversal_type, patterns, content, file_path, target
                )
                findings.extend(type_findings)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error analyzing target for path traversal: {str(e)}")
            return []
    
    def _detect_path_traversal_type(self, traversal_type: str, patterns: List[str], 
                                   content: str, file_path: str, target: Dict[str, Any]) -> List[PathTraversalFinding]:
        """Detect specific path traversal vulnerability type."""
        findings = []
        
        try:
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Extract context and analyze
                    context = self._extract_context(content, match.start(), match.end())
                    
                    # Check for user input sources
                    user_input_source = self._detect_user_input_source(context)
                    allows_external_input = bool(user_input_source)
                    
                    # Analyze path validation
                    path_validation = self._analyze_path_validation(context)
                    sanitization_present = self._check_sanitization(context)
                    
                    # Create finding
                    finding = PathTraversalFinding(
                        vulnerable_method=self._extract_vulnerable_method(context),
                        file_path=file_path,
                        line_number=content[:match.start()].count('\n') + 1,
                        user_input_source=user_input_source,
                        traversal_risk=self._assess_traversal_risk(traversal_type, context),
                        potential_targets=self._identify_potential_targets(context),
                        attack_vectors=self._identify_attack_vectors(traversal_type, context),
                        vulnerable_parameter=self._extract_vulnerable_parameter(context),
                        path_validation=path_validation,
                        sanitization_present=sanitization_present,
                        location=f"Line {content[:match.start()].count(chr(10)) + 1}",
                        is_file_operation=self._is_file_operation(context),
                        is_directory_operation=self._is_directory_operation(context),
                        allows_external_input=allows_external_input,
                        mitigation_strategies=self._get_mitigation_strategies(traversal_type),
                        code_examples=self._get_code_examples(traversal_type)
                    )
                    
                    # Calculate confidence and severity
                    finding.confidence = self._calculate_traversal_confidence(traversal_type, match.group(0), context)
                    finding.severity = self._assess_traversal_severity(traversal_type, allows_external_input)
                    
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error detecting path traversal type {traversal_type}: {str(e)}")
            return []
    
    def _detect_user_input_source(self, context: str) -> str:
        """Detect user input source in the context."""
        for source_type, patterns in self.user_input_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    return source_type
        return ""
    
    def _analyze_path_validation(self, context: str) -> str:
        """Analyze path validation mechanisms in the context."""
        validation_patterns = [
            r'getCanonicalPath\(\)',
            r'toPath\(\)\.normalize\(\)',
            r'Paths\.get\([^)]*\)\.normalize\(\)',
            r'FilenameUtils\.normalize\(',
            r'\.contains\(["\']\.\.["\']\)',
            r'\.startsWith\(',
            r'\.endsWith\(',
            r'validate.*path',
            r'check.*path',
            r'sanitize.*path'
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return "Present"
        
        return "Missing"
    
    def _check_sanitization(self, context: str) -> bool:
        """Check if path sanitization is present."""
        sanitization_patterns = [
            r'\.replace\(["\']\.\.["\']\s*,\s*["\']["\']',
            r'\.replaceAll\(["\']\.\.["\']\s*,\s*["\']["\']',
            r'FilenameUtils\.normalize\(',
            r'Paths\.get\([^)]*\)\.normalize\(\)',
            r'sanitize',
            r'clean.*path',
            r'filter.*path'
        ]
        
        for pattern in sanitization_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_vulnerable_method(self, context: str) -> str:
        """Extract the vulnerable method from context."""
        method_patterns = [
            r'(\w+)\s*\([^)]*\.\.[^)]*\)',
            r'new\s+(\w+)\(',
            r'(\w+)\.(\w+)\(',
            r'(\w+)\s*\('
        ]
        
        for pattern in method_patterns:
            match = re.search(pattern, context)
            if match:
                return match.group(1)
        
        return "Unknown"
    
    def _extract_vulnerable_parameter(self, context: str) -> str:
        """Extract the vulnerable parameter from context."""
        param_patterns = [
            r'(\w+)\s*\+\s*["\'][^"\']*\.\.[^"\']*["\']',
            r'(\w+)\s*\+\s*["\'][^"\']*[\\/][^"\']*["\']',
            r'new\s+File\s*\(\s*(\w+)\s*\)',
            r'File\s*\(\s*(\w+)\s*\)'
        ]
        
        for pattern in param_patterns:
            match = re.search(pattern, context)
            if match:
                return match.group(1)
        
        return "Unknown"
    
    def _assess_traversal_risk(self, traversal_type: str, context: str) -> PathTraversalRisk:
        """Assess the risk level of path traversal vulnerability."""
        # Check for high-risk indicators
        if traversal_type in ["directory_traversal", "web_path_traversal"]:
            if self._detect_user_input_source(context):
                return PathTraversalRisk.HIGH_RISK
            else:
                return PathTraversalRisk.MEDIUM_RISK
        
        # Check for medium-risk indicators
        elif traversal_type in ["path_injection", "file_access_bypass", "zip_slip"]:
            if self._detect_user_input_source(context):
                return PathTraversalRisk.MEDIUM_RISK
            else:
                return PathTraversalRisk.LOW_RISK
        
        # Check for low-risk indicators
        elif traversal_type == "unsafe_file_operations":
            if self._check_sanitization(context):
                return PathTraversalRisk.LOW_RISK
            else:
                return PathTraversalRisk.MEDIUM_RISK
        
        return PathTraversalRisk.LOW_RISK
    
    def _identify_potential_targets(self, context: str) -> List[str]:
        """Identify potential targets for path traversal attack."""
        targets = []
        
        # Check for sensitive file patterns
        sensitive_patterns = [
            r'passwd', r'shadow', r'hosts', r'config', r'private', r'secret',
            r'key', r'certificate', r'database', r'credentials', r'token'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                targets.append(f"Sensitive files containing '{pattern}'")
        
        # Check for system directories
        system_dirs = [
            r'/etc/', r'/system/', r'/data/', r'/proc/', r'/root/',
            r'C:\\Windows\\', r'C:\\Program Files\\', r'C:\\Users\\'
        ]
        
        for dir_pattern in system_dirs:
            if re.search(dir_pattern, context, re.IGNORECASE):
                targets.append(f"System directory: {dir_pattern}")
        
        if not targets:
            targets.append("Application files and directories")
        
        return targets
    
    def _identify_attack_vectors(self, traversal_type: str, context: str) -> List[str]:
        """Identify attack vectors for path traversal vulnerability."""
        vectors = []
        
        if traversal_type == "directory_traversal":
            vectors.extend([
                "Directory traversal using ../../../",
                "URL-encoded directory traversal",
                "Double URL-encoded traversal"
            ])
        
        if traversal_type == "path_injection":
            vectors.extend([
                "Path injection through user input",
                "File path manipulation",
                "Directory path injection"
            ])
        
        if traversal_type == "web_path_traversal":
            vectors.extend([
                "WebView file:// URL manipulation",
                "Content provider path traversal",
                "Intent data path injection"
            ])
        
        if traversal_type == "zip_slip":
            vectors.extend([
                "Zip file entry name manipulation",
                "Archive extraction path traversal",
                "Compressed file path injection"
            ])
        
        if self._detect_user_input_source(context):
            vectors.append("User input manipulation")
        
        return vectors if vectors else ["Unknown attack vector"]
    
    def _is_file_operation(self, context: str) -> bool:
        """Check if context involves file operations."""
        file_ops = ["FileInputStream", "FileOutputStream", "FileReader", "FileWriter", 
                   "File", "createNewFile", "exists", "canRead", "canWrite"]
        return any(op in context for op in file_ops)
    
    def _is_directory_operation(self, context: str) -> bool:
        """Check if context involves directory operations."""
        dir_ops = ["mkdir", "mkdirs", "isDirectory", "listFiles", "list", 
                  "getParent", "getParentFile", "createDirectory"]
        return any(op in context for op in dir_ops)
    
    def _assess_traversal_severity(self, traversal_type: str, allows_external_input: bool) -> VulnerabilitySeverity:
        """Assess severity based on traversal type and input source."""
        if allows_external_input:
            if traversal_type in ["directory_traversal", "web_path_traversal"]:
                return VulnerabilitySeverity.HIGH
            elif traversal_type in ["path_injection", "file_access_bypass", "zip_slip"]:
                return VulnerabilitySeverity.MEDIUM
            else:
                return VulnerabilitySeverity.LOW
        else:
            if traversal_type in ["directory_traversal", "web_path_traversal"]:
                return VulnerabilitySeverity.MEDIUM
            else:
                return VulnerabilitySeverity.LOW
    
    def _calculate_traversal_confidence(self, traversal_type: str, evidence: str, context: str) -> float:
        """Calculate confidence score for path traversal finding."""
        try:
            base_confidence = self.risk_weights.get(traversal_type, 0.5)
            
            # Adjust based on evidence quality
            evidence_boost = 0.0
            if traversal_type == "directory_traversal" and ".." in evidence:
                evidence_boost = 0.3
            elif traversal_type == "path_injection" and "+" in evidence:
                evidence_boost = 0.2
            elif traversal_type == "zip_slip" and "getName" in evidence:
                evidence_boost = 0.2
            
            # Adjust based on user input presence
            input_boost = 0.0
            if self._detect_user_input_source(context):
                input_boost = 0.2
            
            # Reduce confidence if sanitization is present
            sanitization_penalty = 0.0
            if self._check_sanitization(context):
                sanitization_penalty = -0.3
            
            final_confidence = max(0.1, min(1.0, base_confidence + evidence_boost + input_boost + sanitization_penalty))
            return final_confidence
            
        except Exception as e:
            logger.error(f"Error calculating traversal confidence: {str(e)}")
            return 0.5
    
    def _get_mitigation_strategies(self, traversal_type: str) -> List[str]:
        """Get mitigation strategies for path traversal type."""
        strategies = {
            "directory_traversal": [
                "Use absolute paths instead of relative paths",
                "Implement path canonicalization",
                "Validate paths against allowed directories",
                "Use chroot or similar containment mechanisms"
            ],
            "path_injection": [
                "Validate and sanitize user input",
                "Use parameterized file operations",
                "Implement whitelist-based path validation",
                "Use secure file APIs that prevent injection"
            ],
            "unsafe_file_operations": [
                "Use secure file operation APIs",
                "Implement proper path validation",
                "Use file access controls",
                "Avoid user-controlled file paths"
            ],
            "file_access_bypass": [
                "Implement proper access controls",
                "Use security managers",
                "Validate file permissions",
                "Use sandboxing mechanisms"
            ],
            "web_path_traversal": [
                "Disable file:// URL access in WebView",
                "Implement content security policies",
                "Use secure WebView configurations",
                "Validate WebView URLs"
            ],
            "zip_slip": [
                "Validate zip entry names",
                "Use secure extraction methods",
                "Implement path traversal checks",
                "Use zip bomb protection"
            ]
        }
        return strategies.get(traversal_type, [])
    
    def _get_code_examples(self, traversal_type: str) -> List[str]:
        """Get secure code examples for path traversal type."""
        examples = {
            "directory_traversal": [
                "String safePath = file.getCanonicalPath();",
                "Path normalized = Paths.get(userPath).normalize();",
                "if (!safePath.startsWith(baseDir)) { throw new SecurityException(); }"
            ],
            "path_injection": [
                "File baseDir = new File(\"/safe/directory\");",
                "File userFile = new File(baseDir, sanitizeFileName(userInput));",
                "if (!userFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) { /* reject */ }"
            ],
            "zip_slip": [
                "String name = zipEntry.getName();",
                "if (name.contains(\"..\")) { /* reject */ }",
                "File destFile = new File(destDir, name);",
                "if (!destFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())) { /* reject */ }"
            ]
        }
        return examples.get(traversal_type, [])
    
    def _extract_context(self, content: str, start: int, end: int, context_size: int = 150) -> str:
        """Extract context around a match."""
        try:
            context_start = max(0, start - context_size)
            context_end = min(len(content), end + context_size)
            return content[context_start:context_end].strip()
        except Exception:
            return ""
    
    def _filter_and_deduplicate_findings(self, findings: List) -> List:
        """Filter and deduplicate findings using unified deduplication framework."""
        if not findings:
            return findings
        
        # Convert findings to dict format for unified framework
        dict_findings = []
        for finding in findings:
            dict_finding = {
                'title': getattr(finding, 'title', str(finding)),
                'description': getattr(finding, 'description', ''),
                'file_path': getattr(finding, 'file_path', ''),
                'location': getattr(finding, 'location', ''),
                'original_object': finding
            }
            dict_findings.append(dict_finding)
        
        try:
            # Use unified deduplication framework
            result = deduplicate_findings(dict_findings, DeduplicationStrategy.PRESERVATION)
            
            # Convert back to original objects
            unique_findings = []
            for finding in result.unique_findings:
                if 'original_object' in finding:
                    unique_findings.append(finding['original_object'])
            
            return unique_findings
            
        except Exception as e:
            # Fallback to original logic
            return self._filter_and_deduplicate_findings_fallback(findings)
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get path traversal analysis statistics."""
        return {
            "analyzer_type": "path_traversal",
            "statistics": self.analysis_stats.copy(),
            "pattern_counts": {
                pattern_type: len(patterns)
                for pattern_type, patterns in self.path_traversal_patterns.items()
            },
            "analysis_coverage": {
                "total_patterns": sum(len(patterns) for patterns in self.path_traversal_patterns.values()),
                "pattern_types": len(self.path_traversal_patterns),
                "user_input_types": len(self.user_input_patterns),
                "risk_levels": len(PathTraversalRisk),
                "severity_levels": len(VulnerabilitySeverity)
            }
        } 