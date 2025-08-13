"""
Injection Vulnerabilities - Static Analyzer Component

This module provides static analysis capabilities for SQL injection vulnerabilities
including AndroidManifest.xml analysis and code pattern detection.
"""

import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import xml.etree.ElementTree as ET

from core.apk_ctx import APKContext
from plugins.injection_vulnerabilities.data_structures import (
    StaticAnalysisResult, ContentProviderAnalysis, SQLPatternAnalysis,
    InjectionVulnerability, VulnerabilityType, SeverityLevel, RiskLevel,
    AnalysisMethod, ProviderSecurityLevel, InjectionAnalysisConfiguration,
    create_sql_injection_vulnerability, create_provider_analysis
)

# Import graceful shutdown support
try:
    from core.graceful_shutdown_manager import is_shutdown_requested
    GRACEFUL_SHUTDOWN_AVAILABLE = True
except ImportError:
    GRACEFUL_SHUTDOWN_AVAILABLE = False
    def is_shutdown_requested():
        return False

class StaticInjectionAnalyzer:
    """Static analyzer for injection vulnerabilities."""
    
    def __init__(self, config: Optional[InjectionAnalysisConfiguration] = None):
        """Initialize the static analyzer."""
        self.config = config or InjectionAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        self.sql_patterns = self._load_sql_patterns()
    
    def _load_sql_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load SQL injection patterns for code analysis."""
        return {
            'string_concatenation_query': {
                'pattern': r'query\([^)]*\+[^)]*\)',
                'description': 'String concatenation in SQL query method',
                'severity': SeverityLevel.HIGH,
                'confidence': 0.8,
                'cwe_id': 'CWE-89'
            },
            'string_concatenation_raw_query': {
                'pattern': r'rawQuery\([^)]*\+[^)]*\)',
                'description': 'String concatenation in rawQuery method',
                'severity': SeverityLevel.HIGH,
                'confidence': 0.9,
                'cwe_id': 'CWE-89'
            },
            'string_concatenation_exec_sql': {
                'pattern': r'execSQL\([^)]*\+[^)]*\)',
                'description': 'String concatenation in execSQL method',
                'severity': SeverityLevel.CRITICAL,
                'confidence': 0.95,
                'cwe_id': 'CWE-89'
            },
            'direct_string_in_query': {
                'pattern': r'(?:query|rawQuery|execSQL)\s*\([^)]*"[^"]*"\s*\+[^)]*\)',
                'description': 'Direct string concatenation in SQL method',
                'severity': SeverityLevel.HIGH,
                'confidence': 0.85,
                'cwe_id': 'CWE-89'
            },
            'user_input_in_sql': {
                'pattern': r'(?:query|rawQuery|execSQL)\s*\([^)]*(?:getText|getStringExtra|getParam)[^)]*\)',
                'description': 'User input directly used in SQL method',
                'severity': SeverityLevel.CRITICAL,
                'confidence': 0.9,
                'cwe_id': 'CWE-89'
            },
            'sql_without_params': {
                'pattern': r'(?:query|rawQuery)\s*\([^,]*,\s*null\s*,',
                'description': 'SQL query without parameterized arguments',
                'severity': SeverityLevel.MEDIUM,
                'confidence': 0.6,
                'cwe_id': 'CWE-89'
            },
            'content_values_concat': {
                'pattern': r'ContentValues.*put\([^)]*\+[^)]*\)',
                'description': 'String concatenation in ContentValues',
                'severity': SeverityLevel.MEDIUM,
                'confidence': 0.7,
                'cwe_id': 'CWE-89'
            },
            'selection_args_concat': {
                'pattern': r'selectionArgs.*\+|selection.*\+',
                'description': 'String concatenation in selection arguments',
                'severity': SeverityLevel.HIGH,
                'confidence': 0.8,
                'cwe_id': 'CWE-89'
            }
        }
    
    def analyze_static_vulnerabilities(self, apk_ctx: APKContext) -> StaticAnalysisResult:
        """Perform comprehensive static analysis for SQL injection vulnerabilities."""
        start_time = time.time()
        
        # Check for shutdown at the beginning
        if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
            self.logger.info("Static analysis cancelled due to shutdown request")
            return StaticAnalysisResult()
        
        result = StaticAnalysisResult()
        
        try:
            # Analyze AndroidManifest.xml
            if self.config.enable_manifest_analysis:
                result.manifest_analysis = self._analyze_manifest(apk_ctx)
            
            # Analyze code patterns
            if self.config.enable_code_analysis:
                result.code_patterns = self._analyze_code_patterns(apk_ctx)
            
            result.analysis_time = time.time() - start_time
            
            self.logger.info(f"Static analysis completed in {result.analysis_time:.1f}s")
            return result
            
        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            result.analysis_time = time.time() - start_time
            return result
    
    def _analyze_manifest(self, apk_ctx: APKContext) -> List[ContentProviderAnalysis]:
        """Analyze AndroidManifest.xml for content provider vulnerabilities."""
        providers = []
        
        try:
            # Check for shutdown
            if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                return providers
            
            manifest_path = self._get_manifest_path(apk_ctx)
            if not manifest_path or not os.path.exists(manifest_path):
                self.logger.info("AndroidManifest.xml not available for injection analysis - skipping manifest-based checks")
                return providers
            
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Find all content providers
            for provider in root.findall(".//provider"):
                # Check for shutdown during processing
                if GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                    break
                
                provider_analysis = self._analyze_provider(provider)
                if provider_analysis:
                    providers.append(provider_analysis)
            
            self.logger.info(f"Analyzed {len(providers)} content providers")
            
        except ET.ParseError as e:
            self.logger.error(f"Failed to parse AndroidManifest.xml: {e}")
        except Exception as e:
            self.logger.error(f"Manifest analysis failed: {e}")
        
        return providers
    
    def _analyze_provider(self, provider: ET.Element) -> Optional[ContentProviderAnalysis]:
        """Analyze a single content provider element."""
        try:
            # Extract basic information
            name = provider.get('{http://schemas.android.com/apk/res/android}name', 'unknown')
            authority = provider.get('{http://schemas.android.com/apk/res/android}authorities', 'unknown')
            exported = provider.get('{http://schemas.android.com/apk/res/android}exported', 'false').lower() == 'true'
            
            # Extract permissions
            permissions = []
            read_permission = provider.get('{http://schemas.android.com/apk/res/android}readPermission')
            write_permission = provider.get('{http://schemas.android.com/apk/res/android}writePermission')
            permission = provider.get('{http://schemas.android.com/apk/res/android}permission')
            
            if read_permission:
                permissions.append(read_permission)
            if write_permission:
                permissions.append(write_permission)
            if permission:
                permissions.append(permission)
            
            # Extract other attributes
            grant_uri_permissions = provider.get(
                '{http://schemas.android.com/apk/res/android}grantUriPermissions', 'false'
            ).lower() == 'true'
            
            # Create provider analysis
            provider_analysis = create_provider_analysis(
                authority=authority,
                name=name,
                exported=exported,
                permissions=permissions,
                grant_uri_permissions=grant_uri_permissions,
                read_permission=read_permission,
                write_permission=write_permission
            )
            
            # Check for vulnerabilities
            if exported and not permissions:
                # Exported provider without permissions is vulnerable
                vulnerability = create_sql_injection_vulnerability(
                    description=f"Exported content provider '{authority}' without permissions",
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    location=f"AndroidManifest.xml - {name}",
                    method=AnalysisMethod.STATIC_MANIFEST,
                    evidence=f"Provider '{authority}' is exported without read/write permissions"
                )
                provider_analysis.vulnerabilities.append(vulnerability)
                provider_analysis.security_level = ProviderSecurityLevel.VULNERABLE
            
            return provider_analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze provider: {e}")
            return None
    
    def _analyze_code_patterns(self, apk_ctx: APKContext) -> List[SQLPatternAnalysis]:
        """Analyze code for SQL injection patterns."""
        patterns = []
        
        # Get code directory
        code_dir = self._get_code_directory(apk_ctx)
        if not code_dir or not os.path.exists(code_dir):
            self.logger.info("Decompiled code directory not available for injection analysis - skipping code-based checks")
            return patterns
        
        try:
            file_count = 0
            
            for root, dirs, files in os.walk(code_dir):
                for file in files:
                    # Check for shutdown periodically
                    if file_count % 50 == 0 and GRACEFUL_SHUTDOWN_AVAILABLE and is_shutdown_requested():
                        self.logger.info("Code analysis cancelled due to shutdown request")
                        return patterns
                    
                    if file.endswith('.java') or file.endswith('.kt'):
                        file_count += 1
                        
                        # Limit analysis for performance
                        if file_count > self.config.max_files_to_analyze:
                            self.logger.info(f"Code analysis limited to {self.config.max_files_to_analyze} files")
                            break
                        
                        # Skip test files if configured
                        if self.config.exclude_test_files and 'test' in file.lower():
                            continue
                        
                        file_path = os.path.join(root, file)
                        file_patterns = self._analyze_file_patterns(file_path)
                        patterns.extend(file_patterns)
            
            self.logger.info(f"Analyzed {file_count} code files, found {len(patterns)} patterns")
            
        except Exception as e:
            self.logger.error(f"Code pattern analysis failed: {e}")
        
        return patterns
    
    def _get_code_directory(self, apk_ctx: APKContext) -> Optional[str]:
        """Get the decompiled code directory from APK context."""
        # Try multiple potential locations for decompiled code
        potential_dirs = [
            getattr(apk_ctx, 'decompiled_path', None),
            getattr(apk_ctx, 'source_dir', None),
            getattr(apk_ctx, 'workspace_dir', None),
        ]
        
        # Also check workspace for decompiled directories
        if hasattr(apk_ctx, 'workspace_dir') and apk_ctx.workspace_dir:
            import glob
            workspace_pattern = os.path.join(apk_ctx.workspace_dir, '*_decompiled')
            potential_dirs.extend(glob.glob(workspace_pattern))
            
            # Check for common decompiled APK directories
            common_dirs = [
                os.path.join(apk_ctx.workspace_dir, '*_decompiled'),
                os.path.join(apk_ctx.workspace_dir, 'decompiled_*')
            ]
            for pattern in common_dirs:
                potential_dirs.extend(glob.glob(pattern))
        
        for code_dir in potential_dirs:
            if code_dir and os.path.exists(code_dir):
                # Verify it contains Java files
                for root, dirs, files in os.walk(code_dir):
                    if any(f.endswith('.java') for f in files):
                        self.logger.info(f"Found decompiled code directory: {code_dir}")
                        return code_dir
                        
        self.logger.warning("No decompiled code directory found for injection analysis")
        return None
    
    def _analyze_file_patterns(self, file_path: str) -> List[SQLPatternAnalysis]:
        """Analyze a single file for SQL injection patterns."""
        patterns = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Apply SQL injection patterns
            for pattern_name, pattern_info in self.sql_patterns.items():
                matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE)
                
                for match in matches:
                    # Get line number
                    line_number = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet
                    lines = content.split('\n')
                    snippet_start = max(0, line_number - 2)
                    snippet_end = min(len(lines), line_number + 1)
                    code_snippet = '\n'.join(lines[snippet_start:snippet_end])
                    
                    # Create pattern analysis
                    pattern_analysis = SQLPatternAnalysis(
                        pattern_type=pattern_name,
                        description=pattern_info['description'],
                        risk_level=self._severity_to_risk(pattern_info['severity']),
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=code_snippet,
                        confidence=pattern_info['confidence']
                    )
                    
                    patterns.append(pattern_analysis)
            
        except Exception as e:
            self.logger.debug(f"Failed to analyze file {file_path}: {e}")
        
        return patterns
    
    def _get_manifest_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Get path to AndroidManifest.xml."""
        # Try APKTool output directory first
        if hasattr(apk_ctx, 'apktool_output_dir') and apk_ctx.apktool_output_dir:
            manifest_path = Path(apk_ctx.apktool_output_dir) / "AndroidManifest.xml"
            if manifest_path.exists():
                return str(manifest_path)
        
        # Try extraction directory
        if hasattr(apk_ctx, 'extraction_path') and apk_ctx.extraction_path:
            manifest_path = Path(apk_ctx.extraction_path) / "AndroidManifest.xml"
            if manifest_path.exists():
                return str(manifest_path)
        
        # Try to construct from APK path
        if apk_ctx.apk_path:
            apk_name = os.path.basename(apk_ctx.apk_path).replace('.apk', '')
            base_dir = os.path.dirname(apk_ctx.apk_path)
            
            # Try different directory patterns
            possible_paths = [
                os.path.join(base_dir, f"{apk_name}_extracted", "AndroidManifest.xml"),
                os.path.join(base_dir, f"{apk_name}_apktool", "AndroidManifest.xml"),
                os.path.join(base_dir, "AndroidManifest.xml")
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    return path
        
        return None
    
    def _get_code_directory(self, apk_ctx: APKContext) -> Optional[str]:
        """Get directory containing decompiled code."""
        # Try JADX output directory first
        if hasattr(apk_ctx, 'jadx_output_dir') and apk_ctx.jadx_output_dir:
            if os.path.exists(apk_ctx.jadx_output_dir):
                return apk_ctx.jadx_output_dir
        
        # Try extraction directory
        if hasattr(apk_ctx, 'extraction_path') and apk_ctx.extraction_path:
            sources_dir = os.path.join(apk_ctx.extraction_path, 'sources')
            if os.path.exists(sources_dir):
                return sources_dir
        
        # Try to construct from APK path
        if apk_ctx.apk_path:
            apk_name = os.path.basename(apk_ctx.apk_path).replace('.apk', '')
            base_dir = os.path.dirname(apk_ctx.apk_path)
            
            # Try different directory patterns
            possible_paths = [
                os.path.join(base_dir, f"{apk_name}_extracted", "sources"),
                os.path.join(base_dir, f"{apk_name}_jadx", "sources"),
                os.path.join(base_dir, f"{apk_name}_jadx")
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    return path
        
        return None
    
    def _severity_to_risk(self, severity: SeverityLevel) -> RiskLevel:
        """Convert severity level to risk level."""
        mapping = {
            SeverityLevel.CRITICAL: RiskLevel.CRITICAL,
            SeverityLevel.HIGH: RiskLevel.HIGH,
            SeverityLevel.MEDIUM: RiskLevel.MEDIUM,
            SeverityLevel.LOW: RiskLevel.LOW,
            SeverityLevel.INFO: RiskLevel.LOW
        }
        return mapping.get(severity, RiskLevel.UNKNOWN)
    
    def get_vulnerabilities_from_analysis(self, result: StaticAnalysisResult) -> List[InjectionVulnerability]:
        """Extract vulnerabilities from static analysis result."""
        vulnerabilities = []
        
        # Get vulnerabilities from manifest analysis
        for provider in result.manifest_analysis:
            vulnerabilities.extend(provider.vulnerabilities)
        
        # Convert code patterns to vulnerabilities
        for pattern in result.code_patterns:
            if pattern.confidence >= self.config.confidence_threshold:
                vulnerability = create_sql_injection_vulnerability(
                    description=pattern.description,
                    severity=self._risk_to_severity(pattern.risk_level),
                    confidence=pattern.confidence,
                    location=pattern.file_path,
                    method=AnalysisMethod.STATIC_CODE,
                    evidence=pattern.code_snippet or "Code pattern detected",
                    line_number=pattern.line_number,
                    code_snippet=pattern.code_snippet
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _risk_to_severity(self, risk: RiskLevel) -> SeverityLevel:
        """Convert risk level to severity level."""
        mapping = {
            RiskLevel.CRITICAL: SeverityLevel.CRITICAL,
            RiskLevel.HIGH: SeverityLevel.HIGH,
            RiskLevel.MEDIUM: SeverityLevel.MEDIUM,
            RiskLevel.LOW: SeverityLevel.LOW,
            RiskLevel.UNKNOWN: SeverityLevel.INFO
        }
        return mapping.get(risk, SeverityLevel.INFO)
    
    def get_analysis_summary(self, result: StaticAnalysisResult) -> Dict[str, Any]:
        """Generate summary of static analysis results."""
        summary = {
            'analysis_method': 'static_analysis',
            'analysis_time': result.analysis_time,
            'files_analyzed': result.total_files_analyzed,
            'providers_analyzed': len(result.manifest_analysis),
            'code_patterns_found': len(result.code_patterns)
        }
        
        # Count exported providers
        exported_providers = sum(1 for p in result.manifest_analysis if p.exported)
        vulnerable_providers = sum(1 for p in result.manifest_analysis if p.vulnerabilities)
        
        summary['exported_providers'] = exported_providers
        summary['vulnerable_providers'] = vulnerable_providers
        
        # Count patterns by risk level
        risk_counts = {}
        for pattern in result.code_patterns:
            risk = pattern.risk_level.value
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        summary['risk_breakdown'] = risk_counts
        
        return summary 