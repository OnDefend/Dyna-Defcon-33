"""
Main Injection Analyzer for Code Quality & Injection Analysis Plugin

This module orchestrates all injection analysis types and provides a unified interface.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from core.apk_ctx import APKContext
from .data_structures import CodeVulnerability, AnalysisResult, AnalysisConfig, VulnerabilityType
from .pattern_libraries import InjectionPatterns
from .sql_injection_analyzer import SQLInjectionAnalyzer

logger = logging.getLogger(__name__)

class CodeQualityInjectionAnalyzer:
    """Main analyzer that orchestrates all injection vulnerability detection"""
    
    def __init__(self, config: AnalysisConfig = None):
        """Initialize the code quality injection analyzer"""
        self.config = config or AnalysisConfig()
        self.pattern_library = InjectionPatterns()
        self.logger = logging.getLogger(__name__)
        
        # Initialize specialized analyzers
        self.sql_analyzer = SQLInjectionAnalyzer()
        
        # Initialize pattern sets
        self.injection_patterns = self._initialize_injection_patterns()
        self.unsafe_patterns = self._initialize_unsafe_patterns()
    
    def analyze_code_quality_injection(self, apk_ctx: APKContext) -> AnalysisResult:
        """
        Perform comprehensive code quality and injection analysis
        
        Args:
            apk_ctx: APK context with analysis targets
            
        Returns:
            AnalysisResult: Complete analysis results
        """
        vulnerabilities = []
        total_files = 0
        patterns_matched = {}
        errors = []
        
        try:
            # Get all Java/Kotlin files for analysis
            java_files = self._get_java_files(apk_ctx)
            total_files = len(java_files)
            
            self.logger.info(f"Analyzing {total_files} Java/Kotlin files for injection vulnerabilities")
            
            for file_path in java_files:
                try:
                    content = self._read_file_safely(file_path)
                    if content:
                        file_vulns = self._analyze_file(file_path, content)
                        vulnerabilities.extend(file_vulns)
                        
                        # Update pattern statistics
                        for vuln in file_vulns:
                            vuln_type = vuln.vuln_type
                            patterns_matched[vuln_type] = patterns_matched.get(vuln_type, 0) + 1
                            
                except Exception as e:
                    error_msg = f"Error analyzing file {file_path}: {str(e)}"
                    self.logger.error(error_msg)
                    errors.append(error_msg)
            
            # Generate summary
            summary = self._generate_summary(vulnerabilities)
            
            result = AnalysisResult(
                vulnerabilities=vulnerabilities,
                total_files_analyzed=total_files,
                analysis_duration=0.0,  # Will be calculated by caller
                patterns_matched=patterns_matched,
                summary=summary,
                errors=errors
            )
            
            self.logger.info(f"Analysis complete: {len(vulnerabilities)} vulnerabilities found")
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return AnalysisResult(
                vulnerabilities=[],
                total_files_analyzed=0,
                analysis_duration=0.0,
                patterns_matched={},
                summary={},
                errors=[str(e)]
            )
    
    def _analyze_file(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze a single file for all injection types"""
        vulnerabilities = []
        
        # SQL Injection Analysis
        if self.config.enable_sql_injection:
            sql_vulns = self.sql_analyzer.analyze_sql_injection(file_path, content)
            vulnerabilities.extend(sql_vulns)
        
        # XSS WebView Analysis
        if self.config.enable_xss_analysis:
            xss_vulns = self._analyze_xss_webview(file_path, content)
            vulnerabilities.extend(xss_vulns)
        
        # Code Injection Analysis
        if self.config.enable_code_injection:
            code_vulns = self._analyze_code_injection(file_path, content)
            vulnerabilities.extend(code_vulns)
        
        # Object Injection Analysis
        if self.config.enable_object_injection:
            obj_vulns = self._analyze_object_injection(file_path, content)
            vulnerabilities.extend(obj_vulns)
        
        # Path Traversal Analysis
        if self.config.enable_path_traversal:
            path_vulns = self._analyze_path_traversal(file_path, content)
            vulnerabilities.extend(path_vulns)
        
        # Command Injection Analysis
        if self.config.enable_command_injection:
            cmd_vulns = self._analyze_command_injection(file_path, content)
            vulnerabilities.extend(cmd_vulns)
        
        # Unsafe Pattern Analysis
        if self.config.enable_unsafe_patterns:
            unsafe_vulns = self._analyze_unsafe_patterns(file_path, content)
            vulnerabilities.extend(unsafe_vulns)
        
        return vulnerabilities
    
    def _analyze_xss_webview(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze for XSS vulnerabilities in WebViews"""
        vulnerabilities = []
        patterns = self.pattern_library.get_xss_webview_patterns()
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//'):
                continue
            
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    vulnerability = CodeVulnerability(
                        vuln_type=VulnerabilityType.XSS_WEBVIEW.value,
                        location=file_path,
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH",
                        description=f"Potential XSS vulnerability in WebView: {Path(file_path).name}",
                        payload=self._generate_xss_payload(line),
                        context=line.strip()
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_code_injection(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze for code injection vulnerabilities"""
        vulnerabilities = []
        patterns = self.pattern_library.get_code_injection_patterns()
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    vulnerability = CodeVulnerability(
                        vuln_type=VulnerabilityType.CODE_INJECTION.value,
                        location=file_path,
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH",
                        description=f"Potential code injection vulnerability: {Path(file_path).name}",
                        payload=self._generate_code_injection_payload(line),
                        context=line.strip()
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_object_injection(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze for object injection vulnerabilities"""
        vulnerabilities = []
        patterns = self.pattern_library.get_object_injection_patterns()
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    vulnerability = CodeVulnerability(
                        vuln_type=VulnerabilityType.OBJECT_INJECTION.value,
                        location=file_path,
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH",
                        description=f"Potential object injection vulnerability: {Path(file_path).name}",
                        payload=self._generate_object_injection_payload(line),
                        context=line.strip()
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_path_traversal(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze for path traversal vulnerabilities"""
        vulnerabilities = []
        patterns = self.pattern_library.get_path_traversal_patterns()
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    vulnerability = CodeVulnerability(
                        vuln_type=VulnerabilityType.PATH_TRAVERSAL.value,
                        location=file_path,
                        value=line.strip(),
                        line_number=line_num,
                        severity="MEDIUM",
                        description=f"Potential path traversal vulnerability: {Path(file_path).name}",
                        payload=self._generate_path_traversal_payload(line),
                        context=line.strip()
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_command_injection(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze for command injection vulnerabilities"""
        vulnerabilities = []
        patterns = self.pattern_library.get_command_injection_patterns()
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    vulnerability = CodeVulnerability(
                        vuln_type=VulnerabilityType.COMMAND_INJECTION.value,
                        location=file_path,
                        value=line.strip(),
                        line_number=line_num,
                        severity="HIGH",
                        description=f"Potential command injection vulnerability: {Path(file_path).name}",
                        payload=self._generate_command_injection_payload(line),
                        context=line.strip()
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_unsafe_patterns(self, file_path: str, content: str) -> List[CodeVulnerability]:
        """Analyze for unsafe coding patterns"""
        vulnerabilities = []
        patterns = self.pattern_library.get_unsafe_patterns()
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if pattern.lower() in line.lower():
                        vulnerability = CodeVulnerability(
                            vuln_type=VulnerabilityType.UNSAFE_PATTERN.value,
                            location=file_path,
                            value=line.strip(),
                            line_number=line_num,
                            severity="MEDIUM",
                            description=f"Unsafe coding pattern detected ({pattern_type}): {Path(file_path).name}",
                            context=line.strip()
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_xss_payload(self, line: str) -> str:
        """Generate XSS payload for testing"""
        return "<script>alert('XSS')</script>"
    
    def _generate_code_injection_payload(self, line: str) -> str:
        """Generate code injection payload for testing"""
        return "System.exit(0);"
    
    def _generate_object_injection_payload(self, line: str) -> str:
        """Generate object injection payload for testing"""
        return "malicious_serialized_object"
    
    def _generate_path_traversal_payload(self, line: str) -> str:
        """Generate path traversal payload for testing"""
        return "../../../etc/passwd"
    
    def _generate_command_injection_payload(self, line: str) -> str:
        """Generate command injection payload for testing"""
        return "; cat /etc/passwd"
    
    def _get_java_files(self, apk_ctx: APKContext) -> List[str]:
        """Get list of Java/Kotlin files to analyze"""
        java_files = []
        
        try:
            # Get decompiled Java files
            for java_file in apk_ctx.get_java_files():
                if self._should_analyze_file(java_file):
                    java_files.append(java_file)
        except Exception as e:
            self.logger.error(f"Error getting Java files: {e}")
        
        return java_files
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if a file should be analyzed"""
        # Skip test files if configured
        if not self.config.include_test_files and 'test' in file_path.lower():
            return False
        
        # Check file size limit
        try:
            file_size = Path(file_path).stat().st_size
            if file_size > self.config.max_file_size:
                return False
        except Exception:
            pass
        
        return True
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _generate_summary(self, vulnerabilities: List[CodeVulnerability]) -> Dict[str, Any]:
        """Generate analysis summary"""
        total_vulnerabilities = len(vulnerabilities)
        
        # Count by type
        type_counts = {}
        severity_counts = {}
        
        for vuln in vulnerabilities:
            type_counts[vuln.vuln_type] = type_counts.get(vuln.vuln_type, 0) + 1
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        return {
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerabilities_by_type": type_counts,
            "vulnerabilities_by_severity": severity_counts,
            "risk_score": self._calculate_risk_score(vulnerabilities)
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[CodeVulnerability]) -> float:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {
            "CRITICAL": 4.0,
            "HIGH": 3.0,
            "MEDIUM": 2.0,
            "LOW": 1.0,
            "INFO": 0.5
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            weight = severity_weights.get(vuln.severity, 1.0)
            total_score += weight * vuln.confidence
        
        # Normalize to 0-100 scale
        max_possible = len(vulnerabilities) * 4.0
        return min(100.0, (total_score / max_possible) * 100) if max_possible > 0 else 0.0
    
    def _initialize_injection_patterns(self) -> Dict[str, List[str]]:
        """Initialize injection patterns (legacy compatibility)"""
        return {
            "sql_injection": self.pattern_library.get_sql_injection_patterns(),
            "xss_webview": self.pattern_library.get_xss_webview_patterns(),
            "code_injection": self.pattern_library.get_code_injection_patterns(),
            "object_injection": self.pattern_library.get_object_injection_patterns(),
            "path_traversal": self.pattern_library.get_path_traversal_patterns(),
            "command_injection": self.pattern_library.get_command_injection_patterns()
        }
    
    def _initialize_unsafe_patterns(self) -> Dict[str, List[str]]:
        """Initialize unsafe patterns (legacy compatibility)"""
        return self.pattern_library.get_unsafe_patterns() 