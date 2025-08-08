#!/usr/bin/env python3
"""
Code Obfuscation Analyzer Module

Comprehensive code obfuscation analysis for anti-tampering security assessment.
Analyzes various obfuscation techniques, their implementation quality,
and effectiveness against reverse engineering.

Features:
- Multi-layered obfuscation detection
- Obfuscation technique assessment
- Effectiveness evaluation
- confidence calculation
- Pattern-based detection with reliability scoring
"""

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
import statistics

from core.shared_infrastructure.dependency_injection import AnalysisContext

from .data_structures import (
    AntiTamperingVulnerability,
    AntiTamperingMechanismType,
    TamperingVulnerabilitySeverity,
    DetectionStrength,
    BypassResistance,
    AnalysisMethod,
    CodeObfuscationAnalysis
)

logger = logging.getLogger(__name__)

@dataclass
class ObfuscationMetrics:
    """Metrics for code obfuscation analysis."""
    total_classes: int = 0
    obfuscated_classes: int = 0
    total_methods: int = 0
    obfuscated_methods: int = 0
    total_fields: int = 0
    obfuscated_fields: int = 0
    string_literals: int = 0
    obfuscated_strings: int = 0
    control_flow_complexity: float = 0.0
    
    @property
    def class_obfuscation_ratio(self) -> float:
        return self.obfuscated_classes / max(1, self.total_classes)
    
    @property
    def method_obfuscation_ratio(self) -> float:
        return self.obfuscated_methods / max(1, self.total_methods)
    
    @property
    def field_obfuscation_ratio(self) -> float:
        return self.obfuscated_fields / max(1, self.total_fields)
    
    @property
    def string_obfuscation_ratio(self) -> float:
        return self.obfuscated_strings / max(1, self.string_literals)

class CodeObfuscationAnalyzer:
    """
    Comprehensive code obfuscation analyzer.
    
    Analyzes applications for various obfuscation techniques including:
    - Class name obfuscation
    - Method name obfuscation
    - Field name obfuscation
    - String obfuscation
    - Control flow obfuscation
    - Dead code insertion
    - Code packing
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize code obfuscation analyzer.
        
        Args:
            context: Analysis context with dependencies
        """
        self.context = context
        self.logger = context.logger
        self.confidence_calculator = context.get_dependency('confidence_calculator')
        
        # Analysis configuration
        self.max_analysis_time = context.config.get('max_analysis_time', 120)
        self.enable_deep_analysis = context.config.get('enable_deep_analysis', True)
        
        # Obfuscation patterns
        self._initialize_obfuscation_patterns()
        
        # Analysis state
        self.metrics = ObfuscationMetrics()
        self.obfuscation_techniques = []
        
    def _initialize_obfuscation_patterns(self):
        """Initialize obfuscation detection patterns."""
        self.patterns = {
            'class_name_obfuscation': [
                r'\bclass\s+[a-z]{1,3}\b',  # Very short class names
                r'\bclass\s+[A-Z]{1,2}\b',  # Very short uppercase class names
                r'\bclass\s+[a-zA-Z0-9_]{32,}\b',  # Very long class names
                r'\bclass\s+[Il1O0]+\b',  # Confusing character combinations
            ],
            'method_name_obfuscation': [
                r'\b(?:public|private|protected)\s+\w+\s+[a-z]{1,2}\s*\(',  # Very short method names
                r'\b(?:public|private|protected)\s+\w+\s+[A-Z]{1,2}\s*\(',  # Very short uppercase methods
                r'\b(?:public|private|protected)\s+\w+\s+[a-zA-Z0-9_]{25,}\s*\(',  # Very long methods
                r'\b(?:public|private|protected)\s+\w+\s+[Il1O0]+\s*\(',  # Confusing characters
            ],
            'field_name_obfuscation': [
                r'\b(?:public|private|protected)\s+\w+\s+[a-z]{1,2}\s*[;=]',  # Very short field names
                r'\b(?:public|private|protected)\s+\w+\s+[A-Z]{1,2}\s*[;=]',  # Very short uppercase fields
                r'\b(?:public|private|protected)\s+\w+\s+[Il1O0]+\s*[;=]',  # Confusing characters
            ],
            'string_obfuscation': [
                r'"[A-Za-z0-9+/]{20,}={0,2}"',  # Base64-like strings
                r'"\\u[0-9a-fA-F]{4}',  # Unicode escape sequences
                r'new\s+String\s*\(\s*new\s+byte\s*\[',  # Byte array strings
                r'decrypt\s*\(\s*"[^"]+"\s*\)',  # Decrypt function calls
                r'decode\s*\(\s*"[^"]+"\s*\)',  # Decode function calls
            ],
            'control_flow_obfuscation': [
                r'switch\s*\(\s*\w+\s*\)\s*\{[^}]*case\s+\d+:[^}]*case\s+\d+:',  # Switch-based obfuscation
                r'goto\s+\w+',  # Goto statements
                r'while\s*\(\s*true\s*\)\s*\{[^}]*if[^}]*break[^}]*\}',  # Endless loops with breaks
                r'for\s*\(\s*int\s+\w+\s*=\s*\d+\s*;[^;]*;[^)]*\)\s*\{[^}]*if[^}]*continue[^}]*\}',  # Complex for loops
            ],
            'dead_code_patterns': [
                r'if\s*\(\s*false\s*\)\s*\{',  # Dead if blocks
                r'if\s*\(\s*true\s*\)\s*\{[^}]*\}\s*else\s*\{',  # Always true conditions
                r'return\s+[^;]+;\s*[^}]+',  # Unreachable code after return
            ],
            'reflection_obfuscation': [
                r'Class\.forName\s*\(\s*"[^"]+"\s*\)',  # Dynamic class loading
                r'\.getDeclaredMethod\s*\(\s*"[^"]+"\s*',  # Dynamic method access
                r'\.getDeclaredField\s*\(\s*"[^"]+"\s*',  # Dynamic field access
                r'Method\.invoke\s*\(',  # Method invocation
            ]
        }
    
    def analyze(self, apk_ctx) -> CodeObfuscationAnalysis:
        """
        Perform comprehensive code obfuscation analysis.
        
        Args:
            apk_ctx: APK context containing analysis data
            
        Returns:
            CodeObfuscationAnalysis: Comprehensive analysis results
        """
        start_time = time.time()
        analysis = CodeObfuscationAnalysis()
        
        try:
            self.logger.info("Starting code obfuscation analysis")
            
            # Extract content for analysis
            content_data = self._extract_content_for_analysis(apk_ctx)
            
            # Analyze obfuscation techniques
            self._analyze_name_obfuscation(content_data, analysis)
            self._analyze_string_obfuscation(content_data, analysis)
            self._analyze_control_flow_obfuscation(content_data, analysis)
            
            # Calculate obfuscation level and metrics
            self._calculate_obfuscation_metrics(analysis)
            self._assess_obfuscation_effectiveness(analysis)
            
            # Generate recommendations
            self._generate_recommendations(analysis)
            
            analysis_duration = time.time() - start_time
            self.logger.info(f"Code obfuscation analysis completed in {analysis_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Code obfuscation analysis failed: {e}")
            self._create_error_analysis(analysis, str(e))
        
        return analysis
    
    def _extract_content_for_analysis(self, apk_ctx) -> Dict[str, str]:
        """Extract content from various sources for obfuscation analysis."""
        content_data = {}
        
        try:
            # Get source files
            if hasattr(apk_ctx, 'get_source_files'):
                source_files = apk_ctx.get_source_files()
                for file_path in source_files:
                    if self._is_relevant_for_obfuscation_analysis(file_path):
                        content = self._read_file_safely(file_path)
                        if content:
                            content_data[file_path] = content
            
            # Get smali files if available (better for obfuscation analysis)
            if hasattr(apk_ctx, 'get_smali_files'):
                smali_files = apk_ctx.get_smali_files()
                for file_path in smali_files:
                    content = self._read_file_safely(file_path)
                    if content:
                        content_data[file_path] = content
                        
        except Exception as e:
            self.logger.warning(f"Failed to extract content for obfuscation analysis: {e}")
        
        return content_data
    
    def _analyze_name_obfuscation(self, content_data: Dict[str, str], analysis: CodeObfuscationAnalysis):
        """Analyze name obfuscation (classes, methods, fields)."""
        class_names = []
        method_names = []
        field_names = []
        
        for file_path, content in content_data.items():
            # Extract class names
            class_matches = re.findall(r'\bclass\s+(\w+)', content, re.IGNORECASE)
            class_names.extend(class_matches)
            
            # Extract method names
            method_matches = re.findall(r'(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', content)
            method_names.extend(method_matches)
            
            # Extract field names
            field_matches = re.findall(r'(?:public|private|protected)\s+\w+\s+(\w+)\s*[;=]', content)
            field_names.extend(field_matches)
        
        # Analyze obfuscation patterns
        self.metrics.total_classes = len(class_names)
        self.metrics.total_methods = len(method_names)
        self.metrics.total_fields = len(field_names)
        
        # Check for obfuscated names
        self.metrics.obfuscated_classes = self._count_obfuscated_names(class_names)
        self.metrics.obfuscated_methods = self._count_obfuscated_names(method_names)
        self.metrics.obfuscated_fields = self._count_obfuscated_names(field_names)
        
        # Update analysis flags
        analysis.class_name_obfuscation = self.metrics.class_obfuscation_ratio > 0.3
        analysis.method_name_obfuscation = self.metrics.method_obfuscation_ratio > 0.3
        
        # Add obfuscation techniques
        if analysis.class_name_obfuscation:
            analysis.obfuscation_techniques.append("Class Name Obfuscation")
        if analysis.method_name_obfuscation:
            analysis.obfuscation_techniques.append("Method Name Obfuscation")
    
    def _analyze_string_obfuscation(self, content_data: Dict[str, str], analysis: CodeObfuscationAnalysis):
        """Analyze string obfuscation techniques."""
        total_strings = 0
        obfuscated_strings = 0
        
        for file_path, content in content_data.items():
            # Count total string literals
            string_matches = re.findall(r'"[^"]*"', content)
            total_strings += len(string_matches)
            
            # Check for obfuscated strings
            for pattern_type, patterns in self.patterns.items():
                if 'string' in pattern_type:
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        obfuscated_strings += len(matches)
        
        self.metrics.string_literals = total_strings
        self.metrics.obfuscated_strings = min(obfuscated_strings, total_strings)  # Cap at total
        
        analysis.string_obfuscation = self.metrics.string_obfuscation_ratio > 0.1
        
        if analysis.string_obfuscation:
            analysis.obfuscation_techniques.append("String Obfuscation")
    
    def _analyze_control_flow_obfuscation(self, content_data: Dict[str, str], analysis: CodeObfuscationAnalysis):
        """Analyze control flow obfuscation techniques."""
        complexity_scores = []
        control_flow_indicators = 0
        
        for file_path, content in content_data.items():
            # Calculate cyclomatic complexity indicators
            complexity = self._calculate_complexity_score(content)
            complexity_scores.append(complexity)
            
            # Check for control flow obfuscation patterns
            for pattern in self.patterns['control_flow_obfuscation']:
                matches = re.findall(pattern, content, re.DOTALL)
                control_flow_indicators += len(matches)
            
            # Check for dead code patterns
            for pattern in self.patterns['dead_code_patterns']:
                matches = re.findall(pattern, content, re.DOTALL)
                control_flow_indicators += len(matches)
        
        # Calculate average complexity
        if complexity_scores:
            self.metrics.control_flow_complexity = statistics.mean(complexity_scores)
        
        # Determine if control flow is obfuscated
        analysis.control_flow_obfuscation = (
            self.metrics.control_flow_complexity > 15.0 or 
            control_flow_indicators > 5
        )
        
        if analysis.control_flow_obfuscation:
            analysis.obfuscation_techniques.append("Control Flow Obfuscation")
    
    def _count_obfuscated_names(self, names: List[str]) -> int:
        """Count how many names appear to be obfuscated."""
        obfuscated_count = 0
        
        for name in names:
            # Very short names (likely obfuscated)
            if len(name) <= 2 and name.isalpha():
                obfuscated_count += 1
            # Very long names (possibly obfuscated)
            elif len(name) > 25:
                obfuscated_count += 1
            # Names with confusing characters
            elif all(c in 'Il1O0' for c in name) and len(name) > 1:
                obfuscated_count += 1
            # Names that don't follow Java naming conventions
            elif not self._follows_java_naming_conventions(name):
                obfuscated_count += 1
        
        return obfuscated_count
    
    def _follows_java_naming_conventions(self, name: str) -> bool:
        """Check if a name follows standard Java naming conventions."""
        # Class names should start with uppercase
        # Method/field names should start with lowercase
        # Should contain meaningful words (heuristic)
        
        if len(name) < 3:
            return False  # Too short to be meaningful
        
        # Check for common English word patterns
        common_patterns = [
            'get', 'set', 'is', 'has', 'create', 'delete', 'update',
            'init', 'start', 'stop', 'run', 'execute', 'process',
            'handle', 'manage', 'check', 'validate', 'parse', 'build'
        ]
        
        name_lower = name.lower()
        return any(pattern in name_lower for pattern in common_patterns)
    
    def _calculate_complexity_score(self, content: str) -> float:
        """Calculate cyclomatic complexity score for content."""
        # Count decision points
        decision_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', 'try']
        complexity = 1  # Base complexity
        
        for keyword in decision_keywords:
            pattern = r'\b' + keyword + r'\b'
            matches = re.findall(pattern, content, re.IGNORECASE)
            complexity += len(matches)
        
        # Normalize by lines of code
        lines = content.split('\n')
        code_lines = [line for line in lines if line.strip() and not line.strip().startswith('//')]
        
        if code_lines:
            return complexity / len(code_lines) * 100
        else:
            return 0.0
    
    def _calculate_obfuscation_metrics(self, analysis: CodeObfuscationAnalysis):
        """Calculate overall obfuscation metrics and level."""
        # Calculate individual ratios
        class_ratio = self.metrics.class_obfuscation_ratio
        method_ratio = self.metrics.method_obfuscation_ratio
        field_ratio = self.metrics.field_obfuscation_ratio
        string_ratio = self.metrics.string_obfuscation_ratio
        
        # Calculate weighted obfuscation score
        weights = {
            'class': 0.3,
            'method': 0.3,
            'field': 0.2,
            'string': 0.2
        }
        
        weighted_score = (
            class_ratio * weights['class'] +
            method_ratio * weights['method'] +
            field_ratio * weights['field'] +
            string_ratio * weights['string']
        )
        
        # Determine obfuscation level
        if weighted_score >= 0.8:
            analysis.obfuscation_level = DetectionStrength.ADVANCED
        elif weighted_score >= 0.6:
            analysis.obfuscation_level = DetectionStrength.HIGH
        elif weighted_score >= 0.4:
            analysis.obfuscation_level = DetectionStrength.MODERATE
        elif weighted_score >= 0.2:
            analysis.obfuscation_level = DetectionStrength.WEAK
        else:
            analysis.obfuscation_level = DetectionStrength.NONE
        
        # Calculate confidence score
        analysis.confidence_score = min(100.0, weighted_score * 120)  # Boost confidence for good obfuscation
    
    def _assess_obfuscation_effectiveness(self, analysis: CodeObfuscationAnalysis):
        """Assess the effectiveness of obfuscation and create vulnerabilities for weak obfuscation."""
        # Check for insufficient obfuscation
        if analysis.obfuscation_level in [DetectionStrength.NONE, DetectionStrength.WEAK]:
            vulnerability = AntiTamperingVulnerability(
                vulnerability_id="OBFUSCATION_INSUFFICIENT",
                mechanism_type=AntiTamperingMechanismType.CODE_OBFUSCATION,
                title="Insufficient Code Obfuscation",
                description="The application lacks adequate code obfuscation, making reverse engineering easier.",
                severity=TamperingVulnerabilitySeverity.MEDIUM,
                confidence=0.85,
                location="Application-wide",
                evidence=f"Obfuscation level: {analysis.obfuscation_level.value}",
                detection_strength=analysis.obfuscation_level,
                bypass_resistance=BypassResistance.LOW,
                analysis_methods=[AnalysisMethod.STATIC_ANALYSIS],
                remediation="Implement comprehensive code obfuscation including name obfuscation, string encryption, and control flow obfuscation.",
                masvs_refs=["MSTG-RESILIENCE-9"]
            )
            analysis.vulnerabilities.append(vulnerability)
        
        # Check for missing string obfuscation
        if not analysis.string_obfuscation and self.metrics.string_literals > 10:
            vulnerability = AntiTamperingVulnerability(
                vulnerability_id="OBFUSCATION_MISSING_STRING",
                mechanism_type=AntiTamperingMechanismType.CODE_OBFUSCATION,
                title="Missing String Obfuscation",
                description="The application does not obfuscate string literals, exposing sensitive information.",
                severity=TamperingVulnerabilitySeverity.LOW,
                confidence=0.80,
                location="Application-wide",
                evidence=f"Found {self.metrics.string_literals} unobfuscated string literals",
                detection_strength=DetectionStrength.NONE,
                bypass_resistance=BypassResistance.NONE,
                analysis_methods=[AnalysisMethod.STATIC_ANALYSIS],
                remediation="Implement string obfuscation to hide sensitive literals and API endpoints.",
                masvs_refs=["MSTG-RESILIENCE-9"]
            )
            analysis.vulnerabilities.append(vulnerability)
    
    def _generate_recommendations(self, analysis: CodeObfuscationAnalysis):
        """Generate security recommendations for code obfuscation."""
        recommendations = []
        
        if analysis.obfuscation_level in [DetectionStrength.NONE, DetectionStrength.WEAK]:
            recommendations.append("Implement comprehensive code obfuscation using tools like ProGuard or R8")
            recommendations.append("Enable name obfuscation for classes, methods, and fields")
        
        if not analysis.string_obfuscation:
            recommendations.append("Implement string obfuscation to hide sensitive literals")
            recommendations.append("Encrypt API endpoints and configuration strings")
        
        if not analysis.control_flow_obfuscation:
            recommendations.append("Add control flow obfuscation to complicate reverse engineering")
            recommendations.append("Insert dummy code and opaque predicates")
        
        if len(analysis.obfuscation_techniques) < 3:
            recommendations.append("Use multiple obfuscation techniques for better protection")
        
        analysis.recommendations = recommendations
    
    def _create_error_analysis(self, analysis: CodeObfuscationAnalysis, error: str):
        """Create analysis with error information."""
        analysis.confidence_score = 0.0
        analysis.analysis_coverage = 0.0
        analysis.recommendations = [f"Analysis failed: {error}"]
    
    def _is_relevant_for_obfuscation_analysis(self, file_path: str) -> bool:
        """Check if file is relevant for obfuscation analysis."""
        relevant_extensions = {'.java', '.kt', '.smali', '.dex'}
        return any(file_path.endswith(ext) for ext in relevant_extensions)
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Read file content safely."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None 