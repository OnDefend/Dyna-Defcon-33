#!/usr/bin/env python3
"""
Debugger Detection Analyzer Module

Comprehensive debugger detection analysis for anti-tampering security assessment.
Analyzes various anti-debugging mechanisms, their implementation quality,
and resistance to bypass attempts.

Features:
- Multi-layered debugger detection analysis
- Anti-debugging technique assessment
- Implementation strength evaluation
- confidence calculation
- Pattern-based detection with reliability scoring
- Context-aware analysis
"""

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure import AnalysisError  # Updated to generic naming

from .data_structures import (
    AntiTamperingVulnerability,
    AntiTamperingMechanismType,
    TamperingVulnerabilitySeverity,
    DetectionStrength,
    BypassResistance,
    AnalysisMethod,
    DebuggerDetectionAnalysis
)

logger = logging.getLogger(__name__)

@dataclass
class DebuggerDetectionPattern:
    """Debugger detection pattern with metadata."""
    pattern_id: str
    pattern: str
    description: str
    technique: str
    strength: DetectionStrength
    bypass_resistance: BypassResistance
    reliability_score: float
    false_positive_rate: float
    masvs_refs: List[str]

class DebuggerDetectionAnalyzer:
    """
    Comprehensive debugger detection analyzer.
    
    Analyzes applications for anti-debugging mechanisms including:
    - Debug flag checks
    - Debugger process detection
    - Timing-based detection
    - Exception-based detection
    - Native anti-debugging
    - JNI anti-debugging techniques
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize debugger detection analyzer.
        
        Args:
            context: Analysis context with dependencies
        """
        self.context = context
        self.logger = context.logger
        self.confidence_calculator = context.get_dependency('confidence_calculator')
        
        # Analysis configuration
        self.max_analysis_time = context.config.get('max_analysis_time', 120)
        self.enable_deep_analysis = context.config.get('enable_deep_analysis', True)
        
        # Initialize debugger detection patterns
        self.debugger_patterns = self._initialize_debugger_patterns()
        
        # Analysis state
        self.analyzed_files = 0
        self.detected_techniques = []
        self.detected_vulnerabilities = []
        
        logger.info("Debugger Detection Analyzer initialized")
    
    def _initialize_debugger_patterns(self) -> Dict[str, List[DebuggerDetectionPattern]]:
        """Initialize debugger detection patterns."""
        patterns = {
            'debug_flag_checks': [
                DebuggerDetectionPattern(
                    pattern_id="DEBUG_FLAG_BUILD",
                    pattern=r'BuildConfig\.DEBUG',
                    description="Checks BuildConfig.DEBUG flag",
                    technique="debug_flag_check",
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.75,
                    false_positive_rate=0.20,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
                DebuggerDetectionPattern(
                    pattern_id="DEBUG_FLAG_APPLICATION",
                    pattern=r'ApplicationInfo\.FLAG_DEBUGGABLE',
                    description="Checks ApplicationInfo.FLAG_DEBUGGABLE",
                    technique="debug_flag_check",
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.70,
                    false_positive_rate=0.25,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
            ],
            'process_detection': [
                DebuggerDetectionPattern(
                    pattern_id="DEBUGGER_PROCESS_CHECK",
                    pattern=r'android_server|gdb|lldb',
                    description="Checks for debugger processes",
                    technique="process_detection",
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.82,
                    false_positive_rate=0.10,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
            ],
            'timing_based': [
                DebuggerDetectionPattern(
                    pattern_id="TIMING_BASED_DETECTION",
                    pattern=r'System\.currentTimeMillis.*debug',
                    description="Timing-based debugger detection",
                    technique="timing_detection",
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.78,
                    false_positive_rate=0.15,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
            ],
            'exception_based': [
                DebuggerDetectionPattern(
                    pattern_id="EXCEPTION_BASED_DETECTION",
                    pattern=r'try.*catch.*debug',
                    description="Exception-based debugger detection",
                    technique="exception_detection",
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.75,
                    false_positive_rate=0.18,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
            ],
            'native_anti_debugging': [
                DebuggerDetectionPattern(
                    pattern_id="NATIVE_ANTI_DEBUG",
                    pattern=r'ptrace.*PTRACE_TRACEME',
                    description="Native anti-debugging using ptrace",
                    technique="native_anti_debug",
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.90,
                    false_positive_rate=0.05,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
            ],
            'jni_techniques': [
                DebuggerDetectionPattern(
                    pattern_id="JNI_DEBUGGER_CHECK",
                    pattern=r'JNI.*debug.*check',
                    description="JNI-based debugger detection",
                    technique="jni_detection",
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.85,
                    false_positive_rate=0.08,
                    masvs_refs=["MSTG-RESILIENCE-2"]
                ),
            ]
        }
        
        # Add high-strength patterns
        patterns['native_anti_debugging'].extend([
            DebuggerDetectionPattern(
                pattern_id="DEBUGGER_PTRACE_ADVANCED",
                pattern=r'ptrace\s*\(\s*PTRACE_TRACEME',
                description="Advanced ptrace self-tracing",
                technique="native_code_analysis",
                strength=DetectionStrength.HIGH,
                bypass_resistance=BypassResistance.HIGH,
                reliability_score=0.92,
                false_positive_rate=0.03,
                masvs_refs=["MSTG-RESILIENCE-2"]
            ),
            DebuggerDetectionPattern(
                pattern_id="DEBUGGER_TIMING_ANALYSIS",
                pattern=r'gettimeofday|clock_gettime.*debug',
                description="Timing-based debug detection",
                technique="behavioral_analysis",
                strength=DetectionStrength.HIGH,
                bypass_resistance=BypassResistance.MEDIUM,
                reliability_score=0.88,
                false_positive_rate=0.05,
                masvs_refs=["MSTG-RESILIENCE-2"]
            ),
        ])
        
        return patterns
    
    def analyze(self, apk_ctx) -> DebuggerDetectionAnalysis:
        """
        Perform comprehensive debugger detection analysis.
        
        Args:
            apk_ctx: APK context containing analysis data
            
        Returns:
            DebuggerDetectionAnalysis: Comprehensive analysis results
        """
        start_time = time.time()
        analysis = DebuggerDetectionAnalysis()
        
        try:
            self.logger.info("Starting debugger detection analysis")
            
            # Extract content for analysis
            content_data = self._extract_content_for_analysis(apk_ctx)
            
            # Analyze each pattern category
            for category, patterns in self.debugger_patterns.items():
                self._analyze_pattern_category(content_data, patterns, analysis, category)
            
            # Calculate metrics
            self._calculate_analysis_metrics(analysis)
            self._generate_recommendations(analysis)
            
            analysis_duration = time.time() - start_time
            self.logger.info(f"Debugger detection analysis completed in {analysis_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Debugger detection analysis failed: {e}")
            self._create_error_analysis(analysis, str(e))
        
        return analysis
    
    def _extract_content_for_analysis(self, apk_ctx) -> Dict[str, str]:
        """Extract content for analysis."""
        content_data = {}
        
        try:
            if hasattr(apk_ctx, 'get_source_files'):
                source_files = apk_ctx.get_source_files()
                for file_path in source_files:
                    content = self._read_file_safely(file_path)
                    if content:
                        content_data[file_path] = content
        except Exception as e:
            self.logger.warning(f"Failed to extract content: {e}")
        
        return content_data
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.debug(f"Failed to read file {file_path}: {e}")
            return None
    
    def _analyze_pattern_category(self, content_data: Dict[str, str], patterns: List[DebuggerDetectionPattern], analysis: DebuggerDetectionAnalysis, category: str):
        """Analyze a category of debugger detection patterns."""
        for file_path, content in content_data.items():
            for pattern in patterns:
                matches = re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Create detection method entry
                    detection_method = {
                        'pattern_id': pattern.pattern_id,
                        'technique': pattern.technique,
                        'description': pattern.description,
                        'match_text': match.group(0),
                        'location': file_path,
                        'line_number': content[:match.start()].count('\n') + 1,
                        'strength': pattern.strength,
                        'bypass_resistance': pattern.bypass_resistance
                    }
                    analysis.detection_methods.append(detection_method)
                    
                    # Check for vulnerabilities
                    if pattern.bypass_resistance in [BypassResistance.NONE, BypassResistance.LOW]:
                        vulnerability = self._create_vulnerability(pattern, match, file_path, content)
                        analysis.vulnerabilities.append(vulnerability)
        
        # Update mechanism count
        analysis.mechanism_count = len(analysis.detection_methods)
    
    def _create_vulnerability(self, pattern: DebuggerDetectionPattern, match: re.Match, file_path: str, content: str) -> AntiTamperingVulnerability:
        """Create vulnerability from pattern match."""
        vulnerability = AntiTamperingVulnerability(
            vulnerability_id=f"DEBUG_VULN_{pattern.pattern_id}_{hash(match.group(0)) % 1000}",
            mechanism_type=AntiTamperingMechanismType.DEBUGGER_DETECTION,
            title=f"Weak Debugger Detection: {pattern.description}",
            description=f"Debugger detection using {pattern.technique} has low bypass resistance",
            severity=TamperingVulnerabilitySeverity.MEDIUM,
            confidence=pattern.reliability_score,
            location=file_path,
            evidence=match.group(0),
            file_path=file_path,
            line_number=content[:match.start()].count('\n') + 1,
            detection_strength=pattern.strength,
            bypass_resistance=pattern.bypass_resistance,
            analysis_methods=[AnalysisMethod.STATIC_ANALYSIS, AnalysisMethod.PATTERN_MATCHING],
            masvs_refs=pattern.masvs_refs,
            remediation=f"Strengthen {pattern.technique} implementation to increase bypass resistance"
        )
        
        return vulnerability
    
    def _calculate_analysis_metrics(self, analysis: DebuggerDetectionAnalysis):
        """Calculate analysis metrics and scores."""
        # Calculate strength assessment
        if analysis.mechanism_count == 0:
            analysis.strength_assessment = DetectionStrength.NONE
        elif analysis.mechanism_count < 2:
            analysis.strength_assessment = DetectionStrength.WEAK
        elif analysis.mechanism_count < 4:
            analysis.strength_assessment = DetectionStrength.MODERATE
        elif analysis.mechanism_count < 6:
            analysis.strength_assessment = DetectionStrength.HIGH
        else:
            analysis.strength_assessment = DetectionStrength.ADVANCED
        
        # Calculate confidence score
        if analysis.vulnerabilities:
            avg_confidence = sum(v.confidence for v in analysis.vulnerabilities) / len(analysis.vulnerabilities)
            analysis.confidence_score = avg_confidence * 100
        else:
            analysis.confidence_score = 0.0
        
        # Calculate analysis coverage
        total_possible_detections = sum(len(patterns) for patterns in self.debugger_patterns.values())
        analysis.analysis_coverage = min(100.0, (analysis.mechanism_count / total_possible_detections) * 100)
    
    def _generate_recommendations(self, analysis: DebuggerDetectionAnalysis):
        """Generate security recommendations."""
        recommendations = []
        
        if analysis.mechanism_count == 0:
            recommendations.append("Implement debugger detection mechanisms to detect debugging attempts")
        elif analysis.mechanism_count < 2:
            recommendations.append("Add more debugger detection methods for better coverage")
        
        if any(v.bypass_resistance == BypassResistance.LOW for v in analysis.vulnerabilities):
            recommendations.append("Strengthen debugger detection implementations to increase bypass resistance")
        
        if analysis.confidence_score < 70:
            recommendations.append("Review and improve debugger detection pattern reliability")
        
        analysis.recommendations = recommendations
    
    def _create_error_analysis(self, analysis: DebuggerDetectionAnalysis, error: str):
        """Create error analysis result."""
        analysis.limitations.append(f"Debugger detection analysis failed: {error}")
        analysis.confidence_score = 0.0
        analysis.analysis_coverage = 0.0 