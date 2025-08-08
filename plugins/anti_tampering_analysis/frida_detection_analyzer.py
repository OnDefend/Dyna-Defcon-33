#!/usr/bin/env python3
"""
Anti-Frida Detection Analyzer Module

Comprehensive anti-Frida detection analysis for anti-tampering security assessment.
Analyzes various anti-Frida mechanisms, their implementation quality,
and resistance to bypass attempts.

Features:
- Multi-layered Frida detection analysis
- Anti-Frida technique assessment
- Implementation strength evaluation
- confidence calculation
"""

import logging
import re
from typing import Dict, List, Optional, Any

from core.shared_infrastructure.dependency_injection import AnalysisContext

from .data_structures import (
    AntiTamperingVulnerability,
    AntiTamperingMechanismType,
    TamperingVulnerabilitySeverity,
    DetectionStrength,
    BypassResistance,
    AnalysisMethod,
    AntiFridaAnalysis
)

logger = logging.getLogger(__name__)

class AntiFridaAnalyzer:
    """
    Comprehensive anti-Frida analyzer.
    
    Analyzes applications for anti-Frida mechanisms including:
    - Frida server detection
    - Frida signature checks
    - Hook detection
    - Port scanning
    - Process monitoring
    """
    
    def __init__(self, context: AnalysisContext):
        """Initialize anti-Frida analyzer."""
        self.context = context
        self.logger = context.logger
        self.confidence_calculator = context.get_dependency('confidence_calculator')
        
        # Initialize anti-Frida patterns
        self.frida_patterns = {
            'frida_server_detection': [
                r'frida-server',
                r'frida_server',
                r'/data/local/tmp/frida',
                r'27042',  # Default Frida port
                r'frida\.agent',
            ],
            'frida_signature_checks': [
                r'gum-js-loop',
                r'gmain',
                r'gum_js_stalker',
                r'frida_rpc',
                r'FridaScript',
            ],
            'hook_detection': [
                r'hook',
                r'hook_method',
                r'hook_function',
                r'interceptor',
                r'replace_method',
            ],
            'port_scanning': [
                r'27042',
                r'27043',
                r'socket.*27042',
                r'connect.*27042',
            ]
        }
    
    def analyze(self, apk_ctx) -> AntiFridaAnalysis:
        """Perform comprehensive anti-Frida analysis."""
        analysis = AntiFridaAnalysis()
        
        try:
            self.logger.info("Starting anti-Frida analysis")
            
            # Extract content for analysis
            content_data = self._extract_content(apk_ctx)
            
            # Analyze each pattern category
            for category, patterns in self.frida_patterns.items():
                self._analyze_pattern_category(content_data, patterns, analysis, category)
            
            # Calculate metrics
            self._calculate_metrics(analysis)
            self._generate_recommendations(analysis)
            
        except Exception as e:
            self.logger.error(f"Anti-Frida analysis failed: {e}")
            analysis.confidence_score = 0.0
        
        return analysis
    
    def _extract_content(self, apk_ctx) -> Dict[str, str]:
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
    
    def _analyze_pattern_category(self, content_data: Dict[str, str], 
                                patterns: List[str],
                                analysis: AntiFridaAnalysis, 
                                category: str):
        """Analyze a category of anti-Frida patterns."""
        for pattern in patterns:
            total_matches = 0
            
            for file_path, content in content_data.items():
                matches = len(re.findall(pattern, content, re.IGNORECASE))
                total_matches += matches
            
            if total_matches > 0:
                analysis.mechanism_count += 1
                analysis.detection_methods.append(category)
                analysis.frida_signature_checks.append(pattern)
    
    def _calculate_metrics(self, analysis: AntiFridaAnalysis):
        """Calculate analysis metrics."""
        if analysis.mechanism_count == 0:
            analysis.strength_assessment = DetectionStrength.NONE
            analysis.bypass_resistance = BypassResistance.NONE
            analysis.confidence_score = 20.0
        elif analysis.mechanism_count < 3:
            analysis.strength_assessment = DetectionStrength.WEAK
            analysis.bypass_resistance = BypassResistance.LOW
            analysis.confidence_score = 50.0
        elif analysis.mechanism_count < 6:
            analysis.strength_assessment = DetectionStrength.MODERATE
            analysis.bypass_resistance = BypassResistance.MEDIUM
            analysis.confidence_score = 75.0
        elif frida_indicators >= 3:
            analysis.strength_assessment = DetectionStrength.HIGH
        elif frida_indicators >= 2:
            analysis.strength_assessment = DetectionStrength.MODERATE
        elif frida_indicators >= 1:
            analysis.strength_assessment = DetectionStrength.WEAK
        else:
            analysis.strength_assessment = DetectionStrength.NONE
        
        # Create vulnerability if protection is weak
        if analysis.strength_assessment in [DetectionStrength.NONE, DetectionStrength.WEAK]:
            vulnerability = AntiTamperingVulnerability(
                vulnerability_id="ANTI_FRIDA_INSUFFICIENT",
                mechanism_type=AntiTamperingMechanismType.ANTI_FRIDA,
                title="Insufficient Anti-Frida Protection",
                description="The application lacks adequate anti-Frida detection mechanisms.",
                severity=TamperingVulnerabilitySeverity.MEDIUM,
                confidence=0.80,
                location="Application-wide",
                evidence=f"Only {analysis.mechanism_count} anti-Frida mechanisms detected",
                detection_strength=analysis.strength_assessment,
                bypass_resistance=analysis.bypass_resistance,
                analysis_methods=[AnalysisMethod.PATTERN_MATCHING],
                remediation="Implement comprehensive anti-Frida detection including server detection and signature validation.",
                masvs_refs=["MSTG-RESILIENCE-4"]
            )
            analysis.vulnerabilities.append(vulnerability)
        
        analysis.analysis_coverage = min(100.0, (analysis.mechanism_count / 5) * 100)
    
    def _generate_recommendations(self, analysis: AntiFridaAnalysis):
        """Generate security recommendations."""
        recommendations = []
        
        if analysis.strength_assessment in [DetectionStrength.NONE, DetectionStrength.WEAK]:
            recommendations.append("Implement comprehensive anti-Frida detection mechanisms")
            recommendations.append("Add Frida server detection and signature validation")
        
        if analysis.mechanism_count < 3:
            recommendations.append("Increase diversity of anti-Frida detection methods")
        
        if analysis.bypass_resistance in [BypassResistance.NONE, BypassResistance.LOW]:
            recommendations.append("Strengthen anti-Frida mechanisms with obfuscation and multiple layers")
        
        analysis.recommendations = recommendations
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Read file content safely."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None 