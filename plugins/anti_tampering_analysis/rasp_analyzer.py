#!/usr/bin/env python3
"""
RASP (Runtime Application Self Protection) Analyzer Module

Comprehensive RASP analysis for anti-tampering security assessment.
Analyzes various RASP mechanisms, their implementation quality,
and effectiveness against runtime attacks.

Features:
- Runtime protection mechanism detection
- Self-protection technique assessment
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
    RASPAnalysis
)

logger = logging.getLogger(__name__)

class RASPAnalyzer:
    """
    Comprehensive RASP analyzer.
    
    Analyzes applications for RASP mechanisms including:
    - Runtime integrity checks
    - Self-modification detection
    - Threat response mechanisms
    - Runtime monitoring
    - Automatic threat mitigation
    """
    
    def __init__(self, context: AnalysisContext):
        """Initialize RASP analyzer."""
        self.context = context
        self.logger = context.logger
        self.confidence_calculator = context.get_dependency('confidence_calculator')
        
        # Initialize RASP patterns
        self.rasp_patterns = {
            'integrity_checks': [
                r'integrity.*check',
                r'checksum.*verify',
                r'hash.*validation',
                r'signature.*verify',
                r'crc.*check',
                r'digest.*compare'
            ],
            'runtime_monitoring': [
                r'runtime.*monitor',
                r'behavior.*monitor',
                r'threat.*detect',
                r'anomaly.*detect',
                r'activity.*monitor',
                r'execution.*monitor'
            ],
            'self_protection': [
                r'self.*protect',
                r'auto.*protect',
                r'defense.*mechanism',
                r'protection.*layer',
                r'security.*wrapper',
                r'guard.*function'
            ],
            'threat_response': [
                r'threat.*response',
                r'attack.*response',
                r'mitigation.*action',
                r'security.*action',
                r'emergency.*shutdown',
                r'kill.*switch'
            ],
            'code_modification_detection': [
                r'code.*tamper',
                r'modification.*detect',
                r'patch.*detect',
                r'hook.*detect',
                r'injection.*detect',
                r'memory.*protect'
            ]
        }
    
    def analyze(self, apk_ctx) -> RASPAnalysis:
        """Perform comprehensive RASP analysis."""
        analysis = RASPAnalysis()
        
        try:
            self.logger.info("Starting RASP analysis")
            
            # Extract content for analysis
            content_data = self._extract_content(apk_ctx)
            
            # Analyze each RASP category
            for category, patterns in self.rasp_patterns.items():
                self._analyze_rasp_category(content_data, patterns, analysis, category)
            
            # Assess RASP capabilities
            self._assess_rasp_capabilities(analysis)
            
            # Calculate metrics
            self._calculate_metrics(analysis)
            self._generate_recommendations(analysis)
            
        except Exception as e:
            self.logger.error(f"RASP analysis failed: {e}")
            analysis.confidence_score = 0.0
        
        return analysis
    
    def _extract_content(self, apk_ctx) -> Dict[str, str]:
        """Extract content for RASP analysis."""
        content_data = {}
        
        try:
            if hasattr(apk_ctx, 'get_source_files'):
                source_files = apk_ctx.get_source_files()
                for file_path in source_files:
                    if self._is_relevant_for_rasp_analysis(file_path):
                        content = self._read_file_safely(file_path)
                        if content:
                            content_data[file_path] = content
        except Exception as e:
            self.logger.warning(f"Failed to extract content for RASP analysis: {e}")
        
        return content_data
    
    def _analyze_rasp_category(self, content_data: Dict[str, str], 
                              patterns: List[str],
                              analysis: RASPAnalysis, 
                              category: str):
        """Analyze a category of RASP patterns."""
        category_mechanisms = []
        
        for pattern in patterns:
            total_matches = 0
            
            for file_path, content in content_data.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                total_matches += len(matches)
                
                if matches:
                    # Record specific mechanisms found
                    for match in matches:
                        if match not in category_mechanisms:
                            category_mechanisms.append(match)
            
            if total_matches > 0:
                self._record_rasp_mechanism(analysis, category, pattern, total_matches)
        
        # Update analysis based on category
        if category_mechanisms:
            self._update_analysis_for_category(analysis, category, category_mechanisms)
    
    def _record_rasp_mechanism(self, analysis: RASPAnalysis, category: str, pattern: str, matches: int):
        """Record a detected RASP mechanism."""
        mechanism_name = f"{category}_{pattern}"
        
        if mechanism_name not in analysis.rasp_mechanisms:
            analysis.rasp_mechanisms.append(mechanism_name)
        
        # Update specific category lists
        if category == 'integrity_checks' and pattern not in analysis.integrity_checks:
            analysis.integrity_checks.append(pattern)
    
    def _update_analysis_for_category(self, analysis: RASPAnalysis, category: str, mechanisms: List[str]):
        """Update analysis flags based on detected mechanisms."""
        if category == 'runtime_monitoring' and mechanisms:
            analysis.runtime_monitoring = True
        elif category == 'threat_response' and mechanisms:
            analysis.threat_detection = True
        elif category == 'self_protection' and mechanisms:
            analysis.automatic_response = True
    
    def _assess_rasp_capabilities(self, analysis: RASPAnalysis):
        """Assess overall RASP capabilities."""
        capabilities_score = 0
        
        # Score each capability
        if analysis.runtime_monitoring:
            capabilities_score += 25
        if analysis.threat_detection:
            capabilities_score += 25
        if analysis.automatic_response:
            capabilities_score += 25
        if len(analysis.integrity_checks) > 0:
            capabilities_score += 25
        
        # Determine strength based on capabilities
        if capabilities_score >= 75:
            analysis.strength_assessment = DetectionStrength.ADVANCED
        elif capabilities_score >= 0.7:
            analysis.strength_assessment = DetectionStrength.HIGH
        elif capabilities_score >= 0.5:
            analysis.strength_assessment = DetectionStrength.MODERATE
        elif capabilities_score > 0:
            analysis.strength_assessment = DetectionStrength.WEAK
        else:
            analysis.strength_assessment = DetectionStrength.NONE
    
    def _calculate_metrics(self, analysis: RASPAnalysis):
        """Calculate RASP analysis metrics."""
        total_mechanisms = len(analysis.rasp_mechanisms)
        
        # Calculate confidence based on detected mechanisms
        if total_mechanisms == 0:
            analysis.confidence_score = 10.0
        elif total_mechanisms < 3:
            analysis.confidence_score = 40.0
        elif total_mechanisms < 6:
            analysis.confidence_score = 70.0
        else:
            analysis.confidence_score = 90.0
        
        # Adjust confidence based on capability diversity
        capability_count = sum([
            analysis.runtime_monitoring,
            analysis.threat_detection,
            analysis.automatic_response,
            len(analysis.integrity_checks) > 0
        ])
        
        analysis.confidence_score *= (capability_count / 4.0)
        analysis.confidence_score = min(100.0, analysis.confidence_score)
        
        # Create vulnerability if RASP is insufficient
        if analysis.strength_assessment in [DetectionStrength.NONE, DetectionStrength.WEAK]:
            severity = TamperingVulnerabilitySeverity.MEDIUM
            if analysis.strength_assessment == DetectionStrength.NONE:
                severity = TamperingVulnerabilitySeverity.HIGH
            
            vulnerability = AntiTamperingVulnerability(
                vulnerability_id="RASP_INSUFFICIENT",
                mechanism_type=AntiTamperingMechanismType.RASP_MECHANISM,
                title="Insufficient RASP Protection",
                description="The application lacks adequate Runtime Application Self Protection mechanisms.",
                severity=severity,
                confidence=0.85,
                location="Application-wide",
                evidence=f"RASP strength: {analysis.strength_assessment.value}, mechanisms: {total_mechanisms}",
                detection_strength=analysis.strength_assessment,
                bypass_resistance=BypassResistance.LOW if analysis.strength_assessment == DetectionStrength.NONE else BypassResistance.MEDIUM,
                analysis_methods=[AnalysisMethod.PATTERN_MATCHING],
                remediation="Implement comprehensive RASP including runtime monitoring, threat detection, and automatic response mechanisms.",
                masvs_refs=["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"]
            )
            analysis.vulnerabilities.append(vulnerability)
        
        # Calculate coverage
        total_categories = len(self.rasp_patterns)
        covered_categories = len([cat for cat in self.rasp_patterns.keys() 
                                if any(mech.startswith(cat) for mech in analysis.rasp_mechanisms)])
        analysis.analysis_coverage = (covered_categories / total_categories) * 100
    
    def _generate_recommendations(self, analysis: RASPAnalysis):
        """Generate security recommendations for RASP."""
        recommendations = []
        
        if analysis.strength_assessment in [DetectionStrength.NONE, DetectionStrength.WEAK]:
            recommendations.append("Implement comprehensive RASP mechanisms for runtime protection")
            recommendations.append("Add runtime monitoring and threat detection capabilities")
        
        if not analysis.runtime_monitoring:
            recommendations.append("Implement runtime behavior monitoring to detect anomalies")
        
        if not analysis.threat_detection:
            recommendations.append("Add threat detection mechanisms to identify attacks")
        
        if not analysis.automatic_response:
            recommendations.append("Implement automatic response mechanisms for detected threats")
        
        if len(analysis.integrity_checks) == 0:
            recommendations.append("Add integrity checking mechanisms for code and data protection")
        
        if len(analysis.rasp_mechanisms) < 5:
            recommendations.append("Increase diversity of RASP protection mechanisms")
        
        analysis.recommendations = recommendations
    
    def _is_relevant_for_rasp_analysis(self, file_path: str) -> bool:
        """Check if file is relevant for RASP analysis."""
        relevant_extensions = {'.java', '.kt', '.xml', '.smali', '.cpp', '.c'}
        return any(file_path.endswith(ext) for ext in relevant_extensions)
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Read file content safely."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None 