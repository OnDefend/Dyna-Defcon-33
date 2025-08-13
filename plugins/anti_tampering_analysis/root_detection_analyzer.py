#!/usr/bin/env python3
"""
Root Detection Analyzer Module

Comprehensive root detection analysis for anti-tampering security assessment.
Analyzes various root detection mechanisms, their implementation quality,
and resistance to bypass attempts.

Features:
- Multi-layered root detection analysis
- Bypass resistance assessment
- Implementation quality evaluation
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
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from core.shared_infrastructure.dependency_injection import AnalysisContext
from core.shared_infrastructure import AnalysisError, ErrorContext  # Updated to generic naming

from .data_structures import (
    AntiTamperingVulnerability,
    AntiTamperingMechanismType,
    TamperingVulnerabilitySeverity,
    DetectionStrength,
    BypassResistance,
    AnalysisMethod,
    RootDetectionAnalysis
)

logger = logging.getLogger(__name__)

@dataclass
class RootDetectionPattern:
    """Root detection pattern with metadata."""
    pattern_id: str
    pattern: str
    description: str
    detection_method: str
    strength: DetectionStrength
    bypass_resistance: BypassResistance
    reliability_score: float
    false_positive_rate: float
    masvs_refs: List[str]

class RootDetectionAnalyzer:
    """
    Comprehensive root detection analyzer.
    
    Analyzes applications for root detection mechanisms including:
    - Binary checks (su, busybox, etc.)
    - Root management app detection
    - Build property checks
    - System property validation
    - File system permission checks
    - Package manager queries
    - Environment variable analysis
    """
    
    def __init__(self, context: AnalysisContext):
        """
        Initialize root detection analyzer.
        
        Args:
            context: Analysis context with dependencies
        """
        self.context = context
        self.logger = context.logger
        self.confidence_calculator = context.get_dependency('confidence_calculator')
        
        # Analysis configuration
        self.max_analysis_time = context.config.get('max_analysis_time', 180)
        self.enable_deep_analysis = context.config.get('enable_deep_analysis', True)
        self.parallel_processing = context.config.get('parallel_processing', True)
        
        # Initialize root detection patterns
        self.root_detection_patterns = self._initialize_root_detection_patterns()
        
        # Analysis state
        self.analyzed_files = 0
        self.detected_mechanisms = []
        self.bypass_vulnerabilities = []
        
        logger.info("Root Detection Analyzer initialized")
    
    def _initialize_root_detection_patterns(self) -> Dict[str, List[RootDetectionPattern]]:
        """Initialize root detection patterns from configuration."""
        patterns = {
            'binary_checks': [
                RootDetectionPattern(
                    pattern_id="ROOT_BINARY_SU",
                    pattern=r'/system/(?:bin|xbin)/su\b',
                    description="Checks for su binary in system paths",
                    detection_method="binary_detection",
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.85,
                    false_positive_rate=0.05,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_BINARY_BUSYBOX",
                    pattern=r'/system/(?:bin|xbin)/busybox\b',
                    description="Checks for busybox binary",
                    detection_method="binary_detection",
                    strength=DetectionStrength.MODERATE,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.80,
                    false_positive_rate=0.10,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
            ],
            'root_management_apps': [
                RootDetectionPattern(
                    pattern_id="ROOT_APP_SUPERSU",
                    pattern=r'eu\.chainfire\.supersu',
                    description="Detects SuperSU app package",
                    detection_method="package_detection",
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.MEDIUM,
                    reliability_score=0.90,
                    false_positive_rate=0.03,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
                RootDetectionPattern(
                    pattern_id="ROOT_APP_MAGISK",
                    pattern=r'com\.topjohnwu\.magisk',
                    description="Detects Magisk Manager package",
                    detection_method="package_detection",
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.92,
                    false_positive_rate=0.02,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
            ],
            'build_properties': [
                RootDetectionPattern(
                    pattern_id="ROOT_PROP_TAGS",
                    pattern=r'ro\.build\.tags.*test-keys',
                    description="Checks for test-keys in build tags",
                    detection_method="property_detection",
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.70,
                    false_positive_rate=0.20,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
            ],
            'system_properties': [
                RootDetectionPattern(
                    pattern_id="ROOT_PROP_DANGEROUS",
                    pattern=r'ro\.debuggable.*1',
                    description="Checks for debuggable property",
                    detection_method="property_detection",
                    strength=DetectionStrength.WEAK,
                    bypass_resistance=BypassResistance.LOW,
                    reliability_score=0.65,
                    false_positive_rate=0.30,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
            ],
            'advanced_detection': [
                RootDetectionPattern(
                    pattern_id="ROOT_ADVANCED_NATIVE",
                    pattern=r'native.*root.*detection',
                    description="Advanced native root detection",
                    detection_method="native_detection",
                    strength=DetectionStrength.HIGH,
                    bypass_resistance=BypassResistance.HIGH,
                    reliability_score=0.88,
                    false_positive_rate=0.08,
                    masvs_refs=["MSTG-RESILIENCE-1"]
                ),
            ]
        }
        
        return patterns
    
    def analyze(self, apk_ctx) -> RootDetectionAnalysis:
        """
        Perform comprehensive root detection analysis.
        
        Args:
            apk_ctx: APK context containing analysis data
            
        Returns:
            RootDetectionAnalysis: Comprehensive analysis results
        """
        start_time = time.time()
        analysis = RootDetectionAnalysis()
        
        try:
            self.logger.info("Starting root detection analysis")
            
            # Extract analysis targets
            analysis_targets = self._extract_analysis_targets(apk_ctx)
            
            if self.parallel_processing and len(analysis_targets) > 1:
                self._analyze_parallel(analysis_targets, analysis)
            else:
                self._analyze_sequential(analysis_targets, analysis)
            
            # Perform advanced analysis
            if self.enable_deep_analysis:
                self._perform_advanced_analysis(apk_ctx, analysis)
            
            # Calculate final metrics
            self._calculate_analysis_metrics(analysis)
            
            # Generate recommendations
            self._generate_recommendations(analysis)
            
            analysis_duration = time.time() - start_time
            self.logger.info(f"Root detection analysis completed in {analysis_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Root detection analysis failed: {e}")
            self._create_error_analysis(analysis, str(e))
        
        return analysis
    
    def _extract_analysis_targets(self, apk_ctx) -> List[Dict[str, Any]]:
        """Extract files and content for analysis."""
        targets = []
        
        try:
            # Get source files if available
            if hasattr(apk_ctx, 'get_source_files'):
                source_files = apk_ctx.get_source_files()
                for file_path in source_files:
                    if self._is_relevant_file(file_path):
                        content = self._read_file_safely(file_path)
                        if content:
                            targets.append({
                                'type': 'source_file',
                                'path': file_path,
                                'content': content
                            })
            
            # Get manifest content
            if hasattr(apk_ctx, 'get_manifest_content'):
                manifest_content = apk_ctx.get_manifest_content()
                if manifest_content:
                    targets.append({
                        'type': 'manifest',
                        'path': 'AndroidManifest.xml',
                        'content': manifest_content
                    })
            
        except Exception as e:
            self.logger.warning(f"Failed to extract analysis targets: {e}")
        
        return targets
    
    def _is_relevant_file(self, file_path: str) -> bool:
        """Check if file is relevant for root detection analysis."""
        relevant_extensions = ['.java', '.kt', '.xml', '.so', '.c', '.cpp', '.h']
        return any(file_path.endswith(ext) for ext in relevant_extensions)
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.debug(f"Failed to read file {file_path}: {e}")
            return None
    
    def _analyze_parallel(self, targets: List[Dict[str, Any]], analysis: RootDetectionAnalysis):
        """Analyze targets in parallel."""
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            for target in targets:
                future = executor.submit(self._analyze_single_target, target)
                futures.append(future)
            
            # Collect results
            for future in futures:
                try:
                    target_analysis = future.result(timeout=30)
                    self._merge_target_analysis(target_analysis, analysis)
                except FutureTimeoutError:
                    self.logger.warning("Target analysis timed out")
                except Exception as e:
                    self.logger.error(f"Error in parallel analysis: {e}")
    
    def _analyze_sequential(self, targets: List[Dict[str, Any]], analysis: RootDetectionAnalysis):
        """Analyze targets sequentially."""
        for target in targets:
            try:
                target_analysis = self._analyze_single_target(target)
                self._merge_target_analysis(target_analysis, analysis)
            except Exception as e:
                self.logger.error(f"Error analyzing target {target.get('path', 'unknown')}: {e}")
    
    def _analyze_single_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single target for root detection patterns."""
        target_analysis = {
            'mechanisms': [],
            'vulnerabilities': [],
            'confidence_factors': []
        }
        
        content = target.get('content', '')
        if not content:
            return target_analysis
        
        # Analyze each pattern category
        for category, patterns in self.root_detection_patterns.items():
            category_results = self._analyze_pattern_category(content, patterns, target)
            target_analysis['mechanisms'].extend(category_results.get('mechanisms', []))
            target_analysis['vulnerabilities'].extend(category_results.get('vulnerabilities', []))
            target_analysis['confidence_factors'].extend(category_results.get('confidence_factors', []))
        
        return target_analysis
    
    def _analyze_pattern_category(self, content: str, patterns: List[RootDetectionPattern], target: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content against a category of patterns."""
        results = {
            'mechanisms': [],
            'vulnerabilities': [],
            'confidence_factors': []
        }
        
        for pattern in patterns:
            matches = re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                # Create mechanism entry
                mechanism = {
                    'pattern_id': pattern.pattern_id,
                    'description': pattern.description,
                    'detection_method': pattern.detection_method,
                    'match_text': match.group(0),
                    'location': target.get('path', 'unknown'),
                    'line_number': content[:match.start()].count('\n') + 1,
                    'strength': pattern.strength,
                    'bypass_resistance': pattern.bypass_resistance
                }
                results['mechanisms'].append(mechanism)
                
                # Check for vulnerabilities
                if pattern.bypass_resistance in [BypassResistance.NONE, BypassResistance.LOW]:
                    vulnerability = self._create_vulnerability(pattern, match, target)
                    results['vulnerabilities'].append(vulnerability)
                
                # Add confidence factor
                confidence_factor = {
                    'pattern_id': pattern.pattern_id,
                    'reliability_score': pattern.reliability_score,
                    'false_positive_rate': pattern.false_positive_rate,
                    'evidence_strength': pattern.strength.value
                }
                results['confidence_factors'].append(confidence_factor)
        
        return results
    
    def _create_vulnerability(self, pattern: RootDetectionPattern, match: re.Match, target: Dict[str, Any]) -> AntiTamperingVulnerability:
        """Create vulnerability from pattern match."""
        vulnerability = AntiTamperingVulnerability(
            vulnerability_id=f"ROOT_VULN_{pattern.pattern_id}_{hash(match.group(0)) % 1000}",
            mechanism_type=AntiTamperingMechanismType.ROOT_DETECTION,
            title=f"Weak Root Detection: {pattern.description}",
            description=f"Root detection mechanism using {pattern.detection_method} has low bypass resistance",
            severity=TamperingVulnerabilitySeverity.MEDIUM,
            confidence=pattern.reliability_score,
            location=target.get('path', 'unknown'),
            evidence=match.group(0),
            file_path=target.get('path'),
            line_number=target.get('content', '').count('\n', 0, match.start()) + 1,
            detection_strength=pattern.strength,
            bypass_resistance=pattern.bypass_resistance,
            analysis_methods=[AnalysisMethod.STATIC_ANALYSIS, AnalysisMethod.PATTERN_MATCHING],
            masvs_refs=pattern.masvs_refs,
            remediation=f"Strengthen {pattern.detection_method} implementation to increase bypass resistance"
        )
        
        return vulnerability
    
    def _merge_target_analysis(self, target_analysis: Dict[str, Any], analysis: RootDetectionAnalysis):
        """Merge target analysis results into main analysis."""
        analysis.detection_methods.extend(target_analysis.get('mechanisms', []))
        analysis.vulnerabilities.extend(target_analysis.get('vulnerabilities', []))
        
        # Update mechanism count
        analysis.mechanism_count = len(analysis.detection_methods)
    
    def _perform_advanced_analysis(self, apk_ctx, analysis: RootDetectionAnalysis):
        """Perform advanced root detection analysis."""
        # Advanced analysis implementation would go here
        pass
    
    def _calculate_analysis_metrics(self, analysis: RootDetectionAnalysis):
        """Calculate analysis metrics and scores."""
        # Calculate strength assessment
        if analysis.mechanism_count == 0:
            analysis.strength_assessment = DetectionStrength.NONE
        elif analysis.mechanism_count < 3:
            analysis.strength_assessment = DetectionStrength.WEAK
        elif analysis.mechanism_count < 6:
            analysis.strength_assessment = DetectionStrength.MODERATE
        elif analysis.mechanism_count < 10:
            analysis.strength_assessment = DetectionStrength.HIGH
        else:
            analysis.strength_assessment = DetectionStrength.HIGH
        
        # Calculate confidence score
        if analysis.vulnerabilities:
            avg_confidence = sum(v.confidence for v in analysis.vulnerabilities) / len(analysis.vulnerabilities)
            analysis.confidence_score = avg_confidence * 100
        else:
            analysis.confidence_score = 0.0
        
        # Calculate analysis coverage
        total_possible_detections = sum(len(patterns) for patterns in self.root_detection_patterns.values())
        analysis.analysis_coverage = min(100.0, (analysis.mechanism_count / total_possible_detections) * 100)
    
    def _generate_recommendations(self, analysis: RootDetectionAnalysis):
        """Generate security recommendations."""
        recommendations = []
        
        if analysis.mechanism_count == 0:
            recommendations.append("Implement root detection mechanisms to detect rooted devices")
        elif analysis.mechanism_count < 3:
            recommendations.append("Add more root detection methods for better coverage")
        
        if any(v.bypass_resistance == BypassResistance.LOW for v in analysis.vulnerabilities):
            recommendations.append("Strengthen root detection implementations to increase bypass resistance")
        
        if analysis.confidence_score < 70:
            recommendations.append("Review and improve root detection pattern reliability")
        
        analysis.recommendations = recommendations
    
    def _create_error_analysis(self, analysis: RootDetectionAnalysis, error: str):
        """Create error analysis result."""
        analysis.limitations.append(f"Root detection analysis failed: {error}")
        analysis.confidence_score = 0.0
        analysis.analysis_coverage = 0.0 