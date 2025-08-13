#!/usr/bin/env python3
"""
Modular Cross-Platform Analysis Engine

This is the new modular version of the cross-platform analysis engine,
replacing the monolithic 5276-line implementation with a clean, modular
architecture that follows the workspace rules for maintainability and efficiency.

Key Improvements:
- Separated analyzers into focused modules (React Native, Xamarin, PWA)
- confidence calculation system
- Shared data structures and utilities
- Clean dependency injection pattern
- Eliminated code duplication
- Improved testability and maintainability

Usage:
    engine = CrossPlatformAnalysisEngine()
    results = engine.analyze_application(app_data, location)
"""

import logging
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

from .cross_platform_analysis import (
    CrossPlatformFinding,
    FrameworkDetectionResult,
    AnalysisConfiguration,
    CrossPlatformAnalysisResult,
    CrossPlatformConfidenceCalculator,
    ReactNativeAnalyzer,
    XamarinAnalyzer,
    PWAAnalyzer,
    Framework,
    VulnerabilityType,
    Severity,
    ConfidenceEvidence
)

# Import existing AODS foundation if available
try:
    from .flutter_analyzer import FlutterSecurityAnalyzer
    FLUTTER_AVAILABLE = True
except ImportError:
    FLUTTER_AVAILABLE = False
    logging.warning("Flutter analyzer not available")

class CrossPlatformAnalysisEngine:
    """
    Modular cross-platform analysis engine orchestrator.
    
    Coordinates analysis across multiple framework-specific analyzers
    while maintaining professional confidence scoring and unified reporting.
    """
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """
        Initialize the cross-platform analysis engine.
        
        Args:
            config: Analysis configuration (uses defaults if not provided)
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or AnalysisConfiguration()
        
        # Initialize professional confidence calculator
        self.confidence_calculator = CrossPlatformConfidenceCalculator()
        
        # Initialize framework analyzers
        self.analyzers = self._initialize_analyzers()
        
        # Analysis statistics
        self.analysis_stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'frameworks_detected': 0
        }
        
        self.logger.info("Modular cross-platform analysis engine initialized")
    
    def _initialize_analyzers(self) -> Dict[str, Any]:
        """Initialize all available framework analyzers."""
        analyzers = {}
        
        try:
            # React Native analyzer
            analyzers[Framework.REACT_NATIVE.value] = ReactNativeAnalyzer()
            self.logger.info("React Native analyzer initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize React Native analyzer: {e}")
        
        try:
            # Xamarin analyzer
            from .cross_platform_analysis import XamarinAnalyzer
            analyzers[Framework.XAMARIN.value] = XamarinAnalyzer()
            self.logger.info("Xamarin analyzer initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize Xamarin analyzer: {e}")
        
        try:
            # PWA analyzer
            if PWAAnalyzer:
                analyzers[Framework.PWA.value] = PWAAnalyzer()
                self.logger.info("PWA analyzer initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize PWA analyzer: {e}")
        
        try:
            # Flutter analyzer (existing)
            if FLUTTER_AVAILABLE:
                analyzers[Framework.FLUTTER.value] = FlutterSecurityAnalyzer()
                self.logger.info("Flutter analyzer initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize Flutter analyzer: {e}")
        
        self.logger.info(f"Initialized {len(analyzers)} framework analyzers")
        return analyzers
    
    def analyze_application(self, app_data: Dict, location: str = "cross_platform_app") -> CrossPlatformAnalysisResult:
        """
        Analyze application for cross-platform security vulnerabilities.
        
        Args:
            app_data: Application data including content and metadata
            location: Location identifier for the analysis
            
        Returns:
            Comprehensive cross-platform analysis results
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting cross-platform analysis for {location}")
            self.analysis_stats['total_analyses'] += 1
            
            # Get dynamic confidence thresholds from professional calculator
            dynamic_thresholds = self.confidence_calculator.get_dynamic_thresholds()
            confidence_threshold = dynamic_thresholds.get('analysis_confidence_threshold', 0.75)
            high_confidence_threshold = dynamic_thresholds.get('high_confidence_threshold', 0.85)
            framework_detection_threshold = dynamic_thresholds.get('framework_detection_threshold', 0.3)
            
            # Detect all frameworks
            frameworks_detected = self._detect_all_frameworks(app_data, framework_detection_threshold)
            self.analysis_stats['frameworks_detected'] += len(frameworks_detected)
            
            # Analyze each detected framework
            all_findings = []
            framework_results = {}
            errors = []
            warnings = []
            
            for framework_result in frameworks_detected:
                try:
                    framework = framework_result.framework
                    
                    if framework in self.analyzers:
                        self.logger.info(f"Analyzing {framework} framework")
                        
                        # Run framework-specific analysis
                        findings = self._analyze_framework(framework, app_data, location)
                        
                        # Filter findings by dynamic confidence threshold
                        filtered_findings = [
                            f for f in findings 
                            if f.confidence >= confidence_threshold
                        ]
                        
                        all_findings.extend(filtered_findings)
                        framework_results[framework] = {
                            'detection': framework_result,
                            'findings': filtered_findings,
                            'analysis_duration': time.time() - start_time
                        }
                        
                        self.logger.info(f"{framework} analysis completed: {len(filtered_findings)} findings")
                        
                    else:
                        warning_msg = f"No analyzer available for {framework}"
                        warnings.append(warning_msg)
                        self.logger.warning(warning_msg)
                        
                except Exception as e:
                    error_msg = f"Framework analysis failed for {framework_result.framework}: {e}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)
            
            # Generate comprehensive analysis summary
            analysis_summary = self._generate_analysis_summary(all_findings, framework_results)
            
            # Calculate overall risk assessment
            risk_score = self._calculate_cross_platform_risk_score(all_findings)
            
            # Prepare comprehensive results
            return CrossPlatformAnalysisResult(
                frameworks_detected=frameworks_detected,
                findings=all_findings,
                analysis_summary=analysis_summary,
                risk_score=risk_score,
                analysis_duration=time.time() - start_time,
                # Use dynamic threshold for high confidence findings
                total_findings=len(all_findings),
                high_confidence_findings=len([f for f in all_findings if f.confidence >= high_confidence_threshold]),
                framework_results=framework_results,
                errors=errors,
                warnings=warnings,
                confidence_thresholds_used={
                    'analysis_threshold': confidence_threshold,
                    'high_confidence_threshold': high_confidence_threshold,
                    'framework_detection_threshold': framework_detection_threshold
                }
            )
            
        except Exception as e:
            self.logger.error(f"Cross-platform analysis failed: {e}")
            self.analysis_stats['failed_analyses'] += 1
            # Return empty result with error information
            return CrossPlatformAnalysisResult(
                frameworks_detected=[],
                findings=[],
                analysis_summary={},
                risk_score=0.0,
                analysis_duration=time.time() - start_time,
                total_findings=0,
                high_confidence_findings=0,
                framework_results={},
                errors=[str(e)],
                warnings=[],
                confidence_thresholds_used={}
            )
    
    def _detect_all_frameworks(self, app_data: Dict, framework_detection_threshold: float) -> List[FrameworkDetectionResult]:
        """Detect all cross-platform frameworks in the application."""
        frameworks = []
        
        try:
            # Try each framework analyzer's detection method
            for framework_name, analyzer in self.analyzers.items():
                try:
                    if hasattr(analyzer, '_detect_framework') or hasattr(analyzer, f'_detect_{framework_name}_advanced'):
                        # Use analyzer's detection method
                        if framework_name == Framework.REACT_NATIVE.value:
                            detection = analyzer._detect_react_native_advanced(app_data)
                        elif framework_name == Framework.XAMARIN.value and hasattr(analyzer, '_detect_xamarin_advanced'):
                            detection = analyzer._detect_xamarin_advanced(app_data)
                        elif framework_name == Framework.PWA.value and hasattr(analyzer, '_detect_framework_advanced'):
                            detection = analyzer._detect_framework_advanced(app_data)
                        elif framework_name == Framework.FLUTTER.value:
                            detection = self._detect_flutter_enhanced(app_data)
                        else:
                            continue
                        
                        # Use dynamic threshold instead of hardcoded 0.3
                        if detection.confidence >= framework_detection_threshold:
                            frameworks.append(detection)
                            self.logger.info(f"Detected {framework_name} with confidence {detection.confidence:.2f}")
                        
                except Exception as e:
                    self.logger.warning(f"Framework detection failed for {framework_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"Framework detection failed: {e}")
        
        return frameworks
    
    def _detect_flutter_enhanced(self, app_data: Dict) -> FrameworkDetectionResult:
        """Enhanced Flutter detection with professional confidence calculation."""
        try:
            detection_methods = []
            app_content = str(app_data)
            
            # Collect detection evidence
            evidence = []
            
            flutter_indicators = ['flutter', 'dart', 'libflutter', 'flutter_assets']
            for indicator in flutter_indicators:
                if indicator in app_content.lower():
                    detection_methods.append(f"Flutter indicator: {indicator}")
                    evidence.append(f"flutter_indicator:{indicator}")
            
            # Calculate professional confidence using evidence-based approach
            confidence_evidence = ConfidenceEvidence(
                pattern_reliability=0.85,  # Flutter patterns are reliable
                match_quality=len(evidence) / 4.0,  # Quality based on evidence count
                context_relevance=0.80,  # Good relevance for cross-platform analysis
                validation_sources=[f"flutter_detection"],
                cross_validation=len(detection_methods)
            )
            
            confidence = self.confidence_calculator.calculate_confidence(
                'flutter_detection', confidence_evidence
            )
            
            return FrameworkDetectionResult(
                framework=Framework.FLUTTER,
                confidence=confidence,
                version=None,
                detection_methods=detection_methods,
                metadata={'detected_indicators': len(evidence), 'evidence': evidence}
            )
            
        except Exception as e:
            self.logger.error(f"Flutter detection failed: {e}")
            return FrameworkDetectionResult(
                framework=Framework.FLUTTER,
                confidence=0.0,
                version=None,
                detection_methods=[],
                metadata={}
            )
    
    def _analyze_framework(self, framework: str, app_data: Dict, location: str) -> List[CrossPlatformFinding]:
        """Analyze specific framework using its dedicated analyzer."""
        try:
            analyzer = self.analyzers.get(framework)
            if not analyzer:
                return []
            
            # Call analyzer's main analysis method
            if hasattr(analyzer, 'analyze'):
                return analyzer.analyze(app_data, location)
            elif hasattr(analyzer, 'analyze_flutter_security') and framework == Framework.FLUTTER.value:
                # Handle Flutter analyzer's different interface
                flutter_findings = analyzer.analyze_flutter_security(app_data)
                # Convert to CrossPlatformFinding format if needed
                return self._convert_flutter_findings(flutter_findings, location)
            else:
                self.logger.warning(f"No analyze method found for {framework} analyzer")
                return []
                
        except Exception as e:
            self.logger.error(f"Framework analysis failed for {framework}: {e}")
            return []
    
    def _convert_flutter_findings(self, flutter_findings: List, location: str) -> List[CrossPlatformFinding]:
        """Convert Flutter findings to CrossPlatformFinding format."""
        converted_findings = []
        
        try:
            for finding in flutter_findings:
                # Convert Flutter finding to CrossPlatformFinding
                converted = CrossPlatformFinding(
                    framework=Framework.FLUTTER.value,
                    vulnerability_type=getattr(finding, 'vulnerability_type', 'flutter_security'),
                    component=getattr(finding, 'component', 'Flutter Application'),
                    original_content=getattr(finding, 'content', str(finding)),
                    confidence=getattr(finding, 'confidence', 0.7),
                    location=location,
                    severity=getattr(finding, 'severity', Severity.MEDIUM.value),
                    description=getattr(finding, 'description', str(finding)),
                    remediation=getattr(finding, 'remediation', 'Review Flutter security implementation'),
                    attack_vector=getattr(finding, 'attack_vector', 'Flutter application exploit'),
                    cwe_id=getattr(finding, 'cwe_id', None),
                    detection_method='flutter_analysis'
                )
                converted_findings.append(converted)
                
        except Exception as e:
            self.logger.error(f"Flutter finding conversion failed: {e}")
        
        return converted_findings
    
    def _generate_analysis_summary(self, all_findings: List[CrossPlatformFinding], 
                                 framework_results: Dict) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        try:
            # Categorize findings by framework and severity
            framework_summary = {}
            severity_summary = {}
            vulnerability_summary = {}
            
            for finding in all_findings:
                # Framework summary
                if finding.framework not in framework_summary:
                    framework_summary[finding.framework] = 0
                framework_summary[finding.framework] += 1
                
                # Severity summary
                if finding.severity not in severity_summary:
                    severity_summary[finding.severity] = 0
                severity_summary[finding.severity] += 1
                
                # Vulnerability type summary
                if finding.vulnerability_type not in vulnerability_summary:
                    vulnerability_summary[finding.vulnerability_type] = 0
                vulnerability_summary[finding.vulnerability_type] += 1
            
            return {
                'frameworks': framework_summary,
                'severities': severity_summary,
                'vulnerability_types': vulnerability_summary,
                'total_findings': len(all_findings),
                'high_confidence_findings': len([f for f in all_findings if f.confidence >= 0.8]),
                'frameworks_analyzed': len(framework_results)
            }
            
        except Exception as e:
            self.logger.error(f"Analysis summary generation failed: {e}")
            return {}
    
    def _calculate_cross_platform_risk_score(self, findings: List[CrossPlatformFinding]) -> float:
        """Calculate overall cross-platform risk score."""
        try:
            if not findings:
                return 0.0
            
            # Weight findings by severity and confidence
            total_score = 0.0
            severity_weights = {
                Severity.CRITICAL.value: 1.0,
                Severity.HIGH.value: 0.8,
                Severity.MEDIUM.value: 0.6,
                Severity.LOW.value: 0.4,
                Severity.INFO.value: 0.2
            }
            
            for finding in findings:
                severity_weight = severity_weights.get(finding.severity, 0.5)
                confidence_weight = finding.confidence
                total_score += severity_weight * confidence_weight
            
            # Normalize to 0-100 scale
            max_possible_score = len(findings) * 1.0 * 1.0  # max severity * max confidence
            if max_possible_score > 0:
                normalized_score = (total_score / max_possible_score) * 100
            else:
                normalized_score = 0.0
            
            return min(100.0, normalized_score)
            
        except Exception as e:
            self.logger.error(f"Risk score calculation failed: {e}")
            return 0.0
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        elif risk_score >= 20:
            return "low"
        else:
            return "minimal"
    
    def _generate_cross_platform_recommendations(self, findings: List[CrossPlatformFinding]) -> List[str]:
        """Generate cross-platform security recommendations."""
        recommendations = []
        
        try:
            # Framework-specific recommendations
            frameworks = set(finding.framework for finding in findings)
            
            if Framework.REACT_NATIVE.value in frameworks:
                recommendations.extend([
                    "Implement proper input validation for React Native components",
                    "Use secure storage mechanisms instead of AsyncStorage for sensitive data",
                    "Validate all data passed through the native bridge"
                ])
            
            if Framework.XAMARIN.value in frameworks:
                recommendations.extend([
                    "Review P/Invoke calls for security vulnerabilities",
                    "Implement proper certificate pinning for network communications",
                    "Validate IL code for potential security issues"
                ])
            
            if Framework.PWA.value in frameworks:
                recommendations.extend([
                    "Secure service worker registration and message handling",
                    "Implement proper CSP headers for PWA security",
                    "Validate all protocol and file handlers"
                ])
            
            if Framework.FLUTTER.value in frameworks:
                recommendations.extend([
                    "Implement Flutter-specific SSL pinning mechanisms",
                    "Review Dart code for potential security vulnerabilities",
                    "Secure WebView implementations in Flutter apps"
                ])
            
            # General cross-platform recommendations
            recommendations.extend([
                "Regularly update all cross-platform framework dependencies",
                "Implement comprehensive input validation across all frameworks",
                "Use secure communication protocols (HTTPS/TLS) for all network traffic",
                "Implement proper error handling to prevent information disclosure",
                "Conduct regular security assessments of cross-platform components"
            ])
            
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
            recommendations = ["Conduct manual security review of cross-platform components"]
        
        return recommendations
    
    def get_analysis_status(self) -> Dict[str, Any]:
        """Get current analysis engine status and statistics."""
        return {
            'engine_version': '5.0.0',
            'modular_architecture': True,
            'available_analyzers': list(self.analyzers.keys()),
            'supported_frameworks': list(self.analyzers.keys()),
            'analyzer_count': len(self.analyzers),
            'confidence_system': 'professional',
            'analysis_statistics': self.analysis_stats.copy(),
            'configuration': {
                'max_analysis_time': self.config.max_analysis_time,
                'confidence_threshold': self.config.confidence_threshold,
                'parallel_analysis': self.config.enable_parallel_analysis
            }
        }

def get_cross_platform_analysis_engine(config: Optional[AnalysisConfiguration] = None) -> CrossPlatformAnalysisEngine:
    """
    Factory function to create a configured cross-platform analysis engine.
    
    Args:
        config: Optional analysis configuration
        
    Returns:
        Configured CrossPlatformAnalysisEngine instance
    """
    return CrossPlatformAnalysisEngine(config)

# Compatibility function for existing code
async def initialize_phase_f3_1() -> bool:
    """
    Initialize Phase F3.1 cross-platform analysis capabilities.
    
    Returns:
        True if initialization successful, False otherwise
    """
    try:
        # Test engine initialization
        engine = get_cross_platform_analysis_engine()
        status = engine.get_analysis_status()
        
        logging.info(f"Phase F3.1 initialized: {status['analyzer_count']} analyzers available")
        return True
        
    except Exception as e:
        logging.error(f"Phase F3.1 initialization failed: {e}")
        return False 