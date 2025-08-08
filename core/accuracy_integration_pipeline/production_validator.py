#!/usr/bin/env python3
"""
Accuracy Integration Pipeline - Production Validator

production validation framework for accuracy pipeline with
real-world vulnerability detection validation against known test applications.
"""

import logging
from typing import Dict, List, Any

from .data_structures import DetectionQualityIndicators, VulnerabilityPreservationReport

class ProductionAccuracyValidator:
    """
    Production validation framework for accuracy pipeline that validates
    accuracy improvements against real-world APKs and known vulnerable applications.
    """
    
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.validation_results = []
        self.logger = logging.getLogger(__name__)
    
    def validate_security_testing_app(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate accuracy improvements against security testing applications using organic detection.
        Ensures maximum vulnerability preservation for known vulnerable test applications.
        """
        self.logger.info("Validating accuracy against security testing application")
        
        # Detect app context from findings using organic analysis
        app_context = self._detect_app_context_from_findings(findings_data)
        
        # Override with security testing app characteristics
        app_context.update({
            'app_category': 'security_testing',
            'is_debug_build': True,
            'target_sdk': 28,
            'validation_mode': True
        })
        
        # Process findings through accuracy pipeline
        result = self.pipeline.process_findings(findings_data, app_context)
        
        # Validate vulnerability preservation using organic patterns
        vulnerability_preservation = self._validate_vulnerability_preservation(result['final_findings'])
        
        # Calculate quality indicators
        quality_indicators = self._calculate_quality_indicators(
            findings_data, result['final_findings'], vulnerability_preservation
        )
        
        validation_result = {
            'test_name': 'SecurityTestApp_Accuracy_Validation',
            'original_findings': len(findings_data),
            'final_findings': len(result['final_findings']),
            'reduction_achieved': result['accuracy_metrics']['overall_reduction_percentage'],
            'target_reduction': 99.6,  # High reduction for security testing apps
            'vulnerability_preservation': vulnerability_preservation,
            'quality_indicators': quality_indicators,
            'validation_status': self._determine_validation_status(quality_indicators),
            'detection_accuracy': quality_indicators.overall_detection_accuracy,
            'meets_production_standards': quality_indicators.meets_production_standards
        }
        
        self.validation_results.append(validation_result)
        self.logger.info(f"Security testing app validation: {validation_result['validation_status']}")
        
        return validation_result
    
    def validate_vulnerable_test_app(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate accuracy improvements against vulnerable test applications using organic detection.
        Focus on maintaining detection of real vulnerabilities while reducing noise.
        """
        self.logger.info("Validating accuracy against vulnerable test application")
        
        # Detect app context from findings using organic analysis
        app_context = self._detect_app_context_from_findings(findings_data)
        
        # Override with vulnerable app characteristics
        app_context.update({
            'app_category': 'security_testing',
            'is_debug_build': False,
            'contains_real_vulnerabilities': True,
            'validation_mode': True
        })
        
        # Process findings through accuracy pipeline
        result = self.pipeline.process_findings(findings_data, app_context)
        
        # Validate vulnerability preservation
        vulnerability_preservation = self._validate_vulnerability_preservation(result['final_findings'])
        
        # Calculate quality indicators with stricter requirements for vulnerable apps
        quality_indicators = self._calculate_quality_indicators(
            findings_data, result['final_findings'], vulnerability_preservation, strict_mode=True
        )
        
        validation_result = {
            'test_name': 'VulnerableTestApp_Accuracy_Validation',
            'original_findings': len(findings_data),
            'final_findings': len(result['final_findings']),
            'reduction_achieved': result['accuracy_metrics']['overall_reduction_percentage'],
            'target_reduction': 99.3,  # High but lower than security testing apps
            'vulnerability_preservation': vulnerability_preservation,
            'quality_indicators': quality_indicators,
            'validation_status': self._determine_validation_status(quality_indicators),
            'detection_accuracy': quality_indicators.overall_detection_accuracy,
            'meets_production_standards': quality_indicators.meets_production_standards,
            'real_vulnerability_detection': vulnerability_preservation.critical_vulnerability_preservation
        }
        
        self.validation_results.append(validation_result)
        self.logger.info(f"Vulnerable test app validation: {validation_result['validation_status']}")
        
        return validation_result
    
    def validate_production_app(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate accuracy improvements against production applications.
        Focus on high-precision detection with minimal false positives.
        """
        self.logger.info("Validating accuracy against production application")
        
        # Detect app context from findings
        app_context = self._detect_app_context_from_findings(findings_data)
        
        # Override with production app characteristics
        app_context.update({
            'app_category': 'production',
            'is_debug_build': False,
            'high_precision_required': True,
            'validation_mode': True
        })
        
        # Process findings through accuracy pipeline
        result = self.pipeline.process_findings(findings_data, app_context)
        
        # Validate with production standards
        vulnerability_preservation = self._validate_vulnerability_preservation(result['final_findings'])
        quality_indicators = self._calculate_quality_indicators(
            findings_data, result['final_findings'], vulnerability_preservation, production_mode=True
        )
        
        validation_result = {
            'test_name': 'ProductionApp_Accuracy_Validation',
            'original_findings': len(findings_data),
            'final_findings': len(result['final_findings']),
            'reduction_achieved': result['accuracy_metrics']['overall_reduction_percentage'],
            'target_reduction': 95.0,  # Lower reduction target for production
            'vulnerability_preservation': vulnerability_preservation,
            'quality_indicators': quality_indicators,
            'validation_status': self._determine_validation_status(quality_indicators),
            'detection_accuracy': quality_indicators.overall_detection_accuracy,
            'meets_production_standards': quality_indicators.meets_production_standards,
            'high_precision_mode': True
        }
        
        self.validation_results.append(validation_result)
        self.logger.info(f"Production app validation: {validation_result['validation_status']}")
        
        return validation_result
    
    def _detect_app_context_from_findings(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Organically detect app context from findings patterns and characteristics.
        """
        context = {
            'total_findings': len(findings_data),
            'app_category': 'unknown',
            'framework': 'native',
            'is_debug_build': False,
            'organic_detection': True
        }
        
        if not findings_data:
            return context
        
        # Analyze findings patterns to detect app characteristics
        high_severity_count = sum(1 for f in findings_data if str(f.get('severity', '')).upper() in ['HIGH', 'CRITICAL'])
        debug_indicators = sum(1 for f in findings_data if 'debug' in str(f.get('description', '')).lower())
        
        # Detection logic based on finding patterns
        if high_severity_count > len(findings_data) * 0.3:
            context['app_category'] = 'security_testing'
        
        if debug_indicators > 0:
            context['is_debug_build'] = True
        
        # Framework detection
        framework_indicators = {}
        for finding in findings_data:
            description = str(finding.get('description', '')).lower()
            if 'react' in description or 'native' in description:
                framework_indicators['react_native'] = framework_indicators.get('react_native', 0) + 1
            elif 'flutter' in description:
                framework_indicators['flutter'] = framework_indicators.get('flutter', 0) + 1
            elif 'xamarin' in description:
                framework_indicators['xamarin'] = framework_indicators.get('xamarin', 0) + 1
        
        if framework_indicators:
            context['framework'] = max(framework_indicators, key=framework_indicators.get)
        
        return context
    
    def _validate_vulnerability_preservation(self, final_findings: List[Dict[str, Any]]) -> VulnerabilityPreservationReport:
        """
        Validate that genuine vulnerabilities have been preserved through the pipeline.
        """
        # Identify likely vulnerabilities in final findings
        preserved_vulnerabilities = []
        for finding in final_findings:
            if self._is_likely_genuine_vulnerability(finding):
                preserved_vulnerabilities.append(finding)
        
        # Calculate preservation metrics
        total_vulnerabilities = len([f for f in final_findings if self._has_vulnerability_indicators(f)])
        critical_vulnerabilities = len([f for f in preserved_vulnerabilities if str(f.get('severity', '')).upper() == 'CRITICAL'])
        high_severity_vulnerabilities = len([f for f in preserved_vulnerabilities if str(f.get('severity', '')).upper() in ['HIGH', 'CRITICAL']])
        
        preservation_rate = (len(preserved_vulnerabilities) / max(1, total_vulnerabilities)) * 100
        critical_preservation = (critical_vulnerabilities / max(1, len(final_findings))) * 100
        high_severity_preservation = (high_severity_vulnerabilities / max(1, len(final_findings))) * 100
        
        return VulnerabilityPreservationReport(
            preserved_vulnerabilities=preserved_vulnerabilities,
            preservation_rate=preservation_rate,
            critical_vulnerability_preservation=critical_preservation,
            high_severity_preservation=high_severity_preservation,
            meets_detection_standards=preservation_rate >= 85.0  # Minimum 85% preservation required
        )
    
    def _is_likely_genuine_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """
        Determine if a finding represents a likely genuine vulnerability.
        """
        # High confidence threshold
        confidence = finding.get('confidence', 0.0)
        if confidence >= 0.8:
            return True
        
        # High/Critical severity
        severity = str(finding.get('severity', '')).upper()
        if severity in ['HIGH', 'CRITICAL']:
            return True
        
        # Known vulnerability patterns
        finding_type = str(finding.get('type', '')).lower()
        title = str(finding.get('title', '')).lower()
        description = str(finding.get('description', '')).lower()
        
        vulnerability_patterns = [
            'sql_injection', 'xss', 'csrf', 'authentication', 'authorization',
            'hardcoded', 'crypto', 'ssl', 'tls', 'certificate', 'permission',
            'privilege', 'backdoor', 'injection', 'script'
        ]
        
        combined_text = f"{finding_type} {title} {description}"
        return any(pattern in combined_text for pattern in vulnerability_patterns)
    
    def _has_vulnerability_indicators(self, finding: Dict[str, Any]) -> bool:
        """
        Check if finding has basic vulnerability indicators.
        """
        # Any finding with medium+ severity or moderate+ confidence could be a vulnerability
        severity = str(finding.get('severity', '')).upper()
        confidence = finding.get('confidence', 0.0)
        
        return severity in ['MEDIUM', 'HIGH', 'CRITICAL'] or confidence >= 0.6
    
    def _calculate_quality_indicators(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]],
        vulnerability_preservation: VulnerabilityPreservationReport,
        strict_mode: bool = False,
        production_mode: bool = False
    ) -> DetectionQualityIndicators:
        """
        Calculate comprehensive quality indicators for validation.
        """
        total_input = len(original_findings)
        total_output = len(final_findings)
        
        # Calculate metrics
        false_positive_elimination_rate = ((total_input - total_output) / max(1, total_input)) * 100
        overall_detection_accuracy = (len(vulnerability_preservation.preserved_vulnerabilities) / max(1, total_input)) * 100
        
        # Determine quality thresholds based on mode
        if production_mode:
            quality_threshold = 95.0  # Higher threshold for production
        elif strict_mode:
            quality_threshold = 90.0  # High threshold for vulnerable apps
        else:
            quality_threshold = 85.0  # Standard threshold
        
        meets_standards = (
            overall_detection_accuracy >= quality_threshold and
            vulnerability_preservation.meets_detection_standards and
            false_positive_elimination_rate >= 80.0  # Minimum noise reduction
        )
        
        # Determine quality level
        if overall_detection_accuracy >= 95:
            from .data_structures import DetectionQuality
            quality = DetectionQuality.EXCELLENT
        elif overall_detection_accuracy >= 85:
            quality = DetectionQuality.GOOD
        elif overall_detection_accuracy >= 75:
            quality = DetectionQuality.ACCEPTABLE
        else:
            quality = DetectionQuality.POOR
        
        return DetectionQualityIndicators(
            total_vulnerabilities_input=total_input,
            total_vulnerabilities_output=total_output,
            vulnerability_preservation_rate=vulnerability_preservation.preservation_rate,
            false_positive_elimination_rate=false_positive_elimination_rate,
            overall_detection_accuracy=overall_detection_accuracy,
            detection_quality=quality,
            quality_score=overall_detection_accuracy / 100.0,
            meets_production_standards=meets_standards
        )
    
    def _determine_validation_status(self, quality_indicators: DetectionQualityIndicators) -> str:
        """
        Determine overall validation status based on quality indicators.
        """
        if quality_indicators.meets_production_standards:
            if quality_indicators.overall_detection_accuracy >= 95:
                return 'EXCELLENT'
            else:
                return 'PASS'
        else:
            if quality_indicators.overall_detection_accuracy >= 75:
                return 'MARGINAL'
            else:
                return 'FAIL'
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive validation summary across all tests.
        """
        if not self.validation_results:
            return {'message': 'No validation results available'}
        
        total_tests = len(self.validation_results)
        passed_tests = sum(1 for r in self.validation_results if r['validation_status'] in ['PASS', 'EXCELLENT'])
        
        avg_detection_accuracy = sum(r['detection_accuracy'] for r in self.validation_results) / total_tests
        avg_reduction = sum(r['reduction_achieved'] for r in self.validation_results) / total_tests
        
        return {
            'total_validation_tests': total_tests,
            'passed_tests': passed_tests,
            'pass_rate': (passed_tests / total_tests) * 100,
            'average_detection_accuracy': avg_detection_accuracy,
            'average_noise_reduction': avg_reduction,
            'overall_validation_status': 'PASS' if passed_tests >= total_tests * 0.8 else 'FAIL',
            'validation_results': self.validation_results
        } 
"""
Accuracy Integration Pipeline - Production Validator

production validation framework for accuracy pipeline with
real-world vulnerability detection validation against known test applications.
"""

import logging
from typing import Dict, List, Any

from .data_structures import DetectionQualityIndicators, VulnerabilityPreservationReport

class ProductionAccuracyValidator:
    """
    Production validation framework for accuracy pipeline that validates
    accuracy improvements against real-world APKs and known vulnerable applications.
    """
    
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.validation_results = []
        self.logger = logging.getLogger(__name__)
    
    def validate_security_testing_app(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate accuracy improvements against security testing applications using organic detection.
        Ensures maximum vulnerability preservation for known vulnerable test applications.
        """
        self.logger.info("Validating accuracy against security testing application")
        
        # Detect app context from findings using organic analysis
        app_context = self._detect_app_context_from_findings(findings_data)
        
        # Override with security testing app characteristics
        app_context.update({
            'app_category': 'security_testing',
            'is_debug_build': True,
            'target_sdk': 28,
            'validation_mode': True
        })
        
        # Process findings through accuracy pipeline
        result = self.pipeline.process_findings(findings_data, app_context)
        
        # Validate vulnerability preservation using organic patterns
        vulnerability_preservation = self._validate_vulnerability_preservation(result['final_findings'])
        
        # Calculate quality indicators
        quality_indicators = self._calculate_quality_indicators(
            findings_data, result['final_findings'], vulnerability_preservation
        )
        
        validation_result = {
            'test_name': 'SecurityTestApp_Accuracy_Validation',
            'original_findings': len(findings_data),
            'final_findings': len(result['final_findings']),
            'reduction_achieved': result['accuracy_metrics']['overall_reduction_percentage'],
            'target_reduction': 99.6,  # High reduction for security testing apps
            'vulnerability_preservation': vulnerability_preservation,
            'quality_indicators': quality_indicators,
            'validation_status': self._determine_validation_status(quality_indicators),
            'detection_accuracy': quality_indicators.overall_detection_accuracy,
            'meets_production_standards': quality_indicators.meets_production_standards
        }
        
        self.validation_results.append(validation_result)
        self.logger.info(f"Security testing app validation: {validation_result['validation_status']}")
        
        return validation_result
    
    def validate_vulnerable_test_app(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate accuracy improvements against vulnerable test applications using organic detection.
        Focus on maintaining detection of real vulnerabilities while reducing noise.
        """
        self.logger.info("Validating accuracy against vulnerable test application")
        
        # Detect app context from findings using organic analysis
        app_context = self._detect_app_context_from_findings(findings_data)
        
        # Override with vulnerable app characteristics
        app_context.update({
            'app_category': 'security_testing',
            'is_debug_build': False,
            'contains_real_vulnerabilities': True,
            'validation_mode': True
        })
        
        # Process findings through accuracy pipeline
        result = self.pipeline.process_findings(findings_data, app_context)
        
        # Validate vulnerability preservation
        vulnerability_preservation = self._validate_vulnerability_preservation(result['final_findings'])
        
        # Calculate quality indicators with stricter requirements for vulnerable apps
        quality_indicators = self._calculate_quality_indicators(
            findings_data, result['final_findings'], vulnerability_preservation, strict_mode=True
        )
        
        validation_result = {
            'test_name': 'VulnerableTestApp_Accuracy_Validation',
            'original_findings': len(findings_data),
            'final_findings': len(result['final_findings']),
            'reduction_achieved': result['accuracy_metrics']['overall_reduction_percentage'],
            'target_reduction': 99.3,  # High but lower than security testing apps
            'vulnerability_preservation': vulnerability_preservation,
            'quality_indicators': quality_indicators,
            'validation_status': self._determine_validation_status(quality_indicators),
            'detection_accuracy': quality_indicators.overall_detection_accuracy,
            'meets_production_standards': quality_indicators.meets_production_standards,
            'real_vulnerability_detection': vulnerability_preservation.critical_vulnerability_preservation
        }
        
        self.validation_results.append(validation_result)
        self.logger.info(f"Vulnerable test app validation: {validation_result['validation_status']}")
        
        return validation_result
    
    def validate_production_app(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate accuracy improvements against production applications.
        Focus on high-precision detection with minimal false positives.
        """
        self.logger.info("Validating accuracy against production application")
        
        # Detect app context from findings
        app_context = self._detect_app_context_from_findings(findings_data)
        
        # Override with production app characteristics
        app_context.update({
            'app_category': 'production',
            'is_debug_build': False,
            'high_precision_required': True,
            'validation_mode': True
        })
        
        # Process findings through accuracy pipeline
        result = self.pipeline.process_findings(findings_data, app_context)
        
        # Validate with production standards
        vulnerability_preservation = self._validate_vulnerability_preservation(result['final_findings'])
        quality_indicators = self._calculate_quality_indicators(
            findings_data, result['final_findings'], vulnerability_preservation, production_mode=True
        )
        
        validation_result = {
            'test_name': 'ProductionApp_Accuracy_Validation',
            'original_findings': len(findings_data),
            'final_findings': len(result['final_findings']),
            'reduction_achieved': result['accuracy_metrics']['overall_reduction_percentage'],
            'target_reduction': 95.0,  # Lower reduction target for production
            'vulnerability_preservation': vulnerability_preservation,
            'quality_indicators': quality_indicators,
            'validation_status': self._determine_validation_status(quality_indicators),
            'detection_accuracy': quality_indicators.overall_detection_accuracy,
            'meets_production_standards': quality_indicators.meets_production_standards,
            'high_precision_mode': True
        }
        
        self.validation_results.append(validation_result)
        self.logger.info(f"Production app validation: {validation_result['validation_status']}")
        
        return validation_result
    
    def _detect_app_context_from_findings(self, findings_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Organically detect app context from findings patterns and characteristics.
        """
        context = {
            'total_findings': len(findings_data),
            'app_category': 'unknown',
            'framework': 'native',
            'is_debug_build': False,
            'organic_detection': True
        }
        
        if not findings_data:
            return context
        
        # Analyze findings patterns to detect app characteristics
        high_severity_count = sum(1 for f in findings_data if str(f.get('severity', '')).upper() in ['HIGH', 'CRITICAL'])
        debug_indicators = sum(1 for f in findings_data if 'debug' in str(f.get('description', '')).lower())
        
        # Detection logic based on finding patterns
        if high_severity_count > len(findings_data) * 0.3:
            context['app_category'] = 'security_testing'
        
        if debug_indicators > 0:
            context['is_debug_build'] = True
        
        # Framework detection
        framework_indicators = {}
        for finding in findings_data:
            description = str(finding.get('description', '')).lower()
            if 'react' in description or 'native' in description:
                framework_indicators['react_native'] = framework_indicators.get('react_native', 0) + 1
            elif 'flutter' in description:
                framework_indicators['flutter'] = framework_indicators.get('flutter', 0) + 1
            elif 'xamarin' in description:
                framework_indicators['xamarin'] = framework_indicators.get('xamarin', 0) + 1
        
        if framework_indicators:
            context['framework'] = max(framework_indicators, key=framework_indicators.get)
        
        return context
    
    def _validate_vulnerability_preservation(self, final_findings: List[Dict[str, Any]]) -> VulnerabilityPreservationReport:
        """
        Validate that genuine vulnerabilities have been preserved through the pipeline.
        """
        # Identify likely vulnerabilities in final findings
        preserved_vulnerabilities = []
        for finding in final_findings:
            if self._is_likely_genuine_vulnerability(finding):
                preserved_vulnerabilities.append(finding)
        
        # Calculate preservation metrics
        total_vulnerabilities = len([f for f in final_findings if self._has_vulnerability_indicators(f)])
        critical_vulnerabilities = len([f for f in preserved_vulnerabilities if str(f.get('severity', '')).upper() == 'CRITICAL'])
        high_severity_vulnerabilities = len([f for f in preserved_vulnerabilities if str(f.get('severity', '')).upper() in ['HIGH', 'CRITICAL']])
        
        preservation_rate = (len(preserved_vulnerabilities) / max(1, total_vulnerabilities)) * 100
        critical_preservation = (critical_vulnerabilities / max(1, len(final_findings))) * 100
        high_severity_preservation = (high_severity_vulnerabilities / max(1, len(final_findings))) * 100
        
        return VulnerabilityPreservationReport(
            preserved_vulnerabilities=preserved_vulnerabilities,
            preservation_rate=preservation_rate,
            critical_vulnerability_preservation=critical_preservation,
            high_severity_preservation=high_severity_preservation,
            meets_detection_standards=preservation_rate >= 85.0  # Minimum 85% preservation required
        )
    
    def _is_likely_genuine_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """
        Determine if a finding represents a likely genuine vulnerability.
        """
        # High confidence threshold
        confidence = finding.get('confidence', 0.0)
        if confidence >= 0.8:
            return True
        
        # High/Critical severity
        severity = str(finding.get('severity', '')).upper()
        if severity in ['HIGH', 'CRITICAL']:
            return True
        
        # Known vulnerability patterns
        finding_type = str(finding.get('type', '')).lower()
        title = str(finding.get('title', '')).lower()
        description = str(finding.get('description', '')).lower()
        
        vulnerability_patterns = [
            'sql_injection', 'xss', 'csrf', 'authentication', 'authorization',
            'hardcoded', 'crypto', 'ssl', 'tls', 'certificate', 'permission',
            'privilege', 'backdoor', 'injection', 'script'
        ]
        
        combined_text = f"{finding_type} {title} {description}"
        return any(pattern in combined_text for pattern in vulnerability_patterns)
    
    def _has_vulnerability_indicators(self, finding: Dict[str, Any]) -> bool:
        """
        Check if finding has basic vulnerability indicators.
        """
        # Any finding with medium+ severity or moderate+ confidence could be a vulnerability
        severity = str(finding.get('severity', '')).upper()
        confidence = finding.get('confidence', 0.0)
        
        return severity in ['MEDIUM', 'HIGH', 'CRITICAL'] or confidence >= 0.6
    
    def _calculate_quality_indicators(
        self, 
        original_findings: List[Dict[str, Any]], 
        final_findings: List[Dict[str, Any]],
        vulnerability_preservation: VulnerabilityPreservationReport,
        strict_mode: bool = False,
        production_mode: bool = False
    ) -> DetectionQualityIndicators:
        """
        Calculate comprehensive quality indicators for validation.
        """
        total_input = len(original_findings)
        total_output = len(final_findings)
        
        # Calculate metrics
        false_positive_elimination_rate = ((total_input - total_output) / max(1, total_input)) * 100
        overall_detection_accuracy = (len(vulnerability_preservation.preserved_vulnerabilities) / max(1, total_input)) * 100
        
        # Determine quality thresholds based on mode
        if production_mode:
            quality_threshold = 95.0  # Higher threshold for production
        elif strict_mode:
            quality_threshold = 90.0  # High threshold for vulnerable apps
        else:
            quality_threshold = 85.0  # Standard threshold
        
        meets_standards = (
            overall_detection_accuracy >= quality_threshold and
            vulnerability_preservation.meets_detection_standards and
            false_positive_elimination_rate >= 80.0  # Minimum noise reduction
        )
        
        # Determine quality level
        if overall_detection_accuracy >= 95:
            from .data_structures import DetectionQuality
            quality = DetectionQuality.EXCELLENT
        elif overall_detection_accuracy >= 85:
            quality = DetectionQuality.GOOD
        elif overall_detection_accuracy >= 75:
            quality = DetectionQuality.ACCEPTABLE
        else:
            quality = DetectionQuality.POOR
        
        return DetectionQualityIndicators(
            total_vulnerabilities_input=total_input,
            total_vulnerabilities_output=total_output,
            vulnerability_preservation_rate=vulnerability_preservation.preservation_rate,
            false_positive_elimination_rate=false_positive_elimination_rate,
            overall_detection_accuracy=overall_detection_accuracy,
            detection_quality=quality,
            quality_score=overall_detection_accuracy / 100.0,
            meets_production_standards=meets_standards
        )
    
    def _determine_validation_status(self, quality_indicators: DetectionQualityIndicators) -> str:
        """
        Determine overall validation status based on quality indicators.
        """
        if quality_indicators.meets_production_standards:
            if quality_indicators.overall_detection_accuracy >= 95:
                return 'EXCELLENT'
            else:
                return 'PASS'
        else:
            if quality_indicators.overall_detection_accuracy >= 75:
                return 'MARGINAL'
            else:
                return 'FAIL'
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive validation summary across all tests.
        """
        if not self.validation_results:
            return {'message': 'No validation results available'}
        
        total_tests = len(self.validation_results)
        passed_tests = sum(1 for r in self.validation_results if r['validation_status'] in ['PASS', 'EXCELLENT'])
        
        avg_detection_accuracy = sum(r['detection_accuracy'] for r in self.validation_results) / total_tests
        avg_reduction = sum(r['reduction_achieved'] for r in self.validation_results) / total_tests
        
        return {
            'total_validation_tests': total_tests,
            'passed_tests': passed_tests,
            'pass_rate': (passed_tests / total_tests) * 100,
            'average_detection_accuracy': avg_detection_accuracy,
            'average_noise_reduction': avg_reduction,
            'overall_validation_status': 'PASS' if passed_tests >= total_tests * 0.8 else 'FAIL',
            'validation_results': self.validation_results
        } 