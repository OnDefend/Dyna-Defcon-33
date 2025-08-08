#!/usr/bin/env python3
"""
Enhanced False Positive Reduction - Integration Helpers
=======================================================

This module provides integration functions for seamless integration of the
enhanced false positive reduction framework with existing AODS components.

Features:
- Enhanced static analyzer integration
- APK2URL extractor integration
- Dynamic analysis integration
- Framework noise detection integration
- Backward compatibility maintenance

"""

from typing import Any, Dict, Optional, Tuple

from loguru import logger

from .secret_analyzer import EnhancedSecretAnalyzer

def integrate_with_enhanced_static_analyzer(analyzer_instance):
    """
    Integration helper for enhanced static analyzer.
    
    This function enhances the existing static analyzer with advanced
    false positive reduction capabilities.
    
    Args:
        analyzer_instance: The static analyzer instance to enhance
        
    Returns:
        Enhanced analyzer instance with new capabilities
    """
    logger.info("Integrating Enhanced False Positive Reducer with static analyzer")
    
    # Initialize enhanced analyzer
    enhanced_analyzer = EnhancedSecretAnalyzer()

    def enhanced_is_likely_secret_content(self, content: str, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, float, Dict[str, Any]]:
        """Enhanced secret detection method for static analyzer."""
        result = enhanced_analyzer.analyze_potential_secret(content, context)
        return result.is_likely_secret, result.confidence_score, result.analysis_details

    # Replace the existing method with enhanced version
    analyzer_instance.is_likely_secret_content = enhanced_is_likely_secret_content.__get__(
        analyzer_instance, analyzer_instance.__class__
    )
    
    # Add additional enhanced methods
    def get_secret_analysis_details(self, content: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get detailed analysis information for a potential secret."""
        result = enhanced_analyzer.analyze_potential_secret(content, context)
        return {
            'content': result.content,
            'is_likely_secret': result.is_likely_secret,
            'confidence_score': result.confidence_score,
            'analysis_details': result.analysis_details,
            'false_positive_indicators': result.false_positive_indicators,
            'true_positive_indicators': result.true_positive_indicators,
            'framework_classification': result.framework_classification,
            'ml_confidence': result.ml_confidence,
            'explainable_features': result.explainable_features,
            'usage_pattern': result.usage_pattern,
            'recommendation': result.recommendation
        }
    
    def is_framework_noise_content(self, content: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Determine if content is framework noise."""
        if not context:
            context = {}
        context_text = str(context)
        return enhanced_analyzer.context_analyzer.is_framework_noise(content, context_text)
    
    def get_entropy_analysis(self, content: str) -> Dict[str, Any]:
        """Get detailed entropy analysis for content."""
        entropy_result = enhanced_analyzer._analyze_entropy_comprehensive(content, None)
        return entropy_result.__dict__
    
    # Bind enhanced methods to analyzer instance
    analyzer_instance.get_secret_analysis_details = get_secret_analysis_details.__get__(
        analyzer_instance, analyzer_instance.__class__
    )
    analyzer_instance.is_framework_noise_content = is_framework_noise_content.__get__(
        analyzer_instance, analyzer_instance.__class__
    )
    analyzer_instance.get_entropy_analysis = get_entropy_analysis.__get__(
        analyzer_instance, analyzer_instance.__class__
    )
    
    # Store reference to enhanced analyzer for advanced usage
    analyzer_instance._enhanced_false_positive_reducer = enhanced_analyzer

    logger.info("Enhanced False Positive Reducer successfully integrated with static analyzer")
    return analyzer_instance

def integrate_with_apk2url_extraction(extractor_instance):
    """
    Integration helper for APK2URL extraction.
    
    This function enhances the URL extractor with advanced framework noise
    detection capabilities.
    
    Args:
        extractor_instance: The URL extractor instance to enhance
        
    Returns:
        Enhanced extractor instance with noise detection
    """
    logger.info("Integrating Enhanced False Positive Reducer with APK2URL extractor")
    
    # Initialize enhanced analyzer
    enhanced_analyzer = EnhancedSecretAnalyzer()

    def enhanced_is_framework_noise(self, url: str, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any]]:
        """Enhanced framework noise detection for URL extractor."""
        result = enhanced_analyzer.analyze_potential_secret(url, context)
        
        # For URL extraction, we invert the logic: if it's likely a secret, it's NOT framework noise
        is_noise = not result.is_likely_secret
        
        # Add specific URL noise detection
        url_lower = url.lower()
        
        # Common framework URLs that are definitely noise
        framework_urls = [
            'schemas.android.com',
            'www.w3.org',
            'xmlns:',
            'http://www.google.com',
            'https://developer.android.com',
            'https://flutter.dev',
            'https://reactnative.dev'
        ]
        
        if any(framework_url in url_lower for framework_url in framework_urls):
            is_noise = True
        
        analysis_details = {
            'original_analysis': result.analysis_details,
            'framework_classification': result.framework_classification,
            'confidence_score': result.confidence_score,
            'is_framework_noise': is_noise,
            'noise_detection_method': 'enhanced_analyzer'
        }
        
        return is_noise, analysis_details

    def enhanced_classify_url_type(self, url: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Classify the type of URL for better filtering."""
        url_lower = url.lower()
        
        # API endpoints
        if any(keyword in url_lower for keyword in ['api', 'rest', 'graphql', 'endpoint']):
            return 'api_endpoint'
        
        # Configuration/schema URLs
        if any(keyword in url_lower for keyword in ['schema', 'xmlns', 'dtd', 'xsd']):
            return 'schema_definition'
        
        # Documentation URLs
        if any(keyword in url_lower for keyword in ['docs', 'documentation', 'help', 'guide']):
            return 'documentation'
        
        # Framework/library URLs
        if any(keyword in url_lower for keyword in ['android', 'flutter', 'react', 'ios']):
            return 'framework_reference'
        
        # Potential secrets (tokens, keys in URL)
        result = enhanced_analyzer.analyze_potential_secret(url, context)
        if result.is_likely_secret:
            return 'potential_secret'
        
        return 'standard_url'

    def get_url_security_assessment(self, url: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get security assessment for a URL."""
        result = enhanced_analyzer.analyze_potential_secret(url, context)
        url_type = enhanced_classify_url_type(enhanced_analyzer, url, context)
        
        return {
            'url': url,
            'url_type': url_type,
            'contains_secrets': result.is_likely_secret,
            'confidence_score': result.confidence_score,
            'security_recommendations': result.recommendation if result.recommendation else 'No specific recommendations',
            'analysis_timestamp': 'now'  # Could use actual timestamp
        }

    # Replace the existing method with enhanced version
    extractor_instance.is_framework_noise = enhanced_is_framework_noise.__get__(
        extractor_instance, extractor_instance.__class__
    )
    
    # Add new enhanced methods
    extractor_instance.enhanced_classify_url_type = enhanced_classify_url_type.__get__(
        extractor_instance, extractor_instance.__class__
    )
    extractor_instance.get_url_security_assessment = get_url_security_assessment.__get__(
        extractor_instance, extractor_instance.__class__
    )
    
    # Store reference to enhanced analyzer
    extractor_instance._enhanced_false_positive_reducer = enhanced_analyzer

    logger.info("Enhanced False Positive Reducer successfully integrated with APK2URL extractor")
    return extractor_instance

def integrate_with_dynamic_analyzer(analyzer_instance):
    """
    Integration helper for dynamic analysis components.
    
    Args:
        analyzer_instance: The dynamic analyzer instance to enhance
        
    Returns:
        Enhanced analyzer instance
    """
    logger.info("Integrating Enhanced False Positive Reducer with dynamic analyzer")
    
    # Initialize enhanced analyzer
    enhanced_analyzer = EnhancedSecretAnalyzer()

    def enhanced_analyze_runtime_secret(self, content: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze secrets found during runtime analysis."""
        # Add runtime context
        if not context:
            context = {}
        context['analysis_type'] = 'dynamic_runtime'
        
        result = enhanced_analyzer.analyze_potential_secret(content, context)
        
        return {
            'content': content,
            'is_likely_secret': result.is_likely_secret,
            'confidence_score': result.confidence_score,
            'runtime_context': context,
            'analysis_details': result.analysis_details,
            'recommendation': result.recommendation,
            'risk_level': 'HIGH' if result.is_likely_secret and result.confidence_score > 0.8 else 'MEDIUM' if result.is_likely_secret else 'LOW'
        }

    def filter_runtime_noise(self, findings: list, context: Optional[Dict[str, Any]] = None) -> list:
        """Filter runtime findings to remove noise."""
        filtered_findings = []
        
        for finding in findings:
            content = finding.get('content', '')
            finding_context = finding.get('context', {})
            
            # Merge contexts
            merged_context = {**(context or {}), **finding_context}
            
            analysis = enhanced_analyzer.analyze_potential_secret(content, merged_context)
            
            # Keep finding if it's likely a real secret
            if analysis.is_likely_secret:
                finding['enhanced_analysis'] = {
                    'confidence': analysis.confidence_score,
                    'indicators': analysis.true_positive_indicators,
                    'recommendation': analysis.recommendation
                }
                filtered_findings.append(finding)
            else:
                # Log filtered findings for debugging
                logger.debug(f"Filtered runtime noise: {content[:50]}... (confidence: {analysis.confidence_score})")

        return filtered_findings

    # Bind enhanced methods
    analyzer_instance.enhanced_analyze_runtime_secret = enhanced_analyze_runtime_secret.__get__(
        analyzer_instance, analyzer_instance.__class__
    )
    analyzer_instance.filter_runtime_noise = filter_runtime_noise.__get__(
        analyzer_instance, analyzer_instance.__class__
    )
    
    # Store reference
    analyzer_instance._enhanced_false_positive_reducer = enhanced_analyzer

    logger.info("Enhanced False Positive Reducer successfully integrated with dynamic analyzer")
    return analyzer_instance

def integrate_with_vulnerability_scanner(scanner_instance):
    """
    Integration helper for vulnerability scanning components.
    
    Args:
        scanner_instance: The vulnerability scanner instance to enhance
        
    Returns:
        Enhanced scanner instance
    """
    logger.info("Integrating Enhanced False Positive Reducer with vulnerability scanner")
    
    # Initialize enhanced analyzer
    enhanced_analyzer = EnhancedSecretAnalyzer()

    def enhanced_validate_secret_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and enhance secret-related vulnerability findings."""
        content = finding.get('content', finding.get('description', ''))
        context = {
            'file_path': finding.get('file_path', ''),
            'line_number': finding.get('line_number'),
            'vulnerability_type': finding.get('type', ''),
            'severity': finding.get('severity', ''),
            'surrounding_lines': finding.get('context_lines', [])
        }
        
        analysis = enhanced_analyzer.analyze_potential_secret(content, context)
        
        # Enhance the finding with analysis results
        enhanced_finding = finding.copy()
        enhanced_finding.update({
            'is_likely_real_secret': analysis.is_likely_secret,
            'confidence_score': analysis.confidence_score,
            'false_positive_probability': 1.0 - analysis.confidence_score,
            'analysis_details': analysis.analysis_details,
            'recommendations': analysis.recommendation,
            'enhanced_severity': _calculate_enhanced_severity(finding.get('severity', ''), analysis),
            'action_required': _determine_action_required(analysis)
        })
        
        return enhanced_finding

    def filter_false_positive_findings(self, findings: list) -> Tuple[list, list]:
        """Filter findings to separate likely real vulnerabilities from false positives."""
        real_findings = []
        false_positive_findings = []
        
        for finding in findings:
            enhanced_finding = enhanced_validate_secret_finding(scanner_instance, finding)
            
            if enhanced_finding['is_likely_real_secret']:
                real_findings.append(enhanced_finding)
            else:
                false_positive_findings.append(enhanced_finding)
        
        return real_findings, false_positive_findings

    # Bind enhanced methods
    scanner_instance.enhanced_validate_secret_finding = enhanced_validate_secret_finding.__get__(
        scanner_instance, scanner_instance.__class__
    )
    scanner_instance.filter_false_positive_findings = filter_false_positive_findings.__get__(
        scanner_instance, scanner_instance.__class__
    )
    
    # Store reference
    scanner_instance._enhanced_false_positive_reducer = enhanced_analyzer

    logger.info("Enhanced False Positive Reducer successfully integrated with vulnerability scanner")
    return scanner_instance

def _calculate_enhanced_severity(original_severity: str, analysis) -> str:
    """Calculate enhanced severity based on analysis confidence."""
    if not analysis.is_likely_secret:
        return "LOW"  # Reduce severity for likely false positives
    
    confidence = analysis.confidence_score
    
    if confidence > 0.9:
        return "CRITICAL" if original_severity in ["HIGH", "CRITICAL"] else "HIGH"
    elif confidence > 0.7:
        return original_severity  # Keep original severity
    else:
        # Lower severity for low confidence findings
        severity_map = {
            "CRITICAL": "HIGH",
            "HIGH": "MEDIUM",
            "MEDIUM": "LOW",
            "LOW": "INFO"
        }
        return severity_map.get(original_severity, original_severity)

def _determine_action_required(analysis) -> str:
    """Determine the action required based on analysis."""
    if not analysis.is_likely_secret:
        return "IGNORE - Likely false positive"
    
    confidence = analysis.confidence_score
    
    if confidence > 0.9:
        return "IMMEDIATE REVIEW - High confidence secret detected"
    elif confidence > 0.7:
        return "REVIEW REQUIRED - Potential secret detected"
    else:
        return "MANUAL REVIEW - Low confidence finding"

# Convenience function for bulk integration
def integrate_enhanced_false_positive_reducer(components: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to integrate enhanced false positive reducer with multiple components.
    
    Args:
        components: Dictionary of component names to component instances
        
    Returns:
        Dictionary of enhanced component instances
    """
    enhanced_components = {}
    
    integration_map = {
        'static_analyzer': integrate_with_enhanced_static_analyzer,
        'url_extractor': integrate_with_apk2url_extraction,
        'dynamic_analyzer': integrate_with_dynamic_analyzer,
        'vulnerability_scanner': integrate_with_vulnerability_scanner
    }
    
    for component_name, component_instance in components.items():
        if component_name in integration_map:
            enhanced_components[component_name] = integration_map[component_name](component_instance)
            logger.info(f"Enhanced {component_name} with false positive reduction")
        else:
            enhanced_components[component_name] = component_instance
            logger.warning(f"No integration available for {component_name}")
    
    return enhanced_components 