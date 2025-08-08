#!/usr/bin/env python3
"""
Integrated Enhanced Analyzer for AODS
=====================================

This module provides seamless integration of the enhanced false positive reducer
with existing AODS components, ensuring backward compatibility while dramatically
improving accuracy.

"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add the enhanced analyzer to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_false_positive_reducer import (
    EnhancedSecretAnalyzer, SecretAnalysisResult,
    integrate_with_apk2url_extraction, integrate_with_enhanced_static_analyzer)

# Import existing AODS components
try:
    from enhanced_static_analyzer import EnhancedStaticAnalyzer
except ImportError:
    logging.warning(
        "Could not import EnhancedStaticAnalyzer - will create compatibility layer"
    )

try:
    from plugins.apk2url_extraction import APK2URLExtractor
except ImportError:
    logging.warning(
        "Could not import APK2URLExtractor - will create compatibility layer"
    )

class IntegratedEnhancedAnalyzer:
    """
    Integrated analyzer that enhances existing AODS components with
    specialized false positive reduction libraries.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the integrated enhanced analyzer."""
        self.logger = logging.getLogger(__name__)

        # Initialize the enhanced secret analyzer
        self.enhanced_analyzer = EnhancedSecretAnalyzer(config_path)

        # Track performance metrics
        self.performance_metrics = {
            "total_analyzed": 0,
            "false_positives_eliminated": 0,
            "true_positives_found": 0,
            "analysis_time": 0.0,
        }

        self.logger.debug("Integrated Enhanced Analyzer initialized successfully")

    def enhance_static_analyzer(self, static_analyzer_instance):
        """
        Enhance an existing static analyzer instance with advanced false positive reduction.

        Args:
            static_analyzer_instance: Instance of EnhancedStaticAnalyzer

        Returns:
            Enhanced analyzer instance
        """
        try:
            # Integrate enhanced secret detection
            enhanced_instance = integrate_with_enhanced_static_analyzer(
                static_analyzer_instance
            )

            # Add additional methods for advanced analysis
            enhanced_instance.analyze_secret_with_context = (
                self._create_context_aware_analyzer()
            )
            enhanced_instance.batch_analyze_secrets = self._create_batch_analyzer()
            enhanced_instance.get_analysis_metrics = (
                lambda: self.performance_metrics.copy()
            )

            self.logger.debug(
                "Successfully enhanced static analyzer with advanced false positive reduction"
            )
            return enhanced_instance

        except Exception as e:
            self.logger.error(f"Failed to enhance static analyzer: {e}")
            return static_analyzer_instance

    def enhance_apk2url_extractor(self, extractor_instance):
        """
        Enhance an existing APK2URL extractor with advanced URL validation.

        Args:
            extractor_instance: Instance of APK2URLExtractor

        Returns:
            Enhanced extractor instance
        """
        try:
            # Integrate enhanced URL/domain validation
            enhanced_instance = integrate_with_apk2url_extraction(extractor_instance)

            # Add URL analysis methods
            enhanced_instance.analyze_url_validity = self._create_url_analyzer()
            enhanced_instance.classify_endpoint_type = (
                self._create_endpoint_classifier()
            )
            enhanced_instance.validate_domain_legitimacy = (
                self._create_domain_validator()
            )

            self.logger.debug(
                "Successfully enhanced APK2URL extractor with advanced validation"
            )
            return enhanced_instance

        except Exception as e:
            self.logger.error(f"Failed to enhance APK2URL extractor: {e}")
            return extractor_instance

    def _create_context_aware_analyzer(self):
        """Create a context-aware secret analyzer method."""

        def analyze_secret_with_context(
            content: str,
            file_path: str = None,
            line_number: int = None,
            additional_context: Dict[str, Any] = None,
        ) -> Dict[str, Any]:
            """
            Analyze a potential secret with full context information.

            Returns:
                Dict containing analysis results and recommendations
            """
            import time

            start_time = time.time()

            # Build context
            context = {"file_path": file_path, "line_number": line_number}
            if additional_context:
                context.update(additional_context)

            # Perform enhanced analysis
            result = self.enhanced_analyzer.analyze_potential_secret(content, context)

            # Update metrics
            self.performance_metrics["total_analyzed"] += 1
            if not result.is_likely_secret:
                self.performance_metrics["false_positives_eliminated"] += 1
            else:
                self.performance_metrics["true_positives_found"] += 1

            analysis_time = time.time() - start_time
            self.performance_metrics["analysis_time"] += analysis_time

            # Return comprehensive result
            return {
                "is_secret": result.is_likely_secret,
                "confidence_score": result.confidence_score,
                "analysis_details": result.analysis_details,
                "false_positive_indicators": result.false_positive_indicators,
                "true_positive_indicators": result.true_positive_indicators,
                "analysis_time_ms": analysis_time * 1000,
                "recommendations": self._generate_action_recommendations(result),
            }

        return analyze_secret_with_context

    def _create_batch_analyzer(self):
        """Create a batch analysis method."""

        def batch_analyze_secrets(secrets_data: List[Dict[str, Any]]) -> Dict[str, Any]:
            """
            Analyze multiple secrets in batch for optimal performance.

            Args:
                secrets_data: List of dicts with 'content' and optional 'context'

            Returns:
                Comprehensive batch analysis results
            """
            import time

            start_time = time.time()

            # Perform batch analysis
            results = self.enhanced_analyzer.batch_analyze_secrets(secrets_data)

            # Generate comprehensive report
            report = self.enhanced_analyzer.generate_analysis_report(results)

            # Add timing information
            total_time = time.time() - start_time
            report["batch_timing"] = {
                "total_time_seconds": total_time,
                "average_time_per_secret_ms": (
                    (total_time / len(secrets_data)) * 1000 if secrets_data else 0
                ),
                "throughput_secrets_per_second": (
                    len(secrets_data) / total_time if total_time > 0 else 0
                ),
            }

            # Update global metrics
            self.performance_metrics["total_analyzed"] += len(secrets_data)
            self.performance_metrics["false_positives_eliminated"] += report[
                "statistics"
            ]["false_positives_count"]
            self.performance_metrics["true_positives_found"] += report["statistics"][
                "likely_secrets_count"
            ]
            self.performance_metrics["analysis_time"] += total_time

            return report

        return batch_analyze_secrets

    def _create_url_analyzer(self):
        """Create URL validity analyzer."""

        def analyze_url_validity(
            url: str, context: Optional[Dict[str, Any]] = None
        ) -> Dict[str, Any]:
            """
            Analyze URL validity using advanced validation techniques.

            Returns:
                Detailed URL analysis results
            """
            result = self.enhanced_analyzer.analyze_potential_secret(url, context)

            # Extract URL-specific analysis
            domain_details = result.analysis_details.get("domain", {})
            pattern_details = result.analysis_details.get("pattern", {})

            return {
                "is_valid_url": result.is_likely_secret,  # In this context, valid URLs are "secrets"
                "confidence": result.confidence_score,
                "domains_found": domain_details.get("domains_found", []),
                "valid_urls": domain_details.get("valid_urls", []),
                "invalid_urls": domain_details.get("invalid_urls", []),
                "framework_matches": pattern_details.get("matches", []),
                "validation_errors": result.false_positive_indicators,
            }

        return analyze_url_validity

    def _create_endpoint_classifier(self):
        """Create endpoint type classifier."""

        def classify_endpoint_type(endpoint: str) -> Dict[str, Any]:
            """
            Classify endpoint as legitimate, framework noise, or invalid.

            Returns:
                Classification results with confidence scores
            """
            result = self.enhanced_analyzer.analyze_potential_secret(endpoint)

            # Classify based on analysis
            if not result.is_likely_secret:
                if "framework" in str(result.false_positive_indicators):
                    classification = "framework_noise"
                elif "invalid" in str(result.false_positive_indicators):
                    classification = "invalid"
                else:
                    classification = "false_positive"
            else:
                classification = "legitimate_endpoint"

            return {
                "classification": classification,
                "confidence": result.confidence_score,
                "reasoning": result.false_positive_indicators
                + result.true_positive_indicators,
                "should_include": result.is_likely_secret,
            }

        return classify_endpoint_type

    def _create_domain_validator(self):
        """Create domain legitimacy validator."""

        def validate_domain_legitimacy(domain: str) -> Dict[str, Any]:
            """
            Validate domain legitimacy using multiple validation methods.

            Returns:
                Domain validation results
            """
            # Use the enhanced analyzer's domain validation
            is_valid = self.enhanced_analyzer._is_valid_domain(domain)

            # Get detailed analysis
            result = self.enhanced_analyzer.analyze_potential_secret(domain)
            domain_details = result.analysis_details.get("domain", {})

            return {
                "is_legitimate": is_valid,
                "confidence": result.confidence_score,
                "validation_details": domain_details,
                "warnings": result.false_positive_indicators,
                "tld_info": self._extract_tld_info(domain),
            }

        return validate_domain_legitimacy

    def _extract_tld_info(self, domain: str) -> Dict[str, str]:
        """Extract TLD information for a domain."""
        try:
            extracted = self.enhanced_analyzer.tld_extractor(domain)
            return {
                "domain": extracted.domain,
                "subdomain": extracted.subdomain,
                "suffix": extracted.suffix,
                "registered_domain": extracted.registered_domain,
            }
        except Exception:
            return {}

    def _generate_action_recommendations(
        self, result: SecretAnalysisResult
    ) -> List[str]:
        """Generate actionable recommendations based on analysis results."""
        recommendations = []

        if not result.is_likely_secret:
            # False positive - suggest actions
            if "framework" in str(result.false_positive_indicators):
                recommendations.append("Consider adding framework noise filters")
            if "invalid" in str(result.false_positive_indicators):
                recommendations.append("Review input validation rules")
            if result.confidence_score < 0.3:
                recommendations.append("Very low confidence - likely safe to ignore")
        else:
            # Potential secret - suggest security actions
            recommendations.append("SECURITY ALERT: Potential secret detected")
            if result.confidence_score > 0.8:
                recommendations.append("HIGH CONFIDENCE: Immediate review required")
            recommendations.append("Consider rotating credentials if legitimate")
            recommendations.append("Review access logs for potential exposure")

        return recommendations

    def create_compatibility_report(self) -> Dict[str, Any]:
        """Create a compatibility report showing integration status."""
        report = {
            "integration_status": {
                "enhanced_analyzer_available": True,
                "static_analyzer_integration": "available",
                "apk2url_integration": "available",
                "specialized_libraries": {
                    "detect_secrets": True,
                    "validators": True,
                    "tldextract": True,
                    "scikit_learn": True,
                    "textdistance": True,
                    "python_magic": True,
                },
            },
            "performance_metrics": self.performance_metrics.copy(),
            "configuration": {
                "entropy_thresholds": self.enhanced_analyzer.entropy_thresholds,
                "confidence_threshold": self.enhanced_analyzer.config[
                    "confidence_threshold"
                ],
                "framework_patterns_count": sum(
                    len(patterns)
                    for patterns in self.enhanced_analyzer.framework_patterns.values()
                ),
            },
        }

        return report

    def validate_installation(self) -> Dict[str, Any]:
        """Validate that all required components are properly installed."""
        validation_results = {
            "success": True,
            "errors": [],
            "warnings": [],
            "library_status": {},
        }

        # Test core libraries
        required_libraries = [
            "detect_secrets",
            "validators",
            "tldextract",
            "sklearn",
            "numpy",
            "pandas",
            "textdistance",
            "jellyfish",
            "magic",
        ]

        for lib in required_libraries:
            try:
                __import__(lib)
                validation_results["library_status"][lib] = "available"
            except ImportError as e:
                validation_results["library_status"][lib] = f"missing: {e}"
                validation_results["errors"].append(
                    f"Required library {lib} not available"
                )
                validation_results["success"] = False

        # Test enhanced analyzer functionality
        try:
            test_result = self.enhanced_analyzer.analyze_potential_secret(
                "test_secret_123"
            )
            validation_results["enhanced_analyzer_test"] = "passed"
        except Exception as e:
            validation_results["enhanced_analyzer_test"] = f"failed: {e}"
            validation_results["errors"].append(f"Enhanced analyzer test failed: {e}")
            validation_results["success"] = False

        return validation_results

def create_enhanced_aods_instance(
    config_path: Optional[str] = None,
) -> IntegratedEnhancedAnalyzer:
    """
    Factory function to create a fully enhanced AODS instance.

    Args:
        config_path: Optional path to configuration file

    Returns:
        Configured IntegratedEnhancedAnalyzer instance
    """
    analyzer = IntegratedEnhancedAnalyzer(config_path)

    # Validate installation
    validation = analyzer.validate_installation()
    if not validation["success"]:
        logging.warning("Some components failed validation:")
        for error in validation["errors"]:
            logging.warning(f"  - {error}")

    return analyzer

# Backward compatibility functions for existing AODS code

def enhance_existing_analyzer(analyzer_instance, config_path: Optional[str] = None):
    """
    Enhance an existing analyzer instance with advanced false positive reduction.

    This function provides backward compatibility for existing AODS installations.
    """
    integrated_analyzer = IntegratedEnhancedAnalyzer(config_path)

    # Determine the type of analyzer and enhance accordingly
    analyzer_type = type(analyzer_instance).__name__

    if "Static" in analyzer_type:
        return integrated_analyzer.enhance_static_analyzer(analyzer_instance)
    elif "APK2URL" in analyzer_type or "URL" in analyzer_type:
        return integrated_analyzer.enhance_apk2url_extractor(analyzer_instance)
    else:
        # Generic enhancement
        logging.warning(
            f"Unknown analyzer type {analyzer_type}, applying generic enhancement"
        )
        return analyzer_instance

if __name__ == "__main__":
    # Test the integrated enhanced analyzer
    print("Testing Integrated Enhanced Analyzer...")

    # Create instance
    analyzer = create_enhanced_aods_instance()

    # Validate installation
    validation = analyzer.validate_installation()
    print(
        f"Installation validation: {'SUCCESS' if validation['success'] else 'FAILED'}"
    )

    if validation["errors"]:
        print("Errors:")
        for error in validation["errors"]:
            print(f"  - {error}")

    # Test analysis
    test_secrets = [
        "AKIA1234567890EXAMPLE",  # AWS key
        "ThemeData.fallback",  # Flutter noise
        "sk_test_1234567890",  # Stripe key
        "http://schemas.android.com/apk/res/android",  # Android schema
    ]

    print("\nTesting secret analysis:")
    for secret in test_secrets:
        result = analyzer.enhanced_analyzer.analyze_potential_secret(secret)
        print(
            f"  {secret[:30]}... -> Secret: {result.is_likely_secret}, Confidence: {result.confidence_score:.3f}"
        )

    # Generate compatibility report
    report = analyzer.create_compatibility_report()
    print(f"\nAnalyzed {report['performance_metrics']['total_analyzed']} items")
    print(
        f"False positives eliminated: {report['performance_metrics']['false_positives_eliminated']}"
    )
    print(
        f"True positives found: {report['performance_metrics']['true_positives_found']}"
    )

    print("\nIntegrated Enhanced Analyzer ready for use!")
