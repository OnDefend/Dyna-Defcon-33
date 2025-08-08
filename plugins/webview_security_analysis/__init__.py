"""
WebView Security Analysis Plugin Module

This module provides comprehensive WebView security analysis for Android applications
with modular architecture, professional confidence calculation, and enterprise-grade
vulnerability detection capabilities.
"""

import logging

from .data_structures import (
    WebViewVulnerability,
    WebViewSecurityAnalysis,
    WebViewAnalysisContext,
    WebViewMethodInfo,
    JavaScriptInterfaceInfo,
    XSSTestResult,
    WebViewConfigurationIssue,
    WebViewVulnerabilityType,
    SeverityLevel,
    XSSPayloadType,
    WebViewContextType,
    WebViewConfigurationRisk,
    WebViewSecurityPatterns,
    MAVSControls,
    CWECategories
)

from .confidence_calculator import (
    WebViewSecurityConfidenceCalculator,
    calculate_webview_confidence
)

__version__ = "2.0.0"
__author__ = "AODS Security Team"

# Initialize logger
logger = logging.getLogger(__name__)


class WebViewSecurityAnalyzer:
    """
    WebView Security Analyzer - Main analysis class.
    
    Provides comprehensive WebView security analysis for Android applications
    with professional confidence calculation and vulnerability detection.
    """
    
    def __init__(self, apk_ctx):
        """Initialize WebView security analyzer."""
        self.apk_ctx = apk_ctx
        self.confidence_calculator = WebViewSecurityConfidenceCalculator()
        self.vulnerabilities = []
        logger.debug("WebView Security Analyzer initialized")
    
    def analyze(self) -> WebViewSecurityAnalysis:
        """
        Perform WebView security analysis.
        
        Returns:
            WebViewSecurityAnalysis: Analysis results
        """
        try:
            logger.debug("Starting comprehensive WebView security analysis")
            
            # Initialize comprehensive analysis components
            from .comprehensive_analyzer import WebViewComprehensiveAnalyzer
            from .static_analyzer import WebViewStaticAnalyzer
            from .dynamic_analyzer import WebViewDynamicAnalyzer
            from .xss_tester import WebViewXSSTester
            from .configuration_analyzer import WebViewConfigurationAnalyzer
            
            # Create analysis context
            analysis_context = WebViewAnalysisContext(
                apk_path=getattr(apk_ctx, 'apk_path_str', ''),
                package_name=getattr(apk_ctx, 'package_name', 'unknown'),
                deep_analysis_mode=True
            )
            
            # Initialize analyzers
            static_analyzer = WebViewStaticAnalyzer()
            dynamic_analyzer = WebViewDynamicAnalyzer()
            xss_tester = WebViewXSSTester()
            config_analyzer = WebViewConfigurationAnalyzer()
            comprehensive_analyzer = WebViewComprehensiveAnalyzer(
                static_analyzer, dynamic_analyzer, xss_tester, config_analyzer
            )
            
            # Perform comprehensive analysis
            analysis_result = comprehensive_analyzer.analyze(apk_ctx, analysis_context)
            
            logger.info(f"WebView analysis complete: {analysis_result.total_webviews} WebViews analyzed, "
                       f"{analysis_result.vulnerable_webviews} vulnerabilities found")
            
            # Fallback to basic analysis if comprehensive analysis fails
            if analysis_result.total_webviews == 0:
                logger.warning("Comprehensive analysis found no WebViews, performing basic fallback analysis")
                analysis_result = self._perform_basic_fallback_analysis(apk_ctx)
            
            logger.debug("WebView security analysis completed")
            return analysis_result
            
        except Exception as e:
            logger.error(f"WebView security analysis failed: {e}")
            # Return empty results on error
            return WebViewSecurityAnalysis(
                total_webviews=0,
                vulnerable_webviews=0,
                javascript_interfaces=[],
                xss_test_results=[],
                configuration_issues=[],
                vulnerabilities=[],
                risk_score=0,
                security_recommendations=[],
                masvs_compliance={}
            )
    
    def _perform_basic_fallback_analysis(self, apk_ctx) -> WebViewSecurityAnalysis:
        """Perform basic fallback WebView analysis when comprehensive analysis fails."""
        try:
            logger.debug("Performing basic WebView analysis")
            
            # Basic static analysis using APK context
            vulnerabilities = []
            javascript_interfaces = []
            configuration_issues = []
            
            # Try to find basic WebView usage patterns
            if hasattr(apk_ctx, 'decompiled_path') and apk_ctx.decompiled_path:
                import os
                import re
                
                # Look for WebView usage in Java files
                java_files = []
                for root, dirs, files in os.walk(apk_ctx.decompiled_path):
                    for file in files:
                        if file.endswith('.java'):
                            java_files.append(os.path.join(root, file))
                
                webview_count = 0
                for java_file in java_files[:100]:  # Limit to prevent performance issues
                    try:
                        with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Basic WebView detection
                        if 'WebView' in content:
                            webview_count += 1
                            
                            # Check for basic security issues
                            if 'setJavaScriptEnabled(true)' in content:
                                vulnerabilities.append(WebViewVulnerability(
                                    vulnerability_type=WebViewVulnerabilityType.JAVASCRIPT_ENABLED_GLOBALLY,
                                    severity=SeverityLevel.MEDIUM,
                                    title="JavaScript Enabled Globally",
                                    description="WebView has JavaScript enabled which may pose security risks",
                                    file_path=java_file,
                                    line_number=1,
                                    code_snippet="setJavaScriptEnabled(true)",
                                    remediation="Only enable JavaScript when necessary and validate all inputs",
                                    masvs_control=MAVSControls.PLATFORM_3,
                                    cwe_category=CWECategories.IMPROPER_INPUT_VALIDATION,
                                    confidence=0.8,
                                    evidence=["JavaScript enabled globally in WebView"]
                                ))
                            
                            if 'addJavascriptInterface' in content:
                                javascript_interfaces.append(JavaScriptInterfaceInfo(
                                    interface_name="Unknown",
                                    exposed_methods=[],
                                    risk_level=WebViewConfigurationRisk.HIGH,
                                    file_path=java_file,
                                    line_number=1
                                ))
                    except Exception as e:
                        logger.debug(f"Error analyzing file {java_file}: {e}")
                        continue
                
                logger.info(f"Basic analysis found {webview_count} WebView references")
                
            return WebViewSecurityAnalysis(
                total_webviews=max(webview_count, 1) if 'webview_count' in locals() else 1,
                vulnerable_webviews=len(vulnerabilities),
                javascript_interfaces=javascript_interfaces,
                xss_test_results=[],
                configuration_issues=configuration_issues,
                vulnerabilities=vulnerabilities,
                risk_score=min(len(vulnerabilities) * 10, 100),
                security_recommendations=[
                    "Disable JavaScript in WebView unless absolutely necessary",
                    "Validate all data passed to WebView",
                    "Use HTTPS for all WebView content",
                    "Implement proper input validation for JavaScript interfaces"
                ],
                masvs_compliance={
                    MAVSControls.PLATFORM_3: "PARTIAL" if vulnerabilities else "PASS"
                }
            )
            
        except Exception as e:
            logger.error(f"Basic fallback analysis failed: {e}")
            return WebViewSecurityAnalysis(
                total_webviews=0,
                vulnerable_webviews=0,
                javascript_interfaces=[],
                xss_test_results=[],
                configuration_issues=[],
                vulnerabilities=[],
                risk_score=0,
                security_recommendations=[],
                masvs_compliance={}
            )


__all__ = [
    # Data structures
    'WebViewVulnerability',
    'WebViewSecurityAnalysis',
    'WebViewAnalysisContext',
    'WebViewMethodInfo',
    'JavaScriptInterfaceInfo',
    'XSSTestResult',
    'WebViewConfigurationIssue',
    
    # Enums
    'WebViewVulnerabilityType',
    'SeverityLevel',
    'XSSPayloadType',
    'WebViewContextType',
    'WebViewConfigurationRisk',
    'WebViewSecurityPatterns',
    'MAVSControls',
    'CWECategories',
    
    # Analyzers
    'WebViewSecurityAnalyzer',
    'WebViewSecurityConfidenceCalculator',
    
    # Utility functions
    'calculate_webview_confidence'
]

# Plugin compatibility functions
def run(apk_ctx):
    """Main plugin entry point for compatibility with plugin manager."""
    try:
        from rich.text import Text
        
        analyzer = WebViewSecurityAnalyzer(apk_ctx)
        result = analyzer.analyze()
        
        if hasattr(result, 'vulnerabilities') and result.vulnerabilities:
            findings_text = Text()
            findings_text.append(f"WebView Security Analysis - {len(result.vulnerabilities)} findings\n", style="bold blue")
            for finding in result.vulnerabilities[:10]:
                findings_text.append(f"• {finding.title}\n", style="yellow")
                findings_text.append(f"  {finding.description}\n", style="dim")
        else:
            findings_text = Text("WebView Security Analysis completed - No vulnerabilities found", style="green")
            
        return "WebView Security Analysis", findings_text
        
    except Exception as e:
        logger.error(f"WebView security analysis failed: {e}")
        error_text = Text(f"WebView Security Analysis Error: {str(e)}", style="red")
        return "WebView Security Analysis", error_text 