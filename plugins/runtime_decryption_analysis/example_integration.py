#!/usr/bin/env python3
"""
AODS AI/ML-Enhanced Generator Integration Example

This example demonstrates how to integrate the AI/ML-Enhanced Frida Script Generator
into existing AODS workflows for Android security analysis.

Usage Examples:
1. Basic integration with existing AODS plugins
2. Advanced configuration for specific use cases
3. Integration with AODS reporting and analysis pipeline
4. Custom vulnerability detection workflows

Integration Points:
- AODS Plugin Architecture
- AODS Analysis Engine
- AODS Reporting System
- AODS ML Infrastructure
"""

import asyncio
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import AODS data structures
try:
    from data_structures import RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
    from ai_ml_enhanced_generator import (
        AIMLEnhancedFridaScriptGenerator,
        AIMLScriptGenerationContext,
        create_ai_ml_enhanced_generator
    )
    from frida_script_generator import FridaScriptGenerator
    INTEGRATION_AVAILABLE = True
except ImportError as e:
    print(f"Integration components not available: {e}")
    INTEGRATION_AVAILABLE = False


class AODSIntegrationExample:
    """Example integration of AI/ML enhanced generator with AODS workflows."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize integration example with configuration."""
        self.config_path = config_path or Path(__file__).parent / "ai_ml_config.yaml"
        self.enhanced_generator = None
        self.base_generator = None
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize generators
        self._initialize_generators()
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load AI/ML enhancement configuration."""
        # In real implementation, this would load from YAML file
        return {
            'ai_ml_enhancement': {
                'enabled': True,
                'fallback_to_base_generator': True,
                'ml_integration': {
                    'enabled': True,
                    'classification_threshold': 0.75
                },
                'intelligence_engine': {
                    'enabled': True,
                    'enable_cve_correlation': True
                },
                'confidence_scoring': {
                    'enabled': True,
                    'min_confidence_threshold': 0.7
                }
            },
            'hook_intelligence': {
                'ml_hook_selection': {
                    'enabled': True,
                    'confidence_threshold': 0.7,
                    'max_recommendations': 15
                }
            }
        }
    
    def _initialize_generators(self):
        """Initialize both enhanced and base generators."""
        if not INTEGRATION_AVAILABLE:
            print("⚠️  Integration components not available")
            return
        
        try:
            # Initialize AI/ML enhanced generator
            self.enhanced_generator = create_ai_ml_enhanced_generator(self.config)
            
            # Initialize base generator for comparison
            self.base_generator = FridaScriptGenerator(self.config)
            
            print("✅ Generators initialized successfully")
            
        except Exception as e:
            print(f"❌ Failed to initialize generators: {e}")
    
    async def analyze_android_app_vulnerabilities(self, 
                                                findings: List[RuntimeDecryptionFinding],
                                                app_package: str,
                                                analysis_mode: str = "comprehensive") -> Dict[str, Any]:
        """
        Comprehensive Android app vulnerability analysis using AI/ML enhancement.
        
        Args:
            findings: Runtime decryption findings from AODS analysis
            app_package: Android app package name
            analysis_mode: Analysis mode ('fast', 'comprehensive', 'precision')
            
        Returns:
            Analysis results with AI/ML insights
        """
        print(f"🔍 Analyzing {app_package} with {len(findings)} findings in {analysis_mode} mode")
        
        if not self.enhanced_generator:
            return {"error": "AI/ML generator not available"}
        
        # Configure analysis based on mode
        context = self._create_analysis_context(findings, analysis_mode)
        
        try:
            # Generate AI/ML enhanced script
            enhanced_result = await self.enhanced_generator.generate_ai_ml_enhanced_script(
                findings, context
            )
            
            # Generate base script for comparison
            base_result = self.base_generator.generate_script(findings)
            
            # Analyze improvements
            improvements = self._analyze_improvements(enhanced_result, base_result)
            
            # Create comprehensive analysis report
            analysis_report = {
                'app_package': app_package,
                'analysis_mode': analysis_mode,
                'findings_analyzed': len(findings),
                'enhanced_script': {
                    'ml_enhanced': enhanced_result.ml_enhanced,
                    'hooks_generated': len(enhanced_result.hooks_generated),
                    'ml_recommendations': len(enhanced_result.ml_hook_recommendations),
                    'cve_correlations': len(enhanced_result.cve_correlations),
                    'generation_time': enhanced_result.generation_time,
                    'script_size': len(enhanced_result.script_content)
                },
                'base_script': {
                    'hooks_generated': len(base_result.hooks_generated),
                    'generation_time': base_result.generation_time,
                    'script_size': len(base_result.script_content)
                },
                'improvements': improvements,
                'intelligence_metadata': enhanced_result.intelligence_metadata,
                'recommendations': self._generate_recommendations(enhanced_result)
            }
            
            return analysis_report
            
        except Exception as e:
            return {
                'error': f"Analysis failed: {e}",
                'app_package': app_package,
                'fallback_available': True
            }
    
    def _create_analysis_context(self, 
                               findings: List[RuntimeDecryptionFinding],
                               mode: str) -> AIMLScriptGenerationContext:
        """Create analysis context based on mode."""
        mode_configs = {
            'fast': {
                'ml_confidence_threshold': 0.6,
                'max_ml_hooks': 8,
                'enable_cve_correlation': False,
                'enable_adaptive_generation': False
            },
            'comprehensive': {
                'ml_confidence_threshold': 0.7,
                'max_ml_hooks': 15,
                'enable_cve_correlation': True,
                'enable_adaptive_generation': True,
                'vulnerability_focus': ['weak_cryptography', 'key_management']
            },
            'precision': {
                'ml_confidence_threshold': 0.85,
                'max_ml_hooks': 10,
                'enable_cve_correlation': True,
                'enable_adaptive_generation': True,
                'target_cve_years': [2023, 2024, 2025]
            }
        }
        
        config = mode_configs.get(mode, mode_configs['comprehensive'])
        
        return AIMLScriptGenerationContext(
            findings=findings,
            **config
        )
    
    def _analyze_improvements(self, enhanced_result, base_result) -> Dict[str, Any]:
        """Analyze improvements from AI/ML enhancement."""
        improvements = {
            'hook_count_improvement': len(enhanced_result.hooks_generated) - len(base_result.hooks_generated),
            'generation_time_ratio': enhanced_result.generation_time / base_result.generation_time if base_result.generation_time > 0 else 1.0,
            'script_size_ratio': len(enhanced_result.script_content) / len(base_result.script_content) if len(base_result.script_content) > 0 else 1.0,
            'ml_features_added': enhanced_result.ml_enhanced,
            'intelligence_features': {
                'cve_correlations': len(enhanced_result.cve_correlations) > 0,
                'ml_recommendations': len(enhanced_result.ml_hook_recommendations) > 0,
                'vulnerability_predictions': len(enhanced_result.vulnerability_predictions) > 0
            }
        }
        
        # Calculate estimated effectiveness improvement
        if enhanced_result.ml_hook_recommendations:
            avg_effectiveness = sum(r.effectiveness_prediction for r in enhanced_result.ml_hook_recommendations) / len(enhanced_result.ml_hook_recommendations)
            improvements['estimated_effectiveness_improvement'] = f"{(avg_effectiveness - 0.6) * 100:.1f}%"
        
        return improvements
    
    def _generate_recommendations(self, enhanced_result) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on AI/ML analysis."""
        recommendations = []
        
        # CVE-based recommendations
        if enhanced_result.cve_correlations:
            recommendations.append({
                'type': 'security_priority',
                'title': 'Critical CVE Correlations Found',
                'description': f'Found {len(enhanced_result.cve_correlations)} CVE correlations requiring immediate attention',
                'priority': 'HIGH',
                'action': 'Review CVE correlations and prioritize patching'
            })
        
        # ML confidence recommendations
        if enhanced_result.ml_hook_recommendations:
            high_conf_hooks = [r for r in enhanced_result.ml_hook_recommendations if r.confidence_score > 0.8]
            if high_conf_hooks:
                recommendations.append({
                    'type': 'testing_priority',
                    'title': 'High-Confidence Vulnerability Patterns',
                    'description': f'{len(high_conf_hooks)} high-confidence vulnerability patterns detected',
                    'priority': 'MEDIUM',
                    'action': 'Focus testing efforts on high-confidence hooks first'
                })
        
        # False positive risk recommendations
        if enhanced_result.ml_hook_recommendations:
            low_risk_hooks = [r for r in enhanced_result.ml_hook_recommendations if r.false_positive_risk < 0.15]
            if low_risk_hooks:
                recommendations.append({
                    'type': 'efficiency',
                    'title': 'Low False Positive Risk Hooks',
                    'description': f'{len(low_risk_hooks)} hooks with low false positive risk identified',
                    'priority': 'LOW',
                    'action': 'Use these hooks for automated testing pipelines'
                })
        
        return recommendations
    
    async def batch_analysis_workflow(self, 
                                    app_findings_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Batch analysis workflow for multiple Android apps.
        
        Args:
            app_findings_list: List of {'app_package': str, 'findings': List[RuntimeDecryptionFinding]}
            
        Returns:
            Batch analysis results with aggregated insights
        """
        print(f"📊 Starting batch analysis for {len(app_findings_list)} applications")
        
        batch_results = {
            'total_apps': len(app_findings_list),
            'successful_analyses': 0,
            'failed_analyses': 0,
            'app_results': [],
            'aggregated_insights': {},
            'batch_recommendations': []
        }
        
        for app_data in app_findings_list:
            app_package = app_data['app_package']
            findings = app_data['findings']
            
            print(f"  🔍 Analyzing {app_package}...")
            
            try:
                result = await self.analyze_android_app_vulnerabilities(
                    findings, app_package, 'comprehensive'
                )
                
                if 'error' not in result:
                    batch_results['successful_analyses'] += 1
                    batch_results['app_results'].append(result)
                else:
                    batch_results['failed_analyses'] += 1
                    print(f"    ❌ Analysis failed for {app_package}: {result['error']}")
                
            except Exception as e:
                batch_results['failed_analyses'] += 1
                print(f"    ❌ Exception analyzing {app_package}: {e}")
        
        # Generate aggregated insights
        batch_results['aggregated_insights'] = self._generate_batch_insights(
            batch_results['app_results']
        )
        
        # Generate batch recommendations
        batch_results['batch_recommendations'] = self._generate_batch_recommendations(
            batch_results
        )
        
        print(f"✅ Batch analysis completed: {batch_results['successful_analyses']}/{batch_results['total_apps']} successful")
        
        return batch_results
    
    def _generate_batch_insights(self, app_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate aggregated insights from batch analysis."""
        if not app_results:
            return {}
        
        # Aggregate metrics
        total_findings = sum(r['findings_analyzed'] for r in app_results)
        total_cve_correlations = sum(r['enhanced_script']['cve_correlations'] for r in app_results)
        total_ml_recommendations = sum(r['enhanced_script']['ml_recommendations'] for r in app_results)
        
        avg_generation_time = sum(r['enhanced_script']['generation_time'] for r in app_results) / len(app_results)
        
        # Most common vulnerability types
        vulnerability_types = {}
        for result in app_results:
            if 'intelligence_metadata' in result and 'vulnerability_types_covered' in result['intelligence_metadata']:
                for vuln_type in result['intelligence_metadata']['vulnerability_types_covered']:
                    vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        return {
            'total_findings_analyzed': total_findings,
            'total_cve_correlations': total_cve_correlations,
            'total_ml_recommendations': total_ml_recommendations,
            'average_generation_time': avg_generation_time,
            'apps_with_ml_enhancement': len([r for r in app_results if r['enhanced_script']['ml_enhanced']]),
            'most_common_vulnerability_types': sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    def _generate_batch_recommendations(self, batch_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for batch analysis results."""
        recommendations = []
        
        insights = batch_results['aggregated_insights']
        
        # CVE correlation recommendations
        if insights.get('total_cve_correlations', 0) > 0:
            recommendations.append({
                'type': 'portfolio_security',
                'title': 'Enterprise Security Priority',
                'description': f"Found {insights['total_cve_correlations']} total CVE correlations across portfolio",
                'priority': 'CRITICAL',
                'action': 'Implement enterprise-wide vulnerability management program'
            })
        
        # ML enhancement adoption
        enhanced_apps = insights.get('apps_with_ml_enhancement', 0)
        total_apps = batch_results['total_apps']
        
        if enhanced_apps / total_apps > 0.8:
            recommendations.append({
                'type': 'process_optimization',
                'title': 'High AI/ML Enhancement Adoption',
                'description': f"{enhanced_apps}/{total_apps} apps successfully enhanced with AI/ML",
                'priority': 'LOW',
                'action': 'Consider integrating AI/ML enhancement into CI/CD pipeline'
            })
        
        return recommendations
    
    def generate_integration_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a comprehensive integration report."""
        report = f"""
# AODS AI/ML-Enhanced Analysis Report

## Executive Summary
- **Applications Analyzed**: {analysis_results.get('total_apps', 0)}
- **Successful Analyses**: {analysis_results.get('successful_analyses', 0)}
- **AI/ML Enhancement Rate**: {analysis_results.get('aggregated_insights', {}).get('apps_with_ml_enhancement', 0)}/{analysis_results.get('total_apps', 0)}

## Key Findings
- **Total Findings Analyzed**: {analysis_results.get('aggregated_insights', {}).get('total_findings_analyzed', 0)}
- **CVE Correlations Found**: {analysis_results.get('aggregated_insights', {}).get('total_cve_correlations', 0)}
- **ML Recommendations Generated**: {analysis_results.get('aggregated_insights', {}).get('total_ml_recommendations', 0)}

## Performance Metrics
- **Average Generation Time**: {analysis_results.get('aggregated_insights', {}).get('average_generation_time', 0):.2f}s
- **Enhancement Success Rate**: {(analysis_results.get('successful_analyses', 0) / analysis_results.get('total_apps', 1) * 100):.1f}%

## Recommendations
"""
        
        recommendations = analysis_results.get('batch_recommendations', [])
        for i, rec in enumerate(recommendations, 1):
            report += f"\n{i}. **{rec['title']}** ({rec['priority']} Priority)\n"
            report += f"   - {rec['description']}\n"
            report += f"   - Action: {rec['action']}\n"
        
        report += f"""

## Technical Implementation
- **AI/ML Infrastructure**: AODS ML Integration Manager
- **Intelligence Engine**: Advanced CVE Correlation
- **Confidence Scoring**: ML-Enhanced with Uncertainty Quantification
- **Pattern Database**: 1000+ Advanced Vulnerability Patterns

Generated by AODS AI/ML-Enhanced Frida Script Generator v2.0
"""
        
        return report


async def main():
    """Example integration workflow."""
    print("🚀 AODS AI/ML-Enhanced Generator Integration Example")
    print("=" * 60)
    
    if not INTEGRATION_AVAILABLE:
        print("⚠️  Integration components not available")
        print("📝 This is a demonstration of the integration structure")
        return
    
    # Initialize integration
    integration = AODSIntegrationExample()
    
    # Example findings (in real use, these would come from AODS analysis)
    sample_findings = [
        RuntimeDecryptionFinding(
            finding_type="weak_cipher",
            description="DES algorithm usage in payment processing",
            location="com.example.payment.CryptoManager",
            severity=VulnerabilitySeverity.CRITICAL,
            pattern_type=DecryptionType.WEAK_ALGORITHM
        ),
        RuntimeDecryptionFinding(
            finding_type="hardcoded_key",
            description="Hardcoded API key in authentication module",
            location="com.example.auth.KeyManager",
            severity=VulnerabilitySeverity.HIGH,
            pattern_type=DecryptionType.KEY_DERIVATION
        )
    ]
    
    # Single app analysis
    print("\n📱 Single App Analysis Example")
    print("-" * 40)
    
    result = await integration.analyze_android_app_vulnerabilities(
        sample_findings,
        "com.example.testapp",
        "comprehensive"
    )
    
    print(f"✅ Analysis completed for com.example.testapp")
    print(f"   🎯 ML Enhanced: {result.get('enhanced_script', {}).get('ml_enhanced', False)}")
    print(f"   📊 Hooks Generated: {result.get('enhanced_script', {}).get('hooks_generated', 0)}")
    print(f"   🔗 CVE Correlations: {result.get('enhanced_script', {}).get('cve_correlations', 0)}")
    
    # Batch analysis example
    print("\n📊 Batch Analysis Example")
    print("-" * 40)
    
    batch_data = [
        {'app_package': 'com.example.app1', 'findings': sample_findings[:1]},
        {'app_package': 'com.example.app2', 'findings': sample_findings},
        {'app_package': 'com.example.app3', 'findings': sample_findings[1:]}
    ]
    
    batch_results = await integration.batch_analysis_workflow(batch_data)
    
    # Generate and display report
    report = integration.generate_integration_report(batch_results)
    print("\n📄 Integration Report Generated")
    print("=" * 60)
    print(report)


if __name__ == "__main__":
    asyncio.run(main()) 
"""
AODS AI/ML-Enhanced Generator Integration Example

This example demonstrates how to integrate the AI/ML-Enhanced Frida Script Generator
into existing AODS workflows for Android security analysis.

Usage Examples:
1. Basic integration with existing AODS plugins
2. Advanced configuration for specific use cases
3. Integration with AODS reporting and analysis pipeline
4. Custom vulnerability detection workflows

Integration Points:
- AODS Plugin Architecture
- AODS Analysis Engine
- AODS Reporting System
- AODS ML Infrastructure
"""

import asyncio
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import AODS data structures
try:
    from data_structures import RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
    from ai_ml_enhanced_generator import (
        AIMLEnhancedFridaScriptGenerator,
        AIMLScriptGenerationContext,
        create_ai_ml_enhanced_generator
    )
    from frida_script_generator import FridaScriptGenerator
    INTEGRATION_AVAILABLE = True
except ImportError as e:
    print(f"Integration components not available: {e}")
    INTEGRATION_AVAILABLE = False


class AODSIntegrationExample:
    """Example integration of AI/ML enhanced generator with AODS workflows."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize integration example with configuration."""
        self.config_path = config_path or Path(__file__).parent / "ai_ml_config.yaml"
        self.enhanced_generator = None
        self.base_generator = None
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize generators
        self._initialize_generators()
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load AI/ML enhancement configuration."""
        # In real implementation, this would load from YAML file
        return {
            'ai_ml_enhancement': {
                'enabled': True,
                'fallback_to_base_generator': True,
                'ml_integration': {
                    'enabled': True,
                    'classification_threshold': 0.75
                },
                'intelligence_engine': {
                    'enabled': True,
                    'enable_cve_correlation': True
                },
                'confidence_scoring': {
                    'enabled': True,
                    'min_confidence_threshold': 0.7
                }
            },
            'hook_intelligence': {
                'ml_hook_selection': {
                    'enabled': True,
                    'confidence_threshold': 0.7,
                    'max_recommendations': 15
                }
            }
        }
    
    def _initialize_generators(self):
        """Initialize both enhanced and base generators."""
        if not INTEGRATION_AVAILABLE:
            print("⚠️  Integration components not available")
            return
        
        try:
            # Initialize AI/ML enhanced generator
            self.enhanced_generator = create_ai_ml_enhanced_generator(self.config)
            
            # Initialize base generator for comparison
            self.base_generator = FridaScriptGenerator(self.config)
            
            print("✅ Generators initialized successfully")
            
        except Exception as e:
            print(f"❌ Failed to initialize generators: {e}")
    
    async def analyze_android_app_vulnerabilities(self, 
                                                findings: List[RuntimeDecryptionFinding],
                                                app_package: str,
                                                analysis_mode: str = "comprehensive") -> Dict[str, Any]:
        """
        Comprehensive Android app vulnerability analysis using AI/ML enhancement.
        
        Args:
            findings: Runtime decryption findings from AODS analysis
            app_package: Android app package name
            analysis_mode: Analysis mode ('fast', 'comprehensive', 'precision')
            
        Returns:
            Analysis results with AI/ML insights
        """
        print(f"🔍 Analyzing {app_package} with {len(findings)} findings in {analysis_mode} mode")
        
        if not self.enhanced_generator:
            return {"error": "AI/ML generator not available"}
        
        # Configure analysis based on mode
        context = self._create_analysis_context(findings, analysis_mode)
        
        try:
            # Generate AI/ML enhanced script
            enhanced_result = await self.enhanced_generator.generate_ai_ml_enhanced_script(
                findings, context
            )
            
            # Generate base script for comparison
            base_result = self.base_generator.generate_script(findings)
            
            # Analyze improvements
            improvements = self._analyze_improvements(enhanced_result, base_result)
            
            # Create comprehensive analysis report
            analysis_report = {
                'app_package': app_package,
                'analysis_mode': analysis_mode,
                'findings_analyzed': len(findings),
                'enhanced_script': {
                    'ml_enhanced': enhanced_result.ml_enhanced,
                    'hooks_generated': len(enhanced_result.hooks_generated),
                    'ml_recommendations': len(enhanced_result.ml_hook_recommendations),
                    'cve_correlations': len(enhanced_result.cve_correlations),
                    'generation_time': enhanced_result.generation_time,
                    'script_size': len(enhanced_result.script_content)
                },
                'base_script': {
                    'hooks_generated': len(base_result.hooks_generated),
                    'generation_time': base_result.generation_time,
                    'script_size': len(base_result.script_content)
                },
                'improvements': improvements,
                'intelligence_metadata': enhanced_result.intelligence_metadata,
                'recommendations': self._generate_recommendations(enhanced_result)
            }
            
            return analysis_report
            
        except Exception as e:
            return {
                'error': f"Analysis failed: {e}",
                'app_package': app_package,
                'fallback_available': True
            }
    
    def _create_analysis_context(self, 
                               findings: List[RuntimeDecryptionFinding],
                               mode: str) -> AIMLScriptGenerationContext:
        """Create analysis context based on mode."""
        mode_configs = {
            'fast': {
                'ml_confidence_threshold': 0.6,
                'max_ml_hooks': 8,
                'enable_cve_correlation': False,
                'enable_adaptive_generation': False
            },
            'comprehensive': {
                'ml_confidence_threshold': 0.7,
                'max_ml_hooks': 15,
                'enable_cve_correlation': True,
                'enable_adaptive_generation': True,
                'vulnerability_focus': ['weak_cryptography', 'key_management']
            },
            'precision': {
                'ml_confidence_threshold': 0.85,
                'max_ml_hooks': 10,
                'enable_cve_correlation': True,
                'enable_adaptive_generation': True,
                'target_cve_years': [2023, 2024, 2025]
            }
        }
        
        config = mode_configs.get(mode, mode_configs['comprehensive'])
        
        return AIMLScriptGenerationContext(
            findings=findings,
            **config
        )
    
    def _analyze_improvements(self, enhanced_result, base_result) -> Dict[str, Any]:
        """Analyze improvements from AI/ML enhancement."""
        improvements = {
            'hook_count_improvement': len(enhanced_result.hooks_generated) - len(base_result.hooks_generated),
            'generation_time_ratio': enhanced_result.generation_time / base_result.generation_time if base_result.generation_time > 0 else 1.0,
            'script_size_ratio': len(enhanced_result.script_content) / len(base_result.script_content) if len(base_result.script_content) > 0 else 1.0,
            'ml_features_added': enhanced_result.ml_enhanced,
            'intelligence_features': {
                'cve_correlations': len(enhanced_result.cve_correlations) > 0,
                'ml_recommendations': len(enhanced_result.ml_hook_recommendations) > 0,
                'vulnerability_predictions': len(enhanced_result.vulnerability_predictions) > 0
            }
        }
        
        # Calculate estimated effectiveness improvement
        if enhanced_result.ml_hook_recommendations:
            avg_effectiveness = sum(r.effectiveness_prediction for r in enhanced_result.ml_hook_recommendations) / len(enhanced_result.ml_hook_recommendations)
            improvements['estimated_effectiveness_improvement'] = f"{(avg_effectiveness - 0.6) * 100:.1f}%"
        
        return improvements
    
    def _generate_recommendations(self, enhanced_result) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on AI/ML analysis."""
        recommendations = []
        
        # CVE-based recommendations
        if enhanced_result.cve_correlations:
            recommendations.append({
                'type': 'security_priority',
                'title': 'Critical CVE Correlations Found',
                'description': f'Found {len(enhanced_result.cve_correlations)} CVE correlations requiring immediate attention',
                'priority': 'HIGH',
                'action': 'Review CVE correlations and prioritize patching'
            })
        
        # ML confidence recommendations
        if enhanced_result.ml_hook_recommendations:
            high_conf_hooks = [r for r in enhanced_result.ml_hook_recommendations if r.confidence_score > 0.8]
            if high_conf_hooks:
                recommendations.append({
                    'type': 'testing_priority',
                    'title': 'High-Confidence Vulnerability Patterns',
                    'description': f'{len(high_conf_hooks)} high-confidence vulnerability patterns detected',
                    'priority': 'MEDIUM',
                    'action': 'Focus testing efforts on high-confidence hooks first'
                })
        
        # False positive risk recommendations
        if enhanced_result.ml_hook_recommendations:
            low_risk_hooks = [r for r in enhanced_result.ml_hook_recommendations if r.false_positive_risk < 0.15]
            if low_risk_hooks:
                recommendations.append({
                    'type': 'efficiency',
                    'title': 'Low False Positive Risk Hooks',
                    'description': f'{len(low_risk_hooks)} hooks with low false positive risk identified',
                    'priority': 'LOW',
                    'action': 'Use these hooks for automated testing pipelines'
                })
        
        return recommendations
    
    async def batch_analysis_workflow(self, 
                                    app_findings_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Batch analysis workflow for multiple Android apps.
        
        Args:
            app_findings_list: List of {'app_package': str, 'findings': List[RuntimeDecryptionFinding]}
            
        Returns:
            Batch analysis results with aggregated insights
        """
        print(f"📊 Starting batch analysis for {len(app_findings_list)} applications")
        
        batch_results = {
            'total_apps': len(app_findings_list),
            'successful_analyses': 0,
            'failed_analyses': 0,
            'app_results': [],
            'aggregated_insights': {},
            'batch_recommendations': []
        }
        
        for app_data in app_findings_list:
            app_package = app_data['app_package']
            findings = app_data['findings']
            
            print(f"  🔍 Analyzing {app_package}...")
            
            try:
                result = await self.analyze_android_app_vulnerabilities(
                    findings, app_package, 'comprehensive'
                )
                
                if 'error' not in result:
                    batch_results['successful_analyses'] += 1
                    batch_results['app_results'].append(result)
                else:
                    batch_results['failed_analyses'] += 1
                    print(f"    ❌ Analysis failed for {app_package}: {result['error']}")
                
            except Exception as e:
                batch_results['failed_analyses'] += 1
                print(f"    ❌ Exception analyzing {app_package}: {e}")
        
        # Generate aggregated insights
        batch_results['aggregated_insights'] = self._generate_batch_insights(
            batch_results['app_results']
        )
        
        # Generate batch recommendations
        batch_results['batch_recommendations'] = self._generate_batch_recommendations(
            batch_results
        )
        
        print(f"✅ Batch analysis completed: {batch_results['successful_analyses']}/{batch_results['total_apps']} successful")
        
        return batch_results
    
    def _generate_batch_insights(self, app_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate aggregated insights from batch analysis."""
        if not app_results:
            return {}
        
        # Aggregate metrics
        total_findings = sum(r['findings_analyzed'] for r in app_results)
        total_cve_correlations = sum(r['enhanced_script']['cve_correlations'] for r in app_results)
        total_ml_recommendations = sum(r['enhanced_script']['ml_recommendations'] for r in app_results)
        
        avg_generation_time = sum(r['enhanced_script']['generation_time'] for r in app_results) / len(app_results)
        
        # Most common vulnerability types
        vulnerability_types = {}
        for result in app_results:
            if 'intelligence_metadata' in result and 'vulnerability_types_covered' in result['intelligence_metadata']:
                for vuln_type in result['intelligence_metadata']['vulnerability_types_covered']:
                    vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        return {
            'total_findings_analyzed': total_findings,
            'total_cve_correlations': total_cve_correlations,
            'total_ml_recommendations': total_ml_recommendations,
            'average_generation_time': avg_generation_time,
            'apps_with_ml_enhancement': len([r for r in app_results if r['enhanced_script']['ml_enhanced']]),
            'most_common_vulnerability_types': sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    def _generate_batch_recommendations(self, batch_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for batch analysis results."""
        recommendations = []
        
        insights = batch_results['aggregated_insights']
        
        # CVE correlation recommendations
        if insights.get('total_cve_correlations', 0) > 0:
            recommendations.append({
                'type': 'portfolio_security',
                'title': 'Enterprise Security Priority',
                'description': f"Found {insights['total_cve_correlations']} total CVE correlations across portfolio",
                'priority': 'CRITICAL',
                'action': 'Implement enterprise-wide vulnerability management program'
            })
        
        # ML enhancement adoption
        enhanced_apps = insights.get('apps_with_ml_enhancement', 0)
        total_apps = batch_results['total_apps']
        
        if enhanced_apps / total_apps > 0.8:
            recommendations.append({
                'type': 'process_optimization',
                'title': 'High AI/ML Enhancement Adoption',
                'description': f"{enhanced_apps}/{total_apps} apps successfully enhanced with AI/ML",
                'priority': 'LOW',
                'action': 'Consider integrating AI/ML enhancement into CI/CD pipeline'
            })
        
        return recommendations
    
    def generate_integration_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a comprehensive integration report."""
        report = f"""
# AODS AI/ML-Enhanced Analysis Report

## Executive Summary
- **Applications Analyzed**: {analysis_results.get('total_apps', 0)}
- **Successful Analyses**: {analysis_results.get('successful_analyses', 0)}
- **AI/ML Enhancement Rate**: {analysis_results.get('aggregated_insights', {}).get('apps_with_ml_enhancement', 0)}/{analysis_results.get('total_apps', 0)}

## Key Findings
- **Total Findings Analyzed**: {analysis_results.get('aggregated_insights', {}).get('total_findings_analyzed', 0)}
- **CVE Correlations Found**: {analysis_results.get('aggregated_insights', {}).get('total_cve_correlations', 0)}
- **ML Recommendations Generated**: {analysis_results.get('aggregated_insights', {}).get('total_ml_recommendations', 0)}

## Performance Metrics
- **Average Generation Time**: {analysis_results.get('aggregated_insights', {}).get('average_generation_time', 0):.2f}s
- **Enhancement Success Rate**: {(analysis_results.get('successful_analyses', 0) / analysis_results.get('total_apps', 1) * 100):.1f}%

## Recommendations
"""
        
        recommendations = analysis_results.get('batch_recommendations', [])
        for i, rec in enumerate(recommendations, 1):
            report += f"\n{i}. **{rec['title']}** ({rec['priority']} Priority)\n"
            report += f"   - {rec['description']}\n"
            report += f"   - Action: {rec['action']}\n"
        
        report += f"""

## Technical Implementation
- **AI/ML Infrastructure**: AODS ML Integration Manager
- **Intelligence Engine**: Advanced CVE Correlation
- **Confidence Scoring**: ML-Enhanced with Uncertainty Quantification
- **Pattern Database**: 1000+ Advanced Vulnerability Patterns

Generated by AODS AI/ML-Enhanced Frida Script Generator v2.0
"""
        
        return report


async def main():
    """Example integration workflow."""
    print("🚀 AODS AI/ML-Enhanced Generator Integration Example")
    print("=" * 60)
    
    if not INTEGRATION_AVAILABLE:
        print("⚠️  Integration components not available")
        print("📝 This is a demonstration of the integration structure")
        return
    
    # Initialize integration
    integration = AODSIntegrationExample()
    
    # Example findings (in real use, these would come from AODS analysis)
    sample_findings = [
        RuntimeDecryptionFinding(
            finding_type="weak_cipher",
            description="DES algorithm usage in payment processing",
            location="com.example.payment.CryptoManager",
            severity=VulnerabilitySeverity.CRITICAL,
            pattern_type=DecryptionType.WEAK_ALGORITHM
        ),
        RuntimeDecryptionFinding(
            finding_type="hardcoded_key",
            description="Hardcoded API key in authentication module",
            location="com.example.auth.KeyManager",
            severity=VulnerabilitySeverity.HIGH,
            pattern_type=DecryptionType.KEY_DERIVATION
        )
    ]
    
    # Single app analysis
    print("\n📱 Single App Analysis Example")
    print("-" * 40)
    
    result = await integration.analyze_android_app_vulnerabilities(
        sample_findings,
        "com.example.testapp",
        "comprehensive"
    )
    
    print(f"✅ Analysis completed for com.example.testapp")
    print(f"   🎯 ML Enhanced: {result.get('enhanced_script', {}).get('ml_enhanced', False)}")
    print(f"   📊 Hooks Generated: {result.get('enhanced_script', {}).get('hooks_generated', 0)}")
    print(f"   🔗 CVE Correlations: {result.get('enhanced_script', {}).get('cve_correlations', 0)}")
    
    # Batch analysis example
    print("\n📊 Batch Analysis Example")
    print("-" * 40)
    
    batch_data = [
        {'app_package': 'com.example.app1', 'findings': sample_findings[:1]},
        {'app_package': 'com.example.app2', 'findings': sample_findings},
        {'app_package': 'com.example.app3', 'findings': sample_findings[1:]}
    ]
    
    batch_results = await integration.batch_analysis_workflow(batch_data)
    
    # Generate and display report
    report = integration.generate_integration_report(batch_results)
    print("\n📄 Integration Report Generated")
    print("=" * 60)
    print(report)


if __name__ == "__main__":
    asyncio.run(main()) 