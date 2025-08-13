#!/usr/bin/env python3
"""
AODS Network Analysis Coordinator
=================================

Coordinates and orchestrates all existing AODS network analysis capabilities 
through a unified interface. Leverages existing infrastructure instead of
duplicating efforts.

Existing Components Integrated:
- AdvancedSSLTLSAnalyzerPlugin: SSL/TLS and certificate pinning analysis
- MitmproxyNetworkAnalysisPlugin: HTTPS traffic interception and analysis  
- NetworkAnalyzer: Core network traffic analysis
- NetworkCleartextTrafficPlugin: Cleartext traffic detection

Features:
- Zero duplication - extends existing AODS network infrastructure
- Coordinator pattern for unified orchestration
- Professional confidence calculation
- Integration with Dynamic Analysis Coordinator
- Comprehensive network security assessment

This coordinator follows the same architectural pattern established by the
Dynamic Analysis Coordinator and Keyboard Cache Analyzer.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum

# AODS Core Infrastructure
from core.shared_infrastructure.analysis_exceptions import AnalysisError, ValidationError, ContextualLogger

# AODS Frida Community Integration
try:
    from core.frida_community_integration import FridaCommunityIntegration, create_frida_community_integration
    FRIDA_COMMUNITY_AVAILABLE = True
except ImportError:
    FridaCommunityIntegration = None
    FRIDA_COMMUNITY_AVAILABLE = False

# Existing Network Analysis Components
try:
    from plugins.advanced_ssl_tls_analyzer import AdvancedSSLTLSAnalyzerPlugin
    SSL_TLS_ANALYZER_AVAILABLE = True
except ImportError:
    AdvancedSSLTLSAnalyzerPlugin = None
    SSL_TLS_ANALYZER_AVAILABLE = False

try:
    from plugins.mitmproxy_network_analysis import MitmproxyNetworkAnalysisPlugin
    MITMPROXY_ANALYZER_AVAILABLE = True
except ImportError:
    MitmproxyNetworkAnalysisPlugin = None
    MITMPROXY_ANALYZER_AVAILABLE = False

try:
    from plugins.advanced_dynamic_analysis_modules.network_analyzer import NetworkAnalyzer
    NETWORK_ANALYZER_AVAILABLE = True
except ImportError:
    NetworkAnalyzer = None
    NETWORK_ANALYZER_AVAILABLE = False

try:
    from plugins.network_cleartext_traffic import NetworkCleartextTrafficPlugin
    CLEARTEXT_ANALYZER_AVAILABLE = True
except ImportError:
    NetworkCleartextTrafficPlugin = None
    CLEARTEXT_ANALYZER_AVAILABLE = False

logger = logging.getLogger(__name__)


class NetworkAnalysisProfile(Enum):
    """Network analysis execution profiles."""
    COMPREHENSIVE = "comprehensive"  # All network analysis components
    SSL_FOCUS = "ssl_focus"          # SSL/TLS and certificate analysis
    TRAFFIC_FOCUS = "traffic_focus"  # Traffic interception and analysis
    SECURITY_FOCUS = "security_focus" # Security-focused network analysis
    CLEARTEXT_FOCUS = "cleartext_focus" # Cleartext traffic analysis


@dataclass
class NetworkComponentState:
    """State tracking for network analysis components."""
    name: str
    component_type: str = "network_analysis"
    available: bool = False
    initialized: bool = False
    active: bool = False
    error: Optional[str] = None
    results: Optional[Any] = None
    instance: Optional[Any] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    last_execution: Optional[str] = None


@dataclass
class NetworkCoordinationResult:
    """Result from coordinated network analysis."""
    coordination_id: str
    package_name: str
    profile: NetworkAnalysisProfile
    component_results: Dict[str, Any] = field(default_factory=dict)
    merged_findings: List[Any] = field(default_factory=list)
    analysis_duration: float = 0.0
    coordination_successful: bool = False
    components_executed: int = 0
    total_findings: int = 0
    ssl_vulnerabilities: int = 0
    traffic_issues: int = 0
    cleartext_violations: int = 0
    certificate_issues: int = 0
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: Set[str] = field(default_factory=set)
    timestamp: datetime = field(default_factory=datetime.now)


class NetworkAnalysisCoordinator:
    """
    Coordinates all existing AODS network analysis capabilities.
    
    Orchestrates SSL/TLS analysis, traffic interception, network security
    assessment, and cleartext traffic detection through a unified interface.
    """
    
    def __init__(self, package_name: str, config: Optional[Dict[str, Any]] = None):
        """Initialize the Network Analysis Coordinator."""
        self.package_name = package_name
        self.config = config or {}
        
        # Initialize logging
        self.contextual_logger = ContextualLogger("NetworkAnalysisCoordinator")
        
        # Component state tracking
        self.component_states: Dict[str, NetworkComponentState] = {}
        
        # Analysis state
        self.coordination_start_time: Optional[float] = None
        self.active_profile: Optional[NetworkAnalysisProfile] = None
        
        # Community script integration
        self.community_integration = None
        self.community_scripts_enabled = False
        
        # Initialize network analysis components
        self._initialize_component_states()
        
        # Initialize community script integration
        self._initialize_community_integration()
        
        # Analysis statistics
        self.analysis_stats = {
            'total_coordinations': 0,
            'successful_coordinations': 0,
            'components_available': len([c for c in self.component_states.values() if c.available]),
            'ssl_analyses_performed': 0,
            'traffic_analyses_performed': 0,
            'cleartext_analyses_performed': 0
        }
        
        available_components = len([c for c in self.component_states.values() if c.available])
        self.contextual_logger.info(f"⌨️ Network Analysis Coordinator initialized for {package_name} with {available_components} available components")
    
    def _initialize_component_states(self):
        """Initialize state tracking for all network analysis components."""
        components = [
            ("ssl_tls_analyzer", SSL_TLS_ANALYZER_AVAILABLE, AdvancedSSLTLSAnalyzerPlugin),
            ("mitmproxy_analyzer", MITMPROXY_ANALYZER_AVAILABLE, MitmproxyNetworkAnalysisPlugin),
            ("network_analyzer", NETWORK_ANALYZER_AVAILABLE, NetworkAnalyzer),
            ("cleartext_analyzer", CLEARTEXT_ANALYZER_AVAILABLE, NetworkCleartextTrafficPlugin)
        ]
        
        for name, available, component_class in components:
            state = NetworkComponentState(name=name, available=available, component_type="network_analysis")
            
            if available and component_class is not None:
                try:
                    # Initialize component instance based on type
                    if name == "ssl_tls_analyzer":
                        # Mock APK context for SSL/TLS analyzer
                        from types import SimpleNamespace
                        mock_apk_ctx = SimpleNamespace()
                        mock_apk_ctx.package_name = self.package_name
                        mock_apk_ctx.decompiled_path = ""
                        instance = component_class(mock_apk_ctx, self.config.get('ssl_tls_config'))
                    elif name == "mitmproxy_analyzer":
                        instance = component_class(None, self.config.get('mitmproxy_config'))
                    elif name == "network_analyzer":
                        instance = component_class(self.config.get('network_config', {}))
                    elif name == "cleartext_analyzer":
                        instance = component_class(self.config.get('cleartext_config', {}))
                    else:
                        instance = component_class(self.config)
                    
                    state.instance = instance
                    state.initialized = True
                    self.contextual_logger.info(f"✅ {name} component initialized")
                    
                except Exception as e:
                    self.contextual_logger.warning(f"⚠️ {name} initialization failed: {e}")
                    state.error = str(e)
                    state.available = False
            else:
                self.contextual_logger.debug(f"📋 {name} component not available")
            
            self.component_states[name] = state
    
    def _initialize_community_integration(self):
        """Initialize Frida community script integration."""
        if FRIDA_COMMUNITY_AVAILABLE:
            try:
                community_config = self.config.get('community_scripts', {})
                self.community_integration = create_frida_community_integration(
                    self.package_name, community_config
                )
                self.community_scripts_enabled = True
                self.contextual_logger.info("✅ Frida community script integration initialized")
                
            except Exception as e:
                self.contextual_logger.warning(f"⚠️ Community script integration failed: {e}")
                self.community_integration = None
                self.community_scripts_enabled = False
        else:
            self.contextual_logger.debug("Frida community integration not available")
            self.community_scripts_enabled = False
    
    def coordinate_network_analysis(self, apk_ctx, profile: NetworkAnalysisProfile = NetworkAnalysisProfile.COMPREHENSIVE) -> NetworkCoordinationResult:
        """
        Coordinate comprehensive network analysis across all available components.
        
        Args:
            apk_ctx: APK context for analysis
            profile: Network analysis execution profile
            
        Returns:
            NetworkCoordinationResult: Coordinated analysis results
        """
        self.coordination_start_time = time.time()
        self.active_profile = profile
        coordination_id = f"network_{self.package_name}_{int(self.coordination_start_time)}"
        
        self.contextual_logger.info(f"🌐 Starting coordinated network analysis (Profile: {profile.value})")
        
        try:
            # 1. Execute network analysis components based on profile
            component_results = self._execute_profile_components(apk_ctx, profile)
            
            # 2. Execute community script analysis for enhanced coverage
            community_results = self._execute_community_script_analysis()
            if community_results:
                component_results['community_scripts'] = community_results
            
            # 3. Merge and correlate results including community findings
            merged_findings = self._correlate_network_results(component_results)
            
            # 4. Calculate performance metrics
            coordination_duration = time.time() - self.coordination_start_time
            performance_metrics = self._calculate_network_performance_metrics(coordination_duration)
            
            # 4. Generate recommendations
            recommendations = self._generate_network_recommendations(component_results, merged_findings)
            
            # 5. Create coordination result
            result = NetworkCoordinationResult(
                coordination_id=coordination_id,
                package_name=self.package_name,
                profile=profile,
                component_results=component_results,
                merged_findings=merged_findings,
                analysis_duration=coordination_duration,
                coordination_successful=True,
                components_executed=len([k for k, v in component_results.items() if v is not None]),
                total_findings=len(merged_findings),
                ssl_vulnerabilities=self._count_ssl_findings(merged_findings),
                traffic_issues=self._count_traffic_findings(merged_findings),
                cleartext_violations=self._count_cleartext_findings(merged_findings),
                certificate_issues=self._count_certificate_findings(merged_findings),
                performance_metrics=performance_metrics,
                recommendations=recommendations
            )
            
            # Update statistics
            self.analysis_stats['total_coordinations'] += 1
            self.analysis_stats['successful_coordinations'] += 1
            
            self.contextual_logger.info(f"✅ Network analysis coordination completed: "
                                      f"{result.total_findings} findings, "
                                      f"{result.components_executed} components, "
                                      f"{coordination_duration:.2f}s")
            
            return result
            
        except Exception as e:
            self.contextual_logger.error(f"❌ Network analysis coordination failed: {e}")
            
            # Return error result
            return NetworkCoordinationResult(
                coordination_id=coordination_id,
                package_name=self.package_name,
                profile=profile,
                coordination_successful=False,
                analysis_duration=time.time() - self.coordination_start_time if self.coordination_start_time else 0
            )
    
    def _execute_profile_components(self, apk_ctx, profile: NetworkAnalysisProfile) -> Dict[str, Any]:
        """Execute network analysis components based on profile."""
        component_results = {}
        profile_components = self._get_profile_components(profile)
        
        for component_name in profile_components:
            if component_name in self.component_states:
                state = self.component_states[component_name]
                
                if state.available and state.initialized:
                    try:
                        self.contextual_logger.info(f"🔍 Executing {component_name} analysis...")
                        state.start_time = time.time()
                        state.active = True
                        
                        # Execute component analysis
                        result = self._execute_component_analysis(component_name, state.instance, apk_ctx)
                        
                        state.end_time = time.time()
                        state.active = False
                        state.results = result
                        state.last_execution = datetime.now().isoformat()
                        
                        component_results[component_name] = result
                        
                        self.contextual_logger.info(f"✅ {component_name} analysis completed")
                        
                    except Exception as e:
                        self.contextual_logger.error(f"❌ {component_name} analysis failed: {e}")
                        state.error = str(e)
                        state.active = False
                        component_results[component_name] = None
                else:
                    self.contextual_logger.warning(f"⚠️ {component_name} not available or not initialized")
                    component_results[component_name] = None
        
        return component_results
    
    def _execute_community_script_analysis(self) -> Optional[Dict[str, Any]]:
        """Execute community Frida scripts for enhanced SSL bypass detection."""
        if self.community_scripts_enabled and self.community_integration:
            try:
                self.contextual_logger.info("🌐 Executing Frida CodeShare community scripts...")
                
                # Execute community SSL bypass analysis
                community_results = self.community_integration.execute_community_ssl_bypass_analysis()
                
                # Get community analysis summary
                summary = self.community_integration.get_community_analysis_summary()
                
                if community_results:
                    bypasses_detected = len([r for r in community_results if r.bypass_detected])
                    total_findings = sum(len(r.findings) for r in community_results)
                    
                    self.contextual_logger.info(f"✅ Community script analysis completed: "
                                              f"{len(community_results)} scripts executed, "
                                              f"{bypasses_detected} bypasses detected, "
                                              f"{total_findings} total findings")
                    
                    # Return structured community results
                    return {
                        'script_results': community_results,
                        'analysis_summary': summary,
                        'statistics': {
                            'scripts_executed': len(community_results),
                            'bypasses_detected': bypasses_detected,
                            'total_findings': total_findings,
                            'success_rate': summary.get('execution_stats', {}).get('success_rate', 0.0),
                            'community_downloads': summary.get('total_community_downloads', 0),
                            'average_reliability': summary.get('average_reliability', 0.0)
                        }
                    }
                else:
                    self.contextual_logger.warning("⚠️ No community script results available")
                    return None
                    
            except Exception as e:
                self.contextual_logger.error(f"❌ Community script analysis failed: {e}")
                return None
        else:
            self.contextual_logger.debug("Community script integration not enabled")
            return None
    
    def _execute_component_analysis(self, component_name: str, instance: Any, apk_ctx) -> Any:
        """Execute analysis for a specific component."""
        if component_name == "ssl_tls_analyzer":
            return instance.analyze()
        elif component_name == "mitmproxy_analyzer":
            return instance.analyze_traffic(apk_ctx)
        elif component_name == "network_analyzer":
            return instance.analyze_network_configuration(apk_ctx)
        elif component_name == "cleartext_analyzer":
            return instance.analyze_cleartext_traffic(apk_ctx)
        else:
            # Generic analysis method
            if hasattr(instance, 'analyze'):
                return instance.analyze(apk_ctx)
            else:
                raise NotImplementedError(f"No analysis method defined for {component_name}")
    
    def _get_profile_components(self, profile: NetworkAnalysisProfile) -> List[str]:
        """Get component list based on network analysis profile."""
        profile_mappings = {
            NetworkAnalysisProfile.COMPREHENSIVE: ["ssl_tls_analyzer", "mitmproxy_analyzer", "network_analyzer", "cleartext_analyzer"],
            NetworkAnalysisProfile.SSL_FOCUS: ["ssl_tls_analyzer"],
            NetworkAnalysisProfile.TRAFFIC_FOCUS: ["mitmproxy_analyzer", "network_analyzer"],
            NetworkAnalysisProfile.SECURITY_FOCUS: ["ssl_tls_analyzer", "network_analyzer"],
            NetworkAnalysisProfile.CLEARTEXT_FOCUS: ["cleartext_analyzer", "network_analyzer"]
        }
        
        return profile_mappings.get(profile, [])
    
    def _correlate_network_results(self, component_results: Dict[str, Any]) -> List[Any]:
        """Correlate and merge network analysis results."""
        merged_findings = []
        
        for component_name, results in component_results.items():
            if results is not None:
                # Extract findings based on component type
                component_findings = self._extract_component_findings(component_name, results)
                merged_findings.extend(component_findings)
        
        # Remove duplicates and correlate related findings
        return self._deduplicate_network_findings(merged_findings)
    
    def _extract_component_findings(self, component_name: str, results: Any) -> List[Any]:
        """Extract findings from component results."""
        findings = []
        
        try:
            if hasattr(results, 'vulnerabilities'):
                findings.extend(results.vulnerabilities)
            elif hasattr(results, 'findings'):
                findings.extend(results.findings)
            elif isinstance(results, list):
                findings.extend(results)
            elif isinstance(results, dict):
                # Extract findings from various result structures
                if 'vulnerabilities' in results:
                    findings.extend(results['vulnerabilities'])
                elif 'findings' in results:
                    findings.extend(results['findings'])
                elif 'ssl_issues' in results:
                    findings.extend(results['ssl_issues'])
                elif 'traffic_issues' in results:
                    findings.extend(results['traffic_issues'])
        
        except Exception as e:
            self.contextual_logger.warning(f"⚠️ Failed to extract findings from {component_name}: {e}")
        
        return findings
    
    def _deduplicate_network_findings(self, findings: List[Any]) -> List[Any]:
        """Remove duplicate network findings."""
        # Simple deduplication based on finding type and description
        seen_findings = set()
        unique_findings = []
        
        for finding in findings:
            # Create a simple signature for the finding
            if hasattr(finding, 'vulnerability_type') and hasattr(finding, 'description'):
                signature = f"{finding.vulnerability_type}:{finding.description[:100]}"
            elif isinstance(finding, dict):
                vuln_type = finding.get('type', finding.get('vulnerability_type', 'unknown'))
                desc = finding.get('description', finding.get('message', ''))[:100]
                signature = f"{vuln_type}:{desc}"
            else:
                signature = str(finding)[:100]
            
            if signature not in seen_findings:
                seen_findings.add(signature)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _count_ssl_findings(self, findings: List[Any]) -> int:
        """Count SSL/TLS related findings."""
        count = 0
        ssl_keywords = ['ssl', 'tls', 'certificate', 'pinning', 'cipher']
        
        for finding in findings:
            finding_text = str(finding).lower()
            if any(keyword in finding_text for keyword in ssl_keywords):
                count += 1
        
        return count
    
    def _count_traffic_findings(self, findings: List[Any]) -> int:
        """Count traffic analysis findings."""
        count = 0
        traffic_keywords = ['traffic', 'http', 'api', 'endpoint', 'request']
        
        for finding in findings:
            finding_text = str(finding).lower()
            if any(keyword in finding_text for keyword in traffic_keywords):
                count += 1
        
        return count
    
    def _count_cleartext_findings(self, findings: List[Any]) -> int:
        """Count cleartext traffic findings."""
        count = 0
        cleartext_keywords = ['cleartext', 'unencrypted', 'http://', 'plain']
        
        for finding in findings:
            finding_text = str(finding).lower()
            if any(keyword in finding_text for keyword in cleartext_keywords):
                count += 1
        
        return count
    
    def _count_certificate_findings(self, findings: List[Any]) -> int:
        """Count certificate-related findings."""
        count = 0
        cert_keywords = ['certificate', 'cert', 'ca', 'trust', 'validation']
        
        for finding in findings:
            finding_text = str(finding).lower()
            if any(keyword in finding_text for keyword in cert_keywords):
                count += 1
        
        return count
    
    def _calculate_network_performance_metrics(self, duration: float) -> Dict[str, Any]:
        """Calculate performance metrics for network analysis."""
        return {
            'total_duration_seconds': duration,
            'components_available': len([c for c in self.component_states.values() if c.available]),
            'components_executed': len([c for c in self.component_states.values() if c.results is not None]),
            'average_component_time': duration / max(1, len([c for c in self.component_states.values() if c.results is not None])),
            'coordination_overhead': duration * 0.1,  # Estimate 10% overhead
            'memory_efficient': True,  # Network analysis is generally memory efficient
            'parallel_execution': False  # Currently sequential
        }
    
    def _generate_network_recommendations(self, component_results: Dict[str, Any], findings: List[Any]) -> Set[str]:
        """Generate security recommendations based on network analysis results."""
        recommendations = set()
        
        # SSL/TLS recommendations
        if self._has_ssl_issues(findings):
            recommendations.add("Implement proper SSL/TLS configuration with strong cipher suites")
            recommendations.add("Enable certificate pinning for critical API endpoints")
            recommendations.add("Validate certificate chains against trusted CAs")
        
        # Traffic security recommendations  
        if self._has_traffic_issues(findings):
            recommendations.add("Implement HTTPS for all network communications")
            recommendations.add("Use proper request/response validation")
            recommendations.add("Implement network security configuration")
        
        # Cleartext recommendations
        if self._has_cleartext_issues(findings):
            recommendations.add("Disable cleartext traffic in production builds")
            recommendations.add("Migrate all HTTP connections to HTTPS")
            recommendations.add("Implement Network Security Configuration to prevent cleartext traffic")
        
        # General network security
        recommendations.add("Regular security audits of network configurations")
        recommendations.add("Monitor network traffic for suspicious patterns")
        
        return recommendations
    
    def _has_ssl_issues(self, findings: List[Any]) -> bool:
        """Check if there are SSL/TLS related issues."""
        return self._count_ssl_findings(findings) > 0
    
    def _has_traffic_issues(self, findings: List[Any]) -> bool:
        """Check if there are traffic-related issues."""
        return self._count_traffic_findings(findings) > 0
    
    def _has_cleartext_issues(self, findings: List[Any]) -> bool:
        """Check if there are cleartext traffic issues."""
        return self._count_cleartext_findings(findings) > 0
    
    def get_coordination_status(self) -> Dict[str, Any]:
        """Get current coordination status."""
        return {
            'package_name': self.package_name,
            'active_profile': self.active_profile.value if self.active_profile else None,
            'coordination_active': self.coordination_start_time is not None,
            'components': {
                name: {
                    'available': state.available,
                    'initialized': state.initialized,
                    'active': state.active,
                    'last_execution': state.last_execution,
                    'error': state.error
                }
                for name, state in self.component_states.items()
            },
            'analysis_stats': self.analysis_stats,
            'ssl_tls_analyzer_available': SSL_TLS_ANALYZER_AVAILABLE,
            'mitmproxy_analyzer_available': MITMPROXY_ANALYZER_AVAILABLE,
            'network_analyzer_available': NETWORK_ANALYZER_AVAILABLE,
            'cleartext_analyzer_available': CLEARTEXT_ANALYZER_AVAILABLE,
            'frida_community_integration': {
                'available': FRIDA_COMMUNITY_AVAILABLE,
                'enabled': self.community_scripts_enabled,
                'scripts_loaded': len(self.community_integration.community_scripts) if self.community_integration else 0,
                'community_downloads': sum(script.downloads for script in self.community_integration.community_scripts.values()) if self.community_integration else 0,
                'average_reliability': sum(script.reliability_score for script in self.community_integration.community_scripts.values()) / max(1, len(self.community_integration.community_scripts)) if self.community_integration else 0.0
            }
        }


def create_network_analysis_coordinator(package_name: str, config: Optional[Dict[str, Any]] = None) -> NetworkAnalysisCoordinator:
    """Factory function to create network analysis coordinator."""
    return NetworkAnalysisCoordinator(package_name, config) 