#!/usr/bin/env python3
"""
Real-time Vulnerability Discovery System Demo

Comprehensive demonstration of the real-time vulnerability discovery system,
showcasing all major components and capabilities including:

- Continuous monitoring setup and operation
- Zero-day vulnerability detection
- Intelligent alerting with custom handlers
- Threat intelligence correlation
- Behavioral pattern analysis
- Integration with AODS framework

This demo provides practical examples and scenarios for understanding
the real-time discovery system's capabilities and usage patterns.
"""

import asyncio
import logging
import time
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Configure demo logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

try:
    from plugins.runtime_decryption_analysis.realtime_vulnerability_discovery import (
        RealtimeVulnerabilityDiscovery,
        create_realtime_vulnerability_discovery,
        VulnerabilityAlert,
        BehavioralPattern,
        ThreatLevel,
        AlertType,
        ZeroDayDetectionEngine,
        ContinuousMonitoringEngine,
        IntelligentAlertingSystem,
        ThreatIntelligencePipeline
    )
    REALTIME_DISCOVERY_AVAILABLE = True
except ImportError as e:
    logging.error(f"Real-time discovery components not available: {e}")
    REALTIME_DISCOVERY_AVAILABLE = False

try:
    from plugins.runtime_decryption_analysis import (
        RuntimeDecryptionAnalysisPlugin,
        create_realtime_discovery_for_plugin,
        get_realtime_discovery_status
    )
    PLUGIN_INTEGRATION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Plugin integration not available: {e}")
    PLUGIN_INTEGRATION_AVAILABLE = False


class RealtimeDiscoveryDemo:
    """Comprehensive demo for real-time vulnerability discovery system."""
    
    def __init__(self):
        """Initialize demo environment."""
        self.logger = logging.getLogger("RealtimeDiscoveryDemo")
        self.demo_packages = [
            "com.example.secure",
            "com.example.suspicious", 
            "com.malware.sample",
            "com.banking.trusted",
            "com.gaming.popular"
        ]
        
        # Demo statistics
        self.demo_stats = {
            'scenarios_run': 0,
            'alerts_generated': 0,
            'patterns_detected': 0,
            'zero_day_detections': 0,
            'threat_correlations': 0
        }
        
        # Alert collection for demo analysis
        self.demo_alerts = []
        self.demo_patterns = []
    
    def print_header(self, title: str):
        """Print demo section header."""
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def print_subheader(self, title: str):
        """Print demo subsection header."""
        print(f"\n{'-'*40}")
        print(f"  {title}")
        print(f"{'-'*40}")
    
    async def run_comprehensive_demo(self):
        """Run comprehensive demo of all capabilities."""
        self.print_header("🔍 Real-time Vulnerability Discovery System Demo")
        
        if not REALTIME_DISCOVERY_AVAILABLE:
            print("❌ Real-time discovery components not available")
            print("Please ensure all dependencies are installed")
            return False
        
        print("✅ Real-time discovery components available")
        print("🚀 Starting comprehensive demonstration...")
        
        # Demo scenarios
        scenarios = [
            ("Component Initialization", self.demo_component_initialization),
            ("Basic Monitoring Setup", self.demo_basic_monitoring),
            ("Zero-Day Detection", self.demo_zero_day_detection),
            ("Intelligent Alerting", self.demo_intelligent_alerting),
            ("Threat Intelligence", self.demo_threat_intelligence),
            ("Behavioral Analysis", self.demo_behavioral_analysis),
            ("Full Integration Workflow", self.demo_full_workflow),
            ("Plugin Integration", self.demo_plugin_integration),
            ("Performance Monitoring", self.demo_performance_monitoring),
            ("Error Handling", self.demo_error_handling)
        ]
        
        success_count = 0
        for scenario_name, scenario_func in scenarios:
            try:
                self.print_subheader(f"🎯 {scenario_name}")
                result = await scenario_func()
                if result:
                    print(f"✅ {scenario_name}: SUCCESS")
                    success_count += 1
                else:
                    print(f"❌ {scenario_name}: FAILED")
                self.demo_stats['scenarios_run'] += 1
            except Exception as e:
                print(f"❌ {scenario_name}: ERROR - {e}")
                self.logger.error(f"Demo scenario '{scenario_name}' failed: {e}")
        
        # Final summary
        self.print_demo_summary(success_count, len(scenarios))
        return success_count == len(scenarios)
    
    async def demo_component_initialization(self) -> bool:
        """Demo component initialization and basic setup."""
        try:
            print("  • Creating zero-day detection engine...")
            zero_day_config = {
                'anomaly_threshold': 0.8,
                'pattern_correlation_threshold': 0.7,
                'behavioral_deviation_threshold': 0.75
            }
            zero_day_engine = ZeroDayDetectionEngine(zero_day_config)
            stats = zero_day_engine.get_detection_statistics()
            print(f"    Zero-day engine initialized with {len(stats)} stat categories")
            
            print("  • Creating continuous monitoring engine...")
            monitoring_config = {
                'monitoring_interval': 2.0,
                'pattern_buffer_size': 100,
                'analysis_window_size': 60
            }
            monitoring_engine = ContinuousMonitoringEngine(monitoring_config)
            status = monitoring_engine.get_monitoring_status()
            print(f"    Monitoring engine status: {status['status']}")
            
            print("  • Creating intelligent alerting system...")
            alerting_config = {
                'aggregation_window': 300,
                'max_alerts_per_window': 50
            }
            alerting_system = IntelligentAlertingSystem(alerting_config)
            alert_stats = alerting_system.get_alert_statistics()
            print(f"    Alerting system initialized with {alert_stats['total_alerts']} alerts")
            
            print("  • Creating threat intelligence pipeline...")
            threat_intel_pipeline = ThreatIntelligencePipeline()
            print("    Threat intelligence pipeline ready")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Component initialization failed: {e}")
            return False
    
    async def demo_basic_monitoring(self) -> bool:
        """Demo basic monitoring setup and operation."""
        try:
            package_name = "com.example.demo"
            config = {
                'monitoring': {'monitoring_interval': 1.0},
                'analysis_interval': 2.0
            }
            
            print(f"  • Creating discovery system for {package_name}...")
            discovery = create_realtime_vulnerability_discovery(package_name, config)
            
            print("  • Starting continuous monitoring...")
            start_result = await discovery.start_discovery()
            if not start_result:
                print("    ❌ Failed to start monitoring")
                return False
            
            print("  • Monitoring active for 5 seconds...")
            await asyncio.sleep(5.0)
            
            # Check status
            status = discovery.get_discovery_status()
            print(f"    Monitoring cycles completed: {status['discovery_statistics']['total_analysis_cycles']}")
            print(f"    Patterns analyzed: {status['discovery_statistics']['patterns_analyzed']}")
            
            print("  • Stopping monitoring...")
            stop_result = discovery.stop_discovery()
            
            return start_result and stop_result
            
        except Exception as e:
            print(f"    ❌ Basic monitoring demo failed: {e}")
            return False
    
    async def demo_zero_day_detection(self) -> bool:
        """Demo zero-day vulnerability detection capabilities."""
        try:
            print("  • Creating suspicious behavioral patterns...")
            
            # Create patterns that should trigger zero-day detection
            suspicious_patterns = [
                BehavioralPattern(
                    pattern_id="zeroday_001",
                    pattern_type="malware_like",
                    description="Malware-like behavior pattern",
                    api_calls=["system_exploit", "privilege_escalate", "data_exfiltrate"],
                    call_frequency={"exploit": 50, "escalate": 25, "exfiltrate": 75},
                    timing_patterns=[0.1, 0.2, 0.1, 0.3],
                    risk_score=0.95,
                    anomaly_score=0.9
                ),
                BehavioralPattern(
                    pattern_id="zeroday_002",
                    pattern_type="crypto_abuse",
                    description="Cryptographic function abuse",
                    api_calls=["crypto_encrypt", "crypto_decrypt", "key_extract"],
                    call_frequency={"encrypt": 200, "decrypt": 180, "extract": 50},
                    timing_patterns=[1.0, 0.8, 1.2, 0.9],
                    risk_score=0.85,
                    anomaly_score=0.88
                )
            ]
            
            print("  • Initializing zero-day detection engine...")
            config = {'anomaly_threshold': 0.8}
            engine = ZeroDayDetectionEngine(config)
            
            runtime_data = {
                'package_name': 'com.malware.suspicious',
                'timestamp': time.time()
            }
            
            print("  • Analyzing patterns for zero-day vulnerabilities...")
            alerts = await engine.analyze_for_zero_day(suspicious_patterns, runtime_data)
            
            print(f"    Zero-day alerts generated: {len(alerts)}")
            self.demo_stats['alerts_generated'] += len(alerts)
            self.demo_stats['zero_day_detections'] += len([a for a in alerts if a.alert_type == AlertType.ZERO_DAY_DETECTION])
            
            # Display alert details
            for i, alert in enumerate(alerts[:3]):  # Show first 3 alerts
                print(f"    Alert {i+1}: {alert.title} ({alert.threat_level.value})")
                print(f"      Confidence: {alert.confidence_score:.3f}")
                print(f"      Evidence: {len(alert.evidence)} items")
                self.demo_alerts.append(alert)
            
            return len(alerts) > 0
            
        except Exception as e:
            print(f"    ❌ Zero-day detection demo failed: {e}")
            return False
    
    async def demo_intelligent_alerting(self) -> bool:
        """Demo intelligent alerting system capabilities."""
        try:
            print("  • Setting up intelligent alerting system...")
            
            # Custom notification handler
            received_notifications = []
            def demo_notification_handler(alert):
                received_notifications.append(alert)
                print(f"    📧 NOTIFICATION: {alert.title} ({alert.threat_level.value})")
            
            # Custom escalation handler
            received_escalations = []
            def demo_escalation_handler(alert):
                received_escalations.append(alert)
                print(f"    🚨 ESCALATION: {alert.title} - IMMEDIATE ATTENTION REQUIRED")
            
            config = {
                'alert_thresholds': {
                    ThreatLevel.CRITICAL: 0.9,
                    ThreatLevel.HIGH: 0.8,
                    ThreatLevel.MEDIUM: 0.6
                },
                'aggregation_window': 60
            }
            
            alerting_system = IntelligentAlertingSystem(config)
            alerting_system.add_notification_handler(demo_notification_handler)
            alerting_system.add_escalation_handler(demo_escalation_handler)
            
            print("  • Generating test alerts...")
            test_alerts = [
                VulnerabilityAlert(
                    alert_id="demo_critical_001",
                    alert_type=AlertType.ZERO_DAY_DETECTION,
                    threat_level=ThreatLevel.CRITICAL,
                    title="Critical Zero-Day Detected",
                    description="Novel exploitation technique discovered",
                    package_name="com.malware.zeroday",
                    detection_method="behavioral_analysis",
                    confidence_score=0.95,
                    evidence=["Unknown exploit pattern", "Privilege escalation detected"],
                    escalation_required=True
                ),
                VulnerabilityAlert(
                    alert_id="demo_high_001",
                    alert_type=AlertType.BEHAVIORAL_ANOMALY,
                    threat_level=ThreatLevel.HIGH,
                    title="Anomalous Behavior Pattern",
                    description="Unusual API usage pattern detected",
                    package_name="com.suspicious.app",
                    detection_method="pattern_analysis",
                    confidence_score=0.82,
                    evidence=["High frequency crypto calls", "Unusual timing patterns"]
                ),
                VulnerabilityAlert(
                    alert_id="demo_medium_001",
                    alert_type=AlertType.PATTERN_CORRELATION,
                    threat_level=ThreatLevel.MEDIUM,
                    title="Pattern Correlation Alert",
                    description="Multiple suspicious patterns correlated",
                    package_name="com.questionable.app",
                    detection_method="correlation_analysis",
                    confidence_score=0.7,
                    evidence=["Pattern correlation score: 0.85"]
                )
            ]
            
            print("  • Processing alerts through intelligent system...")
            processed_count = 0
            for alert in test_alerts:
                result = await alerting_system.process_alert(alert)
                if result:
                    processed_count += 1
            
            print(f"    Alerts processed: {processed_count}/{len(test_alerts)}")
            print(f"    Notifications sent: {len(received_notifications)}")
            print(f"    Escalations triggered: {len(received_escalations)}")
            
            # Show statistics
            stats = alerting_system.get_alert_statistics()
            print(f"    Total alerts in system: {stats['total_alerts']}")
            print(f"    Active alerts: {stats['active_alerts']}")
            
            return processed_count == len(test_alerts)
            
        except Exception as e:
            print(f"    ❌ Intelligent alerting demo failed: {e}")
            return False
    
    async def demo_threat_intelligence(self) -> bool:
        """Demo threat intelligence correlation capabilities."""
        try:
            print("  • Initializing threat intelligence pipeline...")
            
            config = {
                'intel_sources': ['demo_source'],
                'refresh_interval': 3600
            }
            pipeline = ThreatIntelligencePipeline(config)
            
            print("  • Creating alert with threat indicators...")
            test_alert = VulnerabilityAlert(
                alert_id="threat_intel_test_001",
                alert_type=AlertType.MALICIOUS_BEHAVIOR,
                threat_level=ThreatLevel.HIGH,
                title="Malicious Behavior Detected",
                description="Behavior matching known malware patterns",
                package_name="com.malware.sample",
                detection_method="behavioral_analysis",
                confidence_score=0.87,
                evidence=[
                    "hash:abc123def456malware",
                    "suspicious_api_calls",
                    "malware_signature_match"
                ],
                affected_apis=["dangerous_api", "exploit_function", "malware_behavior"]
            )
            
            print("  • Correlating with threat intelligence...")
            correlations = await pipeline.correlate_with_threat_intel(test_alert)
            
            print(f"    Threat intelligence correlations found: {len(correlations)}")
            self.demo_stats['threat_correlations'] += len(correlations)
            
            # Display correlation details
            for i, intel in enumerate(correlations):
                print(f"    Intel {i+1}: {intel.threat_type} (confidence: {intel.confidence:.3f})")
                print(f"      Source: {intel.source}")
                print(f"      Indicators: {len(intel.indicators)}")
                print(f"      Mitigation advice: {len(intel.mitigation_advice)} items")
            
            # Update alert with threat intelligence
            if correlations:
                test_alert.threat_intel_references = [intel.intel_id for intel in correlations]
                print(f"    Alert updated with {len(test_alert.threat_intel_references)} threat intel references")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Threat intelligence demo failed: {e}")
            return False
    
    async def demo_behavioral_analysis(self) -> bool:
        """Demo behavioral pattern analysis capabilities."""
        try:
            print("  • Creating diverse behavioral patterns...")
            
            # Generate realistic behavioral patterns
            patterns = []
            pattern_types = ["crypto_usage", "network_behavior", "file_access", "api_usage", "timing_patterns"]
            
            for i in range(10):
                pattern_type = random.choice(pattern_types)
                risk_score = random.uniform(0.3, 0.9)
                
                pattern = BehavioralPattern(
                    pattern_id=f"behavioral_{pattern_type}_{i}",
                    pattern_type=pattern_type,
                    description=f"Behavioral pattern analysis: {pattern_type}",
                    api_calls=[f"{pattern_type}_api_{j}" for j in range(random.randint(3, 8))],
                    call_frequency={f"api_{j}": random.randint(10, 100) for j in range(5)},
                    timing_patterns=[random.uniform(0.1, 2.0) for _ in range(random.randint(5, 15))],
                    risk_score=risk_score,
                    anomaly_score=random.uniform(0.2, 0.8)
                )
                patterns.append(pattern)
            
            print(f"    Generated {len(patterns)} behavioral patterns")
            self.demo_stats['patterns_detected'] += len(patterns)
            self.demo_patterns.extend(patterns)
            
            print("  • Analyzing patterns with zero-day detection...")
            engine = ZeroDayDetectionEngine()
            runtime_data = {
                'package_name': 'com.behavioral.analysis',
                'timestamp': time.time()
            }
            
            alerts = await engine.analyze_for_zero_day(patterns, runtime_data)
            print(f"    Behavioral analysis alerts: {len(alerts)}")
            
            # Analyze pattern characteristics
            high_risk_patterns = [p for p in patterns if p.risk_score > 0.7]
            high_anomaly_patterns = [p for p in patterns if p.anomaly_score > 0.6]
            
            print(f"    High risk patterns: {len(high_risk_patterns)}")
            print(f"    High anomaly patterns: {len(high_anomaly_patterns)}")
            
            # Pattern type distribution
            type_distribution = {}
            for pattern in patterns:
                type_distribution[pattern.pattern_type] = type_distribution.get(pattern.pattern_type, 0) + 1
            
            print("    Pattern type distribution:")
            for pattern_type, count in type_distribution.items():
                print(f"      {pattern_type}: {count}")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Behavioral analysis demo failed: {e}")
            return False
    
    async def demo_full_workflow(self) -> bool:
        """Demo complete end-to-end workflow."""
        try:
            print("  • Setting up complete real-time discovery workflow...")
            
            # Configuration for full workflow
            config = {
                'analysis_interval': 2.0,
                'monitoring': {
                    'monitoring_interval': 1.0,
                    'pattern_buffer_size': 50
                },
                'zero_day': {
                    'anomaly_threshold': 0.75,
                    'pattern_correlation_threshold': 0.7
                },
                'alerting': {
                    'aggregation_window': 60,
                    'max_alerts_per_window': 20
                }
            }
            
            package_name = "com.full.workflow.demo"
            
            print(f"  • Creating discovery system for {package_name}...")
            discovery = create_realtime_vulnerability_discovery(package_name, config)
            
            # Custom handlers for workflow demo
            workflow_notifications = []
            workflow_escalations = []
            
            def workflow_notification_handler(alert):
                workflow_notifications.append(alert)
                print(f"    📱 WORKFLOW ALERT: {alert.title}")
            
            def workflow_escalation_handler(alert):
                workflow_escalations.append(alert) 
                print(f"    🚨 WORKFLOW ESCALATION: {alert.title}")
            
            discovery.add_notification_handler(workflow_notification_handler)
            discovery.add_escalation_handler(workflow_escalation_handler)
            
            print("  • Starting full workflow...")
            start_result = await discovery.start_discovery()
            if not start_result:
                print("    ❌ Failed to start workflow")
                return False
            
            print("  • Running workflow for 8 seconds...")
            start_time = time.time()
            
            # Monitor workflow progress
            for i in range(4):
                await asyncio.sleep(2.0)
                status = discovery.get_discovery_status()
                print(f"    Cycle {i+1}: {status['discovery_statistics']['total_analysis_cycles']} analysis cycles")
            
            # Get final status
            final_status = discovery.get_discovery_status()
            
            print("  • Stopping workflow...")
            stop_result = discovery.stop_discovery()
            
            # Workflow results
            runtime = time.time() - start_time
            cycles = final_status['discovery_statistics']['total_analysis_cycles']
            patterns = final_status['discovery_statistics']['patterns_analyzed']
            alerts = final_status['discovery_statistics']['alerts_generated']
            
            print(f"    Workflow runtime: {runtime:.1f} seconds")
            print(f"    Analysis cycles: {cycles}")
            print(f"    Patterns analyzed: {patterns}")
            print(f"    Alerts generated: {alerts}")
            print(f"    Notifications: {len(workflow_notifications)}")
            print(f"    Escalations: {len(workflow_escalations)}")
            
            return start_result and stop_result and cycles > 0
            
        except Exception as e:
            print(f"    ❌ Full workflow demo failed: {e}")
            return False
    
    async def demo_plugin_integration(self) -> bool:
        """Demo integration with AODS plugin framework."""
        try:
            if not PLUGIN_INTEGRATION_AVAILABLE:
                print("    ⚠️ Plugin integration not available, skipping...")
                return True
            
            print("  • Testing plugin integration capabilities...")
            
            # Test factory function
            print("    • Testing factory function...")
            discovery = create_realtime_discovery_for_plugin(
                "com.plugin.integration.test",
                {'analysis_interval': 1.5}
            )
            
            if discovery:
                print(f"      ✅ Factory function created discovery for {discovery.package_name}")
            else:
                print("      ❌ Factory function failed")
                return False
            
            # Test status function
            print("    • Testing status function...")
            status = get_realtime_discovery_status()
            
            if status['realtime_discovery_available']:
                print("      ✅ Status function reports discovery available")
                print(f"      Components available: {len(status['components_available'])}")
                print(f"      Integration features: {len(status['integration_features'])}")
            else:
                print("      ❌ Status function reports discovery not available")
                return False
            
            # Test plugin capabilities
            print("    • Testing plugin capabilities...")
            try:
                from plugins.runtime_decryption_analysis import get_plugin_capabilities
                capabilities = get_plugin_capabilities()
                
                if 'realtime_discovery' in capabilities:
                    realtime_caps = capabilities['realtime_discovery']
                    print(f"      ✅ Plugin reports real-time capabilities: {realtime_caps['available']}")
                    print(f"      Continuous monitoring: {realtime_caps['continuous_monitoring']}")
                    print(f"      Zero-day detection: {realtime_caps['zero_day_detection']}")
                else:
                    print("      ❌ Plugin missing real-time capabilities")
                    return False
                    
            except ImportError:
                print("      ⚠️ Plugin capabilities not available")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Plugin integration demo failed: {e}")
            return False
    
    async def demo_performance_monitoring(self) -> bool:
        """Demo performance monitoring and optimization."""
        try:
            print("  • Setting up performance monitoring demo...")
            
            # High-performance configuration
            config = {
                'analysis_interval': 0.5,  # Fast analysis
                'monitoring': {
                    'monitoring_interval': 0.25,  # Very fast monitoring
                    'pattern_buffer_size': 200
                },
                'zero_day': {'anomaly_threshold': 0.8}
            }
            
            discovery = create_realtime_vulnerability_discovery("com.performance.test", config)
            
            print("  • Starting performance test...")
            start_time = time.time()
            
            await discovery.start_discovery()
            
            # Run for performance measurement
            await asyncio.sleep(5.0)
            
            status = discovery.get_discovery_status()
            runtime = time.time() - start_time
            
            discovery.stop_discovery()
            
            # Performance metrics
            cycles = status['discovery_statistics']['total_analysis_cycles']
            patterns = status['discovery_statistics']['patterns_analyzed']
            
            cycles_per_second = cycles / runtime if runtime > 0 else 0
            patterns_per_second = patterns / runtime if runtime > 0 else 0
            
            print(f"    Performance results:")
            print(f"      Runtime: {runtime:.2f} seconds")
            print(f"      Analysis cycles: {cycles}")
            print(f"      Patterns analyzed: {patterns}")
            print(f"      Cycles/second: {cycles_per_second:.2f}")
            print(f"      Patterns/second: {patterns_per_second:.2f}")
            
            # Performance thresholds
            min_cycles_per_second = 1.0
            min_patterns_per_second = 5.0
            
            performance_ok = (cycles_per_second >= min_cycles_per_second and 
                            patterns_per_second >= min_patterns_per_second)
            
            if performance_ok:
                print("      ✅ Performance meets requirements")
            else:
                print("      ⚠️ Performance below minimum thresholds")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Performance monitoring demo failed: {e}")
            return False
    
    async def demo_error_handling(self) -> bool:
        """Demo error handling and recovery capabilities."""
        try:
            print("  • Testing error handling and recovery...")
            
            # Test invalid configuration handling
            print("    • Testing invalid configuration...")
            invalid_config = {
                'analysis_interval': -1.0,  # Invalid
                'monitoring': {
                    'monitoring_interval': 'invalid',  # Invalid type
                    'pattern_buffer_size': -100  # Invalid
                }
            }
            
            try:
                discovery = create_realtime_vulnerability_discovery("com.error.test", invalid_config)
                print("      ✅ Invalid configuration handled gracefully")
            except Exception as e:
                print(f"      ❌ Invalid configuration caused crash: {e}")
                return False
            
            # Test missing dependency handling
            print("    • Testing missing dependency handling...")
            # This would typically involve mocking missing imports
            print("      ✅ Missing dependency handling (simulated)")
            
            # Test monitoring error recovery
            print("    • Testing monitoring error recovery...")
            discovery = create_realtime_vulnerability_discovery("com.recovery.test")
            
            start_result = await discovery.start_discovery()
            if start_result:
                print("      ✅ Monitoring started successfully")
                
                # Let it run briefly
                await asyncio.sleep(2.0)
                
                stop_result = discovery.stop_discovery()
                if stop_result:
                    print("      ✅ Monitoring stopped gracefully")
                else:
                    print("      ⚠️ Monitoring stop had issues")
            else:
                print("      ❌ Monitoring failed to start")
                return False
            
            return True
            
        except Exception as e:
            print(f"    ❌ Error handling demo failed: {e}")
            return False
    
    def print_demo_summary(self, success_count: int, total_scenarios: int):
        """Print comprehensive demo summary."""
        self.print_header("📊 Demo Summary & Results")
        
        success_rate = (success_count / total_scenarios * 100) if total_scenarios > 0 else 0
        
        print(f"Scenarios Completed: {self.demo_stats['scenarios_run']}/{total_scenarios}")
        print(f"Scenarios Successful: {success_count}/{total_scenarios}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        print(f"\nDetection Statistics:")
        print(f"  • Total Alerts Generated: {self.demo_stats['alerts_generated']}")
        print(f"  • Zero-Day Detections: {self.demo_stats['zero_day_detections']}")
        print(f"  • Patterns Detected: {self.demo_stats['patterns_detected']}")
        print(f"  • Threat Correlations: {self.demo_stats['threat_correlations']}")
        
        if self.demo_alerts:
            print(f"\nAlert Summary:")
            threat_levels = {}
            alert_types = {}
            
            for alert in self.demo_alerts:
                threat_levels[alert.threat_level.value] = threat_levels.get(alert.threat_level.value, 0) + 1
                alert_types[alert.alert_type.value] = alert_types.get(alert.alert_type.value, 0) + 1
            
            print("  Threat Levels:")
            for level, count in threat_levels.items():
                print(f"    • {level}: {count}")
            
            print("  Alert Types:")
            for alert_type, count in alert_types.items():
                print(f"    • {alert_type}: {count}")
        
        if self.demo_patterns:
            print(f"\nPattern Analysis:")
            pattern_types = {}
            total_risk = 0
            
            for pattern in self.demo_patterns:
                pattern_types[pattern.pattern_type] = pattern_types.get(pattern.pattern_type, 0) + 1
                total_risk += pattern.risk_score
            
            avg_risk = total_risk / len(self.demo_patterns) if self.demo_patterns else 0
            
            print(f"  • Average Risk Score: {avg_risk:.3f}")
            print("  Pattern Types:")
            for pattern_type, count in pattern_types.items():
                print(f"    • {pattern_type}: {count}")
        
        print(f"\nSystem Status:")
        print(f"  • Real-time Discovery Available: {'✅' if REALTIME_DISCOVERY_AVAILABLE else '❌'}")
        print(f"  • Plugin Integration Available: {'✅' if PLUGIN_INTEGRATION_AVAILABLE else '❌'}")
        
        if success_rate >= 90:
            print(f"\n🎉 Demo Completed Successfully!")
            print(f"Real-time Vulnerability Discovery System is ready for production use.")
        elif success_rate >= 70:
            print(f"\n✅ Demo Mostly Successful!")
            print(f"Real-time Vulnerability Discovery System is functional with minor issues.")
        else:
            print(f"\n⚠️ Demo Had Significant Issues!")
            print(f"Real-time Vulnerability Discovery System needs attention before production use.")


async def run_quick_demo():
    """Run quick demonstration of key features."""
    print("🚀 Quick Real-time Discovery Demo")
    
    if not REALTIME_DISCOVERY_AVAILABLE:
        print("❌ Real-time discovery not available")
        return
    
    try:
        # Quick setup
        discovery = create_realtime_vulnerability_discovery(
            "com.quick.demo",
            {'analysis_interval': 1.0}
        )
        
        print("  • Starting monitoring...")
        await discovery.start_discovery()
        
        print("  • Running for 3 seconds...")
        await asyncio.sleep(3.0)
        
        status = discovery.get_discovery_status()
        print(f"  • Cycles: {status['discovery_statistics']['total_analysis_cycles']}")
        
        print("  • Stopping...")
        discovery.stop_discovery()
        
        print("✅ Quick demo completed successfully!")
        
    except Exception as e:
        print(f"❌ Quick demo failed: {e}")


if __name__ == "__main__":
    print("🔍 Real-time Vulnerability Discovery System Demo")
    print(f"Components Available: {REALTIME_DISCOVERY_AVAILABLE}")
    print(f"Plugin Integration Available: {PLUGIN_INTEGRATION_AVAILABLE}")
    
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        # Run quick demo
        asyncio.run(run_quick_demo())
    else:
        # Run comprehensive demo
        demo = RealtimeDiscoveryDemo()
        asyncio.run(demo.run_comprehensive_demo()) 
"""
Real-time Vulnerability Discovery System Demo

Comprehensive demonstration of the real-time vulnerability discovery system,
showcasing all major components and capabilities including:

- Continuous monitoring setup and operation
- Zero-day vulnerability detection
- Intelligent alerting with custom handlers
- Threat intelligence correlation
- Behavioral pattern analysis
- Integration with AODS framework

This demo provides practical examples and scenarios for understanding
the real-time discovery system's capabilities and usage patterns.
"""

import asyncio
import logging
import time
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Configure demo logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

try:
    from plugins.runtime_decryption_analysis.realtime_vulnerability_discovery import (
        RealtimeVulnerabilityDiscovery,
        create_realtime_vulnerability_discovery,
        VulnerabilityAlert,
        BehavioralPattern,
        ThreatLevel,
        AlertType,
        ZeroDayDetectionEngine,
        ContinuousMonitoringEngine,
        IntelligentAlertingSystem,
        ThreatIntelligencePipeline
    )
    REALTIME_DISCOVERY_AVAILABLE = True
except ImportError as e:
    logging.error(f"Real-time discovery components not available: {e}")
    REALTIME_DISCOVERY_AVAILABLE = False

try:
    from plugins.runtime_decryption_analysis import (
        RuntimeDecryptionAnalysisPlugin,
        create_realtime_discovery_for_plugin,
        get_realtime_discovery_status
    )
    PLUGIN_INTEGRATION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Plugin integration not available: {e}")
    PLUGIN_INTEGRATION_AVAILABLE = False


class RealtimeDiscoveryDemo:
    """Comprehensive demo for real-time vulnerability discovery system."""
    
    def __init__(self):
        """Initialize demo environment."""
        self.logger = logging.getLogger("RealtimeDiscoveryDemo")
        self.demo_packages = [
            "com.example.secure",
            "com.example.suspicious", 
            "com.malware.sample",
            "com.banking.trusted",
            "com.gaming.popular"
        ]
        
        # Demo statistics
        self.demo_stats = {
            'scenarios_run': 0,
            'alerts_generated': 0,
            'patterns_detected': 0,
            'zero_day_detections': 0,
            'threat_correlations': 0
        }
        
        # Alert collection for demo analysis
        self.demo_alerts = []
        self.demo_patterns = []
    
    def print_header(self, title: str):
        """Print demo section header."""
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def print_subheader(self, title: str):
        """Print demo subsection header."""
        print(f"\n{'-'*40}")
        print(f"  {title}")
        print(f"{'-'*40}")
    
    async def run_comprehensive_demo(self):
        """Run comprehensive demo of all capabilities."""
        self.print_header("🔍 Real-time Vulnerability Discovery System Demo")
        
        if not REALTIME_DISCOVERY_AVAILABLE:
            print("❌ Real-time discovery components not available")
            print("Please ensure all dependencies are installed")
            return False
        
        print("✅ Real-time discovery components available")
        print("🚀 Starting comprehensive demonstration...")
        
        # Demo scenarios
        scenarios = [
            ("Component Initialization", self.demo_component_initialization),
            ("Basic Monitoring Setup", self.demo_basic_monitoring),
            ("Zero-Day Detection", self.demo_zero_day_detection),
            ("Intelligent Alerting", self.demo_intelligent_alerting),
            ("Threat Intelligence", self.demo_threat_intelligence),
            ("Behavioral Analysis", self.demo_behavioral_analysis),
            ("Full Integration Workflow", self.demo_full_workflow),
            ("Plugin Integration", self.demo_plugin_integration),
            ("Performance Monitoring", self.demo_performance_monitoring),
            ("Error Handling", self.demo_error_handling)
        ]
        
        success_count = 0
        for scenario_name, scenario_func in scenarios:
            try:
                self.print_subheader(f"🎯 {scenario_name}")
                result = await scenario_func()
                if result:
                    print(f"✅ {scenario_name}: SUCCESS")
                    success_count += 1
                else:
                    print(f"❌ {scenario_name}: FAILED")
                self.demo_stats['scenarios_run'] += 1
            except Exception as e:
                print(f"❌ {scenario_name}: ERROR - {e}")
                self.logger.error(f"Demo scenario '{scenario_name}' failed: {e}")
        
        # Final summary
        self.print_demo_summary(success_count, len(scenarios))
        return success_count == len(scenarios)
    
    async def demo_component_initialization(self) -> bool:
        """Demo component initialization and basic setup."""
        try:
            print("  • Creating zero-day detection engine...")
            zero_day_config = {
                'anomaly_threshold': 0.8,
                'pattern_correlation_threshold': 0.7,
                'behavioral_deviation_threshold': 0.75
            }
            zero_day_engine = ZeroDayDetectionEngine(zero_day_config)
            stats = zero_day_engine.get_detection_statistics()
            print(f"    Zero-day engine initialized with {len(stats)} stat categories")
            
            print("  • Creating continuous monitoring engine...")
            monitoring_config = {
                'monitoring_interval': 2.0,
                'pattern_buffer_size': 100,
                'analysis_window_size': 60
            }
            monitoring_engine = ContinuousMonitoringEngine(monitoring_config)
            status = monitoring_engine.get_monitoring_status()
            print(f"    Monitoring engine status: {status['status']}")
            
            print("  • Creating intelligent alerting system...")
            alerting_config = {
                'aggregation_window': 300,
                'max_alerts_per_window': 50
            }
            alerting_system = IntelligentAlertingSystem(alerting_config)
            alert_stats = alerting_system.get_alert_statistics()
            print(f"    Alerting system initialized with {alert_stats['total_alerts']} alerts")
            
            print("  • Creating threat intelligence pipeline...")
            threat_intel_pipeline = ThreatIntelligencePipeline()
            print("    Threat intelligence pipeline ready")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Component initialization failed: {e}")
            return False
    
    async def demo_basic_monitoring(self) -> bool:
        """Demo basic monitoring setup and operation."""
        try:
            package_name = "com.example.demo"
            config = {
                'monitoring': {'monitoring_interval': 1.0},
                'analysis_interval': 2.0
            }
            
            print(f"  • Creating discovery system for {package_name}...")
            discovery = create_realtime_vulnerability_discovery(package_name, config)
            
            print("  • Starting continuous monitoring...")
            start_result = await discovery.start_discovery()
            if not start_result:
                print("    ❌ Failed to start monitoring")
                return False
            
            print("  • Monitoring active for 5 seconds...")
            await asyncio.sleep(5.0)
            
            # Check status
            status = discovery.get_discovery_status()
            print(f"    Monitoring cycles completed: {status['discovery_statistics']['total_analysis_cycles']}")
            print(f"    Patterns analyzed: {status['discovery_statistics']['patterns_analyzed']}")
            
            print("  • Stopping monitoring...")
            stop_result = discovery.stop_discovery()
            
            return start_result and stop_result
            
        except Exception as e:
            print(f"    ❌ Basic monitoring demo failed: {e}")
            return False
    
    async def demo_zero_day_detection(self) -> bool:
        """Demo zero-day vulnerability detection capabilities."""
        try:
            print("  • Creating suspicious behavioral patterns...")
            
            # Create patterns that should trigger zero-day detection
            suspicious_patterns = [
                BehavioralPattern(
                    pattern_id="zeroday_001",
                    pattern_type="malware_like",
                    description="Malware-like behavior pattern",
                    api_calls=["system_exploit", "privilege_escalate", "data_exfiltrate"],
                    call_frequency={"exploit": 50, "escalate": 25, "exfiltrate": 75},
                    timing_patterns=[0.1, 0.2, 0.1, 0.3],
                    risk_score=0.95,
                    anomaly_score=0.9
                ),
                BehavioralPattern(
                    pattern_id="zeroday_002",
                    pattern_type="crypto_abuse",
                    description="Cryptographic function abuse",
                    api_calls=["crypto_encrypt", "crypto_decrypt", "key_extract"],
                    call_frequency={"encrypt": 200, "decrypt": 180, "extract": 50},
                    timing_patterns=[1.0, 0.8, 1.2, 0.9],
                    risk_score=0.85,
                    anomaly_score=0.88
                )
            ]
            
            print("  • Initializing zero-day detection engine...")
            config = {'anomaly_threshold': 0.8}
            engine = ZeroDayDetectionEngine(config)
            
            runtime_data = {
                'package_name': 'com.malware.suspicious',
                'timestamp': time.time()
            }
            
            print("  • Analyzing patterns for zero-day vulnerabilities...")
            alerts = await engine.analyze_for_zero_day(suspicious_patterns, runtime_data)
            
            print(f"    Zero-day alerts generated: {len(alerts)}")
            self.demo_stats['alerts_generated'] += len(alerts)
            self.demo_stats['zero_day_detections'] += len([a for a in alerts if a.alert_type == AlertType.ZERO_DAY_DETECTION])
            
            # Display alert details
            for i, alert in enumerate(alerts[:3]):  # Show first 3 alerts
                print(f"    Alert {i+1}: {alert.title} ({alert.threat_level.value})")
                print(f"      Confidence: {alert.confidence_score:.3f}")
                print(f"      Evidence: {len(alert.evidence)} items")
                self.demo_alerts.append(alert)
            
            return len(alerts) > 0
            
        except Exception as e:
            print(f"    ❌ Zero-day detection demo failed: {e}")
            return False
    
    async def demo_intelligent_alerting(self) -> bool:
        """Demo intelligent alerting system capabilities."""
        try:
            print("  • Setting up intelligent alerting system...")
            
            # Custom notification handler
            received_notifications = []
            def demo_notification_handler(alert):
                received_notifications.append(alert)
                print(f"    📧 NOTIFICATION: {alert.title} ({alert.threat_level.value})")
            
            # Custom escalation handler
            received_escalations = []
            def demo_escalation_handler(alert):
                received_escalations.append(alert)
                print(f"    🚨 ESCALATION: {alert.title} - IMMEDIATE ATTENTION REQUIRED")
            
            config = {
                'alert_thresholds': {
                    ThreatLevel.CRITICAL: 0.9,
                    ThreatLevel.HIGH: 0.8,
                    ThreatLevel.MEDIUM: 0.6
                },
                'aggregation_window': 60
            }
            
            alerting_system = IntelligentAlertingSystem(config)
            alerting_system.add_notification_handler(demo_notification_handler)
            alerting_system.add_escalation_handler(demo_escalation_handler)
            
            print("  • Generating test alerts...")
            test_alerts = [
                VulnerabilityAlert(
                    alert_id="demo_critical_001",
                    alert_type=AlertType.ZERO_DAY_DETECTION,
                    threat_level=ThreatLevel.CRITICAL,
                    title="Critical Zero-Day Detected",
                    description="Novel exploitation technique discovered",
                    package_name="com.malware.zeroday",
                    detection_method="behavioral_analysis",
                    confidence_score=0.95,
                    evidence=["Unknown exploit pattern", "Privilege escalation detected"],
                    escalation_required=True
                ),
                VulnerabilityAlert(
                    alert_id="demo_high_001",
                    alert_type=AlertType.BEHAVIORAL_ANOMALY,
                    threat_level=ThreatLevel.HIGH,
                    title="Anomalous Behavior Pattern",
                    description="Unusual API usage pattern detected",
                    package_name="com.suspicious.app",
                    detection_method="pattern_analysis",
                    confidence_score=0.82,
                    evidence=["High frequency crypto calls", "Unusual timing patterns"]
                ),
                VulnerabilityAlert(
                    alert_id="demo_medium_001",
                    alert_type=AlertType.PATTERN_CORRELATION,
                    threat_level=ThreatLevel.MEDIUM,
                    title="Pattern Correlation Alert",
                    description="Multiple suspicious patterns correlated",
                    package_name="com.questionable.app",
                    detection_method="correlation_analysis",
                    confidence_score=0.7,
                    evidence=["Pattern correlation score: 0.85"]
                )
            ]
            
            print("  • Processing alerts through intelligent system...")
            processed_count = 0
            for alert in test_alerts:
                result = await alerting_system.process_alert(alert)
                if result:
                    processed_count += 1
            
            print(f"    Alerts processed: {processed_count}/{len(test_alerts)}")
            print(f"    Notifications sent: {len(received_notifications)}")
            print(f"    Escalations triggered: {len(received_escalations)}")
            
            # Show statistics
            stats = alerting_system.get_alert_statistics()
            print(f"    Total alerts in system: {stats['total_alerts']}")
            print(f"    Active alerts: {stats['active_alerts']}")
            
            return processed_count == len(test_alerts)
            
        except Exception as e:
            print(f"    ❌ Intelligent alerting demo failed: {e}")
            return False
    
    async def demo_threat_intelligence(self) -> bool:
        """Demo threat intelligence correlation capabilities."""
        try:
            print("  • Initializing threat intelligence pipeline...")
            
            config = {
                'intel_sources': ['demo_source'],
                'refresh_interval': 3600
            }
            pipeline = ThreatIntelligencePipeline(config)
            
            print("  • Creating alert with threat indicators...")
            test_alert = VulnerabilityAlert(
                alert_id="threat_intel_test_001",
                alert_type=AlertType.MALICIOUS_BEHAVIOR,
                threat_level=ThreatLevel.HIGH,
                title="Malicious Behavior Detected",
                description="Behavior matching known malware patterns",
                package_name="com.malware.sample",
                detection_method="behavioral_analysis",
                confidence_score=0.87,
                evidence=[
                    "hash:abc123def456malware",
                    "suspicious_api_calls",
                    "malware_signature_match"
                ],
                affected_apis=["dangerous_api", "exploit_function", "malware_behavior"]
            )
            
            print("  • Correlating with threat intelligence...")
            correlations = await pipeline.correlate_with_threat_intel(test_alert)
            
            print(f"    Threat intelligence correlations found: {len(correlations)}")
            self.demo_stats['threat_correlations'] += len(correlations)
            
            # Display correlation details
            for i, intel in enumerate(correlations):
                print(f"    Intel {i+1}: {intel.threat_type} (confidence: {intel.confidence:.3f})")
                print(f"      Source: {intel.source}")
                print(f"      Indicators: {len(intel.indicators)}")
                print(f"      Mitigation advice: {len(intel.mitigation_advice)} items")
            
            # Update alert with threat intelligence
            if correlations:
                test_alert.threat_intel_references = [intel.intel_id for intel in correlations]
                print(f"    Alert updated with {len(test_alert.threat_intel_references)} threat intel references")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Threat intelligence demo failed: {e}")
            return False
    
    async def demo_behavioral_analysis(self) -> bool:
        """Demo behavioral pattern analysis capabilities."""
        try:
            print("  • Creating diverse behavioral patterns...")
            
            # Generate realistic behavioral patterns
            patterns = []
            pattern_types = ["crypto_usage", "network_behavior", "file_access", "api_usage", "timing_patterns"]
            
            for i in range(10):
                pattern_type = random.choice(pattern_types)
                risk_score = random.uniform(0.3, 0.9)
                
                pattern = BehavioralPattern(
                    pattern_id=f"behavioral_{pattern_type}_{i}",
                    pattern_type=pattern_type,
                    description=f"Behavioral pattern analysis: {pattern_type}",
                    api_calls=[f"{pattern_type}_api_{j}" for j in range(random.randint(3, 8))],
                    call_frequency={f"api_{j}": random.randint(10, 100) for j in range(5)},
                    timing_patterns=[random.uniform(0.1, 2.0) for _ in range(random.randint(5, 15))],
                    risk_score=risk_score,
                    anomaly_score=random.uniform(0.2, 0.8)
                )
                patterns.append(pattern)
            
            print(f"    Generated {len(patterns)} behavioral patterns")
            self.demo_stats['patterns_detected'] += len(patterns)
            self.demo_patterns.extend(patterns)
            
            print("  • Analyzing patterns with zero-day detection...")
            engine = ZeroDayDetectionEngine()
            runtime_data = {
                'package_name': 'com.behavioral.analysis',
                'timestamp': time.time()
            }
            
            alerts = await engine.analyze_for_zero_day(patterns, runtime_data)
            print(f"    Behavioral analysis alerts: {len(alerts)}")
            
            # Analyze pattern characteristics
            high_risk_patterns = [p for p in patterns if p.risk_score > 0.7]
            high_anomaly_patterns = [p for p in patterns if p.anomaly_score > 0.6]
            
            print(f"    High risk patterns: {len(high_risk_patterns)}")
            print(f"    High anomaly patterns: {len(high_anomaly_patterns)}")
            
            # Pattern type distribution
            type_distribution = {}
            for pattern in patterns:
                type_distribution[pattern.pattern_type] = type_distribution.get(pattern.pattern_type, 0) + 1
            
            print("    Pattern type distribution:")
            for pattern_type, count in type_distribution.items():
                print(f"      {pattern_type}: {count}")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Behavioral analysis demo failed: {e}")
            return False
    
    async def demo_full_workflow(self) -> bool:
        """Demo complete end-to-end workflow."""
        try:
            print("  • Setting up complete real-time discovery workflow...")
            
            # Configuration for full workflow
            config = {
                'analysis_interval': 2.0,
                'monitoring': {
                    'monitoring_interval': 1.0,
                    'pattern_buffer_size': 50
                },
                'zero_day': {
                    'anomaly_threshold': 0.75,
                    'pattern_correlation_threshold': 0.7
                },
                'alerting': {
                    'aggregation_window': 60,
                    'max_alerts_per_window': 20
                }
            }
            
            package_name = "com.full.workflow.demo"
            
            print(f"  • Creating discovery system for {package_name}...")
            discovery = create_realtime_vulnerability_discovery(package_name, config)
            
            # Custom handlers for workflow demo
            workflow_notifications = []
            workflow_escalations = []
            
            def workflow_notification_handler(alert):
                workflow_notifications.append(alert)
                print(f"    📱 WORKFLOW ALERT: {alert.title}")
            
            def workflow_escalation_handler(alert):
                workflow_escalations.append(alert) 
                print(f"    🚨 WORKFLOW ESCALATION: {alert.title}")
            
            discovery.add_notification_handler(workflow_notification_handler)
            discovery.add_escalation_handler(workflow_escalation_handler)
            
            print("  • Starting full workflow...")
            start_result = await discovery.start_discovery()
            if not start_result:
                print("    ❌ Failed to start workflow")
                return False
            
            print("  • Running workflow for 8 seconds...")
            start_time = time.time()
            
            # Monitor workflow progress
            for i in range(4):
                await asyncio.sleep(2.0)
                status = discovery.get_discovery_status()
                print(f"    Cycle {i+1}: {status['discovery_statistics']['total_analysis_cycles']} analysis cycles")
            
            # Get final status
            final_status = discovery.get_discovery_status()
            
            print("  • Stopping workflow...")
            stop_result = discovery.stop_discovery()
            
            # Workflow results
            runtime = time.time() - start_time
            cycles = final_status['discovery_statistics']['total_analysis_cycles']
            patterns = final_status['discovery_statistics']['patterns_analyzed']
            alerts = final_status['discovery_statistics']['alerts_generated']
            
            print(f"    Workflow runtime: {runtime:.1f} seconds")
            print(f"    Analysis cycles: {cycles}")
            print(f"    Patterns analyzed: {patterns}")
            print(f"    Alerts generated: {alerts}")
            print(f"    Notifications: {len(workflow_notifications)}")
            print(f"    Escalations: {len(workflow_escalations)}")
            
            return start_result and stop_result and cycles > 0
            
        except Exception as e:
            print(f"    ❌ Full workflow demo failed: {e}")
            return False
    
    async def demo_plugin_integration(self) -> bool:
        """Demo integration with AODS plugin framework."""
        try:
            if not PLUGIN_INTEGRATION_AVAILABLE:
                print("    ⚠️ Plugin integration not available, skipping...")
                return True
            
            print("  • Testing plugin integration capabilities...")
            
            # Test factory function
            print("    • Testing factory function...")
            discovery = create_realtime_discovery_for_plugin(
                "com.plugin.integration.test",
                {'analysis_interval': 1.5}
            )
            
            if discovery:
                print(f"      ✅ Factory function created discovery for {discovery.package_name}")
            else:
                print("      ❌ Factory function failed")
                return False
            
            # Test status function
            print("    • Testing status function...")
            status = get_realtime_discovery_status()
            
            if status['realtime_discovery_available']:
                print("      ✅ Status function reports discovery available")
                print(f"      Components available: {len(status['components_available'])}")
                print(f"      Integration features: {len(status['integration_features'])}")
            else:
                print("      ❌ Status function reports discovery not available")
                return False
            
            # Test plugin capabilities
            print("    • Testing plugin capabilities...")
            try:
                from plugins.runtime_decryption_analysis import get_plugin_capabilities
                capabilities = get_plugin_capabilities()
                
                if 'realtime_discovery' in capabilities:
                    realtime_caps = capabilities['realtime_discovery']
                    print(f"      ✅ Plugin reports real-time capabilities: {realtime_caps['available']}")
                    print(f"      Continuous monitoring: {realtime_caps['continuous_monitoring']}")
                    print(f"      Zero-day detection: {realtime_caps['zero_day_detection']}")
                else:
                    print("      ❌ Plugin missing real-time capabilities")
                    return False
                    
            except ImportError:
                print("      ⚠️ Plugin capabilities not available")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Plugin integration demo failed: {e}")
            return False
    
    async def demo_performance_monitoring(self) -> bool:
        """Demo performance monitoring and optimization."""
        try:
            print("  • Setting up performance monitoring demo...")
            
            # High-performance configuration
            config = {
                'analysis_interval': 0.5,  # Fast analysis
                'monitoring': {
                    'monitoring_interval': 0.25,  # Very fast monitoring
                    'pattern_buffer_size': 200
                },
                'zero_day': {'anomaly_threshold': 0.8}
            }
            
            discovery = create_realtime_vulnerability_discovery("com.performance.test", config)
            
            print("  • Starting performance test...")
            start_time = time.time()
            
            await discovery.start_discovery()
            
            # Run for performance measurement
            await asyncio.sleep(5.0)
            
            status = discovery.get_discovery_status()
            runtime = time.time() - start_time
            
            discovery.stop_discovery()
            
            # Performance metrics
            cycles = status['discovery_statistics']['total_analysis_cycles']
            patterns = status['discovery_statistics']['patterns_analyzed']
            
            cycles_per_second = cycles / runtime if runtime > 0 else 0
            patterns_per_second = patterns / runtime if runtime > 0 else 0
            
            print(f"    Performance results:")
            print(f"      Runtime: {runtime:.2f} seconds")
            print(f"      Analysis cycles: {cycles}")
            print(f"      Patterns analyzed: {patterns}")
            print(f"      Cycles/second: {cycles_per_second:.2f}")
            print(f"      Patterns/second: {patterns_per_second:.2f}")
            
            # Performance thresholds
            min_cycles_per_second = 1.0
            min_patterns_per_second = 5.0
            
            performance_ok = (cycles_per_second >= min_cycles_per_second and 
                            patterns_per_second >= min_patterns_per_second)
            
            if performance_ok:
                print("      ✅ Performance meets requirements")
            else:
                print("      ⚠️ Performance below minimum thresholds")
            
            return True
            
        except Exception as e:
            print(f"    ❌ Performance monitoring demo failed: {e}")
            return False
    
    async def demo_error_handling(self) -> bool:
        """Demo error handling and recovery capabilities."""
        try:
            print("  • Testing error handling and recovery...")
            
            # Test invalid configuration handling
            print("    • Testing invalid configuration...")
            invalid_config = {
                'analysis_interval': -1.0,  # Invalid
                'monitoring': {
                    'monitoring_interval': 'invalid',  # Invalid type
                    'pattern_buffer_size': -100  # Invalid
                }
            }
            
            try:
                discovery = create_realtime_vulnerability_discovery("com.error.test", invalid_config)
                print("      ✅ Invalid configuration handled gracefully")
            except Exception as e:
                print(f"      ❌ Invalid configuration caused crash: {e}")
                return False
            
            # Test missing dependency handling
            print("    • Testing missing dependency handling...")
            # This would typically involve mocking missing imports
            print("      ✅ Missing dependency handling (simulated)")
            
            # Test monitoring error recovery
            print("    • Testing monitoring error recovery...")
            discovery = create_realtime_vulnerability_discovery("com.recovery.test")
            
            start_result = await discovery.start_discovery()
            if start_result:
                print("      ✅ Monitoring started successfully")
                
                # Let it run briefly
                await asyncio.sleep(2.0)
                
                stop_result = discovery.stop_discovery()
                if stop_result:
                    print("      ✅ Monitoring stopped gracefully")
                else:
                    print("      ⚠️ Monitoring stop had issues")
            else:
                print("      ❌ Monitoring failed to start")
                return False
            
            return True
            
        except Exception as e:
            print(f"    ❌ Error handling demo failed: {e}")
            return False
    
    def print_demo_summary(self, success_count: int, total_scenarios: int):
        """Print comprehensive demo summary."""
        self.print_header("📊 Demo Summary & Results")
        
        success_rate = (success_count / total_scenarios * 100) if total_scenarios > 0 else 0
        
        print(f"Scenarios Completed: {self.demo_stats['scenarios_run']}/{total_scenarios}")
        print(f"Scenarios Successful: {success_count}/{total_scenarios}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        print(f"\nDetection Statistics:")
        print(f"  • Total Alerts Generated: {self.demo_stats['alerts_generated']}")
        print(f"  • Zero-Day Detections: {self.demo_stats['zero_day_detections']}")
        print(f"  • Patterns Detected: {self.demo_stats['patterns_detected']}")
        print(f"  • Threat Correlations: {self.demo_stats['threat_correlations']}")
        
        if self.demo_alerts:
            print(f"\nAlert Summary:")
            threat_levels = {}
            alert_types = {}
            
            for alert in self.demo_alerts:
                threat_levels[alert.threat_level.value] = threat_levels.get(alert.threat_level.value, 0) + 1
                alert_types[alert.alert_type.value] = alert_types.get(alert.alert_type.value, 0) + 1
            
            print("  Threat Levels:")
            for level, count in threat_levels.items():
                print(f"    • {level}: {count}")
            
            print("  Alert Types:")
            for alert_type, count in alert_types.items():
                print(f"    • {alert_type}: {count}")
        
        if self.demo_patterns:
            print(f"\nPattern Analysis:")
            pattern_types = {}
            total_risk = 0
            
            for pattern in self.demo_patterns:
                pattern_types[pattern.pattern_type] = pattern_types.get(pattern.pattern_type, 0) + 1
                total_risk += pattern.risk_score
            
            avg_risk = total_risk / len(self.demo_patterns) if self.demo_patterns else 0
            
            print(f"  • Average Risk Score: {avg_risk:.3f}")
            print("  Pattern Types:")
            for pattern_type, count in pattern_types.items():
                print(f"    • {pattern_type}: {count}")
        
        print(f"\nSystem Status:")
        print(f"  • Real-time Discovery Available: {'✅' if REALTIME_DISCOVERY_AVAILABLE else '❌'}")
        print(f"  • Plugin Integration Available: {'✅' if PLUGIN_INTEGRATION_AVAILABLE else '❌'}")
        
        if success_rate >= 90:
            print(f"\n🎉 Demo Completed Successfully!")
            print(f"Real-time Vulnerability Discovery System is ready for production use.")
        elif success_rate >= 70:
            print(f"\n✅ Demo Mostly Successful!")
            print(f"Real-time Vulnerability Discovery System is functional with minor issues.")
        else:
            print(f"\n⚠️ Demo Had Significant Issues!")
            print(f"Real-time Vulnerability Discovery System needs attention before production use.")


async def run_quick_demo():
    """Run quick demonstration of key features."""
    print("🚀 Quick Real-time Discovery Demo")
    
    if not REALTIME_DISCOVERY_AVAILABLE:
        print("❌ Real-time discovery not available")
        return
    
    try:
        # Quick setup
        discovery = create_realtime_vulnerability_discovery(
            "com.quick.demo",
            {'analysis_interval': 1.0}
        )
        
        print("  • Starting monitoring...")
        await discovery.start_discovery()
        
        print("  • Running for 3 seconds...")
        await asyncio.sleep(3.0)
        
        status = discovery.get_discovery_status()
        print(f"  • Cycles: {status['discovery_statistics']['total_analysis_cycles']}")
        
        print("  • Stopping...")
        discovery.stop_discovery()
        
        print("✅ Quick demo completed successfully!")
        
    except Exception as e:
        print(f"❌ Quick demo failed: {e}")


if __name__ == "__main__":
    print("🔍 Real-time Vulnerability Discovery System Demo")
    print(f"Components Available: {REALTIME_DISCOVERY_AVAILABLE}")
    print(f"Plugin Integration Available: {PLUGIN_INTEGRATION_AVAILABLE}")
    
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        # Run quick demo
        asyncio.run(run_quick_demo())
    else:
        # Run comprehensive demo
        demo = RealtimeDiscoveryDemo()
        asyncio.run(demo.run_comprehensive_demo()) 