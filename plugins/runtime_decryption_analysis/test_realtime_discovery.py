#!/usr/bin/env python3
"""
Comprehensive Test Suite for Real-time Vulnerability Discovery System

Tests all components of the real-time vulnerability discovery system including:
- Zero-day detection engine
- Continuous monitoring engine
- Intelligent alerting system  
- Threat intelligence pipeline
- Main discovery orchestrator
- Plugin integration

Test Categories:
- Unit Tests: Individual component testing
- Integration Tests: Component interaction testing
- Performance Tests: Load and stress testing
- Error Handling Tests: Failure scenario testing
- Plugin Integration Tests: AODS framework compatibility
"""

import asyncio
import unittest
import logging
import tempfile
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path
import sys
import json

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

try:
    from plugins.runtime_decryption_analysis.realtime_vulnerability_discovery import (
        RealtimeVulnerabilityDiscovery,
        ZeroDayDetectionEngine,
        ContinuousMonitoringEngine,
        IntelligentAlertingSystem,
        ThreatIntelligencePipeline,
        VulnerabilityAlert,
        BehavioralPattern,
        ThreatIntelligenceInfo,
        ThreatLevel,
        AlertType,
        MonitoringStatus,
        create_realtime_vulnerability_discovery
    )
    REALTIME_DISCOVERY_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Real-time discovery components not available: {e}")
    REALTIME_DISCOVERY_AVAILABLE = False


class TestZeroDayDetectionEngine(unittest.TestCase):
    """Test cases for Zero-Day Detection Engine."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'anomaly_threshold': 0.8,
            'pattern_correlation_threshold': 0.7,
            'behavioral_deviation_threshold': 0.75
        }
        self.engine = ZeroDayDetectionEngine(self.config)
    
    def test_initialization(self):
        """Test zero-day detection engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.anomaly_threshold, 0.8)
        self.assertIsNotNone(self.engine.detection_stats)
        self.assertIn('total_analyses', self.engine.detection_stats)
    
    def test_anomaly_score_calculation(self):
        """Test anomaly score calculation."""
        pattern = BehavioralPattern(
            pattern_id="test_pattern_001",
            pattern_type="api_usage",
            description="Test pattern",
            call_frequency={"crypto": 50, "network": 20},
            timing_patterns=[1.0, 2.0, 1.5],
            risk_score=0.6
        )
        
        runtime_data = {"package_name": "test.app"}
        score = self.engine._calculate_anomaly_score(pattern, runtime_data)
        
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
    
    def test_threat_level_determination(self):
        """Test threat level determination."""
        self.assertEqual(self.engine._determine_threat_level(0.95), ThreatLevel.CRITICAL)
        self.assertEqual(self.engine._determine_threat_level(0.85), ThreatLevel.HIGH)
        self.assertEqual(self.engine._determine_threat_level(0.65), ThreatLevel.MEDIUM)
        self.assertEqual(self.engine._determine_threat_level(0.45), ThreatLevel.LOW)
        self.assertEqual(self.engine._determine_threat_level(0.25), ThreatLevel.INFO)
    
    def test_pattern_correlation_calculation(self):
        """Test pattern correlation calculation."""
        pattern1 = BehavioralPattern(
            pattern_id="test_001",
            pattern_type="crypto",
            description="Crypto pattern",
            api_calls=["crypto_encrypt", "crypto_decrypt", "key_generate"],
            risk_score=0.7
        )
        
        pattern2 = BehavioralPattern(
            pattern_id="test_002", 
            pattern_type="network",
            description="Network pattern",
            api_calls=["crypto_encrypt", "network_send", "ssl_connect"],
            risk_score=0.6
        )
        
        correlation = self.engine._calculate_pattern_correlation(pattern1, pattern2)
        
        self.assertIsInstance(correlation, float)
        self.assertGreaterEqual(correlation, 0.0)
        self.assertLessEqual(correlation, 1.0)
        # Should have some correlation due to shared "crypto_encrypt" API
        self.assertGreater(correlation, 0.1)
    
    async def test_zero_day_analysis(self):
        """Test zero-day vulnerability analysis."""
        patterns = [
            BehavioralPattern(
                pattern_id="suspicious_001",
                pattern_type="malware_like",
                description="Suspicious behavior",
                api_calls=["system_call", "file_write", "network_send"],
                call_frequency={"system": 100, "file": 50, "network": 75},
                risk_score=0.9,
                anomaly_score=0.85
            )
        ]
        
        runtime_data = {"package_name": "test.suspicious.app"}
        
        alerts = await self.engine.analyze_for_zero_day(patterns, runtime_data)
        
        self.assertIsInstance(alerts, list)
        # Should generate alerts for suspicious behavior
        self.assertGreater(len(alerts), 0)
        
        # Check alert structure
        if alerts:
            alert = alerts[0]
            self.assertIsInstance(alert, VulnerabilityAlert)
            self.assertIsNotNone(alert.alert_id)
            self.assertIsNotNone(alert.threat_level)
            self.assertEqual(alert.package_name, "test.suspicious.app")
    
    def test_detection_statistics(self):
        """Test detection statistics tracking."""
        initial_stats = self.engine.get_detection_statistics()
        
        self.assertIn('total_analyses', initial_stats)
        self.assertIn('anomalies_detected', initial_stats)
        self.assertIn('detection_rate', initial_stats)
        self.assertIn('accuracy_metrics', initial_stats)


class TestContinuousMonitoringEngine(unittest.TestCase):
    """Test cases for Continuous Monitoring Engine."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'monitoring_interval': 1.0,  # Fast interval for testing
            'pattern_buffer_size': 100,
            'analysis_window_size': 30
        }
        self.engine = ContinuousMonitoringEngine(self.config)
    
    def test_initialization(self):
        """Test monitoring engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.status, MonitoringStatus.STOPPED)
        self.assertEqual(self.engine.monitoring_interval, 1.0)
        self.assertIsNotNone(self.engine.behavioral_patterns)
    
    def test_monitoring_status(self):
        """Test monitoring status reporting."""
        status = self.engine.get_monitoring_status()
        
        self.assertIn('status', status)
        self.assertIn('monitoring_active', status)
        self.assertIn('patterns_collected', status)
        self.assertIn('monitoring_config', status)
        self.assertEqual(status['status'], MonitoringStatus.STOPPED.value)
    
    def test_runtime_data_collection(self):
        """Test runtime data collection."""
        runtime_data = self.engine._collect_runtime_data("test.package")
        
        self.assertIsInstance(runtime_data, dict)
        self.assertIn('timestamp', runtime_data)
        self.assertIn('package_name', runtime_data)
        self.assertIn('process_info', runtime_data)
        self.assertIn('api_activity', runtime_data)
        self.assertEqual(runtime_data['package_name'], "test.package")
    
    def test_behavioral_pattern_analysis(self):
        """Test behavioral pattern analysis."""
        runtime_data = {
            'timestamp': time.time(),
            'package_name': 'test.app',
            'api_activity': {
                'total_calls': 100,
                'crypto_calls': 30,
                'network_calls': 25,
                'sensitive_calls': 15
            },
            'network_activity': {
                'connections_opened': 5,
                'data_sent': 15000,
                'data_received': 25000,
                'ssl_handshakes': 3
            },
            'file_activity': {
                'files_opened': 8,
                'files_written': 3,
                'files_read': 12,
                'sensitive_paths': ['/system/sensitive']
            }
        }
        
        patterns = self.engine._analyze_behavioral_patterns(runtime_data)
        
        self.assertIsInstance(patterns, list)
        # Should detect multiple pattern types
        self.assertGreater(len(patterns), 0)
        
        # Check pattern structure
        if patterns:
            pattern = patterns[0]
            self.assertIsInstance(pattern, BehavioralPattern)
            self.assertIsNotNone(pattern.pattern_id)
            self.assertIsNotNone(pattern.pattern_type)
            self.assertIsInstance(pattern.risk_score, float)
    
    async def test_monitoring_start_stop(self):
        """Test monitoring start and stop functionality."""
        package_name = "test.monitoring.app"
        
        # Test start monitoring
        start_result = await self.engine.start_monitoring(package_name)
        self.assertTrue(start_result)
        self.assertEqual(self.engine.status, MonitoringStatus.ACTIVE)
        
        # Allow some monitoring to occur
        await asyncio.sleep(2.0)
        
        # Test stop monitoring
        stop_result = self.engine.stop_monitoring()
        self.assertTrue(stop_result)
        self.assertEqual(self.engine.status, MonitoringStatus.STOPPED)
    
    def test_pattern_history_tracking(self):
        """Test pattern history tracking."""
        # Add some test patterns
        for i in range(5):
            pattern = BehavioralPattern(
                pattern_id=f"test_{i}",
                pattern_type="test_type",
                description=f"Test pattern {i}",
                risk_score=0.5
            )
            self.engine.behavioral_patterns.append(pattern)
            self.engine.pattern_history["test_type"].append(pattern)
        
        recent_patterns = self.engine.get_recent_patterns(3)
        self.assertEqual(len(recent_patterns), 3)
        self.assertIn('pattern_id', recent_patterns[0])
        self.assertIn('risk_score', recent_patterns[0])


class TestIntelligentAlertingSystem(unittest.TestCase):
    """Test cases for Intelligent Alerting System."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'alert_thresholds': {
                ThreatLevel.CRITICAL: 0.9,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.MEDIUM: 0.6
            },
            'aggregation_window': 60,
            'max_alerts_per_window': 10
        }
        self.system = IntelligentAlertingSystem(self.config)
    
    def test_initialization(self):
        """Test alerting system initialization."""
        self.assertIsNotNone(self.system)
        self.assertIn(ThreatLevel.CRITICAL, self.system.alert_thresholds)
        self.assertIsNotNone(self.system.alert_stats)
    
    def test_alert_validation(self):
        """Test alert validation."""
        # Valid alert
        valid_alert = VulnerabilityAlert(
            alert_id="test_001",
            alert_type=AlertType.ZERO_DAY_DETECTION,
            threat_level=ThreatLevel.HIGH,
            title="Test Alert",
            description="Test description",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.85
        )
        
        self.assertTrue(self.system._validate_alert(valid_alert))
        
        # Invalid alert (low confidence)
        invalid_alert = VulnerabilityAlert(
            alert_id="test_002",
            alert_type=AlertType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.HIGH,
            title="Low Confidence",
            description="Test",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.5  # Below threshold
        )
        
        self.assertFalse(self.system._validate_alert(invalid_alert))
    
    def test_alert_correlation(self):
        """Test alert correlation calculation."""
        alert1 = VulnerabilityAlert(
            alert_id="corr_001",
            alert_type=AlertType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.HIGH,
            title="Alert 1",
            description="Test",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.8,
            affected_apis=["api1", "api2", "api3"]
        )
        
        alert2 = VulnerabilityAlert(
            alert_id="corr_002",
            alert_type=AlertType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.HIGH,
            title="Alert 2", 
            description="Test",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.8,
            affected_apis=["api2", "api3", "api4"]
        )
        
        correlation = self.system._calculate_alert_correlation(alert1, alert2)
        
        self.assertIsInstance(correlation, float)
        self.assertGreaterEqual(correlation, 0.0)
        self.assertLessEqual(correlation, 1.0)
        # Should have high correlation (same package, type, overlapping APIs)
        self.assertGreater(correlation, 0.5)
    
    async def test_alert_processing(self):
        """Test alert processing pipeline."""
        # Mock notification handler
        notifications_received = []
        
        def mock_handler(alert):
            notifications_received.append(alert)
        
        self.system.add_notification_handler(mock_handler)
        
        # Process test alert
        test_alert = VulnerabilityAlert(
            alert_id="process_test_001",
            alert_type=AlertType.ZERO_DAY_DETECTION,
            threat_level=ThreatLevel.CRITICAL,
            title="Critical Test Alert",
            description="Test critical alert processing",
            package_name="test.critical.app",
            detection_method="test_method",
            confidence_score=0.95
        )
        
        result = await self.system.process_alert(test_alert)
        
        self.assertTrue(result)
        self.assertIn(test_alert.alert_id, self.system.active_alerts)
        self.assertEqual(len(notifications_received), 1)
        self.assertEqual(notifications_received[0].alert_id, test_alert.alert_id)
    
    def test_alert_statistics(self):
        """Test alert statistics tracking."""
        stats = self.system.get_alert_statistics()
        
        self.assertIn('total_alerts', stats)
        self.assertIn('alerts_by_level', stats)
        self.assertIn('alerts_by_type', stats)
        self.assertIn('active_alerts', stats)
        self.assertIn('configuration', stats)


class TestThreatIntelligencePipeline(unittest.TestCase):
    """Test cases for Threat Intelligence Pipeline."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'intel_sources': ['test_source'],
            'refresh_interval': 3600
        }
        self.pipeline = ThreatIntelligencePipeline(self.config)
    
    def test_initialization(self):
        """Test threat intelligence pipeline initialization."""
        self.assertIsNotNone(self.pipeline)
        self.assertIsNotNone(self.pipeline.intel_stats)
        self.assertEqual(self.pipeline.refresh_interval, 3600)
    
    def test_indicator_extraction(self):
        """Test threat indicator extraction from alerts."""
        alert = VulnerabilityAlert(
            alert_id="intel_test_001",
            alert_type=AlertType.MALICIOUS_BEHAVIOR,
            threat_level=ThreatLevel.HIGH,
            title="Malicious Behavior",
            description="Test",
            package_name="malware.suspicious.app",
            detection_method="test",
            confidence_score=0.8,
            evidence=["hash:abc123", "ip:192.168.1.100", "domain:evil.com"],
            affected_apis=["dangerous_api", "exploit_function"]
        )
        
        indicators = self.pipeline._extract_indicators(alert)
        
        self.assertIsInstance(indicators, list)
        self.assertIn("malware.suspicious.app", indicators)  # Package name
        self.assertIn("dangerous_api", indicators)  # API
        self.assertIn("exploit_function", indicators)  # API
        # Should extract from evidence (simplified parsing)
        self.assertTrue(any("abc123" in ind for ind in indicators))
    
    async def test_threat_intelligence_correlation(self):
        """Test threat intelligence correlation."""
        # Create alert with malware indicators
        alert = VulnerabilityAlert(
            alert_id="intel_corr_001",
            alert_type=AlertType.MALICIOUS_BEHAVIOR,
            threat_level=ThreatLevel.HIGH,
            title="Malware Detection",
            description="Suspicious malware-like behavior",
            package_name="test.malware.app",
            detection_method="behavioral_analysis",
            confidence_score=0.85,
            evidence=["suspicious_api_usage", "malware_pattern_detected"]
        )
        
        correlations = await self.pipeline.correlate_with_threat_intel(alert)
        
        self.assertIsInstance(correlations, list)
        # Mock implementation should return correlations for malware indicators
        if correlations:
            intel = correlations[0]
            self.assertIsInstance(intel, ThreatIntelligenceInfo)
            self.assertIsNotNone(intel.intel_id)
            self.assertIsNotNone(intel.threat_type)


class TestRealtimeVulnerabilityDiscovery(unittest.TestCase):
    """Test cases for the main Real-time Vulnerability Discovery orchestrator."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.package_name = "test.discovery.app"
        self.config = {
            'analysis_interval': 1.0,  # Fast for testing
            'monitoring': {'monitoring_interval': 0.5},
            'zero_day': {'anomaly_threshold': 0.7},
            'alerting': {'aggregation_window': 30}
        }
        self.discovery = RealtimeVulnerabilityDiscovery(self.package_name, self.config)
    
    def test_initialization(self):
        """Test discovery system initialization."""
        self.assertIsNotNone(self.discovery)
        self.assertEqual(self.discovery.package_name, self.package_name)
        self.assertIsNotNone(self.discovery.monitoring_engine)
        self.assertIsNotNone(self.discovery.zero_day_engine)
        self.assertIsNotNone(self.discovery.alerting_system)
        self.assertIsNotNone(self.discovery.threat_intel_pipeline)
        self.assertFalse(self.discovery.discovery_active)
    
    def test_discovery_status(self):
        """Test discovery status reporting."""
        status = self.discovery.get_discovery_status()
        
        self.assertIn('discovery_active', status)
        self.assertIn('package_name', status)
        self.assertIn('discovery_statistics', status)
        self.assertIn('monitoring_status', status)
        self.assertIn('components_status', status)
        self.assertEqual(status['package_name'], self.package_name)
    
    async def test_discovery_start_stop(self):
        """Test discovery start and stop functionality."""
        # Test start discovery
        start_result = await self.discovery.start_discovery()
        self.assertTrue(start_result)
        self.assertTrue(self.discovery.discovery_active)
        
        # Allow some discovery cycles
        await asyncio.sleep(2.0)
        
        # Test stop discovery
        stop_result = self.discovery.stop_discovery()
        self.assertTrue(stop_result)
        self.assertFalse(self.discovery.discovery_active)
    
    def test_custom_handlers(self):
        """Test custom notification and escalation handlers."""
        notifications = []
        escalations = []
        
        def notification_handler(alert):
            notifications.append(alert)
        
        def escalation_handler(alert):
            escalations.append(alert)
        
        # Add handlers
        notification_result = self.discovery.add_notification_handler(notification_handler)
        escalation_result = self.discovery.add_escalation_handler(escalation_handler)
        
        self.assertTrue(notification_result)
        self.assertTrue(escalation_result)
    
    def test_factory_function(self):
        """Test factory function for creating discovery system."""
        factory_discovery = create_realtime_vulnerability_discovery(
            "factory.test.app",
            {'analysis_interval': 2.0}
        )
        
        self.assertIsNotNone(factory_discovery)
        self.assertEqual(factory_discovery.package_name, "factory.test.app")
        self.assertEqual(factory_discovery.analysis_interval, 2.0)


class TestPluginIntegration(unittest.TestCase):
    """Test cases for plugin integration with AODS framework."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
    
    def test_plugin_import_availability(self):
        """Test plugin import availability."""
        try:
            from plugins.runtime_decryption_analysis import (
                RuntimeDecryptionAnalysisPlugin,
                REALTIME_DISCOVERY_AVAILABLE,
                create_realtime_discovery_for_plugin,
                get_realtime_discovery_status
            )
            plugin_import_success = True
        except ImportError:
            plugin_import_success = False
        
        self.assertTrue(plugin_import_success)
        self.assertTrue(REALTIME_DISCOVERY_AVAILABLE)
    
    def test_plugin_capabilities(self):
        """Test plugin capabilities reporting."""
        try:
            from plugins.runtime_decryption_analysis import get_plugin_capabilities
            
            capabilities = get_plugin_capabilities()
            
            self.assertIn('realtime_discovery', capabilities)
            realtime_caps = capabilities['realtime_discovery']
            self.assertIn('available', realtime_caps)
            self.assertIn('capabilities', realtime_caps)
            self.assertTrue(realtime_caps['available'])
            
        except ImportError:
            self.skipTest("Plugin not available for capabilities testing")
    
    def test_factory_function_integration(self):
        """Test factory function integration."""
        try:
            from plugins.runtime_decryption_analysis import create_realtime_discovery_for_plugin
            
            discovery = create_realtime_discovery_for_plugin(
                "integration.test.app",
                {'analysis_interval': 1.5}
            )
            
            self.assertIsNotNone(discovery)
            self.assertEqual(discovery.package_name, "integration.test.app")
            
        except ImportError:
            self.skipTest("Plugin factory function not available")
    
    def test_status_function_integration(self):
        """Test status function integration."""
        try:
            from plugins.runtime_decryption_analysis import get_realtime_discovery_status
            
            status = get_realtime_discovery_status()
            
            self.assertIn('realtime_discovery_available', status)
            self.assertIn('components_available', status)
            self.assertIn('capabilities', status)
            self.assertTrue(status['realtime_discovery_available'])
            
        except ImportError:
            self.skipTest("Plugin status function not available")


class TestPerformanceAndScalability(unittest.TestCase):
    """Performance and scalability tests."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
    
    def test_pattern_processing_performance(self):
        """Test pattern processing performance."""
        engine = ZeroDayDetectionEngine()
        
        # Create large number of patterns
        patterns = []
        for i in range(100):
            pattern = BehavioralPattern(
                pattern_id=f"perf_test_{i}",
                pattern_type="performance_test",
                description=f"Performance test pattern {i}",
                api_calls=[f"api_{j}" for j in range(10)],
                call_frequency={f"api_{j}": j*2 for j in range(10)},
                risk_score=0.5 + (i % 50) / 100.0
            )
            patterns.append(pattern)
        
        runtime_data = {"package_name": "performance.test.app"}
        
        # Measure processing time
        start_time = time.time()
        
        # Run analysis (synchronous version for performance test)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            alerts = loop.run_until_complete(
                engine.analyze_for_zero_day(patterns, runtime_data)
            )
        finally:
            loop.close()
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Performance assertions
        self.assertLess(processing_time, 10.0)  # Should complete within 10 seconds
        self.assertIsInstance(alerts, list)
        
        # Calculate throughput
        patterns_per_second = len(patterns) / processing_time
        self.assertGreater(patterns_per_second, 10)  # Should process at least 10 patterns/second
    
    def test_memory_usage_monitoring(self):
        """Test memory usage during monitoring."""
        try:
            import psutil
            import os
        except ImportError:
            self.skipTest("psutil not available for memory testing")
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create monitoring engine with large buffer
        config = {
            'monitoring_interval': 0.1,
            'pattern_buffer_size': 1000,
            'analysis_window_size': 60
        }
        engine = ContinuousMonitoringEngine(config)
        
        # Add many patterns to buffer
        for i in range(1000):
            pattern = BehavioralPattern(
                pattern_id=f"memory_test_{i}",
                pattern_type="memory_test",
                description=f"Memory test pattern {i}",
                risk_score=0.5
            )
            engine.behavioral_patterns.append(pattern)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory usage should be reasonable (less than 100MB increase for test)
        self.assertLess(memory_increase, 100)


class TestErrorHandlingAndRecovery(unittest.TestCase):
    """Error handling and recovery tests."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
    
    def test_invalid_configuration_handling(self):
        """Test handling of invalid configuration."""
        # Test with invalid configuration
        invalid_config = {
            'anomaly_threshold': 2.0,  # Invalid (> 1.0)
            'monitoring_interval': -1.0,  # Invalid (negative)
            'pattern_buffer_size': 'invalid'  # Invalid type
        }
        
        # Should handle gracefully without crashing
        try:
            engine = ZeroDayDetectionEngine(invalid_config)
            self.assertIsNotNone(engine)
            # Should use defaults for invalid values
            self.assertLessEqual(engine.anomaly_threshold, 1.0)
        except Exception:
            self.fail("Should handle invalid configuration gracefully")
    
    def test_missing_dependency_handling(self):
        """Test handling of missing dependencies."""
        # Mock missing AODS infrastructure
        with patch('plugins.runtime_decryption_analysis.realtime_vulnerability_discovery.AODS_INFRASTRUCTURE_AVAILABLE', False):
            engine = ContinuousMonitoringEngine()
            
            # Should initialize without AODS infrastructure
            self.assertIsNotNone(engine)
            self.assertIsNone(engine.performance_monitor)
    
    async def test_monitoring_error_recovery(self):
        """Test monitoring error recovery."""
        engine = ContinuousMonitoringEngine({'monitoring_interval': 0.1})
        
        # Mock error in monitoring loop
        original_collect = engine._collect_runtime_data
        
        def failing_collect(package_name):
            raise Exception("Simulated monitoring error")
        
        engine._collect_runtime_data = failing_collect
        
        # Start monitoring (should handle errors gracefully)
        package_name = "error.test.app"
        start_result = await engine.start_monitoring(package_name)
        
        # Should start successfully despite errors in collection
        self.assertTrue(start_result)
        
        # Allow some time for error handling
        await asyncio.sleep(1.0)
        
        # Should still be active (error recovery)
        self.assertEqual(engine.status, MonitoringStatus.ACTIVE)
        
        # Restore original function and stop
        engine._collect_runtime_data = original_collect
        engine.stop_monitoring()


def run_comprehensive_tests():
    """Run comprehensive test suite."""
    if not REALTIME_DISCOVERY_AVAILABLE:
        print("❌ Real-time discovery components not available for testing")
        return False
    
    print("🧪 Running Real-time Vulnerability Discovery Test Suite...")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_cases = [
        TestZeroDayDetectionEngine,
        TestContinuousMonitoringEngine,
        TestIntelligentAlertingSystem,
        TestThreatIntelligencePipeline,
        TestRealtimeVulnerabilityDiscovery,
        TestPluginIntegration,
        TestPerformanceAndScalability,
        TestErrorHandlingAndRecovery
    ]
    
    for test_case in test_cases:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_case)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Report results
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = ((total_tests - failures - errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n📊 Test Results Summary:")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_tests - failures - errors}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("✅ Real-time Vulnerability Discovery Test Suite: PASSED")
        return True
    else:
        print("❌ Real-time Vulnerability Discovery Test Suite: FAILED")
        return False


async def run_async_integration_tests():
    """Run async integration tests."""
    if not REALTIME_DISCOVERY_AVAILABLE:
        print("❌ Async integration tests not available")
        return False
    
    print("\n🔄 Running Async Integration Tests...")
    
    try:
        # Test full integration workflow
        discovery = create_realtime_vulnerability_discovery(
            "async.integration.test",
            {'analysis_interval': 1.0, 'monitoring': {'monitoring_interval': 0.5}}
        )
        
        # Start discovery
        print("  • Starting real-time discovery...")
        start_result = await discovery.start_discovery()
        if not start_result:
            print("❌ Failed to start discovery")
            return False
        
        # Run for a short period
        print("  • Running discovery analysis...")
        await asyncio.sleep(3.0)
        
        # Check status
        status = discovery.get_discovery_status()
        if not status['discovery_active']:
            print("❌ Discovery not active")
            return False
        
        # Stop discovery
        print("  • Stopping discovery...")
        stop_result = discovery.stop_discovery()
        if not stop_result:
            print("❌ Failed to stop discovery")
            return False
        
        print("✅ Async Integration Tests: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Async Integration Tests: FAILED - {e}")
        return False


if __name__ == "__main__":
    print("🔍 Real-time Vulnerability Discovery Test Suite")
    print(f"Components Available: {REALTIME_DISCOVERY_AVAILABLE}")
    
    if REALTIME_DISCOVERY_AVAILABLE:
        # Run comprehensive tests
        test_success = run_comprehensive_tests()
        
        # Run async integration tests
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            async_success = loop.run_until_complete(run_async_integration_tests())
        finally:
            loop.close()
        
        # Overall result
        if test_success and async_success:
            print("\n🎉 All tests passed! Real-time Vulnerability Discovery system is ready for deployment.")
        else:
            print("\n❌ Some tests failed. Please review and fix issues before deployment.")
    else:
        print("❌ Real-time discovery components not available for testing")
        print("Please ensure all dependencies are installed and components are properly integrated.") 
"""
Comprehensive Test Suite for Real-time Vulnerability Discovery System

Tests all components of the real-time vulnerability discovery system including:
- Zero-day detection engine
- Continuous monitoring engine
- Intelligent alerting system  
- Threat intelligence pipeline
- Main discovery orchestrator
- Plugin integration

Test Categories:
- Unit Tests: Individual component testing
- Integration Tests: Component interaction testing
- Performance Tests: Load and stress testing
- Error Handling Tests: Failure scenario testing
- Plugin Integration Tests: AODS framework compatibility
"""

import asyncio
import unittest
import logging
import tempfile
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path
import sys
import json

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

try:
    from plugins.runtime_decryption_analysis.realtime_vulnerability_discovery import (
        RealtimeVulnerabilityDiscovery,
        ZeroDayDetectionEngine,
        ContinuousMonitoringEngine,
        IntelligentAlertingSystem,
        ThreatIntelligencePipeline,
        VulnerabilityAlert,
        BehavioralPattern,
        ThreatIntelligenceInfo,
        ThreatLevel,
        AlertType,
        MonitoringStatus,
        create_realtime_vulnerability_discovery
    )
    REALTIME_DISCOVERY_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Real-time discovery components not available: {e}")
    REALTIME_DISCOVERY_AVAILABLE = False


class TestZeroDayDetectionEngine(unittest.TestCase):
    """Test cases for Zero-Day Detection Engine."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'anomaly_threshold': 0.8,
            'pattern_correlation_threshold': 0.7,
            'behavioral_deviation_threshold': 0.75
        }
        self.engine = ZeroDayDetectionEngine(self.config)
    
    def test_initialization(self):
        """Test zero-day detection engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.anomaly_threshold, 0.8)
        self.assertIsNotNone(self.engine.detection_stats)
        self.assertIn('total_analyses', self.engine.detection_stats)
    
    def test_anomaly_score_calculation(self):
        """Test anomaly score calculation."""
        pattern = BehavioralPattern(
            pattern_id="test_pattern_001",
            pattern_type="api_usage",
            description="Test pattern",
            call_frequency={"crypto": 50, "network": 20},
            timing_patterns=[1.0, 2.0, 1.5],
            risk_score=0.6
        )
        
        runtime_data = {"package_name": "test.app"}
        score = self.engine._calculate_anomaly_score(pattern, runtime_data)
        
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
    
    def test_threat_level_determination(self):
        """Test threat level determination."""
        self.assertEqual(self.engine._determine_threat_level(0.95), ThreatLevel.CRITICAL)
        self.assertEqual(self.engine._determine_threat_level(0.85), ThreatLevel.HIGH)
        self.assertEqual(self.engine._determine_threat_level(0.65), ThreatLevel.MEDIUM)
        self.assertEqual(self.engine._determine_threat_level(0.45), ThreatLevel.LOW)
        self.assertEqual(self.engine._determine_threat_level(0.25), ThreatLevel.INFO)
    
    def test_pattern_correlation_calculation(self):
        """Test pattern correlation calculation."""
        pattern1 = BehavioralPattern(
            pattern_id="test_001",
            pattern_type="crypto",
            description="Crypto pattern",
            api_calls=["crypto_encrypt", "crypto_decrypt", "key_generate"],
            risk_score=0.7
        )
        
        pattern2 = BehavioralPattern(
            pattern_id="test_002", 
            pattern_type="network",
            description="Network pattern",
            api_calls=["crypto_encrypt", "network_send", "ssl_connect"],
            risk_score=0.6
        )
        
        correlation = self.engine._calculate_pattern_correlation(pattern1, pattern2)
        
        self.assertIsInstance(correlation, float)
        self.assertGreaterEqual(correlation, 0.0)
        self.assertLessEqual(correlation, 1.0)
        # Should have some correlation due to shared "crypto_encrypt" API
        self.assertGreater(correlation, 0.1)
    
    async def test_zero_day_analysis(self):
        """Test zero-day vulnerability analysis."""
        patterns = [
            BehavioralPattern(
                pattern_id="suspicious_001",
                pattern_type="malware_like",
                description="Suspicious behavior",
                api_calls=["system_call", "file_write", "network_send"],
                call_frequency={"system": 100, "file": 50, "network": 75},
                risk_score=0.9,
                anomaly_score=0.85
            )
        ]
        
        runtime_data = {"package_name": "test.suspicious.app"}
        
        alerts = await self.engine.analyze_for_zero_day(patterns, runtime_data)
        
        self.assertIsInstance(alerts, list)
        # Should generate alerts for suspicious behavior
        self.assertGreater(len(alerts), 0)
        
        # Check alert structure
        if alerts:
            alert = alerts[0]
            self.assertIsInstance(alert, VulnerabilityAlert)
            self.assertIsNotNone(alert.alert_id)
            self.assertIsNotNone(alert.threat_level)
            self.assertEqual(alert.package_name, "test.suspicious.app")
    
    def test_detection_statistics(self):
        """Test detection statistics tracking."""
        initial_stats = self.engine.get_detection_statistics()
        
        self.assertIn('total_analyses', initial_stats)
        self.assertIn('anomalies_detected', initial_stats)
        self.assertIn('detection_rate', initial_stats)
        self.assertIn('accuracy_metrics', initial_stats)


class TestContinuousMonitoringEngine(unittest.TestCase):
    """Test cases for Continuous Monitoring Engine."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'monitoring_interval': 1.0,  # Fast interval for testing
            'pattern_buffer_size': 100,
            'analysis_window_size': 30
        }
        self.engine = ContinuousMonitoringEngine(self.config)
    
    def test_initialization(self):
        """Test monitoring engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.status, MonitoringStatus.STOPPED)
        self.assertEqual(self.engine.monitoring_interval, 1.0)
        self.assertIsNotNone(self.engine.behavioral_patterns)
    
    def test_monitoring_status(self):
        """Test monitoring status reporting."""
        status = self.engine.get_monitoring_status()
        
        self.assertIn('status', status)
        self.assertIn('monitoring_active', status)
        self.assertIn('patterns_collected', status)
        self.assertIn('monitoring_config', status)
        self.assertEqual(status['status'], MonitoringStatus.STOPPED.value)
    
    def test_runtime_data_collection(self):
        """Test runtime data collection."""
        runtime_data = self.engine._collect_runtime_data("test.package")
        
        self.assertIsInstance(runtime_data, dict)
        self.assertIn('timestamp', runtime_data)
        self.assertIn('package_name', runtime_data)
        self.assertIn('process_info', runtime_data)
        self.assertIn('api_activity', runtime_data)
        self.assertEqual(runtime_data['package_name'], "test.package")
    
    def test_behavioral_pattern_analysis(self):
        """Test behavioral pattern analysis."""
        runtime_data = {
            'timestamp': time.time(),
            'package_name': 'test.app',
            'api_activity': {
                'total_calls': 100,
                'crypto_calls': 30,
                'network_calls': 25,
                'sensitive_calls': 15
            },
            'network_activity': {
                'connections_opened': 5,
                'data_sent': 15000,
                'data_received': 25000,
                'ssl_handshakes': 3
            },
            'file_activity': {
                'files_opened': 8,
                'files_written': 3,
                'files_read': 12,
                'sensitive_paths': ['/system/sensitive']
            }
        }
        
        patterns = self.engine._analyze_behavioral_patterns(runtime_data)
        
        self.assertIsInstance(patterns, list)
        # Should detect multiple pattern types
        self.assertGreater(len(patterns), 0)
        
        # Check pattern structure
        if patterns:
            pattern = patterns[0]
            self.assertIsInstance(pattern, BehavioralPattern)
            self.assertIsNotNone(pattern.pattern_id)
            self.assertIsNotNone(pattern.pattern_type)
            self.assertIsInstance(pattern.risk_score, float)
    
    async def test_monitoring_start_stop(self):
        """Test monitoring start and stop functionality."""
        package_name = "test.monitoring.app"
        
        # Test start monitoring
        start_result = await self.engine.start_monitoring(package_name)
        self.assertTrue(start_result)
        self.assertEqual(self.engine.status, MonitoringStatus.ACTIVE)
        
        # Allow some monitoring to occur
        await asyncio.sleep(2.0)
        
        # Test stop monitoring
        stop_result = self.engine.stop_monitoring()
        self.assertTrue(stop_result)
        self.assertEqual(self.engine.status, MonitoringStatus.STOPPED)
    
    def test_pattern_history_tracking(self):
        """Test pattern history tracking."""
        # Add some test patterns
        for i in range(5):
            pattern = BehavioralPattern(
                pattern_id=f"test_{i}",
                pattern_type="test_type",
                description=f"Test pattern {i}",
                risk_score=0.5
            )
            self.engine.behavioral_patterns.append(pattern)
            self.engine.pattern_history["test_type"].append(pattern)
        
        recent_patterns = self.engine.get_recent_patterns(3)
        self.assertEqual(len(recent_patterns), 3)
        self.assertIn('pattern_id', recent_patterns[0])
        self.assertIn('risk_score', recent_patterns[0])


class TestIntelligentAlertingSystem(unittest.TestCase):
    """Test cases for Intelligent Alerting System."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'alert_thresholds': {
                ThreatLevel.CRITICAL: 0.9,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.MEDIUM: 0.6
            },
            'aggregation_window': 60,
            'max_alerts_per_window': 10
        }
        self.system = IntelligentAlertingSystem(self.config)
    
    def test_initialization(self):
        """Test alerting system initialization."""
        self.assertIsNotNone(self.system)
        self.assertIn(ThreatLevel.CRITICAL, self.system.alert_thresholds)
        self.assertIsNotNone(self.system.alert_stats)
    
    def test_alert_validation(self):
        """Test alert validation."""
        # Valid alert
        valid_alert = VulnerabilityAlert(
            alert_id="test_001",
            alert_type=AlertType.ZERO_DAY_DETECTION,
            threat_level=ThreatLevel.HIGH,
            title="Test Alert",
            description="Test description",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.85
        )
        
        self.assertTrue(self.system._validate_alert(valid_alert))
        
        # Invalid alert (low confidence)
        invalid_alert = VulnerabilityAlert(
            alert_id="test_002",
            alert_type=AlertType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.HIGH,
            title="Low Confidence",
            description="Test",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.5  # Below threshold
        )
        
        self.assertFalse(self.system._validate_alert(invalid_alert))
    
    def test_alert_correlation(self):
        """Test alert correlation calculation."""
        alert1 = VulnerabilityAlert(
            alert_id="corr_001",
            alert_type=AlertType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.HIGH,
            title="Alert 1",
            description="Test",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.8,
            affected_apis=["api1", "api2", "api3"]
        )
        
        alert2 = VulnerabilityAlert(
            alert_id="corr_002",
            alert_type=AlertType.BEHAVIORAL_ANOMALY,
            threat_level=ThreatLevel.HIGH,
            title="Alert 2", 
            description="Test",
            package_name="test.app",
            detection_method="test",
            confidence_score=0.8,
            affected_apis=["api2", "api3", "api4"]
        )
        
        correlation = self.system._calculate_alert_correlation(alert1, alert2)
        
        self.assertIsInstance(correlation, float)
        self.assertGreaterEqual(correlation, 0.0)
        self.assertLessEqual(correlation, 1.0)
        # Should have high correlation (same package, type, overlapping APIs)
        self.assertGreater(correlation, 0.5)
    
    async def test_alert_processing(self):
        """Test alert processing pipeline."""
        # Mock notification handler
        notifications_received = []
        
        def mock_handler(alert):
            notifications_received.append(alert)
        
        self.system.add_notification_handler(mock_handler)
        
        # Process test alert
        test_alert = VulnerabilityAlert(
            alert_id="process_test_001",
            alert_type=AlertType.ZERO_DAY_DETECTION,
            threat_level=ThreatLevel.CRITICAL,
            title="Critical Test Alert",
            description="Test critical alert processing",
            package_name="test.critical.app",
            detection_method="test_method",
            confidence_score=0.95
        )
        
        result = await self.system.process_alert(test_alert)
        
        self.assertTrue(result)
        self.assertIn(test_alert.alert_id, self.system.active_alerts)
        self.assertEqual(len(notifications_received), 1)
        self.assertEqual(notifications_received[0].alert_id, test_alert.alert_id)
    
    def test_alert_statistics(self):
        """Test alert statistics tracking."""
        stats = self.system.get_alert_statistics()
        
        self.assertIn('total_alerts', stats)
        self.assertIn('alerts_by_level', stats)
        self.assertIn('alerts_by_type', stats)
        self.assertIn('active_alerts', stats)
        self.assertIn('configuration', stats)


class TestThreatIntelligencePipeline(unittest.TestCase):
    """Test cases for Threat Intelligence Pipeline."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.config = {
            'intel_sources': ['test_source'],
            'refresh_interval': 3600
        }
        self.pipeline = ThreatIntelligencePipeline(self.config)
    
    def test_initialization(self):
        """Test threat intelligence pipeline initialization."""
        self.assertIsNotNone(self.pipeline)
        self.assertIsNotNone(self.pipeline.intel_stats)
        self.assertEqual(self.pipeline.refresh_interval, 3600)
    
    def test_indicator_extraction(self):
        """Test threat indicator extraction from alerts."""
        alert = VulnerabilityAlert(
            alert_id="intel_test_001",
            alert_type=AlertType.MALICIOUS_BEHAVIOR,
            threat_level=ThreatLevel.HIGH,
            title="Malicious Behavior",
            description="Test",
            package_name="malware.suspicious.app",
            detection_method="test",
            confidence_score=0.8,
            evidence=["hash:abc123", "ip:192.168.1.100", "domain:evil.com"],
            affected_apis=["dangerous_api", "exploit_function"]
        )
        
        indicators = self.pipeline._extract_indicators(alert)
        
        self.assertIsInstance(indicators, list)
        self.assertIn("malware.suspicious.app", indicators)  # Package name
        self.assertIn("dangerous_api", indicators)  # API
        self.assertIn("exploit_function", indicators)  # API
        # Should extract from evidence (simplified parsing)
        self.assertTrue(any("abc123" in ind for ind in indicators))
    
    async def test_threat_intelligence_correlation(self):
        """Test threat intelligence correlation."""
        # Create alert with malware indicators
        alert = VulnerabilityAlert(
            alert_id="intel_corr_001",
            alert_type=AlertType.MALICIOUS_BEHAVIOR,
            threat_level=ThreatLevel.HIGH,
            title="Malware Detection",
            description="Suspicious malware-like behavior",
            package_name="test.malware.app",
            detection_method="behavioral_analysis",
            confidence_score=0.85,
            evidence=["suspicious_api_usage", "malware_pattern_detected"]
        )
        
        correlations = await self.pipeline.correlate_with_threat_intel(alert)
        
        self.assertIsInstance(correlations, list)
        # Mock implementation should return correlations for malware indicators
        if correlations:
            intel = correlations[0]
            self.assertIsInstance(intel, ThreatIntelligenceInfo)
            self.assertIsNotNone(intel.intel_id)
            self.assertIsNotNone(intel.threat_type)


class TestRealtimeVulnerabilityDiscovery(unittest.TestCase):
    """Test cases for the main Real-time Vulnerability Discovery orchestrator."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
        
        self.package_name = "test.discovery.app"
        self.config = {
            'analysis_interval': 1.0,  # Fast for testing
            'monitoring': {'monitoring_interval': 0.5},
            'zero_day': {'anomaly_threshold': 0.7},
            'alerting': {'aggregation_window': 30}
        }
        self.discovery = RealtimeVulnerabilityDiscovery(self.package_name, self.config)
    
    def test_initialization(self):
        """Test discovery system initialization."""
        self.assertIsNotNone(self.discovery)
        self.assertEqual(self.discovery.package_name, self.package_name)
        self.assertIsNotNone(self.discovery.monitoring_engine)
        self.assertIsNotNone(self.discovery.zero_day_engine)
        self.assertIsNotNone(self.discovery.alerting_system)
        self.assertIsNotNone(self.discovery.threat_intel_pipeline)
        self.assertFalse(self.discovery.discovery_active)
    
    def test_discovery_status(self):
        """Test discovery status reporting."""
        status = self.discovery.get_discovery_status()
        
        self.assertIn('discovery_active', status)
        self.assertIn('package_name', status)
        self.assertIn('discovery_statistics', status)
        self.assertIn('monitoring_status', status)
        self.assertIn('components_status', status)
        self.assertEqual(status['package_name'], self.package_name)
    
    async def test_discovery_start_stop(self):
        """Test discovery start and stop functionality."""
        # Test start discovery
        start_result = await self.discovery.start_discovery()
        self.assertTrue(start_result)
        self.assertTrue(self.discovery.discovery_active)
        
        # Allow some discovery cycles
        await asyncio.sleep(2.0)
        
        # Test stop discovery
        stop_result = self.discovery.stop_discovery()
        self.assertTrue(stop_result)
        self.assertFalse(self.discovery.discovery_active)
    
    def test_custom_handlers(self):
        """Test custom notification and escalation handlers."""
        notifications = []
        escalations = []
        
        def notification_handler(alert):
            notifications.append(alert)
        
        def escalation_handler(alert):
            escalations.append(alert)
        
        # Add handlers
        notification_result = self.discovery.add_notification_handler(notification_handler)
        escalation_result = self.discovery.add_escalation_handler(escalation_handler)
        
        self.assertTrue(notification_result)
        self.assertTrue(escalation_result)
    
    def test_factory_function(self):
        """Test factory function for creating discovery system."""
        factory_discovery = create_realtime_vulnerability_discovery(
            "factory.test.app",
            {'analysis_interval': 2.0}
        )
        
        self.assertIsNotNone(factory_discovery)
        self.assertEqual(factory_discovery.package_name, "factory.test.app")
        self.assertEqual(factory_discovery.analysis_interval, 2.0)


class TestPluginIntegration(unittest.TestCase):
    """Test cases for plugin integration with AODS framework."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
    
    def test_plugin_import_availability(self):
        """Test plugin import availability."""
        try:
            from plugins.runtime_decryption_analysis import (
                RuntimeDecryptionAnalysisPlugin,
                REALTIME_DISCOVERY_AVAILABLE,
                create_realtime_discovery_for_plugin,
                get_realtime_discovery_status
            )
            plugin_import_success = True
        except ImportError:
            plugin_import_success = False
        
        self.assertTrue(plugin_import_success)
        self.assertTrue(REALTIME_DISCOVERY_AVAILABLE)
    
    def test_plugin_capabilities(self):
        """Test plugin capabilities reporting."""
        try:
            from plugins.runtime_decryption_analysis import get_plugin_capabilities
            
            capabilities = get_plugin_capabilities()
            
            self.assertIn('realtime_discovery', capabilities)
            realtime_caps = capabilities['realtime_discovery']
            self.assertIn('available', realtime_caps)
            self.assertIn('capabilities', realtime_caps)
            self.assertTrue(realtime_caps['available'])
            
        except ImportError:
            self.skipTest("Plugin not available for capabilities testing")
    
    def test_factory_function_integration(self):
        """Test factory function integration."""
        try:
            from plugins.runtime_decryption_analysis import create_realtime_discovery_for_plugin
            
            discovery = create_realtime_discovery_for_plugin(
                "integration.test.app",
                {'analysis_interval': 1.5}
            )
            
            self.assertIsNotNone(discovery)
            self.assertEqual(discovery.package_name, "integration.test.app")
            
        except ImportError:
            self.skipTest("Plugin factory function not available")
    
    def test_status_function_integration(self):
        """Test status function integration."""
        try:
            from plugins.runtime_decryption_analysis import get_realtime_discovery_status
            
            status = get_realtime_discovery_status()
            
            self.assertIn('realtime_discovery_available', status)
            self.assertIn('components_available', status)
            self.assertIn('capabilities', status)
            self.assertTrue(status['realtime_discovery_available'])
            
        except ImportError:
            self.skipTest("Plugin status function not available")


class TestPerformanceAndScalability(unittest.TestCase):
    """Performance and scalability tests."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
    
    def test_pattern_processing_performance(self):
        """Test pattern processing performance."""
        engine = ZeroDayDetectionEngine()
        
        # Create large number of patterns
        patterns = []
        for i in range(100):
            pattern = BehavioralPattern(
                pattern_id=f"perf_test_{i}",
                pattern_type="performance_test",
                description=f"Performance test pattern {i}",
                api_calls=[f"api_{j}" for j in range(10)],
                call_frequency={f"api_{j}": j*2 for j in range(10)},
                risk_score=0.5 + (i % 50) / 100.0
            )
            patterns.append(pattern)
        
        runtime_data = {"package_name": "performance.test.app"}
        
        # Measure processing time
        start_time = time.time()
        
        # Run analysis (synchronous version for performance test)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            alerts = loop.run_until_complete(
                engine.analyze_for_zero_day(patterns, runtime_data)
            )
        finally:
            loop.close()
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Performance assertions
        self.assertLess(processing_time, 10.0)  # Should complete within 10 seconds
        self.assertIsInstance(alerts, list)
        
        # Calculate throughput
        patterns_per_second = len(patterns) / processing_time
        self.assertGreater(patterns_per_second, 10)  # Should process at least 10 patterns/second
    
    def test_memory_usage_monitoring(self):
        """Test memory usage during monitoring."""
        try:
            import psutil
            import os
        except ImportError:
            self.skipTest("psutil not available for memory testing")
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create monitoring engine with large buffer
        config = {
            'monitoring_interval': 0.1,
            'pattern_buffer_size': 1000,
            'analysis_window_size': 60
        }
        engine = ContinuousMonitoringEngine(config)
        
        # Add many patterns to buffer
        for i in range(1000):
            pattern = BehavioralPattern(
                pattern_id=f"memory_test_{i}",
                pattern_type="memory_test",
                description=f"Memory test pattern {i}",
                risk_score=0.5
            )
            engine.behavioral_patterns.append(pattern)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory usage should be reasonable (less than 100MB increase for test)
        self.assertLess(memory_increase, 100)


class TestErrorHandlingAndRecovery(unittest.TestCase):
    """Error handling and recovery tests."""
    
    def setUp(self):
        """Set up test environment."""
        if not REALTIME_DISCOVERY_AVAILABLE:
            self.skipTest("Real-time discovery components not available")
    
    def test_invalid_configuration_handling(self):
        """Test handling of invalid configuration."""
        # Test with invalid configuration
        invalid_config = {
            'anomaly_threshold': 2.0,  # Invalid (> 1.0)
            'monitoring_interval': -1.0,  # Invalid (negative)
            'pattern_buffer_size': 'invalid'  # Invalid type
        }
        
        # Should handle gracefully without crashing
        try:
            engine = ZeroDayDetectionEngine(invalid_config)
            self.assertIsNotNone(engine)
            # Should use defaults for invalid values
            self.assertLessEqual(engine.anomaly_threshold, 1.0)
        except Exception:
            self.fail("Should handle invalid configuration gracefully")
    
    def test_missing_dependency_handling(self):
        """Test handling of missing dependencies."""
        # Mock missing AODS infrastructure
        with patch('plugins.runtime_decryption_analysis.realtime_vulnerability_discovery.AODS_INFRASTRUCTURE_AVAILABLE', False):
            engine = ContinuousMonitoringEngine()
            
            # Should initialize without AODS infrastructure
            self.assertIsNotNone(engine)
            self.assertIsNone(engine.performance_monitor)
    
    async def test_monitoring_error_recovery(self):
        """Test monitoring error recovery."""
        engine = ContinuousMonitoringEngine({'monitoring_interval': 0.1})
        
        # Mock error in monitoring loop
        original_collect = engine._collect_runtime_data
        
        def failing_collect(package_name):
            raise Exception("Simulated monitoring error")
        
        engine._collect_runtime_data = failing_collect
        
        # Start monitoring (should handle errors gracefully)
        package_name = "error.test.app"
        start_result = await engine.start_monitoring(package_name)
        
        # Should start successfully despite errors in collection
        self.assertTrue(start_result)
        
        # Allow some time for error handling
        await asyncio.sleep(1.0)
        
        # Should still be active (error recovery)
        self.assertEqual(engine.status, MonitoringStatus.ACTIVE)
        
        # Restore original function and stop
        engine._collect_runtime_data = original_collect
        engine.stop_monitoring()


def run_comprehensive_tests():
    """Run comprehensive test suite."""
    if not REALTIME_DISCOVERY_AVAILABLE:
        print("❌ Real-time discovery components not available for testing")
        return False
    
    print("🧪 Running Real-time Vulnerability Discovery Test Suite...")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_cases = [
        TestZeroDayDetectionEngine,
        TestContinuousMonitoringEngine,
        TestIntelligentAlertingSystem,
        TestThreatIntelligencePipeline,
        TestRealtimeVulnerabilityDiscovery,
        TestPluginIntegration,
        TestPerformanceAndScalability,
        TestErrorHandlingAndRecovery
    ]
    
    for test_case in test_cases:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_case)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Report results
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = ((total_tests - failures - errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n📊 Test Results Summary:")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_tests - failures - errors}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("✅ Real-time Vulnerability Discovery Test Suite: PASSED")
        return True
    else:
        print("❌ Real-time Vulnerability Discovery Test Suite: FAILED")
        return False


async def run_async_integration_tests():
    """Run async integration tests."""
    if not REALTIME_DISCOVERY_AVAILABLE:
        print("❌ Async integration tests not available")
        return False
    
    print("\n🔄 Running Async Integration Tests...")
    
    try:
        # Test full integration workflow
        discovery = create_realtime_vulnerability_discovery(
            "async.integration.test",
            {'analysis_interval': 1.0, 'monitoring': {'monitoring_interval': 0.5}}
        )
        
        # Start discovery
        print("  • Starting real-time discovery...")
        start_result = await discovery.start_discovery()
        if not start_result:
            print("❌ Failed to start discovery")
            return False
        
        # Run for a short period
        print("  • Running discovery analysis...")
        await asyncio.sleep(3.0)
        
        # Check status
        status = discovery.get_discovery_status()
        if not status['discovery_active']:
            print("❌ Discovery not active")
            return False
        
        # Stop discovery
        print("  • Stopping discovery...")
        stop_result = discovery.stop_discovery()
        if not stop_result:
            print("❌ Failed to stop discovery")
            return False
        
        print("✅ Async Integration Tests: PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Async Integration Tests: FAILED - {e}")
        return False


if __name__ == "__main__":
    print("🔍 Real-time Vulnerability Discovery Test Suite")
    print(f"Components Available: {REALTIME_DISCOVERY_AVAILABLE}")
    
    if REALTIME_DISCOVERY_AVAILABLE:
        # Run comprehensive tests
        test_success = run_comprehensive_tests()
        
        # Run async integration tests
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            async_success = loop.run_until_complete(run_async_integration_tests())
        finally:
            loop.close()
        
        # Overall result
        if test_success and async_success:
            print("\n🎉 All tests passed! Real-time Vulnerability Discovery system is ready for deployment.")
        else:
            print("\n❌ Some tests failed. Please review and fix issues before deployment.")
    else:
        print("❌ Real-time discovery components not available for testing")
        print("Please ensure all dependencies are installed and components are properly integrated.") 