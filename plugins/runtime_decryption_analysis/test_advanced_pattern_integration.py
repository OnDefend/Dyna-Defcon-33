#!/usr/bin/env python3
"""
Comprehensive Test Suite for Advanced Pattern Integration

This module provides extensive testing coverage for all Advanced Pattern Integration
components, including unit tests, integration tests, performance validation, and
error handling verification.

Test Coverage:
- AdvancedPatternDatabase functionality
- PatternCorrelationEngine ML-enhanced matching  
- DynamicPatternLearner adaptive detection
- Pattern search and correlation workflows
- Performance and scalability validation
- Error handling and edge cases
- Plugin integration compatibility
"""

import sys
import unittest
import asyncio
import time
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from plugins.runtime_decryption_analysis.advanced_pattern_integration import (
        PatternCategory, PatternComplexity, PatternConfidence, PatternSource,
        AdvancedSecurityPattern, PatternMatch, PatternCorrelationResult,
        AdvancedPatternDatabase, PatternCorrelationEngine, DynamicPatternLearner,
        create_advanced_pattern_database, create_pattern_correlation_engine,
        create_dynamic_pattern_learner
    )
    from plugins.runtime_decryption_analysis.data_structures import (
        RuntimeDecryptionConfig, RuntimeDecryptionAnalysisResult
    )
except ImportError as e:
    print(f"Warning: Could not import advanced pattern integration components: {e}")
    # Mock the components for testing environment
    from enum import Enum
    from dataclasses import dataclass
    
    class PatternCategory(Enum):
        CRYPTOGRAPHIC = "cryptographic"
        NETWORK_SECURITY = "network_security"
    
    class PatternComplexity(Enum):
        LOW = "low"
        MODERATE = "moderate"
        HIGH = "high"
    
    class PatternConfidence(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
    
    @dataclass
    class AdvancedSecurityPattern:
        pattern_id: str
        name: str
        description: str
        category: PatternCategory
        
    @dataclass
    class PatternMatch:
        pattern: AdvancedSecurityPattern
        match_confidence: float
    
    # Mock classes for testing
    class AdvancedPatternDatabase:
        def __init__(self, config=None):
            self.patterns = []
            self.config = config or {}
        
        def load_patterns(self): pass
        def search_patterns(self, query): return []
        def get_patterns_by_category(self, category): return []
    
    class PatternCorrelationEngine:
        def __init__(self, config=None):
            self.config = config or {}
        
        def correlate_patterns(self, matches): return None
    
    class DynamicPatternLearner:
        def __init__(self, config=None):
            self.config = config or {}
        
        def observe_pattern(self, data): pass
        def get_learned_patterns(self): return []


class TestAdvancedSecurityPattern(unittest.TestCase):
    """Test AdvancedSecurityPattern data structure."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_pattern = AdvancedSecurityPattern(
            pattern_id="test_001",
            name="Test Pattern",
            description="Test cryptographic pattern",
            category=PatternCategory.CRYPTOGRAPHIC,
            pattern_data={
                "weak_algorithms": ["MD5", "SHA1"],
                "api_patterns": [r"MessageDigest\.getInstance\([\"']MD5[\"']\)"]
            },
            detection_logic="regex_api_match",
            complexity=PatternComplexity.MODERATE,
            confidence=PatternConfidence.HIGH,
            target_apis=["MessageDigest.getInstance"],
            target_classes=["java.security.MessageDigest"],
            mitre_attack_techniques=["T1552.001"],
            false_positive_rate=0.05,
            detection_accuracy=0.92
        )
    
    def test_pattern_creation(self):
        """Test pattern creation and basic properties."""
        self.assertEqual(self.test_pattern.pattern_id, "test_001")
        self.assertEqual(self.test_pattern.name, "Test Pattern")
        self.assertEqual(self.test_pattern.category, PatternCategory.CRYPTOGRAPHIC)
        self.assertEqual(self.test_pattern.complexity, PatternComplexity.MODERATE)
        self.assertEqual(self.test_pattern.confidence, PatternConfidence.HIGH)
    
    def test_pattern_data_structure(self):
        """Test pattern data structure integrity."""
        self.assertIn("weak_algorithms", self.test_pattern.pattern_data)
        self.assertIn("api_patterns", self.test_pattern.pattern_data)
        self.assertIn("MD5", self.test_pattern.pattern_data["weak_algorithms"])
    
    def test_pattern_metadata(self):
        """Test pattern metadata attributes."""
        self.assertEqual(self.test_pattern.false_positive_rate, 0.05)
        self.assertEqual(self.test_pattern.detection_accuracy, 0.92)
        self.assertIn("T1552.001", self.test_pattern.mitre_attack_techniques)


class TestPatternMatch(unittest.TestCase):
    """Test PatternMatch data structure."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_pattern = AdvancedSecurityPattern(
            pattern_id="match_test_001",
            name="Match Test Pattern",
            description="Pattern for match testing",
            category=PatternCategory.CRYPTOGRAPHIC
        )
        
        self.test_match = PatternMatch(
            pattern=self.test_pattern,
            match_confidence=0.85,
            match_location="com.example.CryptoUtils.encrypt",
            match_context="Method uses weak MD5 algorithm",
            detection_metadata={
                "api_call": "MessageDigest.getInstance('MD5')",
                "line_number": 42,
                "file_path": "CryptoUtils.java"
            }
        )
    
    def test_match_creation(self):
        """Test match creation and basic properties."""
        self.assertEqual(self.test_match.pattern.pattern_id, "match_test_001")
        self.assertEqual(self.test_match.match_confidence, 0.85)
        self.assertIn("Method uses weak MD5", self.test_match.match_context)
    
    def test_match_metadata(self):
        """Test match detection metadata."""
        metadata = self.test_match.detection_metadata
        self.assertIn("api_call", metadata)
        self.assertIn("line_number", metadata)
        self.assertEqual(metadata["line_number"], 42)


class TestAdvancedPatternDatabase(unittest.TestCase):
    """Test AdvancedPatternDatabase functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "storage": {
                "cache_ttl": 300,
                "max_cache_entries": 1000
            },
            "builtin_patterns": {
                "enable_cryptographic_patterns": True,
                "enable_network_patterns": True,
                "enable_data_patterns": True,
                "target_pattern_count": 100
            }
        }
        self.database = AdvancedPatternDatabase(self.config)
    
    def test_database_initialization(self):
        """Test database initialization."""
        self.assertIsNotNone(self.database)
        self.assertEqual(self.database.config, self.config)
        self.assertIsInstance(self.database.patterns, list)
    
    def test_pattern_loading(self):
        """Test pattern loading functionality."""
        initial_count = len(self.database.patterns)
        self.database.load_patterns()
        
        # Should have loaded built-in patterns
        self.assertGreaterEqual(len(self.database.patterns), initial_count)
    
    def test_pattern_search(self):
        """Test pattern search functionality."""
        # Load patterns first
        self.database.load_patterns()
        
        # Search for cryptographic patterns
        crypto_patterns = self.database.search_patterns("cryptographic")
        self.assertIsInstance(crypto_patterns, list)
        
        # Search for specific algorithm
        md5_patterns = self.database.search_patterns("MD5")
        self.assertIsInstance(md5_patterns, list)
    
    def test_get_patterns_by_category(self):
        """Test getting patterns by category."""
        self.database.load_patterns()
        
        crypto_patterns = self.database.get_patterns_by_category(PatternCategory.CRYPTOGRAPHIC)
        self.assertIsInstance(crypto_patterns, list)
        
        # All patterns should be cryptographic
        for pattern in crypto_patterns[:5]:  # Check first few
            self.assertEqual(pattern.category, PatternCategory.CRYPTOGRAPHIC)
    
    def test_get_high_confidence_patterns(self):
        """Test getting high confidence patterns."""
        self.database.load_patterns()
        
        high_conf_patterns = self.database.get_high_confidence_patterns()
        self.assertIsInstance(high_conf_patterns, list)
        
        # All patterns should have high confidence
        for pattern in high_conf_patterns[:5]:  # Check first few
            self.assertEqual(pattern.confidence, PatternConfidence.HIGH)
    
    def test_pattern_statistics(self):
        """Test pattern database statistics."""
        self.database.load_patterns()
        
        stats = self.database.get_database_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_patterns", stats)
        self.assertIn("patterns_by_category", stats)
        self.assertIn("patterns_by_confidence", stats)
        self.assertGreater(stats["total_patterns"], 0)


class TestPatternCorrelationEngine(unittest.TestCase):
    """Test PatternCorrelationEngine ML-enhanced matching."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "enabled": True,
            "thresholds": {
                "correlation_threshold": 0.7,
                "high_confidence_threshold": 0.8,
                "pattern_similarity_threshold": 0.6
            },
            "ml_enhancement": {
                "enabled": True,
                "ml_correlation_enabled": True,
                "confidence_weighting": True
            }
        }
        self.engine = PatternCorrelationEngine(self.config)
        
        # Create test patterns and matches
        self.test_patterns = [
            AdvancedSecurityPattern(
                pattern_id="corr_test_001",
                name="Weak Crypto Test",
                description="Test weak cryptography",
                category=PatternCategory.CRYPTOGRAPHIC
            ),
            AdvancedSecurityPattern(
                pattern_id="corr_test_002", 
                name="Network Security Test",
                description="Test network security",
                category=PatternCategory.NETWORK_SECURITY
            )
        ]
        
        self.test_matches = [
            PatternMatch(
                pattern=self.test_patterns[0],
                match_confidence=0.85,
                match_location="CryptoUtils.encrypt"
            ),
            PatternMatch(
                pattern=self.test_patterns[1],
                match_confidence=0.78,
                match_location="NetworkManager.connect"
            )
        ]
    
    def test_engine_initialization(self):
        """Test correlation engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.config, self.config)
        self.assertTrue(self.engine.ml_enabled)
    
    def test_pattern_correlation(self):
        """Test pattern correlation functionality."""
        correlation_result = self.engine.correlate_patterns(self.test_matches)
        
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
        self.assertIsInstance(correlation_result.correlated_matches, list)
        self.assertIsInstance(correlation_result.correlation_score, float)
        self.assertGreaterEqual(correlation_result.correlation_score, 0.0)
        self.assertLessEqual(correlation_result.correlation_score, 1.0)
    
    def test_ml_enhanced_correlation(self):
        """Test ML-enhanced correlation features."""
        # Test with ML enhancement enabled
        correlation_result = self.engine.correlate_patterns(self.test_matches)
        
        self.assertIsNotNone(correlation_result.ml_insights)
        self.assertIn("confidence_analysis", correlation_result.ml_insights)
        self.assertIn("pattern_similarity", correlation_result.ml_insights)
    
    def test_correlation_statistics(self):
        """Test correlation engine statistics."""
        # Perform some correlations first
        self.engine.correlate_patterns(self.test_matches)
        
        stats = self.engine.get_correlation_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_correlations", stats)
        self.assertIn("average_correlation_score", stats)
        self.assertIn("ml_insights_generated", stats)


class TestDynamicPatternLearner(unittest.TestCase):
    """Test DynamicPatternLearner adaptive detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "enabled": True,
            "learning_threshold": 0.8,
            "min_observations": 5,
            "adaptation": {
                "enable_behavioral_learning": True,
                "enable_frequency_analysis": True,
                "pattern_evolution_tracking": True
            }
        }
        self.learner = DynamicPatternLearner(self.config)
    
    def test_learner_initialization(self):
        """Test dynamic learner initialization."""
        self.assertIsNotNone(self.learner)
        self.assertEqual(self.learner.config, self.config)
        self.assertTrue(self.learner.learning_enabled)
    
    def test_behavioral_observation(self):
        """Test behavioral pattern observation."""
        behavioral_data = {
            "api_call": "Cipher.getInstance('AES')",
            "frequency": 15,
            "context": "CryptoHelper.encrypt",
            "confidence": 0.85
        }
        
        # Observe pattern multiple times
        for _ in range(6):  # Above min_observations threshold
            self.learner.observe_behavioral_data(behavioral_data)
        
        learned_patterns = self.learner.get_learned_patterns()
        self.assertIsInstance(learned_patterns, list)
    
    def test_pattern_evolution_tracking(self):
        """Test pattern evolution tracking."""
        # Submit evolving patterns
        base_data = {
            "api_call": "MessageDigest.getInstance",
            "context": "HashUtils",
            "confidence": 0.7
        }
        
        # Evolve the pattern
        evolved_data = {
            "api_call": "MessageDigest.getInstance('SHA-256')",
            "context": "SecureHashUtils", 
            "confidence": 0.85
        }
        
        self.learner.observe_behavioral_data(base_data)
        self.learner.observe_behavioral_data(evolved_data)
        
        evolution_stats = self.learner.get_pattern_evolution_statistics()
        self.assertIsInstance(evolution_stats, dict)
        self.assertIn("evolved_patterns", evolution_stats)
    
    def test_learning_statistics(self):
        """Test learning statistics."""
        # Generate some learning activity
        for i in range(10):
            behavioral_data = {
                "api_call": f"TestAPI.method{i}",
                "frequency": i + 1,
                "confidence": 0.6 + (i * 0.03)
            }
            self.learner.observe_behavioral_data(behavioral_data)
        
        stats = self.learner.get_learning_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_observations", stats)
        self.assertIn("learned_patterns_count", stats)
        self.assertIn("learning_accuracy", stats)


class TestPatternIntegrationWorkflow(unittest.TestCase):
    """Test complete pattern integration workflow."""
    
    def setUp(self):
        """Set up test fixtures for integration testing."""
        self.database_config = {
            "builtin_patterns": {
                "enable_cryptographic_patterns": True,
                "target_pattern_count": 50
            }
        }
        
        self.correlation_config = {
            "enabled": True,
            "thresholds": {"correlation_threshold": 0.7},
            "ml_enhancement": {"enabled": True}
        }
        
        self.learning_config = {
            "enabled": True,
            "learning_threshold": 0.8,
            "min_observations": 3
        }
        
        self.database = AdvancedPatternDatabase(self.database_config)
        self.correlation_engine = PatternCorrelationEngine(self.correlation_config)
        self.learner = DynamicPatternLearner(self.learning_config)
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end pattern integration workflow."""
        # 1. Load patterns
        self.database.load_patterns()
        patterns_loaded = len(self.database.patterns)
        self.assertGreater(patterns_loaded, 0)
        
        # 2. Search for relevant patterns
        crypto_patterns = self.database.search_patterns("cryptographic")
        self.assertIsInstance(crypto_patterns, list)
        
        # 3. Create pattern matches
        test_matches = []
        for pattern in crypto_patterns[:3]:  # Take first 3
            match = PatternMatch(
                pattern=pattern,
                match_confidence=0.80,
                match_location="TestClass.testMethod"
            )
            test_matches.append(match)
        
        # 4. Correlate patterns
        if test_matches:
            correlation_result = self.correlation_engine.correlate_patterns(test_matches)
            self.assertIsInstance(correlation_result, PatternCorrelationResult)
        
        # 5. Learn from observations
        for match in test_matches:
            behavioral_data = {
                "pattern_id": match.pattern.pattern_id,
                "confidence": match.match_confidence,
                "location": match.match_location
            }
            self.learner.observe_behavioral_data(behavioral_data)
        
        # 6. Verify learning occurred
        learned_patterns = self.learner.get_learned_patterns()
        self.assertIsInstance(learned_patterns, list)
    
    def test_pattern_fusion_workflow(self):
        """Test pattern fusion across different sources."""
        self.database.load_patterns()
        
        # Get patterns from different categories
        crypto_patterns = self.database.get_patterns_by_category(PatternCategory.CRYPTOGRAPHIC)
        
        if crypto_patterns:
            # Create mixed matches
            mixed_matches = []
            for i, pattern in enumerate(crypto_patterns[:2]):
                match = PatternMatch(
                    pattern=pattern,
                    match_confidence=0.75 + (i * 0.1),
                    match_location=f"FusionTest.method{i}"
                )
                mixed_matches.append(match)
            
            # Test correlation with mixed patterns
            correlation_result = self.correlation_engine.correlate_patterns(mixed_matches)
            self.assertIsInstance(correlation_result, PatternCorrelationResult)


class TestPerformanceAndScalability(unittest.TestCase):
    """Test performance and scalability aspects."""
    
    def setUp(self):
        """Set up test fixtures for performance testing."""
        self.database = AdvancedPatternDatabase({
            "builtin_patterns": {"target_pattern_count": 100}
        })
        self.correlation_engine = PatternCorrelationEngine({})
        self.learner = DynamicPatternLearner({})
    
    def test_pattern_loading_performance(self):
        """Test pattern loading performance."""
        start_time = time.time()
        self.database.load_patterns()
        loading_time = time.time() - start_time
        
        # Should load patterns reasonably quickly
        self.assertLess(loading_time, 5.0)  # 5 seconds max
        self.assertGreater(len(self.database.patterns), 0)
    
    def test_pattern_search_performance(self):
        """Test pattern search performance."""
        self.database.load_patterns()
        
        start_time = time.time()
        results = self.database.search_patterns("cryptographic")
        search_time = time.time() - start_time
        
        # Search should be fast
        self.assertLess(search_time, 1.0)  # 1 second max
        self.assertIsInstance(results, list)
    
    def test_correlation_performance(self):
        """Test correlation engine performance."""
        self.database.load_patterns()
        patterns = self.database.patterns[:10]  # Take first 10
        
        matches = [
            PatternMatch(
                pattern=pattern,
                match_confidence=0.8,
                match_location=f"TestClass.method{i}"
            )
            for i, pattern in enumerate(patterns)
        ]
        
        start_time = time.time()
        correlation_result = self.correlation_engine.correlate_patterns(matches)
        correlation_time = time.time() - start_time
        
        # Correlation should be reasonably fast
        self.assertLess(correlation_time, 2.0)  # 2 seconds max
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
    
    def test_learning_scalability(self):
        """Test learning system scalability."""
        # Test with larger number of observations
        start_time = time.time()
        
        for i in range(100):  # 100 observations
            behavioral_data = {
                "api_call": f"TestAPI.method{i % 10}",
                "frequency": i,
                "confidence": 0.7 + (i % 3) * 0.1
            }
            self.learner.observe_behavioral_data(behavioral_data)
        
        learning_time = time.time() - start_time
        
        # Learning should handle multiple observations efficiently
        self.assertLess(learning_time, 3.0)  # 3 seconds max
        
        learned_patterns = self.learner.get_learned_patterns()
        self.assertIsInstance(learned_patterns, list)


class TestErrorHandlingAndEdgeCases(unittest.TestCase):
    """Test error handling and edge cases."""
    
    def setUp(self):
        """Set up test fixtures for error testing."""
        self.database = AdvancedPatternDatabase({})
        self.correlation_engine = PatternCorrelationEngine({})
        self.learner = DynamicPatternLearner({})
    
    def test_invalid_pattern_search(self):
        """Test handling of invalid pattern searches."""
        # Test with None query
        results = self.database.search_patterns(None)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 0)
        
        # Test with empty query
        results = self.database.search_patterns("")
        self.assertIsInstance(results, list)
        
        # Test with invalid category
        try:
            results = self.database.get_patterns_by_category("invalid_category")
            self.assertIsInstance(results, list)
        except (ValueError, TypeError):
            pass  # Expected behavior
    
    def test_empty_correlation_input(self):
        """Test correlation with empty input."""
        # Test with empty matches list
        correlation_result = self.correlation_engine.correlate_patterns([])
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
        self.assertEqual(len(correlation_result.correlated_matches), 0)
        
        # Test with None input
        correlation_result = self.correlation_engine.correlate_patterns(None)
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
    
    def test_invalid_learning_data(self):
        """Test learning with invalid data."""
        # Test with None data
        try:
            self.learner.observe_behavioral_data(None)
        except (ValueError, TypeError):
            pass  # Expected behavior
        
        # Test with empty data
        try:
            self.learner.observe_behavioral_data({})
        except (ValueError, TypeError):
            pass  # Expected behavior
        
        # Test with malformed data
        try:
            self.learner.observe_behavioral_data({"invalid": "data"})
        except (ValueError, TypeError):
            pass  # Expected behavior
    
    def test_configuration_edge_cases(self):
        """Test configuration edge cases."""
        # Test with None config
        database_none = AdvancedPatternDatabase(None)
        self.assertIsNotNone(database_none)
        
        # Test with empty config
        database_empty = AdvancedPatternDatabase({})
        self.assertIsNotNone(database_empty)
        
        # Test with invalid config values
        invalid_config = {
            "storage": {"cache_ttl": -1, "max_cache_entries": "invalid"},
            "builtin_patterns": {"target_pattern_count": -5}
        }
        database_invalid = AdvancedPatternDatabase(invalid_config)
        self.assertIsNotNone(database_invalid)


class TestPluginIntegration(unittest.TestCase):
    """Test integration with AODS plugin framework."""
    
    def test_factory_functions(self):
        """Test factory function creation."""
        # Test database factory
        database = create_advanced_pattern_database({})
        self.assertIsInstance(database, AdvancedPatternDatabase)
        
        # Test correlation engine factory
        engine = create_pattern_correlation_engine({})
        self.assertIsInstance(engine, PatternCorrelationEngine)
        
        # Test learner factory
        learner = create_dynamic_pattern_learner({})
        self.assertIsInstance(learner, DynamicPatternLearner)
    
    @patch('sys.modules')
    def test_aods_plugin_compatibility(self, mock_modules):
        """Test compatibility with AODS plugin framework."""
        # Mock AODS core components
        mock_modules['core.shared_infrastructure.cross_plugin_utilities'] = Mock()
        
        # Test plugin initialization with mocked dependencies
        try:
            database = create_advanced_pattern_database({})
            self.assertIsInstance(database, AdvancedPatternDatabase)
        except ImportError:
            # Expected in test environment
            self.skipTest("AODS core components not available in test environment")


# Async test support
class TestAsyncPatternOperations(unittest.TestCase):
    """Test async pattern operations."""
    
    def setUp(self):
        """Set up async test fixtures."""
        self.database = AdvancedPatternDatabase({})
        self.correlation_engine = PatternCorrelationEngine({})
    
    def test_async_pattern_loading(self):
        """Test async pattern loading simulation."""
        async def async_load_test():
            # Simulate async pattern loading
            await asyncio.sleep(0.1)
            self.database.load_patterns()
            return len(self.database.patterns)
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(async_load_test())
            self.assertGreaterEqual(result, 0)
        finally:
            loop.close()
    
    def test_concurrent_operations(self):
        """Test concurrent pattern operations."""
        async def concurrent_test():
            # Load patterns first
            self.database.load_patterns()
            
            # Simulate concurrent operations
            tasks = []
            for i in range(5):
                task = asyncio.create_task(self._async_search_operation(f"search_{i}"))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            return results
        
        async def _async_search_operation(self, query):
            await asyncio.sleep(0.05)  # Simulate async work
            return self.database.search_patterns(query)
        
        self._async_search_operation = _async_search_operation
        
        # Run concurrent test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(concurrent_test())
            self.assertEqual(len(results), 5)
            for result in results:
                self.assertIsInstance(result, list)
        finally:
            loop.close()


# Test runner functions
def run_comprehensive_tests():
    """Run all comprehensive tests."""
    print("🧪 Running Advanced Pattern Integration Comprehensive Tests...")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestAdvancedSecurityPattern,
        TestPatternMatch,
        TestAdvancedPatternDatabase,
        TestPatternCorrelationEngine,
        TestDynamicPatternLearner,
        TestPatternIntegrationWorkflow,
        TestPerformanceAndScalability,
        TestErrorHandlingAndEdgeCases,
        TestPluginIntegration
    ]
    
    for test_class in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_class))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n📊 Test Summary:")
    print(f"   Tests run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    print(f"   Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    return result.wasSuccessful()


def run_async_integration_tests():
    """Run async integration tests."""
    print("\n🔄 Running Async Integration Tests...")
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAsyncPatternOperations)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_performance_benchmarks():
    """Run performance benchmarks."""
    print("\n⚡ Running Performance Benchmarks...")
    
    database = AdvancedPatternDatabase({
        "builtin_patterns": {"target_pattern_count": 200}
    })
    
    # Benchmark pattern loading
    start_time = time.time()
    database.load_patterns()
    load_time = time.time() - start_time
    
    print(f"   Pattern Loading: {load_time:.3f}s ({len(database.patterns)} patterns)")
    
    # Benchmark search operations
    search_times = []
    for query in ["crypto", "network", "security", "algorithm", "encryption"]:
        start_time = time.time()
        results = database.search_patterns(query)
        search_time = time.time() - start_time
        search_times.append(search_time)
        print(f"   Search '{query}': {search_time:.3f}s ({len(results)} results)")
    
    avg_search_time = sum(search_times) / len(search_times)
    print(f"   Average Search Time: {avg_search_time:.3f}s")
    
    return {
        "load_time": load_time,
        "pattern_count": len(database.patterns),
        "average_search_time": avg_search_time
    }


if __name__ == "__main__":
    print("🚀 Advanced Pattern Integration - Comprehensive Test Suite")
    print("=" * 60)
    
    # Run all tests
    success = True
    
    try:
        # Run main test suite
        main_success = run_comprehensive_tests()
        success = success and main_success
        
        # Run async tests
        async_success = run_async_integration_tests()
        success = success and async_success
        
        # Run performance benchmarks
        benchmarks = run_performance_benchmarks()
        
        print(f"\n{'✅' if success else '❌'} Overall Test Status: {'PASSED' if success else 'FAILED'}")
        
        if success:
            print("\n🎉 Advanced Pattern Integration testing completed successfully!")
            print("   All components validated and ready for production use.")
        else:
            print("\n⚠️  Some tests failed. Please review and address issues before deployment.")
    
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        success = False
    
    # Exit with appropriate code
    sys.exit(0 if success else 1) 
"""
Comprehensive Test Suite for Advanced Pattern Integration

This module provides extensive testing coverage for all Advanced Pattern Integration
components, including unit tests, integration tests, performance validation, and
error handling verification.

Test Coverage:
- AdvancedPatternDatabase functionality
- PatternCorrelationEngine ML-enhanced matching  
- DynamicPatternLearner adaptive detection
- Pattern search and correlation workflows
- Performance and scalability validation
- Error handling and edge cases
- Plugin integration compatibility
"""

import sys
import unittest
import asyncio
import time
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from plugins.runtime_decryption_analysis.advanced_pattern_integration import (
        PatternCategory, PatternComplexity, PatternConfidence, PatternSource,
        AdvancedSecurityPattern, PatternMatch, PatternCorrelationResult,
        AdvancedPatternDatabase, PatternCorrelationEngine, DynamicPatternLearner,
        create_advanced_pattern_database, create_pattern_correlation_engine,
        create_dynamic_pattern_learner
    )
    from plugins.runtime_decryption_analysis.data_structures import (
        RuntimeDecryptionConfig, RuntimeDecryptionAnalysisResult
    )
except ImportError as e:
    print(f"Warning: Could not import advanced pattern integration components: {e}")
    # Mock the components for testing environment
    from enum import Enum
    from dataclasses import dataclass
    
    class PatternCategory(Enum):
        CRYPTOGRAPHIC = "cryptographic"
        NETWORK_SECURITY = "network_security"
    
    class PatternComplexity(Enum):
        LOW = "low"
        MODERATE = "moderate"
        HIGH = "high"
    
    class PatternConfidence(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
    
    @dataclass
    class AdvancedSecurityPattern:
        pattern_id: str
        name: str
        description: str
        category: PatternCategory
        
    @dataclass
    class PatternMatch:
        pattern: AdvancedSecurityPattern
        match_confidence: float
    
    # Mock classes for testing
    class AdvancedPatternDatabase:
        def __init__(self, config=None):
            self.patterns = []
            self.config = config or {}
        
        def load_patterns(self): pass
        def search_patterns(self, query): return []
        def get_patterns_by_category(self, category): return []
    
    class PatternCorrelationEngine:
        def __init__(self, config=None):
            self.config = config or {}
        
        def correlate_patterns(self, matches): return None
    
    class DynamicPatternLearner:
        def __init__(self, config=None):
            self.config = config or {}
        
        def observe_pattern(self, data): pass
        def get_learned_patterns(self): return []


class TestAdvancedSecurityPattern(unittest.TestCase):
    """Test AdvancedSecurityPattern data structure."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_pattern = AdvancedSecurityPattern(
            pattern_id="test_001",
            name="Test Pattern",
            description="Test cryptographic pattern",
            category=PatternCategory.CRYPTOGRAPHIC,
            pattern_data={
                "weak_algorithms": ["MD5", "SHA1"],
                "api_patterns": [r"MessageDigest\.getInstance\([\"']MD5[\"']\)"]
            },
            detection_logic="regex_api_match",
            complexity=PatternComplexity.MODERATE,
            confidence=PatternConfidence.HIGH,
            target_apis=["MessageDigest.getInstance"],
            target_classes=["java.security.MessageDigest"],
            mitre_attack_techniques=["T1552.001"],
            false_positive_rate=0.05,
            detection_accuracy=0.92
        )
    
    def test_pattern_creation(self):
        """Test pattern creation and basic properties."""
        self.assertEqual(self.test_pattern.pattern_id, "test_001")
        self.assertEqual(self.test_pattern.name, "Test Pattern")
        self.assertEqual(self.test_pattern.category, PatternCategory.CRYPTOGRAPHIC)
        self.assertEqual(self.test_pattern.complexity, PatternComplexity.MODERATE)
        self.assertEqual(self.test_pattern.confidence, PatternConfidence.HIGH)
    
    def test_pattern_data_structure(self):
        """Test pattern data structure integrity."""
        self.assertIn("weak_algorithms", self.test_pattern.pattern_data)
        self.assertIn("api_patterns", self.test_pattern.pattern_data)
        self.assertIn("MD5", self.test_pattern.pattern_data["weak_algorithms"])
    
    def test_pattern_metadata(self):
        """Test pattern metadata attributes."""
        self.assertEqual(self.test_pattern.false_positive_rate, 0.05)
        self.assertEqual(self.test_pattern.detection_accuracy, 0.92)
        self.assertIn("T1552.001", self.test_pattern.mitre_attack_techniques)


class TestPatternMatch(unittest.TestCase):
    """Test PatternMatch data structure."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_pattern = AdvancedSecurityPattern(
            pattern_id="match_test_001",
            name="Match Test Pattern",
            description="Pattern for match testing",
            category=PatternCategory.CRYPTOGRAPHIC
        )
        
        self.test_match = PatternMatch(
            pattern=self.test_pattern,
            match_confidence=0.85,
            match_location="com.example.CryptoUtils.encrypt",
            match_context="Method uses weak MD5 algorithm",
            detection_metadata={
                "api_call": "MessageDigest.getInstance('MD5')",
                "line_number": 42,
                "file_path": "CryptoUtils.java"
            }
        )
    
    def test_match_creation(self):
        """Test match creation and basic properties."""
        self.assertEqual(self.test_match.pattern.pattern_id, "match_test_001")
        self.assertEqual(self.test_match.match_confidence, 0.85)
        self.assertIn("Method uses weak MD5", self.test_match.match_context)
    
    def test_match_metadata(self):
        """Test match detection metadata."""
        metadata = self.test_match.detection_metadata
        self.assertIn("api_call", metadata)
        self.assertIn("line_number", metadata)
        self.assertEqual(metadata["line_number"], 42)


class TestAdvancedPatternDatabase(unittest.TestCase):
    """Test AdvancedPatternDatabase functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "storage": {
                "cache_ttl": 300,
                "max_cache_entries": 1000
            },
            "builtin_patterns": {
                "enable_cryptographic_patterns": True,
                "enable_network_patterns": True,
                "enable_data_patterns": True,
                "target_pattern_count": 100
            }
        }
        self.database = AdvancedPatternDatabase(self.config)
    
    def test_database_initialization(self):
        """Test database initialization."""
        self.assertIsNotNone(self.database)
        self.assertEqual(self.database.config, self.config)
        self.assertIsInstance(self.database.patterns, list)
    
    def test_pattern_loading(self):
        """Test pattern loading functionality."""
        initial_count = len(self.database.patterns)
        self.database.load_patterns()
        
        # Should have loaded built-in patterns
        self.assertGreaterEqual(len(self.database.patterns), initial_count)
    
    def test_pattern_search(self):
        """Test pattern search functionality."""
        # Load patterns first
        self.database.load_patterns()
        
        # Search for cryptographic patterns
        crypto_patterns = self.database.search_patterns("cryptographic")
        self.assertIsInstance(crypto_patterns, list)
        
        # Search for specific algorithm
        md5_patterns = self.database.search_patterns("MD5")
        self.assertIsInstance(md5_patterns, list)
    
    def test_get_patterns_by_category(self):
        """Test getting patterns by category."""
        self.database.load_patterns()
        
        crypto_patterns = self.database.get_patterns_by_category(PatternCategory.CRYPTOGRAPHIC)
        self.assertIsInstance(crypto_patterns, list)
        
        # All patterns should be cryptographic
        for pattern in crypto_patterns[:5]:  # Check first few
            self.assertEqual(pattern.category, PatternCategory.CRYPTOGRAPHIC)
    
    def test_get_high_confidence_patterns(self):
        """Test getting high confidence patterns."""
        self.database.load_patterns()
        
        high_conf_patterns = self.database.get_high_confidence_patterns()
        self.assertIsInstance(high_conf_patterns, list)
        
        # All patterns should have high confidence
        for pattern in high_conf_patterns[:5]:  # Check first few
            self.assertEqual(pattern.confidence, PatternConfidence.HIGH)
    
    def test_pattern_statistics(self):
        """Test pattern database statistics."""
        self.database.load_patterns()
        
        stats = self.database.get_database_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_patterns", stats)
        self.assertIn("patterns_by_category", stats)
        self.assertIn("patterns_by_confidence", stats)
        self.assertGreater(stats["total_patterns"], 0)


class TestPatternCorrelationEngine(unittest.TestCase):
    """Test PatternCorrelationEngine ML-enhanced matching."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "enabled": True,
            "thresholds": {
                "correlation_threshold": 0.7,
                "high_confidence_threshold": 0.8,
                "pattern_similarity_threshold": 0.6
            },
            "ml_enhancement": {
                "enabled": True,
                "ml_correlation_enabled": True,
                "confidence_weighting": True
            }
        }
        self.engine = PatternCorrelationEngine(self.config)
        
        # Create test patterns and matches
        self.test_patterns = [
            AdvancedSecurityPattern(
                pattern_id="corr_test_001",
                name="Weak Crypto Test",
                description="Test weak cryptography",
                category=PatternCategory.CRYPTOGRAPHIC
            ),
            AdvancedSecurityPattern(
                pattern_id="corr_test_002", 
                name="Network Security Test",
                description="Test network security",
                category=PatternCategory.NETWORK_SECURITY
            )
        ]
        
        self.test_matches = [
            PatternMatch(
                pattern=self.test_patterns[0],
                match_confidence=0.85,
                match_location="CryptoUtils.encrypt"
            ),
            PatternMatch(
                pattern=self.test_patterns[1],
                match_confidence=0.78,
                match_location="NetworkManager.connect"
            )
        ]
    
    def test_engine_initialization(self):
        """Test correlation engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.config, self.config)
        self.assertTrue(self.engine.ml_enabled)
    
    def test_pattern_correlation(self):
        """Test pattern correlation functionality."""
        correlation_result = self.engine.correlate_patterns(self.test_matches)
        
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
        self.assertIsInstance(correlation_result.correlated_matches, list)
        self.assertIsInstance(correlation_result.correlation_score, float)
        self.assertGreaterEqual(correlation_result.correlation_score, 0.0)
        self.assertLessEqual(correlation_result.correlation_score, 1.0)
    
    def test_ml_enhanced_correlation(self):
        """Test ML-enhanced correlation features."""
        # Test with ML enhancement enabled
        correlation_result = self.engine.correlate_patterns(self.test_matches)
        
        self.assertIsNotNone(correlation_result.ml_insights)
        self.assertIn("confidence_analysis", correlation_result.ml_insights)
        self.assertIn("pattern_similarity", correlation_result.ml_insights)
    
    def test_correlation_statistics(self):
        """Test correlation engine statistics."""
        # Perform some correlations first
        self.engine.correlate_patterns(self.test_matches)
        
        stats = self.engine.get_correlation_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_correlations", stats)
        self.assertIn("average_correlation_score", stats)
        self.assertIn("ml_insights_generated", stats)


class TestDynamicPatternLearner(unittest.TestCase):
    """Test DynamicPatternLearner adaptive detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "enabled": True,
            "learning_threshold": 0.8,
            "min_observations": 5,
            "adaptation": {
                "enable_behavioral_learning": True,
                "enable_frequency_analysis": True,
                "pattern_evolution_tracking": True
            }
        }
        self.learner = DynamicPatternLearner(self.config)
    
    def test_learner_initialization(self):
        """Test dynamic learner initialization."""
        self.assertIsNotNone(self.learner)
        self.assertEqual(self.learner.config, self.config)
        self.assertTrue(self.learner.learning_enabled)
    
    def test_behavioral_observation(self):
        """Test behavioral pattern observation."""
        behavioral_data = {
            "api_call": "Cipher.getInstance('AES')",
            "frequency": 15,
            "context": "CryptoHelper.encrypt",
            "confidence": 0.85
        }
        
        # Observe pattern multiple times
        for _ in range(6):  # Above min_observations threshold
            self.learner.observe_behavioral_data(behavioral_data)
        
        learned_patterns = self.learner.get_learned_patterns()
        self.assertIsInstance(learned_patterns, list)
    
    def test_pattern_evolution_tracking(self):
        """Test pattern evolution tracking."""
        # Submit evolving patterns
        base_data = {
            "api_call": "MessageDigest.getInstance",
            "context": "HashUtils",
            "confidence": 0.7
        }
        
        # Evolve the pattern
        evolved_data = {
            "api_call": "MessageDigest.getInstance('SHA-256')",
            "context": "SecureHashUtils", 
            "confidence": 0.85
        }
        
        self.learner.observe_behavioral_data(base_data)
        self.learner.observe_behavioral_data(evolved_data)
        
        evolution_stats = self.learner.get_pattern_evolution_statistics()
        self.assertIsInstance(evolution_stats, dict)
        self.assertIn("evolved_patterns", evolution_stats)
    
    def test_learning_statistics(self):
        """Test learning statistics."""
        # Generate some learning activity
        for i in range(10):
            behavioral_data = {
                "api_call": f"TestAPI.method{i}",
                "frequency": i + 1,
                "confidence": 0.6 + (i * 0.03)
            }
            self.learner.observe_behavioral_data(behavioral_data)
        
        stats = self.learner.get_learning_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_observations", stats)
        self.assertIn("learned_patterns_count", stats)
        self.assertIn("learning_accuracy", stats)


class TestPatternIntegrationWorkflow(unittest.TestCase):
    """Test complete pattern integration workflow."""
    
    def setUp(self):
        """Set up test fixtures for integration testing."""
        self.database_config = {
            "builtin_patterns": {
                "enable_cryptographic_patterns": True,
                "target_pattern_count": 50
            }
        }
        
        self.correlation_config = {
            "enabled": True,
            "thresholds": {"correlation_threshold": 0.7},
            "ml_enhancement": {"enabled": True}
        }
        
        self.learning_config = {
            "enabled": True,
            "learning_threshold": 0.8,
            "min_observations": 3
        }
        
        self.database = AdvancedPatternDatabase(self.database_config)
        self.correlation_engine = PatternCorrelationEngine(self.correlation_config)
        self.learner = DynamicPatternLearner(self.learning_config)
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end pattern integration workflow."""
        # 1. Load patterns
        self.database.load_patterns()
        patterns_loaded = len(self.database.patterns)
        self.assertGreater(patterns_loaded, 0)
        
        # 2. Search for relevant patterns
        crypto_patterns = self.database.search_patterns("cryptographic")
        self.assertIsInstance(crypto_patterns, list)
        
        # 3. Create pattern matches
        test_matches = []
        for pattern in crypto_patterns[:3]:  # Take first 3
            match = PatternMatch(
                pattern=pattern,
                match_confidence=0.80,
                match_location="TestClass.testMethod"
            )
            test_matches.append(match)
        
        # 4. Correlate patterns
        if test_matches:
            correlation_result = self.correlation_engine.correlate_patterns(test_matches)
            self.assertIsInstance(correlation_result, PatternCorrelationResult)
        
        # 5. Learn from observations
        for match in test_matches:
            behavioral_data = {
                "pattern_id": match.pattern.pattern_id,
                "confidence": match.match_confidence,
                "location": match.match_location
            }
            self.learner.observe_behavioral_data(behavioral_data)
        
        # 6. Verify learning occurred
        learned_patterns = self.learner.get_learned_patterns()
        self.assertIsInstance(learned_patterns, list)
    
    def test_pattern_fusion_workflow(self):
        """Test pattern fusion across different sources."""
        self.database.load_patterns()
        
        # Get patterns from different categories
        crypto_patterns = self.database.get_patterns_by_category(PatternCategory.CRYPTOGRAPHIC)
        
        if crypto_patterns:
            # Create mixed matches
            mixed_matches = []
            for i, pattern in enumerate(crypto_patterns[:2]):
                match = PatternMatch(
                    pattern=pattern,
                    match_confidence=0.75 + (i * 0.1),
                    match_location=f"FusionTest.method{i}"
                )
                mixed_matches.append(match)
            
            # Test correlation with mixed patterns
            correlation_result = self.correlation_engine.correlate_patterns(mixed_matches)
            self.assertIsInstance(correlation_result, PatternCorrelationResult)


class TestPerformanceAndScalability(unittest.TestCase):
    """Test performance and scalability aspects."""
    
    def setUp(self):
        """Set up test fixtures for performance testing."""
        self.database = AdvancedPatternDatabase({
            "builtin_patterns": {"target_pattern_count": 100}
        })
        self.correlation_engine = PatternCorrelationEngine({})
        self.learner = DynamicPatternLearner({})
    
    def test_pattern_loading_performance(self):
        """Test pattern loading performance."""
        start_time = time.time()
        self.database.load_patterns()
        loading_time = time.time() - start_time
        
        # Should load patterns reasonably quickly
        self.assertLess(loading_time, 5.0)  # 5 seconds max
        self.assertGreater(len(self.database.patterns), 0)
    
    def test_pattern_search_performance(self):
        """Test pattern search performance."""
        self.database.load_patterns()
        
        start_time = time.time()
        results = self.database.search_patterns("cryptographic")
        search_time = time.time() - start_time
        
        # Search should be fast
        self.assertLess(search_time, 1.0)  # 1 second max
        self.assertIsInstance(results, list)
    
    def test_correlation_performance(self):
        """Test correlation engine performance."""
        self.database.load_patterns()
        patterns = self.database.patterns[:10]  # Take first 10
        
        matches = [
            PatternMatch(
                pattern=pattern,
                match_confidence=0.8,
                match_location=f"TestClass.method{i}"
            )
            for i, pattern in enumerate(patterns)
        ]
        
        start_time = time.time()
        correlation_result = self.correlation_engine.correlate_patterns(matches)
        correlation_time = time.time() - start_time
        
        # Correlation should be reasonably fast
        self.assertLess(correlation_time, 2.0)  # 2 seconds max
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
    
    def test_learning_scalability(self):
        """Test learning system scalability."""
        # Test with larger number of observations
        start_time = time.time()
        
        for i in range(100):  # 100 observations
            behavioral_data = {
                "api_call": f"TestAPI.method{i % 10}",
                "frequency": i,
                "confidence": 0.7 + (i % 3) * 0.1
            }
            self.learner.observe_behavioral_data(behavioral_data)
        
        learning_time = time.time() - start_time
        
        # Learning should handle multiple observations efficiently
        self.assertLess(learning_time, 3.0)  # 3 seconds max
        
        learned_patterns = self.learner.get_learned_patterns()
        self.assertIsInstance(learned_patterns, list)


class TestErrorHandlingAndEdgeCases(unittest.TestCase):
    """Test error handling and edge cases."""
    
    def setUp(self):
        """Set up test fixtures for error testing."""
        self.database = AdvancedPatternDatabase({})
        self.correlation_engine = PatternCorrelationEngine({})
        self.learner = DynamicPatternLearner({})
    
    def test_invalid_pattern_search(self):
        """Test handling of invalid pattern searches."""
        # Test with None query
        results = self.database.search_patterns(None)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 0)
        
        # Test with empty query
        results = self.database.search_patterns("")
        self.assertIsInstance(results, list)
        
        # Test with invalid category
        try:
            results = self.database.get_patterns_by_category("invalid_category")
            self.assertIsInstance(results, list)
        except (ValueError, TypeError):
            pass  # Expected behavior
    
    def test_empty_correlation_input(self):
        """Test correlation with empty input."""
        # Test with empty matches list
        correlation_result = self.correlation_engine.correlate_patterns([])
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
        self.assertEqual(len(correlation_result.correlated_matches), 0)
        
        # Test with None input
        correlation_result = self.correlation_engine.correlate_patterns(None)
        self.assertIsInstance(correlation_result, PatternCorrelationResult)
    
    def test_invalid_learning_data(self):
        """Test learning with invalid data."""
        # Test with None data
        try:
            self.learner.observe_behavioral_data(None)
        except (ValueError, TypeError):
            pass  # Expected behavior
        
        # Test with empty data
        try:
            self.learner.observe_behavioral_data({})
        except (ValueError, TypeError):
            pass  # Expected behavior
        
        # Test with malformed data
        try:
            self.learner.observe_behavioral_data({"invalid": "data"})
        except (ValueError, TypeError):
            pass  # Expected behavior
    
    def test_configuration_edge_cases(self):
        """Test configuration edge cases."""
        # Test with None config
        database_none = AdvancedPatternDatabase(None)
        self.assertIsNotNone(database_none)
        
        # Test with empty config
        database_empty = AdvancedPatternDatabase({})
        self.assertIsNotNone(database_empty)
        
        # Test with invalid config values
        invalid_config = {
            "storage": {"cache_ttl": -1, "max_cache_entries": "invalid"},
            "builtin_patterns": {"target_pattern_count": -5}
        }
        database_invalid = AdvancedPatternDatabase(invalid_config)
        self.assertIsNotNone(database_invalid)


class TestPluginIntegration(unittest.TestCase):
    """Test integration with AODS plugin framework."""
    
    def test_factory_functions(self):
        """Test factory function creation."""
        # Test database factory
        database = create_advanced_pattern_database({})
        self.assertIsInstance(database, AdvancedPatternDatabase)
        
        # Test correlation engine factory
        engine = create_pattern_correlation_engine({})
        self.assertIsInstance(engine, PatternCorrelationEngine)
        
        # Test learner factory
        learner = create_dynamic_pattern_learner({})
        self.assertIsInstance(learner, DynamicPatternLearner)
    
    @patch('sys.modules')
    def test_aods_plugin_compatibility(self, mock_modules):
        """Test compatibility with AODS plugin framework."""
        # Mock AODS core components
        mock_modules['core.shared_infrastructure.cross_plugin_utilities'] = Mock()
        
        # Test plugin initialization with mocked dependencies
        try:
            database = create_advanced_pattern_database({})
            self.assertIsInstance(database, AdvancedPatternDatabase)
        except ImportError:
            # Expected in test environment
            self.skipTest("AODS core components not available in test environment")


# Async test support
class TestAsyncPatternOperations(unittest.TestCase):
    """Test async pattern operations."""
    
    def setUp(self):
        """Set up async test fixtures."""
        self.database = AdvancedPatternDatabase({})
        self.correlation_engine = PatternCorrelationEngine({})
    
    def test_async_pattern_loading(self):
        """Test async pattern loading simulation."""
        async def async_load_test():
            # Simulate async pattern loading
            await asyncio.sleep(0.1)
            self.database.load_patterns()
            return len(self.database.patterns)
        
        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(async_load_test())
            self.assertGreaterEqual(result, 0)
        finally:
            loop.close()
    
    def test_concurrent_operations(self):
        """Test concurrent pattern operations."""
        async def concurrent_test():
            # Load patterns first
            self.database.load_patterns()
            
            # Simulate concurrent operations
            tasks = []
            for i in range(5):
                task = asyncio.create_task(self._async_search_operation(f"search_{i}"))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            return results
        
        async def _async_search_operation(self, query):
            await asyncio.sleep(0.05)  # Simulate async work
            return self.database.search_patterns(query)
        
        self._async_search_operation = _async_search_operation
        
        # Run concurrent test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(concurrent_test())
            self.assertEqual(len(results), 5)
            for result in results:
                self.assertIsInstance(result, list)
        finally:
            loop.close()


# Test runner functions
def run_comprehensive_tests():
    """Run all comprehensive tests."""
    print("🧪 Running Advanced Pattern Integration Comprehensive Tests...")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestAdvancedSecurityPattern,
        TestPatternMatch,
        TestAdvancedPatternDatabase,
        TestPatternCorrelationEngine,
        TestDynamicPatternLearner,
        TestPatternIntegrationWorkflow,
        TestPerformanceAndScalability,
        TestErrorHandlingAndEdgeCases,
        TestPluginIntegration
    ]
    
    for test_class in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_class))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n📊 Test Summary:")
    print(f"   Tests run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    print(f"   Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    return result.wasSuccessful()


def run_async_integration_tests():
    """Run async integration tests."""
    print("\n🔄 Running Async Integration Tests...")
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAsyncPatternOperations)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_performance_benchmarks():
    """Run performance benchmarks."""
    print("\n⚡ Running Performance Benchmarks...")
    
    database = AdvancedPatternDatabase({
        "builtin_patterns": {"target_pattern_count": 200}
    })
    
    # Benchmark pattern loading
    start_time = time.time()
    database.load_patterns()
    load_time = time.time() - start_time
    
    print(f"   Pattern Loading: {load_time:.3f}s ({len(database.patterns)} patterns)")
    
    # Benchmark search operations
    search_times = []
    for query in ["crypto", "network", "security", "algorithm", "encryption"]:
        start_time = time.time()
        results = database.search_patterns(query)
        search_time = time.time() - start_time
        search_times.append(search_time)
        print(f"   Search '{query}': {search_time:.3f}s ({len(results)} results)")
    
    avg_search_time = sum(search_times) / len(search_times)
    print(f"   Average Search Time: {avg_search_time:.3f}s")
    
    return {
        "load_time": load_time,
        "pattern_count": len(database.patterns),
        "average_search_time": avg_search_time
    }


if __name__ == "__main__":
    print("🚀 Advanced Pattern Integration - Comprehensive Test Suite")
    print("=" * 60)
    
    # Run all tests
    success = True
    
    try:
        # Run main test suite
        main_success = run_comprehensive_tests()
        success = success and main_success
        
        # Run async tests
        async_success = run_async_integration_tests()
        success = success and async_success
        
        # Run performance benchmarks
        benchmarks = run_performance_benchmarks()
        
        print(f"\n{'✅' if success else '❌'} Overall Test Status: {'PASSED' if success else 'FAILED'}")
        
        if success:
            print("\n🎉 Advanced Pattern Integration testing completed successfully!")
            print("   All components validated and ready for production use.")
        else:
            print("\n⚠️  Some tests failed. Please review and address issues before deployment.")
    
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        success = False
    
    # Exit with appropriate code
    sys.exit(0 if success else 1) 