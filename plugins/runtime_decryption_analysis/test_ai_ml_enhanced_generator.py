#!/usr/bin/env python3
"""
Comprehensive Test Suite for AI/ML-Enhanced Frida Script Generator

Tests all AI/ML enhancement features including:
- Intelligent hook selection and ML classification
- CVE correlation and threat intelligence integration
- ML-enhanced confidence scoring and validation
- Adaptive script generation and runtime feedback
- Error handling and fallback mechanisms
- Performance and integration testing

Test Categories:
- Unit Tests: Individual component testing
- Integration Tests: ML component interaction testing
- Performance Tests: Generation speed and memory usage
- Edge Case Tests: Error conditions and boundary cases
- Mock Tests: External dependency simulation
"""

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import sys
import os

# Add the plugin directory to Python path for testing
plugin_dir = Path(__file__).parent
sys.path.insert(0, str(plugin_dir))

# Import components under test
from ai_ml_enhanced_generator import (
    AIMLEnhancedFridaScriptGenerator,
    MLHookIntelligenceAnalyzer,
    MLHookRecommendation,
    AIMLScriptGenerationContext,
    AIMLEnhancedScript,
    create_ai_ml_enhanced_generator,
    generate_intelligent_frida_script
)

from data_structures import RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
from frida_script_generator import ScriptGenerationContext, GeneratedScript


class TestMLHookRecommendation(unittest.TestCase):
    """Test MLHookRecommendation data structure."""
    
    def test_valid_recommendation_creation(self):
        """Test creating a valid ML hook recommendation."""
        recommendation = MLHookRecommendation(
            hook_name="cipher_hooks",
            confidence_score=0.85,
            effectiveness_prediction=0.78,
            vulnerability_types=["weak_cryptography", "key_management"],
            cve_correlations=["CVE-2023-1234", "CVE-2024-5678"],
            reasoning="High confidence based on cipher pattern analysis",
            priority=8,
            estimated_detection_rate=0.82,
            false_positive_risk=0.12
        )
        
        self.assertEqual(recommendation.hook_name, "cipher_hooks")
        self.assertEqual(recommendation.confidence_score, 0.85)
        self.assertEqual(len(recommendation.vulnerability_types), 2)
        self.assertEqual(len(recommendation.cve_correlations), 2)
        self.assertEqual(recommendation.priority, 8)
    
    def test_invalid_confidence_score(self):
        """Test validation of confidence score bounds."""
        with self.assertRaises(Exception):
            MLHookRecommendation(
                hook_name="test_hook",
                confidence_score=1.5,  # Invalid: > 1.0
                effectiveness_prediction=0.5,
                vulnerability_types=[],
                cve_correlations=[],
                reasoning="Test",
                priority=1,
                estimated_detection_rate=0.5,
                false_positive_risk=0.1
            )
    
    def test_invalid_priority(self):
        """Test validation of priority values."""
        with self.assertRaises(Exception):
            MLHookRecommendation(
                hook_name="test_hook",
                confidence_score=0.5,
                effectiveness_prediction=0.5,
                vulnerability_types=[],
                cve_correlations=[],
                reasoning="Test",
                priority=0,  # Invalid: must be >= 1
                estimated_detection_rate=0.5,
                false_positive_risk=0.1
            )


class TestAIMLScriptGenerationContext(unittest.TestCase):
    """Test AI/ML-enhanced script generation context."""
    
    def test_context_creation_with_defaults(self):
        """Test creating context with default AI/ML settings."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="cipher_usage",
                description="AES cipher implementation detected",
                location="com.example.crypto.CipherManager",
                severity=VulnerabilitySeverity.HIGH,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        context = AIMLScriptGenerationContext(findings=findings)
        
        self.assertTrue(context.enable_ml_hook_selection)
        self.assertTrue(context.enable_cve_correlation)
        self.assertTrue(context.enable_adaptive_generation)
        self.assertEqual(context.ml_confidence_threshold, 0.7)
        self.assertEqual(context.max_ml_hooks, 15)
        self.assertEqual(context.target_cve_years, [2023, 2024, 2025])
    
    def test_context_custom_configuration(self):
        """Test creating context with custom AI/ML configuration."""
        findings = []
        
        context = AIMLScriptGenerationContext(
            findings=findings,
            enable_ml_hook_selection=False,
            enable_cve_correlation=True,
            ml_confidence_threshold=0.8,
            max_ml_hooks=10,
            vulnerability_focus=["weak_cryptography", "key_management"],
            target_cve_years=[2024, 2025]
        )
        
        self.assertFalse(context.enable_ml_hook_selection)
        self.assertTrue(context.enable_cve_correlation)
        self.assertEqual(context.ml_confidence_threshold, 0.8)
        self.assertEqual(context.max_ml_hooks, 10)
        self.assertEqual(len(context.vulnerability_focus), 2)
        self.assertEqual(len(context.target_cve_years), 2)
    
    def test_invalid_ml_confidence_threshold(self):
        """Test validation of ML confidence threshold."""
        findings = []
        
        with self.assertRaises(Exception):
            AIMLScriptGenerationContext(
                findings=findings,
                ml_confidence_threshold=1.5  # Invalid: > 1.0
            )
    
    def test_invalid_max_ml_hooks(self):
        """Test validation of max ML hooks."""
        findings = []
        
        with self.assertRaises(Exception):
            AIMLScriptGenerationContext(
                findings=findings,
                max_ml_hooks=-5  # Invalid: must be positive
            )


class TestMLHookIntelligenceAnalyzer(unittest.TestCase):
    """Test ML Hook Intelligence Analyzer."""
    
    def setUp(self):
        """Set up test configuration."""
        self.config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True},
                'intelligence_engine': {'enabled': True},
                'confidence_scoring': {'enabled': True},
                'pattern_engine': {'enabled': True}
            }
        }
        
        self.analyzer = MLHookIntelligenceAnalyzer(self.config)
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(self.analyzer.config, self.config)
        self.assertIsNotNone(self.analyzer.logger)
        self.assertIsNotNone(self.analyzer.validator)
    
    @patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', False)
    def test_analyzer_without_ml_components(self):
        """Test analyzer behavior when ML components are unavailable."""
        analyzer = MLHookIntelligenceAnalyzer(self.config)
        
        self.assertIsNone(analyzer.ml_manager)
        self.assertIsNone(analyzer.intelligence_engine)
        self.assertIsNone(analyzer.confidence_scorer)
        self.assertIsNone(analyzer.pattern_engine)
    
    @patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True)
    @patch('ai_ml_enhanced_generator.MLIntegrationManager')
    @patch('ai_ml_enhanced_generator.AdvancedIntelligenceEngine')
    def test_ml_component_initialization(self, mock_engine, mock_ml_manager):
        """Test ML component initialization when available."""
        analyzer = MLHookIntelligenceAnalyzer(self.config)
        analyzer._initialize_ml_components()
        
        # Verify components were initialized
        mock_ml_manager.assert_called_once()
        mock_engine.assert_called_once()
    
    def test_prepare_classification_data_with_finding_object(self):
        """Test data preparation with RuntimeDecryptionFinding object."""
        finding = RuntimeDecryptionFinding(
            finding_type="cipher_usage",
            description="AES cipher detected",
            location="com.example.CryptoManager",
            severity=VulnerabilitySeverity.HIGH,
            pattern_type=DecryptionType.CIPHER_USAGE
        )
        
        data = self.analyzer._prepare_classification_data(finding)
        
        self.assertEqual(data['description'], "AES cipher detected")
        self.assertEqual(data['finding_type'], "cipher_usage")
        self.assertEqual(data['location'], "com.example.CryptoManager")
        self.assertEqual(data['severity'], "HIGH")
    
    def test_prepare_classification_data_with_dict(self):
        """Test data preparation with dictionary input."""
        finding = {
            'description': 'Weak cipher implementation',
            'finding_type': 'weak_crypto',
            'severity': 'CRITICAL',
            'location': 'com.example.WeakCrypto'
        }
        
        data = self.analyzer._prepare_classification_data(finding)
        
        self.assertEqual(data['description'], 'Weak cipher implementation')
        self.assertEqual(data['finding_type'], 'weak_crypto')
        self.assertEqual(data['severity'], 'CRITICAL')
        self.assertEqual(data['location'], 'com.example.WeakCrypto')
    
    def test_extract_vulnerability_text(self):
        """Test vulnerability text extraction."""
        finding = RuntimeDecryptionFinding(
            finding_type="key_management",
            description="Hardcoded encryption key detected",
            location="com.example.KeyManager",
            severity=VulnerabilitySeverity.CRITICAL,
            pattern_type=DecryptionType.KEY_DERIVATION
        )
        
        text = self.analyzer._extract_vulnerability_text(finding)
        
        self.assertIn("Hardcoded encryption key detected", text)
        self.assertIn("key_management", text)
        self.assertIn("com.example.KeyManager", text)
    
    async def test_calculate_ml_confidence_fallback(self):
        """Test ML confidence calculation fallback."""
        hook_data = {'hook_name': 'cipher_hooks', 'pattern_matches': []}
        ml_classifications = []
        
        confidence = await self.analyzer._calculate_ml_confidence(hook_data, ml_classifications)
        
        self.assertEqual(confidence, 0.5)  # Fallback confidence
    
    def test_predict_hook_effectiveness(self):
        """Test hook effectiveness prediction."""
        hook_data = {
            'hook_name': 'cipher_hooks',
            'pattern_matches': ['pattern1', 'pattern2', 'pattern3']
        }
        
        # Mock ML classifications
        mock_classification = Mock()
        mock_classification.confidence = 0.8
        ml_classifications = [mock_classification]
        
        effectiveness = self.analyzer._predict_hook_effectiveness(hook_data, ml_classifications)
        
        self.assertGreater(effectiveness, 0.1)
        self.assertLessEqual(effectiveness, 0.95)
    
    def test_extract_vulnerability_types(self):
        """Test vulnerability type extraction."""
        hook_data = {'hook_name': 'cipher_hooks'}
        
        # Mock ML classification
        mock_classification = Mock()
        mock_classification.vulnerability_type = 'crypto_implementation'
        ml_classifications = [mock_classification]
        
        vuln_types = self.analyzer._extract_vulnerability_types(hook_data, ml_classifications)
        
        self.assertIn('weak_cryptography', vuln_types)
        self.assertIn('crypto_implementation', vuln_types)
    
    def test_calculate_hook_priority(self):
        """Test hook priority calculation."""
        hook_data = {
            'hook_name': 'cipher_hooks',
            'pattern_matches': ['p1', 'p2']
        }
        
        context = AIMLScriptGenerationContext(
            findings=[],
            vulnerability_focus=['weak_cryptography']
        )
        
        priority = self.analyzer._calculate_hook_priority(hook_data, context)
        
        self.assertGreaterEqual(priority, 5)  # Base priority
    
    def test_estimate_detection_rate(self):
        """Test detection rate estimation."""
        hook_data = {'hook_name': 'cipher_hooks'}
        
        # Mock ML classification
        mock_classification = Mock()
        mock_classification.confidence = 0.85
        ml_classifications = [mock_classification]
        
        detection_rate = self.analyzer._estimate_detection_rate(hook_data, ml_classifications)
        
        self.assertGreaterEqual(detection_rate, 0.3)
        self.assertLessEqual(detection_rate, 0.95)
    
    def test_estimate_false_positive_risk(self):
        """Test false positive risk estimation."""
        hook_data = {
            'hook_name': 'cipher_hooks',
            'pattern_matches': ['p1', 'p2', 'p3']  # Multiple patterns = lower FP risk
        }
        
        fp_risk = self.analyzer._estimate_false_positive_risk(hook_data)
        
        self.assertGreaterEqual(fp_risk, 0.02)
        self.assertLessEqual(fp_risk, 0.30)


class TestAIMLEnhancedFridaScriptGenerator(unittest.TestCase):
    """Test AI/ML-Enhanced Frida Script Generator."""
    
    def setUp(self):
        """Set up test configuration and generator."""
        self.config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True},
                'intelligence_engine': {'enabled': True},
                'confidence_scoring': {'enabled': True},
                'pattern_engine': {'enabled': True}
            },
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        self.generator = AIMLEnhancedFridaScriptGenerator(self.config)
    
    def test_generator_initialization(self):
        """Test generator initialization."""
        self.assertIsNotNone(self.generator)
        self.assertTrue(self.generator.ai_ml_enabled)
        self.assertIsNotNone(self.generator.hook_intelligence_analyzer)
    
    @patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', False)
    def test_generator_without_ml_components(self):
        """Test generator behavior when ML components are unavailable."""
        generator = AIMLEnhancedFridaScriptGenerator(self.config)
        
        self.assertFalse(generator.ai_ml_enabled)
        self.assertIsNone(generator.hook_intelligence_analyzer)
    
    def test_ai_ml_config_disabled(self):
        """Test generator with AI/ML disabled in config."""
        config = {
            'ai_ml_enhancement': {'enabled': False},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        generator = AIMLEnhancedFridaScriptGenerator(config)
        
        self.assertFalse(generator.ai_ml_enabled)
    
    async def test_generate_ai_ml_enhanced_script_basic(self):
        """Test basic AI/ML-enhanced script generation."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="cipher_usage",
                description="AES cipher implementation detected",
                location="com.example.crypto.CipherManager",
                severity=VulnerabilitySeverity.HIGH,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        # Mock the hook intelligence analyzer
        with patch.object(self.generator, 'hook_intelligence_analyzer') as mock_analyzer:
            mock_analyzer.analyze_hook_intelligence = AsyncMock(return_value=[])
            
            result = await self.generator.generate_ai_ml_enhanced_script(findings)
            
            self.assertIsInstance(result, AIMLEnhancedScript)
            self.assertIsNotNone(result.script_content)
            self.assertGreater(result.generation_time, 0)
    
    async def test_generate_enhanced_script_with_ml_recommendations(self):
        """Test script generation with ML recommendations."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="weak_crypto",
                description="Weak DES algorithm usage detected",
                location="com.example.crypto.WeakCrypto",
                severity=VulnerabilitySeverity.CRITICAL,
                pattern_type=DecryptionType.WEAK_ALGORITHM
            )
        ]
        
        # Create mock ML recommendations
        mock_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.82,
                vulnerability_types=["weak_cryptography"],
                cve_correlations=["CVE-2023-1234"],
                reasoning="High confidence DES vulnerability detection",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        # Mock the hook intelligence analyzer
        with patch.object(self.generator, 'hook_intelligence_analyzer') as mock_analyzer:
            mock_analyzer.analyze_hook_intelligence = AsyncMock(return_value=mock_recommendations)
            
            context = AIMLScriptGenerationContext(
                findings=findings,
                ml_confidence_threshold=0.7
            )
            
            result = await self.generator.generate_ai_ml_enhanced_script(findings, context)
            
            self.assertIsInstance(result, AIMLEnhancedScript)
            self.assertTrue(result.ml_enhanced)
            self.assertEqual(len(result.ml_hook_recommendations), 1)
            self.assertGreater(len(result.intelligence_metadata), 0)
    
    async def test_generate_script_with_error_handling(self):
        """Test script generation with error conditions."""
        findings = [
            {'invalid': 'finding'}  # Invalid finding format
        ]
        
        result = await self.generator.generate_ai_ml_enhanced_script(findings)
        
        # Should return a result with error information
        self.assertIsInstance(result, AIMLEnhancedScript)
        self.assertIsNotNone(result.error_message)
        self.assertIn('fallback_used', result.intelligence_metadata)
    
    def test_integrate_ml_recommendations(self):
        """Test ML recommendation integration."""
        base_hooks = ['cipher_hooks', 'base64_hooks']
        
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="key_derivation_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["key_management"],
                cve_correlations=["CVE-2024-1111"],
                reasoning="High confidence key management vulnerability",
                priority=7,
                estimated_detection_rate=0.80,
                false_positive_risk=0.15
            )
        ]
        
        context = AIMLScriptGenerationContext(
            findings=[],
            ml_confidence_threshold=0.7,
            max_hooks_per_script=5
        )
        
        enhanced_hooks = self.generator._integrate_ml_recommendations(
            base_hooks, ml_recommendations, context
        )
        
        self.assertIn('key_derivation_hooks', enhanced_hooks)
        self.assertLessEqual(len(enhanced_hooks), context.max_hooks_per_script)
    
    def test_extract_cve_correlations(self):
        """Test CVE correlation extraction."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography"],
                cve_correlations=["CVE-2023-1234", "CVE-2024-5678"],
                reasoning="Multiple CVE correlations found",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        correlations = self.generator._extract_cve_correlations(ml_recommendations)
        
        self.assertEqual(len(correlations), 2)
        self.assertEqual(correlations[0]['cve_id'], "CVE-2023-1234")
        self.assertEqual(correlations[1]['cve_id'], "CVE-2024-5678")
    
    def test_generate_vulnerability_predictions(self):
        """Test vulnerability prediction generation."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography", "crypto_implementation"],
                cve_correlations=["CVE-2023-1234"],
                reasoning="ML analysis indicates high probability of weak crypto",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        predictions = self.generator._generate_vulnerability_predictions(ml_recommendations)
        
        self.assertEqual(len(predictions), 1)
        prediction = predictions[0]
        self.assertEqual(prediction['hook_name'], "cipher_hooks")
        self.assertEqual(len(prediction['predicted_vulnerabilities']), 2)
        self.assertEqual(prediction['detection_rate'], 0.85)
        self.assertEqual(prediction['false_positive_risk'], 0.10)
    
    def test_calculate_ml_confidence_scores(self):
        """Test ML confidence score calculation."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography"],
                cve_correlations=["CVE-2023-1234"],
                reasoning="High confidence analysis",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            ),
            MLHookRecommendation(
                hook_name="base64_hooks",
                confidence_score=0.72,
                effectiveness_prediction=0.65,
                vulnerability_types=["data_encoding"],
                cve_correlations=[],
                reasoning="Moderate confidence analysis",
                priority=5,
                estimated_detection_rate=0.70,
                false_positive_risk=0.20
            )
        ]
        
        confidence_scores = self.generator._calculate_ml_confidence_scores(ml_recommendations)
        
        self.assertEqual(confidence_scores['cipher_hooks'], 0.85)
        self.assertEqual(confidence_scores['base64_hooks'], 0.72)
    
    def test_generate_intelligence_metadata(self):
        """Test intelligence metadata generation."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography", "crypto_implementation"],
                cve_correlations=["CVE-2023-1234", "CVE-2024-5678"],
                reasoning="High confidence ML analysis",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        metadata = self.generator._generate_intelligence_metadata(ml_recommendations)
        
        self.assertTrue(metadata['ml_enhanced'])
        self.assertEqual(metadata['recommendations_count'], 1)
        self.assertEqual(metadata['total_cve_correlations'], 2)
        self.assertEqual(metadata['high_confidence_recommendations'], 1)
        self.assertIn('weak_cryptography', metadata['vulnerability_types_covered'])
        self.assertIn('crypto_implementation', metadata['vulnerability_types_covered'])


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""
    
    def test_create_ai_ml_enhanced_generator(self):
        """Test convenience function for creating enhanced generator."""
        config = {
            'ai_ml_enhancement': {'enabled': True},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        generator = create_ai_ml_enhanced_generator(config)
        
        self.assertIsInstance(generator, AIMLEnhancedFridaScriptGenerator)
    
    async def test_generate_intelligent_frida_script(self):
        """Test convenience function for generating intelligent scripts."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="cipher_usage",
                description="Test cipher usage",
                location="com.example.Test",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_script.js"
            
            # Mock the AODS ML components to avoid import errors
            with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
                with patch('ai_ml_enhanced_generator.MLIntegrationManager'):
                    with patch('ai_ml_enhanced_generator.AdvancedIntelligenceEngine'):
                        result = await generate_intelligent_frida_script(
                            findings, output_path, {'ai_ml_enhancement': {'enabled': True}}
                        )
            
            self.assertIsInstance(result, AIMLEnhancedScript)
            self.assertIsNotNone(result.script_content)


class TestIntegrationScenarios(unittest.TestCase):
    """Test realistic integration scenarios."""
    
    async def test_complete_ai_ml_workflow(self):
        """Test complete AI/ML-enhanced workflow."""
        # Realistic findings from Android app analysis
        findings = [
            RuntimeDecryptionFinding(
                finding_type="weak_cipher",
                description="DES algorithm usage detected in CryptoManager",
                location="com.example.crypto.CryptoManager.decrypt()",
                severity=VulnerabilitySeverity.CRITICAL,
                pattern_type=DecryptionType.WEAK_ALGORITHM
            ),
            RuntimeDecryptionFinding(
                finding_type="hardcoded_key",
                description="Hardcoded AES key found in source code",
                location="com.example.crypto.KeyManager.getKey()",
                severity=VulnerabilitySeverity.HIGH,
                pattern_type=DecryptionType.KEY_DERIVATION
            ),
            RuntimeDecryptionFinding(
                finding_type="base64_encoding",
                description="Base64 encoded sensitive data detected",
                location="com.example.utils.EncodingUtils.encode()",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.RESOURCE_DECRYPTION
            )
        ]
        
        config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True, 'classification_threshold': 0.7},
                'intelligence_engine': {'enabled': True, 'enable_cve_correlation': True},
                'confidence_scoring': {'enabled': True, 'min_confidence_threshold': 0.6},
                'pattern_engine': {'enabled': True, 'pattern_confidence_threshold': 0.5}
            },
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        # Mock the ML components
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
            with patch('ai_ml_enhanced_generator.MLIntegrationManager') as mock_ml:
                with patch('ai_ml_enhanced_generator.AdvancedIntelligenceEngine') as mock_engine:
                    with patch('ai_ml_enhanced_generator.MLEnhancedConfidenceScorer') as mock_scorer:
                        
                        generator = AIMLEnhancedFridaScriptGenerator(config)
                        
                        context = AIMLScriptGenerationContext(
                            findings=findings,
                            enable_ml_hook_selection=True,
                            enable_cve_correlation=True,
                            ml_confidence_threshold=0.7,
                            vulnerability_focus=["weak_cryptography", "key_management"]
                        )
                        
                        result = await generator.generate_ai_ml_enhanced_script(findings, context)
                        
                        # Verify results
                        self.assertIsInstance(result, AIMLEnhancedScript)
                        self.assertIsNotNone(result.script_content)
                        self.assertGreater(result.generation_time, 0)
                        self.assertGreaterEqual(len(result.hooks_generated), 1)
    
    async def test_performance_with_large_finding_set(self):
        """Test performance with large number of findings."""
        # Generate a large set of findings
        findings = []
        for i in range(100):
            finding = RuntimeDecryptionFinding(
                finding_type=f"test_finding_{i}",
                description=f"Test finding {i} for performance testing",
                location=f"com.example.test.Class{i}.method{i}()",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
            findings.append(finding)
        
        config = {
            'ai_ml_enhancement': {'enabled': True},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
            generator = AIMLEnhancedFridaScriptGenerator(config)
            
            start_time = time.time()
            result = await generator.generate_ai_ml_enhanced_script(findings)
            generation_time = time.time() - start_time
            
            # Performance assertions
            self.assertLess(generation_time, 30.0)  # Should complete within 30 seconds
            self.assertIsInstance(result, AIMLEnhancedScript)
    
    def test_error_recovery_scenarios(self):
        """Test error recovery in various failure scenarios."""
        config = {
            'ai_ml_enhancement': {'enabled': True},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        # Test with missing ML components
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', False):
            generator = AIMLEnhancedFridaScriptGenerator(config)
            self.assertFalse(generator.ai_ml_enabled)
        
        # Test with invalid configuration
        invalid_config = {'ai_ml_enhancement': {'enabled': 'invalid'}}
        generator = AIMLEnhancedFridaScriptGenerator(invalid_config)
        self.assertIsNotNone(generator)  # Should still initialize
    
    async def test_edge_case_findings(self):
        """Test handling of edge case findings."""
        # Empty findings list
        result1 = await generate_intelligent_frida_script([], None, {})
        self.assertIsInstance(result1, AIMLEnhancedScript)
        
        # Invalid finding format
        invalid_findings = [{'invalid': 'structure'}]
        result2 = await generate_intelligent_frida_script(invalid_findings, None, {})
        self.assertIsInstance(result2, AIMLEnhancedScript)
        
        # Mixed valid and invalid findings
        mixed_findings = [
            RuntimeDecryptionFinding(
                finding_type="valid_finding",
                description="Valid finding",
                location="com.example.Valid",
                severity=VulnerabilitySeverity.LOW,
                pattern_type=DecryptionType.CIPHER_USAGE
            ),
            {'invalid': 'finding'},
            None  # Null finding
        ]
        result3 = await generate_intelligent_frida_script(mixed_findings, None, {})
        self.assertIsInstance(result3, AIMLEnhancedScript)


def run_comprehensive_test():
    """Run comprehensive test suite for AI/ML enhanced generator."""
    print("🧪 Starting AI/ML Enhanced Frida Script Generator Test Suite...")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestMLHookRecommendation,
        TestAIMLScriptGenerationContext,
        TestMLHookIntelligenceAnalyzer,
        TestAIMLEnhancedFridaScriptGenerator,
        TestConvenienceFunctions,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(test_suite)
    
    # Print summary
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = ((total_tests - failures - errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n📊 Test Results Summary:")
    print(f"   Total Tests: {total_tests}")
    print(f"   Passed: {total_tests - failures - errors}")
    print(f"   Failed: {failures}")
    print(f"   Errors: {errors}")
    print(f"   Success Rate: {success_rate:.1f}%")
    
    if failures > 0:
        print(f"\n❌ Failed Tests:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.split('AssertionError:')[-1].strip() if 'AssertionError:' in traceback else 'Unknown failure'}")
    
    if errors > 0:
        print(f"\n🚨 Error Tests:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.split('Error:')[-1].strip() if 'Error:' in traceback else 'Unknown error'}")
    
    # Performance and integration tests
    print(f"\n🚀 Running Performance and Integration Tests...")
    asyncio.run(run_async_tests())
    
    return result.wasSuccessful()


async def run_async_tests():
    """Run async test scenarios."""
    try:
        # Basic functionality test
        findings = [
            RuntimeDecryptionFinding(
                finding_type="test_cipher",
                description="Test cipher for async testing",
                location="com.example.AsyncTest",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        # Test with minimal config
        result = await generate_intelligent_frida_script(findings)
        print(f"   ✅ Basic async generation: {len(result.script_content) if result.script_content else 0} characters generated")
        
        # Test with advanced config
        config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True},
                'intelligence_engine': {'enabled': True}
            }
        }
        
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
            result2 = await generate_intelligent_frida_script(findings, None, config)
            print(f"   ✅ Advanced async generation: {len(result2.script_content) if result2.script_content else 0} characters generated")
        
        print(f"   ✅ All async tests completed successfully")
        
    except Exception as e:
        print(f"   ❌ Async test failed: {e}")


if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1) 
"""
Comprehensive Test Suite for AI/ML-Enhanced Frida Script Generator

Tests all AI/ML enhancement features including:
- Intelligent hook selection and ML classification
- CVE correlation and threat intelligence integration
- ML-enhanced confidence scoring and validation
- Adaptive script generation and runtime feedback
- Error handling and fallback mechanisms
- Performance and integration testing

Test Categories:
- Unit Tests: Individual component testing
- Integration Tests: ML component interaction testing
- Performance Tests: Generation speed and memory usage
- Edge Case Tests: Error conditions and boundary cases
- Mock Tests: External dependency simulation
"""

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import sys
import os

# Add the plugin directory to Python path for testing
plugin_dir = Path(__file__).parent
sys.path.insert(0, str(plugin_dir))

# Import components under test
from ai_ml_enhanced_generator import (
    AIMLEnhancedFridaScriptGenerator,
    MLHookIntelligenceAnalyzer,
    MLHookRecommendation,
    AIMLScriptGenerationContext,
    AIMLEnhancedScript,
    create_ai_ml_enhanced_generator,
    generate_intelligent_frida_script
)

from data_structures import RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
from frida_script_generator import ScriptGenerationContext, GeneratedScript


class TestMLHookRecommendation(unittest.TestCase):
    """Test MLHookRecommendation data structure."""
    
    def test_valid_recommendation_creation(self):
        """Test creating a valid ML hook recommendation."""
        recommendation = MLHookRecommendation(
            hook_name="cipher_hooks",
            confidence_score=0.85,
            effectiveness_prediction=0.78,
            vulnerability_types=["weak_cryptography", "key_management"],
            cve_correlations=["CVE-2023-1234", "CVE-2024-5678"],
            reasoning="High confidence based on cipher pattern analysis",
            priority=8,
            estimated_detection_rate=0.82,
            false_positive_risk=0.12
        )
        
        self.assertEqual(recommendation.hook_name, "cipher_hooks")
        self.assertEqual(recommendation.confidence_score, 0.85)
        self.assertEqual(len(recommendation.vulnerability_types), 2)
        self.assertEqual(len(recommendation.cve_correlations), 2)
        self.assertEqual(recommendation.priority, 8)
    
    def test_invalid_confidence_score(self):
        """Test validation of confidence score bounds."""
        with self.assertRaises(Exception):
            MLHookRecommendation(
                hook_name="test_hook",
                confidence_score=1.5,  # Invalid: > 1.0
                effectiveness_prediction=0.5,
                vulnerability_types=[],
                cve_correlations=[],
                reasoning="Test",
                priority=1,
                estimated_detection_rate=0.5,
                false_positive_risk=0.1
            )
    
    def test_invalid_priority(self):
        """Test validation of priority values."""
        with self.assertRaises(Exception):
            MLHookRecommendation(
                hook_name="test_hook",
                confidence_score=0.5,
                effectiveness_prediction=0.5,
                vulnerability_types=[],
                cve_correlations=[],
                reasoning="Test",
                priority=0,  # Invalid: must be >= 1
                estimated_detection_rate=0.5,
                false_positive_risk=0.1
            )


class TestAIMLScriptGenerationContext(unittest.TestCase):
    """Test AI/ML-enhanced script generation context."""
    
    def test_context_creation_with_defaults(self):
        """Test creating context with default AI/ML settings."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="cipher_usage",
                description="AES cipher implementation detected",
                location="com.example.crypto.CipherManager",
                severity=VulnerabilitySeverity.HIGH,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        context = AIMLScriptGenerationContext(findings=findings)
        
        self.assertTrue(context.enable_ml_hook_selection)
        self.assertTrue(context.enable_cve_correlation)
        self.assertTrue(context.enable_adaptive_generation)
        self.assertEqual(context.ml_confidence_threshold, 0.7)
        self.assertEqual(context.max_ml_hooks, 15)
        self.assertEqual(context.target_cve_years, [2023, 2024, 2025])
    
    def test_context_custom_configuration(self):
        """Test creating context with custom AI/ML configuration."""
        findings = []
        
        context = AIMLScriptGenerationContext(
            findings=findings,
            enable_ml_hook_selection=False,
            enable_cve_correlation=True,
            ml_confidence_threshold=0.8,
            max_ml_hooks=10,
            vulnerability_focus=["weak_cryptography", "key_management"],
            target_cve_years=[2024, 2025]
        )
        
        self.assertFalse(context.enable_ml_hook_selection)
        self.assertTrue(context.enable_cve_correlation)
        self.assertEqual(context.ml_confidence_threshold, 0.8)
        self.assertEqual(context.max_ml_hooks, 10)
        self.assertEqual(len(context.vulnerability_focus), 2)
        self.assertEqual(len(context.target_cve_years), 2)
    
    def test_invalid_ml_confidence_threshold(self):
        """Test validation of ML confidence threshold."""
        findings = []
        
        with self.assertRaises(Exception):
            AIMLScriptGenerationContext(
                findings=findings,
                ml_confidence_threshold=1.5  # Invalid: > 1.0
            )
    
    def test_invalid_max_ml_hooks(self):
        """Test validation of max ML hooks."""
        findings = []
        
        with self.assertRaises(Exception):
            AIMLScriptGenerationContext(
                findings=findings,
                max_ml_hooks=-5  # Invalid: must be positive
            )


class TestMLHookIntelligenceAnalyzer(unittest.TestCase):
    """Test ML Hook Intelligence Analyzer."""
    
    def setUp(self):
        """Set up test configuration."""
        self.config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True},
                'intelligence_engine': {'enabled': True},
                'confidence_scoring': {'enabled': True},
                'pattern_engine': {'enabled': True}
            }
        }
        
        self.analyzer = MLHookIntelligenceAnalyzer(self.config)
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(self.analyzer.config, self.config)
        self.assertIsNotNone(self.analyzer.logger)
        self.assertIsNotNone(self.analyzer.validator)
    
    @patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', False)
    def test_analyzer_without_ml_components(self):
        """Test analyzer behavior when ML components are unavailable."""
        analyzer = MLHookIntelligenceAnalyzer(self.config)
        
        self.assertIsNone(analyzer.ml_manager)
        self.assertIsNone(analyzer.intelligence_engine)
        self.assertIsNone(analyzer.confidence_scorer)
        self.assertIsNone(analyzer.pattern_engine)
    
    @patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True)
    @patch('ai_ml_enhanced_generator.MLIntegrationManager')
    @patch('ai_ml_enhanced_generator.AdvancedIntelligenceEngine')
    def test_ml_component_initialization(self, mock_engine, mock_ml_manager):
        """Test ML component initialization when available."""
        analyzer = MLHookIntelligenceAnalyzer(self.config)
        analyzer._initialize_ml_components()
        
        # Verify components were initialized
        mock_ml_manager.assert_called_once()
        mock_engine.assert_called_once()
    
    def test_prepare_classification_data_with_finding_object(self):
        """Test data preparation with RuntimeDecryptionFinding object."""
        finding = RuntimeDecryptionFinding(
            finding_type="cipher_usage",
            description="AES cipher detected",
            location="com.example.CryptoManager",
            severity=VulnerabilitySeverity.HIGH,
            pattern_type=DecryptionType.CIPHER_USAGE
        )
        
        data = self.analyzer._prepare_classification_data(finding)
        
        self.assertEqual(data['description'], "AES cipher detected")
        self.assertEqual(data['finding_type'], "cipher_usage")
        self.assertEqual(data['location'], "com.example.CryptoManager")
        self.assertEqual(data['severity'], "HIGH")
    
    def test_prepare_classification_data_with_dict(self):
        """Test data preparation with dictionary input."""
        finding = {
            'description': 'Weak cipher implementation',
            'finding_type': 'weak_crypto',
            'severity': 'CRITICAL',
            'location': 'com.example.WeakCrypto'
        }
        
        data = self.analyzer._prepare_classification_data(finding)
        
        self.assertEqual(data['description'], 'Weak cipher implementation')
        self.assertEqual(data['finding_type'], 'weak_crypto')
        self.assertEqual(data['severity'], 'CRITICAL')
        self.assertEqual(data['location'], 'com.example.WeakCrypto')
    
    def test_extract_vulnerability_text(self):
        """Test vulnerability text extraction."""
        finding = RuntimeDecryptionFinding(
            finding_type="key_management",
            description="Hardcoded encryption key detected",
            location="com.example.KeyManager",
            severity=VulnerabilitySeverity.CRITICAL,
            pattern_type=DecryptionType.KEY_DERIVATION
        )
        
        text = self.analyzer._extract_vulnerability_text(finding)
        
        self.assertIn("Hardcoded encryption key detected", text)
        self.assertIn("key_management", text)
        self.assertIn("com.example.KeyManager", text)
    
    async def test_calculate_ml_confidence_fallback(self):
        """Test ML confidence calculation fallback."""
        hook_data = {'hook_name': 'cipher_hooks', 'pattern_matches': []}
        ml_classifications = []
        
        confidence = await self.analyzer._calculate_ml_confidence(hook_data, ml_classifications)
        
        self.assertEqual(confidence, 0.5)  # Fallback confidence
    
    def test_predict_hook_effectiveness(self):
        """Test hook effectiveness prediction."""
        hook_data = {
            'hook_name': 'cipher_hooks',
            'pattern_matches': ['pattern1', 'pattern2', 'pattern3']
        }
        
        # Mock ML classifications
        mock_classification = Mock()
        mock_classification.confidence = 0.8
        ml_classifications = [mock_classification]
        
        effectiveness = self.analyzer._predict_hook_effectiveness(hook_data, ml_classifications)
        
        self.assertGreater(effectiveness, 0.1)
        self.assertLessEqual(effectiveness, 0.95)
    
    def test_extract_vulnerability_types(self):
        """Test vulnerability type extraction."""
        hook_data = {'hook_name': 'cipher_hooks'}
        
        # Mock ML classification
        mock_classification = Mock()
        mock_classification.vulnerability_type = 'crypto_implementation'
        ml_classifications = [mock_classification]
        
        vuln_types = self.analyzer._extract_vulnerability_types(hook_data, ml_classifications)
        
        self.assertIn('weak_cryptography', vuln_types)
        self.assertIn('crypto_implementation', vuln_types)
    
    def test_calculate_hook_priority(self):
        """Test hook priority calculation."""
        hook_data = {
            'hook_name': 'cipher_hooks',
            'pattern_matches': ['p1', 'p2']
        }
        
        context = AIMLScriptGenerationContext(
            findings=[],
            vulnerability_focus=['weak_cryptography']
        )
        
        priority = self.analyzer._calculate_hook_priority(hook_data, context)
        
        self.assertGreaterEqual(priority, 5)  # Base priority
    
    def test_estimate_detection_rate(self):
        """Test detection rate estimation."""
        hook_data = {'hook_name': 'cipher_hooks'}
        
        # Mock ML classification
        mock_classification = Mock()
        mock_classification.confidence = 0.85
        ml_classifications = [mock_classification]
        
        detection_rate = self.analyzer._estimate_detection_rate(hook_data, ml_classifications)
        
        self.assertGreaterEqual(detection_rate, 0.3)
        self.assertLessEqual(detection_rate, 0.95)
    
    def test_estimate_false_positive_risk(self):
        """Test false positive risk estimation."""
        hook_data = {
            'hook_name': 'cipher_hooks',
            'pattern_matches': ['p1', 'p2', 'p3']  # Multiple patterns = lower FP risk
        }
        
        fp_risk = self.analyzer._estimate_false_positive_risk(hook_data)
        
        self.assertGreaterEqual(fp_risk, 0.02)
        self.assertLessEqual(fp_risk, 0.30)


class TestAIMLEnhancedFridaScriptGenerator(unittest.TestCase):
    """Test AI/ML-Enhanced Frida Script Generator."""
    
    def setUp(self):
        """Set up test configuration and generator."""
        self.config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True},
                'intelligence_engine': {'enabled': True},
                'confidence_scoring': {'enabled': True},
                'pattern_engine': {'enabled': True}
            },
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        self.generator = AIMLEnhancedFridaScriptGenerator(self.config)
    
    def test_generator_initialization(self):
        """Test generator initialization."""
        self.assertIsNotNone(self.generator)
        self.assertTrue(self.generator.ai_ml_enabled)
        self.assertIsNotNone(self.generator.hook_intelligence_analyzer)
    
    @patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', False)
    def test_generator_without_ml_components(self):
        """Test generator behavior when ML components are unavailable."""
        generator = AIMLEnhancedFridaScriptGenerator(self.config)
        
        self.assertFalse(generator.ai_ml_enabled)
        self.assertIsNone(generator.hook_intelligence_analyzer)
    
    def test_ai_ml_config_disabled(self):
        """Test generator with AI/ML disabled in config."""
        config = {
            'ai_ml_enhancement': {'enabled': False},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        generator = AIMLEnhancedFridaScriptGenerator(config)
        
        self.assertFalse(generator.ai_ml_enabled)
    
    async def test_generate_ai_ml_enhanced_script_basic(self):
        """Test basic AI/ML-enhanced script generation."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="cipher_usage",
                description="AES cipher implementation detected",
                location="com.example.crypto.CipherManager",
                severity=VulnerabilitySeverity.HIGH,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        # Mock the hook intelligence analyzer
        with patch.object(self.generator, 'hook_intelligence_analyzer') as mock_analyzer:
            mock_analyzer.analyze_hook_intelligence = AsyncMock(return_value=[])
            
            result = await self.generator.generate_ai_ml_enhanced_script(findings)
            
            self.assertIsInstance(result, AIMLEnhancedScript)
            self.assertIsNotNone(result.script_content)
            self.assertGreater(result.generation_time, 0)
    
    async def test_generate_enhanced_script_with_ml_recommendations(self):
        """Test script generation with ML recommendations."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="weak_crypto",
                description="Weak DES algorithm usage detected",
                location="com.example.crypto.WeakCrypto",
                severity=VulnerabilitySeverity.CRITICAL,
                pattern_type=DecryptionType.WEAK_ALGORITHM
            )
        ]
        
        # Create mock ML recommendations
        mock_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.82,
                vulnerability_types=["weak_cryptography"],
                cve_correlations=["CVE-2023-1234"],
                reasoning="High confidence DES vulnerability detection",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        # Mock the hook intelligence analyzer
        with patch.object(self.generator, 'hook_intelligence_analyzer') as mock_analyzer:
            mock_analyzer.analyze_hook_intelligence = AsyncMock(return_value=mock_recommendations)
            
            context = AIMLScriptGenerationContext(
                findings=findings,
                ml_confidence_threshold=0.7
            )
            
            result = await self.generator.generate_ai_ml_enhanced_script(findings, context)
            
            self.assertIsInstance(result, AIMLEnhancedScript)
            self.assertTrue(result.ml_enhanced)
            self.assertEqual(len(result.ml_hook_recommendations), 1)
            self.assertGreater(len(result.intelligence_metadata), 0)
    
    async def test_generate_script_with_error_handling(self):
        """Test script generation with error conditions."""
        findings = [
            {'invalid': 'finding'}  # Invalid finding format
        ]
        
        result = await self.generator.generate_ai_ml_enhanced_script(findings)
        
        # Should return a result with error information
        self.assertIsInstance(result, AIMLEnhancedScript)
        self.assertIsNotNone(result.error_message)
        self.assertIn('fallback_used', result.intelligence_metadata)
    
    def test_integrate_ml_recommendations(self):
        """Test ML recommendation integration."""
        base_hooks = ['cipher_hooks', 'base64_hooks']
        
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="key_derivation_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["key_management"],
                cve_correlations=["CVE-2024-1111"],
                reasoning="High confidence key management vulnerability",
                priority=7,
                estimated_detection_rate=0.80,
                false_positive_risk=0.15
            )
        ]
        
        context = AIMLScriptGenerationContext(
            findings=[],
            ml_confidence_threshold=0.7,
            max_hooks_per_script=5
        )
        
        enhanced_hooks = self.generator._integrate_ml_recommendations(
            base_hooks, ml_recommendations, context
        )
        
        self.assertIn('key_derivation_hooks', enhanced_hooks)
        self.assertLessEqual(len(enhanced_hooks), context.max_hooks_per_script)
    
    def test_extract_cve_correlations(self):
        """Test CVE correlation extraction."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography"],
                cve_correlations=["CVE-2023-1234", "CVE-2024-5678"],
                reasoning="Multiple CVE correlations found",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        correlations = self.generator._extract_cve_correlations(ml_recommendations)
        
        self.assertEqual(len(correlations), 2)
        self.assertEqual(correlations[0]['cve_id'], "CVE-2023-1234")
        self.assertEqual(correlations[1]['cve_id'], "CVE-2024-5678")
    
    def test_generate_vulnerability_predictions(self):
        """Test vulnerability prediction generation."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography", "crypto_implementation"],
                cve_correlations=["CVE-2023-1234"],
                reasoning="ML analysis indicates high probability of weak crypto",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        predictions = self.generator._generate_vulnerability_predictions(ml_recommendations)
        
        self.assertEqual(len(predictions), 1)
        prediction = predictions[0]
        self.assertEqual(prediction['hook_name'], "cipher_hooks")
        self.assertEqual(len(prediction['predicted_vulnerabilities']), 2)
        self.assertEqual(prediction['detection_rate'], 0.85)
        self.assertEqual(prediction['false_positive_risk'], 0.10)
    
    def test_calculate_ml_confidence_scores(self):
        """Test ML confidence score calculation."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography"],
                cve_correlations=["CVE-2023-1234"],
                reasoning="High confidence analysis",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            ),
            MLHookRecommendation(
                hook_name="base64_hooks",
                confidence_score=0.72,
                effectiveness_prediction=0.65,
                vulnerability_types=["data_encoding"],
                cve_correlations=[],
                reasoning="Moderate confidence analysis",
                priority=5,
                estimated_detection_rate=0.70,
                false_positive_risk=0.20
            )
        ]
        
        confidence_scores = self.generator._calculate_ml_confidence_scores(ml_recommendations)
        
        self.assertEqual(confidence_scores['cipher_hooks'], 0.85)
        self.assertEqual(confidence_scores['base64_hooks'], 0.72)
    
    def test_generate_intelligence_metadata(self):
        """Test intelligence metadata generation."""
        ml_recommendations = [
            MLHookRecommendation(
                hook_name="cipher_hooks",
                confidence_score=0.85,
                effectiveness_prediction=0.80,
                vulnerability_types=["weak_cryptography", "crypto_implementation"],
                cve_correlations=["CVE-2023-1234", "CVE-2024-5678"],
                reasoning="High confidence ML analysis",
                priority=8,
                estimated_detection_rate=0.85,
                false_positive_risk=0.10
            )
        ]
        
        metadata = self.generator._generate_intelligence_metadata(ml_recommendations)
        
        self.assertTrue(metadata['ml_enhanced'])
        self.assertEqual(metadata['recommendations_count'], 1)
        self.assertEqual(metadata['total_cve_correlations'], 2)
        self.assertEqual(metadata['high_confidence_recommendations'], 1)
        self.assertIn('weak_cryptography', metadata['vulnerability_types_covered'])
        self.assertIn('crypto_implementation', metadata['vulnerability_types_covered'])


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""
    
    def test_create_ai_ml_enhanced_generator(self):
        """Test convenience function for creating enhanced generator."""
        config = {
            'ai_ml_enhancement': {'enabled': True},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        generator = create_ai_ml_enhanced_generator(config)
        
        self.assertIsInstance(generator, AIMLEnhancedFridaScriptGenerator)
    
    async def test_generate_intelligent_frida_script(self):
        """Test convenience function for generating intelligent scripts."""
        findings = [
            RuntimeDecryptionFinding(
                finding_type="cipher_usage",
                description="Test cipher usage",
                location="com.example.Test",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_script.js"
            
            # Mock the AODS ML components to avoid import errors
            with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
                with patch('ai_ml_enhanced_generator.MLIntegrationManager'):
                    with patch('ai_ml_enhanced_generator.AdvancedIntelligenceEngine'):
                        result = await generate_intelligent_frida_script(
                            findings, output_path, {'ai_ml_enhancement': {'enabled': True}}
                        )
            
            self.assertIsInstance(result, AIMLEnhancedScript)
            self.assertIsNotNone(result.script_content)


class TestIntegrationScenarios(unittest.TestCase):
    """Test realistic integration scenarios."""
    
    async def test_complete_ai_ml_workflow(self):
        """Test complete AI/ML-enhanced workflow."""
        # Realistic findings from Android app analysis
        findings = [
            RuntimeDecryptionFinding(
                finding_type="weak_cipher",
                description="DES algorithm usage detected in CryptoManager",
                location="com.example.crypto.CryptoManager.decrypt()",
                severity=VulnerabilitySeverity.CRITICAL,
                pattern_type=DecryptionType.WEAK_ALGORITHM
            ),
            RuntimeDecryptionFinding(
                finding_type="hardcoded_key",
                description="Hardcoded AES key found in source code",
                location="com.example.crypto.KeyManager.getKey()",
                severity=VulnerabilitySeverity.HIGH,
                pattern_type=DecryptionType.KEY_DERIVATION
            ),
            RuntimeDecryptionFinding(
                finding_type="base64_encoding",
                description="Base64 encoded sensitive data detected",
                location="com.example.utils.EncodingUtils.encode()",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.RESOURCE_DECRYPTION
            )
        ]
        
        config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True, 'classification_threshold': 0.7},
                'intelligence_engine': {'enabled': True, 'enable_cve_correlation': True},
                'confidence_scoring': {'enabled': True, 'min_confidence_threshold': 0.6},
                'pattern_engine': {'enabled': True, 'pattern_confidence_threshold': 0.5}
            },
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        # Mock the ML components
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
            with patch('ai_ml_enhanced_generator.MLIntegrationManager') as mock_ml:
                with patch('ai_ml_enhanced_generator.AdvancedIntelligenceEngine') as mock_engine:
                    with patch('ai_ml_enhanced_generator.MLEnhancedConfidenceScorer') as mock_scorer:
                        
                        generator = AIMLEnhancedFridaScriptGenerator(config)
                        
                        context = AIMLScriptGenerationContext(
                            findings=findings,
                            enable_ml_hook_selection=True,
                            enable_cve_correlation=True,
                            ml_confidence_threshold=0.7,
                            vulnerability_focus=["weak_cryptography", "key_management"]
                        )
                        
                        result = await generator.generate_ai_ml_enhanced_script(findings, context)
                        
                        # Verify results
                        self.assertIsInstance(result, AIMLEnhancedScript)
                        self.assertIsNotNone(result.script_content)
                        self.assertGreater(result.generation_time, 0)
                        self.assertGreaterEqual(len(result.hooks_generated), 1)
    
    async def test_performance_with_large_finding_set(self):
        """Test performance with large number of findings."""
        # Generate a large set of findings
        findings = []
        for i in range(100):
            finding = RuntimeDecryptionFinding(
                finding_type=f"test_finding_{i}",
                description=f"Test finding {i} for performance testing",
                location=f"com.example.test.Class{i}.method{i}()",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
            findings.append(finding)
        
        config = {
            'ai_ml_enhancement': {'enabled': True},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
            generator = AIMLEnhancedFridaScriptGenerator(config)
            
            start_time = time.time()
            result = await generator.generate_ai_ml_enhanced_script(findings)
            generation_time = time.time() - start_time
            
            # Performance assertions
            self.assertLess(generation_time, 30.0)  # Should complete within 30 seconds
            self.assertIsInstance(result, AIMLEnhancedScript)
    
    def test_error_recovery_scenarios(self):
        """Test error recovery in various failure scenarios."""
        config = {
            'ai_ml_enhancement': {'enabled': True},
            'templates_config_path': str(Path(__file__).parent / 'runtime_decryption_patterns_config.yaml')
        }
        
        # Test with missing ML components
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', False):
            generator = AIMLEnhancedFridaScriptGenerator(config)
            self.assertFalse(generator.ai_ml_enabled)
        
        # Test with invalid configuration
        invalid_config = {'ai_ml_enhancement': {'enabled': 'invalid'}}
        generator = AIMLEnhancedFridaScriptGenerator(invalid_config)
        self.assertIsNotNone(generator)  # Should still initialize
    
    async def test_edge_case_findings(self):
        """Test handling of edge case findings."""
        # Empty findings list
        result1 = await generate_intelligent_frida_script([], None, {})
        self.assertIsInstance(result1, AIMLEnhancedScript)
        
        # Invalid finding format
        invalid_findings = [{'invalid': 'structure'}]
        result2 = await generate_intelligent_frida_script(invalid_findings, None, {})
        self.assertIsInstance(result2, AIMLEnhancedScript)
        
        # Mixed valid and invalid findings
        mixed_findings = [
            RuntimeDecryptionFinding(
                finding_type="valid_finding",
                description="Valid finding",
                location="com.example.Valid",
                severity=VulnerabilitySeverity.LOW,
                pattern_type=DecryptionType.CIPHER_USAGE
            ),
            {'invalid': 'finding'},
            None  # Null finding
        ]
        result3 = await generate_intelligent_frida_script(mixed_findings, None, {})
        self.assertIsInstance(result3, AIMLEnhancedScript)


def run_comprehensive_test():
    """Run comprehensive test suite for AI/ML enhanced generator."""
    print("🧪 Starting AI/ML Enhanced Frida Script Generator Test Suite...")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestMLHookRecommendation,
        TestAIMLScriptGenerationContext,
        TestMLHookIntelligenceAnalyzer,
        TestAIMLEnhancedFridaScriptGenerator,
        TestConvenienceFunctions,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(test_suite)
    
    # Print summary
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = ((total_tests - failures - errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n📊 Test Results Summary:")
    print(f"   Total Tests: {total_tests}")
    print(f"   Passed: {total_tests - failures - errors}")
    print(f"   Failed: {failures}")
    print(f"   Errors: {errors}")
    print(f"   Success Rate: {success_rate:.1f}%")
    
    if failures > 0:
        print(f"\n❌ Failed Tests:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.split('AssertionError:')[-1].strip() if 'AssertionError:' in traceback else 'Unknown failure'}")
    
    if errors > 0:
        print(f"\n🚨 Error Tests:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.split('Error:')[-1].strip() if 'Error:' in traceback else 'Unknown error'}")
    
    # Performance and integration tests
    print(f"\n🚀 Running Performance and Integration Tests...")
    asyncio.run(run_async_tests())
    
    return result.wasSuccessful()


async def run_async_tests():
    """Run async test scenarios."""
    try:
        # Basic functionality test
        findings = [
            RuntimeDecryptionFinding(
                finding_type="test_cipher",
                description="Test cipher for async testing",
                location="com.example.AsyncTest",
                severity=VulnerabilitySeverity.MEDIUM,
                pattern_type=DecryptionType.CIPHER_USAGE
            )
        ]
        
        # Test with minimal config
        result = await generate_intelligent_frida_script(findings)
        print(f"   ✅ Basic async generation: {len(result.script_content) if result.script_content else 0} characters generated")
        
        # Test with advanced config
        config = {
            'ai_ml_enhancement': {
                'enabled': True,
                'ml_integration': {'enabled': True},
                'intelligence_engine': {'enabled': True}
            }
        }
        
        with patch('ai_ml_enhanced_generator.AODS_ML_AVAILABLE', True):
            result2 = await generate_intelligent_frida_script(findings, None, config)
            print(f"   ✅ Advanced async generation: {len(result2.script_content) if result2.script_content else 0} characters generated")
        
        print(f"   ✅ All async tests completed successfully")
        
    except Exception as e:
        print(f"   ❌ Async test failed: {e}")


if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1) 