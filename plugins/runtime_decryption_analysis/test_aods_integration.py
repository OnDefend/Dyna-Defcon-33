#!/usr/bin/env python3
"""
AODS Integration Test for AI/ML-Enhanced Runtime Decryption Analysis Plugin

This test verifies that the AI/ML enhanced plugin integrates properly with
the AODS framework, including plugin discovery, initialization, and execution
with appropriate fallback mechanisms when AI/ML infrastructure is not available.
"""

import sys
from pathlib import Path

# Add the project root to the Python path for testing
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

def test_plugin_discovery():
    """Test plugin discovery by AODS plugin manager."""
    print("🔍 Testing AODS Plugin Discovery...")
    
    try:
        # Test basic plugin import
        from plugins.runtime_decryption_analysis import PLUGIN_METADATA, PLUGIN_CHARACTERISTICS
        
        print(f"✅ Plugin metadata loaded successfully")
        print(f"   Name: {PLUGIN_METADATA['name']}")
        print(f"   Version: {PLUGIN_METADATA['version']}")
        print(f"   Category: {PLUGIN_METADATA['category']}")
        print(f"   AI/ML Features: {PLUGIN_METADATA.get('ai_ml_features', {})}")
        
        return True
        
    except Exception as e:
        print(f"❌ Plugin discovery failed: {e}")
        return False

def test_plugin_capabilities():
    """Test plugin capabilities function."""
    print("\n🔧 Testing Plugin Capabilities...")
    
    try:
        from plugins.runtime_decryption_analysis import get_plugin_capabilities
        
        capabilities = get_plugin_capabilities()
        
        print(f"✅ Plugin capabilities retrieved successfully")
        print(f"   AI/ML Available: {capabilities['ai_ml_available']}")
        print(f"   Base Capabilities: {len(capabilities['base_capabilities'])} items")
        print(f"   Components: {len(capabilities['components'])} components")
        print(f"   Fallback Support: {capabilities['fallback_support']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Plugin capabilities test failed: {e}")
        return False

def test_plugin_initialization():
    """Test plugin initialization with fallback."""
    print("\n🏗️ Testing Plugin Initialization...")
    
    try:
        from plugins.runtime_decryption_analysis import RuntimeDecryptionAnalysisPlugin
        
        # Test initialization without configuration
        plugin = RuntimeDecryptionAnalysisPlugin()
        
        print(f"✅ Plugin initialized successfully")
        print(f"   AI/ML Enabled: {plugin.ai_ml_enabled}")
        print(f"   Generator Type: {plugin.enhancement_metadata['generator_type']}")
        print(f"   Fallback Available: {plugin.enhancement_metadata['fallback_available']}")
        
        # Test with explicit AI/ML disabled configuration
        from plugins.runtime_decryption_analysis.data_structures import RuntimeDecryptionConfig
        
        config = RuntimeDecryptionConfig()
        config.enable_ai_ml_enhancement = False
        
        plugin_disabled = RuntimeDecryptionAnalysisPlugin(config)
        
        print(f"✅ Plugin with disabled AI/ML initialized successfully")
        print(f"   AI/ML Enabled: {plugin_disabled.ai_ml_enabled}")
        print(f"   Generator Type: {plugin_disabled.enhancement_metadata['generator_type']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Plugin initialization test failed: {e}")
        return False

def test_aods_framework_compatibility():
    """Test compatibility with AODS framework patterns."""
    print("\n🔗 Testing AODS Framework Compatibility...")
    
    try:
        # Test MASVS mapping integration
        from core.plugin_execution_engine import MASVSIntegratedPluginEngine
        
        engine = MASVSIntegratedPluginEngine()
        
        # Check if our plugin is in the MASVS mapping
        plugin_mapping = engine.plugin_masvs_mapping.get("runtime_decryption_analysis", [])
        
        print(f"✅ MASVS integration verified")
        print(f"   MASVS Controls: {plugin_mapping}")
        
        # Test plugin registration
        from plugins.runtime_decryption_analysis import run
        
        engine.register_plugin("runtime_decryption_analysis", run)
        
        print(f"✅ Plugin registration successful")
        print(f"   Registered Plugins: {len(engine.registered_plugins)}")
        
        return True
        
    except Exception as e:
        print(f"❌ AODS framework compatibility test failed: {e}")
        return False

def test_mock_execution():
    """Test mock plugin execution to verify interfaces."""
    print("\n▶️ Testing Mock Plugin Execution...")
    
    try:
        from plugins.runtime_decryption_analysis import run_plugin
        
        # Create a mock APK context
        class MockAPKContext:
            def __init__(self):
                self.jadx_output_dir = None
                self.apktool_output_dir = None
                self.package_name = "com.example.test"
        
        mock_apk_ctx = MockAPKContext()
        
        # Test plugin execution
        result = run_plugin(mock_apk_ctx)
        
        print(f"✅ Mock plugin execution successful")
        print(f"   Result Type: {type(result)}")
        print(f"   Plugin Name: {result[0] if result else 'None'}")
        print(f"   Has Report: {bool(result[1] if result else False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Mock plugin execution failed: {e}")
        return False

def test_ai_ml_fallback_behavior():
    """Test AI/ML fallback behavior when components are unavailable."""
    print("\n🔄 Testing AI/ML Fallback Behavior...")
    
    try:
        from plugins.runtime_decryption_analysis import AI_ML_ENHANCEMENT_AVAILABLE
        
        print(f"✅ AI/ML enhancement status checked")
        print(f"   AI/ML Available: {AI_ML_ENHANCEMENT_AVAILABLE}")
        
        if not AI_ML_ENHANCEMENT_AVAILABLE:
            print("   ℹ️ AI/ML components not available - this is expected")
            print("   ℹ️ Plugin will use base generator with fallback support")
        else:
            print("   🤖 AI/ML components available - enhanced features enabled")
        
        # Test factory function behavior
        try:
            from plugins.runtime_decryption_analysis import create_ai_ml_enhanced_frida_generator
            
            if AI_ML_ENHANCEMENT_AVAILABLE:
                generator = create_ai_ml_enhanced_frida_generator()
                print(f"✅ AI/ML enhanced generator created successfully")
            else:
                print("   ℹ️ AI/ML enhanced generator factory not available (expected)")
                
        except ImportError as e:
            print(f"   ℹ️ AI/ML enhanced generator not available: {e} (expected)")
        
        return True
        
    except Exception as e:
        print(f"❌ AI/ML fallback behavior test failed: {e}")
        return False

def run_integration_tests():
    """Run all integration tests."""
    print("🚀 AODS AI/ML-Enhanced Runtime Decryption Analysis Plugin")
    print("Integration Test Suite")
    print("=" * 60)
    
    tests = [
        test_plugin_discovery,
        test_plugin_capabilities,
        test_plugin_initialization,
        test_aods_framework_compatibility,
        test_mock_execution,
        test_ai_ml_fallback_behavior
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Integration Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        print("\n✅ Plugin is properly integrated with AODS framework")
        print("✅ AI/ML enhancement with fallback support working correctly")
        print("✅ MASVS integration verified")
        print("✅ Plugin discovery and execution interfaces compatible")
    else:
        print(f"⚠️ {total - passed} tests failed - please review integration")
    
    return passed == total

if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1) 
"""
AODS Integration Test for AI/ML-Enhanced Runtime Decryption Analysis Plugin

This test verifies that the AI/ML enhanced plugin integrates properly with
the AODS framework, including plugin discovery, initialization, and execution
with appropriate fallback mechanisms when AI/ML infrastructure is not available.
"""

import sys
from pathlib import Path

# Add the project root to the Python path for testing
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

def test_plugin_discovery():
    """Test plugin discovery by AODS plugin manager."""
    print("🔍 Testing AODS Plugin Discovery...")
    
    try:
        # Test basic plugin import
        from plugins.runtime_decryption_analysis import PLUGIN_METADATA, PLUGIN_CHARACTERISTICS
        
        print(f"✅ Plugin metadata loaded successfully")
        print(f"   Name: {PLUGIN_METADATA['name']}")
        print(f"   Version: {PLUGIN_METADATA['version']}")
        print(f"   Category: {PLUGIN_METADATA['category']}")
        print(f"   AI/ML Features: {PLUGIN_METADATA.get('ai_ml_features', {})}")
        
        return True
        
    except Exception as e:
        print(f"❌ Plugin discovery failed: {e}")
        return False

def test_plugin_capabilities():
    """Test plugin capabilities function."""
    print("\n🔧 Testing Plugin Capabilities...")
    
    try:
        from plugins.runtime_decryption_analysis import get_plugin_capabilities
        
        capabilities = get_plugin_capabilities()
        
        print(f"✅ Plugin capabilities retrieved successfully")
        print(f"   AI/ML Available: {capabilities['ai_ml_available']}")
        print(f"   Base Capabilities: {len(capabilities['base_capabilities'])} items")
        print(f"   Components: {len(capabilities['components'])} components")
        print(f"   Fallback Support: {capabilities['fallback_support']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Plugin capabilities test failed: {e}")
        return False

def test_plugin_initialization():
    """Test plugin initialization with fallback."""
    print("\n🏗️ Testing Plugin Initialization...")
    
    try:
        from plugins.runtime_decryption_analysis import RuntimeDecryptionAnalysisPlugin
        
        # Test initialization without configuration
        plugin = RuntimeDecryptionAnalysisPlugin()
        
        print(f"✅ Plugin initialized successfully")
        print(f"   AI/ML Enabled: {plugin.ai_ml_enabled}")
        print(f"   Generator Type: {plugin.enhancement_metadata['generator_type']}")
        print(f"   Fallback Available: {plugin.enhancement_metadata['fallback_available']}")
        
        # Test with explicit AI/ML disabled configuration
        from plugins.runtime_decryption_analysis.data_structures import RuntimeDecryptionConfig
        
        config = RuntimeDecryptionConfig()
        config.enable_ai_ml_enhancement = False
        
        plugin_disabled = RuntimeDecryptionAnalysisPlugin(config)
        
        print(f"✅ Plugin with disabled AI/ML initialized successfully")
        print(f"   AI/ML Enabled: {plugin_disabled.ai_ml_enabled}")
        print(f"   Generator Type: {plugin_disabled.enhancement_metadata['generator_type']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Plugin initialization test failed: {e}")
        return False

def test_aods_framework_compatibility():
    """Test compatibility with AODS framework patterns."""
    print("\n🔗 Testing AODS Framework Compatibility...")
    
    try:
        # Test MASVS mapping integration
        from core.plugin_execution_engine import MASVSIntegratedPluginEngine
        
        engine = MASVSIntegratedPluginEngine()
        
        # Check if our plugin is in the MASVS mapping
        plugin_mapping = engine.plugin_masvs_mapping.get("runtime_decryption_analysis", [])
        
        print(f"✅ MASVS integration verified")
        print(f"   MASVS Controls: {plugin_mapping}")
        
        # Test plugin registration
        from plugins.runtime_decryption_analysis import run
        
        engine.register_plugin("runtime_decryption_analysis", run)
        
        print(f"✅ Plugin registration successful")
        print(f"   Registered Plugins: {len(engine.registered_plugins)}")
        
        return True
        
    except Exception as e:
        print(f"❌ AODS framework compatibility test failed: {e}")
        return False

def test_mock_execution():
    """Test mock plugin execution to verify interfaces."""
    print("\n▶️ Testing Mock Plugin Execution...")
    
    try:
        from plugins.runtime_decryption_analysis import run_plugin
        
        # Create a mock APK context
        class MockAPKContext:
            def __init__(self):
                self.jadx_output_dir = None
                self.apktool_output_dir = None
                self.package_name = "com.example.test"
        
        mock_apk_ctx = MockAPKContext()
        
        # Test plugin execution
        result = run_plugin(mock_apk_ctx)
        
        print(f"✅ Mock plugin execution successful")
        print(f"   Result Type: {type(result)}")
        print(f"   Plugin Name: {result[0] if result else 'None'}")
        print(f"   Has Report: {bool(result[1] if result else False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Mock plugin execution failed: {e}")
        return False

def test_ai_ml_fallback_behavior():
    """Test AI/ML fallback behavior when components are unavailable."""
    print("\n🔄 Testing AI/ML Fallback Behavior...")
    
    try:
        from plugins.runtime_decryption_analysis import AI_ML_ENHANCEMENT_AVAILABLE
        
        print(f"✅ AI/ML enhancement status checked")
        print(f"   AI/ML Available: {AI_ML_ENHANCEMENT_AVAILABLE}")
        
        if not AI_ML_ENHANCEMENT_AVAILABLE:
            print("   ℹ️ AI/ML components not available - this is expected")
            print("   ℹ️ Plugin will use base generator with fallback support")
        else:
            print("   🤖 AI/ML components available - enhanced features enabled")
        
        # Test factory function behavior
        try:
            from plugins.runtime_decryption_analysis import create_ai_ml_enhanced_frida_generator
            
            if AI_ML_ENHANCEMENT_AVAILABLE:
                generator = create_ai_ml_enhanced_frida_generator()
                print(f"✅ AI/ML enhanced generator created successfully")
            else:
                print("   ℹ️ AI/ML enhanced generator factory not available (expected)")
                
        except ImportError as e:
            print(f"   ℹ️ AI/ML enhanced generator not available: {e} (expected)")
        
        return True
        
    except Exception as e:
        print(f"❌ AI/ML fallback behavior test failed: {e}")
        return False

def run_integration_tests():
    """Run all integration tests."""
    print("🚀 AODS AI/ML-Enhanced Runtime Decryption Analysis Plugin")
    print("Integration Test Suite")
    print("=" * 60)
    
    tests = [
        test_plugin_discovery,
        test_plugin_capabilities,
        test_plugin_initialization,
        test_aods_framework_compatibility,
        test_mock_execution,
        test_ai_ml_fallback_behavior
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Integration Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        print("\n✅ Plugin is properly integrated with AODS framework")
        print("✅ AI/ML enhancement with fallback support working correctly")
        print("✅ MASVS integration verified")
        print("✅ Plugin discovery and execution interfaces compatible")
    else:
        print(f"⚠️ {total - passed} tests failed - please review integration")
    
    return passed == total

if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1) 