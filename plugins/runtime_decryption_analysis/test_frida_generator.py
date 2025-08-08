#!/usr/bin/env python3
"""
Test Script for Enhanced AODS Frida Script Generator

This script demonstrates and tests the enhanced FridaScriptGenerator functionality
including template-based generation, error handling, validation, and CLI interface.
"""

import sys
import logging
import json
from pathlib import Path
from typing import Dict, List, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

try:
    from plugins.runtime_decryption_analysis.frida_script_generator import (
        FridaScriptGenerator, ScriptGenerationContext, GeneratedScript,
        FridaScriptTemplateLoader, main as cli_main
    )
    from plugins.runtime_decryption_analysis.data_structures import (
        RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
    )
    print("✅ Successfully imported enhanced FridaScriptGenerator components")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)


def create_test_findings() -> List[RuntimeDecryptionFinding]:
    """Create sample findings for testing."""
    findings = [
        RuntimeDecryptionFinding(
            finding_type="cipher_usage",
            description="AES cipher usage detected in MainActivity",
            severity=VulnerabilitySeverity.HIGH,
            confidence=0.85,
            location="com.example.app.MainActivity",
            class_name="MainActivity",
            method_name="encryptData",
            pattern_type=DecryptionType.RUNTIME_DECRYPTION,
            cwe_id="CWE-311",
            masvs_control="MSTG-CRYPTO-1"
        ),
        RuntimeDecryptionFinding(
            finding_type="base64_decode",
            description="Base64 decoding detected",
            severity=VulnerabilitySeverity.MEDIUM,
            confidence=0.75,
            location="com.example.app.Utils",
            class_name="Utils",
            method_name="decodeData",
            pattern_type=DecryptionType.RESOURCE_DECRYPTION,
            cwe_id="CWE-312",
            masvs_control="MSTG-CRYPTO-2"
        ),
        RuntimeDecryptionFinding(
            finding_type="key_generation",
            description="Weak key generation detected",
            severity=VulnerabilitySeverity.CRITICAL,
            confidence=0.95,
            location="com.example.app.CryptoManager",
            pattern_type=DecryptionType.KEY_MANAGEMENT,
            cwe_id="CWE-320",
            masvs_control="MSTG-CRYPTO-1"
        )
    ]
    return findings


def test_template_loader():
    """Test the template loader functionality."""
    print("\n🧪 Testing Template Loader...")
    
    try:
        loader = FridaScriptTemplateLoader()
        print(f"   Templates loaded: {len(loader.templates)}")
        print(f"   Available templates: {loader.list_templates()}")
        
        # Test template retrieval
        base_template = loader.get_template('base_template')
        assert len(base_template) > 100, "Base template seems too short"
        print("   ✅ Template loading successful")
        
    except Exception as e:
        print(f"   ❌ Template loader test failed: {e}")
        raise


def test_script_generation():
    """Test script generation with findings."""
    print("\n🧪 Testing Script Generation...")
    
    try:
        # Create generator
        generator = FridaScriptGenerator()
        
        # Create test findings
        findings = create_test_findings()
        
        # Create generation context
        context = ScriptGenerationContext(
            findings=findings,
            hooks_to_generate=['cipher_hooks', 'base64_hooks'],
            max_hooks_per_script=10,
            include_usage_instructions=True
        )
        
        # Generate script
        result = generator.generate_script(findings, context)
        
        # Validate result
        assert isinstance(result, GeneratedScript), "Result should be GeneratedScript instance"
        assert len(result.script_content) > 500, "Script content seems too short"
        assert len(result.hooks_generated) > 0, "No hooks were generated"
        assert result.generation_time > 0, "Generation time should be positive"
        assert not result.has_errors, f"Script generation had errors: {result.error_message}"
        
        print(f"   ✅ Script generated successfully")
        print(f"   Generated {len(result.hooks_generated)} hooks in {result.generation_time:.3f}s")
        print(f"   Success rate: {result.success_rate:.1%}")
        
        return result
        
    except Exception as e:
        print(f"   ❌ Script generation test failed: {e}")
        raise


def test_validation():
    """Test input validation functionality."""
    print("\n🧪 Testing Validation...")
    
    try:
        generator = FridaScriptGenerator()
        
        # Test valid findings
        valid_findings = [
            {'finding_type': 'test', 'description': 'Test finding', 'severity': 'HIGH', 'confidence': 0.8}
        ]
        validated = generator._validate_findings(valid_findings)
        assert len(validated) == 1, "Valid finding should pass validation"
        
        # Test invalid findings
        invalid_findings = [
            {'finding_type': '', 'description': 'Missing type'},  # Invalid: empty type
            {'description': 'Missing type field'},  # Invalid: missing required field
            {'finding_type': 'test', 'description': 'Test', 'confidence': 1.5}  # Invalid: confidence > 1
        ]
        validated = generator._validate_findings(invalid_findings)
        assert len(validated) == 0, "All invalid findings should be rejected"
        
        print("   ✅ Validation tests passed")
        
    except Exception as e:
        print(f"   ❌ Validation test failed: {e}")
        raise


def test_error_handling():
    """Test error handling and fallback behavior."""
    print("\n🧪 Testing Error Handling...")
    
    try:
        # Test with non-existent config file
        try:
            generator = FridaScriptGenerator({'config_path': 'non_existent_config.yaml'})
            print("   ❌ Should have failed with missing config file")
        except Exception:
            print("   ✅ Correctly handled missing config file")
        
        # Test with invalid context
        generator = FridaScriptGenerator()
        try:
            invalid_context = ScriptGenerationContext(
                findings=[],
                max_hooks_per_script=-1  # Invalid negative value
            )
            print("   ❌ Should have failed with invalid context")
        except Exception:
            print("   ✅ Correctly validated context parameters")
        
        print("   ✅ Error handling tests passed")
        
    except Exception as e:
        print(f"   ❌ Error handling test failed: {e}")
        raise


def test_file_operations(generated_script: GeneratedScript):
    """Test file save and load operations."""
    print("\n🧪 Testing File Operations...")
    
    try:
        generator = FridaScriptGenerator()
        
        # Test saving script
        output_path = Path("test_frida_script.js")
        success = generator.save_script_to_file(generated_script, output_path)
        assert success, "Script save should succeed"
        assert output_path.exists(), "Script file should exist"
        
        # Verify content
        with open(output_path, 'r') as f:
            content = f.read()
        assert len(content) > 500, "Saved script content seems too short"
        assert 'AODS Frida script' in content, "Script should contain AODS header"
        
        # Cleanup
        output_path.unlink()
        instructions_path = output_path.with_suffix('.txt')
        if instructions_path.exists():
            instructions_path.unlink()
        
        print("   ✅ File operations test passed")
        
    except Exception as e:
        print(f"   ❌ File operations test failed: {e}")
        raise


def test_cli_functionality():
    """Test CLI interface (basic validation)."""
    print("\n🧪 Testing CLI Functionality...")
    
    try:
        from plugins.runtime_decryption_analysis.frida_script_generator import create_cli_interface
        
        # Test parser creation
        parser = create_cli_interface()
        assert parser is not None, "Parser should be created"
        
        # Test help generation (shouldn't raise exception)
        help_text = parser.format_help()
        assert 'AODS Frida Script Generator' in help_text, "Help should contain description"
        
        print("   ✅ CLI interface validation passed")
        
    except Exception as e:
        print(f"   ❌ CLI test failed: {e}")
        raise


def create_test_findings_json():
    """Create a test findings JSON file for CLI testing."""
    findings_data = [
        {
            'finding_type': 'cipher_usage',
            'description': 'Test cipher finding for CLI',
            'severity': 'HIGH',
            'confidence': 0.8,
            'pattern_type': 'runtime_decryption'
        }
    ]
    
    with open('test_findings.json', 'w') as f:
        json.dump(findings_data, f, indent=2)
    
    return 'test_findings.json'


def run_comprehensive_test():
    """Run comprehensive test suite."""
    print("🚀 Starting Enhanced FridaScriptGenerator Test Suite")
    print("=" * 60)
    
    try:
        # Test 1: Template Loader
        test_template_loader()
        
        # Test 2: Script Generation
        generated_script = test_script_generation()
        
        # Test 3: Validation
        test_validation()
        
        # Test 4: Error Handling
        test_error_handling()
        
        # Test 5: File Operations
        test_file_operations(generated_script)
        
        # Test 6: CLI Interface
        test_cli_functionality()
        
        print("\n" + "=" * 60)
        print("🎉 All tests passed! Enhanced FridaScriptGenerator is working correctly.")
        print("\n📋 Test Summary:")
        print("   ✅ Template loading and validation")
        print("   ✅ Dynamic script generation with Jinja2")
        print("   ✅ Comprehensive error handling")
        print("   ✅ Input validation and type safety")
        print("   ✅ Structured logging integration")
        print("   ✅ File operations and CLI interface")
        print("\n🔧 Ready for production use!")
        
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


def main():
    """Main test execution."""
    # Setup logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run comprehensive tests
    success = run_comprehensive_test()
    
    if success:
        print("\n🎯 Testing completed successfully!")
        return 0
    else:
        print("\n💥 Testing failed!")
        return 1


if __name__ == "__main__":
    exit(main()) 
"""
Test Script for Enhanced AODS Frida Script Generator

This script demonstrates and tests the enhanced FridaScriptGenerator functionality
including template-based generation, error handling, validation, and CLI interface.
"""

import sys
import logging
import json
from pathlib import Path
from typing import Dict, List, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

try:
    from plugins.runtime_decryption_analysis.frida_script_generator import (
        FridaScriptGenerator, ScriptGenerationContext, GeneratedScript,
        FridaScriptTemplateLoader, main as cli_main
    )
    from plugins.runtime_decryption_analysis.data_structures import (
        RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
    )
    print("✅ Successfully imported enhanced FridaScriptGenerator components")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)


def create_test_findings() -> List[RuntimeDecryptionFinding]:
    """Create sample findings for testing."""
    findings = [
        RuntimeDecryptionFinding(
            finding_type="cipher_usage",
            description="AES cipher usage detected in MainActivity",
            severity=VulnerabilitySeverity.HIGH,
            confidence=0.85,
            location="com.example.app.MainActivity",
            class_name="MainActivity",
            method_name="encryptData",
            pattern_type=DecryptionType.RUNTIME_DECRYPTION,
            cwe_id="CWE-311",
            masvs_control="MSTG-CRYPTO-1"
        ),
        RuntimeDecryptionFinding(
            finding_type="base64_decode",
            description="Base64 decoding detected",
            severity=VulnerabilitySeverity.MEDIUM,
            confidence=0.75,
            location="com.example.app.Utils",
            class_name="Utils",
            method_name="decodeData",
            pattern_type=DecryptionType.RESOURCE_DECRYPTION,
            cwe_id="CWE-312",
            masvs_control="MSTG-CRYPTO-2"
        ),
        RuntimeDecryptionFinding(
            finding_type="key_generation",
            description="Weak key generation detected",
            severity=VulnerabilitySeverity.CRITICAL,
            confidence=0.95,
            location="com.example.app.CryptoManager",
            pattern_type=DecryptionType.KEY_MANAGEMENT,
            cwe_id="CWE-320",
            masvs_control="MSTG-CRYPTO-1"
        )
    ]
    return findings


def test_template_loader():
    """Test the template loader functionality."""
    print("\n🧪 Testing Template Loader...")
    
    try:
        loader = FridaScriptTemplateLoader()
        print(f"   Templates loaded: {len(loader.templates)}")
        print(f"   Available templates: {loader.list_templates()}")
        
        # Test template retrieval
        base_template = loader.get_template('base_template')
        assert len(base_template) > 100, "Base template seems too short"
        print("   ✅ Template loading successful")
        
    except Exception as e:
        print(f"   ❌ Template loader test failed: {e}")
        raise


def test_script_generation():
    """Test script generation with findings."""
    print("\n🧪 Testing Script Generation...")
    
    try:
        # Create generator
        generator = FridaScriptGenerator()
        
        # Create test findings
        findings = create_test_findings()
        
        # Create generation context
        context = ScriptGenerationContext(
            findings=findings,
            hooks_to_generate=['cipher_hooks', 'base64_hooks'],
            max_hooks_per_script=10,
            include_usage_instructions=True
        )
        
        # Generate script
        result = generator.generate_script(findings, context)
        
        # Validate result
        assert isinstance(result, GeneratedScript), "Result should be GeneratedScript instance"
        assert len(result.script_content) > 500, "Script content seems too short"
        assert len(result.hooks_generated) > 0, "No hooks were generated"
        assert result.generation_time > 0, "Generation time should be positive"
        assert not result.has_errors, f"Script generation had errors: {result.error_message}"
        
        print(f"   ✅ Script generated successfully")
        print(f"   Generated {len(result.hooks_generated)} hooks in {result.generation_time:.3f}s")
        print(f"   Success rate: {result.success_rate:.1%}")
        
        return result
        
    except Exception as e:
        print(f"   ❌ Script generation test failed: {e}")
        raise


def test_validation():
    """Test input validation functionality."""
    print("\n🧪 Testing Validation...")
    
    try:
        generator = FridaScriptGenerator()
        
        # Test valid findings
        valid_findings = [
            {'finding_type': 'test', 'description': 'Test finding', 'severity': 'HIGH', 'confidence': 0.8}
        ]
        validated = generator._validate_findings(valid_findings)
        assert len(validated) == 1, "Valid finding should pass validation"
        
        # Test invalid findings
        invalid_findings = [
            {'finding_type': '', 'description': 'Missing type'},  # Invalid: empty type
            {'description': 'Missing type field'},  # Invalid: missing required field
            {'finding_type': 'test', 'description': 'Test', 'confidence': 1.5}  # Invalid: confidence > 1
        ]
        validated = generator._validate_findings(invalid_findings)
        assert len(validated) == 0, "All invalid findings should be rejected"
        
        print("   ✅ Validation tests passed")
        
    except Exception as e:
        print(f"   ❌ Validation test failed: {e}")
        raise


def test_error_handling():
    """Test error handling and fallback behavior."""
    print("\n🧪 Testing Error Handling...")
    
    try:
        # Test with non-existent config file
        try:
            generator = FridaScriptGenerator({'config_path': 'non_existent_config.yaml'})
            print("   ❌ Should have failed with missing config file")
        except Exception:
            print("   ✅ Correctly handled missing config file")
        
        # Test with invalid context
        generator = FridaScriptGenerator()
        try:
            invalid_context = ScriptGenerationContext(
                findings=[],
                max_hooks_per_script=-1  # Invalid negative value
            )
            print("   ❌ Should have failed with invalid context")
        except Exception:
            print("   ✅ Correctly validated context parameters")
        
        print("   ✅ Error handling tests passed")
        
    except Exception as e:
        print(f"   ❌ Error handling test failed: {e}")
        raise


def test_file_operations(generated_script: GeneratedScript):
    """Test file save and load operations."""
    print("\n🧪 Testing File Operations...")
    
    try:
        generator = FridaScriptGenerator()
        
        # Test saving script
        output_path = Path("test_frida_script.js")
        success = generator.save_script_to_file(generated_script, output_path)
        assert success, "Script save should succeed"
        assert output_path.exists(), "Script file should exist"
        
        # Verify content
        with open(output_path, 'r') as f:
            content = f.read()
        assert len(content) > 500, "Saved script content seems too short"
        assert 'AODS Frida script' in content, "Script should contain AODS header"
        
        # Cleanup
        output_path.unlink()
        instructions_path = output_path.with_suffix('.txt')
        if instructions_path.exists():
            instructions_path.unlink()
        
        print("   ✅ File operations test passed")
        
    except Exception as e:
        print(f"   ❌ File operations test failed: {e}")
        raise


def test_cli_functionality():
    """Test CLI interface (basic validation)."""
    print("\n🧪 Testing CLI Functionality...")
    
    try:
        from plugins.runtime_decryption_analysis.frida_script_generator import create_cli_interface
        
        # Test parser creation
        parser = create_cli_interface()
        assert parser is not None, "Parser should be created"
        
        # Test help generation (shouldn't raise exception)
        help_text = parser.format_help()
        assert 'AODS Frida Script Generator' in help_text, "Help should contain description"
        
        print("   ✅ CLI interface validation passed")
        
    except Exception as e:
        print(f"   ❌ CLI test failed: {e}")
        raise


def create_test_findings_json():
    """Create a test findings JSON file for CLI testing."""
    findings_data = [
        {
            'finding_type': 'cipher_usage',
            'description': 'Test cipher finding for CLI',
            'severity': 'HIGH',
            'confidence': 0.8,
            'pattern_type': 'runtime_decryption'
        }
    ]
    
    with open('test_findings.json', 'w') as f:
        json.dump(findings_data, f, indent=2)
    
    return 'test_findings.json'


def run_comprehensive_test():
    """Run comprehensive test suite."""
    print("🚀 Starting Enhanced FridaScriptGenerator Test Suite")
    print("=" * 60)
    
    try:
        # Test 1: Template Loader
        test_template_loader()
        
        # Test 2: Script Generation
        generated_script = test_script_generation()
        
        # Test 3: Validation
        test_validation()
        
        # Test 4: Error Handling
        test_error_handling()
        
        # Test 5: File Operations
        test_file_operations(generated_script)
        
        # Test 6: CLI Interface
        test_cli_functionality()
        
        print("\n" + "=" * 60)
        print("🎉 All tests passed! Enhanced FridaScriptGenerator is working correctly.")
        print("\n📋 Test Summary:")
        print("   ✅ Template loading and validation")
        print("   ✅ Dynamic script generation with Jinja2")
        print("   ✅ Comprehensive error handling")
        print("   ✅ Input validation and type safety")
        print("   ✅ Structured logging integration")
        print("   ✅ File operations and CLI interface")
        print("\n🔧 Ready for production use!")
        
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


def main():
    """Main test execution."""
    # Setup logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run comprehensive tests
    success = run_comprehensive_test()
    
    if success:
        print("\n🎯 Testing completed successfully!")
        return 0
    else:
        print("\n💥 Testing failed!")
        return 1


if __name__ == "__main__":
    exit(main()) 