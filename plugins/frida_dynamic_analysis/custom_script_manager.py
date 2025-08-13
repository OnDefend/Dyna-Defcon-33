#!/usr/bin/env python3
"""
Custom Frida Script Manager - Security Tester Flexibility

Enables security testers to inject their own custom Frida scripts alongside
the built-in adaptive intelligence. Provides validation, integration, and
management capabilities for custom script libraries.

Author: AODS Team  
Date: January 2025
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum

# Import existing adaptive components
try:
    from .adaptive_script_manager import ScriptProfile, ScriptCategory, ScriptPriority, AdaptiveConfiguration
    ADAPTIVE_MANAGER_AVAILABLE = True
except ImportError:
    ADAPTIVE_MANAGER_AVAILABLE = False
    # Define fallback enums if adaptive manager not available
    from enum import Enum
    
    class ScriptCategory(Enum):
        COMPONENT_ANALYSIS = "component_analysis"
        CRYPTO_ANALYSIS = "crypto_analysis"
        NETWORK_ANALYSIS = "network_analysis"
        STORAGE_ANALYSIS = "storage_analysis"
    
    class ScriptPriority(Enum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
    
    # Fallback classes for when adaptive manager not available
    @dataclass
    class ScriptProfile:
        script_name: str
        file_path: str
        category: 'ScriptCategory'
        priority: 'ScriptPriority'
        execution_parameters: Dict[str, Any] = field(default_factory=dict)
        description: str = ""
    
    @dataclass 
    class AdaptiveConfiguration:
        selected_scripts: List[Any] = field(default_factory=list)
        execution_order: List[str] = field(default_factory=list)
        dynamic_parameters: Dict[str, Any] = field(default_factory=dict)
        monitoring_duration: int = 30
        device_profile: Optional[Dict[str, Any]] = None


class CustomScriptSource(Enum):
    """Sources for custom Frida scripts."""
    FILE_PATH = "file_path"          # Direct file path
    INLINE_CODE = "inline_code"      # JavaScript code as string
    URL_REMOTE = "url_remote"        # Download from URL
    SCRIPT_LIBRARY = "script_library" # From user's script library
    TEMPLATE_BASED = "template_based" # Generated from templates


class ValidationLevel(Enum):
    """Validation levels for custom scripts."""
    NONE = "none"                    # No validation (expert mode)
    BASIC = "basic"                  # Syntax check only
    STANDARD = "standard"            # Syntax + safety checks
    STRICT = "strict"                # Comprehensive validation


@dataclass
class CustomScriptProfile:
    """Profile for a custom Frida script."""
    script_name: str
    source_type: CustomScriptSource
    source_content: str  # File path, URL, or inline code
    category: ScriptCategory = ScriptCategory.COMPONENT_ANALYSIS
    priority: ScriptPriority = ScriptPriority.MEDIUM
    description: str = ""
    author: str = ""
    version: str = "1.0"
    target_apps: List[str] = field(default_factory=list)  # Package names or patterns
    requires_root: bool = False
    validation_level: ValidationLevel = ValidationLevel.STANDARD
    execution_parameters: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_date: str = ""
    last_modified: str = ""


@dataclass
class ScriptValidationResult:
    """Result of custom script validation."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    safety_issues: List[str] = field(default_factory=list)
    performance_notes: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


class CustomFridaScriptManager:
    """
    Advanced custom script manager for security testers.
    
    Provides comprehensive custom Frida script injection capabilities including:
    - Multiple script loading methods (file, inline, URL, library)
    - Script validation and safety checking
    - Integration with adaptive intelligence
    - Script library management
    - Template-based script generation
    """
    
    def __init__(self, adaptive_manager=None):
        """Initialize custom script manager."""
        self.logger = logging.getLogger(__name__)
        self.adaptive_manager = adaptive_manager
        
        # Script storage
        self.custom_scripts: List[CustomScriptProfile] = []
        self.script_library_dir = Path.home() / ".aods" / "custom_scripts"
        self.script_templates_dir = Path(__file__).parent / "templates"
        
        # Validation settings
        self.default_validation_level = ValidationLevel.STANDARD
        self.enable_safety_checks = True
        
        # Create directories
        self.script_library_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"✅ Custom Frida Script Manager initialized")
        self.logger.info(f"   📁 Script library: {self.script_library_dir}")
        self.logger.info(f"   🔒 Validation level: {self.default_validation_level.value}")
        
    def add_custom_script(self, 
                         script_name: str,
                         source_type: CustomScriptSource,
                         source_content: str,
                         **kwargs) -> bool:
        """Add a custom script to the execution queue."""
        
        try:
            # Create custom script profile
            custom_script = CustomScriptProfile(
                script_name=script_name,
                source_type=source_type,
                source_content=source_content,
                **kwargs
            )
            
            # Validate script if required
            if custom_script.validation_level != ValidationLevel.NONE:
                validation_result = self.validate_script(custom_script)
                
                if not validation_result.is_valid:
                    self.logger.error(f"❌ Custom script validation failed: {script_name}")
                    for error in validation_result.errors:
                        self.logger.error(f"   ❌ {error}")
                    return False
                    
                if validation_result.warnings:
                    for warning in validation_result.warnings:
                        self.logger.warning(f"   ⚠️ {warning}")
                        
            # Add to execution queue
            self.custom_scripts.append(custom_script)
            self.logger.info(f"✅ Custom script added: {script_name} ({source_type.value})")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to add custom script {script_name}: {e}")
            return False
    
    def add_script_from_file(self, script_path: str, **kwargs) -> bool:
        """Add custom script from file path."""
        
        script_path = Path(script_path)
        if not script_path.exists():
            self.logger.error(f"❌ Script file not found: {script_path}")
            return False
            
        script_name = kwargs.get('script_name', script_path.stem)
        
        return self.add_custom_script(
            script_name=script_name,
            source_type=CustomScriptSource.FILE_PATH,
            source_content=str(script_path),
            **kwargs
        )
    
    def add_script_inline(self, script_name: str, javascript_code: str, **kwargs) -> bool:
        """Add custom script from inline JavaScript code."""
        
        return self.add_custom_script(
            script_name=script_name,
            source_type=CustomScriptSource.INLINE_CODE,
            source_content=javascript_code,
            **kwargs
        )
    
    def add_script_from_url(self, script_name: str, url: str, **kwargs) -> bool:
        """Add custom script from remote URL."""
        
        return self.add_custom_script(
            script_name=script_name,
            source_type=CustomScriptSource.URL_REMOTE,
            source_content=url,
            **kwargs
        )
    
    def load_script_content(self, custom_script: CustomScriptProfile) -> str:
        """Load actual JavaScript content from custom script profile."""
        
        try:
            if custom_script.source_type == CustomScriptSource.FILE_PATH:
                # Load from file
                script_path = Path(custom_script.source_content)
                if script_path.exists():
                    with open(script_path, 'r', encoding='utf-8') as f:
                        return f.read()
                else:
                    raise FileNotFoundError(f"Script file not found: {script_path}")
                    
            elif custom_script.source_type == CustomScriptSource.INLINE_CODE:
                # Return inline code directly
                return custom_script.source_content
                
            elif custom_script.source_type == CustomScriptSource.URL_REMOTE:
                # Download from URL
                import urllib.request
                with urllib.request.urlopen(custom_script.source_content) as response:
                    return response.read().decode('utf-8')
                    
            elif custom_script.source_type == CustomScriptSource.SCRIPT_LIBRARY:
                # Load from user's script library
                library_path = self.script_library_dir / custom_script.source_content
                if library_path.exists():
                    with open(library_path, 'r', encoding='utf-8') as f:
                        return f.read()
                else:
                    raise FileNotFoundError(f"Library script not found: {library_path}")
                    
            else:
                raise ValueError(f"Unsupported source type: {custom_script.source_type}")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to load script content for {custom_script.script_name}: {e}")
            return ""
    
    def validate_script(self, custom_script: CustomScriptProfile) -> ScriptValidationResult:
        """Validate custom Frida script for safety and correctness."""
        
        result = ScriptValidationResult(is_valid=True)
        
        try:
            # Load script content
            script_content = self.load_script_content(custom_script)
            if not script_content:
                result.is_valid = False
                result.errors.append("Failed to load script content")
                return result
            
            # Basic validation
            if custom_script.validation_level in [ValidationLevel.BASIC, ValidationLevel.STANDARD, ValidationLevel.STRICT]:
                
                # JavaScript syntax validation (basic)
                if not self._validate_javascript_syntax(script_content):
                    result.errors.append("Invalid JavaScript syntax detected")
                    result.is_valid = False
                
                # Frida API usage validation
                if not self._validate_frida_usage(script_content):
                    result.warnings.append("No Frida API usage detected - may not be a valid Frida script")
                
            # Standard validation
            if custom_script.validation_level in [ValidationLevel.STANDARD, ValidationLevel.STRICT]:
                
                # Safety checks
                safety_issues = self._check_safety_issues(script_content)
                result.safety_issues.extend(safety_issues)
                
                # Performance checks
                performance_notes = self._check_performance_issues(script_content)
                result.performance_notes.extend(performance_notes)
                
            # Strict validation
            if custom_script.validation_level == ValidationLevel.STRICT:
                
                # Advanced safety analysis
                advanced_safety = self._advanced_safety_analysis(script_content)
                result.safety_issues.extend(advanced_safety)
                
                # Best practices check
                suggestions = self._check_best_practices(script_content)
                result.suggestions.extend(suggestions)
                
            # Set validation result
            if result.safety_issues and self.enable_safety_checks:
                result.is_valid = False
                result.errors.extend([f"Safety issue: {issue}" for issue in result.safety_issues])
                
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Validation error: {e}")
            
        return result
    
    def _validate_javascript_syntax(self, script_content: str) -> bool:
        """Basic JavaScript syntax validation."""
        try:
            # Check for balanced braces/brackets
            braces = script_content.count('{') == script_content.count('}')
            brackets = script_content.count('[') == script_content.count(']')
            parens = script_content.count('(') == script_content.count(')')
            
            # Check for basic JavaScript structure
            has_java_perform = 'Java.perform' in script_content
            
            return braces and brackets and parens and has_java_perform
            
        except Exception:
            return False
    
    def _validate_frida_usage(self, script_content: str) -> bool:
        """Check if script uses Frida APIs."""
        frida_apis = [
            'Java.perform', 'Java.use', 'send(', 'recv(',
            'setTimeout', 'setInterval', 'Memory.', 'Process.'
        ]
        return any(api in script_content for api in frida_apis)
    
    def _check_safety_issues(self, script_content: str) -> List[str]:
        """Check for potential safety issues."""
        issues = []
        
        # Dangerous operations
        dangerous_patterns = [
            (r'Process\.kill\(', "Process termination detected"),
            (r'Memory\.writeByteArray\(', "Memory write operation detected"),
            (r'system\(', "System command execution detected"),
            (r'eval\(', "Code evaluation detected"),
            (r'setInterval\([^,]+,\s*\d+\)', "High-frequency interval detected"),
        ]
        
        for pattern, message in dangerous_patterns:
            if re.search(pattern, script_content):
                issues.append(message)
                
        return issues
    
    def _check_performance_issues(self, script_content: str) -> List[str]:
        """Check for potential performance issues."""
        issues = []
        
        # Performance anti-patterns
        if script_content.count('send(') > 50:
            issues.append("High number of send() calls may impact performance")
            
        if 'setInterval' in script_content and '10' in script_content:
            issues.append("Very frequent intervals may cause performance issues")
            
        return issues
    
    def _advanced_safety_analysis(self, script_content: str) -> List[str]:
        """Advanced safety analysis for strict validation."""
        issues = []
        
        # Advanced patterns
        if re.search(r'for\s*\([^}]+\)\s*\{[^}]*send\(', script_content):
            issues.append("Loop with send() calls may cause message flooding")
            
        return issues
    
    def _check_best_practices(self, script_content: str) -> List[str]:
        """Check for Frida scripting best practices."""
        suggestions = []
        
        if 'console.log' not in script_content and 'send(' not in script_content:
            suggestions.append("Consider adding logging for debugging")
            
        if 'try' not in script_content and 'catch' not in script_content:
            suggestions.append("Consider adding error handling")
            
        return suggestions
    
    def integrate_with_adaptive_manager(self, adaptive_config: AdaptiveConfiguration) -> AdaptiveConfiguration:
        """Integrate custom scripts with adaptive configuration."""
        
        if not self.custom_scripts:
            return adaptive_config
            
        self.logger.info(f"🔧 Integrating {len(self.custom_scripts)} custom scripts with adaptive configuration")
        
        # Convert custom scripts to standard script profiles for execution
        for custom_script in self.custom_scripts:
            
            # Create compatible script profile
            script_profile = ScriptProfile(
                script_name=custom_script.script_name,
                file_path=f"custom_{custom_script.script_name}.js",  # Virtual path
                category=custom_script.category,
                priority=custom_script.priority,
                execution_parameters=custom_script.execution_parameters,
                description=f"Custom: {custom_script.description}"
            )
            
            # Add to adaptive configuration based on priority
            if custom_script.priority == ScriptPriority.CRITICAL:
                # Insert at beginning (after existing critical scripts)
                critical_count = sum(1 for s in adaptive_config.selected_scripts 
                                   if s.priority == ScriptPriority.CRITICAL)
                adaptive_config.selected_scripts.insert(critical_count, script_profile)
            else:
                # Add in priority order
                adaptive_config.selected_scripts.append(script_profile)
        
        # Update execution order
        adaptive_config.execution_order = [s.script_name for s in adaptive_config.selected_scripts]
        
        # Add custom script metadata
        adaptive_config.dynamic_parameters['custom_scripts_count'] = len(self.custom_scripts)
        adaptive_config.dynamic_parameters['custom_scripts_enabled'] = True
        
        self.logger.info(f"✅ Custom scripts integrated. Total scripts: {len(adaptive_config.selected_scripts)}")
        
        return adaptive_config
    
    def generate_custom_script_content(self, custom_script: CustomScriptProfile, 
                                     adaptive_config: AdaptiveConfiguration) -> str:
        """Generate custom script content with adaptive parameter injection."""
        
        # Load base script content
        script_content = self.load_script_content(custom_script)
        if not script_content:
            return ""
        
        # Inject adaptive parameters if script supports it
        if "// ADAPTIVE_PARAMETERS" in script_content or "// CUSTOM_PARAMETERS" in script_content:
            
            # Combine adaptive and custom parameters
            combined_params = {
                **adaptive_config.dynamic_parameters,
                **custom_script.execution_parameters,
                "device_profile": adaptive_config.device_profile,
                "custom_script": True,
                "script_author": custom_script.author,
                "script_version": custom_script.version
            }
            
            param_injection = f"""
            // Auto-generated adaptive parameters for custom script
            var ADAPTIVE_CONFIG = {json.dumps(combined_params, indent=2)};
            var APP_PACKAGE = "{adaptive_config.dynamic_parameters.get('app_package', 'unknown')}";
            var ANALYSIS_MODE = "adaptive_custom";
            var CUSTOM_SCRIPT_NAME = "{custom_script.script_name}";
            """
            
            # Replace parameter markers
            for marker in ["// ADAPTIVE_PARAMETERS", "// CUSTOM_PARAMETERS"]:
                script_content = script_content.replace(marker, param_injection)
        
        return script_content
    
    def save_script_to_library(self, custom_script: CustomScriptProfile) -> bool:
        """Save custom script to user's script library."""
        
        try:
            library_file = self.script_library_dir / f"{custom_script.script_name}.js"
            
            # Create script metadata
            metadata = {
                "name": custom_script.script_name,
                "description": custom_script.description,
                "author": custom_script.author,
                "version": custom_script.version,
                "category": custom_script.category.value,
                "priority": custom_script.priority.value,
                "tags": custom_script.tags,
                "created": custom_script.created_date,
                "modified": custom_script.last_modified
            }
            
            # Load script content
            script_content = self.load_script_content(custom_script)
            
            # Add metadata as comment header
            header = f"""/*
 * AODS Custom Frida Script
 * {json.dumps(metadata, indent=2)}
 */

"""
            
            # Save to library
            with open(library_file, 'w', encoding='utf-8') as f:
                f.write(header + script_content)
                
            self.logger.info(f"✅ Script saved to library: {library_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save script to library: {e}")
            return False
    
    def list_library_scripts(self) -> List[Dict[str, Any]]:
        """List all scripts in user's library."""
        
        scripts = []
        
        for script_file in self.script_library_dir.glob("*.js"):
            try:
                with open(script_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract metadata from header
                metadata_match = re.search(r'/\*\s*AODS Custom Frida Script\s*(\{.*?\})\s*\*/', 
                                         content, re.DOTALL)
                
                if metadata_match:
                    metadata = json.loads(metadata_match.group(1))
                    metadata['file_path'] = str(script_file)
                    scripts.append(metadata)
                else:
                    # Basic script info
                    scripts.append({
                        "name": script_file.stem,
                        "file_path": str(script_file),
                        "description": "No metadata available"
                    })
                    
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to read script metadata: {script_file} - {e}")
                
        return scripts
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Generate execution summary for custom scripts."""
        
        if not self.custom_scripts:
            return {"custom_scripts_enabled": False}
        
        summary = {
            "custom_scripts_enabled": True,
            "total_custom_scripts": len(self.custom_scripts),
            "script_breakdown": {},
            "source_types": {},
            "validation_levels": {}
        }
        
        # Analyze scripts
        for script in self.custom_scripts:
            # Category breakdown
            category = script.category.value
            summary["script_breakdown"][category] = summary["script_breakdown"].get(category, 0) + 1
            
            # Source type breakdown
            source = script.source_type.value
            summary["source_types"][source] = summary["source_types"].get(source, 0) + 1
            
            # Validation level breakdown
            validation = script.validation_level.value
            summary["validation_levels"][validation] = summary["validation_levels"].get(validation, 0) + 1
        
        return summary


# Global instance for easy access
custom_script_manager = CustomFridaScriptManager()


def add_custom_script_from_file(script_path: str, **kwargs) -> bool:
    """Convenience function to add custom script from file."""
    return custom_script_manager.add_script_from_file(script_path, **kwargs)


def add_custom_script_inline(script_name: str, javascript_code: str, **kwargs) -> bool:
    """Convenience function to add inline custom script."""
    return custom_script_manager.add_script_inline(script_name, javascript_code, **kwargs)


if __name__ == "__main__":
    # Demo usage
    manager = CustomFridaScriptManager()
    
    print("🔧 Custom Frida Script Manager Demo")
    print("=" * 50)
    
    # Example custom script
    custom_js = """
    // ADAPTIVE_PARAMETERS
    
    Java.perform(function() {
        console.log("[CUSTOM] Custom security test script loaded");
        console.log("[CUSTOM] Target package: " + APP_PACKAGE);
        
        // Custom hook example
        var Activity = Java.use("android.app.Activity");
        Activity.onCreate.implementation = function(savedInstanceState) {
            console.log("[CUSTOM] Activity.onCreate called: " + this.getClass().getName());
            send({
                type: "custom_activity_lifecycle",
                activity: this.getClass().getName(),
                timestamp: Date.now()
            });
            return this.onCreate(savedInstanceState);
        };
    });
    """
    
    # Add custom script
    success = manager.add_script_inline(
        script_name="custom_activity_monitor",
        javascript_code=custom_js,
        description="Custom activity lifecycle monitoring",
        author="Security Tester",
        category=ScriptCategory.COMPONENT_ANALYSIS,
        priority=ScriptPriority.HIGH
    )
    
    print(f"✅ Custom script added: {success}")
    print(f"📊 Custom scripts loaded: {len(manager.custom_scripts)}")
    
    # Show execution summary
    summary = manager.get_execution_summary()
    print(f"\n📋 Execution Summary:")
    for key, value in summary.items():
        print(f"   {key}: {value}")
    
    print(f"\n✅ Custom Frida Script Manager Ready!")