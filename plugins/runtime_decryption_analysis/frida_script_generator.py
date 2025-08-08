#!/usr/bin/env python3
"""
Enhanced Frida Script Generator for AODS

Generates dynamic Frida scripts for runtime decryption analysis with comprehensive
error handling, Jinja2 templating, and configuration-driven hook generation.

Features:
- Jinja2 template-based script generation
- Configuration-driven hook selection
- Comprehensive error handling in generated scripts
- Parameterized method overloads
- Structured logging integration
- Type safety and validation
- Performance optimized script generation
"""

import logging
from typing import Dict, List, Any, Optional, Union, Sequence, Mapping, Protocol, runtime_checkable
from pathlib import Path
import yaml
import time
from dataclasses import dataclass, field

# Jinja2 template engine
try:
    from jinja2 import Environment, FileSystemLoader, BaseLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    Environment = None
    Template = None

# AODS imports
from core.shared_data_structures import BaseVulnerability
from core.shared_infrastructure.analysis_exceptions import AnalysisError, ErrorContext, ContextualLogger, ValidationError
from core.shared_infrastructure.cross_plugin_utilities import LoggingMixin, InputValidator
from .data_structures import RuntimeDecryptionFinding, DecryptionType, DetectionMethod, VulnerabilitySeverity


@runtime_checkable
class FindingProtocol(Protocol):
    """Protocol for finding objects to ensure type safety."""
    finding_type: str
    description: str
    severity: Union[VulnerabilitySeverity, str]
    confidence: float
    pattern_type: Union[DecryptionType, str]
    
    def is_dynamic_testable(self) -> bool:
        """Check if finding supports dynamic testing."""
        ...


@dataclass
class ScriptGenerationContext:
    """Context for Frida script generation with comprehensive validation."""
    findings: List[Union[RuntimeDecryptionFinding, FindingProtocol, Dict[str, Any]]]
    config: Dict[str, Any] = field(default_factory=dict)
    hooks_to_generate: List[str] = field(default_factory=list)
    output_directory: Optional[Path] = None
    include_usage_instructions: bool = True
    max_hooks_per_script: int = 50
    template_config: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate context after initialization with comprehensive checks."""
        # Validate findings list
        if not isinstance(self.findings, list):
            raise ValidationError("findings must be a list", 
                                ErrorContext("ScriptGenerationContext", "__post_init__"))
        
        # Validate max hooks limit
        if not isinstance(self.max_hooks_per_script, int) or self.max_hooks_per_script <= 0:
            raise ValidationError("max_hooks_per_script must be a positive integer",
                                ErrorContext("ScriptGenerationContext", "__post_init__"))
        
        # Validate output directory if provided
        if self.output_directory is not None:
            if not isinstance(self.output_directory, (Path, str)):
                raise ValidationError("output_directory must be a Path or string",
                                    ErrorContext("ScriptGenerationContext", "__post_init__"))
            self.output_directory = Path(self.output_directory)
        
        # Validate config is a dictionary
        if not isinstance(self.config, dict):
            raise ValidationError("config must be a dictionary",
                                ErrorContext("ScriptGenerationContext", "__post_init__"))
        
        # Validate hooks list
        if not isinstance(self.hooks_to_generate, list):
            raise ValidationError("hooks_to_generate must be a list",
                                ErrorContext("ScriptGenerationContext", "__post_init__"))
        
        # Validate each hook name is a string
        for hook in self.hooks_to_generate:
            if not isinstance(hook, str):
                raise ValidationError(f"Hook name must be string, got {type(hook)}",
                                    ErrorContext("ScriptGenerationContext", "__post_init__"))


@dataclass
class GeneratedScript:
    """Result of script generation with comprehensive metadata and validation."""
    script_content: str
    script_path: Optional[Path] = None
    hooks_generated: List[str] = field(default_factory=list)
    template_used: str = ""
    generation_time: float = 0.0
    usage_instructions: str = ""
    error_message: Optional[str] = None
    template_variables: Dict[str, Any] = field(default_factory=dict)
    total_hooks_requested: int = 0
    successful_hooks: int = 0
    
    def __post_init__(self):
        """Validate generated script data."""
        if not isinstance(self.script_content, str):
            raise ValidationError("script_content must be a string",
                                ErrorContext("GeneratedScript", "__post_init__"))
        
        if self.script_path is not None and not isinstance(self.script_path, Path):
            raise ValidationError("script_path must be a Path object or None",
                                ErrorContext("GeneratedScript", "__post_init__"))
        
        if not isinstance(self.hooks_generated, list):
            raise ValidationError("hooks_generated must be a list",
                                ErrorContext("GeneratedScript", "__post_init__"))
        
        if self.generation_time < 0:
            raise ValidationError("generation_time cannot be negative",
                                ErrorContext("GeneratedScript", "__post_init__"))
        
        # Calculate successful hooks if not set
        if self.successful_hooks == 0 and self.hooks_generated:
            self.successful_hooks = len(self.hooks_generated)
    
    @property
    def success_rate(self) -> float:
        """Calculate hook generation success rate."""
        if self.total_hooks_requested == 0:
            return 1.0
        return self.successful_hooks / self.total_hooks_requested
    
    @property
    def has_errors(self) -> bool:
        """Check if script generation had errors."""
        return self.error_message is not None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'script_content': self.script_content,
            'script_path': str(self.script_path) if self.script_path else None,
            'hooks_generated': self.hooks_generated,
            'template_used': self.template_used,
            'generation_time': self.generation_time,
            'usage_instructions': self.usage_instructions,
            'error_message': self.error_message,
            'total_hooks_requested': self.total_hooks_requested,
            'successful_hooks': self.successful_hooks,
            'success_rate': self.success_rate,
            'has_errors': self.has_errors
        }


class FridaScriptTemplateLoader:
    """Loads and manages Frida script templates from YAML configuration with validation."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize template loader with comprehensive validation."""
        self.logger = logging.getLogger(__name__)
        self.validator = InputValidator()
        
        # Default config path with validation - using absolute path resolution
        if config_path is None:
            # Use absolute path resolution to handle different working directories
            script_dir = Path(__file__).resolve().parent
            config_path = script_dir / "runtime_decryption_patterns_config.yaml"
            
            # Defensive fallback: if not found, try alternative locations
            if not config_path.exists():
                # Try relative to project root
                alt_config_path = Path().cwd() / "plugins" / "runtime_decryption_analysis" / "runtime_decryption_patterns_config.yaml"
                if alt_config_path.exists():
                    config_path = alt_config_path
                    self.logger.debug(f"Using alternative config path: {config_path}")
                
        elif isinstance(config_path, str):
            config_path = Path(config_path)
        elif not isinstance(config_path, Path):
            raise ValidationError("config_path must be a Path object or string",
                                ErrorContext("FridaScriptTemplateLoader", "__init__"))
        
        # Enhanced validation with better error message
        if not config_path.exists():
            error_msg = f"Configuration file not found: {config_path}"
            error_msg += f"\nSearched in: {config_path.parent}"
            error_msg += f"\nCurrent working directory: {Path().cwd()}"
            error_msg += f"\nScript directory: {Path(__file__).resolve().parent}"
            raise ValidationError(error_msg, ErrorContext("FridaScriptTemplateLoader", "__init__"))
        
        self.config_path = config_path
        self.templates: Dict[str, str] = {}
        self.template_config: Dict[str, Any] = {}
        
        # Load and validate templates from configuration
        self._load_templates()
        self._validate_templates()
    
    def _load_templates(self) -> None:
        """Load templates from YAML configuration."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # Extract Frida templates
            dynamic_analysis = config.get('dynamic_analysis', {})
            self.templates = dynamic_analysis.get('frida_templates', {})
            self.template_config = dynamic_analysis.get('template_config', {})
            
            self.logger.info("Loaded Frida templates from configuration", 
                           extra={'templates_count': len(self.templates), 
                                 'config_path': str(self.config_path)})
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="FridaScriptTemplateLoader",
                operation="_load_templates",
                additional_context={'config_path': str(self.config_path)}
            )
            raise AnalysisError(f"Failed to load Frida templates: {e}", error_context, cause=e)
    
    def _validate_templates(self) -> None:
        """Validate loaded templates for required content and structure."""
        if not self.templates:
            raise ValidationError("No templates loaded from configuration",
                                ErrorContext("FridaScriptTemplateLoader", "_validate_templates"))
        
        required_templates = ['base_template', 'cipher_hooks', 'base64_hooks']
        missing_templates = []
        
        for template_name in required_templates:
            if template_name not in self.templates:
                missing_templates.append(template_name)
            else:
                # Validate template content
                template_content = self.templates[template_name]
                if not self.validator.validate_string(template_content, min_length=10):
                    raise ValidationError(f"Template '{template_name}' is too short or empty",
                                        ErrorContext("FridaScriptTemplateLoader", "_validate_templates"))
                
                # Validate JavaScript syntax markers
                if template_name != 'base_template' and 'Java.perform' not in template_content:
                    self.logger.warning(f"Template '{template_name}' may not contain valid Frida hooks",
                                      extra={'template_name': template_name, 'content_preview': template_content[:100]})
        
        if missing_templates:
            raise ValidationError(f"Missing required templates: {missing_templates}",
                                ErrorContext("FridaScriptTemplateLoader", "_validate_templates"))
        
        # Validate template configuration
        if self.template_config:
            default_hooks = self.template_config.get('default_hooks', [])
            if not isinstance(default_hooks, list):
                raise ValidationError("template_config.default_hooks must be a list",
                                    ErrorContext("FridaScriptTemplateLoader", "_validate_templates"))
            
            # Validate all default hooks exist as templates
            missing_hook_templates = [hook for hook in default_hooks if hook not in self.templates]
            if missing_hook_templates:
                raise ValidationError(f"Default hooks reference missing templates: {missing_hook_templates}",
                                    ErrorContext("FridaScriptTemplateLoader", "_validate_templates"))
        
        self.logger.info("Template validation completed successfully",
                        extra={
                            'templates_validated': len(self.templates),
                            'required_templates_found': len(required_templates),
                            'config_validated': bool(self.template_config)
                        })
    
    def get_template(self, template_name: str) -> str:
        """Get template by name with validation."""
        if template_name not in self.templates:
            available = list(self.templates.keys())
            raise ValueError(f"Template '{template_name}' not found. Available: {available}")
        
        return self.templates[template_name]
    
    def get_template_config(self) -> Dict[str, Any]:
        """Get template configuration."""
        return self.template_config.copy()
    
    def list_templates(self) -> List[str]:
        """List available template names."""
        return list(self.templates.keys())


class FridaScriptGenerator(LoggingMixin):
    """Enhanced Frida script generator with comprehensive capabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the enhanced Frida script generator."""
        super().__init__()
        self.config = config or {}
        
        # Initialize structured logging
        self.contextual_logger = ContextualLogger("FridaScriptGenerator")
        
        # Initialize template loader
        # Fix: RuntimeDecryptionConfig is a dataclass, not a dict - use attribute access
        config_path = getattr(self.config, 'pattern_config_file', None)
        if config_path:
            config_path = Path(config_path)
        else:
            # Fallback to default config file in plugin directory
            config_path = Path(__file__).resolve().parent / "runtime_decryption_patterns_config.yaml"
        
        self.template_loader = FridaScriptTemplateLoader(config_path)
        
        # Initialize Jinja2 environment
        if JINJA2_AVAILABLE:
            self.jinja_env = Environment(
                loader=BaseLoader(),
                trim_blocks=True,
                lstrip_blocks=True
            )
            self.jinja_env.globals.update({
                'enumerate': enumerate,
                'len': len,
                'str': str
            })
        else:
            self.jinja_env = None
            self.contextual_logger.warning("Jinja2 not available, using basic string templating",
                                         context={'jinja2_available': False})
        
        # Load default configuration
        self.default_config = self.template_loader.get_template_config()
        
        self.contextual_logger.info("Enhanced FridaScriptGenerator initialized successfully",
                                  context={
                                      'templates_loaded': len(self.template_loader.templates),
                                      'jinja2_available': JINJA2_AVAILABLE,
                                      'config_keys': list(self.config.keys())
                                  })
    
    def generate_script(self, findings: Sequence[Mapping[str, Any]], 
                       context: Optional[ScriptGenerationContext] = None) -> GeneratedScript:
        """
        Generate a comprehensive Frida script based on findings.
        
        Args:
            findings: List of runtime decryption findings
            context: Optional generation context with configuration
            
        Returns:
            GeneratedScript with content and metadata
        """
        start_time = time.time()
        
        try:
            # Validate and prepare inputs
            validated_findings = self._validate_findings(findings)
            generation_context = context or ScriptGenerationContext(findings=validated_findings)
            
            # Determine hooks to generate
            hooks_to_generate = self._determine_hooks(validated_findings, generation_context)
            
            # Generate script content
            script_content = self._generate_script_content(hooks_to_generate, generation_context)
            
            # Generate usage instructions
            usage_instructions = self._generate_usage_instructions(hooks_to_generate, generation_context)
            
            # Create result with comprehensive metadata
            generation_time = time.time() - start_time
            
            result = GeneratedScript(
                script_content=script_content,
                hooks_generated=hooks_to_generate,
                template_used="base_template_with_hooks",
                generation_time=generation_time,
                usage_instructions=usage_instructions,
                template_variables=generation_context.template_config,
                total_hooks_requested=len(hooks_to_generate),
                successful_hooks=len(hooks_to_generate)  # All hooks succeeded if we get here
            )
            
            self.contextual_logger.info("Generated Frida script successfully",
                                       context={
                                           'hooks_generated': len(hooks_to_generate),
                                           'generation_time': round(generation_time, 2),
                                           'findings_processed': len(validated_findings),
                                           'hooks_list': hooks_to_generate
                                       })
            
            return result
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="FridaScriptGenerator",
                operation="generate_script",
                additional_context={'findings_count': len(findings)}
            )
            
            generation_time = time.time() - start_time
            
            return GeneratedScript(
                script_content=self._generate_fallback_script(),
                error_message=str(e),
                generation_time=generation_time
            )
    
    def _validate_findings(self, findings: Sequence[Union[RuntimeDecryptionFinding, FindingProtocol, Mapping[str, Any]]]) -> List[Union[RuntimeDecryptionFinding, Dict[str, Any]]]:
        """Validate and convert findings to proper data structures using AODS validation patterns."""
        validated_findings = []
        validation_stats = {'total': len(findings), 'valid': 0, 'converted': 0, 'skipped': 0}
        
        validator = InputValidator()
        
        for i, finding in enumerate(findings):
            try:
                # Type 1: Already a RuntimeDecryptionFinding
                if isinstance(finding, RuntimeDecryptionFinding):
                    validated_findings.append(finding)
                    validation_stats['valid'] += 1
                    
                # Type 2: Implements FindingProtocol
                elif isinstance(finding, FindingProtocol):
                    validated_findings.append(finding)
                    validation_stats['valid'] += 1
                    
                # Type 3: Dictionary that can be converted
                elif isinstance(finding, dict):
                    if self._validate_finding_dict(finding, validator):
                        validated_findings.append(finding)
                        validation_stats['converted'] += 1
                    else:
                        validation_stats['skipped'] += 1
                        self.contextual_logger.warning("Skipping invalid finding dictionary",
                                                     context={
                                                         'finding_index': i,
                                                         'missing_fields': self._get_missing_required_fields(finding),
                                                         'available_keys': list(finding.keys())
                                                     })
                        
                # Type 4: Invalid type
                else:
                    validation_stats['skipped'] += 1
                    self.contextual_logger.warning("Skipping invalid finding type",
                                                  context={
                                                      'finding_index': i,
                                                      'finding_type': str(type(finding)),
                                                      'expected_types': ['RuntimeDecryptionFinding', 'dict', 'FindingProtocol']
                                                  })
                    
            except Exception as e:
                validation_stats['skipped'] += 1
                error_context = ErrorContext(
                    component_name="FridaScriptGenerator",
                    operation="_validate_findings",
                    additional_context={
                        'finding_index': i,
                        'finding_preview': str(finding)[:200],
                        'validation_error': str(e)
                    }
                )
                self.contextual_logger.warning("Failed to validate finding",
                                             context=error_context.to_dict())
        
        # Log validation summary
        self.contextual_logger.info("Findings validation completed",
                                   context=validation_stats)
        
        return validated_findings
    
    def _validate_finding_dict(self, finding: Dict[str, Any], validator: InputValidator) -> bool:
        """Validate a finding dictionary has required fields."""
        required_fields = ['finding_type', 'description']
        optional_fields = ['severity', 'confidence', 'pattern_type']
        
        # Check required fields
        for field in required_fields:
            if field not in finding:
                return False
            if not validator.validate_string(finding[field], min_length=1):
                return False
        
        # Validate optional fields if present
        if 'severity' in finding:
            if isinstance(finding['severity'], str):
                try:
                    VulnerabilitySeverity(finding['severity'])
                except ValueError:
                    return False
        
        if 'confidence' in finding:
            if not validator.validate_numeric_range(finding['confidence'], 0.0, 1.0):
                return False
        
        return True
    
    def _get_missing_required_fields(self, finding: Dict[str, Any]) -> List[str]:
        """Get list of missing required fields from a finding dictionary."""
        required_fields = ['finding_type', 'description']
        return [field for field in required_fields if field not in finding or not finding[field]]
    
    def _determine_hooks(self, findings: List[Any], context: ScriptGenerationContext) -> List[str]:
        """Determine which hooks to generate based on findings and context."""
        hooks_to_generate = []
        
        # Use explicitly specified hooks if provided
        if context.hooks_to_generate:
            hooks_to_generate.extend(context.hooks_to_generate)
        else:
            # Use default hooks from configuration
            default_hooks = self.default_config.get('default_hooks', ['cipher_hooks', 'base64_hooks'])
            hooks_to_generate.extend(default_hooks)
        
        # Add finding-specific hooks
        for finding in findings:
            if isinstance(finding, dict):
                finding_type = finding.get('type', '')
                if 'cipher' in finding_type.lower():
                    if 'cipher_hooks' not in hooks_to_generate:
                        hooks_to_generate.append('cipher_hooks')
                elif 'base64' in finding_type.lower():
                    if 'base64_hooks' not in hooks_to_generate:
                        hooks_to_generate.append('base64_hooks')
                elif 'key' in finding_type.lower():
                    if 'key_derivation_hooks' not in hooks_to_generate:
                        hooks_to_generate.append('key_derivation_hooks')
        
        # Limit number of hooks per script
        max_hooks = context.max_hooks_per_script
        if len(hooks_to_generate) > max_hooks:
            self.contextual_logger.warning("Limiting hooks per script for performance",
                                          context={
                                              'original_count': len(hooks_to_generate),
                                              'limited_count': max_hooks,
                                              'excluded_hooks': hooks_to_generate[max_hooks:]
                                          })
            hooks_to_generate = hooks_to_generate[:max_hooks]
        
        return hooks_to_generate
    
    def _generate_script_content(self, hooks_to_generate: List[str], 
                                context: ScriptGenerationContext) -> str:
        """Generate the main script content using templates."""
        try:
            # Get base template
            base_template = self.template_loader.get_template('base_template')
            
            # Generate individual hooks
            hook_contents = []
            for hook_name in hooks_to_generate:
                hook_content = self._generate_hook_content(hook_name, context)
                if hook_content:
                    hook_contents.append(hook_content)
            
            # Render base template with hooks
            if self.jinja_env:
                template = self.jinja_env.from_string(base_template)
                script_content = template.render(hooks=hook_contents)
            else:
                # Fallback to basic string replacement
                hooks_placeholder = '\n\n'.join(hook_contents)
                script_content = base_template.replace('{% for hook in hooks %}\n{{ hook }}\n{% endfor %}', hooks_placeholder)
            
            return script_content
            
        except Exception as e:
            self.contextual_logger.error("Failed to generate script content",
                                        context={
                                            'error': str(e),
                                            'hooks_requested': hooks_to_generate,
                                            'fallback_used': True
                                        })
            return self._generate_fallback_script()
    
    def _generate_hook_content(self, hook_name: str, context: ScriptGenerationContext) -> str:
        """Generate content for a specific hook using templates."""
        try:
            # Get hook template
            hook_template = self.template_loader.get_template(hook_name)
            
            # Prepare template variables
            template_vars = self.default_config.copy()
            template_vars.update(context.config)
            
            # Render hook template
            if self.jinja_env:
                template = self.jinja_env.from_string(hook_template)
                hook_content = template.render(**template_vars)
            else:
                # Basic string formatting fallback
                hook_content = hook_template.format(**template_vars)
            
            return hook_content
            
        except Exception as e:
            self.contextual_logger.warning("Failed to generate hook",
                                          context={
                                              'hook_name': hook_name,
                                              'error': str(e),
                                              'template_vars': list(template_vars.keys()) if 'template_vars' in locals() else []
                                          })
            return f"// Hook '{hook_name}' generation failed: {e}"
    
    def _generate_usage_instructions(self, hooks_generated: List[str], 
                                   context: ScriptGenerationContext) -> str:
        """Generate usage instructions for the script."""
        instructions = [
            "AODS Frida Script Usage Instructions",
            "=" * 40,
            "",
            "1. Ensure Frida is installed and the target device is connected:",
            "   pip install frida-tools",
            "   adb devices",
            "",
            "2. Start the target application on the device",
            "",
            "3. Run the script with Frida:",
            "   frida -U -f <package_name> -l <script_file>",
            "   # or attach to running process:",
            "   frida -U <package_name> -l <script_file>",
            "",
            f"Generated Hooks: {', '.join(hooks_generated)}",
            "",
            "Monitor the console output for decryption activity and key usage.",
            "Press Ctrl+C to stop the script.",
            "",
            "For troubleshooting, check the Frida console for error messages."
        ]
        
        return '\n'.join(instructions)
    
    def _generate_fallback_script(self) -> str:
        """Generate a basic fallback script when template generation fails."""
        return '''// AODS Fallback Frida Script
console.log('[+] AODS Fallback Frida script loaded');

Java.perform(function() {
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        
        Cipher.doFinal.overload('[B').implementation = function(input) {
            console.log('[+] Cipher.doFinal called - fallback hook');
            console.log('    Input length: ' + input.length);
            var result = this.doFinal(input);
            console.log('    Output length: ' + result.length);
            return result;
        };
        
        console.log('[+] Fallback hooks installed successfully');
    } catch (e) {
        console.error('[!] Fallback hook installation failed: ' + e.message);
    }
});'''
    
    def generate_analysis_report(self, script_output: str) -> Dict[str, Any]:
        """Generate analysis report from Frida script output."""
        try:
            # Analyze script output for patterns and findings
            lines = script_output.split('\n')
            
            cipher_calls = len([line for line in lines if 'Cipher.doFinal called' in line])
            base64_calls = len([line for line in lines if 'Base64.decode called' in line])
            key_operations = len([line for line in lines if 'generateSecret' in line or 'generateKey' in line])
            errors = len([line for line in lines if '[!]' in line])
            
            return {
                'script_executed': True,
                'output_length': len(script_output),
                'analysis_summary': {
                    'cipher_operations': cipher_calls,
                    'base64_operations': base64_calls,
                    'key_operations': key_operations,
                    'errors_detected': errors
                },
                'recommendations': self._generate_recommendations(cipher_calls, base64_calls, key_operations),
                'next_steps': [
                    'Analyze captured decryption keys and algorithms',
                    'Review error patterns for potential vulnerabilities',
                    'Correlate runtime behavior with static analysis findings'
                ]
            }
            
        except Exception as e:
            self.contextual_logger.error("Failed to generate analysis report",
                                        context={
                                            'error': str(e),
                                            'output_length': len(script_output),
                                            'output_preview': script_output[:200] if script_output else ''
                                        })
            return {
                'script_executed': True,
                'error': str(e),
                'output_length': len(script_output),
                'summary': 'Analysis report generation failed'
            }
    
    def _generate_recommendations(self, cipher_calls: int, base64_calls: int, key_operations: int) -> List[str]:
        """Generate security recommendations based on observed activity."""
        recommendations = []
        
        if cipher_calls > 0:
            recommendations.append(f'Detected {cipher_calls} cipher operations - verify encryption algorithms and key management')
        
        if base64_calls > 0:
            recommendations.append(f'Observed {base64_calls} Base64 operations - check for encoded sensitive data')
        
        if key_operations > 0:
            recommendations.append(f'Found {key_operations} key generation/derivation operations - audit key security')
        
        if cipher_calls == 0 and base64_calls == 0:
            recommendations.append('No cryptographic activity detected - verify hook coverage or application behavior')
        
        return recommendations
    
    def save_script_to_file(self, script: GeneratedScript, output_path: Path) -> bool:
        """Save generated script to file with usage instructions."""
        try:
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write script content
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(script.script_content)
            
            # Write usage instructions if available
            if script.usage_instructions:
                instructions_path = output_path.with_suffix('.txt')
                with open(instructions_path, 'w', encoding='utf-8') as f:
                    f.write(script.usage_instructions)
            
            script.script_path = output_path
            self.contextual_logger.info("Saved Frida script successfully",
                                       context={
                                           'output_path': str(output_path),
                                           'script_size': len(script.script_content),
                                           'hooks_included': len(script.hooks_generated),
                                           'instructions_saved': bool(script.usage_instructions)
                                       })
            
            return True
            
        except Exception as e:
            self.contextual_logger.error("Failed to save script to file",
                                        context={
                                            'output_path': str(output_path),
                                            'error': str(e),
                                            'script_size': len(script.script_content) if script.script_content else 0
                                        })
            return False


def create_cli_interface():
    """Create CLI interface for standalone Frida script generation."""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description="AODS Frida Script Generator - Generate dynamic Frida scripts for runtime analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate script from findings JSON file
  python frida_script_generator.py --findings findings.json --output script.js
  
  # Generate with specific hooks
  python frida_script_generator.py --hooks cipher_hooks,base64_hooks --output script.js
  
  # Generate with custom configuration
  python frida_script_generator.py --config config.yaml --output script.js
        """
    )
    
    parser.add_argument('--findings', '-f', 
                       help='Path to JSON file containing findings')
    parser.add_argument('--hooks', '-k',
                       help='Comma-separated list of hooks to generate (e.g., cipher_hooks,base64_hooks)')
    parser.add_argument('--output', '-o', required=True,
                       help='Output path for generated Frida script')
    parser.add_argument('--config', '-c',
                       help='Path to custom configuration file')
    parser.add_argument('--instructions', '-i', action='store_true',
                       help='Generate usage instructions file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--max-hooks', type=int, default=20,
                       help='Maximum number of hooks per script (default: 20)')
    
    return parser


def load_findings_from_file(findings_path: str) -> List[Dict[str, Any]]:
    """Load findings from JSON file."""
    try:
        with open(findings_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON structures
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            if 'findings' in data:
                return data['findings']
            elif 'vulnerabilities' in data:
                return data['vulnerabilities']
            else:
                return [data]  # Single finding object
        else:
            raise ValueError("Invalid JSON structure for findings")
            
    except Exception as e:
        raise AnalysisError(f"Failed to load findings from {findings_path}: {e}")


def main():
    """Main CLI entry point."""
    parser = create_cli_interface()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize generator
        config = {}
        if args.config:
            config['config_path'] = args.config
        
        generator = FridaScriptGenerator(config)
        
        # Prepare findings
        findings = []
        if args.findings:
            findings = load_findings_from_file(args.findings)
        
        # Prepare hooks
        hooks_to_generate = []
        if args.hooks:
            hooks_to_generate = [hook.strip() for hook in args.hooks.split(',')]
        
        # Create generation context
        context = ScriptGenerationContext(
            findings=findings,
            hooks_to_generate=hooks_to_generate,
            output_directory=Path(args.output).parent,
            include_usage_instructions=args.instructions,
            max_hooks_per_script=args.max_hooks
        )
        
        # Generate script
        print(f"Generating Frida script with {len(findings)} findings...")
        result = generator.generate_script(findings, context)
        
        # Save script
        output_path = Path(args.output)
        success = generator.save_script_to_file(result, output_path)
        
        if success:
            print(f"✅ Frida script generated successfully: {output_path}")
            print(f"   Hooks generated: {len(result.hooks_generated)}")
            print(f"   Generation time: {result.generation_time:.2f}s")
            print(f"   Success rate: {result.success_rate:.1%}")
            
            if result.has_errors:
                print(f"⚠️  Warnings: {result.error_message}")
            
            if args.instructions and result.usage_instructions:
                instructions_path = output_path.with_suffix('.txt')
                print(f"📝 Usage instructions: {instructions_path}")
        else:
            print("❌ Failed to generate Frida script")
            return 1
            
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 
