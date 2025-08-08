#!/usr/bin/env python3
"""
Configuration-Aware Template Pattern Source

Enhanced template pattern source that loads templates from external YAML configuration.
Supports dynamic template loading, category filtering, and runtime configuration updates.
"""

import logging
from typing import Dict, List, Any, Optional
from ..models import VulnerabilityPattern, PatternTemplate, PatternType, SeverityLevel, LanguageSupport
from ..config.config_manager import get_config_manager
from ..generators.pattern_builder import PatternBuilder
from .base import PatternSource

class ConfigAwareTemplateSource(PatternSource):
    """
    Template pattern source that loads templates from external configuration.
    
    Provides flexible template management through YAML configuration files,
    supporting categories, dynamic loading, and runtime updates.
    """
    
    def __init__(self, **kwargs):
        """Initialize configuration-aware template source."""
        super().__init__(**kwargs)
        self.config_manager = get_config_manager()
        self._template_cache: Optional[List[Dict[str, Any]]] = None
        
    def load_patterns(self) -> List[VulnerabilityPattern]:
        """Generate patterns from configured templates."""
        patterns = []
        templates = self._get_configured_templates()
        
        for template_config in templates:
            template_patterns = self._expand_template_from_config(template_config)
            patterns.extend(template_patterns)
            
        self.logger.info(f"Generated {len(patterns)} configuration-based template patterns")
        return patterns
    
    def _get_configured_templates(self) -> List[Dict[str, Any]]:
        """Load templates from configuration."""
        if self._template_cache is not None:
            return self._template_cache
        
        source_config = self.config_manager.get_source_config('template_source')
        if not source_config:
            self.logger.warning("No template source configuration found")
            return []
        
        # Get template categories to load
        template_categories = source_config.get('template_categories', ['android_security'])
        
        # Load templates for specified categories
        templates = []
        for category in template_categories:
            category_templates = self.config_manager.get_templates_for_category(category)
            templates.extend(category_templates)
        
        # Apply configuration limits
        expand_all = source_config.get('expand_all_templates', True)
        if not expand_all:
            max_templates = source_config.get('max_patterns', 50)
            templates = templates[:max_templates]
        
        self._template_cache = templates
        return templates
    
    def _expand_template_from_config(self, template_config: Dict[str, Any]) -> List[VulnerabilityPattern]:
        """Expand a template configuration into vulnerability patterns."""
        patterns = []
        
        try:
            # Extract template information
            template_id = template_config.get('template_id', 'unknown')
            template_name = template_config.get('template_name', 'Unknown Template')
            base_regex = template_config.get('base_regex', '')
            vuln_type = template_config.get('vulnerability_type', 'general_vulnerability')
            severity = template_config.get('severity', 'MEDIUM')
            cwe_id = template_config.get('cwe_id', 'CWE-200')
            masvs_category = template_config.get('masvs_category', 'MSTG-CODE-8')
            variations = template_config.get('variations', [])
            
            if not base_regex or not variations:
                self.logger.warning(f"Template {template_id} missing base_regex or variations")
                return patterns
            
            # Get source configuration for limits
            source_config = self.config_manager.get_source_config('template_source')
            variation_limit = source_config.get('variation_limit_per_template', 10) if source_config else 10
            
            # Generate patterns for each variation
            for i, variation in enumerate(variations[:variation_limit]):
                try:
                    pattern = self._create_pattern_from_variation(
                        template_id, template_name, base_regex, vuln_type, 
                        severity, cwe_id, masvs_category, variation, i
                    )
                    
                    if pattern and self.validate_pattern(pattern):
                        patterns.append(pattern)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to create pattern from template {template_id} variation {i}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to expand template {template_config.get('template_id', 'unknown')}: {e}")
            
        return patterns
    
    def _create_pattern_from_variation(
        self, 
        template_id: str,
        template_name: str,
        base_regex: str,
        vuln_type: str,
        severity: str,
        cwe_id: str,
        masvs_category: str,
        variation: Dict[str, Any],
        variation_index: int
    ) -> Optional[VulnerabilityPattern]:
        """Create a vulnerability pattern from a template variation."""
        
        # Replace placeholders in base regex
        expanded_regex = base_regex
        for placeholder, value in variation.items():
            if placeholder not in ['context', 'confidence']:
                expanded_regex = expanded_regex.replace(f"{{{placeholder}}}", str(value))
        
        # Extract pattern information
        context = variation.get('context', f'Template variation {variation_index + 1}')
        confidence = variation.get('confidence', 0.8)
        
        # Use PatternBuilder for consistent pattern creation
        return PatternBuilder.create_pattern(
            pattern_id=f"{template_id}_{variation_index:03d}",
            pattern_name=f"{template_name} - {context}",
            pattern_regex=expanded_regex,
            pattern_type=vuln_type,
            severity=severity,
            description=f"Configuration-based template pattern: {context}",
            source="Configuration Templates",
            confidence_base=confidence,
            cwe_id=cwe_id,
            masvs_category=masvs_category,
            language_support=["java", "kotlin"],
            context_requirements=self._extract_context_from_variation(variation),
            source_data={
                "template_id": template_id,
                "variation_index": variation_index,
                "variation_data": variation,
                "config_based": True
            }
        )
    
    def _extract_context_from_variation(self, variation: Dict[str, Any]) -> List[str]:
        """Extract context requirements from variation data."""
        context = variation.get('context', '').lower()
        
        contexts = []
        if 'database' in context or 'sql' in context:
            contexts.extend(['database', 'user_input'])
        elif 'file' in context or 'path' in context:
            contexts.extend(['file_operations', 'user_input'])
        elif 'command' in context or 'exec' in context:
            contexts.extend(['system_commands', 'user_input'])
        elif 'webview' in context or 'web' in context:
            contexts.extend(['web_content', 'browser'])
        elif 'secret' in context or 'key' in context:
            contexts.extend(['cryptography', 'authentication'])
        else:
            contexts.append('general')
        
        return contexts
    
    def get_available_categories(self) -> List[str]:
        """Get list of available template categories."""
        template_config = self.config_manager.get_template_config()
        return list(template_config.get('categories', {}).keys())
    
    def reload_templates(self):
        """Reload templates from configuration."""
        self._template_cache = None
        self.clear_cache()
        self.logger.info("Reloaded templates from configuration")
    
    def get_template_statistics(self) -> Dict[str, Any]:
        """Get statistics about configured templates."""
        templates = self._get_configured_templates()
        
        stats = {
            "total_templates": len(templates),
            "templates_by_type": {},
            "templates_by_severity": {},
            "variation_counts": {}
        }
        
        for template in templates:
            vuln_type = template.get('vulnerability_type', 'unknown')
            severity = template.get('severity', 'UNKNOWN')
            template_id = template.get('template_id', 'unknown')
            variation_count = len(template.get('variations', []))
            
            stats["templates_by_type"][vuln_type] = stats["templates_by_type"].get(vuln_type, 0) + 1
            stats["templates_by_severity"][severity] = stats["templates_by_severity"].get(severity, 0) + 1
            stats["variation_counts"][template_id] = variation_count
        
        return stats
    
    def get_source_info(self) -> Dict[str, Any]:
        """Get enhanced source information including configuration details."""
        base_info = {
            "source_name": "Configuration Templates",
            "source_type": "config_aware_template_expansion",
            "description": "Patterns generated from external YAML template configurations",
            "configuration_driven": True
        }
        
        # Add configuration-specific information
        source_config = self.config_manager.get_source_config('template_source')
        if source_config:
            base_info.update({
                "configured_categories": source_config.get('template_categories', []),
                "expand_all_templates": source_config.get('expand_all_templates', True),
                "variation_limit": source_config.get('variation_limit_per_template', 10),
                "context_variations_enabled": source_config.get('enable_context_variations', True)
            })
        
        # Add template statistics
        base_info["template_statistics"] = self.get_template_statistics()
        
        return base_info
    
    def validate_configuration(self) -> List[str]:
        """
        Validate template configuration for common issues.
        
        Returns:
            List of validation warnings/errors
        """
        issues = []
        templates = self._get_configured_templates()
        
        for template in templates:
            template_id = template.get('template_id', 'unknown')
            
            # Check required fields
            if not template.get('base_regex'):
                issues.append(f"Template {template_id}: missing base_regex")
            
            if not template.get('variations'):
                issues.append(f"Template {template_id}: no variations defined")
            
            # Validate regex syntax
            base_regex = template.get('base_regex', '')
            if base_regex and not PatternBuilder.validate_regex(base_regex):
                issues.append(f"Template {template_id}: invalid base_regex syntax")
            
            # Check placeholder consistency
            variations = template.get('variations', [])
            if variations and base_regex:
                placeholders_in_regex = set()
                import re
                for match in re.finditer(r'\{([^}]+)\}', base_regex):
                    placeholders_in_regex.add(match.group(1))
                
                for i, variation in enumerate(variations):
                    variation_keys = set(variation.keys()) - {'context', 'confidence'}
                    missing_keys = placeholders_in_regex - variation_keys
                    if missing_keys:
                        issues.append(f"Template {template_id} variation {i}: missing placeholders {missing_keys}")
        
        return issues 