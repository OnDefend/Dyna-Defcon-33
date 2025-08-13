#!/usr/bin/env python3
"""
NIST Compliance Configuration Loader

This module provides utilities for loading and managing NIST Cybersecurity Framework
compliance configuration settings, replacing hardcoded values with configurable parameters.

"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

@dataclass
class NISTComplianceConfig:
    """NIST Compliance Configuration Data Class"""
    tier_thresholds: Dict[str, float]
    tier_scores: Dict[str, int]
    severity_weights: Dict[str, int]
    severity_penalties: Dict[str, int]
    risk_thresholds: Dict[str, int]
    compliance_levels: Dict[str, float]
    confidence_mappings: Dict[str, float]
    plugin_settings: Dict[str, Any]
    roadmap_phases: List[Dict[str, Any]]
    framework_version: str
    organization_profile: Dict[str, Any]
    reporting: Dict[str, Any]
    vulnerability_mappings: Dict[str, Dict[str, List[str]]]

class NISTConfigLoader:
    """
    Configuration loader for NIST Cybersecurity Framework compliance settings.
    
    This class loads configuration from YAML files and provides access to
    all configurable parameters used in NIST compliance assessment.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize NIST configuration loader.
        
        Args:
            config_path: Path to NIST compliance configuration file
        """
        self.logger = logging.getLogger(f"{__name__}.NISTConfigLoader")
        
        # Default configuration file path
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "nist_compliance_config.yaml"
        
        self.config_path = config_path
        self.config: Optional[NISTComplianceConfig] = None
        
        # Load configuration
        self._load_configuration()
        
        self.logger.info(f"🔧 NIST compliance configuration loaded from: {self.config_path}")
    
    def _load_configuration(self) -> None:
        """Load NIST compliance configuration from YAML file"""
        try:
            if not self.config_path.exists():
                self.logger.error(f"❌ Configuration file not found: {self.config_path}")
                self._create_default_config()
                return
            
            with open(self.config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file)
            
            # Validate and create configuration object
            self.config = NISTComplianceConfig(
                tier_thresholds=config_data.get('tier_thresholds', {}),
                tier_scores=config_data.get('tier_scores', {}),
                severity_weights=config_data.get('severity_weights', {}),
                severity_penalties=config_data.get('severity_penalties', {}),
                risk_thresholds=config_data.get('risk_thresholds', {}),
                compliance_levels=config_data.get('compliance_levels', {}),
                confidence_mappings=config_data.get('confidence_mappings', {}),
                plugin_settings=config_data.get('plugin_settings', {}),
                roadmap_phases=config_data.get('roadmap_phases', []),
                framework_version=config_data.get('framework_version', '1.1'),
                organization_profile=config_data.get('organization_profile', {}),
                reporting=config_data.get('reporting', {}),
                vulnerability_mappings=config_data.get('vulnerability_mappings', {})
            )
            
            self.logger.info("✅ NIST compliance configuration loaded successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load NIST configuration: {str(e)}")
            self._create_default_config()
    
    def _create_default_config(self) -> None:
        """Create default configuration if file is missing or invalid"""
        self.logger.warning("⚠️ Creating default NIST compliance configuration")
        
        self.config = NISTComplianceConfig(
            tier_thresholds={'adaptive': 0.8, 'repeatable': 0.6, 'risk_informed': 0.4},
            tier_scores={'PARTIAL': 25, 'RISK_INFORMED': 50, 'REPEATABLE': 75, 'ADAPTIVE': 100},
            severity_weights={'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4},
            severity_penalties={'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2},
            risk_thresholds={'low': 80, 'medium': 60},
            compliance_levels={'excellent': 90.0, 'good': 75.0, 'acceptable': 60.0, 'needs_improvement': 40.0},
            confidence_mappings={'HIGH': 0.9, 'MEDIUM': 0.7, 'LOW': 0.5, 'default': 0.8},
            plugin_settings={'timeout': 180, 'max_recommendations': 15, 'max_gap_analysis_items': 20},
            roadmap_phases=[],
            framework_version='1.1',
            organization_profile={'assessment_scope': 'Mobile Application Security', 'target_tier': 'RISK_INFORMED'},
            reporting={'include_executive_summary': True, 'include_detailed_analysis': True},
            vulnerability_mappings={}
        )
    
    def get_tier_threshold(self, tier_name: str) -> float:
        """Get tier threshold value"""
        return self.config.tier_thresholds.get(tier_name.lower(), 0.4)
    
    def get_tier_score(self, tier_name: str) -> int:
        """Get tier score value"""
        return self.config.tier_scores.get(tier_name.upper(), 25)
    
    def get_severity_weight(self, severity: str) -> int:
        """Get severity weight value"""
        return self.config.severity_weights.get(severity.upper(), 2)
    
    def get_severity_penalty(self, severity: str) -> int:
        """Get severity penalty value"""
        return self.config.severity_penalties.get(severity.upper(), 5)
    
    def get_risk_threshold(self, risk_level: str) -> int:
        """Get risk threshold value"""
        return self.config.risk_thresholds.get(risk_level.lower(), 60)
    
    def get_compliance_level_threshold(self, level: str) -> float:
        """Get compliance level threshold"""
        return self.config.compliance_levels.get(level.lower(), 60.0)
    
    def get_confidence_score(self, confidence_level: str) -> float:
        """Get confidence score mapping"""
        return self.config.confidence_mappings.get(confidence_level.upper(), 
                                                  self.config.confidence_mappings.get('default', 0.8))
    
    def get_plugin_setting(self, setting_name: str, default_value: Any = None) -> Any:
        """Get plugin configuration setting"""
        return self.config.plugin_settings.get(setting_name, default_value)
    
    def get_roadmap_phases(self) -> List[Dict[str, Any]]:
        """Get implementation roadmap phases"""
        return self.config.roadmap_phases
    
    def get_vulnerability_mappings(self, category: str = None) -> Dict[str, Any]:
        """Get vulnerability to NIST subcategory mappings"""
        if category:
            return self.config.vulnerability_mappings.get(category, {})
        return self.config.vulnerability_mappings
    
    def get_framework_version(self) -> str:
        """Get NIST framework version"""
        return self.config.framework_version
    
    def get_organization_profile(self) -> Dict[str, Any]:
        """Get organization profile template"""
        return self.config.organization_profile
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration"""
        return self.config.reporting
    
    def reload_configuration(self) -> bool:
        """Reload configuration from file"""
        try:
            self._load_configuration()
            self.logger.info("🔄 NIST compliance configuration reloaded")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to reload configuration: {str(e)}")
            return False
    
    def validate_configuration(self) -> bool:
        """Validate configuration completeness and correctness"""
        if not self.config:
            return False
        
        required_sections = [
            'tier_thresholds', 'tier_scores', 'severity_weights',
            'severity_penalties', 'risk_thresholds', 'compliance_levels'
        ]
        
        for section in required_sections:
            if not getattr(self.config, section):
                self.logger.error(f"❌ Missing required configuration section: {section}")
                return False
        
        # Validate tier thresholds are in correct order
        thresholds = self.config.tier_thresholds
        if not (0 <= thresholds.get('risk_informed', 0) <= thresholds.get('repeatable', 0) <= thresholds.get('adaptive', 0) <= 1):
            self.logger.error("❌ Invalid tier threshold ordering")
            return False
        
        self.logger.info("✅ NIST compliance configuration validation passed")
        return True

# Global configuration loader instance
_config_loader: Optional[NISTConfigLoader] = None

def get_nist_config() -> NISTConfigLoader:
    """
    Get global NIST configuration loader instance.
    
    Returns:
        NISTConfigLoader: Configuration loader instance
    """
    global _config_loader
    if _config_loader is None:
        _config_loader = NISTConfigLoader()
    return _config_loader

def reload_nist_config() -> bool:
    """
    Reload NIST configuration from file.
    
    Returns:
        bool: True if reload successful, False otherwise
    """
    global _config_loader
    if _config_loader is None:
        _config_loader = NISTConfigLoader()
        return True
    return _config_loader.reload_configuration()

if __name__ == "__main__":
    # Test configuration loader
    config_loader = NISTConfigLoader()
    
    print("🔧 NIST Compliance Configuration Test")
    print(f"Framework Version: {config_loader.get_framework_version()}")
    print(f"Adaptive Tier Threshold: {config_loader.get_tier_threshold('adaptive')}")
    print(f"Critical Severity Weight: {config_loader.get_severity_weight('CRITICAL')}")
    print(f"Plugin Timeout: {config_loader.get_plugin_setting('timeout')}")
    print(f"Configuration Valid: {config_loader.validate_configuration()}") 