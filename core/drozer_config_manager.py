#!/usr/bin/env python3
"""
Drozer Configuration Manager
Handles user-configurable connection setups and presets
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict

from .persistent_drozer_connector import ConnectionConfig, PersistentDrozerConnector

class DrozerConfigManager:
    """
    Manages Drozer connection configurations with user customization support.
    
    Features:
    - Load/save custom configurations
    - Preset configuration templates
    - Environment-specific setups
    - Command validation and testing
    """
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.config_file = self.config_dir / "drozer_connection_config.json"
        self.user_config_file = self.config_dir / "user_drozer_config.json"
        
        self.logger = logging.getLogger("drozer_config_manager")
        
        # Load default configuration
        self.default_config = self._load_default_config()
        self.user_config = self._load_user_config()
        
        self.logger.info("📋 Drozer Configuration Manager initialized")
    
    def _load_default_config(self) -> Dict:
        """Load default configuration template"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            else:
                return self._create_default_config()
        except Exception as e:
            self.logger.warning(f"Could not load default config: {e}")
            return self._create_default_config()
    
    def _load_user_config(self) -> Dict:
        """Load user-specific configuration"""
        try:
            if self.user_config_file.exists():
                with open(self.user_config_file, 'r') as f:
                    return json.load(f)
            else:
                return {}
        except Exception as e:
            self.logger.warning(f"Could not load user config: {e}")
            return {}
    
    def _create_default_config(self) -> Dict:
        """Create minimal default configuration"""
        return {
            "connection_settings": {
                "drozer_port": 31415,
                "connection_timeout": 30,
                "command_timeout": 60
            },
            "reconnection_strategy": {
                "max_reconnection_attempts": 3,
                "reconnection_delay": 2.0,
                "persistent_mode": True,
                "force_reconnect_every_command": False
            },
            "custom_commands": {
                "pre_connection_commands": [],
                "custom_adb_setup": [],
                "custom_drozer_start": [],
                "post_connection_commands": []
            }
        }
    
    def get_preset_config(self, preset_name: str) -> Optional[ConnectionConfig]:
        """Get a preset configuration by name"""
        presets = self.default_config.get("preset_configurations", {})
        
        if preset_name not in presets:
            available = list(presets.keys())
            self.logger.error(f"Preset '{preset_name}' not found. Available: {available}")
            return None
        
        preset = presets[preset_name]
        
        # Merge with base settings
        config_data = self._merge_configs(self.default_config, {"reconnection_strategy": preset})
        
        return self._dict_to_connection_config(config_data)
    
    def create_custom_config(self, 
                           preset_base: str = "standard",
                           device_id: str = None,
                           max_attempts: int = None,
                           reconnection_delay: float = None,
                           force_reconnect: bool = None,
                           pre_commands: List[str] = None,
                           adb_setup: List[str] = None,
                           drozer_start: List[str] = None,
                           post_commands: List[str] = None) -> ConnectionConfig:
        """Create a custom configuration with user parameters"""
        
        # Start with preset
        if preset_base:
            config = self.get_preset_config(preset_base)
            if not config:
                config = self._dict_to_connection_config(self.default_config)
        else:
            config = self._dict_to_connection_config(self.default_config)
        
        # Apply user customizations
        if device_id is not None:
            config.device_id = device_id
        if max_attempts is not None:
            config.max_reconnection_attempts = max_attempts
        if reconnection_delay is not None:
            config.reconnection_delay = reconnection_delay
        if force_reconnect is not None:
            config.force_reconnect_every_command = force_reconnect
        
        # Custom commands
        if pre_commands is not None:
            config.pre_connection_commands = pre_commands
        if adb_setup is not None:
            config.custom_adb_setup = adb_setup
        if drozer_start is not None:
            config.custom_drozer_start = drozer_start
        if post_commands is not None:
            config.post_connection_commands = post_commands
        
        return config
    
    def save_user_config(self, config: ConnectionConfig, name: str = "default"):
        """Save user configuration for future use"""
        try:
            if "user_configurations" not in self.user_config:
                self.user_config["user_configurations"] = {}
            
            self.user_config["user_configurations"][name] = asdict(config)
            
            with open(self.user_config_file, 'w') as f:
                json.dump(self.user_config, f, indent=2)
            
            self.logger.info(f"✅ Saved user configuration: {name}")
            
        except Exception as e:
            self.logger.error(f"Failed to save user config: {e}")
    
    def load_user_config(self, name: str = "default") -> Optional[ConnectionConfig]:
        """Load saved user configuration"""
        try:
            user_configs = self.user_config.get("user_configurations", {})
            
            if name not in user_configs:
                self.logger.warning(f"User config '{name}' not found")
                return None
            
            config_data = {"connection_settings": {}, "reconnection_strategy": user_configs[name]}
            return self._dict_to_connection_config(config_data)
            
        except Exception as e:
            self.logger.error(f"Failed to load user config: {e}")
            return None
    
    def list_available_presets(self) -> List[str]:
        """List all available preset configurations"""
        presets = self.default_config.get("preset_configurations", {})
        return list(presets.keys())
    
    def list_user_configs(self) -> List[str]:
        """List all saved user configurations"""
        user_configs = self.user_config.get("user_configurations", {})
        return list(user_configs.keys())
    
    def get_preset_description(self, preset_name: str) -> str:
        """Get description of a preset configuration"""
        presets = self.default_config.get("preset_configurations", {})
        
        if preset_name in presets:
            return presets[preset_name].get("description", "No description available")
        else:
            return "Preset not found"
    
    def validate_commands(self, commands: List[str]) -> List[str]:
        """Validate and filter custom commands"""
        valid_commands = []
        
        for cmd in commands:
            # Skip comments and empty lines
            if cmd.strip().startswith("#") or not cmd.strip():
                continue
            
            # Basic validation
            if len(cmd.strip()) > 0:
                valid_commands.append(cmd.strip())
        
        return valid_commands
    
    def create_drozer_connector(self, package_name: str, 
                              preset: str = "standard",
                              custom_config: ConnectionConfig = None) -> PersistentDrozerConnector:
        """Create a configured Drozer connector"""
        
        if custom_config:
            config = custom_config
        else:
            config = self.get_preset_config(preset)
            if not config:
                self.logger.warning(f"Using default config due to invalid preset: {preset}")
                config = self._dict_to_connection_config(self.default_config)
        
        return PersistentDrozerConnector(package_name, config)
    
    def _merge_configs(self, base: Dict, override: Dict) -> Dict:
        """Merge configuration dictionaries"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _dict_to_connection_config(self, config_dict: Dict) -> ConnectionConfig:
        """Convert dictionary to ConnectionConfig object"""
        # Extract relevant sections
        connection_settings = config_dict.get("connection_settings", {})
        reconnection_strategy = config_dict.get("reconnection_strategy", {})
        custom_commands = config_dict.get("custom_commands", {})
        advanced_options = config_dict.get("advanced_options", {})
        
        # Create ConnectionConfig with merged settings
        return ConnectionConfig(
            # Connection settings
            device_id=connection_settings.get("device_id"),
            drozer_port=connection_settings.get("drozer_port", 31415),
            adb_port=connection_settings.get("adb_port", 5037),
            connection_timeout=connection_settings.get("connection_timeout", 30),
            command_timeout=connection_settings.get("command_timeout", 60),
            
            # Reconnection strategy
            max_reconnection_attempts=reconnection_strategy.get("max_reconnection_attempts", 3),
            reconnection_delay=reconnection_strategy.get("reconnection_delay", 2.0),
            persistent_mode=reconnection_strategy.get("persistent_mode", True),
            force_reconnect_every_command=reconnection_strategy.get("force_reconnect_every_command", False),
            
            # Custom commands
            pre_connection_commands=self.validate_commands(custom_commands.get("pre_connection_commands", [])),
            post_connection_commands=self.validate_commands(custom_commands.get("post_connection_commands", [])),
            custom_adb_setup=self.validate_commands(custom_commands.get("custom_adb_setup", [])),
            custom_drozer_start=self.validate_commands(custom_commands.get("custom_drozer_start", [])),
            connection_test_command=advanced_options.get("connection_test_command", "list"),
            
            # Advanced options
            auto_install_drozer_agent=advanced_options.get("auto_install_drozer_agent", False),
            drozer_agent_apk_path=advanced_options.get("drozer_agent_apk_path"),
            restart_adb_on_failure=reconnection_strategy.get("restart_adb_on_failure", True),
            kill_existing_drozer=reconnection_strategy.get("kill_existing_drozer", True)
        )
    
    def print_configuration_help(self):
        """Print helpful information about configuration options"""
        print("""
🔧 Drozer Connection Configuration Help
========================================

📋 Available Presets:""")
        
        for preset in self.list_available_presets():
            description = self.get_preset_description(preset)
            print(f"  • {preset}: {description}")
        
        print("""
💡 Custom Configuration Options:
  • device_id: Specific device to use (optional)
  • max_attempts: Maximum reconnection attempts (1-10)
  • reconnection_delay: Delay between attempts in seconds
  • force_reconnect: Reconnect before every command (boolean)
  
🔧 Custom Commands Support:
  • pre_commands: Run before establishing connection
  • adb_setup: Custom ADB port forwarding commands
  • drozer_start: Custom Drozer connection commands  
  • post_commands: Run after successful connection
  
📝 Variable Substitution:
  • {device_id}: Device identifier
  • {port}: Drozer port number
  • {package}: Target package name
  
💾 Save/Load Configurations:
  • Save custom configs for reuse
  • Load saved configurations by name
  • Export/import for team sharing
""")

# Factory functions for easy access
def create_standard_drozer(package_name: str) -> PersistentDrozerConnector:
    """Create drozer with standard reconnection"""
    manager = DrozerConfigManager()
    return manager.create_drozer_connector(package_name, "standard")

def create_aggressive_drozer(package_name: str) -> PersistentDrozerConnector:
    """Create drozer with aggressive reconnection"""
    manager = DrozerConfigManager()
    return manager.create_drozer_connector(package_name, "aggressive")

def create_ultra_persistent_drozer(package_name: str) -> PersistentDrozerConnector:
    """Create drozer that reconnects before every command"""
    manager = DrozerConfigManager()
    return manager.create_drozer_connector(package_name, "ultra_persistent")

def create_custom_drozer(package_name: str, **kwargs) -> PersistentDrozerConnector:
    """Create drozer with custom configuration"""
    manager = DrozerConfigManager()
    config = manager.create_custom_config(**kwargs)
    return manager.create_drozer_connector(package_name, custom_config=config) 
 
 
 
 