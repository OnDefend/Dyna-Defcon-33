#!/usr/bin/env python3
"""
Enhanced Anti-Spam Drozer Wrapper with Robust Security
Integrates with RobustConnectionFramework to eliminate misconfigurations
"""

import json
import logging
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from core.robust_connection_framework import (
    RobustConnectionManager, 
    SecurityPolicy, 
    SecurityLevel,
    ConfigurationError,
    SecurityViolationError,
    create_standard_security_manager,
    create_enterprise_security_manager
)

class EnhancedAntiSpamDrozerWrapper:
    """
    Enhanced Drozer wrapper with comprehensive security and anti-misconfiguration features
    """
    
    def __init__(self, package_name: str, security_level: str = "standard"):
        self.package_name = package_name
        self.logger = logging.getLogger(f"{__name__}.wrapper")
        
        # Initialize robust connection manager based on security level
        if security_level.lower() == "enterprise":
            self.connection_manager = create_enterprise_security_manager(package_name)
        else:
            self.connection_manager = create_standard_security_manager(package_name)
        
        # Anti-spam protection
        self.command_history = []
        self.last_command_time = 0
        self.rate_limit_window = 1.0  # seconds
        self.max_commands_per_window = 5
        self.duplicate_command_threshold = 3
        
        # Configuration validation cache
        self.validated_configs = {}
        self.config_validation_lock = threading.Lock()
        
        # Connection state tracking
        self.connection_established = False
        self.last_successful_command = 0
        self.failed_command_streak = 0
        self.max_failed_streak = 5
        
        self.logger.info(f"Enhanced Anti-Spam Drozer Wrapper initialized")
        self.logger.info(f"   Security Level: {security_level.upper()}")
    
    def configure_secure_connection(self, config: Dict[str, Any]) -> bool:
        """
        Configure connection with enhanced validation and anti-misconfiguration checks
        """
        try:
            # Generate configuration hash for caching
            config_hash = self._generate_config_hash(config)
            
            with self.config_validation_lock:
                # Check if we've already validated this configuration
                if config_hash in self.validated_configs:
                    cached_result = self.validated_configs[config_hash]
                    if cached_result["is_valid"]:
                        self.logger.info("Using cached validated configuration")
                        return self.connection_manager.configure_connection(cached_result["config"])
                    else:
                        self.logger.error("Configuration previously failed validation")
                        return False
                
                # Apply enhanced configuration defaults for security
                enhanced_config = self._apply_security_defaults(config)
                
                # Validate configuration with robust framework
                success = self.connection_manager.configure_connection(enhanced_config)
                
                # Cache validation result
                self.validated_configs[config_hash] = {
                    "is_valid": success,
                    "config": enhanced_config,
                    "timestamp": time.time()
                }
                
                # Clean old cache entries
                self._cleanup_config_cache()
                
                if success:
                    self.logger.info("Secure connection configured successfully")
                else:
                    self.logger.error("Configuration validation failed")
                
                return success
                
        except Exception as e:
            self.logger.error(f"Configuration error: {e}")
            return False
    
    def establish_secure_connection(self) -> bool:
        """
        Establish connection with enhanced security and validation
        """
        try:
            self.logger.info("Establishing enhanced secure connection...")
            
            # Pre-connection validation
            if not self._pre_connection_checks():
                return False
            
            # Attempt connection with robust framework
            success = self.connection_manager.establish_connection()
            
            if success:
                self.connection_established = True
                self.failed_command_streak = 0
                self.logger.info("Secure connection established")
                
                # Log security status
                status = self.connection_manager.get_security_status()
                self.logger.info(f"   Security Score: {status['security_score']:.1f}/100")
                self.logger.info(f"   Connection Attempts: {status['connection_attempts']}")
                
            else:
                self.connection_established = False
                self.logger.error("Failed to establish secure connection")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Connection establishment failed: {e}")
            self.connection_established = False
            return False
    
    def execute_command_with_protection(self, command: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """
        Execute command with comprehensive protection against spam and security issues
        """
        if not self.connection_established:
            return False, "No secure connection available"
        
        try:
            # Anti-spam protection
            if not self._check_rate_limit():
                return False, "Rate limit exceeded - too many commands"
            
            if not self._check_duplicate_command(command):
                return False, "Duplicate command detected - potential spam"
            
            # Command validation and sanitization
            sanitized_command = self._sanitize_command(command)
            if not sanitized_command:
                return False, "Command failed security validation"
            
            # Execute with robust framework
            self.logger.debug(f"Executing protected command: {sanitized_command[:50]}...")
            
            success, result = self.connection_manager.execute_command_secure(
                sanitized_command, timeout
            )
            
            # Update tracking
            if success:
                self.last_successful_command = time.time()
                self.failed_command_streak = 0
            else:
                self.failed_command_streak += 1
                
                # Check if too many failures
                if self.failed_command_streak >= self.max_failed_streak:
                    self.logger.warning(f"Too many failed commands ({self.failed_command_streak}), resetting connection")
                    self._reset_connection()
            
            # Record command for anti-spam tracking
            self._record_command(command, success)
            
            return success, result
            
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            self.failed_command_streak += 1
            return False, f"Command execution error: {str(e)}"
    
    def run_command_safe(self, command: str, fallback: str = "Analysis unavailable - connection issue") -> str:
        """
        Safe command execution with fallback for continued analysis
        """
        success, result = self.execute_command_with_protection(command)
        return result if success else fallback
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """
        Get comprehensive status including security metrics and anti-spam statistics
        """
        base_status = self.connection_manager.get_security_status()
        
        # Add anti-spam metrics
        base_status.update({
            "connection_established": self.connection_established,
            "last_successful_command": self.last_successful_command,
            "failed_command_streak": self.failed_command_streak,
            "total_commands_executed": len(self.command_history),
            "command_rate_per_minute": self._calculate_command_rate(),
            "duplicate_commands_blocked": self._count_blocked_duplicates(),
            "rate_limit_violations": self._count_rate_limit_violations(),
            "config_cache_size": len(self.validated_configs),
            "package_name": self.package_name
        })
        
        return base_status
    
    def cleanup_secure(self):
        """
        Secure cleanup with comprehensive resource management
        """
        try:
            self.logger.info("Starting secure cleanup...")
            
            # Clear sensitive data
            self.command_history.clear()
            self.validated_configs.clear()
            
            # Reset state
            self.connection_established = False
            self.last_successful_command = 0
            self.failed_command_streak = 0
            
            # Cleanup robust connection manager
            self.connection_manager.cleanup()
            
            self.logger.info("Secure cleanup completed")
            
        except Exception as e:
            self.logger.debug(f"Cleanup warning: {e}")
    
    def _apply_security_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply security defaults to prevent common misconfigurations
        """
        enhanced_config = config.copy()
        
        # Ensure security settings section exists
        if "security_settings" not in enhanced_config:
            enhanced_config["security_settings"] = {}
        
        # Apply secure defaults
        security_defaults = {
            "enable_command_validation": True,
            "enable_path_validation": True,
            "enable_network_validation": True,
            "log_commands": True,
            "log_security_events": True
        }
        
        for key, default_value in security_defaults.items():
            if key not in enhanced_config["security_settings"]:
                enhanced_config["security_settings"][key] = default_value
        
        # Ensure connection settings have safe defaults
        if "connection_settings" not in enhanced_config:
            enhanced_config["connection_settings"] = {}
        
        connection_defaults = {
            "drozer_port": 31415,
            "connection_timeout": 30,
            "command_timeout": 30
        }
        
        for key, default_value in connection_defaults.items():
            if key not in enhanced_config["connection_settings"]:
                enhanced_config["connection_settings"][key] = default_value
        
        # Ensure reconnection strategy has safe defaults
        if "reconnection_strategy" not in enhanced_config:
            enhanced_config["reconnection_strategy"] = {}
        
        reconnection_defaults = {
            "max_reconnection_attempts": 3,
            "reconnection_delay": 2.0,
            "persistent_mode": True,
            "force_reconnect_every_command": False
        }
        
        for key, default_value in reconnection_defaults.items():
            if key not in enhanced_config["reconnection_strategy"]:
                enhanced_config["reconnection_strategy"][key] = default_value
        
        return enhanced_config
    
    def _generate_config_hash(self, config: Dict[str, Any]) -> str:
        """
        Generate hash for configuration caching
        """
        import hashlib
        config_str = json.dumps(config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]
    
    def _cleanup_config_cache(self):
        """
        Clean up old configuration cache entries
        """
        current_time = time.time()
        cache_ttl = 3600  # 1 hour
        
        expired_keys = [
            key for key, value in self.validated_configs.items()
            if current_time - value["timestamp"] > cache_ttl
        ]
        
        for key in expired_keys:
            del self.validated_configs[key]
    
    def _pre_connection_checks(self) -> bool:
        """
        Perform pre-connection security and validation checks
        """
        # Check if configuration is present
        if not hasattr(self.connection_manager, 'configuration') or not self.connection_manager.configuration:
            self.logger.error("No validated configuration available")
            return False
        
        # Check security score threshold
        security_status = self.connection_manager.get_security_status()
        min_security_score = 50.0  # Minimum acceptable security score
        
        if security_status["security_score"] < min_security_score:
            self.logger.warning(f"Low security score: {security_status['security_score']:.1f}")
            self.logger.warning("   Connection will proceed but security may be compromised")
        
        return True
    
    def _check_rate_limit(self) -> bool:
        """
        Check if command execution is within rate limits
        """
        current_time = time.time()
        
        # Check time-based rate limit
        if current_time - self.last_command_time < (1.0 / self.max_commands_per_window):
            return False
        
        self.last_command_time = current_time
        return True
    
    def _check_duplicate_command(self, command: str) -> bool:
        """
        Check for duplicate commands that might indicate spam
        """
        # Count recent identical commands
        recent_time = time.time() - 60  # Last minute
        recent_identical = [
            entry for entry in self.command_history
            if entry["timestamp"] >= recent_time and entry["command"] == command
        ]
        
        return len(recent_identical) < self.duplicate_command_threshold
    
    def _sanitize_command(self, command: str) -> Optional[str]:
        """
        Sanitize command for additional security
        """
        if not command or not isinstance(command, str):
            return None
        
        # Basic sanitization
        sanitized = command.strip()
        
        # Remove potential injection attempts
        dangerous_chars = [';', '&', '|', '`', '$']
        for char in dangerous_chars:
            if char in sanitized:
                self.logger.warning(f"Potentially dangerous character '{char}' in command")
                return None
        
        # Length check
        if len(sanitized) > 500:
            self.logger.warning("Command too long")
            return None
        
        return sanitized
    
    def _record_command(self, command: str, success: bool):
        """
        Record command execution for anti-spam tracking
        """
        entry = {
            "timestamp": time.time(),
            "command": command[:100],  # Truncate for security
            "success": success
        }
        
        self.command_history.append(entry)
        
        # Keep history size manageable
        if len(self.command_history) > 1000:
            self.command_history = self.command_history[-500:]
    
    def _reset_connection(self):
        """
        Reset connection due to too many failures
        """
        try:
            self.logger.info("Resetting connection due to failures...")
            
            # Cleanup current connection
            self.connection_manager.cleanup()
            
            # Reset state
            self.connection_established = False
            self.failed_command_streak = 0
            
            # Attempt to re-establish connection
            success = self.connection_manager.establish_connection()
            
            if success:
                self.connection_established = True
                self.logger.info("Connection reset successful")
            else:
                self.logger.error("Connection reset failed")
            
        except Exception as e:
            self.logger.error(f"Connection reset error: {e}")
    
    def _calculate_command_rate(self) -> float:
        """
        Calculate command execution rate per minute
        """
        if not self.command_history:
            return 0.0
        
        recent_time = time.time() - 60  # Last minute
        recent_commands = [
            entry for entry in self.command_history
            if entry["timestamp"] >= recent_time
        ]
        
        return len(recent_commands)
    
    def _count_blocked_duplicates(self) -> int:
        """
        Count how many duplicate commands were blocked
        """
        # This would be tracked in practice - for now return estimate
        total_commands = len(self.command_history)
        unique_commands = len(set(entry["command"] for entry in self.command_history))
        return max(0, total_commands - unique_commands)
    
    def _count_rate_limit_violations(self) -> int:
        """
        Count rate limit violations (estimated)
        """
        # This would be tracked in practice - simplified for now
        return max(0, len(self.command_history) - (self.max_commands_per_window * 60))

# Factory functions for different use cases
def create_development_drozer_wrapper(package_name: str) -> EnhancedAntiSpamDrozerWrapper:
    """
    Create Drozer wrapper for development with relaxed security
    """
    return EnhancedAntiSpamDrozerWrapper(package_name, security_level="standard")

def create_production_drozer_wrapper(package_name: str) -> EnhancedAntiSpamDrozerWrapper:
    """
    Create Drozer wrapper for production with maximum security
    """
    return EnhancedAntiSpamDrozerWrapper(package_name, security_level="enterprise")

def create_default_drozer_wrapper(package_name: str) -> EnhancedAntiSpamDrozerWrapper:
    """
    Create Drozer wrapper with balanced security settings
    """
    return EnhancedAntiSpamDrozerWrapper(package_name, security_level="standard") 
 
 
 
 