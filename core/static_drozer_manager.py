#!/usr/bin/env python3
"""
Static-Only Drozer Manager for AODS

This module provides a static-only drozer manager that bypasses device connectivity
requirements and allows the security analysis to continue without dynamic testing.
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class StaticConnectionConfig:
    """Configuration for static-only analysis"""
    enable_static_fallback: bool = True
    log_dynamic_attempts: bool = True

class StaticDrozerManager:
    """
    Static-only drozer manager that provides fallback functionality
    when no Android device/emulator is available.
    """
    
    def __init__(self, package_name: str, config: Optional[StaticConnectionConfig] = None):
        """
        Initialize static drozer manager.
        
        Args:
            package_name: Android package name for analysis
            config: Static analysis configuration
        """
        self.package_name = package_name
        self.config = config or StaticConnectionConfig()
        self.logger = logging.getLogger(f"static_drozer_{package_name}")
        
        # Set up logging
        self._setup_logging()
        
        # Initialize static mode
        self.logger.info("📱 Initializing Static-Only Drozer Manager")
        self.logger.info("✅ Static analysis mode enabled - no device connection required")
        
    def _setup_logging(self) -> None:
        """Setup logging for static drozer operations"""
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def start_connection(self) -> bool:
        """
        Start connection (always returns True for static mode).
        
        Returns:
            bool: Always True for static analysis
        """
        self.logger.info("✅ Static-only mode - no device connection required")
        return True
    
    def start_drozer(self) -> bool:
        """Start drozer (static mode compatibility)"""
        return self.start_connection()
    
    def check_connection(self) -> bool:
        """Check connection status (always True for static mode)"""
        return True
    
    def execute_command(self, command: str, timeout_override: Optional[int] = None) -> Tuple[bool, str]:
        """
        Execute drozer command with static fallback.
        
        Args:
            command: Drozer command to execute
            timeout_override: Ignored in static mode
            
        Returns:
            Tuple[bool, str]: (False, fallback_message) for static mode
        """
        if self.config.log_dynamic_attempts:
            self.logger.debug(f"📱 Static mode: Dynamic command '{command}' not available")
        
        fallback_msg = f"Static analysis mode: Dynamic command '{command}' requires device connection"
        return False, fallback_msg
    
    def execute_command_safe(self, command: str, fallback_message: Optional[str] = None) -> str:
        """
        Execute drozer command safely with fallback.
        
        Args:
            command: Drozer command to execute
            fallback_message: Custom fallback message
            
        Returns:
            str: Fallback message for static mode
        """
        if fallback_message:
            return fallback_message
        else:
            return f"Static analysis mode: Dynamic analysis not available for '{command}'"
    
    def run_command(self, command: str, timeout_override: Optional[int] = None) -> Tuple[bool, str]:
        """Execute command (compatibility alias)"""
        return self.execute_command(command, timeout_override)
    
    def run_command_safe(self, command: str, fallback_message: Optional[str] = None) -> str:
        """Execute command safely (compatibility alias)"""
        return self.execute_command_safe(command, fallback_message)
    
    def get_connection_status(self) -> Dict:
        """
        Get connection status for static mode.
        
        Returns:
            Dict: Static mode connection status
        """
        return {
            "state": "static_only",
            "static_only_mode": True,
            "package_name": self.package_name,
            "connected": False,
            "dynamic_analysis_available": False,
            "last_successful_connection": None,
            "consecutive_failures": 0,
            "device_capabilities": {"mode": "static_only"},
            "error_count": 0,
            "last_error": None
        }
    
    def get_diagnostic_report(self) -> str:
        """
        Generate diagnostic report for static mode.
        
        Returns:
            str: Static mode diagnostic report
        """
        return f"""
Static Drozer Manager Diagnostic Report
======================================
Package: {self.package_name}
Mode: Static Analysis Only
Dynamic Analysis: Not Available
Device Connection: Not Required

Configuration:
  Static Fallback: {self.config.enable_static_fallback}
  Log Dynamic Attempts: {self.config.log_dynamic_attempts}

Status: ✅ Ready for static analysis
Note: Dynamic drozer commands will return fallback messages
"""
    
    def cleanup(self) -> None:
        """Clean up resources (no-op for static mode)"""
        self.logger.info("🧹 Static mode cleanup complete")
    
    def stop_connection(self) -> bool:
        """Stop connection (always successful for static mode)"""
        return True
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()

def create_static_drozer_manager(package_name: str) -> StaticDrozerManager:
    """
    Factory function to create a static drozer manager.
    
    Args:
        package_name: Android package name
        
    Returns:
        StaticDrozerManager: Static drozer manager instance
    """
    return StaticDrozerManager(package_name)

class DrozerHelper(StaticDrozerManager):
    """Compatibility class for existing code"""
    
    def __init__(self, package_name: str, max_retries: int = 3, 
                 command_timeout: int = 90, connection_timeout: int = 45):
        """Initialize with compatibility parameters (ignored in static mode)"""
        super().__init__(package_name) 