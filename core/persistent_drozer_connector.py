#!/usr/bin/env python3
"""
Persistent Drozer Connector with User-Configurable Connection Commands
Aggressively reconnects on every failure and supports custom setup procedures
"""

import time
import subprocess
import threading
import logging
import json
import os
from typing import Dict, Tuple, List, Optional, Callable
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class ConnectionConfig:
    """Configuration for Drozer connection setup"""
    # Basic connection settings
    device_id: Optional[str] = None
    drozer_port: int = 31415
    adb_port: int = 5037
    connection_timeout: int = 30
    command_timeout: int = 60
    
    # Aggressive reconnection settings
    max_reconnection_attempts: int = 5
    reconnection_delay: float = 2.0
    persistent_mode: bool = True
    force_reconnect_every_command: bool = False
    
    # User-configurable connection commands
    pre_connection_commands: List[str] = field(default_factory=list)
    post_connection_commands: List[str] = field(default_factory=list)
    custom_adb_setup: List[str] = field(default_factory=list)
    custom_drozer_start: List[str] = field(default_factory=list)
    connection_test_command: str = "list"
    
    # Advanced options
    auto_install_drozer_agent: bool = False
    drozer_agent_apk_path: Optional[str] = None
    restart_adb_on_failure: bool = True
    kill_existing_drozer: bool = True
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ConnectionConfig':
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            return cls(**data)
        except Exception as e:
            logging.warning(f"Could not load config from {config_path}: {e}")
            return cls()
    
    def save_to_file(self, config_path: str):
        """Save configuration to JSON file"""
        try:
            data = self.__dict__.copy()
            # Convert Path objects to strings
            for key, value in data.items():
                if isinstance(value, Path):
                    data[key] = str(value)
            
            with open(config_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.warning(f"Could not save config to {config_path}: {e}")

class PersistentDrozerConnector:
    """
    Persistent Drozer connector with aggressive reconnection and user customization.
    
    Features:
    - Reconnects on every command failure
    - User-configurable connection procedures
    - Custom ADB and Drozer setup commands
    - Persistent retry mechanisms
    - Comprehensive status reporting
    - Connection health monitoring
    """
    
    def __init__(self, package_name: str, config: Optional[ConnectionConfig] = None):
        self.package_name = package_name
        self.config = config or ConnectionConfig()
        self.logger = logging.getLogger(f"persistent_drozer_{package_name}")
        
        # Connection state
        self.connected = False
        self.connection_lock = threading.Lock()
        self.last_connection_attempt = 0
        self.consecutive_failures = 0
        self.total_reconnections = 0
        self.successful_commands = 0
        self.failed_commands = 0
        
        # Device and session info
        self.device_id = None
        self.drozer_session_id = None
        self.connection_start_time = 0
        
        self.logger.info(f"🔄 Persistent Drozer Connector initialized for {package_name}")
        self.logger.info(f"   Persistent Mode: {self.config.persistent_mode}")
        self.logger.info(f"   Max Reconnection Attempts: {self.config.max_reconnection_attempts}")
    
    def set_custom_commands(self, pre_commands: List[str] = None, 
                          post_commands: List[str] = None,
                          adb_setup: List[str] = None,
                          drozer_start: List[str] = None):
        """Set custom connection commands"""
        if pre_commands:
            self.config.pre_connection_commands = pre_commands
        if post_commands:
            self.config.post_connection_commands = post_commands
        if adb_setup:
            self.config.custom_adb_setup = adb_setup
        if drozer_start:
            self.config.custom_drozer_start = drozer_start
        
        self.logger.info("📝 Custom connection commands updated")
    
    def start_connection(self) -> bool:
        """Start initial connection with aggressive setup"""
        with self.connection_lock:
            return self._establish_persistent_connection()
    
    def _establish_persistent_connection(self) -> bool:
        """Establish connection with full setup procedure"""
        self.logger.info("🔄 Starting persistent connection establishment...")
        
        try:
            # Step 1: Pre-connection setup
            if not self._run_pre_connection_setup():
                return False
            
            # Step 2: Device detection and selection
            if not self._detect_and_select_device():
                return False
            
            # Step 3: ADB setup (custom or default)
            if not self._setup_adb_connection():
                return False
            
            # Step 4: Drozer agent setup
            if not self._setup_drozer_agent():
                return False
            
            # Step 5: Drozer connection
            if not self._establish_drozer_connection():
                return False
            
            # Step 6: Post-connection validation
            if not self._run_post_connection_setup():
                return False
            
            # Success
            self.connected = True
            self.connection_start_time = time.time()
            self.consecutive_failures = 0
            self.logger.info("✅ Persistent connection established successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Connection establishment failed: {e}")
            return False
    
    def _run_pre_connection_setup(self) -> bool:
        """Run user-defined pre-connection commands"""
        if not self.config.pre_connection_commands:
            return True
        
        self.logger.info("🔧 Running pre-connection setup commands...")
        
        for cmd in self.config.pre_connection_commands:
            try:
                self.logger.debug(f"   Executing: {cmd}")
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, 
                    text=True, timeout=45
                )
                
                if result.returncode != 0:
                    self.logger.warning(f"   Pre-connection command failed: {cmd}")
                    self.logger.debug(f"   Error: {result.stderr}")
                else:
                    self.logger.debug(f"   Success: {cmd}")
                    
            except Exception as e:
                self.logger.warning(f"   Pre-connection command error: {e}")
        
        return True
    
    def _detect_and_select_device(self) -> bool:
        """Detect and select target device"""
        try:
            # Get available devices
            result = subprocess.run(
                ["adb", "devices"], capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error("❌ ADB not available or failed")
                return False
            
            # Parse device list
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            devices = []
            
            for line in lines:
                if line.strip() and 'device' in line:
                    device_id = line.split()[0]
                    devices.append(device_id)
            
            if not devices:
                self.logger.error("📱 No devices detected")
                return False
            
            # Select device
            if self.config.device_id and self.config.device_id in devices:
                self.device_id = self.config.device_id
            else:
                self.device_id = devices[0]  # Use first available
            
            self.logger.info(f"📱 Selected device: {self.device_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Device detection failed: {e}")
            return False
    
    def _setup_adb_connection(self) -> bool:
        """Setup ADB connection (custom or default)"""
        try:
            # Custom ADB setup if provided
            if self.config.custom_adb_setup:
                self.logger.info("🔧 Running custom ADB setup...")
                
                for cmd in self.config.custom_adb_setup:
                    cmd_with_device = cmd.replace("{device_id}", self.device_id or "")
                    cmd_with_device = cmd_with_device.replace("{port}", str(self.config.drozer_port))
                    
                    result = subprocess.run(
                        cmd_with_device, shell=True, capture_output=True, 
                        text=True, timeout=45
                    )
                    
                    if result.returncode != 0:
                        self.logger.warning(f"Custom ADB command failed: {cmd_with_device}")
                    else:
                        self.logger.debug(f"Custom ADB success: {cmd_with_device}")
                
                return True
            
            # Default ADB setup
            self.logger.info("🔧 Setting up default ADB port forwarding...")
            
            # Clear existing forwards
            subprocess.run(
                ["adb"] + (["-s", self.device_id] if self.device_id else []) + 
                ["forward", "--remove", f"tcp:{self.config.drozer_port}"],
                capture_output=True, timeout=10
            )
            
            time.sleep(1)
            
            # Setup new forwarding
            result = subprocess.run(
                ["adb"] + (["-s", self.device_id] if self.device_id else []) + 
                ["forward", f"tcp:{self.config.drozer_port}", f"tcp:{self.config.drozer_port}"],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                self.logger.info(f"✅ ADB port forwarding established: {self.config.drozer_port}")
                return True
            else:
                self.logger.error(f"❌ ADB port forwarding failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ ADB setup failed: {e}")
            return False
    
    def _setup_drozer_agent(self) -> bool:
        """Setup Drozer agent on device"""
        try:
            # Auto-install Drozer agent if configured
            if self.config.auto_install_drozer_agent and self.config.drozer_agent_apk_path:
                self.logger.info("📱 Installing Drozer agent...")
                
                install_result = subprocess.run(
                    ["adb"] + (["-s", self.device_id] if self.device_id else []) + 
                    ["install", "-r", self.config.drozer_agent_apk_path],
                    capture_output=True, text=True, timeout=60
                )
                
                if install_result.returncode == 0:
                    self.logger.info("✅ Drozer agent installed")
                else:
                    self.logger.warning("⚠️ Drozer agent installation failed")
            
            # Start Drozer agent
            self.logger.info("🚀 Starting Drozer agent...")
            
            start_result = subprocess.run(
                ["adb"] + (["-s", self.device_id] if self.device_id else []) + 
                ["shell", "am", "start", "-n", "com.mwr.dz/.activities.MainActivity"],
                capture_output=True, text=True, timeout=45
            )
            
            if start_result.returncode == 0:
                self.logger.info("✅ Drozer agent started")
            else:
                self.logger.warning("⚠️ Drozer agent start may have failed")
            
            # Brief wait for agent to initialize
            time.sleep(3)
            return True
            
        except Exception as e:
            self.logger.warning(f"⚠️ Drozer agent setup warning: {e}")
            return True  # Continue even if agent setup fails
    
    def _establish_drozer_connection(self) -> bool:
        """Establish Drozer console connection"""
        try:
            # Custom Drozer start commands if provided
            if self.config.custom_drozer_start:
                self.logger.info("🔧 Running custom Drozer connection...")
                
                for cmd in self.config.custom_drozer_start:
                    cmd_with_vars = cmd.replace("{port}", str(self.config.drozer_port))
                    cmd_with_vars = cmd_with_vars.replace("{package}", self.package_name)
                    
                    result = subprocess.run(
                        cmd_with_vars, shell=True, capture_output=True,
                        text=True, timeout=45
                    )
                    
                    if result.returncode == 0:
                        self.logger.info("✅ Custom Drozer connection successful")
                        return True
                    else:
                        self.logger.warning(f"Custom Drozer command failed: {cmd_with_vars}")
                
                return False
            
            # Default Drozer connection test
            self.logger.info("🔌 Testing Drozer connection...")
            
            test_result = subprocess.run(
                ["drozer", "console", "connect", "--command", self.config.connection_test_command],
                capture_output=True, text=True, timeout=self.config.connection_timeout
            )
            
            if test_result.returncode == 0:
                self.logger.info("✅ Drozer connection test successful")
                return True
            else:
                self.logger.error(f"❌ Drozer connection test failed: {test_result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Drozer connection failed: {e}")
            return False
    
    def _run_post_connection_setup(self) -> bool:
        """Run user-defined post-connection commands"""
        if not self.config.post_connection_commands:
            return True
        
        self.logger.info("🔧 Running post-connection setup commands...")
        
        for cmd in self.config.post_connection_commands:
            try:
                cmd_with_vars = cmd.replace("{package}", self.package_name)
                cmd_with_vars = cmd_with_vars.replace("{device_id}", self.device_id or "")
                
                result = subprocess.run(
                    cmd_with_vars, shell=True, capture_output=True,
                    text=True, timeout=45
                )
                
                if result.returncode != 0:
                    self.logger.warning(f"   Post-connection command failed: {cmd_with_vars}")
                else:
                    self.logger.debug(f"   Post-connection success: {cmd_with_vars}")
                    
            except Exception as e:
                self.logger.warning(f"   Post-connection command error: {e}")
        
        return True
    
    def run_command_with_persistent_reconnection(self, command: str, timeout: int = None) -> Tuple[bool, str]:
        """
        Execute command with aggressive reconnection on failure.
        Reconnects before every command if configured.
        """
        timeout = timeout or self.config.command_timeout
        
        # Force reconnection if configured
        if self.config.force_reconnect_every_command:
            self.logger.debug("🔄 Force reconnecting before command...")
            if not self._establish_persistent_connection():
                return False, "Failed to establish connection before command"
        
        # Execute command with reconnection on failure
        for attempt in range(self.config.max_reconnection_attempts + 1):
            try:
                if not self.connected and attempt > 0:
                    self.logger.info(f"🔄 Reconnection attempt {attempt}/{self.config.max_reconnection_attempts}")
                    
                    if not self._establish_persistent_connection():
                        self.logger.warning(f"   Reconnection attempt {attempt} failed")
                        if attempt < self.config.max_reconnection_attempts:
                            time.sleep(self.config.reconnection_delay * attempt)  # Exponential backoff
                            continue
                        else:
                            return False, f"Failed to reconnect after {self.config.max_reconnection_attempts} attempts"
                
                # Execute the command
                self.logger.debug(f"📤 Executing: {command[:50]}...")
                
                drozer_cmd = f"drozer console connect --command '{command}'"
                result = subprocess.run(
                    drozer_cmd, shell=True, capture_output=True,
                    text=True, timeout=timeout
                )
                
                if result.returncode == 0:
                    self.successful_commands += 1
                    self.consecutive_failures = 0
                    return True, result.stdout.strip()
                else:
                    # Command failed - mark as disconnected for next attempt
                    self.connected = False
                    self.failed_commands += 1
                    self.consecutive_failures += 1
                    
                    error_msg = result.stderr.strip() or "Command execution failed"
                    self.logger.warning(f"   Command failed: {error_msg}")
                    
                    if attempt < self.config.max_reconnection_attempts:
                        self.logger.info("🔄 Will attempt reconnection...")
                        time.sleep(self.config.reconnection_delay)
                        continue
                    else:
                        return False, error_msg
                
            except subprocess.TimeoutExpired:
                self.connected = False
                self.failed_commands += 1
                self.consecutive_failures += 1
                
                error_msg = f"Command timed out after {timeout}s"
                self.logger.warning(f"   {error_msg}")
                
                if attempt < self.config.max_reconnection_attempts:
                    time.sleep(self.config.reconnection_delay)
                    continue
                else:
                    return False, error_msg
                    
            except Exception as e:
                self.connected = False
                self.failed_commands += 1
                self.consecutive_failures += 1
                
                error_msg = f"Command execution error: {str(e)}"
                self.logger.warning(f"   {error_msg}")
                
                if attempt < self.config.max_reconnection_attempts:
                    time.sleep(self.config.reconnection_delay)
                    continue
                else:
                    return False, error_msg
        
        return False, "Maximum reconnection attempts exceeded"
    
    def run_command(self, command: str, timeout: int = None) -> Tuple[bool, str]:
        """Legacy compatibility method"""
        return self.run_command_with_persistent_reconnection(command, timeout)
    
    def run_command_safe(self, command: str, fallback: str = "Analysis unavailable - connection issue") -> str:
        """Safe command execution with fallback"""
        success, result = self.run_command_with_persistent_reconnection(command)
        return result if success else fallback
    
    def check_connection(self) -> bool:
        """Check if connection is active"""
        if not self.connected:
            return False
        
        # Quick connection test
        try:
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True, timeout=5
            )
            
            if result.returncode == 0:
                return True
            else:
                self.connected = False
                return False
                
        except:
            self.connected = False
            return False
    
    def force_reconnection(self) -> bool:
        """Force immediate reconnection"""
        self.logger.info("🔄 Forcing reconnection...")
        self.connected = False
        return self._establish_persistent_connection()
    
    def restart_adb_server(self) -> bool:
        """Restart ADB server (nuclear option)"""
        if not self.config.restart_adb_on_failure:
            return False
        
        self.logger.info("🔄 Restarting ADB server...")
        
        try:
            # Kill ADB server
            subprocess.run(["adb", "kill-server"], capture_output=True, timeout=10)
            time.sleep(2)
            
            # Start ADB server
            result = subprocess.run(["adb", "start-server"], capture_output=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info("✅ ADB server restarted")
                time.sleep(3)  # Wait for stabilization
                return True
            else:
                self.logger.error("❌ ADB server restart failed")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ ADB restart error: {e}")
            return False
    
    def get_connection_status(self) -> Dict:
        """Get comprehensive connection status"""
        uptime = 0
        if self.connected and self.connection_start_time > 0:
            uptime = time.time() - self.connection_start_time
        
        success_rate = 0
        total_commands = self.successful_commands + self.failed_commands
        if total_commands > 0:
            success_rate = (self.successful_commands / total_commands) * 100
        
        return {
            "connected": self.connected,
            "device_id": self.device_id,
            "uptime": uptime,
            "total_reconnections": self.total_reconnections,
            "consecutive_failures": self.consecutive_failures,
            "successful_commands": self.successful_commands,
            "failed_commands": self.failed_commands,
            "success_rate": success_rate,
            "persistent_mode": self.config.persistent_mode,
            "max_reconnection_attempts": self.config.max_reconnection_attempts,
            "force_reconnect_every_command": self.config.force_reconnect_every_command
        }
    
    def get_diagnostic_report(self) -> str:
        """Get detailed diagnostic report"""
        status = self.get_connection_status()
        
        return f"""
🔄 Persistent Drozer Connector Status - {self.package_name}
===========================================================
Connection: {'🟢 Active' if status['connected'] else '🔴 Inactive'}
Device: {status['device_id'] or 'Not selected'}
Uptime: {status['uptime']:.1f}s
Total Reconnections: {status['total_reconnections']}

📊 Command Statistics:
  Success Rate: {status['success_rate']:.1f}%
  Successful Commands: {status['successful_commands']}
  Failed Commands: {status['failed_commands']}
  Consecutive Failures: {status['consecutive_failures']}

⚙️ Configuration:
  Persistent Mode: {'✅' if status['persistent_mode'] else '❌'}
  Max Reconnection Attempts: {status['max_reconnection_attempts']}
  Force Reconnect Every Command: {'✅' if status['force_reconnect_every_command'] else '❌'}
  Custom Pre-Commands: {len(self.config.pre_connection_commands)}
  Custom Post-Commands: {len(self.config.post_connection_commands)}
  Custom ADB Setup: {len(self.config.custom_adb_setup)}
  Custom Drozer Start: {len(self.config.custom_drozer_start)}
"""
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            if self.device_id:
                subprocess.run(
                    ["adb"] + (["-s", self.device_id] if self.device_id else []) + 
                    ["forward", "--remove", f"tcp:{self.config.drozer_port}"],
                    capture_output=True, timeout=5
                )
            
            self.connected = False
            self.logger.info("🧹 Persistent connector cleanup completed")
            
        except Exception as e:
            self.logger.debug(f"Cleanup warning: {e}")

# Factory functions for common configurations
def create_aggressive_reconnection_drozer(package_name: str) -> PersistentDrozerConnector:
    """Create drozer connector with aggressive reconnection"""
    config = ConnectionConfig(
        persistent_mode=True,
        max_reconnection_attempts=5,
        reconnection_delay=1.0,
        force_reconnect_every_command=False,
        restart_adb_on_failure=True
    )
    return PersistentDrozerConnector(package_name, config)

def create_ultra_persistent_drozer(package_name: str) -> PersistentDrozerConnector:
    """Create drozer connector that reconnects before every command"""
    config = ConnectionConfig(
        persistent_mode=True,
        max_reconnection_attempts=3,
        reconnection_delay=0.5,
        force_reconnect_every_command=True,
        restart_adb_on_failure=True
    )
    return PersistentDrozerConnector(package_name, config)

def create_custom_drozer_connector(package_name: str, 
                                 pre_commands: List[str] = None,
                                 adb_setup: List[str] = None,
                                 drozer_start: List[str] = None) -> PersistentDrozerConnector:
    """Create drozer connector with custom commands"""
    config = ConnectionConfig(
        persistent_mode=True,
        max_reconnection_attempts=3,
        pre_connection_commands=pre_commands or [],
        custom_adb_setup=adb_setup or [],
        custom_drozer_start=drozer_start or []
    )
    return PersistentDrozerConnector(package_name, config) 
 
 
 
 