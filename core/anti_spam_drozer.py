import time
import subprocess
import threading
import logging
from typing import Dict, Tuple, Optional

# Try to import persistent connector for enhanced reconnection
try:
    from .drozer_config_manager import create_aggressive_drozer, DrozerConfigManager
    PERSISTENT_DROZER_AVAILABLE = True
except ImportError:
    PERSISTENT_DROZER_AVAILABLE = False

class AntiSpamDrozerWrapper:
    """
    Enhanced Drozer wrapper with connection recovery and spam prevention.
    
    Features:
    - Prevents connection spam when no devices available
    - Automatic connection recovery on failures
    - Seamless scan continuation
    - Connection health monitoring
    - Optional persistent reconnection support
    """
    
    _last_device_check = 0
    _device_available = None
    _connection_cooldown = 0
    
    def __init__(self, package_name: str, enable_recovery: bool = True, 
                 use_persistent_mode: bool = False, reconnection_preset: str = "aggressive"):
        self.package_name = package_name
        self.connected = False
        self.enable_recovery = enable_recovery
        self.use_persistent_mode = use_persistent_mode and PERSISTENT_DROZER_AVAILABLE
        self.logger = logging.getLogger(f"enhanced_drozer_{package_name}")
        
        # Recovery settings
        self.recovery_attempts = 0
        self.max_recovery_attempts = 2
        self.recovery_delay = 3
        self.last_successful_command = 0
        
        # Connection monitoring
        self.connection_lock = threading.Lock()
        self.total_commands = 0
        self.failed_commands = 0
        
        # Persistent drozer integration
        self._persistent_drozer = None
        if self.use_persistent_mode:
            try:
                if reconnection_preset == "custom":
                    # Allow users to create custom configurations
                    manager = DrozerConfigManager()
                    self._persistent_drozer = manager.create_drozer_connector(package_name, "aggressive")
                else:
                    self._persistent_drozer = create_aggressive_drozer(package_name)
                    
                self.logger.info(f"🔄 Persistent reconnection mode enabled with preset: {reconnection_preset}")
            except Exception as e:
                self.logger.warning(f"Persistent mode failed, falling back to standard: {e}")
                self.use_persistent_mode = False
        
        self.logger.debug(f"Enhanced Drozer wrapper initialized for {package_name}")
        self.logger.debug(f"  Recovery: {enable_recovery}, Persistent: {self.use_persistent_mode}")
    
    @classmethod
    def create_with_persistent_reconnection(cls, package_name: str, preset: str = "aggressive"):
        """Factory method to create wrapper with persistent reconnection"""
        return cls(package_name, enable_recovery=True, use_persistent_mode=True, reconnection_preset=preset)
    
    @classmethod
    def create_ultra_persistent(cls, package_name: str):
        """Factory method for ultra-persistent mode (reconnects before every command)"""
        if PERSISTENT_DROZER_AVAILABLE:
            try:
                from .drozer_config_manager import create_ultra_persistent_drozer
                instance = cls(package_name, enable_recovery=True, use_persistent_mode=False)
                instance._persistent_drozer = create_ultra_persistent_drozer(package_name)
                instance.use_persistent_mode = True
                instance.logger.info("⚡ Ultra-persistent mode enabled - reconnects before every command")
                return instance
            except Exception as e:
                logging.warning(f"Ultra-persistent mode failed: {e}")
        
        return cls(package_name, enable_recovery=True)
    
    @classmethod
    def create_with_custom_commands(cls, package_name: str, 
                                  pre_commands=None, adb_setup=None, 
                                  drozer_start=None, post_commands=None):
        """Factory method to create wrapper with custom connection commands"""
        if PERSISTENT_DROZER_AVAILABLE:
            try:
                from .drozer_config_manager import create_custom_drozer
                instance = cls(package_name, enable_recovery=True, use_persistent_mode=False)
                instance._persistent_drozer = create_custom_drozer(
                    package_name,
                    preset_base="aggressive",
                    pre_commands=pre_commands,
                    adb_setup=adb_setup,
                    drozer_start=drozer_start,
                    post_commands=post_commands
                )
                instance.use_persistent_mode = True
                instance.logger.info("🔧 Custom command mode enabled")
                return instance
            except Exception as e:
                logging.warning(f"Custom command mode failed: {e}")
        
        return cls(package_name, enable_recovery=True)
    
    @classmethod
    def quick_device_check(cls) -> bool:
        """Class-level device check with caching"""
        current_time = time.time()
        
        # Use cached result if recent (30 seconds)
        if current_time - cls._last_device_check < 30:
            return cls._device_available or False
        
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                timeout=3
            )
            
            if result.returncode != 0:
                cls._device_available = False
            else:
                lines = result.stdout.decode().split('\n')[1:]
                cls._device_available = any('device' in line for line in lines if line.strip())
            
            cls._last_device_check = current_time
            return cls._device_available
            
        except:
            cls._device_available = False
            cls._last_device_check = current_time
            return False
    
    def start_connection(self) -> bool:
        """Start connection with spam prevention and recovery setup"""
        if self.use_persistent_mode and self._persistent_drozer:
            # Use persistent connector
            success = self._persistent_drozer.start_connection()
            if success:
                self.connected = True
                self.logger.info(f"✅ Persistent connection established for {self.package_name}")
            return success
        
        # Standard connection logic
        current_time = time.time()
        
        # Respect cooldown period
        if current_time < self._connection_cooldown:
            return False
        
        # Quick device check
        if not self.quick_device_check():
            # Set longer cooldown when no devices
            self._connection_cooldown = current_time + 60  # 1 minute
            return False
        
        # Attempt connection with short timeout
        try:
            # Quick connection attempt
            success = self._attempt_connection()
            
            if success:
                self.connected = True
                self.recovery_attempts = 0
                self.last_successful_command = current_time
                self.logger.info(f"✅ Enhanced connection established for {self.package_name}")
            else:
                # Set shorter cooldown on failure
                self._connection_cooldown = current_time + 10  # 10 seconds
            
            return success
            
        except:
            self._connection_cooldown = current_time + 30  # 30 seconds
            return False
    
    def start_drozer(self) -> bool:
        """Legacy compatibility method for start_connection"""
        return self.start_connection()
    
    def _attempt_connection(self) -> bool:
        """Single quick connection attempt with ADB setup"""
        try:
            # Setup port forwarding with recovery
            if not self._setup_port_forwarding_robust():
                return False
            
            # Test drozer connectivity
            if not self._test_drozer_connectivity():
                return False
            
            return True
            
        except:
            return False
    
    def _setup_port_forwarding_robust(self) -> bool:
        """Robust port forwarding setup with multiple attempts"""
        for attempt in range(2):
            try:
                # Clean existing forwards
                subprocess.run(
                    ["adb", "forward", "--remove", "tcp:31415"],
                    capture_output=True, timeout=3
                )
                
                # Wait briefly for cleanup
                time.sleep(0.5)
                
                # Setup new forwarding
                result = subprocess.run(
                    ["adb", "forward", "tcp:31415", "tcp:31415"],
                    capture_output=True, timeout=5
                )
                
                if result.returncode == 0:
                    return True
                    
                # Brief wait before retry
                if attempt < 1:
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.debug(f"Port forwarding attempt {attempt + 1} failed: {e}")
                if attempt < 1:
                    time.sleep(1)
        
        return False
    
    def _test_drozer_connectivity(self) -> bool:
        """Test basic Drozer connectivity with improved timeout"""
        try:
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True, timeout=15  # Increased from 8 to 15 seconds
            )
            return result.returncode == 0
        except:
            return False
    
    def check_connection(self) -> bool:
        """Check if connection is active"""
        if self.use_persistent_mode and self._persistent_drozer:
            return self._persistent_drozer.check_connection()
        return self.connected
    
    def run_command(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Execute command with automatic recovery on failure"""
        if self.use_persistent_mode and self._persistent_drozer:
            # Use persistent connector with aggressive reconnection
            return self._persistent_drozer.run_command_with_persistent_reconnection(command, timeout)
        
        # Standard execution with recovery
        if not self.connected:
            return False, "No device connection - static analysis mode"
        
        with self.connection_lock:
            self.total_commands += 1
            
            # Try command execution with recovery
            for attempt in range(2):
                try:
                    cmd = f"drozer console connect --command '{command}'"
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, 
                        text=True, timeout=timeout
                    )
                    
                    if result.returncode == 0:
                        self.last_successful_command = time.time()
                        return True, result.stdout.strip()
                    else:
                        # Command failed - attempt recovery if enabled
                        if attempt == 0 and self.enable_recovery:
                            self.logger.debug(f"🔄 Command failed, attempting recovery for: {command[:50]}...")
                            if self._attempt_connection_recovery():
                                continue  # Retry the command
                        
                        # Mark as failed
                        self.failed_commands += 1
                        if attempt == 1:  # Final attempt
                            self.connected = False
                        
                        return False, result.stderr.strip() or "Command failed"
                        
                except subprocess.TimeoutExpired:
                    self.failed_commands += 1
                    if attempt == 0 and self.enable_recovery:
                        self.logger.debug("🔄 Command timeout, attempting recovery...")
                        # For timeout cases, be more aggressive with recovery
                        time.sleep(2)  # Brief pause before recovery
                        if self._attempt_connection_recovery():
                            continue
                    
                    # Don't immediately disconnect on timeout - may be temporary
                    if attempt == 1:
                        # Only disconnect after multiple failures
                        if self.failed_commands >= 3:
                            self.connected = False
                    return False, f"Timeout after {timeout}s"
                    
                except Exception as e:
                    self.failed_commands += 1
                    if attempt == 1:
                        self.connected = False
                    return False, f"Command execution error: {str(e)}"
            
            return False, "Command failed after recovery attempts"
    
    def _attempt_connection_recovery(self) -> bool:
        """Attempt connection recovery during command execution"""
        if self.recovery_attempts >= self.max_recovery_attempts:
            self.logger.debug("Max recovery attempts reached")
            return False
        
        self.recovery_attempts += 1
        self.logger.debug(f"Attempting connection recovery {self.recovery_attempts}/{self.max_recovery_attempts}")
        
        try:
            # Quick device check
            if not self.quick_device_check():
                self.logger.debug("No devices available for recovery")
                return False
            
            # Brief delay for stability
            time.sleep(self.recovery_delay)
            
            # Attempt reconnection
            if self._attempt_connection():
                self.connected = True
                self.logger.info(f"✅ Connection recovered for {self.package_name}")
                return True
            else:
                self.logger.debug("Recovery attempt failed")
                return False
                
        except Exception as e:
            self.logger.debug(f"Recovery error: {e}")
            return False
    
    def run_command_safe(self, command: str, fallback: str = "Analysis unavailable - connection issue") -> str:
        """Safe command execution with fallback"""
        success, result = self.run_command(command)
        return result if success else fallback
    
    def execute_command_safe(self, command: str, fallback_message: Optional[str] = None, timeout: Optional[int] = None) -> str:
        """Legacy compatibility method with timeout support"""
        fallback = fallback_message or "Analysis unavailable - connection issue"
        if timeout is not None:
            success, result = self.run_command(command, timeout)
            return result if success else fallback
        else:
            return self.run_command_safe(command, fallback)
    
    def force_reconnection(self) -> bool:
        """Force immediate reconnection"""
        if self.use_persistent_mode and self._persistent_drozer:
            return self._persistent_drozer.force_reconnection()
        else:
            return self.reset_connection()
    
    def reset_connection(self) -> bool:
        """Reset and re-establish drozer connection"""
        try:
            self.logger.info("🔄 Resetting drozer connection...")
            
            # Reset state
            self.connected = False
            self.failed_commands = 0
            self.recovery_attempts = 0
            
            # Clean up existing connections
            try:
                subprocess.run(
                    ["adb", "forward", "--remove", "tcp:31415"],
                    capture_output=True, timeout=5
                )
            except:
                pass
            
            # Brief pause for cleanup
            time.sleep(1)
            
            # Attempt fresh connection
            if self.start_connection():
                self.logger.info("✅ Connection reset successful")
                return True
            else:
                self.logger.warning("⚠️ Connection reset failed")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Connection reset error: {e}")
            return False
    
    def get_connection_status(self) -> Dict:
        """Get enhanced connection status with metrics"""
        if self.use_persistent_mode and self._persistent_drozer:
            # Get status from persistent connector
            persistent_status = self._persistent_drozer.get_connection_status()
            return {
                **persistent_status,
                "mode": "persistent",
                "preset": "aggressive"
            }
        
        # Standard status
        success_rate = 0
        if self.total_commands > 0:
            success_rate = ((self.total_commands - self.failed_commands) / self.total_commands) * 100
        
        return {
            "connected": self.connected,
            "device_available": self._device_available,
            "cooldown_active": time.time() < self._connection_cooldown,
            "recovery_enabled": self.enable_recovery,
            "recovery_attempts": self.recovery_attempts,
            "max_recovery_attempts": self.max_recovery_attempts,
            "total_commands": self.total_commands,
            "failed_commands": self.failed_commands,
            "success_rate": success_rate,
            "last_successful_command": self.last_successful_command,
            "mode": "standard"
        }
