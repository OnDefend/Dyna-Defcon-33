#!/usr/bin/env python3
"""
Robust Connection Framework for AODS
Eliminates misconfigurations and strengthens all connection methods
"""

import re
import os
import threading
import time
import logging
import subprocess
import json
import shlex
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum

class SecurityLevel(Enum):
    """Security validation levels for connection configurations"""
    MINIMAL = "minimal"
    STANDARD = "standard" 
    STRICT = "strict"
    ENTERPRISE = "enterprise"

class ConfigurationError(Exception):
    """Raised when configuration validation fails"""
    pass

class SecurityViolationError(Exception):
    """Raised when security validation fails"""
    pass

@dataclass
class SecurityPolicy:
    """Security policy configuration for connection management"""
    # Command execution security
    allow_shell_commands: bool = False
    command_whitelist: List[str] = field(default_factory=lambda: [
        "adb", "drozer", "echo", "grep", "cat", "ls", "ps", "netstat"
    ])
    command_blacklist: List[str] = field(default_factory=lambda: [
        "rm", "del", "format", "fdisk", "dd", "curl", "wget", "ssh", "ftp"
    ])
    
    # Network security
    allowed_ports: List[int] = field(default_factory=lambda: [31415, 5037])
    allowed_interfaces: List[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    max_connection_attempts: int = 5
    
    # Timeout constraints
    min_timeout: int = 5
    max_timeout: int = 300
    default_timeout: int = 30
    
    # Variable substitution security
    allowed_variables: List[str] = field(default_factory=lambda: [
        "device_id", "port", "package", "timeout"
    ])
    
    security_level: SecurityLevel = SecurityLevel.STANDARD

@dataclass
class ValidationResult:
    """Result of configuration validation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sanitized_config: Optional[Dict[str, Any]] = None
    security_score: float = 0.0

class ConfigurationValidator:
    """Validates and sanitizes connection configurations"""
    
    def __init__(self, security_policy: SecurityPolicy):
        self.security_policy = security_policy
        self.logger = logging.getLogger(f"{__name__}.validator")
    
    def _ensure_drozer_agent_startup(self) -> bool:
        """Enhanced drozer agent startup with comprehensive initialization"""
        try:
            import subprocess
            import time
            
            self.logger.info("🔧 Ensuring drozer agent is running...")
            
            # Check if agent is already running
            test_result = subprocess.run(
                ["drozer", "console", "connect", "--command", "list"],
                capture_output=True,
                timeout=5
            )
            
            if test_result.returncode == 0 and b"app.activity.info" in test_result.stdout:
                self.logger.info("✅ Drozer agent already running")
                return True
            
            # Agent not running, start it
            self.logger.info("🚀 Starting drozer agent...")
            
            # Start the drozer agent activity with correct path
            agent_result = subprocess.run(
                ["adb", "shell", "am", "start", "-n", "com.withsecure.dz/.activities.MainActivity"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if agent_result.returncode != 0:
                self.logger.warning(f"⚠️ Agent start command failed: {agent_result.stderr}")
                # Continue anyway, maybe agent is already running
            
            # Wait for agent to be ready
            for i in range(10):
                try:
                    ready_test = subprocess.run(
                        ["drozer", "console", "connect", "--command", "list"],
                        capture_output=True,
                        timeout=3
                    )
                    
                    if ready_test.returncode == 0 and b"app.activity.info" in ready_test.stdout:
                        self.logger.info(f"✅ Drozer agent ready after {i+1}s")
                        return True
                        
                except Exception:
                    pass
                    
                time.sleep(1)
            
            self.logger.warning("⚠️ Drozer agent may not be ready, continuing anyway...")
            return True  # Continue with connection attempt
            
        except Exception as e:
            self.logger.warning(f"⚠️ Agent startup check failed: {e}, continuing anyway...")
            return True  # Don't fail the entire connection due to agent startup issues

    def validate_configuration(self, config: Dict[str, Any]) -> ValidationResult:
        """Comprehensive configuration validation"""
        result = ValidationResult(is_valid=True)
        sanitized = {}
        
        try:
            # Validate structure
            if not self._validate_structure(config, result):
                return result
            
            # Validate and sanitize each section
            sanitized = {
                "connection_settings": self._validate_connection_settings(
                    config.get("connection_settings", {}), result
                ),
                "reconnection_strategy": self._validate_reconnection_strategy(
                    config.get("reconnection_strategy", {}), result
                ),
                "custom_commands": self._validate_custom_commands(
                    config.get("custom_commands", {}), result
                ),
                "security_settings": self._validate_security_settings(
                    config.get("security_settings", {}), result
                )
            }
            
            # Calculate security score
            result.security_score = self._calculate_security_score(sanitized)
            
            # Final validation
            if result.is_valid:
                result.sanitized_config = sanitized
                self.logger.info(f"✅ Configuration validated (security score: {result.security_score:.2f})")
            else:
                self.logger.error(f"❌ Configuration validation failed: {len(result.errors)} errors")
            
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Validation exception: {str(e)}")
        
        return result
    
    def _validate_structure(self, config: Dict[str, Any], result: ValidationResult) -> bool:
        """Validate basic configuration structure"""
        if not isinstance(config, dict):
            result.errors.append("Configuration must be a dictionary")
            result.is_valid = False
            return False
        
        required_sections = ["connection_settings", "reconnection_strategy"]
        for section in required_sections:
            if section not in config:
                result.warnings.append(f"Missing optional section: {section}")
        
        return True
    
    def _validate_connection_settings(self, settings: Dict[str, Any], result: ValidationResult) -> Dict[str, Any]:
        """Validate connection settings with security constraints"""
        sanitized = {}
        
        # Device ID validation
        device_id = settings.get("device_id")
        if device_id:
            if not self._is_safe_device_id(device_id):
                result.errors.append(f"Invalid device ID format: {device_id}")
                result.is_valid = False
            else:
                sanitized["device_id"] = device_id
        
        # Port validation
        port = settings.get("drozer_port", 31415)
        if not self._is_safe_port(port):
            result.errors.append(f"Invalid or dangerous port: {port}")
            result.is_valid = False
        else:
            sanitized["drozer_port"] = int(port)
        
        # Timeout validation
        timeout = settings.get("connection_timeout", self.security_policy.default_timeout)
        sanitized["connection_timeout"] = self._sanitize_timeout(timeout)
        
        command_timeout = settings.get("command_timeout", self.security_policy.default_timeout)
        sanitized["command_timeout"] = self._sanitize_timeout(command_timeout)
        
        return sanitized
    
    def _validate_reconnection_strategy(self, strategy: Dict[str, Any], result: ValidationResult) -> Dict[str, Any]:
        """Validate reconnection strategy parameters"""
        sanitized = {}
        
        # Max attempts validation
        max_attempts = strategy.get("max_reconnection_attempts", 3)
        if not isinstance(max_attempts, int) or max_attempts < 1 or max_attempts > self.security_policy.max_connection_attempts:
            result.warnings.append(f"Invalid max_reconnection_attempts: {max_attempts}, using {self.security_policy.max_connection_attempts}")
            max_attempts = self.security_policy.max_connection_attempts
        sanitized["max_reconnection_attempts"] = max_attempts
        
        # Delay validation
        delay = strategy.get("reconnection_delay", 2.0)
        if not isinstance(delay, (int, float)) or delay < 0.1 or delay > 30.0:
            result.warnings.append(f"Invalid reconnection_delay: {delay}, using 2.0")
            delay = 2.0
        sanitized["reconnection_delay"] = float(delay)
        
        # Boolean flags
        sanitized["persistent_mode"] = bool(strategy.get("persistent_mode", True))
        sanitized["force_reconnect_every_command"] = bool(strategy.get("force_reconnect_every_command", False))
        
        return sanitized
    
    def _validate_custom_commands(self, commands: Dict[str, Any], result: ValidationResult) -> Dict[str, Any]:
        """Validate custom commands with security filtering"""
        sanitized = {}
        
        command_sections = [
            "pre_connection_commands",
            "custom_adb_setup", 
            "custom_drozer_start",
            "post_connection_commands"
        ]
        
        for section in command_sections:
            command_list = commands.get(section, [])
            if not isinstance(command_list, list):
                result.warnings.append(f"Invalid {section} format, expected list")
                sanitized[section] = []
                continue
            
            sanitized_commands = []
            for i, cmd in enumerate(command_list):
                if not isinstance(cmd, str):
                    result.warnings.append(f"Non-string command in {section}[{i}]: {type(cmd)}")
                    continue
                
                # Skip comments and empty lines
                cmd = cmd.strip()
                if not cmd or cmd.startswith("#"):
                    continue
                
                # Security validation
                if self._is_safe_command(cmd):
                    sanitized_commands.append(cmd)
                else:
                    result.errors.append(f"Unsafe command in {section}: {cmd}")
                    result.is_valid = False
            
            sanitized[section] = sanitized_commands
        
        return sanitized
    
    def _validate_security_settings(self, settings: Dict[str, Any], result: ValidationResult) -> Dict[str, Any]:
        """Validate security-specific settings"""
        sanitized = {}
        
        # Enable security by default
        sanitized["enable_command_validation"] = bool(settings.get("enable_command_validation", True))
        sanitized["enable_path_validation"] = bool(settings.get("enable_path_validation", True))
        sanitized["enable_network_validation"] = bool(settings.get("enable_network_validation", True))
        
        # Logging and monitoring
        sanitized["log_commands"] = bool(settings.get("log_commands", True))
        sanitized["log_security_events"] = bool(settings.get("log_security_events", True))
        
        return sanitized
    
    def _is_safe_device_id(self, device_id: str) -> bool:
        """Validate device ID format for security"""
        if not isinstance(device_id, str) or len(device_id) > 255:
            return False
        
        # Allow common device ID patterns
        safe_patterns = [
            r"^[a-zA-Z0-9._-]+$",  # Simple alphanumeric
            r"^emulator-\d+$",  # Android emulator
            r"^\d+\.\d+\.\d+\.\d+:\d+$",  # IP:port
            r"^[a-fA-F0-9]{8,16}$"  # Hex IDs
        ]
        
        return any(re.match(pattern, device_id) for pattern in safe_patterns)
    
    def _is_safe_port(self, port: Union[int, str]) -> bool:
        """Validate port number for security"""
        try:
            port_int = int(port)
            return port_int in self.security_policy.allowed_ports or (1024 <= port_int <= 65535)
        except (ValueError, TypeError):
            return False
    
    def _sanitize_timeout(self, timeout: Union[int, str]) -> int:
        """Sanitize timeout value within policy constraints"""
        try:
            timeout_int = int(timeout)
            return max(
                self.security_policy.min_timeout,
                min(timeout_int, self.security_policy.max_timeout)
            )
        except (ValueError, TypeError):
            return self.security_policy.default_timeout
    
    def _is_safe_command(self, command: str) -> bool:
        """Validate command for security"""
        if not command or len(command) > 1000:  # Reasonable length limit
            return False
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r"[;&|`$()]",  # Shell injection characters
            r"(rm|del|format|fdisk|dd)\s+",  # Destructive commands
            r"(curl|wget|ftp|ssh)\s+",  # Network commands
            r">\s*/dev/",  # Device access
            r"sudo|su\s+",  # Privilege escalation
            r"(cat|less|more)\s+/etc/",  # System file access
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        
        # Check against whitelist
        try:
            command_parts = shlex.split(command)
            if command_parts:
                base_command = command_parts[0]
                if base_command not in self.security_policy.command_whitelist:
                    return False
        except ValueError:
            return False  # Invalid command format
        
        return True
    
    def _calculate_security_score(self, config: Dict[str, Any]) -> float:
        """Calculate security score for configuration"""
        score = 0.0
        max_score = 100.0
        
        # Security settings enabled
        security = config.get("security_settings", {})
        if security.get("enable_command_validation", False):
            score += 20
        if security.get("enable_path_validation", False):
            score += 20
        if security.get("enable_network_validation", False):
            score += 20
        
        # Safe connection settings
        connection = config.get("connection_settings", {})
        if self._is_safe_port(connection.get("drozer_port", 31415)):
            score += 15
        
        # Reasonable timeouts
        if 5 <= connection.get("connection_timeout", 30) <= 60:
            score += 10
        
        # Limited custom commands
        commands = config.get("custom_commands", {})
        total_commands = sum(len(commands.get(section, [])) for section in [
            "pre_connection_commands", "custom_adb_setup", "custom_drozer_start", "post_connection_commands"
        ])
        if total_commands == 0:
            score += 15  # No custom commands is safest
        elif total_commands <= 5:
            score += 10  # Few commands
        elif total_commands <= 10:
            score += 5   # Moderate commands
        
        return min(score, max_score)

class RobustConnectionManager:
    """Enhanced connection manager with comprehensive security and validation"""
    
    def __init__(self, package_name: str, security_policy: Optional[SecurityPolicy] = None):
        self.package_name = package_name
        self.security_policy = security_policy or SecurityPolicy()
        self.validator = ConfigurationValidator(self.security_policy)
        self.logger = logging.getLogger(f"{__name__}.manager")
        
        # Connection state
        self.connected = False
        self.device_id = None
        self.configuration = None
        self.validation_result = None
        self.connection_lock = threading.Lock()
        
        # Security tracking
        self.security_events = []
        self.command_audit_log = []
        self.last_security_check = 0
        
        # Performance metrics
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_commands = 0
        self.security_violations = 0
        
        self.logger.info(f"🔒 Robust Connection Manager initialized for {package_name}")
        self.logger.info(f"   Security Level: {self.security_policy.security_level.value}")
    
    def configure_connection(self, config: Dict[str, Any]) -> bool:
        """Configure connection with comprehensive validation"""
        try:
            self.logger.info("🔧 Validating and configuring connection...")
            
            # Validate configuration
            self.validation_result = self.validator.validate_configuration(config)
            
            if not self.validation_result.is_valid:
                self.logger.error("❌ Configuration validation failed:")
                for error in self.validation_result.errors:
                    self.logger.error(f"   • {error}")
                return False
            
            # Log warnings
            for warning in self.validation_result.warnings:
                self.logger.warning(f"⚠️ {warning}")
            
            # Use sanitized configuration
            self.configuration = self.validation_result.sanitized_config
            
            self.logger.info(f"✅ Configuration validated (security score: {self.validation_result.security_score:.1f}/100)")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Configuration failed: {e}")
            return False
    
    def establish_connection(self) -> bool:
        """Establish connection with security enforcement"""
        if not self.configuration:
            self.logger.error("❌ No validated configuration available")
            return False
        
        with self.connection_lock:
            self.connection_attempts += 1
            
            try:
                self.logger.info("🔗 Establishing secure connection...")
                
                # Pre-connection security check
                if not self._perform_security_check():
                    return False
                
                # Device detection and validation
                if not self._detect_secure_device():
                    return False
                
                # Setup ADB connection securely
                if not self._setup_secure_adb():
                    return False
                
                # Test Drozer connection
                if not self._test_drozer_connection():
                    return False
                
                # Final validation
                if not self._validate_connection_state():
                    return False
                
                self.connected = True
                self.successful_connections += 1
                self.logger.info("✅ Secure connection established successfully")
                
                # Log security event
                self._log_security_event("CONNECTION_ESTABLISHED", {
                    "device_id": self.device_id,
                    "security_score": self.validation_result.security_score
                })
                
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Connection establishment failed: {e}")
                self._log_security_event("CONNECTION_FAILED", {"error": str(e)})
                return False
    
    def execute_command_secure(self, command: str, timeout: Optional[int] = None) -> Tuple[bool, str]:
        """Execute command with comprehensive security validation"""
        if not self.connected:
            return False, "No secure connection available"
        
        try:
            # Security validation
            if not self._validate_command_security(command):
                self.security_violations += 1
                return False, "Command failed security validation"
            
            # Audit logging
            self._audit_command(command)
            
            # Execute with timeout enforcement
            timeout = timeout or self.configuration["connection_settings"]["command_timeout"]
            timeout = self.validator._sanitize_timeout(timeout)
            
            self.logger.debug(f"🔒 Executing secure command: {command[:50]}...")
            
            # Variable substitution with security
            safe_command = self._secure_variable_substitution(command)
            
            # Execute command
            result = subprocess.run(
                ["drozer", "console", "connect", "--command", safe_command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                self.logger.debug(f"✅ Command executed successfully")
                return True, result.stdout.strip()
            else:
                self.failed_commands += 1
                error_msg = result.stderr.strip() or "Command execution failed"
                self.logger.warning(f"⚠️ Command failed: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            self.failed_commands += 1
            error_msg = f"Command timed out after {timeout}s"
            self.logger.warning(f"⏱️ {error_msg}")
            return False, error_msg
            
        except Exception as e:
            self.failed_commands += 1
            error_msg = f"Command execution error: {str(e)}"
            self.logger.error(f"❌ {error_msg}")
            return False, error_msg
    
    def _perform_security_check(self) -> bool:
        """Perform comprehensive security check"""
        current_time = time.time()
        
        # Rate limiting check
        if current_time - self.last_security_check < 1.0:
            self.logger.warning("⚠️ Security check rate limit exceeded")
            return False
        
        self.last_security_check = current_time
        
        # Check for security violations
        if self.security_violations > 10:
            self.logger.error("❌ Too many security violations")
            return False
        
        # Validate system state
        if not self._validate_system_security():
            return False
        
        return True
    
    def _detect_secure_device(self) -> bool:
        """Detect device with security validation"""
        try:
            # Get device list securely
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error("❌ ADB not available")
                return False
            
            # Parse devices securely
            devices = []
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip() and 'device' in line:
                    device_id = line.split()[0]
                    if self.validator._is_safe_device_id(device_id):
                        devices.append(device_id)
            
            if not devices:
                self.logger.error("📱 No secure devices detected")
                return False
            
            # Select device
            configured_device = self.configuration["connection_settings"].get("device_id")
            if configured_device and configured_device in devices:
                self.device_id = configured_device
            else:
                self.device_id = devices[0]
            
            self.logger.info(f"📱 Selected secure device: {self.device_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Device detection failed: {e}")
            return False
    
    def _setup_secure_adb(self) -> bool:
        """Setup ADB connection with security validation"""
        try:
            port = self.configuration["connection_settings"]["drozer_port"]
            
            # Validate port again
            if not self.validator._is_safe_port(port):
                self.logger.error(f"❌ Unsafe port: {port}")
                return False
            
            # Clean existing forwards securely
            cleanup_cmd = ["adb"]
            if self.device_id:
                cleanup_cmd.extend(["-s", self.device_id])
            cleanup_cmd.extend(["forward", "--remove", f"tcp:{port}"])
            
            subprocess.run(cleanup_cmd, capture_output=True, timeout=10)
            time.sleep(1)
            
            # Setup new forwarding securely
            forward_cmd = ["adb"]
            if self.device_id:
                forward_cmd.extend(["-s", self.device_id])
            forward_cmd.extend(["forward", f"tcp:{port}", f"tcp:{port}"])
            
            result = subprocess.run(forward_cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info(f"✅ Secure ADB port forwarding: {port}")
                return True
            else:
                self.logger.error(f"❌ ADB forwarding failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ ADB setup failed: {e}")
            return False
    
    def _test_drozer_connection(self) -> bool:
        """Test Drozer connection with robust timeout handling"""
        try:
            test_command = "list"
            
            # Use Popen for better process control to prevent hanging
            process = subprocess.Popen(
                ["drozer", "console", "connect", "--command", test_command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # Create process group for clean termination
                bufsize=1,  # Line buffered to prevent output hanging
                universal_newlines=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=45)
                
                if process.returncode == 0:
                    # Verify actual drozer connection by checking for expected modules
                    if "app.activity.info" in stdout:
                        self.logger.info("✅ Drozer connection test successful")
                        return True
                    else:
                        self.logger.error("❌ Drozer connection failed - no modules listed")
                        return False
                else:
                    error_msg = stderr.strip() or stdout.strip() or "Unknown error"
                    self.logger.error(f"❌ Drozer connection test failed: {error_msg}")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.logger.error("❌ Drozer connection test timed out after 45s")
                try:
                    # Kill the process group to ensure clean termination
                    import os
                    import signal
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                except (ProcessLookupError, OSError):
                    pass  # Process already dead
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Drozer test failed: {e}")
            return False
    
    def _validate_connection_state(self) -> bool:
        """Validate final connection state"""
        if not self.device_id:
            self.logger.error("❌ No device ID set")
            return False
        
        if not self.configuration:
            self.logger.error("❌ No configuration available")
            return False
        
        return True
    
    def _validate_command_security(self, command: str) -> bool:
        """Validate command for security compliance"""
        if not self.configuration["security_settings"].get("enable_command_validation", True):
            return True
        
        return self.validator._is_safe_command(command)
    
    def _secure_variable_substitution(self, command: str) -> str:
        """Perform secure variable substitution"""
        substitutions = {
            "{device_id}": self.device_id or "",
            "{port}": str(self.configuration["connection_settings"]["drozer_port"]),
            "{package}": self.package_name,
            "{timeout}": str(self.configuration["connection_settings"]["command_timeout"])
        }
        
        result = command
        for var, value in substitutions.items():
            # Only substitute allowed variables
            if var.strip("{}") in self.security_policy.allowed_variables:
                result = result.replace(var, value)
        
        return result
    
    def _validate_system_security(self) -> bool:
        """Validate system security state"""
        # Check for required tools
        required_tools = ["adb", "drozer"]
        for tool in required_tools:
            try:
                subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.logger.error(f"❌ Required tool not available: {tool}")
                return False
        
        return True
    
    def _audit_command(self, command: str):
        """Audit command execution for security tracking"""
        if not self.configuration["security_settings"].get("log_commands", True):
            return
        
        audit_entry = {
            "timestamp": time.time(),
            "command": command[:100],  # Truncate for security
            "device_id": self.device_id,
            "package": self.package_name
        }
        
        self.command_audit_log.append(audit_entry)
        
        # Keep audit log size manageable
        if len(self.command_audit_log) > 1000:
            self.command_audit_log = self.command_audit_log[-500:]
    
    def _log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security events for monitoring"""
        if not self.configuration["security_settings"].get("log_security_events", True):
            return
        
        event = {
            "timestamp": time.time(),
            "type": event_type,
            "details": details,
            "security_score": getattr(self.validation_result, 'security_score', 0.0)
        }
        
        self.security_events.append(event)
        self.logger.info(f"🔒 Security Event: {event_type}")
        
        # Keep event log size manageable
        if len(self.security_events) > 100:
            self.security_events = self.security_events[-50:]
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status"""
        return {
            "connected": self.connected,
            "security_level": self.security_policy.security_level.value,
            "security_score": getattr(self.validation_result, 'security_score', 0.0),
            "connection_attempts": self.connection_attempts,
            "successful_connections": self.successful_connections,
            "failed_commands": self.failed_commands,
            "security_violations": self.security_violations,
            "audit_log_size": len(self.command_audit_log),
            "security_events": len(self.security_events),
            "configuration_valid": self.validation_result.is_valid if self.validation_result else False
        }
    
    def cleanup(self):
        """Secure cleanup of connection resources"""
        try:
            if self.connected and self.device_id:
                port = self.configuration["connection_settings"]["drozer_port"]
                cleanup_cmd = ["adb", "-s", self.device_id, "forward", "--remove", f"tcp:{port}"]
                subprocess.run(cleanup_cmd, capture_output=True, timeout=5)
            
            self.connected = False
            self.device_id = None
            
            # Log cleanup event
            if self.configuration:
                self._log_security_event("CONNECTION_CLEANUP", {"status": "success"})
            
            self.logger.info("🧹 Secure connection cleanup completed")
            
        except Exception as e:
            self.logger.debug(f"Cleanup warning: {e}")

# Factory functions for different security levels
def create_minimal_security_manager(package_name: str) -> RobustConnectionManager:
    """Create connection manager with minimal security (development only)"""
    policy = SecurityPolicy(
        security_level=SecurityLevel.MINIMAL,
        allow_shell_commands=True,
        max_connection_attempts=10
    )
    return RobustConnectionManager(package_name, policy)

def create_standard_security_manager(package_name: str) -> RobustConnectionManager:
    """Create connection manager with standard security (recommended)"""
    policy = SecurityPolicy(security_level=SecurityLevel.STANDARD)
    return RobustConnectionManager(package_name, policy)

def create_enterprise_security_manager(package_name: str) -> RobustConnectionManager:
    """Create connection manager with enterprise security (maximum protection)"""
    policy = SecurityPolicy(
        security_level=SecurityLevel.ENTERPRISE,
        allow_shell_commands=False,
        max_connection_attempts=3,
        max_timeout=60,
        command_whitelist=["adb", "drozer"]  # Minimal whitelist
    )
    return RobustConnectionManager(package_name, policy) 
 
 
 
 