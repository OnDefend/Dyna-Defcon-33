#!/usr/bin/env python3
"""
MITMProxy Manager Module

This module handles MITMProxy setup, configuration, and lifecycle management
for network traffic analysis. Provides proper subprocess handling with
granular error management and caching.

Features:
- MITMProxy installation and availability checking
- Proxy configuration and script generation
- Traffic capture lifecycle management
- Device proxy configuration
- Subprocess handling with timeout protection
- Resource cleanup and management

"""

import json
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from .data_structures import MitmproxyConfig, NetworkFlow

logger = logging.getLogger(__name__)

class MitmproxyManager:
    """
    MITMProxy lifecycle manager with professional subprocess handling.
    
    Manages MITMProxy installation, configuration, startup, and shutdown
    with proper error handling and resource management.
    """
    
    def __init__(self, config: MitmproxyConfig, package_name: str):
        """
        Initialize MITMProxy manager.
        
        Args:
            config: MITMProxy configuration
            package_name: Target package name for analysis
        """
        self.config = config
        self.package_name = package_name
        self.logger = logging.getLogger(__name__)
        
        # Process management
        self.mitm_process: Optional[subprocess.Popen] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        
        # File management
        self.temp_dir = Path(tempfile.mkdtemp(prefix="mitmproxy_"))
        self.script_file = self.temp_dir / "mitm_script.py"
        self.capture_file = self.temp_dir / f"{package_name}_capture.flows"
        self.har_file = self.temp_dir / f"{package_name}_har.json"
        
        # Update config with generated paths
        self.config.script_file = str(self.script_file)
        self.config.capture_file = str(self.capture_file)
        self.config.har_file = str(self.har_file)
        
        self.logger.info(f"MITMProxy manager initialized for {package_name}")
    
    def check_availability(self) -> Tuple[bool, str]:
        """
        Check if MITMProxy is available and properly configured.
        
        Returns:
            Tuple of (is_available, status_message)
        """
        try:
            # Check if mitmproxy is installed
            result = subprocess.run(
                ['mitmproxy', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version = result.stdout.strip()
                self.logger.info(f"MITMProxy available: {version}")
                return True, f"MITMProxy available: {version}"
            else:
                return False, "MITMProxy command failed"
                
        except subprocess.TimeoutExpired:
            return False, "MITMProxy version check timed out"
        except FileNotFoundError:
            return False, "MITMProxy not installed or not in PATH"
        except Exception as e:
            return False, f"MITMProxy availability check failed: {e}"
    
    def setup_proxy(self) -> bool:
        """
        Set up MITMProxy with configuration and scripts.
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            # Create MITMProxy script
            if not self._create_mitm_script():
                return False
            
            # Verify port availability
            if not self._check_port_available():
                self.logger.error(f"Port {self.config.proxy_port} is not available")
                return False
            
            self.logger.info("MITMProxy setup completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup MITMProxy: {e}")
            return False
    
    def start_capture(self) -> bool:
        """
        Start MITMProxy traffic capture.
        
        Returns:
            True if capture started successfully, False otherwise
        """
        try:
            if self.is_capturing:
                self.logger.warning("Traffic capture already in progress")
                return True
            
            # Start MITMProxy process
            cmd = [
                'mitmdump',
                '--listen-port', str(self.config.proxy_port),
                '--listen-host', self.config.listen_host,
                '-s', str(self.script_file),
                '--set', f'save_stream_file={self.config.capture_file}',
                '--set', 'confdir=' + str(self.temp_dir),
                '--quiet'
            ]
            
            self.logger.info(f"Starting MITMProxy: {' '.join(cmd)}")
            
            self.mitm_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a moment for process to start
            time.sleep(2)
            
            # Check if process is still running
            if self.mitm_process.poll() is not None:
                stdout, stderr = self.mitm_process.communicate()
                self.logger.error(f"MITMProxy failed to start: {stderr}")
                return False
            
            self.is_capturing = True
            self.logger.info(f"MITMProxy capture started on port {self.config.proxy_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start MITMProxy capture: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """
        Stop MITMProxy traffic capture.
        
        Returns:
            True if capture stopped successfully, False otherwise
        """
        try:
            if not self.is_capturing:
                self.logger.warning("No traffic capture in progress")
                return True
            
            # Terminate MITMProxy process
            if self.mitm_process:
                self.mitm_process.terminate()
                
                # Wait for graceful shutdown
                try:
                    self.mitm_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.logger.warning("MITMProxy did not shutdown gracefully, killing")
                    self.mitm_process.kill()
                    self.mitm_process.wait()
                
                self.mitm_process = None
            
            self.is_capturing = False
            self.logger.info("MITMProxy capture stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop MITMProxy capture: {e}")
            return False
    
    def _create_mitm_script(self) -> bool:
        """Create MITMProxy script for traffic capture and analysis."""
        try:
            script_content = self._generate_mitm_script()
            
            with open(self.script_file, 'w') as f:
                f.write(script_content)
            
            # Make script executable
            os.chmod(self.script_file, 0o755)
            
            self.logger.debug(f"MITMProxy script created: {self.script_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create MITMProxy script: {e}")
            return False
    
    def _generate_mitm_script(self) -> str:
        """Generate MITMProxy script content for network analysis."""
        return f'''#!/usr/bin/env python3
"""
MITMProxy Analysis Script for {self.package_name}

This script captures and analyzes network traffic for security assessment.
Generated automatically by AODS MITMProxy Network Analysis Plugin.
"""

import json
import re
from datetime import datetime
from mitmproxy import http, ctx
from mitmproxy.http import HTTPFlow

class NetworkAnalysisAddon:
    """MITMProxy addon for network traffic analysis."""
    
    def __init__(self):
        self.flows = []
        self.security_patterns = {{
            "sensitive_data": [
                r"[aA][pP][iI][_-]?[kK][eE][yY]",
                r"[tT][oO][kK][eE][nN]",
                r"[pP][aA][sS][sS][wW][oO][rR][dD]",
                r"[sS][eE][cC][rR][eE][tT]"
            ],
            "injection_patterns": [
                r"(?i)(union|select|insert|update|delete|drop)",
                r"<script[^>]*>",
                r"javascript:",
                r"on\\w+\\s*="
            ],
            "private_data": [
                r"\\b\\d{{4}}[-\\s]?\\d{{4}}[-\\s]?\\d{{4}}[-\\s]?\\d{{4}}\\b",  # Credit card
                r"\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b",  # SSN
                r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{{2,}}\\b"  # Email
            ]
        }}
    
    def request(self, flow: HTTPFlow):
        """Handle HTTP request."""
        try:
            self._analyze_request(flow)
        except Exception as e:
            ctx.log.error(f"Error analyzing request: {{e}}")
    
    def response(self, flow: HTTPFlow):
        """Handle HTTP response."""
        try:
            self._analyze_response(flow)
            self._store_flow(flow)
        except Exception as e:
            ctx.log.error(f"Error analyzing response: {{e}}")
    
    def _analyze_request(self, flow: HTTPFlow):
        """Analyze HTTP request for security issues."""
        request = flow.request
        
        # Check for sensitive data in URL parameters
        if request.query:
            query_string = str(request.query)
            for category, patterns in self.security_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, query_string, re.IGNORECASE):
                        ctx.log.warn(f"Sensitive data in URL parameters: {{category}}")
        
        # Check request body for sensitive data
        if request.content:
            try:
                body = request.content.decode('utf-8', errors='ignore')
                for category, patterns in self.security_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            ctx.log.warn(f"Sensitive data in request body: {{category}}")
            except Exception:
                pass
    
    def _analyze_response(self, flow: HTTPFlow):
        """Analyze HTTP response for security issues."""
        response = flow.response
        
        if not response:
            return
        
        # Check response headers for security issues
        headers = dict(response.headers)
        
        # Check for missing security headers
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options"
        ]
        
        for header in security_headers:
            if header not in [h.lower() for h in headers.keys()]:
                ctx.log.warn(f"Missing security header: {{header}}")
        
        # Check response body for sensitive data
        if response.content:
            try:
                body = response.content.decode('utf-8', errors='ignore')
                for category, patterns in self.security_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            ctx.log.warn(f"Sensitive data in response: {{category}}")
            except Exception:
                pass
    
    def _store_flow(self, flow: HTTPFlow):
        """Store flow data for analysis."""
        try:
            flow_data = {{
                "id": str(len(self.flows)),
                "timestamp": datetime.now().isoformat(),
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "port": flow.request.port,
                "scheme": flow.request.scheme,
                "path": flow.request.path,
                "query": dict(flow.request.query) if flow.request.query else {{}},
                "request_headers": dict(flow.request.headers),
                "response_code": flow.response.status_code if flow.response else 0,
                "response_headers": dict(flow.response.headers) if flow.response else {{}},
                "response_size": len(flow.response.content) if flow.response and flow.response.content else 0
            }}
            
            self.flows.append(flow_data)
            
            # Save flows periodically
            if len(self.flows) % 10 == 0:
                self._save_flows()
                
        except Exception as e:
            ctx.log.error(f"Error storing flow: {{e}}")
    
    def _save_flows(self):
        """Save captured flows to file."""
        try:
            with open("{self.capture_file}", "w") as f:
                json.dump(self.flows, f, indent=2)
        except Exception as e:
            ctx.log.error(f"Error saving flows: {{e}}")

# Register addon
addons = [NetworkAnalysisAddon()]
'''
    
    def _check_port_available(self) -> bool:
        """Check if the configured port is available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.config.listen_host, self.config.proxy_port))
                return True
        except OSError:
            return False
    
    def get_captured_flows(self) -> List[Dict[str, Any]]:
        """
        Load and return captured network flows.
        
        Returns:
            List of captured network flows
        """
        try:
            if not self.capture_file.exists():
                self.logger.warning("No capture file found")
                return []
            
            with open(self.capture_file, 'r') as f:
                flows_data = json.load(f)
            
            self.logger.info(f"Loaded {len(flows_data)} captured flows")
            return flows_data
            
        except Exception as e:
            self.logger.error(f"Failed to load captured flows: {e}")
            return []
    
    def cleanup(self):
        """Clean up resources and temporary files."""
        try:
            # Stop capture if running
            if self.is_capturing:
                self.stop_capture()
            
            # Remove temporary files
            if self.temp_dir.exists():
                import shutil
                shutil.rmtree(self.temp_dir)
                self.logger.debug(f"Cleaned up temporary directory: {self.temp_dir}")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

class DeviceProxyConfigurator:
    """
    Device proxy configuration manager for Android devices.
    
    Handles ADB commands to configure device proxy settings for
    MITMProxy traffic capture.
    """
    
    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 8080):
        """
        Initialize device proxy configurator.
        
        Args:
            proxy_host: Proxy server host
            proxy_port: Proxy server port
        """
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.logger = logging.getLogger(__name__)
        self.original_settings = {}
    
    def configure_device_proxy(self) -> bool:
        """
        Configure Android device to use MITMProxy.
        
        Returns:
            True if configuration successful, False otherwise
        """
        try:
            # Check if ADB is available
            if not self._check_adb_available():
                self.logger.error("ADB not available for device proxy configuration")
                return False
            
            # Check if device is connected
            if not self._check_device_connected():
                self.logger.error("No Android device connected")
                return False
            
            # Backup current proxy settings
            self._backup_proxy_settings()
            
            # Configure proxy settings
            commands = [
                f"adb shell settings put global http_proxy {self.proxy_host}:{self.proxy_port}",
                f"adb shell settings put global https_proxy {self.proxy_host}:{self.proxy_port}"
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    self.logger.error(f"Failed to configure proxy: {result.stderr}")
                    return False
            
            self.logger.info(f"Device proxy configured: {self.proxy_host}:{self.proxy_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error configuring device proxy: {e}")
            return False
    
    def restore_device_proxy(self) -> bool:
        """
        Restore original device proxy settings.
        
        Returns:
            True if restoration successful, False otherwise
        """
        try:
            if not self._check_adb_available():
                return False
            
            # Restore original settings
            commands = [
                "adb shell settings delete global http_proxy",
                "adb shell settings delete global https_proxy"
            ]
            
            for cmd in commands:
                subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            self.logger.info("Device proxy settings restored")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring device proxy: {e}")
            return False
    
    def _check_adb_available(self) -> bool:
        """Check if ADB is available."""
        try:
            result = subprocess.run(
                ['adb', 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_device_connected(self) -> bool:
        """Check if Android device is connected."""
        try:
            result = subprocess.run(
                ['adb', 'devices'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Check if any devices are listed
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                devices = [line for line in lines if line.strip() and 'device' in line]
                return len(devices) > 0
            
            return False
            
        except Exception:
            return False
    
    def _backup_proxy_settings(self):
        """Backup current proxy settings."""
        try:
            settings = ['http_proxy', 'https_proxy']
            
            for setting in settings:
                result = subprocess.run(
                    ['adb', 'shell', 'settings', 'get', 'global', setting],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    self.original_settings[setting] = result.stdout.strip()
                    
        except Exception as e:
            self.logger.warning(f"Failed to backup proxy settings: {e}")

def create_mitmproxy_manager(config: MitmproxyConfig, package_name: str) -> MitmproxyManager:
    """
    Factory function to create MITMProxy manager with proper configuration.
    
    Args:
        config: MITMProxy configuration
        package_name: Target package name
        
    Returns:
        Configured MITMProxy manager
    """
    return MitmproxyManager(config, package_name)

def create_device_proxy_configurator(
    proxy_host: str = "127.0.0.1", 
    proxy_port: int = 8080
) -> DeviceProxyConfigurator:
    """
    Factory function to create device proxy configurator.
    
    Args:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        
    Returns:
        Configured device proxy configurator
    """
    return DeviceProxyConfigurator(proxy_host, proxy_port) 