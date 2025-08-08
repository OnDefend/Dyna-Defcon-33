"""
Application Manager for Advanced Dynamic Analysis Plugin

This module handles application installation, management, and interaction for dynamic analysis.
Provides comprehensive application lifecycle management and security testing orchestration.
"""

import logging
import subprocess
import re
import time
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from .data_structures import (
    AppInfo,
    AppStatus,
    ComponentStatus,
    DEFAULT_TIMEOUT
)

logger = logging.getLogger(__name__)

class AppManager:
    """Manages application lifecycle and interactions for dynamic analysis"""
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        """Initialize application manager with unified performance optimization framework"""
        self.timeout = timeout
        self.managed_apps: Dict[str, AppInfo] = {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize unified performance optimization components
        try:
            from core.performance_optimizer import (
                EnterpriseTimeoutManager,
                IntelligentCache
            )
            
            # Create timeout manager for robust timeout handling
            self.timeout_manager = EnterpriseTimeoutManager()
            
            # Create intelligent cache for app information (correct parameters)
            self.app_cache = IntelligentCache(
                cache_dir="cache/app_manager",
                max_size_mb=50,  # 50MB cache
                ttl_hours=5  # 5 hours cache
            )
            
            # Performance metrics tracking (simple counter)
            self.operation_metrics = {
                'cache_hits': 0,
                'cache_misses': 0,
                'timeouts': 0,
                'successful_operations': 0
            }
            
            self.logger.info("App manager initialized with unified performance optimization framework")
            
        except Exception as e:
            # Fallback to basic implementation without unified framework
            self.logger.warning(f"Failed to initialize unified performance framework: {e}")
            self.timeout_manager = None
            self.app_cache = None
            self.operation_metrics = None
        
    def check_application_installed(self, device_id: str, package_name: str) -> AppInfo:
        """
        Check if application is installed on device using unified performance optimization
        
        Args:
            device_id: Target device identifier
            package_name: Package name to check
            
        Returns:
            AppInfo: Complete application information and status
        """
        # Check intelligent cache first if available
        cache_key = f"{device_id}:{package_name}"
        if self.app_cache:
            cached_result = self.app_cache.get(cache_key)
            if cached_result:
                if self.operation_metrics:
                    self.operation_metrics['cache_hits'] += 1
                self.logger.debug(f"Cache hit for app check: {package_name}")
                return cached_result
            elif self.operation_metrics:
                self.operation_metrics['cache_misses'] += 1
        
        # Define the actual operation function for timeout management
        def perform_app_check():
            return subprocess.run(
                ['adb', '-s', device_id, 'shell', 'pm', 'list', 'packages', package_name],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        
        try:
            # Use unified timeout manager if available
            if self.timeout_manager:
                timeout_result = self.timeout_manager.execute_with_timeout(
                    operation=perform_app_check,
                    timeout_seconds=self.timeout,
                    operation_name="app_check"
                )
                
                if timeout_result.timed_out:
                    if self.operation_metrics:
                        self.operation_metrics['timeouts'] += 1
                    self.logger.error(f"Application check timed out for {package_name}")
                    return AppInfo(
                        package_name=package_name,
                        status=AppStatus.UNKNOWN,
                        error_message=f"Application check timed out"
                    )
                
                if not timeout_result.success:
                    error_msg = timeout_result.error_message or "Unknown timeout manager error"
                    self.logger.error(f"Timeout manager error for {package_name}: {error_msg}")
                    return AppInfo(
                        package_name=package_name,
                        status=AppStatus.UNKNOWN,
                        error_message=f"Timeout manager error: {error_msg}"
                    )
                
                result = timeout_result.result
            else:
                # Fallback to direct subprocess call
                result = perform_app_check()
            
            if result.returncode != 0:
                self.logger.error(f"Package check failed for {package_name}: {result.stderr}")
                error_result = AppInfo(
                    package_name=package_name,
                    status=AppStatus.UNKNOWN,
                    error_message=f"Package check failed: {result.stderr}"
                )
                return error_result
            
            # Parse package list output
            is_installed = package_name in result.stdout
            
            if not is_installed:
                not_installed_result = AppInfo(
                    package_name=package_name,
                    status=AppStatus.NOT_INSTALLED
                )
                # Cache negative result too (using correct method)
                if self.app_cache:
                    self.app_cache.put(cache_key, not_installed_result)
                return not_installed_result
            
            # Get detailed app information
            app_info = self._get_app_details(device_id, package_name)
            
            # Cache the app information using both legacy and unified cache
            self.managed_apps[package_name] = app_info
            if self.app_cache:
                self.app_cache.put(cache_key, app_info)  # Correct method name
            
            # Update performance metrics if available
            if self.operation_metrics:
                self.operation_metrics['successful_operations'] += 1
            
            return app_info
            
        except subprocess.TimeoutExpired:
            if self.operation_metrics:
                self.operation_metrics['timeouts'] += 1
            self.logger.error(f"Application check timed out for {package_name}")
            timeout_result = AppInfo(
                package_name=package_name,
                status=AppStatus.UNKNOWN,
                error_message="Application check timed out"
            )
        except Exception as e:
            self.logger.error(f"Error checking application {package_name}: {e}")
            return AppInfo(
                package_name=package_name,
                status=AppStatus.UNKNOWN,
                error_message=f"Error checking application: {str(e)}"
            )
    
    def _get_app_details(self, device_id: str, package_name: str) -> AppInfo:
        """Get detailed information about installed application"""
        app_info = AppInfo(package_name=package_name, status=AppStatus.INSTALLED)
        
        try:
            # Get version information
            version_info = self._get_app_version_info(device_id, package_name)
            if version_info:
                app_info.version_name = version_info.get('versionName')
                app_info.version_code = version_info.get('versionCode')
            
            # Get install location
            install_location = self._get_app_install_location(device_id, package_name)
            if install_location:
                app_info.install_location = install_location
            
            # Get permissions
            permissions = self._get_app_permissions(device_id, package_name)
            if permissions:
                app_info.permissions = permissions
            
            # Get components
            components = self._get_app_components(device_id, package_name)
            if components:
                app_info.activities = components.get('activities', [])
                app_info.services = components.get('services', [])
                app_info.receivers = components.get('receivers', [])
            
        except Exception as e:
            self.logger.warning(f"Error getting app details for {package_name}: {e}")
            app_info.error_message = f"Error getting app details: {str(e)}"
        
        return app_info
    
    def _get_app_version_info(self, device_id: str, package_name: str) -> Optional[Dict[str, Any]]:
        """Get application version information"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'dumpsys', 'package', package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                version_info = {}
                for line in result.stdout.split('\n'):
                    if 'versionName=' in line:
                        version_info['versionName'] = line.split('versionName=')[1].strip()
                    elif 'versionCode=' in line:
                        try:
                            version_code = int(line.split('versionCode=')[1].split()[0])
                            version_info['versionCode'] = version_code
                        except (ValueError, IndexError):
                            pass
                
                return version_info if version_info else None
                
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Error getting version info for {package_name}: {e}")
        
        return None
    
    def _get_app_install_location(self, device_id: str, package_name: str) -> Optional[str]:
        """Get application install location"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'pm', 'path', package_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip().replace('package:', '')
                
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Error getting install location for {package_name}: {e}")
        
        return None
    
    def _get_app_permissions(self, device_id: str, package_name: str) -> Optional[List[str]]:
        """Get application permissions"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'pm', 'dump', package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                permissions = []
                in_permissions_section = False
                
                for line in result.stdout.split('\n'):
                    if 'requested permissions:' in line:
                        in_permissions_section = True
                        continue
                    elif in_permissions_section and line.strip().startswith('android.permission.'):
                        permission = line.strip()
                        if permission not in permissions:
                            permissions.append(permission)
                    elif in_permissions_section and not line.strip():
                        break
                
                return permissions if permissions else None
                
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Error getting permissions for {package_name}: {e}")
        
        return None
    
    def _get_app_components(self, device_id: str, package_name: str) -> Optional[Dict[str, List[str]]]:
        """Get application components (activities, services, receivers)"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'dumpsys', 'package', package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                components = {
                    'activities': [],
                    'services': [],
                    'receivers': []
                }
                
                current_section = None
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if 'Activity Resolver Table:' in line:
                        current_section = 'activities'
                    elif 'Service Resolver Table:' in line:
                        current_section = 'services'
                    elif 'Receiver Resolver Table:' in line:
                        current_section = 'receivers'
                    elif current_section and line.startswith(package_name + '/'):
                        component_name = line.split()[0]
                        if component_name not in components[current_section]:
                            components[current_section].append(component_name)
                
                return components if any(components.values()) else None
                
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Error getting components for {package_name}: {e}")
        
        return None
    
    def install_application(self, device_id: str, apk_path: str) -> Tuple[bool, str]:
        """Install application on device"""
        try:
            if not Path(apk_path).exists():
                return False, f"APK file not found: {apk_path}"
            
            result = subprocess.run(
                ['adb', '-s', device_id, 'install', '-r', apk_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0 and 'Success' in result.stdout:
                return True, "Application installed successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Installation failed: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, f"Installation error: {str(e)}"
    
    def uninstall_application(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Uninstall application from device"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'uninstall', package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and 'Success' in result.stdout:
                # Remove from managed apps
                self.managed_apps.pop(package_name, None)
                return True, "Application uninstalled successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Uninstallation failed: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return False, "Uninstallation timed out"
        except Exception as e:
            return False, f"Uninstallation error: {str(e)}"
    
    def start_application(self, device_id: str, package_name: str, activity_name: str = None) -> Tuple[bool, str]:
        """Start application on device"""
        try:
            if not activity_name:
                # Get main activity
                activity_name = self._get_main_activity(device_id, package_name)
                if not activity_name:
                    return False, "Could not find main activity"
            
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'am', 'start', '-n', f"{package_name}/{activity_name}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return True, "Application started successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Failed to start application: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return False, "Application start timed out"
        except Exception as e:
            return False, f"Application start error: {str(e)}"
    
    def stop_application(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Stop application on device"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'am', 'force-stop', package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return True, "Application stopped successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Failed to stop application: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return False, "Application stop timed out"
        except Exception as e:
            return False, f"Application stop error: {str(e)}"
    
    def _get_main_activity(self, device_id: str, package_name: str) -> Optional[str]:
        """Get main activity of application"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'pm', 'dump', package_name, '|', 'grep', '-A', '1', 'MAIN'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if package_name in line and 'filter' in line:
                        # Extract activity name from line
                        match = re.search(r'(\S+)/(\S+)', line)
                        if match:
                            return match.group(2)
                            
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Error getting main activity for {package_name}: {e}")
        
        return None
    
    def get_app_processes(self, device_id: str, package_name: str) -> List[Dict[str, Any]]:
        """Get running processes for application"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'ps', '|', 'grep', package_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            processes = []
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if package_name in line:
                        parts = line.split()
                        if len(parts) >= 9:
                            processes.append({
                                'user': parts[0],
                                'pid': parts[1],
                                'ppid': parts[2],
                                'name': parts[8]
                            })
            
            return processes
            
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.debug(f"Error getting processes for {package_name}: {e}")
            return []
    
    def clear_app_data(self, device_id: str, package_name: str) -> Tuple[bool, str]:
        """Clear application data"""
        try:
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'pm', 'clear', package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and 'Success' in result.stdout:
                return True, "Application data cleared successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Failed to clear data: {error_msg}"
                
        except subprocess.TimeoutExpired:
            return False, "Clear data timed out"
        except Exception as e:
            return False, f"Clear data error: {str(e)}"
    
    def get_app_info(self, package_name: str) -> Optional[AppInfo]:
        """Get cached application information"""
        return self.managed_apps.get(package_name)
    
    def get_managed_apps(self) -> List[AppInfo]:
        """Get list of all managed applications"""
        return list(self.managed_apps.values())
    
    def validate_app_requirements(self, package_name: str) -> Tuple[bool, List[str]]:
        """Validate application meets requirements for dynamic analysis"""
        issues = []
        app_info = self.managed_apps.get(package_name)
        
        if not app_info:
            issues.append("Application not found")
            return False, issues
        
        if app_info.status != AppStatus.INSTALLED:
            issues.append(f"Application status: {app_info.status.value}")
        
        if not app_info.permissions:
            issues.append("Could not read application permissions")
        
        if not app_info.activities:
            issues.append("No activities found")
        
        return len(issues) == 0, issues 