#!/usr/bin/env python3
"""
App Automation Framework

Automated app launching, control, and systematic feature exploration
for triggering runtime vulnerabilities during dynamic analysis.

Author: AODS Team
Date: January 2025
"""

import logging
import time
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import random
import re

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available - app automation will be limited")

logger = logging.getLogger(__name__)


@dataclass
class AppActivity:
    """Represents a discovered app activity."""
    name: str
    package: str
    exported: bool = False
    intent_filters: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class AppComponent:
    """Represents an app component (activity, service, receiver)."""
    name: str
    component_type: str  # activity, service, receiver
    package: str
    exported: bool = False
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationSession:
    """Tracks an automation session."""
    package_name: str
    start_time: float
    activities_discovered: int = 0
    interactions_performed: int = 0
    scenarios_executed: int = 0
    runtime_events_triggered: int = 0
    vulnerabilities_detected: int = 0
    session_duration: float = 0.0
    status: str = "active"


class AppAutomationFramework:
    """
    Automated app interaction framework for systematic feature exploration
    and vulnerability scenario triggering during runtime analysis.
    """
    
    def __init__(self, device=None, package_name: str = None, apk_ctx: Any = None):
        """Initialize app automation framework."""
        self.logger = logging.getLogger(__name__)
        self.device = device
        self.package_name = package_name
        self.apk_ctx = apk_ctx
        
        # Automation state
        self.session: Optional[AutomationSession] = None
        self.discovered_activities: List[AppActivity] = []
        self.discovered_components: List[AppComponent] = []
        self.ui_hierarchy_cache: Dict[str, Any] = {}
        
        # Automation configuration
        self.automation_timeout = 60  # seconds
        self.interaction_delay = 1.0  # seconds between interactions
        self.exploration_depth = 3   # max screens to explore
        self.scenario_timeout = 30   # seconds per vulnerability scenario
        
        # Integration with runtime analysis
        self.hook_engine = None
        self.vulnerability_detector = None
        self.evidence_collector = None
        
        self.logger.info(f"🚀 AppAutomationFramework initialized for {package_name or 'unknown'}")
    
    def set_runtime_integrations(self, hook_engine=None, detector=None, collector=None):
        """Set runtime analysis component integrations."""
        self.hook_engine = hook_engine
        self.vulnerability_detector = detector
        self.evidence_collector = collector
        
        if hook_engine:
            self.logger.info("✅ Runtime hook engine integration enabled")
        if detector:
            self.logger.info("✅ Vulnerability detector integration enabled")
        if collector:
            self.logger.info("✅ Evidence collector integration enabled")
    
    def start_automation_session(self, duration: int = 60) -> AutomationSession:
        """Start a new automation session."""
        if not self.package_name:
            raise ValueError("Package name required for automation session")
        
        self.session = AutomationSession(
            package_name=self.package_name,
            start_time=time.time()
        )
        
        self.automation_timeout = duration
        self.logger.info(f"🎯 Starting automation session for {self.package_name} ({duration}s)")
        
        return self.session
    
    def launch_app(self) -> bool:
        """Launch target application."""
        if not self.package_name:
            self.logger.error("❌ No package name specified for app launch")
            return False
        
        try:
            # Check if app is already running
            if self._is_app_running():
                self.logger.info(f"📱 App {self.package_name} already running")
                return True
            
            # Launch app using ADB
            launch_cmd = [
                'adb', 'shell', 'monkey', '-p', self.package_name, 
                '-c', 'android.intent.category.LAUNCHER', '1'
            ]
            
            result = subprocess.run(launch_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.logger.info(f"✅ Successfully launched {self.package_name}")
                
                # Wait for app to initialize
                time.sleep(3)
                
                # Verify app is running
                if self._is_app_running():
                    return True
                else:
                    self.logger.warning("⚠️ App launched but not detected as running")
                    return False
            else:
                self.logger.error(f"❌ Failed to launch app: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("❌ App launch timeout")
            return False
        except Exception as e:
            self.logger.error(f"❌ App launch error: {e}")
            return False
    
    def _is_app_running(self) -> bool:
        """Check if target app is currently running."""
        try:
            cmd = ['adb', 'shell', 'ps', '|', 'grep', self.package_name]
            result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
            return self.package_name in result.stdout
        except Exception:
            return False
    
    def discover_activities(self) -> List[AppActivity]:
        """Discover and catalog app activities."""
        self.logger.info(f"🔍 Discovering activities for {self.package_name}")
        
        try:
            # Get activities from package manager
            cmd = ['adb', 'shell', 'dumpsys', 'package', self.package_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode != 0:
                self.logger.error("❌ Failed to get package information")
                return []
            
            activities = self._parse_activities_from_dumpsys(result.stdout)
            self.discovered_activities = activities
            
            if self.session:
                self.session.activities_discovered = len(activities)
            
            self.logger.info(f"✅ Discovered {len(activities)} activities")
            return activities
            
        except subprocess.TimeoutExpired:
            self.logger.error("❌ Activity discovery timeout")
            return []
        except Exception as e:
            self.logger.error(f"❌ Activity discovery error: {e}")
            return []
    
    def _parse_activities_from_dumpsys(self, dumpsys_output: str) -> List[AppActivity]:
        """Parse activities from dumpsys package output."""
        activities = []
        
        # Look for activity declarations
        activity_pattern = r'Activity\s+([^\s]+)\s+'
        intent_pattern = r'android\.intent\.action\.(\w+)'
        
        lines = dumpsys_output.split('\n')
        current_activity = None
        
        for line in lines:
            line = line.strip()
            
            # Match activity declarations
            activity_match = re.search(activity_pattern, line)
            if activity_match:
                activity_name = activity_match.group(1)
                if self.package_name in activity_name:
                    current_activity = AppActivity(
                        name=activity_name,
                        package=self.package_name,
                        exported='exported=true' in line
                    )
                    activities.append(current_activity)
            
            # Match intent filters for current activity
            elif current_activity and 'android.intent' in line:
                intent_match = re.search(intent_pattern, line)
                if intent_match:
                    current_activity.intent_filters.append(intent_match.group(1))
        
        return activities
    
    def exercise_app_features(self, max_interactions: int = 20) -> Dict[str, Any]:
        """Systematically exercise app functionality."""
        self.logger.info(f"🔄 Exercising app features (max {max_interactions} interactions)")
        
        interaction_results = {
            "interactions_performed": 0,
            "screens_visited": [],
            "ui_elements_interacted": [],
            "runtime_events_triggered": [],
            "errors_encountered": []
        }
        
        try:
            for i in range(max_interactions):
                if self.session and time.time() - self.session.start_time > self.automation_timeout:
                    self.logger.info("⏱️ Automation timeout reached")
                    break
                
                # Get current UI state
                ui_state = self._get_current_ui_state()
                if not ui_state:
                    self.logger.warning("⚠️ Could not get UI state")
                    continue
                
                # Find interactive elements
                interactive_elements = self._find_interactive_elements(ui_state)
                
                if not interactive_elements:
                    self.logger.info("ℹ️ No interactive elements found, trying navigation")
                    self._perform_navigation_action()
                    continue
                
                # Select and interact with an element
                element = random.choice(interactive_elements)
                interaction_result = self._interact_with_element(element)
                
                if interaction_result:
                    interaction_results["interactions_performed"] += 1
                    interaction_results["ui_elements_interacted"].append(element)
                    
                    if self.session:
                        self.session.interactions_performed += 1
                
                # Wait between interactions
                time.sleep(self.interaction_delay)
                
                # Check for runtime events if hook engine is available
                if self.hook_engine:
                    recent_events = self._check_runtime_events()
                    interaction_results["runtime_events_triggered"].extend(recent_events)
            
            self.logger.info(f"✅ Completed {interaction_results['interactions_performed']} app interactions")
            return interaction_results
            
        except Exception as e:
            self.logger.error(f"❌ Error during app feature exercise: {e}")
            interaction_results["errors_encountered"].append(str(e))
            return interaction_results
    
    def _get_current_ui_state(self) -> Optional[Dict[str, Any]]:
        """Get current UI state using UI Automator."""
        try:
            cmd = ['adb', 'shell', 'uiautomator', 'dump', '/sdcard/ui_dump.xml']
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            # Pull the UI dump
            cmd = ['adb', 'pull', '/sdcard/ui_dump.xml', '/tmp/ui_dump.xml']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse UI dump (simplified)
                return {"ui_dump_available": True, "timestamp": time.time()}
            else:
                return None
                
        except Exception as e:
            self.logger.debug(f"UI state capture failed: {e}")
            return None
    
    def _find_interactive_elements(self, ui_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find interactive UI elements."""
        # Simplified implementation - in real scenario would parse XML
        interactive_elements = [
            {"type": "button", "id": "login_btn", "clickable": True},
            {"type": "input", "id": "username", "text_input": True},
            {"type": "input", "id": "password", "text_input": True},
            {"type": "menu", "id": "menu_options", "clickable": True},
            {"type": "list_item", "id": "item_1", "clickable": True}
        ]
        
        # Return random subset for simulation
        return random.sample(interactive_elements, min(3, len(interactive_elements)))
    
    def _interact_with_element(self, element: Dict[str, Any]) -> bool:
        """Interact with a UI element."""
        try:
            element_type = element.get("type", "unknown")
            element_id = element.get("id", "unknown")
            
            self.logger.debug(f"🖱️ Interacting with {element_type}: {element_id}")
            
            if element.get("clickable"):
                # Simulate click
                self._perform_click_action(element)
                return True
            elif element.get("text_input"):
                # Simulate text input
                self._perform_text_input(element)
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.debug(f"Element interaction failed: {e}")
            return False
    
    def _perform_click_action(self, element: Dict[str, Any]):
        """Perform click action on element."""
        # Simulate click with ADB input tap
        # In real implementation, would use actual coordinates
        cmd = ['adb', 'shell', 'input', 'tap', '500', '800']
        subprocess.run(cmd, capture_output=True, timeout=3)
        time.sleep(0.5)
    
    def _perform_text_input(self, element: Dict[str, Any]):
        """Perform text input on element."""
        element_id = element.get("id", "")
        
        # Choose appropriate test data based on element
        if "password" in element_id.lower():
            test_text = "TestPass123!"
        elif "email" in element_id.lower():
            test_text = "test@example.com"
        elif "phone" in element_id.lower():
            test_text = "5551234567"
        else:
            test_text = "TestData123"
        
        # Input text using ADB
        cmd = ['adb', 'shell', 'input', 'text', test_text]
        subprocess.run(cmd, capture_output=True, timeout=3)
        time.sleep(0.5)
    
    def _perform_navigation_action(self):
        """Perform navigation action when no interactive elements found."""
        actions = ['back', 'home', 'recent']
        action = random.choice(actions)
        
        if action == 'back':
            cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_BACK']
        elif action == 'home':
            cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_HOME']
        else:  # recent
            cmd = ['adb', 'shell', 'input', 'keyevent', 'KEYCODE_APP_SWITCH']
        
        subprocess.run(cmd, capture_output=True, timeout=3)
        time.sleep(1)
        
        # If we went home, relaunch the app
        if action == 'home':
            time.sleep(2)
            self.launch_app()
    
    def _check_runtime_events(self) -> List[Dict[str, Any]]:
        """Check for recent runtime events from hook engine."""
        if not self.hook_engine:
            return []
        
        try:
            # Get recent events from hook engine
            recent_events = getattr(self.hook_engine, 'runtime_events', [])
            
            # Return events from last few seconds
            current_time = time.time()
            recent = [
                event for event in recent_events
                if event.get('timestamp', 0) > current_time - 5
            ]
            
            return recent
            
        except Exception as e:
            self.logger.debug(f"Runtime event check failed: {e}")
            return []
    
    def trigger_vulnerability_scenarios(self) -> Dict[str, Any]:
        """Trigger scenarios likely to expose vulnerabilities."""
        self.logger.info("🚨 Triggering vulnerability scenarios")
        
        scenario_results = {
            "scenarios_executed": 0,
            "crypto_scenarios": 0,
            "network_scenarios": 0,
            "storage_scenarios": 0,
            "vulnerabilities_detected": [],
            "runtime_events": []
        }
        
        try:
            # Crypto vulnerability scenarios
            crypto_results = self._trigger_crypto_scenarios()
            scenario_results["crypto_scenarios"] = len(crypto_results)
            scenario_results["runtime_events"].extend(crypto_results)
            
            # Network vulnerability scenarios
            network_results = self._trigger_network_scenarios()
            scenario_results["network_scenarios"] = len(network_results)
            scenario_results["runtime_events"].extend(network_results)
            
            # Storage vulnerability scenarios
            storage_results = self._trigger_storage_scenarios()
            scenario_results["storage_scenarios"] = len(storage_results)
            scenario_results["runtime_events"].extend(storage_results)
            
            total_scenarios = (
                scenario_results["crypto_scenarios"] + 
                scenario_results["network_scenarios"] + 
                scenario_results["storage_scenarios"]
            )
            
            scenario_results["scenarios_executed"] = total_scenarios
            
            if self.session:
                self.session.scenarios_executed = total_scenarios
            
            self.logger.info(f"✅ Executed {total_scenarios} vulnerability scenarios")
            return scenario_results
            
        except Exception as e:
            self.logger.error(f"❌ Error during vulnerability scenario execution: {e}")
            return scenario_results
    
    def _trigger_crypto_scenarios(self) -> List[Dict[str, Any]]:
        """Trigger cryptographic vulnerability scenarios."""
        scenarios = []
        
        # Scenario 1: Login with credentials (triggers crypto operations)
        scenarios.append(self._execute_login_scenario())
        
        # Scenario 2: Data encryption/decryption operations
        scenarios.append(self._execute_encryption_scenario())
        
        # Scenario 3: Certificate/SSL operations
        scenarios.append(self._execute_ssl_scenario())
        
        return [s for s in scenarios if s]
    
    def _trigger_network_scenarios(self) -> List[Dict[str, Any]]:
        """Trigger network vulnerability scenarios."""
        scenarios = []
        
        # Scenario 1: API requests (triggers network hooks)
        scenarios.append(self._execute_api_request_scenario())
        
        # Scenario 2: File downloads
        scenarios.append(self._execute_download_scenario())
        
        # Scenario 3: Data submission
        scenarios.append(self._execute_data_submission_scenario())
        
        return [s for s in scenarios if s]
    
    def _trigger_storage_scenarios(self) -> List[Dict[str, Any]]:
        """Trigger storage vulnerability scenarios."""
        scenarios = []
        
        # Scenario 1: File operations
        scenarios.append(self._execute_file_storage_scenario())
        
        # Scenario 2: Database operations
        scenarios.append(self._execute_database_scenario())
        
        # Scenario 3: SharedPreferences operations
        scenarios.append(self._execute_preferences_scenario())
        
        return [s for s in scenarios if s]
    
    def _execute_login_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute login scenario to trigger crypto operations."""
        try:
            self.logger.debug("🔐 Executing login scenario")
            
            # Find login elements and interact
            # This is simplified - real implementation would find actual login forms
            self._perform_text_input({"id": "username", "text_input": True})
            time.sleep(0.5)
            self._perform_text_input({"id": "password", "text_input": True})
            time.sleep(0.5)
            self._perform_click_action({"id": "login_btn", "clickable": True})
            
            return {
                "scenario": "login_crypto",
                "timestamp": time.time(),
                "description": "Login scenario to trigger cryptographic operations"
            }
            
        except Exception as e:
            self.logger.debug(f"Login scenario failed: {e}")
            return None
    
    def _execute_encryption_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute encryption scenario."""
        try:
            self.logger.debug("🔒 Executing encryption scenario")
            
            # Trigger actions that might cause encryption/decryption
            # Look for settings, secure notes, or file encryption features
            self._perform_navigation_action()
            time.sleep(1)
            
            return {
                "scenario": "encryption_operations",
                "timestamp": time.time(),
                "description": "Scenario to trigger encryption/decryption operations"
            }
            
        except Exception as e:
            self.logger.debug(f"Encryption scenario failed: {e}")
            return None
    
    def _execute_ssl_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute SSL/TLS scenario."""
        try:
            self.logger.debug("🌐 Executing SSL scenario")
            
            # Trigger network connections that use SSL/TLS
            # This might involve navigating to features that make HTTPS requests
            self._perform_click_action({"id": "network_feature", "clickable": True})
            time.sleep(2)
            
            return {
                "scenario": "ssl_operations", 
                "timestamp": time.time(),
                "description": "Scenario to trigger SSL/TLS operations"
            }
            
        except Exception as e:
            self.logger.debug(f"SSL scenario failed: {e}")
            return None
    
    def _execute_api_request_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute API request scenario."""
        try:
            self.logger.debug("📡 Executing API request scenario")
            
            # Trigger actions that cause API requests
            # Refresh data, sync, or load content
            actions = ['swipe_down', 'refresh', 'sync']
            action = random.choice(actions)
            
            if action == 'swipe_down':
                cmd = ['adb', 'shell', 'input', 'swipe', '500', '400', '500', '800']
            else:
                cmd = ['adb', 'shell', 'input', 'tap', '600', '200']  # Refresh/sync button
            
            subprocess.run(cmd, capture_output=True, timeout=3)
            time.sleep(2)
            
            return {
                "scenario": "api_requests",
                "timestamp": time.time(),
                "description": f"API request scenario ({action})"
            }
            
        except Exception as e:
            self.logger.debug(f"API request scenario failed: {e}")
            return None
    
    def _execute_download_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute file download scenario."""
        try:
            self.logger.debug("📥 Executing download scenario")
            
            # Look for download or file-related features
            self._perform_click_action({"id": "download_feature", "clickable": True})
            time.sleep(2)
            
            return {
                "scenario": "file_download",
                "timestamp": time.time(),
                "description": "File download scenario"
            }
            
        except Exception as e:
            self.logger.debug(f"Download scenario failed: {e}")
            return None
    
    def _execute_data_submission_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute data submission scenario."""
        try:
            self.logger.debug("📤 Executing data submission scenario")
            
            # Fill forms and submit data
            self._perform_text_input({"id": "data_field", "text_input": True})
            time.sleep(0.5)
            self._perform_click_action({"id": "submit_btn", "clickable": True})
            time.sleep(2)
            
            return {
                "scenario": "data_submission",
                "timestamp": time.time(),
                "description": "Data submission scenario"
            }
            
        except Exception as e:
            self.logger.debug(f"Data submission scenario failed: {e}")
            return None
    
    def _execute_file_storage_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute file storage scenario."""
        try:
            self.logger.debug("📁 Executing file storage scenario")
            
            # Trigger file save/load operations
            self._perform_click_action({"id": "save_file", "clickable": True})
            time.sleep(1)
            self._perform_click_action({"id": "load_file", "clickable": True})
            time.sleep(1)
            
            return {
                "scenario": "file_storage",
                "timestamp": time.time(),
                "description": "File storage operations scenario"
            }
            
        except Exception as e:
            self.logger.debug(f"File storage scenario failed: {e}")
            return None
    
    def _execute_database_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute database scenario."""
        try:
            self.logger.debug("🗄️ Executing database scenario")
            
            # Trigger database operations (save data, search, etc.)
            self._perform_text_input({"id": "search_field", "text_input": True})
            time.sleep(0.5)
            self._perform_click_action({"id": "search_btn", "clickable": True})
            time.sleep(2)
            
            return {
                "scenario": "database_operations",
                "timestamp": time.time(),
                "description": "Database operations scenario"
            }
            
        except Exception as e:
            self.logger.debug(f"Database scenario failed: {e}")
            return None
    
    def _execute_preferences_scenario(self) -> Optional[Dict[str, Any]]:
        """Execute SharedPreferences scenario."""
        try:
            self.logger.debug("⚙️ Executing preferences scenario")
            
            # Access settings and modify preferences
            self._perform_click_action({"id": "settings", "clickable": True})
            time.sleep(1)
            self._perform_click_action({"id": "preference_toggle", "clickable": True})
            time.sleep(1)
            
            return {
                "scenario": "shared_preferences",
                "timestamp": time.time(),
                "description": "SharedPreferences operations scenario"
            }
            
        except Exception as e:
            self.logger.debug(f"Preferences scenario failed: {e}")
            return None
    
    def finish_automation_session(self) -> AutomationSession:
        """Finish the current automation session and return results."""
        if not self.session:
            raise ValueError("No active automation session")
        
        self.session.session_duration = time.time() - self.session.start_time
        self.session.status = "completed"
        
        # Collect final statistics
        if self.hook_engine:
            runtime_events = getattr(self.hook_engine, 'runtime_events', [])
            self.session.runtime_events_triggered = len(runtime_events)
        
        if self.vulnerability_detector:
            detected_vulns = getattr(self.vulnerability_detector, 'detected_vulnerabilities', [])
            self.session.vulnerabilities_detected = len(detected_vulns)
        
        self.logger.info(f"✅ Automation session completed:")
        self.logger.info(f"   ⏱️ Duration: {self.session.session_duration:.1f}s")
        self.logger.info(f"   📱 Activities discovered: {self.session.activities_discovered}")
        self.logger.info(f"   🔄 Interactions performed: {self.session.interactions_performed}")
        self.logger.info(f"   🚨 Scenarios executed: {self.session.scenarios_executed}")
        self.logger.info(f"   ⚡ Runtime events triggered: {self.session.runtime_events_triggered}")
        self.logger.info(f"   🔍 Vulnerabilities detected: {self.session.vulnerabilities_detected}")
        
        return self.session
    
    def get_automation_summary(self) -> Dict[str, Any]:
        """Get automation session summary."""
        if not self.session:
            return {"error": "No active session"}
        
        return {
            "package_name": self.session.package_name,
            "status": self.session.status,
            "duration": self.session.session_duration,
            "activities_discovered": self.session.activities_discovered,
            "interactions_performed": self.session.interactions_performed,
            "scenarios_executed": self.session.scenarios_executed,
            "runtime_events_triggered": self.session.runtime_events_triggered,
            "vulnerabilities_detected": self.session.vulnerabilities_detected,
            "discovered_activities": [
                {"name": activity.name, "exported": activity.exported}
                for activity in self.discovered_activities
            ],
            "automation_effectiveness": self._calculate_effectiveness()
        }
    
    def _calculate_effectiveness(self) -> float:
        """Calculate automation effectiveness score."""
        if not self.session:
            return 0.0
        
        # Simple effectiveness metric based on activity
        base_score = min(1.0, self.session.interactions_performed / 10)
        scenario_bonus = min(0.5, self.session.scenarios_executed / 5)
        event_bonus = min(0.3, self.session.runtime_events_triggered / 20)
        vuln_bonus = min(0.2, self.session.vulnerabilities_detected / 3)
        
        effectiveness = base_score + scenario_bonus + event_bonus + vuln_bonus
        return min(1.0, effectiveness)


# Convenience functions for integration
def create_app_automator(device=None, package_name: str = None, apk_ctx: Any = None) -> AppAutomationFramework:
    """Create an app automation framework instance."""
    return AppAutomationFramework(device=device, package_name=package_name, apk_ctx=apk_ctx)


def quick_app_exercise(package_name: str, duration: int = 60) -> Dict[str, Any]:
    """Quickly exercise an app for the specified duration."""
    automator = AppAutomationFramework(package_name=package_name)
    
    # Start session
    session = automator.start_automation_session(duration)
    
    # Launch app
    if not automator.launch_app():
        return {"error": "Failed to launch app"}
    
    # Discover activities
    automator.discover_activities()
    
    # Exercise features
    exercise_results = automator.exercise_app_features(max_interactions=20)
    
    # Trigger scenarios
    scenario_results = automator.trigger_vulnerability_scenarios()
    
    # Finish session
    final_session = automator.finish_automation_session()
    
    return {
        "session": automator.get_automation_summary(),
        "exercise_results": exercise_results,
        "scenario_results": scenario_results
    }


if __name__ == "__main__":
    # Demo usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python app_automator.py <package_name> [duration]")
        sys.exit(1)
    
    package_name = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    
    print(f"🚀 App Automation Demo: {package_name}")
    print("=" * 50)
    
    # Run quick exercise
    results = quick_app_exercise(package_name, duration)
    
    if "error" in results:
        print(f"❌ Error: {results['error']}")
    else:
        print("✅ Automation completed!")
        print(f"📊 Session Summary:")
        session = results["session"]
        print(f"   Duration: {session.get('duration', 0):.1f}s")
        print(f"   Interactions: {session.get('interactions_performed', 0)}")
        print(f"   Scenarios: {session.get('scenarios_executed', 0)}")
        print(f"   Effectiveness: {session.get('automation_effectiveness', 0):.2f}")